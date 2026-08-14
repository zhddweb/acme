<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\TlsAlpn01;

use Mci\Acme\Challenge\AbstractSolver;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Crypto\SelfSignedCertificate;
use Mci\Acme\Exception\ChallengeException;
use Mci\Acme\Protocol\Challenge;
use Mci\Acme\Util\Filesystem;
use Mci\Acme\Util\Logger;
use Mci\Acme\Util\Platform;

/**
 * tls-alpn-01（RFC 8737）：在 443 端口用一张特制自签证书应答。
 *
 * 相比 http-01 的好处是**完全走 443**，80 端口可以关着；相比 dns-01 的好处是
 * 不需要解析商 API。代价是它要求独占 443 端口——和 nginx 共存需要 nginx 配
 * `ssl_preread` 按 ALPN 分流，那属于用户侧的配置，本库管不了。
 *
 * 实现上同样是单进程 + tick()，理由和 StandaloneSolver 一样。
 *
 * 环境要求比较硬：PHP 的 stream 要支持 `alpn_protocols` 上下文选项
 * （PHP 7.0.7+ 且 OpenSSL 1.0.2+）。不满足时给出明确报错让用户换验证方式，
 * 而不是起一个握手必失败的服务器让 CA 那边超时。
 */
class TlsAlpnSolver extends AbstractSolver
{
    const TYPE = 'tls-alpn-01';

    /** ALPN 协商用的协议名，规范固定 */
    const ALPN_PROTOCOL = 'acme-tls/1';

    /** @var int */
    private $port;

    /** @var string */
    private $bindAddress;

    /** @var resource|null */
    private $server;

    /** @var Filesystem */
    private $filesystem;

    /** @var string 临时证书文件目录 */
    private $tempDir;

    /** @var array<int, string> 临时写出的证书文件，cleanup 时删 */
    private $tempFiles = [];

    public function __construct(
        int $port = 443,
        string $bindAddress = '0.0.0.0',
        ?string $tempDir = null,
        ?Logger $logger = null,
        ?Filesystem $filesystem = null
    ) {
        parent::__construct($logger);

        $this->port = $port;
        $this->bindAddress = $bindAddress;
        $this->filesystem = $filesystem !== null ? $filesystem : new Filesystem();
        $this->tempDir = $tempDir !== null ? rtrim($tempDir, '/\\') : sys_get_temp_dir();
    }

    public function getType(): string
    {
        return self::TYPE;
    }

    public function prepare(Challenge $challenge, KeyPair $accountKey): void
    {
        $this->assertSupported();

        // 每个挑战一把独立的临时密钥。用账户密钥或证书私钥都不合适：
        // 这张证书要在公网上出示，和长期密钥绑在一起没有必要
        $keyPair = KeyPair::generate(KeyPair::TYPE_EC_256);

        $certificate = SelfSignedCertificate::forTlsAlpn(
            $keyPair,
            $challenge->getDomain(),
            $challenge->getTlsAlpnDigest($accountKey)
        );

        // PHP 的 SSL 上下文只认文件路径，没法直接喂内存里的 PEM，
        // 所以必须落一个临时文件。权限 0600，用完立刻删
        $path = sprintf(
            '%s/mci-acme-alpn-%s.pem',
            $this->tempDir,
            substr(hash('sha256', $challenge->getDomain() . $challenge->getToken()), 0, 16)
        );

        $this->filesystem->writePrivate($path, $certificate . $keyPair->getPrivateKeyPem());
        $this->tempFiles[] = $path;

        $this->startServer($path);

        $this->logger->debug(sprintf(
            'tls-alpn-01 服务器已就绪，等待 CA 连接 %s:%d',
            $challenge->getDomain(),
            $this->port
        ));
    }

    public function cleanup(Challenge $challenge, KeyPair $accountKey): void
    {
        $this->stopServer();

        foreach ($this->tempFiles as $path) {
            $this->filesystem->delete($path);
        }
        $this->tempFiles = [];
    }

    public function tick(): void
    {
        if ($this->server === null) {
            return;
        }

        for ($i = 0; $i < 8; ++$i) {
            $connection = @stream_socket_accept($this->server, 0.2);
            if ($connection === false) {
                return;
            }

            // 握手成功本身就是应答——CA 要的是证书里的扩展，不看应用层数据。
            // 握手完直接关掉即可
            @stream_socket_enable_crypto($connection, true, STREAM_CRYPTO_METHOD_TLS_SERVER);
            @fclose($connection);

            $this->logger->debug('已应答一次 tls-alpn-01 握手');
        }
    }

    public function verify(Challenge $challenge, KeyPair $accountKey): bool
    {
        return $this->server !== null;
    }

    private function assertSupported(): void
    {
        if (!Platform::hasSockets()) {
            throw new ChallengeException(
                'tls-alpn-01 需要 stream_socket_server()，当前 PHP 禁用了它'
            );
        }

        if (!\extension_loaded('openssl')) {
            throw new ChallengeException('tls-alpn-01 需要 openssl 扩展');
        }

        // alpn_protocols 这个上下文选项在 PHP 7.0.7 加入，且要求
        // 链接的 OpenSSL 是 1.0.2 以上。缺了它握手时不会报错，
        // 只是协商不出 acme-tls/1，CA 会判定验证失败——那种失败极难排查，
        // 所以在这里提前拦下来
        if (!\defined('OPENSSL_VERSION_NUMBER') || OPENSSL_VERSION_NUMBER < 0x10002000) {
            throw new ChallengeException(sprintf(
                'tls-alpn-01 需要 OpenSSL 1.0.2 以上，当前是 %s。请改用 http-01 或 dns-01',
                \defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : '未知版本'
            ));
        }
    }

    private function startServer(string $certificatePath): void
    {
        if ($this->server !== null) {
            return;
        }

        $context = stream_context_create([
            'socket' => ['so_reuseaddr' => true, 'backlog' => 128],
            'ssl' => [
                'local_cert' => $certificatePath,
                'alpn_protocols' => self::ALPN_PROTOCOL,
                // 这张证书本来就是自签的，校验自己没有意义
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
            ],
        ]);

        $address = sprintf('tcp://%s:%d', $this->bindAddress, $this->port);

        $errno = 0;
        $error = '';
        $server = @stream_socket_server(
            $address,
            $errno,
            $error,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
            $context
        );

        if ($server === false) {
            throw new ChallengeException(sprintf(
                '无法监听 %s：%s。443 端口通常已被 web 服务器占用，'
                . 'tls-alpn-01 需要独占它——先停掉 nginx/apache，或改用其他验证方式',
                $address,
                $error !== '' ? $error : '未知错误'
            ));
        }

        stream_set_blocking($server, false);
        $this->server = $server;
    }

    private function stopServer(): void
    {
        if ($this->server === null) {
            return;
        }

        fclose($this->server);
        $this->server = null;
    }

    public function __destruct()
    {
        $this->stopServer();
        foreach ($this->tempFiles as $path) {
            @unlink($path);
        }
    }
}
