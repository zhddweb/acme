<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Http01;

use Mci\Acme\Challenge\AbstractSolver;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ChallengeException;
use Mci\Acme\Protocol\Challenge;
use Mci\Acme\Util\Logger;
use Mci\Acme\Util\Platform;

/**
 * http-01：自己在 80 端口上起一个极简 HTTP 服务器来应答。
 *
 * 用在机器上根本没跑 web 服务的场合（纯邮件服务器、数据库机器）。
 * 如果 80 端口已经被 nginx 占着，这个模式起不来——那种情况该用 webroot。
 *
 * **单进程实现，不 fork。** 目标环境里 pcntl 基本都被禁了，而且 fork 出来的
 * 子进程一旦父进程异常退出就会变成孤儿继续占着端口。代价是必须由调用方
 * 在等待验证的间隙反复调用 tick() 来 accept 连接——ChallengeSolver 接口里
 * 那个 tick() 就是为它设计的。
 *
 * 只回答 `/.well-known/acme-challenge/<已知 token>`，其余一律 404。
 * 这不是偷懒：这个服务器会在公网 80 端口上暴露若干秒，功能越少越安全。
 */
class StandaloneSolver extends AbstractSolver
{
    const TYPE = 'http-01';

    /** @var int */
    private $port;

    /** @var string 监听地址；默认全部网卡，CA 从公网来 */
    private $bindAddress;

    /** @var resource|null 监听 socket */
    private $server;

    /** @var array<string, string> token => keyAuthorization */
    private $tokens = [];

    /** @var int accept 的等待时间（微秒）。给得太大 tick 会卡住轮询循环 */
    private $acceptTimeoutUs = 200000;

    public function __construct(int $port = 80, string $bindAddress = '0.0.0.0', ?Logger $logger = null)
    {
        parent::__construct($logger);

        $this->port = $port;
        $this->bindAddress = $bindAddress;
    }

    public function getType(): string
    {
        return self::TYPE;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function prepare(Challenge $challenge, KeyPair $accountKey): void
    {
        $this->tokens[$challenge->getToken()] = $challenge->getKeyAuthorization($accountKey);
        $this->startServer();

        $this->logger->debug(sprintf(
            'standalone 服务器已就绪，等待 CA 访问 %s',
            $challenge->getHttpUrl()
        ));
    }

    public function cleanup(Challenge $challenge, KeyPair $accountKey): void
    {
        unset($this->tokens[$challenge->getToken()]);

        // 还有别的域名在等验证就先别关，一次多域名签发共用同一个监听
        if ($this->tokens === []) {
            $this->stopServer();
        }
    }

    /**
     * 处理已经排队的连接。
     *
     * 每次最多处理若干个就返回，把控制权交回轮询循环——否则一个慢客户端
     * （或者扫描器）就能把整个签发流程拖住。
     */
    public function tick(): void
    {
        if ($this->server === null) {
            return;
        }

        for ($i = 0; $i < 16; ++$i) {
            $connection = @stream_socket_accept($this->server, $this->acceptTimeoutUs / 1000000);
            if ($connection === false) {
                return;
            }

            $this->handleConnection($connection);
        }
    }

    public function verify(Challenge $challenge, KeyPair $accountKey): bool
    {
        return $this->server !== null && isset($this->tokens[$challenge->getToken()]);
    }

    private function startServer(): void
    {
        if ($this->server !== null) {
            return;
        }

        if (!Platform::hasSockets()) {
            throw new ChallengeException(
                'standalone 模式需要 stream_socket_server()，当前 PHP 禁用了它。'
                . '改用 webroot 模式（-w /网站根目录）或 dns-01'
            );
        }

        $address = sprintf('tcp://%s:%d', $this->bindAddress, $this->port);

        $errno = 0;
        $error = '';
        // SO_REUSEADDR：上一次运行留下的 TIME_WAIT 会让端口在几十秒内绑不上，
        // 续期脚本连着跑两次就会撞上
        $context = stream_context_create(['socket' => ['so_reuseaddr' => true, 'backlog' => 128]]);
        $server = @stream_socket_server($address, $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);

        if ($server === false) {
            throw new ChallengeException(sprintf(
                '无法监听 %s：%s。%s',
                $address,
                $error !== '' ? $error : '未知错误',
                $this->port < 1024
                    ? '小于 1024 的端口需要 root 权限；若 80 端口已被 nginx/apache 占用，请改用 webroot 模式'
                    : '检查端口是否已被占用'
            ));
        }

        // 非阻塞：tick() 里 accept 不能把整个进程挂住
        stream_set_blocking($server, false);
        $this->server = $server;

        $this->logger->debug(sprintf('standalone 服务器已监听 %s', $address));
    }

    private function stopServer(): void
    {
        if ($this->server === null) {
            return;
        }

        fclose($this->server);
        $this->server = null;
        $this->logger->debug('standalone 服务器已关闭');
    }

    /**
     * @param resource $connection
     */
    private function handleConnection($connection): void
    {
        stream_set_timeout($connection, 5);

        $requestLine = fgets($connection, 8192);
        if ($requestLine === false) {
            fclose($connection);

            return;
        }

        // 把请求头读完丢掉。不读的话某些客户端会因为写缓冲满而收不到响应
        while (($line = fgets($connection, 8192)) !== false) {
            if (trim($line) === '') {
                break;
            }
        }

        $path = '';
        if (preg_match('#^(GET|HEAD)\s+(\S+)\s+HTTP/#i', $requestLine, $m) === 1) {
            $path = $m[2];
        }

        // 去掉查询串：CA 不会带，但扫描器会
        $queryPos = strpos($path, '?');
        if ($queryPos !== false) {
            $path = substr($path, 0, $queryPos);
        }

        $prefix = '/.well-known/acme-challenge/';
        $token = str_starts_with($path, $prefix) ? substr($path, \strlen($prefix)) : '';

        if ($token !== '' && isset($this->tokens[$token])) {
            $body = $this->tokens[$token];
            $this->respond($connection, 200, 'application/octet-stream', $body);
            $this->logger->debug(sprintf('已应答验证请求：%s', $path));
        } else {
            $this->respond($connection, 404, 'text/plain', "Not Found\n");
        }

        fclose($connection);
    }

    /**
     * @param resource $connection
     */
    private function respond($connection, int $status, string $contentType, string $body): void
    {
        $reason = $status === 200 ? 'OK' : 'Not Found';

        $headers = sprintf(
            "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
            $status,
            $reason,
            $contentType,
            \strlen($body)
        );

        @fwrite($connection, $headers . $body);
    }

    /** 兜底：对象被回收时别把端口留着 */
    public function __destruct()
    {
        $this->stopServer();
    }
}
