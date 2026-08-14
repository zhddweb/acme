<?php

declare(strict_types=1);

namespace PhpAcme\Crypto;

use PhpAcme\Exception\CryptoException;
use PhpAcme\Util\Domain;

/**
 * 一张已签发的证书，以及证书链的拆分。
 *
 * 解析用 openssl_x509_parse()，不自己动手——X.509 的边角情况太多
 * （各种字符串类型、扩展编码、时间格式），自己写只会引入 bug。
 * 我们自己拼 DER 的地方只有 CSR 和 tls-alpn 自签证书，那两个结构简单且完全可控。
 */
class Certificate
{
    /** @var string PEM 格式的证书本体（只含第一张，不含链） */
    private $pem;

    /** @var array openssl_x509_parse() 的结果 */
    private $info;

    private function __construct(string $pem, array $info)
    {
        $this->pem = $pem;
        $this->info = $info;
    }

    public static function fromPem(string $pem): self
    {
        $certificates = self::splitChain($pem);
        if ($certificates === []) {
            throw new CryptoException('没有从内容里找到任何 PEM 证书');
        }

        $first = $certificates[0];

        // 用默认的短名模式（CN / O / OU）。传 false 会换成长名（commonName），
        // 键名一变下面所有取值都得跟着改，没有好处
        $info = @openssl_x509_parse($first);
        if ($info === false || !\is_array($info)) {
            throw new CryptoException('证书解析失败，内容可能不是合法的 X.509');
        }

        return new self($first, $info);
    }

    public static function fromFile(string $path): self
    {
        $content = @file_get_contents($path);
        if ($content === false) {
            throw new CryptoException(sprintf('读不到证书文件：%s', $path));
        }

        return self::fromPem($content);
    }

    /**
     * 把一串 PEM 拆成单张证书的数组。
     *
     * ACME 下载回来的是整条链（叶子证书在最前，然后是中间 CA），
     * 存盘时要分开放：<domain>.cer 只放叶子，ca.cer 放中间证书，
     * fullchain.cer 放全部——nginx 要 fullchain，有些设备只要叶子。
     *
     * @return array<int, string>
     */
    public static function splitChain(string $pem): array
    {
        $matches = [];
        if (preg_match_all('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $pem, $matches) === false) {
            return [];
        }

        $out = [];
        foreach ($matches[0] as $certificate) {
            // 统一成 LF 结尾并补一个换行：有的 CA 返回 CRLF，
            // 拼接后交给 nginx 会因为 \r 解析失败
            $out[] = rtrim(str_replace("\r\n", "\n", $certificate)) . "\n";
        }

        return $out;
    }

    public function getPem(): string
    {
        return $this->pem;
    }

    /** @return array */
    public function getInfo(): array
    {
        return $this->info;
    }

    public function getSubjectCommonName(): string
    {
        if (isset($this->info['subject']['CN'])) {
            $cn = $this->info['subject']['CN'];

            // 多个同名字段时 openssl 会给数组
            return \is_array($cn) ? (string) $cn[0] : (string) $cn;
        }

        return '';
    }

    public function getIssuerCommonName(): string
    {
        if (isset($this->info['issuer']['CN'])) {
            $cn = $this->info['issuer']['CN'];

            return \is_array($cn) ? (string) $cn[0] : (string) $cn;
        }

        return '';
    }

    public function getSerialNumber(): string
    {
        if (isset($this->info['serialNumberHex'])) {
            return strtoupper((string) $this->info['serialNumberHex']);
        }

        return isset($this->info['serialNumber']) ? (string) $this->info['serialNumber'] : '';
    }

    public function getNotBefore(): int
    {
        return isset($this->info['validFrom_time_t']) ? (int) $this->info['validFrom_time_t'] : 0;
    }

    public function getNotAfter(): int
    {
        return isset($this->info['validTo_time_t']) ? (int) $this->info['validTo_time_t'] : 0;
    }

    /**
     * 证书里的全部域名（SAN + CN 去重）。
     *
     * @return array<int, string>
     */
    public function getDomains(): array
    {
        $domains = [];

        $cn = $this->getSubjectCommonName();
        if ($cn !== '') {
            $domains[] = strtolower($cn);
        }

        if (isset($this->info['extensions']['subjectAltName'])) {
            // 格式是 "DNS:a.com, DNS:*.a.com, IP Address:1.2.3.4"
            foreach (explode(',', (string) $this->info['extensions']['subjectAltName']) as $entry) {
                $entry = trim($entry);
                if (str_starts_with($entry, 'DNS:')) {
                    $domains[] = strtolower(trim(substr($entry, 4)));
                }
            }
        }

        return array_values(array_unique($domains));
    }

    /** 还有几天到期；已经过期返回负数 */
    public function getDaysUntilExpiry(?int $now = null): int
    {
        $now = $now !== null ? $now : time();
        $remaining = $this->getNotAfter() - $now;

        // 向下取整：还剩 29.9 天就说 29 天，宁可早续也不要晚续
        return (int) floor($remaining / 86400);
    }

    public function isExpired(?int $now = null): bool
    {
        $now = $now !== null ? $now : time();

        return $this->getNotAfter() <= $now;
    }

    /**
     * 是否该续期了。
     *
     * acme.sh 的默认是提前 60 天，对应 Let's Encrypt 的 90 天有效期
     * （签发后 30 天就开始续，留足两个月的重试窗口）。
     * 短周期证书（如 6 天的 Let's Encrypt short-lived）要另外传阈值。
     */
    public function needsRenewal(int $renewDaysBefore = 30, ?int $now = null): bool
    {
        return $this->getDaysUntilExpiry($now) <= $renewDaysBefore;
    }

    /**
     * 这张证书能不能覆盖住给定的一批域名。
     *
     * 续期时用：域名列表变了（加了新域名）就不能沿用旧证书，必须重新签。
     *
     * @param array<int, string> $domains
     */
    public function covers(array $domains): bool
    {
        $sans = $this->getDomains();

        foreach ($domains as $domain) {
            if (!Domain::isCoveredBy((string) $domain, $sans)) {
                return false;
            }
        }

        return true;
    }

    /** 证书公钥是不是 EC；决定证书存到 <domain> 还是 <domain>_ecc 目录 */
    public function isEc(): bool
    {
        $key = @openssl_pkey_get_public($this->pem);
        if ($key === false) {
            return false;
        }

        $details = @openssl_pkey_get_details($key);

        return \is_array($details)
            && isset($details['type'])
            && $details['type'] === OPENSSL_KEYTYPE_EC;
    }

    /**
     * 私钥和这张证书是不是配对的。
     *
     * 部署前必查：把不配对的证书和私钥丢给 nginx，它会在 reload 时
     * 拒绝启动，而那时旧配置已经被覆盖了。
     */
    public function matchesPrivateKey(KeyPair $keyPair): bool
    {
        return @openssl_x509_check_private_key($this->pem, $keyPair->getHandle()) === true;
    }

    /**
     * 给 revokeCert 用的 base64url DER。
     *
     * 吊销请求传的是**裸证书的 DER**，既不是 PEM 也不是整条链。
     */
    public function toBase64UrlDer(): string
    {
        return Base64Url::encode(self::pemToDer($this->pem));
    }

    public static function pemToDer(string $pem): string
    {
        if (preg_match('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $pem, $m) !== 1) {
            throw new CryptoException('这不是一份 PEM 证书');
        }

        $der = base64_decode(preg_replace('/\s+/', '', $m[1]), true);
        if ($der === false) {
            throw new CryptoException('证书的 base64 解码失败');
        }

        return $der;
    }

    public static function derToPem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END CERTIFICATE-----\n";
    }
}
