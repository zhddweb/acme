<?php

declare(strict_types=1);

namespace Mci\Acme\Http\Proxy;

use Mci\Acme\Exception\ConfigException;

/**
 * 一个代理服务器的配置。
 *
 * 支持四种 scheme，语义与 curl 一致：
 *
 * | scheme | 含义 |
 * |---|---|
 * | `http` | HTTP 代理。访问 https 目标时走 CONNECT 隧道 |
 * | `https` | 到代理本身的连接也用 TLS（少见，但企业网关会用） |
 * | `socks5` | SOCKS5，**域名由本地解析** |
 * | `socks5h` | SOCKS5，**域名交给代理解析** |
 *
 * `socks5` 与 `socks5h` 的区别在受限网络里很关键：如果本地 DNS 本身就被污染
 * 或不通（这正是要用代理的常见原因），`socks5` 会在解析这一步就失败，
 * 必须用 `socks5h` 把域名原样交给代理去解析。不写 scheme 时默认按 `http` 处理。
 */
class Proxy
{
    const SCHEME_HTTP = 'http';
    const SCHEME_HTTPS = 'https';
    const SCHEME_SOCKS5 = 'socks5';
    /** 域名交给代理解析的 SOCKS5 */
    const SCHEME_SOCKS5H = 'socks5h';

    /** @var string */
    private $scheme;

    /** @var string */
    private $host;

    /** @var int */
    private $port;

    /** @var string|null */
    private $username;

    /** @var string|null */
    private $password;

    public function __construct(
        string $scheme,
        string $host,
        int $port,
        ?string $username = null,
        ?string $password = null
    ) {
        $this->scheme = strtolower($scheme);
        $this->host = $host;
        $this->port = $port;
        $this->username = $username;
        $this->password = $password;
    }

    /**
     * 解析一个代理地址。
     *
     * 接受的写法：
     *
     *     http://127.0.0.1:8080
     *     http://user:pass@proxy.corp:3128
     *     socks5h://127.0.0.1:1080
     *     127.0.0.1:8080          （省略 scheme 时按 http 处理，和 curl 一致）
     */
    public static function fromString(string $value): self
    {
        $value = trim($value);

        if ($value === '') {
            throw new ConfigException('代理地址不能为空');
        }

        // 省略 scheme 时补一个，否则 parse_url 会把 host 当成 path
        if (!preg_match('#^[a-z0-9+.-]+://#i', $value)) {
            $value = 'http://' . $value;
        }

        $parts = parse_url($value);
        if ($parts === false || !isset($parts['host'])) {
            throw new ConfigException(sprintf(
                '解析不了代理地址「%s」。正确写法形如 http://127.0.0.1:8080 或 socks5h://user:pass@host:1080',
                $value
            ));
        }

        $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : self::SCHEME_HTTP;

        // socks 与 socks4 都按 socks5 处理：本库只实现了 SOCKS5，
        // 而写 socks:// 的人十有八九指的就是它
        if ($scheme === 'socks') {
            $scheme = self::SCHEME_SOCKS5;
        }

        $supported = [self::SCHEME_HTTP, self::SCHEME_HTTPS, self::SCHEME_SOCKS5, self::SCHEME_SOCKS5H];
        if (!\in_array($scheme, $supported, true)) {
            throw new ConfigException(sprintf(
                '不支持的代理协议「%s」，可用：%s',
                $scheme,
                implode('、', $supported)
            ));
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : self::defaultPort($scheme);

        return new self(
            $scheme,
            $parts['host'],
            $port,
            isset($parts['user']) ? rawurldecode($parts['user']) : null,
            isset($parts['pass']) ? rawurldecode($parts['pass']) : null
        );
    }

    private static function defaultPort(string $scheme): int
    {
        if ($scheme === self::SCHEME_SOCKS5 || $scheme === self::SCHEME_SOCKS5H) {
            return 1080;
        }

        return $scheme === self::SCHEME_HTTPS ? 443 : 8080;
    }

    public function getScheme(): string
    {
        return $this->scheme;
    }

    public function getHost(): string
    {
        return $this->host;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function hasCredentials(): bool
    {
        return $this->username !== null && $this->username !== '';
    }

    public function isSocks(): bool
    {
        return $this->scheme === self::SCHEME_SOCKS5 || $this->scheme === self::SCHEME_SOCKS5H;
    }

    /** 域名是否该交给代理去解析 */
    public function resolvesRemotely(): bool
    {
        return $this->scheme === self::SCHEME_SOCKS5H;
    }

    public function isHttp(): bool
    {
        return $this->scheme === self::SCHEME_HTTP || $this->scheme === self::SCHEME_HTTPS;
    }

    /** 连到代理本身要不要先做 TLS */
    public function needsTls(): bool
    {
        return $this->scheme === self::SCHEME_HTTPS;
    }

    /** 给 stream_socket_client 用的地址 */
    public function getSocketAddress(): string
    {
        // 到代理这一跳先建明文 TCP；needsTls() 为真时由调用方再升级
        return sprintf('tcp://%s:%d', $this->host, $this->port);
    }

    /** curl 认得的完整地址（含认证信息） */
    public function toCurlString(): string
    {
        return sprintf('%s://%s:%d', $this->scheme, $this->host, $this->port);
    }

    /**
     * 打日志用。
     *
     * **密码必须打码**：日志经常被贴进 issue 或发给同事，
     * 明文代理密码泄露过不止一次。
     */
    public function toSafeString(): string
    {
        if (!$this->hasCredentials()) {
            return sprintf('%s://%s:%d', $this->scheme, $this->host, $this->port);
        }

        return sprintf('%s://%s:***@%s:%d', $this->scheme, $this->username, $this->host, $this->port);
    }

    public function __toString(): string
    {
        return $this->toSafeString();
    }
}
