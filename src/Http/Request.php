<?php

declare(strict_types=1);

namespace Mci\Acme\Http;

/**
 * 一次待发出的 HTTP 请求。
 *
 * 做成值对象是因为重试和重定向都要「拿着同一个请求再发一次」，
 * 用数组传参会在第三次改签名的时候散架。
 */
class Request
{
    /** @var string */
    private $method;

    /** @var string */
    private $url;

    /** @var array<string, string> */
    private $headers;

    /** @var string|null */
    private $body;

    /** @var int 连接超时，秒 */
    private $connectTimeout = 20;

    /** @var int 整体超时，秒 */
    private $timeout = 60;

    /** @var bool 是否校验对端证书；只有本地调试才该关 */
    private $verifyPeer = true;

    /** @var string|null 自定义 CA bundle 路径 */
    private $caFile;

    /** @var \Mci\Acme\Http\Proxy\Proxy|null 这次请求该走的代理；null 表示直连 */
    private $proxy;

    /**
     * @param array<string, string> $headers
     */
    public function __construct(string $method, string $url, array $headers = [], ?string $body = null)
    {
        $this->method = strtoupper($method);
        $this->url = $url;
        $this->headers = $headers;
        $this->body = $body;
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    /** 重定向时用：换个 URL，其余照旧 */
    public function withUrl(string $url): self
    {
        $clone = clone $this;
        $clone->url = $url;

        return $clone;
    }

    public function withMethod(string $method): self
    {
        $clone = clone $this;
        $clone->method = strtoupper($method);

        return $clone;
    }

    public function withBody(?string $body): self
    {
        $clone = clone $this;
        $clone->body = $body;

        return $clone;
    }

    public function withHeader(string $name, string $value): self
    {
        $clone = clone $this;
        $clone->headers[$name] = $value;

        return $clone;
    }

    /** @return array<string, string> */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function getHeader(string $name): ?string
    {
        foreach ($this->headers as $key => $value) {
            if (strcasecmp($key, $name) === 0) {
                return $value;
            }
        }

        return null;
    }

    public function getBody(): ?string
    {
        return $this->body;
    }

    public function getConnectTimeout(): int
    {
        return $this->connectTimeout;
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }

    public function setTimeouts(int $connectTimeout, int $timeout): void
    {
        $this->connectTimeout = $connectTimeout;
        $this->timeout = $timeout;
    }

    public function getVerifyPeer(): bool
    {
        return $this->verifyPeer;
    }

    public function setVerifyPeer(bool $verify): void
    {
        $this->verifyPeer = $verify;
    }

    public function getCaFile(): ?string
    {
        return $this->caFile;
    }

    public function setCaFile(?string $caFile): void
    {
        $this->caFile = $caFile;
    }

    public function getProxyConfig(): ?\Mci\Acme\Http\Proxy\Proxy
    {
        return $this->proxy;
    }

    public function setProxyConfig(?\Mci\Acme\Http\Proxy\Proxy $proxy): void
    {
        $this->proxy = $proxy;
    }

    public function usesProxy(): bool
    {
        return $this->proxy !== null;
    }
}
