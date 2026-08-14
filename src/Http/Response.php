<?php

declare(strict_types=1);

namespace PhpAcme\Http;

use PhpAcme\Util\Json;

/**
 * 一次 HTTP 响应。
 *
 * header 一律按小写键存：ACME 服务端返回的到底是 Replay-Nonce 还是 replay-nonce
 * 取决于 HTTP 版本（HTTP/2 强制小写），大小写敏感地取会在换了 CA 之后莫名其妙失效。
 */
class Response
{
    /** @var int */
    private $status;

    /** @var array<string, array<int, string>> 小写键 => 值列表 */
    private $headers;

    /** @var string */
    private $body;

    /** @var string 实际请求的 URL，跟随重定向后可能与原始 URL 不同 */
    private $url;

    /**
     * @param array<string, array<int, string>|string> $headers
     */
    public function __construct(int $status, array $headers = [], string $body = '', string $url = '')
    {
        $this->status = $status;
        $this->body = $body;
        $this->url = $url;

        $normalized = [];
        foreach ($headers as $name => $value) {
            $key = strtolower((string) $name);
            $normalized[$key] = \is_array($value) ? array_values($value) : [(string) $value];
        }
        $this->headers = $normalized;
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    public function getBody(): string
    {
        return $this->body;
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    /** @return array<string, array<int, string>> */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /** 同名头有多个时返回第一个；ACME 里除了 Link 都是单值 */
    public function getHeader(string $name): ?string
    {
        $key = strtolower($name);

        return isset($this->headers[$key][0]) ? $this->headers[$key][0] : null;
    }

    /** @return array<int, string> */
    public function getHeaderValues(string $name): array
    {
        $key = strtolower($name);

        return isset($this->headers[$key]) ? $this->headers[$key] : [];
    }

    public function getContentType(): string
    {
        $type = $this->getHeader('content-type');
        if ($type === null) {
            return '';
        }

        // "application/json; charset=utf-8" 只取前半段
        $pos = strpos($type, ';');

        return strtolower(trim($pos === false ? $type : substr($type, 0, $pos)));
    }

    public function isSuccess(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }

    public function isRedirect(): bool
    {
        return $this->status >= 300 && $this->status < 400;
    }

    public function isServerError(): bool
    {
        return $this->status >= 500;
    }

    /** 响应体是不是 ACME 的 problem document */
    public function isProblem(): bool
    {
        return $this->getContentType() === 'application/problem+json';
    }

    /** @return array */
    public function json(): array
    {
        return Json::decode($this->body, sprintf('%s 返回的响应', $this->url));
    }

    /** @return array|null */
    public function tryJson(): ?array
    {
        return Json::tryDecode($this->body);
    }

    public function getLocation(): ?string
    {
        return $this->getHeader('location');
    }

    /**
     * 解析 Link 头，按 rel 分组。
     *
     * ACME 用它指向 ToS（rel="terms-of-service"）和备用证书链（rel="alternate"），
     * 一个响应里可能有多个同 rel 的 Link，所以值是数组。
     *
     * @return array<string, array<int, string>>
     */
    public function getLinks(): array
    {
        $links = [];

        foreach ($this->getHeaderValues('link') as $header) {
            // 一行里可能塞了多个 link，用逗号分隔；但 URL 里也可能有逗号，
            // 所以按 `>` 后面的逗号切，不能直接 explode(',')
            foreach (preg_split('/,\s*(?=<)/', $header) as $part) {
                if (preg_match('/<([^>]+)>\s*;\s*rel\s*=\s*"?([^";]+)"?/i', $part, $m) === 1) {
                    $rel = strtolower(trim($m[2]));
                    if (!isset($links[$rel])) {
                        $links[$rel] = [];
                    }
                    $links[$rel][] = trim($m[1]);
                }
            }
        }

        return $links;
    }

    /** @return array<int, string> */
    public function getLink(string $rel): array
    {
        $links = $this->getLinks();
        $rel = strtolower($rel);

        return isset($links[$rel]) ? $links[$rel] : [];
    }

    /**
     * Retry-After 头，统一换算成「还要等几秒」。
     *
     * 这个头有两种合法写法：秒数，或者 HTTP 日期。CA 两种都用过。
     */
    public function getRetryAfter(): ?int
    {
        $value = $this->getHeader('retry-after');
        if ($value === null || trim($value) === '') {
            return null;
        }

        $value = trim($value);
        if (ctype_digit($value)) {
            return (int) $value;
        }

        $timestamp = strtotime($value);
        if ($timestamp === false) {
            return null;
        }

        $delta = $timestamp - time();

        return $delta > 0 ? $delta : 0;
    }
}
