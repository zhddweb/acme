<?php

declare(strict_types=1);

namespace Mci\Acme\Http\Transport;

use Mci\Acme\Exception\HttpException;
use Mci\Acme\Http\Request;
use Mci\Acme\Http\Response;

/**
 * 测试用传输层：不发网络请求，按预设规则返回响应。
 *
 * 放在 src/ 而不是 tests/ 是有意的——用户给自己写的 DNS provider
 * 补测试时也需要它，跟着 composer 装进 vendor 才用得上。
 *
 * 匹配规则按注册顺序逐条试，第一条命中的生效，所以要把特例写在通配前面。
 */
class MockTransport implements TransportInterface
{
    /** @var array<int, array{matcher: callable, handler: callable}> */
    private $rules = [];

    /** @var array<int, Request> 所有收到过的请求，供断言 */
    private $requests = [];

    /** @var callable|null 所有规则都没命中时的兜底 */
    private $fallback;

    public function isAvailable(): bool
    {
        return true;
    }

    public function getName(): string
    {
        return 'mock';
    }

    /**
     * 注册一条规则。
     *
     * @param callable $matcher function (Request $r): bool
     * @param callable|Response $handler function (Request $r): Response，或直接给一个 Response
     */
    public function on(callable $matcher, $handler): self
    {
        $this->rules[] = [
            'matcher' => $matcher,
            'handler' => $handler instanceof Response
                ? static function () use ($handler): Response {
                    return $handler;
                }
                : $handler,
        ];

        return $this;
    }

    /**
     * 按 方法 + URL 精确匹配注册。
     *
     * @param callable|Response $handler
     */
    public function onUrl(string $method, string $url, $handler): self
    {
        $method = strtoupper($method);

        return $this->on(
            static function (Request $request) use ($method, $url): bool {
                return $request->getMethod() === $method && $request->getUrl() === $url;
            },
            $handler
        );
    }

    /**
     * 按 URL 子串匹配注册，方便写「所有 /acme/authz/ 开头的请求」这类规则。
     *
     * @param callable|Response $handler
     */
    public function onUrlContains(string $needle, $handler): self
    {
        return $this->on(
            static function (Request $request) use ($needle): bool {
                return str_contains($request->getUrl(), $needle);
            },
            $handler
        );
    }

    public function setFallback(?callable $fallback): self
    {
        $this->fallback = $fallback;

        return $this;
    }

    public function send(Request $request): Response
    {
        $this->requests[] = $request;

        foreach ($this->rules as $rule) {
            if (\call_user_func($rule['matcher'], $request) === true) {
                $response = \call_user_func($rule['handler'], $request);
                if (!$response instanceof Response) {
                    throw new HttpException('MockTransport 的 handler 必须返回 Response');
                }

                return $response;
            }
        }

        if ($this->fallback !== null) {
            return \call_user_func($this->fallback, $request);
        }

        throw new HttpException(sprintf(
            'MockTransport 没有匹配 %s %s 的规则（已注册 %d 条）',
            $request->getMethod(),
            $request->getUrl(),
            \count($this->rules)
        ));
    }

    /** @return array<int, Request> */
    public function getRequests(): array
    {
        return $this->requests;
    }

    public function getLastRequest(): ?Request
    {
        return $this->requests === [] ? null : $this->requests[\count($this->requests) - 1];
    }

    public function countRequests(): int
    {
        return \count($this->requests);
    }

    /** @return array<int, Request> 发往某个 URL 的所有请求 */
    public function getRequestsTo(string $url): array
    {
        $out = [];
        foreach ($this->requests as $request) {
            if ($request->getUrl() === $url) {
                $out[] = $request;
            }
        }

        return $out;
    }

    public function reset(): void
    {
        $this->requests = [];
    }
}
