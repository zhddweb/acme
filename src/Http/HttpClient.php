<?php

declare(strict_types=1);

namespace Mci\Acme\Http;

use Mci\Acme\Exception\HttpException;
use Mci\Acme\Http\Transport\CurlTransport;
use Mci\Acme\Http\Transport\StreamTransport;
use Mci\Acme\Http\Transport\TransportInterface;
use Mci\Acme\Util\Json;
use Mci\Acme\Util\Logger;

/**
 * HTTP 客户端：重试、重定向、超时、代理、日志都在这一层。
 *
 * 传输层只管「把这个请求发出去」，策略全在这里，好处是 curl 与 stream
 * 两套实现不用各写一遍退避逻辑，测试时换成 MockTransport 也能覆盖到策略代码。
 */
class HttpClient
{
    const VERSION = '1.0.0';

    /** @var TransportInterface */
    private $transport;

    /** @var Logger */
    private $logger;

    /** @var int 网络层失败时的重试次数（含首次） */
    private $retries = 3;

    /** @var int 首次重试前等待的毫秒数，之后指数退避 */
    private $retryDelayMs = 500;

    /** @var int 最多跟随几次重定向 */
    private $maxRedirects = 5;

    /** @var int */
    private $connectTimeout = 20;

    /** @var int */
    private $timeout = 60;

    /** @var bool */
    private $verifyPeer = true;

    /** @var string|null */
    private $caFile;

    /** @var string|null */
    private $proxy;

    /** @var string */
    private $userAgent;

    /** @var callable|null 重试前的等待函数，测试里替换掉就不用真的 sleep */
    private $sleeper;

    public function __construct(?TransportInterface $transport = null, ?Logger $logger = null)
    {
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->transport = $transport !== null ? $transport : self::detectTransport();
        $this->userAgent = sprintf(
            'mci-acme/%s (+https://github.com/likun-mci/acme) PHP/%s',
            self::VERSION,
            PHP_VERSION
        );

        // 代理常用的三个环境变量，acme.sh 也认这几个，行为对齐
        foreach (['HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy'] as $name) {
            $value = getenv($name);
            if (\is_string($value) && $value !== '') {
                $this->proxy = $value;
                break;
            }
        }
    }

    /**
     * 挑一个能用的传输层，curl 优先。
     *
     * 两个都不可用时立刻抛：与其等到第一次请求时才炸，不如在构造阶段
     * 给一句能照着做的提示。
     */
    public static function detectTransport(): TransportInterface
    {
        $curl = new CurlTransport();
        if ($curl->isAvailable()) {
            return $curl;
        }

        $stream = new StreamTransport();
        if ($stream->isAvailable()) {
            return $stream;
        }

        throw new HttpException(
            '当前 PHP 既没有 curl 扩展，allow_url_fopen 也是关闭的，无法发起 HTTP 请求。'
            . '请启用其中之一（推荐 curl）。'
        );
    }

    public function getTransport(): TransportInterface
    {
        return $this->transport;
    }

    public function setTransport(TransportInterface $transport): void
    {
        $this->transport = $transport;
    }

    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
    }

    public function setRetries(int $retries): void
    {
        $this->retries = max(1, $retries);
    }

    public function setRetryDelay(int $milliseconds): void
    {
        $this->retryDelayMs = max(0, $milliseconds);
    }

    public function setTimeouts(int $connectTimeout, int $timeout): void
    {
        $this->connectTimeout = $connectTimeout;
        $this->timeout = $timeout;
    }

    public function setVerifyPeer(bool $verify): void
    {
        $this->verifyPeer = $verify;
    }

    public function setCaFile(?string $caFile): void
    {
        $this->caFile = $caFile;
    }

    public function setProxy(?string $proxy): void
    {
        $this->proxy = $proxy;
    }

    public function setUserAgent(string $userAgent): void
    {
        $this->userAgent = $userAgent;
    }

    /** 测试里换掉，避免真的 sleep 拖慢用例 */
    public function setSleeper(?callable $sleeper): void
    {
        $this->sleeper = $sleeper;
    }

    /**
     * @param array<string, string> $headers
     */
    public function get(string $url, array $headers = []): Response
    {
        return $this->request('GET', $url, null, $headers);
    }

    /**
     * @param array<string, string> $headers
     */
    public function head(string $url, array $headers = []): Response
    {
        return $this->request('HEAD', $url, null, $headers);
    }

    /**
     * @param array<string, string> $headers
     */
    public function post(string $url, ?string $body, array $headers = []): Response
    {
        return $this->request('POST', $url, $body, $headers);
    }

    /**
     * POST 一个 JSON。DNS 提供商的 API 基本都是这个形状。
     *
     * @param mixed $payload
     * @param array<string, string> $headers
     */
    public function postJson(string $url, $payload, array $headers = []): Response
    {
        $headers['Content-Type'] = 'application/json';

        return $this->request('POST', $url, Json::encode($payload), $headers);
    }

    /**
     * POST 一个表单。
     *
     * @param array<string, string|int> $fields
     * @param array<string, string> $headers
     */
    public function postForm(string $url, array $fields, array $headers = []): Response
    {
        $headers['Content-Type'] = 'application/x-www-form-urlencoded';

        return $this->request('POST', $url, http_build_query($fields, '', '&', PHP_QUERY_RFC3986), $headers);
    }

    /**
     * 发请求，带重试与重定向。
     *
     * @param array<string, string> $headers
     */
    public function request(string $method, string $url, ?string $body = null, array $headers = []): Response
    {
        $request = $this->buildRequest($method, $url, $body, $headers);

        $lastError = null;
        for ($attempt = 1; $attempt <= $this->retries; ++$attempt) {
            try {
                $response = $this->sendFollowingRedirects($request);

                // 5xx 大多是 CA 那边的临时抖动，重试有意义；4xx 是我们自己的问题，
                // 重试只会白白撞速率限制，所以直接返回让上层去解析 problem document
                if ($response->isServerError() && $attempt < $this->retries) {
                    $this->logger->debug(sprintf(
                        '%s %s 返回 %d，第 %d/%d 次重试',
                        $method,
                        $url,
                        $response->getStatus(),
                        $attempt,
                        $this->retries
                    ));
                    $this->waitBeforeRetry($attempt, $response->getRetryAfter());
                    continue;
                }

                return $response;
            } catch (HttpException $e) {
                $lastError = $e;
                if ($attempt >= $this->retries) {
                    break;
                }
                $this->logger->debug(sprintf(
                    '%s %s 出错（%s），第 %d/%d 次重试',
                    $method,
                    $url,
                    $e->getMessage(),
                    $attempt,
                    $this->retries
                ));
                $this->waitBeforeRetry($attempt, null);
            }
        }

        if ($lastError !== null) {
            throw $lastError;
        }

        // 循环只可能因为 5xx 用尽重试而走到这里，此时最后一次的响应要返回给上层
        return $this->sendFollowingRedirects($request);
    }

    /**
     * @param array<string, string> $headers
     */
    public function buildRequest(string $method, string $url, ?string $body, array $headers): Request
    {
        if (!isset($headers['User-Agent'])) {
            $headers['User-Agent'] = $this->userAgent;
        }
        if (!isset($headers['Accept'])) {
            $headers['Accept'] = '*/*';
        }

        $request = new Request($method, $url, $headers, $body);
        $request->setTimeouts($this->connectTimeout, $this->timeout);
        $request->setVerifyPeer($this->verifyPeer);
        $request->setCaFile($this->caFile);
        $request->setProxy($this->proxy);

        return $request;
    }

    private function sendFollowingRedirects(Request $request): Response
    {
        $current = $request;

        for ($hop = 0; $hop <= $this->maxRedirects; ++$hop) {
            $this->logger->debug(sprintf('-> %s %s', $current->getMethod(), $current->getUrl()));
            $response = $this->transport->send($current);
            $this->logger->debug(sprintf('<- %d (%d 字节)', $response->getStatus(), \strlen($response->getBody())));

            if (!$response->isRedirect()) {
                return $response;
            }

            $location = $response->getLocation();
            if ($location === null || $location === '') {
                // 3xx 但没给 Location，没法继续，把响应交给上层判断
                return $response;
            }

            $target = $this->resolveUrl($current->getUrl(), $location);

            // ACME 的 POST-as-GET 被重定向时不能把 JWS body 原样重发——
            // 那个签名里带着原 URL，换个地址必然验签失败。303 与 301/302 一律降级成 GET，
            // 307/308 语义上要求保持方法，但 ACME 服务端不会用它们，遇到就报错更安全
            $status = $response->getStatus();
            if ($status === 307 || $status === 308) {
                if ($current->getMethod() === 'POST') {
                    throw new HttpException(sprintf(
                        '%s 返回了 %d 重定向，但 ACME 的 POST 请求带签名不能重放到 %s',
                        $current->getUrl(),
                        $status,
                        $target
                    ));
                }
                $current = $current->withUrl($target);
            } else {
                $current = $current->withUrl($target)->withMethod('GET')->withBody(null);
            }
        }

        throw new HttpException(sprintf('请求 %s 时重定向超过 %d 次', $request->getUrl(), $this->maxRedirects));
    }

    /** 把 Location 里可能出现的相对地址补全成绝对地址 */
    public function resolveUrl(string $base, string $location): string
    {
        if (preg_match('#^https?://#i', $location) === 1) {
            return $location;
        }

        $parts = parse_url($base);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return $location;
        }

        $origin = $parts['scheme'] . '://' . $parts['host'];
        if (isset($parts['port'])) {
            $origin .= ':' . $parts['port'];
        }

        if (str_starts_with($location, '/')) {
            return $origin . $location;
        }

        $path = isset($parts['path']) ? $parts['path'] : '/';
        $dir = substr($path, 0, (int) strrpos($path, '/') + 1);

        return $origin . $dir . $location;
    }

    private function waitBeforeRetry(int $attempt, ?int $retryAfter): void
    {
        // 服务端明确说了等多久就听它的，但别让一个离谱的值把进程挂死
        $ms = $retryAfter !== null
            ? min($retryAfter, 60) * 1000
            : $this->retryDelayMs * (1 << ($attempt - 1));

        if ($this->sleeper !== null) {
            \call_user_func($this->sleeper, $ms);

            return;
        }

        if ($ms > 0) {
            usleep($ms * 1000);
        }
    }
}
