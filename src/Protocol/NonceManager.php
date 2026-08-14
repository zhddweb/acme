<?php

declare(strict_types=1);

namespace PhpAcme\Protocol;

use PhpAcme\Exception\ProtocolException;
use PhpAcme\Http\HttpClient;
use PhpAcme\Http\Response;

/**
 * nonce 池。
 *
 * ACME 用 nonce 防重放：每个 POST 的 protected header 里都要带一个服务端发的
 * nonce，用过即废。服务端在**每个**响应里都会用 Replay-Nonce 头再发一个新的，
 * 所以正常流程下只需要在最开始主动取一次，之后靠响应头续上——
 * 每次请求前都去 newNonce 拿一遍会让请求数翻倍，还更容易撞速率限制。
 *
 * 有意做成「一次只留一个」而不是队列：ACME 请求本来就必须串行发
 * （订单状态机不允许并发推进），囤着多个 nonce 只会增加过期的机会。
 */
class NonceManager
{
    /** @var HttpClient */
    private $http;

    /** @var string */
    private $newNonceUrl;

    /** @var string|null 手里那个还没用掉的 nonce */
    private $nonce;

    public function __construct(HttpClient $http, string $newNonceUrl)
    {
        $this->http = $http;
        $this->newNonceUrl = $newNonceUrl;
    }

    /**
     * 取一个 nonce 用。取走即从池里移除，不会被第二次用到。
     */
    public function take(): string
    {
        if ($this->nonce !== null) {
            $nonce = $this->nonce;
            $this->nonce = null;

            return $nonce;
        }

        return $this->fetch();
    }

    /**
     * 从响应头里收一个新 nonce。
     *
     * 每次请求回来都要调；服务端没给（有些 4xx 响应会漏）就保持空，
     * 下次 take() 自然会去主动拉。
     */
    public function collect(Response $response): void
    {
        $nonce = $response->getHeader('replay-nonce');
        if ($nonce !== null && $nonce !== '') {
            $this->nonce = $nonce;
        }
    }

    /** 遇到 badNonce 时清掉手里的，强制下次重新拉 */
    public function clear(): void
    {
        $this->nonce = null;
    }

    private function fetch(): string
    {
        // 规范要求 newNonce 支持 HEAD，且响应必须带 Replay-Nonce。
        // 用 HEAD 而不是 GET 是因为不需要响应体，省一次传输
        $response = $this->http->head($this->newNonceUrl);

        $nonce = $response->getHeader('replay-nonce');
        if ($nonce === null || $nonce === '') {
            // 有些 CDN 前置的 CA 会吞掉 HEAD 的响应头，退回 GET 再试一次
            $response = $this->http->get($this->newNonceUrl);
            $nonce = $response->getHeader('replay-nonce');
        }

        if ($nonce === null || $nonce === '') {
            throw new ProtocolException(sprintf(
                '%s 没有返回 Replay-Nonce 头（HTTP %d）。若中间有反向代理或 CDN，检查它是否过滤了响应头',
                $this->newNonceUrl,
                $response->getStatus()
            ));
        }

        return $nonce;
    }
}
