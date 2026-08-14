<?php

declare(strict_types=1);

namespace PhpAcme\Notify\Hook;

use PhpAcme\Http\HttpClient;
use PhpAcme\Notify\NotifierInterface;
use PhpAcme\Util\Logger;

/**
 * 钉钉群机器人。
 *
 * 群设置里添加「自定义机器人」，拿到 webhook 地址。
 * 安全设置有三种，本类支持其中两种：
 *
 * - **加签**：给 secret，按 `时间戳\n密钥` 做 HMAC-SHA256 再 base64 + urlencode；
 * - **关键词**：不需要 secret，但消息里必须含有设定的关键词
 *   （所以标题默认带上「证书」两个字，多数人会用它当关键词）。
 *
 * IP 白名单那种不需要客户端做任何事。
 */
class DingTalkNotifier implements NotifierInterface
{
    /** @var string */
    private $webhook;

    /** @var string|null 加签密钥 */
    private $secret;

    /** @var HttpClient */
    private $http;

    /** @var Logger */
    private $logger;

    public function __construct(
        string $webhook,
        ?string $secret = null,
        ?HttpClient $http = null,
        ?Logger $logger = null
    ) {
        $this->webhook = $webhook;
        $this->secret = $secret;
        $this->http = $http !== null ? $http : new HttpClient();
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function getName(): string
    {
        return '钉钉';
    }

    public function send(string $subject, string $body, bool $success = true): bool
    {
        try {
            $url = $this->signUrl();

            $response = $this->http->postJson($url, [
                'msgtype' => 'text',
                'text' => [
                    'content' => sprintf("%s %s\n\n%s", $success ? '✅' : '❌', $subject, $body),
                ],
            ]);

            $data = $response->tryJson();
            // 钉钉的错误也是 HTTP 200，要看 errcode
            if ($data !== null && isset($data['errcode']) && (int) $data['errcode'] !== 0) {
                $this->logger->warning(sprintf(
                    '钉钉通知被拒绝：%s（若用的是关键词模式，确认消息里含有设定的关键词）',
                    isset($data['errmsg']) ? (string) $data['errmsg'] : '未知错误'
                ));

                return false;
            }

            return $response->isSuccess();
        } catch (\Throwable $e) {
            $this->logger->warning(sprintf('钉钉通知失败：%s', $e->getMessage()));

            return false;
        }
    }

    private function signUrl(): string
    {
        if ($this->secret === null || $this->secret === '') {
            return $this->webhook;
        }

        // 钉钉要的是毫秒时间戳
        $timestamp = (string) (int) (microtime(true) * 1000);
        $stringToSign = $timestamp . "\n" . $this->secret;
        $signature = base64_encode(hash_hmac('sha256', $stringToSign, $this->secret, true));

        return $this->webhook
            . (str_contains($this->webhook, '?') ? '&' : '?')
            . http_build_query(['timestamp' => $timestamp, 'sign' => $signature]);
    }
}
