<?php

declare(strict_types=1);

namespace Mci\Acme\Notify\Hook;

use Mci\Acme\Http\HttpClient;
use Mci\Acme\Notify\NotifierInterface;
use Mci\Acme\Util\Logger;

/**
 * 通用 Webhook：把通知 POST 成 JSON。
 *
 * 对接自建的告警系统、n8n、Zapier 之类。字段固定为
 * subject / body / success / timestamp，对端自己解析。
 */
class WebhookNotifier implements NotifierInterface
{
    /** @var string */
    private $url;

    /** @var array<string, string> */
    private $headers;

    /** @var HttpClient */
    private $http;

    /** @var Logger */
    private $logger;

    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        string $url,
        array $headers = [],
        ?HttpClient $http = null,
        ?Logger $logger = null
    ) {
        $this->url = $url;
        $this->headers = $headers;
        $this->http = $http !== null ? $http : new HttpClient();
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function getName(): string
    {
        return 'Webhook';
    }

    public function send(string $subject, string $body, bool $success = true): bool
    {
        try {
            $response = $this->http->postJson($this->url, [
                'subject' => $subject,
                'body' => $body,
                'success' => $success,
                'timestamp' => gmdate('c'),
            ], $this->headers);

            if (!$response->isSuccess()) {
                $this->logger->warning(sprintf('Webhook 通知返回 HTTP %d', $response->getStatus()));

                return false;
            }

            return true;
        } catch (\Throwable $e) {
            // 通知失败绝不能影响主流程，所以这里连 Throwable 都吃掉
            $this->logger->warning(sprintf('Webhook 通知失败：%s', $e->getMessage()));

            return false;
        }
    }
}
