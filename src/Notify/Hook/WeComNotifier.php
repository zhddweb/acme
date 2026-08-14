<?php

declare(strict_types=1);

namespace PhpAcme\Notify\Hook;

use PhpAcme\Http\HttpClient;
use PhpAcme\Notify\NotifierInterface;
use PhpAcme\Util\Logger;

/**
 * 企业微信群机器人。
 *
 * 群里添加「群机器人」拿到 webhook 地址即可，没有签名要求。
 */
class WeComNotifier implements NotifierInterface
{
    /** @var string */
    private $webhook;

    /** @var HttpClient */
    private $http;

    /** @var Logger */
    private $logger;

    public function __construct(string $webhook, ?HttpClient $http = null, ?Logger $logger = null)
    {
        $this->webhook = $webhook;
        $this->http = $http !== null ? $http : new HttpClient();
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function getName(): string
    {
        return '企业微信';
    }

    public function send(string $subject, string $body, bool $success = true): bool
    {
        try {
            $response = $this->http->postJson($this->webhook, [
                'msgtype' => 'markdown',
                'markdown' => [
                    'content' => sprintf(
                        "## %s\n> 状态：<font color=\"%s\">%s</font>\n\n%s",
                        $subject,
                        $success ? 'info' : 'warning',
                        $success ? '成功' : '失败',
                        $body
                    ),
                ],
            ]);

            $data = $response->tryJson();
            if ($data !== null && isset($data['errcode']) && (int) $data['errcode'] !== 0) {
                $this->logger->warning(sprintf(
                    '企业微信通知被拒绝：%s',
                    isset($data['errmsg']) ? (string) $data['errmsg'] : '未知错误'
                ));

                return false;
            }

            return $response->isSuccess();
        } catch (\Throwable $e) {
            $this->logger->warning(sprintf('企业微信通知失败：%s', $e->getMessage()));

            return false;
        }
    }
}
