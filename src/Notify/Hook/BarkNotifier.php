<?php

declare(strict_types=1);

namespace Mci\Acme\Notify\Hook;

use Mci\Acme\Http\HttpClient;
use Mci\Acme\Notify\NotifierInterface;
use Mci\Acme\Util\Logger;

/**
 * Bark（iOS 推送）。
 *
 * 装 Bark app 后拿到形如 https://api.day.app/<key> 的地址。
 * 自建服务端也支持，把 server 换掉即可。
 */
class BarkNotifier implements NotifierInterface
{
    /** @var string */
    private $key;

    /** @var string */
    private $server;

    /** @var HttpClient */
    private $http;

    /** @var Logger */
    private $logger;

    public function __construct(
        string $key,
        string $server = 'https://api.day.app',
        ?HttpClient $http = null,
        ?Logger $logger = null
    ) {
        $this->key = $key;
        $this->server = rtrim($server, '/');
        $this->http = $http !== null ? $http : new HttpClient();
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function getName(): string
    {
        return 'Bark';
    }

    public function send(string $subject, string $body, bool $success = true): bool
    {
        try {
            $response = $this->http->postJson(sprintf('%s/%s', $this->server, $this->key), [
                'title' => $subject,
                'body' => $body,
                // 失败的通知用 timeSensitive，能穿透专注模式
                'level' => $success ? 'active' : 'timeSensitive',
                'group' => 'mci-acme',
            ]);

            return $response->isSuccess();
        } catch (\Throwable $e) {
            $this->logger->warning(sprintf('Bark 通知失败：%s', $e->getMessage()));

            return false;
        }
    }
}
