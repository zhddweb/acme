<?php

declare(strict_types=1);

namespace Mci\Acme\Notify\Hook;

use Mci\Acme\Http\HttpClient;
use Mci\Acme\Notify\NotifierInterface;
use Mci\Acme\Util\Logger;

/**
 * Telegram Bot 通知。
 *
 * 找 @BotFather 建一个 bot 拿到 token，再把 bot 拉进群/私聊，
 * 用 getUpdates 查到 chat_id。
 */
class TelegramNotifier implements NotifierInterface
{
    /** @var string */
    private $token;

    /** @var string */
    private $chatId;

    /** @var HttpClient */
    private $http;

    /** @var Logger */
    private $logger;

    public function __construct(string $token, string $chatId, ?HttpClient $http = null, ?Logger $logger = null)
    {
        $this->token = $token;
        $this->chatId = $chatId;
        $this->http = $http !== null ? $http : new HttpClient();
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function getName(): string
    {
        return 'Telegram';
    }

    public function send(string $subject, string $body, bool $success = true): bool
    {
        try {
            $response = $this->http->postJson(
                sprintf('https://api.telegram.org/bot%s/sendMessage', $this->token),
                [
                    'chat_id' => $this->chatId,
                    'text' => sprintf("%s %s\n\n%s", $success ? '✅' : '❌', $subject, $body),
                    // 不用 Markdown/HTML 解析模式：证书信息里可能有下划线、
                    // 星号这类字符，会被当成格式标记导致整条消息发送失败
                    'disable_web_page_preview' => true,
                ]
            );

            if (!$response->isSuccess()) {
                $this->logger->warning(sprintf(
                    'Telegram 通知失败：%s',
                    substr($response->getBody(), 0, 200)
                ));

                return false;
            }

            return true;
        } catch (\Throwable $e) {
            $this->logger->warning(sprintf('Telegram 通知失败：%s', $e->getMessage()));

            return false;
        }
    }
}
