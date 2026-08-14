<?php

declare(strict_types=1);

namespace Mci\Acme\Notify\Hook;

use Mci\Acme\Notify\NotifierInterface;
use Mci\Acme\Util\Logger;

/**
 * 用 PHP 的 mail() 发邮件。
 *
 * 依赖服务器上配好了 sendmail/postfix。没配的话 mail() 会返回 false，
 * 或者更糟——返回 true 但邮件进了黑洞。所以这个渠道适合已经有邮件基础设施的
 * 环境；没有的话用 Webhook 或即时通讯类渠道更可靠。
 */
class MailNotifier implements NotifierInterface
{
    /** @var string */
    private $to;

    /** @var string|null */
    private $from;

    /** @var Logger */
    private $logger;

    public function __construct(string $to, ?string $from = null, ?Logger $logger = null)
    {
        $this->to = $to;
        $this->from = $from;
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function getName(): string
    {
        return '邮件';
    }

    public function send(string $subject, string $body, bool $success = true): bool
    {
        if (!\function_exists('mail')) {
            $this->logger->warning('mail() 函数不可用，邮件通知已跳过');

            return false;
        }

        // 标题里有中文时必须做 MIME 编码，否则大多数客户端显示乱码
        $encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';

        $headers = [
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
        ];

        if ($this->from !== null && $this->from !== '') {
            $headers[] = 'From: ' . $this->from;
        }

        $ok = @mail($this->to, $encodedSubject, $body, implode("\r\n", $headers));

        if (!$ok) {
            $this->logger->warning(sprintf('邮件发送失败（收件人 %s），检查服务器的 MTA 配置', $this->to));
        }

        return $ok;
    }
}
