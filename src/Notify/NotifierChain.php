<?php

declare(strict_types=1);

namespace PhpAcme\Notify;

use PhpAcme\Util\Logger;

/**
 * 把多个通知渠道串起来，逐个发。
 *
 * 一个渠道挂了不影响别的——通知的意义就在于「至少有一条能送到」，
 * 所以这里对每个渠道单独兜底。
 */
class NotifierChain implements NotifierInterface
{
    /** @var array<int, NotifierInterface> */
    private $notifiers = [];

    /** @var Logger */
    private $logger;

    /**
     * @param array<int, NotifierInterface> $notifiers
     */
    public function __construct(array $notifiers = [], ?Logger $logger = null)
    {
        foreach ($notifiers as $notifier) {
            $this->add($notifier);
        }

        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function add(NotifierInterface $notifier): self
    {
        $this->notifiers[] = $notifier;

        return $this;
    }

    public function isEmpty(): bool
    {
        return $this->notifiers === [];
    }

    public function getName(): string
    {
        $names = [];
        foreach ($this->notifiers as $notifier) {
            $names[] = $notifier->getName();
        }

        return $names === [] ? '（无通知渠道）' : implode(' + ', $names);
    }

    public function send(string $subject, string $body, bool $success = true): bool
    {
        $anySuccess = false;

        foreach ($this->notifiers as $notifier) {
            try {
                if ($notifier->send($subject, $body, $success)) {
                    $anySuccess = true;
                } else {
                    $this->logger->debug(sprintf('%s 渠道发送失败', $notifier->getName()));
                }
            } catch (\Throwable $e) {
                $this->logger->debug(sprintf('%s 渠道抛异常：%s', $notifier->getName(), $e->getMessage()));
            }
        }

        return $anySuccess;
    }
}
