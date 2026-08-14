<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Dns01\Provider;

use Mci\Acme\Challenge\Dns01\DnsProviderInterface;
use Mci\Acme\Util\Logger;

/**
 * 手动 DNS：把要加的记录打印出来，由用户自己去解析商后台操作。
 *
 * 用在没有 API 的解析商，或者不想把 API 密钥放到服务器上的场合。
 *
 * **不能用于自动续期**——cron 跑到这里没人去加记录，只会等到超时。
 * 用它签发时 CLI 会跳过续期配置的写入。
 */
class ManualDns implements DnsProviderInterface
{
    /** @var Logger */
    private $logger;

    /** @var callable|null 打印完等待用户确认的回调 */
    private $confirm;

    public function __construct(?Logger $logger = null, ?callable $confirm = null)
    {
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->confirm = $confirm;
    }

    public function getName(): string
    {
        return '手动 DNS';
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $this->logger->write('');
        $this->logger->write('请到你的 DNS 解析商后台添加以下 TXT 记录：');
        $this->logger->write(sprintf('  记录类型：TXT'));
        $this->logger->write(sprintf('  记录名称：%s', rtrim($fqdn, '.')));
        $this->logger->write(sprintf('  记录值　：%s', $value));
        $this->logger->write('');
        $this->logger->write(sprintf('可以用这条命令确认是否生效：dig +short TXT %s', rtrim($fqdn, '.')));
        $this->logger->write('');

        if ($this->confirm !== null) {
            \call_user_func($this->confirm, $fqdn, $value);
        }
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $this->logger->write(sprintf('验证已结束，可以删除 TXT 记录：%s', rtrim($fqdn, '.')));
    }
}
