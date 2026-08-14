<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Http01;

use Mci\Acme\Challenge\AbstractSolver;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Protocol\Challenge;
use Mci\Acme\Util\Logger;

/**
 * 手动模式：把该做的事打印出来，让用户自己去做。
 *
 * 用在没法自动化的场合——网站在别人管的服务器上、DNS 在没有 API 的
 * 老牌解析商那里。签发流程会停在这里等确认。
 *
 * 手动模式**不能用于自动续期**：cron 跑到这里没人回车，只会卡住然后超时。
 * 所以签发成功后不写续期配置，用户下次得再手动跑一遍。
 */
class ManualSolver extends AbstractSolver
{
    /** @var string http-01 或 dns-01 */
    private $type;

    /** @var callable|null 等待用户确认的回调；null 表示只打印不等待 */
    private $confirm;

    public function __construct(string $type = 'http-01', ?Logger $logger = null, ?callable $confirm = null)
    {
        parent::__construct($logger);
        $this->type = $type;
        $this->confirm = $confirm;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function prepare(Challenge $challenge, KeyPair $accountKey): void
    {
        if ($this->type === 'dns-01') {
            $this->logger->write('');
            $this->logger->write(sprintf('请为 %s 添加一条 TXT 记录：', $challenge->getDomain()));
            $this->logger->write(sprintf('  记录名：%s', $challenge->getDnsRecordName()));
            $this->logger->write(sprintf('  记录值：%s', $challenge->getDnsValue($accountKey)));
            $this->logger->write('');
            $this->logger->write('添加后请等待解析生效（可用 dig TXT 查询确认）再继续。');
        } else {
            $this->logger->write('');
            $this->logger->write(sprintf('请在 %s 的网站根目录下创建文件：', $challenge->getDomain()));
            $this->logger->write(sprintf('  路径：%s', $challenge->getHttpPath()));
            $this->logger->write(sprintf('  内容：%s', $challenge->getKeyAuthorization($accountKey)));
            $this->logger->write('');
            $this->logger->write(sprintf('确保能用浏览器打开：%s', $challenge->getHttpUrl()));
        }

        if ($this->confirm !== null) {
            \call_user_func($this->confirm, $challenge);
        }
    }

    public function cleanup(Challenge $challenge, KeyPair $accountKey): void
    {
        if ($this->type === 'dns-01') {
            $this->logger->write(sprintf(
                '验证已结束，可以删掉 %s 的 TXT 记录了',
                $challenge->getDnsRecordName()
            ));

            return;
        }

        $this->logger->write(sprintf('验证已结束，可以删掉 %s 了', $challenge->getHttpPath()));
    }
}
