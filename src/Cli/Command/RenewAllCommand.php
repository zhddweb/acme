<?php

declare(strict_types=1);

namespace Mci\Acme\Cli\Command;

use Mci\Acme\Acme;
use Mci\Acme\Cli\ArgvParser;
use Mci\Acme\Cli\CommandInterface;
use Mci\Acme\Util\Logger;

/**
 * 续期全部证书。cron 里就跑这个。
 */
class RenewAllCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['renew-all', 'renewAll', 'cron-renew'];
    }

    public function getSummary(): string
    {
        return '检查并续期所有到期的证书（cron 用这个）';
    }

    public function getUsage(): string
    {
        return implode("\n", [
            '用法：mci-acme renew-all [选项]',
            '',
            '选项：',
            '  -f, --force        强制续期全部证书（会撞速率限制，慎用）',
            '      --log <文件>   把日志追加到文件',
            '',
            '逐张检查本机所有证书，到了续期窗口的才续。',
            '单张失败不影响其他证书，最后统一汇报。',
            '',
            '放进 cron（每天凌晨 3 点 27 分跑一次，错开整点避开 CA 的高峰）：',
            '  27 3 * * * /usr/bin/php /path/to/mci-acme renew-all --log /var/log/mci-acme.log',
        ]);
    }

    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int
    {
        $outcomes = $acme->renewAll($args->getFlag('force'));

        if ($outcomes === []) {
            $logger->write('本机还没有任何证书。');

            return 0;
        }

        $renewed = 0;
        $skipped = 0;
        $failed = 0;

        foreach ($outcomes as $outcome) {
            $label = $outcome['domain'] . ($outcome['ecc'] ? '（ECC）' : '');

            if ($outcome['error'] !== '') {
                ++$failed;
                $logger->write(sprintf('  ✗ %s：%s', $label, $outcome['error']));
                continue;
            }

            $result = $outcome['result'];
            if ($result !== null && $result->isIssued()) {
                ++$renewed;
                $certificate = $result->getCertificate();
                $logger->write(sprintf(
                    '  ✓ %s 已续期，有效期至 %s',
                    $label,
                    $certificate !== null ? gmdate('Y-m-d', $certificate->getNotAfter()) : '未知'
                ));
                continue;
            }

            ++$skipped;
        }

        $logger->write('');
        $logger->write(sprintf('共 %d 张：续期 %d，跳过 %d，失败 %d', \count($outcomes), $renewed, $skipped, $failed));

        // 有失败就返回非 0，cron 的 MAILTO 才会把这次输出发出来
        return $failed > 0 ? 1 : 0;
    }
}
