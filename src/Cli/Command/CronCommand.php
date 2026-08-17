<?php

declare(strict_types=1);

namespace Mci\Acme\Cli\Command;

use Mci\Acme\Acme;
use Mci\Acme\Cli\ArgvParser;
use Mci\Acme\Cli\CommandInterface;
use Mci\Acme\Util\Logger;

/**
 * 定时续期的帮助命令。
 *
 * **不会去改 crontab**——那需要执行外部命令，本库不做这件事。
 * 它做的是把该加的那一行打印出来，用户自己贴进去。
 * 顺带检查一下当前环境能不能跑得起来。
 */
class CronCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['cron', 'install-cronjob'];
    }

    public function getSummary(): string
    {
        return '生成定时续期的配置（crontab / systemd timer）';
    }

    public function getUsage(): string
    {
        return implode("\n", [
            '用法：mci-acme cron [--systemd] [--log <文件>]',
            '',
            '选项：',
            '  --systemd    输出 systemd timer 的配置而不是 crontab 行',
            '  --log <文件> 日志文件路径，默认 /var/log/mci-acme.log',
            '',
            '这个命令只负责**打印**该怎么配，不会去改你的 crontab——',
            '改 crontab 需要执行外部命令，而本库的设计前提就是不执行任何外部进程。',
            '把打印出来的内容自己贴进去即可。',
        ]);
    }

    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int
    {
        $binary = $this->resolveBinary();
        $php = PHP_BINARY !== '' ? PHP_BINARY : 'php';
        $logFile = (string) $args->get('log', '/var/log/mci-acme.log');
        $paths = $acme->getPaths();
        $home = $paths->getBaseDir();
        // 证书被挪到别处时（acme.sh 的 --cert-home / CERT_HOME），cron 里也得带上，
        // 否则定时任务找不到证书，只会安静地报一句「没有证书需要续期」
        $certHome = $paths->getCertHome() !== $home ? $paths->getCertHome() : null;

        if ($args->getFlag('systemd')) {
            $this->printSystemd($logger, $php, $binary, $logFile, $home, $certHome);
        } else {
            $this->printCrontab($logger, $php, $binary, $logFile, $home, $certHome);
        }

        $logger->write('');
        $this->printEnvironmentCheck($logger);

        return 0;
    }

    private function printCrontab(
        Logger $logger,
        string $php,
        string $binary,
        string $logFile,
        string $home,
        ?string $certHome
    ): void {
        // 分钟取一个非整点的随机值：所有人都在 0 分跑会给 CA 造成尖峰，
        // Let's Encrypt 明确建议错开
        $minute = random_int(0, 59);
        $hour = random_int(0, 5);

        $logger->write('把下面这行加进 crontab（crontab -e）：');
        $logger->write('');
        $logger->write(sprintf(
            '%d %d * * * MCI_ACME_CONFIG_HOME=%s %s%s %s renew-all --log %s',
            $minute,
            $hour,
            $home,
            $certHome !== null ? sprintf('CERT_HOME=%s ', $certHome) : '',
            $php,
            $binary,
            $logFile
        ));
        $logger->write('');
        $logger->write('说明：');
        $logger->write('  - 每天跑一次就够了。证书提前 30 天开始续，有充足的重试窗口。');
        $logger->write(sprintf('  - 时间是随机挑的（%d:%02d），避开整点能减轻 CA 的压力。', $hour, $minute));
        $logger->write('  - DNS 验证的证书还需要在 crontab 里带上对应的 API 凭据环境变量，');
        $logger->write('    或者确认签发时已经存进了 .conf（默认会存）。');
    }

    private function printSystemd(
        Logger $logger,
        string $php,
        string $binary,
        string $logFile,
        string $home,
        ?string $certHome
    ): void {
        $unit = [
            '[Unit]',
            'Description=mci-acme 证书续期',
            'After=network-online.target',
            '',
            '[Service]',
            'Type=oneshot',
            sprintf('Environment=MCI_ACME_CONFIG_HOME=%s', $home),
        ];

        if ($certHome !== null) {
            $unit[] = sprintf('Environment=CERT_HOME=%s', $certHome);
        }

        $unit[] = sprintf('ExecStart=%s %s renew-all --log %s', $php, $binary, $logFile);

        $logger->write('创建 /etc/systemd/system/mci-acme.service：');
        $logger->write('');
        $logger->write(implode("\n", $unit));
        $logger->write('');
        $logger->write('创建 /etc/systemd/system/mci-acme.timer：');
        $logger->write('');
        $logger->write(implode("\n", [
            '[Unit]',
            'Description=每天检查一次证书是否需要续期',
            '',
            '[Timer]',
            'OnCalendar=daily',
            // RandomizedDelaySec 是 systemd 版的「错开整点」
            'RandomizedDelaySec=6h',
            'Persistent=true',
            '',
            '[Install]',
            'WantedBy=timers.target',
        ]));
        $logger->write('');
        $logger->write('然后启用：systemctl enable --now mci-acme.timer');
    }

    private function printEnvironmentCheck(Logger $logger): void
    {
        $logger->write('环境检查：');

        $checks = [
            ['openssl 扩展', \extension_loaded('openssl')],
            ['curl 扩展（推荐）', \extension_loaded('curl')],
            ['posix 扩展（发重载信号用）', \function_exists('posix_kill')],
            ['stream_socket_server（standalone 模式用）', \function_exists('stream_socket_server')],
        ];

        foreach ($checks as $check) {
            $logger->write(sprintf('  %s %s', $check[1] ? '✓' : '✗', $check[0]));
        }

        if (!\extension_loaded('openssl')) {
            $logger->write('');
            $logger->write('⚠ 没有 openssl 扩展，本库无法工作。');
        }
    }

    private function resolveBinary(): string
    {
        // $_SERVER['SCRIPT_FILENAME'] 在 CLI 下就是脚本路径
        if (isset($_SERVER['SCRIPT_FILENAME']) && \is_string($_SERVER['SCRIPT_FILENAME'])) {
            $path = realpath($_SERVER['SCRIPT_FILENAME']);
            if ($path !== false) {
                return $path;
            }
        }

        return 'mci-acme';
    }
}
