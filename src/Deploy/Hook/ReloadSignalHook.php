<?php

declare(strict_types=1);

namespace PhpAcme\Deploy\Hook;

use PhpAcme\Deploy\DeployHookInterface;
use PhpAcme\Exception\DeployException;
use PhpAcme\Service\IssueResult;
use PhpAcme\Util\Filesystem;
use PhpAcme\Util\Logger;

/**
 * 给服务进程发信号让它重新加载证书。
 *
 * 这是本库对 acme.sh `--reloadcmd "systemctl reload nginx"` 的替代方案。
 * acme.sh 直接跑 shell 命令，本库不能——目标环境禁用了 exec/proc_open。
 *
 * 好在 reload 本来就是靠信号实现的：`nginx -s reload` 干的事就是
 * 读 pid 文件然后 `kill -HUP`，systemctl reload 也只是转发信号。
 * 我们直接用 posix_kill() 发同样的信号，效果一样，还少了一层 shell。
 *
 * 各家服务的 reload 信号：
 *
 * | 服务 | 信号 | 说明 |
 * |---|---|---|
 * | nginx | SIGHUP (1) | 平滑重载配置，旧 worker 处理完请求再退出 |
 * | Apache | SIGUSR1 (10) | graceful restart |
 * | HAProxy | SIGUSR2 (12) | 配合 master-worker 模式 |
 * | PHP-FPM | SIGUSR2 (12) | 平滑重载 |
 * | Postfix | SIGHUP (1) | |
 * | Dovecot | SIGHUP (1) | |
 *
 * 要求 ext-posix。没有它就退回「写触发文件」的方式（见 TouchFileHook）。
 */
class ReloadSignalHook implements DeployHookInterface
{
    /**
     * 信号编号。
     *
     * 有意写成字面量而不是 SIGHUP 那些常量：**它们由 ext-pcntl 定义，
     * 而这个类只需要 ext-posix**。只装了 posix 的机器上引用 SIGHUP
     * 会在类加载时就 fatal，那比功能不可用还糟。
     * 下面的编号是 Linux/BSD 在 x86 与 ARM 上的标准值。
     */
    const SIGNAL_HUP = 1;
    const SIGNAL_USR1 = 10;
    const SIGNAL_USR2 = 12;

    /** 常见服务的默认 pid 文件位置与重载信号 */
    const PRESETS = [
        'nginx' => ['pid' => '/run/nginx.pid', 'signal' => self::SIGNAL_HUP, 'label' => 'nginx'],
        'apache' => ['pid' => '/run/apache2/apache2.pid', 'signal' => self::SIGNAL_USR1, 'label' => 'Apache'],
        'httpd' => ['pid' => '/run/httpd/httpd.pid', 'signal' => self::SIGNAL_USR1, 'label' => 'Apache (httpd)'],
        'haproxy' => ['pid' => '/run/haproxy.pid', 'signal' => self::SIGNAL_USR2, 'label' => 'HAProxy'],
        'php-fpm' => ['pid' => '/run/php-fpm.pid', 'signal' => self::SIGNAL_USR2, 'label' => 'PHP-FPM'],
        'postfix' => ['pid' => '/var/spool/postfix/pid/master.pid', 'signal' => self::SIGNAL_HUP, 'label' => 'Postfix'],
        'dovecot' => ['pid' => '/run/dovecot/master.pid', 'signal' => self::SIGNAL_HUP, 'label' => 'Dovecot'],
    ];

    /** @var string */
    private $pidFile;

    /** @var int */
    private $signal;

    /** @var string */
    private $label;

    /** @var Filesystem */
    private $filesystem;

    /** @var Logger */
    private $logger;

    public function __construct(
        string $pidFile,
        int $signal = self::SIGNAL_HUP,
        string $label = '服务',
        ?Logger $logger = null,
        ?Filesystem $filesystem = null
    ) {
        $this->pidFile = $pidFile;
        $this->signal = $signal;
        $this->label = $label;
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->filesystem = $filesystem !== null ? $filesystem : new Filesystem();
    }

    /**
     * 按服务名建一个，pid 文件用预设值。
     */
    public static function forService(string $service, ?string $pidFile = null, ?Logger $logger = null): self
    {
        $key = strtolower(trim($service));

        if (!isset(self::PRESETS[$key])) {
            throw new DeployException(sprintf(
                '不认识的服务「%s」。已知：%s。'
                . '也可以直接指定 pid 文件与信号',
                $service,
                implode(', ', array_keys(self::PRESETS))
            ));
        }

        $preset = self::PRESETS[$key];

        return new self(
            $pidFile !== null && $pidFile !== '' ? $pidFile : $preset['pid'],
            $preset['signal'],
            $preset['label'],
            $logger
        );
    }

    public function getName(): string
    {
        return sprintf('重载 %s', $this->label);
    }

    public function deploy(IssueResult $result): void
    {
        if (!\function_exists('posix_kill')) {
            throw new DeployException(
                '发送重载信号需要 posix 扩展（ext-posix），当前 PHP 没有安装。'
                . '可以改用「写触发文件」的方式，由外部的 systemd path unit 或 cron 去执行 reload'
            );
        }

        $pid = $this->readPid();

        // 先用信号 0 探一下进程在不在。信号 0 不会真的送出去，
        // 只做权限与存在性检查——直接发 HUP 的话，pid 文件过期时
        // 我们会把信号发给一个恰好复用了这个 pid 的无关进程
        if (!@posix_kill($pid, 0)) {
            throw new DeployException(sprintf(
                '%s 的进程 %d 不存在（pid 文件：%s）。'
                . '可能服务没在跑，或者 pid 文件是上次崩溃留下的',
                $this->label,
                $pid,
                $this->pidFile
            ));
        }

        if (!@posix_kill($pid, $this->signal)) {
            throw new DeployException(sprintf(
                '向 %s（进程 %d）发送信号 %d 失败，通常是权限不足——'
                . '给 root 跑的服务发信号需要 root 权限',
                $this->label,
                $pid,
                $this->signal
            ));
        }

        $this->logger->info(sprintf('已向 %s（进程 %d）发送重载信号', $this->label, $pid));
    }

    private function readPid(): int
    {
        $content = $this->filesystem->readIfExists($this->pidFile);

        if ($content === null) {
            throw new DeployException(sprintf(
                '读不到 pid 文件 %s。确认 %s 正在运行，以及 pid 文件的实际位置'
                . '（不同发行版可能放在 /run、/var/run 或 /usr/local/nginx/logs 下）',
                $this->pidFile,
                $this->label
            ));
        }

        $pid = (int) trim($content);
        if ($pid <= 0) {
            throw new DeployException(sprintf('pid 文件 %s 的内容不是有效的进程号', $this->pidFile));
        }

        return $pid;
    }
}
