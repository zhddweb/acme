<?php

declare(strict_types=1);

namespace PhpAcme\Cli;

use PhpAcme\Acme;
use PhpAcme\Exception\AcmeException;
use PhpAcme\Exception\ProtocolException;
use PhpAcme\Storage\Paths;
use PhpAcme\Util\Logger;

/**
 * CLI 入口：解析参数、挑命令、统一处理错误与退出码。
 *
 * 命令有两种写法，都支持：
 *
 *     php-acme issue -d example.com -w /var/www      # 子命令风格
 *     php-acme --issue -d example.com -w /var/www    # acme.sh 风格
 *
 * 后者是为了让现有的 acme.sh 调用脚本改个程序名就能跑。
 */
class Application
{
    const EXIT_SUCCESS = 0;
    const EXIT_FAILURE = 1;
    /** 参数错误，与运行时失败区分开，便于脚本判断 */
    const EXIT_USAGE = 2;

    /** @var array<int, CommandInterface> */
    private $commands = [];

    /** @var resource */
    private $stdout;

    /** @var resource */
    private $stderr;

    /**
     * @param resource|null $stdout
     * @param resource|null $stderr
     */
    public function __construct($stdout = null, $stderr = null)
    {
        $this->stdout = $stdout !== null ? $stdout : STDOUT;
        $this->stderr = $stderr !== null ? $stderr : STDERR;

        $this->register(new Command\IssueCommand());
        $this->register(new Command\RenewCommand());
        $this->register(new Command\RenewAllCommand());
        $this->register(new Command\ListCommand());
        $this->register(new Command\InfoCommand());
        $this->register(new Command\InstallCertCommand());
        $this->register(new Command\RevokeCommand());
        $this->register(new Command\RemoveCommand());
        $this->register(new Command\AccountCommand());
        $this->register(new Command\CronCommand());
        $this->register(new Command\ToolsCommand());
    }

    public function register(CommandInterface $command): void
    {
        $this->commands[] = $command;
    }

    /**
     * @param array<int, string> $argv 完整的 $argv，含脚本名
     */
    public function run(array $argv): int
    {
        $args = new ArgvParser(\array_slice($argv, 1));

        if ($args->getFlag('version')) {
            $this->writeLine(sprintf('php-acme %s（PHP %s）', Acme::VERSION, PHP_VERSION));

            return self::EXIT_SUCCESS;
        }

        $command = $this->resolveCommand($args);

        if ($command === null) {
            $this->printHelp($args->getArgument(1));

            // 主动求助（help / --help）是正常操作，返回 0；
            // 什么命令都没给则是用法错误，返回 2——脚本靠这个区分
            // 「用户想看帮助」和「命令拼错了」
            $wantsHelp = $args->getFlag('help') || $args->getCommand() === 'help';

            return $wantsHelp ? self::EXIT_SUCCESS : self::EXIT_USAGE;
        }

        // help 作为选项时打印该命令的详细用法，而不是执行它
        if ($args->getFlag('help')) {
            $this->writeLine($command->getUsage());

            return self::EXIT_SUCCESS;
        }

        $logger = $this->buildLogger($args);

        try {
            $acme = new Acme($this->resolveBaseDir($args), $logger);

            return $command->execute($args, $acme, $logger);
        } catch (ProtocolException $e) {
            $this->writeError($e->getMessage());

            // 撞速率限制时给一句能照着做的建议——这是新手最常遇到的坎
            if ($e->isRateLimited()) {
                $this->writeError(
                    '提示：撞到了 CA 的速率限制。Let\'s Encrypt 对同一组域名每周最多签 5 张证书，'
                    . '调试阶段请用 --ca letsencrypt_test（staging 环境）。'
                );
            }

            return self::EXIT_FAILURE;
        } catch (AcmeException $e) {
            $this->writeError($e->getMessage());

            return self::EXIT_FAILURE;
        } catch (\Throwable $e) {
            // 非预期异常：把类型和位置一起打出来，用户报 issue 时能用上
            $this->writeError(sprintf(
                '发生了未预期的错误：%s: %s（%s:%d）',
                get_class($e),
                $e->getMessage(),
                $e->getFile(),
                $e->getLine()
            ));

            if ($args->getFlag('debug')) {
                $this->writeError($e->getTraceAsString());
            }

            return self::EXIT_FAILURE;
        }
    }

    private function resolveCommand(ArgvParser $args): ?CommandInterface
    {
        $name = $args->getCommand();

        foreach ($this->commands as $command) {
            foreach ($command->getNames() as $candidate) {
                // 子命令风格
                if ($name !== '' && $name === $candidate) {
                    return $command;
                }
                // acme.sh 风格：--issue 会被解析成名为 issue 的选项
                if ($args->getFlag($candidate)) {
                    return $command;
                }
            }
        }

        return null;
    }

    private function buildLogger(ArgvParser $args): Logger
    {
        $level = Logger::LEVEL_INFO;
        if ($args->getFlag('debug')) {
            $level = Logger::LEVEL_DEBUG;
        } elseif ($args->getFlag('quiet')) {
            $level = Logger::LEVEL_ERROR;
        }

        $logger = new Logger($level, $this->stdout);

        // --log <文件> 时把日志同时写一份到文件，cron 场景排错全靠它
        $logFile = $args->get('log');
        if ($logFile !== null && $logFile !== '') {
            $logger->setHandler(static function (int $recordLevel, string $message) use ($logFile): void {
                @file_put_contents(
                    $logFile,
                    sprintf('[%s] %s%s', date('Y-m-d H:i:s'), $message, "\n"),
                    FILE_APPEND | LOCK_EX
                );
            });
        }

        return $logger;
    }

    private function resolveBaseDir(ArgvParser $args): ?string
    {
        $home = $args->get('home');

        return $home !== null && $home !== '' ? $home : null;
    }

    private function printHelp(?string $topic): void
    {
        if ($topic !== null && $topic !== '') {
            foreach ($this->commands as $command) {
                if (\in_array($topic, $command->getNames(), true)) {
                    $this->writeLine($command->getUsage());

                    return;
                }
            }

            $this->writeLine(sprintf('没有名为「%s」的命令。', $topic));
        }

        $lines = [
            sprintf('php-acme %s —— 用原生 PHP 实现的 ACME 客户端（acme.sh 的功能对等实现）', Acme::VERSION),
            '',
            '用法：',
            '  php-acme <命令> [选项]',
            '  php-acme --<命令> [选项]        # 兼容 acme.sh 的写法',
            '',
            '命令：',
        ];

        foreach ($this->commands as $command) {
            $names = $command->getNames();
            $lines[] = sprintf('  %-18s %s', $names[0], $command->getSummary());
        }

        $lines[] = '';
        $lines[] = '通用选项：';
        $lines[] = '  --home <目录>       配置与证书的存放目录（默认 ' . Paths::defaultBaseDir() . '）';
        $lines[] = '  --debug             打印调试日志，含每一次 HTTP 请求';
        $lines[] = '  --quiet             只输出错误';
        $lines[] = '  --log <文件>        把日志追加写到文件，cron 里建议加上';
        $lines[] = '  --help              查看某个命令的详细用法：php-acme help issue';
        $lines[] = '  --version           显示版本';
        $lines[] = '';
        $lines[] = '常见用法：';
        $lines[] = '  # 用网站根目录验证，签一张双域名证书';
        $lines[] = '  php-acme issue -d example.com -d www.example.com -w /var/www/html';
        $lines[] = '';
        $lines[] = '  # 用 Cloudflare DNS 验证，签通配符证书';
        $lines[] = '  export CF_Token=你的令牌';
        $lines[] = '  php-acme issue -d example.com -d "*.example.com" --dns dns_cf';
        $lines[] = '';
        $lines[] = '  # 装到 nginx 用的位置，并给 nginx 发重载信号';
        $lines[] = '  php-acme install-cert -d example.com \\';
        $lines[] = '      --key-file /etc/nginx/ssl/example.com.key \\';
        $lines[] = '      --fullchain-file /etc/nginx/ssl/example.com.crt \\';
        $lines[] = '      --reload-service nginx';
        $lines[] = '';
        $lines[] = '  # 续期全部证书（放进 cron 每天跑一次）';
        $lines[] = '  php-acme renew-all --log /var/log/php-acme.log';

        $this->writeLine(implode("\n", $lines));
    }

    private function writeLine(string $text): void
    {
        fwrite($this->stdout, $text . "\n");
    }

    private function writeError(string $text): void
    {
        fwrite($this->stderr, '错误：' . $text . "\n");
    }
}
