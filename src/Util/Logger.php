<?php

declare(strict_types=1);

namespace PhpAcme\Util;

/**
 * 极简日志器。
 *
 * 故意不依赖 psr/log：本库要能在「composer 都跑不起来」的机器上直接解压使用，
 * 多一个依赖就多一分装不上的风险。宿主项目想接自己的 logger，
 * 用 setHandler() 把每条日志转出去即可。
 */
class Logger
{
    const LEVEL_DEBUG = 10;
    const LEVEL_INFO = 20;
    const LEVEL_WARNING = 30;
    const LEVEL_ERROR = 40;
    const LEVEL_SILENT = 100;

    /** @var int */
    private $level;

    /** @var resource|null 输出流，null 表示不写流（只走 handler） */
    private $stream;

    /** @var callable|null */
    private $handler;

    /** @var bool 终端支持颜色时才上色，重定向到文件就不上，免得日志里全是转义序列 */
    private $colors;

    /** @var array<int, array{0: int, 1: string}> 记下所有日志，供测试与通知钩子引用 */
    private $records = [];

    /**
     * @param resource|null $stream
     */
    public function __construct(int $level = self::LEVEL_INFO, $stream = null, ?bool $colors = null)
    {
        $this->level = $level;
        $this->stream = $stream;
        $this->colors = $colors !== null ? $colors : Platform::supportsColor($stream);
    }

    public static function silent(): self
    {
        return new self(self::LEVEL_SILENT, null, false);
    }

    public function setLevel(int $level): void
    {
        $this->level = $level;
    }

    public function getLevel(): int
    {
        return $this->level;
    }

    /** 把每条日志同时转给外部回调，签名是 function (int $level, string $message): void */
    public function setHandler(?callable $handler): void
    {
        $this->handler = $handler;
    }

    public function debug(string $message): void
    {
        $this->log(self::LEVEL_DEBUG, $message);
    }

    public function info(string $message): void
    {
        $this->log(self::LEVEL_INFO, $message);
    }

    public function warning(string $message): void
    {
        $this->log(self::LEVEL_WARNING, $message);
    }

    public function error(string $message): void
    {
        $this->log(self::LEVEL_ERROR, $message);
    }

    /** 不带前缀直接输出，用于 CLI 里给用户看的正文（域名列表、证书路径等） */
    public function write(string $message): void
    {
        $this->records[] = [self::LEVEL_INFO, $message];
        if ($this->handler !== null) {
            \call_user_func($this->handler, self::LEVEL_INFO, $message);
        }
        if ($this->stream !== null && $this->level < self::LEVEL_SILENT) {
            fwrite($this->stream, $message . "\n");
        }
    }

    public function log(int $level, string $message): void
    {
        $this->records[] = [$level, $message];

        if ($this->handler !== null) {
            \call_user_func($this->handler, $level, $message);
        }

        if ($level < $this->level || $this->stream === null) {
            return;
        }

        fwrite($this->stream, $this->format($level, $message) . "\n");
    }

    /** @return array<int, array{0: int, 1: string}> */
    public function getRecords(): array
    {
        return $this->records;
    }

    /** 取最近 $count 条日志文本，通知钩子拿它当正文 */
    public function getRecentMessages(int $count = 20): array
    {
        $slice = \array_slice($this->records, -$count);
        $out = [];
        foreach ($slice as $record) {
            $out[] = $record[1];
        }

        return $out;
    }

    private function format(int $level, string $message): string
    {
        $time = date('Y-m-d H:i:s');

        switch ($level) {
            case self::LEVEL_DEBUG:
                $label = 'DEBUG';
                $color = '0;90';
                break;
            case self::LEVEL_WARNING:
                $label = 'WARN ';
                $color = '0;33';
                break;
            case self::LEVEL_ERROR:
                $label = 'ERROR';
                $color = '0;31';
                break;
            default:
                $label = 'INFO ';
                $color = '0;32';
                break;
        }

        $prefix = sprintf('[%s] %s', $time, $label);
        if ($this->colors) {
            $prefix = sprintf("\033[%sm%s\033[0m", $color, $prefix);
        }

        return $prefix . ' ' . $message;
    }
}
