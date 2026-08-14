<?php

declare(strict_types=1);

namespace Mci\Acme\Cli;

use Mci\Acme\Acme;
use Mci\Acme\Util\Logger;

/**
 * 一个 CLI 子命令。
 */
interface CommandInterface
{
    /**
     * 命令名与别名。
     *
     * 第一个是主名字（`issue`），其余是别名——acme.sh 的写法是
     * `--issue`，解析器会把它变成同名的布尔选项，Application 据此分发，
     * 所以两种写法都能用。
     *
     * @return array<int, string>
     */
    public function getNames(): array;

    /** 一行说明，出现在 help 列表里 */
    public function getSummary(): string;

    /** 详细用法，`mci-acme help <命令>` 时打印 */
    public function getUsage(): string;

    /**
     * 执行。返回进程退出码：0 成功，非 0 失败。
     */
    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int;
}
