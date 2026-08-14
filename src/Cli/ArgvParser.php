<?php

declare(strict_types=1);

namespace Mci\Acme\Cli;

use Mci\Acme\Exception\ConfigException;

/**
 * 命令行参数解析。
 *
 * 支持的写法：
 *
 *     --key value      --key=value      --flag
 *     -d value         -d=value         -f
 *
 * 有意不依赖 getopt()：它不支持同一个选项重复出现（`-d a.com -d b.com`
 * 只会拿到最后一个），而多域名恰恰是最常用的写法。
 *
 * 别名表让 acme.sh 的参数名直接可用——迁移过来的脚本不用改。
 */
class ArgvParser
{
    /** 短名 => 长名 */
    const ALIASES = [
        'd' => 'domain',
        'w' => 'webroot',
        'k' => 'keylength',
        'm' => 'email',
        'f' => 'force',
        'h' => 'help',
        'v' => 'version',
        // acme.sh 的别名
        'server' => 'ca',
        'accountemail' => 'email',
        'domain' => 'domain',
        'dnssleep' => 'dns-sleep',
        'renew-hook' => 'deploy-hook',
        'keypath' => 'key-file',
        'certpath' => 'cert-file',
        'capath' => 'ca-file',
        'fullchainpath' => 'fullchain-file',
    ];

    /** @var array<string, array<int, string>> 选项名 => 值列表 */
    private $options = [];

    /** @var array<int, string> 位置参数 */
    private $arguments = [];

    /** @var string 第一个位置参数，也就是子命令名 */
    private $command = '';

    /**
     * @param array<int, string> $argv 不含脚本名
     */
    public function __construct(array $argv)
    {
        $this->parse($argv);
    }

    /**
     * @param array<int, string> $argv
     */
    private function parse(array $argv): void
    {
        $count = \count($argv);

        for ($i = 0; $i < $count; ++$i) {
            $token = $argv[$i];

            if ($token === '--') {
                // 之后的一律当位置参数
                for ($j = $i + 1; $j < $count; ++$j) {
                    $this->arguments[] = $argv[$j];
                }
                break;
            }

            if (str_starts_with($token, '--')) {
                $name = substr($token, 2);
            } elseif (str_starts_with($token, '-') && $token !== '-') {
                $name = substr($token, 1);
            } else {
                $this->arguments[] = $token;
                continue;
            }

            // --key=value 形式
            $inlineValue = null;
            $equals = strpos($name, '=');
            if ($equals !== false) {
                $inlineValue = substr($name, $equals + 1);
                $name = substr($name, 0, $equals);
            }

            $name = $this->normalize($name);

            if ($inlineValue !== null) {
                $this->push($name, $inlineValue);
                continue;
            }

            // 下一个 token 不是选项就当它是值；否则当成布尔开关。
            // 负数值（--days -1）会被误判成选项，但本库没有接受负数的选项，
            // 真需要时用 --days=-1 写法
            if ($i + 1 < $count && !str_starts_with($argv[$i + 1], '-')) {
                $this->push($name, $argv[$i + 1]);
                ++$i;
                continue;
            }

            $this->push($name, '');
        }

        if ($this->arguments !== []) {
            $this->command = $this->arguments[0];
        }
    }

    private function normalize(string $name): string
    {
        $name = strtolower(str_replace('_', '-', $name));

        return isset(self::ALIASES[$name]) ? self::ALIASES[$name] : $name;
    }

    private function push(string $name, string $value): void
    {
        if (!isset($this->options[$name])) {
            $this->options[$name] = [];
        }

        $this->options[$name][] = $value;
    }

    public function getCommand(): string
    {
        return $this->command;
    }

    /** @return array<int, string> */
    public function getArguments(): array
    {
        return $this->arguments;
    }

    public function getArgument(int $index, ?string $default = null): ?string
    {
        return isset($this->arguments[$index]) ? $this->arguments[$index] : $default;
    }

    public function has(string $name): bool
    {
        return isset($this->options[$this->normalize($name)]);
    }

    /**
     * 取单值选项。多次给了同一个选项时取最后一次——
     * 这符合「后面的覆盖前面的」的直觉。
     */
    public function get(string $name, ?string $default = null): ?string
    {
        $key = $this->normalize($name);

        if (!isset($this->options[$key]) || $this->options[$key] === []) {
            return $default;
        }

        $values = $this->options[$key];
        $last = $values[\count($values) - 1];

        return $last !== '' ? $last : $default;
    }

    /**
     * 取多值选项，比如重复的 -d。
     *
     * @return array<int, string>
     */
    public function getAll(string $name): array
    {
        $key = $this->normalize($name);

        if (!isset($this->options[$key])) {
            return [];
        }

        $out = [];
        foreach ($this->options[$key] as $value) {
            if ($value === '') {
                continue;
            }
            // 允许用逗号一次给多个：-d a.com,b.com
            foreach (explode(',', $value) as $item) {
                $item = trim($item);
                if ($item !== '') {
                    $out[] = $item;
                }
            }
        }

        return $out;
    }

    public function getInt(string $name, int $default): int
    {
        $value = $this->get($name);

        return $value !== null && $value !== '' ? (int) $value : $default;
    }

    /** 布尔开关：给了就是 true，没给就是 false */
    public function getFlag(string $name): bool
    {
        return $this->has($name);
    }

    public function requireOption(string $name, string $hint = ''): string
    {
        $value = $this->get($name);

        if ($value === null || $value === '') {
            throw new ConfigException(sprintf(
                '缺少必填参数 --%s%s',
                $name,
                $hint !== '' ? '。' . $hint : ''
            ));
        }

        return $value;
    }

    /** @return array<string, array<int, string>> */
    public function all(): array
    {
        return $this->options;
    }
}
