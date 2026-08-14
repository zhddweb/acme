<?php

declare(strict_types=1);

namespace PhpAcme\Storage;

use PhpAcme\Util\Filesystem;

/**
 * `KEY='value'` 形式的配置文件读写。
 *
 * 格式是照抄 acme.sh 的——它的 .conf 文件本质是一段 shell 变量赋值，
 * 靠 source 读进来。本库不执行任何外部命令，所以自己解析，但**格式保持兼容**：
 * 已经在用 acme.sh 的机器可以直接把 ~/.acme.sh 指过来，反过来也一样。
 *
 * 只支持最朴素的一行一个赋值，不支持续行、命令替换、变量展开——
 * 那些既是安全隐患（配置文件里能藏 `$(rm -rf /)`），acme.sh 自己也不会写出来。
 */
class ConfigFile
{
    /** @var string */
    private $path;

    /** @var Filesystem */
    private $filesystem;

    /** @var array<string, string> */
    private $values = [];

    /** @var bool 是否已经从磁盘读过 */
    private $loaded = false;

    public function __construct(string $path, ?Filesystem $filesystem = null)
    {
        $this->path = $path;
        $this->filesystem = $filesystem !== null ? $filesystem : new Filesystem();
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function exists(): bool
    {
        return $this->filesystem->isFile($this->path);
    }

    public function load(): self
    {
        $this->values = [];
        $this->loaded = true;

        $content = $this->filesystem->readIfExists($this->path);
        if ($content === null) {
            return $this;
        }

        foreach (self::parse($content) as $key => $value) {
            $this->values[$key] = $value;
        }

        return $this;
    }

    /**
     * @return array<string, string>
     */
    public static function parse(string $content): array
    {
        $values = [];

        foreach (preg_split('/\r\n|\r|\n/', $content) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $pos = strpos($line, '=');
            if ($pos === false || $pos === 0) {
                continue;
            }

            $key = rtrim(substr($line, 0, $pos));
            $value = ltrim(substr($line, $pos + 1));

            // 变量名合法性：acme.sh 写出来的都是 Le_Xxx / DOMAIN_Xxx 这类，
            // 不匹配的行八成是注释残留或用户手改坏了，跳过而不是硬解
            if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $key) !== 1) {
                continue;
            }

            $values[$key] = self::unquote($value);
        }

        return $values;
    }

    private static function unquote(string $value): string
    {
        $length = \strlen($value);
        if ($length >= 2) {
            $first = $value[0];
            $last = $value[$length - 1];
            if (($first === "'" && $last === "'") || ($first === '"' && $last === '"')) {
                $inner = substr($value, 1, -1);

                if ($first === '"') {
                    return str_replace('\\"', '"', $inner);
                }

                // 单引号串里的单引号只能写成 '\'' —— 结束引号、转义的单引号、
                // 重新开始引号。save() 就是这么写的，读回来必须还原，
                // 否则 DNS API 密钥里带撇号的用户会拿到一段坏掉的凭据
                return str_replace("'\\''", "'", $inner);
            }
        }

        return $value;
    }

    public function get(string $key, ?string $default = null): ?string
    {
        if (!$this->loaded) {
            $this->load();
        }

        return isset($this->values[$key]) ? $this->values[$key] : $default;
    }

    public function getInt(string $key, int $default = 0): int
    {
        $value = $this->get($key);

        return $value !== null && $value !== '' ? (int) $value : $default;
    }

    public function getBool(string $key, bool $default = false): bool
    {
        $value = $this->get($key);
        if ($value === null || $value === '') {
            return $default;
        }

        return \in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true);
    }

    public function has(string $key): bool
    {
        if (!$this->loaded) {
            $this->load();
        }

        return isset($this->values[$key]);
    }

    /**
     * @param string|int|bool|null $value null 表示删掉这一项
     */
    public function set(string $key, $value): self
    {
        if (!$this->loaded) {
            $this->load();
        }

        if ($value === null) {
            unset($this->values[$key]);

            return $this;
        }

        if (\is_bool($value)) {
            $value = $value ? '1' : '';
        }

        $this->values[$key] = (string) $value;

        return $this;
    }

    /**
     * @param array<string, string|int|bool|null> $values
     */
    public function setMany(array $values): self
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value);
        }

        return $this;
    }

    /** @return array<string, string> */
    public function all(): array
    {
        if (!$this->loaded) {
            $this->load();
        }

        return $this->values;
    }

    public function save(): void
    {
        if (!$this->loaded) {
            $this->load();
        }

        $lines = ['# php-acme 自动生成，格式与 acme.sh 的 .conf 兼容，可以手工编辑'];

        // 排序保证同样的配置每次写出来字节相同——否则每次续期都会让
        // 版本控制里的配置文件产生无意义的 diff
        $values = $this->values;
        ksort($values, SORT_STRING);

        foreach ($values as $key => $value) {
            $lines[] = $key . '=' . self::quote($value);
        }

        // 配置里存着 DNS API 的密钥，权限必须收紧
        $this->filesystem->write($this->path, implode("\n", $lines) . "\n", Filesystem::MODE_PRIVATE);
    }

    /**
     * 值一律用单引号包，里面的单引号按 shell 的办法转义。
     *
     * `'\''` 这个写法是：结束单引号、一个转义的单引号、重新开始单引号。
     * 看着别扭，但这是 shell 里唯一能在单引号串中表示单引号的办法，
     * acme.sh source 我们写的文件时才不会炸。
     */
    private static function quote(string $value): string
    {
        return "'" . str_replace("'", "'\\''", $value) . "'";
    }

    public function delete(): bool
    {
        $this->values = [];

        return $this->filesystem->delete($this->path);
    }
}
