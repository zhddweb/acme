<?php

declare(strict_types=1);

namespace PhpAcme\Util;

use PhpAcme\Exception\StorageException;

/**
 * 文件读写。
 *
 * 私钥落盘是这个库最敏感的操作，所以这里的写入一律走「临时文件 + rename」，
 * 并且在创建时就把权限收紧到 0600——先 file_put_contents 再 chmod 的话，
 * 中间那一瞬间文件是 0644 的，同机器上的其他用户读得到。
 */
class Filesystem
{
    /** 私钥、账户密钥的权限 */
    const MODE_PRIVATE = 0600;

    /** 证书、配置的权限 */
    const MODE_PUBLIC = 0644;

    /** 目录权限；0700 是因为里面躺着私钥 */
    const MODE_DIR = 0700;

    public function exists(string $path): bool
    {
        return file_exists($path);
    }

    public function isFile(string $path): bool
    {
        return is_file($path);
    }

    public function isDirectory(string $path): bool
    {
        return is_dir($path);
    }

    public function read(string $path): string
    {
        if (!is_file($path)) {
            throw new StorageException(sprintf('文件不存在：%s', $path));
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            throw new StorageException(sprintf('文件读取失败（权限不足？）：%s', $path));
        }

        return $content;
    }

    public function readIfExists(string $path): ?string
    {
        if (!is_file($path)) {
            return null;
        }

        $content = @file_get_contents($path);

        return $content === false ? null : $content;
    }

    /**
     * 原子写入。
     *
     * 同目录下先写临时文件再 rename：rename 在同一文件系统内是原子的，
     * 中途断电或进程被杀，看到的要么是旧内容要么是新内容，不会是半截。
     * 证书续期时这点很关键——nginx 可能正好在这一刻 reload。
     */
    public function write(string $path, string $content, int $mode = self::MODE_PUBLIC): void
    {
        $dir = \dirname($path);
        $this->ensureDirectory($dir);

        $tmp = @tempnam($dir, '.acme-tmp-');
        if ($tmp === false) {
            throw new StorageException(sprintf('无法在 %s 下创建临时文件，检查目录权限', $dir));
        }

        // tempnam() 建出来是 0600，公开文件要放宽；私有文件本来就该是 0600，
        // 这里显式设一遍，不依赖 tempnam 的默认值
        if (@chmod($tmp, $mode) === false) {
            @unlink($tmp);
            throw new StorageException(sprintf('无法设置文件权限：%s', $tmp));
        }

        if (@file_put_contents($tmp, $content) === false) {
            @unlink($tmp);
            throw new StorageException(sprintf('文件写入失败：%s', $path));
        }

        if (@rename($tmp, $path) === false) {
            @unlink($tmp);
            throw new StorageException(sprintf('文件替换失败：%s', $path));
        }

        // rename 会保留临时文件的权限，但目标文件原本存在时某些文件系统的行为不一致，
        // 补一次确保最终状态正确
        @chmod($path, $mode);
    }

    /** 写私钥专用，权限固定 0600 */
    public function writePrivate(string $path, string $content): void
    {
        $this->write($path, $content, self::MODE_PRIVATE);
    }

    public function append(string $path, string $content): void
    {
        $this->ensureDirectory(\dirname($path));
        if (@file_put_contents($path, $content, FILE_APPEND | LOCK_EX) === false) {
            throw new StorageException(sprintf('追加写入失败：%s', $path));
        }
    }

    public function ensureDirectory(string $dir, int $mode = self::MODE_DIR): void
    {
        if (is_dir($dir)) {
            return;
        }

        // 并发下另一个进程可能刚好也在建，mkdir 返回 false 但目录其实有了，
        // 所以失败后要再看一眼是不是已经存在
        if (!@mkdir($dir, $mode, true) && !is_dir($dir)) {
            throw new StorageException(sprintf('目录创建失败：%s', $dir));
        }
    }

    public function delete(string $path): bool
    {
        if (!file_exists($path)) {
            return false;
        }

        return @unlink($path);
    }

    /** 递归删除目录，用于 --remove 与测试清理 */
    public function removeDirectory(string $dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }

        $items = @scandir($dir);
        if ($items === false) {
            return false;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_dir($path) && !is_link($path)) {
                $this->removeDirectory($path);
            } else {
                @unlink($path);
            }
        }

        return @rmdir($dir);
    }

    /** @return array<int, string> 目录下的子目录名（不含 . 与 ..） */
    public function listDirectories(string $dir): array
    {
        if (!is_dir($dir)) {
            return [];
        }

        $items = @scandir($dir);
        if ($items === false) {
            return [];
        }

        $out = [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            if (is_dir($dir . '/' . $item)) {
                $out[] = $item;
            }
        }

        // scandir 的顺序依赖文件系统，排一下保证跨机器输出一致
        sort($out, SORT_STRING);

        return $out;
    }

    public function copy(string $from, string $to): void
    {
        $this->ensureDirectory(\dirname($to));
        if (@copy($from, $to) === false) {
            throw new StorageException(sprintf('文件复制失败：%s -> %s', $from, $to));
        }
    }

    /** 路径是否是绝对路径；Windows 下 C:\ 与 \\server\share 都算 */
    public function isAbsolute(string $path): bool
    {
        if ($path === '') {
            return false;
        }

        if ($path[0] === '/' || $path[0] === '\\') {
            return true;
        }

        return (bool) preg_match('#^[a-zA-Z]:[\\\\/]#', $path);
    }

    /** 归一化路径分隔符与多余的 ./ ../，不碰文件系统（路径可以不存在） */
    public function normalize(string $path): string
    {
        $path = str_replace('\\', '/', $path);
        $isAbsolute = str_starts_with($path, '/');

        $parts = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                if ($parts !== [] && end($parts) !== '..') {
                    array_pop($parts);
                    continue;
                }
                if ($isAbsolute) {
                    // 绝对路径的根之上没有上级，直接丢弃
                    continue;
                }
            }
            $parts[] = $segment;
        }

        return ($isAbsolute ? '/' : '') . implode('/', $parts);
    }
}
