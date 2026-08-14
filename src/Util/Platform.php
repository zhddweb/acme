<?php

declare(strict_types=1);

namespace Mci\Acme\Util;

/**
 * 运行环境探测。
 *
 * 本库的目标环境正是「什么都可能被禁用」的主机，所以每项能力都得先问一遍
 * 再用，不能想当然。
 */
final class Platform
{
    /** @var array<string, bool> 探测结果缓存，disable_functions 运行期不会变 */
    private static $cache = [];

    public static function isWindows(): bool
    {
        return \DIRECTORY_SEPARATOR === '\\';
    }

    public static function hasCurl(): bool
    {
        return self::remember('curl', static function (): bool {
            return \extension_loaded('curl') && \function_exists('curl_init');
        });
    }

    public static function hasSockets(): bool
    {
        return self::remember('sockets', static function (): bool {
            // standalone 模式其实用的是 stream_socket_server（属于标准库不是 sockets 扩展），
            // 但 open_basedir/disable_functions 常把它一起禁掉，所以还是要探
            return \function_exists('stream_socket_server');
        });
    }

    public static function hasStreamHttp(): bool
    {
        return self::remember('stream_http', static function (): bool {
            return \function_exists('fopen')
                && filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN);
        });
    }

    public static function hasIntl(): bool
    {
        return self::remember('intl', static function (): bool {
            return \function_exists('idn_to_ascii');
        });
    }

    public static function hasDnsGet(): bool
    {
        return self::remember('dns_get_record', static function (): bool {
            return \function_exists('dns_get_record');
        });
    }

    /** 是否跑在命令行下 */
    public static function isCli(): bool
    {
        return \PHP_SAPI === 'cli' || \PHP_SAPI === 'phpdbg';
    }

    /**
     * 输出流是否该上色。
     *
     * @param resource|null $stream
     */
    public static function supportsColor($stream = null): bool
    {
        if (!self::isCli()) {
            return false;
        }

        // NO_COLOR 是跨工具的事实标准，用户设了就必须听
        if (getenv('NO_COLOR') !== false) {
            return false;
        }

        if ($stream === null) {
            return false;
        }

        if (\function_exists('stream_isatty')) {
            return @stream_isatty($stream);
        }

        if (\function_exists('posix_isatty')) {
            return @posix_isatty($stream);
        }

        return false;
    }

    /**
     * 当前用户的家目录，取不到时退回系统临时目录。
     *
     * 跑在 web sapi 下时 HOME 常常是空的，不能直接信。
     */
    public static function homeDirectory(): string
    {
        $home = getenv('MCI_ACME_HOME');
        if (\is_string($home) && $home !== '') {
            return rtrim($home, '/\\');
        }

        $home = getenv('HOME');
        if (\is_string($home) && $home !== '' && is_dir($home)) {
            return rtrim($home, '/\\');
        }

        if (self::isWindows()) {
            $drive = getenv('HOMEDRIVE');
            $path = getenv('HOMEPATH');
            if (\is_string($drive) && \is_string($path) && $drive !== '' && $path !== '') {
                return rtrim($drive . $path, '/\\');
            }
            $profile = getenv('USERPROFILE');
            if (\is_string($profile) && $profile !== '') {
                return rtrim($profile, '/\\');
            }
        }

        return rtrim(sys_get_temp_dir(), '/\\');
    }

    /** 供测试重置探测缓存 */
    public static function resetCache(): void
    {
        self::$cache = [];
    }

    private static function remember(string $key, callable $probe): bool
    {
        if (!isset(self::$cache[$key])) {
            self::$cache[$key] = (bool) \call_user_func($probe);
        }

        return self::$cache[$key];
    }
}
