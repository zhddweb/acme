<?php

declare(strict_types=1);

/**
 * PHP 8.0 / 7.3 内置函数的向下兼容实现。
 *
 * 本库最低支持 PHP 7.2，但源码里大量使用 str_starts_with() 一类可读性更好的
 * 新函数。与其把几十处调用退化成 strncmp/substr 的老写法，不如在这里补齐
 * ——运行在 PHP 8 上时这些分支一次都不会进，零开销。
 *
 * 每个函数都用 function_exists() 守卫：宿主项目可能已经引入了
 * symfony/polyfill-php80 之类的实现，重复定义会直接 fatal error。
 *
 * 注意：这些函数必须定义在全局命名空间。源码里的调用都是未限定形式
 * （str_contains(...) 而非 \str_contains(...)），PHP 会先在当前命名空间
 * 查找、找不到再回退到全局，因此能正确命中这里的定义。
 */

if (!\function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool
    {
        // PHP 8 之前 strpos() 遇到空 needle 会返回 false 并告警，
        // 而 PHP 8 的语义是「任何字符串都包含空字符串」，这里对齐后者
        return $needle === '' || strpos($haystack, $needle) !== false;
    }
}

if (!\function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool
    {
        return strncmp($haystack, $needle, \strlen($needle)) === 0;
    }
}

if (!\function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool
    {
        // substr($s, -0) 等价于 substr($s, 0)，会返回整个字符串，
        // 空 needle 必须单独短路，否则非空字符串会判成 false
        if ($needle === '') {
            return true;
        }

        return substr($haystack, -\strlen($needle)) === $needle;
    }
}

if (!\function_exists('array_key_first')) {
    /**
     * @param array $array
     * @return int|string|null
     */
    function array_key_first(array $array)
    {
        foreach ($array as $key => $unused) {
            return $key;
        }

        return null;
    }
}

if (!\function_exists('array_key_last')) {
    /**
     * @param array $array
     * @return int|string|null
     */
    function array_key_last(array $array)
    {
        if ($array === []) {
            return null;
        }

        // end()/key() 会移动内部指针，传值进来的是副本，不影响调用方
        end($array);

        return key($array);
    }
}

if (!\function_exists('is_countable')) {
    /**
     * @param mixed $value
     */
    function is_countable($value): bool
    {
        return \is_array($value) || $value instanceof \Countable;
    }
}
