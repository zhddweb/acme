<?php

declare(strict_types=1);

/**
 * 本库自身的 PSR-4 自动加载器。
 *
 * 用 composer 安装时走 vendor/autoload.php，这个文件用不上；但本库的典型使用场景
 * 就是「机器上跑不了 composer」——直接 git clone 或解压 zip 也必须能用，
 * 所以自带一份零依赖的加载器。
 */

// 必须在注册自动加载之前引入：polyfill 里是函数不是类，自动加载器管不到它，
// 而 src/ 下的类在被加载的瞬间就可能调用 str_starts_with()
require_once __DIR__ . '/src/polyfill.php';

spl_autoload_register(static function (string $class): void {
    $prefix = 'Mci\Acme\\';
    $baseDir = __DIR__ . '/src/';

    $len = \strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $relative) . '.php';

    if (is_file($file)) {
        require $file;
    }
});
