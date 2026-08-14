<?php

declare(strict_types=1);

/**
 * 测试用的引导文件。
 *
 * 优先用 composer 的 autoload（能顺带验证 composer.json 里的 psr-4 配置对不对），
 * 没有就退回项目自带的 bootstrap.php。
 */

$vendorAutoload = __DIR__ . '/../../vendor/autoload.php';

if (is_file($vendorAutoload)) {
    require $vendorAutoload;
} else {
    require __DIR__ . '/../../bootstrap.php';
}

// 测试辅助类不走 composer 的 autoload-dev（没跑 composer install 时它不存在），
// 直接注册一个加载器
spl_autoload_register(static function (string $class): void {
    $prefix = 'Mci\Acme\\Tests\\';
    if (strncmp($prefix, $class, \strlen($prefix)) !== 0) {
        return;
    }

    $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, \strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

/**
 * 测试用的临时目录，每次跑都是干净的。
 */
function test_temp_dir(string $name): string
{
    $dir = sys_get_temp_dir() . '/mci-acme-test-' . $name . '-' . getmypid();

    if (is_dir($dir)) {
        test_remove_dir($dir);
    }

    mkdir($dir, 0700, true);

    // 进程结束时自动清掉，免得测试跑多了塞满 /tmp
    register_shutdown_function(static function () use ($dir): void {
        test_remove_dir($dir);
    });

    return $dir;
}

function test_remove_dir(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }

    $items = scandir($dir);
    if ($items === false) {
        return;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $dir . '/' . $item;
        if (is_dir($path)) {
            test_remove_dir($path);
        } else {
            @unlink($path);
        }
    }

    @rmdir($dir);
}
