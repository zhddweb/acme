<?php

declare(strict_types=1);

/**
 * polyfill 的正确性验证。
 *
 * 难点在于：开发机跑的是 PHP 8，那里这些函数是内置的，function_exists()
 * 守卫会直接跳过 polyfill——真正会执行的那份代码在这些环境里一次都不会被调用，
 * 写错了也看不出来。
 *
 * 所以这里把 polyfill 源码整体改名后 eval 一份出来，逐个用例与原生实现对拍。
 * 跑在 PHP 8 上时比的是「polyfill 与原生行为是否一致」；跑在 7.2 上时
 * 原生不存在，比的是「它自己是否自洽」。
 */

require __DIR__ . '/lib/bootstrap.php';

use PhpAcme\Tests\Runner;

$t = new Runner('polyfill');

const POLYFILLED = ['str_contains', 'str_starts_with', 'str_ends_with', 'array_key_first', 'array_key_last', 'is_countable'];

$source = file_get_contents(__DIR__ . '/../src/polyfill.php');
if ($source === false) {
    $t->fail('读不到 src/polyfill.php');
    exit($t->summary());
}

$renamed = str_replace(POLYFILLED, array_map(static function (string $name): string {
    return 'pa_polyfill_' . $name;
}, POLYFILLED), $source);

// declare(strict_types=1) 只能出现在文件首行，eval 进来会 fatal。
// 剥掉它不影响本测试：下面的用例都不依赖严格模式的类型检查
$renamed = str_replace('declare(strict_types=1);', '', $renamed);
eval('?>' . $renamed);

$t->group('全部定义成功');

foreach (POLYFILLED as $name) {
    $t->ok(\function_exists('pa_polyfill_' . $name), sprintf('%s() 应当被定义', $name));
}

$t->group('str_contains 与原生对拍');

$containsCases = [
    ['hello world', 'world'],
    ['hello world', 'xyz'],
    ['hello', ''],
    ['', ''],
    ['', 'a'],
    ['aaa', 'aa'],
    ['中文测试', '文测'],
    ["\x00binary", "\x00b"],
];

foreach ($containsCases as $case) {
    $mine = pa_polyfill_str_contains($case[0], $case[1]);
    $native = str_contains($case[0], $case[1]);
    $t->equals($native, $mine, sprintf('str_contains(%s, %s)', var_export($case[0], true), var_export($case[1], true)));
}

$t->group('str_starts_with / str_ends_with 与原生对拍');

$affixCases = [
    ['hello', 'he'],
    ['hello', 'lo'],
    ['hello', 'hello'],
    ['hello', 'hello!'],
    ['hello', ''],
    ['', ''],
    ['', 'x'],
    ['中文', '中'],
];

foreach ($affixCases as $case) {
    $t->equals(
        str_starts_with($case[0], $case[1]),
        pa_polyfill_str_starts_with($case[0], $case[1]),
        sprintf('str_starts_with(%s, %s)', var_export($case[0], true), var_export($case[1], true))
    );
    $t->equals(
        str_ends_with($case[0], $case[1]),
        pa_polyfill_str_ends_with($case[0], $case[1]),
        sprintf('str_ends_with(%s, %s)', var_export($case[0], true), var_export($case[1], true))
    );
}

$t->group('array_key_first / array_key_last 与原生对拍');

$arrayCases = [
    ['a' => 1, 'b' => 2, 'c' => 3],
    [10 => 'x', 5 => 'y'],
    ['only'],
    [],
];

foreach ($arrayCases as $index => $array) {
    $t->equals(array_key_first($array), pa_polyfill_array_key_first($array), sprintf('array_key_first 用例 #%d', $index));
    $t->equals(array_key_last($array), pa_polyfill_array_key_last($array), sprintf('array_key_last 用例 #%d', $index));
}

$t->group('array_key_last 不能动到调用方的数组指针');

$array = ['a' => 1, 'b' => 2, 'c' => 3];
// 先把指针推到中间
next($array);
$before = key($array);
pa_polyfill_array_key_last($array);
$t->equals($before, key($array), '按值传参，调用方的内部指针不受影响');

$t->group('is_countable 与原生对拍');

$countableCases = [[], [1, 2], new ArrayObject([1]), 'string', 42, null];

foreach ($countableCases as $index => $value) {
    $t->equals(is_countable($value), pa_polyfill_is_countable($value), sprintf('is_countable 用例 #%d', $index));
}

exit($t->summary());
