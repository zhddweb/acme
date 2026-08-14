<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use PhpAcme\Exception\ConfigException;
use PhpAcme\Tests\Runner;
use PhpAcme\Util\Domain;

$t = new Runner('域名处理');

$t->group('归一化');

$t->equals('example.com', Domain::normalize('  Example.COM  '), '去空白 + 转小写');
$t->equals('example.com', Domain::normalize('example.com.'), '去掉 DNS 的绝对域名尾点');
$t->equals('xn--fiq228c.com', Domain::normalize('中文.com'), '顺带做 IDN 转换');
$t->equals('', Domain::normalize('   '), '空白串归一成空串');

$t->group('通配符');

$t->ok(Domain::isWildcard('*.example.com'), '识别通配符');
$t->ok(!Domain::isWildcard('example.com'), '裸域不是通配符');
$t->equals('example.com', Domain::stripWildcard('*.example.com'), '去掉通配符前缀');
$t->equals('example.com', Domain::stripWildcard('example.com'), '裸域原样返回');

$t->group('校验');

foreach (['example.com', 'a.b.c.example.com', '*.example.com', 'xn--fiq228c.com', 'my-site.co.uk', '_dmarc.example.com'] as $valid) {
    $t->noThrow(static function () use ($valid): void {
        Domain::validate($valid);
    }, sprintf('%s 应当合法', $valid));
}

$invalidCases = [
    '' => '空域名',
    'nodot' => '没有点',
    '*.*.example.com' => '多级通配符',
    'ex*ample.com' => '通配符位置不对',
    'a..example.com' => '连续的点',
    'a b.example.com' => '含空格',
];

foreach ($invalidCases as $invalid => $why) {
    $t->throws(static function () use ($invalid): void {
        Domain::validate($invalid);
    }, ConfigException::class, sprintf('%s（%s）应当被拒', $invalid === '' ? '(空)' : $invalid, $why));
}

$t->throws(static function (): void {
    Domain::validate(str_repeat('a', 64) . '.example.com');
}, ConfigException::class, '单个标签超过 63 字节应当被拒');

$t->group('列表归一化');

$list = Domain::normalizeList(['Example.COM', 'www.example.com', 'EXAMPLE.com', '中文.com']);

$t->equals(3, \count($list), '大小写不同的同一域名应当去重');
$t->equals('example.com', $list[0], '第一个域名的位置要保持——它决定证书目录名');
$t->equals('xn--fiq228c.com', $list[2], 'IDN 要转换');

$t->throws(static function (): void {
    Domain::normalizeList([]);
}, ConfigException::class, '空列表应当报错');

$t->group('挑战记录名');

$t->equals('_acme-challenge.example.com', Domain::challengeRecordName('example.com'), '裸域');
// 通配符与裸域的挑战记录**同名**，这是 dns-01 的一个坑
$t->equals('_acme-challenge.example.com', Domain::challengeRecordName('*.example.com'), '通配符与裸域的记录名相同');
$t->equals('_acme-challenge.a.example.com', Domain::challengeRecordName('a.example.com'), '子域');

$t->group('zone 候选');

$t->equals(
    ['example.com', 'b.example.com', 'a.b.example.com'],
    Domain::zoneCandidates('a.b.example.com'),
    '从短到长；单级顶级域被跳过'
);

$t->equals(
    ['example.com.cn', 'test.example.com.cn'],
    Domain::zoneCandidates('test.example.com.cn'),
    'com.cn 是已知的多级公共后缀，要跳过'
);

$t->equals(
    ['example.com'],
    Domain::zoneCandidates('*.example.com'),
    '通配符前缀先去掉再算'
);

$t->group('相对记录名');

$t->equals('_acme-challenge', Domain::relativeName('_acme-challenge.example.com', 'example.com'), '一级');
$t->equals('_acme-challenge.a', Domain::relativeName('_acme-challenge.a.example.com', 'example.com'), '两级');
$t->equals('@', Domain::relativeName('example.com', 'example.com'), 'zone 顶点用 @');

$t->group('覆盖判断');

$t->ok(Domain::isCoveredBy('example.com', ['example.com']), '精确匹配');
$t->ok(Domain::isCoveredBy('a.example.com', ['*.example.com']), '通配符覆盖一级子域');
$t->ok(!Domain::isCoveredBy('a.b.example.com', ['*.example.com']), '通配符不覆盖两级子域');
$t->ok(!Domain::isCoveredBy('example.com', ['*.example.com']), '通配符不覆盖裸域');
$t->ok(Domain::isCoveredBy('EXAMPLE.com', ['example.com']), '比较时不分大小写');

$t->group('目录名');

$t->equals('example.com', Domain::directoryName('example.com'), '普通域名');
$t->equals('example.com_ecc', Domain::directoryName('example.com', true), 'ECC 加后缀');
// * 在 Windows 下是非法文件名字符，换成 _ 与 acme.sh 一致
$t->equals('_.example.com', Domain::directoryName('*.example.com'), '通配符的 * 换成 _');
$t->equals('_.example.com_ecc', Domain::directoryName('*.example.com', true), '通配符 + ECC');

exit($t->summary());
