<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use PhpAcme\Util\Idn;
use PhpAcme\Tests\Runner;

$t = new Runner('IDN 与 punycode');

$t->group('RFC 3492 的官方测试向量');

// 这些是规范附录 B 里的例子，能过说明编码器实现正确
$vectors = [
    'bücher' => 'bcher-kva',
    'müller' => 'mller-kva',
    '例子' => 'fsqu00a',
    '中文' => 'fiq228c',
    'ドメイン名例' => 'eckwd4c7cu47r2wf',
    'δοκιμή' => 'jxalpdlp',
    'испытание' => '80akhbyknj4f',
];

foreach ($vectors as $unicode => $punycode) {
    $t->equals($punycode, Idn::encodeLabel($unicode), sprintf('编码「%s」', $unicode));
    $t->equals($unicode, Idn::decodeLabel($punycode), sprintf('解码「%s」', $punycode));
}

$t->group('完整域名');

$t->equals('xn--fiq228c.com', Idn::toAscii('中文.com'), '中文域名转 A-label');
$t->equals('xn--fiq228c.xn--fiqs8s', Idn::toAscii('中文.中国'), '各级标签分别编码');
$t->equals('example.com', Idn::toAscii('example.com'), '纯 ASCII 原样返回');
$t->equals('example.com', Idn::toAscii('EXAMPLE.COM'), '大写要转小写');
$t->equals('xn--fiq228c.example.com', Idn::toAscii('中文.example.com'), '混合域名只编码非 ASCII 的那一级');

$t->group('通配符前缀');

$t->equals('*.xn--fiq228c.com', Idn::toAscii('*.中文.com'), '通配符前缀不参与编码');
$t->equals('*.example.com', Idn::toAscii('*.example.com'), 'ASCII 通配符原样返回');

$t->group('往返');

foreach (['中文.com', '例子.测试', 'münchen.de', 'bücher.example.com'] as $domain) {
    $ascii = Idn::toAscii($domain);
    $t->equals(strtolower($domain), Idn::toUnicode($ascii), sprintf('%s 往返一致', $domain));
}

$t->group('isAscii');

$t->ok(Idn::isAscii('example.com'), '纯 ASCII');
$t->ok(!Idn::isAscii('中文.com'), '含中文');
$t->ok(Idn::isAscii(''), '空串算 ASCII');

exit($t->summary());
