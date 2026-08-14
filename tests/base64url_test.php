<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Crypto\Base64Url;
use Mci\Acme\Exception\CryptoException;
use Mci\Acme\Tests\Runner;

$t = new Runner('base64url');

$t->group('RFC 4648 §5 的编码规则');

// 这三个值挑得刻意：它们的标准 base64 里分别含 +、/ 和填充 =
$t->equals('_-8', Base64Url::encode("\xff\xef"), '+ 与 / 必须换成 - 与 _');
$t->equals('AA', Base64Url::encode("\x00"), '填充的 = 必须去掉');
$t->equals('', Base64Url::encode(''), '空串编码后还是空串');

$t->group('往返');

$samples = [
    '',
    'a',
    'ab',
    'abc',
    'hello world',
    random_bytes(32),
    random_bytes(33),
    random_bytes(64),
    str_repeat("\x00", 10),
    "\xff\xfe\xfd\xfc",
    '中文内容也要能往返',
];

foreach ($samples as $index => $sample) {
    $encoded = Base64Url::encode($sample);
    $t->equals($sample, Base64Url::decode($encoded), sprintf('往返用例 #%d', $index));
    $t->ok(
        strpos($encoded, '+') === false && strpos($encoded, '/') === false && strpos($encoded, '=') === false,
        sprintf('用例 #%d 的编码结果不该出现 + / =', $index)
    );
}

$t->group('解码时容错');

$t->equals("\xff\xef", Base64Url::decode('_-8'), '无填充也要能解');
$t->equals("\xff\xef", Base64Url::decode('_-8='), '带填充也要能解');

$t->throws(
    static function (): void {
        Base64Url::decode('!!!not-base64!!!');
    },
    CryptoException::class,
    '非法字符必须报错而不是静默截断'
);

$t->group('与标准 base64 的一致性');

for ($i = 0; $i < 20; ++$i) {
    $data = random_bytes(random_int(1, 40));
    $expected = rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    $t->equals($expected, Base64Url::encode($data), sprintf('随机用例 #%d 与手工换算结果一致', $i));
}

exit($t->summary());
