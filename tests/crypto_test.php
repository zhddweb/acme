<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Crypto\Base64Url;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\CryptoException;
use Mci\Acme\Tests\Runner;
use Mci\Acme\Util\Json;

$t = new Runner('密钥与 JWK');

$t->group('各类型密钥的参数');

$expectations = [
    'ec-256' => ['alg' => 'ES256', 'bits' => 256, 'sig' => 64, 'ec' => true, 'crv' => 'P-256'],
    'ec-384' => ['alg' => 'ES384', 'bits' => 384, 'sig' => 96, 'ec' => true, 'crv' => 'P-384'],
    // P-521 是 521 位不是 512，所以 r/s 各 66 字节。这个 1 字节的差
    // 是 ES512 实现最常见的 bug
    'ec-521' => ['alg' => 'ES512', 'bits' => 521, 'sig' => 132, 'ec' => true, 'crv' => 'P-521'],
    '2048' => ['alg' => 'RS256', 'bits' => 2048, 'sig' => 256, 'ec' => false, 'crv' => null],
    '3072' => ['alg' => 'RS256', 'bits' => 3072, 'sig' => 384, 'ec' => false, 'crv' => null],
];

$keys = [];

foreach ($expectations as $type => $expected) {
    // PHP 会把 '2048' 这种全数字的数组键自动转成 int，而库在
    // strict_types 下只收 string，这里必须转回来
    $type = (string) $type;

    $keyPair = KeyPair::generate($type);
    $keys[$type] = $keyPair;

    $t->equals($expected['alg'], $keyPair->getSignatureAlgorithm(), sprintf('%s 的签名算法', $type));
    $t->equals($expected['bits'], $keyPair->getBits(), sprintf('%s 的位数', $type));
    $t->equals($expected['ec'], $keyPair->isEc(), sprintf('%s 的算法族', $type));
    $t->equals($expected['sig'], \strlen($keyPair->signForJws('test')), sprintf('%s 的 JWS 签名长度', $type));

    $jwk = $keyPair->getJwk();
    if ($expected['ec']) {
        $t->equals(['crv', 'kty', 'x', 'y'], array_keys($jwk), sprintf('%s 的 JWK 字段与顺序', $type));
        $t->equals($expected['crv'], $jwk['crv'], sprintf('%s 的曲线名', $type));

        // JWK 要求坐标定长左补零，openssl 可能给出更短的
        $size = intdiv($expected['bits'] + 7, 8);
        $t->equals($size, \strlen(Base64Url::decode($jwk['x'])), sprintf('%s 的 x 坐标应当补齐到 %d 字节', $type, $size));
        $t->equals($size, \strlen(Base64Url::decode($jwk['y'])), sprintf('%s 的 y 坐标应当补齐到 %d 字节', $type, $size));
    } else {
        $t->equals(['e', 'kty', 'n'], array_keys($jwk), sprintf('%s 的 JWK 字段与顺序', $type));
    }
}

$t->group('JWK thumbprint（RFC 7638）');

// 规范的示例：用文档里给的 RSA 公钥算出的 thumbprint 是固定值
$rfcJwk = [
    'e' => 'AQAB',
    'kty' => 'RSA',
    'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
];
$expectedThumbprint = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

$t->equals(
    $expectedThumbprint,
    Base64Url::encode(hash('sha256', Json::encode($rfcJwk), true)),
    'RFC 7638 §3.1 的示例值应当算得出来（验证字段顺序与紧凑编码）'
);

$t->group('thumbprint 的稳定性');

foreach ($keys as $type => $keyPair) {
    $type = (string) $type;
    $first = $keyPair->getThumbprint();
    $second = $keyPair->getThumbprint();
    $t->equals($first, $second, sprintf('%s 的 thumbprint 应当稳定', $type));

    $reloaded = KeyPair::fromPem($keyPair->getPrivateKeyPem());
    $t->equals($first, $reloaded->getThumbprint(), sprintf('%s 从 PEM 载入后 thumbprint 不变', $type));
    $t->equals($keyPair->getType(), $reloaded->getType(), sprintf('%s 从 PEM 载入后类型不变', $type));
}

$t->group('签名与验签');

foreach ($keys as $type => $keyPair) {
    $type = (string) $type;
    $data = 'message-' . $type . '-' . bin2hex(random_bytes(8));
    $signature = $keyPair->sign($data);

    $t->ok($keyPair->verify($data, $signature), sprintf('%s 的签名应当能验过', $type));
    $t->ok(!$keyPair->verify($data . 'x', $signature), sprintf('%s 改了内容后不该验过', $type));
}

$t->group('类型名归一化');

$aliases = [
    'ec-256' => 'ec-256', 'EC-256' => 'ec-256', 'ec256' => 'ec-256', '256' => 'ec-256',
    'P-256' => 'ec-256', 'prime256v1' => 'ec-256', 'secp256r1' => 'ec-256',
    'ec-384' => 'ec-384', 'secp384r1' => 'ec-384',
    // acme.sh 里 ec-512 其实指的是 P-521，这个别名要认
    'ec-512' => 'ec-521', 'ec-521' => 'ec-521', 'P-521' => 'ec-521',
    '2048' => '2048', 'rsa2048' => '2048', 'RSA-2048' => '2048',
    '4096' => '4096',
];

foreach ($aliases as $input => $expected) {
    $input = (string) $input;
    $t->equals($expected, KeyPair::normalizeType($input), sprintf('「%s」应当归一到 %s', $input, $expected));
}

$t->throws(
    static function (): void {
        KeyPair::normalizeType('ed25519');
    },
    CryptoException::class,
    '不支持的类型应当报错并列出可用值'
);

$t->group('拒绝弱密钥');

$weakKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 1024]);
$weakPem = '';
openssl_pkey_export($weakKey, $weakPem);

$t->throws(
    static function () use ($weakPem): void {
        KeyPair::fromPem($weakPem);
    },
    CryptoException::class,
    '1024 位的 RSA 必须被拒绝——CA 一律不接受'
);

$t->group('坏输入');

$t->throws(
    static function (): void {
        KeyPair::fromPem('这不是一个 PEM 私钥');
    },
    CryptoException::class,
    '垃圾内容当私钥载入应当报错'
);

$t->group('SubjectPublicKeyInfo');

foreach ($keys as $type => $keyPair) {
    $type = (string) $type;
    $spki = $keyPair->getSubjectPublicKeyInfo();
    $t->ok(\strlen($spki) > 0, sprintf('%s 应当能导出 SPKI', $type));
    // SPKI 的最外层必须是 SEQUENCE
    $t->equals(0x30, \ord($spki[0]), sprintf('%s 的 SPKI 最外层是 SEQUENCE', $type));
}

exit($t->summary());
