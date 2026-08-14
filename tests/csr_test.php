<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Crypto\Csr;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Tests\Runner;

$t = new Runner('CSR 生成');

$t->group('openssl 能解析并验签');

foreach (['ec-256', 'ec-384', 'ec-521', '2048'] as $type) {
    $keyPair = KeyPair::generate($type);
    $pem = Csr::createPem($keyPair, ['example.com', 'www.example.com']);

    // openssl_csr_get_subject 解析失败会返回 false，等于替我们验了结构
    $subject = @openssl_csr_get_subject($pem);
    $t->ok(\is_array($subject), sprintf('%s 的 CSR 应当能被 openssl 解析', $type));
    $t->equals('example.com', isset($subject['CN']) ? $subject['CN'] : null, sprintf('%s 的 CN 应当是第一个域名', $type));

    // 从 CSR 里把公钥掏出来，能掏出来说明 SubjectPublicKeyInfo 是对的
    $publicKey = @openssl_csr_get_public_key($pem);
    $t->ok($publicKey !== false, sprintf('%s 的 CSR 里应当有可用的公钥', $type));
}

$t->group('SAN 扩展');

$keyPair = KeyPair::generate('ec-256');
$domains = ['example.com', 'www.example.com', '*.example.com', 'a.b.example.com'];
$pem = Csr::createPem($keyPair, $domains);

$extracted = Csr::extractDomains($pem);
sort($extracted, SORT_STRING);
$expected = $domains;
sort($expected, SORT_STRING);

$t->equals($expected, $extracted, '所有域名都应当出现在 SAN 里');

$t->group('国际化域名');

$idnPem = Csr::createPem($keyPair, ['中文.example.com', 'example.com']);
$idnDomains = Csr::extractDomains($idnPem);

$t->ok(
    \in_array('xn--fiq228c.example.com', $idnDomains, true),
    'IDN 必须以 A-label 形式进 CSR —— 直接放 UTF-8 的话 CA 会拒'
);

$t->group('subject 附加字段');

$withSubject = Csr::createPem($keyPair, ['example.com'], [
    'C' => 'CN',
    'O' => '测试组织',
    'OU' => '运维部',
]);

$subject = @openssl_csr_get_subject($withSubject);
$t->equals('CN', isset($subject['C']) ? $subject['C'] : null, '国家代码');
$t->equals('测试组织', isset($subject['O']) ? $subject['O'] : null, '组织名要能装中文（用 UTF8String）');
$t->equals('运维部', isset($subject['OU']) ? $subject['OU'] : null, '部门名');

$t->group('超长 CN');

// CN 上限 64 字节，超了必须省略而不是截断——写超长的 CN 会让 CA 拒收整个 CSR
$longDomain = str_repeat('a', 60) . '.example.com';
$longPem = Csr::createPem($keyPair, [$longDomain]);
$longSubject = @openssl_csr_get_subject($longPem);

$t->ok(!isset($longSubject['CN']) || $longSubject['CN'] === '', 'CN 超过 64 字节时应当省略');
$t->ok(\in_array($longDomain, Csr::extractDomains($longPem), true), '但域名仍要出现在 SAN 里');

$t->group('PEM 与 DER 互转');

$der = Csr::create($keyPair, ['example.com']);
$roundtrip = Csr::pemToDer(Csr::derToPem($der));
$t->equals($der, $roundtrip, 'DER -> PEM -> DER 应当一致');

$t->equals(
    rtrim(strtr(base64_encode($der), '+/', '-_'), '='),
    Csr::toBase64Url($der),
    'finalize 提交的是 DER 的 base64url'
);

$t->throws(
    static function (): void {
        Csr::pemToDer('这不是 CSR');
    },
    \Mci\Acme\Exception\CryptoException::class,
    '非 PEM 内容应当报错'
);

$t->group('域名校验');

$t->throws(
    static function () use ($keyPair): void {
        Csr::create($keyPair, []);
    },
    ConfigException::class,
    '空域名列表应当报错'
);

$t->throws(
    static function () use ($keyPair): void {
        Csr::create($keyPair, ['*.*.example.com']);
    },
    ConfigException::class,
    '多级通配符应当被拒'
);

$t->group('域名去重但保持顺序');

$duplicated = Csr::createPem($keyPair, ['b.example.com', 'a.example.com', 'b.example.com']);
$duplicatedDomains = Csr::extractDomains($duplicated);

$t->equals(2, \count($duplicatedDomains), '重复的域名应当去掉');
$subjectDup = @openssl_csr_get_subject($duplicated);
$t->equals('b.example.com', $subjectDup['CN'], '第一个域名仍是 CN，顺序不能被排序打乱');

exit($t->summary());
