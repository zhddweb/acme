<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use PhpAcme\Crypto\Certificate;
use PhpAcme\Crypto\Jws;
use PhpAcme\Crypto\KeyPair;
use PhpAcme\Crypto\SelfSignedCertificate;
use PhpAcme\Exception\CryptoException;
use PhpAcme\Tests\Runner;

$t = new Runner('证书解析与自签');

$t->group('基本字段');

$keyPair = KeyPair::generate('ec-256');
$pem = SelfSignedCertificate::forPlaceholder($keyPair, ['example.com', 'www.example.com', '*.example.com'], 90 * 86400);
$certificate = Certificate::fromPem($pem);

$t->equals('example.com', $certificate->getSubjectCommonName(), 'CN 是第一个域名');
$t->equals('example.com', $certificate->getIssuerCommonName(), '自签证书的 issuer 等于 subject');
$t->ok($certificate->getSerialNumber() !== '', '应当有序列号');
$t->ok($certificate->getNotBefore() < time(), 'notBefore 应当在过去（留了时钟偏差的余量）');
$t->ok($certificate->getNotAfter() > time(), 'notAfter 应当在将来');
$t->ok($certificate->isEc(), 'EC 密钥签的证书应当被识别为 EC');
$t->ok($certificate->matchesPrivateKey($keyPair), '证书应当与生成它的私钥配对');

$other = KeyPair::generate('ec-256');
$t->ok(!$certificate->matchesPrivateKey($other), '换一把私钥就不该配对');

$t->group('SAN 域名');

$domains = $certificate->getDomains();
foreach (['example.com', 'www.example.com', '*.example.com'] as $domain) {
    $t->ok(\in_array($domain, $domains, true), sprintf('SAN 里应当有 %s', $domain));
}

$t->group('有效期计算');

$shortLived = Certificate::fromPem(SelfSignedCertificate::forPlaceholder($keyPair, ['short.example.com'], 10 * 86400));

// notAfter = 签发时刻 + 10 天，所以刚签完时剩余正好是 10 天；
// 跨秒边界时会掉到 9，用范围断言避免这种偶发失败
$daysLeft = $shortLived->getDaysUntilExpiry();
$t->ok($daysLeft === 10 || $daysLeft === 9, sprintf('10 天有效期的证书刚签完应当剩 9~10 天，实际 %d', $daysLeft));
$t->ok(!$shortLived->isExpired(), '还没到期');
$t->ok($shortLived->needsRenewal(30), '剩 9 天，30 天阈值下该续了');
$t->ok(!$shortLived->needsRenewal(5), '剩 9 天，5 天阈值下还不用续');

$t->group('域名覆盖判断');

$wildcard = Certificate::fromPem(SelfSignedCertificate::forPlaceholder($keyPair, ['example.com', '*.example.com']));

$t->ok($wildcard->covers(['example.com']), '裸域被覆盖');
$t->ok($wildcard->covers(['a.example.com']), '一级子域被通配符覆盖');
$t->ok($wildcard->covers(['example.com', 'b.example.com']), '多个域名都被覆盖');
// RFC 6125：通配符只匹配一级
$t->ok(!$wildcard->covers(['a.b.example.com']), '两级子域不该被通配符覆盖');
$t->ok(!$wildcard->covers(['other.com']), '无关域名不该被覆盖');

$t->group('证书链拆分');

$leaf = SelfSignedCertificate::forPlaceholder($keyPair, ['leaf.example.com']);
$intermediate = SelfSignedCertificate::forPlaceholder(KeyPair::generate('2048'), ['intermediate.example.com']);
$chain = $leaf . $intermediate;

$parts = Certificate::splitChain($chain);
$t->equals(2, \count($parts), '两张证书的链应当拆成两份');
$t->contains('leaf.example.com', (string) @openssl_x509_parse($parts[0])['subject']['CN'], '第一张是叶子证书');

// CA 返回 CRLF 是常有的事，拼给 nginx 之前必须规整掉
$crlfChain = str_replace("\n", "\r\n", $chain);
$crlfParts = Certificate::splitChain($crlfChain);
$t->equals(2, \count($crlfParts), 'CRLF 换行的链也要能拆');
$t->ok(strpos($crlfParts[0], "\r") === false, '拆出来的内容应当已经统一成 LF');

$t->equals(0, \count(Certificate::splitChain('里面没有证书')), '没有证书时返回空数组');

$t->group('PEM 与 DER 互转');

$der = Certificate::pemToDer($leaf);
$t->equals(0x30, \ord($der[0]), 'DER 最外层是 SEQUENCE');

$back = Certificate::fromPem(Certificate::derToPem($der));
$t->equals(
    $certificate->getSerialNumber() !== $back->getSerialNumber(),
    true,
    '不同证书的序列号不同（说明确实转的是那一张）'
);

$t->group('吊销用的 base64url DER');

$revokeValue = Certificate::fromPem($leaf)->toBase64UrlDer();
$t->ok(strpos($revokeValue, '-----') === false, '吊销传的是 DER 不是 PEM');
$t->ok(strpos($revokeValue, '+') === false && strpos($revokeValue, '/') === false, '必须是 base64url');

$t->group('tls-alpn-01 的自签证书');

$accountKey = KeyPair::generate('ec-256');
$digest = Jws::tlsAlpnDigest('token-xyz', $accountKey);
$alpnPem = SelfSignedCertificate::forTlsAlpn($keyPair, 'alpn.example.com', $digest);
$alpnCert = Certificate::fromPem($alpnPem);

$t->equals('alpn.example.com', $alpnCert->getSubjectCommonName(), 'CN 是被验证的域名');
$t->ok(\in_array('alpn.example.com', $alpnCert->getDomains(), true), 'SAN 里也要有它');

$info = $alpnCert->getInfo();
$t->ok(
    isset($info['extensions']['1.3.6.1.5.5.7.1.31']),
    'acmeIdentifier 扩展（OID 1.3.6.1.5.5.7.1.31）必须存在'
);

// 摘要是「装在 OCTET STRING 里的 OCTET STRING」，外层由 openssl 剥掉，
// 剩下的内容里应当能找到那 32 字节
$extensionValue = $info['extensions']['1.3.6.1.5.5.7.1.31'];
$t->contains($digest, $extensionValue, '扩展里应当装着 keyAuthorization 的 SHA-256 原始字节');

$t->group('通配符域名的自签证书');

// tls-alpn 的证书要用去掉 *. 的域名
$wildcardAlpn = Certificate::fromPem(SelfSignedCertificate::forTlsAlpn($keyPair, '*.example.com', $digest));
$t->equals('example.com', $wildcardAlpn->getSubjectCommonName(), '通配符前缀应当被去掉');

$t->group('坏输入');

$t->throws(
    static function (): void {
        Certificate::fromPem('这里没有证书');
    },
    CryptoException::class,
    '没有 PEM 块时应当报错'
);

$t->throws(
    static function (): void {
        Certificate::fromPem("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n");
    },
    CryptoException::class,
    '内容不是合法 X.509 时应当报错'
);

exit($t->summary());
