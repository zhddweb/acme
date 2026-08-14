<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use PhpAcme\Crypto\Base64Url;
use PhpAcme\Crypto\Jws;
use PhpAcme\Crypto\KeyPair;
use PhpAcme\Tests\Runner;
use PhpAcme\Util\Json;

$t = new Runner('JWS 签名');

$types = ['ec-256', 'ec-384', 'ec-521', '2048'];

$t->group('签名可验证（含 EC 的 R||S 转换）');

foreach ($types as $type) {
    $keyPair = KeyPair::generate($type);
    $jws = Jws::sign($keyPair, 'https://acme.test/new-order', 'nonce-1', ['identifiers' => []]);

    $t->ok(Jws::verify($jws, $keyPair), sprintf('%s 签出来的 JWS 应当能验过', $type));

    // 篡改 payload 之后必须验不过
    $tampered = $jws;
    $tampered['payload'] = Base64Url::encodeJson(['identifiers' => ['evil']]);
    $t->ok(!Jws::verify($tampered, $keyPair), sprintf('%s 改了 payload 后不该验过', $type));
}

$t->group('protected header 的内容');

$keyPair = KeyPair::generate('ec-256');

$withJwk = Jws::sign($keyPair, 'https://acme.test/new-account', 'n1', ['x' => 1]);
$header = Jws::inspect($withJwk)['header'];

$t->equals('ES256', $header['alg'], 'alg 应当与密钥类型匹配');
$t->equals('n1', $header['nonce'], 'nonce 必须原样带上');
$t->equals('https://acme.test/new-account', $header['url'], 'url 必须与请求地址一致');
$t->ok(isset($header['jwk']), '没给 kid 时应当放 jwk');
$t->ok(!isset($header['kid']), 'jwk 模式下不该有 kid');

$withKid = Jws::sign($keyPair, 'https://acme.test/order/1', 'n2', null, 'https://acme.test/acct/1');
$kidHeader = Jws::inspect($withKid)['header'];

$t->ok(isset($kidHeader['kid']), '给了 kid 就该用 kid');
$t->ok(!isset($kidHeader['jwk']), 'kid 模式下不该有 jwk —— 两者同时出现服务端会判 malformed');

$t->group('POST-as-GET 的 payload 必须是空串');

// 写成 base64url("null") 或 base64url("{}") 都会被服务端当成带内容的 POST
$t->equals('', $withKid['payload'], 'payload 为 null 时编码结果必须是空字符串');
$t->notEquals('', $withJwk['payload'], '有 payload 时不该是空串');

$t->group('空对象 payload 与 null 的区别');

$emptyObject = Jws::sign($keyPair, 'https://acme.test/chall/1', 'n3', new stdClass(), 'https://acme.test/acct/1');
$t->equals('e30', $emptyObject['payload'], '空对象应当编码成 {} 的 base64url，也就是 e30');

$t->group('签名对象是 protected.payload 这个 ASCII 串');

// 用 RSA 做这个断言：PKCS#1 v1.5 是确定性的，同样的输入必然给出同样的签名，
// 可以直接比字节。ECDSA 每次签名都掺随机数 k，比不了字节，只能验签
$rsaKey = KeyPair::generate('2048');
$rsaJws = Jws::sign($rsaKey, 'https://acme.test/new-order', 'nonce-rsa', ['a' => 1]);

$t->equals(
    Base64Url::encode($rsaKey->signForJws($rsaJws['protected'] . '.' . $rsaJws['payload'])),
    $rsaJws['signature'],
    '签名输入必须是 base64url(protected) + "." + base64url(payload) 这个 ASCII 串'
);

// 换个分隔方式（比如漏掉那个点）必须签出不同结果，证明上面比的是真东西
$t->notEquals(
    Base64Url::encode($rsaKey->signForJws($rsaJws['protected'] . $rsaJws['payload'])),
    $rsaJws['signature'],
    '少了分隔用的点就该是另一个签名'
);

$t->group('External Account Binding');

$macKey = random_bytes(32);
$eab = Jws::signExternalAccountBinding($keyPair, 'https://acme.test/new-account', 'kid-abc', Base64Url::encode($macKey));

$eabHeader = Json::decode(Base64Url::decode($eab['protected']));

$t->equals('HS256', $eabHeader['alg'], 'EAB 用 HMAC-SHA256');
$t->equals('kid-abc', $eabHeader['kid'], 'EAB 的 kid 是 CA 分配的');
$t->equals('https://acme.test/new-account', $eabHeader['url'], 'EAB 的 url 是 newAccount 地址');
$t->ok(!isset($eabHeader['nonce']), 'EAB 的内层 JWS 不能带 nonce —— 带了会被判 malformed');

$expectedSignature = Base64Url::encode(
    hash_hmac('sha256', $eab['protected'] . '.' . $eab['payload'], $macKey, true)
);
$t->equals($expectedSignature, $eab['signature'], 'EAB 的 HMAC 应当按规范计算');

$eabPayload = Json::decode(Base64Url::decode($eab['payload']));
$t->equals($keyPair->getJwk(), $eabPayload, 'EAB 的 payload 是账户密钥的 JWK');

$t->group('挑战应答值');

$token = 'token-abc123';
$thumbprint = $keyPair->getThumbprint();

$keyAuth = Jws::keyAuthorization($token, $keyPair);
$t->equals($token . '.' . $thumbprint, $keyAuth, 'http-01 的值是 token.thumbprint');

$dnsValue = Jws::dnsTxtValue($token, $keyPair);
$t->equals(
    Base64Url::encode(hash('sha256', $keyAuth, true)),
    $dnsValue,
    'dns-01 的值要在 keyAuthorization 之上再做一次 SHA-256'
);
$t->equals(43, \strlen($dnsValue), 'dns-01 的 TXT 值固定 43 个字符');
$t->notEquals($keyAuth, $dnsValue, 'dns-01 与 http-01 的值必须不同');

$alpnDigest = Jws::tlsAlpnDigest($token, $keyPair);
$t->equals(32, \strlen($alpnDigest), 'tls-alpn-01 用的是 32 字节的裸摘要，不做 base64');
$t->equals(hash('sha256', $keyAuth, true), $alpnDigest, 'tls-alpn-01 的摘要算法');

exit($t->summary());
