<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Asn1\Der;
use Mci\Acme\Asn1\DerParser;
use Mci\Acme\Asn1\Oid;
use Mci\Acme\Exception\CryptoException;
use Mci\Acme\Tests\Runner;

$t = new Runner('ASN.1 DER 编解码');

$t->group('长度域用最短形式');

$t->equals("\x00", Der::encodeLength(0), '长度 0');
$t->equals("\x7f", Der::encodeLength(127), '127 用短形式');
$t->equals("\x81\x80", Der::encodeLength(128), '128 起用长形式，一个长度字节');
$t->equals("\x81\xff", Der::encodeLength(255), '255');
$t->equals("\x82\x01\x00", Der::encodeLength(256), '256 需要两个长度字节');
$t->equals("\x82\xff\xff", Der::encodeLength(65535), '65535');
$t->equals("\x83\x01\x00\x00", Der::encodeLength(65536), '65536 需要三个字节');

$t->group('INTEGER 的符号处理');

// ASN.1 的 INTEGER 是有符号补码，最高位为 1 时必须补 0x00，
// 否则会被读成负数。ECDSA 签名里的 r/s 有一半概率撞上
$t->equals("\x02\x01\x00", Der::integer("\x00"), '零');
$t->equals("\x02\x01\x7f", Der::integer("\x7f"), '0x7f 不需要补零');
$t->equals("\x02\x02\x00\x80", Der::integer("\x80"), '0x80 必须补一个 0x00');
$t->equals("\x02\x02\x00\xff", Der::integer("\xff"), '0xff 必须补零');
$t->equals("\x02\x01\x01", Der::integer("\x00\x00\x01"), '多余的前导零要去掉');
$t->equals("\x02\x02\x00\x80", Der::integer("\x00\x00\x80"), '去掉前导零后仍要按需补一个');

$t->group('integerFromInt');

$t->equals("\x02\x01\x00", Der::integerFromInt(0), '0');
$t->equals("\x02\x01\x02", Der::integerFromInt(2), '2（证书版本号 v3）');
$t->equals("\x02\x01\x7f", Der::integerFromInt(127), '127');
$t->equals("\x02\x02\x00\x80", Der::integerFromInt(128), '128 要补零');
$t->equals("\x02\x02\x01\x00", Der::integerFromInt(256), '256');

$t->group('BOOLEAN 必须是 0xFF');

// BER 允许任意非零表示 true，DER 只允许 0xFF
$t->equals("\x01\x01\xff", Der::boolean(true), 'true 编码成 0xFF');
$t->equals("\x01\x01\x00", Der::boolean(false), 'false 编码成 0x00');

$t->group('OID 编码');

$oidCases = [
    Oid::COMMON_NAME => "\x06\x03\x55\x04\x03",
    Oid::SUBJECT_ALT_NAME => "\x06\x03\x55\x1d\x11",
    Oid::RSA_ENCRYPTION => "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01",
    Oid::EC_PUBLIC_KEY => "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01",
    Oid::PRIME256V1 => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
];

foreach ($oidCases as $oid => $expected) {
    $t->equals($expected, Der::oid($oid), sprintf('OID %s', $oid));
}

$t->group('OID 往返');

foreach ([Oid::COMMON_NAME, Oid::ACME_IDENTIFIER, Oid::SECP521R1, Oid::ECDSA_WITH_SHA384, '1.2.3.4.5.6.7.8.9.100000'] as $oid) {
    $encoded = Der::oid($oid);
    $offset = 0;
    $tlv = DerParser::readTlv($encoded, $offset);
    $t->equals($oid, DerParser::decodeOid($tlv['content']), sprintf('%s 往返', $oid));
}

$t->throws(
    static function (): void {
        Der::oid('1');
    },
    CryptoException::class,
    '只有一节的 OID 应当报错'
);

$t->group('SET OF 必须按编码字节排序');

$sorted = Der::setOf(Der::utf8String('b'), Der::utf8String('a'), Der::utf8String('c'));
$offset = 0;
$set = DerParser::readTlv($sorted, $offset);

$values = [];
$inner = 0;
while ($inner < \strlen($set['content'])) {
    $item = DerParser::readTlv($set['content'], $inner);
    $values[] = $item['content'];
}

$t->equals(['a', 'b', 'c'], $values, 'SET OF 的成员应当按字节序升序排列');

$t->group('上下文标签');

// EXPLICIT 是在外面再套一层；IMPLICIT 是把原 tag 换掉
$t->equals("\xa0\x03\x02\x01\x02", Der::explicitContext(0, Der::integerFromInt(2)), 'EXPLICIT [0] 套住一个 INTEGER');
$t->equals("\x82\x03abc", Der::implicitContext(2, 'abc', false), 'IMPLICIT [2] primitive（SAN 的 dNSName）');
$t->equals("\xa0\x03abc", Der::implicitContext(0, 'abc', true), 'IMPLICIT [0] constructed（CSR 的 attributes）');

$t->group('AlgorithmIdentifier');

// RFC 5758：RSA 要带 NULL 参数，ECDSA 必须不带
$rsaAlg = Der::algorithmIdentifier(Oid::SHA256_WITH_RSA, Der::null());
$ecAlg = Der::algorithmIdentifier(Oid::ECDSA_WITH_SHA256);

$t->contains("\x05\x00", $rsaAlg, 'RSA 的 AlgorithmIdentifier 应当带 NULL 参数');
$t->ok(strpos($ecAlg, "\x05\x00") === false, 'ECDSA 的 AlgorithmIdentifier 不该带 NULL 参数');

$t->group('X.509 的 Time 类型选择');

// RFC 5280：2050 年之前用 UTCTime（两位年），之后用 GeneralizedTime
$utc = Der::time(gmmktime(12, 0, 0, 6, 15, 2026));
$generalized = Der::time(gmmktime(12, 0, 0, 6, 15, 2055));

$t->equals(Der::TAG_UTC_TIME, \ord($utc[0]), '2026 年应当用 UTCTime');
$t->contains('260615120000Z', $utc, 'UTCTime 的格式是 YYMMDDHHMMSSZ');
$t->equals(Der::TAG_GENERALIZED_TIME, \ord($generalized[0]), '2055 年应当用 GeneralizedTime');
$t->contains('20550615120000Z', $generalized, 'GeneralizedTime 的格式是 YYYYMMDDHHMMSSZ');

$t->group('解析器');

$nested = Der::sequence(
    Der::integerFromInt(1),
    Der::sequence(Der::oid(Oid::COMMON_NAME), Der::utf8String('test')),
    Der::bitString("\xab\xcd")
);

$dump = DerParser::dump($nested);
$t->equals(1, \count($dump), '顶层只有一个 SEQUENCE');
$t->equals(Der::TAG_SEQUENCE, $dump[0]['tag'], '顶层是 SEQUENCE');
$t->equals(3, \count($dump[0]['children']), 'SEQUENCE 下有三个成员');
$t->equals(Der::TAG_BIT_STRING, $dump[0]['children'][2]['tag'], '第三个成员是 BIT STRING');

$t->throws(
    static function (): void {
        $offset = 0;
        DerParser::readTlv("\x30\x82\xff\xff", $offset);
    },
    CryptoException::class,
    '声明长度超过实际数据时必须报错'
);

$t->throws(
    static function (): void {
        $offset = 0;
        // 0x80 长度字节表示不定长，DER 里不允许
        DerParser::readTlv("\x30\x80\x00\x00", $offset);
    },
    CryptoException::class,
    'DER 不允许不定长编码'
);

$t->group('ECDSA 签名 DER 与定长 R||S 的互转');

for ($i = 0; $i < 30; ++$i) {
    // 有意造出最高位为 1 的 r/s，那正是需要补零的情况
    $r = random_bytes(32);
    $s = random_bytes(32);

    $der = DerParser::encodeEcdsaSignature($r, $s);
    $parts = DerParser::parseEcdsaSignature($der);

    $t->equals(ltrim($r, "\x00"), $parts[0], sprintf('第 %d 轮 r 应当往返一致', $i));
    $t->equals(ltrim($s, "\x00"), $parts[1], sprintf('第 %d 轮 s 应当往返一致', $i));
}

exit($t->summary());
