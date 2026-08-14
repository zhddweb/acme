<?php

declare(strict_types=1);

namespace Mci\Acme\Crypto;

use Mci\Acme\Asn1\Der;
use Mci\Acme\Asn1\Oid;
use Mci\Acme\Util\Domain;

/**
 * 自签 X.509 证书生成，专供 tls-alpn-01 使用。
 *
 * 这个挑战方式（RFC 8737）的做法是：在 443 端口上用一张特制的自签证书应答
 * ALPN 协商为 `acme-tls/1` 的握手，证书里带一个 critical 的 acmeIdentifier
 * 扩展，值是 keyAuthorization 的 SHA-256。CA 连上来看到那个扩展就算验证通过。
 *
 * 同样不走 openssl_csr_sign()：那条路要 openssl.cnf 才能塞自定义扩展，
 * 而且 acmeIdentifier 这个 OID 在多数发行版的 openssl.cnf 里根本没定义。
 * 自己拼 DER 反而简单。
 *
 * 结构（RFC 5280）：
 *
 *   Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 *   TBSCertificate ::= SEQUENCE {
 *       [0] EXPLICIT version,  serialNumber,  signature,
 *       issuer,  validity,  subject,  subjectPublicKeyInfo,
 *       [3] EXPLICIT extensions }
 */
final class SelfSignedCertificate
{
    /**
     * 生成 tls-alpn-01 应答证书。
     *
     * @param string $digest keyAuthorization 的 SHA-256 原始字节（32 字节，不是 base64）
     * @return string PEM 证书
     */
    public static function forTlsAlpn(KeyPair $keyPair, string $domain, string $digest): string
    {
        $domain = Domain::stripWildcard(Domain::normalize($domain));

        // acmeIdentifier 的值是「装着 OCTET STRING 的 OCTET STRING」：
        // 外层是扩展通用的 extnValue 包装，内层才是 RFC 8737 定义的摘要。
        // 少套一层 CA 会判 invalid，而且报错只说扩展格式不对
        $acmeExtension = Der::sequence(
            Der::oid(Oid::ACME_IDENTIFIER),
            // 这个扩展必须标 critical：不标的话客户端可能忽略它，
            // 规范要求 critical 正是为了防止证书被当成普通服务证书误用
            Der::boolean(true),
            Der::octetString(Der::octetString($digest))
        );

        return self::build($keyPair, $domain, [$acmeExtension], 7 * 86400);
    }

    /**
     * 生成一张普通的自签证书。
     *
     * 用途：证书还没签下来时先给 nginx 一张占位证书，否则配置里引用了
     * 不存在的文件会导致服务起不来——鸡生蛋问题在首次签发时很常见。
     *
     * @param array<int, string> $domains
     */
    public static function forPlaceholder(KeyPair $keyPair, array $domains, int $lifetimeSeconds = 365 * 86400): string
    {
        $domains = Domain::normalizeList($domains);

        $generalNames = [];
        foreach ($domains as $domain) {
            $generalNames[] = Der::implicitContext(2, $domain, false);
        }

        $extensions = [
            Der::sequence(
                Der::oid(Oid::SUBJECT_ALT_NAME),
                Der::octetString(Der::sequence(...$generalNames))
            ),
            // CA:FALSE，明确它不是 CA 证书
            Der::sequence(
                Der::oid(Oid::BASIC_CONSTRAINTS),
                Der::boolean(true),
                Der::octetString(Der::sequence())
            ),
            Der::sequence(
                Der::oid(Oid::EXT_KEY_USAGE),
                Der::octetString(Der::sequence(Der::oid(Oid::SERVER_AUTH)))
            ),
        ];

        return self::build($keyPair, $domains[0], $extensions, $lifetimeSeconds, $domains);
    }

    /**
     * @param array<int, string> $extensions 已编码好的扩展 DER
     * @param array<int, string>|null $sanDomains 为 null 时按 $commonName 生成单域名 SAN
     */
    private static function build(
        KeyPair $keyPair,
        string $commonName,
        array $extensions,
        int $lifetimeSeconds,
        ?array $sanDomains = null
    ): string {
        $now = time();

        // 往前挪 5 分钟：客户端与 CA 的时钟不可能完全一致，
        // notBefore 卡在「现在」会让时钟稍慢的验证方看到一张「还没生效」的证书
        $notBefore = $now - 300;
        $notAfter = $now + $lifetimeSeconds;

        $subject = Der::sequence(
            Der::set(Der::sequence(Der::oid(Oid::COMMON_NAME), Der::utf8String($commonName)))
        );

        $algorithm = $keyPair->isRsa()
            ? Der::algorithmIdentifier($keyPair->getSignatureOid(), Der::null())
            : Der::algorithmIdentifier($keyPair->getSignatureOid());

        if ($sanDomains === null) {
            // tls-alpn 的证书也得有 SAN：CA 会核对证书是签给被验证域名的
            $extensions[] = Der::sequence(
                Der::oid(Oid::SUBJECT_ALT_NAME),
                Der::octetString(Der::sequence(Der::implicitContext(2, $commonName, false)))
            );
        }

        $tbs = Der::sequence(
            // version：[0] EXPLICIT，值 2 表示 v3。v3 才允许带扩展
            Der::explicitContext(0, Der::integerFromInt(2)),
            Der::integer(self::randomSerial()),
            $algorithm,
            // 自签，所以 issuer 就是 subject
            $subject,
            Der::sequence(Der::time($notBefore), Der::time($notAfter)),
            $subject,
            $keyPair->getSubjectPublicKeyInfo(),
            Der::explicitContext(3, Der::sequence(...$extensions))
        );

        $signature = $keyPair->sign($tbs);

        return Certificate::derToPem(Der::sequence($tbs, $algorithm, Der::bitString($signature)));
    }

    /**
     * 随机序列号。
     *
     * 最高位清零保证它被当成正数——ASN.1 的 INTEGER 是有符号的，
     * 负序列号虽然能编码但违反 RFC 5280，有些校验严格的实现会拒。
     */
    private static function randomSerial(): string
    {
        $bytes = random_bytes(16);
        $bytes[0] = \chr(\ord($bytes[0]) & 0x7F);

        return $bytes;
    }
}
