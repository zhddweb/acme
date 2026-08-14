<?php

declare(strict_types=1);

namespace PhpAcme\Crypto;

use PhpAcme\Asn1\Der;
use PhpAcme\Asn1\Oid;
use PhpAcme\Exception\CryptoException;
use PhpAcme\Util\Domain;

/**
 * CSR（PKCS#10）生成。
 *
 * 全程自己拼 DER，openssl 只负责最后那一次签名。这么做是为了绕开
 * openssl_csr_new() 对 openssl.cnf 的依赖——SAN 扩展只能通过配置文件里的
 * req_extensions 传，而本库的目标环境经常连临时目录都写不了。
 *
 * 结构（RFC 2986）：
 *
 *   CertificationRequest ::= SEQUENCE {
 *       certificationRequestInfo  CertificationRequestInfo,
 *       signatureAlgorithm        AlgorithmIdentifier,
 *       signature                 BIT STRING }
 *
 *   CertificationRequestInfo ::= SEQUENCE {
 *       version        INTEGER (0),
 *       subject        Name,
 *       subjectPKInfo  SubjectPublicKeyInfo,
 *       attributes     [0] IMPLICIT SET OF Attribute }
 */
final class Csr
{
    /**
     * 生成 CSR。
     *
     * @param array<int, string> $domains 第一个作为 CN；全部都会进 SAN
     * @param array<string, string> $subject 额外的 subject 字段，键用 C/ST/L/O/OU
     * @return string DER 编码的 CSR
     */
    public static function create(KeyPair $keyPair, array $domains, array $subject = []): string
    {
        $domains = Domain::normalizeList($domains);

        $info = self::buildRequestInfo($keyPair, $domains, $subject);

        // 签的是 CertificationRequestInfo 的完整 DER（含它自己的 tag 与长度），
        // 不是里面的内容字节——少了外层头，openssl 验不过
        $signature = $keyPair->sign($info);

        return Der::sequence(
            $info,
            self::signatureAlgorithm($keyPair),
            Der::bitString($signature)
        );
    }

    /** 生成 CSR 并转成 PEM */
    public static function createPem(KeyPair $keyPair, array $domains, array $subject = []): string
    {
        return self::derToPem(self::create($keyPair, $domains, $subject));
    }

    /**
     * @param array<int, string> $domains
     * @param array<string, string> $subject
     */
    private static function buildRequestInfo(KeyPair $keyPair, array $domains, array $subject): string
    {
        return Der::sequence(
            Der::integerFromInt(0),
            self::buildSubject($domains[0], $subject),
            $keyPair->getSubjectPublicKeyInfo(),
            self::buildAttributes($domains)
        );
    }

    /**
     * Subject。
     *
     * CN 放第一个域名。现代 CA 其实只看 SAN，CN 早就不作为身份依据了，
     * 但留着它有实际好处：openssl 命令行和各种面板列证书时显示的就是 CN，
     * 空着的话运维看到的是一片 "(none)"。
     *
     * CN 长度上限 64 字节，超了要留空——不是省略，是必须省略，
     * 写超长的 CN 会让 CA 直接拒收整个 CSR。
     *
     * @param array<string, string> $extra
     */
    private static function buildSubject(string $commonName, array $extra): string
    {
        $rdns = [];

        // 顺序按 X.500 惯例从大到小：C, ST, L, O, OU, CN
        $order = ['C', 'ST', 'L', 'O', 'OU'];
        foreach ($order as $short) {
            if (!isset($extra[$short]) || trim((string) $extra[$short]) === '') {
                continue;
            }
            $rdns[] = self::rdn(Oid::SUBJECT_SHORT_NAMES[$short], (string) $extra[$short], $short === 'C');
        }

        if (\strlen($commonName) <= 64) {
            $rdns[] = self::rdn(Oid::COMMON_NAME, $commonName, false);
        }

        if (isset($extra['emailAddress']) && trim((string) $extra['emailAddress']) !== '') {
            $rdns[] = self::rdn(Oid::EMAIL_ADDRESS, (string) $extra['emailAddress'], false);
        }

        return Der::sequence(...$rdns);
    }

    /**
     * 一条 RDN。
     *
     * countryName 在 X.520 里被定义成 PrintableString 且长度恰好 2，
     * 用 UTF8String 装会被严格的解析器拒；其余字段用 UTF8String 最保险
     * （PrintableString 装不下中文的组织名）。
     */
    private static function rdn(string $oid, string $value, bool $printable): string
    {
        $encoded = $printable
            ? Der::printableString(strtoupper(substr($value, 0, 2)))
            : Der::utf8String($value);

        return Der::set(Der::sequence(Der::oid($oid), $encoded));
    }

    /**
     * attributes [0]，里面装 extensionRequest -> subjectAltName。
     *
     * 就算只有一个域名也必须写 SAN：CA/Browser Forum 从 2017 年起要求
     * 证书必须有 SAN，只有 CN 的 CSR 会被 Let's Encrypt 直接拒。
     *
     * @param array<int, string> $domains
     */
    private static function buildAttributes(array $domains): string
    {
        $generalNames = [];
        foreach ($domains as $domain) {
            // dNSName 是 GeneralName 的 [2]，IMPLICIT 且是 primitive（底层是 IA5String）。
            // 写成 constructed 会让 openssl 报 "nested asn1 error"
            $generalNames[] = Der::implicitContext(2, $domain, false);
        }

        $san = Der::sequence(
            Der::oid(Oid::SUBJECT_ALT_NAME),
            Der::octetString(Der::sequence(...$generalNames))
        );

        $extensions = Der::sequence($san);

        $attribute = Der::sequence(
            Der::oid(Oid::EXTENSION_REQUEST),
            Der::set($extensions)
        );

        // attributes 是 [0] IMPLICIT SET OF Attribute —— 替换掉的是 SET 的 tag，
        // SET 是 constructed，所以这里必须传 true
        return Der::implicitContext(0, $attribute, true);
    }

    private static function signatureAlgorithm(KeyPair $keyPair): string
    {
        // RSA 的 AlgorithmIdentifier 要带 NULL 参数，ECDSA 的必须不带（RFC 5758）
        return $keyPair->isRsa()
            ? Der::algorithmIdentifier($keyPair->getSignatureOid(), Der::null())
            : Der::algorithmIdentifier($keyPair->getSignatureOid());
    }

    public static function derToPem(string $der): string
    {
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END CERTIFICATE REQUEST-----\n";
    }

    public static function pemToDer(string $pem): string
    {
        if (preg_match('/-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----(.+?)-----END (?:NEW )?CERTIFICATE REQUEST-----/s', $pem, $m) !== 1) {
            throw new CryptoException('这不是一份 PEM 格式的 CSR');
        }

        $der = base64_decode(preg_replace('/\s+/', '', $m[1]), true);
        if ($der === false) {
            throw new CryptoException('CSR 的 base64 解码失败');
        }

        return $der;
    }

    /**
     * CSR 的 base64url 形式，finalize 请求里就是这么传的。
     *
     * ACME 传的是 DER 的 base64url，不是 PEM——把 PEM 整段塞进去是个常见错误，
     * 服务端会回一句含糊的 malformed。
     */
    public static function toBase64Url(string $der): string
    {
        return Base64Url::encode($der);
    }

    /**
     * 从已有的 CSR（PEM 或 DER）里读出域名列表。
     *
     * 用户用 --csr 指定自己的 CSR 时，得知道要为哪些域名去做验证。
     * 这里借 openssl_csr_get_subject() 拿 CN，SAN 则自己从 DER 里翻——
     * PHP 没有暴露读 CSR 扩展的 API。
     *
     * @return array<int, string>
     */
    public static function extractDomains(string $csr): array
    {
        $der = str_contains($csr, '-----BEGIN') ? self::pemToDer($csr) : $csr;

        $domains = [];

        // SAN 的 dNSName 在 DER 里是 [2] IMPLICIT IA5String，tag 字节 0x82，
        // 长度一定小于 128（域名最长 253 字节，但单条 dNSName 在这里用短长度形式）。
        // 直接扫 extensionRequest 那一段，比完整解析 PKCS#10 省事且够用
        $offset = 0;
        $length = \strlen($der);
        while ($offset < $length - 2) {
            if ($der[$offset] === "\x82") {
                $itemLength = \ord($der[$offset + 1]);
                if ($itemLength > 0 && $itemLength < 0x80 && $offset + 2 + $itemLength <= $length) {
                    $candidate = substr($der, $offset + 2, $itemLength);
                    // 只有长得像域名的才算，避免把二进制噪声当成 SAN 收进来
                    if (preg_match('/^\*?[a-z0-9._-]+\.[a-z]{2,}$/i', $candidate) === 1) {
                        $domains[] = strtolower($candidate);
                    }
                }
            }
            ++$offset;
        }

        if ($domains === []) {
            // 没有 SAN 就退回 CN。这种 CSR 现代 CA 会拒，但先让用户拿到
            // 「你的 CSR 里只有 CN」这个明确信息，比报一句 no domains 强
            $subject = @openssl_csr_get_subject(
                str_contains($csr, '-----BEGIN') ? $csr : self::derToPem($der)
            );
            if (\is_array($subject) && isset($subject['CN']) && \is_string($subject['CN'])) {
                $domains[] = strtolower($subject['CN']);
            }
        }

        return array_values(array_unique($domains));
    }
}
