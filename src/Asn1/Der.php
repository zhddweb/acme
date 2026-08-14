<?php

declare(strict_types=1);

namespace Mci\Acme\Asn1;

use Mci\Acme\Exception\CryptoException;

/**
 * ASN.1 DER 编码器。
 *
 * 为什么要自己写：CSR 必须带 subjectAltName 扩展（现代 CA 只认 SAN，
 * 不看 CN），而 PHP 的 openssl_csr_new() 要通过 openssl.cnf 文件里的
 * req_extensions 段来传 SAN——那意味着运行时得往磁盘写一个临时 cnf 文件，
 * 在 open_basedir 受限、临时目录只读的主机上直接歇菜，而这正是本库的目标环境。
 *
 * 自己拼 DER 就完全绕开了配置文件：openssl 扩展只用来做「签名」这一件事
 * （openssl_sign），字节结构由我们自己负责。
 *
 * DER 是 BER 的严格子集，编码唯一：长度必须用最短形式、SET OF 必须排序、
 * BOOLEAN 的 true 必须是 0xFF。下面每个方法都按 DER 规则写，不能按 BER 的松散规则来，
 * 否则签名校验会在某些 CA 那里失败。
 */
final class Der
{
    const TAG_BOOLEAN = 0x01;
    const TAG_INTEGER = 0x02;
    const TAG_BIT_STRING = 0x03;
    const TAG_OCTET_STRING = 0x04;
    const TAG_NULL = 0x05;
    const TAG_OID = 0x06;
    const TAG_UTF8_STRING = 0x0C;
    const TAG_SEQUENCE = 0x30;
    const TAG_SET = 0x31;
    const TAG_PRINTABLE_STRING = 0x13;
    const TAG_IA5_STRING = 0x16;
    const TAG_UTC_TIME = 0x17;
    const TAG_GENERALIZED_TIME = 0x18;

    /** 把 tag + 长度 + 内容拼成一个 TLV */
    public static function encode(int $tag, string $content): string
    {
        return \chr($tag) . self::encodeLength(\strlen($content)) . $content;
    }

    /**
     * DER 的长度域：0-127 用一个字节，更长的用「0x80|字节数」再跟大端长度。
     * 必须用最短形式，多补一个前导零就不是合法 DER 了。
     */
    public static function encodeLength(int $length): string
    {
        if ($length < 0) {
            throw new CryptoException('ASN.1 长度不能为负');
        }

        if ($length < 0x80) {
            return \chr($length);
        }

        $bytes = '';
        $remaining = $length;
        while ($remaining > 0) {
            $bytes = \chr($remaining & 0xFF) . $bytes;
            $remaining >>= 8;
        }

        return \chr(0x80 | \strlen($bytes)) . $bytes;
    }

    public static function sequence(string ...$items): string
    {
        return self::encode(self::TAG_SEQUENCE, implode('', $items));
    }

    /**
     * SET OF。
     *
     * DER 要求 SET OF 的成员按编码后的字节串升序排列。RDN 里通常只有一个成员，
     * 但 extensionRequest 的 values 和多值 RDN 会用到，排序不能省——
     * 顺序错了在 openssl 那边照样能解析，却算不出同样的哈希。
     */
    public static function setOf(string ...$items): string
    {
        // DER 的 SET OF 排序是按编码字节串比较，strcmp 的语义正好一致
        // （逐字节无符号比较，短的是前缀时排前面）。
        // 比较器只会对**完全相同**的元素返回 0，此时谁前谁后结果一样，
        // 因此不受 PHP 7 排序不稳定的影响，不需要额外的 tie-breaker
        usort($items, static function (string $a, string $b): int {
            return strcmp($a, $b);
        });

        return self::encode(self::TAG_SET, implode('', $items));
    }

    /** SET，不排序，用于确定只有一个成员的场合 */
    public static function set(string ...$items): string
    {
        return self::encode(self::TAG_SET, implode('', $items));
    }

    /**
     * INTEGER。输入是大端二进制的无符号整数。
     *
     * ASN.1 的 INTEGER 是**有符号**补码，所以最高位为 1 时必须补一个 0x00，
     * 否则会被解读成负数。ECDSA 签名里的 r/s 有一半概率撞上这条，
     * 漏了的话签出来的 CSR 在 openssl 眼里是坏的。
     */
    public static function integer(string $bigEndianBytes): string
    {
        // 去掉多余的前导零，但至少留一个字节
        $bytes = ltrim($bigEndianBytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }

        if ((\ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return self::encode(self::TAG_INTEGER, $bytes);
    }

    /** 小整数（版本号、序列号那种）直接给数值 */
    public static function integerFromInt(int $value): string
    {
        if ($value === 0) {
            return self::encode(self::TAG_INTEGER, "\x00");
        }

        $negative = $value < 0;
        $bytes = '';
        $remaining = $negative ? -$value - 1 : $value;

        while ($remaining > 0) {
            $byte = $remaining & 0xFF;
            $bytes = \chr($negative ? ~$byte & 0xFF : $byte) . $bytes;
            $remaining >>= 8;
        }

        if ($bytes === '') {
            $bytes = $negative ? "\xFF" : "\x00";
        }

        $first = \ord($bytes[0]);
        if (!$negative && ($first & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        } elseif ($negative && ($first & 0x80) === 0) {
            $bytes = "\xFF" . $bytes;
        }

        return self::encode(self::TAG_INTEGER, $bytes);
    }

    /**
     * BIT STRING。
     *
     * 第一个内容字节是「末尾有几个填充位」。我们包的都是整字节数据
     * （公钥、签名），所以恒为 0。
     */
    public static function bitString(string $data, int $unusedBits = 0): string
    {
        return self::encode(self::TAG_BIT_STRING, \chr($unusedBits) . $data);
    }

    public static function octetString(string $data): string
    {
        return self::encode(self::TAG_OCTET_STRING, $data);
    }

    public static function null(): string
    {
        return self::encode(self::TAG_NULL, '');
    }

    /** DER 的 TRUE 必须是 0xFF，不能是 0x01——BER 允许任意非零，DER 不允许 */
    public static function boolean(bool $value): string
    {
        return self::encode(self::TAG_BOOLEAN, $value ? "\xFF" : "\x00");
    }

    public static function utf8String(string $value): string
    {
        return self::encode(self::TAG_UTF8_STRING, $value);
    }

    public static function printableString(string $value): string
    {
        return self::encode(self::TAG_PRINTABLE_STRING, $value);
    }

    public static function ia5String(string $value): string
    {
        return self::encode(self::TAG_IA5_STRING, $value);
    }

    /**
     * OID 编码。
     *
     * 前两节合并成 first*40+second 塞进一个字节，其余每节按 base-128 编码、
     * 除最后一字节外最高位置 1。
     */
    public static function oid(string $dotted): string
    {
        $parts = explode('.', $dotted);
        if (\count($parts) < 2) {
            throw new CryptoException(sprintf('OID 至少要有两节：%s', $dotted));
        }

        $numbers = [];
        foreach ($parts as $part) {
            if (!ctype_digit($part)) {
                throw new CryptoException(sprintf('OID 含非数字节：%s', $dotted));
            }
            $numbers[] = (int) $part;
        }

        $content = \chr($numbers[0] * 40 + $numbers[1]);
        $count = \count($numbers);
        for ($i = 2; $i < $count; ++$i) {
            $content .= self::base128($numbers[$i]);
        }

        return self::encode(self::TAG_OID, $content);
    }

    /**
     * 上下文标签，EXPLICIT 形式：外面再套一层 [n]。
     *
     * 证书里的 version 和 extensions 用的就是这个。
     */
    public static function explicitContext(int $number, string $content): string
    {
        return self::encode(0xA0 | $number, $content);
    }

    /**
     * 上下文标签，IMPLICIT 形式：直接把原 tag 换成 [n]。
     *
     * SAN 里的 dNSName 和 CSR 的 attributes 用的是这个。
     * 注意 constructed 位要按被替换类型来定——SEQUENCE/SET 是 constructed（0x20），
     * IA5String 是 primitive。搞反了 openssl 会报 "nested asn1 error"。
     */
    public static function implicitContext(int $number, string $content, bool $constructed = false): string
    {
        $tag = 0x80 | $number;
        if ($constructed) {
            $tag |= 0x20;
        }

        return self::encode($tag, $content);
    }

    /**
     * X.509 的 Time：2050 年之前用 UTCTime（两位年），之后用 GeneralizedTime。
     * 这是 RFC 5280 的硬性要求，不是风格问题。
     */
    public static function time(int $timestamp): string
    {
        $year = (int) gmdate('Y', $timestamp);

        if ($year < 2050) {
            return self::encode(self::TAG_UTC_TIME, gmdate('ymdHis', $timestamp) . 'Z');
        }

        return self::encode(self::TAG_GENERALIZED_TIME, gmdate('YmdHis', $timestamp) . 'Z');
    }

    /**
     * AlgorithmIdentifier。
     *
     * RSA 系列要显式带一个 NULL 参数，ECDSA 系列**必须不带**——这是 RFC 5758
     * 明确规定的，多写一个 NULL 有些校验严格的实现会拒。
     */
    public static function algorithmIdentifier(string $oid, ?string $parameters = null): string
    {
        return $parameters === null
            ? self::sequence(self::oid($oid))
            : self::sequence(self::oid($oid), $parameters);
    }

    private static function base128(int $value): string
    {
        if ($value === 0) {
            return "\x00";
        }

        $bytes = '';
        $first = true;
        while ($value > 0) {
            $byte = $value & 0x7F;
            if (!$first) {
                $byte |= 0x80;
            }
            $bytes = \chr($byte) . $bytes;
            $first = false;
            $value >>= 7;
        }

        return $bytes;
    }
}
