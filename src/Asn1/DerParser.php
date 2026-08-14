<?php

declare(strict_types=1);

namespace PhpAcme\Asn1;

use PhpAcme\Exception\CryptoException;

/**
 * 够用就好的 DER 解析器。
 *
 * 只解决三件事：拆 ECDSA 签名里的 r/s、从 SubjectPublicKeyInfo 里掏出
 * EC 公钥点、以及测试里回读自己编码出来的结构做对拍。
 * 完整的 X.509 解析交给 openssl_x509_parse()，那个成熟得多，没必要重造。
 */
final class DerParser
{
    /**
     * 解析一个 TLV。
     *
     * @param string $data
     * @param int $offset 读到哪了，按引用推进
     * @return array{tag: int, length: int, content: string, headerLength: int}
     */
    public static function readTlv(string $data, int &$offset): array
    {
        $total = \strlen($data);
        if ($offset + 2 > $total) {
            throw new CryptoException('DER 数据被截断：读不到 tag 与长度');
        }

        $start = $offset;
        $tag = \ord($data[$offset]);
        ++$offset;

        $lengthByte = \ord($data[$offset]);
        ++$offset;

        if (($lengthByte & 0x80) === 0) {
            $length = $lengthByte;
        } else {
            $count = $lengthByte & 0x7F;
            if ($count === 0) {
                // 不定长形式，DER 里不允许出现
                throw new CryptoException('DER 不允许不定长编码');
            }
            if ($offset + $count > $total) {
                throw new CryptoException('DER 数据被截断：长度域读不全');
            }
            $length = 0;
            for ($i = 0; $i < $count; ++$i) {
                $length = ($length << 8) | \ord($data[$offset]);
                ++$offset;
            }
        }

        if ($offset + $length > $total) {
            throw new CryptoException(sprintf(
                'DER 数据被截断：声明长度 %d，实际只剩 %d 字节',
                $length,
                $total - $offset
            ));
        }

        $content = substr($data, $offset, $length);
        $offset += $length;

        return [
            'tag' => $tag,
            'length' => $length,
            'content' => $content,
            'headerLength' => $offset - $start - $length,
        ];
    }

    /**
     * 拆 ECDSA 的 DER 签名，得到 r 与 s 的大端字节串。
     *
     * openssl_sign() 对 EC 密钥吐出来的是 SEQUENCE { r INTEGER, s INTEGER }，
     * 而 JWS 要的是定长的 R||S 拼接。两者不能混用，这个函数是中间那道转换。
     *
     * @return array{0: string, 1: string}
     */
    public static function parseEcdsaSignature(string $der): array
    {
        $offset = 0;
        $seq = self::readTlv($der, $offset);
        if ($seq['tag'] !== Der::TAG_SEQUENCE) {
            throw new CryptoException('ECDSA 签名的最外层不是 SEQUENCE，openssl 返回的数据可能已损坏');
        }

        $inner = 0;
        $r = self::readTlv($seq['content'], $inner);
        $s = self::readTlv($seq['content'], $inner);

        if ($r['tag'] !== Der::TAG_INTEGER || $s['tag'] !== Der::TAG_INTEGER) {
            throw new CryptoException('ECDSA 签名里的 r/s 不是 INTEGER');
        }

        // INTEGER 是有符号的，正数最高位为 1 时前面会补一个 0x00，转回定长时要去掉
        return [ltrim($r['content'], "\x00"), ltrim($s['content'], "\x00")];
    }

    /**
     * 把 JWS 的定长 R||S 签名转回 DER，用于校验时喂给 openssl_verify()。
     */
    public static function encodeEcdsaSignature(string $r, string $s): string
    {
        return Der::sequence(Der::integer($r), Der::integer($s));
    }

    /**
     * 从 SubjectPublicKeyInfo 里取出 EC 公钥点（未压缩形式，0x04 || X || Y）。
     *
     * SPKI ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
     */
    public static function extractEcPoint(string $spkiDer): string
    {
        $offset = 0;
        $seq = self::readTlv($spkiDer, $offset);
        if ($seq['tag'] !== Der::TAG_SEQUENCE) {
            throw new CryptoException('SubjectPublicKeyInfo 的最外层不是 SEQUENCE');
        }

        $inner = 0;
        self::readTlv($seq['content'], $inner);
        $bitString = self::readTlv($seq['content'], $inner);

        if ($bitString['tag'] !== Der::TAG_BIT_STRING) {
            throw new CryptoException('SubjectPublicKeyInfo 里没有找到 BIT STRING');
        }

        // BIT STRING 的第一个字节是填充位数，公钥这里恒为 0，跳过
        $point = substr($bitString['content'], 1);
        if ($point === '' || $point[0] !== "\x04") {
            throw new CryptoException('EC 公钥不是未压缩点格式（应以 0x04 开头）');
        }

        return $point;
    }

    /**
     * 把整个结构递归拆成树，仅用于测试断言与调试输出。
     *
     * @return array
     */
    public static function dump(string $data, int $maxDepth = 12): array
    {
        $offset = 0;
        $items = [];
        $length = \strlen($data);

        while ($offset < $length) {
            $tlv = self::readTlv($data, $offset);
            $node = ['tag' => $tlv['tag'], 'length' => $tlv['length']];

            // constructed 位是 0x20；置位的才有子结构可以往下拆
            if (($tlv['tag'] & 0x20) !== 0 && $maxDepth > 0 && $tlv['content'] !== '') {
                $node['children'] = self::dump($tlv['content'], $maxDepth - 1);
            } else {
                $node['content'] = $tlv['content'];
            }

            $items[] = $node;
        }

        return $items;
    }

    /** 把 DER 里的 OID 内容字节解回点分形式，dump 出来才看得懂 */
    public static function decodeOid(string $content): string
    {
        if ($content === '') {
            throw new CryptoException('OID 内容为空');
        }

        $first = \ord($content[0]);
        $parts = [(string) intdiv($first, 40), (string) ($first % 40)];

        $value = 0;
        $length = \strlen($content);
        for ($i = 1; $i < $length; ++$i) {
            $byte = \ord($content[$i]);
            $value = ($value << 7) | ($byte & 0x7F);
            if (($byte & 0x80) === 0) {
                $parts[] = (string) $value;
                $value = 0;
            }
        }

        return implode('.', $parts);
    }
}
