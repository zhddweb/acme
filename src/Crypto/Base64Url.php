<?php

declare(strict_types=1);

namespace Mci\Acme\Crypto;

use Mci\Acme\Exception\CryptoException;

/**
 * base64url 编解码（RFC 4648 §5）。
 *
 * 和普通 base64 的区别只有三处：`+` 变 `-`、`/` 变 `_`、去掉 `=` 填充。
 * 看着微不足道，但 JWS 的每一个字段、http-01 的 keyAuthorization、
 * dns-01 的 TXT 值全都用它——写错一个字符，服务端只会回一句
 * "the key authorization file from the server did not match"，
 * 根本看不出是编码问题。所以全库统一走这里，不允许就地手写 strtr()。
 */
final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $data): string
    {
        // 补回填充：base64 的长度必须是 4 的倍数，解码器才认
        $remainder = \strlen($data) % 4;
        if ($remainder !== 0) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        // strict 模式：混进非法字符时返回 false 而不是悄悄跳过。
        // 宁可炸也不要拿着一段被静默截断的密钥继续跑
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new CryptoException('base64url 解码失败：数据含非法字符');
        }

        return $decoded;
    }

    /**
     * 编码 JSON。JWS 的 protected header 与 payload 都是这个形状。
     *
     * @param mixed $value
     */
    public static function encodeJson($value): string
    {
        return self::encode(\Mci\Acme\Util\Json::encode($value));
    }
}
