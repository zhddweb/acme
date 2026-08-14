<?php

declare(strict_types=1);

namespace Mci\Acme\Util;

use Mci\Acme\Exception\AcmeException;

/**
 * JSON 编解码的统一入口。
 *
 * 不直接用 json_decode()，原因有两个：
 * 1. JSON_THROW_ON_ERROR 是 PHP 7.3 才有的，本库要支持 7.2，只能手工查
 *    json_last_error()。散落在各处写会漏。
 * 2. ACME 协议里编码出来的 JSON 要参与签名，不能有多余空白、不能转义斜杠，
 *    否则签名对不上。这里把 flags 固定住。
 */
final class Json
{
    /**
     * 解码，失败抛异常。
     *
     * @return array
     */
    public static function decode(string $json, string $context = ''): array
    {
        if (trim($json) === '') {
            throw new AcmeException(self::describe('响应体是空的，没有 JSON 可解析', $context));
        }

        $data = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new AcmeException(self::describe(
                sprintf('JSON 解析失败：%s，原文前 200 字节：%s', json_last_error_msg(), substr($json, 0, 200)),
                $context
            ));
        }

        if (!\is_array($data)) {
            throw new AcmeException(self::describe('JSON 顶层不是对象或数组', $context));
        }

        return $data;
    }

    /**
     * 解码，失败返回 null 而不抛异常。
     *
     * 用在「对面可能回 JSON 也可能回 HTML 错误页」的场合，比如某些 DNS 厂商
     * 的网关超时会吐一段 nginx 的 502 页面。
     *
     * @return array|null
     */
    public static function tryDecode(string $json): ?array
    {
        $data = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE || !\is_array($data)) {
            return null;
        }

        return $data;
    }

    /**
     * 编码成紧凑形式，用于参与签名的 payload。
     *
     * 必须不转义斜杠与 Unicode：ACME 的 JWS 是对「编码后的字节」签名的，
     * 服务端不会帮你规范化，多一个 \/ 就验不过。
     *
     * @param mixed $value
     */
    public static function encode($value): string
    {
        $json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new AcmeException('JSON 编码失败：' . json_last_error_msg());
        }

        return $json;
    }

    /**
     * 编码成人类可读形式，用于写配置文件和日志。
     *
     * @param mixed $value
     */
    public static function encodePretty($value): string
    {
        $json = json_encode(
            $value,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
        );
        if ($json === false) {
            throw new AcmeException('JSON 编码失败：' . json_last_error_msg());
        }

        return $json;
    }

    private static function describe(string $message, string $context): string
    {
        return $context !== '' ? sprintf('%s（%s）', $message, $context) : $message;
    }
}
