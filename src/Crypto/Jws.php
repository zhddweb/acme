<?php

declare(strict_types=1);

namespace PhpAcme\Crypto;

use PhpAcme\Exception\CryptoException;
use PhpAcme\Util\Json;

/**
 * JWS 签名封装（RFC 7515 的 flattened JSON 序列化）。
 *
 * ACME 的每一个 POST 请求都是一份 JWS。协议对它的要求比通用 JWS 更严：
 *
 * - protected header 里**必须**有 nonce 和 url，且 url 要与实际请求的地址
 *   逐字符相同（含大小写与末尾斜杠）。服务端拿它防重放和防转发，
 *   差一个字符就是 unauthorized。
 * - jwk 与 kid **二选一，不能同时出现**。只有 newAccount 和 revokeCert
 *   （用证书私钥签的那种）用 jwk，其余一律用 kid。同时给会被判 malformed。
 * - 签名对象是 `base64url(protected) + "." + base64url(payload)` 这个
 *   **ASCII 串**，不是原始 JSON 字节。
 */
final class Jws
{
    /**
     * 用账户密钥签一个 ACME 请求。
     *
     * @param mixed $payload 要签的内容；传 null 表示 POST-as-GET（payload 是空串，不是 "null"）
     * @param string|null $kid 账户 URL；给了就用 kid 模式，没给就把 jwk 塞进头里
     * @return array{protected: string, payload: string, signature: string}
     */
    public static function sign(
        KeyPair $keyPair,
        string $url,
        string $nonce,
        $payload,
        ?string $kid = null
    ): array {
        $protected = [
            'alg' => $keyPair->getSignatureAlgorithm(),
            'nonce' => $nonce,
            'url' => $url,
        ];

        if ($kid !== null && $kid !== '') {
            $protected['kid'] = $kid;
        } else {
            $protected['jwk'] = $keyPair->getJwk();
        }

        // POST-as-GET：payload 必须是**空字符串**。写成 base64url("null") 或
        // base64url("{}") 都会被服务端当成一次带内容的 POST 而拒绝
        $encodedPayload = $payload === null ? '' : Base64Url::encodeJson($payload);
        $encodedProtected = Base64Url::encodeJson($protected);

        $signature = $keyPair->signForJws($encodedProtected . '.' . $encodedPayload);

        return [
            'protected' => $encodedProtected,
            'payload' => $encodedPayload,
            'signature' => Base64Url::encode($signature),
        ];
    }

    /**
     * 签完直接给出请求体字符串。
     *
     * @param mixed $payload
     */
    public static function signToJson(
        KeyPair $keyPair,
        string $url,
        string $nonce,
        $payload,
        ?string $kid = null
    ): string {
        return Json::encode(self::sign($keyPair, $url, $nonce, $payload, $kid));
    }

    /**
     * External Account Binding 用的内层 JWS。
     *
     * 和上面那个形状像但规则完全不同（RFC 8555 §7.3.4）：
     * - 算法是 HS256，用 CA 给的 MAC key 做 HMAC，**不是**账户密钥的非对称签名
     * - protected header 里只有 alg、kid、url 三个字段，**不能有 nonce**
     * - payload 是账户密钥的 JWK
     *
     * 这份 JWS 会作为 newAccount 请求 payload 里的 externalAccountBinding 字段，
     * 外面再套一层用账户密钥签的正常 JWS。
     *
     * @param string $kid CA 分配的 EAB Key ID
     * @param string $hmacKeyBase64Url CA 给的 MAC key，base64url 编码
     * @return array{protected: string, payload: string, signature: string}
     */
    public static function signExternalAccountBinding(
        KeyPair $accountKey,
        string $url,
        string $kid,
        string $hmacKeyBase64Url
    ): array {
        if ($kid === '') {
            throw new CryptoException('EAB 的 Key ID 不能为空');
        }

        // CA 网页上给的 HMAC key 一律是 base64url 的；有的地方会带 = 填充，
        // Base64Url::decode 两种都吃得下
        $macKey = Base64Url::decode($hmacKeyBase64Url);
        if ($macKey === '') {
            throw new CryptoException('EAB 的 HMAC key 解码后是空的，检查是不是复制漏了');
        }

        $protected = Base64Url::encodeJson([
            'alg' => 'HS256',
            'kid' => $kid,
            'url' => $url,
        ]);

        $payload = Base64Url::encodeJson($accountKey->getJwk());

        $signature = hash_hmac('sha256', $protected . '.' . $payload, $macKey, true);

        return [
            'protected' => $protected,
            'payload' => $payload,
            'signature' => Base64Url::encode($signature),
        ];
    }

    /**
     * 只解不验，读回 JWS 里的 header 与 payload。测试与排错用。
     *
     * @param array{protected: string, payload: string, signature: string} $jws
     * @return array{header: array, payload: array|null}
     */
    public static function inspect(array $jws): array
    {
        if (!isset($jws['protected'])) {
            throw new CryptoException('这不是一份 JWS：缺 protected 字段');
        }

        $header = Json::decode(Base64Url::decode($jws['protected']), 'JWS protected header');

        $payload = null;
        if (isset($jws['payload']) && $jws['payload'] !== '') {
            $payload = Json::tryDecode(Base64Url::decode($jws['payload']));
        }

        return ['header' => $header, 'payload' => $payload];
    }

    /**
     * 验签，只在测试里用来确认我们签出来的东西是对的。
     *
     * @param array{protected: string, payload: string, signature: string} $jws
     */
    public static function verify(array $jws, KeyPair $keyPair): bool
    {
        $signingInput = $jws['protected'] . '.' . $jws['payload'];
        $signature = Base64Url::decode($jws['signature']);

        if ($keyPair->isRsa()) {
            return $keyPair->verify($signingInput, $signature);
        }

        // EC 的签名在 JWS 里是定长 R||S，openssl_verify 要 DER，转回去再验
        $length = \strlen($signature);
        if ($length % 2 !== 0) {
            return false;
        }

        $half = intdiv($length, 2);
        $der = \PhpAcme\Asn1\DerParser::encodeEcdsaSignature(
            substr($signature, 0, $half),
            substr($signature, $half)
        );

        return $keyPair->verify($signingInput, $der);
    }

    /**
     * 挑战的 keyAuthorization：token + "." + 账户密钥指纹。
     *
     * http-01 把这个字符串原样写进文件；dns-01 要再 SHA-256 + base64url，
     * 见 dnsTxtValue()。
     */
    public static function keyAuthorization(string $token, KeyPair $accountKey): string
    {
        return $token . '.' . $accountKey->getThumbprint();
    }

    /**
     * dns-01 的 TXT 记录值。
     *
     * 和 http-01 差一步哈希，这一步漏了或者多做了都是 unauthorized，
     * 而服务端的报错完全看不出区别，所以单独拎成一个函数，别在调用处手写。
     */
    public static function dnsTxtValue(string $token, KeyPair $accountKey): string
    {
        return Base64Url::encode(hash('sha256', self::keyAuthorization($token, $accountKey), true));
    }

    /**
     * tls-alpn-01 证书里 acmeIdentifier 扩展的值：keyAuthorization 的 SHA-256 原始字节。
     *
     * 注意这里**不做** base64url，扩展里放的是 32 字节的裸摘要（RFC 8737 §3）。
     */
    public static function tlsAlpnDigest(string $token, KeyPair $accountKey): string
    {
        return hash('sha256', self::keyAuthorization($token, $accountKey), true);
    }
}
