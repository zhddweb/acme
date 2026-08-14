<?php

declare(strict_types=1);

namespace PhpAcme\Asn1;

/**
 * 用得到的 OID 常量。
 *
 * 写成点分字符串而不是预编码的字节串，是为了在报错和调试输出里能一眼认出来；
 * 编码开销可以忽略（一次签发也就调几十次）。
 */
final class Oid
{
    // 签名算法
    const SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
    const SHA384_WITH_RSA = '1.2.840.113549.1.1.12';
    const SHA512_WITH_RSA = '1.2.840.113549.1.1.13';
    const ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2';
    const ECDSA_WITH_SHA384 = '1.2.840.10045.4.3.3';
    const ECDSA_WITH_SHA512 = '1.2.840.10045.4.3.4';

    // 公钥算法
    const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
    const EC_PUBLIC_KEY = '1.2.840.10045.2.1';

    // 曲线
    const PRIME256V1 = '1.2.840.10045.3.1.7';
    const SECP384R1 = '1.3.132.0.34';
    const SECP521R1 = '1.3.132.0.35';

    // Name 里的属性
    const COMMON_NAME = '2.5.4.3';
    const COUNTRY_NAME = '2.5.4.6';
    const LOCALITY_NAME = '2.5.4.7';
    const STATE_NAME = '2.5.4.8';
    const ORGANIZATION_NAME = '2.5.4.10';
    const ORGANIZATIONAL_UNIT = '2.5.4.11';
    const EMAIL_ADDRESS = '1.2.840.113549.1.9.1';

    // CSR 属性与 X.509 扩展
    const EXTENSION_REQUEST = '1.2.840.113549.1.9.14';
    const SUBJECT_ALT_NAME = '2.5.29.17';
    const BASIC_CONSTRAINTS = '2.5.29.19';
    const KEY_USAGE = '2.5.29.15';
    const EXT_KEY_USAGE = '2.5.29.37';
    const SUBJECT_KEY_IDENTIFIER = '2.5.29.14';

    /** tls-alpn-01 用的扩展，RFC 8737 定义 */
    const ACME_IDENTIFIER = '1.3.6.1.5.5.7.1.31';

    const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
    const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';

    /** 域名短名 => OID，给 --csr-subject 之类的参数用 */
    const SUBJECT_SHORT_NAMES = [
        'CN' => self::COMMON_NAME,
        'C' => self::COUNTRY_NAME,
        'L' => self::LOCALITY_NAME,
        'ST' => self::STATE_NAME,
        'O' => self::ORGANIZATION_NAME,
        'OU' => self::ORGANIZATIONAL_UNIT,
        'emailAddress' => self::EMAIL_ADDRESS,
    ];
}
