<?php

declare(strict_types=1);

namespace PhpAcme\Exception;

/**
 * 密钥、签名、编解码相关的失败。
 *
 * openssl 扩展报错、密钥格式不对、曲线不支持都归到这里。
 * 这类错误基本都是配置或环境问题，重试没有意义。
 */
class CryptoException extends AcmeException
{
}
