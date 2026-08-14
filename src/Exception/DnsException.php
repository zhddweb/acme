<?php

declare(strict_types=1);

namespace Mci\Acme\Exception;

/**
 * DNS 提供商 API 调用失败，或 TXT 记录在超时时间内没能传播开。
 */
class DnsException extends AcmeException
{
}
