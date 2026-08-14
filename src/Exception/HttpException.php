<?php

declare(strict_types=1);

namespace PhpAcme\Exception;

/**
 * 网络层失败：连不上、超时、TLS 握手失败、响应体读不全。
 *
 * 注意与 ProtocolException 的分工：HTTP 通了但服务端回了 ACME 错误文档，
 * 那是 ProtocolException，不是这个。这里只管「话没说到对面」。
 */
class HttpException extends AcmeException
{
}
