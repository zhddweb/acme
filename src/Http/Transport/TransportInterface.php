<?php

declare(strict_types=1);

namespace PhpAcme\Http\Transport;

use PhpAcme\Http\Request;
use PhpAcme\Http\Response;

/**
 * 真正把请求发出去的那一层。
 *
 * 抽出接口是为了两件事：curl 与 stream 两套实现可以互换；测试里能塞一个
 * MockTransport 把整个 ACME 服务端假掉——本库的测试不许打真实 CA，
 * 全靠这个接口。
 */
interface TransportInterface
{
    /**
     * @throws \PhpAcme\Exception\HttpException 连不上、超时、读不全时抛
     */
    public function send(Request $request): Response;

    /** 这套实现在当前环境能不能用 */
    public function isAvailable(): bool;

    /** 给日志用的名字 */
    public function getName(): string;
}
