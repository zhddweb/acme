<?php

declare(strict_types=1);

namespace PhpAcme\Challenge;

use PhpAcme\Crypto\KeyPair;
use PhpAcme\Protocol\Challenge;
use PhpAcme\Util\Logger;

/**
 * 求解器的公共部分：日志、以及 tick/verify 的默认实现。
 *
 * 多数求解器不需要 tick（它们不是服务器），也没法本地自检
 * （写完 webroot 文件后去 HTTP 请求自己，在 NAT 后面会得到误判），
 * 所以默认给「什么都不做」和「直接就绪」。
 */
abstract class AbstractSolver implements ChallengeSolverInterface
{
    /** @var Logger */
    protected $logger;

    public function __construct(?Logger $logger = null)
    {
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
    }

    public function tick(): void
    {
        // 默认什么都不做
    }

    public function verify(Challenge $challenge, KeyPair $accountKey): bool
    {
        return true;
    }
}
