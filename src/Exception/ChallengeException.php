<?php

declare(strict_types=1);

namespace PhpAcme\Exception;

/**
 * 挑战验证环节失败：写不进 webroot、端口占用、TXT 记录加不上、服务端判定 invalid。
 */
class ChallengeException extends AcmeException
{
}
