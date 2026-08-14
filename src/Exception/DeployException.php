<?php

declare(strict_types=1);

namespace Mci\Acme\Exception;

/**
 * 部署或通知钩子执行失败。
 *
 * 证书本身已经签发成功了，所以调用方通常应该记录告警而不是当作签发失败。
 */
class DeployException extends AcmeException
{
}
