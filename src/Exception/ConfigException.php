<?php

declare(strict_types=1);

namespace PhpAcme\Exception;

/**
 * 配置不合法：缺必填项、值不在允许范围内、互斥选项同时给了。
 */
class ConfigException extends AcmeException
{
}
