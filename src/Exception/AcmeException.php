<?php

declare(strict_types=1);

namespace Mci\Acme\Exception;

/**
 * 本库所有异常的基类。
 *
 * 调用方想一网打尽就 catch 这个；想区分处理就 catch 下面的子类。
 * 不用 \Exception 直接抛，是为了让宿主应用能把本库的错误和自己的错误分开。
 */
class AcmeException extends \RuntimeException
{
}
