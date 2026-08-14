<?php

declare(strict_types=1);

namespace Mci\Acme\Exception;

/**
 * 证书、账户密钥、配置文件的读写失败。
 *
 * 目录建不出来、权限不足、磁盘满都在这里。密钥落盘失败必须当场炸，
 * 不然会出现「证书签下来了但私钥没了」这种最难受的状态。
 */
class StorageException extends AcmeException
{
}
