<?php

declare(strict_types=1);

namespace Mci\Acme\Cli\Command;

use Mci\Acme\Acme;
use Mci\Acme\Cli\ArgvParser;
use Mci\Acme\Cli\CommandInterface;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Util\Logger;

/**
 * 删掉本地的证书目录（不吊销）。
 */
class RemoveCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['remove'];
    }

    public function getSummary(): string
    {
        return '删除本地证书文件（不吊销，只是不再续期）';
    }

    public function getUsage(): string
    {
        return implode("\n", [
            '用法：mci-acme remove -d <域名> [--ecc]',
            '',
            '只删本地文件，证书本身**仍然有效**——已经部署出去的地方不受影响，',
            '只是这台机器不再为它续期了。要让证书失效请用 revoke。',
        ]);
    }

    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int
    {
        $domain = $args->get('domain');
        if ($domain === null || $domain === '') {
            throw new ConfigException('用 -d 指定域名');
        }

        $ecc = $args->getFlag('ecc');
        $storage = $acme->getCertificateStorage();

        if (!$storage->exists($domain, $ecc)) {
            throw new ConfigException(sprintf('找不到 %s 的证书%s', $domain, $ecc ? '（ECC）' : ''));
        }

        $dir = $storage->getPaths()->getDomainDir($domain, $ecc);
        $storage->remove($domain, $ecc);

        $logger->write(sprintf('已删除 %s', $dir));
        $logger->write('提醒：证书本身仍然有效，需要作废请用 mci-acme revoke。');

        return 0;
    }
}
