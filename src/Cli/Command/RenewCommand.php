<?php

declare(strict_types=1);

namespace Mci\Acme\Cli\Command;

use Mci\Acme\Acme;
use Mci\Acme\Cli\ArgvParser;
use Mci\Acme\Cli\CommandInterface;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Util\Logger;

/**
 * 续期单张证书，参数从 .conf 里读回来。
 */
class RenewCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['renew'];
    }

    public function getSummary(): string
    {
        return '续期一张证书（参数沿用上次签发时的设置）';
    }

    public function getUsage(): string
    {
        return implode("\n", [
            '用法：mci-acme renew -d <域名> [选项]',
            '',
            '选项：',
            '  -d, --domain <域名>   要续期的主域名（就是签发时的第一个域名）',
            '      --ecc             续期 ECC 那张证书',
            '  -f, --force           即使没到续期时间也强制续',
            '',
            '续期用的验证方式、CA、密钥类型都从证书目录下的 .conf 读，',
            '不用重复指定。想改这些参数，直接重新跑一次 issue。',
        ]);
    }

    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int
    {
        $domains = $args->getAll('domain');
        if ($domains === []) {
            throw new ConfigException('用 -d 指定要续期的域名');
        }

        $ecc = $args->getFlag('ecc');
        $force = $args->getFlag('force');
        $failed = 0;

        foreach ($domains as $domain) {
            $result = $acme->renew($domain, $ecc, $force);

            if ($result->isSkipped()) {
                $logger->write($result->getMessage());
                continue;
            }

            $certificate = $result->getCertificate();
            $logger->write(sprintf(
                '%s 已续期，有效期至 %s',
                $domain,
                $certificate !== null ? gmdate('Y-m-d H:i:s', $certificate->getNotAfter()) : '未知'
            ));
        }

        return $failed === 0 ? 0 : 1;
    }
}
