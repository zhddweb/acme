<?php

declare(strict_types=1);

namespace Mci\Acme\Cli\Command;

use Mci\Acme\Acme;
use Mci\Acme\Cli\ArgvParser;
use Mci\Acme\Cli\CommandInterface;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Service\RevocationService;
use Mci\Acme\Util\Logger;

/**
 * 吊销证书。
 */
class RevokeCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['revoke'];
    }

    public function getSummary(): string
    {
        return '吊销证书';
    }

    public function getUsage(): string
    {
        $reasons = [];
        foreach (RevocationService::REASON_NAMES as $code => $name) {
            $reasons[] = sprintf('    %d = %s', $code, $name);
        }

        return implode("\n", array_merge([
            '用法：mci-acme revoke -d <域名> [--reason <码>] [--ecc] [--remove]',
            '',
            '选项：',
            '      --reason <码>   吊销原因，默认 0：',
        ], $reasons, [
            '      --remove        吊销后连本地文件一起删掉',
            '      --ecc           吊销 ECC 那张',
            '',
            '注意：原因码 1（私钥泄露）会让 CA 把这个公钥永久拉黑，',
            '同一把私钥再也签不出新证书。只是想换证书的话用 4。',
        ]));
    }

    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int
    {
        $domain = $args->get('domain');
        if ($domain === null || $domain === '') {
            throw new ConfigException('用 -d 指定要吊销的域名');
        }

        $reason = $args->getInt('reason', RevocationService::REASON_UNSPECIFIED);

        if (!isset(RevocationService::REASON_NAMES[$reason])) {
            throw new ConfigException(sprintf(
                '不认识的吊销原因码 %d。可用：%s',
                $reason,
                implode(', ', array_keys(RevocationService::REASON_NAMES))
            ));
        }

        $acme->revoke($domain, $args->getFlag('ecc'), $reason, $args->getFlag('remove'));

        $logger->write(sprintf('%s 的证书已吊销。', $domain));

        if (!$args->getFlag('remove')) {
            $logger->write('本地文件还留着，确认无误后可以用 mci-acme remove -d ' . $domain . ' 删掉。');
        }

        return 0;
    }
}
