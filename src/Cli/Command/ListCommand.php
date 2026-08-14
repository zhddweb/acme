<?php

declare(strict_types=1);

namespace PhpAcme\Cli\Command;

use PhpAcme\Acme;
use PhpAcme\Cli\ArgvParser;
use PhpAcme\Cli\CommandInterface;
use PhpAcme\Storage\CertificateStorage;
use PhpAcme\Util\Json;
use PhpAcme\Util\Logger;

/**
 * 列出本机所有证书。
 */
class ListCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['list'];
    }

    public function getSummary(): string
    {
        return '列出本机所有证书及到期时间';
    }

    public function getUsage(): string
    {
        return implode("\n", [
            '用法：php-acme list [--json]',
            '',
            '选项：',
            '  --json    输出 JSON，方便脚本处理与接监控',
        ]);
    }

    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int
    {
        $storage = $acme->getCertificateStorage();
        $items = $storage->listCertificates();

        if ($items === []) {
            $logger->write('本机还没有任何证书。用 php-acme issue 签发第一张。');

            return 0;
        }

        $rows = [];
        foreach ($items as $item) {
            $certificate = $storage->loadCertificate($item['domain'], $item['ecc']);
            if ($certificate === null) {
                continue;
            }

            $config = $storage->getConfig($item['domain'], $item['ecc']);

            $rows[] = [
                'domain' => $item['domain'],
                'type' => $item['ecc'] ? 'ECC' : 'RSA',
                'domains' => $certificate->getDomains(),
                'issuer' => $certificate->getIssuerCommonName(),
                'not_after' => gmdate('Y-m-d', $certificate->getNotAfter()),
                'days_left' => $certificate->getDaysUntilExpiry(),
                'ca' => $config->get(CertificateStorage::KEY_API, ''),
                'dir' => $item['dir'],
            ];
        }

        if ($args->getFlag('json')) {
            $logger->write(Json::encodePretty($rows));

            return 0;
        }

        $logger->write(sprintf('%-32s %-5s %-12s %-8s %s', '主域名', '类型', '到期日', '剩余', '颁发者'));
        $logger->write(str_repeat('-', 88));

        foreach ($rows as $row) {
            // 快到期的加个标记，扫一眼就能看出哪张需要关注
            $mark = $row['days_left'] <= 7 ? ' !' : '';

            $logger->write(sprintf(
                '%-32s %-5s %-12s %-8s %s%s',
                $row['domain'],
                $row['type'],
                $row['not_after'],
                $row['days_left'] . ' 天',
                $row['issuer'],
                $mark
            ));
        }

        return 0;
    }
}
