<?php

declare(strict_types=1);

namespace Mci\Acme\Cli\Command;

use Mci\Acme\Acme;
use Mci\Acme\Ca\CaRegistry;
use Mci\Acme\Cli\ArgvParser;
use Mci\Acme\Cli\CommandInterface;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Util\Json;
use Mci\Acme\Util\Logger;

/**
 * 看一张证书的详细信息。
 */
class InfoCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['info'];
    }

    public function getSummary(): string
    {
        return '显示某张证书的详细信息与签发参数';
    }

    public function getUsage(): string
    {
        return implode("\n", [
            '用法：mci-acme info -d <域名> [--ecc] [--json]',
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

        $certificate = $storage->loadCertificate($domain, $ecc);
        if ($certificate === null) {
            throw new ConfigException(sprintf(
                '找不到 %s 的证书%s。用 mci-acme list 看看有哪些',
                $domain,
                $ecc ? '（ECC）' : ''
            ));
        }

        $config = $storage->getConfig($domain, $ecc);
        $paths = $storage->getPaths();

        $info = [
            'domain' => $domain,
            'domains' => $certificate->getDomains(),
            'issuer' => $certificate->getIssuerCommonName(),
            'serial' => $certificate->getSerialNumber(),
            'not_before' => gmdate('c', $certificate->getNotBefore()),
            'not_after' => gmdate('c', $certificate->getNotAfter()),
            'days_left' => $certificate->getDaysUntilExpiry(),
            'key_type' => $certificate->isEc() ? 'EC' : 'RSA',
            'ca' => CaRegistry::getDisplayName((string) $config->get('Le_API', '')),
            'files' => [
                'key' => $paths->getKeyPath($domain, $ecc),
                'cert' => $paths->getCertPath($domain, $ecc),
                'ca' => $paths->getCaCertPath($domain, $ecc),
                'fullchain' => $paths->getFullchainPath($domain, $ecc),
            ],
        ];

        if ($args->getFlag('json')) {
            $logger->write(Json::encodePretty($info));

            return 0;
        }

        $logger->write(sprintf('主域名　：%s%s', $info['domain'], $ecc ? '（ECC）' : ''));
        $logger->write(sprintf('全部域名：%s', implode(', ', $info['domains'])));
        $logger->write(sprintf('颁发者　：%s', $info['issuer']));
        $logger->write(sprintf('序列号　：%s', $info['serial']));
        $logger->write(sprintf('生效时间：%s', $info['not_before']));
        $logger->write(sprintf('到期时间：%s（还有 %d 天）', $info['not_after'], $info['days_left']));
        $logger->write(sprintf('密钥类型：%s', $info['key_type']));
        $logger->write(sprintf('签发 CA　：%s', $info['ca']));
        $logger->write('');
        $logger->write('文件：');
        foreach ($info['files'] as $name => $path) {
            $logger->write(sprintf('  %-10s %s', $name, $path));
        }

        // 私钥与证书对不上是最难查的故障之一，顺手验一下
        $keyPair = $storage->loadKey($domain, $ecc);
        if ($keyPair !== null && !$certificate->matchesPrivateKey($keyPair)) {
            $logger->write('');
            $logger->write('⚠ 私钥与证书不匹配！用 mci-acme issue --force --new-key 重新签发');
        }

        return 0;
    }
}
