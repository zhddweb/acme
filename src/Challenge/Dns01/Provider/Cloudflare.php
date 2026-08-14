<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01\Provider;

use PhpAcme\Challenge\Dns01\AbstractDnsProvider;
use PhpAcme\Exception\ConfigException;

/**
 * Cloudflare（acme.sh 里的 dns_cf）。
 *
 * 两种鉴权都支持：
 * - **API Token**（CF_Token，推荐）：可以精确授权到「只能改这一个 zone 的 DNS」，
 *   泄露了损失可控。需要 Zone:DNS:Edit 权限。
 * - Global API Key（CF_Key + CF_Email）：等于账号密码，能干任何事，
 *   包括删域名。除非用的是很老的教程，否则别用它。
 */
class Cloudflare extends AbstractDnsProvider
{
    const API = 'https://api.cloudflare.com/client/v4';

    public function getName(): string
    {
        return 'Cloudflare';
    }

    protected function findZone(string $domain): ?string
    {
        $data = $this->requestJson(
            'GET',
            self::API . '/zones?' . http_build_query(['name' => $domain, 'status' => 'active']),
            null,
            $this->authHeaders()
        );

        if (!isset($data['result']) || !\is_array($data['result'])) {
            return null;
        }

        foreach ($data['result'] as $zone) {
            if (\is_array($zone) && isset($zone['id'], $zone['name']) && strtolower((string) $zone['name']) === $domain) {
                return (string) $zone['id'];
            }
        }

        return null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $this->requestJson(
            'POST',
            sprintf('%s/zones/%s/dns_records', self::API, $zone['id']),
            [
                'type' => 'TXT',
                'name' => rtrim($fqdn, '.'),
                'content' => $value,
                // TTL 给 120（Cloudflare 允许的最小值是 60，1 表示 auto）。
                // 用小 TTL 是为了让上一轮的残留记录尽快过期
                'ttl' => 120,
            ],
            $this->authHeaders()
        );
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $data = $this->requestJson(
            'GET',
            sprintf('%s/zones/%s/dns_records?', self::API, $zone['id']) . http_build_query([
                'type' => 'TXT',
                'name' => rtrim($fqdn, '.'),
                'content' => $value,
            ]),
            null,
            $this->authHeaders()
        );

        if (!isset($data['result']) || !\is_array($data['result'])) {
            return;
        }

        foreach ($data['result'] as $record) {
            if (!\is_array($record) || !isset($record['id'])) {
                continue;
            }

            $this->requestJson(
                'DELETE',
                sprintf('%s/zones/%s/dns_records/%s', self::API, $zone['id'], $record['id']),
                null,
                $this->authHeaders()
            );
        }
    }

    /** @return array<string, string> */
    private function authHeaders(): array
    {
        $token = $this->optional('CF_Token');
        if ($token !== '') {
            return ['Authorization' => 'Bearer ' . $token];
        }

        $key = $this->optional('CF_Key');
        $email = $this->optional('CF_Email');

        if ($key !== '' && $email !== '') {
            return ['X-Auth-Key' => $key, 'X-Auth-Email' => $email];
        }

        throw new ConfigException(
            'Cloudflare 需要凭据：推荐设 CF_Token（在 Cloudflare 控制台创建 API Token，'
            . '权限选 Zone:DNS:Edit）；也可以用旧式的 CF_Key + CF_Email（Global API Key）'
        );
    }
}
