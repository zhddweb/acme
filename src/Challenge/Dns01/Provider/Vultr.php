<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Dns01\Provider;

use Mci\Acme\Challenge\Dns01\AbstractDnsProvider;

/**
 * Vultr（acme.sh 里的 dns_vultr）。
 *
 * 凭据：VULTR_API_KEY。注意 Vultr 的 API 默认有 IP 白名单，
 * 在控制台的 API 页面要把服务器 IP 加进去，否则一律 403。
 */
class Vultr extends AbstractDnsProvider
{
    const API = 'https://api.vultr.com/v2';

    public function getName(): string
    {
        return 'Vultr';
    }

    protected function findZone(string $domain): ?string
    {
        $response = $this->send('GET', self::API . '/domains/' . rawurlencode($domain), null, $this->authHeaders());

        return $response->isSuccess() ? $domain : null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $this->requestJson(
            'POST',
            sprintf('%s/domains/%s/records', self::API, rawurlencode($zone['zone'])),
            ['type' => 'TXT', 'name' => $zone['record'], 'data' => $value, 'ttl' => 300],
            $this->authHeaders()
        );
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $data = $this->requestJson(
            'GET',
            sprintf('%s/domains/%s/records?per_page=500', self::API, rawurlencode($zone['zone'])),
            null,
            $this->authHeaders()
        );

        if (!isset($data['records']) || !\is_array($data['records'])) {
            return;
        }

        foreach ($data['records'] as $record) {
            if (!\is_array($record) || !isset($record['id'], $record['type'], $record['name'], $record['data'])) {
                continue;
            }
            if ((string) $record['type'] !== 'TXT' || (string) $record['name'] !== $zone['record']) {
                continue;
            }
            // Vultr 返回的 TXT 值带引号
            if (trim((string) $record['data'], '"') !== $value) {
                continue;
            }

            $this->send(
                'DELETE',
                sprintf('%s/domains/%s/records/%s', self::API, rawurlencode($zone['zone']), $record['id']),
                null,
                $this->authHeaders()
            );
        }
    }

    /** @return array<string, string> */
    private function authHeaders(): array
    {
        return ['Authorization' => 'Bearer ' . $this->required('VULTR_API_KEY')];
    }
}
