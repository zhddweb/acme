<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Dns01\Provider;

use Mci\Acme\Challenge\Dns01\AbstractDnsProvider;

/**
 * Hetzner DNS（acme.sh 里的 dns_hetzner）。
 *
 * 凭据：HETZNER_Token，在 https://dns.hetzner.com/settings/api-token 创建。
 */
class Hetzner extends AbstractDnsProvider
{
    const API = 'https://dns.hetzner.com/api/v1';

    public function getName(): string
    {
        return 'Hetzner DNS';
    }

    protected function findZone(string $domain): ?string
    {
        $data = $this->requestJson(
            'GET',
            self::API . '/zones?' . http_build_query(['name' => $domain]),
            null,
            $this->authHeaders()
        );

        if (!isset($data['zones']) || !\is_array($data['zones'])) {
            return null;
        }

        foreach ($data['zones'] as $zone) {
            if (\is_array($zone) && isset($zone['id'], $zone['name'])
                && strtolower((string) $zone['name']) === $domain) {
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
            self::API . '/records',
            [
                'zone_id' => $zone['id'],
                'type' => 'TXT',
                'name' => $zone['record'],
                'value' => $value,
                'ttl' => 300,
            ],
            $this->authHeaders()
        );
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $data = $this->requestJson(
            'GET',
            self::API . '/records?' . http_build_query(['zone_id' => $zone['id'], 'per_page' => 500]),
            null,
            $this->authHeaders()
        );

        if (!isset($data['records']) || !\is_array($data['records'])) {
            return;
        }

        foreach ($data['records'] as $record) {
            if (!\is_array($record) || !isset($record['id'], $record['type'], $record['name'], $record['value'])) {
                continue;
            }
            if ((string) $record['type'] !== 'TXT'
                || (string) $record['name'] !== $zone['record']
                || (string) $record['value'] !== $value) {
                continue;
            }

            $this->send('DELETE', self::API . '/records/' . $record['id'], null, $this->authHeaders());
        }
    }

    /** @return array<string, string> */
    private function authHeaders(): array
    {
        return ['Auth-API-Token' => $this->required('HETZNER_Token')];
    }
}
