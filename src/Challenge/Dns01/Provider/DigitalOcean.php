<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Dns01\Provider;

use Mci\Acme\Challenge\Dns01\AbstractDnsProvider;

/**
 * DigitalOcean（acme.sh 里的 dns_dgon）。
 *
 * 凭据：DO_API_KEY（个人访问令牌，需要 write 权限）。
 */
class DigitalOcean extends AbstractDnsProvider
{
    const API = 'https://api.digitalocean.com/v2';

    public function getName(): string
    {
        return 'DigitalOcean';
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
            sprintf(
                '%s/domains/%s/records?%s',
                self::API,
                rawurlencode($zone['zone']),
                http_build_query(['type' => 'TXT', 'name' => rtrim($fqdn, '.'), 'per_page' => 200])
            ),
            null,
            $this->authHeaders()
        );

        if (!isset($data['domain_records']) || !\is_array($data['domain_records'])) {
            return;
        }

        foreach ($data['domain_records'] as $record) {
            if (!\is_array($record) || !isset($record['id'], $record['data'])) {
                continue;
            }
            if ((string) $record['data'] !== $value) {
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
        return [
            'Authorization' => 'Bearer ' . $this->required('DO_API_KEY', 'https://cloud.digitalocean.com/account/api/tokens'),
        ];
    }
}
