<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01\Provider;

use PhpAcme\Challenge\Dns01\AbstractDnsProvider;

/**
 * Gandi LiveDNS（acme.sh 里的 dns_gandi_livedns）。
 *
 * 凭据：GANDI_LIVEDNS_KEY（旧版 API Key）或 GANDI_LIVEDNS_TOKEN（新版 PAT）。
 * Gandi 正在把旧 key 下线，新账号只能拿到 PAT。
 *
 * 它的记录接口也是按 (名字, 类型) 整组替换的，同名多值要一起提交。
 */
class Gandi extends AbstractDnsProvider
{
    const API = 'https://api.gandi.net/v5/livedns';

    public function getName(): string
    {
        return 'Gandi LiveDNS';
    }

    protected function findZone(string $domain): ?string
    {
        $response = $this->send('GET', self::API . '/domains/' . rawurlencode($domain), null, $this->authHeaders());

        return $response->isSuccess() ? $domain : null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $values = $this->listValues($zone['zone'], $zone['record']);
        $values[] = '"' . $value . '"';

        $this->requestJson(
            'PUT',
            sprintf('%s/domains/%s/records/%s/TXT', self::API, rawurlencode($zone['zone']), rawurlencode($zone['record'])),
            ['rrset_values' => array_values(array_unique($values)), 'rrset_ttl' => 300],
            $this->authHeaders()
        );
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $quoted = '"' . $value . '"';
        $values = array_values(array_filter(
            $this->listValues($zone['zone'], $zone['record']),
            static function (string $item) use ($quoted, $value): bool {
                return $item !== $quoted && trim($item, '"') !== $value;
            }
        ));

        $url = sprintf(
            '%s/domains/%s/records/%s/TXT',
            self::API,
            rawurlencode($zone['zone']),
            rawurlencode($zone['record'])
        );

        if ($values === []) {
            $this->send('DELETE', $url, null, $this->authHeaders());

            return;
        }

        $this->requestJson('PUT', $url, ['rrset_values' => $values, 'rrset_ttl' => 300], $this->authHeaders());
    }

    /**
     * @return array<int, string>
     */
    private function listValues(string $zone, string $record): array
    {
        $response = $this->send(
            'GET',
            sprintf('%s/domains/%s/records/%s/TXT', self::API, rawurlencode($zone), rawurlencode($record)),
            null,
            $this->authHeaders()
        );

        if (!$response->isSuccess()) {
            return [];
        }

        $data = $response->tryJson();
        if ($data === null || !isset($data['rrset_values']) || !\is_array($data['rrset_values'])) {
            return [];
        }

        $out = [];
        foreach ($data['rrset_values'] as $value) {
            $out[] = (string) $value;
        }

        return $out;
    }

    /** @return array<string, string> */
    private function authHeaders(): array
    {
        $token = $this->optional('GANDI_LIVEDNS_TOKEN');
        if ($token !== '') {
            return ['Authorization' => 'Bearer ' . $token];
        }

        return ['Authorization' => 'Apikey ' . $this->required(
            'GANDI_LIVEDNS_KEY',
            '新账号请改用 GANDI_LIVEDNS_TOKEN（个人访问令牌）'
        )];
    }
}
