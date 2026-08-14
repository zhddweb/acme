<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Dns01\Provider;

use Mci\Acme\Challenge\Dns01\AbstractDnsProvider;

/**
 * Linode DNS v4（acme.sh 里的 dns_linode_v4）。
 *
 * 凭据：LINODE_V4_API_KEY，需要 Domains 的读写权限。
 *
 * Linode 的解析生效慢是出了名的（官方说最长 15 分钟），
 * 用它时建议把 --dnssleep 调大，或者依赖内置的权威 NS 轮询。
 */
class Linode extends AbstractDnsProvider
{
    const API = 'https://api.linode.com/v4';

    public function getName(): string
    {
        return 'Linode';
    }

    protected function findZone(string $domain): ?string
    {
        // Linode 用 X-Filter 头传查询条件，不是查询串
        $data = $this->requestJson('GET', self::API . '/domains', null, array_merge(
            $this->authHeaders(),
            ['X-Filter' => \Mci\Acme\Util\Json::encode(['domain' => $domain])]
        ));

        if (!isset($data['data']) || !\is_array($data['data'])) {
            return null;
        }

        foreach ($data['data'] as $item) {
            if (\is_array($item) && isset($item['id'], $item['domain'])
                && strtolower((string) $item['domain']) === $domain) {
                return (string) $item['id'];
            }
        }

        return null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $this->requestJson(
            'POST',
            sprintf('%s/domains/%s/records', self::API, $zone['id']),
            [
                'type' => 'TXT',
                // Linode 的 zone 顶点用空串表示，不是 @
                'name' => $zone['record'] === '@' ? '' : $zone['record'],
                'target' => $value,
                'ttl_sec' => 300,
            ],
            $this->authHeaders()
        );
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);
        $name = $zone['record'] === '@' ? '' : $zone['record'];

        $data = $this->requestJson(
            'GET',
            sprintf('%s/domains/%s/records?page_size=500', self::API, $zone['id']),
            null,
            $this->authHeaders()
        );

        if (!isset($data['data']) || !\is_array($data['data'])) {
            return;
        }

        foreach ($data['data'] as $record) {
            if (!\is_array($record) || !isset($record['id'], $record['type'], $record['name'], $record['target'])) {
                continue;
            }
            if ((string) $record['type'] !== 'TXT'
                || (string) $record['name'] !== $name
                || (string) $record['target'] !== $value) {
                continue;
            }

            $this->send(
                'DELETE',
                sprintf('%s/domains/%s/records/%s', self::API, $zone['id'], $record['id']),
                null,
                $this->authHeaders()
            );
        }
    }

    /** @return array<string, string> */
    private function authHeaders(): array
    {
        return ['Authorization' => 'Bearer ' . $this->required('LINODE_V4_API_KEY')];
    }
}
