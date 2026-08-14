<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Dns01\Provider;

use Mci\Acme\Challenge\Dns01\AbstractDnsProvider;

/**
 * GoDaddy（acme.sh 里的 dns_gd）。
 *
 * 鉴权很简单：`Authorization: sso-key <key>:<secret>`。
 *
 * 但它的记录接口是**按 (类型, 名字) 整组替换**的 PUT，没有单条删除。
 * 所以同名多值必须一次性提交全部值——通配符与裸域同时验证时这点是刚需。
 * 删除也只能靠「提交剩下的值」，全删光时 GoDaddy 允许提交空数组。
 *
 * 凭据：GD_Key、GD_Secret。注意 GoDaddy 对新账号的 API 有域名数量门槛，
 * 小账号可能拿不到生产环境 key。
 */
class GoDaddy extends AbstractDnsProvider
{
    const API = 'https://api.godaddy.com/v1';

    public function getName(): string
    {
        return 'GoDaddy';
    }

    protected function findZone(string $domain): ?string
    {
        $response = $this->send('GET', self::API . '/domains/' . rawurlencode($domain), null, $this->authHeaders());

        if (!$response->isSuccess()) {
            return null;
        }

        $data = $response->tryJson();

        return $data !== null && isset($data['domain']) ? $domain : null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $values = $this->listValues($zone['zone'], $zone['record']);
        $values[] = $value;

        $this->replace($zone['zone'], $zone['record'], array_values(array_unique($values)));
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $values = array_values(array_filter(
            $this->listValues($zone['zone'], $zone['record']),
            static function (string $item) use ($value): bool {
                return $item !== $value;
            }
        ));

        if ($values === []) {
            // 整组删除走 DELETE；提交空数组 GoDaddy 会报 422
            $this->send(
                'DELETE',
                sprintf('%s/domains/%s/records/TXT/%s', self::API, rawurlencode($zone['zone']), rawurlencode($zone['record'])),
                null,
                $this->authHeaders()
            );

            return;
        }

        $this->replace($zone['zone'], $zone['record'], $values);
    }

    /**
     * @return array<int, string>
     */
    private function listValues(string $zone, string $record): array
    {
        $response = $this->send(
            'GET',
            sprintf('%s/domains/%s/records/TXT/%s', self::API, rawurlencode($zone), rawurlencode($record)),
            null,
            $this->authHeaders()
        );

        if (!$response->isSuccess()) {
            return [];
        }

        $data = $response->tryJson();
        if ($data === null) {
            return [];
        }

        $out = [];
        foreach ($data as $item) {
            if (\is_array($item) && isset($item['data'])) {
                $out[] = (string) $item['data'];
            }
        }

        return $out;
    }

    /**
     * @param array<int, string> $values
     */
    private function replace(string $zone, string $record, array $values): void
    {
        $payload = [];
        foreach ($values as $value) {
            $payload[] = ['data' => $value, 'ttl' => 600];
        }

        $this->requestJson(
            'PUT',
            sprintf('%s/domains/%s/records/TXT/%s', self::API, rawurlencode($zone), rawurlencode($record)),
            $payload,
            $this->authHeaders()
        );
    }

    /** @return array<string, string> */
    private function authHeaders(): array
    {
        return [
            'Authorization' => sprintf(
                'sso-key %s:%s',
                $this->required('GD_Key', 'https://developer.godaddy.com/keys 创建'),
                $this->required('GD_Secret')
            ),
        ];
    }
}
