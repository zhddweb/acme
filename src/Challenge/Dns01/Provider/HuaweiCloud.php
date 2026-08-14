<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Dns01\Provider;

use Mci\Acme\Challenge\Dns01\AbstractDnsProvider;
use Mci\Acme\Exception\DnsException;
use Mci\Acme\Util\Json;

/**
 * 华为云 DNS（acme.sh 里的 dns_huaweicloud）。
 *
 * 签名是 SDK-HMAC-SHA256，结构与 AWS SigV4 同源但简化了：没有区域与服务的
 * 逐层派生，直接用 SK 签一次。要点是**头必须全部参与签名**、
 * 名字小写、按字典序，且 X-Sdk-Date 是 UTC。
 *
 * 凭据：HUAWEICLOUD_AccessKey、HUAWEICLOUD_SecretKey。
 * 在「我的凭证 -> 访问密钥」创建，权限给 DNS ReadWriteAccess。
 */
class HuaweiCloud extends AbstractDnsProvider
{
    const HOST = 'dns.myhuaweicloud.com';

    public function getName(): string
    {
        return '华为云 DNS';
    }

    protected function findZone(string $domain): ?string
    {
        // 华为云的 zone name 带尾点
        $data = $this->call('GET', '/v2/zones?' . http_build_query(['name' => $domain . '.', 'limit' => 50]));

        if (!isset($data['zones']) || !\is_array($data['zones'])) {
            return null;
        }

        $target = rtrim(strtolower($domain), '.') . '.';
        foreach ($data['zones'] as $zone) {
            if (\is_array($zone) && isset($zone['id'], $zone['name'])
                && strtolower((string) $zone['name']) === $target) {
                return (string) $zone['id'];
            }
        }

        return null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);
        $name = rtrim(strtolower($fqdn), '.') . '.';

        $existing = $this->findRecordSet($zone['id'], $name);

        if ($existing === null) {
            $this->call('POST', sprintf('/v2/zones/%s/recordsets', $zone['id']), [
                'name' => $name,
                'type' => 'TXT',
                'ttl' => 300,
                // 华为云要求 TXT 值自带引号
                'records' => ['"' . $value . '"'],
            ]);

            return;
        }

        // 同名记录集已存在（通配符 + 裸域的情况），追加值而不是新建，
        // 华为云不允许同名同类型的两个记录集
        $records = $existing['records'];
        $records[] = '"' . $value . '"';

        $this->call(
            'PUT',
            sprintf('/v2/zones/%s/recordsets/%s', $zone['id'], $existing['id']),
            ['records' => array_values(array_unique($records)), 'ttl' => 300]
        );
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);
        $name = rtrim(strtolower($fqdn), '.') . '.';

        $existing = $this->findRecordSet($zone['id'], $name);
        if ($existing === null) {
            return;
        }

        $quoted = '"' . $value . '"';
        $remaining = array_values(array_filter(
            $existing['records'],
            static function (string $item) use ($quoted, $value): bool {
                return $item !== $quoted && trim($item, '"') !== $value;
            }
        ));

        if ($remaining === []) {
            $this->call('DELETE', sprintf('/v2/zones/%s/recordsets/%s', $zone['id'], $existing['id']));

            return;
        }

        $this->call(
            'PUT',
            sprintf('/v2/zones/%s/recordsets/%s', $zone['id'], $existing['id']),
            ['records' => $remaining, 'ttl' => 300]
        );
    }

    /**
     * @return array{id: string, records: array<int, string>}|null
     */
    private function findRecordSet(string $zoneId, string $name): ?array
    {
        $data = $this->call('GET', sprintf(
            '/v2/zones/%s/recordsets?%s',
            $zoneId,
            http_build_query(['type' => 'TXT', 'name' => $name])
        ));

        if (!isset($data['recordsets']) || !\is_array($data['recordsets'])) {
            return null;
        }

        foreach ($data['recordsets'] as $set) {
            if (!\is_array($set) || !isset($set['id'], $set['name'])) {
                continue;
            }
            if (strtolower((string) $set['name']) !== $name) {
                continue;
            }

            $records = [];
            if (isset($set['records']) && \is_array($set['records'])) {
                foreach ($set['records'] as $record) {
                    $records[] = (string) $record;
                }
            }

            return ['id' => (string) $set['id'], 'records' => $records];
        }

        return null;
    }

    /**
     * @param array|null $body
     * @return array
     */
    private function call(string $method, string $path, ?array $body = null): array
    {
        $accessKey = $this->required('HUAWEICLOUD_AccessKey', '华为云「我的凭证 -> 访问密钥」');
        $secretKey = $this->required('HUAWEICLOUD_SecretKey');

        $payload = $body !== null ? Json::encode($body) : '';

        $query = '';
        $questionMark = strpos($path, '?');
        if ($questionMark !== false) {
            $query = substr($path, $questionMark + 1);
            $path = substr($path, 0, $questionMark);
        }

        $date = gmdate('Ymd\THis\Z');

        $headers = ['host' => self::HOST, 'x-sdk-date' => $date];
        if ($payload !== '') {
            $headers['content-type'] = 'application/json';
        }
        ksort($headers, SORT_STRING);

        $canonicalHeaders = '';
        foreach ($headers as $name => $value) {
            $canonicalHeaders .= $name . ':' . trim($value) . "\n";
        }
        $signedHeaders = implode(';', array_keys($headers));

        // 华为云要求规范路径以 / 结尾
        $canonicalPath = str_ends_with($path, '/') ? $path : $path . '/';

        $canonicalRequest = implode("\n", [
            $method,
            $canonicalPath,
            $this->canonicalQuery($query),
            $canonicalHeaders,
            $signedHeaders,
            hash('sha256', $payload),
        ]);

        $stringToSign = implode("\n", ['SDK-HMAC-SHA256', $date, hash('sha256', $canonicalRequest)]);
        $signature = hash_hmac('sha256', $stringToSign, $secretKey);

        $requestHeaders = [
            'X-Sdk-Date' => $date,
            'Authorization' => sprintf(
                'SDK-HMAC-SHA256 Access=%s, SignedHeaders=%s, Signature=%s',
                $accessKey,
                $signedHeaders,
                $signature
            ),
        ];

        if ($payload !== '') {
            $requestHeaders['Content-Type'] = 'application/json';
        }

        $url = 'https://' . self::HOST . $path . ($query !== '' ? '?' . $query : '');
        $response = $this->send($method, $url, $payload !== '' ? $payload : null, $requestHeaders);

        if (!$response->isSuccess()) {
            $data = $response->tryJson();
            throw new DnsException(sprintf(
                '华为云 DNS 返回 HTTP %d：%s',
                $response->getStatus(),
                $data !== null ? $this->describeError($data) : substr($response->getBody(), 0, 200)
            ));
        }

        $data = $response->tryJson();

        return $data !== null ? $data : [];
    }

    private function canonicalQuery(string $query): string
    {
        if ($query === '') {
            return '';
        }

        $pairs = [];
        foreach (explode('&', $query) as $pair) {
            $parts = explode('=', $pair, 2);
            $pairs[] = [
                rawurlencode(rawurldecode($parts[0])),
                rawurlencode(isset($parts[1]) ? rawurldecode($parts[1]) : ''),
            ];
        }

        usort($pairs, static function (array $a, array $b): int {
            $result = strcmp($a[0], $b[0]);

            return $result !== 0 ? $result : strcmp($a[1], $b[1]);
        });

        $out = [];
        foreach ($pairs as $pair) {
            $out[] = $pair[0] . '=' . $pair[1];
        }

        return implode('&', $out);
    }
}
