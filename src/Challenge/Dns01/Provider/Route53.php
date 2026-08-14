<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01\Provider;

use PhpAcme\Challenge\Dns01\AbstractDnsProvider;
use PhpAcme\Exception\DnsException;

/**
 * AWS Route 53（acme.sh 里的 dns_aws）。
 *
 * 两个特别之处：
 *
 * 1. **接口是 XML 不是 JSON**。这是 AWS 的老接口，至今没有 JSON 版本。
 *    响应结构固定且简单，用正则提取比拉一个 XML 扩展依赖更划算
 *    ——ext-simplexml 在精简的 PHP 环境里经常没装。
 *
 * 2. **Route53 的签名区域恒为 us-east-1**，不管 zone 实际在哪。
 *    它是全局服务，签成别的区域会得到 SignatureDoesNotMatch。
 *
 * 凭据：AWS_ACCESS_KEY_ID、AWS_SECRET_ACCESS_KEY，
 * 可选 AWS_SESSION_TOKEN（用 STS 临时凭据时）。
 */
class Route53 extends AbstractDnsProvider
{
    const HOST = 'route53.amazonaws.com';
    const REGION = 'us-east-1';
    const SERVICE = 'route53';
    const API_VERSION = '2013-04-01';

    public function getName(): string
    {
        return 'AWS Route 53';
    }

    protected function findZone(string $domain): ?string
    {
        // ListHostedZonesByName 按字典序返回，从给定名字开始。
        // 只要第一页里有精确匹配就行
        $xml = $this->call('GET', sprintf(
            '/%s/hostedzonesbyname?dnsname=%s&maxitems=10',
            self::API_VERSION,
            rawurlencode($domain)
        ));

        $target = rtrim(strtolower($domain), '.') . '.';

        // 每个 HostedZone 块里有 Id 与 Name，成对提取才不会错配
        if (preg_match_all('#<HostedZone>(.*?)</HostedZone>#s', $xml, $blocks) === false) {
            return null;
        }

        foreach ($blocks[1] as $block) {
            if (preg_match('#<Name>([^<]+)</Name>#', $block, $nameMatch) !== 1) {
                continue;
            }
            if (strtolower($nameMatch[1]) !== $target) {
                continue;
            }
            if (preg_match('#<Id>([^<]+)</Id>#', $block, $idMatch) !== 1) {
                continue;
            }

            // Id 的形式是 /hostedzone/Z123ABC，后面调用只要末段
            return basename(trim($idMatch[1]));
        }

        return null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        // Route53 的 UPSERT 是**整组覆盖**：同名同类型的记录集会被整体替换。
        // 所以要先把已有的值读出来一起提交，否则通配符与裸域同时验证时
        // 后写的那条会把先写的冲掉
        $existing = $this->listExistingValues($fqdn);
        $existing[] = $value;

        $this->changeRecord($fqdn, array_values(array_unique($existing)), 'UPSERT');
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $existing = $this->listExistingValues($fqdn);

        $remaining = array_values(array_filter($existing, static function (string $item) use ($value): bool {
            return $item !== $value;
        }));

        if ($remaining === $existing) {
            // 本来就没有这条，无事可做
            return;
        }

        if ($remaining === []) {
            // 记录集不能为空，只能整条删掉。DELETE 要求提交的内容与现存的完全一致
            $this->changeRecord($fqdn, $existing, 'DELETE');

            return;
        }

        $this->changeRecord($fqdn, $remaining, 'UPSERT');
    }

    /**
     * @return array<int, string>
     */
    private function listExistingValues(string $fqdn): array
    {
        $zone = $this->resolveZone($fqdn);
        $name = rtrim(strtolower($fqdn), '.') . '.';

        $xml = $this->call('GET', sprintf(
            '/%s/hostedzone/%s/rrset?name=%s&type=TXT&maxitems=1',
            self::API_VERSION,
            $zone['id'],
            rawurlencode($name)
        ));

        if (preg_match('#<ResourceRecordSet>(.*?)</ResourceRecordSet>#s', $xml, $block) !== 1) {
            return [];
        }

        // 确认这个记录集就是我们要的那个：查询是「从这个名字开始」，
        // 没有精确匹配时会返回后面的其他记录
        if (preg_match('#<Name>([^<]+)</Name>#', $block[1], $nameMatch) !== 1
            || strtolower($nameMatch[1]) !== $name) {
            return [];
        }

        if (preg_match_all('#<Value>([^<]*)</Value>#', $block[1], $values) === false) {
            return [];
        }

        $out = [];
        foreach ($values[1] as $value) {
            // Route53 的 TXT 值在 XML 里是带引号存的，去掉才是真实值
            $out[] = trim($this->decodeXml($value), '"');
        }

        return $out;
    }

    /**
     * @param array<int, string> $values
     */
    private function changeRecord(string $fqdn, array $values, string $action): void
    {
        $zone = $this->resolveZone($fqdn);
        $name = rtrim(strtolower($fqdn), '.') . '.';

        $records = '';
        foreach ($values as $value) {
            $records .= sprintf(
                '<ResourceRecord><Value>%s</Value></ResourceRecord>',
                $this->encodeXml('"' . $value . '"')
            );
        }

        $body = sprintf(
            '<?xml version="1.0" encoding="UTF-8"?>'
            . '<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/%s/">'
            . '<ChangeBatch><Changes><Change>'
            . '<Action>%s</Action>'
            . '<ResourceRecordSet><Name>%s</Name><Type>TXT</Type><TTL>60</TTL>'
            . '<ResourceRecords>%s</ResourceRecords>'
            . '</ResourceRecordSet></Change></Changes></ChangeBatch>'
            . '</ChangeResourceRecordSetsRequest>',
            self::API_VERSION,
            $action,
            $this->encodeXml($name),
            $records
        );

        $this->call('POST', sprintf('/%s/hostedzone/%s/rrset/', self::API_VERSION, $zone['id']), $body);
    }

    /**
     * 发一次 SigV4 签名的请求，返回 XML 文本。
     */
    private function call(string $method, string $path, string $body = ''): string
    {
        $accessKey = $this->required('AWS_ACCESS_KEY_ID', 'IAM 用户需要 route53:ChangeResourceRecordSets 权限');
        $secretKey = $this->required('AWS_SECRET_ACCESS_KEY');
        $sessionToken = $this->optional('AWS_SESSION_TOKEN');

        // 查询串要和路径分开：签名里它们是两个不同的字段
        $query = '';
        $questionMark = strpos($path, '?');
        if ($questionMark !== false) {
            $query = substr($path, $questionMark + 1);
            $path = substr($path, 0, $questionMark);
        }

        $timestamp = time();
        $amzDate = gmdate('Ymd\THis\Z', $timestamp);
        $dateStamp = gmdate('Ymd', $timestamp);

        $headers = ['host' => self::HOST, 'x-amz-date' => $amzDate];
        if ($sessionToken !== '') {
            $headers['x-amz-security-token'] = $sessionToken;
        }

        ksort($headers, SORT_STRING);

        $canonicalHeaders = '';
        foreach ($headers as $name => $value) {
            $canonicalHeaders .= $name . ':' . $value . "\n";
        }
        $signedHeaders = implode(';', array_keys($headers));

        $canonicalRequest = implode("\n", [
            $method,
            $path,
            $this->canonicalQuery($query),
            $canonicalHeaders,
            $signedHeaders,
            hash('sha256', $body),
        ]);

        $credentialScope = sprintf('%s/%s/%s/aws4_request', $dateStamp, self::REGION, self::SERVICE);
        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256',
            $amzDate,
            $credentialScope,
            hash('sha256', $canonicalRequest),
        ]);

        $kDate = hash_hmac('sha256', $dateStamp, 'AWS4' . $secretKey, true);
        $kRegion = hash_hmac('sha256', self::REGION, $kDate, true);
        $kService = hash_hmac('sha256', self::SERVICE, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        $signature = hash_hmac('sha256', $stringToSign, $kSigning);

        $requestHeaders = [
            'X-Amz-Date' => $amzDate,
            'Authorization' => sprintf(
                'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s',
                $accessKey,
                $credentialScope,
                $signedHeaders,
                $signature
            ),
        ];

        if ($sessionToken !== '') {
            $requestHeaders['X-Amz-Security-Token'] = $sessionToken;
        }
        if ($body !== '') {
            $requestHeaders['Content-Type'] = 'text/xml';
        }

        $url = 'https://' . self::HOST . $path . ($query !== '' ? '?' . $query : '');
        $response = $this->send($method, $url, $body !== '' ? $body : null, $requestHeaders);

        if (!$response->isSuccess()) {
            $message = '';
            if (preg_match('#<Message>([^<]+)</Message>#', $response->getBody(), $m) === 1) {
                $message = $this->decodeXml($m[1]);
            }

            throw new DnsException(sprintf(
                'Route 53 返回 HTTP %d：%s',
                $response->getStatus(),
                $message !== '' ? $message : substr($response->getBody(), 0, 200)
            ));
        }

        return $response->getBody();
    }

    /**
     * 规范化查询串：参数按名字排序，键值都要 percent-encode。
     */
    private function canonicalQuery(string $query): string
    {
        if ($query === '') {
            return '';
        }

        $pairs = [];
        foreach (explode('&', $query) as $pair) {
            $parts = explode('=', $pair, 2);
            $key = rawurldecode($parts[0]);
            $value = isset($parts[1]) ? rawurldecode($parts[1]) : '';
            $pairs[] = [rawurlencode($key), rawurlencode($value)];
        }

        usort($pairs, static function (array $a, array $b): int {
            $result = strcmp($a[0], $b[0]);

            // 同名参数按值排，保证顺序确定
            return $result !== 0 ? $result : strcmp($a[1], $b[1]);
        });

        $out = [];
        foreach ($pairs as $pair) {
            $out[] = $pair[0] . '=' . $pair[1];
        }

        return implode('&', $out);
    }

    private function encodeXml(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }

    private function decodeXml(string $value): string
    {
        return htmlspecialchars_decode($value, ENT_XML1 | ENT_QUOTES);
    }
}
