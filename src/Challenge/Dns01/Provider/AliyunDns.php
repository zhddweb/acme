<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01\Provider;

use PhpAcme\Challenge\Dns01\AbstractDnsProvider;

/**
 * 阿里云 DNS（acme.sh 里的 dns_ali）。
 *
 * 用的是阿里云的 RPC 风格接口，签名算法是 HMAC-SHA1，规则很挑剔：
 * 参数要按名字字典序排、URL 编码要用 RFC 3986（PHP 的 rawurlencode
 * 已经是这个规则，但要额外把 `*` 编成 %2A、`~` 还原成 `~`）、
 * 待签名串是 `GET&%2F&<编码后的查询串>`。任何一步差一点就是
 * SignatureDoesNotMatch，而错误信息不会告诉你差在哪。
 *
 * 凭据：Ali_Key（AccessKey ID）、Ali_Secret（AccessKey Secret）。
 * 建议用 RAM 子账号并只授予 AliyunDNSFullAccess。
 */
class AliyunDns extends AbstractDnsProvider
{
    const API = 'https://alidns.aliyuncs.com/';

    public function getName(): string
    {
        return '阿里云 DNS';
    }

    protected function findZone(string $domain): ?string
    {
        $data = $this->call([
            'Action' => 'DescribeDomainRecords',
            'DomainName' => $domain,
            'PageSize' => '1',
        ], false);

        // 域名不在账号下时阿里云回的是 InvalidDomainName.NoExist，
        // call() 已经把它转成了 null
        return $data !== null ? $domain : null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $this->call([
            'Action' => 'AddDomainRecord',
            'DomainName' => $zone['zone'],
            'RR' => $zone['record'],
            'Type' => 'TXT',
            'Value' => $value,
            'TTL' => '600',
        ]);
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $data = $this->call([
            'Action' => 'DescribeDomainRecords',
            'DomainName' => $zone['zone'],
            'RRKeyWord' => $zone['record'],
            'TypeKeyWord' => 'TXT',
            'PageSize' => '100',
        ]);

        if ($data === null || !isset($data['DomainRecords']['Record'])) {
            return;
        }

        foreach ($data['DomainRecords']['Record'] as $record) {
            if (!\is_array($record) || !isset($record['RecordId'], $record['Value'])) {
                continue;
            }
            // 只删值也对得上的那条：同名 TXT 可能还有别的用途，
            // 更不能把另一个域名正在验证的记录删掉
            if ((string) $record['Value'] !== $value) {
                continue;
            }

            $this->call(['Action' => 'DeleteDomainRecord', 'RecordId' => (string) $record['RecordId']]);
        }
    }

    /**
     * 发一次已签名的 RPC 调用。
     *
     * @param array<string, string> $params
     * @param bool $throwOnError false 时把「域名不存在」这类错误转成 null
     * @return array|null
     */
    private function call(array $params, bool $throwOnError = true): ?array
    {
        $key = $this->required('Ali_Key', '在阿里云控制台 -> AccessKey 管理里创建');
        $secret = $this->required('Ali_Secret');

        $params = array_merge($params, [
            'Format' => 'JSON',
            'Version' => '2015-01-09',
            'AccessKeyId' => $key,
            'SignatureMethod' => 'HMAC-SHA1',
            // 必须是 UTC，且与服务端时差不能超过 15 分钟。
            // 机器时钟不准是这个接口第二常见的失败原因
            'Timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            'SignatureVersion' => '1.0',
            'SignatureNonce' => bin2hex(random_bytes(16)),
        ]);

        $params['Signature'] = $this->sign($params, $secret);

        $response = $this->send('POST', self::API, http_build_query($params, '', '&', PHP_QUERY_RFC3986), [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ]);

        $data = $response->tryJson();
        if ($data === null) {
            if ($throwOnError) {
                throw new \PhpAcme\Exception\DnsException(sprintf(
                    '阿里云 DNS 返回了非 JSON 内容（HTTP %d）：%s',
                    $response->getStatus(),
                    substr($response->getBody(), 0, 200)
                ));
            }

            return null;
        }

        if (!$response->isSuccess()) {
            if (!$throwOnError) {
                return null;
            }

            throw new \PhpAcme\Exception\DnsException(sprintf(
                '阿里云 DNS 返回错误：%s %s',
                isset($data['Code']) ? (string) $data['Code'] : 'HTTP ' . $response->getStatus(),
                isset($data['Message']) ? (string) $data['Message'] : ''
            ));
        }

        return $data;
    }

    /**
     * 阿里云 RPC 签名。
     *
     * @param array<string, string> $params
     */
    private function sign(array $params, string $secret): string
    {
        ksort($params, SORT_STRING);

        $pairs = [];
        foreach ($params as $name => $value) {
            $pairs[] = self::encode($name) . '=' . self::encode((string) $value);
        }

        $stringToSign = 'POST&' . self::encode('/') . '&' . self::encode(implode('&', $pairs));

        // 密钥要在末尾加一个 &，这是阿里云特有的规定
        return base64_encode(hash_hmac('sha1', $stringToSign, $secret . '&', true));
    }

    /**
     * 阿里云要求的 percent-encoding。
     *
     * rawurlencode 基本符合 RFC 3986，但 PHP 5.3 之前会把 `~` 编码掉，
     * 而 `*` 按 RFC 3986 属于 sub-delims 不该编——阿里云偏偏要求编。
     * 两处都手工修正。
     */
    private static function encode(string $value): string
    {
        return str_replace(['+', '*', '%7E'], ['%20', '%2A', '~'], rawurlencode($value));
    }
}
