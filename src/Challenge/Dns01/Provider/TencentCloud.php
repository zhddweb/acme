<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01\Provider;

use PhpAcme\Challenge\Dns01\AbstractDnsProvider;
use PhpAcme\Exception\DnsException;
use PhpAcme\Util\Json;

/**
 * 腾讯云 DNSPod v3 接口（acme.sh 里的 dns_tencent）。
 *
 * 和 DnsPod 那个类的区别：这里走腾讯云统一的 API 网关，用 TC3-HMAC-SHA256
 * 签名、按 CAM 授权，凭据是云账号的 SecretId/SecretKey。新用户应该用这个，
 * 老的 login_token 接口腾讯已经不推荐了。
 *
 * TC3 签名分三步（和 AWS SigV4 同源，细节不同）：
 * 1. 拼规范请求串（方法、路径、查询串、头、载荷哈希）
 * 2. 拼待签串（算法、时间戳、凭证范围、规范请求串的哈希）
 * 3. 用 SecretKey 逐层派生出签名密钥再签
 *
 * 凭据：Tencent_SecretId、Tencent_SecretKey。
 */
class TencentCloud extends AbstractDnsProvider
{
    const HOST = 'dnspod.tencentcloudapi.com';
    const SERVICE = 'dnspod';
    const VERSION = '2021-03-23';

    public function getName(): string
    {
        return '腾讯云 DNSPod';
    }

    protected function findZone(string $domain): ?string
    {
        $data = $this->call('DescribeDomain', ['Domain' => $domain], false);

        if ($data === null || !isset($data['Response']['DomainInfo']['DomainId'])) {
            return null;
        }

        return (string) $data['Response']['DomainInfo']['DomainId'];
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $this->call('CreateRecord', [
            'Domain' => $zone['zone'],
            'SubDomain' => $zone['record'],
            'RecordType' => 'TXT',
            'RecordLine' => '默认',
            'Value' => $value,
            'TTL' => 600,
        ]);
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $data = $this->call('DescribeRecordList', [
            'Domain' => $zone['zone'],
            'Subdomain' => $zone['record'],
            'RecordType' => 'TXT',
        ], false);

        if ($data === null || !isset($data['Response']['RecordList'])) {
            return;
        }

        foreach ($data['Response']['RecordList'] as $record) {
            if (!\is_array($record) || !isset($record['RecordId'], $record['Value'])) {
                continue;
            }
            if ((string) $record['Value'] !== $value) {
                continue;
            }

            $this->call('DeleteRecord', [
                'Domain' => $zone['zone'],
                'RecordId' => (int) $record['RecordId'],
            ]);
        }
    }

    /**
     * @param array<string, mixed> $payload
     * @return array|null
     */
    private function call(string $action, array $payload, bool $throwOnError = true): ?array
    {
        $secretId = $this->required('Tencent_SecretId', '腾讯云控制台 -> 访问管理 -> API 密钥管理');
        $secretKey = $this->required('Tencent_SecretKey');

        $body = Json::encode($payload);
        $timestamp = time();

        $headers = [
            'Content-Type' => 'application/json; charset=utf-8',
            'Host' => self::HOST,
            'X-TC-Action' => $action,
            'X-TC-Timestamp' => (string) $timestamp,
            'X-TC-Version' => self::VERSION,
        ];

        $headers['Authorization'] = $this->buildAuthorization($secretId, $secretKey, $body, $timestamp, $action);

        $response = $this->send('POST', 'https://' . self::HOST . '/', $body, $headers);
        $data = $response->tryJson();

        if ($data === null) {
            if (!$throwOnError) {
                return null;
            }

            throw new DnsException(sprintf(
                '腾讯云返回了非 JSON 内容（HTTP %d）：%s',
                $response->getStatus(),
                substr($response->getBody(), 0, 200)
            ));
        }

        // 腾讯云的业务错误也是 HTTP 200，要看 Response.Error
        if (isset($data['Response']['Error'])) {
            if (!$throwOnError) {
                return null;
            }

            throw new DnsException(sprintf(
                '腾讯云返回错误 %s：%s',
                isset($data['Response']['Error']['Code']) ? (string) $data['Response']['Error']['Code'] : '未知',
                isset($data['Response']['Error']['Message']) ? (string) $data['Response']['Error']['Message'] : ''
            ));
        }

        return $data;
    }

    private function buildAuthorization(
        string $secretId,
        string $secretKey,
        string $body,
        int $timestamp,
        string $action
    ): string {
        $date = gmdate('Y-m-d', $timestamp);

        // 第一步：规范请求串。签名头固定取 content-type 与 host 两个，
        // 且必须小写、按字典序、值去掉首尾空白
        $canonicalHeaders = sprintf(
            "content-type:%s\nhost:%s\nx-tc-action:%s\n",
            'application/json; charset=utf-8',
            self::HOST,
            strtolower($action)
        );
        $signedHeaders = 'content-type;host;x-tc-action';

        $canonicalRequest = implode("\n", [
            'POST',
            '/',
            '',
            $canonicalHeaders,
            $signedHeaders,
            hash('sha256', $body),
        ]);

        // 第二步：待签串
        $credentialScope = $date . '/' . self::SERVICE . '/tc3_request';
        $stringToSign = implode("\n", [
            'TC3-HMAC-SHA256',
            (string) $timestamp,
            $credentialScope,
            hash('sha256', $canonicalRequest),
        ]);

        // 第三步：逐层派生签名密钥。每一层都用上一层的输出当密钥，
        // 这样即使某天的密钥泄露也推不出主密钥
        $secretDate = hash_hmac('sha256', $date, 'TC3' . $secretKey, true);
        $secretService = hash_hmac('sha256', self::SERVICE, $secretDate, true);
        $secretSigning = hash_hmac('sha256', 'tc3_request', $secretService, true);
        $signature = hash_hmac('sha256', $stringToSign, $secretSigning);

        return sprintf(
            'TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s',
            $secretId,
            $credentialScope,
            $signedHeaders,
            $signature
        );
    }
}
