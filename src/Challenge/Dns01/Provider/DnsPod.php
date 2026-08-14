<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Dns01\Provider;

use Mci\Acme\Challenge\Dns01\AbstractDnsProvider;
use Mci\Acme\Exception\DnsException;

/**
 * DNSPod 国内版（acme.sh 里的 dns_dp）。
 *
 * 用的是老的 token 接口：登录令牌写成 `<ID>,<Token>` 一起提交，
 * 没有签名，全靠 HTTPS 保护。腾讯云新的 v3 接口见 TencentCloud。
 *
 * 凭据：DP_Id、DP_Key。在 DNSPod 控制台 -> 用户中心 -> 安全设置 -> API Token 创建。
 */
class DnsPod extends AbstractDnsProvider
{
    const API = 'https://dnsapi.cn';

    public function getName(): string
    {
        return 'DNSPod';
    }

    protected function findZone(string $domain): ?string
    {
        try {
            $data = $this->call('/Domain.Info', ['domain' => $domain]);
        } catch (DnsException $e) {
            return null;
        }

        return isset($data['domain']['id']) ? (string) $data['domain']['id'] : null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $this->call('/Record.Create', [
            'domain_id' => $zone['id'],
            'sub_domain' => $zone['record'],
            'record_type' => 'TXT',
            // 「默认」是 DNSPod 的线路名，免费套餐只有这一条
            'record_line' => '默认',
            'value' => $value,
            'ttl' => '600',
        ]);
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        try {
            $data = $this->call('/Record.List', [
                'domain_id' => $zone['id'],
                'sub_domain' => $zone['record'],
                'record_type' => 'TXT',
            ]);
        } catch (DnsException $e) {
            // 一条记录都没有时 DNSPod 会返回「没有记录」错误码，不是真失败
            return;
        }

        if (!isset($data['records']) || !\is_array($data['records'])) {
            return;
        }

        foreach ($data['records'] as $record) {
            if (!\is_array($record) || !isset($record['id'], $record['value'])) {
                continue;
            }
            if ((string) $record['value'] !== $value) {
                continue;
            }

            $this->call('/Record.Remove', [
                'domain_id' => $zone['id'],
                'record_id' => (string) $record['id'],
            ]);
        }
    }

    /**
     * @param array<string, string> $params
     * @return array
     */
    private function call(string $path, array $params): array
    {
        $id = $this->required('DP_Id', 'DNSPod 控制台 -> 用户中心 -> 安全设置 -> API Token');
        $key = $this->required('DP_Key');

        $params = array_merge($params, [
            'login_token' => $id . ',' . $key,
            'format' => 'json',
            'lang' => 'cn',
            'error_on_empty' => 'no',
        ]);

        $response = $this->send('POST', self::API . $path, http_build_query($params), [
            'Content-Type' => 'application/x-www-form-urlencoded',
            // DNSPod 要求带 UA 且必须包含联系邮箱，否则直接拒绝
            'User-Agent' => 'mci-acme/1.0 (https://github.com/likun-mci/acme)',
        ]);

        $data = $response->tryJson();
        if ($data === null) {
            throw new DnsException(sprintf(
                'DNSPod 返回了非 JSON 内容（HTTP %d）：%s',
                $response->getStatus(),
                substr($response->getBody(), 0, 200)
            ));
        }

        // DNSPod 的 HTTP 状态永远是 200，真正的结果看 status.code，'1' 才是成功
        $code = isset($data['status']['code']) ? (string) $data['status']['code'] : '-1';
        if ($code !== '1') {
            throw new DnsException(sprintf(
                'DNSPod 返回错误 %s：%s',
                $code,
                isset($data['status']['message']) ? (string) $data['status']['message'] : '未知错误'
            ));
        }

        return $data;
    }
}
