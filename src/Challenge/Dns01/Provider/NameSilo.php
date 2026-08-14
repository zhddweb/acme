<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01\Provider;

use PhpAcme\Challenge\Dns01\AbstractDnsProvider;
use PhpAcme\Exception\DnsException;

/**
 * NameSilo（acme.sh 里的 dns_namesilo）。
 *
 * 老派接口：全部参数走 URL 查询串，响应是 XML。这里同样用正则提取
 * ——结构固定，不值得为它引入 XML 扩展依赖。
 *
 * 凭据：Namesilo_Key。在账号的 API Manager 里生成，注意要勾上
 * 「允许从任意 IP 访问」或把服务器 IP 加白。
 *
 * NameSilo 的解析生效有 15 分钟左右的延迟，是所有主流商里最慢的之一，
 * 用它签发时要有耐心。
 */
class NameSilo extends AbstractDnsProvider
{
    const API = 'https://www.namesilo.com/api';

    public function getName(): string
    {
        return 'NameSilo';
    }

    protected function findZone(string $domain): ?string
    {
        $xml = $this->call('dnsListRecords', ['domain' => $domain], false);

        return $xml !== null ? $domain : null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $this->call('dnsAddRecord', [
            'domain' => $zone['zone'],
            'rrtype' => 'TXT',
            // NameSilo 的 zone 顶点用空串
            'rrhost' => $zone['record'] === '@' ? '' : $zone['record'],
            'rrvalue' => $value,
            'rrttl' => '3600',
        ]);
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $zone = $this->resolveZone($fqdn);

        $xml = $this->call('dnsListRecords', ['domain' => $zone['zone']], false);
        if ($xml === null) {
            return;
        }

        $target = rtrim(strtolower($fqdn), '.');

        if (preg_match_all('#<resource_record>(.*?)</resource_record>#s', $xml, $blocks) === false) {
            return;
        }

        foreach ($blocks[1] as $block) {
            if (preg_match('#<type>([^<]*)</type>#', $block, $type) !== 1 || $type[1] !== 'TXT') {
                continue;
            }
            if (preg_match('#<host>([^<]*)</host>#', $block, $host) !== 1
                || strtolower($host[1]) !== $target) {
                continue;
            }
            if (preg_match('#<value>([^<]*)</value>#', $block, $recordValue) !== 1
                || $recordValue[1] !== $value) {
                continue;
            }
            if (preg_match('#<record_id>([^<]*)</record_id>#', $block, $id) !== 1) {
                continue;
            }

            $this->call('dnsDeleteRecord', ['domain' => $zone['zone'], 'rrid' => $id[1]]);
        }
    }

    /**
     * @param array<string, string> $params
     * @return string|null XML 文本
     */
    private function call(string $operation, array $params, bool $throwOnError = true): ?string
    {
        $params = array_merge($params, [
            'version' => '1',
            'type' => 'xml',
            'key' => $this->required('Namesilo_Key', 'NameSilo 账号 -> API Manager 生成'),
        ]);

        $url = sprintf('%s/%s?%s', self::API, $operation, http_build_query($params));
        $response = $this->send('GET', $url);
        $body = $response->getBody();

        // NameSilo 的 HTTP 状态永远 200，成功码是 reply.code = 300
        if (preg_match('#<code>(\d+)</code>#', $body, $code) !== 1 || $code[1] !== '300') {
            if (!$throwOnError) {
                return null;
            }

            $detail = preg_match('#<detail>([^<]*)</detail>#', $body, $m) === 1 ? $m[1] : '未知错误';

            throw new DnsException(sprintf(
                'NameSilo 返回错误码 %s：%s',
                isset($code[1]) ? $code[1] : '未知',
                $detail
            ));
        }

        return $body;
    }
}
