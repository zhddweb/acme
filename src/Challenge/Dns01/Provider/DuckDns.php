<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01\Provider;

use PhpAcme\Challenge\Dns01\AbstractDnsProvider;
use PhpAcme\Exception\DnsException;
use PhpAcme\Util\Domain;

/**
 * DuckDNS（acme.sh 里的 dns_duckdns）。
 *
 * 免费动态域名服务，接口简单到只有一个 GET。限制也相应地大：
 *
 * - 每个子域**只能有一条** TXT 记录，写新的会覆盖旧的。
 *   这意味着 `example.duckdns.org` 与 `*.example.duckdns.org`
 *   **不能同时**签发——两者的挑战记录同名，后写的会冲掉前一条。
 *   真要通配符就单独签，别和裸域放在一张证书里。
 * - 只能管 *.duckdns.org 下自己的子域。
 *
 * 凭据：DuckDNS_Token。
 */
class DuckDns extends AbstractDnsProvider
{
    const API = 'https://www.duckdns.org/update';

    public function getName(): string
    {
        return 'DuckDNS';
    }

    protected function findZone(string $domain): ?string
    {
        // DuckDNS 没有查询接口，zone 恒为 duckdns.org 下的那一级子域
        return str_ends_with($domain, '.duckdns.org') ? $domain : null;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $this->update($fqdn, $value);
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        // 用 clear=true 清空，DuckDNS 没有删除单条的概念
        $this->update($fqdn, '', true);
    }

    private function update(string $fqdn, string $value, bool $clear = false): void
    {
        $token = $this->required('DuckDNS_Token', '登录 duckdns.org 首页即可看到');

        // 记录名要去掉 _acme-challenge 前缀和 .duckdns.org 后缀，
        // DuckDNS 的 domains 参数要的是子域名本身
        $subdomain = Domain::stripWildcard(rtrim(strtolower($fqdn), '.'));
        $subdomain = preg_replace('/^_acme-challenge\./', '', $subdomain);
        $subdomain = preg_replace('/\.duckdns\.org$/', '', $subdomain);

        $params = ['domains' => $subdomain, 'token' => $token, 'txt' => $value];
        if ($clear) {
            $params['clear'] = 'true';
        }

        $response = $this->send('GET', self::API . '?' . http_build_query($params));

        // 响应体就一个单词：OK 或 KO
        if (trim($response->getBody()) !== 'OK') {
            throw new DnsException(sprintf(
                'DuckDNS 更新失败（返回 %s）。确认 token 正确，且 %s 是你账号下的子域',
                trim($response->getBody()),
                $subdomain
            ));
        }
    }
}
