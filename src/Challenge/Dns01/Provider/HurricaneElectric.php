<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01\Provider;

use PhpAcme\Challenge\Dns01\AbstractDnsProvider;
use PhpAcme\Exception\DnsException;

/**
 * Hurricane Electric 免费 DNS（acme.sh 里的 dns_he）。
 *
 * HE 没有正式的 REST API，只有一个给动态 DNS 用的接口：
 * 先在 web 界面上为 `_acme-challenge.<域名>` 建一条 TXT 记录并勾选
 * 「Enable entry for dynamic dns」，拿到该记录的动态更新密码，
 * 之后就能用这个接口改它的值。
 *
 * 所以它**不能自动创建记录**，只能改已存在的。首次使用需要手工建一次。
 * 凭据：HE_DDNS_Key（那条记录的动态更新密码）。
 */
class HurricaneElectric extends AbstractDnsProvider
{
    const API = 'https://dyn.dns.he.net/nic/update';

    public function getName(): string
    {
        return 'Hurricane Electric';
    }

    protected function findZone(string $domain): ?string
    {
        // 没有查询接口，直接认下来，由更新接口去报错
        return $domain;
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $this->update($fqdn, $value);
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        // 没法删除，只能把值置成一个占位串。留着一条无意义的 TXT
        // 比留着上一次的有效挑战值安全——后者会干扰下一次验证
        $this->update($fqdn, 'acme-challenge-cleared');
    }

    private function update(string $fqdn, string $value): void
    {
        $key = $this->required(
            'HE_DDNS_Key',
            '在 HE 控制台为该 TXT 记录勾选 dynamic dns 后获得的密码'
        );

        $response = $this->send('POST', self::API, http_build_query([
            'hostname' => rtrim(strtolower($fqdn), '.'),
            'password' => $key,
            'txt' => $value,
        ]), ['Content-Type' => 'application/x-www-form-urlencoded']);

        $body = trim($response->getBody());

        // 成功是 good 或 nochg（值没变），其余都是失败
        if (!str_starts_with($body, 'good') && !str_starts_with($body, 'nochg')) {
            throw new DnsException(sprintf(
                'Hurricane Electric 更新失败：%s。'
                . '确认已在控制台为 %s 建好 TXT 记录并启用了 dynamic dns',
                $body !== '' ? $body : '（空响应）',
                rtrim($fqdn, '.')
            ));
        }
    }
}
