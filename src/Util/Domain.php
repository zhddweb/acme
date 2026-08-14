<?php

declare(strict_types=1);

namespace Mci\Acme\Util;

use Mci\Acme\Exception\ConfigException;

/**
 * 域名处理：校验、通配符、以及 dns-01 最关键的「把域名切成 zone + 主机名」。
 *
 * 切 zone 这件事没有本地可靠解法：example.com 和 example.co.uk 的 zone 边界
 * 不看字符串是看不出来的，而完整的 Public Suffix List 有近万条、还会变。
 * 本库的做法和 acme.sh 一致——**由 DNS 提供商的 API 来裁决**：
 * 从最短的候选（com）一路试到最长（a.b.example.com），哪个能在账号下查到 zone
 * 就用哪个。下面的多级后缀表只是用来**跳过**那些明显不可能是 zone 的候选，
 * 减少无谓的 API 调用，不作为判定依据。
 */
final class Domain
{
    /**
     * 常见的多级公共后缀。
     *
     * 只收录实际会拿来签证书的那些。漏了不会出错，只是多打一两次 API；
     * 多收了才会出错（把真 zone 当成后缀跳过），所以宁可少列。
     *
     * @var array<int, string>
     */
    const MULTI_LEVEL_SUFFIXES = [
        'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn', 'mil.cn',
        'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'ac.uk', 'gov.uk',
        'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
        'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'ad.jp',
        'co.kr', 'or.kr', 'ne.kr', 're.kr', 'go.kr',
        'com.tw', 'net.tw', 'org.tw', 'edu.tw', 'gov.tw', 'idv.tw',
        'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk', 'idv.hk',
        'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
        'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
        'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.ve', 'com.ec',
        'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
        'com.my', 'net.my', 'org.my', 'edu.my', 'gov.my',
        'co.id', 'or.id', 'web.id', 'ac.id', 'go.id',
        'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
        'co.za', 'org.za', 'net.za', 'web.za',
        'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
        'com.ru', 'net.ru', 'org.ru', 'com.ua', 'com.pl', 'net.pl', 'org.pl',
        'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn',
        'com.ph', 'com.pk', 'com.bd', 'com.np', 'com.sa', 'com.eg', 'com.ng',
        'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il',
        'com.es', 'org.es', 'nom.es', 'gob.es',
        'co.th', 'in.th', 'ac.th', 'go.th', 'or.th',
        'eu.org', 'us.org', 'co.nl', 'co.at', 'or.at', 'co.de',
        's3.amazonaws.com', 'github.io', 'gitlab.io', 'herokuapp.com',
    ];

    /**
     * 归一化：去空白、去尾点、小写、IDN 转 A-label。
     *
     * 尾点（example.com.）在 DNS 里是合法的绝对域名写法，但 ACME 的 identifier
     * 不接受，必须去掉。
     */
    public static function normalize(string $domain): string
    {
        $domain = trim($domain);
        $domain = rtrim($domain, '.');
        if ($domain === '') {
            return '';
        }

        return Idn::toAscii($domain);
    }

    public static function isWildcard(string $domain): bool
    {
        return str_starts_with($domain, '*.');
    }

    /** 去掉通配符前缀，*.example.com -> example.com */
    public static function stripWildcard(string $domain): string
    {
        return self::isWildcard($domain) ? substr($domain, 2) : $domain;
    }

    /**
     * 校验域名是否可用于签发证书，不合法直接抛。
     *
     * 有意比 RFC 1035 宽松一点（允许下划线用于某些内网场景的 SAN），
     * 但通配符位置、标签长度这些 CA 一定会拒的必须提前拦下来——
     * 让用户在本地看到清楚的报错，好过跑到 CA 那里换回一句 rejectedIdentifier。
     */
    public static function validate(string $domain): void
    {
        if ($domain === '') {
            throw new ConfigException('域名不能为空');
        }

        if (\strlen($domain) > 253) {
            throw new ConfigException(sprintf('域名总长超过 253 字节：%s', $domain));
        }

        $bare = $domain;
        if (self::isWildcard($domain)) {
            $bare = substr($domain, 2);
            if (str_contains($bare, '*')) {
                // *.*.example.com 这种，CA 一律拒绝
                throw new ConfigException(sprintf('通配符只能出现在最左侧一级：%s', $domain));
            }
        } elseif (str_contains($domain, '*')) {
            throw new ConfigException(sprintf('通配符必须写成 *.example.com 的形式：%s', $domain));
        }

        if ($bare === '' || !str_contains($bare, '.')) {
            throw new ConfigException(sprintf('域名至少要有一个点：%s', $domain));
        }

        foreach (explode('.', $bare) as $label) {
            if ($label === '') {
                throw new ConfigException(sprintf('域名里有空标签（连续的点？）：%s', $domain));
            }
            if (\strlen($label) > 63) {
                throw new ConfigException(sprintf('域名标签「%s」超过 63 字节：%s', $label, $domain));
            }
            if (preg_match('/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/i', $label) !== 1) {
                throw new ConfigException(sprintf('域名标签「%s」含非法字符：%s', $label, $domain));
            }
        }
    }

    /**
     * 一批域名的归一化 + 去重 + 校验。
     *
     * 顺序很重要：第一个域名是证书的 CN，也决定了证书存到哪个目录，
     * 所以去重时保留首次出现的位置，不能排序。
     *
     * @param array<int, string> $domains
     * @return array<int, string>
     */
    public static function normalizeList(array $domains): array
    {
        $out = [];
        $seen = [];

        foreach ($domains as $domain) {
            $normalized = self::normalize((string) $domain);
            if ($normalized === '') {
                continue;
            }
            self::validate($normalized);
            if (isset($seen[$normalized])) {
                continue;
            }
            $seen[$normalized] = true;
            $out[] = $normalized;
        }

        if ($out === []) {
            throw new ConfigException('至少要指定一个域名');
        }

        return $out;
    }

    /**
     * dns-01 要写的记录名：_acme-challenge.<域名>。
     *
     * 通配符 *.example.com 的挑战记录挂在 _acme-challenge.example.com，
     * 和裸域 example.com 的记录名**完全一样**——所以同时申请这两个时，
     * 会有两条同名不同值的 TXT 记录，DNS 提供商必须支持同名多值，
     * 覆盖式写入的提供商（比如 Namecheap）要特别处理。
     */
    public static function challengeRecordName(string $domain): string
    {
        return '_acme-challenge.' . self::stripWildcard($domain);
    }

    /**
     * 生成 zone 候选列表，从最短到最长。
     *
     * a.b.example.com 会得到 [example.com, b.example.com, a.b.example.com]
     * （com 因为是公共后缀被跳过）。DNS provider 拿着它逐个问 API
     * 「这个 zone 在我账号下吗」，第一个命中的就是真 zone。
     *
     * 从短到长而不是从长到短：托管商账号里通常只有主域的 zone，
     * 短的先试命中更快；而且万一 a.b.example.com 真被独立托管了，
     * 后面的候选也还在，不会漏。
     *
     * @return array<int, string>
     */
    public static function zoneCandidates(string $domain): array
    {
        $domain = self::stripWildcard(self::normalize($domain));
        $labels = explode('.', $domain);
        $count = \count($labels);

        $candidates = [];
        // 至少要两级才可能是 zone
        for ($take = 2; $take <= $count; ++$take) {
            $candidate = implode('.', \array_slice($labels, $count - $take));
            if (self::isKnownPublicSuffix($candidate)) {
                continue;
            }
            $candidates[] = $candidate;
        }

        if ($candidates === []) {
            $candidates[] = $domain;
        }

        return $candidates;
    }

    /**
     * 已知 zone 的情况下，算出记录的相对名。
     *
     * _acme-challenge.a.example.com 在 zone example.com 下的相对名是
     * _acme-challenge.a；恰好等于 zone 本身时返回 '@'，这是绝大多数
     * DNS API 表示「zone 顶点」的写法。
     */
    public static function relativeName(string $fqdn, string $zone): string
    {
        $fqdn = rtrim(strtolower($fqdn), '.');
        $zone = rtrim(strtolower($zone), '.');

        if ($fqdn === $zone) {
            return '@';
        }

        $suffix = '.' . $zone;
        if (str_ends_with($fqdn, $suffix)) {
            return substr($fqdn, 0, -\strlen($suffix));
        }

        // 不属于这个 zone，原样返回让调用方自己判断——
        // 这种情况说明 zone 判断有误，provider 会在下一步报错
        return $fqdn;
    }

    /** 是否是内置表里的多级公共后缀，或单级顶级域 */
    public static function isKnownPublicSuffix(string $candidate): bool
    {
        $candidate = strtolower($candidate);

        if (!str_contains($candidate, '.')) {
            return true;
        }

        return \in_array($candidate, self::MULTI_LEVEL_SUFFIXES, true);
    }

    /**
     * 域名是否被证书的 SAN 列表覆盖（考虑通配符）。
     *
     * 续期时用来判断「现有证书还管不管用」。注意通配符只能匹配一级：
     * *.example.com 覆盖 a.example.com，但不覆盖 a.b.example.com，
     * 也不覆盖裸域 example.com——这是 RFC 6125 的规则，不是实现偷懒。
     *
     * @param array<int, string> $sans
     */
    public static function isCoveredBy(string $domain, array $sans): bool
    {
        $domain = strtolower(self::normalize($domain));

        foreach ($sans as $san) {
            $san = strtolower(self::normalize((string) $san));
            if ($san === $domain) {
                return true;
            }

            if (self::isWildcard($san) && !self::isWildcard($domain)) {
                $base = substr($san, 2);
                $suffix = '.' . $base;
                if (str_ends_with($domain, $suffix)) {
                    $head = substr($domain, 0, -\strlen($suffix));
                    if ($head !== '' && !str_contains($head, '.')) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * 证书存储目录名。
     *
     * 通配符域名不能直接当目录名（Windows 下 * 非法，Linux 下也难打），
     * 换成 acme.sh 用的 `*.` -> `_.` 约定，迁移过来的用户目录名对得上。
     */
    public static function directoryName(string $domain, bool $ecc = false): string
    {
        $name = str_replace('*.', '_.', self::normalize($domain));

        return $ecc ? $name . '_ecc' : $name;
    }
}
