<?php

declare(strict_types=1);

namespace PhpAcme\Ca;

use PhpAcme\Exception\ConfigException;

/**
 * 内置 CA 列表。
 *
 * 短名与 acme.sh 的 --server 参数保持一致，从 acme.sh 迁过来的脚本
 * 不用改。也可以直接传目录 URL，不在表里的 CA 照样能用——这个表只是
 * 省得用户去记一长串地址。
 */
final class CaRegistry
{
    const LETSENCRYPT = 'letsencrypt';
    const LETSENCRYPT_TEST = 'letsencrypt_test';
    const ZEROSSL = 'zerossl';
    const BUYPASS = 'buypass';
    const BUYPASS_TEST = 'buypass_test';
    const GOOGLE = 'google';
    const GOOGLE_TEST = 'google_test';
    const SSLCOM = 'sslcom';
    const SSLCOM_ECC = 'sslcom_ecc';
    const ACTALIS = 'actalis';

    /** 默认 CA。选 Let's Encrypt：不用 EAB，注册即用，签发额度也最宽 */
    const DEFAULT_CA = self::LETSENCRYPT;

    /**
     * @var array<string, array{url: string, name: string, eab: bool, test: bool, aliases: array<int, string>}>
     */
    private static $servers = [
        self::LETSENCRYPT => [
            'url' => 'https://acme-v02.api.letsencrypt.org/directory',
            'name' => "Let's Encrypt",
            'eab' => false,
            'test' => false,
            'aliases' => ['le', 'letsencrypt.org'],
        ],
        self::LETSENCRYPT_TEST => [
            'url' => 'https://acme-staging-v02.api.letsencrypt.org/directory',
            'name' => "Let's Encrypt Staging",
            'eab' => false,
            'test' => true,
            'aliases' => ['staging', 'le_test', 'letsencrypt-test'],
        ],
        self::ZEROSSL => [
            'url' => 'https://acme.zerossl.com/v2/DV90',
            'name' => 'ZeroSSL',
            'eab' => true,
            'test' => false,
            'aliases' => ['zero'],
        ],
        self::BUYPASS => [
            'url' => 'https://api.buypass.com/acme/directory',
            'name' => 'Buypass Go SSL',
            'eab' => false,
            'test' => false,
            'aliases' => [],
        ],
        self::BUYPASS_TEST => [
            'url' => 'https://api.test4.buypass.no/acme/directory',
            'name' => 'Buypass Go SSL Test',
            'eab' => false,
            'test' => true,
            'aliases' => [],
        ],
        self::GOOGLE => [
            'url' => 'https://dv.acme-v02.api.pki.goog/directory',
            'name' => 'Google Trust Services',
            'eab' => true,
            'test' => false,
            'aliases' => ['gts'],
        ],
        self::GOOGLE_TEST => [
            'url' => 'https://dv.acme-v02.test-api.pki.goog/directory',
            'name' => 'Google Trust Services Test',
            'eab' => true,
            'test' => true,
            'aliases' => ['gts_test'],
        ],
        self::SSLCOM => [
            'url' => 'https://acme.ssl.com/sslcom-dv-rsa',
            'name' => 'SSL.com (RSA)',
            'eab' => true,
            'test' => false,
            'aliases' => ['ssl.com'],
        ],
        self::SSLCOM_ECC => [
            'url' => 'https://acme.ssl.com/sslcom-dv-ecc',
            'name' => 'SSL.com (ECC)',
            'eab' => true,
            'test' => false,
            'aliases' => ['ssl.com_ecc'],
        ],
        self::ACTALIS => [
            'url' => 'https://acme-api.actalis.com/acme/directory',
            'name' => 'Actalis',
            'eab' => true,
            'test' => false,
            'aliases' => [],
        ],
    ];

    /**
     * 短名或 URL -> 目录 URL。
     */
    public static function resolveUrl(string $server): string
    {
        $server = trim($server);
        if ($server === '') {
            $server = self::DEFAULT_CA;
        }

        // 直接给 URL 的情况：不在表里的 CA 也要能用
        if (preg_match('#^https?://#i', $server) === 1) {
            return $server;
        }

        $key = self::resolveKey($server);
        if ($key !== null) {
            return self::$servers[$key]['url'];
        }

        throw new ConfigException(sprintf(
            '不认识的 CA「%s」。可用短名：%s；也可以直接写目录 URL',
            $server,
            implode(', ', array_keys(self::$servers))
        ));
    }

    /** 短名（含别名）归一到主键；不是已知短名则返回 null */
    public static function resolveKey(string $server): ?string
    {
        $needle = strtolower(str_replace('-', '_', trim($server)));

        if (isset(self::$servers[$needle])) {
            return $needle;
        }

        foreach (self::$servers as $key => $meta) {
            foreach ($meta['aliases'] as $alias) {
                if (strtolower(str_replace('-', '_', $alias)) === $needle) {
                    return $key;
                }
            }
        }

        return null;
    }

    /** 由目录 URL 反查短名，用于展示与配置回写 */
    public static function findByUrl(string $url): ?string
    {
        foreach (self::$servers as $key => $meta) {
            if (rtrim($meta['url'], '/') === rtrim($url, '/')) {
                return $key;
            }
        }

        return null;
    }

    public static function getDisplayName(string $server): string
    {
        $key = self::resolveKey($server);
        if ($key !== null) {
            return self::$servers[$key]['name'];
        }

        $key = self::findByUrl($server);

        return $key !== null ? self::$servers[$key]['name'] : $server;
    }

    /**
     * 这个 CA 是否需要 EAB。
     *
     * 只是个提示：真正的判定看目录文档里的 externalAccountRequired，
     * CA 改了策略这个表可能滞后。用它来提前给用户友好提示，不作为拒绝的依据。
     */
    public static function requiresEab(string $server): bool
    {
        $key = self::resolveKey($server);
        if ($key === null) {
            $key = self::findByUrl($server);
        }

        return $key !== null && self::$servers[$key]['eab'];
    }

    public static function isTestServer(string $server): bool
    {
        $key = self::resolveKey($server);
        if ($key === null) {
            $key = self::findByUrl($server);
        }

        return $key !== null && self::$servers[$key]['test'];
    }

    /** @return array<string, array{url: string, name: string, eab: bool, test: bool, aliases: array<int, string>}> */
    public static function all(): array
    {
        return self::$servers;
    }

    /**
     * 目录 URL -> 存储用的目录名。
     *
     * 布局照抄 acme.sh：ca/<host>/<path>/，这样同一台机器上两个客户端
     * 可以共用账户目录，双向迁移不用搬文件。
     */
    public static function directoryPath(string $directoryUrl): string
    {
        $parts = parse_url($directoryUrl);

        $host = isset($parts['host']) ? $parts['host'] : 'unknown';
        $path = isset($parts['path']) ? trim($parts['path'], '/') : '';

        if ($path === '') {
            return $host;
        }

        // 路径里的斜杠原样保留成子目录，其余可能不合法的字符换成下划线
        $safe = preg_replace('#[^a-zA-Z0-9._/-]#', '_', $path);

        return $host . '/' . $safe;
    }
}
