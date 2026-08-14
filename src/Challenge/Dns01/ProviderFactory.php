<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01;

use PhpAcme\Exception\ConfigException;
use PhpAcme\Http\HttpClient;
use PhpAcme\Util\Logger;

/**
 * 按短名创建 DNS 提供商实例，并负责凭据的来源。
 *
 * 短名与 acme.sh 的 `--dns dns_cf` 完全一致，凭据的环境变量名也一样，
 * 所以从 acme.sh 迁过来的机器上，原来 export 的那些变量继续有效。
 *
 * 凭据查找顺序：显式传入 > 环境变量 > 全局配置文件。
 * **provider 自己不读环境变量**——那样就没法测了，也没法在一个进程里
 * 同时给两个域名用不同的账号。
 */
class ProviderFactory
{
    /**
     * 短名 => [类名, 需要的凭据键]。
     *
     * 凭据键的顺序有意义：第一项是「主凭据」，用它判断用户到底配了没有。
     *
     * @var array<string, array{class: string, keys: array<int, string>, name: string}>
     */
    const MAP = [
        'dns_cf' => [
            'class' => Provider\Cloudflare::class,
            'keys' => ['CF_Token', 'CF_Key', 'CF_Email', 'CF_Account_ID'],
            'name' => 'Cloudflare',
        ],
        'dns_ali' => [
            'class' => Provider\AliyunDns::class,
            'keys' => ['Ali_Key', 'Ali_Secret'],
            'name' => '阿里云 DNS',
        ],
        'dns_dp' => [
            'class' => Provider\DnsPod::class,
            'keys' => ['DP_Id', 'DP_Key'],
            'name' => 'DNSPod',
        ],
        'dns_tencent' => [
            'class' => Provider\TencentCloud::class,
            'keys' => ['Tencent_SecretId', 'Tencent_SecretKey'],
            'name' => '腾讯云 DNSPod',
        ],
        'dns_huaweicloud' => [
            'class' => Provider\HuaweiCloud::class,
            'keys' => ['HUAWEICLOUD_AccessKey', 'HUAWEICLOUD_SecretKey'],
            'name' => '华为云 DNS',
        ],
        'dns_gd' => [
            'class' => Provider\GoDaddy::class,
            'keys' => ['GD_Key', 'GD_Secret'],
            'name' => 'GoDaddy',
        ],
        'dns_aws' => [
            'class' => Provider\Route53::class,
            'keys' => ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'],
            'name' => 'AWS Route 53',
        ],
        'dns_namesilo' => [
            'class' => Provider\NameSilo::class,
            'keys' => ['Namesilo_Key'],
            'name' => 'NameSilo',
        ],
        'dns_duckdns' => [
            'class' => Provider\DuckDns::class,
            'keys' => ['DuckDNS_Token'],
            'name' => 'DuckDNS',
        ],
        'dns_gandi_livedns' => [
            'class' => Provider\Gandi::class,
            'keys' => ['GANDI_LIVEDNS_TOKEN', 'GANDI_LIVEDNS_KEY'],
            'name' => 'Gandi LiveDNS',
        ],
        'dns_linode_v4' => [
            'class' => Provider\Linode::class,
            'keys' => ['LINODE_V4_API_KEY'],
            'name' => 'Linode',
        ],
        'dns_vultr' => [
            'class' => Provider\Vultr::class,
            'keys' => ['VULTR_API_KEY'],
            'name' => 'Vultr',
        ],
        'dns_dgon' => [
            'class' => Provider\DigitalOcean::class,
            'keys' => ['DO_API_KEY'],
            'name' => 'DigitalOcean',
        ],
        'dns_hetzner' => [
            'class' => Provider\Hetzner::class,
            'keys' => ['HETZNER_Token'],
            'name' => 'Hetzner DNS',
        ],
        'dns_he' => [
            'class' => Provider\HurricaneElectric::class,
            'keys' => ['HE_DDNS_Key'],
            'name' => 'Hurricane Electric',
        ],
    ];

    /** 手动模式不需要凭据，单独处理 */
    const MANUAL = 'dns_manual';

    /** @var HttpClient */
    private $http;

    /** @var Logger */
    private $logger;

    /** @var array<string, string> 额外的凭据来源（比如全局配置文件） */
    private $credentialStore;

    /**
     * @param array<string, string> $credentialStore
     */
    public function __construct(?HttpClient $http = null, ?Logger $logger = null, array $credentialStore = [])
    {
        $this->http = $http !== null ? $http : new HttpClient();
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->credentialStore = $credentialStore;
    }

    /**
     * @param array<string, string> $store
     */
    public function setCredentialStore(array $store): void
    {
        $this->credentialStore = $store;
    }

    /** @return array<int, string> 所有支持的短名 */
    public static function supportedProviders(): array
    {
        $names = array_keys(self::MAP);
        $names[] = self::MANUAL;
        sort($names, SORT_STRING);

        return $names;
    }

    /**
     * 归一化用户写的名字。
     *
     * `cf`、`dns_cf`、`Cloudflare` 都能认——用户记不住前缀是常事。
     */
    public static function normalizeName(string $name): string
    {
        $value = strtolower(trim($name));
        $value = str_replace('-', '_', $value);

        if ($value === self::MANUAL || $value === 'manual') {
            return self::MANUAL;
        }

        if (isset(self::MAP[$value])) {
            return $value;
        }

        // 补上 dns_ 前缀再试
        if (isset(self::MAP['dns_' . $value])) {
            return 'dns_' . $value;
        }

        // 按展示名匹配
        foreach (self::MAP as $key => $meta) {
            if (strtolower($meta['name']) === $value) {
                return $key;
            }
        }

        throw new ConfigException(sprintf(
            '不支持的 DNS 提供商「%s」。可用值：%s',
            $name,
            implode(', ', self::supportedProviders())
        ));
    }

    /**
     * 创建实例。
     *
     * @param array<string, string> $overrides 显式指定的凭据，优先级最高
     */
    public function create(string $name, array $overrides = []): DnsProviderInterface
    {
        $key = self::normalizeName($name);

        if ($key === self::MANUAL) {
            return new Provider\ManualDns($this->logger);
        }

        $meta = self::MAP[$key];
        $credentials = $this->collectCredentials($meta['keys'], $overrides);

        // 主凭据一个都没有时提前报错，附上该设哪些变量——
        // 比让用户等到 API 返回 401 才知道要清楚得多
        if ($this->countPresent($meta['keys'], $credentials) === 0) {
            throw new ConfigException(sprintf(
                '%s 需要 API 凭据，但一个都没找到。请设置环境变量：%s'
                . "\n例如：export %s=你的密钥",
                $meta['name'],
                implode(' / ', $meta['keys']),
                $meta['keys'][0]
            ));
        }

        $class = $meta['class'];

        return new $class($credentials, $this->http, $this->logger);
    }

    /**
     * @param array<int, string> $keys
     * @param array<string, string> $overrides
     * @return array<string, string>
     */
    private function collectCredentials(array $keys, array $overrides): array
    {
        $credentials = [];

        foreach ($keys as $envKey) {
            if (isset($overrides[$envKey]) && trim((string) $overrides[$envKey]) !== '') {
                $credentials[$envKey] = trim((string) $overrides[$envKey]);
                continue;
            }

            $value = getenv($envKey);
            if (\is_string($value) && trim($value) !== '') {
                $credentials[$envKey] = trim($value);
                continue;
            }

            if (isset($this->credentialStore[$envKey]) && trim((string) $this->credentialStore[$envKey]) !== '') {
                $credentials[$envKey] = trim((string) $this->credentialStore[$envKey]);
            }
        }

        return $credentials;
    }

    /**
     * @param array<int, string> $keys
     * @param array<string, string> $credentials
     */
    private function countPresent(array $keys, array $credentials): int
    {
        $count = 0;
        foreach ($keys as $key) {
            if (isset($credentials[$key])) {
                ++$count;
            }
        }

        return $count;
    }

    /**
     * 这个 provider 会用到哪些凭据键——存配置时要把它们一起记下来，
     * 续期时才不用用户重新 export 一遍。
     *
     * @return array<int, string>
     */
    public static function credentialKeys(string $name): array
    {
        $key = self::normalizeName($name);

        return $key === self::MANUAL ? [] : self::MAP[$key]['keys'];
    }

    public static function displayName(string $name): string
    {
        $key = self::normalizeName($name);

        return $key === self::MANUAL ? '手动 DNS' : self::MAP[$key]['name'];
    }
}
