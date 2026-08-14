<?php

declare(strict_types=1);

namespace PhpAcme\Service;

use PhpAcme\Challenge\ChallengeSolverInterface;
use PhpAcme\Challenge\Dns01\DnsSolver;
use PhpAcme\Challenge\Dns01\DnsVerifier;
use PhpAcme\Challenge\Dns01\ProviderFactory;
use PhpAcme\Challenge\Http01\ManualSolver;
use PhpAcme\Challenge\Http01\StandaloneSolver;
use PhpAcme\Challenge\Http01\WebrootSolver;
use PhpAcme\Challenge\TlsAlpn01\TlsAlpnSolver;
use PhpAcme\Exception\ConfigException;
use PhpAcme\Http\HttpClient;
use PhpAcme\Util\Logger;

/**
 * 按一个字符串创建求解器。
 *
 * 这个字符串就是 .conf 里的 `Le_Webroot`——acme.sh 用同一个字段
 * 存三种含义：webroot 路径、`dns_cf` 这样的 DNS 提供商名、
 * 或者 `no` 表示 standalone。看着别扭，但兼容它意味着
 * acme.sh 的配置目录可以直接拿来用，这个价值大于形式上的整洁。
 */
class SolverFactory
{
    /** acme.sh 用这几个值表示非 webroot 的模式 */
    const MODE_STANDALONE = 'no';
    const MODE_TLS_ALPN = 'alpn';
    const MODE_MANUAL = 'manual';

    /** @var HttpClient */
    private $http;

    /** @var Logger */
    private $logger;

    /** @var array<string, string> DNS 凭据，从全局配置读来的 */
    private $credentials = [];

    /** @var callable|null 测试注入的等待函数 */
    private $sleeper;

    public function __construct(?HttpClient $http = null, ?Logger $logger = null)
    {
        $this->http = $http !== null ? $http : new HttpClient();
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    /**
     * @param array<string, string> $credentials
     */
    public function setCredentials(array $credentials): void
    {
        $this->credentials = $credentials;
    }

    public function setSleeper(?callable $sleeper): void
    {
        $this->sleeper = $sleeper;
    }

    /**
     * @param array<string, mixed> $options 端口、传播超时之类的调节项
     */
    public function create(string $spec, array $options = []): ChallengeSolverInterface
    {
        $spec = trim($spec);

        if ($spec === '') {
            throw new ConfigException(
                '没有指定验证方式。用 -w <网站根目录> 走 http-01，'
                . '或 --dns <提供商> 走 dns-01，或 --standalone 用内置服务器'
            );
        }

        if ($spec === self::MODE_STANDALONE || $spec === 'standalone') {
            $port = isset($options['port']) ? (int) $options['port'] : 80;
            $bind = isset($options['bind']) ? (string) $options['bind'] : '0.0.0.0';

            return new StandaloneSolver($port, $bind, $this->logger);
        }

        if ($spec === self::MODE_TLS_ALPN || $spec === 'tls-alpn' || $spec === 'alpn-standalone') {
            $port = isset($options['port']) ? (int) $options['port'] : 443;
            $bind = isset($options['bind']) ? (string) $options['bind'] : '0.0.0.0';
            $tempDir = isset($options['temp_dir']) ? (string) $options['temp_dir'] : null;

            return new TlsAlpnSolver($port, $bind, $tempDir, $this->logger);
        }

        if ($spec === self::MODE_MANUAL || $spec === 'manual-http') {
            return new ManualSolver('http-01', $this->logger);
        }

        // dns 开头的一律当 DNS 提供商。dns_manual 也走这条，
        // 由 ProviderFactory 去分辨
        if (str_starts_with($spec, 'dns')) {
            return $this->createDnsSolver($spec, $options);
        }

        // 剩下的当 webroot 路径
        return $this->createWebrootSolver($spec, $options);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function createDnsSolver(string $spec, array $options): DnsSolver
    {
        $factory = new ProviderFactory($this->http, $this->logger, $this->credentials);

        $overrides = isset($options['dns_credentials']) && \is_array($options['dns_credentials'])
            ? $options['dns_credentials']
            : [];

        $provider = $factory->create($spec, $overrides);

        $verifier = new DnsVerifier(null, $this->logger);
        $solver = new DnsSolver($provider, $verifier, $this->logger);

        if (isset($options['dns_sleep'])) {
            // acme.sh 的 --dnssleep 是「无条件等这么久」；本库改成
            // 「最多等这么久，查到就走」，语义更好但参数名保持兼容
            $solver->setPropagationTimeout((int) $options['dns_sleep']);
        }
        if (isset($options['dns_initial_delay'])) {
            $solver->setInitialDelay((int) $options['dns_initial_delay']);
        }
        if (isset($options['dns_poll_interval'])) {
            $solver->setPollInterval((int) $options['dns_poll_interval']);
        }
        if (isset($options['dns_strict'])) {
            $solver->setContinueOnTimeout(!$options['dns_strict']);
        }

        if ($this->sleeper !== null) {
            $solver->setSleeper($this->sleeper);
        }

        return $solver;
    }

    /**
     * @param array<string, mixed> $options
     */
    private function createWebrootSolver(string $spec, array $options): WebrootSolver
    {
        // 多个 webroot 时用「域名=路径」的形式，逗号分隔
        if (str_contains($spec, '=')) {
            $map = [];
            foreach (explode(',', $spec) as $pair) {
                $parts = explode('=', $pair, 2);
                if (\count($parts) !== 2) {
                    continue;
                }
                $map[trim($parts[0])] = trim($parts[1]);
            }

            if ($map === []) {
                throw new ConfigException(sprintf('webroot 映射「%s」解析不出任何条目', $spec));
            }

            return new WebrootSolver($map, $this->logger);
        }

        if (!is_dir($spec)) {
            throw new ConfigException(sprintf(
                'webroot 目录不存在：%s。'
                . '这个路径要指向网站的根目录（也就是 index.html 所在的地方）',
                $spec
            ));
        }

        return new WebrootSolver($spec, $this->logger);
    }

    /**
     * 反推：从求解器还原出该存进 .conf 的字符串。
     */
    public static function describe(ChallengeSolverInterface $solver): string
    {
        if ($solver instanceof DnsSolver) {
            foreach (ProviderFactory::MAP as $key => $meta) {
                if (get_class($solver->getProvider()) === $meta['class']) {
                    return $key;
                }
            }

            return ProviderFactory::MANUAL;
        }

        if ($solver instanceof StandaloneSolver) {
            return self::MODE_STANDALONE;
        }

        if ($solver instanceof TlsAlpnSolver) {
            return self::MODE_TLS_ALPN;
        }

        if ($solver instanceof ManualSolver) {
            return self::MODE_MANUAL;
        }

        if ($solver instanceof WebrootSolver) {
            return $solver->describe();
        }

        return '';
    }
}
