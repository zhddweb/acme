<?php

declare(strict_types=1);

namespace Mci\Acme;

use Mci\Acme\Challenge\ChallengeSolverInterface;
use Mci\Acme\Deploy\DeployHookInterface;
use Mci\Acme\Http\HttpClient;
use Mci\Acme\Notify\NotifierInterface;
use Mci\Acme\Service\AccountService;
use Mci\Acme\Service\CertificateIssuer;
use Mci\Acme\Service\IssueRequest;
use Mci\Acme\Service\IssueResult;
use Mci\Acme\Service\RenewalService;
use Mci\Acme\Service\RevocationService;
use Mci\Acme\Service\SolverFactory;
use Mci\Acme\Storage\AccountStorage;
use Mci\Acme\Storage\CertificateStorage;
use Mci\Acme\Storage\ConfigFile;
use Mci\Acme\Storage\Paths;
use Mci\Acme\Util\Logger;

/**
 * 门面：在自己的代码里用这个库时，从这里开始。
 *
 *     $acme = new Acme();
 *     $result = $acme->issue(['example.com', 'www.example.com'], '/var/www/html');
 *     echo $result->getPath('fullchain');
 *
 * 内部各层（协议、存储、求解器）都可以单独拿出来用，
 * 这个类只是把最常见的组合方式固定下来，省掉一堆样板代码。
 */
class Acme
{
    const VERSION = '1.0.0';

    /** account.conf 里代理地址的键名 */
    const CONFIG_PROXY = 'PROXY';
    /** account.conf 里不走代理的主机清单 */
    const CONFIG_NO_PROXY = 'NO_PROXY';
    /** account.conf 里证书根目录的键名，与 acme.sh 的 --cert-home 同一个键 */
    const CONFIG_CERT_HOME = 'CERT_HOME';

    /** @var Paths */
    private $paths;

    /** @var HttpClient */
    private $http;

    /** @var Logger */
    private $logger;

    /** @var CertificateStorage */
    private $certificates;

    /** @var AccountStorage */
    private $accountStorage;

    /** @var AccountService */
    private $accounts;

    /** @var CertificateIssuer */
    private $issuer;

    /** @var SolverFactory */
    private $solvers;

    /** @var RenewalService */
    private $renewals;

    /** @var RevocationService */
    private $revocations;

    /** @var ConfigFile 全局配置 */
    private $globalConfig;

    public function __construct(?string $baseDir = null, ?Logger $logger = null, ?HttpClient $http = null)
    {
        $this->paths = new Paths($baseDir);
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->http = $http !== null ? $http : new HttpClient(null, $this->logger);

        $this->globalConfig = (new ConfigFile($this->paths->getAccountConfPath()))->load();
        $this->applyCertHomeFromConfig();

        $this->certificates = new CertificateStorage($this->paths);
        $this->accountStorage = new AccountStorage($this->paths);
        $this->accounts = new AccountService($this->http, $this->accountStorage, $this->logger);
        $this->issuer = new CertificateIssuer($this->http, $this->certificates, $this->accounts, $this->logger);

        $this->solvers = new SolverFactory($this->http, $this->logger);
        // 全局配置里存着 DNS 凭据，让求解器工厂能取到
        $this->solvers->setCredentials($this->globalConfig->all());

        $this->renewals = new RenewalService($this->issuer, $this->solvers, $this->logger);
        $this->revocations = new RevocationService($this->http, $this->certificates, $this->accounts, $this->logger);

        $this->applyProxyFromConfig();
    }

    /**
     * account.conf 里的 CERT_HOME 决定证书放在哪。
     *
     * acme.sh 用 --cert-home 挪证书目录时，就是把路径写进 account.conf 的
     * 这个键。默认根目录已经和 acme.sh 共用，这里再认一下这个键，
     * 挪过证书目录的机器上才能真的找到那些证书。
     *
     * 显式指定过（构造参数 / CERT_HOME 环境变量 / --cert-home）时不覆盖：
     * 那是「这一次就想换个地方」，优先级高于配置文件。
     */
    private function applyCertHomeFromConfig(): void
    {
        if ($this->paths->hasCustomCertHome()) {
            return;
        }

        $certHome = $this->globalConfig->get(self::CONFIG_CERT_HOME);
        if ($certHome !== null && trim($certHome) !== '') {
            $this->paths->setCertHome(trim($certHome));
        }
    }

    /**
     * 把全局配置里的代理设置应用到 HTTP 客户端。
     *
     * 放在这里而不是只做进 CLI：受限网络下用库直接调用的人同样需要代理，
     * 让他们在 account.conf 里配一次就够，不必每次 new 完再手工 setProxy()。
     * 环境变量仍然有效，配置文件优先级更高。
     */
    private function applyProxyFromConfig(): void
    {
        $proxy = $this->globalConfig->get(self::CONFIG_PROXY);
        if ($proxy !== null && trim($proxy) !== '') {
            $this->http->setProxy(trim($proxy));
        }

        $noProxy = $this->globalConfig->get(self::CONFIG_NO_PROXY);
        if ($noProxy !== null && trim($noProxy) !== '') {
            $this->http->addNoProxy(trim($noProxy));
        }
    }

    /**
     * 签发证书。
     *
     * @param array<int, string> $domains 第一个是主域名
     * @param string $solverSpec webroot 路径、`dns_cf` 这类提供商名、或 `no`（standalone）
     * @param array<string, mixed> $options 见 IssueRequest 的各个 setter
     */
    public function issue(array $domains, string $solverSpec, array $options = []): IssueResult
    {
        $solver = $this->solvers->create($solverSpec, $options);

        $request = new IssueRequest($domains, $solver);
        $this->applyOptions($request, $options);

        // 把验证方式记进 .conf，续期时才知道该怎么再来一遍
        $extra = $request->getExtraConfig();
        $extra[CertificateStorage::KEY_WEBROOT] = SolverFactory::describe($solver);
        $request->setExtraConfig($extra);

        return $this->issuer->issue($request);
    }

    /**
     * 用已经构造好的求解器签发，适合需要自定义 DNS 适配器的场合。
     *
     * @param array<int, string> $domains
     * @param array<string, mixed> $options
     */
    public function issueWith(array $domains, ChallengeSolverInterface $solver, array $options = []): IssueResult
    {
        $request = new IssueRequest($domains, $solver);
        $this->applyOptions($request, $options);

        return $this->issuer->issue($request);
    }

    public function renew(string $domain, bool $ecc = false, bool $force = false): IssueResult
    {
        return $this->renewals->renew($domain, $ecc, $force);
    }

    /**
     * @return array<int, array{domain: string, ecc: bool, result: IssueResult|null, error: string}>
     */
    public function renewAll(bool $force = false): array
    {
        return $this->renewals->renewAll($force);
    }

    public function revoke(
        string $domain,
        bool $ecc = false,
        int $reason = RevocationService::REASON_UNSPECIFIED,
        bool $removeFiles = false
    ): void {
        $this->revocations->revoke($domain, $ecc, $reason, null, $removeFiles);
    }

    /**
     * @return array<int, array{domain: string, ecc: bool, dir: string}>
     */
    public function listCertificates(): array
    {
        return $this->certificates->listCertificates();
    }

    public function addDeployHook(DeployHookInterface $hook): self
    {
        $this->renewals->addDeployHook($hook);

        return $this;
    }

    public function setNotifier(?NotifierInterface $notifier): self
    {
        $this->renewals->setNotifier($notifier);

        return $this;
    }

    public function getPaths(): Paths
    {
        return $this->paths;
    }

    public function getCertificateStorage(): CertificateStorage
    {
        return $this->certificates;
    }

    public function getAccountStorage(): AccountStorage
    {
        return $this->accountStorage;
    }

    public function getAccountService(): AccountService
    {
        return $this->accounts;
    }

    public function getIssuer(): CertificateIssuer
    {
        return $this->issuer;
    }

    public function getRenewalService(): RenewalService
    {
        return $this->renewals;
    }

    public function getRevocationService(): RevocationService
    {
        return $this->revocations;
    }

    public function getSolverFactory(): SolverFactory
    {
        return $this->solvers;
    }

    public function getGlobalConfig(): ConfigFile
    {
        return $this->globalConfig;
    }

    public function getHttpClient(): HttpClient
    {
        return $this->http;
    }

    public function getLogger(): Logger
    {
        return $this->logger;
    }

    /**
     * @param array<string, mixed> $options
     */
    private function applyOptions(IssueRequest $request, array $options): void
    {
        $map = [
            'ca' => 'setCa',
            'key_type' => 'setKeyType',
            'email' => 'setEmail',
            'renew_days' => 'setRenewDays',
            'force' => 'setForce',
            'new_key' => 'setNewKey',
            'preferred_chain' => 'setPreferredChain',
            'subject' => 'setSubject',
            'eab' => 'setEab',
            'csr' => 'setCsr',
            'challenge_timeout' => 'setChallengeTimeout',
            'order_timeout' => 'setOrderTimeout',
            'extra_config' => 'setExtraConfig',
            'persist_config' => 'setPersistConfig',
        ];

        foreach ($map as $key => $setter) {
            if (\array_key_exists($key, $options)) {
                $request->{$setter}($options[$key]);
            }
        }

        // 邮箱没显式给就用全局配置里的，省得每次都要传
        if (!isset($options['email'])) {
            $email = $this->globalConfig->get('ACCOUNT_EMAIL');
            if ($email !== null && $email !== '') {
                $request->setEmail($email);
            }
        }
    }
}
