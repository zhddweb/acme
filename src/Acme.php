<?php

declare(strict_types=1);

namespace PhpAcme;

use PhpAcme\Challenge\ChallengeSolverInterface;
use PhpAcme\Deploy\DeployHookInterface;
use PhpAcme\Http\HttpClient;
use PhpAcme\Notify\NotifierInterface;
use PhpAcme\Service\AccountService;
use PhpAcme\Service\CertificateIssuer;
use PhpAcme\Service\IssueRequest;
use PhpAcme\Service\IssueResult;
use PhpAcme\Service\RenewalService;
use PhpAcme\Service\RevocationService;
use PhpAcme\Service\SolverFactory;
use PhpAcme\Storage\AccountStorage;
use PhpAcme\Storage\CertificateStorage;
use PhpAcme\Storage\ConfigFile;
use PhpAcme\Storage\Paths;
use PhpAcme\Util\Logger;

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

        $this->certificates = new CertificateStorage($this->paths);
        $this->accountStorage = new AccountStorage($this->paths);
        $this->accounts = new AccountService($this->http, $this->accountStorage, $this->logger);
        $this->issuer = new CertificateIssuer($this->http, $this->certificates, $this->accounts, $this->logger);

        $this->solvers = new SolverFactory($this->http, $this->logger);
        // 全局配置里存着 DNS 凭据，让求解器工厂能取到
        $this->solvers->setCredentials($this->globalConfig->all());

        $this->renewals = new RenewalService($this->issuer, $this->solvers, $this->logger);
        $this->revocations = new RevocationService($this->http, $this->certificates, $this->accounts, $this->logger);
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
