<?php

declare(strict_types=1);

namespace PhpAcme\Service;

use PhpAcme\Challenge\Dns01\ProviderFactory;
use PhpAcme\Deploy\DeployHookInterface;
use PhpAcme\Deploy\Hook\InstallFilesHook;
use PhpAcme\Deploy\Hook\Pkcs12Hook;
use PhpAcme\Deploy\Hook\ReloadSignalHook;
use PhpAcme\Deploy\Hook\TouchFileHook;
use PhpAcme\Exception\AcmeException;
use PhpAcme\Exception\ConfigException;
use PhpAcme\Notify\NotifierInterface;
use PhpAcme\Storage\CertificateStorage;
use PhpAcme\Storage\ConfigFile;
use PhpAcme\Util\Logger;

/**
 * 续期：从 .conf 里读回上次的签发参数，原样再跑一遍。
 *
 * 这是无人值守场景的主入口——cron 里跑 `renew --all`，
 * 到期的续、没到期的跳过。用户不用重新敲那一长串 -d -w --dns 参数，
 * 因为签发时已经把它们记在 .conf 里了。
 *
 * 失败处理的原则是**一个域名失败不影响其他域名**：
 * 十张证书里有一张的 DNS 凭据过期了，另外九张该续还得续。
 */
class RenewalService
{
    /** @var CertificateIssuer */
    private $issuer;

    /** @var SolverFactory */
    private $solvers;

    /** @var CertificateStorage */
    private $storage;

    /** @var Logger */
    private $logger;

    /** @var array<int, DeployHookInterface> */
    private $deployHooks = [];

    /** @var NotifierInterface|null */
    private $notifier;

    public function __construct(
        CertificateIssuer $issuer,
        SolverFactory $solvers,
        ?Logger $logger = null
    ) {
        $this->issuer = $issuer;
        $this->solvers = $solvers;
        $this->storage = $issuer->getStorage();
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function addDeployHook(DeployHookInterface $hook): self
    {
        $this->deployHooks[] = $hook;

        return $this;
    }

    public function setNotifier(?NotifierInterface $notifier): self
    {
        $this->notifier = $notifier;

        return $this;
    }

    /**
     * 续一张证书。
     */
    public function renew(string $domain, bool $ecc = false, bool $force = false): IssueResult
    {
        $request = $this->buildRequestFromConfig($domain, $ecc);
        $request->setForce($force);

        $result = $this->issuer->issue($request);

        if ($result->isIssued()) {
            // 先跑 .conf 里记的那套（install-cert 存下来的目标路径与重载方式），
            // 再跑调用方额外挂的。顺序要紧：文件得先就位，重载才有意义
            $this->runDeployHooks($result, $this->buildConfiguredHooks($domain, $ecc));
            $this->runDeployHooks($result, $this->deployHooks);
        }

        return $result;
    }

    /**
     * 从 .conf 重建部署钩子。
     *
     * 这是 install-cert 那句「之后每次续期都会自动重放」的兑现处：
     * 用户配一次目标路径与重载方式，续期时自动照做，不用在 cron 里
     * 再串一条 install-cert 命令。
     *
     * @return array<int, DeployHookInterface>
     */
    private function buildConfiguredHooks(string $domain, bool $ecc): array
    {
        $config = $this->storage->getConfig($domain, $ecc);
        $hooks = [];

        $targets = [];
        foreach ([
            'key' => CertificateStorage::KEY_REAL_KEY_PATH,
            'cert' => CertificateStorage::KEY_REAL_CERT_PATH,
            'ca' => CertificateStorage::KEY_REAL_CA_PATH,
            'fullchain' => CertificateStorage::KEY_REAL_FULLCHAIN_PATH,
        ] as $type => $key) {
            $path = $config->get($key);
            if ($path !== null && $path !== '') {
                $targets[$type] = $path;
            }
        }

        if ($targets !== []) {
            $hook = new InstallFilesHook($targets, $this->logger);

            $keyMode = $config->get('Le_KeyMode');
            if ($keyMode !== null && $keyMode !== '') {
                $hook->setKeyMode((int) octdec($keyMode));
            }
            $hook->setOwner($config->get('Le_Owner'));

            $hooks[] = $hook;
        }

        $pfx = $config->get('Le_PfxPath');
        if ($pfx !== null && $pfx !== '') {
            $hooks[] = new Pkcs12Hook(
                $pfx,
                (string) $config->get('Le_PfxPassword', ''),
                $domain,
                $this->logger
            );
        }

        $touchFile = $config->get('Le_TouchFile');
        if ($touchFile !== null && $touchFile !== '') {
            $hooks[] = new TouchFileHook($touchFile, $this->logger);
        }

        // 重载放最后：前面的文件都写完了才该让服务去读
        $service = $config->get('Le_ReloadService');
        if ($service !== null && $service !== '') {
            $hooks[] = ReloadSignalHook::forService($service, $config->get('Le_ReloadPid'), $this->logger);
        }

        return $hooks;
    }

    /**
     * 续所有该续的证书。
     *
     * @return array<int, array{domain: string, ecc: bool, result: IssueResult|null, error: string}>
     */
    public function renewAll(bool $force = false): array
    {
        $certificates = $this->storage->listCertificates();

        if ($certificates === []) {
            $this->logger->info('本机还没有任何证书，无事可做');

            return [];
        }

        $this->logger->info(sprintf('共 %d 张证书待检查', \count($certificates)));

        $outcomes = [];
        $renewed = [];
        $failed = [];

        foreach ($certificates as $item) {
            $domain = $item['domain'];
            $ecc = $item['ecc'];
            $label = $domain . ($ecc ? '（ECC）' : '');

            try {
                $result = $this->renew($domain, $ecc, $force);

                $outcomes[] = ['domain' => $domain, 'ecc' => $ecc, 'result' => $result, 'error' => ''];

                if ($result->isIssued()) {
                    $renewed[] = $label;
                }
            } catch (AcmeException $e) {
                // 单张失败不能中断整批。这是 renewAll 存在的全部意义——
                // cron 里一次跑几十个域名，任何一个都可能因为
                // DNS 凭据过期、防火墙变更之类挂掉
                $this->logger->error(sprintf('%s 续期失败：%s', $label, $e->getMessage()));

                $outcomes[] = ['domain' => $domain, 'ecc' => $ecc, 'result' => null, 'error' => $e->getMessage()];
                $failed[] = sprintf('%s（%s）', $label, $e->getMessage());
            }
        }

        $this->notifySummary($renewed, $failed, \count($certificates));

        return $outcomes;
    }

    /**
     * 从 .conf 重建签发请求。
     */
    public function buildRequestFromConfig(string $domain, bool $ecc = false): IssueRequest
    {
        if (!$this->storage->exists($domain, $ecc)) {
            throw new ConfigException(sprintf(
                '找不到 %s 的证书%s。先用 issue 命令签发一次',
                $domain,
                $ecc ? '（ECC）' : ''
            ));
        }

        $loaded = $this->storage->loadIssueConfig($domain, $ecc);
        $config = $loaded['config'];
        $domains = $loaded['domains'];

        $webroot = $config->get(CertificateStorage::KEY_WEBROOT, '');
        if ($webroot === null || $webroot === '') {
            throw new ConfigException(sprintf(
                '%s 的配置里没有记录验证方式，没法自动续期。'
                . '用完整参数重新跑一次 issue，之后就能自动续了',
                $domain
            ));
        }

        // DNS 凭据也存在 .conf 里，续期时不用用户重新 export
        $this->solvers->setCredentials($this->extractCredentials($config));

        $solver = $this->solvers->create($webroot, [
            'dns_sleep' => $config->getInt(CertificateStorage::KEY_DNS_SLEEP, 120),
        ]);

        $request = new IssueRequest($domains, $solver);
        $request->setCa($config->get(CertificateStorage::KEY_API, \PhpAcme\Ca\CaRegistry::DEFAULT_CA));
        $request->setRenewDays($config->getInt(CertificateStorage::KEY_RENEW_DAYS, 30));
        $request->setPreferredChain($config->get(CertificateStorage::KEY_PREFERRED_CHAIN));

        $keyType = $config->get(CertificateStorage::KEY_KEYLENGTH);
        if ($keyType !== null && $keyType !== '') {
            $request->setKeyType($keyType);
        }

        // 保留原有的额外配置，免得续期把它们冲掉
        $request->setExtraConfig($this->preservedConfig($config));

        return $request;
    }

    /**
     * 从配置里挑出 DNS 凭据。
     *
     * @return array<string, string>
     */
    private function extractCredentials(ConfigFile $config): array
    {
        $known = [];
        foreach (ProviderFactory::MAP as $meta) {
            foreach ($meta['keys'] as $key) {
                $known[$key] = true;
            }
        }

        $credentials = [];
        foreach ($config->all() as $key => $value) {
            // .conf 里存的键名带 SAVED_ 前缀，与 acme.sh 一致
            if (str_starts_with($key, 'SAVED_')) {
                $realKey = substr($key, 6);
                if (isset($known[$realKey])) {
                    $credentials[$realKey] = $value;
                }
                continue;
            }

            if (isset($known[$key])) {
                $credentials[$key] = $value;
            }
        }

        return $credentials;
    }

    /**
     * 续期时要原样保留的配置项。
     *
     * @return array<string, string>
     */
    private function preservedConfig(ConfigFile $config): array
    {
        $preserved = [];

        foreach ($config->all() as $key => $value) {
            // 这几项由签发流程自己重新写，其余（webroot、DNS 凭据、
            // 部署路径）都要带过去
            if (\in_array($key, [
                CertificateStorage::KEY_DOMAIN,
                CertificateStorage::KEY_ALT,
                CertificateStorage::KEY_KEYLENGTH,
                CertificateStorage::KEY_API,
                CertificateStorage::KEY_RENEW_DAYS,
                CertificateStorage::KEY_PREFERRED_CHAIN,
                CertificateStorage::KEY_CERT_CREATE_TIME,
                CertificateStorage::KEY_NEXT_RENEW_TIME,
            ], true)) {
                continue;
            }

            $preserved[$key] = $value;
        }

        return $preserved;
    }

    /**
     * @param array<int, DeployHookInterface> $hooks
     */
    private function runDeployHooks(IssueResult $result, array $hooks): void
    {
        foreach ($hooks as $hook) {
            try {
                $hook->deploy($result);
            } catch (AcmeException $e) {
                // 证书已经签下来了，部署失败不该让整次续期算作失败——
                // 但必须让人知道，否则新证书躺在磁盘上没生效
                $this->logger->error(sprintf('部署钩子「%s」执行失败：%s', $hook->getName(), $e->getMessage()));
            }
        }
    }

    /**
     * @param array<int, string> $renewed
     * @param array<int, string> $failed
     */
    private function notifySummary(array $renewed, array $failed, int $total): void
    {
        if ($this->notifier === null) {
            return;
        }

        // 什么都没发生就不发通知。每天一封「今天也没啥事」的邮件
        // 只会让人把规则拉黑，真出事时反而看不到
        if ($renewed === [] && $failed === []) {
            $this->logger->debug('本次没有证书需要续期，不发送通知');

            return;
        }

        $success = $failed === [];

        $lines = [sprintf('共检查 %d 张证书。', $total)];
        if ($renewed !== []) {
            $lines[] = sprintf('已续期 %d 张：%s', \count($renewed), implode('、', $renewed));
        }
        if ($failed !== []) {
            $lines[] = sprintf('失败 %d 张：', \count($failed));
            foreach ($failed as $item) {
                $lines[] = '  - ' . $item;
            }
        }

        $this->notifier->send(
            $success ? '证书续期完成' : '证书续期出现失败',
            implode("\n", $lines),
            $success
        );
    }
}
