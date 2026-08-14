<?php

declare(strict_types=1);

namespace Mci\Acme\Service;

use Mci\Acme\Challenge\ChallengeSolverInterface;
use Mci\Acme\Crypto\Certificate;
use Mci\Acme\Crypto\Csr;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ChallengeException;
use Mci\Acme\Exception\ProtocolException;
use Mci\Acme\Http\HttpClient;
use Mci\Acme\Protocol\AcmeClient;
use Mci\Acme\Protocol\Authorization;
use Mci\Acme\Protocol\Challenge;
use Mci\Acme\Protocol\Order;
use Mci\Acme\Storage\CertificateStorage;
use Mci\Acme\Storage\Paths;
use Mci\Acme\Util\Logger;

/**
 * 签发编排：把协议层的一堆调用串成「给我一张证书」这一件事。
 *
 * 这一层的价值在于把「顺序」和「失败处理」定下来：
 * 什么时候该跳过验证（授权还在有效期内）、清理动作放在哪个 finally 里、
 * 哪些失败该重试哪些该直接报——这些散在调用方会写错，而且每个人错法不同。
 */
class CertificateIssuer
{
    /** @var HttpClient */
    private $http;

    /** @var CertificateStorage */
    private $storage;

    /** @var AccountService */
    private $accounts;

    /** @var Logger */
    private $logger;

    /** @var callable|null 等待函数，测试注入 */
    private $sleeper;

    public function __construct(
        HttpClient $http,
        CertificateStorage $storage,
        AccountService $accounts,
        ?Logger $logger = null
    ) {
        $this->http = $http;
        $this->storage = $storage;
        $this->accounts = $accounts;
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function setSleeper(?callable $sleeper): void
    {
        $this->sleeper = $sleeper;
    }

    public function getStorage(): CertificateStorage
    {
        return $this->storage;
    }

    /**
     * 签发或续期一张证书。
     */
    public function issue(IssueRequest $request): IssueResult
    {
        $mainDomain = $request->getMainDomain();
        $ecc = $request->isEcc();
        $paths = $this->collectPaths($mainDomain, $ecc);

        // 先看看还要不要签。这一步放在建连接之前：不需要续期时
        // 连 CA 的目录都不该去拉，cron 每天跑一次不该产生任何网络流量
        if (!$request->isForce()) {
            $skip = $this->checkSkip($request, $ecc);
            if ($skip !== null) {
                return $skip;
            }
        }

        $this->logger->info(sprintf('开始为 %s 签发证书（共 %d 个域名）', $mainDomain, \count($request->getDomains())));

        $client = AcmeClient::create($this->http, $request->getDirectoryUrl(), $this->logger);
        $client->setSleeper($this->sleeper);

        $account = $this->accounts->resolve($client, $request);
        $client->useAccount($account);

        $order = $client->newOrder($request->getDomains());
        $this->logger->debug(sprintf('订单状态：%s', $order->getStatus()));

        $this->satisfyAuthorizations($client, $order, $request);

        // 所有授权都过了之后订单会转成 ready，这里再拉一次确认——
        // 有些 CA 的状态更新有几百毫秒的延迟
        $order = $this->waitForReady($client, $order, $request->getOrderTimeout());

        $keyPair = $this->prepareKey($request, $ecc);
        $csrDer = $this->prepareCsr($request, $keyPair, $ecc);

        $this->logger->info('提交 CSR，等待 CA 签发');
        $order = $client->finalizeOrder($order, $csrDer);
        $order = $client->waitForOrder($order, $request->getOrderTimeout());

        $chain = $client->downloadCertificate($order, $request->getPreferredChain());

        $this->storage->saveCertificateChain($mainDomain, $chain, $ecc);
        $certificate = Certificate::fromPem($chain);

        if ($request->isPersistConfig()) {
            $this->persistConfig($request, $ecc);
        }

        $this->logger->info(sprintf(
            '证书已签发：%s，有效期至 %s（%d 天）',
            $mainDomain,
            gmdate('Y-m-d H:i:s', $certificate->getNotAfter()),
            $certificate->getDaysUntilExpiry()
        ));

        return IssueResult::issued($mainDomain, $request->getDomains(), $certificate, $paths);
    }

    /**
     * 判断能不能跳过这次签发。
     *
     * 三个条件全满足才跳过：证书存在、还没到续期窗口、域名列表没变。
     * 最后一条容易被忽略——用户加了个新域名重新跑命令，
     * 如果只看到期时间就会被跳过，然后一脸困惑地发现新域名没进证书。
     */
    private function checkSkip(IssueRequest $request, bool $ecc): ?IssueResult
    {
        $mainDomain = $request->getMainDomain();

        $certificate = $this->storage->loadCertificate($mainDomain, $ecc);
        if ($certificate === null) {
            return null;
        }

        if ($certificate->needsRenewal($request->getRenewDays())) {
            $this->logger->info(sprintf(
                '%s 的证书还有 %d 天到期，进入续期流程',
                $mainDomain,
                $certificate->getDaysUntilExpiry()
            ));

            return null;
        }

        if (!$certificate->covers($request->getDomains())) {
            $this->logger->info(sprintf(
                '%s 的现有证书没有覆盖全部域名（缺少：%s），重新签发',
                $mainDomain,
                implode(', ', array_diff($request->getDomains(), $certificate->getDomains()))
            ));

            return null;
        }

        $message = sprintf(
            '%s 的证书还有 %d 天到期，未到续期阈值（%d 天），跳过。要强制续期请加 --force',
            $mainDomain,
            $certificate->getDaysUntilExpiry(),
            $request->getRenewDays()
        );

        $this->logger->info($message);

        return IssueResult::skipped(
            $mainDomain,
            $request->getDomains(),
            $certificate,
            $this->collectPaths($mainDomain, $ecc),
            $message
        );
    }

    /**
     * 逐个域名完成验证。
     *
     * 有意串行而不是并行：ACME 的 nonce 是串行语义，并发请求会互相
     * 作废对方的 nonce；而且 standalone/tls-alpn 求解器共用一个监听端口，
     * 并行也没有意义。
     */
    private function satisfyAuthorizations(AcmeClient $client, Order $order, IssueRequest $request): void
    {
        $solver = $request->getSolver();
        $accountKey = $client->getAccountKey();

        foreach ($order->getAuthorizationUrls() as $url) {
            $authorization = $client->fetchAuthorization($url);

            if ($authorization->isValid()) {
                // CA 会把成功的授权缓存一段时间（Let's Encrypt 是 30 天），
                // 这期间重新下单不用再验一次
                $this->logger->info(sprintf('%s 的授权仍然有效，跳过验证', $authorization->getDomain()));
                continue;
            }

            if ($authorization->isInvalid()) {
                throw new ChallengeException(sprintf(
                    '%s 的授权已被判为无效：%s',
                    $authorization->getDomain(),
                    $authorization->getErrorMessage()
                ));
            }

            $this->satisfyOne($client, $authorization, $solver, $accountKey, $request);
        }
    }

    private function satisfyOne(
        AcmeClient $client,
        Authorization $authorization,
        ChallengeSolverInterface $solver,
        KeyPair $accountKey,
        IssueRequest $request
    ): void {
        $domain = $authorization->getDomain();
        $challenge = $authorization->findChallenge($solver->getType());

        if ($challenge === null) {
            throw new ChallengeException(sprintf(
                '%s 不支持 %s 验证方式，CA 提供的是：%s。%s',
                $domain,
                $solver->getType(),
                implode(', ', $authorization->getAvailableTypes()),
                $authorization->isWildcard() ? '通配符域名只能用 dns-01' : ''
            ));
        }

        $this->logger->info(sprintf('正在验证 %s（%s）', $domain, $solver->getType()));

        $solver->prepare($challenge, $accountKey);

        try {
            // 自检没过就别去敲 CA 的门：一次失败的验证会计入
            // 该域名的失败次数，攒够了会被限流好几个小时
            if (!$solver->verify($challenge, $accountKey)) {
                throw new ChallengeException(sprintf(
                    '%s 的验证条件没能就绪（%s），已放弃通知 CA 以免浪费验证配额',
                    $domain,
                    $solver->getType()
                ));
            }

            $challenge = $client->triggerChallenge($challenge);
            $challenge = $this->pollChallenge($client, $challenge, $solver, $request->getChallengeTimeout());

            if (!$challenge->isValid()) {
                throw new ChallengeException(sprintf(
                    '%s 的 %s 验证失败：%s',
                    $domain,
                    $solver->getType(),
                    $challenge->getErrorMessage() !== '' ? $challenge->getErrorMessage() : '状态为 ' . $challenge->getStatus()
                ));
            }

            $this->logger->info(sprintf('%s 验证通过', $domain));
        } finally {
            // 无论成败都要清理。失败时尤其重要——残留的 TXT 记录
            // 会让下一次验证读到过期的值
            $solver->cleanup($challenge, $accountKey);
        }
    }

    /**
     * 轮询挑战结果，期间驱动求解器。
     *
     * 不直接用 AcmeClient::waitForChallenge()：standalone 与 tls-alpn 求解器
     * 需要在等待期间被反复 tick() 才能应答 CA 的请求，而协议层不该知道
     * 求解器的存在。
     */
    private function pollChallenge(
        AcmeClient $client,
        Challenge $challenge,
        ChallengeSolverInterface $solver,
        int $timeout
    ): Challenge {
        $deadline = time() + $timeout;
        $current = $challenge;

        while ($current->isPending() || $current->getStatus() === Challenge::STATUS_PROCESSING) {
            if (time() >= $deadline) {
                throw new ChallengeException(sprintf(
                    '等待 %s 的验证结果超时（%d 秒）。'
                    . 'CA 可能访问不到你的服务器，检查防火墙与 DNS 解析是否指向本机',
                    $current->getDomain(),
                    $timeout
                ));
            }

            // 先 tick 再睡：CA 的请求可能已经在队列里了
            $solver->tick();
            $this->sleep(2);

            $current = $client->fetchChallenge($current);
        }

        return $current;
    }

    private function waitForReady(AcmeClient $client, Order $order, int $timeout): Order
    {
        $deadline = time() + $timeout;
        $current = $order;

        while ($current->isPending()) {
            if (time() >= $deadline) {
                throw new ProtocolException(sprintf(
                    '所有域名都验证通过了，但订单仍停在 pending（等了 %d 秒）。'
                    . '这通常是 CA 侧的延迟，稍后重跑同样的命令即可',
                    $timeout
                ));
            }

            $this->sleep(2);
            $current = $client->fetchOrder($current->getUrl());
        }

        if ($current->isInvalid()) {
            throw new ProtocolException('订单被判为无效：' . $current->getErrorMessage());
        }

        return $current;
    }

    private function prepareKey(IssueRequest $request, bool $ecc): KeyPair
    {
        // 用户自带 CSR 时不需要我们的私钥——私钥在用户手里，
        // 我们连见都不该见到
        if ($request->getCsr() !== null) {
            return KeyPair::generate($request->getKeyType());
        }

        return $this->storage->loadOrCreateKey(
            $request->getMainDomain(),
            $request->getKeyType(),
            $ecc,
            $request->isNewKey()
        );
    }

    private function prepareCsr(IssueRequest $request, KeyPair $keyPair, bool $ecc): string
    {
        $userCsr = $request->getCsr();
        if ($userCsr !== null) {
            $this->logger->debug('使用用户提供的 CSR');

            return Csr::pemToDer($userCsr);
        }

        $csrDer = Csr::create($keyPair, $request->getDomains(), $request->getSubject());
        $this->storage->saveCsr($request->getMainDomain(), Csr::derToPem($csrDer), $ecc);

        return $csrDer;
    }

    /**
     * 把这次的参数写进 .conf，续期时照着重放。
     */
    private function persistConfig(IssueRequest $request, bool $ecc): void
    {
        $extra = array_merge([
            CertificateStorage::KEY_KEYLENGTH => $request->getKeyType(),
            CertificateStorage::KEY_API => $request->getDirectoryUrl(),
            CertificateStorage::KEY_RENEW_DAYS => (string) $request->getRenewDays(),
            CertificateStorage::KEY_PREFERRED_CHAIN => $request->getPreferredChain(),
        ], $request->getExtraConfig());

        $this->storage->saveIssueConfig($request->getDomains(), $extra, $ecc);
        $this->storage->markRenewed($request->getMainDomain(), $request->getRenewDays(), $ecc);
    }

    /**
     * @return array<string, string>
     */
    private function collectPaths(string $domain, bool $ecc): array
    {
        $paths = $this->storage->getPaths();

        return [
            'key' => $paths->getKeyPath($domain, $ecc),
            'csr' => $paths->getCsrPath($domain, $ecc),
            'cert' => $paths->getCertPath($domain, $ecc),
            'ca' => $paths->getCaCertPath($domain, $ecc),
            'fullchain' => $paths->getFullchainPath($domain, $ecc),
            'conf' => $paths->getDomainConfPath($domain, $ecc),
            'dir' => $paths->getDomainDir($domain, $ecc),
        ];
    }

    private function sleep(int $seconds): void
    {
        if ($this->sleeper !== null) {
            \call_user_func($this->sleeper, $seconds);

            return;
        }

        sleep($seconds);
    }
}
