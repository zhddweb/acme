<?php

declare(strict_types=1);

namespace Mci\Acme\Service;

use Mci\Acme\Ca\CaRegistry;
use Mci\Acme\Ca\Eab;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Http\HttpClient;
use Mci\Acme\Protocol\Account;
use Mci\Acme\Protocol\AcmeClient;
use Mci\Acme\Storage\AccountStorage;
use Mci\Acme\Util\Logger;

/**
 * 账户的取用与维护。
 *
 * 账户是「每个 CA 一个」的：同一台机器上 Let's Encrypt 和 ZeroSSL
 * 各有各的密钥和账户 URL，互不相干。所以这里所有方法的第一个参数
 * 都得能定位到具体的 CA。
 */
class AccountService
{
    /** @var HttpClient */
    private $http;

    /** @var AccountStorage */
    private $storage;

    /** @var Logger */
    private $logger;

    public function __construct(HttpClient $http, AccountStorage $storage, ?Logger $logger = null)
    {
        $this->http = $http;
        $this->storage = $storage;
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function getStorage(): AccountStorage
    {
        return $this->storage;
    }

    /**
     * 签发流程要用的账户：有就用，没有就注册一个。
     */
    public function resolve(AcmeClient $client, IssueRequest $request): Account
    {
        $directoryUrl = $request->getDirectoryUrl();

        $existing = $this->storage->loadAccount($directoryUrl);
        if ($existing !== null) {
            $this->logger->debug(sprintf('使用已有账户：%s', $existing->getUrl()));

            return $existing;
        }

        $this->logger->info(sprintf('在 %s 注册新账户', CaRegistry::getDisplayName($request->getCa())));

        return $this->register(
            $client,
            $directoryUrl,
            $request->getEmail(),
            $this->resolveEab($client, $request, $directoryUrl),
            // 账户密钥的类型跟证书密钥走。没有强制关系，但用户选了 EC
            // 多半是希望全套都用 EC
            $request->getKeyType()
        );
    }

    /**
     * 注册账户并落盘。
     */
    public function register(
        AcmeClient $client,
        string $directoryUrl,
        ?string $email,
        ?Eab $eab = null,
        string $keyType = KeyPair::DEFAULT_TYPE
    ): Account {
        $keyPair = $this->storage->loadOrCreateAccountKey($directoryUrl, $keyType);

        $contacts = $email !== null ? Account::buildContacts($email) : [];

        $account = $client->registerAccount(
            $keyPair,
            $contacts,
            true,
            $eab !== null ? $eab->toArray() : null
        );

        $this->storage->saveAccount($directoryUrl, $account, $eab);

        $this->logger->info(sprintf('账户已就绪：%s', $account->getUrl()));

        return $account;
    }

    /**
     * 拿到 EAB 凭据。
     *
     * 三个来源，按优先级：命令行显式给的 > 之前存过的 >
     * ZeroSSL 用邮箱现换的。最后那条是 ZeroSSL 独有的便利，
     * 别的 CA 只能去它们控制台手工申请。
     */
    private function resolveEab(AcmeClient $client, IssueRequest $request, string $directoryUrl): ?Eab
    {
        $explicit = $request->getEab();
        if ($explicit !== null) {
            $eab = new Eab($explicit['kid'], $explicit['hmac']);
            $this->storage->saveEab($directoryUrl, $eab);

            return $eab;
        }

        $stored = $this->storage->loadEab($directoryUrl);
        if ($stored !== null) {
            $this->logger->debug('使用已保存的 EAB 凭据');

            return $stored;
        }

        if (!$client->getDirectory()->requiresExternalAccountBinding()) {
            return null;
        }

        // 到这里说明 CA 要 EAB 但用户没给。ZeroSSL 可以用邮箱自动换，
        // 其余的只能让用户自己去申请
        $isZeroSsl = str_contains($directoryUrl, 'zerossl.com');
        $email = $request->getEmail();

        if (!$isZeroSsl || $email === null) {
            throw new ConfigException(sprintf(
                '%s 要求 External Account Binding，请到它的控制台申请 EAB 凭据，'
                . '再用 --eab-kid 与 --eab-hmac-key 传入%s',
                CaRegistry::getDisplayName($request->getCa()),
                $isZeroSsl ? '；或者用 --email 指定邮箱，让 ZeroSSL 自动分配一组' : ''
            ));
        }

        $this->logger->info(sprintf('正在用邮箱 %s 向 ZeroSSL 申请 EAB 凭据', $email));

        $eab = Eab::fetchFromZeroSsl($this->http, $email);
        $this->storage->saveEab($directoryUrl, $eab);

        return $eab;
    }

    /**
     * 改联系邮箱。
     */
    public function updateEmail(string $ca, string $email): Account
    {
        $directoryUrl = CaRegistry::resolveUrl($ca);

        $account = $this->requireAccount($directoryUrl, $ca);
        $client = AcmeClient::create($this->http, $directoryUrl, $this->logger);

        $updated = $client->updateAccount($account, Account::buildContacts($email));
        $this->storage->saveAccount($directoryUrl, $updated);

        $this->logger->info(sprintf('联系邮箱已更新为 %s', $email));

        return $updated;
    }

    /**
     * 换账户密钥。
     *
     * 换完必须**先确认服务端接受了**再覆盖本地密钥文件——
     * 反过来的话，一旦服务端拒绝，本地就只剩下一把服务端不认识的新密钥，
     * 老账户彻底失联。
     */
    public function rotateKey(string $ca, string $keyType = KeyPair::DEFAULT_TYPE): Account
    {
        $directoryUrl = CaRegistry::resolveUrl($ca);

        $account = $this->requireAccount($directoryUrl, $ca);
        $client = AcmeClient::create($this->http, $directoryUrl, $this->logger);

        $newKey = KeyPair::generate($keyType);
        $updated = $client->changeAccountKey($account, $newKey);

        $this->storage->saveAccountKey($directoryUrl, $newKey, true);
        $this->storage->saveAccount($directoryUrl, $updated);

        $this->logger->info('账户密钥已轮换，旧密钥已失效');

        return $updated;
    }

    /**
     * 注销账户。不可逆。
     */
    public function deactivate(string $ca): Account
    {
        $directoryUrl = CaRegistry::resolveUrl($ca);

        $account = $this->requireAccount($directoryUrl, $ca);
        $client = AcmeClient::create($this->http, $directoryUrl, $this->logger);

        $updated = $client->deactivateAccount($account);
        $this->storage->saveAccount($directoryUrl, $updated);

        $this->logger->warning('账户已注销，这把密钥不能再用于签发');

        return $updated;
    }

    /** 查账户当前状态 */
    public function fetch(string $ca): Account
    {
        $directoryUrl = CaRegistry::resolveUrl($ca);

        $account = $this->requireAccount($directoryUrl, $ca);
        $client = AcmeClient::create($this->http, $directoryUrl, $this->logger);

        return $client->fetchAccount($account);
    }

    public function findLocal(string $ca): ?Account
    {
        return $this->storage->loadAccount(CaRegistry::resolveUrl($ca));
    }

    private function requireAccount(string $directoryUrl, string $ca): Account
    {
        $account = $this->storage->loadAccount($directoryUrl);

        if ($account === null) {
            throw new ConfigException(sprintf(
                '本机还没有 %s 的账户。先跑一次签发，或用 register-account 命令注册',
                CaRegistry::getDisplayName($ca)
            ));
        }

        return $account;
    }
}
