<?php

declare(strict_types=1);

namespace Mci\Acme\Storage;

use Mci\Acme\Ca\Eab;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\StorageException;
use Mci\Acme\Protocol\Account;
use Mci\Acme\Util\Filesystem;
use Mci\Acme\Util\Json;

/**
 * 账户密钥与元数据的落盘。
 *
 * 账户密钥是最不能丢的东西：丢了就等于换了个人，之前签发的证书虽然还有效，
 * 但吊销不了、续期要重新走注册。所以写入一律走原子替换，
 * 而且**绝不覆盖已存在的密钥**——重新生成一把会静默地把旧账户弃掉。
 */
class AccountStorage
{
    /** 账户 URL，也就是 JWS 里的 kid */
    const KEY_ACCOUNT_URL = 'ACCOUNT_URL';
    const KEY_EMAIL = 'ACCOUNT_EMAIL';
    const KEY_EAB_KID = 'EAB_KID';
    const KEY_EAB_HMAC = 'EAB_HMAC_KEY';
    const KEY_KEY_TYPE = 'ACCOUNT_KEY_TYPE';
    const KEY_CREATED = 'ACCOUNT_CREATED';

    /** @var Paths */
    private $paths;

    /** @var Filesystem */
    private $filesystem;

    public function __construct(Paths $paths, ?Filesystem $filesystem = null)
    {
        $this->paths = $paths;
        $this->filesystem = $filesystem !== null ? $filesystem : new Filesystem();
    }

    public function hasAccountKey(string $directoryUrl): bool
    {
        return $this->filesystem->isFile($this->paths->getAccountKeyPath($directoryUrl));
    }

    public function loadAccountKey(string $directoryUrl): ?KeyPair
    {
        $path = $this->paths->getAccountKeyPath($directoryUrl);
        $pem = $this->filesystem->readIfExists($path);

        if ($pem === null || trim($pem) === '') {
            return null;
        }

        return KeyPair::fromPem($pem);
    }

    /**
     * 保存账户密钥。
     *
     * @param bool $overwrite 换密钥（keyChange）之后才该传 true
     */
    public function saveAccountKey(string $directoryUrl, KeyPair $keyPair, bool $overwrite = false): void
    {
        $path = $this->paths->getAccountKeyPath($directoryUrl);

        if (!$overwrite && $this->filesystem->isFile($path)) {
            throw new StorageException(sprintf(
                '账户密钥已存在：%s。覆盖它会导致原账户失联（已签发的证书将无法吊销），'
                . '确实要换请显式指定覆盖',
                $path
            ));
        }

        $this->filesystem->writePrivate($path, $keyPair->getPrivateKeyPem());
    }

    /**
     * 取已存在的密钥，没有就生成一把新的并存下来。
     */
    public function loadOrCreateAccountKey(string $directoryUrl, string $keyType = KeyPair::TYPE_EC_256): KeyPair
    {
        $existing = $this->loadAccountKey($directoryUrl);
        if ($existing !== null) {
            return $existing;
        }

        $keyPair = KeyPair::generate($keyType);
        $this->saveAccountKey($directoryUrl, $keyPair);

        return $keyPair;
    }

    public function getConfig(string $directoryUrl): ConfigFile
    {
        return (new ConfigFile($this->paths->getCaConfPath($directoryUrl), $this->filesystem))->load();
    }

    /**
     * 存账户信息。account.json 存服务端返回的原文，ca.conf 存我们要用的那几项。
     */
    public function saveAccount(string $directoryUrl, Account $account, ?Eab $eab = null): void
    {
        $config = $this->getConfig($directoryUrl);

        $config->set(self::KEY_ACCOUNT_URL, $account->getUrl());
        $config->set(self::KEY_KEY_TYPE, $account->getKeyPair()->getType());

        $emails = $account->getEmails();
        if ($emails !== []) {
            $config->set(self::KEY_EMAIL, implode(',', $emails));
        }

        if ($eab !== null) {
            // EAB 凭据要留着：ZeroSSL 换一次凭据就多一个子账户，
            // 而且他们对换取接口有频率限制，续期时不能每次都重新申请
            $config->set(self::KEY_EAB_KID, $eab->getKid());
            $config->set(self::KEY_EAB_HMAC, $eab->getHmacKey());
        }

        if (!$config->has(self::KEY_CREATED)) {
            $config->set(self::KEY_CREATED, (string) time());
        }

        $config->save();

        $data = $account->toArray();
        if ($data !== []) {
            $this->filesystem->write(
                $this->paths->getAccountJsonPath($directoryUrl),
                Json::encodePretty($data),
                Filesystem::MODE_PRIVATE
            );
        }
    }

    /**
     * 读回已保存的账户；密钥或账户 URL 缺任何一个都算没有。
     */
    public function loadAccount(string $directoryUrl): ?Account
    {
        $keyPair = $this->loadAccountKey($directoryUrl);
        if ($keyPair === null) {
            return null;
        }

        $config = $this->getConfig($directoryUrl);
        $url = $config->get(self::KEY_ACCOUNT_URL);
        if ($url === null || $url === '') {
            return null;
        }

        $data = [];
        $json = $this->filesystem->readIfExists($this->paths->getAccountJsonPath($directoryUrl));
        if ($json !== null && trim($json) !== '') {
            $parsed = Json::tryDecode($json);
            if ($parsed !== null) {
                $data = $parsed;
            }
        }

        return new Account($keyPair, $url, $data);
    }

    public function loadEab(string $directoryUrl): ?Eab
    {
        $config = $this->getConfig($directoryUrl);

        $kid = $config->get(self::KEY_EAB_KID);
        $hmac = $config->get(self::KEY_EAB_HMAC);

        if ($kid === null || $kid === '' || $hmac === null || $hmac === '') {
            return null;
        }

        return new Eab($kid, $hmac);
    }

    public function saveEab(string $directoryUrl, Eab $eab): void
    {
        $config = $this->getConfig($directoryUrl);
        $config->set(self::KEY_EAB_KID, $eab->getKid());
        $config->set(self::KEY_EAB_HMAC, $eab->getHmacKey());
        $config->save();
    }

    public function getEmail(string $directoryUrl): ?string
    {
        return $this->getConfig($directoryUrl)->get(self::KEY_EMAIL);
    }
}
