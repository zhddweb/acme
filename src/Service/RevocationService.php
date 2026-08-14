<?php

declare(strict_types=1);

namespace PhpAcme\Service;

use PhpAcme\Ca\CaRegistry;
use PhpAcme\Exception\ConfigException;
use PhpAcme\Http\HttpClient;
use PhpAcme\Protocol\AcmeClient;
use PhpAcme\Storage\CertificateStorage;
use PhpAcme\Util\Logger;

/**
 * 吊销证书。
 *
 * 吊销的原因码不是摆设：keyCompromise(1) 会让 CA 把这张证书的公钥
 * 拉黑，之后**同一把私钥再也签不出新证书**。私钥真泄露了必须用它；
 * 只是想换证书的话用 superseded(4)，别选错。
 */
class RevocationService
{
    const REASON_UNSPECIFIED = 0;
    const REASON_KEY_COMPROMISE = 1;
    const REASON_AFFILIATION_CHANGED = 3;
    const REASON_SUPERSEDED = 4;
    const REASON_CESSATION_OF_OPERATION = 5;

    /** 原因码的中文名，CLI 里展示用 */
    const REASON_NAMES = [
        self::REASON_UNSPECIFIED => '未指定',
        self::REASON_KEY_COMPROMISE => '私钥泄露（会拉黑该公钥）',
        self::REASON_AFFILIATION_CHANGED => '归属变更',
        self::REASON_SUPERSEDED => '已被新证书取代',
        self::REASON_CESSATION_OF_OPERATION => '停止使用',
    ];

    /** @var HttpClient */
    private $http;

    /** @var CertificateStorage */
    private $storage;

    /** @var AccountService */
    private $accounts;

    /** @var Logger */
    private $logger;

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

    /**
     * 吊销本机存着的某张证书。
     *
     * @param int $reason 见上面的 REASON_* 常量
     * @param bool $removeFiles 吊销后是否连本地文件一起删掉
     */
    public function revoke(
        string $domain,
        bool $ecc = false,
        int $reason = self::REASON_UNSPECIFIED,
        ?string $ca = null,
        bool $removeFiles = false
    ): void {
        $certificate = $this->storage->loadCertificate($domain, $ecc);
        if ($certificate === null) {
            throw new ConfigException(sprintf(
                '找不到 %s 的证书%s。用 list 命令看看有哪些证书',
                $domain,
                $ecc ? '（ECC）' : ''
            ));
        }

        // CA 优先从证书自己的 .conf 里读：证书是哪家签的就得找哪家吊销，
        // 拿 Let's Encrypt 的账户去吊销 ZeroSSL 的证书只会得到 unauthorized
        if ($ca === null) {
            $config = $this->storage->getConfig($domain, $ecc);
            $ca = $config->get(CertificateStorage::KEY_API, CaRegistry::DEFAULT_CA);
        }

        $directoryUrl = CaRegistry::resolveUrl((string) $ca);

        $client = AcmeClient::create($this->http, $directoryUrl, $this->logger);
        $account = $this->accounts->findLocal((string) $ca);

        $this->logger->info(sprintf(
            '正在吊销 %s 的证书（原因：%s）',
            $domain,
            isset(self::REASON_NAMES[$reason]) ? self::REASON_NAMES[$reason] : (string) $reason
        ));

        if ($account !== null) {
            $client->useAccount($account);
            $client->revokeCertificate($certificate->getPem(), $reason);
        } else {
            // 没有账户时用证书私钥签吊销请求。这是 RFC 8555 给
            // 「账户丢了但私钥还在」准备的后路
            $keyPair = $this->storage->loadKey($domain, $ecc);
            if ($keyPair === null) {
                throw new ConfigException(sprintf(
                    '既没有 %s 的账户，也找不到证书私钥，无法吊销',
                    CaRegistry::getDisplayName((string) $ca)
                ));
            }

            $this->logger->debug('没有账户，改用证书私钥签名吊销请求');
            $client->setAccountKey($keyPair);
            $client->revokeCertificate($certificate->getPem(), $reason, $keyPair);
        }

        $this->logger->info(sprintf('%s 的证书已吊销', $domain));

        if ($removeFiles) {
            $this->storage->remove($domain, $ecc);
            $this->logger->info(sprintf('已删除本地文件：%s', $this->storage->getPaths()->getDomainDir($domain, $ecc)));
        }
    }

    /**
     * 吊销一份外部证书（不在本机存储里的）。
     */
    public function revokePem(string $certificatePem, string $ca, int $reason = self::REASON_UNSPECIFIED): void
    {
        $directoryUrl = CaRegistry::resolveUrl($ca);
        $client = AcmeClient::create($this->http, $directoryUrl, $this->logger);

        $account = $this->accounts->findLocal($ca);
        if ($account === null) {
            throw new ConfigException(sprintf(
                '本机没有 %s 的账户，无法吊销外部证书',
                CaRegistry::getDisplayName($ca)
            ));
        }

        $client->useAccount($account);
        $client->revokeCertificate($certificatePem, $reason);

        $this->logger->info('证书已吊销');
    }
}
