<?php

declare(strict_types=1);

namespace Mci\Acme\Storage;

use Mci\Acme\Crypto\Certificate;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\StorageException;
use Mci\Acme\Util\Domain;
use Mci\Acme\Util\Filesystem;

/**
 * 证书套件的落盘与读取。
 *
 * 「套件」指一次签发产出的全部东西：私钥、CSR、证书、中间证书、fullchain、
 * 以及记录了签发参数的 .conf。续期时靠 .conf 里的参数原样再跑一遍，
 * 用户不用重新敲一长串命令——这也是 acme.sh 最实用的设计，照搬。
 *
 * 落盘顺序是有讲究的：先私钥后证书。反过来的话，如果中途失败，
 * 磁盘上会留下一张配不上私钥的证书，而部署脚本可能已经把它捡走了。
 */
class CertificateStorage
{
    // .conf 里的键名与 acme.sh 保持一致，两边可以互读
    const KEY_DOMAIN = 'Le_Domain';
    const KEY_ALT = 'Le_Alt';
    const KEY_KEYLENGTH = 'Le_Keylength';
    const KEY_WEBROOT = 'Le_Webroot';
    const KEY_API = 'Le_API';
    const KEY_RENEW_DAYS = 'Le_RenewalDays';
    const KEY_NEXT_RENEW_TIME = 'Le_NextRenewTime';
    const KEY_CERT_CREATE_TIME = 'Le_CertCreateTime';
    const KEY_DNS_SLEEP = 'Le_DNSSleep';
    const KEY_PREFERRED_CHAIN = 'Le_PreferredChain';
    const KEY_DEPLOY_HOOK = 'Le_DeployHook';
    const KEY_RELOAD_CMD = 'Le_ReloadCmd';
    const KEY_REAL_CERT_PATH = 'Le_RealCertPath';
    const KEY_REAL_KEY_PATH = 'Le_RealKeyPath';
    const KEY_REAL_CA_PATH = 'Le_RealCACertPath';
    const KEY_REAL_FULLCHAIN_PATH = 'Le_RealFullChainPath';
    const KEY_NOTIFY_HOOK = 'Le_NotifyHook';

    /**
     * 根目录下不是证书的子目录。
     *
     * ca/ 与 tmp/ 是本库自己的；deploy/ dnsapi/ notify/ 是 acme.sh 装在
     * 同一个目录里的脚本——默认根目录就是 ~/.acme.sh，两边共存是常态。
     * 漏掉某个也不会出错（下面还会检查证书文件在不在），只是白跑一次 stat。
     *
     * @var array<int, string>
     */
    const NON_CERT_DIRS = ['ca', 'tmp', 'deploy', 'dnsapi', 'notify'];

    /** @var Paths */
    private $paths;

    /** @var Filesystem */
    private $filesystem;

    public function __construct(Paths $paths, ?Filesystem $filesystem = null)
    {
        $this->paths = $paths;
        $this->filesystem = $filesystem !== null ? $filesystem : new Filesystem();
    }

    public function getPaths(): Paths
    {
        return $this->paths;
    }

    public function exists(string $domain, bool $ecc = false): bool
    {
        return $this->filesystem->isFile($this->paths->getCertPath($domain, $ecc));
    }

    public function hasKey(string $domain, bool $ecc = false): bool
    {
        return $this->filesystem->isFile($this->paths->getKeyPath($domain, $ecc));
    }

    public function loadKey(string $domain, bool $ecc = false): ?KeyPair
    {
        $pem = $this->filesystem->readIfExists($this->paths->getKeyPath($domain, $ecc));
        if ($pem === null || trim($pem) === '') {
            return null;
        }

        return KeyPair::fromPem($pem);
    }

    public function saveKey(string $domain, KeyPair $keyPair, bool $ecc = false): void
    {
        $this->filesystem->writePrivate(
            $this->paths->getKeyPath($domain, $ecc),
            $keyPair->getPrivateKeyPem()
        );
    }

    /**
     * 取证书私钥；没有或类型不符就生成新的。
     *
     * @param bool $forceNew 强制换新私钥。默认复用旧的：很多设备
     *        （HSM、某些 CDN）绑定了公钥指纹，每次续期都换会触发重新配置
     */
    public function loadOrCreateKey(
        string $domain,
        string $keyType,
        bool $ecc = false,
        bool $forceNew = false
    ): KeyPair {
        if (!$forceNew) {
            $existing = $this->loadKey($domain, $ecc);
            if ($existing !== null && $existing->getType() === KeyPair::normalizeType($keyType)) {
                return $existing;
            }
        }

        $keyPair = KeyPair::generate($keyType);
        $this->saveKey($domain, $keyPair, $ecc);

        return $keyPair;
    }

    public function loadCertificate(string $domain, bool $ecc = false): ?Certificate
    {
        $pem = $this->filesystem->readIfExists($this->paths->getCertPath($domain, $ecc));
        if ($pem === null || trim($pem) === '') {
            return null;
        }

        return Certificate::fromPem($pem);
    }

    public function loadFullchain(string $domain, bool $ecc = false): ?string
    {
        return $this->filesystem->readIfExists($this->paths->getFullchainPath($domain, $ecc));
    }

    /**
     * 保存一整条证书链。
     *
     * 链的第一张是叶子证书，其余是中间 CA。三个文件都要写：
     * nginx 要 fullchain，Apache 的老版本要 cert + ca 分开，
     * 某些设备只吃叶子。全写出来省得用户自己拆。
     */
    public function saveCertificateChain(string $domain, string $chainPem, bool $ecc = false): void
    {
        $certificates = Certificate::splitChain($chainPem);
        if ($certificates === []) {
            throw new StorageException('CA 返回的内容里没有证书，无法保存');
        }

        $leaf = $certificates[0];
        $intermediates = \array_slice($certificates, 1);

        $this->filesystem->write($this->paths->getCertPath($domain, $ecc), $leaf);
        $this->filesystem->write(
            $this->paths->getCaCertPath($domain, $ecc),
            $intermediates === [] ? '' : implode('', $intermediates)
        );
        // fullchain 用拆分后重新拼的版本，而不是原样落盘：
        // 这样能顺带统一掉 CRLF 与多余空行，交给 nginx 一定解析得了
        $this->filesystem->write($this->paths->getFullchainPath($domain, $ecc), implode('', $certificates));
    }

    public function saveCsr(string $domain, string $csrPem, bool $ecc = false): void
    {
        $this->filesystem->write($this->paths->getCsrPath($domain, $ecc), $csrPem);
    }

    public function getConfig(string $domain, bool $ecc = false): ConfigFile
    {
        return (new ConfigFile($this->paths->getDomainConfPath($domain, $ecc), $this->filesystem))->load();
    }

    /**
     * 记下这次签发用的参数，续期时照着重放。
     *
     * @param array<int, string> $domains 全部域名，第一个是主域名
     * @param array<string, string|int|bool|null> $extra 额外要记的项
     */
    public function saveIssueConfig(array $domains, array $extra = [], bool $ecc = false): void
    {
        $domains = Domain::normalizeList($domains);
        $main = $domains[0];
        $alt = \array_slice($domains, 1);

        $config = $this->getConfig($main, $ecc);
        $config->set(self::KEY_DOMAIN, $main);
        // 多域名用逗号分隔，和 acme.sh 的 Le_Alt 格式一致
        $config->set(self::KEY_ALT, $alt === [] ? null : implode(',', $alt));
        $config->setMany($extra);
        $config->save();
    }

    /**
     * 从 .conf 读回签发参数。
     *
     * @return array{domains: array<int, string>, config: ConfigFile}
     */
    public function loadIssueConfig(string $domain, bool $ecc = false): array
    {
        $config = $this->getConfig($domain, $ecc);

        $main = $config->get(self::KEY_DOMAIN);
        if ($main === null || $main === '') {
            $main = $domain;
        }

        $domains = [$main];
        $alt = $config->get(self::KEY_ALT);
        if ($alt !== null && trim($alt) !== '') {
            foreach (preg_split('/[,\s]+/', $alt) as $item) {
                $item = trim($item);
                // acme.sh 在没有备用域名时会写 Le_Alt='no'，别把它当成域名
                if ($item !== '' && $item !== 'no') {
                    $domains[] = $item;
                }
            }
        }

        return ['domains' => $domains, 'config' => $config];
    }

    /**
     * 列出所有已签发的证书目录。
     *
     * @return array<int, array{domain: string, ecc: bool, dir: string}>
     */
    public function listCertificates(): array
    {
        $out = [];

        foreach ($this->filesystem->listDirectories($this->paths->getCertHome()) as $name) {
            // 和 acme.sh 共用目录时，那边自己的子目录也会在这里出现，先排掉
            if (\in_array($name, self::NON_CERT_DIRS, true) || str_starts_with($name, '.')) {
                continue;
            }

            $ecc = str_ends_with($name, '_ecc');
            $domain = $ecc ? substr($name, 0, -4) : $name;
            // 目录名里的 _. 是通配符 *. 的转写，还原回去
            $domain = str_replace('_.', '*.', $domain);

            // 目录里没有证书就不算——可能是上次失败留下的空壳
            if (!$this->filesystem->isFile($this->paths->getCertPath($domain, $ecc))) {
                continue;
            }

            $out[] = [
                'domain' => $domain,
                'ecc' => $ecc,
                'dir' => $this->paths->getDomainDir($domain, $ecc),
            ];
        }

        return $out;
    }

    /** 删掉一个证书目录，--remove 用 */
    public function remove(string $domain, bool $ecc = false): bool
    {
        return $this->filesystem->removeDirectory($this->paths->getDomainDir($domain, $ecc));
    }

    /**
     * 记录下次该续期的时间戳。
     *
     * 存成绝对时间而不是「还剩几天」：cron 可能几天才跑一次，
     * 存相对值会随着每次读取而漂移。
     */
    public function markRenewed(string $domain, int $renewDays, bool $ecc = false): void
    {
        $config = $this->getConfig($domain, $ecc);
        $now = time();
        $config->set(self::KEY_CERT_CREATE_TIME, (string) $now);
        $config->set(self::KEY_NEXT_RENEW_TIME, (string) ($now + $renewDays * 86400));
        $config->save();
    }
}
