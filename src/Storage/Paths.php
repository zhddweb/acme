<?php

declare(strict_types=1);

namespace Mci\Acme\Storage;

use Mci\Acme\Ca\CaRegistry;
use Mci\Acme\Util\Domain;
use Mci\Acme\Util\Platform;

/**
 * 目录布局的唯一权威。
 *
 * 所有路径拼接都收在这里，别处不许出现字符串拼路径——布局要改的时候
 * 只有这一个地方需要动，而且能保证 CLI 打印给用户的路径和实际写入的一致。
 *
 * 布局与 acme.sh 完全一致，而且默认就用 acme.sh 的那个目录（~/.acme.sh），
 * 装过 acme.sh 的机器上原有的账户与证书直接可用，不必重签、不必迁移：
 *
 *   <base>/account.conf                     全局配置
 *   <base>/ca/<host>/<path>/account.key     账户私钥
 *   <base>/ca/<host>/<path>/ca.conf         账户元数据
 *   <base>/<domain>[_ecc]/<domain>.key      证书私钥
 *   <base>/<domain>[_ecc]/<domain>.cer      证书
 *   <base>/<domain>[_ecc]/ca.cer            中间证书
 *   <base>/<domain>[_ecc]/fullchain.cer     证书 + 中间证书
 *   <base>/<domain>[_ecc]/<domain>.conf     这张证书的签发参数
 */
class Paths
{
    /** 默认目录名——就是 acme.sh 的那个，为的是两边共用同一份数据 */
    const DIR_NAME = '.acme.sh';

    /** 1.0 之前的默认目录名，只在它已经存在时兜底使用 */
    const LEGACY_DIR_NAME = '.mci-acme';

    /**
     * 按优先级排列的根目录环境变量。
     *
     * 后两个是 acme.sh 自己的：LE_CONFIG_HOME 对应它的 --config-home，
     * LE_WORKING_DIR 对应 --home（acme.sh 里 LE_CONFIG_HOME 缺省就等于它）。
     * 认这两个变量，用 acme.sh 时把目录挪过位置的人才不用再配一遍。
     *
     * @var array<int, string>
     */
    const HOME_ENV_VARS = ['MCI_ACME_CONFIG_HOME', 'LE_CONFIG_HOME', 'LE_WORKING_DIR'];

    /** @var string */
    private $baseDir;

    /** @var string 证书目录的根，默认与 baseDir 相同（对应 acme.sh 的 CERT_HOME） */
    private $certHome;

    /** @var bool 证书根是否被显式指定过 */
    private $certHomeExplicit = false;

    public function __construct(?string $baseDir = null, ?string $certHome = null)
    {
        $this->baseDir = $baseDir !== null && $baseDir !== ''
            ? rtrim($baseDir, '/\\')
            : self::defaultBaseDir();
        $this->certHome = $this->baseDir;

        if ($certHome === null || $certHome === '') {
            $env = getenv('CERT_HOME');
            $certHome = \is_string($env) && $env !== '' ? $env : null;
        }
        if ($certHome !== null && $certHome !== '') {
            $this->setCertHome($certHome);
        }
    }

    /**
     * 默认根目录。
     *
     * 直接用 acme.sh 的 ~/.acme.sh，不另起炉灶——目标用户里很多人机器上
     * 已经有 acme.sh 签好的证书和注册好的账户，换个目录等于逼他们重签一遍，
     * 还会撞上 CA 的速率限制。布局本来就是照抄 acme.sh 的，共用一个目录
     * 两个客户端可以随时互换着用。想彻底分开的话设 MCI_ACME_CONFIG_HOME 即可。
     *
     * 优先级：MCI_ACME_CONFIG_HOME > LE_CONFIG_HOME > LE_WORKING_DIR > ~/.acme.sh。
     *
     * 最后还有一条兜底：早期版本写在 ~/.mci-acme，如果那个目录还在而
     * ~/.acme.sh 不存在，就继续用旧的，免得升级之后用户的证书像凭空消失。
     */
    public static function defaultBaseDir(): string
    {
        foreach (self::HOME_ENV_VARS as $name) {
            $value = getenv($name);
            if (\is_string($value) && $value !== '') {
                return rtrim($value, '/\\');
            }
        }

        $home = Platform::homeDirectory();
        $legacy = $home . '/' . self::LEGACY_DIR_NAME;
        if (!is_dir($home . '/' . self::DIR_NAME) && is_dir($legacy)) {
            return $legacy;
        }

        return $home . '/' . self::DIR_NAME;
    }

    public function getBaseDir(): string
    {
        return $this->baseDir;
    }

    /**
     * 证书存放的根目录。
     *
     * acme.sh 的 --cert-home / CERT_HOME 允许把证书挪到配置目录之外
     * （典型场景：配置在家目录，证书放 /etc/ssl 那种备份得到的位置）。
     * 没设过就等于 baseDir，与 acme.sh 的缺省行为一致。
     */
    public function getCertHome(): string
    {
        return $this->certHome;
    }

    /**
     * 指定证书根目录。
     *
     * 允许构造之后再设，是因为这个值可能存在 account.conf 里——
     * 而 account.conf 的路径本身要先有 baseDir 才知道，读它必然发生在构造之后。
     */
    public function setCertHome(string $certHome): void
    {
        $certHome = rtrim(trim($certHome), '/\\');
        if ($certHome === '') {
            return;
        }

        $this->certHome = $certHome;
        $this->certHomeExplicit = true;
    }

    /** 证书根是否被显式指定过——用来决定要不要拿配置文件里的值去覆盖 */
    public function hasCustomCertHome(): bool
    {
        return $this->certHomeExplicit;
    }

    /** 全局配置文件 */
    public function getAccountConfPath(): string
    {
        return $this->baseDir . '/account.conf';
    }

    /** 某个 CA 的账户目录 */
    public function getCaDir(string $directoryUrl): string
    {
        return $this->baseDir . '/ca/' . CaRegistry::directoryPath($directoryUrl);
    }

    public function getAccountKeyPath(string $directoryUrl): string
    {
        return $this->getCaDir($directoryUrl) . '/account.key';
    }

    /** 账户元数据（账户 URL、邮箱、EAB 凭据） */
    public function getCaConfPath(string $directoryUrl): string
    {
        return $this->getCaDir($directoryUrl) . '/ca.conf';
    }

    /** 服务端返回的账户对象原文，纯粹留档，排错时有用 */
    public function getAccountJsonPath(string $directoryUrl): string
    {
        return $this->getCaDir($directoryUrl) . '/account.json';
    }

    /**
     * 证书目录。
     *
     * ECC 证书单独放 <domain>_ecc，这样同一个域名可以同时有 RSA 和 ECC 两张证书
     * ——老设备只认 RSA，新设备用 ECC 更快，双证书部署是常见需求。
     */
    public function getDomainDir(string $domain, bool $ecc = false): string
    {
        return $this->certHome . '/' . Domain::directoryName($domain, $ecc);
    }

    /** 证书文件名里用的域名（通配符的 * 换成 _） */
    private function fileBase(string $domain): string
    {
        return str_replace('*.', '_.', Domain::normalize($domain));
    }

    public function getKeyPath(string $domain, bool $ecc = false): string
    {
        return $this->getDomainDir($domain, $ecc) . '/' . $this->fileBase($domain) . '.key';
    }

    public function getCsrPath(string $domain, bool $ecc = false): string
    {
        return $this->getDomainDir($domain, $ecc) . '/' . $this->fileBase($domain) . '.csr';
    }

    public function getCertPath(string $domain, bool $ecc = false): string
    {
        return $this->getDomainDir($domain, $ecc) . '/' . $this->fileBase($domain) . '.cer';
    }

    public function getCaCertPath(string $domain, bool $ecc = false): string
    {
        return $this->getDomainDir($domain, $ecc) . '/ca.cer';
    }

    public function getFullchainPath(string $domain, bool $ecc = false): string
    {
        return $this->getDomainDir($domain, $ecc) . '/fullchain.cer';
    }

    public function getDomainConfPath(string $domain, bool $ecc = false): string
    {
        return $this->getDomainDir($domain, $ecc) . '/' . $this->fileBase($domain) . '.conf';
    }

    /** 续期日志，每次续期追加一行，用于排查「上次到底跑没跑」 */
    public function getRenewLogPath(): string
    {
        return $this->baseDir . '/renew.log';
    }

    /** standalone 模式与 dns-01 的临时文件放这 */
    public function getTempDir(): string
    {
        return $this->baseDir . '/tmp';
    }
}
