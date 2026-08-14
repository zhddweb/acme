<?php

declare(strict_types=1);

namespace PhpAcme\Storage;

use PhpAcme\Ca\CaRegistry;
use PhpAcme\Util\Domain;
use PhpAcme\Util\Platform;

/**
 * 目录布局的唯一权威。
 *
 * 所有路径拼接都收在这里，别处不许出现字符串拼路径——布局要改的时候
 * 只有这一个地方需要动，而且能保证 CLI 打印给用户的路径和实际写入的一致。
 *
 * 布局与 acme.sh 一致：
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
    /** @var string */
    private $baseDir;

    public function __construct(?string $baseDir = null)
    {
        $this->baseDir = $baseDir !== null && $baseDir !== ''
            ? rtrim($baseDir, '/\\')
            : self::defaultBaseDir();
    }

    /**
     * 默认根目录。
     *
     * 优先认 PHP_ACME_HOME，方便在 web sapi 下把它指到可写位置；
     * 其次是 ~/.php-acme。有意不叫 .acme.sh——共存时不会互相覆盖，
     * 想接管 acme.sh 的数据显式把 baseDir 指过去即可。
     */
    public static function defaultBaseDir(): string
    {
        $custom = getenv('PHP_ACME_CONFIG_HOME');
        if (\is_string($custom) && $custom !== '') {
            return rtrim($custom, '/\\');
        }

        return Platform::homeDirectory() . '/.php-acme';
    }

    public function getBaseDir(): string
    {
        return $this->baseDir;
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
        return $this->baseDir . '/' . Domain::directoryName($domain, $ecc);
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
