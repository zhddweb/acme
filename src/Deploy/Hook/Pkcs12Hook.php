<?php

declare(strict_types=1);

namespace Mci\Acme\Deploy\Hook;

use Mci\Acme\Deploy\DeployHookInterface;
use Mci\Acme\Exception\DeployException;
use Mci\Acme\Service\IssueResult;
use Mci\Acme\Util\Filesystem;
use Mci\Acme\Util\Logger;

/**
 * 导出成 PKCS#12（.pfx / .p12）。
 *
 * Windows 的 IIS、Java 的 keystore、以及不少网络设备只吃这个格式
 * ——它把证书、私钥、证书链打包成一个文件。
 *
 * 口令可以为空，但很多导入端（尤其是 Windows 的证书管理器）
 * 遇到空口令会报一个含糊的错，所以默认还是要求给一个。
 */
class Pkcs12Hook implements DeployHookInterface
{
    /** @var string */
    private $targetPath;

    /** @var string */
    private $password;

    /** @var string|null 显示在证书管理器里的名字 */
    private $friendlyName;

    /** @var Filesystem */
    private $filesystem;

    /** @var Logger */
    private $logger;

    public function __construct(
        string $targetPath,
        string $password = '',
        ?string $friendlyName = null,
        ?Logger $logger = null,
        ?Filesystem $filesystem = null
    ) {
        $this->targetPath = $targetPath;
        $this->password = $password;
        $this->friendlyName = $friendlyName;
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->filesystem = $filesystem !== null ? $filesystem : new Filesystem();
    }

    public function getName(): string
    {
        return '导出 PKCS#12';
    }

    public function deploy(IssueResult $result): void
    {
        $certPath = $result->getPath('cert');
        $keyPath = $result->getPath('key');
        $caPath = $result->getPath('ca');

        if ($certPath === null || $keyPath === null) {
            throw new DeployException('导出 PKCS#12 需要证书与私钥，但路径信息不完整');
        }

        $certificate = $this->filesystem->read($certPath);
        $privateKey = $this->filesystem->read($keyPath);

        $options = [];
        if ($this->friendlyName !== null && $this->friendlyName !== '') {
            $options['friendly_name'] = $this->friendlyName;
        }

        // 中间证书要一起打进去，否则客户端会因为链不完整而报警告
        $chain = $caPath !== null ? $this->filesystem->readIfExists($caPath) : null;
        if ($chain !== null && trim($chain) !== '') {
            $options['extracerts'] = \Mci\Acme\Crypto\Certificate::splitChain($chain);
        }

        $output = '';
        $ok = @openssl_pkcs12_export($certificate, $output, $privateKey, $this->password, $options);

        if ($ok === false || $output === '') {
            $errors = [];
            while (($error = openssl_error_string()) !== false) {
                $errors[] = $error;
            }

            throw new DeployException(sprintf(
                'PKCS#12 导出失败：%s',
                $errors === [] ? '（openssl 没有给出原因）' : implode('; ', $errors)
            ));
        }

        // 这个文件里有私钥，权限必须收紧
        $this->filesystem->write($this->targetPath, $output, Filesystem::MODE_PRIVATE);

        $this->logger->info(sprintf('已导出 PKCS#12：%s', $this->targetPath));
    }
}
