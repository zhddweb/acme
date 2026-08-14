<?php

declare(strict_types=1);

namespace Mci\Acme\Cli\Command;

use Mci\Acme\Acme;
use Mci\Acme\Cli\ArgvParser;
use Mci\Acme\Cli\CommandInterface;
use Mci\Acme\Deploy\Hook\InstallFilesHook;
use Mci\Acme\Deploy\Hook\Pkcs12Hook;
use Mci\Acme\Deploy\Hook\ReloadSignalHook;
use Mci\Acme\Deploy\Hook\TouchFileHook;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Service\IssueResult;
use Mci\Acme\Storage\CertificateStorage;
use Mci\Acme\Util\Logger;

/**
 * 把证书安装到服务实际读取的位置，并记住这套配置供续期时自动重放。
 *
 * 对应 acme.sh 的 --install-cert。差别在重载方式：acme.sh 用
 * `--reloadcmd "systemctl reload nginx"` 执行 shell，本库不执行外部进程，
 * 改成 `--reload-service nginx` 直接给进程发 SIGHUP，效果相同。
 */
class InstallCertCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['install-cert', 'installcert'];
    }

    public function getSummary(): string
    {
        return '把证书安装到指定路径并重载服务';
    }

    public function getUsage(): string
    {
        return implode("\n", [
            '用法：mci-acme install-cert -d <域名> [目标路径选项] [重载选项]',
            '',
            '目标路径：',
            '      --key-file <路径>        私钥装到哪',
            '      --cert-file <路径>       证书装到哪',
            '      --ca-file <路径>         中间证书装到哪',
            '      --fullchain-file <路径>  完整链装到哪（nginx 用这个）',
            '      --pfx-file <路径>        另外导出一份 PKCS#12（IIS / Java 用）',
            '      --pfx-password <口令>    PKCS#12 的口令',
            '',
            '重载服务：',
            '      --reload-service <名称>  给服务发重载信号，可选值：',
            '                               ' . implode(' / ', array_keys(ReloadSignalHook::PRESETS)),
            '      --reload-pid <文件>      服务的 pid 文件位置（默认按服务名推断）',
            '      --touch-file <路径>      改成写一个标记文件，由外部脚本去重载',
            '',
            '其他：',
            '      --ecc                 装 ECC 那张证书',
            '      --key-mode <权限>     私钥安装后的权限，默认 0640',
            '      --owner <用户[:组]>   安装后的属主，需要 root',
            '',
            '这些设置会记进证书的 .conf，之后每次续期成功都会自动重放一遍，',
            '不用再手工执行。',
            '',
            '例子：',
            '  mci-acme install-cert -d example.com \\',
            '      --key-file /etc/nginx/ssl/example.com.key \\',
            '      --fullchain-file /etc/nginx/ssl/example.com.crt \\',
            '      --reload-service nginx',
            '',
            '没有 ext-posix 时改用标记文件，配合 systemd path unit：',
            '  mci-acme install-cert -d example.com --key-file ... --touch-file /run/mci-acme/renewed.json',
        ]);
    }

    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int
    {
        $domain = $args->get('domain');
        if ($domain === null || $domain === '') {
            throw new ConfigException('用 -d 指定域名');
        }

        $ecc = $args->getFlag('ecc');
        $storage = $acme->getCertificateStorage();

        if (!$storage->exists($domain, $ecc)) {
            throw new ConfigException(sprintf('找不到 %s 的证书，先签发一张', $domain));
        }

        $result = $this->buildResult($storage, $domain, $ecc);

        $targets = [];
        foreach (['key' => 'key-file', 'cert' => 'cert-file', 'ca' => 'ca-file', 'fullchain' => 'fullchain-file'] as $type => $option) {
            $path = $args->get($option);
            if ($path !== null && $path !== '') {
                $targets[$type] = $path;
            }
        }

        $pfx = $args->get('pfx-file');

        if ($targets === [] && ($pfx === null || $pfx === '')) {
            throw new ConfigException(
                '没有指定要装到哪。至少给一个 --key-file / --cert-file / --fullchain-file / --ca-file / --pfx-file'
            );
        }

        if ($targets !== []) {
            $hook = new InstallFilesHook($targets, $logger);

            $keyMode = $args->get('key-mode');
            if ($keyMode !== null && $keyMode !== '') {
                // 权限是八进制写法，intval 按十进制读会把 0640 读成 640
                $hook->setKeyMode((int) octdec(ltrim($keyMode, '0') !== '' ? $keyMode : '0640'));
            }

            $hook->setOwner($args->get('owner'));
            $hook->deploy($result);
        }

        if ($pfx !== null && $pfx !== '') {
            $pkcs12 = new Pkcs12Hook($pfx, (string) $args->get('pfx-password', ''), $domain, $logger);
            $pkcs12->deploy($result);
        }

        $this->runReload($args, $result, $logger);

        // 把这套安装配置记进 .conf，续期成功后自动重放
        $this->persist($args, $storage, $domain, $ecc, $targets, $pfx);

        $logger->write('安装完成。之后每次续期成功都会自动重复这套动作。');

        return 0;
    }

    private function runReload(ArgvParser $args, IssueResult $result, Logger $logger): void
    {
        $service = $args->get('reload-service');
        if ($service !== null && $service !== '') {
            ReloadSignalHook::forService($service, $args->get('reload-pid'), $logger)->deploy($result);
        }

        $touchFile = $args->get('touch-file');
        if ($touchFile !== null && $touchFile !== '') {
            (new TouchFileHook($touchFile, $logger))->deploy($result);
        }
    }

    /**
     * @param array<string, string> $targets
     */
    private function persist(
        ArgvParser $args,
        CertificateStorage $storage,
        string $domain,
        bool $ecc,
        array $targets,
        ?string $pfx
    ): void {
        $config = $storage->getConfig($domain, $ecc);

        $config->set(CertificateStorage::KEY_REAL_KEY_PATH, isset($targets['key']) ? $targets['key'] : null);
        $config->set(CertificateStorage::KEY_REAL_CERT_PATH, isset($targets['cert']) ? $targets['cert'] : null);
        $config->set(CertificateStorage::KEY_REAL_CA_PATH, isset($targets['ca']) ? $targets['ca'] : null);
        $config->set(
            CertificateStorage::KEY_REAL_FULLCHAIN_PATH,
            isset($targets['fullchain']) ? $targets['fullchain'] : null
        );

        $config->set('Le_PfxPath', $pfx);
        $config->set('Le_PfxPassword', $args->get('pfx-password'));
        $config->set('Le_ReloadService', $args->get('reload-service'));
        $config->set('Le_ReloadPid', $args->get('reload-pid'));
        $config->set('Le_TouchFile', $args->get('touch-file'));
        $config->set('Le_KeyMode', $args->get('key-mode'));
        $config->set('Le_Owner', $args->get('owner'));

        $config->save();
    }

    private function buildResult(CertificateStorage $storage, string $domain, bool $ecc): IssueResult
    {
        $paths = $storage->getPaths();

        return new IssueResult(
            true,
            false,
            $domain,
            [$domain],
            $storage->loadCertificate($domain, $ecc),
            [
                'key' => $paths->getKeyPath($domain, $ecc),
                'cert' => $paths->getCertPath($domain, $ecc),
                'ca' => $paths->getCaCertPath($domain, $ecc),
                'fullchain' => $paths->getFullchainPath($domain, $ecc),
                'conf' => $paths->getDomainConfPath($domain, $ecc),
                'dir' => $paths->getDomainDir($domain, $ecc),
            ],
            '手工安装'
        );
    }
}
