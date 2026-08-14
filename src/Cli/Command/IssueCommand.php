<?php

declare(strict_types=1);

namespace Mci\Acme\Cli\Command;

use Mci\Acme\Acme;
use Mci\Acme\Ca\CaRegistry;
use Mci\Acme\Challenge\Dns01\ProviderFactory;
use Mci\Acme\Cli\ArgvParser;
use Mci\Acme\Cli\CommandInterface;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Service\SolverFactory;
use Mci\Acme\Storage\CertificateStorage;
use Mci\Acme\Util\Logger;

/**
 * 签发证书。这是整个 CLI 的主命令。
 */
class IssueCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['issue'];
    }

    public function getSummary(): string
    {
        return '签发证书（已有且未到续期时间则跳过）';
    }

    public function getUsage(): string
    {
        return implode("\n", [
            '用法：mci-acme issue -d <域名> [-d <域名>...] <验证方式> [选项]',
            '',
            '验证方式（三选一）：',
            '  -w, --webroot <目录>     http-01：把验证文件写到网站根目录',
            '      --dns <提供商>       dns-01：通过解析商 API 加 TXT 记录（通配符必须用这个）',
            '      --standalone         http-01：临时占用 80 端口自己应答',
            '      --alpn               tls-alpn-01：临时占用 443 端口自己应答',
            '',
            '主要选项：',
            '  -d, --domain <域名>      要签的域名，可重复，也可用逗号分隔',
            '  -k, --keylength <类型>   ' . implode(' / ', KeyPair::supportedTypes()) . '（默认 ' . KeyPair::DEFAULT_TYPE . '）',
            '      --ca <CA>            ' . implode(' / ', array_keys(CaRegistry::all())) . '，或直接写目录 URL',
            '  -m, --email <邮箱>       账户联系邮箱，CA 用它发到期提醒',
            '  -f, --force              即使没到续期时间也强制重签',
            '      --new-key            换一把新的证书私钥（默认复用旧的）',
            '      --days <天数>        到期前多少天算该续了（默认 30）',
            '      --dns-sleep <秒>     等 TXT 记录传播的最长时间（默认 120）',
            '      --preferred-chain <名称>  偏好的证书链根，如 "ISRG Root X1"',
            '      --eab-kid <值>       External Account Binding 的 Key ID',
            '      --eab-hmac-key <值>  External Account Binding 的 HMAC Key',
            '      --csr <文件>         用自带的 CSR，不再生成私钥',
            '      --port <端口>        standalone/alpn 模式监听的端口',
            '',
            '支持的 DNS 提供商：',
            '  ' . implode(' ', ProviderFactory::supportedProviders()),
            '',
            '例子：',
            '  mci-acme issue -d example.com -d www.example.com -w /var/www/html',
            '  mci-acme issue -d example.com -d "*.example.com" --dns dns_cf -k ec-384',
            '  mci-acme issue -d example.com --standalone --ca letsencrypt_test',
        ]);
    }

    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int
    {
        $domains = $args->getAll('domain');
        if ($domains === []) {
            throw new ConfigException('至少要用 -d 指定一个域名');
        }

        $solverSpec = $this->resolveSolverSpec($args);
        $options = $this->buildOptions($args, $solverSpec);

        $result = $acme->issue($domains, $solverSpec, $options);

        if ($result->isSkipped()) {
            $logger->write($result->getMessage());

            return 0;
        }

        $paths = $result->getPaths();
        $certificate = $result->getCertificate();

        $logger->write('');
        $logger->write('证书已签发：');
        $logger->write(sprintf('  域名　　：%s', implode(', ', $result->getDomains())));
        if ($certificate !== null) {
            $logger->write(sprintf('  有效期至：%s（还有 %d 天）', gmdate('Y-m-d H:i:s', $certificate->getNotAfter()), $certificate->getDaysUntilExpiry()));
            $logger->write(sprintf('  颁发者　：%s', $certificate->getIssuerCommonName()));
        }
        $logger->write(sprintf('  私钥　　：%s', $paths['key']));
        $logger->write(sprintf('  证书　　：%s', $paths['cert']));
        $logger->write(sprintf('  中间证书：%s', $paths['ca']));
        $logger->write(sprintf('  完整链　：%s', $paths['fullchain']));
        $logger->write('');
        $logger->write('接下来通常要把证书装到服务用的位置：');
        $logger->write(sprintf(
            '  mci-acme install-cert -d %s --key-file /path/to/key --fullchain-file /path/to/crt --reload-service nginx',
            $result->getMainDomain()
        ));

        return 0;
    }

    /**
     * 从各个互斥选项里定出验证方式。
     */
    private function resolveSolverSpec(ArgvParser $args): string
    {
        $webroot = $args->get('webroot');
        $dns = $args->get('dns');
        $standalone = $args->getFlag('standalone');
        $alpn = $args->getFlag('alpn');

        $given = 0;
        foreach ([$webroot !== null, $dns !== null, $standalone, $alpn] as $flag) {
            if ($flag) {
                ++$given;
            }
        }

        if ($given === 0) {
            throw new ConfigException(
                '没有指定验证方式。三选一：'
                . '-w <网站根目录>（最常用）、--dns <提供商>（通配符必须用它）、--standalone（临时占用 80 端口）'
            );
        }

        if ($given > 1) {
            throw new ConfigException('验证方式只能选一种，-w / --dns / --standalone / --alpn 不能同时给');
        }

        if ($webroot !== null) {
            return $webroot;
        }
        if ($dns !== null) {
            return $dns;
        }

        return $standalone ? SolverFactory::MODE_STANDALONE : SolverFactory::MODE_TLS_ALPN;
    }

    /**
     * @return array<string, mixed>
     */
    private function buildOptions(ArgvParser $args, string $solverSpec): array
    {
        $options = [
            'force' => $args->getFlag('force'),
            'new_key' => $args->getFlag('new-key'),
            'renew_days' => $args->getInt('days', 30),
            'dns_sleep' => $args->getInt('dns-sleep', 120),
        ];

        foreach ([
            'ca' => 'ca',
            'keylength' => 'key_type',
            'email' => 'email',
            'preferred-chain' => 'preferred_chain',
        ] as $option => $key) {
            $value = $args->get($option);
            if ($value !== null && $value !== '') {
                $options[$key] = $value;
            }
        }

        if ($args->has('port')) {
            $options['port'] = $args->getInt('port', 80);
        }

        $eabKid = $args->get('eab-kid');
        $eabHmac = $args->get('eab-hmac-key');
        if ($eabKid !== null && $eabHmac !== null) {
            $options['eab'] = ['kid' => $eabKid, 'hmac' => $eabHmac];
        } elseif ($eabKid !== null || $eabHmac !== null) {
            throw new ConfigException('--eab-kid 与 --eab-hmac-key 必须同时提供');
        }

        $csrFile = $args->get('csr');
        if ($csrFile !== null && $csrFile !== '') {
            $csr = @file_get_contents($csrFile);
            if ($csr === false) {
                throw new ConfigException(sprintf('读不到 CSR 文件：%s', $csrFile));
            }
            $options['csr'] = $csr;
        }

        // DNS 凭据从环境变量取出来存进 .conf，续期时不用再 export。
        // 手动模式不存——它本来就没法自动续期
        $extra = [];
        if (str_starts_with($solverSpec, 'dns') && $solverSpec !== ProviderFactory::MANUAL) {
            foreach (ProviderFactory::credentialKeys($solverSpec) as $key) {
                $value = getenv($key);
                if (\is_string($value) && $value !== '') {
                    // 加 SAVED_ 前缀与 acme.sh 保持一致
                    $extra['SAVED_' . $key] = $value;
                }
            }
        }

        if ($args->has('dns-sleep')) {
            $extra[CertificateStorage::KEY_DNS_SLEEP] = (string) $args->getInt('dns-sleep', 120);
        }

        if ($extra !== []) {
            $options['extra_config'] = $extra;
        }

        // 手动验证没法无人值守续期，不写续期配置免得 cron 白跑
        if ($solverSpec === ProviderFactory::MANUAL || $solverSpec === SolverFactory::MODE_MANUAL) {
            $options['persist_config'] = false;
        }

        return $options;
    }
}
