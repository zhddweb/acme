<?php

declare(strict_types=1);

namespace PhpAcme\Cli\Command;

use PhpAcme\Acme;
use PhpAcme\Ca\CaRegistry;
use PhpAcme\Challenge\Dns01\ProviderFactory;
use PhpAcme\Cli\ArgvParser;
use PhpAcme\Cli\CommandInterface;
use PhpAcme\Crypto\Certificate;
use PhpAcme\Crypto\Csr;
use PhpAcme\Crypto\KeyPair;
use PhpAcme\Exception\ConfigException;
use PhpAcme\Util\DnsResolver;
use PhpAcme\Util\Domain;
use PhpAcme\Util\Filesystem;
use PhpAcme\Util\Logger;

/**
 * 零散的工具命令：生成密钥/CSR、看证书、查 DNS、列 CA 与 DNS 提供商。
 *
 * 合在一个类里是因为它们都很小，而且都属于「排错和准备工作」这一类，
 * 拆成十个文件只会让 help 列表变得啰嗦。
 */
class ToolsCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['tools', 'create-key', 'create-csr', 'show-csr', 'show-cert', 'check-dns', 'list-ca', 'list-dns'];
    }

    public function getSummary(): string
    {
        return '工具集：生成密钥/CSR、查看证书、排查 DNS';
    }

    public function getUsage(): string
    {
        return implode("\n", [
            '用法：php-acme tools <工具> [选项]',
            '',
            '工具：',
            '  create-key -k <类型> [-o <文件>]          生成一把私钥',
            '  create-csr -d <域名>... -k <类型> [-o <文件>]  生成 CSR（自带私钥）',
            '  show-csr <文件>                          解析 CSR，看里面有哪些域名',
            '  show-cert <文件>                         解析证书，看有效期与域名',
            '  check-dns -d <域名>                      查 _acme-challenge 的 TXT 记录',
            '  list-ca                                  列出内置的 CA',
            '  list-dns                                 列出支持的 DNS 提供商及所需凭据',
            '',
            'check-dns 是排查 dns-01 失败的第一步：它直接问域名的权威 NS，',
            '绕开所有缓存，看到的就是 CA 会看到的。',
        ]);
    }

    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int
    {
        $tool = $this->resolveTool($args);

        switch ($tool) {
            case 'create-key':
                return $this->createKey($args, $logger);
            case 'create-csr':
                return $this->createCsr($args, $logger);
            case 'show-csr':
                return $this->showCsr($args, $logger);
            case 'show-cert':
                return $this->showCert($args, $logger);
            case 'check-dns':
                return $this->checkDns($args, $logger);
            case 'list-ca':
                return $this->listCa($logger);
            case 'list-dns':
                return $this->listDns($logger);
            default:
                $logger->write($this->getUsage());

                return 2;
        }
    }

    private function resolveTool(ArgvParser $args): string
    {
        $command = $args->getCommand();

        // 直接当命令用：php-acme create-key -k ec-256
        if ($command !== '' && $command !== 'tools') {
            return $command;
        }

        // 子形式：php-acme tools create-key
        $second = $args->getArgument(1);
        if ($second !== null && $second !== '') {
            return $second;
        }

        // acme.sh 风格的 --create-key
        foreach ($this->getNames() as $name) {
            if ($name !== 'tools' && $args->getFlag($name)) {
                return $name;
            }
        }

        return '';
    }

    private function createKey(ArgvParser $args, Logger $logger): int
    {
        $keyPair = KeyPair::generate((string) $args->get('keylength', KeyPair::DEFAULT_TYPE));
        $pem = $keyPair->getPrivateKeyPem();

        $output = $args->get('output', $args->get('o'));
        if ($output !== null && $output !== '') {
            (new Filesystem())->writePrivate($output, $pem);
            $logger->write(sprintf('已生成 %s 私钥：%s（权限 0600）', $keyPair->getType(), $output));

            return 0;
        }

        $logger->write($pem);

        return 0;
    }

    private function createCsr(ArgvParser $args, Logger $logger): int
    {
        $domains = $args->getAll('domain');
        if ($domains === []) {
            throw new ConfigException('用 -d 指定域名');
        }

        $keyFile = $args->get('key-file');
        $keyPair = $keyFile !== null && $keyFile !== ''
            ? KeyPair::fromPem((new Filesystem())->read($keyFile))
            : KeyPair::generate((string) $args->get('keylength', KeyPair::DEFAULT_TYPE));

        $subject = [];
        foreach (['C', 'ST', 'L', 'O', 'OU'] as $field) {
            $value = $args->get(strtolower($field));
            if ($value !== null && $value !== '') {
                $subject[$field] = $value;
            }
        }

        $csrPem = Csr::createPem($keyPair, $domains, $subject);

        $output = $args->get('output', $args->get('o'));
        if ($output !== null && $output !== '') {
            $filesystem = new Filesystem();
            $filesystem->write($output, $csrPem);

            // 自己生成的私钥必须一起给出来，否则这个 CSR 没用
            if ($keyFile === null || $keyFile === '') {
                $keyPath = preg_replace('/\.csr$/', '', $output) . '.key';
                $filesystem->writePrivate($keyPath, $keyPair->getPrivateKeyPem());
                $logger->write(sprintf('私钥：%s', $keyPath));
            }

            $logger->write(sprintf('CSR：%s', $output));

            return 0;
        }

        $logger->write($csrPem);
        if ($keyFile === null || $keyFile === '') {
            $logger->write($keyPair->getPrivateKeyPem());
        }

        return 0;
    }

    private function showCsr(ArgvParser $args, Logger $logger): int
    {
        $file = $this->requireFile($args, 'CSR');
        $content = (new Filesystem())->read($file);

        $domains = Csr::extractDomains($content);
        $subject = @openssl_csr_get_subject($content);

        $logger->write(sprintf('域名：%s', $domains === [] ? '（没有找到）' : implode(', ', $domains)));

        if (\is_array($subject)) {
            $parts = [];
            foreach ($subject as $key => $value) {
                $parts[] = $key . '=' . (\is_array($value) ? implode('+', $value) : $value);
            }
            $logger->write(sprintf('主体：%s', implode(', ', $parts)));
        }

        return 0;
    }

    private function showCert(ArgvParser $args, Logger $logger): int
    {
        $file = $this->requireFile($args, '证书');
        $certificate = Certificate::fromFile($file);

        $logger->write(sprintf('域名　　：%s', implode(', ', $certificate->getDomains())));
        $logger->write(sprintf('颁发者　：%s', $certificate->getIssuerCommonName()));
        $logger->write(sprintf('序列号　：%s', $certificate->getSerialNumber()));
        $logger->write(sprintf('生效时间：%s', gmdate('Y-m-d H:i:s', $certificate->getNotBefore())));
        $logger->write(sprintf(
            '到期时间：%s（%s）',
            gmdate('Y-m-d H:i:s', $certificate->getNotAfter()),
            $certificate->isExpired() ? '已过期' : sprintf('还有 %d 天', $certificate->getDaysUntilExpiry())
        ));
        $logger->write(sprintf('密钥类型：%s', $certificate->isEc() ? 'EC' : 'RSA'));

        return 0;
    }

    private function checkDns(ArgvParser $args, Logger $logger): int
    {
        $domain = $args->get('domain');
        if ($domain === null || $domain === '') {
            throw new ConfigException('用 -d 指定要查的域名');
        }

        $resolver = new DnsResolver(null, $logger);
        $record = Domain::challengeRecordName($domain);

        $logger->write(sprintf('查询 %s 的权威 NS...', $domain));
        $nameservers = $resolver->authoritativeNameservers(Domain::stripWildcard($domain));

        if ($nameservers === []) {
            $logger->write('查不到权威 NS。可能这个域名还没解析，或者 UDP 53 被网络屏蔽了。');
        } else {
            $logger->write(sprintf('权威 NS：%s', implode(', ', $nameservers)));
        }

        $logger->write('');
        $logger->write(sprintf('查询 TXT 记录 %s ...', $record));

        $values = $resolver->txtFromAuthoritative($record);

        if ($values === []) {
            $logger->write('没有查到 TXT 记录。');
            $logger->write('如果正在签发中，说明记录还没传播开或者根本没加上去。');
        } else {
            foreach ($values as $value) {
                $logger->write(sprintf('  %s', $value));
            }
        }

        return 0;
    }

    private function listCa(Logger $logger): int
    {
        $logger->write(sprintf('%-18s %-28s %-6s %s', '短名', '名称', 'EAB', '目录 URL'));
        $logger->write(str_repeat('-', 100));

        foreach (CaRegistry::all() as $key => $meta) {
            $logger->write(sprintf(
                '%-18s %-28s %-6s %s',
                $key,
                $meta['name'],
                $meta['eab'] ? '需要' : '不需要',
                $meta['url']
            ));
        }

        $logger->write('');
        $logger->write('调试阶段请用 letsencrypt_test（staging），它的速率限制宽松得多，');
        $logger->write('签出来的证书不被浏览器信任，但流程完全一样。');

        return 0;
    }

    private function listDns(Logger $logger): int
    {
        $logger->write(sprintf('%-22s %-22s %s', '短名', '提供商', '需要的环境变量'));
        $logger->write(str_repeat('-', 90));

        foreach (ProviderFactory::MAP as $key => $meta) {
            $logger->write(sprintf('%-22s %-22s %s', $key, $meta['name'], implode(' ', $meta['keys'])));
        }

        $logger->write(sprintf('%-22s %-22s %s', ProviderFactory::MANUAL, '手动 DNS', '（无需凭据，不能自动续期）'));
        $logger->write('');
        $logger->write('用法：先 export 对应的变量，再 php-acme issue -d 域名 --dns <短名>');
        $logger->write('签发时凭据会存进证书目录的 .conf，之后续期不用再 export。');

        return 0;
    }

    private function requireFile(ArgvParser $args, string $label): string
    {
        // 支持两种给法：位置参数或 --file
        $file = $args->getArgument(1);
        if ($file === null || $file === '' || $file === $args->getCommand()) {
            $file = $args->get('file');
        }

        if ($file === null || $file === '') {
            throw new ConfigException(sprintf('请指定%s文件路径', $label));
        }

        if (!is_file($file)) {
            throw new ConfigException(sprintf('文件不存在：%s', $file));
        }

        return $file;
    }
}
