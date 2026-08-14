<?php

declare(strict_types=1);

namespace Mci\Acme\Cli\Command;

use Mci\Acme\Acme;
use Mci\Acme\Ca\CaRegistry;
use Mci\Acme\Ca\Eab;
use Mci\Acme\Cli\ArgvParser;
use Mci\Acme\Cli\CommandInterface;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Protocol\AcmeClient;
use Mci\Acme\Util\Logger;

/**
 * 账户相关操作：注册、改邮箱、换密钥、注销、查看。
 */
class AccountCommand implements CommandInterface
{
    public function getNames(): array
    {
        return ['account', 'register-account', 'update-account', 'deactivate-account'];
    }

    public function getSummary(): string
    {
        return '管理 ACME 账户（注册 / 改邮箱 / 换密钥 / 注销）';
    }

    public function getUsage(): string
    {
        return implode("\n", [
            '用法：mci-acme account <动作> [选项]',
            '',
            '动作：',
            '  show        显示当前账户信息（默认）',
            '  register    注册账户',
            '  update      修改联系邮箱',
            '  rotate-key  更换账户密钥（旧密钥立即失效）',
            '  deactivate  注销账户，不可逆',
            '',
            '选项：',
            '      --ca <CA>            对哪个 CA 操作，默认 ' . CaRegistry::DEFAULT_CA,
            '  -m, --email <邮箱>       联系邮箱',
            '  -k, --keylength <类型>   账户密钥类型，默认 ' . KeyPair::DEFAULT_TYPE,
            '      --eab-kid <值>       External Account Binding 的 Key ID',
            '      --eab-hmac-key <值>  External Account Binding 的 HMAC Key',
            '',
            '一般不用手工注册——首次签发时会自动建账户。',
            '需要单独跑的情况：想先配好 ZeroSSL 的 EAB，或者要换账户密钥。',
        ]);
    }

    public function execute(ArgvParser $args, Acme $acme, Logger $logger): int
    {
        $ca = (string) $args->get('ca', CaRegistry::DEFAULT_CA);
        $action = $this->resolveAction($args);

        switch ($action) {
            case 'register':
                return $this->register($args, $acme, $logger, $ca);
            case 'update':
                return $this->update($args, $acme, $logger, $ca);
            case 'rotate-key':
                return $this->rotateKey($args, $acme, $logger, $ca);
            case 'deactivate':
                return $this->deactivate($acme, $logger, $ca);
            default:
                return $this->show($acme, $logger, $ca);
        }
    }

    private function resolveAction(ArgvParser $args): string
    {
        // acme.sh 风格：--register-account / --update-account / --deactivate-account
        if ($args->getFlag('register-account')) {
            return 'register';
        }
        if ($args->getFlag('update-account')) {
            return 'update';
        }
        if ($args->getFlag('deactivate-account')) {
            return 'deactivate';
        }

        // 子命令风格：account <动作>
        $second = $args->getArgument(1);

        return $second !== null && $second !== '' ? $second : 'show';
    }

    private function register(ArgvParser $args, Acme $acme, Logger $logger, string $ca): int
    {
        $directoryUrl = CaRegistry::resolveUrl($ca);
        $client = AcmeClient::create($acme->getHttpClient(), $directoryUrl, $logger);

        $eab = null;
        $kid = $args->get('eab-kid');
        $hmac = $args->get('eab-hmac-key');

        if ($kid !== null && $hmac !== null) {
            $eab = new Eab($kid, $hmac);
        } elseif ($client->getDirectory()->requiresExternalAccountBinding()) {
            $email = $args->get('email');
            if (str_contains($directoryUrl, 'zerossl.com') && $email !== null) {
                $logger->info('正在向 ZeroSSL 申请 EAB 凭据');
                $eab = Eab::fetchFromZeroSsl($acme->getHttpClient(), $email);
            } else {
                throw new ConfigException(sprintf(
                    '%s 需要 EAB 凭据，请用 --eab-kid 与 --eab-hmac-key 提供',
                    CaRegistry::getDisplayName($ca)
                ));
            }
        }

        $account = $acme->getAccountService()->register(
            $client,
            $directoryUrl,
            $args->get('email'),
            $eab,
            (string) $args->get('keylength', KeyPair::DEFAULT_TYPE)
        );

        $logger->write(sprintf('账户已注册：%s', $account->getUrl()));

        $tos = $client->getDirectory()->getTermsOfService();
        if ($tos !== null) {
            $logger->write(sprintf('（注册即表示同意服务条款：%s）', $tos));
        }

        return 0;
    }

    private function update(ArgvParser $args, Acme $acme, Logger $logger, string $ca): int
    {
        $email = $args->get('email');
        if ($email === null || $email === '') {
            throw new ConfigException('用 -m 指定新的联系邮箱');
        }

        $account = $acme->getAccountService()->updateEmail($ca, $email);

        $logger->write(sprintf('联系邮箱已更新：%s', implode(', ', $account->getEmails())));

        return 0;
    }

    private function rotateKey(ArgvParser $args, Acme $acme, Logger $logger, string $ca): int
    {
        $account = $acme->getAccountService()->rotateKey(
            $ca,
            (string) $args->get('keylength', KeyPair::DEFAULT_TYPE)
        );

        $logger->write(sprintf('账户 %s 的密钥已更换。', $account->getUrl()));
        $logger->write('旧密钥即刻失效，如果别处备份了它，记得一并更新。');

        return 0;
    }

    private function deactivate(Acme $acme, Logger $logger, string $ca): int
    {
        $account = $acme->getAccountService()->deactivate($ca);

        $logger->write(sprintf('账户已注销，当前状态：%s', $account->getStatus()));
        $logger->write('这把密钥不能再签发新证书，已签发的证书仍然有效。');

        return 0;
    }

    private function show(Acme $acme, Logger $logger, string $ca): int
    {
        $account = $acme->getAccountService()->findLocal($ca);

        if ($account === null) {
            $logger->write(sprintf(
                '本机还没有 %s 的账户。首次签发时会自动创建，也可以跑 mci-acme account register 手工建。',
                CaRegistry::getDisplayName($ca)
            ));

            return 0;
        }

        $logger->write(sprintf('CA　　：%s', CaRegistry::getDisplayName($ca)));
        $logger->write(sprintf('账户 URL：%s', $account->getUrl()));
        $logger->write(sprintf('密钥类型：%s', $account->getKeyPair()->getType()));
        $logger->write(sprintf('联系邮箱：%s', $account->getEmails() === [] ? '（未设置）' : implode(', ', $account->getEmails())));
        $logger->write(sprintf('状态　　：%s', $account->getStatus()));
        $logger->write(sprintf(
            '密钥文件：%s',
            $acme->getPaths()->getAccountKeyPath(CaRegistry::resolveUrl($ca))
        ));

        return 0;
    }
}
