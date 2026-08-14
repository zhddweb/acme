<?php

declare(strict_types=1);

/**
 * 对 Let's Encrypt staging 环境跑一次真实签发。
 *
 * **这个测试默认不跑**，也不在 `composer test` 里——它需要一个你能控制 DNS
 * 或 web 根目录的真实域名，跑一次要几十秒，还会在 CA 那边留下记录。
 * 离线测试（`composer test`）已经用 FakeAcmeServer 覆盖了全部协议逻辑，
 * 这个脚本的作用是确认「跟真实 CA 对接时也没问题」——网络、TLS、
 * 以及 staging 与我们假设的行为是否一致。
 *
 * 用法：
 *
 *     export ACME_TEST_DOMAIN=test.example.com
 *     export ACME_TEST_WEBROOT=/var/www/html
 *     composer test-network
 *
 * 或者用 DNS 验证（能测通配符）：
 *
 *     export ACME_TEST_DOMAIN=test.example.com
 *     export ACME_TEST_DNS=dns_cf
 *     export CF_Token=你的令牌
 *     composer test-network
 *
 * 一律打 staging，**绝不要改成正式环境**：正式环境每域名每周只能签 5 张，
 * 测试跑几次就把额度用光了。
 */

require __DIR__ . '/../lib/bootstrap.php';

use Mci\Acme\Acme;
use Mci\Acme\Tests\Runner;
use Mci\Acme\Util\Logger;

$t = new Runner('Let\'s Encrypt staging 真实签发');

$domain = getenv('ACME_TEST_DOMAIN');
$webroot = getenv('ACME_TEST_WEBROOT');
$dns = getenv('ACME_TEST_DNS');

if (!\is_string($domain) || $domain === '') {
    echo "  跳过：没有设置 ACME_TEST_DOMAIN。\n";
    echo "  这个测试需要一个你能控制的真实域名，用法见文件头的注释。\n\n";
    exit(0);
}

$solverSpec = '';
if (\is_string($dns) && $dns !== '') {
    $solverSpec = $dns;
} elseif (\is_string($webroot) && $webroot !== '') {
    $solverSpec = $webroot;
} else {
    echo "  跳过：需要设置 ACME_TEST_WEBROOT 或 ACME_TEST_DNS 之一。\n\n";
    exit(0);
}

$base = sys_get_temp_dir() . '/mci-acme-staging-' . getmypid();

$logger = new Logger(Logger::LEVEL_DEBUG, STDOUT);
$acme = new Acme($base, $logger);

$t->group(sprintf('为 %s 签发（%s）', $domain, $solverSpec));

$domains = [$domain];

// DNS 验证时顺带测通配符——这是 dns-01 独有的能力
if (\is_string($dns) && $dns !== '') {
    $domains[] = '*.' . $domain;
}

$result = $acme->issue($domains, $solverSpec, [
    // 硬编码 staging，不接受从环境变量覆盖
    'ca' => 'letsencrypt_test',
    'key_type' => 'ec-256',
    'email' => (string) getenv('ACME_TEST_EMAIL'),
    'force' => true,
]);

$t->ok($result->isIssued(), '证书应当签发成功');

$certificate = $result->getCertificate();
$t->ok($certificate !== null, '应当拿到证书对象');

if ($certificate !== null) {
    $t->ok($certificate->covers($domains), '证书应当覆盖全部申请的域名');
    $t->ok($certificate->getDaysUntilExpiry() > 80, 'staging 证书也是 90 天有效期');
    $t->contains('STAGING', $certificate->getIssuerCommonName(), '颁发者应当是 staging CA —— 确认没有误打正式环境');

    $keyPair = $acme->getCertificateStorage()->loadKey($domain, true);
    $t->ok($keyPair !== null && $certificate->matchesPrivateKey($keyPair), '私钥与证书应当配对');
}

$t->group('续期');

$skipped = $acme->renew($domain, true);
$t->ok($skipped->isSkipped(), '刚签完的证书续期应当被跳过');

$forced = $acme->renew($domain, true, true);
$t->ok($forced->isIssued(), '强制续期应当成功');

$t->group('吊销');

$t->noThrow(static function () use ($acme, $domain): void {
    $acme->revoke($domain, true, \Mci\Acme\Service\RevocationService::REASON_CESSATION_OF_OPERATION);
}, '吊销应当成功');

echo sprintf("\n  测试数据在 %s，确认无误后可以删掉。\n\n", $base);

exit($t->summary());
