<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use PhpAcme\Acme;
use PhpAcme\Challenge\AbstractSolver;
use PhpAcme\Crypto\KeyPair;
use PhpAcme\Exception\ConfigException;
use PhpAcme\Http\HttpClient;
use PhpAcme\Protocol\Challenge;
use PhpAcme\Tests\FakeAcmeServer;
use PhpAcme\Tests\Runner;
use PhpAcme\Util\Logger;

$t = new Runner('续期流程');

/** 只记录调用、不做实际动作的求解器 */
final class NoopSolver extends AbstractSolver
{
    /** @var int */
    public $prepareCount = 0;

    public function getType(): string
    {
        return 'http-01';
    }

    public function prepare(Challenge $challenge, KeyPair $accountKey): void
    {
        ++$this->prepareCount;
    }

    public function cleanup(Challenge $challenge, KeyPair $accountKey): void
    {
    }
}

/**
 * @return array{acme: Acme, server: FakeAcmeServer, base: string, webroot: string}
 */
function buildAcme(?FakeAcmeServer $server = null): array
{
    $server = $server !== null ? $server : new FakeAcmeServer();

    $logger = Logger::silent();
    $http = new HttpClient($server->getTransport(), $logger);
    $http->setSleeper(static function (): void {
    });

    $base = test_temp_dir('renew-' . bin2hex(random_bytes(4)));
    $webroot = $base . '/www';
    mkdir($webroot, 0755, true);

    $acme = new Acme($base, $logger, $http);
    $acme->getIssuer()->setSleeper(static function (): void {
    });

    return ['acme' => $acme, 'server' => $server, 'base' => $base, 'webroot' => $webroot];
}

$t->group('签发之后配置被记下来');

$env = buildAcme();
$acme = $env['acme'];

$result = $acme->issue(['example.com', 'www.example.com'], $env['webroot'], [
    'ca' => $env['server']->getDirectoryUrl(),
    'key_type' => 'ec-256',
    'renew_days' => 30,
]);

$t->ok($result->isIssued(), '首次签发成功');

$config = $acme->getCertificateStorage()->getConfig('example.com', true);
$t->equals($env['webroot'], $config->get('Le_Webroot'), '验证方式应当记进 .conf');
$t->equals('ec-256', $config->get('Le_Keylength'), '密钥类型应当记下来');
$t->equals('30', $config->get('Le_RenewalDays'), '续期天数应当记下来');
$t->equals('www.example.com', $config->get('Le_Alt'), '备用域名应当记下来');

$t->group('续期能读回全部参数');

$request = $acme->getRenewalService()->buildRequestFromConfig('example.com', true);

$t->equals(['example.com', 'www.example.com'], $request->getDomains(), '域名列表应当完整读回');
$t->equals('ec-256', $request->getKeyType(), '密钥类型');
$t->equals(30, $request->getRenewDays(), '续期天数');
$t->equals('http-01', $request->getSolver()->getType(), '验证方式应当重建出来');

$t->group('没到期时续期会跳过');

$renewResult = $acme->renew('example.com', true);
$t->ok($renewResult->isSkipped(), '没到续期窗口应当跳过');

$t->group('强制续期');

$forced = $acme->renew('example.com', true, true);
$t->ok($forced->isIssued(), '加 force 应当重新签发');

$t->group('续期复用同一把证书私钥');

$keyBefore = $acme->getCertificateStorage()->loadKey('example.com', true);
$acme->renew('example.com', true, true);
$keyAfter = $acme->getCertificateStorage()->loadKey('example.com', true);

// 有些设备绑定了公钥指纹，每次续期都换私钥会触发重新配置
$t->equals($keyBefore->getThumbprint(), $keyAfter->getThumbprint(), '默认应当复用私钥');

$t->group('renew-all');

$acme->issue(['second.example.com'], $env['webroot'], ['ca' => $env['server']->getDirectoryUrl()]);

$outcomes = $acme->renewAll();
$t->equals(2, \count($outcomes), '两张证书都应当被检查');

foreach ($outcomes as $outcome) {
    $t->equals('', $outcome['error'], sprintf('%s 不该出错', $outcome['domain']));
    $t->ok($outcome['result'] !== null && $outcome['result']->isSkipped(), '都没到期，应当都跳过');
}

$t->group('renew-all：一张失败不影响其他');

$brokenBase = $env['base'] . '/broken.example.com';
mkdir($brokenBase, 0700, true);
// 造一个有证书文件但没有 .conf 的目录：模拟手工拷贝进来的证书
file_put_contents(
    $brokenBase . '/broken.example.com.cer',
    \PhpAcme\Crypto\SelfSignedCertificate::forPlaceholder(KeyPair::generate('ec-256'), ['broken.example.com'], 86400)
);

$outcomesWithBroken = $acme->renewAll();

$errors = 0;
$fine = 0;
foreach ($outcomesWithBroken as $outcome) {
    if ($outcome['error'] !== '') {
        ++$errors;
    } else {
        ++$fine;
    }
}

$t->equals(1, $errors, '缺配置的那张应当报错');
$t->equals(2, $fine, '其余两张仍要被正常处理——这正是 renew-all 存在的意义');

$t->group('缺配置时的报错要能指导用户');

$t->throws(static function () use ($acme): void {
    $acme->getRenewalService()->buildRequestFromConfig('broken.example.com', false);
}, ConfigException::class, '没有 Le_Webroot 时应当报错');

$t->group('域名列表变化触发重签');

$expanded = $acme->issue(['example.com', 'www.example.com', 'new.example.com'], $env['webroot'], [
    'ca' => $env['server']->getDirectoryUrl(),
]);

$t->ok($expanded->isIssued(), '加了新域名应当重新签发，即使旧证书还没到期');
$certificate = $expanded->getCertificate();
$t->ok(
    $certificate !== null && \in_array('new.example.com', $certificate->getDomains(), true),
    '新证书里应当有新域名'
);

$t->group('部署配置在续期时自动重放');

$installDir = $env['base'] . '/deployed';
mkdir($installDir, 0755, true);

$deployConfig = $acme->getCertificateStorage()->getConfig('example.com', true);
$deployConfig->set('Le_RealKeyPath', $installDir . '/site.key');
$deployConfig->set('Le_RealFullChainPath', $installDir . '/site.crt');
$deployConfig->save();

$acme->renew('example.com', true, true);

$t->ok(is_file($installDir . '/site.key'), '续期后应当自动把私钥装到配置的位置');
$t->ok(is_file($installDir . '/site.crt'), '完整链也应当自动安装');
$t->equals(
    file_get_contents($acme->getPaths()->getFullchainPath('example.com', true)),
    file_get_contents($installDir . '/site.crt'),
    '安装的内容应当与源文件一致'
);
// 装到别处的私钥要让服务读得到，但不能全世界可读
$t->equals('0640', substr(sprintf('%o', fileperms($installDir . '/site.key')), -4), '安装的私钥权限应当是 0640');

exit($t->summary());
