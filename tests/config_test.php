<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Ca\CaRegistry;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Storage\ConfigFile;
use Mci\Acme\Tests\Runner;

$t = new Runner('配置文件与 CA 注册表');

$dir = test_temp_dir('config');

$t->group('写入与读回');

$path = $dir . '/test.conf';
$config = new ConfigFile($path);

$values = [
    'Le_Domain' => 'example.com',
    'Le_Alt' => 'www.example.com,*.example.com',
    'Le_Keylength' => 'ec-256',
    'Empty' => '',
    'WithSpaces' => 'a b c',
    // 这几个是最容易在 shell 引号上翻车的
    'WithSingleQuote' => "it's fine",
    'WithDoubleQuote' => 'say "hi"',
    'WithDollar' => 'p$$word',
    'WithEquals' => 'a=b=c',
    'WithBackslash' => 'C:\\path\\to\\file',
    'Chinese' => '中文值也要能存',
];

foreach ($values as $key => $value) {
    $config->set($key, $value);
}
$config->save();

$reloaded = (new ConfigFile($path))->load();

foreach ($values as $key => $value) {
    $t->equals($value, $reloaded->get($key), sprintf('%s 应当原样读回', $key));
}

$t->group('权限');

// 里面存着 DNS API 密钥，不能让同机器的其他用户读到
$t->equals('0600', substr(sprintf('%o', fileperms($path)), -4), '配置文件权限必须是 0600');

$t->group('输出稳定');

$first = file_get_contents($path);
$reloaded->save();
$second = file_get_contents($path);

$t->equals($first, $second, '同样的配置重复保存应当得到完全相同的字节（否则每次续期都产生无意义 diff）');

$t->group('acme.sh 格式兼容');

$acmeShStyle = <<<'CONF'
#!/usr/bin/env sh
Le_Domain='example.com'
Le_Alt="www.example.com"
Le_Webroot='dns_cf'
Le_Keylength='ec-256'
Le_RenewalDays='60'
SAVED_CF_Token='token-value'
# 这是注释
不合法的行
Le_NextRenewTime='1800000000'
CONF;

$parsed = ConfigFile::parse($acmeShStyle);

$t->equals('example.com', $parsed['Le_Domain'], '单引号值');
$t->equals('www.example.com', $parsed['Le_Alt'], '双引号值');
$t->equals('dns_cf', $parsed['Le_Webroot'], 'DNS 提供商');
$t->equals('token-value', $parsed['SAVED_CF_Token'], 'SAVED_ 前缀的凭据');
$t->ok(!isset($parsed['#!/usr/bin/env sh']), 'shebang 不该被当成配置');
$t->ok(!isset($parsed['不合法的行']), '不合法的行应当跳过');
$t->equals(7, \count($parsed), '应当只解析出 7 项');

$t->group('类型转换');

$typed = new ConfigFile($dir . '/typed.conf');
$typed->set('IntValue', '60')->set('BoolTrue', '1')->set('BoolFalse', '')->set('BoolYes', 'yes')->save();

$typedReloaded = (new ConfigFile($dir . '/typed.conf'))->load();

$t->equals(60, $typedReloaded->getInt('IntValue', 0), 'getInt');
$t->equals(30, $typedReloaded->getInt('Missing', 30), 'getInt 的默认值');
$t->ok($typedReloaded->getBool('BoolTrue'), '"1" 是 true');
$t->ok(!$typedReloaded->getBool('BoolFalse'), '空串是 false');
$t->ok($typedReloaded->getBool('BoolYes'), '"yes" 也算 true');

$t->group('删除项');

$typedReloaded->set('IntValue', null);
$typedReloaded->save();

$t->ok(!(new ConfigFile($dir . '/typed.conf'))->load()->has('IntValue'), '设成 null 应当把这一项删掉');

$t->group('CA 注册表');

$t->equals(
    'https://acme-v02.api.letsencrypt.org/directory',
    CaRegistry::resolveUrl('letsencrypt'),
    'Let\'s Encrypt 的目录地址'
);
$t->equals(CaRegistry::resolveUrl('letsencrypt'), CaRegistry::resolveUrl('le'), '别名 le');
$t->equals(
    'https://acme-staging-v02.api.letsencrypt.org/directory',
    CaRegistry::resolveUrl('staging'),
    '别名 staging'
);
$t->equals('https://custom.ca/dir', CaRegistry::resolveUrl('https://custom.ca/dir'), '直接给 URL 应当原样返回');

$t->throws(static function (): void {
    CaRegistry::resolveUrl('不存在的CA');
}, ConfigException::class, '未知短名应当报错并列出可用值');

$t->ok(CaRegistry::requiresEab('zerossl'), 'ZeroSSL 需要 EAB');
$t->ok(CaRegistry::requiresEab('google'), 'Google Trust Services 需要 EAB');
$t->ok(!CaRegistry::requiresEab('letsencrypt'), 'Let\'s Encrypt 不需要 EAB');
$t->ok(CaRegistry::isTestServer('letsencrypt_test'), 'staging 应当被标记为测试环境');
$t->ok(!CaRegistry::isTestServer('letsencrypt'), '正式环境不是测试环境');

$t->group('账户目录路径');

$t->equals(
    'acme-v02.api.letsencrypt.org/directory',
    CaRegistry::directoryPath('https://acme-v02.api.letsencrypt.org/directory'),
    '路径按 host/path 拆分（与 acme.sh 的布局一致）'
);
$t->equals(
    'acme.zerossl.com/v2/DV90',
    CaRegistry::directoryPath('https://acme.zerossl.com/v2/DV90'),
    '多级路径要保留'
);

$t->equals("Let's Encrypt", CaRegistry::getDisplayName('le'), '短名转展示名');
$t->equals(
    'Buypass Go SSL',
    CaRegistry::getDisplayName('https://api.buypass.com/acme/directory'),
    'URL 也要能反查到展示名'
);

exit($t->summary());
