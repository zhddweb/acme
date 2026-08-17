<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Crypto\SelfSignedCertificate;
use Mci\Acme\Exception\StorageException;
use Mci\Acme\Protocol\Account;
use Mci\Acme\Storage\AccountStorage;
use Mci\Acme\Storage\CertificateStorage;
use Mci\Acme\Storage\Paths;
use Mci\Acme\Tests\Runner;
use Mci\Acme\Util\Filesystem;

$t = new Runner('存储层');

$base = test_temp_dir('storage');
$paths = new Paths($base);

$t->group('路径布局（与 acme.sh 对齐）');

$t->equals($base . '/account.conf', $paths->getAccountConfPath(), '全局配置');
$t->equals(
    $base . '/ca/acme-v02.api.letsencrypt.org/directory/account.key',
    $paths->getAccountKeyPath('https://acme-v02.api.letsencrypt.org/directory'),
    '账户密钥'
);
$t->equals($base . '/example.com', $paths->getDomainDir('example.com'), '证书目录');
$t->equals($base . '/example.com_ecc', $paths->getDomainDir('example.com', true), 'ECC 证书目录');
$t->equals($base . '/example.com/example.com.key', $paths->getKeyPath('example.com'), '私钥');
$t->equals($base . '/example.com/fullchain.cer', $paths->getFullchainPath('example.com'), 'fullchain');
$t->equals($base . '/_.example.com/_.example.com.cer', $paths->getCertPath('*.example.com'), '通配符目录名用 _. 代替 *.');

$t->group('证书存取');

$storage = new CertificateStorage($paths);
$keyPair = KeyPair::generate('ec-256');

$storage->saveKey('example.com', $keyPair, true);
$loadedKey = $storage->loadKey('example.com', true);

$t->ok($loadedKey !== null, '私钥应当能读回');
$t->equals($keyPair->getThumbprint(), $loadedKey->getThumbprint(), '读回的应当是同一把密钥');
$t->equals(
    '0600',
    substr(sprintf('%o', fileperms($paths->getKeyPath('example.com', true))), -4),
    '私钥权限必须是 0600'
);

$leaf = SelfSignedCertificate::forPlaceholder($keyPair, ['example.com', 'www.example.com']);
$intermediate = SelfSignedCertificate::forPlaceholder(KeyPair::generate('2048'), ['intermediate.test']);

$storage->saveCertificateChain('example.com', $leaf . $intermediate, true);

$t->ok($storage->exists('example.com', true), '证书应当存在');
$t->ok(!$storage->exists('example.com', false), '非 ECC 目录下不该有');

$certificate = $storage->loadCertificate('example.com', true);
$t->ok($certificate !== null, '证书应当能读回');
$t->equals('example.com', $certificate->getSubjectCommonName(), 'CN 正确');

$caContent = (new Filesystem())->read($paths->getCaCertPath('example.com', true));
$t->contains('BEGIN CERTIFICATE', $caContent, 'ca.cer 里应当只有中间证书');
$t->equals(1, substr_count($caContent, 'BEGIN CERTIFICATE'), 'ca.cer 里只该有一张');

$fullchain = $storage->loadFullchain('example.com', true);
$t->equals(2, substr_count((string) $fullchain, 'BEGIN CERTIFICATE'), 'fullchain 里应当有两张');

$t->group('签发配置的存取');

$storage->saveIssueConfig(
    ['example.com', 'www.example.com', '*.example.com'],
    ['Le_Keylength' => 'ec-256', 'Le_Webroot' => 'dns_cf'],
    true
);

$loaded = $storage->loadIssueConfig('example.com', true);

$t->equals(
    ['example.com', 'www.example.com', '*.example.com'],
    $loaded['domains'],
    '域名列表应当完整读回，且顺序不变'
);
$t->equals('dns_cf', $loaded['config']->get('Le_Webroot'), '验证方式应当记下来');

$t->group('acme.sh 的 Le_Alt=no');

// acme.sh 在没有备用域名时会写 Le_Alt='no'，不能把它当成域名
$singleStorage = new CertificateStorage($paths);
$singleStorage->saveIssueConfig(['single.example.com'], [], false);
$singleConfig = $singleStorage->getConfig('single.example.com', false);
$singleConfig->set('Le_Alt', 'no');
$singleConfig->save();

$singleLoaded = $singleStorage->loadIssueConfig('single.example.com', false);
$t->equals(['single.example.com'], $singleLoaded['domains'], "Le_Alt='no' 应当被忽略");

$t->group('列出证书');

$storage->saveKey('*.wild.example.com', $keyPair, false);
$storage->saveCertificateChain('*.wild.example.com', $leaf, false);

$list = $storage->listCertificates();
$domains = [];
foreach ($list as $item) {
    $domains[] = $item['domain'] . ($item['ecc'] ? '(ecc)' : '');
}
sort($domains, SORT_STRING);

$t->ok(\in_array('example.com(ecc)', $domains, true), 'ECC 证书应当被列出');
$t->ok(\in_array('*.wild.example.com', $domains, true), '通配符证书的目录名应当还原回 *.');
$t->ok(!\in_array('ca', $domains, true), 'ca 目录不该被当成证书');

// 和 acme.sh 共用根目录时，它的 deploy/ dnsapi/ notify/ 就在旁边，
// 里面万一有个同名的 .cer 也不能被当成证书列出来
mkdir($base . '/deploy', 0700, true);
file_put_contents($base . '/deploy/deploy.cer', 'not-a-cert');
$deployDomains = [];
foreach ($storage->listCertificates() as $item) {
    $deployDomains[] = $item['domain'];
}
$t->ok(!\in_array('deploy', $deployDomains, true), 'acme.sh 自己的 deploy/ 目录不该被当成证书');

$t->group('续期时间标记');

$storage->markRenewed('example.com', 30, true);
$config = $storage->getConfig('example.com', true);

$createTime = $config->getInt('Le_CertCreateTime', 0);
$nextRenew = $config->getInt('Le_NextRenewTime', 0);

$t->ok($createTime > 0, '应当记下签发时间');
$t->equals(30 * 86400, $nextRenew - $createTime, '下次续期时间应当是签发时间加上续期天数');

$t->group('删除');

$t->ok($storage->remove('*.wild.example.com', false), '删除应当成功');
$t->ok(!$storage->exists('*.wild.example.com', false), '删完就不该存在了');

$t->group('账户存储');

$accountStorage = new AccountStorage($paths);
$directoryUrl = 'https://acme.test/directory';

$t->ok(!$accountStorage->hasAccountKey($directoryUrl), '一开始没有账户密钥');

$accountKey = $accountStorage->loadOrCreateAccountKey($directoryUrl, 'ec-256');
$t->ok($accountStorage->hasAccountKey($directoryUrl), '应当创建出账户密钥');

$again = $accountStorage->loadOrCreateAccountKey($directoryUrl, 'ec-256');
$t->equals($accountKey->getThumbprint(), $again->getThumbprint(), '再次调用应当复用已有密钥，不能生成新的');

$t->group('账户密钥不许被静默覆盖');

$t->throws(
    static function () use ($accountStorage, $directoryUrl): void {
        $accountStorage->saveAccountKey($directoryUrl, KeyPair::generate('ec-256'));
    },
    StorageException::class,
    '覆盖已有账户密钥必须显式声明——否则等于把原账户弄丢'
);

$t->noThrow(
    static function () use ($accountStorage, $directoryUrl): void {
        $accountStorage->saveAccountKey($directoryUrl, KeyPair::generate('ec-256'), true);
    },
    '显式要求覆盖时应当允许（换密钥的场景）'
);

$t->group('账户信息');

$account = new Account($accountKey, 'https://acme.test/acct/1', [
    'status' => 'valid',
    'contact' => ['mailto:admin@example.com'],
]);

$accountStorage->saveAccount($directoryUrl, $account);
$loadedAccount = $accountStorage->loadAccount($directoryUrl);

$t->ok($loadedAccount !== null, '账户应当能读回');
$t->equals('https://acme.test/acct/1', $loadedAccount->getUrl(), '账户 URL');
$t->equals(['admin@example.com'], $loadedAccount->getEmails(), '联系邮箱');

$t->group('EAB 凭据');

$eab = new \Mci\Acme\Ca\Eab('kid-1', 'aG1hYy1rZXk');
$accountStorage->saveEab($directoryUrl, $eab);

$loadedEab = $accountStorage->loadEab($directoryUrl);
$t->ok($loadedEab !== null, 'EAB 应当能读回');
$t->equals('kid-1', $loadedEab->getKid(), 'EAB 的 kid');
$t->equals('aG1hYy1rZXk', $loadedEab->getHmacKey(), 'EAB 的 hmac');

$t->group('原子写入');

$filesystem = new Filesystem();
$target = $base . '/atomic.txt';

$filesystem->write($target, 'first');
$filesystem->write($target, 'second');

$t->equals('second', $filesystem->read($target), '覆盖写入应当生效');
$t->equals(0, \count(glob($base . '/.acme-tmp-*')), '不该留下临时文件');

$t->group('默认目录：与 acme.sh 共用同一份数据');

// 环境变量会影响后面的用例，先存下来，这一段跑完原样还回去
$savedEnv = [];
foreach (['MCI_ACME_HOME', 'MCI_ACME_CONFIG_HOME', 'LE_CONFIG_HOME', 'LE_WORKING_DIR', 'CERT_HOME'] as $name) {
    $savedEnv[$name] = getenv($name);
    putenv($name);
}

$fakeHome = test_temp_dir('home');
putenv('MCI_ACME_HOME=' . $fakeHome);

$t->equals($fakeHome . '/.acme.sh', Paths::defaultBaseDir(), '默认目录就是 acme.sh 的那个');

// 旧版本默认写在 ~/.mci-acme，升级后不能把用户的证书甩掉
mkdir($fakeHome . '/.mci-acme', 0700, true);
$t->equals(
    $fakeHome . '/.mci-acme',
    Paths::defaultBaseDir(),
    '没有 ~/.acme.sh 而旧目录还在时，继续用旧的'
);

mkdir($fakeHome . '/.acme.sh', 0700, true);
$t->equals($fakeHome . '/.acme.sh', Paths::defaultBaseDir(), '两个都在时以 acme.sh 的为准');

putenv('LE_WORKING_DIR=/opt/acme-working/');
$t->equals('/opt/acme-working', Paths::defaultBaseDir(), '认 acme.sh 的 LE_WORKING_DIR，尾部斜杠要去掉');

putenv('LE_CONFIG_HOME=/etc/acme-config');
$t->equals('/etc/acme-config', Paths::defaultBaseDir(), 'LE_CONFIG_HOME 优先于 LE_WORKING_DIR');

putenv('MCI_ACME_CONFIG_HOME=/var/lib/mci');
$t->equals('/var/lib/mci', Paths::defaultBaseDir(), 'MCI_ACME_CONFIG_HOME 最高——想和 acme.sh 分家就设它');

putenv('MCI_ACME_CONFIG_HOME');
putenv('LE_CONFIG_HOME');
putenv('LE_WORKING_DIR');

$t->group('CERT_HOME：证书目录可以单独挪走');

putenv('CERT_HOME=/srv/certs/');
$envCertPaths = new Paths($base);
$t->equals($base . '/account.conf', $envCertPaths->getAccountConfPath(), '账户与全局配置仍留在根目录');
$t->equals(
    $base . '/ca/acme-v02.api.letsencrypt.org/directory/account.key',
    $envCertPaths->getAccountKeyPath('https://acme-v02.api.letsencrypt.org/directory'),
    '账户密钥也留在根目录'
);
$t->equals('/srv/certs/example.com', $envCertPaths->getDomainDir('example.com'), '证书跟着 CERT_HOME 走');
$t->ok($envCertPaths->hasCustomCertHome(), '环境变量算显式指定');
putenv('CERT_HOME');

$plainPaths = new Paths($base);
$t->equals($base, $plainPaths->getCertHome(), '没设过就等于根目录');
$t->ok(!$plainPaths->hasCustomCertHome(), '没设过不算显式指定');

$explicitPaths = new Paths($base, '/srv/explicit/');
$t->equals('/srv/explicit/example.com_ecc', $explicitPaths->getDomainDir('example.com', true), '构造参数指定的证书根');

// acme.sh 用 --cert-home 挪过证书时，路径就写在 account.conf 的 CERT_HOME 里
$configHomeBase = test_temp_dir('certhome-conf');
$configCertHome = test_temp_dir('certhome-conf-certs');
file_put_contents($configHomeBase . '/account.conf', "CERT_HOME='" . $configCertHome . "'\n");
$acmeWithCertHome = new \Mci\Acme\Acme($configHomeBase);
$t->equals(
    $configCertHome . '/example.com',
    $acmeWithCertHome->getPaths()->getDomainDir('example.com'),
    'account.conf 里的 CERT_HOME 应当被认出来'
);
$t->equals(
    $configHomeBase . '/account.conf',
    $acmeWithCertHome->getPaths()->getAccountConfPath(),
    '账户配置本身不受 CERT_HOME 影响'
);

foreach ($savedEnv as $name => $value) {
    if (\is_string($value) && $value !== '') {
        putenv($name . '=' . $value);
    } else {
        putenv($name);
    }
}

exit($t->summary());
