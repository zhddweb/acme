<?php

declare(strict_types=1);

/**
 * 端到端签发流程：对着 FakeAcmeServer 走完整个 ACME 协议。
 *
 * 这是最重要的一个测试文件——它把协议层、加密层、存储层、求解器串起来跑，
 * 而且服务端那边**真的验签、真的查 nonce、真的核对 CSR 里的域名**。
 * 这里过了，剩下的多半就是环境问题而不是代码问题。
 */

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Challenge\AbstractSolver;
use Mci\Acme\Crypto\Certificate;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ChallengeException;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Http\HttpClient;
use Mci\Acme\Protocol\Challenge;
use Mci\Acme\Service\AccountService;
use Mci\Acme\Service\CertificateIssuer;
use Mci\Acme\Service\IssueRequest;
use Mci\Acme\Storage\AccountStorage;
use Mci\Acme\Storage\CertificateStorage;
use Mci\Acme\Storage\Paths;
use Mci\Acme\Tests\FakeAcmeServer;
use Mci\Acme\Tests\Runner;
use Mci\Acme\Util\Logger;

$t = new Runner('端到端签发流程');

/**
 * 记录调用情况的假求解器。
 *
 * 真去写文件或改 DNS 就没法在测试里跑了，这里只记「被调用了什么」，
 * 断言时检查顺序与参数。
 */
final class RecordingSolver extends AbstractSolver
{
    /** @var string */
    private $type;

    /** @var array<int, string> */
    public $calls = [];

    /** @var array<string, string> 域名 => keyAuthorization */
    public $prepared = [];

    /** @var bool verify() 返回什么 */
    public $verifyResult = true;

    /** @var int tick() 被调用了几次 */
    public $ticks = 0;

    public function __construct(string $type = 'http-01')
    {
        parent::__construct(null);
        $this->type = $type;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function prepare(Challenge $challenge, KeyPair $accountKey): void
    {
        $this->calls[] = 'prepare:' . $challenge->getDomain();
        $this->prepared[$challenge->getDomain()] = $challenge->getKeyAuthorization($accountKey);
    }

    public function cleanup(Challenge $challenge, KeyPair $accountKey): void
    {
        $this->calls[] = 'cleanup:' . $challenge->getDomain();
    }

    public function verify(Challenge $challenge, KeyPair $accountKey): bool
    {
        $this->calls[] = 'verify:' . $challenge->getDomain();

        return $this->verifyResult;
    }

    public function tick(): void
    {
        ++$this->ticks;
    }
}

/**
 * @return array{issuer: CertificateIssuer, server: FakeAcmeServer, storage: CertificateStorage, base: string}
 */
function buildIssuer(?FakeAcmeServer $server = null): array
{
    $server = $server !== null ? $server : new FakeAcmeServer();

    $logger = Logger::silent();
    $http = new HttpClient($server->getTransport(), $logger);
    // 测试里不真的等待
    $http->setSleeper(static function (): void {
    });

    $base = test_temp_dir('issue-' . bin2hex(random_bytes(4)));
    $paths = new Paths($base);

    $storage = new CertificateStorage($paths);
    $accounts = new AccountService($http, new AccountStorage($paths), $logger);

    $issuer = new CertificateIssuer($http, $storage, $accounts, $logger);
    $issuer->setSleeper(static function (): void {
    });

    return ['issuer' => $issuer, 'server' => $server, 'storage' => $storage, 'base' => $base];
}

// ---------------------------------------------------------------- 基本签发

$t->group('单域名 http-01 签发');

$env = buildIssuer();
$solver = new RecordingSolver('http-01');

$request = new IssueRequest(['example.com'], $solver);
$request->setCa($env['server']->getDirectoryUrl());
$request->setEmail('admin@example.com');

$result = $env['issuer']->issue($request);

$t->ok($result->isIssued(), '证书应当被签发');
$t->ok(!$result->isSkipped(), '首次签发不该被跳过');
$t->equals('example.com', $result->getMainDomain(), '主域名应当正确');

$certificate = $result->getCertificate();
$t->ok($certificate !== null, '结果里应当带证书对象');
$t->ok($certificate !== null && \in_array('example.com', $certificate->getDomains(), true), '证书里应当包含该域名');

$t->equals(
    ['prepare:example.com', 'verify:example.com', 'cleanup:example.com'],
    $solver->calls,
    '求解器的调用顺序应当是 prepare -> verify -> cleanup'
);

$t->group('落盘的文件');

foreach (['key', 'cert', 'ca', 'fullchain', 'csr', 'conf'] as $type) {
    $path = $type === 'csr'
        ? $env['storage']->getPaths()->getCsrPath('example.com', true)
        : $result->getPath($type);
    $t->ok($path !== null && is_file($path), sprintf('%s 文件应当存在', $type));
}

$keyPath = $result->getPath('key');
$t->equals('0600', substr(sprintf('%o', fileperms($keyPath)), -4), '私钥权限必须是 0600');

$fullchain = file_get_contents($result->getPath('fullchain'));
$t->equals(2, \count(Certificate::splitChain($fullchain)), 'fullchain 里应当有叶子证书 + 中间证书两张');

$leafOnly = file_get_contents($result->getPath('cert'));
$t->equals(1, \count(Certificate::splitChain($leafOnly)), '<domain>.cer 里只该有叶子证书');

$storedKey = $env['storage']->loadKey('example.com', true);
$t->ok(
    $storedKey !== null && $certificate !== null && $certificate->matchesPrivateKey($storedKey),
    '落盘的私钥必须与证书配对'
);

// ---------------------------------------------------------------- 多域名与通配符

$t->group('多域名 + 通配符（dns-01）');

$env2 = buildIssuer();
$dnsSolver = new RecordingSolver('dns-01');

$request2 = new IssueRequest(['example.com', 'www.example.com', '*.example.com'], $dnsSolver);
$request2->setCa($env2['server']->getDirectoryUrl());

$result2 = $env2['issuer']->issue($request2);

$t->ok($result2->isIssued(), '多域名证书应当签发成功');
$t->equals(3, \count($result2->getDomains()), '应当有三个域名');

$certificate2 = $result2->getCertificate();
$t->ok(
    $certificate2 !== null && \in_array('*.example.com', $certificate2->getDomains(), true),
    '证书里应当包含通配符域名'
);
$t->equals(9, \count($dnsSolver->calls), '三个域名各走一遍 prepare/verify/cleanup，共 9 次调用');

$t->group('通配符必须用 dns-01');

$t->throws(
    static function (): void {
        new IssueRequest(['*.example.com'], new RecordingSolver('http-01'));
    },
    ConfigException::class,
    '通配符配 http-01 应当在构造请求时就被拦下'
);

// ---------------------------------------------------------------- 跳过与强制

$t->group('未到期时跳过');

$solver3 = new RecordingSolver('http-01');
$request3 = new IssueRequest(['example.com'], $solver3);
$request3->setCa($env['server']->getDirectoryUrl());

$result3 = $env['issuer']->issue($request3);

$t->ok($result3->isSkipped(), '证书还没到续期时间，应当跳过');
$t->equals([], $solver3->calls, '跳过时不该动求解器');
$t->contains('跳过', $result3->getMessage(), '跳过的说明里应当讲清楚原因');

$t->group('--force 强制重签');

$solver4 = new RecordingSolver('http-01');
$request4 = new IssueRequest(['example.com'], $solver4);
$request4->setCa($env['server']->getDirectoryUrl());
$request4->setForce(true);

$result4 = $env['issuer']->issue($request4);

$t->ok($result4->isIssued(), '加了 force 就该重新签发');

$t->group('域名列表变了要重签');

$solver5 = new RecordingSolver('http-01');
$request5 = new IssueRequest(['example.com', 'new.example.com'], $solver5);
$request5->setCa($env['server']->getDirectoryUrl());

$result5 = $env['issuer']->issue($request5);

$t->ok($result5->isIssued(), '加了新域名时即使没到期也要重签');

// ---------------------------------------------------------------- 账户复用

$t->group('账户复用');

$t->equals(1, $env['server']->getAccountCount(), '同一个存储目录下只该注册一个账户');

// ---------------------------------------------------------------- 密钥类型

$t->group('各种密钥类型');

foreach (['ec-256', 'ec-384', '2048'] as $keyType) {
    $envKey = buildIssuer();
    $requestKey = new IssueRequest(['key-' . $keyType . '.example.com'], new RecordingSolver('http-01'));
    $requestKey->setCa($envKey['server']->getDirectoryUrl());
    $requestKey->setKeyType($keyType);

    $resultKey = $envKey['issuer']->issue($requestKey);

    $t->ok($resultKey->isIssued(), sprintf('%s 密钥应当能签发', $keyType));

    $isEcc = KeyPair::isEcType($keyType);
    $t->contains(
        $isEcc ? '_ecc' : 'key-' . $keyType . '.example.com',
        (string) $resultKey->getPath('dir'),
        sprintf('%s 应当存到%s目录', $keyType, $isEcc ? ' _ecc ' : '普通')
    );
}

// ---------------------------------------------------------------- 失败路径

$t->group('验证失败');

$failServer = new FakeAcmeServer();
$failServer->failNextChallenge('CA 访问 http://example.com/.well-known/... 得到 404');
$envFail = buildIssuer($failServer);
$failSolver = new RecordingSolver('http-01');

$requestFail = new IssueRequest(['fail.example.com'], $failSolver);
$requestFail->setCa($failServer->getDirectoryUrl());

$t->throws(
    static function () use ($envFail, $requestFail): void {
        $envFail['issuer']->issue($requestFail);
    },
    ChallengeException::class,
    '验证失败应当抛 ChallengeException'
);

$t->ok(
    \in_array('cleanup:fail.example.com', $failSolver->calls, true),
    '验证失败后仍然必须调用 cleanup —— 否则会留下垃圾文件或 TXT 记录'
);

$t->group('自检没过就不通知 CA');

$envSkip = buildIssuer();
$skipSolver = new RecordingSolver('http-01');
$skipSolver->verifyResult = false;

$requestSkip = new IssueRequest(['notready.example.com'], $skipSolver);
$requestSkip->setCa($envSkip['server']->getDirectoryUrl());

$t->throws(
    static function () use ($envSkip, $requestSkip): void {
        $envSkip['issuer']->issue($requestSkip);
    },
    ChallengeException::class,
    'verify() 返回 false 时应当中止，不去浪费 CA 的验证配额'
);

$challengeRequests = $envSkip['server']->getPayloadsFor('/chall/');
$t->equals(0, \count($challengeRequests), '自检没过时不该向挑战端点发任何请求');

// ---------------------------------------------------------------- nonce 重放

$t->group('badNonce 自动重放');

$nonceServer = new FakeAcmeServer();
$envNonce = buildIssuer($nonceServer);
$nonceServer->injectBadNonce();

$requestNonce = new IssueRequest(['nonce.example.com'], new RecordingSolver('http-01'));
$requestNonce->setCa($nonceServer->getDirectoryUrl());

$t->noThrow(
    static function () use ($envNonce, $requestNonce): void {
        $envNonce['issuer']->issue($requestNonce);
    },
    '遇到 badNonce 应当自动重取并重放，不该失败'
);

// ---------------------------------------------------------------- EAB

$t->group('External Account Binding');

$eabServer = new FakeAcmeServer();
$eabServer->setRequireEab(true);
$envEab = buildIssuer($eabServer);

$requestNoEab = new IssueRequest(['eab.example.com'], new RecordingSolver('http-01'));
$requestNoEab->setCa($eabServer->getDirectoryUrl());

$t->throws(
    static function () use ($envEab, $requestNoEab): void {
        $envEab['issuer']->issue($requestNoEab);
    },
    ConfigException::class,
    'CA 要求 EAB 而没提供时应当给出明确报错'
);

$envEab2 = buildIssuer($eabServer);
$requestEab = new IssueRequest(['eab2.example.com'], new RecordingSolver('http-01'));
$requestEab->setCa($eabServer->getDirectoryUrl());
$requestEab->setEab(['kid' => 'test-kid', 'hmac' => \Mci\Acme\Crypto\Base64Url::encode('test-hmac-key-bytes')]);

$t->noThrow(
    static function () use ($envEab2, $requestEab): void {
        $envEab2['issuer']->issue($requestEab);
    },
    '提供了 EAB 就应当能注册成功'
);

$accountPayloads = $eabServer->getPayloadsFor('new-account');
$hasEab = false;
foreach ($accountPayloads as $payload) {
    if (\is_array($payload) && isset($payload['externalAccountBinding'])) {
        $hasEab = true;
    }
}
$t->ok($hasEab, 'newAccount 的 payload 里应当带 externalAccountBinding');

// ---------------------------------------------------------------- 协议细节

$t->group('协议细节');

$log = $env['server']->getLog();
$t->ok($log !== [], '服务端应当收到过请求');

$postAsGetCount = 0;
$kidCount = 0;
$jwkCount = 0;

foreach ($log as $entry) {
    if ($entry['payload'] === null) {
        ++$postAsGetCount;
    }
    if (isset($entry['header']['kid'])) {
        ++$kidCount;
    }
    if (isset($entry['header']['jwk'])) {
        ++$jwkCount;
    }
}

$t->ok($postAsGetCount > 0, '应当用到 POST-as-GET 读取资源');
$t->ok($kidCount > 0, '注册之后的请求应当用 kid 模式');
$t->equals(1, $jwkCount, '只有 newAccount 那一次该用 jwk 模式');

exit($t->summary());
