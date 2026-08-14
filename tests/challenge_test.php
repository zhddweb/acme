<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Challenge\Dns01\DnsProviderInterface;
use Mci\Acme\Challenge\Dns01\DnsSolver;
use Mci\Acme\Challenge\Http01\WebrootSolver;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ChallengeException;
use Mci\Acme\Protocol\Challenge;
use Mci\Acme\Service\SolverFactory;
use Mci\Acme\Tests\Runner;
use Mci\Acme\Util\Filesystem;

$t = new Runner('挑战求解器');

$accountKey = KeyPair::generate('ec-256');

function makeChallenge(string $type, string $domain, string $token = 'tok-123'): Challenge
{
    return new Challenge([
        'type' => $type,
        'url' => 'https://acme.test/chall/1',
        'token' => $token,
        'status' => 'pending',
    ], $domain);
}

$t->group('webroot：写文件与清理');

$base = test_temp_dir('challenge');
$webroot = $base . '/www';
mkdir($webroot, 0755, true);

$solver = new WebrootSolver($webroot);
$challenge = makeChallenge('http-01', 'example.com');

$solver->prepare($challenge, $accountKey);

$expectedPath = $webroot . '/.well-known/acme-challenge/tok-123';
$t->ok(is_file($expectedPath), '验证文件应当被写出来');
$t->equals($challenge->getKeyAuthorization($accountKey), file_get_contents($expectedPath), '内容必须恰好是 keyAuthorization');
// web 服务器与 php-fpm 常跑在不同用户下，0600 会让 CA 拿到 403
$t->equals('0644', substr(sprintf('%o', fileperms($expectedPath)), -4), '验证文件权限必须是 0644，让 web 服务器读得到');
$t->ok($solver->verify($challenge, $accountKey), '自检应当通过');

$solver->cleanup($challenge, $accountKey);
$t->ok(!is_file($expectedPath), '清理后文件应当消失');
$t->ok(!is_dir($webroot . '/.well-known'), '自己建的空目录也应当清掉');

$t->group('webroot：不删用户原有的目录内容');

mkdir($webroot . '/.well-known', 0755, true);
file_put_contents($webroot . '/.well-known/apple-app-site-association', '{}');

$solver->prepare($challenge, $accountKey);
$solver->cleanup($challenge, $accountKey);

$t->ok(is_file($webroot . '/.well-known/apple-app-site-association'), '.well-known 下的其他文件不能被误删');
$t->ok(is_dir($webroot . '/.well-known'), '非空目录不该被删');

$t->group('webroot：多域名映射');

$rootA = $base . '/site-a';
$rootB = $base . '/site-b';
mkdir($rootA, 0755, true);
mkdir($rootB, 0755, true);

$multi = new WebrootSolver(['a.com' => $rootA, 'b.com' => $rootB]);

$multi->prepare(makeChallenge('http-01', 'a.com', 'ta'), $accountKey);
$multi->prepare(makeChallenge('http-01', 'b.com', 'tb'), $accountKey);

$t->ok(is_file($rootA . '/.well-known/acme-challenge/ta'), 'a.com 的文件写到了 a 的根目录');
$t->ok(is_file($rootB . '/.well-known/acme-challenge/tb'), 'b.com 的文件写到了 b 的根目录');

$t->group('webroot：子域回退到父域的配置');

$parent = new WebrootSolver(['example.com' => $rootA]);
$parent->prepare(makeChallenge('http-01', 'sub.example.com', 'tsub'), $accountKey);

$t->ok(is_file($rootA . '/.well-known/acme-challenge/tsub'), '子域应当能用父域配的 webroot');

$t->group('webroot：找不到映射时报错');

$strict = new WebrootSolver(['only.com' => $rootA]);

$t->throws(static function () use ($strict, $accountKey): void {
    $strict->prepare(makeChallenge('http-01', 'other.com', 'x'), $accountKey);
}, ChallengeException::class, '没有对应 webroot 的域名应当报错，并提示怎么配');

$t->group('webroot 的序列化');

$t->equals($webroot, (new WebrootSolver($webroot))->describe(), '单个路径原样返回');
$t->equals('a.com=' . $rootA . ',b.com=' . $rootB, $multi->describe(), '多域名写成 域名=路径 的形式');

$t->group('dns-01');

/** 记录调用的假 DNS 提供商 */
final class FakeDnsProvider implements DnsProviderInterface
{
    /** @var array<int, array{0: string, 1: string, 2: string}> */
    public $calls = [];

    /** @var array<string, array<int, string>> */
    public $records = [];

    /** @var bool 删除时是否抛异常 */
    public $failRemoval = false;

    public function getName(): string
    {
        return '测试用 DNS';
    }

    public function addTxtRecord(string $fqdn, string $value): void
    {
        $this->calls[] = ['add', $fqdn, $value];
        if (!isset($this->records[$fqdn])) {
            $this->records[$fqdn] = [];
        }
        $this->records[$fqdn][] = $value;
    }

    public function removeTxtRecord(string $fqdn, string $value): void
    {
        $this->calls[] = ['remove', $fqdn, $value];

        if ($this->failRemoval) {
            throw new \Mci\Acme\Exception\DnsException('模拟的删除失败');
        }

        if (!isset($this->records[$fqdn])) {
            return;
        }

        $this->records[$fqdn] = array_values(array_filter(
            $this->records[$fqdn],
            static function (string $item) use ($value): bool {
                return $item !== $value;
            }
        ));
    }
}

$provider = new FakeDnsProvider();
$dnsSolver = new DnsSolver($provider);
$dnsSolver->setPropagationTimeout(0);
$dnsSolver->setInitialDelay(0);
$dnsSolver->setSleeper(static function (): void {
});

$dnsChallenge = makeChallenge('dns-01', 'example.com', 'dnstok');
$dnsSolver->prepare($dnsChallenge, $accountKey);

$t->equals(1, \count($provider->calls), '应当调了一次加记录');
$t->equals('_acme-challenge.example.com', $provider->calls[0][1], '记录名');
$t->equals($dnsChallenge->getDnsValue($accountKey), $provider->calls[0][2], '记录值是 SHA-256 之后的');
$t->equals(43, \strlen($provider->calls[0][2]), 'dns-01 的值固定 43 字符');

$dnsSolver->cleanup($dnsChallenge, $accountKey);
$t->equals('remove', $provider->calls[1][0], '清理时应当删记录');
$t->equals([], $provider->records['_acme-challenge.example.com'], '记录应当被删干净');

$t->group('dns-01：通配符与裸域的同名记录');

$wildProvider = new FakeDnsProvider();
$wildSolver = new DnsSolver($wildProvider);
$wildSolver->setPropagationTimeout(0);
$wildSolver->setInitialDelay(0);

$bare = makeChallenge('dns-01', 'example.com', 'tok-bare');
$wild = makeChallenge('dns-01', '*.example.com', 'tok-wild');

$wildSolver->prepare($bare, $accountKey);
$wildSolver->prepare($wild, $accountKey);

// 两条挑战记录的名字**完全一样**，值不同——DNS 提供商必须支持同名多值
$t->equals('_acme-challenge.example.com', $wildProvider->calls[0][1], '裸域的记录名');
$t->equals('_acme-challenge.example.com', $wildProvider->calls[1][1], '通配符的记录名与裸域相同');
$t->notEquals($wildProvider->calls[0][2], $wildProvider->calls[1][2], '但两条的值必须不同');
$t->equals(2, \count($wildProvider->records['_acme-challenge.example.com']), '两条记录要能共存');

$t->group('dns-01：删除失败不该让流程崩');

$failProvider = new FakeDnsProvider();
$failProvider->failRemoval = true;
$failSolver = new DnsSolver($failProvider);
$failSolver->setPropagationTimeout(0);
$failSolver->setInitialDelay(0);

$failSolver->prepare($dnsChallenge, $accountKey);

$t->noThrow(static function () use ($failSolver, $dnsChallenge, $accountKey): void {
    $failSolver->cleanup($dnsChallenge, $accountKey);
}, '清理失败只该记警告，不能把已经成功的签发变成失败');

$t->group('SolverFactory');

$factory = new SolverFactory();

$t->equals('http-01', $factory->create($webroot)->getType(), 'webroot 路径 -> http-01');
$t->equals('http-01', $factory->create('no')->getType(), 'acme.sh 用 no 表示 standalone');
$t->equals('http-01', $factory->create('standalone')->getType(), 'standalone 也认');
$t->equals('tls-alpn-01', $factory->create('alpn')->getType(), 'alpn -> tls-alpn-01');
$t->equals('dns-01', $factory->create('dns_manual')->getType(), '手动 DNS');

$t->throws(static function () use ($factory): void {
    $factory->create('/不存在的目录');
}, \Mci\Acme\Exception\ConfigException::class, '不存在的 webroot 目录应当报错');

$t->throws(static function () use ($factory): void {
    $factory->create('');
}, \Mci\Acme\Exception\ConfigException::class, '空的验证方式应当报错并给出三个选项');

$t->group('SolverFactory 的多 webroot 解析');

$mapped = $factory->create('a.com=' . $rootA . ',b.com=' . $rootB);
$t->ok($mapped instanceof WebrootSolver, '域名=路径 的形式应当解析成 webroot 求解器');
$t->equals('a.com=' . $rootA . ',b.com=' . $rootB, SolverFactory::describe($mapped), '序列化应当能往返');

exit($t->summary());
