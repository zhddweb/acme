<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ProtocolException;
use Mci\Acme\Http\HttpClient;
use Mci\Acme\Http\Response;
use Mci\Acme\Http\Transport\MockTransport;
use Mci\Acme\Protocol\AcmeClient;
use Mci\Acme\Protocol\Authorization;
use Mci\Acme\Protocol\Challenge;
use Mci\Acme\Protocol\Directory;
use Mci\Acme\Protocol\NonceManager;
use Mci\Acme\Protocol\Order;
use Mci\Acme\Tests\FakeAcmeServer;
use Mci\Acme\Tests\Runner;
use Mci\Acme\Util\Json;

$t = new Runner('ACME 协议层');

$t->group('problem document 解析');

$exception = ProtocolException::fromProblem([
    'type' => 'urn:ietf:params:acme:error:rateLimited',
    'detail' => '每周只能签 5 张',
    'status' => 429,
], 429);

$t->equals('urn:ietf:params:acme:error:rateLimited', $exception->getType(), 'type');
$t->ok($exception->isRateLimited(), '应当识别出速率限制');
$t->contains('rateLimited', $exception->getMessage(), '错误信息里应当带上简短类型名');
$t->contains('每周只能签 5 张', $exception->getMessage(), '应当带上服务端给的细节');

$badNonce = ProtocolException::fromProblem(['type' => 'urn:ietf:params:acme:error:badNonce']);
$t->ok($badNonce->isBadNonce(), '应当识别出 badNonce');

$withSub = ProtocolException::fromProblem([
    'type' => 'urn:ietf:params:acme:error:malformed',
    'detail' => '部分域名有问题',
    'subproblems' => [
        ['identifier' => ['value' => 'bad.example.com'], 'detail' => '域名格式不对'],
    ],
]);
$t->contains('bad.example.com', $withSub->getMessage(), '子问题里的域名应当出现在错误信息里');
$t->contains('域名格式不对', $withSub->getMessage(), '子问题的细节也要带上');

$t->group('目录文档');

$transport = new MockTransport();
$transport->onUrl('GET', 'https://acme.test/directory', new Response(200, ['Content-Type' => 'application/json'], Json::encode([
    'newNonce' => 'https://acme.test/new-nonce',
    'newAccount' => 'https://acme.test/new-account',
    'newOrder' => 'https://acme.test/new-order',
    'revokeCert' => 'https://acme.test/revoke',
    'meta' => ['termsOfService' => 'https://acme.test/tos', 'externalAccountRequired' => true],
])));

$directory = Directory::fetch(new HttpClient($transport), 'https://acme.test/directory');

$t->equals('https://acme.test/new-order', $directory->getNewOrderUrl(), 'newOrder 端点');
$t->equals('https://acme.test/tos', $directory->getTermsOfService(), '服务条款');
$t->ok($directory->requiresExternalAccountBinding(), '应当识别出需要 EAB');
$t->ok(!$directory->hasUrl('renewalInfo'), '没有的端点应当报告不存在');

$t->throws(static function () use ($directory): void {
    $directory->getKeyChangeUrl();
}, ProtocolException::class, '取不存在的端点应当报错');

$t->group('目录缺关键端点时提前报错');

$badTransport = new MockTransport();
$badTransport->onUrl('GET', 'https://old.test/directory', new Response(200, ['Content-Type' => 'application/json'], Json::encode([
    'new-authz' => 'https://old.test/new-authz',
])));

$t->throws(static function () use ($badTransport): void {
    Directory::fetch(new HttpClient($badTransport), 'https://old.test/directory');
}, ProtocolException::class, 'ACME v1 风格的目录应当被识别并报错');

$t->group('nonce 管理');

$nonceTransport = new MockTransport();
$issued = 0;
$nonceTransport->setFallback(static function () use (&$issued): Response {
    ++$issued;

    return new Response(200, ['Replay-Nonce' => 'nonce-' . $issued]);
});

$nonce = new NonceManager(new HttpClient($nonceTransport), 'https://acme.test/new-nonce');

$first = $nonce->take();
$t->equals('nonce-1', $first, '第一次应当主动去拉');

// 从响应头里收一个，下次就不用再拉
$nonce->collect(new Response(200, ['Replay-Nonce' => 'from-response']));
$t->equals('from-response', $nonce->take(), '应当优先用响应头里带回来的');
$t->equals(1, $issued, '收到响应头之后不该再去拉');

$t->equals('nonce-2', $nonce->take(), '用掉之后要重新拉');

$nonce->collect(new Response(200, ['Replay-Nonce' => 'will-be-cleared']));
$nonce->clear();
$t->equals('nonce-3', $nonce->take(), 'clear 之后必须重新拉');

$t->group('值对象：Order');

$order = new Order([
    'status' => 'ready',
    'identifiers' => [['type' => 'dns', 'value' => 'example.com'], ['type' => 'dns', 'value' => 'www.example.com']],
    'authorizations' => ['https://acme.test/authz/1', 'https://acme.test/authz/2'],
    'finalize' => 'https://acme.test/order/1/finalize',
], 'https://acme.test/order/1');

$t->ok($order->isReady(), '状态判断');
$t->ok(!$order->isPending(), '不是 pending');
$t->equals(['example.com', 'www.example.com'], $order->getDomains(), '域名列表');
$t->equals(2, \count($order->getAuthorizationUrls()), '授权列表');
$t->equals('https://acme.test/order/1/finalize', $order->getFinalizeUrl(), 'finalize 地址');
$t->equals(null, $order->getCertificateUrl(), '还没签发时没有证书地址');

$invalidOrder = new Order([
    'status' => 'invalid',
    'error' => ['type' => 'urn:ietf:params:acme:error:unauthorized', 'detail' => '验证没过'],
], 'https://acme.test/order/2');

$t->ok($invalidOrder->isInvalid(), '识别出无效订单');
$t->contains('验证没过', $invalidOrder->getErrorMessage(), '应当能取出失败原因');

$t->group('值对象：Authorization 与通配符');

$wildcardAuth = new Authorization([
    'status' => 'pending',
    'identifier' => ['type' => 'dns', 'value' => 'example.com'],
    'wildcard' => true,
    'challenges' => [
        ['type' => 'dns-01', 'url' => 'https://acme.test/chall/1', 'token' => 'tok', 'status' => 'pending'],
    ],
], 'https://acme.test/authz/1');

// 服务端在通配符授权里给的 identifier 是不带 *. 的裸域名
$t->equals('*.example.com', $wildcardAuth->getDomain(), '通配符授权应当把 *. 拼回去');
$t->equals('example.com', $wildcardAuth->getBaseDomain(), '裸域名单独可取');
$t->ok($wildcardAuth->isWildcard(), '识别出通配符');
$t->equals(['dns-01'], $wildcardAuth->getAvailableTypes(), '通配符只有 dns-01');
$t->equals(null, $wildcardAuth->findChallenge('http-01'), '找不到 http-01 应当返回 null');
$t->ok($wildcardAuth->findChallenge('dns-01') !== null, '应当能找到 dns-01');

$t->group('值对象：Challenge 的应答值');

$accountKey = KeyPair::generate('ec-256');
$challenge = new Challenge([
    'type' => 'http-01',
    'url' => 'https://acme.test/chall/1',
    'token' => 'test-token',
    'status' => 'pending',
], 'example.com');

$t->equals('test-token.' . $accountKey->getThumbprint(), $challenge->getKeyAuthorization($accountKey), 'http-01 的值');
$t->equals('.well-known/acme-challenge/test-token', $challenge->getHttpPath(), '文件路径');
$t->equals('http://example.com/.well-known/acme-challenge/test-token', $challenge->getHttpUrl(), 'CA 会访问的地址');
$t->equals('_acme-challenge.example.com', $challenge->getDnsRecordName(), 'dns-01 的记录名');

$failedChallenge = new Challenge([
    'type' => 'http-01',
    'url' => 'https://acme.test/chall/1',
    'token' => 'x',
    'status' => 'invalid',
    'error' => ['type' => 'urn:ietf:params:acme:error:unauthorized', 'detail' => '拿到的是 404'],
], 'example.com');

$t->ok($failedChallenge->isInvalid(), '识别出失败');
$t->contains('404', $failedChallenge->getErrorMessage(), '失败原因是排错的关键信息，必须能取出来');

$t->group('账户联系方式');

$t->equals(['mailto:a@b.com'], \Mci\Acme\Protocol\Account::buildContacts('a@b.com'), '单个邮箱');
$t->equals(
    ['mailto:a@b.com', 'mailto:c@d.com'],
    \Mci\Acme\Protocol\Account::buildContacts('a@b.com,c@d.com'),
    '逗号分隔的多个邮箱'
);
$t->equals(['mailto:a@b.com'], \Mci\Acme\Protocol\Account::buildContacts('mailto:a@b.com'), '已经带 mailto: 的不该套两层');
$t->equals([], \Mci\Acme\Protocol\Account::buildContacts(''), '空串');

$t->group('对着模拟服务端跑协议方法');

$server = new FakeAcmeServer();
$http = new HttpClient($server->getTransport());
$client = AcmeClient::create($http, $server->getDirectoryUrl());
$client->setSleeper(static function (): void {
});

$keyPair = KeyPair::generate('ec-256');
$account = $client->registerAccount($keyPair, ['mailto:test@example.com']);

$t->contains('/acct/', $account->getUrl(), '注册应当返回账户 URL');
$t->equals(['test@example.com'], $account->getEmails(), '联系邮箱应当被记录');

// 幂等性：同一把密钥再注册一次应当返回同一个账户
$again = $client->registerAccount($keyPair, ['mailto:test@example.com']);
$t->equals($account->getUrl(), $again->getUrl(), 'newAccount 必须是幂等的');
$t->equals(1, $server->getAccountCount(), '服务端只该有一个账户');

$lookup = $client->lookupAccount($keyPair);
$t->ok($lookup !== null, 'onlyReturnExisting 应当查到已有账户');

$unknown = $client->lookupAccount(KeyPair::generate('ec-256'));
$t->equals(null, $unknown, '没注册过的密钥应当查不到（而不是抛异常）');

$client->useAccount($account);
$newOrder = $client->newOrder(['example.com', 'www.example.com']);

$t->ok($newOrder->isPending(), '新订单是 pending');
$t->equals(2, \count($newOrder->getAuthorizationUrls()), '两个域名两个授权');

$authorization = $client->fetchAuthorization($newOrder->getAuthorizationUrls()[0]);
$t->ok($authorization->isPending(), '授权是 pending');
$t->ok(\count($authorization->getChallenges()) > 0, '应当有挑战可选');

exit($t->summary());
