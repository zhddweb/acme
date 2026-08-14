<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use PhpAcme\Exception\HttpException;
use PhpAcme\Http\HttpClient;
use PhpAcme\Http\Request;
use PhpAcme\Http\Response;
use PhpAcme\Http\Transport\MockTransport;
use PhpAcme\Tests\Runner;

$t = new Runner('HTTP 客户端');

$t->group('响应头大小写不敏感');

// HTTP/2 强制小写头名，HTTP/1.1 习惯首字母大写。
// 大小写敏感地取会在换了 CA（或它换了 CDN）之后莫名其妙失效
$response = new Response(200, ['Replay-Nonce' => 'abc', 'CONTENT-TYPE' => 'application/json']);

$t->equals('abc', $response->getHeader('replay-nonce'), '小写取');
$t->equals('abc', $response->getHeader('Replay-Nonce'), '原样取');
$t->equals('abc', $response->getHeader('REPLAY-NONCE'), '大写取');
$t->equals('application/json', $response->getContentType(), 'Content-Type 应当去掉 charset 部分');

$withCharset = new Response(200, ['Content-Type' => 'application/problem+json; charset=utf-8']);
$t->equals('application/problem+json', $withCharset->getContentType(), '带 charset 的也要正确解析');
$t->ok($withCharset->isProblem(), '应当识别出 problem document');

$t->group('Link 头解析');

$linked = new Response(200, [
    'Link' => [
        '<https://acme.test/terms>;rel="terms-of-service"',
        '<https://acme.test/alt/1>;rel="alternate", <https://acme.test/alt/2>;rel="alternate"',
    ],
]);

$links = $linked->getLinks();
$t->equals(['https://acme.test/terms'], $links['terms-of-service'], '服务条款链接');
$t->equals(
    ['https://acme.test/alt/1', 'https://acme.test/alt/2'],
    $linked->getLink('alternate'),
    '一行里的多个 alternate 都要解析出来'
);
$t->equals([], $linked->getLink('不存在的rel'), '没有的 rel 返回空数组');

$t->group('Retry-After');

$t->equals(30, (new Response(429, ['Retry-After' => '30']))->getRetryAfter(), '秒数形式');
$t->ok((new Response(429, ['Retry-After' => gmdate('D, d M Y H:i:s \G\M\T', time() + 60)]))->getRetryAfter() > 50, 'HTTP 日期形式');
$t->equals(null, (new Response(200))->getRetryAfter(), '没有这个头时返回 null');

$t->group('状态判断');

$t->ok((new Response(200))->isSuccess(), '200 是成功');
$t->ok((new Response(201))->isSuccess(), '201 是成功');
$t->ok(!(new Response(404))->isSuccess(), '404 不是成功');
$t->ok((new Response(301))->isRedirect(), '301 是重定向');
$t->ok((new Response(503))->isServerError(), '503 是服务端错误');

$t->group('重定向跟随');

$transport = new MockTransport();
$transport->onUrl('GET', 'https://acme.test/a', new Response(302, ['Location' => 'https://acme.test/b']));
$transport->onUrl('GET', 'https://acme.test/b', new Response(302, ['Location' => '/c']));
$transport->onUrl('GET', 'https://acme.test/c', new Response(200, [], 'final'));

$client = new HttpClient($transport);
$result = $client->get('https://acme.test/a');

$t->equals('final', $result->getBody(), '应当一路跟到最后');
$t->equals(3, $transport->countRequests(), '跳了两次，一共三次请求');

$t->group('相对地址补全');

$t->equals('https://a.test/x', $client->resolveUrl('https://a.test/dir/page', '/x'), '绝对路径');
$t->equals('https://a.test/dir/x', $client->resolveUrl('https://a.test/dir/page', 'x'), '相对路径');
$t->equals('https://b.test/x', $client->resolveUrl('https://a.test/dir/page', 'https://b.test/x'), '完整 URL 原样返回');

$t->group('POST 被 307 重定向时必须报错');

// ACME 的 POST 带签名，签名里绑了原 URL，重放到别处必然验签失败。
// 与其发一个注定失败的请求，不如当场给出能看懂的报错
$postTransport = new MockTransport();
$postTransport->onUrl('POST', 'https://acme.test/order', new Response(307, ['Location' => 'https://other.test/order']));

$postClient = new HttpClient($postTransport);

$t->throws(
    static function () use ($postClient): void {
        $postClient->post('https://acme.test/order', '{}');
    },
    HttpException::class,
    'POST 遇到 307 应当报错而不是盲目重放签名'
);

$t->group('重定向次数上限');

$loopTransport = new MockTransport();
$loopTransport->setFallback(static function (Request $request): Response {
    return new Response(302, ['Location' => $request->getUrl() . '/next']);
});

$loopClient = new HttpClient($loopTransport);

$t->throws(
    static function () use ($loopClient): void {
        $loopClient->get('https://acme.test/loop');
    },
    HttpException::class,
    '无限重定向应当被上限拦住'
);

$t->group('5xx 重试，4xx 不重试');

$attempts = 0;
$retryTransport = new MockTransport();
$retryTransport->setFallback(static function () use (&$attempts): Response {
    ++$attempts;

    return $attempts < 3 ? new Response(503) : new Response(200, [], 'ok');
});

$retryClient = new HttpClient($retryTransport);
$retryClient->setSleeper(static function (): void {
});

$retryResult = $retryClient->get('https://acme.test/flaky');
$t->equals('ok', $retryResult->getBody(), '503 之后重试应当成功');
$t->equals(3, $attempts, '应当试了三次');

$clientErrorAttempts = 0;
$clientErrorTransport = new MockTransport();
$clientErrorTransport->setFallback(static function () use (&$clientErrorAttempts): Response {
    ++$clientErrorAttempts;

    return new Response(400, ['Content-Type' => 'application/problem+json'], '{"type":"x"}');
});

$clientErrorClient = new HttpClient($clientErrorTransport);
$clientErrorClient->setSleeper(static function (): void {
});
$clientErrorClient->get('https://acme.test/bad');

$t->equals(1, $clientErrorAttempts, '4xx 是我们自己的问题，重试只会白撞速率限制');

$t->group('网络异常也重试');

$networkAttempts = 0;
$networkTransport = new MockTransport();
$networkTransport->setFallback(static function () use (&$networkAttempts): Response {
    ++$networkAttempts;
    if ($networkAttempts < 2) {
        throw new HttpException('连接超时');
    }

    return new Response(200, [], 'recovered');
});

$networkClient = new HttpClient($networkTransport);
$networkClient->setSleeper(static function (): void {
});

$t->equals('recovered', $networkClient->get('https://acme.test/x')->getBody(), '网络抖动后重试应当成功');

$t->group('请求构造');

$request = $client->buildRequest('POST', 'https://acme.test/x', '{"a":1}', ['Content-Type' => 'application/jose+json']);

$t->equals('POST', $request->getMethod(), '方法');
$t->equals('application/jose+json', $request->getHeader('content-type'), '取头时不分大小写');
$t->contains('php-acme/', (string) $request->getHeader('User-Agent'), '应当自动带上 User-Agent');

$t->group('MockTransport 的断言能力');

$assertTransport = new MockTransport();
$assertTransport->setFallback(static function (): Response {
    return new Response(200, [], '{}');
});

$assertClient = new HttpClient($assertTransport);
$assertClient->postJson('https://api.test/records', ['name' => 'x', 'type' => 'TXT']);

$last = $assertTransport->getLastRequest();
$t->ok($last !== null, '应当记录下请求');
$t->equals('application/json', $last->getHeader('Content-Type'), 'postJson 应当设好 Content-Type');
$t->contains('"type":"TXT"', (string) $last->getBody(), '请求体应当是紧凑 JSON');

exit($t->summary());
