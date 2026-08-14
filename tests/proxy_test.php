<?php

declare(strict_types=1);

/**
 * 代理支持测试。
 *
 * 重点在**手写的那两段协议**：HTTP CONNECT 隧道与 SOCKS5 握手。
 * 这两处是纯字节操作，写错一个偏移量就会得到「连接被重置」这种毫无信息量的
 * 报错，所以这里用 stream_socket_pair() 造一对连通的 socket，
 * 预先把服务端该回的字节塞进去，再逐字节断言客户端发出来的报文。
 */

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Exception\HttpException;
use Mci\Acme\Http\HttpClient;
use Mci\Acme\Http\Proxy\Proxy;
use Mci\Acme\Http\Proxy\ProxyConnector;
use Mci\Acme\Http\Proxy\ProxyResolver;
use Mci\Acme\Http\Request;
use Mci\Acme\Http\Transport\SocketTransport;
use Mci\Acme\Tests\Runner;

$t = new Runner('代理');

// ---------------------------------------------------------------- 地址解析

$t->group('代理地址解析');

$proxy = Proxy::fromString('http://127.0.0.1:8080');
$t->equals('http', $proxy->getScheme(), 'scheme');
$t->equals('127.0.0.1', $proxy->getHost(), 'host');
$t->equals(8080, $proxy->getPort(), 'port');
$t->ok(!$proxy->hasCredentials(), '没有认证信息');
$t->ok($proxy->isHttp(), '是 HTTP 代理');
$t->ok(!$proxy->isSocks(), '不是 SOCKS');

$authProxy = Proxy::fromString('http://user:secret@proxy.corp:3128');
$t->equals('user', $authProxy->getUsername(), '用户名');
$t->equals('secret', $authProxy->getPassword(), '密码');
$t->ok($authProxy->hasCredentials(), '有认证信息');

// 密码里带 @ 或 : 时必须 URL 编码，解析要还原回去
$encoded = Proxy::fromString('http://user:p%40ss%3Aword@proxy:3128');
$t->equals('p@ss:word', $encoded->getPassword(), 'URL 编码的密码应当被还原');

$socks = Proxy::fromString('socks5h://127.0.0.1:1080');
$t->ok($socks->isSocks(), '是 SOCKS');
$t->ok($socks->resolvesRemotely(), 'socks5h 表示域名交给代理解析');
$t->ok(!Proxy::fromString('socks5://127.0.0.1:1080')->resolvesRemotely(), 'socks5 是本地解析');

$t->group('省略 scheme 与端口');

// curl 的习惯：不写 scheme 就当 http
$bare = Proxy::fromString('proxy.corp:3128');
$t->equals('http', $bare->getScheme(), '省略 scheme 时按 http 处理');
$t->equals(3128, $bare->getPort(), '端口');

$t->equals(1080, Proxy::fromString('socks5://host')->getPort(), 'SOCKS 默认端口 1080');
$t->equals(8080, Proxy::fromString('http://host')->getPort(), 'HTTP 代理默认端口 8080');

$t->group('密码不能出现在日志里');

// 代理密码跟着日志被贴进 issue 是真实发生过的事故
$safe = $authProxy->toSafeString();
$t->ok(strpos($safe, 'secret') === false, '打码后的字符串里不能有密码');
$t->contains('user', $safe, '用户名可以保留，便于确认配对了');
$t->contains('***', $safe, '密码位置应当有打码标记');

$t->group('非法输入');

$t->throws(static function (): void {
    Proxy::fromString('');
}, ConfigException::class, '空地址');

$t->throws(static function (): void {
    Proxy::fromString('ftp://host:21');
}, ConfigException::class, '不支持的协议应当报错并列出可用值');

// ---------------------------------------------------------------- 选择逻辑

$t->group('按 scheme 选环境变量');

$resolver = new ProxyResolver();
$resolver->setEnvironmentOverride([
    'HTTP_PROXY' => 'http://http-proxy:8080',
    'HTTPS_PROXY' => 'http://https-proxy:8443',
]);

$t->equals('https-proxy', $resolver->resolve('https://acme.test/x')->getHost(), 'https 目标用 HTTPS_PROXY');
$t->equals('http-proxy', $resolver->resolve('http://acme.test/x')->getHost(), 'http 目标用 HTTP_PROXY');

$t->group('ALL_PROXY 兜底');

$allResolver = new ProxyResolver();
$allResolver->setEnvironmentOverride(['ALL_PROXY' => 'socks5h://all:1080']);

$t->equals('all', $allResolver->resolve('https://acme.test/x')->getHost(), 'https 回落到 ALL_PROXY');
$t->equals('all', $allResolver->resolve('http://acme.test/x')->getHost(), 'http 也回落到 ALL_PROXY');

$t->group('小写变量名也认');

$lowerResolver = new ProxyResolver();
$lowerResolver->setEnvironmentOverride(['https_proxy' => 'http://lower:8080']);
$t->equals('lower', $lowerResolver->resolve('https://x.test/')->getHost(), '小写的 https_proxy 应当生效');

$t->group('NO_PROXY');

$noProxyResolver = new ProxyResolver();
$noProxyResolver->setEnvironmentOverride([
    'ALL_PROXY' => 'http://proxy:8080',
    'NO_PROXY' => 'example.com,.internal,10.0.0.1',
]);

$t->equals(null, $noProxyResolver->resolve('https://example.com/x'), '精确匹配的域名直连');
$t->equals(null, $noProxyResolver->resolve('https://sub.example.com/x'), '子域也直连');
$t->equals(null, $noProxyResolver->resolve('https://a.internal/x'), '前导点的写法匹配子域');
$t->equals(null, $noProxyResolver->resolve('https://10.0.0.1/x'), 'IP 直连');
$t->ok($noProxyResolver->resolve('https://other.com/x') !== null, '不在清单里的照常走代理');
// notexample.com 不该被 example.com 命中——按后缀匹配时最容易犯的错
$t->ok($noProxyResolver->resolve('https://notexample.com/x') !== null, 'notexample.com 不该被 example.com 匹配');

$starResolver = new ProxyResolver();
$starResolver->setEnvironmentOverride(['ALL_PROXY' => 'http://p:1', 'NO_PROXY' => '*']);
$t->equals(null, $starResolver->resolve('https://anything.test/'), 'NO_PROXY=* 表示全部直连');

$t->group('显式设置优先于环境变量');

$explicitResolver = new ProxyResolver(Proxy::fromString('http://explicit:9999'));
$explicitResolver->setEnvironmentOverride(['HTTPS_PROXY' => 'http://from-env:8080']);

$t->equals('explicit', $explicitResolver->resolve('https://x.test/')->getHost(), '显式设置应当胜出');

$explicitResolver->setUseEnvironment(false);
$explicitResolver->setExplicit(null);
$t->equals(null, $explicitResolver->resolve('https://x.test/'), '关掉环境变量后应当直连');

$t->group('环境变量写错了不该让流程崩');

$badResolver = new ProxyResolver();
$badResolver->setEnvironmentOverride(['HTTPS_PROXY' => 'ftp://不合法']);
$t->noThrow(static function () use ($badResolver): void {
    $badResolver->resolve('https://x.test/');
}, '环境变量里的地址不合法时应当忽略而不是抛异常');

// ---------------------------------------------------------------- CONNECT 隧道

$t->group('HTTP CONNECT 隧道的报文');

/**
 * 造一对连通的 socket。
 *
 * 一端交给被测代码当作「连到代理的连接」，另一端由测试扮演代理：
 * 先把代理该回的字节塞进去，被测代码 read 时就能立刻拿到，
 * 不会因为等不到响应而阻塞。
 *
 * @return array{0: resource, 1: resource}
 */
function socketPair(): array
{
    $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    if ($pair === false) {
        throw new RuntimeException('这个环境不支持 stream_socket_pair()');
    }

    return $pair;
}

/**
 * 用反射调私有方法：握手逻辑本身不该是公开 API，
 * 但它是最需要逐字节验证的部分。
 *
 * @param array<int, mixed> $arguments
 * @return mixed
 */
function callPrivate(object $object, string $method, array $arguments)
{
    $reflection = new ReflectionMethod($object, $method);
    $reflection->setAccessible(true);

    return $reflection->invokeArgs($object, $arguments);
}

$connector = new ProxyConnector();

list($client, $server) = socketPair();
fwrite($server, "HTTP/1.1 200 Connection established\r\n\r\n");

$t->noThrow(static function () use ($connector, $client): void {
    callPrivate($connector, 'httpConnect', [
        $client,
        Proxy::fromString('http://proxy:8080'),
        'acme-v02.api.letsencrypt.org',
        443,
    ]);
}, '代理回 200 时隧道应当建立成功');

$sent = fread($server, 4096);

$t->contains(
    "CONNECT acme-v02.api.letsencrypt.org:443 HTTP/1.1\r\n",
    (string) $sent,
    'CONNECT 请求行应当写目标主机与端口'
);
$t->contains(
    "Host: acme-v02.api.letsencrypt.org:443\r\n",
    (string) $sent,
    'Host 头写的是目标而不是代理'
);
$t->ok(str_ends_with((string) $sent, "\r\n\r\n"), '请求应当以空行结束');

fclose($client);
fclose($server);

$t->group('CONNECT 的代理认证');

list($client2, $server2) = socketPair();
fwrite($server2, "HTTP/1.1 200 OK\r\n\r\n");

callPrivate($connector, 'httpConnect', [
    $client2,
    Proxy::fromString('http://alice:s3cret@proxy:8080'),
    'x.test',
    443,
]);

$sentAuth = (string) fread($server2, 4096);
$t->contains(
    'Proxy-Authorization: Basic ' . base64_encode('alice:s3cret'),
    $sentAuth,
    '有凭据时应当带 Proxy-Authorization 头'
);

fclose($client2);
fclose($server2);

$t->group('CONNECT 被拒绝时的报错');

$rejectCases = [
    "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n" => '认证',
    "HTTP/1.1 403 Forbidden\r\n\r\n" => '拒绝',
    "HTTP/1.1 502 Bad Gateway\r\n\r\n" => '网关',
];

foreach ($rejectCases as $response => $label) {
    list($c, $s) = socketPair();
    fwrite($s, $response);

    $t->throws(static function () use ($connector, $c): void {
        callPrivate($connector, 'httpConnect', [$c, Proxy::fromString('http://proxy:8080'), 'x.test', 443]);
    }, HttpException::class, sprintf('代理返回%s时应当报错', $label));

    fclose($c);
    fclose($s);
}

$t->group('407 的报错要教用户怎么改');

list($c407, $s407) = socketPair();
fwrite($s407, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");

try {
    callPrivate($connector, 'httpConnect', [$c407, Proxy::fromString('http://proxy:8080'), 'x.test', 443]);
    $t->fail('应当抛异常');
} catch (HttpException $e) {
    $t->contains('user:pass', $e->getMessage(), '407 的报错里应当给出带认证的写法');
}

fclose($c407);
fclose($s407);

// ---------------------------------------------------------------- SOCKS5

$t->group('SOCKS5 握手的报文（无认证）');

list($sc, $ss) = socketPair();
// 版本协商响应：VER=5, METHOD=0（无需认证）
fwrite($ss, "\x05\x00");
// CONNECT 响应：VER=5, REP=0（成功）, RSV=0, ATYP=1(IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
fwrite($ss, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00");

$t->noThrow(static function () use ($connector, $sc): void {
    callPrivate($connector, 'socks5Handshake', [
        $sc,
        Proxy::fromString('socks5h://127.0.0.1:1080'),
        'acme.test',
        443,
    ]);
}, 'SOCKS5 握手应当成功');

$socksSent = (string) fread($ss, 4096);

// 第一段：VER=5, NMETHODS=1, METHODS=[0]
$t->equals("\x05\x01\x00", substr($socksSent, 0, 3), '版本协商报文：只声明支持无认证');

// 第二段：VER=5, CMD=1(CONNECT), RSV=0, ATYP=3(域名), LEN=9, "acme.test", PORT=443
$expectedConnect = "\x05\x01\x00\x03" . \chr(9) . 'acme.test' . pack('n', 443);
$t->equals($expectedConnect, substr($socksSent, 3), 'CONNECT 报文：socks5h 应当用域名类型(ATYP=3)把解析交给代理');

fclose($sc);
fclose($ss);

$t->group('SOCKS5：socks5 用 IP 类型');

list($sc2, $ss2) = socketPair();
fwrite($ss2, "\x05\x00");
fwrite($ss2, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00");

callPrivate($connector, 'socks5Handshake', [
    $sc2,
    Proxy::fromString('socks5://127.0.0.1:1080'),
    '93.184.216.34',
    443,
]);

$ipSent = (string) fread($ss2, 4096);
$expectedIp = "\x05\x01\x00\x01" . inet_pton('93.184.216.34') . pack('n', 443);
$t->equals($expectedIp, substr($ipSent, 3), '目标已经是 IP 时用 ATYP=1');

fclose($sc2);
fclose($ss2);

$t->group('SOCKS5 用户名密码认证（RFC 1929）');

list($ac, $as) = socketPair();
// 版本协商：选中方法 2（用户名密码）
fwrite($as, "\x05\x02");
// 认证响应：VER=1, STATUS=0（成功）
fwrite($as, "\x01\x00");
// CONNECT 响应
fwrite($as, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00");

callPrivate($connector, 'socks5Handshake', [
    $ac,
    Proxy::fromString('socks5h://bob:pw123@127.0.0.1:1080'),
    'x.test',
    443,
]);

$authSent = (string) fread($as, 4096);

// 第一段应当声明支持两种方法
$t->equals("\x05\x02\x00\x02", substr($authSent, 0, 4), '有凭据时应当同时声明支持无认证与用户名密码');

// 第二段是认证子协商：VER=1, ULEN=3, "bob", PLEN=5, "pw123"
$expectedAuth = "\x01" . \chr(3) . 'bob' . \chr(5) . 'pw123';
$t->equals($expectedAuth, substr($authSent, 4, \strlen($expectedAuth)), '认证报文格式应当符合 RFC 1929');

fclose($ac);
fclose($as);

$t->group('SOCKS5 的各种失败');

// 认证被拒
list($fc, $fs) = socketPair();
fwrite($fs, "\x05\x02");
fwrite($fs, "\x01\x01");

$t->throws(static function () use ($connector, $fc): void {
    callPrivate($connector, 'socks5Handshake', [
        $fc,
        Proxy::fromString('socks5://u:p@127.0.0.1:1080'),
        'x.test',
        443,
    ]);
}, HttpException::class, '认证失败应当报错');

fclose($fc);
fclose($fs);

// 没有可接受的认证方式
list($nc, $ns) = socketPair();
fwrite($ns, "\x05\xff");

try {
    callPrivate($connector, 'socks5Handshake', [$nc, Proxy::fromString('socks5://127.0.0.1:1080'), 'x.test', 443]);
    $t->fail('应当抛异常');
} catch (HttpException $e) {
    $t->contains('用户名密码', $e->getMessage(), '0xFF 的报错应当提示可能需要用户名密码');
}

fclose($nc);
fclose($ns);

// 目标连不上
$socksErrors = [
    "\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00" => '规则不允许',
    "\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00" => '网络不可达',
    "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00" => '连接被拒绝',
];

foreach ($socksErrors as $reply => $expectedText) {
    list($ec, $es) = socketPair();
    fwrite($es, "\x05\x00");
    fwrite($es, $reply);

    try {
        callPrivate($connector, 'socks5Handshake', [$ec, Proxy::fromString('socks5://127.0.0.1:1080'), 'x.test', 443]);
        $t->fail('应当抛异常');
    } catch (HttpException $e) {
        $t->contains($expectedText, $e->getMessage(), sprintf('错误码应当翻译成「%s」', $expectedText));
    }

    fclose($ec);
    fclose($es);
}

$t->group('不是 SOCKS5 服务时的报错');

list($wc, $ws) = socketPair();
// 拿 HTTP 代理的地址配成 socks5 是很常见的手误
fwrite($ws, "HT");

try {
    callPrivate($connector, 'socks5Handshake', [$wc, Proxy::fromString('socks5://127.0.0.1:8080'), 'x.test', 443]);
    $t->fail('应当抛异常');
} catch (HttpException $e) {
    $t->contains('不是 SOCKS5', $e->getMessage(), '版本字节不对时应当明确指出它不是 SOCKS5 代理');
}

fclose($wc);
fclose($ws);

$t->group('SOCKS5 应答分包到达也要能处理');

// 真实网络下 10 字节的应答可能分两个 TCP 包来，
// 只 fread 一次会少读——这个用例专门盯这个
list($pc, $ps) = socketPair();
fwrite($ps, "\x05\x00");
fwrite($ps, "\x05\x00\x00\x01\x00\x00");
fwrite($ps, "\x00\x00\x00\x00");

$t->noThrow(static function () use ($connector, $pc): void {
    callPrivate($connector, 'socks5Handshake', [$pc, Proxy::fromString('socks5://127.0.0.1:1080'), 'x.test', 443]);
}, '应答分多次到达时应当读满再解析');

fclose($pc);
fclose($ps);

// ---------------------------------------------------------------- 隧道里的 HTTP

$t->group('SocketTransport 在隧道上收发 HTTP');

/** 把已经准备好的 socket 直接交出去，跳过真实连接 */
final class StubConnector extends ProxyConnector
{
    /** @var resource */
    private $socket;

    /**
     * @param resource $socket
     */
    public function __construct($socket)
    {
        $this->socket = $socket;
    }

    public function connect(
        Proxy $proxy,
        string $host,
        int $port,
        bool $useTls,
        array $sslOptions = [],
        int $timeout = 30
    ) {
        return $this->socket;
    }
}

/**
 * @param string $rawResponse 服务端要回的完整 HTTP 报文
 * @return array{response: \Mci\Acme\Http\Response, sent: string}
 */
function sendThroughSocket(string $rawResponse, Request $request): array
{
    list($client, $server) = socketPair();
    fwrite($server, $rawResponse);

    $transport = new SocketTransport(new StubConnector($client));
    $request->setProxyConfig(Proxy::fromString('http://proxy:8080'));

    $response = $transport->send($request);
    $sent = (string) stream_get_contents($server);

    fclose($server);

    return ['response' => $response, 'sent' => $sent];
}

$result = sendThroughSocket(
    "HTTP/1.1 200 OK\r\n"
    . "Content-Type: application/json\r\n"
    . "Replay-Nonce: abc123\r\n"
    . "Content-Length: 17\r\n"
    . "\r\n"
    . '{"status":"ok"}  ',
    new Request('GET', 'https://acme.test/directory', ['User-Agent' => 'test'])
);

$t->equals(200, $result['response']->getStatus(), '状态码');
$t->equals('abc123', $result['response']->getHeader('replay-nonce'), '响应头（取值不分大小写）');
$t->equals('{"status":"ok"}  ', $result['response']->getBody(), '按 Content-Length 精确读取响应体');
$t->contains("GET /directory HTTP/1.1\r\n", $result['sent'], '请求行用的是路径而不是绝对 URI（隧道里是普通请求）');
$t->contains("Host: acme.test\r\n", $result['sent'], 'Host 头');

$t->group('chunked 编码');

$chunked = sendThroughSocket(
    "HTTP/1.1 200 OK\r\n"
    . "Transfer-Encoding: chunked\r\n"
    . "\r\n"
    . "5\r\nhello\r\n"
    . "7\r\n, world\r\n"
    . "0\r\n\r\n",
    new Request('GET', 'https://acme.test/x')
);

$t->equals('hello, world', $chunked['response']->getBody(), 'chunked 的各块应当拼回原文');

$t->group('带扩展参数的 chunk 大小行');

$chunkedExt = sendThroughSocket(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    . "5;ext=1\r\nhello\r\n0\r\n\r\n",
    new Request('GET', 'https://acme.test/x')
);

$t->equals('hello', $chunkedExt['response']->getBody(), '块大小后面的分号扩展应当被忽略');

$t->group('POST 请求体与 Content-Length');

$posted = sendThroughSocket(
    "HTTP/1.1 201 Created\r\nLocation: https://acme.test/acct/1\r\nContent-Length: 2\r\n\r\n{}",
    new Request('POST', 'https://acme.test/new-account', ['Content-Type' => 'application/jose+json'], '{"protected":"x"}')
);

$t->equals(201, $posted['response']->getStatus(), '状态码');
$t->equals('https://acme.test/acct/1', $posted['response']->getLocation(), 'Location 头');
$t->contains("Content-Length: 17\r\n", $posted['sent'], '应当自动算出 Content-Length');
$t->contains('{"protected":"x"}', $posted['sent'], '请求体应当被发出去');

$t->group('没有响应体的状态码');

$noBody = sendThroughSocket(
    "HTTP/1.1 204 No Content\r\n\r\n",
    new Request('GET', 'https://acme.test/x')
);

$t->equals(204, $noBody['response']->getStatus(), '204');
$t->equals('', $noBody['response']->getBody(), '204 按规范没有响应体，不该去读以致超时');

$headResult = sendThroughSocket(
    "HTTP/1.1 200 OK\r\nReplay-Nonce: n1\r\nContent-Length: 100\r\n\r\n",
    new Request('HEAD', 'https://acme.test/new-nonce')
);

$t->equals('n1', $headResult['response']->getHeader('replay-nonce'), 'HEAD 也要能拿到响应头');
$t->equals('', $headResult['response']->getBody(), 'HEAD 即使声明了 Content-Length 也没有响应体');

$t->group('先来一个 100 Continue');

$continue = sendThroughSocket(
    "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    new Request('POST', 'https://acme.test/x', [], 'body')
);

$t->equals(200, $continue['response']->getStatus(), '应当跳过 1xx 中间响应，取真正的那个');
$t->equals('ok', $continue['response']->getBody(), '响应体');

// ---------------------------------------------------------------- 客户端接线

$t->group('HttpClient 的代理接口');

$client = new HttpClient(new \Mci\Acme\Http\Transport\MockTransport());
$client->getProxyResolver()->setEnvironmentOverride([]);

$client->setProxy('socks5h://127.0.0.1:1080');
$t->equals('127.0.0.1', $client->getProxyResolver()->resolve('https://x.test/')->getHost(), '字符串形式设置代理');

$client->setProxy(Proxy::fromString('http://obj:8080'));
$t->equals('obj', $client->getProxyResolver()->resolve('https://x.test/')->getHost(), '对象形式设置代理');

$client->addNoProxy('skip.test');
$t->equals(null, $client->getProxyResolver()->resolve('https://skip.test/'), 'addNoProxy 应当生效');

$client->disableProxy();
$t->equals(null, $client->getProxyResolver()->resolve('https://x.test/'), 'disableProxy 之后应当直连');

$t->group('请求上带着解析好的代理');

$proxyClient = new HttpClient(new \Mci\Acme\Http\Transport\MockTransport());
$proxyClient->getProxyResolver()->setEnvironmentOverride([]);
$proxyClient->setProxy('http://p:8080');
$proxyClient->addNoProxy('direct.test');

$viaProxy = $proxyClient->buildRequest('GET', 'https://acme.test/x', null, []);
$t->ok($viaProxy->usesProxy(), '普通请求应当带上代理');
$t->equals('p', $viaProxy->getProxyConfig()->getHost(), '带的是设置的那个代理');

$direct = $proxyClient->buildRequest('GET', 'https://direct.test/x', null, []);
$t->ok(!$direct->usesProxy(), 'NO_PROXY 命中的请求不该带代理');

exit($t->summary());
