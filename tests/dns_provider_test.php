<?php

declare(strict_types=1);

/**
 * DNS 提供商适配器测试。
 *
 * 全部用 MockTransport，**不打任何真实 API**——既是为了能离线跑，
 * 也是因为这些接口都有频率限制，测试打真的会把开发者的账号搞挂。
 *
 * 断言的重点是三件事：请求发到了正确的地址、鉴权头对不对、
 * 以及最关键的「同名多值」——通配符与裸域同时验证时会有两条同名 TXT，
 * 覆盖式写入的提供商必须先读后写。
 */

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Challenge\Dns01\Provider\AliyunDns;
use Mci\Acme\Challenge\Dns01\Provider\Cloudflare;
use Mci\Acme\Challenge\Dns01\Provider\DnsPod;
use Mci\Acme\Challenge\Dns01\Provider\GoDaddy;
use Mci\Acme\Challenge\Dns01\Provider\Route53;
use Mci\Acme\Challenge\Dns01\Provider\TencentCloud;
use Mci\Acme\Challenge\Dns01\ProviderFactory;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Exception\DnsException;
use Mci\Acme\Http\HttpClient;
use Mci\Acme\Http\Request;
use Mci\Acme\Http\Response;
use Mci\Acme\Http\Transport\MockTransport;
use Mci\Acme\Tests\Runner;
use Mci\Acme\Util\Json;

$t = new Runner('DNS 提供商');

/**
 * @param array<string, mixed> $routes URL 片段 => 响应数据
 */
function mockClient(MockTransport $transport): HttpClient
{
    $client = new HttpClient($transport);
    $client->setSleeper(static function (): void {
    });

    return $client;
}

// ---------------------------------------------------------------- Cloudflare

$t->group('Cloudflare');

$transport = new MockTransport();
$transport->onUrlContains('/zones?', static function (Request $request): Response {
    // 只认 example.com 这个 zone，example.com.test 之类应当查不到
    $matched = str_contains($request->getUrl(), 'name=example.com&');

    return new Response(200, ['Content-Type' => 'application/json'], Json::encode([
        'success' => true,
        'result' => $matched ? [['id' => 'zone-123', 'name' => 'example.com']] : [],
    ]));
});
$transport->onUrlContains('/dns_records', static function (): Response {
    return new Response(200, ['Content-Type' => 'application/json'], Json::encode([
        'success' => true,
        'result' => ['id' => 'rec-1'],
    ]));
});

$cloudflare = new Cloudflare(['CF_Token' => 'test-token'], mockClient($transport));
$cloudflare->addTxtRecord('_acme-challenge.a.example.com', 'value-1');

$last = $transport->getLastRequest();
$t->equals('POST', $last->getMethod(), '加记录用 POST');
$t->contains('zone-123', $last->getUrl(), '应当用查到的 zone id');
$t->equals('Bearer test-token', $last->getHeader('Authorization'), 'API Token 用 Bearer 鉴权');

$payload = Json::decode((string) $last->getBody());
$t->equals('TXT', $payload['type'], '记录类型');
$t->equals('_acme-challenge.a.example.com', $payload['name'], '记录名用完整 FQDN');
$t->equals('value-1', $payload['content'], '记录值');

$t->group('Cloudflare 的旧式鉴权');

$legacyTransport = new MockTransport();
$legacyTransport->setFallback(static function (): Response {
    return new Response(200, ['Content-Type' => 'application/json'], Json::encode([
        'success' => true,
        'result' => [['id' => 'z', 'name' => 'example.com']],
    ]));
});

$legacy = new Cloudflare(['CF_Key' => 'global-key', 'CF_Email' => 'a@b.com'], mockClient($legacyTransport));
$legacy->addTxtRecord('_acme-challenge.example.com', 'v');

$legacyRequest = $legacyTransport->getLastRequest();
$t->equals('global-key', $legacyRequest->getHeader('X-Auth-Key'), 'Global API Key 走 X-Auth-Key');
$t->equals('a@b.com', $legacyRequest->getHeader('X-Auth-Email'), '同时要带邮箱');

$t->throws(static function (): void {
    (new Cloudflare([], mockClient(new MockTransport())))->addTxtRecord('_acme-challenge.example.com', 'v');
}, ConfigException::class, '没有任何凭据时应当给出明确提示');

$t->group('Cloudflare：zone 找不到时的报错');

$noZoneTransport = new MockTransport();
$noZoneTransport->setFallback(static function (): Response {
    return new Response(200, ['Content-Type' => 'application/json'], Json::encode(['success' => true, 'result' => []]));
});

$t->throws(static function () use ($noZoneTransport): void {
    (new Cloudflare(['CF_Token' => 'x'], mockClient($noZoneTransport)))
        ->addTxtRecord('_acme-challenge.notmine.com', 'v');
}, DnsException::class, '账号下没有这个域名时应当报错');

// ---------------------------------------------------------------- 阿里云

$t->group('阿里云 DNS 的签名');

$aliTransport = new MockTransport();
$aliTransport->setFallback(static function (): Response {
    return new Response(200, ['Content-Type' => 'application/json'], Json::encode([
        'DomainRecords' => ['Record' => []],
        'RecordId' => '1',
    ]));
});

$aliyun = new AliyunDns(['Ali_Key' => 'test-key-id', 'Ali_Secret' => 'test-secret'], mockClient($aliTransport));
$aliyun->addTxtRecord('_acme-challenge.example.com', 'ali-value');

$aliRequest = $aliTransport->getLastRequest();
parse_str((string) $aliRequest->getBody(), $params);

$t->equals('AddDomainRecord', $params['Action'], '调用的接口');
$t->equals('example.com', $params['DomainName'], 'zone');
$t->equals('_acme-challenge', $params['RR'], '记录名要用相对于 zone 的形式');
$t->equals('ali-value', $params['Value'], '记录值');
$t->equals('HMAC-SHA1', $params['SignatureMethod'], '签名算法');
$t->ok(isset($params['Signature']) && $params['Signature'] !== '', '应当带签名');
$t->ok(isset($params['SignatureNonce']) && \strlen($params['SignatureNonce']) === 32, '应当带随机 nonce');
$t->ok(preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $params['Timestamp']) === 1, '时间戳必须是 UTC 的 ISO 格式');

// 签名正确性：按阿里云的规则重算一遍，应当得到同一个值
$toSign = $params;
unset($toSign['Signature']);
ksort($toSign, SORT_STRING);
$pairs = [];
foreach ($toSign as $key => $value) {
    $encode = static function (string $v): string {
        return str_replace(['+', '*', '%7E'], ['%20', '%2A', '~'], rawurlencode($v));
    };
    $pairs[] = $encode((string) $key) . '=' . $encode((string) $value);
}
$stringToSign = 'POST&' . rawurlencode('/') . '&' . str_replace(['+', '*', '%7E'], ['%20', '%2A', '~'], rawurlencode(implode('&', $pairs)));
$expectedSignature = base64_encode(hash_hmac('sha1', $stringToSign, 'test-secret&', true));

$t->equals($expectedSignature, $params['Signature'], '签名应当与按规范手工计算的一致');

// ---------------------------------------------------------------- DNSPod

$t->group('DNSPod');

$dpTransport = new MockTransport();
$dpTransport->onUrlContains('/Domain.Info', new Response(200, ['Content-Type' => 'application/json'], Json::encode([
    'status' => ['code' => '1', 'message' => 'ok'],
    'domain' => ['id' => 'domain-9'],
])));
$dpTransport->onUrlContains('/Record.Create', new Response(200, ['Content-Type' => 'application/json'], Json::encode([
    'status' => ['code' => '1', 'message' => 'ok'],
    'record' => ['id' => 'r1'],
])));

$dnspod = new DnsPod(['DP_Id' => '12345', 'DP_Key' => 'secret'], mockClient($dpTransport));
$dnspod->addTxtRecord('_acme-challenge.example.com', 'dp-value');

$dpRequest = $dpTransport->getLastRequest();
parse_str((string) $dpRequest->getBody(), $dpParams);

$t->equals('12345,secret', $dpParams['login_token'], 'DNSPod 的令牌是 ID,Key 的形式');
$t->equals('domain-9', $dpParams['domain_id'], '应当先查出 domain id');
$t->equals('_acme-challenge', $dpParams['sub_domain'], '记录名');
$t->contains('mci-acme', (string) $dpRequest->getHeader('User-Agent'), 'DNSPod 强制要求带 UA');

$t->group('DNSPod 的业务错误');

$dpFailTransport = new MockTransport();
$dpFailTransport->setFallback(static function (): Response {
    // DNSPod 的 HTTP 状态永远 200，错误藏在 status.code 里
    return new Response(200, ['Content-Type' => 'application/json'], Json::encode([
        'status' => ['code' => '-1', 'message' => '登录失败'],
    ]));
});

$t->throws(static function () use ($dpFailTransport): void {
    (new DnsPod(['DP_Id' => '1', 'DP_Key' => 'x'], mockClient($dpFailTransport)))
        ->addTxtRecord('_acme-challenge.example.com', 'v');
}, DnsException::class, 'HTTP 200 但 code 非 1 时也必须当成失败');

// ---------------------------------------------------------------- 腾讯云

$t->group('腾讯云 TC3 签名');

$tcTransport = new MockTransport();
$tcTransport->setFallback(static function (Request $request): Response {
    $action = (string) $request->getHeader('X-TC-Action');

    if ($action === 'DescribeDomain') {
        return new Response(200, ['Content-Type' => 'application/json'], Json::encode([
            'Response' => ['DomainInfo' => ['DomainId' => 555]],
        ]));
    }

    return new Response(200, ['Content-Type' => 'application/json'], Json::encode([
        'Response' => ['RecordId' => 1],
    ]));
});

$tencent = new TencentCloud(
    ['Tencent_SecretId' => 'AKIDtest', 'Tencent_SecretKey' => 'secret-key'],
    mockClient($tcTransport)
);
$tencent->addTxtRecord('_acme-challenge.example.com', 'tc-value');

$tcRequest = $tcTransport->getLastRequest();
$authorization = (string) $tcRequest->getHeader('Authorization');

$t->contains('TC3-HMAC-SHA256', $authorization, '用 TC3 签名');
$t->contains('Credential=AKIDtest/', $authorization, 'Credential 里带 SecretId');
$t->contains('SignedHeaders=content-type;host;x-tc-action', $authorization, '签名头列表固定');
$t->equals('CreateRecord', $tcRequest->getHeader('X-TC-Action'), '调用的接口');

$tcPayload = Json::decode((string) $tcRequest->getBody());
$t->equals('example.com', $tcPayload['Domain'], 'zone');
$t->equals('_acme-challenge', $tcPayload['SubDomain'], '记录名');

// ---------------------------------------------------------------- GoDaddy（覆盖式 API）

$t->group('GoDaddy 的同名多值处理');

// 通配符与裸域同时验证时，_acme-challenge.example.com 会有两条值不同的 TXT。
// GoDaddy 的接口是整组 PUT 覆盖，必须先读出已有的再一起提交，否则会互相冲掉
$gdRecords = [['data' => 'existing-value', 'ttl' => 600]];

$gdTransport = new MockTransport();
$gdTransport->on(
    static function (Request $request): bool {
        return $request->getMethod() === 'GET' && str_contains($request->getUrl(), '/records/TXT/');
    },
    static function () use (&$gdRecords): Response {
        return new Response(200, ['Content-Type' => 'application/json'], Json::encode($gdRecords));
    }
);
$gdTransport->on(
    static function (Request $request): bool {
        return $request->getMethod() === 'GET' && str_contains($request->getUrl(), '/domains/example.com');
    },
    new Response(200, ['Content-Type' => 'application/json'], Json::encode(['domain' => 'example.com']))
);
$gdTransport->on(
    static function (Request $request): bool {
        return $request->getMethod() === 'PUT';
    },
    static function (Request $request) use (&$gdRecords): Response {
        $gdRecords = Json::decode((string) $request->getBody());

        return new Response(200, ['Content-Type' => 'application/json'], '[]');
    }
);

$godaddy = new GoDaddy(['GD_Key' => 'key', 'GD_Secret' => 'secret'], mockClient($gdTransport));
$godaddy->addTxtRecord('_acme-challenge.example.com', 'new-value');

$values = [];
foreach ($gdRecords as $record) {
    $values[] = $record['data'];
}

$t->ok(\in_array('existing-value', $values, true), '已有的值必须保留');
$t->ok(\in_array('new-value', $values, true), '新值应当加进去');
$t->equals(2, \count($values), '两条同名 TXT 应当共存');

$gdAuth = (string) $gdTransport->getLastRequest()->getHeader('Authorization');
$t->equals('sso-key key:secret', $gdAuth, 'GoDaddy 的鉴权格式');

$t->group('GoDaddy 删除时只去掉指定的那条');

$godaddy->removeTxtRecord('_acme-challenge.example.com', 'new-value');

$remaining = [];
foreach ($gdRecords as $record) {
    $remaining[] = $record['data'];
}

$t->equals(['existing-value'], $remaining, '只该删掉指定的值，别人的记录要留着');

// ---------------------------------------------------------------- Route53（XML + SigV4）

$t->group('Route 53 的 SigV4 与 XML');

$r53Transport = new MockTransport();
$r53Transport->on(
    static function (Request $request): bool {
        return str_contains($request->getUrl(), 'hostedzonesbyname');
    },
    new Response(200, ['Content-Type' => 'text/xml'], '<?xml version="1.0"?><ListHostedZonesByNameResponse>'
        . '<HostedZones><HostedZone><Id>/hostedzone/Z123ABC</Id><Name>example.com.</Name></HostedZone></HostedZones>'
        . '</ListHostedZonesByNameResponse>')
);
$r53Transport->on(
    static function (Request $request): bool {
        return str_contains($request->getUrl(), '/rrset?');
    },
    new Response(200, ['Content-Type' => 'text/xml'], '<?xml version="1.0"?><ListResourceRecordSetsResponse>'
        . '<ResourceRecordSets></ResourceRecordSets></ListResourceRecordSetsResponse>')
);
$r53Transport->on(
    static function (Request $request): bool {
        return $request->getMethod() === 'POST';
    },
    new Response(200, ['Content-Type' => 'text/xml'], '<?xml version="1.0"?><ChangeResourceRecordSetsResponse/>')
);

$route53 = new Route53(
    ['AWS_ACCESS_KEY_ID' => 'AKIATEST', 'AWS_SECRET_ACCESS_KEY' => 'secret'],
    mockClient($r53Transport)
);
$route53->addTxtRecord('_acme-challenge.example.com', 'r53-value');

$r53Request = $r53Transport->getLastRequest();
$r53Auth = (string) $r53Request->getHeader('Authorization');

$t->contains('AWS4-HMAC-SHA256', $r53Auth, '用 SigV4 签名');
// Route53 是全局服务，签名区域恒为 us-east-1，签成别的会 SignatureDoesNotMatch
$t->contains('/us-east-1/route53/aws4_request', $r53Auth, '区域必须是 us-east-1');
$t->contains('Credential=AKIATEST/', $r53Auth, 'Credential 里带 access key');

$body = (string) $r53Request->getBody();
$t->contains('<Action>UPSERT</Action>', $body, '加记录用 UPSERT');
$t->contains('Z123ABC', $r53Request->getUrl(), '应当用查到的 hosted zone id');
// Route53 的 TXT 值在 XML 里必须带引号
$t->contains('&quot;r53-value&quot;', $body, 'TXT 值要用引号包起来');

// ---------------------------------------------------------------- 工厂

$t->group('ProviderFactory');

$factory = new ProviderFactory(mockClient(new MockTransport()));

$t->equals('dns_cf', ProviderFactory::normalizeName('cf'), '短名补前缀');
$t->equals('dns_cf', ProviderFactory::normalizeName('DNS_CF'), '不分大小写');
$t->equals('dns_cf', ProviderFactory::normalizeName('Cloudflare'), '按展示名匹配');
$t->equals('dns_manual', ProviderFactory::normalizeName('manual'), '手动模式');

$t->throws(static function (): void {
    ProviderFactory::normalizeName('dns_nonexistent');
}, ConfigException::class, '未知提供商应当报错并列出可用值');

$provider = $factory->create('dns_cf', ['CF_Token' => 'x']);
$t->equals('Cloudflare', $provider->getName(), '显式传入的凭据应当被采纳');

$t->throws(static function () use ($factory): void {
    $factory->create('dns_vultr');
}, ConfigException::class, '缺凭据时应当在创建阶段就报错');

$t->ok(\count(ProviderFactory::supportedProviders()) >= 16, '应当支持至少 16 家提供商');
$t->equals(['CF_Token', 'CF_Key', 'CF_Email', 'CF_Account_ID'], ProviderFactory::credentialKeys('dns_cf'), '凭据键列表');

$t->group('凭据来源优先级');

// 环境变量应当被显式传入的值覆盖
putenv('CF_Token=from-env');
$fromEnv = $factory->create('dns_cf');
$t->equals('Cloudflare', $fromEnv->getName(), '环境变量里的凭据应当能被读到');

$storeFactory = new ProviderFactory(mockClient(new MockTransport()), null, ['VULTR_API_KEY' => 'from-store']);
$t->noThrow(static function () use ($storeFactory): void {
    $storeFactory->create('dns_vultr');
}, '配置文件里的凭据也应当能用（续期时不用重新 export）');

putenv('CF_Token');

exit($t->summary());
