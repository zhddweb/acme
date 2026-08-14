<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Crypto\SelfSignedCertificate;
use Mci\Acme\Deploy\Hook\InstallFilesHook;
use Mci\Acme\Deploy\Hook\Pkcs12Hook;
use Mci\Acme\Deploy\Hook\ReloadSignalHook;
use Mci\Acme\Deploy\Hook\TouchFileHook;
use Mci\Acme\Deploy\Hook\WebhookDeployHook;
use Mci\Acme\Exception\DeployException;
use Mci\Acme\Http\HttpClient;
use Mci\Acme\Http\Response;
use Mci\Acme\Http\Transport\MockTransport;
use Mci\Acme\Notify\Hook\DingTalkNotifier;
use Mci\Acme\Notify\Hook\TelegramNotifier;
use Mci\Acme\Notify\Hook\WebhookNotifier;
use Mci\Acme\Notify\NotifierChain;
use Mci\Acme\Notify\NotifierInterface;
use Mci\Acme\Service\IssueResult;
use Mci\Acme\Tests\Runner;
use Mci\Acme\Util\Json;

$t = new Runner('部署与通知');

$base = test_temp_dir('deploy');
$keyPair = KeyPair::generate('ec-256');
$certificatePem = SelfSignedCertificate::forPlaceholder($keyPair, ['example.com']);

// 造一套「已经签发好」的文件
$sourceDir = $base . '/source';
mkdir($sourceDir, 0700, true);
file_put_contents($sourceDir . '/example.com.key', $keyPair->getPrivateKeyPem());
file_put_contents($sourceDir . '/example.com.cer', $certificatePem);
file_put_contents($sourceDir . '/ca.cer', SelfSignedCertificate::forPlaceholder(KeyPair::generate('2048'), ['ca.test']));
file_put_contents($sourceDir . '/fullchain.cer', $certificatePem);

$result = new IssueResult(
    true,
    false,
    'example.com',
    ['example.com'],
    \Mci\Acme\Crypto\Certificate::fromPem($certificatePem),
    [
        'key' => $sourceDir . '/example.com.key',
        'cert' => $sourceDir . '/example.com.cer',
        'ca' => $sourceDir . '/ca.cer',
        'fullchain' => $sourceDir . '/fullchain.cer',
    ],
    '测试'
);

$t->group('安装文件');

$target = $base . '/target';

$hook = new InstallFilesHook([
    'key' => $target . '/site.key',
    'fullchain' => $target . '/site.crt',
]);
$hook->deploy($result);

$t->ok(is_file($target . '/site.key'), '私钥应当被安装');
$t->ok(is_file($target . '/site.crt'), '完整链应当被安装');
$t->equals(file_get_contents($sourceDir . '/example.com.key'), file_get_contents($target . '/site.key'), '内容一致');
// 私钥要让服务用户读得到（0640），但证书可以 0644
$t->equals('0640', substr(sprintf('%o', fileperms($target . '/site.key')), -4), '私钥默认 0640');
$t->equals('0644', substr(sprintf('%o', fileperms($target . '/site.crt')), -4), '证书 0644');

$hook->setKeyMode(0600);
$hook->deploy($result);
$t->equals('0600', substr(sprintf('%o', fileperms($target . '/site.key')), -4), '权限应当可调');

$t->group('安装时的错误');

$t->throws(static function () use ($result): void {
    (new InstallFilesHook(['不存在的类型' => '/tmp/x']))->deploy($result);
}, DeployException::class, '不认识的文件类型应当报错');

$t->group('PKCS#12 导出');

$pfxPath = $base . '/site.pfx';
(new Pkcs12Hook($pfxPath, 'test-password', 'example.com'))->deploy($result);

$t->ok(is_file($pfxPath), 'pfx 文件应当生成');
$t->equals('0600', substr(sprintf('%o', fileperms($pfxPath)), -4), 'pfx 里有私钥，权限必须收紧');

// 用 openssl 读回来，验证格式确实正确
$parsed = [];
$ok = openssl_pkcs12_read(file_get_contents($pfxPath), $parsed, 'test-password');
$t->ok($ok, 'openssl 应当能用给定口令读回这个 pfx');
$t->ok(isset($parsed['cert'], $parsed['pkey']), 'pfx 里应当同时有证书与私钥');
$t->ok(isset($parsed['extracerts']) && \count($parsed['extracerts']) > 0, '中间证书也要打进去，否则客户端会报链不完整');

$t->ok(!openssl_pkcs12_read(file_get_contents($pfxPath), $parsed, '错误口令'), '错误口令应当读不出来');

$t->group('触发文件');

$touchPath = $base . '/renewed.json';
(new TouchFileHook($touchPath))->deploy($result);

$t->ok(is_file($touchPath), '标记文件应当生成');

$payload = Json::decode(file_get_contents($touchPath));
$t->equals('example.com', $payload['domain'], '内容里应当有域名');
$t->ok(isset($payload['paths']['fullchain']), '应当带上各文件路径，供外部脚本使用');
$t->equals('0644', substr(sprintf('%o', fileperms($touchPath)), -4), '监听方通常是别的用户，权限要 0644');

$t->group('重载信号');

$pidFile = $base . '/fake.pid';
// 用当前进程的 pid，这样进程一定存在；信号用 0（只做存在性检查，不真的送出去）
file_put_contents($pidFile, (string) getmypid());

$t->noThrow(static function () use ($pidFile, $result): void {
    (new ReloadSignalHook($pidFile, 0, '测试服务'))->deploy($result);
}, '给存在的进程发信号应当成功');

$t->throws(static function () use ($base, $result): void {
    (new ReloadSignalHook($base . '/missing.pid', 0, '测试服务'))->deploy($result);
}, DeployException::class, 'pid 文件不存在时应当报错并说明可能的原因');

file_put_contents($base . '/stale.pid', '999999');
$t->throws(static function () use ($base, $result): void {
    (new ReloadSignalHook($base . '/stale.pid', 0, '测试服务'))->deploy($result);
}, DeployException::class, '进程不存在时应当报错——过期的 pid 文件很常见');

$t->group('预设服务的信号编号');

$t->equals(1, ReloadSignalHook::PRESETS['nginx']['signal'], 'nginx 用 SIGHUP(1)');
$t->equals(10, ReloadSignalHook::PRESETS['apache']['signal'], 'Apache 用 SIGUSR1(10)');
$t->equals(12, ReloadSignalHook::PRESETS['haproxy']['signal'], 'HAProxy 用 SIGUSR2(12)');

$t->throws(static function (): void {
    ReloadSignalHook::forService('不认识的服务');
}, DeployException::class, '未知服务名应当报错并列出已知的');

$t->group('Webhook 部署');

$transport = new MockTransport();
$transport->setFallback(static function (): Response {
    return new Response(200, [], 'ok');
});

$webhook = new WebhookDeployHook('https://deploy.test/hook', ['Authorization' => 'Bearer x'], new HttpClient($transport));
$webhook->deploy($result);

$request = $transport->getLastRequest();
$body = Json::decode((string) $request->getBody());

$t->equals('Bearer x', $request->getHeader('Authorization'), '自定义头应当带上');
$t->contains('BEGIN CERTIFICATE', (string) $body['fullchain'], '应当带上完整链');
// 私钥经网络传输是有风险的，必须显式打开
$t->ok(!isset($body['key']), '默认不该发送私钥');

$webhook->setIncludeKey(true);
$webhook->deploy($result);
$bodyWithKey = Json::decode((string) $transport->getLastRequest()->getBody());
$t->contains('PRIVATE KEY', (string) $bodyWithKey['key'], '显式打开后才发私钥');

$t->group('Webhook：拒绝把私钥发到明文 HTTP');

$plainWebhook = new WebhookDeployHook('http://insecure.test/hook', [], new HttpClient($transport));
$plainWebhook->setIncludeKey(true);

$t->throws(static function () use ($plainWebhook, $result): void {
    $plainWebhook->deploy($result);
}, DeployException::class, '私钥不能明文发到 http:// 地址');

$t->group('Webhook：对端报错要抛出来');

$errorTransport = new MockTransport();
$errorTransport->setFallback(static function (): Response {
    return new Response(500, [], 'internal error');
});

$t->throws(static function () use ($errorTransport, $result): void {
    (new WebhookDeployHook('https://deploy.test/hook', [], new HttpClient($errorTransport)))->deploy($result);
}, DeployException::class, '对端 5xx 应当报错');

// ---------------------------------------------------------------- 通知

$t->group('Webhook 通知');

$notifyTransport = new MockTransport();
$notifyTransport->setFallback(static function (): Response {
    return new Response(200, [], 'ok');
});

$notifier = new WebhookNotifier('https://notify.test/hook', [], new HttpClient($notifyTransport));
$t->ok($notifier->send('证书已续期', 'example.com 续期成功', true), '发送应当成功');

$notifyBody = Json::decode((string) $notifyTransport->getLastRequest()->getBody());
$t->equals('证书已续期', $notifyBody['subject'], '标题');
$t->equals(true, $notifyBody['success'], '成功标记');

$t->group('通知失败不能抛异常');

$failTransport = new MockTransport();
$failTransport->setFallback(static function (): Response {
    throw new \Mci\Acme\Exception\HttpException('网络不通');
});

$failNotifier = new WebhookNotifier('https://notify.test/hook', [], new HttpClient($failTransport));

$t->noThrow(static function () use ($failNotifier): void {
    $failNotifier->send('x', 'y');
}, '通知渠道挂了不该让续期算作失败');
$t->ok(!$failNotifier->send('x', 'y'), '失败时返回 false');

$t->group('钉钉的加签');

$dingTransport = new MockTransport();
$dingTransport->setFallback(static function (): Response {
    return new Response(200, ['Content-Type' => 'application/json'], Json::encode(['errcode' => 0]));
});

$ding = new DingTalkNotifier('https://oapi.dingtalk.com/robot/send?access_token=t', 'SEC-secret', new HttpClient($dingTransport));
$ding->send('证书续期', '正文');

$dingUrl = $dingTransport->getLastRequest()->getUrl();
$t->contains('timestamp=', $dingUrl, '加签模式要带时间戳');
$t->contains('sign=', $dingUrl, '加签模式要带签名');
$t->contains('access_token=t', $dingUrl, '原有的查询参数要保留');

$t->group('钉钉的业务错误');

$dingFailTransport = new MockTransport();
$dingFailTransport->setFallback(static function (): Response {
    return new Response(200, ['Content-Type' => 'application/json'], Json::encode([
        'errcode' => 310000,
        'errmsg' => 'keywords not in content',
    ]));
});

$dingFail = new DingTalkNotifier('https://oapi.dingtalk.com/robot/send', null, new HttpClient($dingFailTransport));
$t->ok(!$dingFail->send('x', 'y'), 'HTTP 200 但 errcode 非 0 应当算失败');

$t->group('Telegram');

$tgTransport = new MockTransport();
$tgTransport->setFallback(static function (): Response {
    return new Response(200, ['Content-Type' => 'application/json'], Json::encode(['ok' => true]));
});

$telegram = new TelegramNotifier('123:ABC', '456', new HttpClient($tgTransport));
$telegram->send('标题', '正文', false);

$tgRequest = $tgTransport->getLastRequest();
$t->contains('/bot123:ABC/sendMessage', $tgRequest->getUrl(), 'URL 里带 bot token');

$tgBody = Json::decode((string) $tgRequest->getBody());
$t->equals('456', (string) $tgBody['chat_id'], 'chat id');
$t->contains('❌', (string) $tgBody['text'], '失败时应当用醒目的标记');
// 证书信息里常有下划线和星号，开了 Markdown 解析会导致整条消息发不出去
$t->ok(!isset($tgBody['parse_mode']), '不该开 Markdown 解析模式');

$t->group('通知链');

/** 记录调用的假通知渠道 */
final class RecordingNotifier implements NotifierInterface
{
    /** @var bool */
    private $result;

    /** @var int */
    public $calls = 0;

    public function __construct(bool $result)
    {
        $this->result = $result;
    }

    public function getName(): string
    {
        return '测试渠道';
    }

    public function send(string $subject, string $body, bool $success = true): bool
    {
        ++$this->calls;

        return $this->result;
    }
}

$good = new RecordingNotifier(true);
$bad = new RecordingNotifier(false);

$chain = new NotifierChain([$bad, $good]);
$t->ok($chain->send('x', 'y'), '只要有一个渠道成功就算成功');
$t->equals(1, $bad->calls, '失败的渠道也要被调用过');
$t->equals(1, $good->calls, '后面的渠道不能因为前面失败就被跳过');

$t->ok((new NotifierChain())->isEmpty(), '空链应当能识别');

exit($t->summary());
