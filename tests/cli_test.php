<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use PhpAcme\Cli\Application;
use PhpAcme\Cli\ArgvParser;
use PhpAcme\Tests\Runner;

$t = new Runner('命令行');

$t->group('参数解析：多值选项');

// getopt() 不支持重复选项，而 -d a.com -d b.com 恰恰是最常用的写法，
// 这是自己写解析器的主要原因
$args = new ArgvParser(['issue', '-d', 'a.com', '-d', 'b.com', '-w', '/var/www']);

$t->equals('issue', $args->getCommand(), '子命令');
$t->equals(['a.com', 'b.com'], $args->getAll('domain'), '重复的 -d 应当全部收集');
$t->equals('/var/www', $args->get('webroot'), '-w 是 --webroot 的别名');

$t->group('参数解析：逗号分隔');

$comma = new ArgvParser(['-d', 'a.com,b.com,c.com']);
$t->equals(['a.com', 'b.com', 'c.com'], $comma->getAll('domain'), '逗号分隔的域名应当拆开');

$t->group('参数解析：等号形式与布尔开关');

$mixed = new ArgvParser(['issue', '--ca=zerossl', '--force', '--days', '45', '--debug']);

$t->equals('zerossl', $mixed->get('ca'), '--key=value 形式');
$t->ok($mixed->getFlag('force'), '布尔开关');
$t->equals(45, $mixed->getInt('days', 30), '数值选项');
$t->ok($mixed->getFlag('debug'), '末尾的布尔开关');
$t->equals(30, $mixed->getInt('missing', 30), '没给的选项用默认值');

$t->group('参数解析：acme.sh 的别名');

$acmeSh = new ArgvParser(['--issue', '-d', 'x.com', '--server', 'letsencrypt_test', '--accountemail', 'a@b.com', '--dnssleep', '60']);

$t->ok($acmeSh->getFlag('issue'), 'acme.sh 风格的 --issue');
$t->equals('letsencrypt_test', $acmeSh->get('ca'), '--server 是 --ca 的别名');
$t->equals('a@b.com', $acmeSh->get('email'), '--accountemail 是 --email 的别名');
$t->equals(60, $acmeSh->getInt('dns-sleep', 0), '--dnssleep 映射到 --dns-sleep');

$t->group('参数解析：下划线与短横线等价');

$underscore = new ArgvParser(['--preferred_chain', 'ISRG Root X1', '--eab_kid', 'k1']);
$t->equals('ISRG Root X1', $underscore->get('preferred-chain'), '下划线写法应当被认');
$t->equals('k1', $underscore->get('eab-kid'), 'eab_kid 也一样');

$t->group('参数解析：-- 之后全是位置参数');

$separated = new ArgvParser(['show-cert', '--', '--这是文件名.pem']);
$t->equals(['show-cert', '--这是文件名.pem'], $separated->getArguments(), '-- 之后不再解析成选项');

$t->group('必填参数缺失');

$t->throws(static function (): void {
    (new ArgvParser([]))->requireOption('domain', '用 -d 指定');
}, \PhpAcme\Exception\ConfigException::class, '缺必填参数应当报错并给出提示');

// ---------------------------------------------------------------- 端到端跑 CLI

$t->group('CLI 进程');

$binary = __DIR__ . '/../bin/php-acme';
$home = test_temp_dir('cli');

/**
 * @return array{code: int, out: string}
 */
function runCli(string $binary, string $home, array $arguments): array
{
    // 用 proc_open 跑子进程是测试代码的做法；被测的库本身一行外部调用都没有，
    // 这一点由 no_exec_test.php 守着
    $command = escapeshellcmd(PHP_BINARY) . ' ' . escapeshellarg($binary);
    foreach ($arguments as $argument) {
        $command .= ' ' . escapeshellarg($argument);
    }
    $command .= ' --home ' . escapeshellarg($home) . ' 2>&1';

    $output = [];
    $code = 0;
    exec($command, $output, $code);

    return ['code' => $code, 'out' => implode("\n", $output)];
}

$version = runCli($binary, $home, ['--version']);
$t->equals(0, $version['code'], '--version 应当成功退出');
$t->contains('php-acme', $version['out'], '应当打印版本号');

$help = runCli($binary, $home, []);
$t->equals(Application::EXIT_USAGE, $help['code'], '不给命令时应当返回用法错误码（脚本可据此区分）');
$t->contains('用法：', $help['out'], '应当打印用法');
$t->contains('issue', $help['out'], '应当列出 issue 命令');

$helpExplicit = runCli($binary, $home, ['help']);
$t->equals(0, $helpExplicit['code'], '主动求助应当返回 0');

$helpIssue = runCli($binary, $home, ['help', 'issue']);
$t->contains('--dns', $helpIssue['out'], 'issue 的帮助里应当有验证方式说明');
$t->contains('通配符', $helpIssue['out'], '应当提到通配符的限制');

$listCa = runCli($binary, $home, ['list-ca']);
$t->equals(0, $listCa['code'], 'list-ca 应当成功');
$t->contains('letsencrypt', $listCa['out'], '应当列出 Let\'s Encrypt');
$t->contains('zerossl', $listCa['out'], '应当列出 ZeroSSL');

$listDns = runCli($binary, $home, ['list-dns']);
$t->contains('dns_cf', $listDns['out'], '应当列出 Cloudflare');
$t->contains('CF_Token', $listDns['out'], '应当说明需要哪个环境变量');

$emptyList = runCli($binary, $home, ['list']);
$t->equals(0, $emptyList['code'], '没有证书时 list 也该正常退出');
$t->contains('还没有任何证书', $emptyList['out'], '应当给出友好提示');

$t->group('CLI 的参数校验');

$noMethod = runCli($binary, $home, ['issue', '-d', 'example.com']);
$t->equals(1, $noMethod['code'], '没指定验证方式应当失败');
$t->contains('验证方式', $noMethod['out'], '报错里应当说清楚缺什么');

$twoMethods = runCli($binary, $home, ['issue', '-d', 'example.com', '-w', '/tmp', '--standalone']);
$t->equals(1, $twoMethods['code'], '同时给两种验证方式应当失败');
$t->contains('只能选一种', $twoMethods['out'], '应当说明互斥');

$noDomain = runCli($binary, $home, ['issue', '-w', '/tmp']);
$t->equals(1, $noDomain['code'], '没给域名应当失败');

$eabHalf = runCli($binary, $home, ['issue', '-d', 'x.com', '-w', '/tmp', '--eab-kid', 'k']);
$t->contains('必须同时提供', $eabHalf['out'], 'EAB 只给一半应当报错');

$badReason = runCli($binary, $home, ['revoke', '-d', 'x.com', '--reason', '99']);
$t->contains('原因码', $badReason['out'], '非法的吊销原因码应当报错');

$t->group('CLI 工具命令');

$createKey = runCli($binary, $home, ['create-key', '-k', 'ec-384']);
$t->equals(0, $createKey['code'], 'create-key 应当成功');
$t->contains('BEGIN PRIVATE KEY', $createKey['out'], '应当输出 PEM 私钥');

$csrPath = $home . '/test.csr';
$createCsr = runCli($binary, $home, ['create-csr', '-d', 'example.com', '-d', 'www.example.com', '-o', $csrPath]);
$t->equals(0, $createCsr['code'], 'create-csr 应当成功');
$t->ok(is_file($csrPath), 'CSR 文件应当生成');
$t->ok(is_file($home . '/test.key'), '自动生成的私钥也要写出来，否则 CSR 没用');

$showCsr = runCli($binary, $home, ['show-csr', $csrPath]);
$t->contains('example.com', $showCsr['out'], 'show-csr 应当解析出域名');
$t->contains('www.example.com', $showCsr['out'], 'SAN 里的域名都要列出来');

$t->group('cron 命令');

$cron = runCli($binary, $home, ['cron']);
$t->equals(0, $cron['code'], 'cron 应当成功');
$t->contains('renew-all', $cron['out'], '应当给出 renew-all 的 crontab 行');
$t->contains('环境检查', $cron['out'], '应当顺带检查环境');

$systemd = runCli($binary, $home, ['cron', '--systemd']);
$t->contains('[Timer]', $systemd['out'], '应当输出 systemd timer 配置');
$t->contains('RandomizedDelaySec', $systemd['out'], '应当带上随机延迟，避免所有人整点打 CA');

$t->group('未知命令');

$unknown = runCli($binary, $home, ['不存在的命令']);
$t->equals(Application::EXIT_USAGE, $unknown['code'], '未知命令应当返回用法错误码');

exit($t->summary());
