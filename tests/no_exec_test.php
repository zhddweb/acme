<?php

declare(strict_types=1);

/**
 * 「不执行任何外部进程」的静态扫描。
 *
 * 这是本库最核心的一条设计约束：目标环境是禁用了 exec/proc_open 的
 * 共享主机与受管控服务器。一旦源码里混进一个 shell 调用，
 * 整个库在那些机器上就直接不可用了——而且往往要等到用户报障才发现。
 *
 * acme.sh 靠 openssl 命令行、curl、crontab 干活，本库把这些全换成了
 * PHP 自己的能力（ext-openssl、curl 扩展或 stream、以及打印 crontab 配置
 * 让用户自己贴）。这个测试就是守着这条线不被越过。
 *
 * 注意扫描范围只有 src/ 与 bin/：tests/ 里可以用 exec 去跑 CLI 子进程，
 * 那是测试代码，不随库分发。
 */

require __DIR__ . '/lib/bootstrap.php';

use PhpAcme\Tests\Runner;

$t = new Runner('禁止外部进程调用');

/**
 * 禁用的函数。
 *
 * @var array<string, string>
 */
$forbidden = [
    'exec' => '执行外部命令',
    'shell_exec' => '执行外部命令',
    'system' => '执行外部命令',
    'passthru' => '执行外部命令',
    'proc_open' => '开子进程',
    'popen' => '开子进程',
    'pcntl_exec' => '替换进程映像',
    'pcntl_fork' => 'fork 子进程（目标环境多半禁用了 pcntl，且孤儿进程难收拾）',
    'eval' => '执行动态代码（不是外部进程，但同样属于该避免的动态执行）',
    'create_function' => '动态创建函数（7.2 起废弃）',
    'assert' => '在旧版本里会执行字符串',
];

/**
 * 扫一个文件。
 *
 * 先用 tokenizer 剔掉注释与字符串——否则本文件自己的说明文字、
 * 以及报错信息里出现的「proc_open」都会被扫成违规。
 *
 * @param array<string, string> $forbidden
 * @return array<int, string>
 */
function scanForExec(string $path, array $forbidden): array
{
    $code = file_get_contents($path);
    if ($code === false) {
        return [sprintf('%s 读不到', $path)];
    }

    $tokens = token_get_all($code);
    $issues = [];
    $count = \count($tokens);

    for ($i = 0; $i < $count; ++$i) {
        $token = $tokens[$i];

        // 反引号执行：`ls -l` 这种写法
        if (!\is_array($token) && $token === '`') {
            $issues[] = sprintf('%s 里出现了反引号执行操作符', $path);
            continue;
        }

        if (!\is_array($token)) {
            continue;
        }

        // 只看函数名 token；注释与字符串里的同名文字不算
        if ($token[0] !== T_STRING && $token[0] !== T_EVAL) {
            continue;
        }

        $name = strtolower($token[1]);
        if ($token[0] === T_EVAL) {
            $name = 'eval';
        }

        if (!isset($forbidden[$name])) {
            continue;
        }

        // 必须是「函数调用」的形态：后面跟着左括号。
        // 这样 'exec' => '...' 这种数组键、或者 $this->system 这类属性不会被误判
        $j = $i + 1;
        while ($j < $count && \is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
            ++$j;
        }

        if ($j >= $count || \is_array($tokens[$j]) || $tokens[$j] !== '(') {
            continue;
        }

        // 前面是 -> 或 :: 的话，那是方法调用不是全局函数
        $k = $i - 1;
        while ($k >= 0 && \is_array($tokens[$k]) && $tokens[$k][0] === T_WHITESPACE) {
            --$k;
        }

        if ($k >= 0 && \is_array($tokens[$k])
            && \in_array($tokens[$k][0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION], true)) {
            continue;
        }

        $issues[] = sprintf('%s:%d 调用了 %s()（%s）', $path, $token[2], $name, $forbidden[$name]);
    }

    return $issues;
}

$t->group('规则自检');

$badSamples = [
    '<?php exec("ls");' => 'exec',
    '<?php $x = shell_exec("ls");' => 'shell_exec',
    '<?php system("ls");' => 'system',
    '<?php $h = proc_open("ls", [], $p);' => 'proc_open',
    '<?php $h = popen("ls", "r");' => 'popen',
    '<?php $out = `ls -l`;' => '反引号',
    '<?php eval("1+1");' => 'eval',
];

foreach ($badSamples as $sample => $label) {
    $path = tempnam(sys_get_temp_dir(), 'noexec');
    file_put_contents($path, $sample . "\n");

    $t->ok(scanForExec($path, $forbidden) !== [], sprintf('应当抓到 %s', $label));

    @unlink($path);
}

$t->group('反向自检：不该误报');

$goodSamples = [
    // 数组键、字符串、注释里出现这些词都是合法的
    '<?php $map = ["exec" => "不允许", "system" => "也不允许"];',
    '<?php // 本库不使用 exec() 与 proc_open()',
    '<?php throw new Exception("当前环境禁用了 proc_open，请改用其他方式");',
    '<?php $this->system("x");',
    '<?php Helper::exec("x");',
    '<?php /** 说明：不调用 shell_exec() */ function f() {}',
    '<?php class A { public function exec() {} }',
];

foreach ($goodSamples as $index => $sample) {
    $path = tempnam(sys_get_temp_dir(), 'noexec');
    file_put_contents($path, $sample . "\n");

    $issues = scanForExec($path, $forbidden);
    $t->ok($issues === [], sprintf('合法写法 #%d 不该误报：%s', $index, $issues === [] ? '' : $issues[0]));

    @unlink($path);
}

$t->group('扫描 src/ 与 bin/');

$files = [];

$directory = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator(__DIR__ . '/../src', RecursiveDirectoryIterator::SKIP_DOTS)
);

foreach ($directory as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
        $files[] = $file->getPathname();
    }
}

$files[] = __DIR__ . '/../bootstrap.php';
$files[] = __DIR__ . '/../bin/php-acme';

sort($files, SORT_STRING);

$allIssues = [];
foreach ($files as $file) {
    foreach (scanForExec($file, $forbidden) as $issue) {
        $allIssues[] = $issue;
    }
}

if ($allIssues === []) {
    $t->ok(true, sprintf('%d 个文件里一处外部进程调用都没有', \count($files)));
} else {
    foreach ($allIssues as $issue) {
        $t->fail($issue);
    }
}

$t->group('替代方案确实存在');

// 光「没有 exec」不够，还得确认该有的能力是用别的方式实现的，
// 否则可能只是功能缺失
$sourceOf = static function (string $relative): string {
    return (string) file_get_contents(__DIR__ . '/../src/' . $relative);
};

$t->contains('openssl_pkey_new', $sourceOf('Crypto/KeyPair.php'), '密钥生成用 openssl 扩展而不是 openssl 命令');
$t->contains('openssl_sign', $sourceOf('Crypto/KeyPair.php'), '签名用 openssl 扩展');
$t->contains('openssl_x509_parse', $sourceOf('Crypto/Certificate.php'), '证书解析用 openssl 扩展');
$t->contains('curl_init', $sourceOf('Http/Transport/CurlTransport.php'), 'HTTP 用 curl 扩展');
$t->contains('fopen', $sourceOf('Http/Transport/StreamTransport.php'), '没有 curl 时退回 stream');
$t->contains('posix_kill', $sourceOf('Deploy/Hook/ReloadSignalHook.php'), '服务重载用信号而不是 systemctl 命令');
$t->contains('stream_socket_server', $sourceOf('Challenge/Http01/StandaloneSolver.php'), 'standalone 用 PHP 自己的 socket');
$t->contains('Der::sequence', $sourceOf('Crypto/Csr.php'), 'CSR 自己拼 DER，不依赖 openssl.cnf');

exit($t->summary());
