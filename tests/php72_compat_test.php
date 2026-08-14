<?php

declare(strict_types=1);

/**
 * PHP 7.2 语法兼容性静态扫描。
 *
 * 为什么需要它：开发机与 CI 的多数 job 跑的是 PHP 8，`php -l` 用的是当前版本的
 * 解析器，**7.3+ 的语法在那里一路绿灯**，只有真跑在 7.2 上才会炸。
 * 不能靠「本地没报错」判断。
 *
 * 做法是先用 tokenizer 把注释与字符串**剔掉**（否则文档里写的
 * 「不要用 ??=」会把自己扫成违规），再跑文本规则与 token 结构规则。
 *
 * 新增一类禁用语法时，务必同时往 $rules 或 findTokenViolations() 里补规则，
 * **并在下面的自检样例里加一条正例**——没有正例的规则等于没写。
 */

require __DIR__ . '/lib/bootstrap.php';

use PhpAcme\Tests\Runner;

$t = new Runner('PHP 7.2 语法兼容性');

/**
 * 文本规则：在剔除了注释与字符串的代码上跑正则。
 *
 * @var array<int, array{pattern: string, message: string, since: string}>
 */
$rules = [
    [
        'pattern' => '/(?<![=!<>])\?\?=/',
        'message' => '?? = 复合赋值是 PHP 7.4 引入的，改写成 $a = $a ?? $b',
        'since' => '7.4',
    ],
    [
        'pattern' => '/\bfn\s*\(/',
        'message' => '箭头函数 fn() 是 PHP 7.4 引入的，改用 function () use () {}',
        'since' => '7.4',
    ],
    [
        'pattern' => '/\[\s*\.\.\./',
        'message' => '数组展开 [...$a] 是 PHP 7.4 引入的，改用 array_merge()',
        'since' => '7.4',
    ],
    [
        'pattern' => '/\b\d+_\d/',
        'message' => '数字分隔符 1_000 是 PHP 7.4 引入的，直接写 1000',
        'since' => '7.4',
    ],
    [
        'pattern' => '/\bmatch\s*\(/',
        'message' => 'match 表达式是 PHP 8.0 引入的，改用 switch 或 if/elseif',
        'since' => '8.0',
    ],
    [
        'pattern' => '/\?->/',
        'message' => 'nullsafe 调用 ?-> 是 PHP 8.0 引入的，改成显式的 null 判断',
        'since' => '8.0',
    ],
    [
        'pattern' => '/\bcatch\s*\(\s*\\\\?[A-Za-z_][A-Za-z0-9_\\\\]*(\s*\|\s*\\\\?[A-Za-z_][A-Za-z0-9_\\\\]*)*\s*\)/',
        'message' => '非捕获的 catch (\Throwable) 是 PHP 8.0 引入的，写成 catch (\Throwable $e)',
        'since' => '8.0',
    ],
    [
        'pattern' => '/::class\s*(?!\s*[;,\)\]])/',
        'message' => '$obj::class 是 PHP 8.0 引入的，改用 get_class($obj)',
        'since' => '8.0',
    ],
    [
        'pattern' => '/\benum\s+[A-Z]/',
        'message' => 'enum 是 PHP 8.1 引入的',
        'since' => '8.1',
    ],
    [
        'pattern' => '/\breadonly\s+/',
        'message' => 'readonly 属性是 PHP 8.1 引入的',
        'since' => '8.1',
    ],
    [
        'pattern' => '/\)\s*:\s*never\b/',
        'message' => 'never 返回类型是 PHP 8.1 引入的',
        'since' => '8.1',
    ],
    [
        'pattern' => '/\barray_is_list\s*\(/',
        'message' => 'array_is_list() 是 PHP 8.1 引入的',
        'since' => '8.1',
    ],
    [
        'pattern' => '/\bstr_contains\s*\(|\bstr_starts_with\s*\(|\bstr_ends_with\s*\(|\barray_key_first\s*\(|\barray_key_last\s*\(|\bis_countable\s*\(/',
        'message' => '这些函数需要 polyfill（src/polyfill.php 已提供，此规则只用于确认 polyfill 存在）',
        'since' => 'polyfill',
    ],
];

/**
 * 把注释与字符串换成等长空白，保留行号与列位置。
 */
function stripLiterals(string $code): string
{
    $tokens = token_get_all($code);
    $out = '';

    foreach ($tokens as $token) {
        if (\is_array($token)) {
            $text = $token[1];
            $id = $token[0];

            // 注释、文档注释、字符串内容、内联 HTML 一律抹掉，
            // 只保留换行以维持行号
            if (\in_array($id, [T_COMMENT, T_DOC_COMMENT, T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE, T_INLINE_HTML], true)) {
                $out .= preg_replace('/[^\n]/', ' ', $text);
                continue;
            }

            $out .= $text;
            continue;
        }

        $out .= $token;
    }

    return $out;
}

/**
 * token 结构规则：正则查不出来的那些。
 *
 * @return array<int, array{line: int, message: string}>
 */
function findTokenViolations(string $code): array
{
    $tokens = token_get_all($code);
    $violations = [];
    $count = \count($tokens);

    for ($i = 0; $i < $count; ++$i) {
        $token = $tokens[$i];

        if (!\is_array($token)) {
            continue;
        }

        // 类型化属性（7.4）：可见性关键字后面直接跟类型再跟变量
        if (\in_array($token[0], [T_PRIVATE, T_PROTECTED, T_PUBLIC], true)) {
            $j = $i + 1;
            $sawType = false;

            while ($j < $count) {
                $next = $tokens[$j];

                if (\is_array($next) && \in_array($next[0], [T_WHITESPACE, T_STATIC], true)) {
                    ++$j;
                    continue;
                }

                // function 说明是方法不是属性
                if (\is_array($next) && $next[0] === T_FUNCTION) {
                    break;
                }
                if (\is_array($next) && $next[0] === T_CONST) {
                    break;
                }

                // 类型名（含 ?、array、可空标记）
                if (\is_array($next) && \in_array($next[0], [T_STRING, T_ARRAY, T_NS_SEPARATOR], true)) {
                    $sawType = true;
                    ++$j;
                    continue;
                }
                if (!\is_array($next) && $next === '?') {
                    $sawType = true;
                    ++$j;
                    continue;
                }

                if (\is_array($next) && $next[0] === T_VARIABLE && $sawType) {
                    $violations[] = [
                        'line' => $next[2],
                        'message' => sprintf('类型化属性 %s 是 PHP 7.4 引入的，改用 /** @var T */ 注解', $next[1]),
                    ];
                }

                break;
            }
        }

        // 构造器属性提升（8.0）：function __construct 的参数列表里出现可见性关键字
        if ($token[0] === T_FUNCTION) {
            $j = $i + 1;
            while ($j < $count && \is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                ++$j;
            }

            if ($j < $count && \is_array($tokens[$j]) && strtolower($tokens[$j][1]) === '__construct') {
                $depth = 0;
                for ($k = $j; $k < $count; ++$k) {
                    $inner = $tokens[$k];

                    if (!\is_array($inner)) {
                        if ($inner === '(') {
                            ++$depth;
                        } elseif ($inner === ')') {
                            --$depth;
                            if ($depth === 0) {
                                break;
                            }
                        }
                        continue;
                    }

                    if ($depth > 0 && \in_array($inner[0], [T_PRIVATE, T_PROTECTED, T_PUBLIC], true)) {
                        $violations[] = [
                            'line' => $inner[2],
                            'message' => '构造器属性提升是 PHP 8.0 引入的，改成独立属性声明 + 构造器内赋值',
                        ];
                    }
                }
            }
        }
    }

    return $violations;
}

/**
 * 扫一个文件。
 *
 * @param array<int, array{pattern: string, message: string, since: string}> $rules
 * @return array<int, string>
 */
function scanFile(string $path, array $rules): array
{
    $code = file_get_contents($path);
    if ($code === false) {
        return [sprintf('%s 读不到', $path)];
    }

    $stripped = stripLiterals($code);
    $lines = preg_split('/\r\n|\r|\n/', $stripped);
    $issues = [];

    foreach ($rules as $rule) {
        // polyfill 那条只是登记，不作为违规
        if ($rule['since'] === 'polyfill') {
            continue;
        }

        foreach ($lines as $index => $line) {
            if (preg_match($rule['pattern'], $line) === 1) {
                $issues[] = sprintf('%s:%d %s', $path, $index + 1, $rule['message']);
            }
        }
    }

    foreach (findTokenViolations($code) as $violation) {
        $issues[] = sprintf('%s:%d %s', $path, $violation['line'], $violation['message']);
    }

    return $issues;
}

// ---------------------------------------------------------------- 规则自检

$t->group('规则自检：违规样例必须被抓到');

$badSamples = [
    '$a ??= $b;' => '?? =',
    '$f = fn ($x) => $x;' => '箭头函数',
    '$c = [...$a, ...$b];' => '数组展开',
    '$n = 1_000_000;' => '数字分隔符',
    '$r = match ($x) { 1 => "a" };' => 'match',
    '$v = $obj?->method();' => 'nullsafe',
    'try { x(); } catch (\Throwable) { }' => '非捕获 catch',
    'enum Suit { case A; }' => 'enum',
    'class A { public readonly int $x; }' => 'readonly',
    'function f(): never { }' => 'never 返回类型',
    'if (array_is_list($a)) { }' => 'array_is_list',
];

foreach ($badSamples as $sample => $label) {
    $path = tempnam(sys_get_temp_dir(), 'compat');
    file_put_contents($path, "<?php\n" . $sample . "\n");

    $issues = scanFile($path, $rules);
    $t->ok($issues !== [], sprintf('应当抓到「%s」', $label));

    @unlink($path);
}

$t->group('规则自检：token 规则');

$tokenSamples = [
    "class A { private string \$x; }" => '类型化属性',
    "class A { public function __construct(private int \$x) {} }" => '构造器属性提升',
];

foreach ($tokenSamples as $sample => $label) {
    $path = tempnam(sys_get_temp_dir(), 'compat');
    file_put_contents($path, "<?php\n" . $sample . "\n");

    $t->ok(scanFile($path, $rules) !== [], sprintf('应当抓到「%s」', $label));

    @unlink($path);
}

$t->group('反向自检：合法写法不能误报');

$goodSamples = [
    '$a = $a ?? $b;',
    '$f = function ($x) use ($y) { return $x + $y; };',
    '$c = array_merge($a, $b);',
    '$n = 1000000;',
    'switch ($x) { case 1: return "a"; }',
    '$v = $obj !== null ? $obj->method() : null;',
    'try { x(); } catch (\Throwable $e) { }',
    'class A { /** @var string */ private $x; }',
    'class A { public function __construct(int $x) { $this->x = $x; } }',
    '$name = MyClass::class;',
    '$list = [MyClass::class, Other::class];',
    'function f(): void { }',
    '$x = $a <=> $b;',
    '// 注释里写 ??= 和 fn () => 不该被误报',
    '$s = "字符串里写 match ($x) 也不该被误报";',
    'class A { private $items = []; public function f(): ?string { return null; } }',
];

foreach ($goodSamples as $index => $sample) {
    $path = tempnam(sys_get_temp_dir(), 'compat');
    file_put_contents($path, "<?php\n" . $sample . "\n");

    $issues = scanFile($path, $rules);
    $t->ok($issues === [], sprintf('合法写法 #%d 不该报违规：%s', $index, $issues === [] ? '' : $issues[0]));

    @unlink($path);
}

// ---------------------------------------------------------------- 扫描全库

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
    foreach (scanFile($file, $rules) as $issue) {
        $allIssues[] = $issue;
    }
}

$t->ok(\count($files) > 60, sprintf('应当扫到足够多的文件（实际 %d 个）', \count($files)));

if ($allIssues === []) {
    $t->ok(true, sprintf('%d 个文件全部符合 PHP 7.2 语法', \count($files)));
} else {
    foreach ($allIssues as $issue) {
        $t->fail($issue);
    }
}

$t->group('最低版本声明一致');

$composer = json_decode((string) file_get_contents(__DIR__ . '/../composer.json'), true);
$t->equals('>=7.2', $composer['require']['php'], 'composer.json 里的 PHP 版本要求');

$binary = (string) file_get_contents(__DIR__ . '/../bin/php-acme');
$t->contains("'7.2.0'", $binary, 'CLI 入口的版本检查应当与 composer.json 一致');

exit($t->summary());
