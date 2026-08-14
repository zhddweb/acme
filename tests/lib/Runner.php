<?php

declare(strict_types=1);

namespace PhpAcme\Tests;

/**
 * 极简测试运行器。
 *
 * 不用 PHPUnit 是有理由的：本库的卖点之一就是「在装不了 composer 的机器上
 * 也能用」，那么它的测试也该能在那种机器上跑起来——`php tests/xxx_test.php`
 * 就够了，不需要任何依赖。
 */
class Runner
{
    /** @var string */
    private $title;

    /** @var int */
    private $passed = 0;

    /** @var array<int, string> */
    private $failures = [];

    /** @var string 当前分组名 */
    private $group = '';

    public function __construct(string $title)
    {
        $this->title = $title;
        printf("== %s ==\n", $title);
    }

    public function group(string $name): void
    {
        $this->group = $name;
        printf("-- %s\n", $name);
    }

    public function ok(bool $condition, string $message): void
    {
        if ($condition) {
            ++$this->passed;

            return;
        }

        $this->fail($message);
    }

    /**
     * @param mixed $expected
     * @param mixed $actual
     */
    public function equals($expected, $actual, string $message): void
    {
        if ($expected === $actual) {
            ++$this->passed;

            return;
        }

        $this->fail(sprintf(
            "%s\n     期望：%s\n     实际：%s",
            $message,
            $this->describe($expected),
            $this->describe($actual)
        ));
    }

    /**
     * @param mixed $unexpected
     * @param mixed $actual
     */
    public function notEquals($unexpected, $actual, string $message): void
    {
        $this->ok($unexpected !== $actual, $message);
    }

    public function contains(string $needle, string $haystack, string $message): void
    {
        if (strpos($haystack, $needle) !== false) {
            ++$this->passed;

            return;
        }

        $this->fail(sprintf(
            "%s\n     期望包含：%s\n     实际内容：%s",
            $message,
            $needle,
            $this->truncate($haystack)
        ));
    }

    /**
     * 断言某段代码抛出指定异常。
     *
     * @param string $expectedClass 异常类名；给空串表示只要抛了就行
     */
    public function throws(callable $callback, string $expectedClass, string $message): void
    {
        try {
            $callback();
        } catch (\Throwable $e) {
            if ($expectedClass === '' || $e instanceof $expectedClass) {
                ++$this->passed;

                return;
            }

            $this->fail(sprintf(
                "%s\n     期望异常：%s\n     实际异常：%s（%s）",
                $message,
                $expectedClass,
                get_class($e),
                $e->getMessage()
            ));

            return;
        }

        $this->fail(sprintf('%s（没有抛出任何异常）', $message));
    }

    /** 断言某段代码**不**抛异常 */
    public function noThrow(callable $callback, string $message): void
    {
        try {
            $callback();
            ++$this->passed;
        } catch (\Throwable $e) {
            $this->fail(sprintf('%s（抛出了 %s：%s）', $message, get_class($e), $e->getMessage()));
        }
    }

    public function fail(string $message): void
    {
        $label = $this->group !== '' ? sprintf('[%s] %s', $this->group, $message) : $message;
        $this->failures[] = $label;
        printf("  ✗ %s\n", $label);
    }

    /** 返回进程退出码：全过是 0 */
    public function summary(): int
    {
        $total = $this->passed + \count($this->failures);

        if ($this->failures === []) {
            printf("  ✓ %d/%d 通过\n\n", $this->passed, $total);

            return 0;
        }

        printf("\n  %d/%d 通过，%d 个失败：\n", $this->passed, $total, \count($this->failures));
        foreach ($this->failures as $failure) {
            printf("    - %s\n", explode("\n", $failure)[0]);
        }
        printf("\n");

        return 1;
    }

    /**
     * @param mixed $value
     */
    private function describe($value): string
    {
        if (\is_string($value)) {
            return $this->truncate($value);
        }
        if (\is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return 'null';
        }
        if (\is_array($value)) {
            return $this->truncate(json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        }
        if (\is_object($value)) {
            return get_class($value);
        }

        return (string) $value;
    }

    private function truncate(string $value): string
    {
        // 二进制内容直接打出来会把终端搞乱，转成 hex
        if (preg_match('//u', $value) !== 1) {
            return '(binary) ' . substr(bin2hex($value), 0, 80);
        }

        return \strlen($value) > 200 ? substr($value, 0, 200) . '…' : $value;
    }
}
