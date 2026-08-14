<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01;

use PhpAcme\Util\DnsResolver;
use PhpAcme\Util\Logger;

/**
 * 等 TXT 记录传播开。
 *
 * dns-01 最常见的失败就是**记录加上了但还没生效就通知了 CA**。
 * CA 查不到就判 invalid，而这次失败会计入该域名的失败次数
 * （Let's Encrypt 每域名每小时 5 次验证失败就会被限流），
 * 所以宁可在这里多等一会儿，也不要贸然去敲 CA 的门。
 *
 * 检测直接问域名的权威 NS，绕开所有缓存——本地解析器的负缓存
 * 会让「其实已经生效」的记录看起来还没生效。
 */
class DnsVerifier
{
    /** @var DnsResolver */
    private $resolver;

    /** @var Logger */
    private $logger;

    /** @var callable|null 等待函数，测试里换掉免得真 sleep */
    private $sleeper;

    public function __construct(?DnsResolver $resolver = null, ?Logger $logger = null)
    {
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->resolver = $resolver !== null ? $resolver : new DnsResolver(null, $this->logger);
    }

    public function setSleeper(?callable $sleeper): void
    {
        $this->sleeper = $sleeper;
    }

    /**
     * 轮询直到查到目标值，或超时。
     *
     * @param int $timeout 最多等几秒
     * @param int $interval 每次查询间隔
     * @return bool 是否等到了
     */
    public function waitForTxt(string $fqdn, string $expected, int $timeout = 120, int $interval = 10): bool
    {
        $deadline = time() + $timeout;
        $attempt = 0;

        while (true) {
            ++$attempt;

            if ($this->hasTxt($fqdn, $expected)) {
                $this->logger->info(sprintf('%s 的 TXT 记录已生效（第 %d 次查询）', $fqdn, $attempt));

                return true;
            }

            if (time() >= $deadline) {
                $this->logger->warning(sprintf(
                    '等待 %s 的 TXT 记录生效超时（%d 秒）。'
                    . '记录可能确实还没传播开，也可能是解析商的 TTL 设得太长',
                    $fqdn,
                    $timeout
                ));

                return false;
            }

            $this->logger->debug(sprintf('%s 的 TXT 记录还没查到，%d 秒后重试', $fqdn, $interval));
            $this->sleep($interval);
        }
    }

    /** 当前是否已经能查到目标值 */
    public function hasTxt(string $fqdn, string $expected): bool
    {
        $values = $this->resolver->txtFromAuthoritative($fqdn);

        foreach ($values as $value) {
            if ($value === $expected) {
                return true;
            }
        }

        if ($values !== []) {
            // 查到了记录但值对不上：多半是上一轮的旧记录还没删，
            // 或者用户手工加过一条。把实际值打出来，排错时能省很多时间
            $this->logger->debug(sprintf(
                '%s 当前的 TXT 值是 %s，还不是期望的 %s',
                $fqdn,
                implode(' | ', \array_slice($values, 0, 3)),
                $expected
            ));
        }

        return false;
    }

    /**
     * @return array<int, string>
     */
    public function lookupTxt(string $fqdn): array
    {
        return $this->resolver->txtFromAuthoritative($fqdn);
    }

    private function sleep(int $seconds): void
    {
        if ($this->sleeper !== null) {
            \call_user_func($this->sleeper, $seconds);

            return;
        }

        sleep($seconds);
    }
}
