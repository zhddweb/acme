<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Dns01;

use Mci\Acme\Challenge\AbstractSolver;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\DnsException;
use Mci\Acme\Protocol\Challenge;
use Mci\Acme\Util\Logger;

/**
 * dns-01：通过解析商 API 加一条 TXT 记录来证明域名归属。
 *
 * 唯一能给**通配符**签证书的验证方式，也是唯一不要求服务器本身可从公网访问的
 * ——内网服务、还没上线的域名都能用它。代价是要有解析商的 API 凭据。
 *
 * 值得注意的是 `_acme-challenge.example.com` 这个记录名对
 * `example.com` 与 `*.example.com` 是**同一个**。同时申请这两个时会有
 * 两条同名不同值的 TXT，缺一不可——这是很多 DNS 适配器的坑：
 * 覆盖式写入会把前一条冲掉，导致第二个域名怎么都验不过。
 */
class DnsSolver extends AbstractSolver
{
    const TYPE = 'dns-01';

    /** @var DnsProviderInterface */
    private $provider;

    /** @var DnsVerifier */
    private $verifier;

    /** @var int 加完记录后至少等多少秒再开始查询 */
    private $initialDelay = 10;

    /** @var int 等待传播的总超时 */
    private $propagationTimeout = 120;

    /** @var int 查询间隔 */
    private $pollInterval = 10;

    /** @var bool 传播检测失败时是否仍然继续（让 CA 去试） */
    private $continueOnTimeout = true;

    /** @var array<string, array<int, string>> fqdn => 已添加的值，cleanup 按它删 */
    private $added = [];

    /** @var callable|null 等待函数，测试里换掉免得真 sleep */
    private $sleeper;

    public function __construct(
        DnsProviderInterface $provider,
        ?DnsVerifier $verifier = null,
        ?Logger $logger = null
    ) {
        parent::__construct($logger);

        $this->provider = $provider;
        $this->verifier = $verifier !== null ? $verifier : new DnsVerifier(null, $this->logger);
    }

    public function getType(): string
    {
        return self::TYPE;
    }

    public function getProvider(): DnsProviderInterface
    {
        return $this->provider;
    }

    public function setPropagationTimeout(int $seconds): void
    {
        $this->propagationTimeout = max(0, $seconds);
    }

    public function setInitialDelay(int $seconds): void
    {
        $this->initialDelay = max(0, $seconds);
    }

    public function setPollInterval(int $seconds): void
    {
        $this->pollInterval = max(1, $seconds);
    }

    public function setContinueOnTimeout(bool $continue): void
    {
        $this->continueOnTimeout = $continue;
    }

    /** 测试注入点：连同 verifier 的等待一起换掉，用例才不会真的睡两分钟 */
    public function setSleeper(?callable $sleeper): void
    {
        $this->sleeper = $sleeper;
        $this->verifier->setSleeper($sleeper);
    }

    public function prepare(Challenge $challenge, KeyPair $accountKey): void
    {
        $fqdn = $challenge->getDnsRecordName();
        $value = $challenge->getDnsValue($accountKey);

        $this->logger->info(sprintf('通过 %s 添加 TXT 记录 %s', $this->provider->getName(), $fqdn));

        $this->provider->addTxtRecord($fqdn, $value);

        if (!isset($this->added[$fqdn])) {
            $this->added[$fqdn] = [];
        }
        $this->added[$fqdn][] = $value;
    }

    public function cleanup(Challenge $challenge, KeyPair $accountKey): void
    {
        $fqdn = $challenge->getDnsRecordName();
        $value = $challenge->getDnsValue($accountKey);

        if (!isset($this->added[$fqdn])) {
            return;
        }

        try {
            $this->provider->removeTxtRecord($fqdn, $value);
            $this->logger->debug(sprintf('已删除 TXT 记录 %s', $fqdn));
        } catch (DnsException $e) {
            // 清理失败不该盖掉真正的失败原因，也不该让已经成功的签发变成失败。
            // 但要吼一声——残留的 TXT 记录会污染下一次验证
            $this->logger->warning(sprintf(
                '删除 TXT 记录 %s 失败：%s。请手工到解析商后台确认并删除',
                $fqdn,
                $e->getMessage()
            ));
        }

        $remaining = array_values(array_filter(
            $this->added[$fqdn],
            static function (string $item) use ($value): bool {
                return $item !== $value;
            }
        ));

        if ($remaining === []) {
            unset($this->added[$fqdn]);
        } else {
            $this->added[$fqdn] = $remaining;
        }
    }

    /**
     * 等记录传播开。
     *
     * 返回 false 会让调用方推迟通知 CA。默认 continueOnTimeout 为 true——
     * 超时后仍然返回 true 让流程走下去：我们的检测点和 CA 的检测点
     * 未必是同一批解析器，我们查不到不代表 CA 查不到，
     * 而白白放弃一次已经加好记录的签发更可惜。
     */
    public function verify(Challenge $challenge, KeyPair $accountKey): bool
    {
        $fqdn = $challenge->getDnsRecordName();
        $value = $challenge->getDnsValue($accountKey);

        if ($this->initialDelay > 0) {
            $this->logger->debug(sprintf('等待 %d 秒让 TXT 记录开始传播', $this->initialDelay));
            $this->sleep($this->initialDelay);
        }

        if ($this->propagationTimeout <= 0) {
            return true;
        }

        $ok = $this->verifier->waitForTxt($fqdn, $value, $this->propagationTimeout, $this->pollInterval);

        if (!$ok && $this->continueOnTimeout) {
            $this->logger->warning('本地没能确认 TXT 记录已生效，仍然继续——CA 那边可能已经能查到了');

            return true;
        }

        return $ok;
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
