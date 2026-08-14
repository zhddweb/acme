<?php

declare(strict_types=1);

namespace Mci\Acme\Service;

use Mci\Acme\Ca\CaRegistry;
use Mci\Acme\Challenge\ChallengeSolverInterface;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ConfigException;
use Mci\Acme\Util\Domain;

/**
 * 一次签发请求的全部参数。
 *
 * 做成对象而不是一长串函数参数：签发要传的东西有十几项，
 * 按位置传参没人记得住第七个是什么；而且续期时要把这些参数
 * 从 .conf 里读回来重建，有个明确的对象边界会清楚很多。
 */
class IssueRequest
{
    /** @var array<int, string> */
    private $domains;

    /** @var ChallengeSolverInterface */
    private $solver;

    /** @var string 目录 URL 或 CA 短名 */
    private $ca = CaRegistry::DEFAULT_CA;

    /** @var string */
    private $keyType = KeyPair::DEFAULT_TYPE;

    /** @var string|null 联系邮箱 */
    private $email;

    /** @var int 到期前多少天算该续了 */
    private $renewDays = 30;

    /** @var bool 即使证书还没到续期时间也强制重签 */
    private $force = false;

    /** @var bool 换一把新的证书私钥 */
    private $newKey = false;

    /** @var string|null 偏好的证书链根 */
    private $preferredChain;

    /** @var array<string, string> CSR 的 subject 额外字段 */
    private $subject = [];

    /** @var array{kid: string, hmac: string}|null */
    private $eab;

    /** @var string|null 用户自带的 CSR（PEM）；给了就不自己生成 */
    private $csr;

    /** @var int 单个挑战的等待超时 */
    private $challengeTimeout = 120;

    /** @var int 订单完成的等待超时 */
    private $orderTimeout = 180;

    /** @var array<string, string> 要写进 .conf 的额外项（DNS 凭据、hook 配置等） */
    private $extraConfig = [];

    /** @var bool 是否把这次的参数写进 .conf 供续期复用 */
    private $persistConfig = true;

    /**
     * @param array<int, string> $domains
     */
    public function __construct(array $domains, ChallengeSolverInterface $solver)
    {
        $this->domains = Domain::normalizeList($domains);
        $this->solver = $solver;

        $this->assertWildcardUsesDns();
    }

    /**
     * 通配符只能用 dns-01 验证。
     *
     * 这是 CA 的硬规则，不是本库的限制：*.example.com 的授权里
     * 服务端根本不会提供 http-01 挑战。提前拦下来能省掉一次
     * 「下单成功但找不到可用挑战」的困惑。
     */
    private function assertWildcardUsesDns(): void
    {
        foreach ($this->domains as $domain) {
            if (!Domain::isWildcard($domain)) {
                continue;
            }

            if ($this->solver->getType() !== 'dns-01') {
                throw new ConfigException(sprintf(
                    '通配符域名 %s 只能用 dns-01 验证，当前用的是 %s。'
                    . '请改用 --dns <提供商>，或去掉通配符域名',
                    $domain,
                    $this->solver->getType()
                ));
            }
        }
    }

    /** @return array<int, string> */
    public function getDomains(): array
    {
        return $this->domains;
    }

    /** 主域名，决定证书存到哪个目录 */
    public function getMainDomain(): string
    {
        return $this->domains[0];
    }

    public function getSolver(): ChallengeSolverInterface
    {
        return $this->solver;
    }

    public function getCa(): string
    {
        return $this->ca;
    }

    public function setCa(string $ca): self
    {
        $this->ca = $ca;

        return $this;
    }

    public function getDirectoryUrl(): string
    {
        return CaRegistry::resolveUrl($this->ca);
    }

    public function getKeyType(): string
    {
        return $this->keyType;
    }

    public function setKeyType(string $keyType): self
    {
        $this->keyType = KeyPair::normalizeType($keyType);

        return $this;
    }

    /** 证书是不是 ECC，决定存 <domain> 还是 <domain>_ecc */
    public function isEcc(): bool
    {
        return KeyPair::isEcType($this->keyType);
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(?string $email): self
    {
        $this->email = $email !== null && trim($email) !== '' ? trim($email) : null;

        return $this;
    }

    public function getRenewDays(): int
    {
        return $this->renewDays;
    }

    public function setRenewDays(int $days): self
    {
        $this->renewDays = max(1, $days);

        return $this;
    }

    public function isForce(): bool
    {
        return $this->force;
    }

    public function setForce(bool $force): self
    {
        $this->force = $force;

        return $this;
    }

    public function isNewKey(): bool
    {
        return $this->newKey;
    }

    public function setNewKey(bool $newKey): self
    {
        $this->newKey = $newKey;

        return $this;
    }

    public function getPreferredChain(): ?string
    {
        return $this->preferredChain;
    }

    public function setPreferredChain(?string $chain): self
    {
        $this->preferredChain = $chain !== null && trim($chain) !== '' ? trim($chain) : null;

        return $this;
    }

    /** @return array<string, string> */
    public function getSubject(): array
    {
        return $this->subject;
    }

    /**
     * @param array<string, string> $subject
     */
    public function setSubject(array $subject): self
    {
        $this->subject = $subject;

        return $this;
    }

    /** @return array{kid: string, hmac: string}|null */
    public function getEab(): ?array
    {
        return $this->eab;
    }

    /**
     * @param array{kid: string, hmac: string}|null $eab
     */
    public function setEab(?array $eab): self
    {
        $this->eab = $eab;

        return $this;
    }

    public function getCsr(): ?string
    {
        return $this->csr;
    }

    public function setCsr(?string $csr): self
    {
        $this->csr = $csr;

        return $this;
    }

    public function getChallengeTimeout(): int
    {
        return $this->challengeTimeout;
    }

    public function setChallengeTimeout(int $seconds): self
    {
        $this->challengeTimeout = max(10, $seconds);

        return $this;
    }

    public function getOrderTimeout(): int
    {
        return $this->orderTimeout;
    }

    public function setOrderTimeout(int $seconds): self
    {
        $this->orderTimeout = max(10, $seconds);

        return $this;
    }

    /** @return array<string, string> */
    public function getExtraConfig(): array
    {
        return $this->extraConfig;
    }

    /**
     * @param array<string, string> $config
     */
    public function setExtraConfig(array $config): self
    {
        $this->extraConfig = $config;

        return $this;
    }

    public function isPersistConfig(): bool
    {
        return $this->persistConfig;
    }

    public function setPersistConfig(bool $persist): self
    {
        $this->persistConfig = $persist;

        return $this;
    }
}
