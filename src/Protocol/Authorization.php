<?php

declare(strict_types=1);

namespace PhpAcme\Protocol;

use PhpAcme\Exception\ProtocolException;

/**
 * 一个域名的授权（RFC 8555 §7.1.4）。
 *
 * 一张证书有几个域名就有几个授权，每个授权底下挂着若干挑战，
 * 完成**任意一个**即可让该授权变成 valid。
 */
class Authorization
{
    const STATUS_PENDING = 'pending';
    const STATUS_VALID = 'valid';
    const STATUS_INVALID = 'invalid';
    const STATUS_DEACTIVATED = 'deactivated';
    const STATUS_EXPIRED = 'expired';
    const STATUS_REVOKED = 'revoked';

    /** @var array */
    private $data;

    /** @var string 这个授权自己的 URL */
    private $url;

    public function __construct(array $data, string $url)
    {
        $this->data = $data;
        $this->url = $url;
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    public function getStatus(): string
    {
        return isset($this->data['status']) ? (string) $this->data['status'] : self::STATUS_PENDING;
    }

    public function isValid(): bool
    {
        return $this->getStatus() === self::STATUS_VALID;
    }

    public function isPending(): bool
    {
        return $this->getStatus() === self::STATUS_PENDING;
    }

    public function isInvalid(): bool
    {
        return $this->getStatus() === self::STATUS_INVALID;
    }

    /**
     * 被授权的域名。
     *
     * 通配符订单的授权里，identifier.value 是**不带** `*.` 的裸域名，
     * 另有一个 wildcard: true 标记。要把 `*.` 拼回去才能对上用户给的域名列表。
     */
    public function getDomain(): string
    {
        if (!isset($this->data['identifier']['value'])) {
            throw new ProtocolException('授权里没有 identifier，服务端返回的数据不完整');
        }

        $value = (string) $this->data['identifier']['value'];

        return $this->isWildcard() ? '*.' . $value : $value;
    }

    /** 不带通配符前缀的域名，dns-01 加记录时用这个 */
    public function getBaseDomain(): string
    {
        return isset($this->data['identifier']['value']) ? (string) $this->data['identifier']['value'] : '';
    }

    public function isWildcard(): bool
    {
        return isset($this->data['wildcard']) && $this->data['wildcard'] === true;
    }

    public function getExpires(): ?string
    {
        return isset($this->data['expires']) ? (string) $this->data['expires'] : null;
    }

    /** @return array<int, Challenge> */
    public function getChallenges(): array
    {
        if (!isset($this->data['challenges']) || !\is_array($this->data['challenges'])) {
            return [];
        }

        $domain = $this->getDomain();
        $out = [];
        foreach ($this->data['challenges'] as $challenge) {
            if (\is_array($challenge)) {
                $out[] = new Challenge($challenge, $domain);
            }
        }

        return $out;
    }

    /**
     * 找指定类型的挑战。
     *
     * 通配符域名只能用 dns-01——CA 不会为 *.example.com 提供 http-01，
     * 所以这里返回 null 是正常情况，调用方要给出「通配符必须用 DNS 验证」
     * 这种能照着改的提示，而不是干巴巴一句「找不到挑战」。
     */
    public function findChallenge(string $type): ?Challenge
    {
        foreach ($this->getChallenges() as $challenge) {
            if ($challenge->getType() === $type) {
                return $challenge;
            }
        }

        return null;
    }

    /** @return array<int, string> 这个授权支持哪几种验证方式 */
    public function getAvailableTypes(): array
    {
        $types = [];
        foreach ($this->getChallenges() as $challenge) {
            $types[] = $challenge->getType();
        }

        return $types;
    }

    /** 授权失败时，从挑战里翻出具体原因 */
    public function getErrorMessage(): string
    {
        $messages = [];
        foreach ($this->getChallenges() as $challenge) {
            $message = $challenge->getErrorMessage();
            if ($message !== '') {
                $messages[] = sprintf('[%s] %s', $challenge->getType(), $message);
            }
        }

        return implode('; ', $messages);
    }

    public function toArray(): array
    {
        return $this->data;
    }
}
