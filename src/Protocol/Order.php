<?php

declare(strict_types=1);

namespace PhpAcme\Protocol;

use PhpAcme\Exception\ProtocolException;

/**
 * 一份证书订单（RFC 8555 §7.1.3）。
 *
 * 状态机：pending --(所有授权 valid)--> ready --(提交 CSR)--> processing
 *         --(CA 签完)--> valid；任一环节出错则 invalid。
 * 客户端不能跳步：在 pending 时提交 CSR 会被拒，在 ready 时去做验证是白做。
 */
class Order
{
    const STATUS_PENDING = 'pending';
    const STATUS_READY = 'ready';
    const STATUS_PROCESSING = 'processing';
    const STATUS_VALID = 'valid';
    const STATUS_INVALID = 'invalid';

    /** @var array */
    private $data;

    /** @var string 订单 URL，来自 newOrder 响应的 Location 头 */
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

    public function isPending(): bool
    {
        return $this->getStatus() === self::STATUS_PENDING;
    }

    public function isReady(): bool
    {
        return $this->getStatus() === self::STATUS_READY;
    }

    public function isProcessing(): bool
    {
        return $this->getStatus() === self::STATUS_PROCESSING;
    }

    public function isValid(): bool
    {
        return $this->getStatus() === self::STATUS_VALID;
    }

    public function isInvalid(): bool
    {
        return $this->getStatus() === self::STATUS_INVALID;
    }

    /** @return array<int, string> 授权 URL 列表 */
    public function getAuthorizationUrls(): array
    {
        if (!isset($this->data['authorizations']) || !\is_array($this->data['authorizations'])) {
            return [];
        }

        $out = [];
        foreach ($this->data['authorizations'] as $url) {
            $out[] = (string) $url;
        }

        return $out;
    }

    /** @return array<int, string> 订单覆盖的域名 */
    public function getDomains(): array
    {
        if (!isset($this->data['identifiers']) || !\is_array($this->data['identifiers'])) {
            return [];
        }

        $out = [];
        foreach ($this->data['identifiers'] as $identifier) {
            if (!\is_array($identifier) || !isset($identifier['value'])) {
                continue;
            }
            $out[] = (string) $identifier['value'];
        }

        return $out;
    }

    public function getFinalizeUrl(): string
    {
        if (!isset($this->data['finalize'])) {
            throw new ProtocolException('订单里没有 finalize 地址，服务端返回的数据不完整');
        }

        return (string) $this->data['finalize'];
    }

    /** 证书下载地址；只有订单 valid 之后才有 */
    public function getCertificateUrl(): ?string
    {
        return isset($this->data['certificate']) ? (string) $this->data['certificate'] : null;
    }

    public function getExpires(): ?string
    {
        return isset($this->data['expires']) ? (string) $this->data['expires'] : null;
    }

    /** 订单失败的原因 */
    public function getError(): ?ProtocolException
    {
        if (!isset($this->data['error']) || !\is_array($this->data['error'])) {
            return null;
        }

        return ProtocolException::fromProblem($this->data['error']);
    }

    public function getErrorMessage(): string
    {
        $error = $this->getError();

        return $error !== null ? $error->getMessage() : '';
    }

    public function toArray(): array
    {
        return $this->data;
    }
}
