<?php

declare(strict_types=1);

namespace PhpAcme\Protocol;

use PhpAcme\Exception\ProtocolException;
use PhpAcme\Http\HttpClient;

/**
 * ACME 的目录文档（RFC 8555 §7.1.1）。
 *
 * 这是整个协议唯一硬编码的 URL，其余端点全从这里读。
 * 所以换 CA 只需要换目录地址，客户端代码一行都不用动。
 */
class Directory
{
    const NEW_NONCE = 'newNonce';
    const NEW_ACCOUNT = 'newAccount';
    const NEW_ORDER = 'newOrder';
    const NEW_AUTHZ = 'newAuthz';
    const REVOKE_CERT = 'revokeCert';
    const KEY_CHANGE = 'keyChange';
    const RENEWAL_INFO = 'renewalInfo';

    /** @var string */
    private $directoryUrl;

    /** @var array 目录文档原文 */
    private $data;

    public function __construct(string $directoryUrl, array $data)
    {
        $this->directoryUrl = $directoryUrl;
        $this->data = $data;
    }

    public static function fetch(HttpClient $http, string $directoryUrl): self
    {
        $response = $http->get($directoryUrl, ['Accept' => 'application/json']);

        if (!$response->isSuccess()) {
            $problem = $response->tryJson();
            if ($problem !== null && isset($problem['type'])) {
                throw ProtocolException::fromProblem($problem, $response->getStatus());
            }

            throw new ProtocolException(sprintf(
                '拉取 ACME 目录失败：%s 返回 HTTP %d。确认这个地址是 CA 的 directory 端点',
                $directoryUrl,
                $response->getStatus()
            ));
        }

        $data = $response->json();

        // 这三个端点缺任何一个都没法干活，早点报比签到一半再炸强
        foreach ([self::NEW_NONCE, self::NEW_ACCOUNT, self::NEW_ORDER] as $required) {
            if (!isset($data[$required])) {
                throw new ProtocolException(sprintf(
                    '%s 返回的目录里没有 %s 端点，这可能不是一个 ACME v2 服务（v1 的目录长得不一样）',
                    $directoryUrl,
                    $required
                ));
            }
        }

        return new self($directoryUrl, $data);
    }

    public function getDirectoryUrl(): string
    {
        return $this->directoryUrl;
    }

    public function getUrl(string $name): string
    {
        if (!isset($this->data[$name]) || !\is_string($this->data[$name])) {
            throw new ProtocolException(sprintf('当前 CA 的目录里没有 %s 端点', $name));
        }

        return $this->data[$name];
    }

    public function hasUrl(string $name): bool
    {
        return isset($this->data[$name]) && \is_string($this->data[$name]);
    }

    public function getNewNonceUrl(): string
    {
        return $this->getUrl(self::NEW_NONCE);
    }

    public function getNewAccountUrl(): string
    {
        return $this->getUrl(self::NEW_ACCOUNT);
    }

    public function getNewOrderUrl(): string
    {
        return $this->getUrl(self::NEW_ORDER);
    }

    public function getRevokeCertUrl(): string
    {
        return $this->getUrl(self::REVOKE_CERT);
    }

    public function getKeyChangeUrl(): string
    {
        return $this->getUrl(self::KEY_CHANGE);
    }

    /** ARI（RFC 9773）端点，用来问 CA「这张证书什么时候续最合适」，不是所有 CA 都有 */
    public function getRenewalInfoUrl(): ?string
    {
        return $this->hasUrl(self::RENEWAL_INFO) ? $this->getUrl(self::RENEWAL_INFO) : null;
    }

    /** 服务条款链接；注册账户时要带上同意标记，这个 URL 用于展示给用户 */
    public function getTermsOfService(): ?string
    {
        if (isset($this->data['meta']['termsOfService']) && \is_string($this->data['meta']['termsOfService'])) {
            return $this->data['meta']['termsOfService'];
        }

        return null;
    }

    public function getWebsite(): ?string
    {
        if (isset($this->data['meta']['website']) && \is_string($this->data['meta']['website'])) {
            return $this->data['meta']['website'];
        }

        return null;
    }

    /**
     * 这个 CA 是否强制要求 External Account Binding。
     *
     * ZeroSSL 和 SSL.com 是 true，没带 EAB 注册会被拒。
     */
    public function requiresExternalAccountBinding(): bool
    {
        return isset($this->data['meta']['externalAccountRequired'])
            && $this->data['meta']['externalAccountRequired'] === true;
    }

    /** @return array<int, string> CA 支持的 CAA 标识，一般用不上，排错时有用 */
    public function getCaaIdentities(): array
    {
        if (!isset($this->data['meta']['caaIdentities']) || !\is_array($this->data['meta']['caaIdentities'])) {
            return [];
        }

        $out = [];
        foreach ($this->data['meta']['caaIdentities'] as $identity) {
            $out[] = (string) $identity;
        }

        return $out;
    }

    /** @return array */
    public function toArray(): array
    {
        return $this->data;
    }
}
