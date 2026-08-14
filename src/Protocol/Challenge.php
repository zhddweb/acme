<?php

declare(strict_types=1);

namespace Mci\Acme\Protocol;

use Mci\Acme\Crypto\Jws;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ProtocolException;

/**
 * 一个挑战（RFC 8555 §8）。
 *
 * 挑战本身只是「服务端出的题」：类型 + token + 状态。怎么答题
 * （写文件、加 TXT 记录、起 TLS 服务）是 Challenge\ 那边求解器的事，
 * 这里只负责表示题面和算出正确答案。
 */
class Challenge
{
    const TYPE_HTTP_01 = 'http-01';
    const TYPE_DNS_01 = 'dns-01';
    const TYPE_TLS_ALPN_01 = 'tls-alpn-01';

    const STATUS_PENDING = 'pending';
    const STATUS_PROCESSING = 'processing';
    const STATUS_VALID = 'valid';
    const STATUS_INVALID = 'invalid';

    /** @var array 服务端返回的原始 JSON */
    private $data;

    /** @var string 所属域名，服务端不给，是从 authorization 带下来的 */
    private $domain;

    public function __construct(array $data, string $domain = '')
    {
        $this->data = $data;
        $this->domain = $domain;
    }

    public function getType(): string
    {
        return isset($this->data['type']) ? (string) $this->data['type'] : '';
    }

    public function getUrl(): string
    {
        if (!isset($this->data['url'])) {
            throw new ProtocolException('挑战里没有 url 字段，服务端返回的数据不完整');
        }

        return (string) $this->data['url'];
    }

    public function getToken(): string
    {
        if (!isset($this->data['token'])) {
            throw new ProtocolException('挑战里没有 token 字段，服务端返回的数据不完整');
        }

        return (string) $this->data['token'];
    }

    public function getStatus(): string
    {
        return isset($this->data['status']) ? (string) $this->data['status'] : self::STATUS_PENDING;
    }

    public function getDomain(): string
    {
        return $this->domain;
    }

    public function isValid(): bool
    {
        return $this->getStatus() === self::STATUS_VALID;
    }

    public function isInvalid(): bool
    {
        return $this->getStatus() === self::STATUS_INVALID;
    }

    public function isPending(): bool
    {
        return $this->getStatus() === self::STATUS_PENDING;
    }

    /**
     * 验证失败的原因。
     *
     * 这是排错最有用的一段信息：CA 会在这里写清楚「我去 http://x/.well-known/...
     * 拿到的是 404」还是「拿到的内容对不上」。丢掉它用户就只能靠猜。
     */
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

    /** 已验证的时间，valid 之后才有 */
    public function getValidatedAt(): ?string
    {
        return isset($this->data['validated']) ? (string) $this->data['validated'] : null;
    }

    /** http-01 要写进文件的内容 */
    public function getKeyAuthorization(KeyPair $accountKey): string
    {
        return Jws::keyAuthorization($this->getToken(), $accountKey);
    }

    /** dns-01 要写进 TXT 记录的值（比 keyAuthorization 多一步 SHA-256） */
    public function getDnsValue(KeyPair $accountKey): string
    {
        return Jws::dnsTxtValue($this->getToken(), $accountKey);
    }

    /** tls-alpn-01 证书扩展里的裸摘要 */
    public function getTlsAlpnDigest(KeyPair $accountKey): string
    {
        return Jws::tlsAlpnDigest($this->getToken(), $accountKey);
    }

    /** http-01 的文件要放在 webroot 下的哪个相对路径 */
    public function getHttpPath(): string
    {
        return '.well-known/acme-challenge/' . $this->getToken();
    }

    /** CA 会去访问的完整 URL，打日志用 */
    public function getHttpUrl(): string
    {
        return sprintf('http://%s/%s', \Mci\Acme\Util\Domain::stripWildcard($this->domain), $this->getHttpPath());
    }

    /** dns-01 要写的记录名 */
    public function getDnsRecordName(): string
    {
        return \Mci\Acme\Util\Domain::challengeRecordName($this->domain);
    }

    public function toArray(): array
    {
        return $this->data;
    }
}
