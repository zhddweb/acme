<?php

declare(strict_types=1);

namespace Mci\Acme\Protocol;

use Mci\Acme\Crypto\KeyPair;

/**
 * ACME 账户。
 *
 * 账户的身份就是那把密钥——邮箱只是联系方式，换邮箱账户不变，
 * 换密钥（keyChange）才是换身份。所以密钥文件丢了等于账户丢了，
 * 存储层对它的写入必须是原子的。
 */
class Account
{
    const STATUS_VALID = 'valid';
    const STATUS_DEACTIVATED = 'deactivated';
    const STATUS_REVOKED = 'revoked';

    /** @var KeyPair */
    private $keyPair;

    /** @var string 账户 URL，也就是 JWS 里的 kid */
    private $url;

    /** @var array 服务端返回的账户对象 */
    private $data;

    public function __construct(KeyPair $keyPair, string $url, array $data = [])
    {
        $this->keyPair = $keyPair;
        $this->url = $url;
        $this->data = $data;
    }

    public function getKeyPair(): KeyPair
    {
        return $this->keyPair;
    }

    /** JWS 的 kid 字段用它 */
    public function getUrl(): string
    {
        return $this->url;
    }

    public function getStatus(): string
    {
        return isset($this->data['status']) ? (string) $this->data['status'] : self::STATUS_VALID;
    }

    public function isValid(): bool
    {
        return $this->getStatus() === self::STATUS_VALID;
    }

    /** @return array<int, string> 联系方式，形如 mailto:a@b.com */
    public function getContacts(): array
    {
        if (!isset($this->data['contact']) || !\is_array($this->data['contact'])) {
            return [];
        }

        $out = [];
        foreach ($this->data['contact'] as $contact) {
            $out[] = (string) $contact;
        }

        return $out;
    }

    /** @return array<int, string> 去掉 mailto: 前缀的邮箱 */
    public function getEmails(): array
    {
        $out = [];
        foreach ($this->getContacts() as $contact) {
            if (str_starts_with($contact, 'mailto:')) {
                $out[] = substr($contact, 7);
            }
        }

        return $out;
    }

    public function getOrdersUrl(): ?string
    {
        return isset($this->data['orders']) ? (string) $this->data['orders'] : null;
    }

    public function getCreatedAt(): ?string
    {
        return isset($this->data['createdAt']) ? (string) $this->data['createdAt'] : null;
    }

    public function toArray(): array
    {
        return $this->data;
    }

    /** 换过服务端数据后返回新实例（比如 update 之后） */
    public function withData(array $data): self
    {
        return new self($this->keyPair, $this->url, $data);
    }

    /**
     * 把邮箱列表规整成 ACME 要的 contact 数组。
     *
     * @param array<int, string>|string $emails
     * @return array<int, string>
     */
    public static function buildContacts($emails): array
    {
        if (\is_string($emails)) {
            $emails = $emails === '' ? [] : preg_split('/[,;\s]+/', $emails);
        }

        $out = [];
        foreach ((array) $emails as $email) {
            $email = trim((string) $email);
            if ($email === '') {
                continue;
            }
            // 用户可能直接写了 mailto:，别给它套两层
            $out[] = str_starts_with($email, 'mailto:') ? $email : 'mailto:' . $email;
        }

        return $out;
    }
}
