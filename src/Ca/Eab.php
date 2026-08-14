<?php

declare(strict_types=1);

namespace PhpAcme\Ca;

use PhpAcme\Exception\ConfigException;
use PhpAcme\Exception\ProtocolException;
use PhpAcme\Http\HttpClient;

/**
 * External Account Binding 凭据。
 *
 * ZeroSSL、Google Trust Services、SSL.com 这些 CA 要求先在它们的控制台
 * 注册一个账号，拿到一对 (kid, hmacKey)，注册 ACME 账户时带上，
 * CA 才知道这个 ACME 账户属于谁。
 */
class Eab
{
    /** ZeroSSL 提供的免注册通道：用邮箱换一对 EAB 凭据 */
    const ZEROSSL_EAB_ENDPOINT = 'https://api.zerossl.com/acme/eab-credentials-email';

    /** @var string */
    private $kid;

    /** @var string base64url 编码的 HMAC key */
    private $hmacKey;

    public function __construct(string $kid, string $hmacKey)
    {
        $kid = trim($kid);
        $hmacKey = trim($hmacKey);

        if ($kid === '' || $hmacKey === '') {
            throw new ConfigException('EAB 的 Key ID 与 HMAC Key 都不能为空');
        }

        $this->kid = $kid;
        $this->hmacKey = $hmacKey;
    }

    public function getKid(): string
    {
        return $this->kid;
    }

    public function getHmacKey(): string
    {
        return $this->hmacKey;
    }

    /** @return array{kid: string, hmac: string} 传给 AcmeClient::registerAccount() 的形状 */
    public function toArray(): array
    {
        return ['kid' => $this->kid, 'hmac' => $this->hmacKey];
    }

    /**
     * 用邮箱向 ZeroSSL 换一对 EAB 凭据。
     *
     * 这是 ZeroSSL 官方给 acme.sh 开的通道，不需要先注册账号。
     * 换来的凭据要存起来复用——每次都换新的会在 ZeroSSL 那边堆出一堆
     * 无用的子账户，而且他们对这个接口有频率限制。
     */
    public static function fetchFromZeroSsl(HttpClient $http, string $email): self
    {
        $email = trim($email);
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new ConfigException(sprintf(
                'ZeroSSL 需要一个有效邮箱来换取 EAB 凭据，「%s」不是。用 --email 指定',
                $email
            ));
        }

        $response = $http->postForm(self::ZEROSSL_EAB_ENDPOINT, ['email' => $email]);

        $data = $response->tryJson();
        if ($data === null) {
            throw new ProtocolException(sprintf(
                'ZeroSSL 的 EAB 接口返回了非 JSON 内容（HTTP %d）：%s',
                $response->getStatus(),
                substr($response->getBody(), 0, 200)
            ));
        }

        if (!isset($data['success']) || $data['success'] !== true) {
            $message = isset($data['error']['type']) ? (string) $data['error']['type'] : '未知错误';
            throw new ProtocolException(sprintf('ZeroSSL 拒绝了 EAB 申请：%s', $message));
        }

        if (!isset($data['eab_kid'], $data['eab_hmac_key'])) {
            throw new ProtocolException('ZeroSSL 返回成功但没有给出 eab_kid / eab_hmac_key');
        }

        return new self((string) $data['eab_kid'], (string) $data['eab_hmac_key']);
    }
}
