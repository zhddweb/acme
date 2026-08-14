<?php

declare(strict_types=1);

namespace Mci\Acme\Protocol;

use Mci\Acme\Crypto\Certificate;
use Mci\Acme\Crypto\Csr;
use Mci\Acme\Crypto\Jws;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ProtocolException;
use Mci\Acme\Http\HttpClient;
use Mci\Acme\Http\Response;
use Mci\Acme\Util\Domain;
use Mci\Acme\Util\Json;
use Mci\Acme\Util\Logger;

/**
 * ACME 协议客户端：把 RFC 8555 的每个端点包成一个方法。
 *
 * 这一层只管协议本身，不碰文件系统、不碰 DNS、不做重试编排——
 * 那些是 Service\ 那边的事。分开的好处是这个类可以完全用
 * MockTransport 测到，不需要任何真实 CA。
 */
class AcmeClient
{
    /** @var HttpClient */
    private $http;

    /** @var Directory */
    private $directory;

    /** @var NonceManager */
    private $nonce;

    /** @var Logger */
    private $logger;

    /** @var KeyPair|null 账户密钥 */
    private $accountKey;

    /** @var string|null 账户 URL，也就是 JWS 的 kid */
    private $accountUrl;

    /** @var callable|null 轮询时的等待函数，测试里换掉免得真 sleep */
    private $sleeper;

    public function __construct(HttpClient $http, Directory $directory, ?Logger $logger = null)
    {
        $this->http = $http;
        $this->directory = $directory;
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->nonce = new NonceManager($http, $directory->getNewNonceUrl());
    }

    /** 从目录地址一步建好客户端 */
    public static function create(HttpClient $http, string $directoryUrl, ?Logger $logger = null): self
    {
        return new self($http, Directory::fetch($http, $directoryUrl), $logger);
    }

    public function getDirectory(): Directory
    {
        return $this->directory;
    }

    public function getHttpClient(): HttpClient
    {
        return $this->http;
    }

    public function setSleeper(?callable $sleeper): void
    {
        $this->sleeper = $sleeper;
    }

    /** 设定当前使用的账户；之后的请求都用 kid 模式签名 */
    public function useAccount(Account $account): void
    {
        $this->accountKey = $account->getKeyPair();
        $this->accountUrl = $account->getUrl();
    }

    public function setAccountKey(KeyPair $keyPair): void
    {
        $this->accountKey = $keyPair;
    }

    public function getAccountKey(): KeyPair
    {
        if ($this->accountKey === null) {
            throw new ProtocolException('还没有设置账户密钥');
        }

        return $this->accountKey;
    }

    // ---------------------------------------------------------------- 账户

    /**
     * 注册账户，已存在则直接拿回来。
     *
     * ACME 的 newAccount 天然幂等：同一把密钥再注册一次，服务端返回 200 +
     * 已有账户的 URL，而不是报错。所以不需要先查再建。
     *
     * @param array<int, string> $contacts 形如 mailto:a@b.com
     * @param array{kid: string, hmac: string}|null $eab EAB 凭据
     */
    public function registerAccount(
        KeyPair $keyPair,
        array $contacts = [],
        bool $agreeToTerms = true,
        ?array $eab = null
    ): Account {
        $this->accountKey = $keyPair;
        $this->accountUrl = null;

        $url = $this->directory->getNewAccountUrl();

        $payload = ['termsOfServiceAgreed' => $agreeToTerms];
        if ($contacts !== []) {
            $payload['contact'] = array_values($contacts);
        }

        if ($eab !== null) {
            if (!isset($eab['kid'], $eab['hmac'])) {
                throw new ProtocolException('EAB 凭据必须同时包含 kid 与 hmac');
            }
            $payload['externalAccountBinding'] = Jws::signExternalAccountBinding(
                $keyPair,
                $url,
                (string) $eab['kid'],
                (string) $eab['hmac']
            );
        } elseif ($this->directory->requiresExternalAccountBinding()) {
            throw new ProtocolException(
                '这个 CA 要求 External Account Binding，但没有提供 EAB 凭据。'
                . '请到 CA 控制台申请 EAB Key ID 与 HMAC Key，再用 --eab-kid / --eab-hmac-key 传入'
            );
        }

        // 注册时账户还没有 URL，只能用 jwk 模式——这是全流程里唯二用 jwk 的地方
        $response = $this->signedRequest($url, $payload, true);

        $accountUrl = $response->getLocation();
        if ($accountUrl === null || $accountUrl === '') {
            throw new ProtocolException('注册账户成功但服务端没有返回 Location 头，拿不到账户 URL');
        }

        $this->accountUrl = $accountUrl;

        $data = $response->tryJson();
        $account = new Account($keyPair, $accountUrl, $data !== null ? $data : []);

        $this->logger->debug(sprintf(
            '账户 %s（%s）',
            $accountUrl,
            $response->getStatus() === 201 ? '新注册' : '已存在'
        ));

        return $account;
    }

    /**
     * 只查不建。
     *
     * onlyReturnExisting 让服务端在账户不存在时回 accountDoesNotExist，
     * 用于「我想确认这把密钥还有效」的场合。
     */
    public function lookupAccount(KeyPair $keyPair): ?Account
    {
        $this->accountKey = $keyPair;
        $this->accountUrl = null;

        try {
            $response = $this->signedRequest(
                $this->directory->getNewAccountUrl(),
                ['onlyReturnExisting' => true],
                true
            );
        } catch (ProtocolException $e) {
            if ($e->isAccountDoesNotExist()) {
                return null;
            }

            throw $e;
        }

        $accountUrl = $response->getLocation();
        if ($accountUrl === null || $accountUrl === '') {
            return null;
        }

        $this->accountUrl = $accountUrl;
        $data = $response->tryJson();

        return new Account($keyPair, $accountUrl, $data !== null ? $data : []);
    }

    /** 拉取账户当前状态 */
    public function fetchAccount(Account $account): Account
    {
        $this->useAccount($account);
        $response = $this->postAsGet($account->getUrl());

        return $account->withData($response->json());
    }

    /**
     * 改联系方式。
     *
     * @param array<int, string> $contacts
     */
    public function updateAccount(Account $account, array $contacts): Account
    {
        $this->useAccount($account);

        $response = $this->signedRequest($account->getUrl(), ['contact' => array_values($contacts)]);

        return $account->withData($response->json());
    }

    /**
     * 换账户密钥（RFC 8555 §7.3.5）。
     *
     * 这是个套娃结构：内层 JWS 用**新密钥**签，payload 是
     * {account, oldKey}，声明「我这把新钥匙要接管这个账户」；
     * 外层再用**旧密钥**签，证明「我是现任持有者，同意换」。
     * 少了任何一层服务端都会拒——这是防止别人拿你的账户 URL 去劫持。
     */
    public function changeAccountKey(Account $account, KeyPair $newKey): Account
    {
        $this->useAccount($account);

        $url = $this->directory->getKeyChangeUrl();

        $inner = $this->signInnerKeyChange($newKey, $url, [
            'account' => $account->getUrl(),
            'oldKey' => $account->getKeyPair()->getJwk(),
        ]);

        $response = $this->signedRequest($url, $inner);

        $this->logger->info('账户密钥已更换');

        $data = $response->tryJson();

        return new Account($newKey, $account->getUrl(), $data !== null ? $data : $account->toArray());
    }

    /**
     * 注销账户。不可逆——注销后这把密钥再也签不了新订单。
     */
    public function deactivateAccount(Account $account): Account
    {
        $this->useAccount($account);

        $response = $this->signedRequest($account->getUrl(), ['status' => 'deactivated']);

        return $account->withData($response->json());
    }

    // ---------------------------------------------------------------- 订单

    /**
     * 下单。
     *
     * @param array<int, string> $domains
     * @param string|null $notBefore RFC 3339 时间；多数 CA 会忽略
     */
    public function newOrder(array $domains, ?string $notBefore = null, ?string $notAfter = null): Order
    {
        $domains = Domain::normalizeList($domains);

        $identifiers = [];
        foreach ($domains as $domain) {
            $identifiers[] = ['type' => 'dns', 'value' => $domain];
        }

        $payload = ['identifiers' => $identifiers];
        if ($notBefore !== null) {
            $payload['notBefore'] = $notBefore;
        }
        if ($notAfter !== null) {
            $payload['notAfter'] = $notAfter;
        }

        $response = $this->signedRequest($this->directory->getNewOrderUrl(), $payload);

        $url = $response->getLocation();
        if ($url === null || $url === '') {
            throw new ProtocolException('下单成功但服务端没有返回 Location 头，拿不到订单 URL');
        }

        $this->logger->debug(sprintf('订单已创建：%s', $url));

        return new Order($response->json(), $url);
    }

    public function fetchOrder(string $url): Order
    {
        return new Order($this->postAsGet($url)->json(), $url);
    }

    public function fetchAuthorization(string $url): Authorization
    {
        return new Authorization($this->postAsGet($url)->json(), $url);
    }

    /**
     * 告诉服务端「我准备好了，来验吧」。
     *
     * payload 是个空对象 `{}`，不是 null——那是 POST-as-GET 的意思，
     * 服务端不会开始验证。
     */
    public function triggerChallenge(Challenge $challenge): Challenge
    {
        $response = $this->signedRequest($challenge->getUrl(), new \stdClass());

        return new Challenge($response->json(), $challenge->getDomain());
    }

    public function fetchChallenge(Challenge $challenge): Challenge
    {
        $response = $this->postAsGet($challenge->getUrl());

        return new Challenge($response->json(), $challenge->getDomain());
    }

    /**
     * 放弃一个授权。
     *
     * 用在「验证怎么都过不去，不想让这个 pending 授权占着订单」的时候。
     */
    public function deactivateAuthorization(Authorization $authorization): Authorization
    {
        $response = $this->signedRequest($authorization->getUrl(), ['status' => 'deactivated']);

        return new Authorization($response->json(), $authorization->getUrl());
    }

    /**
     * 提交 CSR，让 CA 开始签发。
     *
     * 订单必须已经是 ready 状态。CSR 传的是 DER 的 base64url，不是 PEM。
     */
    public function finalizeOrder(Order $order, string $csrDer): Order
    {
        $response = $this->signedRequest($order->getFinalizeUrl(), ['csr' => Csr::toBase64Url($csrDer)]);

        // finalize 的响应体就是更新后的订单，但 Location 头指向订单本身，
        // 有些 CA 不给这个头，所以沿用原来的 URL
        $location = $response->getLocation();

        return new Order($response->json(), $location !== null && $location !== '' ? $location : $order->getUrl());
    }

    /**
     * 轮询订单直到不再是 pending/processing。
     *
     * @param int $timeout 最多等几秒
     */
    public function waitForOrder(Order $order, int $timeout = 120, int $interval = 3): Order
    {
        $deadline = time() + $timeout;
        $current = $order;

        while ($current->isPending() || $current->isProcessing()) {
            if (time() >= $deadline) {
                throw new ProtocolException(sprintf(
                    '等待订单完成超时（%d 秒），当前状态仍是 %s。CA 可能正忙，稍后用同样的命令重试即可，订单不会重复创建',
                    $timeout,
                    $current->getStatus()
                ));
            }

            $this->sleep($interval);
            $current = $this->fetchOrder($current->getUrl());
        }

        if ($current->isInvalid()) {
            $message = $current->getErrorMessage();
            throw new ProtocolException(
                '订单被 CA 判为无效' . ($message !== '' ? '：' . $message : '')
            );
        }

        return $current;
    }

    /**
     * 轮询挑战直到出结果。
     */
    public function waitForChallenge(Challenge $challenge, int $timeout = 120, int $interval = 3): Challenge
    {
        $deadline = time() + $timeout;
        $current = $challenge;

        while ($current->isPending() || $current->getStatus() === Challenge::STATUS_PROCESSING) {
            if (time() >= $deadline) {
                throw new ProtocolException(sprintf(
                    '等待 %s 验证结果超时（%d 秒），域名 %s',
                    $current->getType(),
                    $timeout,
                    $current->getDomain()
                ));
            }

            $this->sleep($interval);
            $current = $this->fetchChallenge($current);
        }

        return $current;
    }

    /**
     * 下载证书链。
     *
     * @param string|null $preferredIssuer 想要的根，比如 "ISRG Root X1"。
     *        CA 会在 Link: rel="alternate" 里给出备选链，用于避开
     *        老安卓不认的交叉签名根。给了但没匹配上时用默认链，不报错。
     */
    public function downloadCertificate(Order $order, ?string $preferredIssuer = null): string
    {
        $url = $order->getCertificateUrl();
        if ($url === null || $url === '') {
            throw new ProtocolException('订单里没有证书地址，可能还没签发完成');
        }

        $response = $this->postAsGet($url, ['Accept' => 'application/pem-certificate-chain']);
        $chain = $response->getBody();

        if ($preferredIssuer === null || $preferredIssuer === '') {
            return $chain;
        }

        if ($this->chainMatchesIssuer($chain, $preferredIssuer)) {
            return $chain;
        }

        foreach ($response->getLink('alternate') as $alternateUrl) {
            $alternate = $this->postAsGet($alternateUrl, ['Accept' => 'application/pem-certificate-chain'])->getBody();
            if ($this->chainMatchesIssuer($alternate, $preferredIssuer)) {
                $this->logger->info(sprintf('已选用备选证书链：%s', $preferredIssuer));

                return $alternate;
            }
        }

        $this->logger->warning(sprintf(
            '没有找到根为「%s」的备选链，使用 CA 的默认链',
            $preferredIssuer
        ));

        return $chain;
    }

    /**
     * 吊销证书。
     *
     * 有两种签法：用账户密钥签（要求该账户签发过这张证书），
     * 或者用**证书自己的私钥**签（此时走 jwk 模式，不带 kid）。
     * 后者用于账户丢了但私钥还在的情况。
     *
     * @param int $reason CRL 原因码，0=unspecified、1=keyCompromise、4=superseded、5=cessationOfOperation
     */
    public function revokeCertificate(string $certificatePem, int $reason = 0, ?KeyPair $certificateKey = null): void
    {
        $certificate = Certificate::fromPem($certificatePem);

        $payload = [
            'certificate' => $certificate->toBase64UrlDer(),
            'reason' => $reason,
        ];

        $url = $this->directory->getRevokeCertUrl();

        if ($certificateKey !== null) {
            $savedKey = $this->accountKey;
            $savedUrl = $this->accountUrl;

            $this->accountKey = $certificateKey;
            $this->accountUrl = null;

            try {
                $this->signedRequest($url, $payload, true);
            } finally {
                // 不管成功失败都要把账户身份换回来，否则后续请求会用错密钥
                $this->accountKey = $savedKey;
                $this->accountUrl = $savedUrl;
            }

            return;
        }

        $this->signedRequest($url, $payload);
    }

    // ------------------------------------------------------------ 请求底层

    /**
     * POST-as-GET（RFC 8555 §6.3）。
     *
     * ACME v2 里除了目录和 nonce，所有读取都要用带签名的空 POST，
     * 不能用 GET——这样服务端才知道是谁在读，能做访问控制。
     *
     * @param array<string, string> $headers
     */
    public function postAsGet(string $url, array $headers = []): Response
    {
        return $this->signedRequest($url, null, false, $headers);
    }

    /**
     * 发一个带 JWS 签名的请求，自动处理 badNonce。
     *
     * @param mixed $payload null 表示 POST-as-GET
     * @param bool $useJwk true 用 jwk 模式（只有 newAccount 与用证书私钥吊销时才需要）
     * @param array<string, string> $headers
     */
    public function signedRequest(string $url, $payload, bool $useJwk = false, array $headers = []): Response
    {
        $key = $this->getAccountKey();

        // badNonce 是服务端明确说「这个 nonce 我不认，换一个重来」，
        // 属于正常现象（nonce 有有效期，也可能被并发的另一个进程用掉了）。
        // 重试一次基本都能过，所以不该向上抛
        for ($attempt = 1; $attempt <= 2; ++$attempt) {
            $kid = $useJwk ? null : $this->accountUrl;

            if (!$useJwk && ($kid === null || $kid === '')) {
                throw new ProtocolException(
                    '还没有账户 URL，无法用 kid 模式签名。请先调用 registerAccount() 或 useAccount()'
                );
            }

            $body = Jws::signToJson($key, $url, $this->nonce->take(), $payload, $kid);

            $requestHeaders = array_merge(['Content-Type' => 'application/jose+json'], $headers);
            $response = $this->http->post($url, $body, $requestHeaders);

            $this->nonce->collect($response);

            if ($response->isSuccess()) {
                return $response;
            }

            $problem = $response->tryJson();
            if ($problem === null) {
                throw new ProtocolException(sprintf(
                    '%s 返回 HTTP %d，响应体不是 JSON：%s',
                    $url,
                    $response->getStatus(),
                    substr($response->getBody(), 0, 200)
                ));
            }

            $exception = ProtocolException::fromProblem($problem, $response->getStatus());

            if ($exception->isBadNonce() && $attempt === 1) {
                $this->logger->debug('nonce 被服务端拒绝，重取一个重放');
                $this->nonce->clear();
                continue;
            }

            throw $exception;
        }

        // 上面的循环要么 return 要么 throw，走不到这里
        throw new ProtocolException('签名请求进入了不该到达的分支');
    }

    /**
     * keyChange 的内层 JWS。
     *
     * 不走 Jws::sign() 是因为内层 protected header 里**只能有** alg、jwk、url
     * 三个字段，多一个 nonce 服务端就判 malformed。而 Jws::sign() 的 nonce 是必填的
     * ——给它开个可选参数会让所有正常调用点都多一个要考虑的东西，不划算，
     * 这里单独拼这一处反而更清楚。
     *
     * @param mixed $payload
     * @return array{protected: string, payload: string, signature: string}
     */
    private function signInnerKeyChange(KeyPair $newKey, string $url, $payload): array
    {
        $protected = Json::encode([
            'alg' => $newKey->getSignatureAlgorithm(),
            'jwk' => $newKey->getJwk(),
            'url' => $url,
        ]);

        $encodedProtected = \Mci\Acme\Crypto\Base64Url::encode($protected);
        $encodedPayload = \Mci\Acme\Crypto\Base64Url::encodeJson($payload);

        return [
            'protected' => $encodedProtected,
            'payload' => $encodedPayload,
            'signature' => \Mci\Acme\Crypto\Base64Url::encode(
                $newKey->signForJws($encodedProtected . '.' . $encodedPayload)
            ),
        ];
    }

    /** 链里的任何一张证书的 issuer CN 是不是目标根 */
    private function chainMatchesIssuer(string $chain, string $issuer): bool
    {
        foreach (Certificate::splitChain($chain) as $pem) {
            $info = @openssl_x509_parse($pem);
            if (!\is_array($info)) {
                continue;
            }

            foreach ([
                isset($info['issuer']['CN']) ? $info['issuer']['CN'] : '',
                isset($info['issuer']['O']) ? $info['issuer']['O'] : '',
                isset($info['subject']['CN']) ? $info['subject']['CN'] : '',
            ] as $candidate) {
                $value = \is_array($candidate) ? (string) $candidate[0] : (string) $candidate;
                if ($value !== '' && stripos($value, $issuer) !== false) {
                    return true;
                }
            }
        }

        return false;
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
