<?php

declare(strict_types=1);

namespace Mci\Acme\Tests;

use Mci\Acme\Asn1\DerParser;
use Mci\Acme\Crypto\Base64Url;
use Mci\Acme\Crypto\Certificate;
use Mci\Acme\Crypto\Csr;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Crypto\SelfSignedCertificate;
use Mci\Acme\Http\Request;
use Mci\Acme\Http\Response;
use Mci\Acme\Http\Transport\MockTransport;
use Mci\Acme\Util\Json;

/**
 * 假的 ACME 服务端，跑在 MockTransport 之上。
 *
 * 这不是「返回几个写死的 JSON」那种敷衍的桩：它**真的验证 JWS 签名**、
 * 真的检查 nonce 有没有被重放、真的按状态机推进订单，最后用一把测试 CA 密钥
 * 给提交上来的 CSR 签一张真证书。
 *
 * 这么做的理由：签名格式、nonce 处理、状态机流转恰恰是这类客户端最容易写错
 * 又最难排查的地方——真去打 Let's Encrypt 的 staging 只会换回一句
 * "JWS verification error"，而这里能明确告诉你是哪一步的哪个字段不对。
 */
class FakeAcmeServer
{
    const BASE = 'https://acme.test/';

    /** @var MockTransport */
    private $transport;

    /** @var KeyPair 假 CA 的签发密钥 */
    private $caKey;

    /** @var array<string, bool> 发出去还没被用掉的 nonce */
    private $nonces = [];

    /** @var array<string, bool> 已经用过的 nonce，用来检测重放 */
    private $usedNonces = [];

    /** @var array<string, array> 账户 URL => 账户数据 */
    private $accounts = [];

    /** @var array<string, array<string, string>> 账户 URL => JWK */
    private $accountKeys = [];

    /** @var array<string, array> 订单 URL => 订单数据 */
    private $orders = [];

    /** @var array<string, array> 授权 URL => 授权数据 */
    private $authorizations = [];

    /** @var array<string, array> 挑战 URL => 挑战数据 */
    private $challenges = [];

    /** @var array<string, string> 证书 URL => PEM 链 */
    private $certificates = [];

    /** @var int 自增计数，用来编 URL */
    private $counter = 0;

    /** @var array<int, array{url: string, header: array, payload: array|null}> 收到过的每一个请求，供断言 */
    private $log = [];

    /** @var bool 是否要求 EAB */
    private $requireEab = false;

    /** @var bool 下一次挑战验证是否判失败 */
    private $failNextChallenge = false;

    /** @var string 挑战失败时给的原因 */
    private $challengeFailureDetail = '模拟的验证失败';

    /** @var bool 是否在下一次签名请求上回一次 badNonce（测重放逻辑） */
    private $injectBadNonce = false;

    /** @var array<int, string> 服务端认可的挑战类型 */
    private $challengeTypes = ['http-01', 'dns-01', 'tls-alpn-01'];

    public function __construct(?KeyPair $caKey = null)
    {
        $this->caKey = $caKey !== null ? $caKey : KeyPair::generate(KeyPair::TYPE_EC_256);
        $this->transport = new MockTransport();
        $this->registerRoutes();
    }

    public function getTransport(): MockTransport
    {
        return $this->transport;
    }

    public function getDirectoryUrl(): string
    {
        return self::BASE . 'directory';
    }

    public function setRequireEab(bool $require): void
    {
        $this->requireEab = $require;
    }

    public function failNextChallenge(string $detail = '模拟的验证失败'): void
    {
        $this->failNextChallenge = true;
        $this->challengeFailureDetail = $detail;
    }

    public function injectBadNonce(): void
    {
        $this->injectBadNonce = true;
    }

    /**
     * @param array<int, string> $types
     */
    public function setChallengeTypes(array $types): void
    {
        $this->challengeTypes = $types;
    }

    /** @return array<int, array{url: string, header: array, payload: array|null}> */
    public function getLog(): array
    {
        return $this->log;
    }

    /** @return array<int, array> 发往某个 URL 的请求的 payload */
    public function getPayloadsFor(string $urlSuffix): array
    {
        $out = [];
        foreach ($this->log as $entry) {
            if (str_ends_with($entry['url'], $urlSuffix) || str_contains($entry['url'], $urlSuffix)) {
                $out[] = $entry['payload'];
            }
        }

        return $out;
    }

    public function getAccountCount(): int
    {
        return \count($this->accounts);
    }

    private function registerRoutes(): void
    {
        $server = $this;

        $this->transport->onUrl('GET', self::BASE . 'directory', static function () use ($server): Response {
            return $server->directoryResponse();
        });

        $this->transport->on(
            static function (Request $request): bool {
                return $request->getUrl() === self::BASE . 'new-nonce';
            },
            static function () use ($server): Response {
                return new Response(200, ['Replay-Nonce' => $server->issueNonce()]);
            }
        );

        // 其余全部走签名请求的统一入口
        $this->transport->setFallback(static function (Request $request) use ($server): Response {
            return $server->handleSigned($request);
        });
    }

    private function directoryResponse(): Response
    {
        $meta = [
            'termsOfService' => self::BASE . 'terms',
            'website' => 'https://acme.test',
        ];

        if ($this->requireEab) {
            $meta['externalAccountRequired'] = true;
        }

        return new Response(
            200,
            ['Content-Type' => 'application/json', 'Replay-Nonce' => $this->issueNonce()],
            Json::encode([
                'newNonce' => self::BASE . 'new-nonce',
                'newAccount' => self::BASE . 'new-account',
                'newOrder' => self::BASE . 'new-order',
                'revokeCert' => self::BASE . 'revoke-cert',
                'keyChange' => self::BASE . 'key-change',
                'meta' => $meta,
            ])
        );
    }

    public function issueNonce(): string
    {
        $nonce = 'nonce-' . bin2hex(random_bytes(8));
        $this->nonces[$nonce] = true;

        return $nonce;
    }

    /**
     * 所有签名请求的总入口：先验签，再按 URL 分发。
     */
    private function handleSigned(Request $request): Response
    {
        $url = $request->getUrl();
        $body = (string) $request->getBody();

        $jws = Json::tryDecode($body);
        if ($jws === null || !isset($jws['protected'], $jws['payload'], $jws['signature'])) {
            return $this->problem(400, 'malformed', '请求体不是合法的 JWS');
        }

        $header = Json::decode(Base64Url::decode($jws['protected']));

        // url 必须与实际请求地址完全一致，这是协议的硬要求
        if (!isset($header['url']) || $header['url'] !== $url) {
            return $this->problem(400, 'unauthorized', sprintf(
                'JWS 头里的 url 是 %s，与实际请求的 %s 不符',
                isset($header['url']) ? $header['url'] : '(缺失)',
                $url
            ));
        }

        if ($this->injectBadNonce) {
            $this->injectBadNonce = false;

            return $this->problem(400, 'badNonce', '模拟的 nonce 失效');
        }

        $nonceError = $this->checkNonce($header);
        if ($nonceError !== null) {
            return $nonceError;
        }

        // jwk 与 kid 只能有一个
        if (isset($header['jwk'], $header['kid'])) {
            return $this->problem(400, 'malformed', 'jwk 与 kid 不能同时出现');
        }

        $jwk = $this->resolveJwk($header);
        if ($jwk === null) {
            return $this->problem(400, 'accountDoesNotExist', '找不到对应的账户');
        }

        if (!$this->verifySignature($jws, $header, $jwk)) {
            return $this->problem(400, 'malformed', 'JWS 签名校验失败');
        }

        $payload = $jws['payload'] === '' ? null : Json::tryDecode(Base64Url::decode($jws['payload']));

        $this->log[] = ['url' => $url, 'header' => $header, 'payload' => $payload];

        return $this->route($url, $payload, $header, $jwk);
    }

    /**
     * @param array $header
     */
    private function checkNonce(array $header): ?Response
    {
        if (!isset($header['nonce'])) {
            return $this->problem(400, 'badNonce', 'JWS 头里没有 nonce');
        }

        $nonce = (string) $header['nonce'];

        if (isset($this->usedNonces[$nonce])) {
            return $this->problem(400, 'badNonce', 'nonce 被重复使用了');
        }

        if (!isset($this->nonces[$nonce])) {
            return $this->problem(400, 'badNonce', '未知的 nonce');
        }

        unset($this->nonces[$nonce]);
        $this->usedNonces[$nonce] = true;

        return null;
    }

    /**
     * @param array $header
     * @return array<string, string>|null
     */
    private function resolveJwk(array $header): ?array
    {
        if (isset($header['jwk']) && \is_array($header['jwk'])) {
            return $header['jwk'];
        }

        if (isset($header['kid']) && isset($this->accountKeys[(string) $header['kid']])) {
            return $this->accountKeys[(string) $header['kid']];
        }

        return null;
    }

    /**
     * 真正验一遍签名。
     *
     * @param array $jws
     * @param array $header
     * @param array<string, string> $jwk
     */
    private function verifySignature(array $jws, array $header, array $jwk): bool
    {
        $signingInput = $jws['protected'] . '.' . $jws['payload'];
        $signature = Base64Url::decode($jws['signature']);

        $publicKeyPem = $this->jwkToPem($jwk);
        if ($publicKeyPem === null) {
            return false;
        }

        $alg = isset($header['alg']) ? (string) $header['alg'] : '';

        $algorithms = [
            'RS256' => OPENSSL_ALGO_SHA256,
            'ES256' => OPENSSL_ALGO_SHA256,
            'ES384' => OPENSSL_ALGO_SHA384,
            'ES512' => OPENSSL_ALGO_SHA512,
        ];

        if (!isset($algorithms[$alg])) {
            return false;
        }

        // EC 的签名在 JWS 里是定长 R||S，openssl_verify 要 DER，转一下
        if ($alg !== 'RS256') {
            $length = \strlen($signature);
            if ($length % 2 !== 0) {
                return false;
            }
            $half = intdiv($length, 2);
            $signature = DerParser::encodeEcdsaSignature(
                substr($signature, 0, $half),
                substr($signature, $half)
            );
        }

        return @openssl_verify($signingInput, $signature, $publicKeyPem, $algorithms[$alg]) === 1;
    }

    /**
     * JWK 转 PEM 公钥。
     *
     * 自己拼 SubjectPublicKeyInfo 的 DER：PHP 没有从 JWK 直接建公钥的 API，
     * 而这一步恰好复用了本库的 ASN.1 编码器——顺带也验证了它。
     *
     * @param array<string, string> $jwk
     */
    private function jwkToPem(array $jwk): ?string
    {
        if (!isset($jwk['kty'])) {
            return null;
        }

        if ($jwk['kty'] === 'EC') {
            if (!isset($jwk['crv'], $jwk['x'], $jwk['y'])) {
                return null;
            }

            $curves = [
                'P-256' => \Mci\Acme\Asn1\Oid::PRIME256V1,
                'P-384' => \Mci\Acme\Asn1\Oid::SECP384R1,
                'P-521' => \Mci\Acme\Asn1\Oid::SECP521R1,
            ];

            if (!isset($curves[$jwk['crv']])) {
                return null;
            }

            $point = "\x04" . Base64Url::decode($jwk['x']) . Base64Url::decode($jwk['y']);

            $spki = \Mci\Acme\Asn1\Der::sequence(
                \Mci\Acme\Asn1\Der::sequence(
                    \Mci\Acme\Asn1\Der::oid(\Mci\Acme\Asn1\Oid::EC_PUBLIC_KEY),
                    \Mci\Acme\Asn1\Der::oid($curves[$jwk['crv']])
                ),
                \Mci\Acme\Asn1\Der::bitString($point)
            );

            return $this->derToPem($spki);
        }

        if ($jwk['kty'] === 'RSA') {
            if (!isset($jwk['n'], $jwk['e'])) {
                return null;
            }

            $rsaKey = \Mci\Acme\Asn1\Der::sequence(
                \Mci\Acme\Asn1\Der::integer(Base64Url::decode($jwk['n'])),
                \Mci\Acme\Asn1\Der::integer(Base64Url::decode($jwk['e']))
            );

            $spki = \Mci\Acme\Asn1\Der::sequence(
                \Mci\Acme\Asn1\Der::algorithmIdentifier(
                    \Mci\Acme\Asn1\Oid::RSA_ENCRYPTION,
                    \Mci\Acme\Asn1\Der::null()
                ),
                \Mci\Acme\Asn1\Der::bitString($rsaKey)
            );

            return $this->derToPem($spki);
        }

        return null;
    }

    private function derToPem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * @param array|null $payload
     * @param array $header
     * @param array<string, string> $jwk
     */
    private function route(string $url, ?array $payload, array $header, array $jwk): Response
    {
        if ($url === self::BASE . 'new-account') {
            return $this->newAccount($payload, $jwk);
        }

        if ($url === self::BASE . 'new-order') {
            return $this->newOrder($payload, (string) $header['kid']);
        }

        if ($url === self::BASE . 'revoke-cert') {
            return $this->ok([]);
        }

        if ($url === self::BASE . 'key-change') {
            return $this->ok(['status' => 'valid']);
        }

        if (isset($this->orders[$url])) {
            return $this->ok($this->orders[$url]);
        }

        if (isset($this->authorizations[$url])) {
            return $this->ok($this->authorizations[$url]);
        }

        if (isset($this->challenges[$url])) {
            return $this->handleChallenge($url, $payload);
        }

        if (str_ends_with($url, '/finalize')) {
            return $this->finalize($url, $payload);
        }

        if (isset($this->certificates[$url])) {
            return new Response(
                200,
                ['Content-Type' => 'application/pem-certificate-chain', 'Replay-Nonce' => $this->issueNonce()],
                $this->certificates[$url]
            );
        }

        if (isset($this->accounts[$url])) {
            return $this->ok($this->accounts[$url]);
        }

        return $this->problem(404, 'malformed', sprintf('未知的端点：%s', $url));
    }

    /**
     * @param array|null $payload
     * @param array<string, string> $jwk
     */
    private function newAccount(?array $payload, array $jwk): Response
    {
        // 同一把密钥重复注册要返回同一个账户，这是协议要求的幂等性
        foreach ($this->accountKeys as $accountUrl => $existing) {
            if ($existing === $jwk) {
                return new Response(
                    200,
                    ['Location' => $accountUrl, 'Replay-Nonce' => $this->issueNonce(), 'Content-Type' => 'application/json'],
                    Json::encode($this->accounts[$accountUrl])
                );
            }
        }

        if ($payload !== null && isset($payload['onlyReturnExisting']) && $payload['onlyReturnExisting'] === true) {
            return $this->problem(400, 'accountDoesNotExist', '这把密钥还没注册过');
        }

        if ($this->requireEab && ($payload === null || !isset($payload['externalAccountBinding']))) {
            return $this->problem(403, 'externalAccountRequired', '本 CA 需要 External Account Binding');
        }

        $accountUrl = self::BASE . 'acct/' . (++$this->counter);

        $account = [
            'status' => 'valid',
            'contact' => $payload !== null && isset($payload['contact']) ? $payload['contact'] : [],
            'orders' => $accountUrl . '/orders',
            'createdAt' => gmdate('c'),
        ];

        $this->accounts[$accountUrl] = $account;
        $this->accountKeys[$accountUrl] = $jwk;

        return new Response(
            201,
            ['Location' => $accountUrl, 'Replay-Nonce' => $this->issueNonce(), 'Content-Type' => 'application/json'],
            Json::encode($account)
        );
    }

    /**
     * @param array|null $payload
     */
    private function newOrder(?array $payload, string $accountUrl): Response
    {
        if ($payload === null || !isset($payload['identifiers'])) {
            return $this->problem(400, 'malformed', '订单里没有 identifiers');
        }

        $orderId = ++$this->counter;
        $orderUrl = self::BASE . 'order/' . $orderId;

        $authorizationUrls = [];

        foreach ($payload['identifiers'] as $identifier) {
            $value = (string) $identifier['value'];
            $isWildcard = str_starts_with($value, '*.');
            $bare = $isWildcard ? substr($value, 2) : $value;

            $authId = ++$this->counter;
            $authUrl = self::BASE . 'authz/' . $authId;

            $challenges = [];
            foreach ($this->challengeTypes as $type) {
                // 通配符只给 dns-01，和真实 CA 的行为一致
                if ($isWildcard && $type !== 'dns-01') {
                    continue;
                }

                $challengeUrl = self::BASE . 'chall/' . (++$this->counter);
                $challenge = [
                    'type' => $type,
                    'url' => $challengeUrl,
                    'status' => 'pending',
                    'token' => 'token-' . bin2hex(random_bytes(8)),
                ];

                $this->challenges[$challengeUrl] = $challenge + ['_authz' => $authUrl];
                $challenges[] = $challenge;
            }

            $authorization = [
                'status' => 'pending',
                'expires' => gmdate('c', time() + 3600),
                'identifier' => ['type' => 'dns', 'value' => $bare],
                'challenges' => $challenges,
                '_order' => $orderUrl,
            ];

            if ($isWildcard) {
                $authorization['wildcard'] = true;
            }

            $this->authorizations[$authUrl] = $authorization;
            $authorizationUrls[] = $authUrl;
        }

        $order = [
            'status' => 'pending',
            'expires' => gmdate('c', time() + 3600),
            'identifiers' => $payload['identifiers'],
            'authorizations' => $authorizationUrls,
            'finalize' => $orderUrl . '/finalize',
        ];

        $this->orders[$orderUrl] = $order;

        return new Response(
            201,
            ['Location' => $orderUrl, 'Replay-Nonce' => $this->issueNonce(), 'Content-Type' => 'application/json'],
            Json::encode($order)
        );
    }

    /**
     * @param array|null $payload
     */
    private function handleChallenge(string $url, ?array $payload): Response
    {
        $challenge = $this->challenges[$url];

        // payload 是 {} 表示客户端在通知「来验吧」；null 是 POST-as-GET，只读状态
        if ($payload !== null) {
            if ($this->failNextChallenge) {
                $this->failNextChallenge = false;

                $challenge['status'] = 'invalid';
                $challenge['error'] = [
                    'type' => 'urn:ietf:params:acme:error:unauthorized',
                    'detail' => $this->challengeFailureDetail,
                ];

                $this->challenges[$url] = $challenge;
                $this->markAuthorization($challenge['_authz'], 'invalid');
            } else {
                $challenge['status'] = 'valid';
                $challenge['validated'] = gmdate('c');
                $this->challenges[$url] = $challenge;
                $this->markAuthorization($challenge['_authz'], 'valid');
            }
        }

        $public = $challenge;
        unset($public['_authz']);

        return $this->ok($public);
    }

    private function markAuthorization(string $authUrl, string $status): void
    {
        if (!isset($this->authorizations[$authUrl])) {
            return;
        }

        $authorization = $this->authorizations[$authUrl];
        $authorization['status'] = $status;

        // 授权里的挑战副本也要同步，客户端可能重新拉授权来看
        foreach ($authorization['challenges'] as $index => $challenge) {
            if (isset($this->challenges[$challenge['url']])) {
                $stored = $this->challenges[$challenge['url']];
                unset($stored['_authz']);
                $authorization['challenges'][$index] = $stored;
            }
        }

        $this->authorizations[$authUrl] = $authorization;

        $this->refreshOrder($authorization['_order']);
    }

    /**
     * 所有授权都 valid 时订单转 ready；任一 invalid 则订单 invalid。
     */
    private function refreshOrder(string $orderUrl): void
    {
        if (!isset($this->orders[$orderUrl])) {
            return;
        }

        $order = $this->orders[$orderUrl];

        $allValid = true;
        foreach ($order['authorizations'] as $authUrl) {
            $status = $this->authorizations[$authUrl]['status'];

            if ($status === 'invalid') {
                $order['status'] = 'invalid';
                $order['error'] = [
                    'type' => 'urn:ietf:params:acme:error:unauthorized',
                    'detail' => '有域名没能通过验证',
                ];
                $this->orders[$orderUrl] = $order;

                return;
            }

            if ($status !== 'valid') {
                $allValid = false;
            }
        }

        if ($allValid && $order['status'] === 'pending') {
            $order['status'] = 'ready';
        }

        $this->orders[$orderUrl] = $order;
    }

    /**
     * @param array|null $payload
     */
    private function finalize(string $url, ?array $payload): Response
    {
        $orderUrl = substr($url, 0, -\strlen('/finalize'));

        if (!isset($this->orders[$orderUrl])) {
            return $this->problem(404, 'malformed', '订单不存在');
        }

        $order = $this->orders[$orderUrl];

        if ($order['status'] !== 'ready') {
            return $this->problem(403, 'orderNotReady', sprintf(
                '订单当前状态是 %s，不能提交 CSR',
                $order['status']
            ));
        }

        if ($payload === null || !isset($payload['csr'])) {
            return $this->problem(400, 'malformed', '没有提交 CSR');
        }

        $csrDer = Base64Url::decode((string) $payload['csr']);

        // 核对 CSR 里的域名与订单一致——真实 CA 会做这个检查，
        // 我们这里做是为了验证客户端生成的 CSR 确实带了正确的 SAN
        $csrDomains = Csr::extractDomains($csrDer);
        $orderDomains = [];
        foreach ($order['identifiers'] as $identifier) {
            $orderDomains[] = strtolower((string) $identifier['value']);
        }

        sort($csrDomains, SORT_STRING);
        sort($orderDomains, SORT_STRING);

        if ($csrDomains !== $orderDomains) {
            return $this->problem(400, 'badCSR', sprintf(
                'CSR 里的域名（%s）与订单（%s）对不上',
                implode(',', $csrDomains),
                implode(',', $orderDomains)
            ));
        }

        $certificateUrl = self::BASE . 'cert/' . (++$this->counter);
        $this->certificates[$certificateUrl] = $this->signCertificate($csrDer, $orderDomains);

        $order['status'] = 'valid';
        $order['certificate'] = $certificateUrl;
        $this->orders[$orderUrl] = $order;

        return new Response(
            200,
            ['Location' => $orderUrl, 'Replay-Nonce' => $this->issueNonce(), 'Content-Type' => 'application/json'],
            Json::encode($order)
        );
    }

    /**
     * 用假 CA 的密钥给 CSR 签一张证书，再附一张假的中间 CA，凑成两级链。
     *
     * 关键在于**证书里的公钥必须取自 CSR**，不能拿 CA 自己的公钥凑数——
     * 否则签出来的证书和客户端的私钥对不上，而「私钥与证书是否配对」
     * 正是测试要验的东西之一。
     *
     * @param array<int, string> $domains
     */
    private function signCertificate(string $csrDer, array $domains): string
    {
        $leaf = $this->buildCertificate($this->extractSpki($csrDer), $domains, 90 * 86400);
        $intermediate = SelfSignedCertificate::forPlaceholder(
            $this->caKey,
            ['fake-intermediate.acme.test'],
            365 * 86400
        );

        return $leaf . $intermediate;
    }

    /**
     * 从 CSR 里取出 SubjectPublicKeyInfo 的完整 TLV。
     *
     * CertificationRequest ::= SEQUENCE {
     *     CertificationRequestInfo ::= SEQUENCE { version, subject, SPKI, attributes },
     *     signatureAlgorithm, signature }
     *
     * 所以路径是：外层 SEQUENCE -> 第一个成员 -> 跳过 version 与 subject -> 第三个成员。
     */
    private function extractSpki(string $csrDer): string
    {
        $offset = 0;
        $outer = DerParser::readTlv($csrDer, $offset);

        $inner = 0;
        $info = DerParser::readTlv($outer['content'], $inner);

        $cursor = 0;
        DerParser::readTlv($info['content'], $cursor);
        DerParser::readTlv($info['content'], $cursor);

        $start = $cursor;
        DerParser::readTlv($info['content'], $cursor);

        return substr($info['content'], $start, $cursor - $start);
    }

    /**
     * 拼一张 X.509 证书：主体公钥来自参数，签名用假 CA 的密钥。
     *
     * @param array<int, string> $domains
     */
    private function buildCertificate(string $spki, array $domains, int $lifetime): string
    {
        $der = \Mci\Acme\Asn1\Der::class;

        $generalNames = [];
        foreach ($domains as $domain) {
            $generalNames[] = $der::implicitContext(2, $domain, false);
        }

        $subject = $der::sequence(
            $der::set($der::sequence(
                $der::oid(\Mci\Acme\Asn1\Oid::COMMON_NAME),
                $der::utf8String($domains[0])
            ))
        );

        $issuer = $der::sequence(
            $der::set($der::sequence(
                $der::oid(\Mci\Acme\Asn1\Oid::COMMON_NAME),
                $der::utf8String('Fake ACME Test CA')
            ))
        );

        $algorithm = $this->caKey->isRsa()
            ? $der::algorithmIdentifier($this->caKey->getSignatureOid(), $der::null())
            : $der::algorithmIdentifier($this->caKey->getSignatureOid());

        $now = time();

        $tbs = $der::sequence(
            $der::explicitContext(0, $der::integerFromInt(2)),
            $der::integer(random_bytes(8)),
            $algorithm,
            $issuer,
            $der::sequence($der::time($now - 300), $der::time($now + $lifetime)),
            $subject,
            $spki,
            $der::explicitContext(3, $der::sequence(
                $der::sequence(
                    $der::oid(\Mci\Acme\Asn1\Oid::SUBJECT_ALT_NAME),
                    $der::octetString($der::sequence(...$generalNames))
                )
            ))
        );

        return Certificate::derToPem(
            $der::sequence($tbs, $algorithm, $der::bitString($this->caKey->sign($tbs)))
        );
    }

    /**
     * @param array $data
     */
    private function ok(array $data): Response
    {
        return new Response(
            200,
            ['Content-Type' => 'application/json', 'Replay-Nonce' => $this->issueNonce()],
            Json::encode($data)
        );
    }

    private function problem(int $status, string $type, string $detail): Response
    {
        return new Response(
            $status,
            ['Content-Type' => 'application/problem+json', 'Replay-Nonce' => $this->issueNonce()],
            Json::encode([
                'type' => 'urn:ietf:params:acme:error:' . $type,
                'detail' => $detail,
                'status' => $status,
            ])
        );
    }

    /** 取出签发的证书链，测试里用来对比 */
    public function getIssuedCertificate(): ?string
    {
        if ($this->certificates === []) {
            return null;
        }

        $values = array_values($this->certificates);

        return $values[\count($values) - 1];
    }

    /** 假 CA 的证书，用于校验签发出来的证书确实是它签的 */
    public function getCaCertificate(): Certificate
    {
        return Certificate::fromPem(SelfSignedCertificate::forPlaceholder($this->caKey, ['fake-ca.acme.test']));
    }
}
