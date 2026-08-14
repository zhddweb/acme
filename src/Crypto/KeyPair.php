<?php

declare(strict_types=1);

namespace PhpAcme\Crypto;

use PhpAcme\Asn1\DerParser;
use PhpAcme\Exception\CryptoException;

/**
 * 一对非对称密钥，以及围绕它的签名、JWK、PEM 导入导出。
 *
 * 所有 openssl_* 调用都收在这个类里。原因是这些函数的错误处理方式在
 * PHP 7 和 8 之间不一致（7.x 是 warning + false，8.x 有些会抛），
 * 而且 openssl 的错误队列要主动 openssl_error_string() 排空，
 * 否则上一次操作的残留错误会被算到下一次头上。集中处理才管得住。
 */
class KeyPair
{
    // 与 acme.sh 的 --keylength 取值保持一致，用户迁移过来不用改习惯
    const TYPE_RSA_2048 = '2048';
    const TYPE_RSA_3072 = '3072';
    const TYPE_RSA_4096 = '4096';
    const TYPE_EC_256 = 'ec-256';
    const TYPE_EC_384 = 'ec-384';
    const TYPE_EC_521 = 'ec-521';

    const DEFAULT_TYPE = self::TYPE_EC_256;

    /** @var array<string, array{type: int, curve: string|null, bits: int|null, alg: string, hash: int, size: int}> */
    private static $specs = [
        self::TYPE_RSA_2048 => ['type' => OPENSSL_KEYTYPE_RSA, 'curve' => null, 'bits' => 2048, 'alg' => 'RS256', 'hash' => OPENSSL_ALGO_SHA256, 'size' => 0],
        self::TYPE_RSA_3072 => ['type' => OPENSSL_KEYTYPE_RSA, 'curve' => null, 'bits' => 3072, 'alg' => 'RS256', 'hash' => OPENSSL_ALGO_SHA256, 'size' => 0],
        self::TYPE_RSA_4096 => ['type' => OPENSSL_KEYTYPE_RSA, 'curve' => null, 'bits' => 4096, 'alg' => 'RS256', 'hash' => OPENSSL_ALGO_SHA256, 'size' => 0],
        // size 是 ECDSA 签名里 r/s 各自的定长字节数，等于 ceil(曲线位数/8)。
        // P-521 是 521 位不是 512，所以是 66 而不是 64——这个 1 字节的差
        // 是 ES512 实现最常见的 bug
        self::TYPE_EC_256 => ['type' => OPENSSL_KEYTYPE_EC, 'curve' => 'prime256v1', 'bits' => 256, 'alg' => 'ES256', 'hash' => OPENSSL_ALGO_SHA256, 'size' => 32],
        self::TYPE_EC_384 => ['type' => OPENSSL_KEYTYPE_EC, 'curve' => 'secp384r1', 'bits' => 384, 'alg' => 'ES384', 'hash' => OPENSSL_ALGO_SHA384, 'size' => 48],
        self::TYPE_EC_521 => ['type' => OPENSSL_KEYTYPE_EC, 'curve' => 'secp521r1', 'bits' => 521, 'alg' => 'ES512', 'hash' => OPENSSL_ALGO_SHA512, 'size' => 66],
    ];

    /** @var resource|\OpenSSLAsymmetricKey openssl 的私钥句柄 */
    private $key;

    /** @var string 上面几个 TYPE_* 之一 */
    private $type;

    /** @var array openssl_pkey_get_details() 的结果，缓存下来免得反复解析 */
    private $details;

    /**
     * @param resource|\OpenSSLAsymmetricKey $key
     */
    private function __construct($key, string $type, array $details)
    {
        $this->key = $key;
        $this->type = $type;
        $this->details = $details;
    }

    /** @return array<int, string> 支持的密钥类型 */
    public static function supportedTypes(): array
    {
        return array_keys(self::$specs);
    }

    /**
     * 把用户写的各种花样归一到内部类型名。
     *
     * acme.sh 里 `--keylength ec-256` 和 `--keylength 256` 都能用，
     * 还有人习惯写 `P-256`、`secp384r1`，这里全都认下来。
     */
    public static function normalizeType(string $type): string
    {
        $value = strtolower(trim($type));
        $value = str_replace(['_', ' '], '-', $value);

        $aliases = [
            'rsa-2048' => self::TYPE_RSA_2048, 'rsa2048' => self::TYPE_RSA_2048,
            'rsa-3072' => self::TYPE_RSA_3072, 'rsa3072' => self::TYPE_RSA_3072,
            'rsa-4096' => self::TYPE_RSA_4096, 'rsa4096' => self::TYPE_RSA_4096,
            'ec256' => self::TYPE_EC_256, '256' => self::TYPE_EC_256,
            'p-256' => self::TYPE_EC_256, 'prime256v1' => self::TYPE_EC_256,
            'secp256r1' => self::TYPE_EC_256, 'es256' => self::TYPE_EC_256,
            'ec384' => self::TYPE_EC_384, '384' => self::TYPE_EC_384,
            'p-384' => self::TYPE_EC_384, 'secp384r1' => self::TYPE_EC_384,
            'es384' => self::TYPE_EC_384,
            'ec521' => self::TYPE_EC_521, '521' => self::TYPE_EC_521,
            'ec-512' => self::TYPE_EC_521, 'ec512' => self::TYPE_EC_521,
            'p-521' => self::TYPE_EC_521, 'secp521r1' => self::TYPE_EC_521,
            'es512' => self::TYPE_EC_521,
        ];

        if (isset($aliases[$value])) {
            return $aliases[$value];
        }

        if (isset(self::$specs[$value])) {
            return $value;
        }

        throw new CryptoException(sprintf(
            '不支持的密钥类型「%s」，可用值：%s',
            $type,
            implode(', ', self::supportedTypes())
        ));
    }

    public static function isEcType(string $type): bool
    {
        $normalized = self::normalizeType($type);

        return self::$specs[$normalized]['type'] === OPENSSL_KEYTYPE_EC;
    }

    /**
     * 生成新密钥。
     */
    public static function generate(string $type = self::DEFAULT_TYPE): self
    {
        $type = self::normalizeType($type);
        $spec = self::$specs[$type];

        self::clearErrors();

        $config = ['private_key_type' => $spec['type']];
        if ($spec['type'] === OPENSSL_KEYTYPE_EC) {
            $config['curve_name'] = $spec['curve'];
        } else {
            $config['private_key_bits'] = $spec['bits'];
        }

        $key = @openssl_pkey_new($config);
        if ($key === false) {
            throw new CryptoException(sprintf(
                '生成 %s 密钥失败：%s。若是 EC 密钥，检查 openssl 是否编译了对应曲线',
                $type,
                self::lastError()
            ));
        }

        return new self($key, $type, self::readDetails($key));
    }

    /**
     * 从 PEM 私钥载入。
     *
     * 密钥类型是从 openssl 解析出的实际参数反推的，不看文件名也不信调用方传的值——
     * 用户可能把 ec-256 的 key 放在名叫 rsa 的文件里，按错误的类型去签会直接失败。
     */
    public static function fromPem(string $pem, ?string $passphrase = null): self
    {
        self::clearErrors();

        $key = $passphrase !== null && $passphrase !== ''
            ? @openssl_pkey_get_private($pem, $passphrase)
            : @openssl_pkey_get_private($pem);

        if ($key === false) {
            throw new CryptoException(sprintf(
                '私钥载入失败：%s。确认这是 PEM 格式的私钥，且没有加密（或已提供正确口令）',
                self::lastError()
            ));
        }

        $details = self::readDetails($key);

        return new self($key, self::detectType($details), $details);
    }

    /**
     * 从 details 反推类型。
     *
     * EC 看曲线名，RSA 看模数位数；位数不是标准值时向上取到最近的标准档，
     * 因为签名算法只跟哈希强度有关，2049 位的 key 一样用 RS256。
     */
    private static function detectType(array $details): string
    {
        if (!isset($details['type'])) {
            throw new CryptoException('无法判断密钥类型：openssl 没有返回 type 字段');
        }

        if ($details['type'] === OPENSSL_KEYTYPE_EC) {
            $curve = isset($details['ec']['curve_name']) ? (string) $details['ec']['curve_name'] : '';
            foreach (self::$specs as $name => $spec) {
                if ($spec['curve'] === $curve) {
                    return $name;
                }
            }

            throw new CryptoException(sprintf(
                '不支持的 EC 曲线「%s」，ACME 只接受 P-256 / P-384 / P-521',
                $curve !== '' ? $curve : '未知'
            ));
        }

        if ($details['type'] === OPENSSL_KEYTYPE_RSA) {
            $bits = isset($details['bits']) ? (int) $details['bits'] : 0;
            if ($bits < 2048) {
                throw new CryptoException(sprintf(
                    'RSA 密钥只有 %d 位，CA 一律要求至少 2048 位',
                    $bits
                ));
            }
            if ($bits >= 4096) {
                return self::TYPE_RSA_4096;
            }
            if ($bits >= 3072) {
                return self::TYPE_RSA_3072;
            }

            return self::TYPE_RSA_2048;
        }

        throw new CryptoException('不支持的密钥算法，ACME 只接受 RSA 与 EC');
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function isEc(): bool
    {
        return self::$specs[$this->type]['type'] === OPENSSL_KEYTYPE_EC;
    }

    public function isRsa(): bool
    {
        return !$this->isEc();
    }

    public function getBits(): int
    {
        return isset($this->details['bits']) ? (int) $this->details['bits'] : 0;
    }

    /** JWS 的 alg 值：RS256 / ES256 / ES384 / ES512 */
    public function getSignatureAlgorithm(): string
    {
        return self::$specs[$this->type]['alg'];
    }

    /** 证书与 CSR 用的签名算法 OID */
    public function getSignatureOid(): string
    {
        $map = [
            'RS256' => \PhpAcme\Asn1\Oid::SHA256_WITH_RSA,
            'ES256' => \PhpAcme\Asn1\Oid::ECDSA_WITH_SHA256,
            'ES384' => \PhpAcme\Asn1\Oid::ECDSA_WITH_SHA384,
            'ES512' => \PhpAcme\Asn1\Oid::ECDSA_WITH_SHA512,
        ];

        return $map[$this->getSignatureAlgorithm()];
    }

    /**
     * @return resource|\OpenSSLAsymmetricKey
     */
    public function getHandle()
    {
        return $this->key;
    }

    public function getPrivateKeyPem(?string $passphrase = null): string
    {
        self::clearErrors();

        $out = '';
        $ok = $passphrase !== null && $passphrase !== ''
            ? @openssl_pkey_export($this->key, $out, $passphrase)
            : @openssl_pkey_export($this->key, $out);

        if ($ok === false || $out === '') {
            throw new CryptoException('私钥导出失败：' . self::lastError());
        }

        return $out;
    }

    public function getPublicKeyPem(): string
    {
        if (!isset($this->details['key']) || !\is_string($this->details['key'])) {
            throw new CryptoException('公钥导出失败：openssl 没有返回公钥 PEM');
        }

        return $this->details['key'];
    }

    /**
     * SubjectPublicKeyInfo 的 DER 编码。
     *
     * 公钥 PEM 的 base64 主体本来就是 SPKI，直接解出来即可，
     * 不用自己按算法拼——省掉一堆 RSA/EC 分支，也不会拼错。
     */
    public function getSubjectPublicKeyInfo(): string
    {
        $pem = $this->getPublicKeyPem();

        if (preg_match('/-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----/s', $pem, $m) !== 1) {
            throw new CryptoException('公钥 PEM 格式不认识，取不到 SubjectPublicKeyInfo');
        }

        $der = base64_decode(preg_replace('/\s+/', '', $m[1]), true);
        if ($der === false) {
            throw new CryptoException('公钥 PEM 的 base64 解码失败');
        }

        return $der;
    }

    /**
     * 签名。
     *
     * 返回的是 openssl 的原生格式：RSA 是 PKCS#1 v1.5，EC 是 DER 编码的
     * SEQUENCE{r,s}。**JWS 不能直接用 EC 的这份**，要先转成定长 R||S，
     * 见 signForJws()。CSR 和 X.509 证书用的则正是这份 DER。
     */
    public function sign(string $data): string
    {
        self::clearErrors();

        $signature = '';
        $ok = @openssl_sign($data, $signature, $this->key, self::$specs[$this->type]['hash']);
        if ($ok === false) {
            throw new CryptoException('签名失败：' . self::lastError());
        }

        return $signature;
    }

    /**
     * 签出 JWS 要的格式。
     *
     * EC 这一步是必须的：JWS（RFC 7518 §3.4）规定签名是 R 与 S 各自左补零到
     * 曲线字节长后拼接，而 openssl 给的是 DER。直接把 DER 塞进 JWS，
     * 服务端一律回 "JWS verification error"，而且不会告诉你是格式问题。
     */
    public function signForJws(string $data): string
    {
        $signature = $this->sign($data);

        if ($this->isRsa()) {
            return $signature;
        }

        $parts = DerParser::parseEcdsaSignature($signature);
        $size = self::$specs[$this->type]['size'];

        return self::padLeft($parts[0], $size) . self::padLeft($parts[1], $size);
    }

    /** 验签，主要给测试用；正式流程里我们只签不验 */
    public function verify(string $data, string $signature): bool
    {
        self::clearErrors();

        $result = @openssl_verify($data, $signature, $this->getPublicKeyPem(), self::$specs[$this->type]['hash']);

        return $result === 1;
    }

    /**
     * JWK 表示（RFC 7517）。
     *
     * 字段顺序按 RFC 7638 的规定排好——thumbprint 是对这个 JSON 直接做 SHA-256，
     * 顺序不对算出来就是另一个值，http-01 与 dns-01 的校验值会全部对不上。
     *
     * @return array<string, string>
     */
    public function getJwk(): array
    {
        if ($this->isEc()) {
            if (!isset($this->details['ec']['x'], $this->details['ec']['y'])) {
                throw new CryptoException('取不到 EC 公钥坐标');
            }

            $size = self::$specs[$this->type]['size'];
            $curveNames = [
                self::TYPE_EC_256 => 'P-256',
                self::TYPE_EC_384 => 'P-384',
                self::TYPE_EC_521 => 'P-521',
            ];

            // openssl 返回的坐标可能因为去掉前导零而短于曲线长度，
            // JWK 要求定长，必须补齐
            return [
                'crv' => $curveNames[$this->type],
                'kty' => 'EC',
                'x' => Base64Url::encode(self::padLeft($this->details['ec']['x'], $size)),
                'y' => Base64Url::encode(self::padLeft($this->details['ec']['y'], $size)),
            ];
        }

        if (!isset($this->details['rsa']['n'], $this->details['rsa']['e'])) {
            throw new CryptoException('取不到 RSA 公钥参数');
        }

        return [
            'e' => Base64Url::encode($this->details['rsa']['e']),
            'kty' => 'RSA',
            'n' => Base64Url::encode($this->details['rsa']['n']),
        ];
    }

    /**
     * JWK Thumbprint（RFC 7638）。
     *
     * 规范要求：只保留必需字段、按字典序排、无空白的紧凑 JSON，再取 SHA-256。
     * getJwk() 返回的数组已经是按字典序建的，这里直接编码即可。
     */
    public function getThumbprint(): string
    {
        return Base64Url::encode(hash('sha256', \PhpAcme\Util\Json::encode($this->getJwk()), true));
    }

    /**
     * 左补零到指定长度。
     *
     * 已经够长就原样返回——EC 坐标理论上不会超长，真超了说明前面解析错了，
     * 这里截断只会把问题藏起来。
     */
    private static function padLeft(string $value, int $length): string
    {
        $current = \strlen($value);
        if ($current >= $length) {
            return $value;
        }

        return str_repeat("\x00", $length - $current) . $value;
    }

    /**
     * @param resource|\OpenSSLAsymmetricKey $key
     */
    private static function readDetails($key): array
    {
        $details = @openssl_pkey_get_details($key);
        if ($details === false) {
            throw new CryptoException('读取密钥参数失败：' . self::lastError());
        }

        return $details;
    }

    /**
     * 排空 openssl 的错误队列。
     *
     * 这个队列是全局累积的：上一次操作留下的错误如果不清，下一次失败时
     * openssl_error_string() 取到的会是那条旧的，排查时能把人绕进去。
     */
    private static function clearErrors(): void
    {
        while (openssl_error_string() !== false) {
            // 只是排空，内容不要
        }
    }

    private static function lastError(): string
    {
        $messages = [];
        while (($error = openssl_error_string()) !== false) {
            $messages[] = $error;
        }

        return $messages === [] ? '（openssl 没有给出原因）' : implode('; ', array_reverse($messages));
    }
}
