<?php

declare(strict_types=1);

namespace Mci\Acme\Exception;

/**
 * ACME 服务端返回了 problem document（RFC 7807）。
 *
 * type 是判断该怎么处理的依据，比如 urn:ietf:params:acme:error:badNonce
 * 要重放、rateLimited 要退避，所以单独存出来而不是只留一句 message。
 */
class ProtocolException extends AcmeException
{
    /** @var string */
    private $type;

    /** @var string */
    private $detail;

    /** @var int */
    private $status;

    /** @var array 子问题列表，一次提交多个域名时服务端会逐个报错 */
    private $subproblems;

    public function __construct(
        string $message,
        string $type = '',
        string $detail = '',
        int $status = 0,
        array $subproblems = [],
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, 0, $previous);
        $this->type = $type;
        $this->detail = $detail;
        $this->status = $status;
        $this->subproblems = $subproblems;
    }

    /**
     * 从服务端返回的 problem document 构造异常。
     *
     * @param array $problem 解析后的 JSON
     */
    public static function fromProblem(array $problem, int $httpStatus = 0): self
    {
        $type = isset($problem['type']) ? (string) $problem['type'] : 'about:blank';
        $detail = isset($problem['detail']) ? (string) $problem['detail'] : '';
        $title = isset($problem['title']) ? (string) $problem['title'] : '';

        $subproblems = [];
        if (isset($problem['subproblems']) && \is_array($problem['subproblems'])) {
            $subproblems = $problem['subproblems'];
        }

        // 把 urn:ietf:params:acme:error:xxx 里的 xxx 拎出来放在最前面，
        // 用户看日志第一眼就知道是哪类错误
        $short = self::shortType($type);
        $message = $short !== '' ? sprintf('ACME 服务端返回错误 [%s]', $short) : 'ACME 服务端返回错误';
        if ($detail !== '') {
            $message .= '：' . $detail;
        } elseif ($title !== '') {
            $message .= '：' . $title;
        }

        foreach ($subproblems as $sub) {
            if (!\is_array($sub)) {
                continue;
            }
            $identifier = '';
            if (isset($sub['identifier']['value'])) {
                $identifier = (string) $sub['identifier']['value'];
            }
            $subDetail = isset($sub['detail']) ? (string) $sub['detail'] : '';
            $message .= sprintf("\n  - %s: %s", $identifier !== '' ? $identifier : '(无域名)', $subDetail);
        }

        return new self($message, $type, $detail, $httpStatus, $subproblems);
    }

    /** 取 urn 末段，about:blank 之类非 ACME urn 原样返回空串 */
    public static function shortType(string $type): string
    {
        $prefix = 'urn:ietf:params:acme:error:';
        if (str_starts_with($type, $prefix)) {
            return substr($type, \strlen($prefix));
        }

        return '';
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getDetail(): string
    {
        return $this->detail;
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    public function getSubproblems(): array
    {
        return $this->subproblems;
    }

    /** nonce 过期，重取一个重放即可，不算真失败 */
    public function isBadNonce(): bool
    {
        return self::shortType($this->type) === 'badNonce';
    }

    /** 撞到 CA 的速率限制，重试也没用，得等 */
    public function isRateLimited(): bool
    {
        return self::shortType($this->type) === 'rateLimited';
    }

    /** 账户已存在（newAccount 带 onlyReturnExisting 时会遇到） */
    public function isAccountDoesNotExist(): bool
    {
        return self::shortType($this->type) === 'accountDoesNotExist';
    }
}
