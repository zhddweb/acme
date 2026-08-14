<?php

declare(strict_types=1);

namespace PhpAcme\Service;

use PhpAcme\Crypto\Certificate;

/**
 * 一次签发的结果。
 *
 * `skipped` 是个重要状态：证书还没到续期时间时，本次调用什么都没做
 * ——不是失败，也不是成功签发。cron 里每天跑一次的场景下，
 * 绝大多数调用都会是 skipped，通知钩子要靠它来决定该不该发消息。
 */
class IssueResult
{
    /** @var bool */
    private $issued;

    /** @var bool */
    private $skipped;

    /** @var string */
    private $mainDomain;

    /** @var array<int, string> */
    private $domains;

    /** @var Certificate|null */
    private $certificate;

    /** @var array<string, string> 各文件的落盘路径 */
    private $paths;

    /** @var string 说明性文字，给日志和通知用 */
    private $message;

    /**
     * @param array<int, string> $domains
     * @param array<string, string> $paths
     */
    public function __construct(
        bool $issued,
        bool $skipped,
        string $mainDomain,
        array $domains,
        ?Certificate $certificate,
        array $paths,
        string $message
    ) {
        $this->issued = $issued;
        $this->skipped = $skipped;
        $this->mainDomain = $mainDomain;
        $this->domains = $domains;
        $this->certificate = $certificate;
        $this->paths = $paths;
        $this->message = $message;
    }

    /**
     * @param array<int, string> $domains
     * @param array<string, string> $paths
     */
    public static function issued(
        string $mainDomain,
        array $domains,
        Certificate $certificate,
        array $paths,
        string $message = ''
    ): self {
        return new self(
            true,
            false,
            $mainDomain,
            $domains,
            $certificate,
            $paths,
            $message !== '' ? $message : sprintf('证书已签发，%d 天后到期', $certificate->getDaysUntilExpiry())
        );
    }

    /**
     * @param array<int, string> $domains
     * @param array<string, string> $paths
     */
    public static function skipped(
        string $mainDomain,
        array $domains,
        ?Certificate $certificate,
        array $paths,
        string $message
    ): self {
        return new self(false, true, $mainDomain, $domains, $certificate, $paths, $message);
    }

    public function isIssued(): bool
    {
        return $this->issued;
    }

    public function isSkipped(): bool
    {
        return $this->skipped;
    }

    public function getMainDomain(): string
    {
        return $this->mainDomain;
    }

    /** @return array<int, string> */
    public function getDomains(): array
    {
        return $this->domains;
    }

    public function getCertificate(): ?Certificate
    {
        return $this->certificate;
    }

    /** @return array<string, string> */
    public function getPaths(): array
    {
        return $this->paths;
    }

    public function getPath(string $name): ?string
    {
        return isset($this->paths[$name]) ? $this->paths[$name] : null;
    }

    public function getMessage(): string
    {
        return $this->message;
    }
}
