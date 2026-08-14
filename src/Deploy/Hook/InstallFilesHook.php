<?php

declare(strict_types=1);

namespace PhpAcme\Deploy\Hook;

use PhpAcme\Deploy\DeployHookInterface;
use PhpAcme\Exception\DeployException;
use PhpAcme\Service\IssueResult;
use PhpAcme\Util\Filesystem;
use PhpAcme\Util\Logger;

/**
 * 把证书文件安装到指定路径（对应 acme.sh 的 --install-cert）。
 *
 * 为什么不让用户直接引用 ~/.php-acme 下的原始文件：
 *
 * 1. 那个目录权限是 0700，nginx 的 worker 用户读不到；
 * 2. 续期时原文件会被替换，某些服务持有的是 inode 而不是路径；
 * 3. 把证书目录和服务配置解耦，换 ACME 客户端时不用改 nginx 配置。
 *
 * 写入用的是原子替换，nginx 正在 reload 时也不会读到半截文件。
 */
class InstallFilesHook implements DeployHookInterface
{
    /** @var array<string, string> 源类型（key/cert/ca/fullchain）=> 目标路径 */
    private $targets;

    /** @var Filesystem */
    private $filesystem;

    /** @var Logger */
    private $logger;

    /** @var int 私钥落到目标位置时的权限 */
    private $keyMode = 0640;

    /** @var string|null 目标文件的属主，形如 "nginx" 或 "nginx:nginx" */
    private $owner;

    /**
     * @param array<string, string> $targets
     */
    public function __construct(array $targets, ?Logger $logger = null, ?Filesystem $filesystem = null)
    {
        $this->targets = $targets;
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->filesystem = $filesystem !== null ? $filesystem : new Filesystem();
    }

    public function getName(): string
    {
        return '安装证书文件';
    }

    public function setKeyMode(int $mode): void
    {
        $this->keyMode = $mode;
    }

    public function setOwner(?string $owner): void
    {
        $this->owner = $owner;
    }

    public function deploy(IssueResult $result): void
    {
        foreach ($this->targets as $type => $target) {
            if (trim((string) $target) === '') {
                continue;
            }

            $source = $result->getPath($type);
            if ($source === null) {
                throw new DeployException(sprintf(
                    '不认识的证书文件类型「%s」，可用值：key、cert、ca、fullchain',
                    $type
                ));
            }

            $content = $this->filesystem->readIfExists($source);
            if ($content === null) {
                throw new DeployException(sprintf('源文件不存在，没法安装：%s', $source));
            }

            // 私钥的权限要单独给：证书是公开信息，私钥不是
            $mode = $type === 'key' ? $this->keyMode : Filesystem::MODE_PUBLIC;
            $this->filesystem->write($target, $content, $mode);

            $this->applyOwner($target);

            $this->logger->info(sprintf('已安装 %s -> %s', $type, $target));
        }
    }

    /**
     * 设置属主。
     *
     * 用 chown() 函数而不是 shell，只有 root 跑的时候才会成功；
     * 非 root 下静默跳过——普通用户本来就没法改属主，
     * 为此报错会让非特权场景没法用
     */
    private function applyOwner(string $path): void
    {
        if ($this->owner === null || $this->owner === '') {
            return;
        }

        $parts = explode(':', $this->owner, 2);
        $user = trim($parts[0]);
        $group = isset($parts[1]) ? trim($parts[1]) : '';

        if ($user !== '' && !@chown($path, $user)) {
            $this->logger->debug(sprintf('设置 %s 的属主为 %s 失败（需要 root 权限）', $path, $user));
        }

        if ($group !== '' && !@chgrp($path, $group)) {
            $this->logger->debug(sprintf('设置 %s 的属组为 %s 失败（需要 root 权限）', $path, $group));
        }
    }
}
