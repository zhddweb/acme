<?php

declare(strict_types=1);

namespace Mci\Acme\Deploy\Hook;

use Mci\Acme\Deploy\DeployHookInterface;
use Mci\Acme\Service\IssueResult;
use Mci\Acme\Util\Filesystem;
use Mci\Acme\Util\Json;
use Mci\Acme\Util\Logger;

/**
 * 写一个「证书更新了」的标记文件，把重载交给外部。
 *
 * 用在两种情况：
 *
 * 1. 没有 ext-posix，发不了信号；
 * 2. 要重载的服务不在本机（容器里、另一台机器上）。
 *
 * 配合 systemd path unit 最顺手：
 *
 *     # /etc/systemd/system/cert-reload.path
 *     [Path]
 *     PathChanged=/run/mci-acme/renewed.json
 *     [Install]
 *     WantedBy=multi-user.target
 *
 *     # /etc/systemd/system/cert-reload.service
 *     [Service]
 *     Type=oneshot
 *     ExecStart=/bin/systemctl reload nginx
 *
 * 文件内容是 JSON，带上域名与各文件路径，外部脚本可以据此做更细的处理。
 */
class TouchFileHook implements DeployHookInterface
{
    /** @var string */
    private $path;

    /** @var Filesystem */
    private $filesystem;

    /** @var Logger */
    private $logger;

    public function __construct(string $path, ?Logger $logger = null, ?Filesystem $filesystem = null)
    {
        $this->path = $path;
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->filesystem = $filesystem !== null ? $filesystem : new Filesystem();
    }

    public function getName(): string
    {
        return '写更新标记文件';
    }

    public function deploy(IssueResult $result): void
    {
        $certificate = $result->getCertificate();

        $payload = [
            'domain' => $result->getMainDomain(),
            'domains' => $result->getDomains(),
            'renewed_at' => gmdate('c'),
            'not_after' => $certificate !== null ? gmdate('c', $certificate->getNotAfter()) : null,
            'paths' => $result->getPaths(),
        ];

        // 权限给 0644：监听方通常是另一个用户跑的
        $this->filesystem->write($this->path, Json::encodePretty($payload) . "\n", Filesystem::MODE_PUBLIC);

        $this->logger->info(sprintf('已写入更新标记：%s', $this->path));
    }
}
