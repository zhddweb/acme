<?php

declare(strict_types=1);

namespace PhpAcme\Deploy\Hook;

use PhpAcme\Deploy\DeployHookInterface;
use PhpAcme\Exception\DeployException;
use PhpAcme\Http\HttpClient;
use PhpAcme\Service\IssueResult;
use PhpAcme\Util\Filesystem;
use PhpAcme\Util\Logger;

/**
 * 把证书 POST 给一个 HTTP 接口。
 *
 * 用于把证书推到别的地方：CDN 的 API、Kubernetes 的 secret、
 * 面板系统、或者自己写的分发服务。
 *
 * **默认不带私钥**：私钥经网络传输的风险要由使用者明确接受，
 * 所以要显式打开 includeKey。真要传就务必确认对端是 HTTPS
 * 且带鉴权头。
 */
class WebhookDeployHook implements DeployHookInterface
{
    /** @var string */
    private $url;

    /** @var array<string, string> */
    private $headers;

    /** @var bool */
    private $includeKey = false;

    /** @var HttpClient */
    private $http;

    /** @var Filesystem */
    private $filesystem;

    /** @var Logger */
    private $logger;

    /**
     * @param array<string, string> $headers 一般用来放 Authorization
     */
    public function __construct(
        string $url,
        array $headers = [],
        ?HttpClient $http = null,
        ?Logger $logger = null,
        ?Filesystem $filesystem = null
    ) {
        $this->url = $url;
        $this->headers = $headers;
        $this->http = $http !== null ? $http : new HttpClient();
        $this->logger = $logger !== null ? $logger : Logger::silent();
        $this->filesystem = $filesystem !== null ? $filesystem : new Filesystem();
    }

    public function getName(): string
    {
        return 'Webhook 部署';
    }

    public function setIncludeKey(bool $include): void
    {
        $this->includeKey = $include;
    }

    public function deploy(IssueResult $result): void
    {
        if ($this->includeKey && !str_starts_with(strtolower($this->url), 'https://')) {
            throw new DeployException(sprintf(
                '拒绝把私钥明文发到非 HTTPS 地址：%s',
                $this->url
            ));
        }

        $certificate = $result->getCertificate();

        $payload = [
            'domain' => $result->getMainDomain(),
            'domains' => $result->getDomains(),
            'not_after' => $certificate !== null ? gmdate('c', $certificate->getNotAfter()) : null,
            'fullchain' => $this->readPath($result, 'fullchain'),
            'cert' => $this->readPath($result, 'cert'),
            'ca' => $this->readPath($result, 'ca'),
        ];

        if ($this->includeKey) {
            $payload['key'] = $this->readPath($result, 'key');
        }

        $response = $this->http->postJson($this->url, $payload, $this->headers);

        if (!$response->isSuccess()) {
            throw new DeployException(sprintf(
                'Webhook %s 返回 HTTP %d：%s',
                $this->url,
                $response->getStatus(),
                substr(trim($response->getBody()), 0, 200)
            ));
        }

        $this->logger->info(sprintf('已推送证书到 %s', $this->url));
    }

    private function readPath(IssueResult $result, string $type): ?string
    {
        $path = $result->getPath($type);

        return $path !== null ? $this->filesystem->readIfExists($path) : null;
    }
}
