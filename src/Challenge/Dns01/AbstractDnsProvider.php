<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01;

use PhpAcme\Exception\ConfigException;
use PhpAcme\Exception\DnsException;
use PhpAcme\Http\HttpClient;
use PhpAcme\Http\Response;
use PhpAcme\Util\Domain;
use PhpAcme\Util\Logger;

/**
 * DNS 提供商的公共部分：凭据读取、zone 定位、HTTP 调用与错误包装。
 *
 * 各家 API 千奇百怪，但「找到这个域名属于我账号下哪个 zone」这件事
 * 是共通的，而且是最容易写错的一步——example.com 与 example.co.uk
 * 的 zone 边界光看字符串分不出来。这里给出统一的解法：
 * 拿 Domain::zoneCandidates() 的候选列表逐个问 API，第一个命中的就是。
 */
abstract class AbstractDnsProvider implements DnsProviderInterface
{
    /** @var HttpClient */
    protected $http;

    /** @var Logger */
    protected $logger;

    /** @var array<string, string> 凭据 */
    protected $credentials;

    /** @var array<string, string> zone 查找结果缓存：域名 => zone 标识 */
    private $zoneCache = [];

    /**
     * @param array<string, string> $credentials
     */
    public function __construct(array $credentials, ?HttpClient $http = null, ?Logger $logger = null)
    {
        $this->credentials = $credentials;
        $this->http = $http !== null ? $http : new HttpClient();
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    /**
     * 取一项必填凭据，缺了就抛出带「该设哪个环境变量」的提示。
     */
    protected function required(string $key, string $hint = ''): string
    {
        if (!isset($this->credentials[$key]) || trim((string) $this->credentials[$key]) === '') {
            throw new ConfigException(sprintf(
                '%s 缺少必填凭据 %s%s',
                $this->getName(),
                $key,
                $hint !== '' ? '。' . $hint : ''
            ));
        }

        return trim((string) $this->credentials[$key]);
    }

    protected function optional(string $key, string $default = ''): string
    {
        return isset($this->credentials[$key]) && trim((string) $this->credentials[$key]) !== ''
            ? trim((string) $this->credentials[$key])
            : $default;
    }

    /**
     * 找出 fqdn 属于哪个 zone，带缓存。
     *
     * 子类实现 findZone() 去问自家 API；这里只管候选顺序和缓存——
     * 一次签发里同一个 zone 会被查好几次（多个子域名），
     * 每次都打 API 既慢又容易撞人家的频率限制。
     *
     * @return array{zone: string, id: string, record: string}
     *         zone 是域名，id 是提供商内部标识，record 是相对记录名
     */
    protected function resolveZone(string $fqdn): array
    {
        $fqdn = rtrim(strtolower($fqdn), '.');

        if (isset($this->zoneCache[$fqdn])) {
            $cached = json_decode($this->zoneCache[$fqdn], true);
            if (\is_array($cached)) {
                return $cached;
            }
        }

        foreach (Domain::zoneCandidates($fqdn) as $candidate) {
            $id = $this->findZone($candidate);
            if ($id === null) {
                continue;
            }

            $result = [
                'zone' => $candidate,
                'id' => $id,
                'record' => Domain::relativeName($fqdn, $candidate),
            ];

            $this->zoneCache[$fqdn] = json_encode($result);
            $this->logger->debug(sprintf('%s：%s 属于 zone %s', $this->getName(), $fqdn, $candidate));

            return $result;
        }

        throw new DnsException(sprintf(
            '%s：在账号下找不到能管理 %s 的域名。'
            . '确认这个域名已经添加到该 DNS 提供商，且 API 凭据有读取权限',
            $this->getName(),
            $fqdn
        ));
    }

    /**
     * 问 API「这个域名是不是我账号下的 zone」。
     *
     * @return string|null 是则返回提供商内部的 zone 标识（没有的话回域名本身），否则 null
     */
    abstract protected function findZone(string $domain): ?string;

    /**
     * 发请求并解析 JSON，出错时抛带上下文的异常。
     *
     * @param array<string, string> $headers
     * @param mixed $body 数组会被 JSON 编码；字符串原样发
     * @return array
     */
    protected function requestJson(string $method, string $url, $body = null, array $headers = []): array
    {
        $response = $this->send($method, $url, $body, $headers);

        $data = $response->tryJson();
        if ($data === null) {
            // 有些 API 成功时回空体（204），那不算错
            if ($response->isSuccess() && trim($response->getBody()) === '') {
                return [];
            }

            throw new DnsException(sprintf(
                '%s 的 API 返回了非 JSON 内容（HTTP %d）：%s',
                $this->getName(),
                $response->getStatus(),
                substr(trim($response->getBody()), 0, 300)
            ));
        }

        if (!$response->isSuccess()) {
            throw new DnsException(sprintf(
                '%s 的 API 返回 HTTP %d：%s',
                $this->getName(),
                $response->getStatus(),
                $this->describeError($data)
            ));
        }

        return $data;
    }

    /**
     * @param mixed $body
     * @param array<string, string> $headers
     */
    protected function send(string $method, string $url, $body = null, array $headers = []): Response
    {
        $payload = null;

        if (\is_array($body)) {
            $payload = \PhpAcme\Util\Json::encode($body);
            if (!isset($headers['Content-Type'])) {
                $headers['Content-Type'] = 'application/json';
            }
        } elseif (\is_string($body)) {
            $payload = $body;
        }

        $this->logger->debug(sprintf('%s -> %s %s', $this->getName(), $method, $url));

        return $this->http->request($method, $url, $payload, $headers);
    }

    /**
     * 从各家五花八门的错误响应里凑一句人能看懂的话。
     *
     * @param array $data
     */
    protected function describeError(array $data): string
    {
        // 按常见程度排：Cloudflare 的 errors[]、通用的 message/error、
        // 阿里/腾讯的 Message、GoDaddy 的 fields[]
        if (isset($data['errors']) && \is_array($data['errors']) && $data['errors'] !== []) {
            $parts = [];
            foreach ($data['errors'] as $error) {
                if (\is_array($error)) {
                    $parts[] = isset($error['message']) ? (string) $error['message'] : \PhpAcme\Util\Json::encode($error);
                } else {
                    $parts[] = (string) $error;
                }
            }

            return implode('; ', $parts);
        }

        foreach (['message', 'Message', 'error', 'error_description', 'errorMessage', 'detail'] as $key) {
            if (isset($data[$key])) {
                if (\is_string($data[$key])) {
                    return $data[$key];
                }
                if (\is_array($data[$key]) && isset($data[$key]['Message'])) {
                    return (string) $data[$key]['Message'];
                }
            }
        }

        return \PhpAcme\Util\Json::encode($data);
    }

    /** 记录名去掉 zone 后缀；zone 顶点返回 '@' */
    protected function relativeName(string $fqdn, string $zone): string
    {
        return Domain::relativeName($fqdn, $zone);
    }
}
