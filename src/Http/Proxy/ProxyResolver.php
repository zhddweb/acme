<?php

declare(strict_types=1);

namespace Mci\Acme\Http\Proxy;

/**
 * 决定某个 URL 该不该走代理、走哪个。
 *
 * 查找顺序：显式设置 > 环境变量。环境变量的名字与语义沿用 curl 那一套，
 * 因为受限环境里的运维基本都是按 curl 的习惯配的：
 *
 * - `HTTPS_PROXY` / `https_proxy` —— 只作用于 https 目标
 * - `HTTP_PROXY` / `http_proxy` —— 只作用于 http 目标
 * - `ALL_PROXY` / `all_proxy` —— 两者的兜底
 * - `NO_PROXY` / `no_proxy` —— 例外清单，逗号分隔
 *
 * 大小写两种都认：不同的部署脚本习惯不一样，只认一种会让人白折腾半天。
 * 有一个例外要注意：CGI/FPM 下 `HTTP_PROXY` 可能来自客户端发来的
 * `Proxy:` 请求头（就是当年的 httpoxy 漏洞），所以**只在 CLI 下读它**。
 */
class ProxyResolver
{
    /** @var Proxy|null 显式设置的代理，优先级最高 */
    private $explicit;

    /** @var array<int, string> 不走代理的主机模式 */
    private $noProxy = [];

    /** @var bool 是否读环境变量 */
    private $useEnvironment = true;

    /** @var array<string, string>|null 覆盖环境变量，测试用 */
    private $environmentOverride;

    public function __construct(?Proxy $explicit = null)
    {
        $this->explicit = $explicit;
        $this->noProxy = $this->parseNoProxy($this->readEnv('NO_PROXY'));
    }

    public function setExplicit(?Proxy $proxy): void
    {
        $this->explicit = $proxy;
    }

    public function getExplicit(): ?Proxy
    {
        return $this->explicit;
    }

    /** 关掉环境变量读取，只认显式设置 */
    public function setUseEnvironment(bool $use): void
    {
        $this->useEnvironment = $use;
    }

    /**
     * @param array<string, string>|null $environment 测试注入
     */
    public function setEnvironmentOverride(?array $environment): void
    {
        $this->environmentOverride = $environment;
        $this->noProxy = $this->parseNoProxy($this->readEnv('NO_PROXY'));
    }

    /**
     * 追加不走代理的主机。
     *
     * @param string|array<int, string> $hosts 逗号分隔的串或数组
     */
    public function addNoProxy($hosts): void
    {
        $list = \is_array($hosts) ? $hosts : $this->parseNoProxy($hosts);

        foreach ($list as $host) {
            $host = strtolower(trim((string) $host));
            if ($host !== '' && !\in_array($host, $this->noProxy, true)) {
                $this->noProxy[] = $host;
            }
        }
    }

    /** @return array<int, string> */
    public function getNoProxy(): array
    {
        return $this->noProxy;
    }

    /**
     * 这个 URL 该用哪个代理；返回 null 表示直连。
     */
    public function resolve(string $url): ?Proxy
    {
        $parts = parse_url($url);
        $host = isset($parts['host']) ? strtolower($parts['host']) : '';
        $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : 'https';

        if ($host !== '' && $this->isExcluded($host)) {
            return null;
        }

        if ($this->explicit !== null) {
            return $this->explicit;
        }

        if (!$this->useEnvironment) {
            return null;
        }

        // https 目标优先看 HTTPS_PROXY，http 目标看 HTTP_PROXY，都没有再看 ALL_PROXY
        $candidates = $scheme === 'http'
            ? ['HTTP_PROXY', 'ALL_PROXY']
            : ['HTTPS_PROXY', 'ALL_PROXY'];

        foreach ($candidates as $name) {
            $value = $this->readEnv($name);
            if ($value === null || trim($value) === '') {
                continue;
            }

            try {
                return Proxy::fromString($value);
            } catch (\Mci\Acme\Exception\ConfigException $e) {
                // 环境变量里写错了不该让整个流程崩掉——直连试试也许就通了。
                // 显式传参写错则会照常抛出，那是用户当场能改的
                continue;
            }
        }

        return null;
    }

    /**
     * 主机是否在 NO_PROXY 清单里。
     *
     * 规则与 curl 一致：
     * - `*` 表示全部直连
     * - `example.com` 匹配它自己以及所有子域
     * - `.example.com` 同上（前导点是常见写法）
     * - IP 直接按字符串比
     */
    public function isExcluded(string $host): bool
    {
        $host = strtolower(trim($host));

        if ($host === '' || $this->noProxy === []) {
            return false;
        }

        foreach ($this->noProxy as $pattern) {
            if ($pattern === '*') {
                return true;
            }

            $pattern = ltrim($pattern, '.');

            if ($host === $pattern) {
                return true;
            }

            // 子域匹配：a.example.com 命中 example.com，
            // 但 notexample.com 不该命中 example.com
            if (str_ends_with($host, '.' . $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, string>
     */
    private function parseNoProxy(?string $value): array
    {
        if ($value === null || trim($value) === '') {
            return [];
        }

        $out = [];
        foreach (preg_split('/[,\s]+/', $value) as $item) {
            $item = strtolower(trim($item));
            if ($item !== '') {
                $out[] = $item;
            }
        }

        return $out;
    }

    /**
     * 读环境变量，大小写两种写法都认。
     */
    private function readEnv(string $name): ?string
    {
        if ($this->environmentOverride !== null) {
            foreach ([$name, strtolower($name)] as $candidate) {
                if (isset($this->environmentOverride[$candidate])) {
                    return $this->environmentOverride[$candidate];
                }
            }

            return null;
        }

        // httpoxy：CGI 环境下 HTTP_PROXY 可能是客户端伪造的 Proxy: 头带进来的，
        // 拿它当代理会把请求引到攻击者的服务器上。非 CLI 时一律不认这个变量
        if ($name === 'HTTP_PROXY' && PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg') {
            return null;
        }

        foreach ([$name, strtolower($name)] as $candidate) {
            $value = getenv($candidate);
            if (\is_string($value) && trim($value) !== '') {
                return $value;
            }
        }

        return null;
    }
}
