<?php

declare(strict_types=1);

namespace Mci\Acme\Challenge\Http01;

use Mci\Acme\Challenge\AbstractSolver;
use Mci\Acme\Crypto\KeyPair;
use Mci\Acme\Exception\ChallengeException;
use Mci\Acme\Protocol\Challenge;
use Mci\Acme\Util\Domain;
use Mci\Acme\Util\Filesystem;
use Mci\Acme\Util\Logger;

/**
 * http-01：把答案写成 webroot 下的一个文件。
 *
 * 最常用也最容易配错的方式。CA 会去访问
 * `http://<域名>/.well-known/acme-challenge/<token>`，要求：
 *
 * - **必须是 80 端口的明文 HTTP**（CA 不看 https，但允许 301 跳到 https）
 * - 响应体必须**恰好**是 keyAuthorization，多一个换行也不行
 * - 不能要求任何认证，不能被 WAF 拦
 *
 * 最常见的失败是 nginx 里有个 `location ~ /\.` 的规则把点开头的目录
 * 全 deny 了，或者整站强制跳转到 https 时把这个路径也带上了。
 */
class WebrootSolver extends AbstractSolver
{
    const TYPE = 'http-01';

    /** @var array<string, string> 域名 => webroot 路径；键 '*' 是兜底 */
    private $webroots;

    /** @var Filesystem */
    private $filesystem;

    /** @var array<int, string> 记下写过的文件，cleanup 时按这个删 */
    private $written = [];

    /** @var bool 是否连带删掉自己建的空目录 */
    private $removeEmptyDirs = true;

    /**
     * @param string|array<string, string> $webroot 单个路径，或 域名=>路径 的映射
     */
    public function __construct($webroot, ?Logger $logger = null, ?Filesystem $filesystem = null)
    {
        parent::__construct($logger);

        $this->filesystem = $filesystem !== null ? $filesystem : new Filesystem();

        if (\is_string($webroot)) {
            $this->webroots = ['*' => rtrim($webroot, '/\\')];
        } else {
            $normalized = [];
            foreach ($webroot as $domain => $path) {
                $normalized[strtolower((string) $domain)] = rtrim((string) $path, '/\\');
            }
            $this->webroots = $normalized;
        }

        if ($this->webroots === []) {
            throw new ChallengeException('webroot 模式至少要指定一个网站根目录');
        }
    }

    public function getType(): string
    {
        return self::TYPE;
    }

    public function prepare(Challenge $challenge, KeyPair $accountKey): void
    {
        $path = $this->resolvePath($challenge);
        $content = $challenge->getKeyAuthorization($accountKey);

        $this->filesystem->ensureDirectory(\dirname($path), 0755);

        // 权限必须是 web 服务器读得到的 0644——Filesystem 默认的 0600
        // 在 php-fpm 与 nginx 跑不同用户时会让 CA 拿到 403
        $this->filesystem->write($path, $content, Filesystem::MODE_PUBLIC);
        $this->written[] = $path;

        $this->logger->debug(sprintf('已写入验证文件：%s', $path));
        $this->logger->debug(sprintf('CA 将访问：%s', $challenge->getHttpUrl()));
    }

    public function cleanup(Challenge $challenge, KeyPair $accountKey): void
    {
        try {
            $path = $this->resolvePath($challenge);
        } catch (ChallengeException $e) {
            // 连路径都算不出来说明 prepare 就没成功，没有东西要清
            return;
        }

        if ($this->filesystem->isFile($path)) {
            $this->filesystem->delete($path);
            $this->logger->debug(sprintf('已删除验证文件：%s', $path));
        }

        if (!$this->removeEmptyDirs) {
            return;
        }

        // 只删自己建的那两级，且只在空的时候删。用户的 .well-known 下面
        // 可能还放着别的东西（比如 apple-app-site-association）
        $challengeDir = \dirname($path);
        if ($this->isEmptyDirectory($challengeDir)) {
            @rmdir($challengeDir);
            $wellKnown = \dirname($challengeDir);
            if ($this->isEmptyDirectory($wellKnown)) {
                @rmdir($wellKnown);
            }
        }
    }

    public function setRemoveEmptyDirs(bool $remove): void
    {
        $this->removeEmptyDirs = $remove;
    }

    /**
     * 当前的 webroot 配置，续期时要把它写回 .conf。
     *
     * @return array<string, string>
     */
    public function getWebroots(): array
    {
        return $this->webroots;
    }

    /**
     * 序列化成 .conf 里 Le_Webroot 的形式。
     *
     * 单个路径直接给路径（与 acme.sh 完全一致）；
     * 多个则写成 `域名=路径,域名=路径`。
     */
    public function describe(): string
    {
        if (\count($this->webroots) === 1 && isset($this->webroots['*'])) {
            return $this->webroots['*'];
        }

        $parts = [];
        foreach ($this->webroots as $domain => $path) {
            $parts[] = $domain . '=' . $path;
        }

        return implode(',', $parts);
    }

    /**
     * 本地自检：文件确实写进去了、内容对得上。
     *
     * 有意**不**发 HTTP 请求验证：机器在 NAT 或负载均衡后面时，
     * 从本机访问自己的域名往往走不通，那会得到一个吓人但无意义的失败。
     * 真正的连通性只有 CA 说了算。
     */
    public function verify(Challenge $challenge, KeyPair $accountKey): bool
    {
        $path = $this->resolvePath($challenge);
        $actual = $this->filesystem->readIfExists($path);

        return $actual !== null && $actual === $challenge->getKeyAuthorization($accountKey);
    }

    private function resolvePath(Challenge $challenge): string
    {
        return $this->resolveWebroot($challenge->getDomain()) . '/' . $challenge->getHttpPath();
    }

    /**
     * 找这个域名该用哪个 webroot。
     *
     * 查找顺序：精确匹配 -> 去掉通配符前缀 -> 逐级往上找父域 -> '*' 兜底。
     * 逐级往上是为了让 `-d a.example.com -d b.example.com -w /var/www`
     * 这种常见写法能工作，同时又允许给某个子域单独指定目录。
     */
    private function resolveWebroot(string $domain): string
    {
        $domain = strtolower(Domain::stripWildcard($domain));

        if (isset($this->webroots[$domain])) {
            return $this->webroots[$domain];
        }

        $labels = explode('.', $domain);
        while (\count($labels) > 2) {
            array_shift($labels);
            $parent = implode('.', $labels);
            if (isset($this->webroots[$parent])) {
                return $this->webroots[$parent];
            }
        }

        if (isset($this->webroots['*'])) {
            return $this->webroots['*'];
        }

        throw new ChallengeException(sprintf(
            '没有为域名 %s 指定 webroot。用 -w /path/to/webroot 指定，多个域名可以重复使用 -d 与 -w',
            $domain
        ));
    }

    private function isEmptyDirectory(string $dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }

        $items = @scandir($dir);
        if ($items === false) {
            return false;
        }

        return \count($items) <= 2;
    }
}
