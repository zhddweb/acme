<?php

declare(strict_types=1);

namespace PhpAcme\Challenge;

use PhpAcme\Crypto\KeyPair;
use PhpAcme\Protocol\Challenge;

/**
 * 挑战求解器：负责「把答案摆到 CA 能看见的地方」。
 *
 * 生命周期固定是 prepare -> （客户端通知 CA 来验）-> tick* -> cleanup。
 * cleanup **必须**在失败路径上也被调用，否则会在用户的 webroot 里
 * 留下一堆 .well-known 垃圾文件，或者在 DNS 上堆积过期的 TXT 记录
 * ——后者更麻烦，某些解析商对同名 TXT 的条数有上限，堆满了下次就加不进去。
 */
interface ChallengeSolverInterface
{
    /** 返回处理的挑战类型：http-01 / dns-01 / tls-alpn-01 */
    public function getType(): string;

    /**
     * 把答案准备好。返回后 CA 随时可能来验证。
     */
    public function prepare(Challenge $challenge, KeyPair $accountKey): void;

    /**
     * 清理 prepare 留下的痕迹。
     *
     * 实现里不要抛异常——它总是在 finally 里被调用，
     * 这时候抛出去会盖掉真正的失败原因。
     */
    public function cleanup(Challenge $challenge, KeyPair $accountKey): void;

    /**
     * 等待 CA 验证期间被反复调用。
     *
     * 给 standalone 这类「自己就是服务器」的实现用：单进程下没人替它
     * accept 连接，只能靠轮询循环的间隙来跑。其他实现留空即可。
     */
    public function tick(): void;

    /**
     * prepare 之后、通知 CA 之前的自检。
     *
     * 返回 false 表示「我这边还没就绪」，调用方会等一会儿再问。
     * 这一步能挡掉大部分失败：DNS 没传播开就通知 CA，换来的是一次
     * 失败的授权（且该域名的失败次数会计入 CA 的速率限制）。
     */
    public function verify(Challenge $challenge, KeyPair $accountKey): bool;
}
