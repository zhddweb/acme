<?php

declare(strict_types=1);

namespace PhpAcme\Challenge\Dns01;

/**
 * DNS 提供商适配器。
 *
 * 只有两个动作：加一条 TXT、删一条 TXT。这是有意收窄的——
 * dns-01 只需要这两样，接口越小，新增一家提供商的成本越低。
 *
 * 实现须知：
 *
 * 1. **必须支持同名多值**。同时申请 example.com 和 *.example.com 时，
 *    两条挑战记录的名字都是 `_acme-challenge.example.com`，值不同。
 *    覆盖式写入的 API（Namecheap 那种整表提交的）要先读出现有记录再合并。
 *
 * 2. **凭据从构造器传入**，不要在实现里读环境变量或全局配置。
 *    那是 ProviderFactory 的职责，也是这些类可测的前提。
 *
 * 3. **删除要幂等**。cleanup 在失败路径上也会被调用，记录可能压根没加上去，
 *    这时候删一个不存在的记录不该抛异常。
 */
interface DnsProviderInterface
{
    /** 展示用的名字，出现在日志里 */
    public function getName(): string;

    /**
     * 加一条 TXT 记录。
     *
     * @param string $fqdn 完整记录名，如 _acme-challenge.example.com
     * @param string $value 记录值（43 字节的 base64url 串）
     *
     * @throws \PhpAcme\Exception\DnsException
     */
    public function addTxtRecord(string $fqdn, string $value): void;

    /**
     * 删掉之前加的那条 TXT 记录。
     *
     * @throws \PhpAcme\Exception\DnsException
     */
    public function removeTxtRecord(string $fqdn, string $value): void;
}
