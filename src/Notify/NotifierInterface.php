<?php

declare(strict_types=1);

namespace Mci\Acme\Notify;

/**
 * 通知渠道。
 *
 * 续期是无人值守跑的，出了问题没人知道——直到某天证书过期，
 * 用户在浏览器里看到红色警告。通知钩子存在的意义就是把这个反馈闭环补上。
 *
 * 实现里**不要抛异常**：通知失败不该让一次成功的续期变成失败。
 * 出错记日志就好，返回 false 即可。
 */
interface NotifierInterface
{
    public function getName(): string;

    /**
     * 发一条通知。
     *
     * @param string $subject 标题
     * @param string $body 正文，可能是多行
     * @param bool $success 这次是成功还是失败，渠道可以据此换颜色/图标
     * @return bool 发送是否成功
     */
    public function send(string $subject, string $body, bool $success = true): bool;
}
