<?php

declare(strict_types=1);

namespace Mci\Acme\Deploy;

use Mci\Acme\Service\IssueResult;

/**
 * 部署钩子：把签好的证书送到真正用它的地方去。
 *
 * 签发只是第一步——证书躺在 ~/.acme.sh 下面对 nginx 没有任何意义。
 * 部署做两件事：把文件放到目标位置，然后让服务重新加载。
 *
 * **本库不执行任何外部命令**，所以「重新加载」是靠给进程发信号实现的
 * （见 ReloadSignalHook）。目标环境禁用了 exec/proc_open，
 * 这不是洁癖而是必须——详见 CLAUDE.md。
 */
interface DeployHookInterface
{
    /** 展示用的名字 */
    public function getName(): string;

    /**
     * 执行部署。
     *
     * 只在证书**确实重新签发**时被调用；跳过续期的那些次不会调，
     * 否则每天 cron 都会白白重启一次 nginx。
     *
     * @throws \Mci\Acme\Exception\DeployException
     */
    public function deploy(IssueResult $result): void;
}
