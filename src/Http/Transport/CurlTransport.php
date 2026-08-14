<?php

declare(strict_types=1);

namespace PhpAcme\Http\Transport;

use PhpAcme\Exception\HttpException;
use PhpAcme\Http\Request;
use PhpAcme\Http\Response;
use PhpAcme\Util\Platform;

/**
 * 基于 curl 扩展的实现，首选。
 *
 * 有意不开 CURLOPT_FOLLOWLOCATION：设了 open_basedir 或 safe_mode 的主机上
 * 这个选项会被 libcurl 直接拒绝，导致请求整个失败。重定向交给上层的
 * HttpClient 手工跟，顺带还能限制跳转次数、避免把 Authorization 头
 * 带到跨域的地址上去。
 */
class CurlTransport implements TransportInterface
{
    public function isAvailable(): bool
    {
        return Platform::hasCurl();
    }

    public function getName(): string
    {
        return 'curl';
    }

    public function send(Request $request): Response
    {
        $handle = curl_init();
        if ($handle === false) {
            throw new HttpException('curl_init() 失败');
        }

        $headerLines = [];

        $options = [
            CURLOPT_URL => $request->getUrl(),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => $request->getConnectTimeout(),
            CURLOPT_TIMEOUT => $request->getTimeout(),
            CURLOPT_SSL_VERIFYPEER => $request->getVerifyPeer(),
            CURLOPT_SSL_VERIFYHOST => $request->getVerifyPeer() ? 2 : 0,
            CURLOPT_HTTPHEADER => $this->buildHeaderLines($request),
            // 响应头逐行回调收集，比 CURLOPT_HEADER=true 再切分靠谱：
            // 后者遇到 100 Continue 或重定向会把多段头拼在一起
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$headerLines): int {
                $headerLines[] = $line;

                return \strlen($line);
            },
        ];

        $method = $request->getMethod();
        if ($method === 'HEAD') {
            $options[CURLOPT_NOBODY] = true;
        } elseif ($method !== 'GET') {
            $options[CURLOPT_CUSTOMREQUEST] = $method;
            $body = $request->getBody();
            if ($body !== null) {
                $options[CURLOPT_POSTFIELDS] = $body;
            }
        }

        $caFile = $request->getCaFile();
        if ($caFile !== null && $caFile !== '') {
            $options[CURLOPT_CAINFO] = $caFile;
        }

        $proxy = $request->getProxy();
        if ($proxy !== null && $proxy !== '') {
            $options[CURLOPT_PROXY] = $proxy;
            // socks5h 让 DNS 也走代理，内网环境里这是刚需
            if (str_starts_with($proxy, 'socks5h://')) {
                $options[CURLOPT_PROXYTYPE] = CURLPROXY_SOCKS5_HOSTNAME;
            } elseif (str_starts_with($proxy, 'socks5://')) {
                $options[CURLOPT_PROXYTYPE] = CURLPROXY_SOCKS5;
            } elseif (str_starts_with($proxy, 'socks4://')) {
                $options[CURLOPT_PROXYTYPE] = CURLPROXY_SOCKS4;
            }
        }

        curl_setopt_array($handle, $options);

        $body = curl_exec($handle);
        if ($body === false) {
            $error = curl_error($handle);
            $errno = curl_errno($handle);
            curl_close($handle);

            throw new HttpException(sprintf(
                '请求 %s 失败：%s（curl 错误码 %d）',
                $request->getUrl(),
                $error !== '' ? $error : '未知错误',
                $errno
            ));
        }

        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $effectiveUrl = (string) curl_getinfo($handle, CURLINFO_EFFECTIVE_URL);
        curl_close($handle);

        return new Response(
            $status,
            $this->parseHeaderLines($headerLines),
            \is_string($body) ? $body : '',
            $effectiveUrl !== '' ? $effectiveUrl : $request->getUrl()
        );
    }

    /** @return array<int, string> */
    private function buildHeaderLines(Request $request): array
    {
        $lines = [];
        foreach ($request->getHeaders() as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }

        // curl 默认会加 Expect: 100-continue，body 一大就要多一轮往返，
        // 而部分 CA 的网关根本不回 100，直接卡到超时
        $lines[] = 'Expect:';

        return $lines;
    }

    /**
     * @param array<int, string> $lines
     * @return array<string, array<int, string>>
     */
    private function parseHeaderLines(array $lines): array
    {
        $headers = [];

        foreach ($lines as $line) {
            $line = rtrim($line, "\r\n");
            if ($line === '') {
                continue;
            }
            if (str_starts_with($line, 'HTTP/')) {
                // 又一段状态行说明前面是 100 Continue 或重定向，
                // 之前收的头作废，只保留最后一段
                $headers = [];
                continue;
            }
            $pos = strpos($line, ':');
            if ($pos === false) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $pos)));
            $value = trim(substr($line, $pos + 1));
            if (!isset($headers[$name])) {
                $headers[$name] = [];
            }
            $headers[$name][] = $value;
        }

        return $headers;
    }
}
