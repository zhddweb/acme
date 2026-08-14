<?php

declare(strict_types=1);

namespace Mci\Acme\Http\Transport;

use Mci\Acme\Exception\HttpException;
use Mci\Acme\Http\Request;
use Mci\Acme\Http\Response;
use Mci\Acme\Util\Platform;

/**
 * 基于 stream wrapper 的实现，没有 curl 扩展时的退路。
 *
 * 只要 allow_url_fopen 开着就能工作。缺点是超时控制粗糙、拿不到细分的错误码，
 * 所以只在 curl 缺席时用。
 */
class StreamTransport implements TransportInterface
{
    public function isAvailable(): bool
    {
        return Platform::hasStreamHttp();
    }

    public function getName(): string
    {
        return 'stream';
    }

    public function send(Request $request): Response
    {
        $headerLines = [];
        foreach ($request->getHeaders() as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        $httpOptions = [
            'method' => $request->getMethod(),
            'header' => implode("\r\n", $headerLines),
            'timeout' => $request->getTimeout(),
            // 4xx/5xx 也要把响应体读回来——ACME 的错误信息全在 body 里，
            // 默认行为是返回 false 并只留一句 warning，那就什么都看不到了
            'ignore_errors' => true,
            'follow_location' => 0,
            'protocol_version' => 1.1,
        ];

        $body = $request->getBody();
        if ($body !== null && $request->getMethod() !== 'GET' && $request->getMethod() !== 'HEAD') {
            $httpOptions['content'] = $body;
        }

        $proxy = $request->getProxy();
        if ($proxy !== null && $proxy !== '') {
            if (str_starts_with($proxy, 'socks')) {
                throw new HttpException(
                    'stream 传输层不支持 SOCKS 代理，请安装 curl 扩展，或改用 http:// 代理'
                );
            }
            // stream 的代理地址要写成 tcp://host:port
            $httpOptions['proxy'] = str_replace(['http://', 'https://'], 'tcp://', $proxy);
            $httpOptions['request_fulluri'] = true;
        }

        $sslOptions = [
            'verify_peer' => $request->getVerifyPeer(),
            'verify_peer_name' => $request->getVerifyPeer(),
            'SNI_enabled' => true,
            // 不允许自签：ACME 全程走公网 CA 签的证书，放开这个等于放弃中间人防护
            'allow_self_signed' => false,
        ];

        $caFile = $request->getCaFile();
        if ($caFile !== null && $caFile !== '') {
            $sslOptions['cafile'] = $caFile;
        }

        $context = stream_context_create(['http' => $httpOptions, 'ssl' => $sslOptions]);

        // $http_response_header 是 fopen 系列在当前作用域自动注入的魔术变量，
        // 拿不到别的办法，只能这么用
        $handle = @fopen($request->getUrl(), 'rb', false, $context);
        if ($handle === false) {
            $error = error_get_last();
            throw new HttpException(sprintf(
                '请求 %s 失败：%s',
                $request->getUrl(),
                isset($error['message']) ? $this->cleanMessage($error['message']) : '未知错误'
            ));
        }

        $meta = stream_get_meta_data($handle);
        $responseBody = stream_get_contents($handle);
        fclose($handle);

        if ($responseBody === false) {
            throw new HttpException(sprintf('读取 %s 的响应体失败', $request->getUrl()));
        }

        $rawHeaders = isset($meta['wrapper_data']) && \is_array($meta['wrapper_data'])
            ? $meta['wrapper_data']
            : [];

        return new Response(
            $this->extractStatus($rawHeaders),
            $this->parseHeaderLines($rawHeaders),
            $request->getMethod() === 'HEAD' ? '' : $responseBody,
            $request->getUrl()
        );
    }

    /** @param array<int, string> $lines */
    private function extractStatus(array $lines): int
    {
        $status = 0;
        foreach ($lines as $line) {
            // 取最后一段状态行：中间可能夹着 100 Continue 或重定向
            if (preg_match('#^HTTP/\d(?:\.\d)?\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        return $status;
    }

    /**
     * @param array<int, string> $lines
     * @return array<string, array<int, string>>
     */
    private function parseHeaderLines(array $lines): array
    {
        $headers = [];
        foreach ($lines as $line) {
            if (preg_match('#^HTTP/\d#', $line) === 1) {
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

    /** fopen 的报错前面挂着一长串函数名，对用户没意义，去掉 */
    private function cleanMessage(string $message): string
    {
        return trim(preg_replace('/^fopen\([^)]*\):\s*/', '', $message));
    }
}
