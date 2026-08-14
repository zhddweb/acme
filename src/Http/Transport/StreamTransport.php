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
    /** @var SocketTransport 需要隧道时委托给它 */
    private $socketTransport;

    public function __construct(?SocketTransport $socketTransport = null)
    {
        $this->socketTransport = $socketTransport !== null ? $socketTransport : new SocketTransport();
    }

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
        // stream wrapper 的 proxy 选项只能做一件事：把绝对 URI 发给 http 代理。
        // 访问 https 目标要先 CONNECT 建隧道，SOCKS 更是另一套协议，
        // 这两种它都做不到，交给 SocketTransport 自己拿 socket 干
        if ($this->needsTunnel($request)) {
            return $this->socketTransport->send($request);
        }

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

        $proxy = $request->getProxyConfig();
        if ($proxy !== null) {
            // 走到这里只剩「http 代理 + http 目标」一种组合，
            // 其余的在 send() 开头就转给 SocketTransport 了
            $httpOptions['proxy'] = sprintf('tcp://%s:%d', $proxy->getHost(), $proxy->getPort());
            // 让 stream 发绝对 URI（GET http://host/path），代理才认
            $httpOptions['request_fulluri'] = true;

            if ($proxy->hasCredentials()) {
                $headerLines[] = 'Proxy-Authorization: Basic ' . base64_encode(
                    $proxy->getUsername() . ':' . (string) $proxy->getPassword()
                );
                $httpOptions['header'] = implode("\r\n", $headerLines);
            }
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

    /**
     * 这次请求是不是必须自己建隧道。
     */
    private function needsTunnel(Request $request): bool
    {
        $proxy = $request->getProxyConfig();

        if ($proxy === null) {
            return false;
        }

        if ($proxy->isSocks()) {
            return true;
        }

        return str_starts_with(strtolower($request->getUrl()), 'https://');
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
