<?php

declare(strict_types=1);

namespace Mci\Acme\Http\Transport;

use Mci\Acme\Exception\HttpException;
use Mci\Acme\Http\Proxy\ProxyConnector;
use Mci\Acme\Http\Request;
use Mci\Acme\Http\Response;
use Mci\Acme\Util\Platform;

/**
 * 在裸 socket 上自己收发 HTTP/1.1。
 *
 * 只在一种情况下用得上：**没有 curl 扩展，同时又要走代理访问 https**。
 * 那时 stream wrapper 帮不上忙（它的 proxy 选项不做 CONNECT 隧道），
 * 只能自己建隧道、自己写请求、自己解析响应。
 *
 * 实现范围刻意收窄到 ACME 用得到的部分：HTTP/1.1、一次请求一个连接、
 * 不做 keep-alive 复用、不处理 100-continue。少一分功能少一分出错的可能，
 * 而这一层是最难排查的一层。
 */
class SocketTransport implements TransportInterface
{
    /** @var ProxyConnector */
    private $connector;

    public function __construct(?ProxyConnector $connector = null)
    {
        $this->connector = $connector !== null ? $connector : new ProxyConnector();
    }

    public function isAvailable(): bool
    {
        return Platform::hasSockets();
    }

    public function getName(): string
    {
        return 'socket';
    }

    public function send(Request $request): Response
    {
        $proxy = $request->getProxyConfig();
        if ($proxy === null) {
            throw new HttpException('SocketTransport 只用于走代理的请求');
        }

        $url = $request->getUrl();
        $parts = parse_url($url);

        if ($parts === false || !isset($parts['host'])) {
            throw new HttpException(sprintf('解析不了地址：%s', $url));
        }

        $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : 'https';
        $useTls = $scheme === 'https';
        $host = $parts['host'];
        $port = isset($parts['port']) ? (int) $parts['port'] : ($useTls ? 443 : 80);

        $sslOptions = [
            'verify_peer' => $request->getVerifyPeer(),
            'verify_peer_name' => $request->getVerifyPeer(),
            'allow_self_signed' => false,
            'SNI_enabled' => true,
        ];

        $caFile = $request->getCaFile();
        if ($caFile !== null && $caFile !== '') {
            $sslOptions['cafile'] = $caFile;
        }

        $socket = $this->connector->connect(
            $proxy,
            $host,
            $port,
            $useTls,
            $sslOptions,
            $request->getConnectTimeout()
        );

        try {
            stream_set_timeout($socket, $request->getTimeout());

            $this->writeRequest($socket, $request, $parts, $host, $port, $useTls);

            return $this->readResponse($socket, $request);
        } finally {
            // 不做连接复用，用完就关。ACME 的请求之间本来就要串行，
            // 复用省不下多少时间，却会引入一堆状态管理的坑
            if (\is_resource($socket)) {
                fclose($socket);
            }
        }
    }

    /**
     * @param resource $socket
     * @param array<string, mixed> $parts
     */
    private function writeRequest($socket, Request $request, array $parts, string $host, int $port, bool $useTls): void
    {
        $path = isset($parts['path']) && $parts['path'] !== '' ? $parts['path'] : '/';
        if (isset($parts['query']) && $parts['query'] !== '') {
            $path .= '?' . $parts['query'];
        }

        // Host 头要按 URL 里的原样写：带了非默认端口就得带上，
        // 否则有些服务端（尤其是虚拟主机）会返回错误的站点
        $hostHeader = $host;
        if (($useTls && $port !== 443) || (!$useTls && $port !== 80)) {
            $hostHeader .= ':' . $port;
        }

        $body = $request->getBody();
        $method = $request->getMethod();

        $lines = [sprintf('%s %s HTTP/1.1', $method, $path)];
        $lines[] = 'Host: ' . $hostHeader;

        $seen = ['host' => true];
        foreach ($request->getHeaders() as $name => $value) {
            $lower = strtolower($name);
            if (isset($seen[$lower])) {
                continue;
            }
            $seen[$lower] = true;
            $lines[] = $name . ': ' . $value;
        }

        if ($body !== null && $body !== '' && !isset($seen['content-length'])) {
            $lines[] = 'Content-Length: ' . \strlen($body);
        }

        // 明确要求关闭连接：我们不复用，也就不用去猜服务端会不会保持
        if (!isset($seen['connection'])) {
            $lines[] = 'Connection: close';
        }

        $payload = implode("\r\n", $lines) . "\r\n\r\n";

        if ($body !== null && $body !== '' && $method !== 'GET' && $method !== 'HEAD') {
            $payload .= $body;
        }

        $length = \strlen($payload);
        $written = 0;

        while ($written < $length) {
            $result = @fwrite($socket, substr($payload, $written));

            if ($result === false || $result === 0) {
                throw new HttpException(sprintf('向 %s 发送请求失败', $request->getUrl()));
            }

            $written += $result;
        }
    }

    /**
     * @param resource $socket
     */
    private function readResponse($socket, Request $request): Response
    {
        $statusLine = '';
        $headerLines = [];

        while (($line = fgets($socket, 16384)) !== false) {
            $line = rtrim($line, "\r\n");

            if ($statusLine === '') {
                $statusLine = $line;
                continue;
            }

            if ($line === '') {
                break;
            }

            $headerLines[] = $line;
        }

        if ($statusLine === '') {
            $meta = stream_get_meta_data($socket);

            throw new HttpException(sprintf(
                '%s 没有返回任何响应（%s）',
                $request->getUrl(),
                isset($meta['timed_out']) && $meta['timed_out'] ? '超时' : '连接被对端关闭'
            ));
        }

        if (preg_match('#^HTTP/(\d(?:\.\d)?)\s+(\d{3})#', $statusLine, $m) !== 1) {
            throw new HttpException(sprintf('无法解析响应状态行：%s', $statusLine));
        }

        $status = (int) $m[2];
        $headers = $this->parseHeaders($headerLines);

        // 1xx 是中间响应，真正的响应还在后面。ACME 用不到，
        // 但代理有时会插一个 100 Continue，得跳过去
        if ($status >= 100 && $status < 200) {
            return $this->readResponse($socket, $request);
        }

        $body = $this->readBody($socket, $headers, $status, $request->getMethod());

        return new Response($status, $headers, $body, $request->getUrl());
    }

    /**
     * @param array<int, string> $lines
     * @return array<string, array<int, string>>
     */
    private function parseHeaders(array $lines): array
    {
        $headers = [];

        foreach ($lines as $line) {
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

    /**
     * @param resource $socket
     * @param array<string, array<int, string>> $headers
     */
    private function readBody($socket, array $headers, int $status, string $method): string
    {
        // 这几种响应按规范就没有响应体，去读只会阻塞到超时
        if ($method === 'HEAD' || $status === 204 || $status === 304) {
            return '';
        }

        $encoding = isset($headers['transfer-encoding'][0])
            ? strtolower($headers['transfer-encoding'][0])
            : '';

        if (str_contains($encoding, 'chunked')) {
            return $this->readChunked($socket);
        }

        if (isset($headers['content-length'][0])) {
            $length = (int) $headers['content-length'][0];

            return $length > 0 ? $this->readExactly($socket, $length) : '';
        }

        // 既没有长度也没有分块，那就读到对端关闭为止（HTTP/1.0 的做法）
        $body = '';
        while (!feof($socket)) {
            $chunk = @fread($socket, 8192);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $body .= $chunk;
        }

        return $body;
    }

    /**
     * 解 chunked 编码。
     *
     * @param resource $socket
     */
    private function readChunked($socket): string
    {
        $body = '';

        while (true) {
            $line = fgets($socket, 8192);
            if ($line === false) {
                break;
            }

            // 块大小是十六进制，后面可能跟着分号和扩展参数
            $size = trim($line);
            $semicolon = strpos($size, ';');
            if ($semicolon !== false) {
                $size = substr($size, 0, $semicolon);
            }

            if ($size === '') {
                continue;
            }

            $length = hexdec(trim($size));
            if (!\is_int($length) || $length <= 0) {
                break;
            }

            $body .= $this->readExactly($socket, $length);

            // 每个块后面跟一个 CRLF，读掉
            fgets($socket, 8192);
        }

        return $body;
    }

    /**
     * @param resource $socket
     */
    private function readExactly($socket, int $length): string
    {
        $data = '';

        while (\strlen($data) < $length) {
            $chunk = @fread($socket, min(8192, $length - \strlen($data)));

            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($socket);
                if (isset($meta['timed_out']) && $meta['timed_out']) {
                    throw new HttpException('读取响应体超时');
                }
                break;
            }

            $data .= $chunk;
        }

        return $data;
    }
}
