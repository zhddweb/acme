<?php

declare(strict_types=1);

namespace Mci\Acme\Http\Proxy;

use Mci\Acme\Exception\HttpException;

/**
 * 通过代理建立一条到目标主机的 TCP 连接，返回可直接读写的 socket。
 *
 * 为什么要手写这一层：**PHP 的 stream wrapper 用不了代理访问 https**。
 * `stream_context` 的 `proxy` 选项只对 `http://` 有效（做法是把绝对 URI
 * 发给代理），而 `https://` 需要先发 CONNECT 建隧道再在隧道里握手 TLS
 * —— PHP 的 https wrapper 不做这件事，直接给代理发 TLS ClientHello 只会失败。
 * SOCKS5 更是完全没有支持。
 *
 * 有 curl 扩展时用不到这个类（curl 自己全支持），它是为
 * 「没有 curl + 网络受限」这个组合准备的，而那恰恰是本库的目标环境之一。
 */
class ProxyConnector
{
    /**
     * 连到目标主机。
     *
     * @param string $host 目标主机名
     * @param int $port 目标端口
     * @param bool $useTls 建好隧道后是否要在上面做 TLS 握手
     * @param array<string, mixed> $sslOptions TLS 上下文选项
     * @return resource
     */
    public function connect(
        Proxy $proxy,
        string $host,
        int $port,
        bool $useTls,
        array $sslOptions = [],
        int $timeout = 30
    ) {
        $socket = $this->openSocket($proxy, $timeout);

        try {
            if ($proxy->isSocks()) {
                $this->socks5Handshake($socket, $proxy, $host, $port);
            } else {
                $this->httpConnect($socket, $proxy, $host, $port);
            }

            if ($useTls) {
                $this->enableTls($socket, $host, $sslOptions);
            }
        } catch (HttpException $e) {
            fclose($socket);

            throw $e;
        }

        return $socket;
    }

    /**
     * @return resource
     */
    private function openSocket(Proxy $proxy, int $timeout)
    {
        $errno = 0;
        $error = '';

        $context = stream_context_create([]);

        $socket = @stream_socket_client(
            $proxy->getSocketAddress(),
            $errno,
            $error,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($socket === false) {
            throw new HttpException(sprintf(
                '连不上代理 %s：%s',
                $proxy->toSafeString(),
                $error !== '' ? $error : ('错误码 ' . $errno)
            ));
        }

        stream_set_timeout($socket, $timeout);

        // https:// 形式的代理，到代理这一跳本身也要加密
        if ($proxy->needsTls()) {
            $ok = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
            if ($ok !== true) {
                fclose($socket);

                throw new HttpException(sprintf('与代理 %s 的 TLS 握手失败', $proxy->toSafeString()));
            }
        }

        return $socket;
    }

    /**
     * HTTP CONNECT 隧道（RFC 7231 §4.3.6）。
     *
     * @param resource $socket
     */
    private function httpConnect($socket, Proxy $proxy, string $host, int $port): void
    {
        $target = sprintf('%s:%d', $host, $port);

        $lines = [
            sprintf('CONNECT %s HTTP/1.1', $target),
            // Host 要写目标而不是代理，这是 CONNECT 的规定
            sprintf('Host: %s', $target),
            'Proxy-Connection: Keep-Alive',
        ];

        if ($proxy->hasCredentials()) {
            $lines[] = 'Proxy-Authorization: Basic ' . base64_encode(
                $proxy->getUsername() . ':' . (string) $proxy->getPassword()
            );
        }

        $request = implode("\r\n", $lines) . "\r\n\r\n";

        if (@fwrite($socket, $request) === false) {
            throw new HttpException(sprintf('向代理 %s 发送 CONNECT 请求失败', $proxy->toSafeString()));
        }

        $statusLine = '';
        $headerBlock = '';

        // 一行一行读到空行为止。不能用 fread 按块读——多读的字节属于隧道内容，
        // 丢掉的话后面的 TLS 握手就乱了
        while (($line = fgets($socket, 8192)) !== false) {
            if ($statusLine === '') {
                $statusLine = trim($line);
            }

            $headerBlock .= $line;

            if (trim($line) === '') {
                break;
            }
        }

        if ($statusLine === '') {
            throw new HttpException(sprintf(
                '代理 %s 没有响应 CONNECT 请求（连接可能被直接关闭）',
                $proxy->toSafeString()
            ));
        }

        if (preg_match('#^HTTP/\d(?:\.\d)?\s+(\d{3})#', $statusLine, $m) !== 1) {
            throw new HttpException(sprintf('代理 %s 返回了无法解析的响应：%s', $proxy->toSafeString(), $statusLine));
        }

        $status = (int) $m[1];

        if ($status === 407) {
            throw new HttpException(sprintf(
                '代理 %s 要求认证（HTTP 407）。在代理地址里带上用户名密码，'
                . '形如 http://user:pass@%s:%d',
                $proxy->toSafeString(),
                $proxy->getHost(),
                $proxy->getPort()
            ));
        }

        if ($status < 200 || $status > 299) {
            throw new HttpException(sprintf(
                '代理 %s 拒绝建立到 %s 的隧道：%s',
                $proxy->toSafeString(),
                $target,
                $statusLine
            ));
        }
    }

    /**
     * SOCKS5 握手（RFC 1928）与用户名密码认证（RFC 1929）。
     *
     * @param resource $socket
     */
    private function socks5Handshake($socket, Proxy $proxy, string $host, int $port): void
    {
        // 第一步：告诉代理我们支持哪些认证方式。
        // 0x00 = 不认证，0x02 = 用户名密码
        $methods = $proxy->hasCredentials() ? "\x00\x02" : "\x00";
        $greeting = "\x05" . \chr(\strlen($methods)) . $methods;

        $this->write($socket, $greeting, $proxy);
        $response = $this->read($socket, 2, $proxy);

        if ($response[0] !== "\x05") {
            throw new HttpException(sprintf(
                '%s 不是 SOCKS5 代理（版本字节是 0x%02x）',
                $proxy->toSafeString(),
                \ord($response[0])
            ));
        }

        $method = \ord($response[1]);

        if ($method === 0xFF) {
            throw new HttpException(sprintf(
                'SOCKS5 代理 %s 不接受我们提供的认证方式。%s',
                $proxy->toSafeString(),
                $proxy->hasCredentials() ? '请确认用户名密码正确' : '这个代理可能需要用户名密码'
            ));
        }

        if ($method === 0x02) {
            $this->socks5Authenticate($socket, $proxy);
        } elseif ($method !== 0x00) {
            throw new HttpException(sprintf(
                'SOCKS5 代理 %s 要求不支持的认证方式 0x%02x',
                $proxy->toSafeString(),
                $method
            ));
        }

        // 第二步：请求连接目标。
        // ATYP=0x03（域名）把解析交给代理——socks5h 的语义；
        // socks5 则本地解析成 IP 再发。本地 DNS 不通时必须用前者
        if ($proxy->resolvesRemotely() || !filter_var($host, FILTER_VALIDATE_IP)) {
            $address = "\x03" . \chr(\strlen($host)) . $host;
        } elseif (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $address = "\x01" . inet_pton($host);
        } else {
            $address = "\x04" . inet_pton($host);
        }

        // VER=5, CMD=1(CONNECT), RSV=0
        $request = "\x05\x01\x00" . $address . pack('n', $port);

        $this->write($socket, $request, $proxy);

        // 回复的前 4 字节是 VER REP RSV ATYP，之后的长度取决于 ATYP
        $head = $this->read($socket, 4, $proxy);
        $reply = \ord($head[1]);

        if ($reply !== 0x00) {
            throw new HttpException(sprintf(
                'SOCKS5 代理 %s 无法连接到 %s:%d：%s',
                $proxy->toSafeString(),
                $host,
                $port,
                $this->describeSocksError($reply)
            ));
        }

        // 把绑定地址读完丢掉，不读的话它会混进后面的 TLS 握手
        $type = \ord($head[3]);
        if ($type === 0x01) {
            $this->read($socket, 4 + 2, $proxy);
        } elseif ($type === 0x04) {
            $this->read($socket, 16 + 2, $proxy);
        } elseif ($type === 0x03) {
            $length = \ord($this->read($socket, 1, $proxy));
            $this->read($socket, $length + 2, $proxy);
        } else {
            throw new HttpException(sprintf('SOCKS5 代理返回了未知的地址类型 0x%02x', $type));
        }
    }

    /**
     * @param resource $socket
     */
    private function socks5Authenticate($socket, Proxy $proxy): void
    {
        $username = (string) $proxy->getUsername();
        $password = (string) $proxy->getPassword();

        // RFC 1929 的长度字段都是一字节，超了没法表示
        if (\strlen($username) > 255 || \strlen($password) > 255) {
            throw new HttpException('SOCKS5 的用户名与密码都不能超过 255 字节');
        }

        $request = "\x01"
            . \chr(\strlen($username)) . $username
            . \chr(\strlen($password)) . $password;

        $this->write($socket, $request, $proxy);
        $response = $this->read($socket, 2, $proxy);

        if (\ord($response[1]) !== 0x00) {
            throw new HttpException(sprintf(
                'SOCKS5 代理 %s 拒绝了用户名密码',
                $proxy->toSafeString()
            ));
        }
    }

    /**
     * 在已经建好的隧道上做 TLS 握手。
     *
     * @param resource $socket
     * @param array<string, mixed> $sslOptions
     */
    private function enableTls($socket, string $host, array $sslOptions): void
    {
        $options = array_merge([
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
            'SNI_enabled' => true,
        ], $sslOptions);

        // peer_name 必须显式给：socket 是连到代理的，PHP 无从知道
        // 我们真正想验证的是哪个域名，不给的话证书校验会对着代理的地址做
        $options['peer_name'] = $host;

        foreach ($options as $name => $value) {
            stream_context_set_option($socket, 'ssl', $name, $value);
        }

        $method = STREAM_CRYPTO_METHOD_TLS_CLIENT;

        $ok = @stream_socket_enable_crypto($socket, true, $method);

        if ($ok !== true) {
            $error = error_get_last();

            throw new HttpException(sprintf(
                '在代理隧道里与 %s 握手 TLS 失败：%s',
                $host,
                isset($error['message']) ? trim($error['message']) : '未知错误'
            ));
        }
    }

    /**
     * @param resource $socket
     */
    private function write($socket, string $data, Proxy $proxy): void
    {
        $length = \strlen($data);
        $written = 0;

        while ($written < $length) {
            $result = @fwrite($socket, substr($data, $written));

            if ($result === false || $result === 0) {
                throw new HttpException(sprintf('向代理 %s 写数据失败', $proxy->toSafeString()));
            }

            $written += $result;
        }
    }

    /**
     * 读满指定字节数。
     *
     * 必须按长度读满而不是读一次就算——SOCKS5 的应答可能分几个 TCP 包到，
     * 少读几个字节会让后面的解析全部错位。
     *
     * @param resource $socket
     */
    private function read($socket, int $length, Proxy $proxy): string
    {
        $data = '';

        while (\strlen($data) < $length) {
            $chunk = @fread($socket, $length - \strlen($data));

            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($socket);

                throw new HttpException(sprintf(
                    '从代理 %s 读数据失败（%s）',
                    $proxy->toSafeString(),
                    isset($meta['timed_out']) && $meta['timed_out'] ? '超时' : '连接被关闭'
                ));
            }

            $data .= $chunk;
        }

        return $data;
    }

    private function describeSocksError(int $code): string
    {
        $messages = [
            0x01 => '代理内部错误',
            0x02 => '规则不允许（代理的 ACL 拦了）',
            0x03 => '网络不可达',
            0x04 => '主机不可达',
            0x05 => '连接被拒绝',
            0x06 => 'TTL 超时',
            0x07 => '不支持的命令',
            0x08 => '不支持的地址类型',
        ];

        return isset($messages[$code]) ? $messages[$code] : sprintf('未知错误码 0x%02x', $code);
    }
}
