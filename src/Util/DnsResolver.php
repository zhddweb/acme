<?php

declare(strict_types=1);

namespace PhpAcme\Util;

use PhpAcme\Exception\DnsException;

/**
 * 轻量 DNS 客户端，直接向指定服务器发 UDP 查询。
 *
 * 为什么不用 dns_get_record()：它走系统解析器，而系统解析器有缓存。
 * dns-01 的流程是「刚写完 TXT 记录马上查」，此时本地解析器很可能
 * 还留着几分钟前的**负缓存**（NXDOMAIN 或空 TXT），于是我们等到超时，
 * 而记录其实早就生效了。直接问域名的**权威 NS** 就没有这个问题。
 *
 * 只实现 TXT、NS、A/AAAA 四种查询，够 dns-01 用。
 * 没有 EDNS0、没有 DNSSEC 校验、不做 TCP 重试——响应超过 512 字节时
 * 会被截断标记，那种情况退回系统解析器。
 */
class DnsResolver
{
    const TYPE_A = 1;
    const TYPE_NS = 2;
    const TYPE_CNAME = 5;
    const TYPE_TXT = 16;
    const TYPE_AAAA = 28;

    /**
     * 公共递归解析器，用于查权威 NS。
     *
     * 列了四家不同运营方的：某一家在某些网络里被劫持或屏蔽是常事，
     * 挨个试总有一个通的。
     *
     * @var array<int, string>
     */
    const PUBLIC_RESOLVERS = [
        '1.1.1.1',        // Cloudflare
        '8.8.8.8',        // Google
        '9.9.9.9',        // Quad9
        '223.5.5.5',      // 阿里，境内网络下往往只有这个通
    ];

    /** @var int 单次查询超时（秒） */
    private $timeout = 5;

    /** @var array<int, string> 覆盖默认解析器 */
    private $resolvers;

    /** @var Logger */
    private $logger;

    /**
     * @param array<int, string>|null $resolvers
     */
    public function __construct(?array $resolvers = null, ?Logger $logger = null)
    {
        $this->resolvers = $resolvers !== null && $resolvers !== [] ? $resolvers : self::PUBLIC_RESOLVERS;
        $this->logger = $logger !== null ? $logger : Logger::silent();
    }

    public function setTimeout(int $seconds): void
    {
        $this->timeout = max(1, $seconds);
    }

    /**
     * 查 TXT 记录。
     *
     * @param string|null $server 指定 DNS 服务器；null 表示挨个试内置的公共解析器
     * @return array<int, string>
     */
    public function txt(string $name, ?string $server = null): array
    {
        return $this->lookup($name, self::TYPE_TXT, $server);
    }

    /**
     * 查某个域名的权威 NS。
     *
     * 从完整域名开始逐级往上问：a.b.example.com 没有独立 NS 时，
     * 会一路退到 example.com。返回空数组表示一个都没查到。
     *
     * @return array<int, string>
     */
    public function authoritativeNameservers(string $domain): array
    {
        $labels = explode('.', rtrim(strtolower($domain), '.'));

        while (\count($labels) >= 2) {
            $candidate = implode('.', $labels);
            $records = $this->lookup($candidate, self::TYPE_NS, null);
            if ($records !== []) {
                return $records;
            }
            array_shift($labels);
        }

        return [];
    }

    /**
     * 向域名的权威 NS 直接查 TXT。
     *
     * 这是 dns-01 传播检测该用的方式：绕开一切缓存，问的就是最终答案。
     * 拿不到权威 NS（网络限制、UDP 被封）时退回普通查询，
     * 让流程还能走下去，只是慢一点。
     *
     * @return array<int, string>
     */
    public function txtFromAuthoritative(string $name): array
    {
        $nameservers = $this->authoritativeNameservers($name);

        if ($nameservers === []) {
            $this->logger->debug(sprintf('查不到 %s 的权威 NS，退回公共解析器', $name));

            return $this->txt($name);
        }

        $values = [];
        foreach ($nameservers as $nameserver) {
            $ips = $this->lookup($nameserver, self::TYPE_A, null);
            if ($ips === []) {
                continue;
            }

            $records = $this->query($name, self::TYPE_TXT, $ips[0]);
            if ($records === null) {
                continue;
            }

            // 权威服务器之间可能还没同步完，任何一台上有就算数——
            // CA 也是随机挑一台问的，宽松判定反而更贴近真实情况
            foreach ($records as $record) {
                $values[] = $record;
            }
        }

        return array_values(array_unique($values));
    }

    /**
     * 逐个解析器尝试，第一个有响应的算数。
     *
     * @return array<int, string>
     */
    public function lookup(string $name, int $type, ?string $server = null): array
    {
        $servers = $server !== null ? [$server] : $this->resolvers;

        foreach ($servers as $candidate) {
            $result = $this->query($name, $type, $candidate);
            if ($result !== null) {
                return $result;
            }
        }

        // UDP 全都不通时（容器里常见）退回系统解析器
        return $this->fallbackToSystem($name, $type);
    }

    /**
     * 发一次查询。返回 null 表示这台服务器没能给出响应。
     *
     * @return array<int, string>|null
     */
    public function query(string $name, int $type, string $server): ?array
    {
        $name = rtrim(strtolower($name), '.');

        // 事务 ID 用随机数：不校验它的话，任何抢先到达的 UDP 包都会被当成答案
        $id = random_int(0, 0xFFFF);
        $packet = $this->buildQuery($id, $name, $type);

        $errno = 0;
        $error = '';
        $socket = @stream_socket_client(
            sprintf('udp://%s:53', $server),
            $errno,
            $error,
            $this->timeout
        );

        if ($socket === false) {
            return null;
        }

        stream_set_timeout($socket, $this->timeout);

        if (@fwrite($socket, $packet) === false) {
            fclose($socket);

            return null;
        }

        $response = @fread($socket, 4096);
        $meta = stream_get_meta_data($socket);
        fclose($socket);

        if ($response === false || $response === '' || (isset($meta['timed_out']) && $meta['timed_out'])) {
            return null;
        }

        // TC 位置位说明答案装不进 512 字节的 UDP 响应，服务端只回了个空壳。
        // 这在域名有多条 TXT 记录时很常见（SPF + DKIM + 各种站长验证），
        // 而 _acme-challenge 恰恰可能和它们挤在一起。按 RFC 1035 换 TCP 重问
        if ($this->isTruncated($response)) {
            $response = $this->queryTcp($packet, $server);
            if ($response === null) {
                return null;
            }
        }

        try {
            return $this->parseResponse($response, $id, $type);
        } catch (DnsException $e) {
            $this->logger->debug(sprintf('解析 %s 的 DNS 响应失败：%s', $server, $e->getMessage()));

            return null;
        }
    }

    /** 响应头 flags 的第 6 位（从高位数）是 TC —— 答案被截断 */
    private function isTruncated(string $response): bool
    {
        if (\strlen($response) < 4) {
            return false;
        }

        $header = unpack('nid/nflags', substr($response, 0, 4));

        return $header !== false && (($header['flags'] >> 9) & 1) === 1;
    }

    /**
     * 走 TCP 重问一次。
     *
     * TCP 上的 DNS 报文前面多两个字节的长度前缀，其余和 UDP 完全一样。
     * 要按这个长度读满——TCP 是流，一次 fread 不保证给全。
     */
    private function queryTcp(string $packet, string $server): ?string
    {
        $errno = 0;
        $error = '';
        $socket = @stream_socket_client(
            sprintf('tcp://%s:53', $server),
            $errno,
            $error,
            $this->timeout
        );

        if ($socket === false) {
            return null;
        }

        stream_set_timeout($socket, $this->timeout);

        if (@fwrite($socket, pack('n', \strlen($packet)) . $packet) === false) {
            fclose($socket);

            return null;
        }

        $prefix = @fread($socket, 2);
        if ($prefix === false || \strlen($prefix) < 2) {
            fclose($socket);

            return null;
        }

        $unpacked = unpack('nlength', $prefix);
        if ($unpacked === false || $unpacked['length'] === 0) {
            fclose($socket);

            return null;
        }

        $remaining = $unpacked['length'];
        $response = '';
        while ($remaining > 0) {
            $chunk = @fread($socket, $remaining);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $response .= $chunk;
            $remaining -= \strlen($chunk);
        }

        fclose($socket);

        return $response !== '' ? $response : null;
    }

    private function buildQuery(int $id, string $name, int $type): string
    {
        // flags = 0x0100：标准查询 + 期望递归
        $header = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);

        $qname = '';
        foreach (explode('.', $name) as $label) {
            if ($label === '') {
                continue;
            }
            $qname .= \chr(\strlen($label)) . $label;
        }
        $qname .= "\x00";

        return $header . $qname . pack('nn', $type, 1);
    }

    /**
     * @return array<int, string>
     */
    private function parseResponse(string $response, int $expectedId, int $expectedType): array
    {
        if (\strlen($response) < 12) {
            throw new DnsException('DNS 响应太短，连头都不完整');
        }

        $header = unpack('nid/nflags/nqd/nan/nns/nar', substr($response, 0, 12));
        if ($header === false) {
            throw new DnsException('DNS 响应头解析失败');
        }

        if ($header['id'] !== $expectedId) {
            // 不是我们的问题的答案，可能是上一次查询的迟到响应，或者投毒
            throw new DnsException('DNS 响应的事务 ID 对不上');
        }

        $rcode = $header['flags'] & 0x0F;
        if ($rcode === 3) {
            // NXDOMAIN 是合法答案，意思是「没有这条记录」
            return [];
        }
        if ($rcode !== 0) {
            throw new DnsException(sprintf('DNS 服务器返回错误码 %d', $rcode));
        }

        $offset = 12;

        // 跳过 question section
        for ($i = 0; $i < $header['qd']; ++$i) {
            $this->skipName($response, $offset);
            $offset += 4;
        }

        $results = [];
        for ($i = 0; $i < $header['an']; ++$i) {
            $this->skipName($response, $offset);

            if ($offset + 10 > \strlen($response)) {
                break;
            }

            $rr = unpack('ntype/nclass/Nttl/nlength', substr($response, $offset, 10));
            if ($rr === false) {
                break;
            }
            $offset += 10;

            $rdata = substr($response, $offset, $rr['length']);
            $rdataOffset = $offset;
            $offset += $rr['length'];

            if ($rr['type'] !== $expectedType) {
                // 常见于查 A 却先收到 CNAME，跳过继续看下一条
                continue;
            }

            $results[] = $this->parseRdata($response, $rdata, $rdataOffset, $expectedType);
        }

        return array_values(array_filter($results, static function (string $value): bool {
            return $value !== '';
        }));
    }

    private function parseRdata(string $response, string $rdata, int $rdataOffset, int $type): string
    {
        switch ($type) {
            case self::TYPE_TXT:
                // TXT 的 RDATA 是一串 <长度><内容>，长文本会被切成多段，
                // 拼回去才是原值。dns-01 的值只有 43 字节，用不着拼，
                // 但用户的其他 TXT 记录可能很长
                $text = '';
                $pos = 0;
                $length = \strlen($rdata);
                while ($pos < $length) {
                    $partLength = \ord($rdata[$pos]);
                    ++$pos;
                    $text .= substr($rdata, $pos, $partLength);
                    $pos += $partLength;
                }

                return $text;

            case self::TYPE_A:
                return \strlen($rdata) === 4 ? inet_ntop($rdata) : '';

            case self::TYPE_AAAA:
                return \strlen($rdata) === 16 ? inet_ntop($rdata) : '';

            case self::TYPE_NS:
            case self::TYPE_CNAME:
                // 域名可能用了压缩指针，得回到整个响应里去读
                $offset = $rdataOffset;

                return $this->readName($response, $offset);

            default:
                return '';
        }
    }

    /**
     * 读一个域名，处理压缩指针。
     *
     * 压缩指针（高两位为 11）指向响应里的某个偏移，避免重复存储相同后缀。
     * 恶意或损坏的响应可能构造出指针环，所以要限制跳转次数。
     */
    private function readName(string $response, int &$offset): string
    {
        $labels = [];
        $jumps = 0;
        $position = $offset;
        $jumped = false;

        while (true) {
            if ($position >= \strlen($response)) {
                throw new DnsException('DNS 响应里的域名越界');
            }

            $length = \ord($response[$position]);

            if ($length === 0) {
                ++$position;
                break;
            }

            if (($length & 0xC0) === 0xC0) {
                if ($position + 1 >= \strlen($response)) {
                    throw new DnsException('DNS 压缩指针不完整');
                }
                if (++$jumps > 16) {
                    throw new DnsException('DNS 域名压缩指针成环');
                }

                $pointer = (($length & 0x3F) << 8) | \ord($response[$position + 1]);
                if (!$jumped) {
                    // 只有第一次跳转要推进外部偏移，后面都在别处读
                    $offset = $position + 2;
                    $jumped = true;
                }
                $position = $pointer;
                continue;
            }

            ++$position;
            $labels[] = substr($response, $position, $length);
            $position += $length;
        }

        if (!$jumped) {
            $offset = $position;
        }

        return implode('.', $labels);
    }

    private function skipName(string $response, int &$offset): void
    {
        $this->readName($response, $offset);
    }

    /**
     * UDP 走不通时的退路。
     *
     * @return array<int, string>
     */
    private function fallbackToSystem(string $name, int $type): array
    {
        if (!Platform::hasDnsGet()) {
            return [];
        }

        $map = [
            self::TYPE_TXT => DNS_TXT,
            self::TYPE_NS => DNS_NS,
            self::TYPE_A => DNS_A,
            self::TYPE_AAAA => DNS_AAAA,
        ];

        if (!isset($map[$type])) {
            return [];
        }

        $records = @dns_get_record($name, $map[$type]);
        if (!\is_array($records)) {
            return [];
        }

        $out = [];
        foreach ($records as $record) {
            if ($type === self::TYPE_TXT && isset($record['txt'])) {
                $out[] = (string) $record['txt'];
            } elseif ($type === self::TYPE_NS && isset($record['target'])) {
                $out[] = (string) $record['target'];
            } elseif ($type === self::TYPE_A && isset($record['ip'])) {
                $out[] = (string) $record['ip'];
            } elseif ($type === self::TYPE_AAAA && isset($record['ipv6'])) {
                $out[] = (string) $record['ipv6'];
            }
        }

        return $out;
    }
}
