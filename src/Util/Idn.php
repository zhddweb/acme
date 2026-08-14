<?php

declare(strict_types=1);

namespace PhpAcme\Util;

use PhpAcme\Exception\ConfigException;

/**
 * 国际化域名（IDN）与 punycode。
 *
 * ACME 协议里 identifier 的 value 必须是 A-label（xn-- 形式），
 * 直接把「中文.com」提交上去服务端会拒。ext-intl 装了就用它，
 * 没装则用这里的纯 PHP 实现——目标环境上 intl 经常是缺的。
 *
 * 实现的是 RFC 3492 的 Punycode 编码；不做完整的 IDNA2008 映射
 * （大小写折叠、NFC 归一化那些），只做最常见的小写化。
 * 域名本身大小写不敏感，这个取舍对签证书够用了。
 */
final class Idn
{
    const BASE = 36;
    const TMIN = 1;
    const TMAX = 26;
    const SKEW = 38;
    const DAMP = 700;
    const INITIAL_BIAS = 72;
    const INITIAL_N = 128;
    const DELIMITER = '-';
    const PREFIX = 'xn--';

    /**
     * 域名转 ASCII（A-label）。
     *
     * 已经是纯 ASCII 的原样返回（只做小写化），避免对 example.com 也走一遍编码。
     */
    public static function toAscii(string $domain): string
    {
        $domain = trim($domain);
        if ($domain === '') {
            return '';
        }

        // 通配符前缀不参与编码，先摘掉最后再拼回去
        $wildcard = false;
        if (str_starts_with($domain, '*.')) {
            $wildcard = true;
            $domain = substr($domain, 2);
        }

        $result = self::isAscii($domain)
            ? strtolower($domain)
            : self::encodeDomain($domain);

        return $wildcard ? '*.' . $result : $result;
    }

    /**
     * A-label 转回 Unicode，只用于给用户看的输出。
     */
    public static function toUnicode(string $domain): string
    {
        $wildcard = false;
        if (str_starts_with($domain, '*.')) {
            $wildcard = true;
            $domain = substr($domain, 2);
        }

        if (Platform::hasIntl()) {
            $converted = @idn_to_utf8($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if (\is_string($converted) && $converted !== '') {
                return $wildcard ? '*.' . $converted : $converted;
            }
        }

        $labels = [];
        foreach (explode('.', $domain) as $label) {
            $labels[] = str_starts_with(strtolower($label), self::PREFIX)
                ? self::decodeLabel(substr($label, \strlen(self::PREFIX)))
                : $label;
        }

        $result = implode('.', $labels);

        return $wildcard ? '*.' . $result : $result;
    }

    public static function isAscii(string $value): bool
    {
        return preg_match('/[^\x00-\x7F]/', $value) !== 1;
    }

    private static function encodeDomain(string $domain): string
    {
        if (Platform::hasIntl()) {
            // UTS46 变体才是现行标准，IDNA2003 那套对某些字符的映射已经过时
            $converted = @idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if (\is_string($converted) && $converted !== '') {
                return strtolower($converted);
            }
        }

        $labels = [];
        foreach (explode('.', $domain) as $label) {
            $labels[] = self::isAscii($label)
                ? strtolower($label)
                : self::PREFIX . self::encodeLabel($label);
        }

        return implode('.', $labels);
    }

    /**
     * RFC 3492 的 punycode 编码，输入是单个 UTF-8 标签。
     */
    public static function encodeLabel(string $label): string
    {
        $codePoints = self::utf8ToCodePoints($label);

        $basic = [];
        foreach ($codePoints as $code) {
            if ($code < self::INITIAL_N) {
                // 基本码位保留原字符，但要小写化
                $basic[] = $code >= 65 && $code <= 90 ? $code + 32 : $code;
            }
        }

        $output = '';
        foreach ($basic as $code) {
            $output .= \chr($code);
        }

        $handled = \count($basic);
        $basicCount = $handled;
        if ($basicCount > 0) {
            $output .= self::DELIMITER;
        }

        $n = self::INITIAL_N;
        $delta = 0;
        $bias = self::INITIAL_BIAS;
        $total = \count($codePoints);

        while ($handled < $total) {
            // 找出还没处理的码位里最小的那个
            $m = null;
            foreach ($codePoints as $code) {
                if ($code >= $n && ($m === null || $code < $m)) {
                    $m = $code;
                }
            }

            if ($m === null) {
                break;
            }

            $delta += ($m - $n) * ($handled + 1);
            $n = $m;

            foreach ($codePoints as $code) {
                if ($code < $n) {
                    ++$delta;
                } elseif ($code === $n) {
                    $q = $delta;
                    for ($k = self::BASE; ; $k += self::BASE) {
                        $t = self::threshold($k, $bias);
                        if ($q < $t) {
                            break;
                        }
                        $output .= self::digitToChar($t + (($q - $t) % (self::BASE - $t)));
                        $q = intdiv($q - $t, self::BASE - $t);
                    }
                    $output .= self::digitToChar($q);
                    $bias = self::adapt($delta, $handled + 1, $handled === $basicCount);
                    $delta = 0;
                    ++$handled;
                }
            }

            ++$delta;
            ++$n;
        }

        return $output;
    }

    /**
     * punycode 解码，输入是去掉 xn-- 前缀的部分。
     */
    public static function decodeLabel(string $encoded): string
    {
        $n = self::INITIAL_N;
        $i = 0;
        $bias = self::INITIAL_BIAS;

        $pos = strrpos($encoded, self::DELIMITER);
        $output = [];
        if ($pos !== false && $pos > 0) {
            for ($k = 0; $k < $pos; ++$k) {
                $output[] = \ord($encoded[$k]);
            }
            $encoded = substr($encoded, $pos + 1);
        }

        $length = \strlen($encoded);
        for ($idx = 0; $idx < $length;) {
            $oldi = $i;
            $w = 1;
            for ($k = self::BASE; ; $k += self::BASE) {
                if ($idx >= $length) {
                    throw new ConfigException(sprintf('punycode 串不完整：%s', $encoded));
                }
                $digit = self::charToDigit($encoded[$idx]);
                ++$idx;
                $i += $digit * $w;
                $t = self::threshold($k, $bias);
                if ($digit < $t) {
                    break;
                }
                $w *= self::BASE - $t;
            }

            $outLen = \count($output) + 1;
            $bias = self::adapt($i - $oldi, $outLen, $oldi === 0);
            $n += intdiv($i, $outLen);
            $i %= $outLen;
            array_splice($output, $i, 0, [$n]);
            ++$i;
        }

        return self::codePointsToUtf8($output);
    }

    private static function threshold(int $k, int $bias): int
    {
        $t = $k - $bias;
        if ($t < self::TMIN) {
            return self::TMIN;
        }
        if ($t > self::TMAX) {
            return self::TMAX;
        }

        return $t;
    }

    private static function adapt(int $delta, int $numPoints, bool $firstTime): int
    {
        $delta = $firstTime ? intdiv($delta, self::DAMP) : $delta >> 1;
        $delta += intdiv($delta, $numPoints);

        $k = 0;
        while ($delta > intdiv((self::BASE - self::TMIN) * self::TMAX, 2)) {
            $delta = intdiv($delta, self::BASE - self::TMIN);
            $k += self::BASE;
        }

        return $k + intdiv((self::BASE - self::TMIN + 1) * $delta, $delta + self::SKEW);
    }

    private static function digitToChar(int $digit): string
    {
        // 0-25 -> a-z，26-35 -> 0-9
        return \chr($digit + 22 + ($digit < 26 ? 75 : 0));
    }

    private static function charToDigit(string $char): int
    {
        $code = \ord($char);
        if ($code >= 48 && $code <= 57) {
            return $code - 22;
        }
        if ($code >= 97 && $code <= 122) {
            return $code - 97;
        }
        if ($code >= 65 && $code <= 90) {
            return $code - 65;
        }

        throw new ConfigException(sprintf('punycode 串里出现非法字符：%s', $char));
    }

    /** @return array<int, int> */
    private static function utf8ToCodePoints(string $value): array
    {
        $points = [];
        $length = \strlen($value);

        for ($i = 0; $i < $length;) {
            $byte = \ord($value[$i]);

            if ($byte < 0x80) {
                $points[] = $byte;
                $i += 1;
            } elseif (($byte & 0xE0) === 0xC0) {
                $points[] = (($byte & 0x1F) << 6) | (\ord($value[$i + 1]) & 0x3F);
                $i += 2;
            } elseif (($byte & 0xF0) === 0xE0) {
                $points[] = (($byte & 0x0F) << 12)
                    | ((\ord($value[$i + 1]) & 0x3F) << 6)
                    | (\ord($value[$i + 2]) & 0x3F);
                $i += 3;
            } elseif (($byte & 0xF8) === 0xF0) {
                $points[] = (($byte & 0x07) << 18)
                    | ((\ord($value[$i + 1]) & 0x3F) << 12)
                    | ((\ord($value[$i + 2]) & 0x3F) << 6)
                    | (\ord($value[$i + 3]) & 0x3F);
                $i += 4;
            } else {
                throw new ConfigException('域名不是合法的 UTF-8 编码');
            }
        }

        return $points;
    }

    /** @param array<int, int> $points */
    private static function codePointsToUtf8(array $points): string
    {
        $out = '';
        foreach ($points as $code) {
            if ($code < 0x80) {
                $out .= \chr($code);
            } elseif ($code < 0x800) {
                $out .= \chr(0xC0 | ($code >> 6)) . \chr(0x80 | ($code & 0x3F));
            } elseif ($code < 0x10000) {
                $out .= \chr(0xE0 | ($code >> 12))
                    . \chr(0x80 | (($code >> 6) & 0x3F))
                    . \chr(0x80 | ($code & 0x3F));
            } else {
                $out .= \chr(0xF0 | ($code >> 18))
                    . \chr(0x80 | (($code >> 12) & 0x3F))
                    . \chr(0x80 | (($code >> 6) & 0x3F))
                    . \chr(0x80 | ($code & 0x3F));
            }
        }

        return $out;
    }
}
