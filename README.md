# php-acme

用**原生 PHP** 实现的 ACME v2（RFC 8555）证书客户端 —— [acme.sh](https://github.com/acmesh-official/acme.sh) 的功能对等实现。

申请、续期、吊销、部署 Let's Encrypt / ZeroSSL / BuyPass / Google Trust Services / SSL.com 的免费 TLS 证书，
**全程不调用任何外部进程**。

[![PHP](https://img.shields.io/badge/PHP-%3E%3D7.2-777bb4)](composer.json)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 为什么又造一个轮子

acme.sh 很好用，但它是 shell 脚本，依赖 `openssl` 命令行、`curl`、`crontab`、`sed`/`awk`。
这在两类环境里会直接卡死：

- **共享主机 / 虚拟主机**：`disable_functions` 里躺着 `exec,shell_exec,system,proc_open,popen`，
  连 shell 都进不去，更别说跑脚本。
- **受管控的容器与 PaaS**：只给一个 PHP 运行时，没有 crontab，文件系统只读一半。

php-acme 把这些依赖全部换成 PHP 自己的能力：

| acme.sh 依赖 | php-acme 的做法 |
|---|---|
| `openssl genrsa` / `ecparam` | `ext-openssl` 的 `openssl_pkey_new()` |
| `openssl req -new`（要配 openssl.cnf 才能写 SAN） | 自己用 ASN.1 DER 编码器拼 CSR，**不碰配置文件** |
| `openssl x509 -noout -dates` | `openssl_x509_parse()` |
| `curl` | curl 扩展优先，没有则退回 stream wrapper |
| `crontab -e` | 打印该加的那行让你自己贴，或输出 systemd timer 配置 |
| `systemctl reload nginx` | 读 pid 文件 + `posix_kill()` 发 SIGHUP |
| `dns_*.sh`（150 个 shell 脚本） | `src/Challenge/Dns01/Provider/` 下的 PHP 类 |

源码里**没有一处** `exec`/`shell_exec`/`system`/`passthru`/`proc_open`/`popen`/反引号，
`tests/no_exec_test.php` 每次跑测试都会扫一遍守着这条线。

## 安装

```bash
composer require likun-mci/php-acme
```

跑不了 composer 的机器上，直接下载解压也能用 —— 项目自带零依赖的 `bootstrap.php`：

```bash
git clone https://github.com/likun-mci/php-acme.git
php php-acme/bin/php-acme --version
```

**要求**：PHP >= 7.2，`ext-openssl`、`ext-json`、`ext-mbstring`。
建议装 `ext-curl`（更稳的 HTTP）与 `ext-posix`（发重载信号）。

## 命令行用法

### 签发

```bash
# 用网站根目录验证（最常用）
php-acme issue -d example.com -d www.example.com -w /var/www/html

# 用 DNS 验证，可以签通配符
export CF_Token=你的-Cloudflare-令牌
php-acme issue -d example.com -d "*.example.com" --dns dns_cf

# 机器上没跑 web 服务时，临时占用 80 端口自己应答
php-acme issue -d example.com --standalone

# 换 CA、换密钥类型
php-acme issue -d example.com -w /var/www/html --ca zerossl -m you@example.com -k ec-384
```

> **调试时请用 staging**：`--ca letsencrypt_test`。正式环境每组域名每周只能签 5 张，
> 调参数很容易把额度用光，而额度是按周滚动的，用光了只能等。

### 安装到服务并自动重载

```bash
php-acme install-cert -d example.com \
    --key-file /etc/nginx/ssl/example.com.key \
    --fullchain-file /etc/nginx/ssl/example.com.crt \
    --reload-service nginx
```

这套配置会被记进证书的 `.conf`，**之后每次续期成功都自动重放一遍**，不用再手工执行。

`--reload-service` 支持 `nginx` / `apache` / `httpd` / `haproxy` / `php-fpm` / `postfix` / `dovecot`，
原理是读 pid 文件后发对应的信号（nginx 是 SIGHUP，Apache 是 SIGUSR1……）。

没有 `ext-posix` 或者服务不在本机时，改用标记文件：

```bash
php-acme install-cert -d example.com --key-file ... --touch-file /run/php-acme/renewed.json
```

配一个 systemd path unit 监听那个文件，由它去执行 `systemctl reload nginx`。

### 续期

```bash
php-acme renew -d example.com          # 单张
php-acme renew-all                     # 全部（cron 里跑这个）
php-acme cron                          # 打印该加的 crontab 行
php-acme cron --systemd                # 或者输出 systemd timer 配置
```

续期用的验证方式、CA、密钥类型、DNS 凭据都从证书目录的 `.conf` 读，不用重复指定。
单张失败不影响其他证书，最后统一汇报。

### 其他

```bash
php-acme list                          # 列出所有证书与到期时间
php-acme info -d example.com           # 看某张证书的详情
php-acme revoke -d example.com --reason 4
php-acme remove -d example.com         # 只删本地文件，证书仍有效
php-acme account show                  # 看账户信息
php-acme check-dns -d example.com      # 排查 dns-01：直接问权威 NS
php-acme list-dns                      # 列出支持的 DNS 提供商与所需变量
```

acme.sh 风格的写法也能用，现有脚本改个程序名就行：

```bash
php-acme --issue -d example.com -w /var/www/html --server letsencrypt_test
```

## 作为库使用

```php
require 'vendor/autoload.php';

use PhpAcme\Acme;
use PhpAcme\Util\Logger;

$acme = new Acme(null, new Logger(Logger::LEVEL_INFO, STDOUT));

$result = $acme->issue(
    ['example.com', 'www.example.com'],
    '/var/www/html',                       // 或 'dns_cf'，或 'no'（standalone）
    ['email' => 'you@example.com', 'key_type' => 'ec-256']
);

if ($result->isIssued()) {
    echo $result->getPath('fullchain'), "\n";
    echo $result->getCertificate()->getDaysUntilExpiry(), " 天后到期\n";
} elseif ($result->isSkipped()) {
    echo $result->getMessage(), "\n";   // 还没到续期窗口
}
```

各层都可以单独拿出来用：

```php
// 只想生成一个带 SAN 的 CSR，不走 openssl.cnf
use PhpAcme\Crypto\{KeyPair, Csr};

$key = KeyPair::generate('ec-256');
$csr = Csr::createPem($key, ['example.com', '*.example.com']);
```

## 支持的 CA

| 短名 | CA | 需要 EAB |
|---|---|---|
| `letsencrypt` | Let's Encrypt（默认） | 否 |
| `letsencrypt_test` | Let's Encrypt Staging | 否 |
| `zerossl` | ZeroSSL | 是（可用邮箱自动换取） |
| `buypass` / `buypass_test` | Buypass Go SSL | 否 |
| `google` / `google_test` | Google Trust Services | 是 |
| `sslcom` / `sslcom_ecc` | SSL.com | 是 |
| `actalis` | Actalis | 是 |

也可以直接写目录 URL，用没列在这里的 CA。

## 支持的 DNS 提供商

短名与环境变量都与 acme.sh 保持一致，已经 export 过的变量继续有效：

| 短名 | 提供商 | 环境变量 |
|---|---|---|
| `dns_cf` | Cloudflare | `CF_Token`（推荐）或 `CF_Key` + `CF_Email` |
| `dns_ali` | 阿里云 DNS | `Ali_Key`、`Ali_Secret` |
| `dns_dp` | DNSPod | `DP_Id`、`DP_Key` |
| `dns_tencent` | 腾讯云 DNSPod | `Tencent_SecretId`、`Tencent_SecretKey` |
| `dns_huaweicloud` | 华为云 DNS | `HUAWEICLOUD_AccessKey`、`HUAWEICLOUD_SecretKey` |
| `dns_gd` | GoDaddy | `GD_Key`、`GD_Secret` |
| `dns_aws` | AWS Route 53 | `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY` |
| `dns_dgon` | DigitalOcean | `DO_API_KEY` |
| `dns_vultr` | Vultr | `VULTR_API_KEY` |
| `dns_linode_v4` | Linode | `LINODE_V4_API_KEY` |
| `dns_hetzner` | Hetzner DNS | `HETZNER_Token` |
| `dns_gandi_livedns` | Gandi LiveDNS | `GANDI_LIVEDNS_TOKEN` 或 `GANDI_LIVEDNS_KEY` |
| `dns_namesilo` | NameSilo | `Namesilo_Key` |
| `dns_duckdns` | DuckDNS | `DuckDNS_Token` |
| `dns_he` | Hurricane Electric | `HE_DDNS_Key` |
| `dns_manual` | 手动（打印记录让你自己加） | — |

签发时凭据会存进证书目录的 `.conf`（带 `SAVED_` 前缀，与 acme.sh 一致），之后续期不用再 export。

**加一家新的很简单**：实现 `DnsProviderInterface` 的两个方法，在 `ProviderFactory::MAP` 注册短名，
补一条用 `MockTransport` 的测试。详见 [.claude/CLAUDE.md](.claude/CLAUDE.md)。

## 文件布局

默认在 `~/.php-acme/`，结构照抄 acme.sh，两边可以互相迁移：

```
~/.php-acme/
  account.conf                    全局配置
  ca/<host>/<path>/
    account.key                   账户私钥（0600）
    ca.conf                       账户 URL、邮箱、EAB 凭据
  example.com_ecc/
    example.com.key               证书私钥（0600）
    example.com.csr
    example.com.cer               叶子证书
    ca.cer                        中间证书
    fullchain.cer                 叶子 + 中间（nginx 用这个）
    example.com.conf              签发参数，续期时照着重放
```

想直接接管 acme.sh 的数据，把 `--home ~/.acme.sh` 指过去即可。

## 一些实现上的取舍

**CSR 自己拼 DER。** `openssl_csr_new()` 要通过 openssl.cnf 里的 `req_extensions`
才能写 subjectAltName，那意味着运行时得往磁盘写临时配置文件 —— 在 `open_basedir` 受限、
临时目录只读的主机上直接歇菜。自己拼字节就完全绕开了这个问题，
openssl 扩展只负责最后那一次签名。生成的 CSR 通过了 `openssl req -verify` 的校验。

**dns-01 的传播检测直接问权威 NS。** 不用 `dns_get_record()`：它走系统解析器，
而刚写完 TXT 记录马上查的话，本地解析器很可能还留着几分钟前的**负缓存**。
`src/Util/DnsResolver.php` 是一个轻量 DNS 客户端，先查域名的 NS 再直接问它们，
UDP 响应被截断（TC 位）时自动换 TCP。

**服务重载用信号而不是 shell。** `nginx -s reload` 本质就是读 pid 文件然后 `kill -HUP`，
`systemctl reload` 也只是转发信号。直接 `posix_kill()` 效果一样，还少一层依赖。

**通配符只能用 dns-01**，这是 CA 的硬规则 —— 服务端根本不会为 `*.example.com`
提供 http-01 挑战。本库在构造请求时就拦下来，而不是等到跑一半才失败。

## 测试

```bash
composer test          # 全部离线测试，不联网，约 20 秒
composer test-network  # 对 Let's Encrypt staging 跑一次真实签发（需要真实域名）
```

离线测试有 **21 个文件、900 多项断言**，全部不打真实 CA、不打真实 DNS API：

- `tests/lib/FakeAcmeServer.php` 是一个**会真验签的** ACME 服务端模拟器 ——
  它校验 JWS 签名、检测 nonce 重放、按状态机推进订单、核对 CSR 里的 SAN
  是否与订单一致，最后用测试 CA 密钥给 CSR 签一张真证书。
  签名格式、nonce 处理、状态机流转这些最容易写错又最难排查的地方，在这里能给出明确的失败原因。
- 加密部分用了 **RFC 7638（JWK Thumbprint）与 RFC 3492（Punycode）的官方测试向量**，
  CSR 与自签证书另外过了一遍 `openssl` 命令行的交叉校验。
- DNS 提供商的签名算法（阿里云 HMAC-SHA1、腾讯云 TC3、AWS SigV4）都按规范手工重算了一遍对拍。
- `php72_compat_test.php` 静态扫描 PHP 7.2 语法兼容性，`no_exec_test.php` 扫描外部进程调用，
  两者都带规则自检与反向自检。

## 协作与开发约定

见 [.claude/CLAUDE.md](.claude/CLAUDE.md)：PHP 7.2 的语法红线、加密相关的坑、
新增 DNS 提供商的步骤、以及「改完必须跑测试再提交」的收尾流程。

## 许可

MIT
