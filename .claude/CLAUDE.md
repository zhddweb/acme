# php-acme 项目约束

## 这个库是做什么的

用**原生 PHP** 完整实现 [acme.sh](https://github.com/acmesh-official/acme.sh) 的功能：
一个 ACME v2（RFC 8555）客户端，从头到尾申请、续期、吊销、部署 TLS 证书。

acme.sh 是 shell 脚本，依赖 `openssl` 命令行、`curl`、`crontab`、`sed`/`awk`。
本库把这些全部换成 PHP 自己的能力：

| acme.sh 依赖 | 本库的做法 |
|---|---|
| `openssl genrsa` / `ecparam` | `ext-openssl` 的 `openssl_pkey_new()` |
| `openssl req -new`（配 openssl.cnf 写 SAN） | 自己用 ASN.1 DER 编码器拼 CSR，见 `src/Asn1/` |
| `openssl x509 -noout -dates` | `openssl_x509_parse()` |
| `curl` | `src/Http/HttpClient.php`，curl 扩展优先、无则退回 stream |
| `crontab` | `src/Cli/Command/CronCommand.php`，也可由外部调度器直接调 `renew --all` |
| shell 里的 dns_*.sh | `src/Challenge/Dns01/Provider/` 下的 PHP 类 |

**不调用任何外部进程**：源码里不允许出现 `exec`、`shell_exec`、`system`、
`passthru`、`proc_open`、`popen`。理由和 php-composer 一样——目标运行环境是
禁用了这些函数的共享主机与受管控服务器。`tests/no_exec_test.php` 会扫描并拦截。

### 功能范围

- **协议**：目录发现、nonce 管理、账户注册/更新/密钥轮换/注销、
  订单、授权、挑战、finalize、下载证书、吊销（RFC 8555 全流程）
- **密钥**：RSA 2048/3072/4096、EC P-256/P-384/P-521；JWS 签名 RS256/ES256/ES384/ES512
- **CA**：Let's Encrypt、ZeroSSL、BuyPass、Google Trust Services、SSL.com，
  含 External Account Binding（ZeroSSL 支持用邮箱自动换取 EAB 凭据）
- **验证方式**：http-01（webroot / 内置 standalone 服务器）、dns-01、tls-alpn-01
- **DNS 提供商**：`src/Challenge/Dns01/Provider/` 下一家一个类，见下节
- **部署**：`src/Deploy/Hook/`，安装到 nginx/apache 路径、导出 PKCS#12 等
- **通知**：`src/Notify/Hook/`，签发/续期/失败时推送
- **CLI**：`bin/php-acme`，命令与 acme.sh 对齐（`--issue`、`--renew`、`--revoke` …）
- **库调用**：`PhpAcme\Acme` 门面类，不用 CLI 也能在业务代码里直接签发

### 目录布局

证书与账户默认存在 `~/.php-acme/`，结构照抄 acme.sh，方便双向迁移：

```
~/.php-acme/
  account.conf              # 全局配置
  ca/<ca-host>/<dir>/       # 每个 CA 一份账户密钥 + account.json
  <domain>[_ecc]/           # 每个证书一个目录
    <domain>.key  .csr  .cer  ca.cer  fullchain.cer  <domain>.conf
```

## 最低支持 PHP 7.2 —— 这是硬约束

开发机跑的是 PHP 8.3，`php -l` 用的是当前版本的解析器，**7.3+ 的语法在那里一路绿灯**，
只有真跑在 7.2 上才会炸。不能靠"本地没报错"判断。

### 禁止使用的语法（按引入版本）

| 版本 | 禁用 | 改用 |
|---|---|---|
| 7.3 | heredoc/nowdoc 缩进结束标识符 | 结束标识符顶格，**内容也要同步顶格** |
| 7.3 | 函数**调用**的尾随逗号 | 删掉（数组字面量 `[1, 2,]` 不受限） |
| 7.3 | 解构中的引用 `[&$a] = $x` | 分开写 |
| 7.3 | `array_key_first()`、`array_key_last()`、`is_countable()` | 已在 polyfill 补齐，可直接用 |
| 7.3 | `JSON_THROW_ON_ERROR` | `json_last_error()` 检查，用 `Util\Json` 封装 |
| 7.4 | 类型化属性 `private string $x;` | `/** @var string */ private $x;` |
| 7.4 | 箭头函数 `fn ($x) => $x` | `function ($x) use ($外层变量) { return $x; }` |
| 7.4 | `??=` | `$a = $a ?? $b` |
| 7.4 | 数组展开 `[...$a, ...$b]` | `array_merge($a, $b)` |
| 7.4 | 数字分隔符 `1_000_000` | `1000000` |
| 7.4 | `preg_replace_callback()` 的 `$flags` 参数 | 不传 |
| 8.0 | `match` 表达式 | `switch` + `return`；条件链用 `if/elseif` |
| 8.0 | 构造器属性提升 | 独立属性声明 + 构造器内赋值 |
| 8.0 | nullsafe `?->` | `$x !== null ? $x->m() : null` |
| 8.0 | 非捕获 `catch (\Throwable)` | `catch (\Throwable $e)` |
| 8.0 | 联合类型 `int\|string`、`mixed`、`static` 返回 | 不写类型，docblock 标注 |
| 8.0 | `$obj::class` | `get_class($obj)` |
| 8.0 | 参数**声明**的尾随逗号 | 删掉 |
| 8.0 | `throw` 作为表达式 | 拆成语句 |
| 8.0 | 命名参数、属性 `#[...]` | 按位置传参；注解写进 docblock |
| 8.0 | `str_contains`/`str_starts_with`/`str_ends_with` | 已在 polyfill 补齐，可直接用 |
| 8.1+ | `enum`、`readonly`、`never`、first-class callable、`array_is_list`、`0o` 八进制 | — |

**7.2 本身就有的，放心用**：`?T` 可空类型、`void`、`iterable`、`object` 类型声明、
类常量可见性、短数组解构 `[$a, $b] = $x`、多类型 catch、`Closure::fromCallable`、
`list()` 键名解构。

### 可以直接调用的"新"函数

`src/polyfill.php` 已用 `function_exists()` 守卫补齐，源码里随便用：

- `str_contains()`、`str_starts_with()`、`str_ends_with()`（8.0）
- `array_key_first()`、`array_key_last()`、`is_countable()`（7.3）

要用其他高版本函数时，**先往 polyfill 里加实现，并在 `tests/polyfill_test.php` 补对拍用例**，
不要在业务代码里手写 `strpos() !== false` 这类退化写法。

### 运行期语义差异（`php -l` 查不出来）

1. **排序稳定性**：PHP 8.0 起 `sort`/`usort`/`uasort` 稳定，7.x **不是**。
   比较器可能返回 `0` 的地方都要加确定性 tie-breaker（通常按名字 `strcmp` 兜底）。
   证书候选、DNS 记录排序都受影响。

2. **字符串与数字比较**：PHP 8.0 起 `0 == "abc"` 为 `false`，7.x 为 `true`。
   ACME 服务端返回的 JSON 里 status 之类都是字符串，一律用 `===` 比。

3. **内部函数报错方式**：8.0 起许多内置函数抛 `TypeError`/`ValueError`，7.x 只 warning + 返回 `false`。
   `openssl_*` 系列尤其明显——坚持检查返回值，不要依赖异常兜错。

4. **`openssl_pkey_free()`**：8.0 起是 no-op（`OpenSSLAsymmetricKey` 由 GC 管），
   7.x 是真的释放资源句柄。代码里保留调用，但不能在调用后继续用那个变量。

### 怎么验证

```bash
composer test                      # 全部测试
php tests/php72_compat_test.php    # 静态扫描：7.2 语法兼容性，含规则自检与反向自检
php tests/no_exec_test.php         # 静态扫描：禁止外部进程调用
```

`tests/php72_compat_test.php` 是拦回退的主要手段：先用 tokenizer 剔除注释与字符串，
再跑文本规则 + token 结构规则。**新增一类禁用语法时，务必同时补规则并在自检样例里加正例**
——没有正例的规则等于没写。

## 加密相关的坑

1. **ECDSA 签名格式有两种，别搞混**。`openssl_sign()` 对 EC 密钥产出的是
   **DER 编码的 `SEQUENCE { r INTEGER, s INTEGER }`**；而 JWS（RFC 7515）要的是
   **定长 `R || S` 原始拼接**（P-256 各 32 字节、P-384 各 48、P-521 各 66）。
   `src/Crypto/Jws.php` 负责转换，CSR 与自签证书里则直接用 DER 那份。改动签名相关代码时先确认要哪种。

2. **`base64url` 不是 `base64`**。`+/` 换成 `-_`，去掉 `=` 填充。全库统一走
   `src/Crypto/Base64Url.php`，不要就地手写 `strtr()`。

3. **JWK thumbprint 的字段顺序是规范强制的**（RFC 7638）：
   EC 是 `crv,kty,x,y`，RSA 是 `e,kty,n`，字典序，无空格。顺序错了 thumbprint 就错，
   http-01 与 dns-01 的校验值全都对不上，而服务端只会回一句含糊的 unauthorized。

4. **dns-01 的 TXT 值要再 SHA-256 一次**：http-01 是 `token.thumbprint` 明文，
   dns-01 是 `base64url(sha256(token.thumbprint))`。

## 网络与幂等

- **nonce 必须串行使用**。`src/Protocol/NonceManager.php` 缓存服务端每次响应回的
  `Replay-Nonce`；并发发请求会导致 `badNonce`。遇到 `badNonce` 要自动重取并重放一次。
- **速率限制**：Let's Encrypt 每域名每周 5 张证书。测试一律用 staging 目录，
  正式目录只在真要签发时用。`tests/` 里的测试**不许**打真实 CA，
  网络相关的验证放 `tests/network/` 并单独用 `composer test-network` 跑。
- **DNS 传播要等**。写完 TXT 记录不能立刻 finalize，得先自己查权威 NS 确认记录可见，
  见 `src/Challenge/Dns01/DnsVerifier.php`。默认等 120 秒，可配。

## 新增一家 DNS 提供商

1. 在 `src/Challenge/Dns01/Provider/` 建类，实现 `DnsProviderInterface`
   （`addTxtRecord()` / `removeTxtRecord()`）。
2. 凭据一律从构造器传入的数组读，**不要**在 provider 内部直接读环境变量或全局配置——
   那样没法测。读环境变量是 `ProviderFactory` 的职责。
3. 在 `ProviderFactory::MAP` 注册短名（与 acme.sh 的 `dns_cf` 这类名字保持一致，便于迁移）。
4. 在 `tests/dns_provider_test.php` 里用假 HTTP transport 补一条用例，
   断言请求的 URL、方法、鉴权头、请求体——**不要打真实 API**。

## 完成一项改动后：测试 → 提交 → 推送

**这是本项目的固定收尾动作，写完代码不要停在"改好了"。** 顺序不能颠倒：

```bash
composer test        # 1. 必须全绿，有失败就先修，不许带着红灯提交
git add -A
git commit -m "<type>: <做了什么>"
git push
```

- 测试没过就不要提交。
- commit message 用中文，前缀 `feat:` / `fix:` / `refactor:` / `docs:` / `test:` / `chore:`，
  正文说清楚**为什么改**，不是罗列改了哪些文件——那个 diff 里有。
- 只推 commit，不自动打 tag。发版是单独的动作，见下节。

## 发版：Packagist 只认 tag

光 `git push` 推 commit，Packagist 那边永远只有 `dev-master`，
用户 `composer require` 拿不到新版本。

```bash
git push
git tag -a v1.1.0 -F <说明文件>   # annotated tag，说明写清楚变更
git push origin v1.1.0            # 单独推 tag，这一步才触发发布
```

版本号：加 DNS 提供商 / 加 CA / 放宽平台要求 → minor。
改 `DnsProviderInterface` 之类的公开契约、收紧 PHP 版本要求 → major。
证书文件落盘布局的变化即使不改签名也要在 tag 说明里写明白——用户靠这个判断能不能升。
