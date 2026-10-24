---
chapter: Web安全
section: Web 安全导论与 HTTP 深化
order: 601
tags:
  - CTF
  - Web安全
  - HTTP
  - Web基础
publish: true
---

# W01 Web 安全导论与 HTTP 深化
## Web Security Introduction & HTTP in Depth

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[10-网络协议基础|10 章]] · [[11-Web安全版图与Burp|11 章]]
> **本章目标**：在 11 章的版图之上，把一条 HTTP 请求里服务端能读到的每个部件逐一吃透：四个安全高频请求头、Cookie 属性全集与 Session 的服务端存储、JWT 的手工签发与校验、同源策略与 CORS 的边界、HTTPS 在 Web 侧的校验细节、DevTools Network 面板的系统用法。学完能亲手伪造请求头通过校验、读懂一份 session 文件、手工签发并篡改一个 JWT、用 curl 模拟一次预检，把"报文层"这个输入面变成后续漏洞章节的下手位置。

## 1. 导论：请求的每个部件都是攻击面

[[11-Web安全版图与Burp|11 章]]把九类漏洞排成了一张版图，第 5 节的打题流程里有一句"所有 GET/POST 参数、cookie、甚至 User-Agent 和 Referer，有输入的地方就有注入的候选"。本章把这句话落到一条请求的每个部件上——服务端读到的每个值，都是某段代码的输入，也都是潜在攻击面：

| 请求部件 | 服务端拿它做什么 | 出问题就是哪类问题 | 展开位置 |
| ---- | ---- | ---- | ---- |
| URL 路径 | 路由、静态文件映射 | 信息泄露、目录穿越 | [[W03-信息泄露与前端安全\|W03]] |
| URL 参数 | 业务逻辑的输入 | SQL 注入、命令注入、文件包含 | [[W04-SQL注入\|W04]] · [[W05-命令注入与代码执行\|W05]] · [[W06-文件包含\|W06]] |
| 请求头 | 指纹识别、虚拟主机路由、访问控制 | 伪造绕过校验、CORS 配置错误 | 本章第 2、5 节 |
| Cookie / Session / JWT | 认证与授权 | 认证绕过、会话劫持 | 本章第 3、4 节 |
| 请求体 | 业务逻辑的输入 | 与 URL 参数同类 | [[W04-SQL注入\|W04]] 起 |

报文结构、方法、状态码、Cookie/Session 的最小机制、TLS 握手概览，[[10-网络协议基础|10 章]]都已讲过，本章一律直接使用。==先在报文层把"输入面"吃透，后面的漏洞章节才有下手的位置==。

> [!note] 本章的 curl 约定
> 所有 curl 命令都带 `--noproxy '*'`：绕过环境变量里配置的 HTTP 代理直连靶机。没配代理的环境加不加都一样；[[10-网络协议基础|10 章]]常见问题表里"Trying 127.0.0.1:7897"那种症状，就是没加它时的样子。

本章的靶场有三台，都在 8100 段：`php -S 127.0.0.1:8100` 起的 PHP 站（请求头回显、Cookie 下发、Session 演示都在这台）、Python 写的 CORS 靶（8102）、带自签证书的 HTTPS 靶（8103）。代码随用随给，读者照敲即可复现同款输出。

## 2. 安全相关请求头深化

### 2.1 四个安全高频头

[[10-网络协议基础|10 章]] 5.1 节拆报文时见过 `Host` 和 `User-Agent`，[[11-Web安全版图与Burp|11 章]]提过它们常被服务端读取。这里把安全上最常出事的四个头放在一起，语义、常见用法与考法对照：

| 头部 | 规范语义 | 服务端常见用法 | CTF 里怎么考 |
| ---- | ---- | ---- | ---- |
| `Host` | HTTP/1.1 必带，声明请求的目标主机 | 同机多站点的虚拟主机路由；基于 Host 做访问控制 | 改 Host 过"仅限某域名访问"的校验；服务端拿 Host 拼接跳转链接时成为注入点 |
| `Referer` | 请求发起页的完整 URL | 防盗链、来源校验 | "必须从管理页发起请求"才返回数据 |
| `User-Agent` | 客户端程序的标识串 | 统计、爬虫拦截、按浏览器降级 | "仅限管理员浏览器"的校验；扫描器的指纹识别 |
| `X-Forwarded-For` | 代理链逐跳追加的来源 IP 列表 | 限流、日志、判定"真实 IP" | "仅限 127.0.0.1 / 内网访问"的校验 |

`X-Forwarded-For` 单独多说两句。它不是标准头（标准化的同类是 RFC 7239 的 `Forwarded`，nginx 圈还习惯用 `X-Real-IP`），格式是逗号分隔的列表：

```
X-Forwarded-For: 203.0.113.7, 10.0.0.2, 10.0.0.3
```

每经过一层代理，代理把自己的上游地址追加到末尾。第一个值是客户端**声称**的来源；服务端取第一个还是最后一个当"真实 IP"，是实现者的自由——==而这每一个值都是客户端或中间节点拼出来的文本，没有一个能当作鉴权依据==。真正由 TCP 连接决定、代码改不了的是 `$_SERVER['REMOTE_ADDR']`（PHP 里的叫法）：无代理直连时它就是客户端地址；挂了反向代理时它是代理的地址，这正是 XFF 这类头存在的原因。

> [!note] Referer 的拼写
> 规范草案把 referrer 拼成了 referer，头名从此将错就错。写代码取值用 `HTTP_REFERER`，查文档搜 "referer"，写文章才用正确的 referrer。

### 2.2 靶场：回显服务端收到的请求头

把下面这个 PHP 文件放进站点目录（本节起 `php -S 127.0.0.1:8100 -t www01` 启动，`account/` 子目录的用途见 3.2）：

```php
<?php
/* headers.php —— 回显服务端实际收到的全部请求头 */
foreach ($_SERVER as $k => $v) {
    if (str_starts_with($k, 'HTTP_')) {
        echo str_replace('_', '-', substr($k, 5)) . ': ' . $v . "\n";
    }
}
echo 'REMOTE_ADDR: ' . $_SERVER['REMOTE_ADDR'] . "\n";
```

PHP 把请求头统一存成 `HTTP_` 前缀、大写、下划线分隔的形式（`Referer` 存成 `HTTP_REFERER`），脚本再把它还原成头名打印。先裸访问一次，看服务端的"默认视野"：

```bash
php -S 127.0.0.1:8100 -t www01 &
curl -s --noproxy '*' http://127.0.0.1:8100/headers.php
```

输出：

```
HOST: 127.0.0.1:8100
USER-AGENT: curl/8.18.0
ACCEPT: */*
REMOTE_ADDR: 127.0.0.1
```

curl 默认只带这三个头。在服务端眼里，这条请求的全部"来源事实"只有 `REMOTE_ADDR: 127.0.0.1`。接着一次伪造三个头，再看服务端收到什么：

```bash
curl -s --noproxy '*' \
  -H 'X-Forwarded-For: 8.8.8.8' \
  -H 'Referer: https://admin.example.com/panel' \
  -H 'User-Agent: AdminBrowser/9.0' \
  http://127.0.0.1:8100/headers.php
```

输出：

```
HOST: 127.0.0.1:8100
ACCEPT: */*
X-FORWARDED-FOR: 8.8.8.8
REFERER: https://admin.example.com/panel
USER-AGENT: AdminBrowser/9.0
REMOTE_ADDR: 127.0.0.1
```

`$_SERVER['HTTP_X_FORWARDED_FOR']` 拿到的就是 `8.8.8.8`，服务端代码分不出它是真来的还是伪造的。`Host` 用 `-H` 也能覆盖：

```bash
curl -s --noproxy '*' -H 'Host: flag.internal' http://127.0.0.1:8100/headers.php
```

输出：

```
HOST: flag.internal
USER-AGENT: curl/8.18.0
ACCEPT: */*
REMOTE_ADDR: 127.0.0.1
```

> [!warning] REMOTE_ADDR 不随请求头变
> 三个头都改了，`REMOTE_ADDR` 纹丝不动——它是 TCP 连接的对端地址，不是请求头，`-H` 伪造不了。"绕过 IP 限流"类题目考的就是这个差别：限流代码若读的是 XFF 一类可伪造的头，加个头就绕过；若读 REMOTE_ADDR，加头没用。

### 2.3 题型：校验请求头才给 flag

一类高频题型：页面正常打开，但 flag 的位置写着一个条件——"仅限本地访问""请从内部管理页进入""管理员浏览器专享"。实现就是读请求头做比对：

```php
<?php
/* gate.php —— 常见校验型题目：请求头满足条件才输出 flag */
$xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
$ref = $_SERVER['HTTP_REFERER'] ?? '';
$ip_ok  = str_contains($xff, '127.0.0.1');
$ref_ok = str_contains($ref, 'admin');
if ($ip_ok && $ref_ok) {
    echo "flag{h34d3r_ch3ck_1s_n0t_s3cur1ty}\n";
} else {
    echo "denied\n";
    echo '  X-Forwarded-For: ' . ($xff ?: '(无)') . "\n";
    echo '  Referer: ' . ($ref ?: '(无)') . "\n";
}
```

不带头访问，被拒：

```bash
curl -s --noproxy '*' http://127.0.0.1:8100/gate.php
```

输出：

```
denied
  X-Forwarded-For: (无)
  Referer: (无)
```

被拒信息把要满足的两个头直接报了出来。照条件伪造：

```bash
curl -s --noproxy '*' \
  -H 'X-Forwarded-For: 127.0.0.1' \
  -H 'Referer: http://127.0.0.1:8100/admin' \
  http://127.0.0.1:8100/gate.php
```

输出：

```
flag{h34d3r_ch3ck_1s_n0t_s3cur1ty}
```

==请求头是客户端拼出来的文本，任何把请求头当鉴权依据的实现都不构成安全边界==。同类校验还会用别的头，遇到 IP 类校验轮着试：`X-Forwarded-For`、`X-Real-IP`、`X-Client-IP`、`True-Client-IP`、`Forwarded`；反向代理场景下还有 `X-Original-URL`、`X-Rewrite-URL`（声明"用户实际想访问的路径"），路径校验卡住时值得一试。

## 3. Cookie 属性全集与 Session 存储

[[10-网络协议基础|10 章]] 6 节用 20 行服务器演示过最小机制：响应带 `Set-Cookie` 下发，之后请求自动带 `Cookie` 回传，Session 把数据放服务端、Cookie 只带编号。本节把两个方向各补齐：属性全集与服务端存储。

### 3.1 Set-Cookie 属性全集

一个 `Set-Cookie` 头可以携带一组属性，七个属性一张表：

| 属性 | 作用 | 安全意义 |
| ---- | ---- | ---- |
| `Expires=<HTTP 日期>` | 硬编码的过期时刻 | 不设就是会话 cookie：关浏览器即失效，不落盘 |
| `Max-Age=<秒>` | 相对有效期，与 Expires 同时出现时优先 | 同上 |
| `Domain=<域>` | 指定回带域名（含全部子域）；不设则只在当前主机回带 | 放宽到父域等于把 cookie 共享给所有子域，任一子域被攻破即波及 |
| `Path=<路径>` | 路径前缀匹配的请求才回带 | 隔离不同应用的 cookie；但防不了同站其他页面的 JS |
| `HttpOnly` | 禁止 JS 通过 `document.cookie` 读取 | ==XSS 偷不走它==——[[11-Web安全版图与Burp|11 章]] 3.6 那段窃取脚本对它失效；请求里照样携带，防"读"不防"用" |
| `Secure` | 仅在 HTTPS 连接上回带 | 明文信道不再泄露 cookie |
| `SameSite=Lax/Strict/None` | 跨站请求是否回带 | 缓解利用"浏览器自动带 cookie"发请求的攻击：Strict 全禁，Lax 只放行顶级导航的 GET，None 放行但必须配 `Secure` |

浏览器（和 curl 的 cookie 罐）收到 `Set-Cookie` 就把名值连同属性存起来；之后每个请求按四道关判定要不要带上：域匹配、路径匹配、Secure 检查、SameSite 检查，任何一关不过就不带。

> [!note] 跨站不是跨源
> SameSite 比的是**站点**（注册域，如 `example.com`），SOP 比的是**源**（协议 + 域名 + 端口，见 5.1）。`a.example.com` 与 `b.example.com` 同站不同源——SameSite 管不着它们互发请求，SOP 管着它们互读数据。

### 3.2 回带规则：cookie 罐里发生了什么

一次下发四个不同属性组合的 cookie：

```php
<?php
/* cookies.php —— 一次下发四个不同属性组合的 Set-Cookie */
header('Set-Cookie: basic=1; Path=/', false);
header('Set-Cookie: acct=abc123; Max-Age=3600; Path=/account; HttpOnly; SameSite=Lax', false);
header('Set-Cookie: lang=zh; Expires=Fri, 27 Nov 2026 00:00:00 GMT; Path=/', false);
header('Set-Cookie: wide=3; Path=/; Secure', false);
header('Content-Type: text/plain; charset=utf-8');
echo "4 个 Set-Cookie 已下发\n";
```

`header()` 的第二个参数 `false` 表示追加而不是覆盖，四个 `Set-Cookie` 才能同时出现在响应里：

```bash
curl -si --noproxy '*' http://127.0.0.1:8100/cookies.php
```

输出（节选，状态行后的 Host/Date/Connection 三行已删）：

```
HTTP/1.1 200 OK
X-Powered-By: PHP/8.5.4
Set-Cookie: basic=1; Path=/
Set-Cookie: acct=abc123; Max-Age=3600; Path=/account; HttpOnly; SameSite=Lax
Set-Cookie: lang=zh; Expires=Fri, 27 Nov 2026 00:00:00 GMT; Path=/
Set-Cookie: wide=3; Path=/; Secure
Content-Type: text/plain; charset=utf-8

4 个 Set-Cookie 已下发
```

curl 用 `-c` 把响应里的 cookie 存进罐文件，`-b` 再带出去：

```bash
curl -s --noproxy '*' -c jar.txt http://127.0.0.1:8100/cookies.php > /dev/null
cat jar.txt
```

输出：

```
# Netscape HTTP Cookie File
# https://curl.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.

127.0.0.1	FALSE	/	TRUE	0	wide	3
127.0.0.1	FALSE	/	FALSE	1795737600	lang	zh
#HttpOnly_127.0.0.1	FALSE	/account	FALSE	1792754898	acct	abc123
127.0.0.1	FALSE	/	FALSE	0	basic	1
```

罐文件每行七列：域名、是否含子域、路径、是否 Secure、过期时间戳（`0` 是会话 cookie）、名字、值；`#HttpOnly_` 前缀是 curl 用来标记 HttpOnly 的。对照 3.1 的属性表逐列读，`acct` 的路径列是 `/account`——按规则它只在 `/account` 前缀下回带：

```bash
curl -s --noproxy '*' -b jar.txt http://127.0.0.1:8100/headers.php | grep -i '^COOKIE'
curl -s --noproxy '*' -b jar.txt http://127.0.0.1:8100/account/login.php
```

输出：

```
COOKIE: basic=1; lang=zh; wide=3
```

```
HTTP_COOKIE: acct=abc123; basic=1; lang=zh; wide=3
```

`/headers.php` 不在 `/account` 前缀下，`acct` 没跟上；`/account/login.php` 在，四个全带。Path 前缀匹配就是这一条规则。

但上面输出里有一个反常的地方：`wide` 带 `Secure` 属性，走的却是 `http://`，按规则它不该出现在回带列表里。原因：==curl 和现代浏览器把 127.0.0.1、localhost 这类回环地址当作可信上下文，Secure cookie 在回环地址的 http 上照样存取==。所以 Secure 属性在回环地址上测不出效果，要换一个假域名——`--resolve ctf.local:8100:127.0.0.1` 让 curl 把 `ctf.local` 临时解析到 127.0.0.1（等价于改 `/etc/hosts`，浏览器测试就得改 hosts 了）：

```bash
curl -s --noproxy '*' --resolve ctf.local:8100:127.0.0.1 \
  -c jar2.txt http://ctf.local:8100/cookies.php > /dev/null
cat jar2.txt
```

输出：

```
# Netscape HTTP Cookie File
# https://curl.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.

ctf.local	FALSE	/	FALSE	1795737600	lang	zh
#HttpOnly_ctf.local	FALSE	/account	FALSE	1792754972	acct	abc123
ctf.local	FALSE	/	FALSE	0	basic	1
```

这次 `wide` 压根没进罐：经普通 http 下发的 Secure cookie，curl 在存储阶段就丢弃了。要测它的完整语义，得经 HTTPS 下发。8103 端口有一台带自签证书的 HTTPS 靶（实现见 [[#6.2 自签证书与"校验不过就拒连"|6.2]]），它有两个路由：`/setcookie` 经 TLS 下发一个 Secure cookie，`/cookie` 回显收到的 `Cookie` 头。`-k` 表示跳过证书校验（6.2 细讲）：

```bash
curl -sk --noproxy '*' --resolve ctf.local:8103:127.0.0.1 \
  -c jar3.txt https://ctf.local:8103/setcookie
grep wide jar3.txt
```

输出：

```
secure cookie issued over TLS
ctf.local	FALSE	/	TRUE	0	wide	3
```

经 TLS 下发的 Secure cookie 进罐了，Secure 列是 `TRUE`。分别用 http 和 https 回带：

```bash
curl -s --noproxy '*' --resolve ctf.local:8100:127.0.0.1 \
  -b jar3.txt http://ctf.local:8100/headers.php
```

输出：

```
HOST: ctf.local:8100
USER-AGENT: curl/8.18.0
ACCEPT: */*
REMOTE_ADDR: 127.0.0.1
```

http 上没有 `Cookie` 头——`wide` 没有回带。

```bash
curl -sk --noproxy '*' --resolve ctf.local:8103:127.0.0.1 \
  -b jar3.txt https://ctf.local:8103/cookie
```

输出：

```
服务端收到的 Cookie 头: wide=3
```

https 上回带了。==Secure 的全部语义就这两条：明文信道不发，密文信道照发==。

### 3.3 Session：数据在服务端，cookie 只带编号

Session 的机制[[10-网络协议基础|10 章]] 6 节讲过：数据存服务端，cookie 只带一把编号。本节看服务端那本"登记簿"长什么样。PHP 的最小演示：

```php
<?php
/* sess.php —— 服务端 Session 最小演示 */
session_start();
if (isset($_SESSION['user'])) {
    echo '已存在的会话，user = ' . $_SESSION['user'] . "\n";
} else {
    $_SESSION['user'] = 'admin';
    $_SESSION['role'] = 'player';
    echo '新会话已建立，session id: ' . session_id() . "\n";
    echo 'save_handler: ' . ini_get('session.save_handler') . "\n";
    echo 'save_path: ' . (ini_get('session.save_path') ?: '(空 → 系统临时目录)') . "\n";
}
```

一次请求把下发、落盘、文件内容连起来看（`-D` 把响应头存进 head.txt，`-o` 把响应体存进 body.txt）：

```bash
curl -s --noproxy '*' -D head.txt http://127.0.0.1:8100/sess.php -o body.txt
grep -i set-cookie head.txt
cat body.txt
SID=$(grep -oP 'PHPSESSID=\K[a-z0-9]+' head.txt)
ls -l /var/lib/php/sessions/sess_$SID
cat /var/lib/php/sessions/sess_$SID
```

输出：

```
Set-Cookie: PHPSESSID=e7ae8be9e5d4a390be607f01af46dccf; path=/
新会话已建立，session id: e7ae8be9e5d4a390be607f01af46dccf
save_handler: files
save_path: /var/lib/php/sessions
-rw------- 1 hua hua 35 Oct 23 18:32 /var/lib/php/sessions/sess_e7ae8be9e5d4a390be607f01af46dccf
user|s:5:"admin";role|s:6:"player";
```

三个事实：

- **PHP 默认用文件存 session**（`save_handler: files`）：Debian/Ubuntu 系把 `session.save_path` 配置成 `/var/lib/php/sessions`，配置为空时落在系统临时目录；文件名就是 `sess_` 拼上 session id——==id 和文件路径一一对应，拿到 id 就等于拿到文件名==。
- **文件内容是 `键|值` 的拼接**，值部分是 PHP 的序列化格式（`s:5:"admin"` 即长度 5 的字符串）。[[11-Web安全版图与Burp|11 章]] 3.8 里 `O:4:"User"` 的对象序列化是同一套格式——==session 数据一旦能被注入对象序列化串，就能接到反序列化利用链上==。
- **PHPSESSID 默认不带 HttpOnly**：`Set-Cookie` 里只有 `path=/`，页面里任何 JS 都能 `document.cookie` 读到它。生产配置应设 `session.cookie_httponly=1`，很多靶场不设。

再把编号送回去，看服务端怎么"认人"：

```bash
curl -s --noproxy '*' -b "PHPSESSID=$SID" http://127.0.0.1:8100/sess.php
```

输出：

```
已存在的会话，user = admin
```

服务端从 cookie 里拿到 id，找到 `sess_<id>` 文件，把内容反序列化回 `$_SESSION`——`isset($_SESSION['user'])` 成立，走了"已存在"分支。==所谓登录态，就是服务端一个文件加浏览器里一个编号==。

> [!warning] 会话固定
> 如果登录成功后服务端不更换 session id（PHP 里对应 `session_regenerate_id()`），攻击者提前把受害者引导到一个已知 id 的会话上，等受害者登录，攻击者用同一个 id 直接继承登录态。CTF 直接考得少，写代码是必修项。

### 3.4 session id 的传递方式与框架变体

cookie 是 session id 的默认载体，但不是唯一载体。PHP 的旧配置 `session.use_trans_sid` 允许把 id 拼进 URL（`?PHPSESSID=...`）跟随每个链接；现代默认 `session.use_only_cookies=1` 关掉了这条路，原因很直接：==id 进了 URL 就会进访问日志、Referer 头、浏览器历史，任何一处泄露都等于把会话送人==。CTF 里从日志、Referer、历史记录里"捡"到别人的 session id 直接接管会话，就是这条机制的攻击面。

框架侧还有一个重要变体：Flask 的 session 不落盘，把全部数据 base64 编码后连同时间戳和**签名**一起塞进 cookie——服务端零存储。==签名只防篡改、不保密==：数据谁都能解开看；签名密钥（`SECRET_KEY`）一旦是弱值，数据还能被伪造。这套"数据进 cookie、签名保平安"的思路，下一节的 JWT 把它做成了标准。

## 4. JWT：自包含的身份凭证

### 4.1 结构：三段 base64url

Session 方案要求服务端存得住数据；一个服务背后挂着多台机器、多个服务时要共享这份存储。JWT（JSON Web Token）把方向反过来：==服务端什么都不存，数据加签名一起发给客户端==，谁签的谁认。

一个 JWT 是三段 base64url 编码的字符串，用 `.` 连接：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 . eyJzdWIiOi... . KgB90FvL7MGlh...
     header（头部）                payload（载荷）        signature（签名）
```

base64url 与普通 base64 的差别：`+` 换成 `-`，`/` 换成 `_`，末尾的 `=` 填充去掉——为的是能在 URL 和 cookie 里安全出现。三段的内容：

| 段 | 解开后是什么 | 示例 |
| ---- | ---- | ---- |
| header | JSON：算法与类型 | `{"alg":"HS256","typ":"JWT"}` |
| payload | JSON：一组声明（claims） | `{"sub":"1001","role":"admin","exp":...}` |
| signature | 对前两段的签名 | 纯二进制，base64url 后那串乱码 |

==编码不是加密：三段谁都能解开，payload 完全公开==。

### 4.2 手工签发与校验

HS256 表示 HMAC-SHA256：拿服务端的密钥，对 `header.payload` 这段字符串算 HMAC。标准库就够用，下面是完整的签发、解码、校验脚本：

```python
# jwt_demo.py —— 用标准库手工实现 HS256 JWT 的签发、解码与校验
import base64, hashlib, hmac, json
from datetime import datetime, timezone

SECRET = b'weak-key-123456'          # 服务端的签名密钥（本例故意用弱密钥）

def b64url(data: bytes) -> str:      # base64url：+ 换成 -，/ 换成 _，去掉 = 填充
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def sign(header: dict, payload: dict) -> str:
    h = b64url(json.dumps(header, separators=(',', ':')).encode())
    p = b64url(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f'{h}.{p}'.encode()
    s = b64url(hmac.new(SECRET, signing_input, hashlib.sha256).digest())
    return f'{h}.{p}.{s}'

def verify(token: str, key: bytes) -> bool:
    h, p, s = token.split('.')
    expect = b64url(hmac.new(key, f'{h}.{p}'.encode(), hashlib.sha256).digest())
    return hmac.compare_digest(s, expect)

iat = int(datetime(2026, 10, 23, tzinfo=timezone.utc).timestamp())
payload = {'sub': '1001', 'name': 'admin', 'role': 'superadmin',
           'iat': iat, 'exp': iat + 86400}
token = sign({'alg': 'HS256', 'typ': 'JWT'}, payload)

print('token  :', token)
print('header :', b64url_dec(token.split('.')[0]).decode())
print('payload:', b64url_dec(token.split('.')[1]).decode())
print('iat =', iat, '->', datetime.fromtimestamp(iat, timezone.utc).isoformat())
print('exp =', iat + 86400, '->', datetime.fromtimestamp(iat + 86400, timezone.utc).isoformat())

# 校验 1：原 token，签名一致
print('verify(原 token)   :', verify(token, SECRET))
# 校验 2：payload 里 role 改成 guest，签名原样保留 -> 校验失败
h, p, s = token.split('.')
forged_payload = dict(payload, role='guest')
forged = f"{h}.{b64url(json.dumps(forged_payload, separators=(',', ':')).encode())}.{s}"
print('verify(篡改 token) :', verify(forged, SECRET))
```

```bash
python3 jwt_demo.py
```

输出：

```
token  : eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwibmFtZSI6ImFkbWluIiwicm9sZSI6InN1cGVyYWRtaW4iLCJpYXQiOjE3OTI3MTM2MDAsImV4cCI6MTc5MjgwMDAwMH0.KgB90FvL7MGlhN2--YpWL3n9ZGWAkYV8rxwP1bIMpUs
header : {"alg":"HS256","typ":"JWT"}
payload: {"sub":"1001","name":"admin","role":"superadmin","iat":1792713600,"exp":1792800000}
iat = 1792713600 -> 2026-10-23T00:00:00+00:00
exp = 1792800000 -> 2026-10-24T00:00:00+00:00
verify(原 token)   : True
verify(篡改 token) : False
```

逐点读：

- **签名覆盖的是前两段的编码文本**（`h.p` 这串），不是解码后的 JSON。payload 改一个字节，重编码后就是另一段文本，旧签名对不上，`verify` 返回 False——这就是"签名防篡改"的全部含义；
- **校验 = 重算一遍再比较**。服务端拿自己的密钥对收到的 `h.p` 重算 HMAC，与 token 第三段比对（`hmac.compare_digest` 是恒定时间比较，比较耗时与是否一致无关，不给时序侧信道留信号）；
- **签名一致只是第一步，时间声明是第二步**：签名对了还要检查 `exp` 是否已过、`nbf` 是否已到。==exp 是服务端要检查的声明，token 自己不会失效==；
- `iat`/`exp` 存的是 Unix 时间戳：上面分别是 2026-10-23 与 2026-10-24 的零点，有效期 24 小时。

### 4.3 注册声明

payload 里的字段叫声明（claim）。IANA 注册了七个，含义跨服务通用：

| 声明 | 全称 | 含义 |
| ---- | ---- | ---- |
| `iss` | issuer | 签发者标识 |
| `sub` | subject | 主体，通常是用户 id |
| `aud` | audience | 面向的接收方，防止"发给 A 服务的 token 被 B 服务当真" |
| `exp` | expiration time | 过期时间戳，过了必须拒收 |
| `nbf` | not before | 生效时间，之前不收 |
| `iat` | issued at | 签发时间 |
| `jti` | JWT ID | 唯一编号，用于防重放 |

这七个之外，`name`、`role` 这类业务字段随便加——全都在公开的 payload 里。==别把密码、密钥、敏感数据放进 payload，它是编码过的明文==。

### 4.4 与 Session 的对照和攻击面

| 维度 | Session | JWT |
| ---- | ---- | ---- |
| 状态存储 | 服务端（文件 / Redis / 数据库） | 无状态，全在 token 里 |
| 吊销 | 删掉服务端数据即刻生效 | 难——只能等 `exp`，或额外维护黑名单 |
| 防篡改 | 数据不出服务端 | 靠签名 |
| 泄露后果 | id 泄露即被冒用 | 整个 token 泄露即被冒用 |
| 典型载体 | `PHPSESSID` 一类的 cookie | `Authorization: Bearer` 头，或 cookie |

JWT 的攻击面集中在"服务端怎么验签"上，而验签算法写在 header 的 `alg` 字段里——==这个字段是攻击者可控的==：把它改成 `none` 是在要求服务端免验签；HS256/RS256 混淆是诱导服务端拿公开的 RSA 公钥当 HMAC 密钥，谁都能算签名；密钥本身弱（本例的 `weak-key-123456` 量级）则字典一秒爆破。这些玩法的展开在后面的认证漏洞章。

## 5. 同源策略与 CORS

### 5.1 源与同源判定

**源**（origin）= 协议 + 域名 + 端口，三者完全一致才算同源（http 默认端口 80、https 默认 443，写不写都一样）：

| 源 A | 源 B | 判定 |
| ---- | ---- | ---- |
| `http://a.com` | `http://a.com/page` | 同源（路径不参与） |
| `http://a.com` | `https://a.com` | 不同源（协议） |
| `http://a.com` | `http://a.com:8080` | 不同源（端口） |
| `http://a.com` | `http://b.a.com` | 不同源（域名） |
| `http://a.com` | `http://127.0.0.1` | 不同源（域名） |

为什么要有同源策略（Same-Origin Policy，SOP）：浏览器里同时跑着无数别人写的代码——每个打开的网页都是。没有 SOP，你开着的任意一个页面都能用 JS 去读你登录着的邮箱、内网系统的响应。SOP 是浏览器执行的策略，==服务器之间没有 SOP 这回事==。

### 5.2 拦"读"，不拦"写"

SOP 的规则不是"跨源就禁止"，它拦和放的是两类不同的事：

| 跨源行为 | 结果 |
| ---- | ---- |
| JS 用 fetch/XHR **读取**跨源响应 | 拦——响应到了浏览器，JS 不许读内容 |
| `<img>` `<script>` `<link>` 嵌入跨源资源 | 放——能加载能执行，只是读不到内容 |
| 表单提交、页面跳转到别的源 | 放——请求照发，响应读不到 |

==SOP 拦的是"读响应"，不拦"发请求"==。第二行解释了为什么 CDN 的图片和统计脚本能跨站工作；第三行解释了一类攻击为什么能存在：别的网站可以构造一个自动提交到你银行的表单，浏览器还带着你的 cookie 发出去——只是攻击者读不到响应。CORS 解决的是第一行的例外通道。

### 5.3 CORS：服务端的放行名单

跨源资源共享（CORS）的机制一句话：**跨源请求浏览器自动带上 `Origin` 头，服务端用 `Access-Control-Allow-Origin` 响应头声明允许谁，浏览器比对后放行 JS 读取**。==CORS 由浏览器执行：服务器照常返回数据，curl 之类的工具从来没有 SOP/CORS 概念==。

跨源请求分两类。满足"简单请求"条件的直接发送：方法是 GET/HEAD/POST，只带安全列表里的头（Accept、Accept-Language、Content-Language、Content-Type），且 Content-Type 限于 `application/x-www-form-urlencoded`、`multipart/form-data`、`text/plain` 三种。不满足的先发一次 **OPTIONS 预检**（带 `Origin` 和 `Access-Control-Request-Method`，问服务器允不允许），拿到许可才发正式请求。预检结果可以由 `Access-Control-Max-Age` 缓存。

写一个把 Origin 原样反射进响应的靶场（注意这个写法本身就是 5.4 要讲的配置错误）：

```python
# cors.py —— CORS 靶场：/api/data，带 Origin 时把 Origin 原样反射进 ACAO（漏洞写法）
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def _reflect(self):
        o = self.headers.get('Origin')
        if o:  # 漏洞点：不校验来源，直接回显 Origin
            self.send_header('Access-Control-Allow-Origin', o)
            self.send_header('Access-Control-Allow-Credentials', 'true')

    def do_OPTIONS(self):
        self.send_response(204)
        self._reflect()
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'X-Token')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        if self.path == '/api/data':
            self.send_response(200)
            self._reflect()
            self.send_header('Content-Type', 'application/json')
            body = b'{"user":"admin","role":"superadmin"}'
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

HTTPServer(('127.0.0.1', 8102), H).serve_forever()
```

三步看全机制。第一步，不带 Origin 访问——这是 curl 的视角，浏览器之外的世界：

```bash
python3 cors.py &
curl -si --noproxy '*' http://127.0.0.1:8102/api/data
```

输出：

```
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.14.4
Date: Fri, 23 Oct 2026 10:44:01 GMT
Content-Type: application/json
Content-Length: 36

{"user":"admin","role":"superadmin"}
```

没有 Origin 就没有 ACAO，数据照常返回——服务器不拦任何人。第二步，带上 Origin，模拟浏览器发出的跨源请求：

```bash
curl -si --noproxy '*' -H 'Origin: http://evil.example' http://127.0.0.1:8102/api/data
```

输出：

```
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.14.4
Date: Fri, 23 Oct 2026 10:44:01 GMT
Access-Control-Allow-Origin: http://evil.example
Access-Control-Allow-Credentials: true
Content-Type: application/json
Content-Length: 36

{"user":"admin","role":"superadmin"}
```

响应多了两行：ACAO 精确等于请求里的 Origin，另附"允许带凭证"。浏览器拿到这个组合，就会允许 `evil.example` 页面里的 JS 读取这份响应。第三步，模拟预检——一个要发 DELETE、带自定义头 `X-Token` 的请求不属于简单请求，浏览器会先发 OPTIONS：

```bash
curl -si --noproxy '*' -X OPTIONS \
  -H 'Origin: http://evil.example' \
  -H 'Access-Control-Request-Method: DELETE' \
  -H 'Access-Control-Request-Headers: x-token' \
  http://127.0.0.1:8102/api/data
```

输出：

```
HTTP/1.0 204 No Content
Server: BaseHTTP/0.6 Python/3.14.4
Date: Fri, 23 Oct 2026 10:44:01 GMT
Access-Control-Allow-Origin: http://evil.example
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, DELETE
Access-Control-Allow-Headers: X-Token
Content-Length: 0
```

预检应答是一张许可清单：方法允许 DELETE，头允许 X-Token。清单里有，浏览器才发正式请求。curl 不会自动预检——预检是浏览器自己的行为，这也是 Web 测试里"curl 通了浏览器却报错"最常见的原因。

### 5.4 配置错误：反射 Origin

`Access-Control-Allow-Origin: *` 表示对任何源开放，但规范规定 ==`*` 与凭证互斥==：带 cookie 的请求遇到 `ACAO: *` 一律不放行。很多实现为了绕开这条限制，改成"请求带什么 Origin 就回显什么"再加 `Allow-Credentials: true`——5.3 的靶场就是这个写法。后果：

==任意网站都可以带着用户的 cookie 读取该接口的响应==。受害者只是开着 `evil.example` 的页面，浏览器就会替攻击者完成一次带凭证的跨源读取，接口返回的身份信息、数据全部交到攻击者 JS 手里。正确写法是维护域名白名单，命中才反射，未命中一律不放 ACAO。

CTF 里这一配置错误的识别：响应头出现 `Access-Control-Allow-Origin: <你发的 Origin>` 加 `Access-Control-Allow-Credentials: true`，就值得构造一个反射页面去读数据。练手路径见 [[W03-信息泄露与前端安全|W03]]。

## 6. HTTPS 的 Web 侧深化

[[10-网络协议基础|10 章]] 7 节讲过 TLS 握手四步与非对称换钥匙、对称扛流量的分工。本节补 Web 侧的三件事：页面内的混合内容、HSTS、以及亲手触发一次"证书校验失败"。

### 6.1 混合内容与 HSTS

**混合内容**：HTTPS 页面里引用 `http://` 资源。分两类：被动内容（图片、音频）与主动内容（script、iframe、XHR）。现代浏览器对主动混合内容直接阻止加载，对被动内容逐步升级为 https 或阻止。CTF 里"页面图片全裂、JS 不执行"的题，先看 DevTools Console 是不是混合内容拦截。

**HSTS**（HTTP Strict Transport Security）：服务端用一个响应头声明"此域只准 https"：

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

浏览器在 max-age 内记住这条声明：明文请求在浏览器内部直接改写为 https，证书错误也不提供"继续访问"的点击项。`includeSubDomains` 覆盖子域，`preload` 申请进入浏览器内置的强制列表。==HSTS 防不了首次访问==——用户第一次明文进来时浏览器还没记住它，preload 列表补的就是这个洞。

### 6.2 自签证书与"校验不过就拒连"

先生成一张自签证书：`-x509` 表示自签，`-nodes` 表示私钥不加密存储，`-subj` 免交互填主题：

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 36500 -subj '/CN=ctf.local'
ls -l key.pem cert.pem
```

输出：

```
-rwxrwxrwx 1 hua hua 1115 Oct 23 18:29 cert.pem
-rwxrwxrwx 1 hua hua 1704 Oct 23 18:29 key.pem
```

把它挂到 Python 的 HTTP 服务上（就是 3.2 用到的 8103 靶）：

```python
# https_srv.py —— 自签证书的 HTTPS 靶场，8103 端口
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler

CERT = 'cert.pem'
KEY = 'key.pem'

class H(BaseHTTPRequestHandler):
    def _reply(self, text):
        body = text.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/':
            self._reply('TLS 握手通过：这条响应全程加密')
        elif self.path == '/setcookie':
            self.send_response(200)
            self.send_header('Set-Cookie', 'wide=3; Path=/; Secure')
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            body = b'secure cookie issued over TLS'
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/cookie':
            self._reply('服务端收到的 Cookie 头: ' + self.headers.get('Cookie', '(无)'))

httpd = HTTPServer(('127.0.0.1', 8103), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
```

直接访问，看校验失败的完整报错。`--resolve ctf.local:8103:127.0.0.1` 让域名与证书的 CN 一致，把"域名匹配"这一关先排除掉：

```bash
curl --noproxy '*' --resolve ctf.local:8103:127.0.0.1 https://ctf.local:8103/
```

输出（进度条行已删）：

```
curl: (60) SSL certificate OpenSSL verify result: self-signed certificate (18)
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the webpage mentioned above.
```

连 TCP 和 TLS 握手都走完了，卡死在证书校验上，错误码 60。`-v` 看全过程的关键行：

```bash
curl -sv --noproxy '*' --resolve ctf.local:8103:127.0.0.1 https://ctf.local:8103/ 2>&1
```

输出（关键行）：

```
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* SSL Trust Anchors:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
*   CApath: /etc/ssl/certs
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / RSASSA-PSS
* Server certificate:
*   subject: CN=ctf.local
*   start date: Oct 23 10:29:31 2026 GMT
*   expire date: Sep 29 10:29:31 2126 GMT
*   issuer: CN=ctf.local
*  common name: ctf.local (matched)
* SSL certificate OpenSSL verify result: self-signed certificate (18)
* closing connection #0
```

客户端证书校验检查三件事，对照这份输出：

1. **信任链**：证书的签发者（`issuer: CN=ctf.local`，自己签自己）要能追到本机信任的根 CA——`SSL Trust Anchors` 两行显示的信任库 `/etc/ssl/certs/ca-certificates.crt` 里没有它，==自签证书在第一关就断了==，`(18)` 是 OpenSSL 的错误号；
2. **域名匹配**：`common name: ctf.local (matched)`——这次过了，但它是独立的一关。换个方式访问就看得出：

```bash
curl --noproxy '*' https://127.0.0.1:8103/
```

输出（进度条行已删）：

```
curl: (60) SSL: certificate subject name 'ctf.local' does not match target hostname '127.0.0.1'
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the webpage mentioned above.
```

用 IP 访问，报错换成了主机名不匹配——就算换成 CA 签发的证书，证书里没写这个 IP（SAN 字段）照样拒。

3. **有效期**：`start date` 到 `expire date` 之间才有效，本例 36500 天，不构成问题。

三关全过才继续，任何一关不过就拒连。==拒连拦的是"冒充"==：没有信任链背书，任何人都造得出一把 `CN=ctf.local` 的钥匙，浏览器无法区分真站和假站——[[10-网络协议基础|10 章]] 7 节"验签不过直接拒连，拦冒充就拦在这"落的就是这件事。

`-k` 关掉的就是证书校验，加密照常进行：

```bash
curl -sk --noproxy '*' https://127.0.0.1:8103/
```

输出：

```
TLS 握手通过：这条响应全程加密
```

==CTF 靶场几乎全是自签证书，`-k` 是日常操作==；对真实站点用 `-k`，等于放弃防冒充，链路上的中间人可以直接顶上。

> [!note] Burp 抓 HTTPS 的原理
> [[11-Web安全版图与Burp|11 章]] 2.1 让你把 Burp 的 CA 证书装进系统信任库——Burp 拦 HTTPS 时用自己的证书冒充目标站，你的信任库里有 Burp 的根证书，信任链就通了。它和 `-k` 是同一道检查的两种处理：一个是把中间人变成"可信"，一个是干脆不查身份。

## 7. DevTools Network 面板系统用法

[[11-Web安全版图与Burp|11 章]] 2.2 用一段话提过 DevTools，本节把 Network 面板按操作路径讲全。打开：`F12`（或 `Ctrl+Shift+I`）→ 选 **Network** 标签 → 刷新页面开始录制；左上角圆点控制录制开关，**Disable cache** 勾选后（面板打开期间）禁用缓存——调 Cookie 和请求头的实验必勾，否则浏览器用缓存响应，你改的东西根本没发出去。

### 7.1 面板布局与各列含义

| 列 | 含义 | 详情与说明 |
| ---- | ---- | ---- |
| Name | 资源名 / URL | 点击后的子标签：**Headers**（请求/响应头）、**Payload**（参数）、**Response**（响应体）、**Cookies**、**Initiator**（调用栈）、**Timing**（耗时分解） |
| Status | 状态码 | 灰色表示来自缓存 |
| Type | 资源类型 | document / script / stylesheet / xhr / fetch 等 |
| Initiator | 谁发起的请求 | 见 7.2 |
| Size | 两行：传输大小 / 资源大小 | 压缩前后的对比 |
| Time | 总耗时 | — |
| Waterfall | 时间线条 | 请求各阶段（排队、连接、等待、下载）的起止 |

Status、Size、Time 三列在终端的等价物是 curl 的 `-w` 变量（`-o /dev/null` 把响应体丢掉，只留统计）：

```bash
curl -s --noproxy '*' -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8100/headers.php
curl -s --noproxy '*' -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8100/no_such.php
curl -s --noproxy '*' -o /dev/null -w '%{time_total}s\n' http://127.0.0.1:8100/headers.php
```

输出：

```
200
404
0.001001s
```

### 7.2 过滤与录制控制

面板顶部过滤栏支持一组 `token:value` 语法，空格连用表示 AND，前缀 `-` 表示排除：

| 过滤式 | 作用 |
| ---- | ---- |
| `domain:api.example.com` | 只看该域 |
| `method:POST` | 只看该方法的请求 |
| `status-code:404` | 只看该状态码 |
| `mime-type:application/json` | 只看该响应类型 |
| `is:from-cache` | 只看缓存命中 |
| `larger-than:1k` | 按响应体大小筛 |

**Preserve log**：勾选后跳转到新页面、新标签都不清空请求列表。跟踪 302 链和登录流程（登录往往要连跳几站）必勾。终端等价物是 `curl -L`——跳转链的每一跳都排在同一条命令的输出里：

```bash
curl -svL --noproxy '*' http://127.0.0.1:8100/redir.php 2>&1
```

输出（节选，每跳只留请求行、状态行与跳转头）：

```
> GET /redir.php HTTP/1.1
< HTTP/1.1 302 Found
< Location: /headers.php
> GET /headers.php HTTP/1.1
< HTTP/1.1 200 OK
```

`redir.php` 的全部内容就一行 `header('Location: /headers.php', true, 302);`。[[10-网络协议基础|10 章]] 5.3 提过 302 响应体照样存在、curl 默认不跟跳——`-L` 跟跳之后，两跳的收发一目了然。

**Initiator** 列的取值：`parser`（HTML 解析遇到资源）、`script`（JS 发起）、`redirect`（前一跳转来）、`other`（地址栏直接访问等）。点开能看到发起调用的 JS 调用栈——==找"页面上这个请求是哪段代码发的"，就点它==。这一列没有终端等价物：它是浏览器侧的上下文信息。

另一个高频入口在搜索：面板左侧的放大镜（或 `Ctrl+Shift+F`）跨**所有响应**搜字符串——找 flag 字样、找接口返回里隐藏的参数，先搜再说。

### 7.3 Copy as cURL 与 Edit and Resend

**Copy as cURL**：任意请求右键 → **Copy** → **Copy as cURL (bash)**（还有 cmd 变体）。产物是一条带齐全部请求头（Cookie、UA、浏览器特征头一个不少）的 curl 命令，粘到终端就能重放，改一两个头就能做实验——==它就是"把浏览器里的请求搬到命令行"的标准通道==。

> [!warning] 复制出来的命令带着你的登录态
> Copy as cURL 的产物里含你的 Cookie。发给别人、贴到群里、写进文档之前，先把 `-H 'Cookie: ...'` 那段删掉。

**Edit and Resend**：请求右键 → **Edit and Resend**（新版 Chrome 与 Firefox 都有），在面板内改方法、URL、头、正文后直接重发，相当于面板内置的 Burp Repeater（[[11-Web安全版图与Burp|11 章]] 2.1）。旧版 Chrome 用右键 **Copy → Copy as fetch** 贴进 Console，改完参数回车执行，效果相同。终端的等价做法就是改 curl 命令重跑——2.3 节伪造请求头那套操作，在面板里对应的就是这两个功能。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---------- |
| WSL 里起靶，Windows 浏览器访问不了 | 服务绑了 `127.0.0.1` 时只在 WSL 内可见：对外提供绑 `0.0.0.0`，或用 WSL 的 IP；WSL2 的 localhost 转发方向是 Windows→WSL，反向要额外配置（[[01-Linux环境与CTF实验环境搭建\|01 章]]） |
| curl 输出里出现 `Trying 127.0.0.1:7897` 一类陌生端口 | 环境代理变量在劫持：`--noproxy '*'`（[[10-网络协议基础\|10 章]]常见问题表同款现象） |
| Set-Cookie 下发了，后续请求没回带 | 按四道关逐项查：过期没有；域匹配吗（host-only 的 cookie 不会发给子域）；路径前缀匹配吗；`Secure` 在 http 上不发、`SameSite` 跨站不发（[[#3.2 回带规则：cookie 罐里发生了什么\|3.2]]） |
| 回环地址上 Secure 属性测不出效果 | curl 与现代浏览器把 127.0.0.1/localhost 当可信上下文，http 照样存取 Secure cookie；换假域名加 `--resolve` 再测（[[#3.2 回带规则：cookie 罐里发生了什么\|3.2]]） |
| `SameSite=None` 的 cookie 被浏览器整个丢弃 | None 必须配 `Secure`，缺了整条 Set-Cookie 作废；本地 http 测试改用 Lax |
| 预检通过了，正式请求还是被浏览器拦 | 预检应答带了 ACAO，正式响应没带（预检和正式请求的响应头要分别设置）；或 `Access-Control-Allow-Headers` 没包含实际发的自定义头 |
| 配了 `ACAO: *`，带 cookie 的跨源请求仍读不到 | `*` 与凭证互斥；要反射具体 Origin 并加 `Access-Control-Allow-Credentials: true`——反射写法本身就是配置错误（[[#5.4 配置错误：反射 Origin\|5.4]]） |
| 改了 payload 的 JWT 服务端照样认 | 该服务端没验签或验签实现有洞；正常实现重算签名必拒（[[#4.2 手工签发与校验\|4.2]]），漏洞利用在后面的认证漏洞章 |
| 找不到 session 文件 | `save_path` 三种情况：php.ini 有配置（Debian 系常见 `/var/lib/php/sessions`）、为空走系统临时目录、CLI 与 web 进程用户不同各有一套；`ini_get('session.save_path')` 直接看（[[#3.3 Session：数据在服务端，cookie 只带编号\|3.3]]） |
| Copy as cURL 复制的命令跑不起来 | Chrome 复制的 bash 版含单引号与反斜杠续行，粘进 cmd 会断：Git Bash 里跑 bash 版，cmd 里选 Copy as cURL (cmd) |
| php -S 上并发请求互相卡 | 内置服务器默认单进程：`PHP_CLI_SERVER_WORKERS=N` 起多个 worker，或换正规服务器 |
| 改了 X-Forwarded-For，REMOTE_ADDR 没变 | 本来就不会变：REMOTE_ADDR 是 TCP 对端地址，不是请求头（[[#2.2 靶场：回显服务端收到的请求头\|2.2]]）；两者混用正是限流绕过类题的考点 |
| `-k` 都连不上 HTTPS 靶 | 三查：服务起没起（`ss -tanp` 看端口）、证书文件加载没加载（服务自身的报错输出）、绑的地址对不对 |

## 9. 配套练习与延伸阅读

配套练习：

1. 把 `gate.php` 的校验改成"X-Forwarded-For 的**第一个** IP 在 `10.0.0.0/8` 段内，且 User-Agent 含 `Mobile`"，用 `curl -H` 逐项伪造通过。注意 XFF 是逗号列表，校验的是第一个值，伪造时多放几个 IP 体会"取第一个还是最后一个"的区别。
2. 给 `cookies.php` 新增一条 `SameSite=None` 但缺 `Secure` 的 Set-Cookie，用真浏览器访问 `http://127.0.0.1:8100/cookies.php`，在 DevTools 的 **Console** 看丢弃警告，在 **Application → Cookies** 面板确认它没进罐。
3. 把 `jwt_demo.py` 的 `SECRET` 换成弱口令字典里的某个词，写个循环对密钥爆破（拿 4.2 的 `verify` 当校验函数），统计多久命中；再把 `role` 改成 `guest` 重新签发一个合法 token，对比篡改 token 的 verify 结果。
4. 8100 与 8102 是两个源。写一个页面放在 8100，用 `fetch('http://127.0.0.1:8102/api/data')` 读 8102，打开 DevTools 看 Console 的跨源报错与 Network 面板里有没有预检；再把 `cors.py` 的反射改成白名单（只放行 `http://127.0.0.1:8100`），重看两种请求的命运。
5. 用自己的测试账号登录任一真实站点，Network 面板里对登录后的第一个请求 Copy as cURL，终端重放确认成功，再只改密码字段看响应差异；全程注意别把含 Cookie 的命令外发。

延伸阅读：

- MDN HTTP 头部参考（<https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers>），`Set-Cookie`（<https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Set-Cookie>）与 `Strict-Transport-Security` 的权威字段说明；
- MDN CORS 文档（<https://developer.mozilla.org/zh-CN/docs/Web/HTTP/CORS>），简单请求判定与预检流程的完整规范描述；
- RFC 6265（Cookie，<https://datatracker.ietf.org/doc/html/rfc6265>）与 RFC 7519（JWT，<https://datatracker.ietf.org/doc/html/rfc7519>），两份协议原文，字段语义存疑时查它们；
- OWASP Session Management Cheat Sheet（<https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>），session id 生成、传递、吊销的工程清单；
- PortSwigger Web Security Academy（<https://portswigger.net/web-security>），CORS 与认证相关章节的免费互动实验，[[02-书单与Wiki|02 篇]]收录的入门书单可作为配套阅读。

下一站：[[W02-工具链实战与靶场搭建|W02]] 把本章手工敲的命令升级成系统化的工具链与靶场环境；本章的请求头伪造、Cookie 规则与 JWT 结构会反复出现在 [[W03-信息泄露与前端安全|W03]] 之后的每一章里。
