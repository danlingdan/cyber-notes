---
chapter: MISC
section: 流量取证 II：加密流量与 USB
order: 811
tags:
  - CTF
  - MISC
  - 流量分析
publish: true
---

# M11 流量取证 II：加密流量与 USB
## Network Forensics II: TLS and USB

> [!info]- 章节信息
> **所属方向**：MISC ｜ **难度阶段**：L3 进阶期 ｜ **前置要求**：[[12-隐写与流量取证|12 章]] · [[M01-MISC导论与工具箱|M01]] · [[M10-流量取证I-协议还原深挖|M10]]
> **本章目标**：把流量取证推进到"看不到明文"的现场：TLS 加密流量拿 SSLKEYLOGFILE 解密，还原出完整会话；USB 键鼠与蓝牙流量按 report 结构逐字节翻译；WiFi 从 EAPOL 四次握手读出口令验证材料，并用 aircrack-ng 对字典做离线爆破。

## 1. 定位：从明文协议到密文与外设

[[M10-流量取证I-协议还原深挖|M10]]把明文协议的还原做完了：HTTP 对象导出、自定义协议猜字段、ICMP/DNS 隧道重组。但赛题里还有三类现场，[[M10-流量取证I-协议还原深挖|M10]]的那套方法在这里不够用：

1. ==TLS 加密流量==：TCP 载荷里是加密的 TLS 记录，`strings` 扫不出任何明文。突破口不在流量本身，而在会话密钥的另一份落盘副本——key log 文件。
2. ==USB 键鼠流量==：pcap 里记录的不是网络报文，而是主机与外设之间的总线通信，帧里装的是 8 字节的键盘 report、3 字节的鼠标 report，要按 HID 规范逐字节翻译。[[12-隐写与流量取证#7.3 流量题四大套路|12 章 7.3]]四大套路里"USB 键鼠"一条只给了一行识别思路，本节展开成完整方法。
3. ==WiFi 流量==：链路层是 802.11 而不是以太网；WPA2 加密的数据抓不到明文，但握手帧本身是明文的，其中的材料足以离线验证任意一个候选口令——这是握手爆破的原理。

三类现场在 pcap 文件结构上是统一的：[[M10-流量取证I-协议还原深挖#3.1 global header：24 字节定全局|M10 3.1]]拆过 global header 的最后一个字段 network（链路类型），它决定每条 record 的报文本体按什么格式解析。本章四类靶的链路类型放在一起看：

| 链路类型值 | file 的说法 | 帧里装什么 | 本章哪节 |
| ---- | ---- | ---- | ---- |
| 1 | Ethernet | 以太网帧（[[M10-流量取证I-协议还原深挖\|M10]]全章） | — |
| 220 | Memory-mapped Linux USB | 64 字节 usbmon 头 + USB 数据 | 3、4 节 |
| 201 | Bluetooth HCI H4 with pseudo-header | 4 字节方向伪头 + HCI H4 包 | 5 节 |
| 127 | 802.11 with radiotap header | radiotap 头 + 802.11 帧 | 6 节 |

```bash
file tls.pcap usb_kb.pcap bt_att.pcap wpa.pcap
```

输出：

```text
tls.pcap:       pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
usb_kb.pcap:    pcap capture file, microsecond ts (little-endian) - version 2.4 (Memory-mapped Linux USB, capture length 65535)
usb_mouse.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Memory-mapped Linux USB, capture length 65535)
bt_att.pcap:    pcap capture file, microsecond ts (little-endian) - version 2.4 (Bluetooth HCI H4 with pseudo-header, capture length 65535)
wpa.pcap:       pcap capture file, microsecond ts (little-endian) - version 2.4 (802.11 with radiotap header, capture length 65535)
```

拿到非 Ethernet 的流量包，第一件事就是确认链路类型，后面的解析全部跟着它走。本章的靶子继续按 [[M10-流量取证I-协议还原深挖#2.2 造靶方法论|M10 2.2]]的三条原则自造，识别入口沿用 [[M10-流量取证I-协议还原深挖#4.4 可复用的四步范式|M10 4.4]]的四步范式：统计占比 → 找会话 → 收敛 → 字段提取。

## 2. TLS 流量与 SSLKEYLOGFILE 解密

### 2.1 抓到的 TLS 为什么是密文

浏览器与服务器之间的 HTTPS，在 TCP 载荷里是逐条封装的 TLS 记录（record）：握手阶段的记录协商参数与密钥，应用数据阶段的记录把 HTTP 报文整体加密。抓包能拿到全部字节，却读不出一个字符——==会话密钥只存在于通信双方的进程内存里，抓包者手里没有==。

密钥能不能从抓包字节里算出来？现代 TLS（TLS 1.3 以及配 ECDHE 的 TLS 1.2）的会话密钥由双方各自的临时密钥参数派生，握手帧里交换的只有公开参数，推不出私有部分——这个性质叫前向秘密，它保证"拿到流量推不出密钥"。因此解密 TLS 流量的标准姿势是另一条路：==让客户端进程把会话密钥写进文件==。主流浏览器和 OpenSSL 都支持 NSS key log 格式：环境变量 `SSLKEYLOGFILE` 指向一个文件路径，客户端每完成一次握手就把该会话的密钥追加进去。文件里一行一个会话，三列：

| 行标签 | 出现于 | 第二列 | 第三列 |
| ---- | ---- | ---- | ---- |
| `CLIENT_RANDOM` | TLS 1.2 | ClientHello 的 32 字节 random | 48 字节主密钥 |
| `CLIENT_HANDSHAKE_TRAFFIC_SECRET` | TLS 1.3 | 同上 | 客户端握手阶段流量密钥 |
| `SERVER_HANDSHAKE_TRAFFIC_SECRET` | TLS 1.3 | 同上 | 服务器握手阶段流量密钥 |
| `CLIENT_TRAFFIC_SECRET_0` | TLS 1.3 | 同上 | 客户端应用数据流量密钥 |
| `SERVER_TRAFFIC_SECRET_0` | TLS 1.3 | 同上 | 服务器应用数据流量密钥 |
| `EXPORTER_SECRET` | TLS 1.3 | 同上 | 导出器密钥，解题很少用 |

三列都是十六进制，`#` 开头的行是注释。第二列的 client random 是配对键：每个会话的 ClientHello 里就有这个 32 字节随机数，解密器拿它把"哪一行密钥"对到"哪一条流"。TLS 1.3 一次握手写四行（握手阶段两行 + 应用数据两行），TLS 1.2 只写一行 `CLIENT_RANDOM`。

> [!note] 真实流量怎么拿到 keylog
> 给 Chrome 或 Firefox 设置系统环境变量 `SSLKEYLOGFILE=C:\keys\sslkeys.log` 再启动，浏览器访问的所有 HTTPS 会话密钥都会追加进该文件——这是"解自己浏览器流量"的标准姿势。赛题里出题人通常直接把 keylog 文件作为附件给出，考的是会不会用。

### 2.2 造靶：把一段真实 TLS 会话落成 pcap

[[M10-流量取证I-协议还原深挖#2.2 造靶方法论|M10 2.2]]的警告框说过，本库 WSL 的回环抓包抓不到 TCP 流量，"本机起 TLS 服务 + 现场抓包"这条路走不通。造靶换一个入口：==用 Python ssl 库的 MemoryBIO 跑一段真实握手，把两个方向的记录字节截下来，再用 scapy 组装成 pcap==。线上字节由 ssl 库本体生成，与真实 socket 上跑的完全一致，解密端照常工作。

> [!note] 真机 Linux 上的另一条造靶路
> 在能抓回环的机器上不需要 MemoryBIO：`openssl s_server -accept 5011 -cert cert.pem -key key.pem -www` 起服务，`tshark -i lo -f "tcp port 5011" -w tls.pcap` 挂在后台抓包，另开一个终端 `openssl s_client -connect 127.0.0.1:5011 -keylogfile sslkeys.log` 完成一次握手，pcap 与 keylog 同时到手（`-keylogfile` 写出的行格式与 2.1 的表相同）。本库 WSL 受回环抓包限制，所以本章正文走 MemoryBIO。

> [!info]- wrap_bio 与握手循环
> `ssl.MemoryBIO` 是一块可读写的内存缓冲。`context.wrap_bio(incoming, outgoing)` 返回的 SSLObject 不绑定 socket：`do_handshake()` 把要发送的记录写进 outgoing、从 incoming 读收到的记录，数据不够时抛 `SSLWantReadError`，没写完时抛 `SSLWantWriteError`。循环里每次尝试握手后，把 outgoing 的字节搬进对端的 incoming，同时记进事件列表，直到双方都报告握手完成；应用数据同理，`write()` 产生记录、搬运、对端 `read()` 解出。所谓"截获"，就是搬运时留一份副本。

```python
# build_tls.py —— MemoryBIO 跑两段真 TLS 握手（1.3 / 1.2），按事件顺序记录
# 两个方向的线上字节，配 scapy 搓成 pcap；同时产出 SSLKEYLOGFILE。
import calendar
import os
import ssl
import subprocess

from scapy.all import Ether, IP, Raw, TCP, wrpcap

BASE = calendar.timegm((2026, 10, 24, 17, 0, 0))
C_MAC, S_MAC = "52:54:00:12:34:56", "52:54:00:78:9a:bc"
C_IP, S_IP = "10.13.0.2", "10.13.0.1"
KEYLOG = "sslkeys.log"

if os.path.exists(KEYLOG):
    os.remove(KEYLOG)

# 服务器证书：自签一张，openssl 命令现场生成
if not (os.path.exists("cert.pem") and os.path.exists("key.pem")):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", "key.pem", "-out", "cert.pem",
                    "-days", "1", "-nodes", "-subj", "/CN=ctf.local"],
                   check=True, capture_output=True)

FLAG13 = b"flag{tls_keyl0g_decryped}"
FLAG12 = b"flag{tls12_also_0k}"
RESP13 = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
          + str(len(FLAG13)).encode() + b"\r\n\r\n" + FLAG13)
RESP12 = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
          + str(len(FLAG12)).encode() + b"\r\n\r\n" + FLAG12)


def tls_wire(version_tls12=False):
    """跑一段真实 TLS 握手 + 一轮 HTTP 应用数据。
    返回 (事件列表 [(方向, 线上字节)], 协商版本)。字节全部来自 ssl 库本体，
    事件顺序即真实会话的时间顺序：ClientHello -> 服务器握手 -> 客户端 Finished
    -> 服务器票据 -> GET -> 200。"""
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    client_ctx.keylog_filename = KEYLOG
    if version_tls12:
        client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        client_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain("cert.pem", "key.pem")

    c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    c = client_ctx.wrap_bio(c_in, c_out, server_hostname="ctf.local")
    s = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    events = []

    def flush(direction, bio, peer):
        """把一方的待发记录字节推到线上（记为事件），写进对端入口"""
        moved = False
        while bio.pending:
            data = bio.read()
            events.append((direction, data))
            peer.write(data)
            moved = True
        return moved

    c_done = s_done = False
    while not (c_done and s_done):
        progressed = False
        if not c_done:
            try:
                c.do_handshake()
                c_done = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            progressed = flush("c", c_out, s_in) or progressed
        if not s_done:
            try:
                s.do_handshake()
                s_done = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            progressed = flush("s", s_out, c_in) or progressed
        if not progressed and not (c_done and s_done):
            raise RuntimeError("handshake stalled")
    flush("c", c_out, s_in)     # 收尾：把双方残留记录（会话票据等）推完
    flush("s", s_out, c_in)

    # 应用数据：GET 请求 -> 200 响应，同样按事件顺序记在记录层
    c.write(b"GET /flag HTTP/1.1\r\nHost: ctf.local\r\nUser-Agent: curl/8.16.0\r\n\r\n")
    flush("c", c_out, s_in)
    s.read()
    s.write(RESP13 if not version_tls12 else RESP12)
    flush("s", s_out, c_in)
    c.read()

    return events, c.version()


def build_stream(sport, events):
    """一段 TCP 会话：三次握手 + 数据包与 ACK 按事件顺序交错，返回包列表"""
    pkts = []
    t = [0.0]
    cseq, sseq = 1000, 5000

    def add(p, src=C_IP):
        ether = (Ether(src=C_MAC, dst=S_MAC) if src == C_IP
                 else Ether(src=S_MAC, dst=C_MAC))
        pkt = (ether / IP(src=src, dst=S_IP if src == C_IP else C_IP) / p)
        pkt.time = BASE + t[0]
        t[0] += 0.5
        pkts.append(pkt)

    add(TCP(sport=sport, dport=443, flags="S", seq=cseq))
    add(TCP(sport=443, dport=sport, flags="SA", seq=sseq, ack=cseq + 1), src=S_IP)
    add(TCP(sport=sport, dport=443, flags="A", seq=cseq + 1, ack=sseq + 1))
    cseq += 1
    sseq += 1
    for direction, payload in events:
        if direction == "c":
            add(TCP(sport=sport, dport=443, flags="PA", seq=cseq, ack=sseq) / Raw(payload))
            cseq += len(payload)
            add(TCP(sport=443, dport=sport, flags="A", seq=sseq, ack=cseq), src=S_IP)
        else:
            add(TCP(sport=443, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(payload), src=S_IP)
            sseq += len(payload)
            add(TCP(sport=sport, dport=443, flags="A", seq=cseq, ack=sseq))
    return pkts


# --- 两段会话：TLS 1.3 与 TLS 1.2 ---
ev13, ver13 = tls_wire(version_tls12=False)
ev12, ver12 = tls_wire(version_tls12=True)
pkts = build_stream(40001, ev13) + build_stream(40002, ev12)
wrpcap("tls.pcap", pkts)

print(f"[1] TLS {ver13}: {len(ev13)} 次线上发送；TLS {ver12}: {len(ev12)} 次")
print(f"[2] tls.pcap 共 {len(pkts)} 个包")

lines = sorted(l for l in open(KEYLOG).read().splitlines() if l and not l.startswith("#"))
print(f"[3] {KEYLOG} 共 {len(lines)} 行密钥行（另有一行 # 开头的注释；密钥十六进制截短显示）:")
for l in lines:
    parts = l.split(" ")
    print("    " + parts[0] + " " + parts[1][:16] + ".."
          + f"(random {len(parts[1])//2}B)" + " " + parts[2][:16] + ".."
          + f"(secret {len(parts[2])//2}B)")
```

输出：

```text
[1] TLS TLSv1.3: 6 次线上发送；TLS TLSv1.2: 6 次
[2] tls.pcap 共 30 个包
[3] sslkeys.log 共 6 行密钥行（另有一行 # 开头的注释；密钥十六进制截短显示）:
    CLIENT_HANDSHAKE_TRAFFIC_SECRET 7d67ec50a687784d..(random 32B) a70646f9d982a040..(secret 48B)
    CLIENT_RANDOM 36232037d664ee51..(random 32B) 66b4c97d9205b85c..(secret 48B)
    CLIENT_TRAFFIC_SECRET_0 7d67ec50a687784d..(random 32B) 430bb33609173f13..(secret 48B)
    EXPORTER_SECRET 7d67ec50a687784d..(random 32B) 0b68f4869da2b90f..(secret 48B)
    SERVER_HANDSHAKE_TRAFFIC_SECRET 7d67ec50a687784d..(random 32B) 7be32b5f24e5c709..(secret 48B)
    SERVER_TRAFFIC_SECRET_0 7d67ec50a687784d..(random 32B) 4371188518fea2ac..(secret 48B)
```

与 2.1 的表对上：TLS 1.3 的会话写了四行 `*_TRAFFIC_SECRET` 加一行 `EXPORTER_SECRET`，TLS 1.2 的会话只有一行 `CLIENT_RANDOM`，两类行各自带着 32 字节 client random。密钥材料每次生成都不同——TLS 的随机数本来就是随机的，造靶的可复现性退到"结构固定"：每次包数、格式、标志一致，具体字节不同。

> [!warning] 数据包必须按真实时序排列
> tshark 顺序解析每一条记录。如果客户端的应用数据记录排在 ServerHello 之前（比如把客户端方向的所有包先发完、服务器的包全排在后面），解析器读到那条记录时还没有可用的会话密钥，==这条记录会保持密文不被解密==。造 TLS 的 pcap 必须照真实会话的时间顺序交错：ClientHello → 服务器握手记录 → 客户端 Finished → 服务器会话票据 → GET → 200。2.3 节解靶时若发现"响应解开了、请求还是密文"，先查包的排列顺序。

### 2.3 解靶：tshark 三步解密

第 1 步，识别。`-z io,phs` 显示 30 个帧全是 tcp，其中 12 个被归入 tls 层：

```bash
tshark -r tls.pcap -q -z io,phs
```

输出：

```text
===================================================================
Protocol Hierarchy Statistics
Filter: 

frame                                    frames:30 bytes:8314
  eth                                    frames:30 bytes:8314
    ip                                   frames:30 bytes:8314
      tcp                                frames:30 bytes:8314
        tls                              frames:12 bytes:7342
===================================================================
```

第 2 步，无 keylog 的对照：`-Y http` 一个包都筛不出来，流 0 的载荷开头是 `16 03 03`（TLS 记录头：类型 22/23 + 版本 + 长度），后面全是密文：

```bash
tshark -r tls.pcap -Y http | wc -l
tshark -r tls.pcap -Y 'tcp.stream==0 && tcp.len>0' -T fields -e tcp.payload | head -2 | cut -c1-72
```

输出：

```text
0
160301060a0100060603037d67ec50a687784d7f17fa6e624c4c4bf6da03d92bada1ab84
16030304ba020004b603035820bdbfceb97c688792784f17f40f3eebd05f1ca532c99db6
```

第 3 步，带上 keylog 解密。`-o tls.keylog_file:` 指定密钥文件（读文件用相对路径或绝对路径都行）：

```bash
tshark -r tls.pcap -o tls.keylog_file:sslkeys.log -Y http \
    -T fields -e frame.number -e http.request.method -e http.request.uri \
    -e http.response.code -E header=y
```

输出：

```text
frame.number	http.request.method	http.request.uri	http.response.code
12	GET	/flag	
14		/flag	200
27	GET	/flag	
29		/flag	200
```

两条流各解开一对请求响应，`http` 过滤器、字段提取与 [[M10-流量取证I-协议还原深挖#5. HTTP 对象批量导出|M10 5 节]]完全一致——==解密发生在 TLS 层，解开的明文自动交给上层协议解析器==，后面的手法与明文 HTTP 相同。看完整对话用 follow，流编号从 0 起：

```bash
tshark -r tls.pcap -o tls.keylog_file:sslkeys.log -q -z follow,tls,ascii,0
```

输出：

```text
===================================================================
Follow: tls,ascii
Filter: tls.stream eq 0
Node 0: 10.13.0.1:443
Node 1: 10.13.0.2:40001
	64
GET /flag HTTP/1.1
Host: ctf.local
User-Agent: curl/8.16.0


90
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 25

flag{tls_keyl0g_decryped}
===================================================================
```

`follow,tls` 是 TLS 专用的流跟随（`follow,tcp` 只能看到密文），明文 flag 直接在输出里。流 1 是 TLS 1.2 那段：

```bash
tshark -r tls.pcap -o tls.keylog_file:sslkeys.log -q -z follow,tls,ascii,1 | tail -3
```

输出：

```text
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 19

flag{tls12_also_0k}
===================================================================
```

批量取响应体走 [[M10-流量取证I-协议还原深挖#5. HTTP 对象批量导出|M10 5 节]]的导出对象，解密后照常可用：

```bash
tshark -r tls.pcap -o tls.keylog_file:sslkeys.log --export-objects http,tlsobjs -q
ls tlsobjs
for f in tlsobjs/*; do cat "$f"; echo; done
```

输出：

```text
flag
flag(1)
flag{tls_keyl0g_decryped}
flag{tls12_also_0k}
```

> [!note] Wireshark 图形界面的对应配置（Windows 侧）
> 菜单 编辑 → 首选项 → Protocols → TLS → (Pre)-Master-Secret log filename 填 keylog 文件的 Windows 路径，确认后整包自动解密，右键 TLS 包 → Follow → TLS Stream 即可看到明文；也可以对任意 TLS 包右键 → 协议首选项临时指定。注意 keylog 与 pcap 必须同源：不同会话的 client random 对不上，一行密钥都不会被采用。

## 3. USB HID 键盘流量

### 3.1 report 结构与两张表

[[12-隐写与流量取证#7.3 流量题四大套路|12 章 7.3]]说过：USB 键盘一次按键 8 字节，第 3 字节是 HID 位置码。本节把结构说全。这 8 字节是一份 HID 键盘 report：

| 偏移 | 字段 | 说明 |
| ---- | ---- | ---- |
| 0 | 修饰键（modifier） | 位掩码，见下表 |
| 1 | 保留 | 恒为 0 |
| 2–7 | 键码（keycode）× 6 | 本次按下的键，最多同时 6 个；全零 report 表示"无键按下"（放键） |

修饰键一个字节八个位，左半与右半各占一半：

| 位值 | 键 | 位值 | 键 |
| ---- | ---- | ---- | ---- |
| 0x01 | 左 Ctrl | 0x10 | 右 Ctrl |
| 0x02 | 左 Shift | 0x20 | 右 Shift |
| 0x04 | 左 Alt | 0x40 | 右 Alt（AltGr） |
| 0x08 | 左 Win | 0x80 | 右 Win |

键码节选（完整表叫 USB HID Usage Tables，键盘页 Keyboard/Keypad）：

| 键码 | 键 | Shift 后 | 键码 | 键 | Shift 后 |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 0x04–0x1D | a–z | A–Z | 0x28 | Enter | — |
| 0x1E–0x26 | 1–9 | ! @ # $ % ^ & * ( | 0x29 | Esc | — |
| 0x27 | 0 | ) | 0x2A | Backspace | — |
| 0x2C | 空格 | — | 0x2D | - | _ |
| 0x2E | = | + | 0x2F | [ | { |
| 0x30 | ] | } | 0x33 | ; | : |
| 0x34 | ' | " | 0x35 | \` | ~ |
| 0x36 | , | < | 0x37 | . | > |
| 0x38 | / | ? | 0x39 | CapsLock | — |

击键在流量里的形态是固定的：==一次按键至少两条 report——按下（键码写进 2–7 号槽，需要 Shift 时把修饰键字节的 Shift 位置 1）加放键（全零）==；键按住不放时，主机会按重复率反复上报同一条按下 report。还原击键固定三步：跳过全零 report、相邻重复的 report 只算一次、按键码和修饰键位查表拼字符。

### 3.2 造靶：usbmon 格式的 pcap

USB 流量不走以太网，pcap 的链路类型字段决定帧结构。Linux 内核的 USB 监视器 usbmon 写出的 pcap 链路类型为 220，每条 record 是 64 字节 usbmon 头加数据本体——[[M10-流量取证I-协议还原深挖#3.2 record：长度字段驱动遍历|M10 3.2]]的 record 遍历机制原样适用，只是报文本体从以太网帧换成了 usbmon 头。造靶脚本照 M10 3 节的文件结构手写整个 pcap：

```python
# build_usb_kb.py —— 手搓 usbmon 格式（linktype 220）pcap：键盘 HID report 敲出 flag
import calendar
import struct

LINKTYPE_USB_LINUX_MMAPPED = 220
BASE = calendar.timegm((2026, 10, 24, 18, 0, 0))

# ---- HID 键盘 8 字节 report 的字符映射（build 与 solve 各用一半） ----
CHAR2KEY = {}
for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz"):
    CHAR2KEY[ch] = (0x04 + i, False)
    CHAR2KEY[ch.upper()] = (0x04 + i, True)
for i, ch in enumerate("1234567890"):
    CHAR2KEY[ch] = (0x1E + i, False)
SYM = {" ": (0x2C, False), "-": (0x2D, False), "_": (0x2D, True),
       "=": (0x2E, False), "+": (0x2E, True), "[": (0x2F, False), "{": (0x2F, True),
       "]": (0x30, False), "}": (0x30, True), "\\": (0x31, False), "|": (0x31, True),
       ";": (0x33, False), ":": (0x33, True), "'": (0x34, False), '"': (0x34, True),
       "`": (0x35, False), "~": (0x35, True), ",": (0x36, False), "<": (0x36, True),
       ".": (0x37, False), ">": (0x37, True), "/": (0x38, False), "?": (0x38, True),
       "\n": (0x28, False)}
CHAR2KEY.update(SYM)


def pcap_records(linktype, records):
    """经典 pcap：24 字节 global header + 逐包 record（文件结构同 M10 3 节）"""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)]
    for ts, data in records:
        out.append(struct.pack("<IIII", int(ts), int(round((ts - int(ts)) * 1e6)),
                               len(data), len(data)))
        out.append(data)
    return b"".join(out)


_id = [0]


def usbmon(ts, typ, xfer, epnum, devnum, flag_data, payload, status=0, length=None):
    """usbmon 64 字节头（mmapped 格式，小端）+ 数据本体。
    xfer: 0 ISO / 1 Interrupt / 2 Control / 3 Bulk；typ: 'S' 提交 / 'C' 完成"""
    _id[0] += 1
    ts_sec = int(ts)
    ts_usec = int(round((ts - ts_sec) * 1e6))
    length = len(payload) if length is None else length
    hdr = struct.pack("<qBBBBHccqiiII8siiiI",
                      _id[0], ord(typ), xfer, epnum, devnum, 1,
                      b"-", flag_data,
                      ts_sec, ts_usec, status, length, len(payload),
                      b"\x00" * 8, 0, 0, 0, 0)
    assert len(hdr) == 64, len(hdr)
    return hdr + payload


def type_reports(text):
    """把要敲的文本展开成 [(report 字节, 时间偏移)]：每键一压一放"""
    reps = []
    t = 0.0
    for ch in text:
        key, shift = CHAR2KEY[ch]
        mod = 0x02 if shift else 0x00           # 左 Shift
        reps.append((bytes([mod, 0, key, 0, 0, 0, 0, 0]), t)); t += 0.02
        reps.append((bytes(8), t)); t += 0.03   # 放键：全零 report
    return reps


TEXT = "flag{usb_h1d_keyb0ard}\n"
reports = type_reports(TEXT)

records = []
ts = float(BASE)
for report, dt in reports:
    ts += dt
    records.append((ts, usbmon(ts, "S", 1, 0x81, 1, b"-", b"", status=-115, length=8)))
    ts += 0.001
    records.append((ts, usbmon(ts, "C", 1, 0x81, 1, b"<", report)))

open("usb_kb.pcap", "wb").write(pcap_records(LINKTYPE_USB_LINUX_MMAPPED, records))
print(f"usb_kb.pcap：{len(records)} 条记录（每键 S/C 各一对），"
      f"敲入 {len(TEXT) - 1} 个字符 + 回车")
```

输出：

```text
usb_kb.pcap：92 条记录（每键 S/C 各一对），敲入 22 个字符 + 回车
```

> [!info]- usbmon 64 字节头的字段表
> | 字段 | 大小 | 本靶取值 | 说明 |
> | ---- | ---- | ---- | ---- |
> | id | 8 | 递增 | 记录序号 |
> | type | 1 | 'S' / 'C' | 提交（submit）/ 完成（callback）；USB 键盘数据在 'C' 记录里 |
> | xfer_type | 1 | 1 | 传输类型：0 ISO、1 中断、2 控制、3 批量；键鼠走中断传输 |
> | epnum | 1 | 0x81 | 端点号 + 0x80 表示 IN（设备 → 主机） |
> | devnum | 1 | 1 | 设备地址，鼠标靶里用 2 区分 |
> | busnum | 2 | 1 | 总线号 |
> | flag_setup / flag_data | 1 + 1 | '-' / '<' | 数据标志：'-' 无数据，'<' 数据在正文（IN） |
> | ts_sec / ts_usec | 8 + 4 | 当前时间 | 秒 + 微秒 |
> | status | 4 | 0 / -115 | 完成状态；提交侧 -115 表示传输进行中 |
> | length / len_cap | 4 + 4 | 8 / 8 | URB 申请长度 / 实际捕获长度 |
> | setup | 8 | 0 | 控制传输的 setup 包，中断传输不用 |
> | interval、start_frame、xfer_flags、ndesc | 12 + 4 | 0 | 中断间隔等附加字段 |
>
> 全部小端，总计 64 字节。tshark 显示为 `URB_INTERRUPT in`，设备地址形如 1.1.1（总线.设备.端点）。

识别与提取。协议统计里只有一层 usb（没抓到 HID 描述符时 Wireshark 认不出键盘设备），但数据载荷的字段名是 `usb.capdata`：

```bash
tshark -r usb_kb.pcap -q -z io,phs | sed -n '6,7p'
tshark -r usb_kb.pcap -Y usb.capdata -T fields -e usb.capdata | head -4
```

输出：

```text
frame                                    frames:92 bytes:6256
  usb                                    frames:92 bytes:6256
0000090000000000
0000000000000000
00000f0000000000
0000000000000000
```

第一行 `00 00 09 ...`：修饰键 0、键码 0x09 = f 键——敲的第一个字符；第二行全零是放键。每行恰好 16 个十六进制字符 = 8 字节 report。

> [!note] usb.capdata 与 usbhid.data
> 本靶没有捕获 HID 描述符（那要靠控制传输的几条记录），Wireshark 认不出"这是键盘"，数据落在通用载荷字段 usb.capdata；USBPcap 抓的完整包里，同一份数据常被 USB HID 解析器认领，字段名为 usbhid.data。解题时两个过滤器都试一下，[[12-隐写与流量取证#7.1 显示过滤器速查|12 章 7.1]]的速查表里两个名字都在。

### 3.3 解靶：去重、查表、拼接

```python
# solve_usb_kb.py —— 读 stdin 里 tshark 提取的 8 字节 report（hex），还原击键文本
import sys

# 键码 -> (普通字符, Shift 字符)；0x04-0x1D 是 a-z，0x1E-0x27 是数字行
KEYMAP = {}
for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz"):
    KEYMAP[0x04 + i] = (ch, ch.upper())
for i, d in enumerate("123456789"):
    KEYMAP[0x1E + i] = (d, "!@#$%^&*("[i])
KEYMAP[0x27] = ("0", ")")
KEYMAP.update({
    0x28: ("\n", "\n"), 0x29: ("<ESC>", "<ESC>"), 0x2A: ("<BS>", "<BS>"),
    0x2C: (" ", " "), 0x2D: ("-", "_"), 0x2E: ("=", "+"), 0x2F: ("[", "{"),
    0x30: ("]", "}"), 0x31: ("\\", "|"), 0x33: (";", ":"), 0x34: ("'", '"'),
    0x35: ("`", "~"), 0x36: (",", "<"), 0x37: (".", ">"), 0x38: ("/", "?"),
})

prev = None
out = []
for line in sys.stdin:
    hx = line.strip().replace(":", "")
    if len(hx) != 16:            # 不是 8 字节 report：跳过
        continue
    report = bytes.fromhex(hx)
    if report == prev:           # 键按住不放，主机会重复上报同一 report：去重
        continue
    prev = report
    shift = bool(report[0] & 0x22)          # 左Shift(0x02) 或 右Shift(0x20)
    for key in report[2:8]:
        if key == 0:
            continue             # 放键 report 或空槽位
        normal, shifted = KEYMAP.get(key, (f"<0x{key:02x}>", f"<0x{key:02x}>"))
        out.append(shifted if shift else normal)
print("".join(out), end="")
```

```bash
tshark -r usb_kb.pcap -Y usb.capdata -T fields -e usb.capdata | python3 solve_usb_kb.py
```

输出：

```text
flag{usb_h1d_keyb0ard}
```

三处处理对应 3.1 的三个结构点：`report == prev` 去掉按住时的重复上报；全零 report 在键码循环里天然跳过；`0x22` 位掩码同时接住左右两个 Shift，flag 里的 `{`、`}`、`_` 全靠它翻出来。

## 4. USB HID 鼠标流量

### 4.1 report 结构：按键加有符号位移

鼠标 report 的经典结构是 3 字节（现代鼠标多出滚轮等字节，但前三节含义不变）：

| 偏移 | 字段 | 说明 |
| ---- | ---- | ---- |
| 0 | 按键位 | 位掩码：0x01 左键、0x02 右键、0x04 中键 |
| 1 | Δx | 有符号 8 位整数，> 127 要减 256 |
| 2 | Δy | 同上；屏幕坐标 y 向下为正 |

鼠标上报的是相对位移，绝对位置要自己累加：

$$x_t = x_0 + \textstyle\sum_i \Delta x_i, \qquad y_t = y_0 + \textstyle\sum_i \Delta y_i \tag{4.1}$$

==按下左键期间的位移是"画线"，抬键期间的位移是"挪笔"==——把按下区间的轨迹画出来，得到出题人写下的字符。位移字节 $b_i > 127$ 时按 $\Delta = b_i - 256$ 处理，漏掉这一步轨迹会整体跑偏。

### 4.2 造靶与解靶：拖出三个字母

造靶：按住左键沿笔画逐像素走线（按键位 0x01），笔画之间抬笔挪到下一笔起点（按键位 0），usbmon 头与第 3 节同一套，只是设备地址用 2、report 长 3 字节：

```python
# build_usb_mouse.py —— 鼠标 HID report（3 字节：按键/Δx/Δy）：按住左键写出 "CTF" 轨迹
import calendar
import struct

LINKTYPE = 220
BASE = calendar.timegm((2026, 10, 24, 19, 0, 0))

# "CTF" 的笔画（画布坐标，y 向下；每笔 = 一串折点）
STROKES = [
    [(10, 3), (3, 3), (3, 12), (10, 12)],            # C
    [(14, 3), (24, 3)],
    [(19, 3), (19, 12)],                             # T 两笔
    [(30, 3), (30, 12)],
    [(30, 3), (37, 3)],
    [(30, 8), (35, 8)],                              # F 三笔
]


def signed(v):
    return v & 0xFF


def reports_for(strokes):
    """展开成 [(buttons, dx, dy, dt)]：抬笔移动 + 落笔逐像素走线"""
    reps = []
    pos = (0, 0)
    t = 0.0
    for stroke in strokes:
        # 抬笔移动到笔画起点
        x, y = pos
        tx, ty = stroke[0]
        while x != tx or y != ty:
            dx = (tx > x) - (tx < x)
            dy = (ty > y) - (ty < y)
            reps.append((0, dx, dy, 0.01))
            x, y = x + dx, y + dy
        # 落笔沿折线走
        for (ax, ay), (bx, by) in zip(stroke, stroke[1:]):
            x, y = ax, ay
            while x != bx or y != by:
                dx = (bx > x) - (bx < x)
                dy = (by > y) - (by < y)
                reps.append((1, dx, dy, 0.01))
                x, y = x + dx, y + dy
        pos = stroke[-1]
    return reps


def usbmon_mmapped(uid, ts, typ, xfer, epnum, devnum, flag_data, payload,
                   status=0, length=None):
    ts_sec = int(ts)
    ts_usec = int(round((ts - ts_sec) * 1e6))
    length = len(payload) if length is None else length
    hdr = struct.pack("<qBBBBHccqiiII8siiiI",
                      uid, ord(typ), xfer, epnum, devnum, 1,
                      b"-", flag_data,
                      ts_sec, ts_usec, status, length, len(payload),
                      b"\x00" * 8, 0, 0, 0, 0)
    return hdr + payload


reps = reports_for(STROKES)
out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE)]
ts = float(BASE)
uid = 0
for buttons, dx, dy, dt in reps:
    ts += dt
    uid += 1
    out.append(struct.pack("<IIII", int(ts), int(round((ts - int(ts)) * 1e6)), 64, 64))
    out.append(usbmon_mmapped(uid, ts, "S", 1, 0x81, 2, b"-", b"", status=-115, length=3))
    ts += 0.001
    uid += 1
    report = bytes([buttons, signed(dx), signed(dy)])
    out.append(struct.pack("<IIII", int(ts), int(round((ts - int(ts)) * 1e6)), 67, 67))
    out.append(usbmon_mmapped(uid, ts, "C", 1, 0x81, 2, b"<", report))
open("usb_mouse.pcap", "wb").write(b"".join(out))
print(f"usb_mouse.pcap：{len(reps)} 个 report，每个一对 S/C 记录，共 {len(reps) * 2} 条")
```

输出：

```text
usb_mouse.pcap：114 个 report，每个一对 S/C 记录，共 228 条
```

解靶脚本：累加坐标、按下区间画线，PIL 出图（[[M01-MISC导论与工具箱#3.1 PIL：图像的打开与变形|M01 3.1]]），同时打一份 ASCII 预览便于在终端里直接读：

```python
# solve_usb_mouse.py —— 读 stdin 里 tshark 提取的 3 字节鼠标 report（hex），
# 还原绝对坐标轨迹：按住左键的位移画线，输出 PNG 与 ASCII 预览
import sys

from PIL import Image, ImageDraw

W, H, SCALE = 40, 16, 3
x = y = 0
prev = None
pressed_prev = False
img = Image.new("L", (W * SCALE, H * SCALE), 255)
draw = ImageDraw.Draw(img)
grid = Image.new("L", (W, H), 255)
gdraw = ImageDraw.Draw(grid)

for line in sys.stdin:
    hx = line.strip().replace(":", "")
    if len(hx) != 6:                 # 不是 3 字节 report：跳过
        continue
    b = bytes.fromhex(hx)
    buttons = b[0]
    dx = b[1] - 256 if b[1] > 127 else b[1]     # 位移是有符号 8 位数
    dy = b[2] - 256 if b[2] > 127 else b[2]
    x, y = x + dx, y + dy
    pressed = bool(buttons & 0x01)
    cur, gcur = (x * SCALE, y * SCALE), (x, y)
    if pressed and prev is not None:
        if pressed_prev:
            draw.line([prev, cur], fill=0, width=2)
            gdraw.line([gprev, gcur], fill=0, width=1)
        else:
            draw.point(cur, fill=0)              # 落笔的第一点
            gdraw.point(gcur, fill=0)
    prev, gprev = cur, gcur
    pressed_prev = pressed

img.save("mouse_path.png")
px = grid.load()
for row in range(H):
    print("".join("#" if px[col, row] < 128 else "." for col in range(W)))
print("mouse_path.png 已保存")
```

```bash
tshark -r usb_mouse.pcap -Y usb.capdata -T fields -e usb.capdata | head -3
tshark -r usb_mouse.pcap -Y usb.capdata -T fields -e usb.capdata | python3 solve_usb_mouse.py
```

输出：

```text
000101
000101
000101
........................................
........................................
........................................
...#######.....##########......#######..
...#...............#..........#.........
...#...............#..........#.........
...#...............#..........#.........
...#...............#..........#.........
...#...............#..........######....
...#...............#..........#.........
...#...............#..........#.........
...#...............#..........#.........
...########........#..........#.........
........................................
........................................
........................................
mouse_path.png 已保存
```

前三个 report `00 01 01` 是抬笔挪位（按键位 0、Δx=1、Δy=1），落笔后的轨迹在 ASCII 图里拼出 C、T、F 三个字母——mouse_path.png 是同一轨迹的 3 倍放大版。==这类题的解法固定三步：按键位筛轨迹、按式 (4.1) 累加坐标、PIL 画出来看==；画歪了先查符号处理。

## 5. 蓝牙流量

### 5.1 切入点

蓝牙 pcap 的链路类型是 HCI UART：主机与蓝牙适配器之间的通信记录。CTF 常见的两个切入点：

1. ==btatt（BLE 属性协议）==：BLE 设备之间的一切数据读写都走 ATT，帧里的 value 字段就是载荷。分片藏 flag、口令回传，多落在写请求与值通知里。
2. ==HID over GATT==：蓝牙键鼠的 report 也走 ATT 通知/写入，value 本身就是第 3 节那种 HID report，翻译逻辑直接复用。

识别入口照旧是协议统计：bluetooth → hci_h4 → bthci_acl → btl2cap → btatt 一层层套下来，ATT 的常用操作码：

| 操作码 | 名称 | 方向 | 载荷 |
| ---- | ---- | ---- | ---- |
| 0x52 | 写请求（Write Request） | 中心 → 外设 | 句柄 + 值 |
| 0x0B | 读响应（Read Response） | 外设 → 中心 | 值 |
| 0x1B | 值通知（Handle Value Notification） | 外设 → 中心 | 句柄 + 值 |
| 0x1D | 值指示（Handle Value Indication） | 外设 → 中心 | 句柄 + 值 |

### 5.2 造靶与解靶

HCI H4 with pseudo-header（链路类型 201）的每条 record 是三层嵌套：4 字节方向伪头（0 = 本机发出，1 = 收到）+ 1 字节 H4 包类型（0x02 = ACL 数据）+ ACL 头（连接句柄 12 位与包边界 PB 位拼成一个 16 位小端 + ACL 数据总长）+ L2CAP 头（载荷长度 + 通道 ID，0x0004 固定交给 ATT）+ ATT 载荷：

```python
# build_bt.py —— 手搓 HCI H4（带 4 字节伪头，linktype 201）pcap：BLE ATT 读写流量
import calendar
import struct

LINKTYPE = 201                      # Bluetooth HCI UART with pseudo-header
BASE = calendar.timegm((2026, 10, 24, 20, 0, 0))

HANDLE = 0x0041                     # ACL 连接句柄
PB_FIRST = 2                        # 包边界位：0b10 = L2CAP 完整 PDU 的第一包


def acl(direction, payload):
    """direction: 0 = 主机->控制器（本机发出），1 = 控制器->主机（收到）。
    HCI H4 包类型 0x02 = ACL 数据；ACL 头 = 句柄|PB<<12 + 总长。"""
    l2cap = struct.pack("<HH", len(payload), 0x0004) + payload   # CID 0x0004 = ATT
    acl = struct.pack("<HH", HANDLE | (PB_FIRST << 12), len(l2cap)) + l2cap
    return struct.pack("<I", direction) + b"\x02" + acl


def att_write_req(handle, value):
    """ATT 写请求：操作码 0x52 + 句柄(小端) + 值"""
    return b"\x52" + struct.pack("<H", handle) + value


def att_notify(handle, value):
    """ATT 值通知：操作码 0x1B + 句柄(小端) + 值"""
    return b"\x1b" + struct.pack("<H", handle) + value


records = []
ts = float(BASE)


def add(direction, payload):
    global ts
    records.append((ts, acl(direction, payload)))
    ts += 0.5


# 中心 -> 外设：向特征句柄 0x0010 写一条查询
add(0, att_write_req(0x0010, b"get flag"))
# 外设 -> 中心：把 flag 分片放进值通知
FLAG = b"flag{ble_att_n0tify}"
chunks = [FLAG[i:i + 6] for i in range(0, len(FLAG), 6)]
for c in chunks:
    add(1, att_notify(0x0010, c))

out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE)]
for t, data in records:
    out.append(struct.pack("<IIII", int(t), int(round((t - int(t)) * 1e6)),
                           len(data), len(data)))
    out.append(data)
open("bt_att.pcap", "wb").write(b"".join(out))
print(f"bt_att.pcap：{len(records)} 条记录，通知分片 {len(chunks)} 片")
```

输出：

```text
bt_att.pcap：5 条记录，通知分片 4 片
```

tshark 全层解析到位，字段直接取：

```bash
tshark -r bt_att.pcap -q -z io,phs | sed -n '6,11p'
tshark -r bt_att.pcap -Y btatt -T fields -e frame.number -e btatt.opcode -e btatt.handle -e btatt.value
```

输出：

```text
frame                                    frames:5 bytes:88
  bluetooth                              frames:5 bytes:88
    hci_h4                              frames:5 bytes:88
      bthci_acl                         frames:5 bytes:88
        btl2cap                         frames:5 bytes:88
          btatt                         frames:5 bytes:88
1	0x52	0x0010	67657420666c6167
2	0x1b	0x0010	666c61677b62
3	0x1b	0x0010	6c655f617474
4	0x1b	0x0010	5f6e30746966
5	0x1b	0x0010	797d
```

第 1 帧操作码 0x52 是写请求，value 解出 ASCII "get flag"；2–5 帧操作码 0x1B 是通知，四个 value 按帧序拼起来就是 flag：

```python
# solve_bt.py —— 读 stdin 里 tshark 提取的 btatt.value（hex），按序拼接解码
import sys

out = b""
for line in sys.stdin:
    hx = line.strip().replace(":", "")
    if hx:
        out += bytes.fromhex(hx)
print(out.decode())
```

```bash
tshark -r bt_att.pcap -Y 'btatt.opcode==0x1b' -T fields -e btatt.value | python3 solve_bt.py
```

输出：

```text
flag{ble_att_n0tify}
```

> [!note] HID over GATT 变体与真实抓包
> 真实的蓝牙键鼠抓包里，ATT 通知的 value 就是 HID report——按第 3 节的键码表翻译即可，识别线索是 GATT 服务声明里的 0x1812（HID 服务）。真题还常见 HCI ACL 之外的控制层（HCI 命令与事件），`-z io,phs` 里哪层占比大先看哪层。抓真机的蓝牙流量需要 hcidump 或 Wireshark 配 Android btsnoop 文件，赛题通常直接给 pcap。

## 6. WiFi WPA 握手与爆破

### 6.1 四次握手的帧角色

WPA2-PSK 的口令从不出现在流量里，但四次握手帧携带着足以==离线验证任意候选口令==的材料：两个 Nonce 加一条带 MIC 的 EAPOL 帧。帧角色表：

| 帧 | 方向 | Key Nonce | Key MIC | 要点 |
| ---- | ---- | ---- | ---- | ---- |
| M1 | AP → STA | ANonce | 无 | AP 下发 ANonce |
| M2 | STA → AP | SNonce | 有 | STA 交出 SNonce，MIC 供 AP 验证 |
| M3 | AP → STA | ANonce | 有 | 装配完成；Key Data 加密携带组密钥 GTK |
| M4 | STA → AP | 全零 | 有 | 收尾确认 |

Nonce 只出现在 M1/M2（M4 重置为全零），MIC 从 M2 开始出现。==破解方需要的最少材料是 M1 加 M2==：两个 Nonce 齐、MIC 有，缺 M3/M4 不影响验证——口令验证只用 Nonce 与 MIC，M3 加密的 Key Data 与 M4 的确认都不参与。

### 6.2 密钥派生链

口令与 SSID 先派生出成对主密钥 PMK，PMK 展开成成对传输密钥 PTK，再从 PTK 切出 MIC 密钥，三步：

$$\text{PMK} = \text{PBKDF2-HMAC-SHA1}(\text{口令},\ \text{SSID},\ 4096,\ 32\ \text{字节}) \tag{6.1}$$

$$\text{PTK} = \text{PRF512}(\text{PMK},\ \text{"Pairwise key expansion"},\ D) \tag{6.2}$$

$$\text{MIC} = \text{HMAC-SHA1}(\text{KCK},\ \text{MIC 置零的完整 EAPOL 帧})[:16] \tag{6.3}$$

式 (6.2) 的 $D$ 由四个值按字典序小的在前依次拼接：AP 与 STA 的 MAC 地址（$\text{AA}$、$\text{SPA}$）、ANonce 与 SNonce（各 32 字节）；PRF512 是 802.11i 定义的密钥展开函数，HMAC-SHA1 带单字节计数器迭代，输出 64 字节。PTK 的前 16 字节是 KCK（MIC 密钥），接着 16 字节是 KEK（M3 加密 Key Data 用的密钥）。式 (6.3) 的哈希选择跟随 Key Descriptor Version：1 用 HMAC-MD5，2 用 HMAC-SHA1（WPA2-CCMP 的默认值），3 用 AES-128-CMAC。

==字典爆破就是这三步的循环==：每个候选口令按式 (6.1)(6.2) 算出 KCK，对 M2 重算式 (6.3)，与帧里的 MIC 一致即口令正确。aircrack-ng 把整个循环包好了。

### 6.3 造靶：scapy 手搓四次握手

```python
# build_wpa.py —— scapy 手搓 WPA2-PSK 四次握手 pcap：口令可被 aircrack-ng 字典验证
import calendar
import hashlib
import hmac
import struct

from Crypto.Cipher import AES
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, LLC, RadioTap, SNAP, wrpcap

SSID = b"CTF-Net"
PASS = "flag{wpa_4way_psk}"          # WPA 口令：8~63 字符
AP_MAC = "52:54:00:aa:bb:cc"
STA_MAC = "52:54:00:11:22:33"

# ---------- 密钥派生链 ----------
pmk = hashlib.pbkdf2_hmac("sha1", PASS.encode(), SSID, 4096, 32)


def prf512(key, label, data):
    """802.11i 的 PRF-512：HMAC-SHA1 按计数器迭代拼接，取 64 字节"""
    out = b""
    for i in range(4):
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
    return out[:64]


def order(a, b):
    return (a, b) if a < b else (b, a)


aa = bytes.fromhex(AP_MAC.replace(":", ""))
spa = bytes.fromhex(STA_MAC.replace(":", ""))
anonce = hashlib.sha256(b"anonce-2026").digest()
snonce = hashlib.sha256(b"snonce-2026").digest()
lo_a, hi_a = order(aa, spa)
lo_n, hi_n = order(anonce, snonce)
ptk = prf512(pmk, b"Pairwise key expansion", lo_a + hi_a + lo_n + hi_n)
kck, kek = ptk[:16], ptk[16:32]      # 前两个 16 字节：MIC 密钥与 EAPOL 密钥加密密钥

# ---------- EAPOL-Key 帧体 ----------
def key_body(keyinfo, replay, nonce, mic=b"\x00" * 16, keydata=b""):
    return (struct.pack(">B", 2)              # Descriptor Type：2 = RSN (802.11i)
            + struct.pack(">H", keyinfo)      # Key Information：大端位域（与 EAPOL 各字段一致）
            + struct.pack(">H", 16)           # Key Length：CCMP-128
            + struct.pack(">Q", replay)       # Replay Counter
            + nonce.ljust(32, b"\x00")        # Key Nonce
            + b"\x00" * 16                    # Key IV
            + b"\x00" * 8                     # Key RSC
            + b"\x00" * 8                     # 保留
            + mic                             # Key MIC
            + struct.pack(">H", len(keydata))
            + keydata)


def eapol(body):
    """EAPOL 头：版本 2 + 类型 3 (EAPOL-Key) + 体长（大端）"""
    return struct.pack(">BBH", 2, 3, len(body)) + body


def mic_of(body):
    """Key Descriptor Version 2 的 MIC = HMAC-SHA1(KCK, MIC 置零的整个 EAPOL 帧) 前 16 字节"""
    return hmac.new(kck, eapol(body), hashlib.sha1).digest()[:16]


# ---------- M3 的 GTK：KDE 封装 + RFC 3394 AES Key Wrap ----------
def aes_key_wrap(kek, plain):
    data = plain + b"\x00" * (-len(plain) % 8)
    n = len(data) // 8
    a = 0xA6A6A6A6A6A6A6A6
    r = [data[i * 8:(i + 1) * 8] for i in range(n)]
    for j in range(6):
        for i in range(n):
            blk = AES.new(kek, AES.MODE_ECB).encrypt(struct.pack(">Q", a) + r[i])
            a = struct.unpack(">Q", blk[:8])[0] ^ (n * j + i + 1)
            r[i] = blk[8:]
    return struct.pack(">Q", a) + b"".join(r)


gtk = hashlib.sha256(b"gtk-2026").digest()[:16]
kde = b"\xdd" + bytes([3 + 1 + 1 + 16]) + b"\x00\x0f\xac\x01" + b"\x00" + gtk
m3_keydata = aes_key_wrap(kek, kde)

# ---------- 四个消息体 ----------
m1_body = key_body(0x008A, 1, anonce)                                  # ANonce，无 MIC
m2_body = key_body(0x010A, 1, snonce, mic=mic_of(key_body(0x010A, 1, snonce)))
m3_body = key_body(0x13CA, 2, anonce,
                   mic=mic_of(key_body(0x13CA, 2, anonce, keydata=m3_keydata)),
                   keydata=m3_keydata)
m4_body = key_body(0x030A, 2, b"\x00" * 32, mic=mic_of(key_body(0x030A, 2, b"\x00" * 32)))

# ---------- 802.11 帧封装 ----------
def data_frame(from_ap, seq, eapol_bytes):
    if from_ap:   # AP -> STA：FromDS，addr1 收方 STA，addr2 发方 AP
        dot11 = Dot11(type=2, subtype=0, FCfield=2, addr1=STA_MAC, addr2=AP_MAC,
                      addr3=AP_MAC, SC=(seq << 4))
    else:         # STA -> AP：ToDS
        dot11 = Dot11(type=2, subtype=0, FCfield=1, addr1=AP_MAC, addr2=STA_MAC,
                      addr3=AP_MAC, SC=(seq << 4))
    return (RadioTap() / dot11 / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
            / SNAP(OUI=0, code=0x888E) / eapol_bytes)


# Beacon：aircrack 从这里读 SSID；RSN IE 声明 CCMP + PSK
rsn = (struct.pack("<H", 1) + b"\x00\x0f\xac\x04"          # 版本 + 组加密套件 CCMP-128
       + struct.pack("<H", 1) + b"\x00\x0f\xac\x04"        # 成对套件数 + CCMP-128
       + struct.pack("<H", 1) + b"\x00\x0f\xac\x02"        # AKM 数 + PSK
       + struct.pack("<H", 0))                             # RSN 能力位
beacon = (RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                             addr2=AP_MAC, addr3=AP_MAC, SC=(0 << 4))
          / Dot11Beacon(cap="ESS+short-preamble")
          / Dot11Elt(ID=0, info=SSID)
          / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
          / Dot11Elt(ID=48, info=rsn))

pkts = [beacon,
        data_frame(True, 1, eapol(m1_body)),               # M1: AP -> STA
        data_frame(False, 2, eapol(m2_body)),              # M2: STA -> AP
        data_frame(True, 3, eapol(m3_body)),               # M3: AP -> STA
        data_frame(False, 4, eapol(m4_body))]              # M4: STA -> AP

BASE = calendar.timegm((2026, 10, 24, 21, 0, 0))
for i, p in enumerate(pkts):
    p.time = BASE + i * 0.1
wrpcap("wpa.pcap", pkts)
print(f"wpa.pcap：1 个 Beacon + M1~M4 共 {len(pkts)} 帧")
print(f"PMK 前 8 字节 {pmk[:8].hex()}  KCK 前 8 字节 {kck[:8].hex()}  M2 MIC {m2_body[-18:-2].hex()[:16]}..")
```

输出：

```text
wpa.pcap：1 个 Beacon + M1~M4 共 5 帧
PMK 前 8 字节 6ab56e50ac596632  KCK 前 8 字节 303a8f0e2185f7fa  M2 MIC 3644c4ffcb3e9912..
```

Key Information 的四个值各是一组位标志：0x008A = M1（版本 2 + 成对密钥 + ACK），0x010A = M2（再 + MIC 位），0x13CA = M3（再 + 安装位 + Secure 位 + Key Data 加密位），0x030A = M4（MIC + Secure）。tshark 逐位核对 M1：

```bash
tshark -r wpa.pcap -Y 'frame.number==2' -V | grep -E "Key Descriptor Type|Key Information|Key Descriptor Version|Key Type|Key ACK|Key MIC|Replay Counter|Key Nonce|Key MIC:"
```

输出：

```text
    Key Descriptor Type: EAPOL RSN Key (2)
    Key Information: 0x008a
        .... .... .... .010 = Key Descriptor Version: AES Cipher, HMAC-SHA1 MIC (2)
        .... .... .... 1... = Key Type: Pairwise Key
        .... .... 1... .... = Key ACK: Set
        .... ...0 .... .... = Key MIC: Not set
    Replay Counter: 1
    WPA Key Nonce: 29654c51098f540f043ee42d4d596e4a3e0a8e2388709b57fdc550dd111a3b2f
    WPA Key MIC: 00000000000000000000000000000000
```

> [!warning] EAPOL 的所有字段都是大端，Key Information 也不例外
> EAPOL 继承 802.1X 的网络字节序约定，整个 EAPOL-Key 帧体没有一个小端字段。Key Information 若按小端打包（比如把 0x008A 写成 `8a 00`），tshark 的 Key Information 会显示成 0x8a00 这类错位值，位分解全部不对，==aircrack-ng 与 wpapcap2john 则直接判定"包里没有 EAPOL 数据"==。自己造握手包遇到工具不认，先拿 tshark -V 对照上面 M1 的位分解逐字段查。

> [!info]- M3 的 Key Data：GTK KDE 与 AES Key Wrap
> M3 的 Key Data 加密携带组密钥 GTK：先封装成 KDE（Key Data Encapsulation）——类型 0xDD + 长度 + OUI `00:0F:AC` + 数据类型 1（GTK）+ 1 字节标志 + 16 字节 GTK；再用 KEK 做 RFC 3394 的 AES Key Wrap（输出长度对齐到 8 字节倍数，脚本里 `aes_key_wrap` 是它的完整实现，默认初始值 A6A6A6A6A6A6A6A6、6 轮 × n 块的包裹循环）。tshark 配合密钥能解出 GTK，但破解口令用不到它——aircrack 只验 M2/M4 的 MIC。

### 6.4 解靶：aircrack-ng 字典爆破

```bash
printf 'password123\nletmein\n12345678\nctfpassword\nflag{wrong_guess}\nflag{wpa_4way_psk}\n1234567890\n' > dict.txt
aircrack-ng -w dict.txt -b 52:54:00:aa:bb:cc wpa.pcap
```

输出：

```text
Reading packets, please wait...
Opening wpa.pcap
Read 5 packets.
1 potential targets
[00:00:00] 7/7 keys tested (580.96 k/s) Time left: --
Current passphrase: flag{wpa_4way_psk}
Master Key     : 6A B5 6E 50 AC 59 66 32 23 BB 09 0A 9D E2 B9 81
                 EF A2 FF 91 30 3B 0B 00 4A 64 52 D4 64 07 44 D8
EAPOL HMAC     : 36 44 C4 FF CB 3E 99 12 5F F7 F1 C7 73 E2 42 56
KEY FOUND! [ flag{wpa_4way_psk} ]
```

先不带 `-w` 跑一次，确认"1 potential targets"能认出 AP 与握手，再上字典；`-b` 指定 BSSID 过滤噪声，多个网络时必加。EAPOL HMAC 与造靶脚本打印的 M2 MIC 一致——==这一行就是"口令对应的 PTK 算出的 MIC 与帧内一致"的判定结果==。

> [!note] 另两条等价路线
> `wpapcap2john wpa.pcap > wpa.john` 把握手转成 john 格式，`john --wordlist=dict.txt wpa.john` 跑字典（john 套件里随附，位置在 /usr/sbin/）；Windows 侧 hashcat 用 `-m 22000` 配 GPU 跑大字典更快，格式也是同一个提取步骤。真实赛题的握手包常缺 M3/M4、带重传与多个网络，aircrack 照常处理；口令长度超出 8–63 字符的候选会被跳过，这是 WPA 规范约束。

## 7. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 配了 keylog，TLS 还是密文 | 路径写错、keylog 与 pcap 不同源、或数据包顺序"先密文后握手"（2.2 警告框）。用 `-o tls.keylog_file:` 指向文件本身，先确认 `-Y http` 在别的流上能筛出东西 |
| `-Y http` 筛不出 HTTPS 的请求 | 解密之前 http 层不存在，先配 keylog 再筛；解开后手法与 [[M10-流量取证I-协议还原深挖#5. HTTP 对象批量导出\|M10 5 节]]一致 |
| 响应解开了、请求仍是密文 | tshark 顺序解析，请求记录排在 ServerHello 之前时没有密钥可用。造靶按 2.2 警告框的时序重排 |
| usb.capdata 提出来长度错乱 | 链路类型或 usbmon 头长不对。本库用法是链路类型 220 配 64 字节 mmapped 头；用 `tshark -V` 看首帧的 URB 头字段是否对得上 3.2 的折叠框 |
| 键盘翻译出乱字符 | 没去重（按住重复上报）或 Shift 位没处理。放键的全零 report 不产生字符；Shift 掩码 0x22 同时覆盖左右两侧 |
| 鼠标轨迹画歪 | Δx/Δy 是有符号 8 位数，大于 127 要减 256；报告多于 3 字节时，第 4 字节起是滚轮等字段，别当位移累加 |
| `btatt` 筛不出任何包 | L2CAP 的 CID 不是 0x0004，或 ACL 头的 PB 位写错。先 `-z io,phs` 看 btl2cap 层是否存在，再对照 5.2 的三层嵌套逐字节查 |
| aircrack 报 no EAPOL data | EAPOL-Key 字段字节序或 Key Information 位域错，或帧的 ToDS/FromDS 与三个地址安排不对。拿 tshark -V 对照 6.3 的 M1 输出逐字段查 |
| aircrack 认出握手但字典跑完不中 | 口令不在字典里、长度超出 8–63、或 SSID 不对。PMK 依赖 SSID，SSID 错一个字符，派生出的密钥就完全不同；缺 Beacon 的包用 `-e SSID` 手工指定 |

## 8. 配套练习与延伸阅读

配套练习：

1. 把 2.2 的造靶改出 TLS 1.2 与 1.3 之外的第三条流：同一个服务器证书、客户端端口 40003，应用数据换成一条 POST，keylog 里数一数新会话写了几行——对照 2.1 的表解释。
2. 按 3.2 的方法造一个"敲了又删"的键盘靶：正文里夹几个字符再按 Backspace（0x2A），解靶脚本要额外处理 0x2A 把已拼出的最后一个字符删掉。
3. 把 4.2 的轨迹换成两个小写字母加一条下划线（符号在鼠标轨迹里怎么写？先想再画），只交 pcap 给同学还原。
4. 给 bt_att.pcap 加噪声：若干条操作码 0x03（读组类型请求）与一条对其他句柄的通知，solve_bt.py 需要先按句柄过滤再拼接。
5. 把 build_wpa.py 的 PASS 换成随机 12 位口令，字典里只放对的一行，跑 aircrack 确认仍能命中；再删掉 M3/M4 只留 M1+M2 重造一张 pcap，确认 aircrack 照常出 KEY FOUND——对应 6.1 的"最少材料"结论。

练习场：

- [[01-练习平台索引|练习平台索引]]：MISC 分区按套路分类，USB 与加密流量的靶对照本章各节逐个练
- [[03-工具清单|工具清单]]：tshark、aircrack-ng、john 的安装方式与同类替代

延伸阅读：

- RFC 8446（TLS 1.3）：记录层与密钥层次（handshake/application traffic secret 的出处）
- Wireshark Wiki 的 TLS Decryption 页面：SSLKEYLOGFILE 行格式的权威描述与 Wireshark 配置
- USB HID Usage Tables（USB-IF）：键盘键码与修饰键位定义的规范原文
- USBPcap 项目：Windows 下抓 USB 总线流量的驱动，真实键鼠 pcap 的常见来源
- Bluetooth Core Spec 的 ATT 章节：操作码与句柄语义；Android btsnoop 文件是蓝牙 pcap 的常见来源
- IEEE 802.11i / RFC 3394：四次握手与 AES Key Wrap 的规范依据
- 下一站：[[M12-内存取证I-Volatility基础|M12]]——离开流量包，进入内存镜像这第二取证现场；keylog 那类"只存在于进程内存里的密钥"，正是内存取证要回答的问题。
