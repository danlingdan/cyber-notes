---
chapter: PWN
section: Linux 安全缓解机制
order: 304
tags:
  - CTF
  - PWN
  - 安全缓解
publish: true
---

# P4 Linux 安全缓解机制
## Linux Security Mitigations

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[P01-PWN导论与缓解机制全景|P1]] · [[P02-前置基础C汇编与Linux|P2]] · [[R04-可执行文件格式ELF与PE|R04]]
> **本章目标**：把 P1 全景表里的每个机制按"原理 → 二进制里的证据 → 防住什么 → 没防住什么 → 绕过方向"讲透；学会逐行读 checksec 的输出，并从一份保护清单直接列出可行的攻击方向。

## 1. 缓解机制拦的是利用链的哪一环

[[P01-PWN导论与缓解机制全景#2. 利用链构建的五步流程|P1 第 2 节]]的五步流程里，第一步"查保护"决定第四步"构造利用链"的选型。本章把 [[P01-PWN导论与缓解机制全景#3. 现代缓解机制全景|P1 第 3 节]]的全景表逐项拆开讲，每个机制按固定的五段展开：

1. **原理**：它在系统或编译层面做了什么；
2. **二进制里长什么样**：用 readelf / objdump / file 在文件里指出它的痕迹；
3. **防住什么**：堵死了哪条利用路线；
4. **没防住什么**：漏洞本身，以及它管不到的地方；
5. **绕过方向**：后续各章的入口。

先立一个总判断：==缓解机制不修复漏洞==。本章演示程序的溢出在任何保护组合下都照样发生，数据照样写过缓冲区边界。保护提高的是"从漏洞到 getshell"这一段的成本：溢出能发生，但覆盖出来的东西能不能用、指向哪、跳过去之后跑什么，被逐层设卡。按利用链的环节对应：

| 利用链环节 | 拦它的机制 | 一句话 |
| ---- | ---- | ---- |
| 把机器码写进数据区再跳过去执行 | NX / DEP | 数据页没有执行权限 |
| 溢出覆盖返回地址 | Stack Canary | 返回前核对哨兵值，不对就终止 |
| payload 写死程序内地址 | PIE | 程序本体装载基址随机 |
| payload 写死 libc / 栈地址 | ASLR | 库、栈、堆基址随机 |
| 改写 GOT 把函数调用引走 | RELRO | 重定位区域提前只读 |

本章演示程序只有一个 `vuln.c`，后面所有输出都出自它的不同编译产物：

```c
/* vuln.c —— 本章演示程序（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("[win] reached");
}

void vuln(void) {
    char buf[64];
    ssize_t n = read(0, buf, 256);   /* 漏洞点：256 字节写进 64 字节的 buf */
    (void)n;
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    puts("bye");
    return 0;
}
```

`read(0, buf, 256)` 从标准输入最多读 256 字节进 64 字节的 `buf`——漏洞形态与 P1 的 `gets` 相同：==长度不受控的写入==，只是这次的边界问题工具链在编译期就能看出来：

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector vuln.c -o vuln
```

输出：

```
vuln.c: In function 'vuln':
vuln.c:11:17: warning: 'read' writing 256 bytes into a region of size 64 overflows the destination [-Wstringop-overflow=]
   11 |     ssize_t n = read(0, buf, 256);   /* 漏洞点：256 字节写进 64 字节的 buf */
      |                 ^~~~~~~~~~~~~~~~~
vuln.c:10:10: note: destination object 'buf' of size 64
```

警告点得很直白：往 64 字节的目标里写 256 字节。==警告不是错误，二进制照常生成，漏洞照常存在==——与 P1 的 `gets` 警告同一个性质。为了后续输出干净，本章其余编译命令都带 `-w`，把这条警告压掉。

这条编译命令本身也值得看：`-fno-pie -no-pie` 关 PIE、`-fno-stack-protector` 关 Canary，==P1 的 ret2win 就是在这两个保护被关掉的环境里做的==（那组参数 [[P01-PWN导论与缓解机制全景#5.1 漏洞程序与编译|P1 5.1]] 的折叠框列过）。真实赛题不会替你关保护，所以本章的路线是：先逐个讲机制，最后把一个程序从"全关"编到"全开"，看 checksec 怎么变、利用方向怎么跟着变。机制与编译开关的对应表 [[02-C语言与内存模型#2.2 PWN 学习必会的编译选项|02 章 2.2]] 列过，这里不重复，讲的是每条开关背后的原理。

## 2. NX / DEP：数据页不可执行

**原理。** 分页机制里每个页都有一个"不可执行"位（AMD 文档叫 NX，Intel 叫 XD）。内核装载程序时按程序头表里的 `GNU_STACK` 段决定栈页的权限：这一段没有 E（execute）标志，栈就被映射成"可读写、不可执行"。CPU 在取指阶段检查这个位，==从不可执行的页取指令，直接触发页错误，进程收到 SIGSEGV==。数据（栈、堆、.data）与指令（.text）从此按页隔离，写入与执行互斥（这套思路常被称作 W^X，Write XOR Execute）。名字对齐：AMD 叫 NX、Intel 叫 XD、Windows 术语叫 DEP（数据执行保护），Linux 内核的实现是同一件事。

**二进制里长什么样。** 编译两个产物对比——默认一个、加 `-z execstack`（把栈声明为可执行栈）一个，然后看程序头表：

```bash
gcc -w -O0 -fno-pie -no-pie -fno-stack-protector vuln.c -o nx_on
gcc -w -O0 -fno-pie -no-pie -fno-stack-protector -z execstack vuln.c -o nx_off
readelf -l nx_on  | grep -A1 GNU_STACK
readelf -l nx_off | grep -A1 GNU_STACK
```

输出：

```
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RWE    0x10
```

默认编译是 `RW`——可读写、不可执行；`-z execstack` 重新链接后变成 `RWE`，栈恢复可执行。checksec 报的 `NX enabled` / 栈可执行，读的就是这一个标志（checksec 不是黑盒，它读的就是 [[R04-可执行文件格式ELF与PE#1.1 链接视图与执行视图：两套目录|R04 第 1 节]]的程序头表，P1 第 3 节的折叠框点过）。运行期的样子 [[R02-C语言与内存模型#2. 内存四区：先对完地址再谈别的|R02 第 2 节]]那张映射表里也有：`[stack]` 一行的权限是 `rw-p`，正是 NX 开着的形态。

**防住什么。** 注入式利用：把机器码（shellcode）写进栈上的缓冲区，把返回地址盖成 buf 的地址，`ret` 一跳就开始执行注入的代码。NX 开着时，==跳过去的第一条指令就取指失败==，进程当场 SIGSEGV。

**没防住什么。** ==NX 只拦"执行数据"，不拦"改写数据"==。溢出写坏返回地址照样成功，程序照样跳去一个合法的、程序里本来就有的代码地址；`.text` 里的代码不受任何影响。

**经典绕过方向。** 既然带不进代码，就用程序自带的代码——==代码重用==：把程序里现成的指令片段（gadget）用 `ret` 串成链，让"执行你的意图"这件事完全用已有代码拼出来。这是 ROP 与 ret2libc 的出发点，[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]、[[P08-ROP进阶与SROP|P8]] 展开；`-z execstack` 这种人为关掉 NX 的环境里 shellcode 怎么写、怎么跳，也在 P7。

> [!info]- NX 的三个边角
> - 没有程序头的极老二进制——按 ELF 规范，没有 `GNU_STACK` 段时内核按老规矩把栈映射成可执行。现代工具链总会生成这一段，赛题里见不到。
> - `-z execstack` 打开后，内核还会给进程设置 READ_IMPLIES_EXEC 标记：==所有可读页都变成可执行==，堆和 .data 也能跑代码——比"只开栈"走得更远。
> - 32 位 x86 早期没有 NX 位（要 PAE 页表才支持），当时的"不可执行"靠段限长近似；x86-64 长模式的页表天生带 NX 位，没有历史包袱。入门题都在 64 位下，知道即可。

## 3. Stack Canary：栈上的哨兵值

**原理。** 编译器在"局部变量"与"保存的 rbp + 返回地址"之间插入一个随机值（canary，金丝雀——名字借自矿工带下井、用来预警毒气的金丝雀）。函数入口把这个值放进栈上，返回前核对：==对不上，说明溢出发生过，函数在 `ret` 之前主动终止进程==。值不写在代码里——它存在线程局部存储（TLS）的固定槽位 `fs:0x28`，==进程启动时由 libc 从内核给的随机字节生成，每个进程一个值，进程活着就不变==。

**二进制里长什么样。** 同一个 `vuln` 函数，关与开 Canary 各编一份，反汇编对比（x86-64 Linux / System V AMD64 ABI，objdump -d -M intel）：

```bash
gcc -w -O0 -fno-pie -no-pie -fno-stack-protector vuln.c -o v_nocanary
gcc -w -O0 -fno-pie -no-pie vuln.c -o v_canary
```

`-fno-stack-protector` 关掉 Canary 的版本，`vuln` 全程只有业务逻辑（`sed` 取出 `<vuln>` 函数那一段）：

```bash
objdump -d -M intel v_nocanary | sed -n '/<vuln>:/,/^$/p'
```

输出：

```asm
000000000040118b <vuln>:
  40118b:	f3 0f 1e fa          	endbr64
  40118f:	55                   	push   rbp
  401190:	48 89 e5             	mov    rbp,rsp
  401193:	48 83 ec 50          	sub    rsp,0x50
  401197:	48 8d 45 b0          	lea    rax,[rbp-0x50]
  40119b:	ba 00 01 00 00       	mov    edx,0x100
  4011a0:	48 89 c6             	mov    rsi,rax
  4011a3:	bf 00 00 00 00       	mov    edi,0x0
  4011a8:	e8 d3 fe ff ff       	call   401080 <read@plt>
  4011ad:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4011b1:	90                   	nop
  4011b2:	c9                   	leave
  4011b3:	c3                   	ret
```

Ubuntu 的 gcc 默认带 `-fstack-protector-strong`，所以"什么都不加"的版本就有 Canary：

```bash
objdump -d -M intel v_canary | sed -n '/<vuln>:/,/^$/p'
```

输出：

```asm
00000000004011ab <vuln>:
  4011ab:	f3 0f 1e fa          	endbr64
  4011af:	55                   	push   rbp
  4011b0:	48 89 e5             	mov    rbp,rsp
  4011b3:	48 83 ec 60          	sub    rsp,0x60
  4011b7:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  4011be:	00 00 
  4011c0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4011c4:	31 c0                	xor    eax,eax
  4011c6:	48 8d 45 b0          	lea    rax,[rbp-0x50]
  4011ca:	ba 00 01 00 00       	mov    edx,0x100
  4011cf:	48 89 c6             	mov    rsi,rax
  4011d2:	bf 00 00 00 00       	mov    edi,0x0
  4011d7:	e8 c4 fe ff ff       	call   4010a0 <read@plt>
  4011dc:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  4011e0:	90                   	nop
  4011e1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4011e5:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
  4011ec:	00 00 
  4011ee:	74 05                	je     4011f5 <vuln+0x4a>
  4011f0:	e8 8b fe ff ff       	call   401080 <__stack_chk_fail@plt>
  4011f5:	c9                   	leave
  4011f6:	c3                   	ret
```

两份对比，差异三处：

- **序言**多两条（4011b7–4011c0）：从 `fs:0x28` 取出哨兵，存进 `[rbp-0x8]`——==哨兵插在局部变量与保存的 rbp 之间==；
- **尾声**多四条（4011e1–4011f0）：把 `[rbp-0x8]` 取回，与 `fs:0x28` 的原件相减，`je` 相等才放行去 `leave; ret`，不相等 `call __stack_chk_fail` 终止进程；
- **帧布局**整体变了：Canary 占走 `[rbp-0x8]`，原来放返回值 n 的位置被挤到 `[rbp-0x58]`，帧从 `0x50` 涨到 `0x60`。

溢出覆盖的方向是从 buf 向高地址走（[[02-C语言与内存模型#5.3 栈向低地址增长|02 章 5.3]]），==想够到 rbp+0x8 的返回地址，必先碾过 `[rbp-0x8]` 的哨兵==——这正是它选这个位置的原因。

符号表里还有一处固定痕迹——开 Canary 的二进制必然引用 `__stack_chk_fail`，checksec 判 "Canary found" 看的就是它：

```bash
nm v_canary | grep stack_chk
```

输出：

```
                 U __stack_chk_fail@GLIBC_2.4
```

哨兵长什么样、它在哪两个位置，用 gdb 一次看清。命令写进 `gdb_canary.cmds`（`nexti 2` 从断点处往下走两条指令，跳过序言的装载与入栈）：

```
# gdb_canary.cmds —— 跑法：gdb -q -batch -x gdb_canary.cmds ./v_canary
set pagination off
set disassembly-flavor intel
break vuln
run < payload256.bin
nexti 2
printf "stack [rbp-0x8]    = "
x/1gx $rbp-0x8
printf "tls   fs:0x28      = "
x/1gx $fs_base+0x28
continue
```

输出（节选）：

```
Breakpoint 1, vuln () at vuln.c:9
9	void vuln(void) {
0x00000000004011c4	9	void vuln(void) {
stack [rbp-0x8]    = 0x7fffffffe158:	0x4660ffded33bd400
tls   fs:0x28      = 0x7ffff7fab768:	0x4660ffded33bd400
*** stack smashing detected ***: terminated

Program received signal SIGABRT, Aborted.
```

栈上的 `[rbp-0x8]` 与 TLS 的 `fs:0x28` 是同一个值 `0x4660ffded33bd400`——==序言只是复制，尾声比对的正是这两处==。`continue` 之后，256 字节输入把栈上那份碾掉了，尾声检查失败，进程死于 SIGABRT。

**触发现场。** 同一份 256 字节输入（`python3 -c "print('A'*256)" > payload256.bin`），两种编译两种结局：

```bash
./v_nocanary < payload256.bin || echo "exit=$?"
./v_canary   < payload256.bin || echo "exit=$?"
```

输出：

```
Segmentation fault
exit=139
*** stack smashing detected ***: terminated
Aborted
exit=134
```

==溢出在两个进程里都完整发生了==，差别只在结局：无 Canary 的版本返回地址被 8 个 `A` 顶掉，`ret` 跳进 0x4141414141414141，死于 SIGSEGV（exit 139）；有 Canary 的版本在尾声被拦下，进程被 `abort`，死于 SIGABRT（exit 134）。==退出码与死法本身就是判据==：SIGSEGV 说明覆盖成功、跳去了坏地址；SIGABRT 加这句报错说明 Canary 拦住了你。

**Canary 的三条特性。** 下面这个程序直接读出 `fs:0x28` 的值，父进程打印一次，fork 出的子进程再打印一次：

```c
/* canary_fork.c —— 读出并打印自己的 canary（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

static unsigned long read_canary(void) {
    unsigned long v;
    __asm__ volatile("mov %%fs:0x28, %0" : "=r"(v));
    return v;
}

int main(void) {
    setbuf(stdout, NULL);   /* 不缓冲，避免 fork 把未刷出的缓冲区复制出重复行 */
    printf("parent canary = %#018lx\n", read_canary());
    pid_t pid = fork();
    if (pid == 0) {
        printf("child  canary = %#018lx\n", read_canary());
        return 0;
    }
    wait(NULL);
    return 0;
}
```

```bash
gcc -w -O0 canary_fork.c -o canary_fork
./canary_fork
./canary_fork
```

输出：

```
parent canary = 0x4c9c995f96562900
child  canary = 0x4c9c995f96562900
parent canary = 0xdf1832eaae239a00
child  canary = 0xdf1832eaae239a00
```

三条特性都在这四行里：

| 特性 | 输出里的证据 | 含义 |
| ---- | ---- | ---- |
| 最低字节恒为 0x00 | 四个值都以 `00` 结尾 | 这是故意设计的，见下方说明 |
| 每进程一个值 | 两次运行两组不同的值 | 生成于进程启动时，之后不变 |
| fork 后不变 | 同一次运行 parent 与 child 相同 | fork 复制整个地址空间，TLS 原样带过去 |

低字节 0x00 的设计意图：`strcpy`、`gets` 这类按 `\0` 截断的拷贝函数，==碰到哨兵就停了==，纯字符串形式的溢出恰好写不坏哨兵之后的数据。对利用者它还有另一面：泄露 Canary 时这个 0 会把输出截断，取值要绕开它（[[P09-格式化字符串漏洞|P9]] 会处理）。第三条特性直接连到一类绕过：==fork 型网络服务（每个连接 fork 一个子进程处理）的 Canary 每个连接都一样==，逐字节爆破因此可行——这是 [[P11-Canary绕过与GOT攻击|P11]] 的第一课，这里留个记号。

**防住什么。** ==用溢出数据整个顶掉返回地址==这一条路：覆盖从 buf 一路向高地址推进，必然碾过 `[rbp-0x8]`，尾声检查必炸。

**没防住什么。** 三类：

- **泄露**：把哨兵读出来，构造 payload 时在原位置填回原值，尾声检查照常通过（P9 的格式化字符串是标准读法）；
- **栈外的写**：GOT、函数指针、其他全局数据都不在哨兵的管辖区内，往那里写不会被拦（P11）；
- **fork 爆破**：上面第三条特性。

**经典绕过方向。** ==泄露后原样回填 / fork 逐字节爆破 / 不碰栈、改写别的控制目标==，三条路分别在 P9 与 P11 展开。

> [!warning] 报 stack smashing detected 就是 Canary 拦的
> 溢出后程序报 `*** stack smashing detected ***: terminated` 并以 SIGABRT 退出，说明返回地址并没有被成功利用。这时加大填充长度硬试没有意义——==要么先泄露哨兵原样回填，要么换一个栈外的写目标==，方法在 [[P11-Canary绕过与GOT攻击|P11]]。

> [!info]- 哨兵的值从哪来；-fstack-protector 的三档
> - 进程启动时，内核通过辅助向量 AT_RANDOM 递给 libc 一段 16 字节随机数；libc 取前 8 字节放进 TLS 的 stack_guard 槽（就是 `fs:0x28`），并把最低字节清成 0。三条特性全部来自这一处实现——所谓"每进程随机"，随机源是内核，搬运与加工的是 libc。
> - `-fstack-protector` 只挑高危函数插哨兵（调用 alloca 的、缓冲区较大的）；`-fstack-protector-strong`（Ubuntu 默认）把范围扩大到"有数组定义或对局部变量取地址"的函数；`-fstack-protector-all` 无条件保护所有函数。做题遇到的大多是 strong。
> - glibc 的 `__stack_chk_fail` 打印那句报错后走 `abort`。老版本 glibc 还会把"程序名"一并打印进报错，而它读程序名的方式有缺陷（把哨兵位置当成 argv[0] 来指），攻击者借它反把哨兵泄露出去——这就是历史上的 SSPLeak，现版本已修，知道有这回事即可。

## 4. ASLR：装载地址随机化

**原理。** 进程的地址布局——栈在哪、堆在哪、libc 装到哪——本可以每次都一样。ASLR（Address Space Layout Randomization）让内核在建立这些映射时各加一段随机偏移：==每次执行，栈、堆、mmap 区（libc 等共享库的装载地）的基址都换一套==。攻击脚本里写死的地址，到了下一个进程指向的是完全无关的数据。

**开关在系统侧。** 档位记录在 `/proc/sys/kernel/randomize_va_space`，只读文件直接 cat，不需要 root（改动才需要）：

```bash
cat /proc/sys/kernel/randomize_va_space
```

输出：

```
2
```

三档含义：0 关闭；1 保守（随机化栈、mmap、vDSO）；2 完整（再加上堆的 brk 起点）。Ubuntu 默认 2。

**现象。** 写一个把四类地址都打印出来的程序——程序内代码地址、堆、栈，libc 基址从 `/proc/self/maps` 读第一条 libc 映射：

```c
/* aslr.c —— 打印程序代码、堆、栈、libc 的地址（x86-64 Linux） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void probe(void) {}

int main(void) {
    int local = 0;
    void *heap = malloc(16);
    char line[256], libc_base[32] = "-";
    FILE *m = fopen("/proc/self/maps", "r");
    while (fgets(line, sizeof line, m) != NULL) {
        if (strstr(line, "/libc.so.6") != NULL && strcmp(libc_base, "-") == 0) {
            sscanf(line, "%31s", libc_base);   /* libc 第一条映射的起始地址 */
        }
    }
    fclose(m);
    printf("code=%p  heap=%p  stack=%p  libc=%s\n",
           (void *)probe, heap, (void *)&local, libc_base);
    free(heap);
    return 0;
}
```

先编成无 PIE 版本，连跑两次：

```bash
gcc -w -O0 -fno-pie -no-pie aslr.c -o aslr_nopie
./aslr_nopie
./aslr_nopie
```

输出：

```
code=0x401256  heap=0x27ab8010  stack=0x7ffd8c8dff4c  libc=7264c3e00000-7264c3e28000
code=0x401256  heap=0x13281010  stack=0x7fffdc2a80ec  libc=74ba91a00000-74ba91a28000
```

两次运行，`code` 纹丝不动（都是 0x401256），heap、stack、libc 三样全换。==这就是"无 PIE + ASLR"的典型形态：程序本体固定，动态区域随机==——[[R02-C语言与内存模型#2. 内存四区：先对完地址再谈别的|R02 第 2 节]]的 regions 程序看到的就是这个。

**ASLR 与 PIE 的关系。** ==ASLR 是内核行为，PIE 是二进制的属性==——P1 第 3 节的 warning 强调过两者不是一回事，这里用同一个程序补全另一半证据。同一份 `aslr.c` 编成 PIE：

```bash
gcc -w -O0 aslr.c -o aslr_pie
./aslr_pie
./aslr_pie
```

输出：

```
code=0x599625d72269  heap=0x59965d7c0010  stack=0x7ffc86d2863c  libc=7e0add400000-7e0add428000
code=0x57f1fd38e269  heap=0x57f222209010  stack=0x7fff02e7bfcc  libc=76efa9a00000-76efa9a28000
```

四样全换。对照两组输出，分工就清楚了：==ASLR 负责"每次运行都换"，PIE 决定"程序本体参不参加换"==。反过来，PIE 开着而 ASLR 关掉（`randomize_va_space` 为 0）时，基址退回固定值——==PIE 的随机性来自 ASLR，自己不产生随机==。

调试时还有一个固定值值得认识：==GDB 默认关掉被调试进程的 ASLR==（[[R02-C语言与内存模型#11. 常见问题|R02 常见问题]]提过），所以 gdb 里跑 PIE 程序，地址每次都落在同一个位置：

```bash
gdb -q -batch -x gdb_aslr.cmds ./aslr_pie
gdb -q -batch -x gdb_aslr.cmds ./aslr_pie
```

输出：

```
main = 0x555555555274
main = 0x555555555274
```

**防住什么。** payload 里的绝对地址：libc 函数地址（ret2libc 要用）、栈地址（shellcode 落点）、堆地址。==写死即失效==——对着上一次运行的地址打这一次的进程，跳到的是无关数据。

**没防住什么。** ==泄露一个指针，就赢了一半==：栈上残留的 libc 指针、保存的程序内返回地址，读出一个就能推算所在区域的基址（P9 的格式化字符串是标准读法）。另外随机化以页（0x1000）为单位，==地址低 12 位永远不变==——下一节展开。

**经典绕过方向。** 两轮式利用：第一轮制造一次泄露（打印某个指针），算出基址；第二轮带着正确地址构造完整 payload。P7、P9 展开。

> [!info]- gdb_aslr.cmds 内容与随机化的位数量级
> cmds 就五条：`set pagination off`、`break main`、`run`、`printf "main = %p\n", &main`、`quit`。
> 随机化不是无限位数。x86-64 Linux 的默认配置下，libc 所在的 mmap 区基址约 28 位、栈约 22 位的随机空间（页面粒度；内核参数 /proc/sys/vm/mmap_rnd_bits 可调）。意义在量级：==2²⁸ 种可能，逐次猜等于不可能==，所以现代利用一律"先泄露再利用"，而不是碰运气。

## 5. PIE：程序本体的基址随机化

**原理。** PIE（Position-Independent Executable，位置无关可执行）：代码不做"我一定装载在 0x400000"的假设，对数据和函数的引用全部走相对寻址（RIP 相对）或经过 GOT，装载时由内核挑一个基址放下。它是编译期决定的产品形态，配合 ASLR 实现随机化。Ubuntu 的 gcc 默认开启（编译器配置项 `--enable-default-pie`），==现代 Linux 发行版的程序几乎全是 PIE==。

**二进制里长什么样。** `file` 的措辞差一个词，`readelf -h` 的 Type 字段是它的权威出处：

```bash
file v_nopie
file v_pie
readelf -h v_nopie | grep Type:
readelf -h v_pie | grep Type:
```

输出：

```
v_nopie: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=80b4227aa0f5f0aefe024a1c1ee9aaaf13917593, for GNU/Linux 3.2.0, not stripped
v_pie: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d5035a607e8bc18ed7ae55696fd6ce64d3cdeae5, for GNU/Linux 3.2.0, not stripped
  Type:                              EXEC (Executable file)
  Type:                              DYN (Position-Independent Executable file)
```

`executable` 与 `pie executable` 一字之差，对应 `e_type` 的 `EXEC` 与 `DYN`。checksec 报的 `No PIE (0x400000)` 与 `PIE enabled` 读的也是这个字段——`0x400000` 顺带把无 PIE 程序的固定基址写在了脸上。

**运行形态与低 12 位不变。** 第 4 节的 `aslr_pie` 两次运行，code 从 `0x599625d72269` 跳到 `0x57f1fd38e269`——程序本体真的在换位置。同时注意一个细节：==两个地址的末三位都是 `0x269`==。装载基址以页（0x1000）对齐，程序内部的相对布局不变，所以==任何程序内地址的低 12 位是常量，ASLR 和 PIE 都动不了它==。这是"部分覆盖"的物理基础：只改写目标地址的最低 1–2 字节，就能把执行引到相邻函数附近，而不需要知道完整地址——[[P09-格式化字符串漏洞|P9]] 与 [[P10-整数溢出与off-by-one|P10]] 都会用到这个思路，这里先记住"低 12 位不变"。

**`-no-pie` 的意义。** 编译加 `-fno-pie`、链接加 `-no-pie`，程序回到 0x400000 固定基址：`nm` 查到的地址直接写进 payload 就能用，P1 的 ret2win 全靠这一点。分工是——==学习阶段用 -no-pie 排除地址干扰，把注意力放在漏洞与利用构造本身；真实赛题 PIE 默认全开，必须走第 4 节的两轮式==。

**防住什么。** ==payload 里写死程序内地址==：win 函数的地址、gadget 的地址、程序内字符串的地址。无 PIE 时这些全是常量；PIE enabled 时每次运行都是新的随机值，写死即失效。

**没防住什么。** 低 12 位不变；泄露任何一个程序内地址（栈上保存的返回地址、GOT 表项都行）即可推算基址：==基址 = 泄露值 − 静态偏移==，静态偏移在文件里就有（`nm`、IDA 都能读，stripped 程序的相对布局也还在，[[R04-可执行文件格式ELF与PE#2.2 符号已删，地址还在|R04 2.2]]的方法适用）。

**经典绕过方向。** 泄露程序内地址推基址，或者利用低 12 位不变做部分覆盖。

> [!info]- PIE 与共享库都是 DYN，怎么区分；无 PIE 程序也用 RIP 相对寻址
> - 共享库的 `e_type` 同样是 DYN，`file` 认 PIE 靠的是配套特征：PIE 有 PT_INTERP 段（声明动态链接器）和程序入口，共享库没有。拿不准时 `readelf -l` 看 INTERP 一行。
> - PIE 关闭不等于代码里没有相对寻址——`-no-pie` 的程序同样大量使用 RIP 相对寻址（现代编译器的默认习惯）。位置无关决定的是==能不能整体搬走==，不是"有没有绝对地址"。
> - 无 PIE 程序的 0x400000 是链接器默认脚本的安排，不是内核给的；gdb 里 PIE 程序的 0x555555554000 则是 gdb 关 ASLR 后内核的固定选择（第 4 节），两处"固定"来源不同。

## 6. RELRO：重定位区域只读

**原理。** GOT（全局偏移表）是动态链接程序调用库函数的跳板，落在可写数据段里——==可写 + 参与"函数调用往哪跳"，就是攻击面==：把某个函数的 GOT 表项改成别的地址，之后每次调用都跳去改后的地址。GOT 表项怎么被填、延迟绑定在第一次调用时做了什么，[[P03-ELF链接与延迟绑定|P3]] 从链接视角拆过，本节只关心一件事：==运行期哪些地址还可写==。

RELRO（Relocation Read-Only）把"链接期要用、运行期不该再动"的重定位区域提前设成只读，分两档：

| 档位 | 到位时机 | 只读范围 | GOT 的函数槽 |
| ---- | ---- | ---- | ---- |
| Partial RELRO | 程序启动早期 | .init_array / .fini_array / .dynamic / .got | ==仍可写==（延迟绑定还要往里写） |
| Full RELRO（`-z now`） | 启动时一次完成全部重定位（BIND_NOW） | 上述全部，函数槽并入 .got 一并覆盖 | ==只读== |

**二进制里长什么样。** 三处证据：GNU_RELRO 段的范围、GOT 两节的位置与尺寸、动态段里有没有 BIND_NOW。先看默认（Partial）：

```bash
gcc -w -O0 -fno-stack-protector -fno-pie -no-pie vuln.c -o r_partial
readelf -l r_partial | grep -A1 GNU_RELRO
readelf -S r_partial | grep -A1 ' \.got'
readelf -d r_partial | grep -i bind || echo '(没有 BIND_NOW)'
```

输出：

```
  GNU_RELRO      0x0000000000002df8 0x0000000000403df8 0x0000000000403df8
                 0x0000000000000208 0x0000000000000208  R      0x1
  [23] .got              PROGBITS         0000000000403fd8  00002fd8
       0000000000000010  0000000000000008  WA       0     0     8
  [24] .got.plt          PROGBITS         0000000000403fe8  00002fe8
       0000000000000030  0000000000000008  WA       0     0     8
(没有 BIND_NOW)
```

读法：GNU_RELRO 从 0x403df8 起、长 0x208，==恰好到 0x404000 这一页边界为止==。GOT 分两节——`.got`（0x403fd8，16 字节）在保护圈内；`.got.plt`（0x403fe8，0x30 共 6 个槽）跨在边界上：前三个保留槽落在 0x404000 之前的圈内，==read、puts、setbuf 的三个函数槽从 0x404000 起，在圈外==，运行期照常可写，延迟绑定才有地方写（P3）。节表里的 WA（可写、参与分配）是静态声明，运行期真正的只读化由动态链接器完成：重定位处理完后对 GNU_RELRO 覆盖的页调 mprotect。动态段里没有 BIND_NOW，确认这是延迟绑定。

再编一份加 `-Wl,-z,now` 的 Full 版，同样三处：

```bash
gcc -w -O0 -fno-stack-protector -fno-pie -no-pie -Wl,-z,now vuln.c -o r_full
readelf -l r_full | grep -A1 GNU_RELRO
readelf -S r_full | grep -A1 ' \.got'
readelf -d r_full | grep -i bind
```

输出：

```
  GNU_RELRO      0x0000000000002dc0 0x0000000000403dc0 0x0000000000403dc0
                 0x0000000000000240 0x0000000000000240  R      0x1
  [23] .got              PROGBITS         0000000000403fc0  00002fc0
       0000000000000040  0000000000000008  WA       0     0     8
 0x000000000000001e (FLAGS)              BIND_NOW
```

变化三处：==`.got.plt` 节消失了==（函数槽并入 `.got`，0x40 共 8 槽，全部落进 0x403dc0 到 0x404000 的保护圈）；GNU_RELRO 把 GOT 区域整个盖满；动态段出现 `BIND_NOW`——启动时一次完成全部重定位，之后==整张 GOT 只读==。checksec 的判读依据就是"GNU_RELRO 范围 + BIND_NOW"这一组：

```bash
pwn checksec r_partial 2>&1 | grep RELRO
pwn checksec r_full    2>&1 | grep RELRO
```

输出：

```
    RELRO:      Partial RELRO
    RELRO:      Full RELRO
```

（pwntools 的输出走标准错误，管道过滤前先 `2>&1` 并到标准输出——第 7 节还会见到这个细节。）

**防住什么。** ==运行期改写 GOT 表项==这一整类劫持：把 `puts@GOT` 改成 system 的地址，等下次调用 puts 时跳去 system——Partial 下成立的打法，Full 下 GOT 只读，写进去会直接段错误。

**没防住什么。** 漏洞本身照旧；==栈上的返回地址、.data / .bss 里的函数指针都不在 RELRO 管辖内==——它们本来就设计为可写。Full RELRO 锁的只是"重定位区域"，不是"所有控制流数据"。

**经典绕过方向。** Partial：改 GOT 是首选目标（[[P11-Canary绕过与GOT攻击|P11]] 的主题之一）。Full：GOT 这条路封死，==换一个可写的控制目标==——栈上的返回地址（如果 Canary 也没拦）、.data / .bss 里的函数指针，按题目给的条件选。

> [!info]- 默认档为什么是它：看 gcc 传给链接器的参数
> `gcc -###` 把驱动传给链接器的参数原样打印，默认编译与 `-no-pie` 各看一遍 `-z`、`-pie` 开关：
>
> ```
> gcc -### -O0 vuln.c -o /dev/null 2>&1 | tr ' ' '\n' | grep -A1 -E '^-z$|^-pie$'
> ```
>
> 输出（默认）：
>
> ```
> -pie
> -z
> now
> -z
> relro
> ```
>
> 输出（-fno-pie -no-pie）：
>
> ```
> -z
> relro
> ```
>
> 默认链接是 `-pie -z now -z relro`：==PIE 链接自动附带 BIND_NOW==，所以现代 Ubuntu 上"什么都不加"编出来就是 Full RELRO（第 7 节 c_default 的输出可对证）；`-no-pie` 链接只给 `-z relro`，落回 Partial。两个组合可以手动改：PIE 下想要 Partial，加 `-Wl,-z,lazy` 压过默认的 `-z now`；`-no-pie` 下想要 Full，手动加 `-Wl,-z,now`（本节 r_full 就是这么编的）。不同发行版、不同版本的默认值可能不同，==判断依据始终是文件里的三处证据，不是"印象里默认是什么"==。

## 7. checksec 逐行判读

把默认编译（全部保护到位）的产物交给 checksec：

```bash
gcc -w -O0 vuln.c -o c_default
pwn checksec c_default
```

输出：

```
[*] '/tmp/p4/c_default'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

逐行判读，每一行都对应文件里的一处固定字段——==读完本章，不用工具也能手工判出全表==：

| 字段 | 本例的值 | 判读依据 | 关系最近的章节 |
| ---- | ---- | ---- | ---- |
| Arch | amd64-64-little | ELF 头的机器类型与字节序（[[R04-可执行文件格式ELF与PE\|R04]]） | 决定 payload 位数与小端打包（p64） |
| RELRO | Full RELRO | GNU_RELRO 段范围 + 动态段 BIND_NOW（第 6 节） | [[P11-Canary绕过与GOT攻击\|P11]] |
| Stack | Canary found | 符号表里对 `__stack_chk_fail` 的引用（第 3 节） | [[P11-Canary绕过与GOT攻击\|P11]] |
| NX | NX enabled | GNU_STACK 段有无 E 标志（第 2 节） | [[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]、[[P08-ROP进阶与SROP\|P8]] |
| PIE | PIE enabled | ELF 头 e_type 为 DYN（第 5 节） | [[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]、[[P09-格式化字符串漏洞\|P9]] |
| SHSTK / IBT | Enabled | .note.gnu.property 里的 CET 声明（见下方折叠框） | 入门栈题不受影响 |
| Stripped | No | 有没有符号表（[[R04-可执行文件格式ELF与PE#2.2 符号已删，地址还在\|R04 2.2]]） | 影响静态分析难度，不影响保护 |

两个使用提示：pwntools 的输出走标准错误，要用管道过滤时先 `2>&1`；查的目标一定是==题目附件那个文件本身==，别拿本机另编的程序替它回答。

> [!info]- SHSTK / IBT：CET 的两个属性，为什么报 Enabled 却不影响做题
> 这两个字段写在文件里，`readelf -n` 能看到：
>
> ```
> Displaying notes found in: .note.gnu.property
>   Owner                Data size 	Description
>   GNU                  0x00000020	NT_GNU_PROPERTY_TYPE_0
>       Properties: x86 feature: IBT, SHSTK
> ```
>
> 这是 Intel CET（Control-flow Enforcement Technology，控制流强制技术）的两个用户态特性在二进制里的自我声明：IBT（间接分支跟踪）要求间接 jmp / call 的落点必须是 endbr64 指令——第 3 节两份反汇编开头那条 `endbr64` 就是它的产物；SHSTK（影子栈）由硬件另建一条只存返回地址的栈，`ret` 时两边对不上即报错。checksec 读到这份声明就报 Enabled。==对入门题没有影响==：Linux 用户态的 CET 强制需要内核与 glibc 同时支持并启用，CTF 靶机环境普遍没有开运行时强制，二进制里带着声明只是表示"兼容"。学 ROP 之前不必管它，[[P08-ROP进阶与SROP|P8]] 再回头看。

> [!info]- FORTIFY_SOURCE：checksec 不显示、现代 Ubuntu 默认开启的又一层
> Ubuntu 的 gcc 在开优化时默认定义 `_FORTIFY_SOURCE=3`：编译器若能推知目标缓冲区大小，就把危险函数调用换成 `_chk` 后缀的安全版本，运行期越界直接 abort（报 "buffer overflow detected"）。同一程序 `-O2` 编译后，read 变成了 `__read_chk`：
>
> ```
>   4011d7:	e8 84 fe ff ff       	call   401060 <__read_chk@plt>
> ```
>
> 对做题的影响：`-O2` 产物里见到 `__read_chk` / `__printf_chk` 一类符号，说明 fortify 在场，其中 `__printf_chk` 会拒绝执行"位于可写内存的格式串"里的 %n（[[P09-格式化字符串漏洞|P9]] 会碰到）。它没有对应的 checksec 字段——==fortify 是编译属性，改变的是函数调用，不是内存布局==。`-O0` 下不生效，本章程序照常长成普通的 read。

## 8. 六种编译组合：checksec 对比与攻击方向决策

同一个 `vuln.c`，六种编译。第 2 行是 P1 的教学基准（[[P01-PWN导论与缓解机制全景#5.1 漏洞程序与编译|P1 5.1]] 的那组参数），第 3、4 行在它之上逐个恢复默认保护，第 1、5、6 行各从基准单独动一个开关：

| # | 组合 | 编译命令 | 相对基准的改动 |
| ---- | ---- | ---- | ---- |
| 1 | 全关 | `gcc -w -O0 -fno-stack-protector -fno-pie -no-pie -z execstack -Wl,-z,norelro vuln.c -o c1` | 再关 NX 与 RELRO |
| 2 | -no-pie 基准 | `gcc -w -O0 -fno-stack-protector -fno-pie -no-pie vuln.c -o c2` | —— |
| 3 | 开 Canary | `gcc -w -O0 -fno-pie -no-pie vuln.c -o c3` | 去掉 `-fno-stack-protector`，默认的 strong 生效 |
| 4 | 开 PIE（现代默认） | `gcc -w -O0 vuln.c -o c4` | 再去掉 `-fno-pie -no-pie`，编译器默认值全上 |
| 5 | 单开 Full RELRO | `gcc -w -O0 -fno-stack-protector -fno-pie -no-pie -Wl,-z,now vuln.c -o c5` | 加 `-Wl,-z,now` |
| 6 | 单关 NX | `gcc -w -O0 -fno-stack-protector -fno-pie -no-pie -z execstack vuln.c -o c6` | 加 `-z execstack` |

六份产物的 checksec 结果汇总：

| # | RELRO | Stack | NX | PIE |
| ---- | ---- | ---- | ---- | ---- |
| 1 | No RELRO | No canary found | 栈可执行 * | No PIE (0x400000) |
| 2 | Partial RELRO | No canary found | NX enabled | No PIE (0x400000) |
| 3 | Partial RELRO | Canary found | NX enabled | No PIE (0x400000) |
| 4 | Full RELRO | Canary found | NX enabled | PIE enabled |
| 5 | Full RELRO | No canary found | NX enabled | No PIE (0x400000) |
| 6 | Partial RELRO | No canary found | 栈可执行 * | No PIE (0x400000) |

> [!warning] 开了 execstack 的产物，checksec 不报 "NX disabled"
> 对 GNU_STACK 为 RWE 的二进制，pwntools 给出的是这样几行（c1 与 c6 实际输出）：
>
> ```
>     NX:         NX unknown - GNU_STACK missing
>     Stack:      Executable
>     RWX:        Has RWX segments
> ```
>
> 字样随版本会变，判读时抓住本体：==GNU_STACK 带 E 标志 = 栈可执行 = NX 没生效==（第 2 节的 readelf 证据优先于工具字样），再扫一眼 "Has RWX segments"——可写又可执行的段是注入代码的理想落点。另注意第 4 行：本工具链在 PIE 链接时默认附带 `-z now`（第 6 节折叠框），所以这一步 RELRO 列跟着变成了 Full，==PIE 单独的效果由第 5 节 file / readelf 的对照单独确认==。

==查保护的产出是一张"能做什么、不能做什么"的清单==。把第 2 节到第 6 节的结论收拢成决策表——每读到一格，立即知道下一步往哪走：

| checksec 读到 | 立刻知道 | 可行方向 |
| ---- | ---- | ---- |
| NX enabled | 栈上的数据跑不起来 | 代码重用：ROP / ret2libc（[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]、[[P08-ROP进阶与SROP\|P8]]） |
| 栈可执行（RWE） | 注入的代码有落点 | shellcode 注入，落点与跳转构造（[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]） |
| No canary found | 溢出可直达返回地址 | 直接覆盖返回地址（[[P06-栈溢出原理与ret2win\|P6]]） |
| Canary found | 硬覆盖会在尾声被拦 | 泄露原样回填（[[P09-格式化字符串漏洞\|P9]]）、fork 逐字节爆破、改写 GOT 等栈外目标（[[P11-Canary绕过与GOT攻击\|P11]]） |
| No PIE (0x400000) | 程序内地址是常量 | 地址写死进 payload（[[P06-栈溢出原理与ret2win\|P6]]） |
| PIE enabled | 程序内地址每次运行都变 | 泄露推基址、低 12 位部分覆盖（[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]、[[P09-格式化字符串漏洞\|P9]]） |
| Partial RELRO | GOT 函数槽可写 | 改 GOT 劫持调用（[[P11-Canary绕过与GOT攻击\|P11]]） |
| Full RELRO | GOT 只读 | 换可写目标：栈上返回地址、.data / .bss 函数指针，按题选（[[P11-Canary绕过与GOT攻击\|P11]]） |

两点组合判断收尾：

- ==全关（第 1 行）时五步流程一步直通==。P1 的 ret2win 环境其实只关了 Canary 和 PIE（NX 当时开着，所以走"跳 win"而不是"跳栈上 shellcode"）——把第 1 行拆成两步看，就是这个区别。
- ==全开（第 4 行，现代工具链的默认值）时，注入、硬覆盖、写死地址全部堵死==，通用解只剩==两轮式==：先制造一次泄露，再构造第二轮利用。从 P6 到 P11 的每一章，本质都是"把这张决策表的一格拆掉"；==以后拿到任何题目，第一件事就是把这张表填出来==。

## 9. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| checksec 报 PIE enabled，两次运行地址却没变 | GDB 默认关 ASLR；或系统 randomize_va_space 为 0。`cat /proc/sys/kernel/randomize_va_space` 看档位（第 4 节） |
| checksec 报 "NX unknown - GNU_STACK missing"，可我没动过段 | GNU_STACK 带 E 时 pwntools 的说法，是开了 execstack 的产物；看 `Stack: Executable` 与 readelf 的 RWE（第 2、8 节） |
| 无 PIE 程序，payload 里的 libc 地址却每次都错 | libc 基址归 ASLR 管，与 PIE 无关——能写死的只有无 PIE 程序自己的地址，libc 地址必须先泄露（第 4 节） |
| 溢出后报 `*** stack smashing detected ***` 而不是崩溃 | Canary 在尾声拦下了覆盖，进程死于 SIGABRT（exit 134）。转泄露或换目标（第 3 节，方法在 [[P11-Canary绕过与GOT攻击\|P11]]） |
| readelf -S 找不到 .got.plt 节 | Full RELRO 把函数槽并进了 .got，属正常形态；找 BIND_NOW 确认（第 6 节） |
| -O2 编译后 read / printf 变成了 __read_chk / __printf_chk | FORTIFY_SOURCE 的函数替换，编译属性而非独立开关（第 7 节折叠框） |
| 按旧程序手算的偏移在 Canary 版里对不上 | Canary 占走 `[rbp-0x8]`，帧布局整体平移（第 3 节两份反汇编的第三处差异）——==偏移一律用 cyclic 重新量==（[[P01-PWN导论与缓解机制全景#5.4 第三步：cyclic 算偏移\|P1 5.4]]） |
| 想关 ASLR 本地复现老题 | 改 randomize_va_space 需要 root；用 gdb 跑更省事，它默认关被调试进程的 ASLR（第 4 节） |
| file 说 pie executable，checksec 说 PIE enabled，以谁为准 | 同一个字段（e_type = DYN）的两种读法，永远一致；readelf -h 是最直接的出处（第 5 节） |
