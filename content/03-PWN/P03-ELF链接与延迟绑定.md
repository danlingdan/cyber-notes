---
chapter: PWN
section: ELF、链接与延迟绑定
order: 303
tags:
  - CTF
  - PWN
  - ELF
publish: true
---

# P3 ELF 链接与延迟绑定
## ELF Linking & Lazy Binding

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[R04-可执行文件格式ELF与PE|R04]] · [[P01-PWN导论与缓解机制全景|P1]]
> **本章目标**：讲清动态链接在运行时如何工作——PLT/GOT 延迟绑定的完整跳转链、RELRO 对 GOT 可写性的影响；再打通 PWN 的 libc 主线：用 ret2plt 泄露 libc 地址，识别 libc 版本，算出基址与任意函数的真实地址。

## 1. 动态链接留给 PWN 的三个部件

ELF 文件本身的结构——节区与段、符号表、重定位表——[[05-ELF文件格式与链接|通用基础 05 章]]完整讲过，做题视角的速查在 [[R04-可执行文件格式ELF与PE|R04]]，本章不重讲格式。本章回答的是一个运行时问题：==程序里写死的 `call puts@plt`，是怎么一路走到 libc 里真正的 puts 的==。答案的两半 [[05-ELF文件格式与链接#5. 符号表与重定位|05 章第 5 节]]已经给出：GLOB_DAT 重定位装载时由动态链接器填好，JUMP_SLOT 重定位第一次调用时才填。本章把"第一次调用才填"的全过程逐指令走完，因为它直接决定三件 PWN 最关心的事：

| 部件 | 在哪 | 是什么 | PWN 关心什么 |
| ---- | ---- | ---- | ---- |
| PLT | 程序自己的代码段（`.plt` / `.plt.sec`） | 调用外部函数的跳板代码 | `puts@plt` 是编译期常量（非 PIE 下），可以直接写进 payload 当函数地址用 |
| GOT | 程序自己的数据段（`.got` / `.got.plt`） | 外部函数真实地址的表 | 里面存着 libc 地址：读它等于泄露，写它等于劫持 |
| libc 本体 | 每台机器一份，装载基址随机 | printf / puts / system 的实现 | system 与 "/bin/sh" 都在其中，拿到基址就能算出它们 |

本章主线是 [[P01-PWN导论与缓解机制全景|P1]] 五步流程里"构造利用链"这一步的前置子问题，一句话：==泄露 GOT 里的地址 → 识别 libc 版本 → 算出基址 → 加偏移得到 system 与 "/bin/sh"==。第 2–3 节讲机制（跳转链与 RELRO），第 4 节讲泄露（ret2plt），第 5 节补运行环境（ld.so 与 patchelf），第 6 节把版本匹配完整走一遍；把它们接进完整 ret2libc 是 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 的内容。

## 2. 延迟绑定：puts 的第一次调用

[[05-ELF文件格式与链接#6. 动态链接：printf@plt 的完整跳转链|05 章第 6 节]]给过这条链的速览；本节换 puts 把每一步的地址落到实处，并用 GDB 观察 GOT 槽位被改写的现场——这是后续泄露与劫持两类手法共同的地基。

演示程序只有两次 puts：

```c
/* p3_demo.c —— 延迟绑定演示程序（x86-64 Linux） */
#include <stdio.h>

int main(void) {
    puts("first call");
    puts("second call");
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector p3_demo.c -o p3_demo
```

同一编译环境会得到与下文相同的布局；工具链版本不同则地址不同，方法不变，数值以自己机器的输出为准。

### 2.1 静态视角：一段调用、两段跳板、一张表

先看重定位表——它记录"哪个槽位、填哪个符号、什么时候填"（[[R04-可执行文件格式ELF与PE#1.5 重定位：哪个地址在什么时候填|R04 1.5]]的读法）：

```bash
readelf -r p3_demo
```

输出：

```
Relocation section '.rela.dyn' at offset 0x490 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000403fd8  000100000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.34 + 0
000000403fe0  000300000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0

Relocation section '.rela.plt' at offset 0x4c0 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404000  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
```

puts 的 JUMP_SLOT 条目说：槽位 0x404000，第一次调用 puts 时填入真实地址。这张表是本章反复用到的底账，pwntools 的 `e.got['puts']` 查的就是 Offset 列。

三个部件在反汇编里各就各位（x86-64 Linux / System V AMD64 ABI，Intel 语法）。main 的两条调用：

```bash
objdump -d -M intel p3_demo | sed -n '/<main>:/,/^$/p'
```

输出：

```
0000000000401136 <main>:
  401136:	f3 0f 1e fa          	endbr64
  40113a:	55                   	push   rbp
  40113b:	48 89 e5             	mov    rbp,rsp
  40113e:	bf 04 20 40 00       	mov    edi,0x402004
  401143:	e8 f8 fe ff ff       	call   401040 <puts@plt>
  401148:	bf 0f 20 40 00       	mov    edi,0x40200f
  40114d:	e8 ee fe ff ff       	call   401040 <puts@plt>
  401152:	b8 00 00 00 00       	mov    eax,0x0
  401157:	5d                   	pop    rbp
  401158:	c3                   	ret
```

两条 `call 401040` 指向同一个跳板 `puts@plt`。跳板本体分布在两个节里（现代工具链带 CET 后是 `.plt.sec` + `.plt` 两段，两种布局的差别见本节末尾折叠框）：

```bash
objdump -d -M intel -j .plt.sec p3_demo
objdump -d -M intel -j .plt p3_demo
```

输出：

```
0000000000401040 <puts@plt>:
  401040:	f3 0f 1e fa          	endbr64
  401044:	ff 25 b6 2f 00 00    	jmp    QWORD PTR [rip+0x2fb6]        # 404000 <puts@GLIBC_2.2.5>
  40104a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000401020 <.plt>:
  401020:	ff 35 ca 2f 00 00    	push   QWORD PTR [rip+0x2fca]        # 403ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 cc 2f 00 00    	jmp    QWORD PTR [rip+0x2fcc]        # 403ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401030:	f3 0f 1e fa          	endbr64
  401034:	68 00 00 00 00       	push   0x0
  401039:	e9 e2 ff ff ff       	jmp    401020 <_init+0x20>
```

那张表——`.got.plt`——此刻的内容：

```bash
objdump -s -j .got.plt p3_demo
```

输出：

```
Contents of section .got.plt:
 403fe8 083e4000 00000000 00000000 00000000  .>@.............
 403ff8 00000000 00000000 30104000 00000000  ........0.@.....
```

| 地址 | 初值 | 角色 |
| ---- | ---- | ---- |
| 0x403fe8 | 0x403e08 | GOT[0]，指向 `.dynamic` 节 |
| 0x403ff0 | 0（装载时由 ld.so 填） | GOT[1]，link_map：本模块的装载信息 |
| 0x403ff8 | 0（装载时由 ld.so 填） | GOT[2]，动态链接器的解析函数 |
| 0x404000 | 0x401030 | puts 的函数槽位 |

关键一行：0x404000 里存的 0x401030 ==不是 libc 地址，是程序自己 `.plt` 里的地址==。第一次调用就从这里拐进解析流程；GOT[1]、GOT[2] 则已在装载阶段被 ld.so 填好（第 4 步读的正是它们，[[#5.1 动态链接器做什么|5.1]]）。

> [!note] push 0x0 的 0 是什么
> 0x401034 压入的立即数 0，是 puts 的 JUMP_SLOT 条目在 `.rela.plt` 里的下标（本程序只有一条，下标 0）。解析函数拿"模块 link_map + 这个下标"，就能在重定位表里定位到"要解析的符号是 puts"。

### 2.2 第一次调用的完整路径

把 2.1 的静态材料串成运行时顺序（x86-64 Linux / System V AMD64 ABI）：

1. `main` 执行 `call 401040`：返回地址压栈，控制流进入 `.plt.sec` 里的 puts 跳板；
2. 跳板执行 `jmp QWORD PTR [0x404000]`：查表跳转，此刻槽里是 0x401030，于是落进 `.plt` 的 puts 表项；
3. 表项执行 `push 0x0`：把重定位下标 0 压栈当作解析参数，随后 `jmp 401020` 进入 PLT 表头（PLT0）；
4. PLT0 执行 `push QWORD PTR [0x403ff0]` 压入 link_map，再 `jmp QWORD PTR [0x403ff8]` 跳进动态链接器的解析函数 `_dl_runtime_resolve`；
5. 解析函数按 link_map 找到本模块的 `.rela.plt`，取第 0 条得到符号 `puts`，按名字在已装载的 libc 里查出真实地址，==写回 GOT 槽位 0x404000==，最后跳到真正的 puts 执行；
6. puts 返回，main 继续执行——0x404000 里的值已经换成 libc 地址。

调用链一行版：

```text
call puts@plt → jmp [GOT] → push 下标 → PLT0 → _dl_runtime_resolve 解析 → 真地址写回 GOT → 进入 puts
```

==地址解析被推迟到第一次调用，所以叫延迟绑定（lazy binding）==：程序启动时一个库函数都不解析，谁先被调到才解析谁，解析结果缓存在 GOT 里。

### 2.3 之后的每次调用

第二次 `call 401040` 时，0x404000 里已经是 libc 的真实地址，第 2 步的 `jmp [GOT]` 一步直达 puts，第 3–5 步不再发生。==解析的代价只付一次，之后每次调用都是一次间接跳转==。

### 2.4 在 GDB 里看 GOT 槽位被改写

第 5 步的"写回 GOT"可以直接观察。断点下在两条 call 指令上（地址来自 2.1：0x401143 与 0x40114d），对比 GOT 槽位 0x404000 的值。GDB 用原生命令就够，不需要插件（插件的增强功能 [[P05-pwntools与GDB插件工具链|P5]] 梳理）：

```
# gdb.cmds
set pagination off
set confirm off
break *0x401143
break *0x40114d
run
x/gx 0x404000
continue
x/gx 0x404000
info symbol *(unsigned long *)0x404000
quit
```

```bash
gdb -q -batch -x gdb.cmds ./p3_demo
```

输出：

```
Breakpoint 1 at 0x401143
Breakpoint 2 at 0x40114d
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000000000401143 in main ()
0x404000 <puts@got.plt>:	0x0000000000401030

Breakpoint 2, 0x000000000040114d in main ()
0x404000 <puts@got.plt>:	0x00007ffff7c8e860
puts in section .text of /usr/lib/x86_64-linux-gnu/libc.so.6
```

两个断点之间只隔了一次 puts 调用，槽位值从 0x401030（自己 `.plt` 里的地址）变成 0x7ffff7c8e860；`info symbol` 确认新值落在 libc 的 `.text` 里，就是 puts 的实现。==延迟绑定的全部效果，就是这 8 个字节在第一次调用前后的一换==。

> [!warning] 断点要下在 call 上，不要下在 puts 里
> 解析发生在"call 进入跳板"到"跳进 libc"之间。断点下在 libc 的 puts 函数内部，停下时解析早已完成，GOT 里看到的只会是 libc 地址，观察不到前后变化。另外 GDB 默认关闭 ASLR，这里 libc 地址固定为 0x7ffff7 开头（[[05-ELF文件格式与链接#11. 常见问题|05 章常见问题]]记过这条）——不要把它当成远程服务上的真实地址。

> [!info]- 为什么要延迟绑定，以及 .plt.sec 与老布局
> 动态程序往往引用几百个库函数，多数一次都调不到；启动时全部解析既慢又浪费，延迟绑定把开销摊到实际调用上。代价是第一次调用多走几步，且 GOT 必须保持可写——后者引出第 3 节的 RELRO。
> 布局方面，本章的反汇编是现代工具链带 CET 的形状：`call` 先落 `.plt.sec`（`endbr64; jmp [GOT]`），解析逻辑在 `.plt`。老一些的二进制没有 `.plt.sec`，`call` 直接落 `.plt` 表项，表项形状是 `jmp [GOT]; push 下标; jmp PLT0`，首次调用跳进 `push` 那几行——机制完全相同。判断手头是哪种形状，看 `.plt` 表项第一行是不是 `endbr64` 即可（endbr64 的来历见 [[P01-PWN导论与缓解机制全景|P1]] 第 3 节折叠框）。
> `puts@GLIBC_2.2.5` 这类版本后缀是 glibc 的符号版本机制，保证老程序继续拿到老行为的实现；做题时只认符号名，版本列不用管。

## 3. RELRO：GOT 什么时候变只读

第 2 节的机制留下一道口子：GOT 必须可写，延迟绑定才能把解析结果写进去。==可写不只对动态链接器成立，对拿到内存写能力的攻击者同样成立==——把 0x404000 的内容改成别处，下一次 `call puts@plt` 就跳去了别处。RELRO（Relocation Read-Only）就是对这个口子的收窄，分两档：

| 等级 | 怎么得到 | GOT 状态 | 延迟绑定 |
| ---- | ---- | ---- | ---- |
| Partial RELRO | 现代工具链默认 | `.got` 只读，`.got.plt` 的函数槽可写 | 保留 |
| Full RELRO | 链接时加 `-Wl,-z,now` | 整张 GOT 只读 | 关闭，启动时全部解析完 |

两个产物对比，后者只多一个链接参数 `-Wl,-z,now`：

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector -Wl,-z,now p3_demo.c -o p3_demo_full
pwn checksec p3_demo
pwn checksec p3_demo_full
```

输出：

```
[*] '/home/hua/p3demo/p3_demo'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[*] '/home/hua/p3demo/p3_demo_full'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

checksec 的 RELRO 行读的是两处：程序头里的 GNU_RELRO 段（保护区的范围）与动态段里的 BIND_NOW 标记（是否启动即解析）。

```bash
readelf -d p3_demo_full | grep -i BIND
```

输出：

```
 0x000000000000001e (FLAGS)              BIND_NOW
```

默认产物没有这一条（`readelf -d p3_demo | grep -i BIND` 无输出），对应 Partial RELRO 保留延迟绑定。保护区范围再看程序头（[[R04-可执行文件格式ELF与PE#1.1 链接视图与执行视图：两套目录|R04 1.1]]的逐列读法）与节区表：

```bash
readelf -l p3_demo | grep -A1 GNU_RELRO
readelf -l p3_demo_full | grep -A1 GNU_RELRO
readelf -SW p3_demo | grep -E ' \.(got|got\.plt) '
readelf -SW p3_demo_full | grep -E ' \.(got|got\.plt) '
```

输出：

```
  GNU_RELRO      0x0000000000002df8 0x0000000000403df8 0x0000000000403df8
                 0x0000000000000208 0x0000000000000208  R      0x1
  GNU_RELRO      0x0000000000002dd0 0x0000000000403dd0 0x0000000000403dd0
                 0x0000000000000230 0x0000000000000230  R      0x1
  [23] .got              PROGBITS        0000000000403fd8 002fd8 000010 08  WA  0   0  8
  [24] .got.plt          PROGBITS        0000000000403fe8 002fe8 000020 08  WA  0   0  8
  [23] .got              PROGBITS        0000000000403fd0 002fd0 000030 08  WA  0   0  8
```

逐行对账（第 1–2 行是 partial 的 GNU_RELRO，第 3–4 行是 full 的，末两行是两个产物的节区表）：

- **partial**：保护区是 [0x403df8, 0x404000)。`.got`（0x403fd8–0x403fe8）和 `.got.plt` 的前三格 GOT[0..2]（0x403fe8–0x404000）被罩住；==puts 的函数槽 0x404000 恰好落在保护区外，仍可写==。
- **full**：`.got.plt` 整节消失，内容并入 `.got`（0x403fd0–0x404000），保护区 [0x403dd0, 0x404000) 把整张 GOT 罩满；配合 BIND_NOW，启动时所有函数解析完毕，==此后没有任何代码需要再写 GOT，操作系统把这一页锁成只读==。

对利用的影响一句话：==改写 GOT 这条路只在 Partial RELRO 下可行==。格式化字符串用 `%n` 打 GOT（[[P09-格式化字符串漏洞|P9]]）、溢出后篡改 GOT 表项（[[P11-Canary绕过与GOT攻击|P11]]）都以此为前提；拿到 full RELRO 的题转走泄露加 ROP 的路线（[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]）。RELRO 只锁"写"不锁"读"——下一节的泄露在两种等级下都成立，因为 puts 的真实地址无论如何都躺在 0x404000 里。保护机制的原理细节 [[P04-Linux安全缓解机制|P4]] 展开。

## 4. ret2plt：把 libc 地址打印出来

第 2、3 节回答了"puts 的真实地址在哪"——在 GOT 槽位里。本节回答"怎么把它拿出来"。

原理三句话：

1. `puts(s)` 从 s 指向的内存逐字节输出，遇到 `\0` 停止；
2. `puts@got` 槽位（解析后）存的就是 puts 的真实地址，8 个字节连成一片内存；
3. ==把槽位地址当参数调用 `puts@plt`，打出来的就是 libc 里的 puts 真实地址==。

这就是 ret2plt：把返回地址（或其他控制点）改成 `puts@plt`，第一参数寄存器 rdi 装上 `puts@got` 的地址（rdi 传参见 [[R03-x86与x64汇编精要复习|R03]]的调用约定；栈上怎么为它摆参数 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 详解）。地址常量用 pwntools 直接读文件：

```python
#!/usr/bin/env python3
# p3_elf.py —— 用 pwntools 查 PLT / GOT / 符号地址
from pwn import *
context.log_level = 'error'

e = ELF('./p3_demo', checksec=False)
print('puts@plt =', hex(e.plt['puts']))
print('puts@got =', hex(e.got['puts']))
print('main     =', hex(e.symbols['main']))

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
print('libc puts    偏移 =', hex(libc.symbols['puts']))
print('libc system  偏移 =', hex(libc.symbols['system']))
print('libc /bin/sh 偏移 =', hex(next(libc.search(b'/bin/sh\x00'))))
```

```bash
python3 p3_elf.py
```

输出：

```
puts@plt = 0x401044
puts@got = 0x404000
main     = 0x401136
libc puts    偏移 = 0x8e860
libc system  偏移 = 0x5c2e0
libc /bin/sh 偏移 = 0x1db799
```

前三行与 2.1 的 readelf、objdump 输出一一对应。后三行是第 6 节的原料：==libc 文件里每个符号的位置（偏移）是常量，随机的只是装载基址==；`/bin/sh` 不是符号，`search` 在整个 libc 文件里找那段 7 字节字符串，返回它的偏移。

> [!warning] pwntools 的 puts@plt 与 objdump 的标签差 4 字节
> pwntools 给的 0x401044 是 `jmp [GOT]` 那条指令的地址，objdump 的 `<puts@plt>` 标签 0x401040 是 `endbr64` 的开头。跳到哪一个都能正常调到 puts（endbr64 只是 CET 的标记指令），两处数字对不上不是出错。
> 另一条：`ELF().plt` / `got` / `symbols` 给的都是文件内的地址。非 PIE 程序装载基址固定 0x400000，直接用；PIE 程序要加上运行期基址（PIE 的处理 [[P04-Linux安全缓解机制|P4]] 讲）。

泄露回来的地址长什么样？0x00007ffff7c8e860——正是 2.4 里 GOT 槽位解析后的值（GDB 默认关 ASLR，两处是同一个内存布局）。==libc 映射在用户空间高位，最高两个字节恒为 `00 00`==（x86-64 用户态地址不超过 0x7fff_ffff_ffff）：puts 打到第一个 `\0` 就停，实际收到 6 个字节，脚本里用 `u64(recv.ljust(8, b'\x00'))` 给高位补零还原成完整地址（打包函数 [[P05-pwntools与GDB插件工具链|P5]] 介绍）。

到这里手上有了一个真实的 libc 地址。第 5 节先补齐运行环境知识，第 6 节回答泄露后的关键问题：==这个数是哪一版 libc 里的 puts==。

## 5. 运行环境：ld.so、LD_PRELOAD 与 patchelf

### 5.1 动态链接器做什么

第 2 节的解析流程不是内核做的。内核只把 ELF 的 LOAD 段映射进地址空间，然后按 INTERP 程序头（[[R04-可执行文件格式ELF与PE#1.1 链接视图与执行视图：两套目录|R04 1.1]]输出里 `Requesting program interpreter` 那行）把控制权交给动态链接器 `/lib64/ld-linux-x86-64.so.2`，习惯叫 ld.so。它接着做三件事：

1. 递归装载依赖库：读 `.dynamic` 里的 NEEDED 条目（`readelf -d` 列出的那些），把 libc.so.6 映射进地址空间；
2. 做装载期重定位：GLOB_DAT 类条目现在就填——`__libc_start_main` 的槽位 0x403fd8 在 main 执行前已是 libc 地址（[[05-ELF文件格式与链接#5. 符号表与重定位|05 章第 5 节]]的结论在这里兑现）；
3. 给延迟绑定当后端：把本模块的 link_map 挂进 GOT[1]，把自己的解析函数挂进 GOT[2]——2.2 第 4 步跳进去的就是它。

### 5.2 LD_PRELOAD 与题目附带的 ld

ld.so 认识一组环境变量，最有名的是 LD_PRELOAD：值里列出的库会在所有 NEEDED 依赖之前装载，==符号解析时先查先装进来的库==——如果里面定义了与 libc 同名的函数，程序调到的就是它。这是运行时 hook 的标准做法，也是某些题目"远程行为与本地不一致"的来源：远程环境可能用 LD_PRELOAD 挂了自定义库。

> [!info]- LD_PRELOAD 的另一面
> 正因为它能改写任意库函数的解析结果，setuid 程序会忽略 LD_PRELOAD，防止提权路径被注入。CTF 里更常见的用法是反向的：出题环境缺某个函数时，自己编一个同名 `.so` 预加载补齐（比如给移除了 `gets` 声明的新版环境补上实现）。

附件层面：libc 类题目常给两个文件——`libc.so.6` 和 `ld-linux-x86-64.so.2`。原因是 ld.so 与 libc 是同一次构建的配套件，==版本必须配对==；远程跑的是配对的一套，本地调试要还原同一套，否则轻则符号对不上，重则程序起不来。

### 5.3 patchelf：把题目环境装到本地

patchelf 直接改 ELF 文件里的 interpreter 与库搜索信息。安装不需要 root：用 apt 把包下载到当前目录、解开即可用：

```bash
apt-get download patchelf
dpkg -x patchelf_*.deb pe
./pe/usr/bin/patchelf --version
```

输出：

```
Get:1 http://archive.ubuntu.com/ubuntu resolute/universe amd64 patchelf amd64 0.18.0-1.4build1 [106 kB]
Fetched 106 kB in 2s (53.0 kB/s)
patchelf 0.18.0
```

也可以 `pip3 install --break-system-packages patchelf`，装完在 `~/.local/bin/` 下。用法：把题目附件的两个文件放进一个目录，对目标程序下两条参数：

```bash
mkdir -p libs
cp /usr/lib/x86_64-linux-gnu/libc.so.6 /lib64/ld-linux-x86-64.so.2 libs/   # 赛题里这两个文件来自题目附件
cp p3_demo target                                                          # 拿演示程序当靶子，赛题里就是题目二进制
./pe/usr/bin/patchelf --set-rpath '$ORIGIN/libs' --set-interpreter "$PWD/libs/ld-linux-x86-64.so.2" target
ldd target | grep -E 'libc|ld-linux'
./target
```

输出：

```
	libc.so.6 => /home/hua/p3_pe/libs/libc.so.6 (0x000078b8bb800000)
	/home/hua/p3_pe/libs/ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x000078b8bba60000)
first call
second call
```

换库之前 `ldd target` 显示的还是系统 libc（`/usr/lib/x86_64-linux-gnu/libc.so.6`，对照 [[R04-可执行文件格式ELF与PE#1.7 静态还是动态：file 与 ldd|R04 1.7]]），patchelf 之后两行都指向 `libs/` 下的附件版本，程序照常运行。`--set-interpreter` 换掉 INTERP 指向的 ld.so；`--set-rpath` 设置运行时找库的搜索目录，`$ORIGIN` 代表程序所在目录。==用题目附件调试的固定流程：patchelf 换 interpreter 与 rpath → ldd 确认 → pwntools 调试==。来路不明的附件放进隔离环境再运行是基本安全习惯（环境与工具的安装汇总见 [[P02-前置基础C汇编与Linux|P2]]）。

## 6. libc 识别与版本匹配

### 6.1 为什么一个泄露值还不够

先看 libc 基址在 ASLR 下的表现。每个进程的地址空间清单在 `/proc/<pid>/maps`，`/proc/self/maps` 让进程读它自己的：

```bash
sh -c 'grep "libc.so.6" /proc/self/maps' | head -1
sh -c 'grep "libc.so.6" /proc/self/maps' | head -1
sh -c 'grep "libc.so.6" /proc/self/maps' | head -1
```

输出：

```
7de6a8200000-7de6a8228000 r--p 00000000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
71b7d7800000-71b7d7828000 r--p 00000000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7e9cae000000-7e9cae028000 r--p 00000000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
```

第一列是本次运行 libc 的映射区间（起始-结束地址）：三次三个值，这就是 ASLR（机制 [[P04-Linux安全缓解机制|P4]] 展开）。泄露值满足：

$$\text{泄露地址} = \text{libc 基址} + \text{该函数在这版 libc 里的偏移} \tag{3.1}$$

倒过来算基址需要减数：

$$\text{libc 基址} = \text{泄露地址} - \text{同版 libc 中该函数的偏移} \tag{3.2}$$

难点在"同版"两个字：==每一版 libc 的偏移表都不同==——glibc 改动任何一行代码，其后所有符号的偏移都可能挪动。用错版本的偏移，3.2 减出来的"基址"是错的，而且通常页对齐检查不通过（6.4 的判据一眼可辨）。所以拿到泄露值后的第一件事是==确定它来自哪一版 libc==，这就是版本匹配。两条路：题目给了 libc 文件就直接用（6.6）；没给就靠指纹检索（6.3、6.5）。

### 6.2 方法一：strings 读版本串

libc 文件里带着自述版本（下面以本地系统 libc 为例；赛题附件里的 libc.so.6 用同一条命令）：

```bash
strings /usr/lib/x86_64-linux-gnu/libc.so.6 | grep -i "GNU C Library"
```

输出：

```
GNU C Library (Ubuntu GLIBC 2.43-2ubuntu2.4) stable release version 2.43.
```

版本号与发行包名（Ubuntu GLIBC 2.43-2ubuntu2.4）都在。拿着这串去找一模一样的文件：本机恰好同版就直接用；不同就按发行版和包名下载对应的 deb（Ubuntu 系在 packages.ubuntu.com 或 launchpad 上找），解出 libc 与配套 ld。题目附带 libc 时这一步可以整个跳过，但文件到手后仍值得跑一遍确认它自称的版本。

### 6.3 方法二：双符号偏移差指纹

没有版本串可用时（例如手上只有两个泄露值），用两个符号的差值当指纹。由 3.1，两个泄露值相减，基址被消掉：

$$\text{leak}_1 - \text{leak}_2 = \text{offset}_1 - \text{offset}_2 \tag{3.3}$$

右边是==这一版 libc 的常量==。本地 libc 的 puts − system：

```python
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
print('指纹 puts-system  =', hex(libc.symbols['puts'] - libc.symbols['system']))
```

输出：

```
指纹 puts-system  = 0x32580
```

换个 libc 这就是另一个数——差值相等才可能是同一版。实践中更常用的是**低 12 位指纹**：内存按页管理，x86-64 页大小 0x1000（4096 字节 = 2^12），==地址低 12 位是页内偏移，随机化动不到它==（12 位 = 1.5 字节，社区常说"泄露值只有低 1.5 字节可信"）。于是每个泄露值能给指纹库贡献 3 位十六进制数：把 puts 与另一个常用符号（read、write 这类程序必调的函数）的低 12 位拿去检索，命中的候选版本往往只剩一两个。

> [!info]- 为什么低 12 位不随机
> mmap 分配的起点只能落在页边界上，libc 映射的基址低 12 位永远是 0（6.1 三次输出的结尾都是 000）。leak = 基址 + 偏移，基址低 12 位为 0，所以 leak 低 12 位就是偏移低 12 位本身，与基址落在哪个页无关。

6.4 的输出里有现成的对账：leak 低 12 位 0x860 与偏移低 12 位 0x860 相同——不管基址怎么随机，这条恒成立。

### 6.4 手工匹配完整流程

把全流程走一遍。环境设定：演示机器的系统 libc 就是 6.2 查到的 Ubuntu GLIBC 2.43。本地演示没有远程服务，用 `setarch -R`（util-linux 的工具，`-R` 关闭地址随机化）起进程读出它的真实基址；脚本按 3.1 生成"泄露值"，再==只凭泄露值和偏移==把基址算回来，与真实值对照：

```python
#!/usr/bin/env python3
# p3_match.py —— 手工 libc 匹配：泄露 -> 减偏移 -> 算基址 -> 检查页对齐
import sys
from pwn import *
context.log_level = 'error'

base = int(sys.argv[1], 16)          # setarch -R 下的真实基址，用来生成并核对“泄露地址”
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
off_puts   = libc.symbols['puts']
off_system = libc.symbols['system']
off_binsh  = next(libc.search(b'/bin/sh\x00'))

leak = base + off_puts               # 等价于 ret2plt 泄露回来的 puts 真实地址

print(f'泄露的 puts 地址          leak          = {leak:#x}')
print(f'puts 的 libc 偏移         offset        = {off_puts:#x}')
calc = leak - off_puts
print(f'推算的 libc 基址          leak - offset = {calc:#x}')
print(f'推算基址的低 12 位                      = {calc & 0xfff:#05x}  （页对齐则必须为 0x000）')
print(f'leak 低 12 位 {leak & 0xfff:#05x} == offset 低 12 位 {off_puts & 0xfff:#05x} -> {leak & 0xfff == off_puts & 0xfff}')
print(f'推算基址 == 真实基址                    = {calc == base}')
print(f'由基址算 system 真实地址                = {calc + off_system:#x}')
print(f'由基址算 /bin/sh 真实地址               = {calc + off_binsh:#x}')
leak2 = base + off_system
print(f'双符号指纹：leak-leak2 = {leak - leak2:#x}，偏移差 = {off_puts - off_system:#x}，相等 -> {leak - leak2 == off_puts - off_system}')
```

```bash
BASE=$(setarch -R sh -c 'grep "libc.so.6" /proc/self/maps' | head -1 | cut -d- -f1)
echo "libc base = 0x$BASE"
python3 p3_match.py "0x$BASE"
```

输出：

```
libc base = 0x7ffff7c00000
泄露的 puts 地址          leak          = 0x7ffff7c8e860
puts 的 libc 偏移         offset        = 0x8e860
推算的 libc 基址          leak - offset = 0x7ffff7c00000
推算基址的低 12 位                      = 0x000  （页对齐则必须为 0x000）
leak 低 12 位 0x860 == offset 低 12 位 0x860 -> True
推算基址 == 真实基址                    = True
由基址算 system 真实地址                = 0x7ffff7c5c2e0
由基址算 /bin/sh 真实地址               = 0x7ffff7ddb799
双符号指纹：leak-leak2 = 0x32580，偏移差 = 0x32580，相等 -> True
```

对照读：

- 泄露值 0x7ffff7c8e860 与 2.4 GDB 看到的 GOT 槽位解析值一致——GDB 默认也关 ASLR，两边是同一个固定布局；
- `leak - offset` 减回的基址低 12 位为 0（页对齐），且与真实基址相等。==拿到赛题的泄露值做完减法，先检查低 12 位是不是 0==：不是 0，说明偏移用错了版本，或泄露收的字节不全；
- 基址一到手，system 与 "/bin/sh" 的真实地址各加一个偏移就出来，[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 的 payload 用它们组装。

偏移表不靠 pwntools 也能拿——readelf 直接读符号表，st_value 列就是相对基址的偏移（[[R04-可执行文件格式ELF与PE#1.4 符号表：.symtab 与 .dynsym|R04 1.4]]）：

```bash
readelf -sW /usr/lib/x86_64-linux-gnu/libc.so.6 | grep -E ' (puts|system)(@@GLIBC|@GLIBC)'
```

输出：

```
   237: 000000000008e860   558 FUNC    GLOBAL DEFAULT   15 puts@@GLIBC_2.2.5
  1064: 000000000005c2e0    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```

`/bin/sh` 不是符号，用 strings 带偏移搜（`-t x` 列出文件偏移，[[R04-可执行文件格式ELF与PE#2.2 符号已删，地址还在|R04 2.2]]用过这个参数）：

```bash
strings -t x /usr/lib/x86_64-linux-gnu/libc.so.6 | grep '/bin/sh'
```

输出：

```
 1db799 /bin/sh
```

0x1db799 与 pwntools 的结果一致——libc 这类共享库的 LOAD 段里，代码与只读数据的文件偏移和虚拟地址数值相同（`readelf -l` 看 p_offset 与 p_vaddr 的对应，[[05-ELF文件格式与链接#2. 两个视角：节与段|05 章第 2 节]]）。

做题时的完整流程收拢成五步：

1. ret2plt 拿到泄露值（第 4 节）；
2. 题目给了 libc → 跳到 6.6；没给 → 低 12 位指纹检索（6.3、6.5）确定版本；
3. 从确定版本的 libc 里查泄露函数、system、"/bin/sh" 的偏移（pwntools 或 readelf / strings）；
4. 基址 = 泄露值 − 对应偏移（3.2），检查低 12 位为 0；
5. 目标地址 = 基址 + 目标偏移，组装 payload（[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]）。

### 6.5 LibcSearcher 与 libc-database

6.3 的指纹检索有现成工具。LibcSearcher 是 pip 包：

```bash
pip3 install --break-system-packages -q LibcSearcher
python3 -c "from LibcSearcher import LibcSearcher; print('LibcSearcher 导入成功')"
```

输出：

```
LibcSearcher 导入成功
```

用法示意（首次检索会自动下载符号数据库，需要等待）：

```python
libc   = LibcSearcher('puts', leak & 0xfff)   # 用低 12 位检索候选版本
base   = leak - libc.dump('puts')             # 该版 libc 的 puts 偏移，套 3.2
system = base + libc.dump('system')
```

它的数据来自 libc-database——GitHub 上的开源工程（niklasb/libc-database），收录常见发行版的 libc 及各符号偏移，clone 到本地后可以用 `./find puts 860 write 5c0` 这类命令按低 12 位检索（参数是各符号泄露值的低 12 位，写成 3 位十六进制）；也有基于它的在线检索站点（如 libc.rip）。检索时多给一两个符号的低 12 位，能把候选压到唯一。

> [!info]- 检索匹配不上时
> 候选为空或太多，常见原因：泄露符号太冷门（数据库没收）、低 12 位抄错（先用 6.4 第 4 步的判据自检）、远程用了自行编译的 libc（少数题会魔改，此时只能依赖题目附件）。检索是辅助手段，6.4 的手工流程不依赖任何工具库。

### 6.6 题目自带 libc 时

题目给了 libc.so.6，识别环节整个跳过——附件就是标准答案：

```python
libc = ELF('./libc.so.6', checksec=False)     # 题目附件，路径按实际改
puts_off   = libc.symbols['puts']
system_off = libc.symbols['system']
binsh_off  = next(libc.search(b'/bin/sh\x00'))
```

泄露值减附件偏移得基址（3.2），基址加目标偏移得 system 与 "/bin/sh" 的远程真实地址。本地调试用同一份附件，按 5.3 patchelf 换载，保证本地进程实际加载的 libc 与算偏移用的完全一致。==本地调通与远程命中用的是同一套偏移表==——这就是 [[P01-PWN导论与缓解机制全景|P1]] 5.6 节"附件与远程是同一个程序"在 libc 维度上的含义。

## 7. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| GDB 断在 puts（libc 内部）时查 GOT，槽位已经是 libc 地址 | 断晚了：解析发生在 call 与跳进 libc 之间。断点下在 call 指令或 `puts@plt` 上（2.4），对比第二次调用前的槽位值 |
| pwntools 的 `plt['puts']` 与 objdump 标签差 4 字节 | pwntools 指向 `endbr64` 之后的 `jmp` 指令，两者都能当 puts@plt 用（第 4 节的 warning） |
| 算出的基址低 12 位不是 0 | 泄露少收或多收了字节，或偏移用了另一版 libc 的偏移表。先核对收字节数（6 字节补零），再核对版本（6.4） |
| LibcSearcher 查不到候选 | 指纹符号太冷门、低位抄错或数据库没覆盖该版本。换常用符号多给一组低 12 位，或回退手工流程（6.5 的折叠框） |
| patchelf 之后运行报 No such file or directory | `--set-interpreter` 的路径写错或文件没拷到位，`ldd target` 看两行各解析到了哪里（5.3） |
| 换上附件 libc 后程序起不来或行为异常 | libc 与 ld 版本不配对，两个文件必须取自题目同一份附件（5.2） |
| checksec 报 Full RELRO，想改 GOT | 此路不通：full 下整张 GOT 只读（第 3 节）。泄露加 ROP 的路线不受影响，见 [[P07-ret2libc-ret2syscall-ret2shellcode\|P7]] |
| puts 泄露只收到 6 个字节 | 正常：libc 地址最高两个字节是 `00 00`，puts 遇 `\0` 停。`u64(recv.ljust(8, b'\x00'))` 补齐（第 4 节） |
| PIE 程序里 `ELF().got['puts']` 的值和 GDB 里看到的对不上 | pwntools 给的是文件内偏移，运行期要加基址；PIE 的处理 [[P04-Linux安全缓解机制\|P4]] |

