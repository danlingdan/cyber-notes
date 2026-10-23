---
chapter: 逆向工程
section: 虚拟机保护（VM）逆向
order: 212
tags:
  - CTF
  - 逆向工程
  - RE
  - VM
publish: true
---

# R12 虚拟机保护（VM）逆向
## Virtual Machine Protection: Custom VM Reversing

> [!info]- 章节信息
> **所属方向**：逆向工程 ｜ **难度阶段**：L3 进阶专题期 ｜ **前置要求**：[[R11-代码混淆花指令与OLLVM|R11]] · [[R06-动态调试GDB与x64dbg|R06]] · [[R03-x86与x64汇编精要复习|R03]]
> **本章目标**：理解 VM 保护的字节码、分发器、handler 三要素；能从二进制里识别 VM 结构；对一个小型自定义 VM 完整走通五步流程——识别、定位分发器与 handler 表、trace 字节码、翻译语义、逆推正确输入并拿 flag。先说清楚难度定位：==VM 逆向是 RE 方向的压轴题型==，本章解决的是"小型自定义 VM 怎么拆"；VMProtect 这一档商业壳的完整翻译超出本章范围，第 8 节给概览与进阶路径。

## 1. VM 保护：把程序搬进另一套指令系统

### 1.1 原理与三要素

[[R08-CrackMe经典题型|R08]]里的 crackme，校验逻辑编译成 x86 指令，由 CPU 直接执行；[[R11-代码混淆花指令与OLLVM|R11]]的混淆手段让这些 x86 指令变得难读，但它们始终是 x86。VM 保护换了一条路：==把校验逻辑先翻译成一套自定义指令的字节序列，运行时由程序自带的解释器逐条执行==。x86 层面剩下的只有解释器本身，业务逻辑全部落在那串字节里。

这套结构有三个组成部分，习惯上叫三要素：

| 要素 | 是什么 | 在二进制里的形态 |
| ---- | ---- | ---- |
| 字节码（bytecode） | 原程序逻辑翻译成的自定义指令序列 | 一段按 x86 反汇编不出合理结果的字节数组 |
| 分发器（dispatch loop） | 取指-译码-执行的主循环 | 一段反复执行的循环：读计数器、按它取字节、查表、call 寄存器 |
| handler | 每条字节码的语义实现 | 一群不调库函数、共享同一组状态变量的小函数 |

一次校验的执行路径变成：分发器从字节码数组取出一个操作码（opcode），用它在 handler 表里索引出一个函数，call 进去执行语义，回到分发器取下一条。==原程序的一条运算，现在由"一条字节码 + 一次查表 + 一个 handler"合作完成==。

### 1.2 为什么 VM 保护难逆

三个原因，一个比一个根本：

- **语义间接化**。原生的 `xor eax,1` 一条指令读完语义就知道了；VM 里同一个语义要经过"取指 → 查表 → handler"三层间接。静态反汇编读到的每条 x86 指令都属于解释器的机制，没有一条直接描述业务逻辑。
- **体积膨胀**。一条字节码在宿主上摊开是十几到几十条 x86（取数、索引、写状态、推进计数器）；原本几十条指令的校验函数，变成"一个解释器 + 一大段字节码"。
- **结构可变**。opcode 编号、handler 划分、指令编码宽度、虚拟寄存器数量，全部是自定义的，换一道题就换一套。==上一题记下的 opcode 表对下一题无效==，能复用的只有方法论。

还有一层与 [[R09-加壳与脱壳|R09]] 的本质区别要分清：压缩壳（UPX 一类）运行前把原始代码还原出来，dump 一次就拿到了 x86；VM 保护不还原，==程序从头到尾都以字节码形态运行，"脱"没有目标==，只能翻译。

### 1.3 本章怎么走：先造一台，再拆一台

VM 题的难点在于结构是自定义的，每一步都没有现成答案可对照。所以本章的教具是一台自己写的最小 VM：第 2 节给出全部源码，用它做一个"输入经 VM 程序校验"的 crackme；从第 3 节起切换视角，==当作只拿到一个陌生二进制==，按固定五步走完整个流程：

1. **识别**：认出二进制里有 VM（第 3 节）；
2. **定位**：找到分发器与 handler 表，建立 opcode → handler 映射（第 4 节）；
3. **trace**：记录字节码的执行序列（第 5 节）；
4. **翻译**：把字节码逐条标注成可读的伪汇编（第 6 节）；
5. **逆推**：还原校验逻辑，算出正确输入，运行拿 flag（第 7 节）。

每一步的命令、输出、结论全部来自这台 VM——它就是标准答案，走错了能立刻发现。赛题的 VM 结构各不相同，五步流程不变。

## 2. 教具：一个最小自定义 VM

### 2.1 指令集与编码设计

这台 VM 有 8 个 32 位虚拟寄存器 `r0`–`r7`、一段按字节编址的虚拟数据段 `vmem`、一个虚拟栈，外加虚拟程序计数器 `vpc` 和一个相等标志 `EQ`（由 CMP 设置，由 JZ 读）。指令集 12 条，编码==定长 4 字节 `[opcode][a][b][c]`==：

| opcode | 指令 | 操作数 | 语义 |
| ---- | ---- | ---- | ---- |
| 0x00 | HALT | 无 | 停机 |
| 0x01 | MOVI a, imm | a=寄存器，b=立即数 | reg[a] = imm |
| 0x02 | XOR a, b, c | 三个寄存器 | reg[a] = reg[b] ^ reg[c] |
| 0x03 | ADD a, b, c | 三个寄存器 | reg[a] = reg[b] + reg[c] |
| 0x04 | LOAD a, addr | a=寄存器，b=虚拟地址 | reg[a] = vmem[b]（取 1 字节，零扩展） |
| 0x05 | STORE a, addr | a=寄存器，b=虚拟地址 | vmem[b] = reg[a] 的低字节 |
| 0x06 | READ a | a=寄存器 | reg[a] = 下一个输入字符；用尽得 0xFFFFFFFF |
| 0x07 | CMP a, b | 两个寄存器 | reg[a] == reg[b] 则置 EQ 标志 |
| 0x08 | JZ addr | a=目标（字节偏移） | EQ 为 1 则 vpc = addr |
| 0x09 | JMP addr | a=目标（字节偏移） | vpc = addr |
| 0x0A | PUSH a | a=寄存器 | vstack[vsp++] = reg[a] |
| 0x0B | POP a | a=寄存器 | reg[a] = vstack[--vsp] |

操作数槽位的分工是自定义约定：==a 槽放主寄存器，b 槽放第二操作数（立即数、虚拟地址或寄存器），c 槽放第三个寄存器==；跳转类把目标地址放在 a 槽。除跳转外，每条指令执行完 vpc 统一加 4。

VM 程序与宿主程序之间只有两个交接点：READ 从宿主准备好的输入缓冲区取字符；VM 程序把"是否全部通过"留在 r7（0 为通过），宿主的 main 读 reg[7] 决定输出。

### 2.2 完整源码

`minivm.c` 全文。字节码数组就是 VM 程序本体：3 条序言，之后 6 个结构相同的"字符块"（每块 8 条、32 字节），最后 4 条收尾，共 55 条、220 字节。这段程序做的事在第 6 节翻译之后才揭晓，这里先只看机器：

```c
/* minivm.c —— 教学用最小自定义 VM：一个"输入经 VM 程序校验"的 crackme
 * 平台：x86-64 Linux，宿主调用约定 System V AMD64 ABI
 * 编译：gcc -O0 -fno-pie -no-pie -g minivm.c -o minivm
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ---------- 虚拟机状态 ---------- */
static uint32_t reg[8];       /* 8 个虚拟寄存器 r0..r7 */
static uint8_t  vmem[256];    /* 虚拟数据段：按字节编址 */
static uint32_t vstack[64];   /* 虚拟栈 */
static uint32_t vsp;          /* 虚拟栈指针 */
static uint32_t vpc;          /* 虚拟程序计数器 */
static uint32_t flag_eq;      /* CMP 留下的相等标志 */
static int      running;      /* 主循环开关 */

static char     input[64];    /* 待校验的输入 */
static int      in_pos;       /* READ 的读取位置 */

/* ---------- 虚拟数据段：期望值表从 vmem[0x40] 开始 ---------- */
static const uint8_t vdata[] = {
    0x5A, 0x07, 0x5B, 0x61, 0x45, 0x5F
};

/* ---------- 字节码：定长编码，每条 4 字节 [opcode][a][b][c] ---------- */
static const uint8_t prog[] = {
    /* 0x00 */ 0x01, 0x07, 0x00, 0x00,
    /* 0x04 */ 0x01, 0x01, 0x37, 0x00,
    /* 0x08 */ 0x02, 0x05, 0x05, 0x05,
    /* ---- 字符块 i = 0，之后 i = 1..5 各重复一块（每块 32 字节）---- */
    /* 0x0C */ 0x06, 0x00, 0x00, 0x00,
    /* 0x10 */ 0x02, 0x02, 0x00, 0x01,
    /* 0x14 */ 0x01, 0x03, 0x00, 0x00,
    /* 0x18 */ 0x03, 0x02, 0x02, 0x03,
    /* 0x1C */ 0x04, 0x04, 0x40, 0x00,
    /* 0x20 */ 0x07, 0x02, 0x04, 0x00,
    /* 0x24 */ 0x08, 0x2C, 0x00, 0x00,
    /* 0x28 */ 0x01, 0x07, 0x01, 0x00,
    /* 0x2C */ 0x06, 0x00, 0x00, 0x00,
    /* 0x30 */ 0x02, 0x02, 0x00, 0x01,
    /* 0x34 */ 0x01, 0x03, 0x01, 0x00,
    /* 0x38 */ 0x03, 0x02, 0x02, 0x03,
    /* 0x3C */ 0x04, 0x04, 0x41, 0x00,
    /* 0x40 */ 0x07, 0x02, 0x04, 0x00,
    /* 0x44 */ 0x08, 0x4C, 0x00, 0x00,
    /* 0x48 */ 0x01, 0x07, 0x01, 0x00,
    /* 0x4C */ 0x06, 0x00, 0x00, 0x00,
    /* 0x50 */ 0x02, 0x02, 0x00, 0x01,
    /* 0x54 */ 0x01, 0x03, 0x02, 0x00,
    /* 0x58 */ 0x03, 0x02, 0x02, 0x03,
    /* 0x5C */ 0x04, 0x04, 0x42, 0x00,
    /* 0x60 */ 0x07, 0x02, 0x04, 0x00,
    /* 0x64 */ 0x08, 0x6C, 0x00, 0x00,
    /* 0x68 */ 0x01, 0x07, 0x01, 0x00,
    /* 0x6C */ 0x06, 0x00, 0x00, 0x00,
    /* 0x70 */ 0x02, 0x02, 0x00, 0x01,
    /* 0x74 */ 0x01, 0x03, 0x03, 0x00,
    /* 0x78 */ 0x03, 0x02, 0x02, 0x03,
    /* 0x7C */ 0x04, 0x04, 0x43, 0x00,
    /* 0x80 */ 0x07, 0x02, 0x04, 0x00,
    /* 0x84 */ 0x08, 0x8C, 0x00, 0x00,
    /* 0x88 */ 0x01, 0x07, 0x01, 0x00,
    /* 0x8C */ 0x06, 0x00, 0x00, 0x00,
    /* 0x90 */ 0x02, 0x02, 0x00, 0x01,
    /* 0x94 */ 0x01, 0x03, 0x04, 0x00,
    /* 0x98 */ 0x03, 0x02, 0x02, 0x03,
    /* 0x9C */ 0x04, 0x04, 0x44, 0x00,
    /* 0xA0 */ 0x07, 0x02, 0x04, 0x00,
    /* 0xA4 */ 0x08, 0xAC, 0x00, 0x00,
    /* 0xA8 */ 0x01, 0x07, 0x01, 0x00,
    /* 0xAC */ 0x06, 0x00, 0x00, 0x00,
    /* 0xB0 */ 0x02, 0x02, 0x00, 0x01,
    /* 0xB4 */ 0x01, 0x03, 0x05, 0x00,
    /* 0xB8 */ 0x03, 0x02, 0x02, 0x03,
    /* 0xBC */ 0x04, 0x04, 0x45, 0x00,
    /* 0xC0 */ 0x07, 0x02, 0x04, 0x00,
    /* 0xC4 */ 0x08, 0xCC, 0x00, 0x00,
    /* 0xC8 */ 0x01, 0x07, 0x01, 0x00,
    /* 0xCC */ 0x07, 0x07, 0x05, 0x00,
    /* 0xD0 */ 0x08, 0xD8, 0x00, 0x00,
    /* 0xD4 */ 0x01, 0x07, 0x01, 0x00,
    /* 0xD8 */ 0x00, 0x00, 0x00, 0x00,
};

/* ---------- 12 个 handler：opcode 对应的指令语义 ----------
 * FETCH(n) 取本条指令的第 n 字节；除跳转外，handler 统一 vpc += 4 */
#define FETCH(n)  prog[vpc + (n)]

static void h_halt(void)  { running = 0; }
static void h_movi(void)  { reg[FETCH(1)] = FETCH(2);                    vpc += 4; }
static void h_xor(void)   { reg[FETCH(1)] = reg[FETCH(2)] ^ reg[FETCH(3)]; vpc += 4; }
static void h_add(void)   { reg[FETCH(1)] = reg[FETCH(2)] + reg[FETCH(3)]; vpc += 4; }
static void h_load(void)  { reg[FETCH(1)] = vmem[FETCH(2)];              vpc += 4; }   /* 读 1 字节，零扩展 */
static void h_store(void) { vmem[FETCH(2)] = (uint8_t)reg[FETCH(1)];     vpc += 4; }   /* 写低 1 字节 */
static void h_read(void)
{
    if (input[in_pos] != '\0')
        reg[FETCH(1)] = (uint8_t)input[in_pos++];   /* 取一个输入字符 */
    else
        reg[FETCH(1)] = 0xFFFFFFFFu;                /* 输入用尽 */
    vpc += 4;
}
static void h_cmp(void)   { flag_eq = (reg[FETCH(1)] == reg[FETCH(2)]);  vpc += 4; }
static void h_jz(void)    { if (flag_eq) vpc = FETCH(1); else vpc += 4; }
static void h_jmp(void)   { vpc = FETCH(1); }
static void h_push(void)  { vstack[vsp++] = reg[FETCH(1)];               vpc += 4; }
static void h_pop(void)   { reg[FETCH(1)] = vstack[--vsp];               vpc += 4; }

/* ---------- handler 表：下标即 opcode ---------- */
typedef void (*handler_t)(void);
static const handler_t table[12] = {
    h_halt,    /* 0x00 */
    h_movi,    /* 0x01 */
    h_xor,     /* 0x02 */
    h_add,     /* 0x03 */
    h_load,    /* 0x04 */
    h_store,   /* 0x05 */
    h_read,    /* 0x06 */
    h_cmp,     /* 0x07 */
    h_jz,      /* 0x08 */
    h_jmp,     /* 0x09 */
    h_push,    /* 0x0A */
    h_pop,     /* 0x0B */
};

/* ---------- 初始化：清状态 + 装载虚拟数据段 ---------- */
static void vm_start(void)
{
    memset(reg, 0, sizeof reg);
    memset(vmem, 0, sizeof vmem);
    memcpy(vmem + 0x40, vdata, sizeof vdata);
    vsp = 0;
    vpc = 0;
    flag_eq = 0;
    running = 1;
}

/* ---------- 分发循环：取指 - 查表 - 执行 ---------- */
void vm_run(void)
{
    while (running)
        table[prog[vpc]]();
}

int main(void)
{
    printf("key: ");
    if (scanf("%63s", input) != 1)
        return 1;
    vm_start();
    vm_run();
    if (reg[7] == 0)
        printf("Correct! flag{tr4c3_th3_vm}\n");
    else
        printf("Wrong key\n");
    return 0;
}
```

两点设计说明。其一，PUSH/POP 在这段 VM 程序里没有被用到，但指令和 handler 都在——==逆向时要把表里每一项都标注，包括没执行到的==。其二，分发循环只有一行：取指（`prog[vpc]`）、查表（`table[...]`）、执行（函数调用）压缩在一个表达式里，第 3 节会看到它编译后的样子。

### 2.3 编译与运行

```bash
gcc -O0 -fno-pie -no-pie -g minivm.c -o minivm
printf 'aaaaaa\n' | ./minivm
printf 'm1nivm\n' | ./minivm
```

输出：

```
key: Wrong key
key: Correct! flag{tr4c3_th3_vm}
```

输入 m1nivm 通过校验，其余输入被拒（包括大小写不同和长度不够的变体）。`-O0 -fno-pie -no-pie` 的用意 [[R03-x86与x64汇编精要复习#1. 本章范围与编译基线|R03 第 1 节]]讲过：关优化让机器码与源码逐行对应，关 PIE 让地址固定可引用。

> [!info]- `-g` 与真实赛题的差别
> 本章保留 `-g` 调试信息，GDB 里才能直接写 `vpc`、`prog`、`reg` 这些变量名。真实赛题的 VM 题几乎总是 strip 过的：名字全部消失，只剩地址。这不影响流程——第 4 节会看到每个变量名都对应一个确定的地址，把名字换成地址，命令照样工作（[[R06-动态调试GDB与x64dbg#3.1 软件断点：break 与 0xCC|R06 3.1]] 的 `b *地址`）。

## 3. 识别 VM：分发循环的三个特征

从这一节起，视角切换为"只拿到 minivm 这个文件"。先做常规侦察：`file` 确认格式（ELF 64 位、动态链接），`strings` 扫字符串：

```bash
strings minivm | grep -E 'key|Correct|Wrong'
```

输出：

```
key: 
Correct! flag{tr4c3_th3_vm}
Wrong key
```

字符串只有提示语。[[R08-CrackMe经典题型|R08]]里"搜提示语 → 找引用 → 读校验函数"的路线在这里只走前半：能找到引用这些字符串的 main，但 main 附近没有校验逻辑——只有一次对 `vm_run` 的调用。==校验逻辑不在这台机器的指令里==。

VM 的辨识特征集中在三个形状上。用 objdump 找到反复出现的那段循环（`objdump -d -M intel minivm` 全文搜索，`vm_run` 是循环所在）：

```bash
objdump -d -M intel minivm | sed -n '/<vm_run>:/,/^$/p'
```

输出（x86-64 Linux · System V AMD64 ABI · Intel 语法，逐行注释）：

```asm
0000000000401603 <vm_run>:
  401603:  f3 0f 1e fa              endbr64
  401607:  55                       push   rbp
  401608:  48 89 e5                 mov    rbp,rsp
  40160b:  eb 1e                    jmp    40162b                      ; 先跳去循环条件（R03 7.3 的循环骨架）
  40160d:  8b 05 71 2c 00 00        mov    eax,DWORD PTR [rip+0x2c71]  # 404284 <vpc>   ; 读虚拟程序计数器
  401613:  89 c0                    mov    eax,eax
  401615:  0f b6 80 40 20 40 00     movzx  eax,BYTE PTR [rax+0x402040] ; 取指：字节码数组在 0x402040
  40161c:  0f b6 c0                 movzx  eax,al
  40161f:  48 98                    cdqe
  401621:  48 8b 04 c5 20 21 40 00  mov    rax,QWORD PTR [rax*8+0x402120]              ; 查表：handler 表在 0x402120，下标 ×8
  401629:  ff d0                    call   rax                         ; 分发：进入 opcode 对应的 handler
  40162b:  8b 05 5b 2c 00 00        mov    eax,DWORD PTR [rip+0x2c5b]  # 40428c <running>  ; 循环条件
  401631:  85 c0                    test   eax,eax
  401633:  75 d8                    jne    40160d                      ; running != 0 → 回到取指
  401635:  90                       nop
  401636:  90                       nop
  401637:  5d                       pop    rbp
  401638:  c3                       ret
```

三个特征在这 15 行里全部出现：

- **取指循环**：一小段代码反复执行——读一个计数器（`vpc`，地址 0x404284）、按它从一个固定地址取 1 字节（`BYTE PTR [rax+0x402040]`）、循环尾一条 `jne` 跳回。循环体没有边界变化，与 [[R03-x86与x64汇编精要复习#7.3 形状三：循环|R03 7.3]] 的循环形状一致，但循环变量驱动的是"取字节码"而不是数组运算。
- **寄存器间接调用**：`call rax`，目标要运行时才知道——[[R02-C语言与内存模型回顾#5. 函数指针、间接调用与那张地址表|R02 第 5 节]]的函数指针。往前看 rax 的来源：`mov rax,QWORD PTR [rax*8+0x402120]`，==以刚才取到的字节为下标、从一个固定地址的数组里取函数指针，比例因子 8 正是 64 位指针宽度==。
- **一段反汇编不出语义的字节数组**：0x402040 处的 220 字节，`strings` 无意义，按 x86 反汇编也读不出连贯逻辑（开头 `01 07 00 00 01 01 37 00`，按 x86 会拆出 `add DWORD PTR [rdi],eax` 这类与字节码本意无关的指令）。

> [!note] 三特征速查
> 看到"计数器 → 取 1 字节 → ×8 查表 → call 寄存器 → 回跳"的循环加一个 8 字节对齐的地址数组，==先按 VM 处理==。没有函数名时也一样：形状本身就是签名。商业壳有现成签名可查（[[R09-加壳与脱壳#3. 查壳：工具与手工特征|R09 第 3 节]]的查壳思路），自定义 VM 没有签名库可撞，识别靠的就是这套结构。

> [!info]- 本章输出里的函数名从哪来
> 上面的输出里出现了 `<vm_run>`、`<vpc>` 这些名字，它们来自 `-g` 调试信息。真实赛题 strip 之后同一段反汇编长这样：`mov eax,DWORD PTR [rip+0x2c71]` 后面没有 `# 404284 <vpc>` 注释，地址要自己跟。判断只靠形状，名字是奢侈品。

## 4. 定位分发器与 handler 表

### 4.1 从 call rax 找到分发点

第 3 节的反汇编已经给出全部坐标：

| 反汇编里看到的 | 结论 |
| ---- | ---- |
| `movzx eax,BYTE PTR [rax+0x402040]` | 0x402040 是字节码数组首地址 |
| `mov rax,QWORD PTR [rax*8+0x402120]` | 0x402120 是 handler 表首地址，每项 8 字节 |
| `call rax`（地址 0x401629） | 分发点：每条字节码都从这里进入 handler |
| `jne 40160d` | 循环头在 0x40160d |

==trace 的断点就下在分发点==：0x401629 的 `call rax` 执行前，rax 已经是"本条 opcode 对应的 handler"，0x402040 处的 `prog[vpc]` 就是本条 opcode——取指之后、执行之前，正是观察的窗口。

### 4.2 dump 出 opcode → handler 映射

GDB 脚本：断在 vm_run 入口，跑起来后把 handler 表整个 dump 出来，再把 12 个表项地址逐一问 GDB 是哪个符号（[[R06-动态调试GDB与x64dbg|R06]] 的命令集在这里原样适用）：

```bash
# tbl.gdb
set pagination off
break vm_run
run < in_ok.txt
x/12gx 0x402120
info symbol 0x401196
info symbol 0x4011ab
info symbol 0x4011f8
info symbol 0x40126e
info symbol 0x4012e4
info symbol 0x40133d
info symbol 0x401392
info symbol 0x40141e
info symbol 0x401482
info symbol 0x4014c3
info symbol 0x4014e9
info symbol 0x40153a
```

（后 12 行 info symbol 的地址来自 `x/12gx` 的输出——先 dump 表，再逐项问符号。）

```bash
gdb -q -batch -x tbl.gdb ./minivm
```

输出：

```
Breakpoint 1 at 0x40160b: file minivm.c, line 141.

Breakpoint 1, vm_run () at minivm.c:141
141	    while (running)
0x402120 <table>:	0x0000000000401196	0x00000000004011ab
0x402130 <table+16>:	0x00000000004011f8	0x000000000040126e
0x402140 <table+32>:	0x00000000004012e4	0x000000000040133d
0x402150 <table+48>:	0x0000000000401392	0x000000000040141e
0x402160 <table+64>:	0x0000000000401482	0x00000000004014c3
0x402170 <table+80>:	0x00000000004014e9	0x000000000040153a
h_halt in section .text of /tmp/r12bk/minivm
h_movi in section .text of /tmp/r12bk/minivm
h_xor in section .text of /tmp/r12bk/minivm
h_add in section .text of /tmp/r12bk/minivm
h_load in section .text of /tmp/r12bk/minivm
h_store in section .text of /tmp/r12bk/minivm
h_read in section .text of /tmp/r12bk/minivm
h_cmp in section .text of /tmp/r12bk/minivm
h_jz in section .text of /tmp/r12bk/minivm
h_jmp in section .text of /tmp/r12bk/minivm
h_push in section .text of /tmp/r12bk/minivm
h_pop in section .text of /tmp/r12bk/minivm
```

整理成映射表——==opcode 与 handler 一一对应，表的下标就是 opcode==：

| opcode | 表项地址 | handler | opcode | 表项地址 | handler |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 0x00 | 0x401196 | h_halt | 0x06 | 0x401392 | h_read |
| 0x01 | 0x4011ab | h_movi | 0x07 | 0x40141e | h_cmp |
| 0x02 | 0x4011f8 | h_xor | 0x08 | 0x401482 | h_jz |
| 0x03 | 0x40126e | h_add | 0x09 | 0x4014c3 | h_jmp |
| 0x04 | 0x4012e4 | h_load | 0x0A | 0x4014e9 | h_push |
| 0x05 | 0x40133d | h_store | 0x0B | 0x40153a | h_pop |

> [!info]- 没有 -g 时怎么办
> strip 过的程序 `info symbol` 只会说"在 .text 里"，给不出名字。此时把每个表项地址当普通函数对待：`objdump -d` 或 IDA 里逐个读反汇编，自己起名字（`sub_401482_jz` 这类）。映射关系本身不受影响——opcode 到地址的对应是从表里 dump 出来的，不依赖符号。

### 4.3 读 handler 反汇编定语义

映射表有了，语义要从 handler 的机器码里读。看三个代表（x86-64 Linux · System V AMD64 ABI · Intel 语法，objdump 输出加注释）：

h_movi（opcode 0x01）——一条"装载立即数"指令的实现：

```asm
00000000004011ab <h_movi>:
  4011ab:  f3 0f 1e fa           endbr64
  4011af:  55                    push   rbp
  4011b0:  48 89 e5              mov    rbp,rsp
  4011b3:  8b 05 cb 30 00 00     mov    eax,DWORD PTR [rip+0x30cb]     # 404284 <vpc>
  4011b9:  83 c0 02              add    eax,0x2                        ; vpc + 2
  4011bc:  89 c0                 mov    eax,eax
  4011be:  0f b6 90 40 20 40 00  movzx  edx,BYTE PTR [rax+0x402040]    ; edx = prog[vpc+2]（立即数）
  4011c5:  8b 05 b9 30 00 00     mov    eax,DWORD PTR [rip+0x30b9]     # 404284 <vpc>
  4011cb:  83 c0 01              add    eax,0x1                        ; vpc + 1
  4011ce:  89 c0                 mov    eax,eax
  4011d0:  0f b6 80 40 20 40 00  movzx  eax,BYTE PTR [rax+0x402040]    ; eax = prog[vpc+1]（寄存器编号）
  4011d7:  0f b6 c0              movzx  eax,al
  4011da:  0f b6 d2              movzx  edx,dl
  4011dd:  48 98                 cdqe
  4011df:  89 14 85 60 40 40 00  mov    DWORD PTR [rax*4+0x404060],edx ; reg[编号] = 立即数（reg 在 0x404060，每项 4 字节）
  4011e6:  8b 05 98 30 00 00     mov    eax,DWORD PTR [rip+0x3098]     # 404284 <vpc>
  4011ec:  83 c0 04              add    eax,0x4                        ; vpc += 4
  4011ef:  89 05 8f 30 00 00     mov    DWORD PTR [rip+0x308f],eax     # 404284 <vpc>
  4011f5:  90                    nop
  4011f6:  5d                    pop    rbp
  4011f7:  c3                    ret
```

读出的语义：`reg[prog[vpc+1]] = prog[vpc+2]; vpc += 4`——第 1 字节是目标寄存器，第 2 字节是立即数，与 2.1 的 MOVI 定义一致。

h_jz（opcode 0x08）——条件跳转的实现：

```asm
0000000000401482 <h_jz>:
  40148a:  8b 05 f8 2d 00 00     mov    eax,DWORD PTR [rip+0x2df8]     # 404288 <flag_eq>
  401490:  85 c0                 test   eax,eax                        ; EQ 标志判零（R03 3.7）
  401492:  74 1d                 je     4014b1                         ; EQ=0 → 走不跳分支
  401494:  8b 05 ea 2d 00 00     mov    eax,DWORD PTR [rip+0x2dea]     # 404284 <vpc>
  40149a:  83 c0 01              add    eax,0x1
  40149d:  89 c0                 mov    eax,eax
  40149f:  0f b6 80 40 20 40 00  movzx  eax,BYTE PTR [rax+0x402040]    ; eax = prog[vpc+1]（跳转目标）
  4014a6:  0f b6 c0              movzx  eax,al
  4014a9:  89 05 d5 2d 00 00     mov    DWORD PTR [rip+0x2dd5],eax     # vpc = 目标
  4014af:  eb 0f                 jmp    4014c0
  4014b1:  8b 05 cd 2d 00 00     mov    eax,DWORD PTR [rip+0x2dcd]     # 404284 <vpc>
  4014b7:  83 c0 04              add    eax,0x4
  4014ba:  89 05 c4 2d 00 00     mov    DWORD PTR [rip+0x2dc4],eax     # vpc += 4
```

EQ 为 1 时 vpc 直接改成 `prog[vpc+1]`，为 0 时加 4 走下一条——==跳转目标放在第 1 字节，按字节偏移计==。

h_load（opcode 0x04）——只看两条关键指令就能定数据段宽度：

```asm
  401303:  0f b6 90 80 40 40 00  movzx  edx,BYTE PTR [rax+0x404080]   ; vmem 在 0x404080；BYTE PTR + movzx = 取 1 字节零扩展
  401324:  89 14 85 60 40 40 00  mov    DWORD PTR [rax*4+0x404060],edx ; 写进 4 字节的虚拟寄存器
```

把 12 个 handler 都这样过一遍，重建出的指令集与 2.1 的表完全一致——这正是先造后拆的价值：每一步都有标准答案可对照。其余 handler 里值得一提的还有 h_read：它从 0x4042a0 处的输入缓冲区按 `in_pos` 取字符，缓冲区读到 `\0` 就写 0xFFFFFFFF（反汇编里是 `test al,al` 加一个分支）。

> [!warning] 观察点要选在"取指后、执行前"
> 断在取指之前，打印的 opcode 是上一条的；断在 handler 内部，寄存器快照已经变了。==分发点 `call rax` 的前一刻（循环头 0x40160d 之后、0x401629 之前）是唯一正确的窗口==。下一节 trace 脚本的断点就选在分发那一行的源码位置，GDB 停下时指令尚未执行。

## 5. trace：记录字节码执行序列

### 5.1 trace 脚本

思路：在分发点下断点，每次命中打印"本条字节码"（vpc、opcode、handler 地址）和全部虚拟寄存器快照，然后自动放行。GDB 的断点命令块（[[R06-动态调试GDB与x64dbg#5.3 continue 与断点自动化：commands|R06 5.3]]）正好做这件事：

```bash
# trace.gdb —— 逐条记录字节码执行
set pagination off
set confirm off
break minivm.c:142
commands
silent
printf "VPC=%02x OP=%02x H=%lx R0=%08x R1=%08x R2=%08x R3=%08x R4=%08x R5=%08x R6=%08x R7=%08x EQ=%x\n", vpc, prog[vpc], (unsigned long)table[prog[vpc]], reg[0], reg[1], reg[2], reg[3], reg[4], reg[5], reg[6], reg[7], flag_eq
continue
end
run < in_ok.txt
```

`minivm.c:142` 是 `table[prog[vpc]]();` 那一行——停在它上面时取指已完成、handler 未执行，OP 列和 H 列由此可信。没有调试信息时换成 `break *0x401629`（4.1 定位到的分发指令），打印表达式里的变量名也全部换成地址。`in_ok.txt` 里是一行 m1nivm。

```bash
gdb -q -batch -x trace.gdb ./minivm | grep -c '^VPC'
```

输出：

```
48
```

正确输入下 VM 程序执行了 48 条字节码。把 grep 换成重定向就得到完整 trace 文件；错误输入（in_bad.txt 里是一行 aaaaaa，脚本 trace_bad.gdb 与 trace.gdb 只差最后的 `run < in_bad.txt`）再跑一遍：

```bash
gdb -q -batch -x trace_bad.gdb ./minivm | grep -c '^VPC'
```

输出：

```
55
```

### 5.2 读 trace

正确输入的 trace 前 12 行：

```
VPC=00 OP=01 H=4011ab R0=00000000 R1=00000000 R2=00000000 R3=00000000 R4=00000000 R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=04 OP=01 H=4011ab R0=00000000 R1=00000000 R2=00000000 R3=00000000 R4=00000000 R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=08 OP=02 H=4011f8 R0=00000000 R1=00000037 R2=00000000 R3=00000000 R4=00000000 R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=0c OP=06 H=401392 R0=00000000 R1=00000037 R2=00000000 R3=00000000 R4=00000000 R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=10 OP=02 H=4011f8 R0=0000006d R1=00000037 R2=00000000 R3=00000000 R4=00000000 R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=14 OP=01 H=4011ab R0=0000006d R1=00000037 R2=0000005a R3=00000000 R4=00000000 R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=18 OP=03 H=40126e R0=0000006d R1=00000037 R2=0000005a R3=00000000 R4=00000000 R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=1c OP=04 H=4012e4 R0=0000006d R1=00000037 R2=0000005a R3=00000000 R4=00000000 R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=20 OP=07 H=40141e R0=0000006d R1=00000037 R2=0000005a R3=00000000 R4=0000005a R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=24 OP=08 H=401482 R0=0000006d R1=00000037 R2=0000005a R3=00000000 R4=0000005a R5=00000000 R6=00000000 R7=00000000 EQ=1
VPC=2c OP=06 H=401392 R0=0000006d R1=00000037 R2=0000005a R3=00000000 R4=0000005a R5=00000000 R6=00000000 R7=00000000 EQ=1
VPC=30 OP=02 H=4011f8 R0=00000031 R1=00000037 R2=0000005a R3=00000000 R4=0000005a R5=00000000 R6=00000000 R7=00000000 EQ=1
```

正确输入的 trace 尾部 6 行：

```
VPC=bc OP=04 H=4012e4 R0=0000006d R1=00000037 R2=0000005f R3=00000005 R4=00000045 R5=00000000 R6=00000000 R7=00000000 EQ=1
VPC=c0 OP=07 H=40141e R0=0000006d R1=00000037 R2=0000005f R3=00000005 R4=0000005f R5=00000000 R6=00000000 R7=00000000 EQ=1
VPC=c4 OP=08 H=401482 R0=0000006d R1=00000037 R2=0000005f R3=00000005 R4=0000005f R5=00000000 R6=00000000 R7=00000000 EQ=1
VPC=cc OP=07 H=40141e R0=0000006d R1=00000037 R2=0000005f R3=00000005 R4=0000005f R5=00000000 R6=00000000 R7=00000000 EQ=1
VPC=d0 OP=08 H=401482 R0=0000006d R1=00000037 R2=0000005f R3=00000005 R4=0000005f R5=00000000 R6=00000000 R7=00000000 EQ=1
VPC=d8 OP=00 H=401196 R0=0000006d R1=00000037 R2=0000005f R3=00000005 R4=0000005f R5=00000000 R6=00000000 R7=00000000 EQ=1
```

停下的瞬间指令还没执行，所以==一条指令的效果要在下一行才能看到==，三个关键读法：

- **VPC 列就是控制流**。摘录第 10 行 VPC=24（JZ），下一行 VPC=2c——从 24 跳到 2c，越过了 28；尾部摘录里同样 c4 跳到 cc、d0 跳到 d8。==JZ 有没有跳、跳到哪里，直接读相邻两行==。
- **EQ 列体现 CMP 的效果**。摘录第 9 行 VPC=20 执行 CMP 时 EQ 还是 0，第 10 行已经变 1——第 9 行的比较结果是相等的。
- **寄存器快照给出数据流**。摘录第 4 行执行 READ，第 5 行 R0=0000006d（字符 m 的 ASCII）；第 5 行执行 XOR 时 R2 还是 0，第 6 行 R2=0000005a——==0x6d ^ 0x37 = 0x5a，逐字符变换在寄存器里全程可见==。

错误输入的 trace 多 7 条。摘录第一个字符块的分叉点（第 9–12 行，输入 aaaaaa 时 R0=00000061）：

```
VPC=20 OP=07 H=40141e R0=00000061 R1=00000037 R2=00000056 R3=00000000 R4=0000005a R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=24 OP=08 H=401482 R0=00000061 R1=00000037 R2=00000056 R3=00000000 R4=0000005a R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=28 OP=01 H=4011ab R0=00000061 R1=00000037 R2=00000056 R3=00000000 R4=0000005a R5=00000000 R6=00000000 R7=00000000 EQ=0
VPC=2c OP=06 H=401392 R0=00000061 R1=00000037 R2=00000056 R3=00000000 R4=0000005a R5=00000000 R6=00000000 R7=00000001 EQ=0
```

R2=0x56 与 R4=0x5a 不等，EQ 保持 0，JZ 没有跳（VPC 24 → 28），失败标记 0x28 被执行，下一行 R7 变成 1。结尾也不同：错误输入的 trace 最后是 `d0`（JZ 不跳）→ `d4`（MOVI r7, 1）→ `d8`（HALT），48 与 55 的差 7 正是 6 个失败标记加结尾多出的 1 条。

> [!info]- trace 太大时
> 每条字节码一次断点命中，trace 的速度比正常运行慢几个数量级。字节码上百万条的题，不要逐条看：先按 VPC 折叠周期（第 9 节草图的做法），或者给断点加条件（`break ... if vpc == 目标`）只停关心的位置；GDB 的 `dprintf` 也能在不真正停下的前提下打日志，代价同样是速度。

## 6. 翻译字节码：还原 VM 程序

### 6.1 从 handler 反推指令编码

trace 只给执行序列，静态翻译还需要指令的编码格式。==编码不用猜，从 handler 的取数方式反推==——4.3 的三份反汇编里每一条证据都对应一条编码事实：

| handler 反汇编里的动作 | 反推出的编码事实 |
| ---- | ---- |
| h_movi 读 `prog[vpc+1]` 当寄存器编号、读 `prog[vpc+2]` 当立即数 | 第 1 字节是寄存器槽，第 2 字节是立即数槽 |
| h_jz 直接 `vpc = prog[vpc+1]` | 跳转目标在第 1 字节，按字节偏移计 |
| h_load 用 `BYTE PTR` + movzx 读 0x404080 | 数据段按字节编址，LOAD 取 1 字节零扩展 |
| 除跳转外所有 handler 收尾 `vpc += 4` | ==定长编码：每条指令 4 字节== |
| handler 表 12 项、从 0 连续编号 | opcode 空间 0x00–0x0B |

判断定长还是变长，通用做法是把==每个 handler 的 vpc 推进量==列出来：全部相等就是定长；参差不齐就是变长，此时每个 opcode 的推进量就是它各自的长度表。

### 6.2 dump 字节码

编码定了，把字节码数组整个读出来。首地址 0x402040、长度 220 字节（`p sizeof(prog)` 可确认；没有符号时从 ELF 头算段范围，[[R04-可执行文件格式ELF与PE|R04]]的方法）：

```bash
# 追加进 tbl.gdb 的执行流程，或单独一条
x/24xb prog
```

输出：

```
0x402040 <prog>:	0x01	0x07	0x00	0x00	0x01	0x01	0x37	0x00
0x402048 <prog+8>:	0x02	0x05	0x05	0x05	0x06	0x00	0x00	0x00
0x402050 <prog+16>:	0x02	0x02	0x00	0x01	0x01	0x03	0x00	0x00
```

按 4 字节一组切：`01 07 00 00`、`01 01 37 00`、`02 05 05 05`、`06 00 00 00`、`02 02 00 01`、`01 03 00 00`——首字节查 4.2 的映射表得 MOVI、MOVI、XOR、READ、XOR、MOVI，与 trace 前六条的 OP 列完全一致。静态 dump 与动态 trace 互相印证，翻译就不容易错位。

### 6.3 逐条翻译成伪汇编

按编码规则把 220 字节全部翻过来（trace 里没执行到的失败标记也在——静态翻译覆盖全量，动态 trace 确认哪条真走到）：

```asm
; minivm 字节码的翻译结果 · VM 伪汇编（不是 x86；地址是字节码内偏移）
00: MOVI r7, 0        ; 结果寄存器清零：先假设全部字符正确
04: MOVI r1, 0x37     ; 异或密钥
08: XOR  r5, r5, r5   ; r5 = 0，结尾比较用
0C: READ r0           ; ---- 字符块 i = 0：取输入第 0 个字符（无输入得 0xFFFFFFFF）----
10: XOR  r2, r0, r1   ; r2 = 输入 ^ 0x37
14: MOVI r3, 0        ; r3 = 字符下标 i
18: ADD  r2, r2, r3   ; r2 = (输入 ^ 0x37) + i
1C: LOAD r4, 0x40     ; r4 = 期望值表第 0 项
20: CMP  r2, r4       ; 相等置 EQ 标志
24: JZ   0x2C         ; 相等 → 跳过失败标记
28: MOVI r7, 1        ; 失败标记
2C: READ r0           ; ---- 字符块 i = 1 ----
30: XOR  r2, r0, r1
34: MOVI r3, 1
38: ADD  r2, r2, r3
3C: LOAD r4, 0x41
40: CMP  r2, r4
44: JZ   0x4C
48: MOVI r7, 1
4C: READ r0           ; ---- 字符块 i = 2 ----
50: XOR  r2, r0, r1
54: MOVI r3, 2
58: ADD  r2, r2, r3
5C: LOAD r4, 0x42
60: CMP  r2, r4
64: JZ   0x6C
68: MOVI r7, 1
6C: READ r0           ; ---- 字符块 i = 3 ----
70: XOR  r2, r0, r1
74: MOVI r3, 3
78: ADD  r2, r2, r3
7C: LOAD r4, 0x43
80: CMP  r2, r4
84: JZ   0x8C
88: MOVI r7, 1
8C: READ r0           ; ---- 字符块 i = 4 ----
90: XOR  r2, r0, r1
94: MOVI r3, 4
98: ADD  r2, r2, r3
9C: LOAD r4, 0x44
A0: CMP  r2, r4
A4: JZ   0xAC
A8: MOVI r7, 1
AC: READ r0           ; ---- 字符块 i = 5 ----
B0: XOR  r2, r0, r1
B4: MOVI r3, 5
B8: ADD  r2, r2, r3
BC: LOAD r4, 0x45
C0: CMP  r2, r4
C4: JZ   0xCC
C8: MOVI r7, 1
CC: CMP  r7, r5       ; r7 应为 0
D0: JZ   0xD8         ; 全对 → 跳过失败标记
D4: MOVI r7, 1        ; 失败路径
D8: HALT              ; 停机，主程序看 r7
```

VM 程序的形状一目了然：序言置初值，六个同构的字符块逐个校验，结尾按 r7 收尾。==1.2 说的"体积膨胀"也看得见==：等价的 C 循环只要几行，展开成字节码是 55 条。

### 6.4 在 IDA 与 Ghidra 里整理 handler 语义

题目规模变大后，12 个 handler 的标注要在反编译器里做，操作路径如下（GUI 操作无固定输出）。

IDA（[[R05-静态分析工具链IDA与Ghidra|R05]]）：

1. 跳到 handler 表地址（0x402120），光标放首项，按 `y` 把数组类型改成 `void (*[12])(void)`——12 项立即变成带名字的函数指针（无符号时是 sub_xxx）。
2. 逐项双击进入 handler，读反汇编或按 F5 出伪代码（能力与局限见 [[R05-静态分析工具链IDA与Ghidra#3.7 F5 伪代码：能力与局限|R05 3.7]]），按语义重命名（快捷键 `n`），如 `vm_xor`、`vm_jz`。
3. 给全局状态重命名：0x404060 命名为 `vm_reg`、0x404284 命名为 `vm_vpc`，之后每个 handler 的伪代码里 `vm_reg[i]`、`vm_vpc` 直接可读。
4. handler 数量多时用 IDAPython 脚本批量做 2、3 两步：遍历表、逐个重命名并加注释。

Ghidra：Window → Data Type Manager 里定义 `void (*)(void)` 指针数组类型套到表上；handler 右键 → Rename Function；全局变量在 Listing 里右键 → Rename Data；结构体见下。

对"虚拟寄存器"建结构体，是把散落的全局变量或栈槽收拢成 `ctx->r[i]` 形式的关键一步：

```c
/* 在 IDA Local Types（Shift+F1）或 Ghidra Data Type Manager 里定义，
   再用 y / Retype 把持有 VM 状态的变量或指针改成本类型 */
struct vm_ctx {
    uint32_t r[8];        /* 虚拟寄存器组 */
    uint8_t  mem[256];    /* 虚拟数据段 */
    uint32_t vsp;
    uint32_t vpc;
    uint32_t flag_eq;
};
```

本章的 VM 状态本来就是独立全局变量，建结构体的收益有限；==商业壳的 context 是一个真实存在的结构体（甚至混在栈里），这一步在那里是必备操作==（第 8 节）。handler 内部出现整段查表、移位、异或组合时，先用 [[R07-编码与算法识别还原|R07]] 的形状表认一遍算法再标注，别逐行硬读。

## 7. 还原校验逻辑，逆推输入

### 7.1 读出校验式

6.3 的伪汇编里，每个字符块做同一件事：

$$t_i = (c_i \oplus 0x37) + i \tag{1}$$

其中 $c_i$ 是输入第 $i$ 个字符，$t_i$ 与期望值表（`LOAD r4` 的源，vmem 0x40 起）的第 $i$ 项比较，全对则 r7 保持 0。期望值 dump 出来：

```bash
x/6xb vmem+0x40
```

输出：

```
0x4040c0 <vmem+64>:	0x5a	0x07	0x5b	0x61	0x45	0x5f
```

### 7.2 逆推

式 (1) 两步可逆——异或自反、减法回退：

$$c_i = ((e_i - i) \bmod 256) \oplus 0x37 \tag{2}$$

```python
# solve.py —— 从期望值逆推正确输入
exp = [0x5A, 0x07, 0x5B, 0x61, 0x45, 0x5F]   # vmem[0x40] 起的 6 个期望值
key = bytes(((e - i) & 0xFF) ^ 0x37 for i, e in enumerate(exp))
print(key.decode())
```

输出：

```
m1nivm
```

### 7.3 运行拿 flag

```bash
python3 solve.py | ./minivm
```

输出：

```
key: Correct! flag{tr4c3_th3_vm}
```

五步流程到此闭环：识别 → 定位 → trace → 翻译 → 逆推。回看会发现，剥掉 VM 这层壳之后，校验式就是 [[R08-CrackMe经典题型#3. 类型二：变换比较型|R08 的变换比较型]]——逐字符异或加下标偏移；VM 改变的只是逻辑的存放形态，不改变逻辑本身。

> [!note] 更省力的路：把约束交给求解器
> 校验逻辑还原成式 (1) 后，逐字符手推只是小题待遇；字符一多、变换一复杂，把每个输入字符建成约束变量、让求解器直接给答案更快。VM 题的约束形式高度统一（每字符一条等式），很适合这套做法，工具与模板见 [[R14-自动化分析angr与z3|R14]]。

## 8. VMProtect 风格的商业壳：难在哪

### 8.1 架构与随机化

VMProtect 是 Windows 平台最常用的商业虚拟化保护壳，对选中的函数做"虚拟化"：原始 x86 指令被翻译成一套私有微码，运行在壳内置的 VM 里。它比本章的教学 VM 难几个量级，差距在结构设计上：

| 维度 | 本章的 minivm | VMProtect 一档的商业壳 |
| ---- | ---- | ---- |
| 档位 | 单一形态 | mutation（指令变异）/ virtualization（虚拟化）/ ultra（两者叠加）按函数选择 |
| handler 数量 | 12 个 | 上百个，语义碎片化：一条 x86 常拆成多条微码指令 |
| 编码 | 定长 4 字节 | 变长、含前缀与修饰位，且随保护实例变化 |
| handler 本体 | 直白的 C 函数 | 每个内部再套混淆（不可优化表达式、跳转链） |
| 虚拟寄存器 | 8 个固定全局变量 | 一段 context（虚拟寄存器组 + vpc 等），与宿主真实栈混用、位置漂移 |
| 随机化 | 无 | ==每次保护的 opcode 编号、handler 顺序、编码宽度、指令选择都重新生成== |
| 对抗 | 无 | 叠加多层反调试（[[R10-反调试与反分析对抗\|R10]]）与完整性校验 |

"context 与栈混用"值得单独解释：教学 VM 的状态是静态全局变量，地址固定；商业壳把 context 放在栈上，偏移每次保护都不同，还会穿插真实寄存器——==6.4 的结构体重类型化在这里成为必备步骤==，先恢复 context 的布局，handler 伪代码才读得动。

### 8.2 分析操作路径

商业壳没有"一条命令还原"，通用的手工路径与本章五步同构，只是每步都重得多：

1. **定位 VM 入口**。x64dbg（[[R06-动态调试GDB与x64dbg#12. x64dbg：Windows 下的动态调试|R06 第 12 节]]）里从加壳入口单步跟进，观察到执行流进入一大段反复执行的区域即 VM 主循环；IDA 里从入口函数向下找最大的、含间接跳转的循环。
2. **识别 context 与分发器**。找到"读 vpc → 查 handler 表 → 间接 call/jmp"的循环后，记录 handler 表位置；沿 context 的初始化序列（入口处成片的 mov 写入）恢复虚拟寄存器布局，建结构体（6.4）。
3. **标注 handler**。逐个读 handler、命名、记录语义。上百个 handler 靠脚本批量处理：IDA 里遍历表项重命名加注释，或 x64dbg 的命令脚本记录每个 handler 的入口与操作摘要。
4. **trace 归纳 opcode 映射**。带已知输入跑一遍，用 x64dbg 的 trace/日志功能记录每条微码的 opcode 与 handler，归纳出与 4.2 同款的映射表。
5. **翻译与求解**。把微码翻译回高级语义，交给脚本或求解器（[[R14-自动化分析angr与z3|R14]]）。

> [!warning] 不要在 F5 里找"原来的 main"
> 反编译器对虚拟化函数输出的伪代码是 VM 的机制代码加混淆，==业务逻辑不在这份伪代码里==。指望 F5 直接还原原始函数，是新手在商业壳上最常见也最耗时的误区。正确的目标始终是：字节码 + handler 语义。

> [!info]- 公开资料怎么用
> VMProtect 的虚拟化结构与常见 handler 语义，社区有大量公开分析（第 11 节列了入口），读懂一两篇再动手，能省掉很多重复劳动。但注意==分析结论绑定保护版本==：VMProtect 每个大版本都会改 opcode 分配与 handler 实现，旧笔记的映射表对新样本同样只有方法论层面的参考价值。

## 9. trace 自动化：从一次性脚本到工具

第 5 节的 trace.gdb 是为本章 VM 定制的。把它泛化成"VM trace 工具"，骨架固定，换题只改三处：

| 要改的 | 在脚本里的位置 | 换题时怎么找 |
| ---- | ---- | ---- |
| 断点位置 | `break` 行 | 分发点：取指后、handler 执行前的那条指令（4.1 的方法） |
| opcode / vpc 表达式 | printf 参数 | 该 VM 的计数器与字节数组在哪个寄存器或地址（4.3 读 handler） |
| 上下文快照 | printf 参数 | 虚拟寄存器组的地址（建结构体后表达式更短） |

```bash
# vmtrace.gdb 模板 —— 三个尖括号占位符对应上表三行
set pagination off
set confirm off
break *0x<分发点地址>
commands
silent
printf "%3d  op=%02x  ctx=%08x %08x %08x\n", <vpc表达式>, <opcode表达式>, <快照1>, <快照2>, <快照3>
continue
end
run < input.txt
```

trace 文件到手后的后处理也值得固化。以本章的 trace_ok.txt 为例，统计 opcode 分布、按 opcode 窗口找重复结构：

```python
# vmtrace.py —— trace 后处理草图：统计 opcode 分布、折叠重复结构
from collections import Counter

rows = [l.split() for l in open("trace_ok.txt") if l.startswith("VPC")]
ops = [int(r[1].split("=")[1], 16) for r in rows]

print("执行总条数:", len(rows))
print("opcode 分布:", dict(sorted(Counter(ops).items())))

# 重复结构折叠：绝对地址不同的重复块，opcode 序列相同——按 opcode 窗口找周期
W = 7
pat = Counter(tuple(ops[i:i + W]) for i in range(len(ops) - W + 1))
print("7 条 opcode 窗口 Top3:")
for w, n in pat.most_common(3):
    print("   ", " ".join("%02x" % o for o in w), "x", n)
```

输出：

```
执行总条数: 48
opcode 分布: {0: 1, 1: 8, 2: 7, 3: 6, 4: 6, 6: 6, 7: 7, 8: 7}
7 条 opcode 窗口 Top3:
    06 02 01 03 04 07 08 x 6
    02 01 03 04 07 08 06 x 5
    01 03 04 07 08 06 02 x 5
```

两个信息都是第 6 节翻译结论的预告：READ、XOR、MOVI、ADD、LOAD、CMP、JZ 这 7 条一组的序列出现 6 次，==六个同构字符块在翻译之前就从 trace 里显现了==。大题里这一步决定策略——重复窗口长且多，说明 VM 程序有循环或展开块，先盯一个周期翻译就够；trace 全程无重复，才需要硬读全量。

## 10. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 断在分发点，打印的 opcode 紊乱 | 断点位置在取指之前或执行之后；选"取指后、handler 执行前"的窗口（[[#4.1 从 call rax 找到分发点\|4.1]]） |
| trace 行数大到没法看 | VM 程序带循环；先按 opcode 窗口折叠（第 9 节草图），或给断点加条件只停目标 opcode |
| printf 里的变量名全部报 No symbol | 程序 strip 没有 `-g`；变量名换地址（从反汇编注释与 handler 里读出），断点换 `b *地址`（[[R06-动态调试GDB与x64dbg#3.1 软件断点：break 与 0xCC\|R06 3.1]]） |
| handler 表 dump 出来地址对不上 | 表项宽度用错（函数指针 8 字节，用 `x/12gx`）；PIE 程序每次基址不同，先 `info proc mappings` 拿基址再换算 |
| 两个 opcode 指向同一个 handler | 出题人复用 handler 或表含填充项；按 opcode 分别记录，空槽的执行行为要单独确认（越界下标会取到表外的代码） |
| 翻译出的伪汇编前后接不上 | 操作数槽位读反了（a/b/c 的分工是自定义的）；回 handler 反汇编核对 FETCH 顺序（[[#4.3 读 handler 反汇编定语义\|4.3]]） |
| JZ 目标跳出了字节码数组 | 目标单位看错：有的 VM 按字节偏移、有的按指令序号；从 handler 的赋值语句确认目标有没有乘指令宽度 |
| 逆推的输入程序不认 | 宽度截断（`& 0xFF`）、下标起点、借位没处理；严格按 handler 语义逐条撤（式 (2) 的顺序） |
| READ 后寄存器是 0xFFFFFFFF | 输入长度不够。先按"缺字符必失败"理解；若怀疑 0xFFFFFFFF 参与变换后仍可能撞上期望值，代回校验式算一遍 |
| IDA 里 handler 表被识别成字节数组 | 光标放首项按 `y` 改成函数指针数组类型（[[#6.4 在 IDA 与 Ghidra 里整理 handler 语义\|6.4]]） |
| 商业壳按五步走不动 | 正常：handler 上百个且变异。先做第 8 节的结构定位与 context 恢复，再决定要不要上脚本与求解器 |

## 11. 配套练习与延伸阅读

练习按"改教具再拆一遍"设计，三道都只需本章的工具：

1. **改变换**：把字符块的变换换成 `(输入 * 3) ^ 0x5A - i`（ADD/XOR 不够用，给 VM 加一条 MUL 或用移位加法合成），重新生成字节码，只靠 trace 和 dump 把它逆回来。
2. **用上 PUSH/POP**：写一段"先把输入全部 PUSH、再逐个 POP 比较"的 VM 程序（倒序比较），完整走五步流程，观察 trace 里虚拟栈指针的变化。
3. **换分发形状**：把分发循环从函数指针表改写成 switch，重新编译后重做第 3、4 节，对比两种分发在 objdump 下的形状差异。

> [!note] 实战任务
> 完成 1 个小型自定义 VM 赛题。找题路径：BUUCTF（buuoj.cn）的 Reverse 分类按 VM、虚拟机、bytecode、opcode 等关键词检索，优先挑带公开题解的旧赛题入手；crackmes.one 搜索 vm 也有大量社区练习。做题时严格按五步走，卡住时先回到本章对照：识别卡住看第 3 节，定位卡住看第 4 节，trace 卡住看第 5 节，翻译卡住看第 6 节。做完一题后，把该题的 opcode 映射表与伪汇编存档——它们就是你个人笔记里的第二台 VM。

延伸阅读（按深入程度排序）：

- CTF Wiki 的 VM 逆向条目：与本章同思路的赛题向整理，含更多题型变体。
- Rolf Rolles 的经典文章 *Unpacking Virtualization Obfuscators*：商业壳手工分析的奠基之作，第 8 节操作路径的展开版。
- Tim Blazytko 的博客与会议演讲（搜名字加 vm deobfuscation）：符号执行与程序分析自动化处理 VM 的现代路线，衔接 [[R14-自动化分析angr与z3|R14]]。
- VMProtect 官网（vmpsoft.com）的文档：mutation、virtualization、ultra 三个档位的官方定义，第 8.1 节术语的出处。
