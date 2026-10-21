---
chapter: 逆向工程
section: 可执行文件格式：ELF 与 PE
order: 204
tags:
  - CTF
  - 逆向工程
  - RE
  - ELF
  - PE
publish: true
---

# R4 可执行文件格式：ELF 与 PE
## Executable File Formats: ELF & PE

> [!info]- 章节信息
> **所属方向**：逆向工程 ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[R03-x86与x64汇编精要复习|R03]] · [[05-ELF文件格式与链接|通用基础 05 章]]
> **本章目标**：把做题要用的可执行文件格式知识整理成速查——ELF 的两种视图、ELF 头字段、核心节区与 C 代码的对应、符号表与重定位、入口点；stripped 程序的函数定位方法；PE 的 DOS 头、COFF 头、Optional Header、节表、导入表、导出表与 RVA 换算。动手部分是用 Python `struct` 写两个解析器：ELF 一个（stripped 也能跑），PE 一个。
> **示例平台**：x86-64 Linux（System V AMD64 ABI）与 x86-64 Windows（PE32+）。ELF 侧示例程序 license.c 贯穿全篇；PE 侧示例取 Windows 系统目录下的真实 DLL。

## 1. ELF：速查与补全

[[05-ELF文件格式与链接|05 章]]已经完整讲过 ELF 的整体框架，这里不重讲。先放一张索引，做题时按需回翻：

| 想看什么 | 命令 | 05 章位置 |
| ---- | ---- | ---- |
| ELF 头（magic / e_type / e_entry） | `readelf -h` | [[05-ELF文件格式与链接#3. ELF 头：64 个字节的元信息\|ELF 头]] |
| 节区表、程序头 | `readelf -S`、`readelf -l` | [[05-ELF文件格式与链接#2. 两个视角：节与段\|节与段双视角]] |
| 动态依赖、RELRO、重定位、符号表 | `readelf -d` / `-r` / `--syms` | [[05-ELF文件格式与链接#5. 符号表与重定位\|符号表与重定位]] |
| 延迟绑定跳转链 | `objdump -d -M intel` | [[05-ELF文件格式与链接#6. 动态链接：printf@plt 的完整跳转链\|printf@plt 完整跳转链]] |
| 静态链接与 stripped 概览 | `file` | [[05-ELF文件格式与链接#8. 静态链接与 stripped\|静态链接与 stripped]] |

05 章的示例程序只有一行 `printf`；本节换一个函数更多、更接近赛题形态的 license.c（见 2.1），把字段级的细节补齐。已讲透的部分（延迟绑定、RELRO）只留双链，不再展开。

### 1.1 链接视图与执行视图：两套目录

同一个 ELF 文件里有两套目录，视角不同：

- **节区表**（section header table）：按**内容**分类——代码、只读数据、符号各是一节。给编译器、链接器和静态分析工具用：`readelf -S`、`objdump`、IDA 读的都是它。
- **程序头表**（program header table）：按**装载**分类——每个 LOAD 段描述一块连续文件映射到哪段虚拟地址、什么权限。给内核 loader 和动态链接器用，是**运行时唯一必需的目录**。

两套目录的对应关系只有一条：==权限相同的节合并进同一个 LOAD 段==（[[05-ELF文件格式与链接#2. 两个视角：节与段|05 章第 2 节]]讲过对应表）。看 lic_full 的 LOAD 段：

```bash
readelf -l lic_full | grep -A1 -E 'LOAD|GNU_RELRO|GNU_STACK|Requesting'
```

输出：

```
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000005d0 0x00000000000005d0  R      0x1000
  LOAD           0x0000000000001000 0x0000000000401000 0x0000000000401000
                 0x00000000000002b1 0x00000000000002b1  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000402000 0x0000000000402000
                 0x00000000000001b8 0x00000000000001b8  R      0x1000
  LOAD           0x0000000000002df8 0x0000000000403df8 0x0000000000403df8
                 0x0000000000000238 0x0000000000000240  RW     0x1000
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002df8 0x0000000000403df8 0x0000000000403df8
                 0x0000000000000208 0x0000000000000208  R      0x1
```

读法：每个 LOAD 占两行，第一行是 Offset（文件偏移）和 VirtAddr（虚拟地址），第二行是 FileSiz（文件里占多少）、MemSiz（内存里占多少）和权限。第 2 个 LOAD 权限 `R E`，装的就是 `.text`（1.3 的节区清单）；第 4 个 LOAD 的 FileSiz `0x238` 小于 MemSiz `0x240`，差的 8 字节是 `.bss`——文件里不存在、装载时补零的内容（1.3 的 vars.c 实验演示这一点）。

另一个 LOAD 值得单独记：偏移 `0x2000` 映到 `0x402000`。非 PIE 程序的这个差值恒定，2.2 靠它做文件偏移到虚拟地址的换算。

> [!info]- 其余常见程序头类型
> - `PHDR`：程序头表自身的位置（0x40，紧跟 ELF 头）。
> - `INTERP`：动态链接器路径 `/lib64/ld-linux-x86-64.so.2`，有它才是动态链接。
> - `DYNAMIC`：`.dynamic` 节的位置，动态链接信息（依赖库、重定位）都在里面。
> - `GNU_STACK`：栈权限。这里是 `RW` 没有 `E`，就是 NX 的来源。
> - `GNU_RELRO`：装载后设为只读的区间，RELRO 的判定依据（[[05-ELF文件格式与链接#6. 动态链接：printf@plt 的完整跳转链|延迟绑定一节]]）。
> - `GNU_EH_FRAME` / `GNU_PROPERTY`：异常展开信息、CET/IBT 属性。

==程序头删不得，节区表删得==：loader 只看程序头，所以 sstrip 或壳把节区表整个删掉后程序照常运行（后果见 2.1 的 warning）。分析以程序头为准——它是装载的必需品，节区表则可以被任意工具增删。

### 1.2 ELF 头关键字段

`readelf -h` 读的就是文件开头 64 字节的 `Elf64_Ehdr`：

```bash
readelf -h lic_full
```

输出：

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4010b0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          14112 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         14
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```

逐个看做题要用到的字段：

| 字段 | lic_full 的值 | 含义 |
| ---- | ---- | ---- |
| `e_type` | `EXEC` | `EXEC` = 固定地址的可执行文件；`DYN` = PIE 可执行文件或共享库；`REL` = 目标文件 `.o`。判断 PIE 先看它，再看有没有 `INTERP` |
| `e_machine` | `Advanced Micro Devices X86-64` | 架构，决定反汇编用哪套指令集 |
| `e_entry` | `0x4010b0` | 入口点地址，指向 `_start` 而不是 main（1.6） |
| `e_phoff` | `64`（`0x40`） | 程序头表在文件里的偏移，紧跟 64 字节的 ELF 头 |
| `e_phentsize` / `e_phnum` | `56` / `14` | 程序头每项 56 字节、共 14 项；`e_phoff + i × 56` 是第 i 项的位置 |
| `e_shoff` | `14112`（`0x3720`） | 节区表在文件里的偏移 |
| `e_shentsize` / `e_shnum` | `64` / `31` | 节区头每项 64 字节、共 31 项 |
| `e_shstrndx` | `30` | 节名字符串表 `.shstrtab` 的节区索引；解析节名时从它入手（第 4 节的脚本用到） |

> [!info]- e_ident：前 16 字节
> `Magic: 7f 45 4c 46 02 01 01 00 ...` 里，`7f 45 4c 46` 是 `"\x7fELF"` 魔数；第 5 字节 `02` 是 EI_CLASS（1 = 32 位 ELF32，2 = 64 位 ELF64）；第 6 字节 `01` 是 EI_DATA（1 = 小端，2 = 大端）。第 4 节解析器里的 `data[4]`、`data[5]` 读的就是这两字节，先确定位宽和字节序再解包后面的字段。

ELF64 头固定 64 字节。`readelf -h` 的输出顺序就是结构体成员顺序，第 4 节的解析器按"偏移 16 起解包"正是跳过这 16 字节 e_ident 直接读 `e_type` 及之后。

### 1.3 核心节区与 C 代码的对应

```bash
readelf -SW lic_full | grep -E ' \.(text|rodata|data|bss|plt|plt\.sec|got|got\.plt|symtab|dynsym|strtab) '
```

输出：

```
  [ 4] .dynsym           DYNSYM          00000000004003b0 0003b0 0000a8 18   A  5   1  8
  [11] .plt              PROGBITS        0000000000401020 001020 000050 10  AX  0   0 16
  [12] .plt.sec          PROGBITS        0000000000401070 001070 000040 10  AX  0   0 16
  [13] .text             PROGBITS        00000000004010b0 0010b0 0001f3 00  AX  0   0 16
  [15] .rodata           PROGBITS        0000000000402000 002000 000035 00   A  0   0  4
  [23] .got              PROGBITS        0000000000403fd8 002fd8 000010 08  WA  0   0  8
  [24] .got.plt          PROGBITS        0000000000403fe8 002fe8 000038 08  WA  0   0  8
  [25] .data             PROGBITS        0000000000404020 003020 000010 00  WA  0   0  8
  [26] .bss              NOBITS          0000000000404030 003030 000008 00  WA  0   0  1
  [28] .symtab           SYMTAB          0000000000000000 003058 0003a8 18     29  18  8
  [29] .strtab           STRTAB          0000000000000000 003400 000200 00      0   0  1
```

每个节里放什么，用 C 代码对号：

| 节 | 里面放什么 | C 代码里的东西（本例） |
| --- | --- | --- |
| `.text` | 函数编译出的机器指令 | `rotl32` / `check_license` / `main` / `_start` 的指令，0x4010b0 起 |
| `.rodata` | 只读数据：字符串字面量、const 全局变量、switch 跳转表 | `"correct, enjoy"`（在 0x402017，2.2 会用到） |
| `.data` | 已初始化且可写的全局、静态变量 | vars.c 的 `g_init`、`s_cnt`（见下） |
| `.bss` | 未初始化或零初始化的全局、静态变量；类型 NOBITS，**不占文件空间** | vars.c 的 `g_zero`（见下） |
| `.plt` / `.plt.sec` | 调用外部库函数的跳板代码 | `puts("correct, enjoy")` 编译成 `call puts@plt` |
| `.got` / `.got.plt` | 外部函数、外部数据的真实地址表 | `puts` 的地址槽位 0x404000（1.5 的重定位会指到它） |

注意：**局部变量不属于任何节**。`main` 里的 `char buf[64]` 在栈上，运行时才存在。

`.data` / `.bss` / `.rodata` 的分工用一个专用实验看清楚：

```c
/* vars.c：观察不同存储类别的变量分别落在哪个节区 */
#include <stdio.h>

int g_init = 0x11223344;      /* 已初始化全局变量   */
int g_zero;                   /* 未初始化全局变量   */
static int s_cnt = 5;         /* static 全局变量    */
const int limit = 100;        /* const 全局变量     */

static void helper(void) {    /* static 函数        */
    g_zero += s_cnt;
}

int main(void) {
    helper();
    printf("%d %d %d\n", g_init, g_zero, limit);
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie vars.c -o vars
nm vars | grep -E ' g_init| g_zero| s_cnt| limit| helper| main'
```

输出：

```
0000000000404018 D g_init
0000000000404024 B g_zero
0000000000401136 t helper
0000000000402004 R limit
0000000000401155 T main
000000000040401c d s_cnt
```

`nm` 每行中间的字母就是节区归属：大写表示 GLOBAL 符号、小写表示 LOCAL 符号（1.4 讲绑定）。`T/t` 在 `.text`，`D/d` 在 `.data`，`B/b` 在 `.bss`，`R/r` 在 `.rodata`。五个变量正好五条：`g_init`、`s_cnt` 落 `.data`，`g_zero` 落 `.bss`，`limit` 落 `.rodata`，`helper` 是 LOCAL 函数。

```bash
readelf -SW vars | grep -E ' \.(data|bss|rodata) '
```

输出：

```
  [15] .rodata           PROGBITS        0000000000402000 002000 000012 00   A  0   0  4
  [25] .data             PROGBITS        0000000000404008 003008 000018 00  WA  0   0  8
  [26] .bss              NOBITS          0000000000404020 003020 000008 00  WA  0   0  4
```

```bash
readelf -l vars | grep -A1 'LOAD'
```

输出：

```
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000004e0 0x00000000000004e0  R      0x1000
  LOAD           0x0000000000001000 0x0000000000401000 0x0000000000401000
                 0x0000000000000199 0x0000000000000199  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000402000 0x0000000000402000
                 0x0000000000000168 0x0000000000000168  R      0x1000
  LOAD           0x0000000000002df8 0x0000000000403df8 0x0000000000403df8
                 0x0000000000000228 0x0000000000000230  RW     0x1000
```

最后一块 LOAD 的 FileSiz `0x228` 小于 MemSiz `0x230`：差的 8 字节就是 `.bss`（`g_zero` 加对齐）。它参与内存映射，但文件里一个字节都没有——这就是 NOBITS 的含义。

### 1.4 符号表：.symtab 与 .dynsym

符号是"名字 ↔ 地址"的记录，每条 24 字节（`Elf64_Sym`），核心字段：`st_name`（名字在字符串表中的偏移）、`st_info`（绑定与类型）、`st_shndx`（定义在哪个节，0 表示未定义）、`st_value`（地址）。

ELF 里有两张符号表，角色不同：

- **`.symtab`**：完整符号表，含所有 LOCAL 符号。给链接器和调试器用，**strip 删的就是它**（连同 `.strtab`）。
- **`.dynsym`**：动态链接需要的最小集合，只有导入/导出符号。运行时要用，**strip 不删**。

绑定（bind）分三种：

| 绑定 | 含义 | 例子 |
| ---- | ---- | ---- |
| `LOCAL` | 只在本文件可见，不参与链接时的符号仲裁；`static` 函数和内部符号是 LOCAL | vars.c 的 `helper`（`nm` 显示小写 `t`） |
| `GLOBAL` | 全局可见，全程序唯一 | `main`、`check_license`、导入的 `puts` |
| `WEAK` | 弱定义：可以被同名 GLOBAL 覆盖；未定义的 WEAK 符号不报错、按 0 处理 | `__gmon_start__`（gprof 分析钩子，程序没被插桩就没有定义） |

```bash
readelf -sW lic_full | grep -E ' FILE | WEAK | main|_start|check_license|rotl32|deregister|puts@'
```

输出：

```
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (3)
     6: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crt1.o
     3: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
     4: 00000000004010f0     0 FUNC    LOCAL  DEFAULT   13 deregister_tm_clones
    11: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS license.c
    12: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    14: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS 
    18: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34
    19: 0000000000404020     0 NOTYPE  WEAK   DEFAULT   25 data_start
    20: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5
    26: 0000000000404020     0 NOTYPE  GLOBAL DEFAULT   25 __data_start
    27: 0000000000000000     0 NOTYPE  WEAK   DEFAULT   UND __gmon_start__
    32: 00000000004010b0    38 FUNC    GLOBAL DEFAULT   13 _start
    33: 0000000000404030     0 NOTYPE  GLOBAL DEFAULT   26 __bss_start
    34: 0000000000401222   129 FUNC    GLOBAL DEFAULT   13 main
    35: 00000000004011b2   112 FUNC    GLOBAL DEFAULT   13 check_license
    38: 0000000000401196    28 FUNC    GLOBAL DEFAULT   13 rotl32
```

前三行来自 `.dynsym`（readelf 先打印它），其余来自 `.symtab`。对照三种绑定：`FILE` 类型的 `crt1.o`、`license.c` 记录的是"这份代码来自哪个源文件"，全部 LOCAL；crt 启动代码的 `deregister_tm_clones` 是 LOCAL 函数；`__gmon_start__` 以 WEAK UND 出现——没有定义也不影响运行；用户函数 `main` / `check_license` / `rotl32` / `_start` 都是 GLOBAL，`Ndx` 列的 13 就是 `.text` 的节区索引（1.3 输出里的 `[13]`）。`UND` 表示本文件使用但未定义，交给动态链接解决。

> [!info]- st_info 的编码
> `st_info` 一个字节拆成两半：高 4 位是绑定（0 = LOCAL，1 = GLOBAL，2 = WEAK），低 4 位是类型（1 = OBJECT 数据，2 = FUNC 函数）。`readelf` 的 Bind/Type 两列、第 4 节脚本里的 `st_info >> 4` 和 `st_info & 0xF` 都是在拆这一个字节。

### 1.5 重定位：哪个地址在什么时候填

==重定位表回答一个问题：哪个地址槽位、要填哪个符号的地址、什么时候填。== 看 lic_full 的全部重定位条目：

```bash
readelf -r lic_full
```

输出：

```
Relocation section '.rela.dyn' at offset 0x540 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000403fd8  000100000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.34 + 0
000000403fe0  000600000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0

Relocation section '.rela.plt' at offset 0x570 contains 4 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404000  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000404008  000300000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000404010  000400000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000404018  000500000007 R_X86_64_JUMP_SLO 0000000000000000 __isoc23_scanf@GLIBC_2.38 + 0
```

两条类型、两种填法：

- `GLOB_DAT`（`.rela.dyn`）：**装载时**由动态链接器填好。`__libc_start_main` 的地址被填进 0x403fd8 这个 GOT 槽位——1.6 会看到 `_start` 的 `call` 正是走这个槽。
- `JUMP_SLOT`（`.rela.plt`）：**第一次调用时**才填（延迟绑定）。`puts` 对应槽位 0x404000，位于 `.got.plt`。

Offset 列就是 GOT 里的槽位地址，Sym. Name 列是要填进去的符号——泄露 libc 地址时算的"某个 GOT 槽与 libc 基址的偏移"，用的就是这对关系（[[05-ELF文件格式与链接#5. 符号表与重定位|05 章第 5 节]]、[[05-ELF文件格式与链接#6. 动态链接：printf@plt 的完整跳转链|第 6 节]]）。stripped 程序里这两张表原样保留，这是 2.2 手工定位的基石。

### 1.6 入口点：_start 与 main

`e_entry = 0x4010b0` 指向的是 `_start`，不是 main——main 的地址是 `_start` 传给 libc 的参数（[[05-ELF文件格式与链接#7. 入口点：main 不是入口|05 章第 7 节]]）。lic_full 的 `.text` 恰好从 `_start` 开始，反汇编它（x86-64 Linux，System V AMD64 ABI）：

```bash
objdump -d -M intel lic_full --start-address=0x4010b0 --stop-address=0x4010d6
```

输出：

```
00000000004010b0 <_start>:
  4010b0:	f3 0f 1e fa          	endbr64
  4010b4:	31 ed                	xor    ebp,ebp
  4010b6:	49 89 d1             	mov    r9,rdx
  4010b9:	5e                   	pop    rsi
  4010ba:	48 89 e2             	mov    rdx,rsp
  4010bd:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  4010c1:	50                   	push   rax
  4010c2:	54                   	push   rsp
  4010c3:	45 31 c0             	xor    r8d,r8d
  4010c6:	31 c9                	xor    ecx,ecx
  4010c8:	48 c7 c7 22 12 40 00 	mov    rdi,0x401222
  4010cf:	ff 15 03 2f 00 00    	call   QWORD PTR [rip+0x2f03]        # 403fd8 <__libc_start_main@GLIBC_2.34>
  4010d5:	f4                   	hlt
```

逐行对照：`pop rsi` 取栈上的 argc，`mov rdx,rsp` 让 rdx 指向 argv 数组；`mov rdi,0x401222` 把 **main 的地址**装进第一个参数寄存器 rdi（System V AMD64 ABI 的参数顺序是 rdi、rsi、rdx、rcx、r8、r9）；最后 `call QWORD PTR [rip+0x2f03]` 通过 0x403fd8 槽位调用 `__libc_start_main`——这个槽位正是 1.5 里那条 `GLOB_DAT` 重定位，装载时已填好 libc 地址。`__libc_start_main` 完成 libc 初始化后调用 main，main 返回后由它调用 `exit` 结束进程。

==找 main 的两条路==：非 stripped 程序直接查符号表（1.4 的 `main 0x401222`）；stripped 程序从 `e_entry` 反汇编 `_start`，找 `mov rdi, 0x4xxxxx` 那条指令（2.2 用到）。

### 1.7 静态还是动态：file 与 ldd

`file` 一条命令就能回答链接方式：

| file 输出片段 | 含义 |
| ---- | ---- |
| `dynamically linked` + `interpreter /lib64/ld-linux-x86-64.so.2` | 动态链接，运行时由 ld.so 装载 libc |
| `statically linked` | 静态链接，libc 已编进文件，无 interpreter |
| `not stripped` / `stripped` | `.symtab` 在 / 不在 |

`ldd` 进一步列出动态依赖。lic_full：

```bash
ldd lic_full
```

输出：

```
	linux-vdso.so.1 (0x0000719f73e82000)
	libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (0x0000719f73c00000)
	/lib64/ld-linux-x86-64.so.2 (0x0000719f73e84000)
```

括号里的地址是本次运行的装载基址，每次执行都不同（ASLR）。静态版本则完全没有依赖：

```bash
gcc -static -O0 license.c -o lic_static
file lic_static
ldd lic_static
```

输出：

```
lic_static: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=69098a5a0aeb9af7c1a54ac63ae2ee5be6c0c286, for GNU/Linux 3.2.0, not stripped
	not a dynamic executable
```

代价是体积：lic_full 16,096 字节，lic_static 959,800 字节。静态链接的题型影响（无 libc 泄露问题、gadget 密度高）见 [[05-ELF文件格式与链接#8. 静态链接与 stripped|05 章第 8 节]]。

> [!warning] 不要对不可信的二进制跑 ldd
> `ldd` 的实现方式是让动态链接器以跟踪模式**执行**目标程序。对恶意样本或来路不明的赛题附件运行 ldd，等于放任其中的代码执行。判断链接方式用 `file` 和 `readelf -d`（看 `NEEDED` 条目）就够了，两者都是纯文件解析。

## 2. stripped 程序：赛题的常态

==逆向题的 Linux 附件大多是 stripped 的。== stripped 不是加密也不是加壳：只是删掉了符号表，代码、地址、重定位、动态链接信息全部原样保留。这一节把"没符号"变成"有方法的定位题"。

### 2.1 同一份源码的两种产物

示例程序 license.c 贯穿本章：`check_license` 对输入做循环移位异或校验，通过则输出 "correct, enjoy"——它在 stripped 实验里扮演的就是赛题中 flag 校验函数的角色。

```c
// license.c —— 本章的示例程序
#include <stdio.h>

unsigned rotl32(unsigned x, int n) { return (x << n) | (x >> (32 - n)); }

int check_license(const char *s) {          // 校验函数，2.2 在 stripped 里定位它
    unsigned h = 0x12345678u;
    for (size_t i = 0; s[i]; i++) h = rotl32(h ^ s[i], 5) + i;
    return h == 0xCAFEF00Du;
}

int main(void) {
    char buf[64];
    printf("license key: ");
    scanf("%63s", buf);
    if (check_license(buf)) puts("correct, enjoy");
    else puts("wrong key, bye");
    return 0;
}
```

编译两份，唯一区别是 `-s`（strip）：

```bash
gcc -O0 -fno-pie -no-pie license.c -o lic_full
gcc -s -O0 -fno-pie -no-pie license.c -o lic_strip
file lic_full lic_strip
```

输出：

```
lic_full:  ELF 64-bit LSB executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped
lic_strip: ELF 64-bit LSB executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

逐项对比：

| 观察              | lic_full                                                             | lic_strip                                                         |
| --------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------- |
| 文件大小            | 16,096 字节                                                            | 14,504 字节                                                         |
| 节区数（readelf -h） | 31                                                                   | 29，少的是 `.symtab` 和 `.strtab`                                      |
| `nm` 列函数        | `_start 4010b0`、`rotl32 401196`、`check_license 4011b2`、`main 401222` | `nm: lic_strip: no symbols`                                       |
| `objdump -d` 标签 | `<main>:`、`<check_license>:` 齐全                                      | 用户函数只剩裸地址，`main` 头上变成 `<.text>:`；`printf@plt` 标签仍在，名字来自 `.dynsym` |

> [!info]- 1,592 字节的差值明细
> 16,096 − 14,504 = 1,592。其中：`.symtab` 0x3a8 = 936 字节；`.strtab` 0x200 = 512 字节；节区表少了 2 项，2 × 64 = 128 字节；`.shstrtab` 因为少了两个节名缩短 16 字节。936 + 512 + 128 + 16 = 1,592，与文件差值吻合。除符号表相关内容外，两个文件的节区清单完全一致（可用 `readelf -S` 逐行 diff 核对）。

==strip 删的是符号表里的名字，地址一处没变==：`check_license` 的代码仍在 0x4011b2，只是没有任何表再记录"这个地址叫 check_license"。

> [!warning] strip 到底删了什么
> 只删 `.symtab` / `.strtab` 和调试信息。节区表、`.dynsym`、字符串常量都保留。把节区表也删掉的是 sstrip 或加壳，那种文件 `readelf -S` 会报 "There are no sections"（[[05-ELF文件格式与链接#8. 静态链接与 stripped|05 章第 8 节]]），但程序头表和 `.dynamic` 仍在，按 1.1 的程序头路线继续分析即可。拿到 stripped 文件的第一步仍然是 `file` 和 `readelf -S`，确认被删的只是符号表。

### 2.2 符号已删，地址还在

目标：在 lic_strip 里定位 `check_license`，不借助任何符号表。三步走完再给完整思路清单。

**第一步：`strings` 带偏移扫关键字符串。**

```bash
strings -t x lic_strip | grep -E "license|correct|wrong"
```

输出：

```
   2004 license key: 
   2017 correct, enjoy
   2026 wrong key, bye
```

`-t x` 让 strings 在每行前面列出**文件偏移**。三个字符串都落在 `.rodata` 里（1.3：`.rodata` 从文件偏移 0x2000、地址 0x402000 开始）。

**第二步：文件偏移换算虚拟地址。** 1.1 的 LOAD 表显示偏移 0x2000 的段映到 0x402000，且各 LOAD 段的"虚拟地址 − 文件偏移"恒为 0x400000，于是对本程序：

$$\text{虚拟地址} = \text{文件偏移} + \mathtt{0x400000} \tag{4.1}$$

"correct, enjoy" 的 0x2017 换算成 0x402017。本程序非 PIE，基址固定 0x400000；PIE 程序没有固定基址，但节区地址照样写在节区表里（PIE 文件内 `e_entry` 等值直接就是小偏移），方法不变。

```bash
objdump -d -M intel lic_strip | grep -B4 -A1 402017
```

输出：

```
  401266:	48 89 c7             	mov    rdi,rax
  401269:	e8 44 ff ff ff       	call   4011b2 <__isoc23_scanf@plt+0x112>
  40126e:	85 c0                	test   eax,eax
  401270:	74 0c                	je     40127e <__isoc23_scanf@plt+0x1de>
  401272:	bf 17 20 40 00       	mov    edi,0x402017
  401277:	e8 f4 fd ff ff       	call   401070 <puts@plt>
```

读这段：`mov edi,0x402017` 把 "correct, enjoy" 的地址装进第一参数，随后 `call puts@plt` 打印它。它前面紧挨着 `call 4011b2`——校验函数的返回值在 eax 里，`test eax,eax` 后 `je 40127e` 在 eax 为 0（校验失败）时跳去打印 "wrong key, bye"，非 0 则落到 "correct, enjoy" 分支。==call 指令的目标地址写在指令编码里（`e8` 后 4 字节相对位移），符号表删不掉指令里的数字==。对照 2.1 的 `nm` 输出：0x4011b2 正是 `check_license`。地址旁的 `<__isoc23_scanf@plt+0x112>` 是 objdump 的注记——stripped 文件里最近的已知符号来自 `.dynsym`（2.3），只说明"离 scanf@plt 有 0x112 字节"，不代表属于它。

**第三步：把它当函数起点反汇编。**

```bash
objdump -d -M intel lic_strip --start-address=0x4011b2 --stop-address=0x4011f9
```

输出：

```
00000000004011b2 <.text+0x102>:
  4011b2:	f3 0f 1e fa          	endbr64
  4011b6:	55                   	push   rbp
  4011b7:	48 89 e5             	mov    rbp,rsp
  4011ba:	48 83 ec 18          	sub    rsp,0x18
  4011be:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
  4011c2:	c7 45 f4 78 56 34 12 	mov    DWORD PTR [rbp-0xc],0x12345678
  4011c9:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
  4011d0:	00 
  4011d1:	eb 2e                	jmp    401201 <__isoc23_scanf@plt+0x161>
  4011d3:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
  4011d7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4011db:	48 01 d0             	add    rax,rdx
  4011de:	0f b6 00             	movzx  eax,BYTE PTR [rax]
  4011e1:	0f be c0             	movsx  eax,al
  4011e4:	33 45 f4             	xor    eax,DWORD PTR [rbp-0xc]
  4011e7:	be 05 00 00 00       	mov    esi,0x5
  4011ec:	89 c7                	mov    edi,eax
  4011ee:	e8 a3 ff ff ff       	call   401196 <__isoc23_scanf@plt+0xf6>
  4011f3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
  4011f7:	01 d0                	add    eax,edx
```

函数序言、常量 `0x12345678`（源码里的哈希初值）、立即数 `0x5`（循环移位的位数）、`call 401196`（对照 `nm`：`rotl32`）、`add eax,edx`（源码里的 `+ i`）——机器码与源码逐句对应，校验函数就此定位。之后读懂算法、写 keygen 是逆向主线的常规后续（IDA/Ghidra 里做同样的定位：字符串窗口 → 交叉引用（X 键）→ 反编译，工具不同、线索相同，[[R05-静态分析工具链IDA与Ghidra|R05]] 展开）。

完整思路清单（stripped 定位函数的通用流程）：

1. `file` / `readelf -h`：确认 stripped、确认非 PIE（`e_type = EXEC`）；
2. `strings -t x` 搜提示字符串，拿到文件偏移；
3. 按 4.1 换算虚拟地址（或直接读节区表的 addr 列）；
4. `objdump -d` 搜引用该地址的指令，找到关键 `call`；
5. 以 `call` 的目标为起点反汇编，读算法、定边界；
6. 找 main：`readelf -h` 的 `e_entry` → 反汇编 `_start` → `mov rdi, 0x4xxxxx` 即 main（1.6 的机制，lic_strip 上同样有效：入口 0x4010b0 处能看到 `mov rdi,0x401222`）。

### 2.3 .dynsym：stripped 后仍在的符号表

stripped 之后 `readelf --dyn-syms`（读 `.dynsym`）并不为空：

```
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (3)
```

lic_strip 的 `.dynsym` 共 7 项：6 个导入函数（`__libc_start_main`、`puts`、`__stack_chk_fail`、`printf`、`__isoc23_scanf` 加一个空项）和 1 个 WEAK UND `__gmon_start__`。==导入函数的名字永远删不掉==，动态链接运行时解析全靠它（1.4、1.5）。规律一句话：**库里的函数有名字，程序自己定义的函数没有名字**。stripped 程序反汇编里看到 `puts@plt`、`printf@plt` 标签，名字来源就是 `.dynsym`。

## 3. PE：Windows 的可执行文件格式

### 3.1 总览：与 ELF 对照

Windows 逆向题绕不开 PE（Portable Executable）。两套格式解决的问题相同——描述代码和数据的位置、声明外部依赖、支持运行时装载——部件一一对应（[[05-ELF文件格式与链接#9. PE 速览|05 章第 9 节]]有一张更简的速览）：

| PE 部件 | ELF 里的对应物 | 干什么 |
| ---- | ---- | ---- |
| DOS 头（`MZ`）+ `PE\0\0` 签名 | `\x7fELF` 魔数 | 格式识别 |
| COFF 头 + Optional Header | ELF 头 | 架构、类型、入口点、装载基址 |
| 节表（Section Table） | 节区表 | `.text` / `.rdata` / `.data` 各节位置 |
| 导入表（INT + IAT） | `.rela.plt` + `.dynsym` + GOT | 要用哪些外部函数，地址运行时填 |
| 导出表 | `.dynsym` 的导出部分 | DLL 提供给其他模块的函数名单 |
| `.reloc` 基址重定位 | `.rela.dyn` | ASLR 改变基址后修正指针 |

三个先说明白的差别：

1. PE 字段全部小端存储，多字节字段按小端解包；
2. PE32+（64 位，Optional Header Magic `0x20b`）与 PE32（32 位，`0x10b`）的 Optional Header 字段偏移不同，解析前必须先读 Magic 分流；
3. PE 的"虚拟地址"一律用 **RVA**（Relative Virtual Address，相对装载基址的偏移），换算文件偏移的规则与 ELF 不同（3.6）。虚拟地址与 RVA 的关系：

$$\text{VA} = \text{ImageBase} + \text{RVA} \tag{4.2}$$

练手文件用 `C:\Windows\System32\cryptbase.dll`：70,096 字节，7 个节，导入导出齐全，`file` 判定为 `PE32+ executable for MS Windows 10.00 (DLL), x86-64`。

### 3.2 解析脚本：用 struct 拆

读 PE 不需要任何库，`struct` 模块就够了。脚本按规范从 DOS 头一路拆到导入表：

```python
#!/usr/bin/env python3
"""最小 PE64 解析器：DOS 头 -> PE 签名 -> COFF 头 -> Optional Header -> 节表 -> 导入表。
用法：python3 parse_pe.py <file>"""
import struct, sys

data = open(sys.argv[1], "rb").read()

# --- DOS 头：真正有用的只有末尾那个 e_lfanew ---
assert data[:2] == b"MZ", "not an MZ"
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
print(f"[DOS头] magic={data[:2].decode()}  e_lfanew(0x3C处)={e_lfanew:#x}")

# --- PE 签名 + COFF 头（20 字节）---
assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0", "PE signature missing"
off = e_lfanew + 4
machine, num_sec, _ts, _ptr_sym, _nsym, opt_size, chars = struct.unpack_from(
    "<HHIIIHH", data, off)
print(f"[COFF] machine={machine:#06x}({'x64' if machine == 0x8664 else '??'})  "
      f"NumberOfSections={num_sec}  SizeOfOptionalHeader={opt_size:#x}  "
      f"Characteristics={chars:#06x}({'DLL' if chars & 0x2000 else 'EXE'})")

# --- Optional Header（PE32+，Magic 0x20B）---
off += 20
magic, _lvmaj, _lvmin, size_code = struct.unpack_from("<HBBI", data, off)
assert magic == 0x20B, f"not PE32+ (magic={magic:#x})"
entry, base_code = struct.unpack_from("<II", data, off + 16)
image_base, sec_align, file_align = struct.unpack_from("<QII", data, off + 24)
size_image, size_hdr = struct.unpack_from("<II", data, off + 56)
subsystem = struct.unpack_from("<H", data, off + 68)[0]
n_rva = struct.unpack_from("<I", data, off + 108)[0]
print(f"[Optional] magic={magic:#x}(PE32+)  entry={entry:#x}  ImageBase={image_base:#x}  "
      f"SectionAlign={sec_align:#x}  FileAlign={file_align:#x}")
print(f"           SizeOfImage={size_image:#x}  SizeOfHeaders={size_hdr:#x}  "
      f"Subsystem={subsystem}({'GUI' if subsystem == 2 else 'CUI' if subsystem == 3 else '?'})  "
      f"DataDirectory项数={n_rva}")

# --- DataDirectory（off+112 起，每项 8 字节）：第 0 项导出表、第 1 项导入表 ---
dd_off = off + 112
dd = [struct.unpack_from("<II", data, dd_off + i * 8) for i in range(n_rva)]
print(f"[DataDirectory] 导出表 rva={dd[0][0]:#x} size={dd[0][1]:#x}  "
      f"导入表 rva={dd[1][0]:#x} size={dd[1][1]:#x}")

# --- 节表（紧跟 Optional Header，每项 40 字节）---
sec_off = off + opt_size
secs = []
print("[节表]")
print(f"  {'名称':<8}{'VirtualAddress':>15}{'VirtualSize':>13}{'SizeOfRawData':>14}{'PointerToRawData':>17}")
for i in range(num_sec):
    name, vsize, va, rsize, raw = struct.unpack_from("<8sIIII", data, sec_off + i * 40)
    cname = name.rstrip(b"\0").decode()
    secs.append(dict(name=cname, va=va, vsize=vsize, rsize=rsize, raw=raw))
    print(f"  {cname:<8}{va:#13x}{vsize:#12x}{rsize:#14x}{raw:#17x}")

def rva2off(rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
            return rva - s["va"] + s["raw"]
    raise ValueError(f"rva {rva:#x} 不在任何节里")

# --- 导出表：IMAGE_EXPORT_DIRECTORY，Name@12 / NumberOfFunctions@20 / NumberOfNames@24 ---
rva_exp, size_exp = dd[0]
if rva_exp:
    o = rva2off(rva_exp)
    name_rva = struct.unpack_from("<I", data, o + 12)[0]
    n_funcs, n_names = struct.unpack_from("<II", data, o + 20)
    eo = rva2off(name_rva)
    dll_self = data[eo:data.index(b"\0", eo)].decode()
    print(f"[导出表] 模块名={dll_self}  导出函数数={n_funcs}  具名数={n_names}")

# --- 导入表：IMAGE_IMPORT_DESCRIPTOR 数组（每项 20 字节），全零项结束 ---
rva_imp, _size_imp = dd[1]
print("[导入表]")
if not rva_imp:
    print("  （这个 DLL 的导入表 rva=0：它一个外部函数都不需要）")
    sys.exit(0)
o = rva2off(rva_imp)
while True:
    oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, o)
    if oft == 0 and name_rva == 0:
        break
    do = rva2off(name_rva)
    dll = data[do:data.index(b"\0", do)].decode()
    funcs = []
    thunk_rva = oft or ft
    t = rva2off(thunk_rva)
    while True:
        val = struct.unpack_from("<Q", data, t)[0]
        if val == 0:
            break
        if val & (1 << 63):                       # 最高位 1 = 按序号导入
            funcs.append(f"#{val & 0xFFFF}")
        else:
            no = rva2off(val & 0x7FFFFFFF)
            funcs.append(data[no + 2:data.index(b"\0", no + 2)].decode())
        t += 8
    print(f"  {dll}: {' '.join(funcs[:6])}"
          + (f" ...共{len(funcs)}个" if len(funcs) > 6 else ""))
    o += 20
```

`struct` 用法速查，读脚本时按行查阅：

| 写法 | 含义 |
| ---- | ---- |
| `"<I"` | `<` 小端；`H` 2 字节、`I` 4 字节、`Q` 8 字节、`8s` 8 字节定长串 |
| `struct.unpack_from(fmt, data, off)` | 从 `data` 的 `off` 偏移起按 `fmt` 解包，返回元组 |
| `data.index(b"\0", o)` | 从 `o` 起找下一个 `\0`，用于取 `\0` 结尾的字符串 |

脚本各段与后文小节的对应：

| 脚本段 | 对应结构体 | 详见 |
| ---- | ---- | ---- |
| DOS 头 | `IMAGE_DOS_HEADER`（64 字节，只取 `e_lfanew`） | 3.3 |
| PE 签名 + COFF 头 | `"PE\0\0"` + `IMAGE_FILE_HEADER`（20 字节） | 3.4 |
| Optional Header | `IMAGE_OPTIONAL_HEADER64` | 3.5 |
| DataDirectory | `IMAGE_DATA_DIRECTORY` × 16 | 3.5 |
| 节表 | `IMAGE_SECTION_HEADER` × N（每项 40 字节） | 3.6 |
| 导出表 | `IMAGE_EXPORT_DIRECTORY` | 3.8 |
| 导入表 | `IMAGE_IMPORT_DESCRIPTOR` 数组 | 3.7 |

运行（WSL 里 Windows 盘挂在 `/mnt/c`）：

```bash
python3 parse_pe.py /mnt/c/Windows/System32/cryptbase.dll
```

输出（3.3–3.5 逐行解读；节表、导入表两段在 3.6、3.7 单独展开）：

```
[DOS头] magic=MZ  e_lfanew(0x3C处)=0xf0
[COFF] machine=0x8664(x64)  NumberOfSections=7  SizeOfOptionalHeader=0xf0  Characteristics=0x2022(DLL)
[Optional] magic=0x20b(PE32+)  entry=0x11e0  ImageBase=0x180000000  SectionAlign=0x1000  FileAlign=0x1000
           SizeOfImage=0xc000  SizeOfHeaders=0x1000  Subsystem=3(CUI)  DataDirectory项数=16
[DataDirectory] 导出表 rva=0x5ee0 size=0x16c  导入表 rva=0x604c size=0xdc
```

### 3.3 DOS 头与 PE 签名

先看文件最开头的字节：

```bash
xxd -l 64 /mnt/c/Windows/System32/cryptbase.dll
xxd -s 0xf0 -l 16 /mnt/c/Windows/System32/cryptbase.dll
```

输出：

```
00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............
00000030: 0000 0000 0000 0000 0000 0000 f000 0000  ................
000000f0: 5045 0000 6486 0700 fc38 b595 0000 0000  PE..d....8......
```

三个事实：

- `4d 5a` 是 `"MZ"`，DOS 头的 `e_magic` 字段——这套格式从 1981 年的 DOS 沿用至今，MZ 是当时链接器作者 Mark Zbikowski 的姓名缩写；
- 偏移 0x3C 处的 4 字节按小端读出 `f0 00 00 00`，即 `e_lfanew = 0xf0`——真正的 PE 头在文件偏移 0xf0 处。DOS 头固定 64 字节，其余字段（`e_cblp`、`e_cp` 等）只对 16 位 DOS 有意义，现代解析只取 `e_lfanew`；
- 0xf0 处 `50 45 00 00` 是 `"PE\0\0"` 签名，紧跟的 `64 86` 按小端是 `0x8664`，即 Machine 字段（x64）。

脚本开头两行做的正是这两件事：`assert data[:2] == b"MZ"` 校验 `e_magic`，`struct.unpack_from("<I", data, 0x3C)` 读 `e_lfanew`。

0x40 到 0xef 之间是 DOS stub：一段 16 位 DOS 程序，在 DOS 上运行会打印 "This program cannot be run in DOS mode." 后退出。Windows 加载器不执行它，只按 `e_lfanew` 跳到 PE 头。有些构建工具会在这段塞自己的信息（少数编译器放提示文本），做特征扫描时可以看一眼。

### 3.4 COFF 头：PE 签名后的 20 字节

`IMAGE_FILE_HEADER` 紧跟 `"PE\0\0"`，共 20 字节、7 个字段：

| 偏移 | 字段 | cryptbase 的值 | 含义 |
| ---- | ---- | ---- | ---- |
| +0 | `Machine` (2B) | `0x8664` | CPU 架构：`0x8664` x64，`0x014c` i386，`0xAA64` ARM64 |
| +2 | `NumberOfSections` (2B) | `7` | 节数，节表循环的次数（脚本直接用它） |
| +4 | `TimeDateStamp` (4B) | `0x95b538fc` | 编译时间戳，含义见下方折叠框 |
| +8 | `PointerToSymbolTable` (4B) | `0` | COFF 符号表偏移，现代 PE 一律 0（符号在独立 PDB 文件里） |
| +12 | `NumberOfSymbols` (4B) | `0` | 同上 |
| +16 | `SizeOfOptionalHeader` (2B) | `0xf0` | Optional Header 的大小；==节表起点 = COFF 头偏移 + 20 + 这个值== |
| +18 | `Characteristics` (2B) | `0x2022` | 标志位集合，见下 |

`Characteristics = 0x2022` 按位拆开是三个常用标志：

| 位 | 名称 | 含义 |
| ---- | ---- | ---- |
| `0x0002` | `IMAGE_FILE_EXECUTABLE_IMAGE` | 可执行映像 |
| `0x0020` | `IMAGE_FILE_LARGE_ADDRESS_AWARE` | 64 位/大地址感知 |
| `0x2000` | `IMAGE_FILE_DLL` | 是 DLL 而不是 EXE |

脚本里的 `chars & 0x2000` 就是在测 DLL 位；格式串 `"<HHIIIHH"` 对应上表 7 个字段，合计 20 字节。

> [!info]- TimeDateStamp 的现代含义
> 本文件的 `0x95b538fc` 按 Unix 时间戳换算落在 2049 年——显然不是真实编译时间。微软的构建管线用可复现构建哈希填充该字段（同一文件的 debug 目录里有 `Repro` 类型条目可佐证），因此==不能拿系统 DLL 的 TimeDateStamp 换算编译日期==。自己做时间线分析时，对这类文件要改用其他来源。

### 3.5 Optional Header

COFF 头之后是 Optional Header（名字里的 Optional 是历史遗留：目标文件没有它，可执行映像都有）。脚本对它的输出见 3.2 末尾的 `[Optional]` 与 `[DataDirectory]` 两行。关键字段（偏移从 Optional Header 起算）：

| 偏移 | 字段 | cryptbase 的值 | 含义 |
| ---- | ---- | ---- | ---- |
| +0 | `Magic` (2B) | `0x20b` | `0x20b` = PE32+（64 位），`0x10b` = PE32（32 位），解析前先分流 |
| +16 | `AddressOfEntryPoint` (4B) | `0x11e0` | 入口 RVA，作用同 ELF 的 `e_entry`；按 4.2 加基址得实际入口 VA = 0x1800011e0 |
| +24 | `ImageBase` (8B) | `0x180000000` | 首选装载基址；DLL 默认 0x180000000，EXE 常见 0x140000000 |
| +32 | `SectionAlignment` (4B) | `0x1000` | 节在**内存**中的对齐粒度 |
| +36 | `FileAlignment` (4B) | `0x1000` | 节在**文件**中的对齐粒度（两者的差别是 3.6 换算的关键） |
| +56 | `SizeOfImage` (4B) | `0xc000` | 映像在内存中的总大小（按 SectionAlignment 向上取整） |
| +60 | `SizeOfHeaders` (4B) | `0x1000` | 所有头 + 节表的总大小 |
| +68 | `Subsystem` (2B) | `3` | 2 = GUI 程序，3 = CUI 控制台程序 |
| +108 | `NumberOfRvaAndSizes` (4B) | `16` | DataDirectory 的项数 |
| +112 | `DataDirectory` (16 × 8B) | 见下 | 数据目录数组，每项（RVA 4B + Size 4B） |

DataDirectory 是 PE 的"目录页"：16 个下标各指向一类信息。脚本只用第 0、1 项：

| 下标 | 内容 | cryptbase 的值 |
| ---- | ---- | ---- |
| 0 | 导出表 | RVA `0x5ee0`，大小 `0x16c` |
| 1 | 导入表 | RVA `0x604c`，大小 `0xdc` |

`objdump -p` 打印的 DataDirectory 与脚本一致：

```bash
objdump -p /mnt/c/Windows/System32/cryptbase.dll | grep -E 'Entry (0|1|2|3) '
```

输出：

```
Entry 0 0000000000005ee0 0000016c Export Directory [.edata (or where ever we found it)]
Entry 1 000000000000604c 000000dc Import Directory [parts of .idata]
Entry 2 000000000000a000 00000410 Resource Directory [.rsrc]
Entry 3 0000000000008000 000001ec Exception Directory [.pdata]
```

> [!info]- DataDirectory 常用下标
> 0 导出表；1 导入表；2 资源（`.rsrc`）；3 异常（`.pdata`，x64 展开信息）；5 基址重定位（`.reloc`）；14 CLR 元数据（.NET 程序从这里识别）。完整清单见 Microsoft 的 PE Format 文档。

> [!warning] 两个高频错位点
> 一是把偏移记错：+64 到 +67 是 **CheckSum**（cryptbase 为 `0x0001e444`），**Subsystem 在 +68**——把 64 当 Subsystem 偏移，读出来的是校验和。二是 DataDirectory 的起点与位宽有关：PE32+ 在 +112，PE32 在 +96（PE32 的 ImageBase 只有 4 字节且多一个 BaseOfData 字段）。==写死偏移前，先读 Magic 分流，再用 `objdump -p` 交叉核对一遍==。

### 3.6 节表与 RVA 换算

节表紧跟 Optional Header，每项 40 字节 `IMAGE_SECTION_HEADER`。cryptbase 的节表（3.2 脚本输出）：

```
[节表]
  名称       VirtualAddress  VirtualSize SizeOfRawData PointerToRawData
  .text          0x1000      0x2bc6        0x3000           0x1000
  .rdata         0x4000      0x2660        0x3000           0x4000
  .data          0x7000       0x660        0x1000           0x7000
  .pdata         0x8000       0x1ec        0x1000           0x8000
  .didat         0x9000        0x60        0x1000           0x9000
  .rsrc          0xa000       0x410        0x1000           0xa000
  .reloc         0xb000        0x44        0x1000           0xb000
```

脚本里 `"<8sIIII"` 解包的前 5 个字段（每项后 16 字节是 Characteristics 权限标志，脚本未打印）：

| 字段 | 含义 |
| ---- | ---- |
| `Name` (8B) | 节名，`\0` 结尾（不足 8 字节补零） |
| `VirtualSize` | 节在内存里的实际大小 |
| `VirtualAddress` | 节的起始 **RVA**（不是 VA；加载后按 4.2 加 ImageBase） |
| `SizeOfRawData` | 节在**文件**里占的大小，按 FileAlignment 向上取整 |
| `PointerToRawData` | 节在**文件**里的起始偏移 |

七个节各自存放：`.text` 代码；`.rdata` 只读数据（导入表、导出表的字符串都在这里）；`.data` 可写数据；`.pdata` 异常展开表，角色对应 ELF 的 `.eh_frame`；`.didat` 延迟加载导入的描述（本 DLL 有延迟加载依赖，见 3.7 末尾的 delayload 条目）；`.rsrc` 资源（图标、版本信息）；`.reloc` 基址重定位表，ASLR 下装载器按它修正指针，角色对应 ELF 的 `.rela.dyn`。

RVA 换算文件偏移：先确定 RVA 落在哪个节（`VirtualAddress ≤ RVA < VirtualAddress + 节大小`），然后

$$\text{文件偏移} = \text{RVA} - \text{节 VirtualAddress} + \text{节 PointerToRawData} \tag{4.3}$$

这就是脚本 `rva2off` 的三行逻辑。两个注意点：

1. **cryptbase 恰好是恒等换算**：SectionAlignment = FileAlignment = 0x1000，且每个节的 PointerToRawData 等于自己的 VirtualAddress，所以 RVA 与文件偏移数值相同（导出表 RVA 0x5ee0 按公式：0x5ee0 − 0x4000 + 0x4000 = 0x5ee0）。==这是本文件的巧合，不是 PE 的规则==。
2. **VirtualSize 与 SizeOfRawData 经常不等**：`.text` 是 0x2bc6 对 0x3000——后者按 FileAlignment 向上取整。判断 RVA 归属时取两者较大者（脚本的 `max(vsize, rsize)`）。

换算不必恒等的实例——`C:\Windows\System32\X3DAudio1_2.dll`（21,000 字节，SectionAlignment 0x1000，**FileAlignment 0x200**）：

```bash
python3 parse_pe.py /mnt/c/Windows/System32/X3DAudio1_2.dll
```

输出：

```
[DOS头] magic=MZ  e_lfanew(0x3C处)=0xe0
[COFF] machine=0x8664(x64)  NumberOfSections=4  SizeOfOptionalHeader=0xf0  Characteristics=0x2022(DLL)
[Optional] magic=0x20b(PE32+)  entry=0x2c30  ImageBase=0x78500000  SectionAlign=0x1000  FileAlign=0x200
           SizeOfImage=0x7000  SizeOfHeaders=0x400  Subsystem=3(CUI)  DataDirectory项数=16
[DataDirectory] 导出表 rva=0x3160 size=0x71  导入表 rva=0x300c size=0x3c
[节表]
  名称       VirtualAddress  VirtualSize SizeOfRawData PointerToRawData
  .text          0x1000      0x21d1        0x2200            0x400
  .data          0x4000       0x128        0x200           0x2600
  .pdata         0x5000       0xb4         0x200            0x2800
  .rsrc          0x6000       0x3d8        0x400            0x2a00
[导出表] 模块名=X3DAudio1_2.dll  导出函数数=2  具名数=2
[导入表]
  msvcrt.dll: acosf cosf sinf sin sqrt _initterm ...共11个
  KERNEL32.dll: Sleep DisableThreadLibraryCalls
```

它的导入表 RVA 是 0x300c，套用 4.3 完整走一遍：

1. **定位节**：`.text` 的 VirtualAddress = 0x1000，节大小取 max(0x21d1, 0x2200) = 0x2200，覆盖范围 [0x1000, 0x3200)，0x300c 落在其中（这个 DLL 没有 `.rdata`，只读数据接在代码后面）；
2. **算偏移**：文件偏移 = 0x300c − 0x1000 + 0x400 = **0x240c**；
3. **读导入描述符**：

```bash
xxd -s 0x240c -l 20 /mnt/c/Windows/System32/X3DAudio1_2.dll
```

输出：

```
0000240c: 6030 0000 0000 0000 0000 0000 1431 0000  `0...........1..
0000241c: 1810 0000                                ....
```

按 `IMAGE_IMPORT_DESCRIPTOR` 的字段（见 3.7）解读 20 字节：OriginalFirstThunk = 0x3060，TimeDateStamp = 0，ForwarderChain = 0，Name RVA = **0x3114**，FirstThunk = 0x1018。

4. **算 DLL 名字的偏移**：0x3114 − 0x1000 + 0x400 = **0x2514**：

```bash
xxd -s 0x2514 -l 16 /mnt/c/Windows/System32/X3DAudio1_2.dll
```

输出：

```
00002514: 6d73 7663 7274 2e64 6c6c 0000 9902 6d61  msvcrt.dll....ma
```

ASCII 直接可读：`msvcrt.dll`。两次换算全部对应真实字节，4.3 完整走了一遍。

还有一个换算盲区：RVA 小于第一节 VirtualAddress（本例小于 0x1000）时目标不在任何节里，而在 PE 头自身（0 到 SizeOfHeaders 的头区），`rva2off` 会拒绝这种输入（见 5 的常见问题）。

### 3.7 导入表与 IAT

DataDirectory 第 1 项指向的导入表，是一串 20 字节的 `IMAGE_IMPORT_DESCRIPTOR`，以一个全零项结束。每个描述符对应一个被依赖的 DLL：

| 偏移 | 字段 | 含义 |
| ---- | ---- | ---- |
| +0 | `OriginalFirstThunk` | 导入名字表（INT）的 RVA：逐项列出要导入的函数 |
| +4 | `TimeDateStamp` | 绑定时间戳，通常 0 |
| +8 | `ForwarderChain` | 转发链索引，通常 -1 |
| +12 | `Name` | DLL 名字的 RVA |
| +16 | `FirstThunk` | **IAT**（导入地址表）的 RVA |

INT 和 IAT 是两张并排的数组，加载前内容相同，每项 8 字节（PE32+），两种取值：

- **按名字导入**：值是 `IMAGE_IMPORT_BY_NAME` 结构的 RVA——2 字节 Hint 加函数名字符串。脚本里 `val & 0x7FFFFFFF` 取出 RVA、`no + 2` 跳过 Hint 读名字；
- **按序号导入**：最高位（PE32+ 的 bit 63，PE32 的 bit 31）置 1，低 16 位是序号。脚本里 `val & (1 << 63)` 判断、`val & 0xFFFF` 取序号。序号直接作为导出表的索引，不需要名字（3.8）。现代二进制按名字导入占绝大多数，按序号导入偶见于刻意减小体积或做混淆的文件。

装载过程：loader 读描述符 → 按名字找到依赖 DLL → 对 INT 的每一项在该 DLL 的导出表（3.8）里查出函数地址 → **把地址写进 IAT 的对应项**。代码里调用外部函数的形态是 `call QWORD PTR [IAT 项]`。==IAT 就是 Windows 版的 GOT==：改 IAT 某一项等于改写 GOT，API hook 的一半手法建立在这张表上（[[05-ELF文件格式与链接#6. 动态链接：printf@plt 的完整跳转链|延迟绑定]]的 Windows 对应物见下）。

cryptbase 的导入表完整输出：

```
[导入表]
  ntdll.dll: NtDeviceIoControlFile NtClose NtOpenFile RtlAppendUnicodeStringToString RtlAllocateHeap RtlCaptureContext ...共16个
  api-ms-win-core-libraryloader-l1-2-0.dll: DisableThreadLibraryCalls
  api-ms-win-core-profile-l1-1-0.dll: QueryPerformanceCounter
  api-ms-win-core-processthreads-l1-1-0.dll: GetCurrentThreadId GetCurrentProcessId GetCurrentProcess TerminateProcess
  api-ms-win-core-sysinfo-l1-1-0.dll: GetSystemTimeAsFileTime GetTickCount
  api-ms-win-core-errorhandling-l1-1-0.dll: SetUnhandledExceptionFilter UnhandledExceptionFilter
  api-ms-win-core-rtlsupport-l1-1-0.dll: RtlCompareMemory
  api-ms-win-core-xstate-l2-1-0.dll: GetEnabledXStateFeatures
  api-ms-win-core-delayload-l1-1-1.dll: ResolveDelayLoadedAPI
  api-ms-win-core-delayload-l1-1-0.dll: DelayLoadFailureHook
```

`api-ms-win-core-*` 是 Windows 的 **API Set** 虚拟模块名：它们本身没有实现，loader 按注册表规则把这些名字重定向到真正的实现 DLL。看到这类依赖，真实提供函数的是被重定向的目标模块。

最后两条 delayload 依赖与 3.6 的 `.didat` 节对应：cryptbase 的一部分导入是**延迟加载**的——启动时不解析，首次调用时经 `ResolveDelayLoadedAPI` 补解析，失败则调 `DelayLoadFailureHook`。机制上就是 Windows 版的延迟绑定，与 ELF 的 PLT/GOT 思路同源（[[05-ELF文件格式与链接#6. 动态链接：printf@plt 的完整跳转链|05 章第 6 节]]），只是描述信息单独放在 `.didat`。

### 3.8 导出表

DLL 对外提供函数靠导出表。DataDirectory 第 0 项（RVA 0x5ee0）指向一个 40 字节的 `IMAGE_EXPORT_DIRECTORY`，它后面挂三张并排的子表：

- **导出地址表（EAT）**：按导出序号顺序排列的函数 RVA 数组；
- **名字表**：导出名的 RVA 数组，按字典序排列（可用二分查找）；
- **序号表**：名字表第 i 项对应的 EAT 下标。

按名字查找的流程：在名字表里二分找到名字 → 得到它在名字表中的下标 i → 查序号表得 EAT 下标 → `EAT[下标]` 就是函数 RVA；按序号查找则直接用"序号 − OrdinalBase"做 EAT 下标。`objdump -p` 打印出 cryptbase 的完整结构：

```bash
objdump -p /mnt/c/Windows/System32/cryptbase.dll | sed -n '/The Export Tables/,/Table Addresses/p'
```

输出：

```
The Export Tables (interpreted .rdata section contents)

Export Flags 			0
Time/Date stamp 		95b538fc
Major/Minor 			0/0
Name 				0000000000005f76 CRYPTBASE.dll
Ordinal Base 			1
Number in:
	Export Address Table 		0000000b
	[Name Pointer/Ordinal] Table	0000000b
Table Addresses
	Export Address Table 		0000000000005f08
	Name Pointer Table 		0000000000005f34
	Ordinal Table 			0000000000005f60
```

11 个导出函数、11 个具名（3.2 脚本输出的 `[导出表]` 行与此一致），三张子表的 RVA 与脚本注释里的字段偏移（`Name@12`、`NumberOfFunctions@20`、`NumberOfNames@24`）对应同一结构。名字表内容：

```bash
objdump -p /mnt/c/Windows/System32/cryptbase.dll | sed -n '/Ordinal.Name Pointer/,+12p'
```

输出：

```
[Ordinal/Name Pointer] Table -- Ordinal Base 1
	          Ordinal   Hint Name
	[   0] +base[   1]  0000 SystemFunction001
	[   1] +base[   2]  0001 SystemFunction002
	[   2] +base[   3]  0002 SystemFunction003
	[   3] +base[   4]  0003 SystemFunction004
	[   4] +base[   5]  0004 SystemFunction005
	[   5] +base[   6]  0005 SystemFunction028
	[   6] +base[   7]  0006 SystemFunction029
	[   7] +base[   8]  0007 SystemFunction034
	[   8] +base[   9]  0008 SystemFunction036
	[   9] +base[ 10]  0009 SystemFunction040
	[ 10] +base[ 11]  000a SystemFunction041
```

两点值得记：第一，导出名与文档名可以完全不同——这组 `SystemFunction*` 是 Windows 哈希与随机数函数的内部名，`SystemFunction036` 在微软文档里就是 `RtlGenRandom`；第二，Ordinary 序号列从 OrdinalBase = 1 起算，按序号导入时用"序号 − 1"做 EAT 下标。导出表在 ELF 侧的对应物是 `.dynsym` 的导出部分（1.4），3.7 的 loader 正是在这张表里替 IAT 查地址。

> [!info]- 转发导出（forwarder）
> 若 EAT 里某项的 RVA 落在导出表自身范围内，这一项不是函数地址，而是一个 `"目标模块.函数名"` 形式的字符串——调用被转发给另一个模块。kernel32 的不少导出就是这样转发到 kernelbase 的。解析时遇到这种值，按字符串读出来即可。

### 3.9 对照样本：导入表为空的 DLL

换一个形态相反的样本：

```bash
python3 parse_pe.py /mnt/c/Windows/System32/lz32.dll
```

输出：

```
[DOS头] magic=MZ  e_lfanew(0x3C处)=0xc8
[COFF] machine=0x8664(x64)  NumberOfSections=2  SizeOfOptionalHeader=0xf0  Characteristics=0x2022(DLL)
[Optional] magic=0x20b(PE32+)  entry=0x0  ImageBase=0x180000000  SectionAlign=0x1000  FileAlign=0x1000
           SizeOfImage=0x3000  SizeOfHeaders=0x1000  Subsystem=3(CUI)  DataDirectory项数=16
[DataDirectory] 导出表 rva=0x1070 size=0x260  导入表 rva=0x0 size=0x0
[节表]
  名称       VirtualAddress  VirtualSize SizeOfRawData PointerToRawData
  .rdata         0x1000       0x3b0        0x1000           0x1000
  .rsrc          0x2000       0x3c8        0x1000           0x2000
[导出表] 模块名=LZ32.dll  导出函数数=14  具名数=14
[导入表]
  （这个 DLL 的导入表 rva=0：它一个外部函数都不需要）
```

12,288 字节、2 个节、导出 14 个函数，但导入表 RVA 为 0、入口点也是 0——它不引用任何外部函数，也没有初始化代码。这不是解析错误：现代 Windows 把一批老 DLL 的实现移走，文件里只剩一份导出名册，调用被 API Set 与转发导出重定向到别处。==系统目录里遇到"反常"的 PE，先核对 Windows 自身的机制（API Set、转发导出、延迟加载），再怀疑自己的解析逻辑==。

## 4. 实战任务：升级 05 章的 ELF 解析器

[[05-ELF文件格式与链接#10. 实操：手写一个 ELF 解析器|05 章的解析器]]能读头、节区表和符号表，但它写死要找 `.symtab`。喂给 stripped 程序会怎样：

```
Traceback (most recent call last):
  File "elf05.py", line 40, in <module>
    sym = next(shdr(i) for i in range(e_shnum) if secname(shdr(i)["name"]) == ".symtab")
StopIteration
```

stripped 程序没有 `.symtab`，`next()` 无匹配时抛 `StopIteration`。本章版补两件事：符号表缺席时退回 `.dynsym`；符号输出加绑定属性和 UND 标记，配合 1.4、2.2 的分析。

```python
#!/usr/bin/env python3
"""R4 版：头 + 节区表 + 符号表（.symtab 缺席时退回 .dynsym）。
用法：python3 r4_parse_elf.py <file>"""
import struct, sys

data = open(sys.argv[1], "rb").read()
assert data[:4] == b"\x7fELF", "not an ELF"
end = "<" if data[5] == 1 else ">"                        # 1 = 小端
(e_type, _mach, _v, e_entry, e_phoff, e_shoff, _f, _e,
 _p, e_phnum, _sz) = struct.unpack_from(end + "HHIQQQIHHHH", data, 16)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 58)
kind = {2:"EXEC（固定地址）", 3:"DYN（PIE/共享库）"}.get(e_type, hex(e_type))
print(f"type={kind}  entry={e_entry:#x}  shoff={e_shoff:#x}({e_shnum}项)")

def shdr(i):
    f = struct.unpack_from(end + "IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
    return dict(name=f[0], type=f[1], addr=f[3], off=f[4], size=f[5], link=f[6])

shstr = shdr(e_shstrndx)
def secname(s):
    o = shstr["off"] + s["name"]
    return data[o:data.index(b"\0", o)].decode()

secs = [shdr(i) for i in range(e_shnum)]

print("\n[节区表]")
for s in secs:
    if s["type"]:
        print(f"  {secname(s):<18} addr={s['addr']:#010x} size={s['size']:#x}")

ST_BIND = {0:"LOCAL", 1:"GLOBAL", 2:"WEAK"}
ST_TYPE = {0:"NOTYPE", 1:"OBJECT", 2:"FUNC", 3:"SECTION", 4:"FILE"}

def dump_syms(want, label):
    sec = next((s for s in secs if secname(s) == want), None)
    if sec is None:
        return False
    strtab = secs[sec["link"]]            # sh_link 指向关联的字符串表
    print(f"\n[{label}]")
    for i in range(sec["size"] // 24):
        st_name, st_info, _o, st_shndx, st_value, _sz = struct.unpack_from(
            end + "IBBHQQ", data, sec["off"] + i * 24)
        typ = ST_TYPE.get(st_info & 0xF, st_info & 0xF)
        if typ not in ("FUNC", "OBJECT") or not st_name:
            continue
        bind = ST_BIND.get(st_info >> 4, hex(st_info >> 4))
        o = strtab["off"] + st_name
        name = data[o:data.index(b"\0", o)].decode()
        where = "UND(外部)" if st_shndx == 0 else f"{st_value:#x}"
        print(f"  {bind:<7}{typ:<7}{name:<24}{where}")
    return True

if not dump_syms(".symtab", "符号表 .symtab"):
    dump_syms(".dynsym", "没有 .symtab —— 此程序被 stripped，退回 .dynsym")
```

逐段对照前文读：

1. **ELF 头**（1.2）：`data[5]` 是 e_ident 里的字节序；格式串 `"HHIQQQIHHHH"` 从偏移 16 起解包——前 16 字节是 e_ident，其后依次是 `e_type`(H)、`e_machine`(H)、`e_version`(I)、`e_entry`(Q)、`e_phoff`(Q)、`e_shoff`(Q)、`e_flags`(I)、各 2 字节的尺寸/数量字段；偏移 58 处的 `"HHH"` 是 `e_shentsize`、`e_shnum`、`e_shstrndx`；
2. **节区头**（1.1、1.3）：`"IIQQQQIIQQ"` 是 64 字节的 `Elf64_Shdr`，脚本取名字偏移、类型、地址、文件偏移、大小和 `sh_link`；
3. **节名**：`e_shstrndx` 指向 `.shstrtab`，每个节名是这张表里的偏移，`secname` 按此读 `\0` 结尾字符串；
4. **符号表**（1.4）：`"IBBHQQ"` 是 24 字节的 `Elf64_Sym`——`st_name`(I)、`st_info`(B)、`st_other`(B)、`st_shndx`(H)、`st_value`(Q)、`st_size`(Q)。`st_info & 0xF` 取类型、`st_info >> 4` 取绑定（同一个字节的两个半边）；`sh_link` 指向本符号表配套的字符串表；`st_shndx == 0` 即 UND；
5. **退回逻辑**：`next(..., None)` 找不到 `.symtab` 时返回 `None`，`dump_syms` 返回 False，改走 `.dynsym` 分支。

对 lic_full，`.symtab` 分支输出的用户函数与 2.1 的 `nm` 一致：

```
[符号表 .symtab]
  LOCAL  FUNC   deregister_tm_clones    0x4010f0
  …
  GLOBAL FUNC   _start                  0x4010b0
  GLOBAL FUNC   main                    0x401222
  GLOBAL FUNC   check_license           0x4011b2
  GLOBAL FUNC   rotl32                  0x401196
```

对 lic_strip，退回 `.dynsym`：

```
[没有 .symtab —— 此程序被 stripped，退回 .dynsym]
  GLOBAL FUNC   __libc_start_main       UND(外部)
  GLOBAL FUNC   puts                    UND(外部)
  GLOBAL FUNC   __stack_chk_fail        UND(外部)
  GLOBAL FUNC   printf                  UND(外部)
  GLOBAL FUNC   __isoc23_scanf          UND(外部)
```

与 2.3 互相印证：stripped 之后 `.dynsym` 里只剩导入函数，`main` 和 `check_license` 在任何表里都不存在。==解析器能把格式信息读干净，但程序自己函数的名字只能靠 2.2 的手工定位==——`.symtab` 删除后，没有任何结构记录"0x4011b2 叫 check_license"。工具与手工方法互补。

## 5. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| IDA 打开赛题全是 `sub_4011B2` | stripped 的正常形态。按 2.2 定位关键函数，IDA 里按 N 重命名；[[R05-静态分析工具链IDA与Ghidra\|R05 整章讲这个流程]] |
| `nm` 报 no symbols，IDA 里 `puts` 却有名字 | `puts` 的名字来自 `.dynsym`，导入函数永远在；程序自己的函数才是被删的对象 |
| `readelf -S` 报 "There are no sections" | 节区表被 sstrip 或壳删除，改用 `readelf -l` 看程序头、解析 `.dynamic` |
| PE 脚本报 `PE signature missing` | `e_lfanew` 指向处不是 `PE\0\0`：文件可能只是 MZ 开头的自解压包，或头部被改坏 |
| `VirtualSize` 和 `SizeOfRawData` 对不上 | 后者按 FileAlignment 向上取整，判断 RVA 归属取较大者（3.6） |
| `rva2off` 报"不在任何节里" | 目标可能落在 PE 头区（RVA 小于第一节 VirtualAddress 时在 SizeOfHeaders 内），或文件尾部有 overlay |
| PE32 程序解析出一堆乱码字段 | 用 PE32+ 的偏移解析了 PE32（或反之），先按 Optional Magic 分流（3.5） |
| `ldd` 报 not a dynamic executable | 静态链接文件，无依赖可列；链接方式以 `file` 为准（1.7） |

