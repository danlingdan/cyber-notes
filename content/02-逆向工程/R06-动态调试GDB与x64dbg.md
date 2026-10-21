---
chapter: 逆向工程
section: 动态调试：GDB 与 x64dbg
order: 206
tags:
  - CTF
  - 逆向工程
  - RE
  - GDB
  - x64dbg
publish: true
---

# R6 动态调试：GDB 与 x64dbg
## Dynamic Debugging: GDB & x64dbg

> [!info]- 章节信息
> **所属方向**：逆向工程 ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[R05-静态分析工具链IDA与Ghidra|R05 静态分析工具链]] · [[06-Python与CTF脚本基础|通用基础 06 章]] · [[04-汇编语言精要|04 汇编语言精要]]
> **本章目标**：掌握 GDB 的启动、断点、观察点、单步、数据查看、栈回溯六类核心命令；会用 strace / ltrace 观察程序行为；能对一个密钥运行时才组装的 crackme 完成动态 dump；能在 x64dbg 里用字符串引用定位校验函数；拿到同一个题，说得出静态和动态两条路各怎么走、什么时候该换路。

## 1. 动态调试解决什么问题

静态分析读的是磁盘上的文件。三类情况从文件里读不出答案：

- **数据运行时才生成**：密钥由程序启动后拼装，磁盘上任何位置都搜不到明文（[[#10. 实战：动态 dump 出密钥|第 10 节]]就是这种题）。
- **逻辑复杂到读不下去**：多层循环嵌套位运算，伪代码读几遍仍无法确定每一步的中间值。
- **程序自我保护**：有的程序校验自身代码有没有被改动，校验逻辑和业务逻辑混在一起。

动态调试的做法：把程序作为被调试进程启动，或附加到一个已经运行的进程；在指定位置停下，读寄存器和内存；再逐条指令执行、观察变化。==程序停下的那一刻，寄存器和内存里的全部中间结果都可以直接读出，不需要从代码反推==。

动态调试和静态分析的分工：静态分析给出函数分布、调用关系和每条指令的地址（这是下断点的依据），动态调试给出某一次运行中每个位置上的具体值。怎么在两条路之间选择，见 [[#11. 静态与动态怎么选|第 11 节]]。

[[06-Python与CTF脚本基础#6. GDB 最小工作集|06 章]]给过一组十几条命令的最小工作集（`b`、`r`、`ni`、`x` 等），本章不再重复，而是在它之上把 GDB 的核心命令逐类讲全，再讲两个行为观察工具，最后完成一次完整实战，并把同一套操作对应到 Windows 的 x64dbg。

两个全文通用的约定：本章按"命令 + 输出"成对展示，输出块标题写"输出："；需要一次执行多条 GDB 命令时写成命令文件（每行一条），用 `gdb -batch -x 文件名 ./程序` 执行，交互式则在 `(gdb)` 提示符下逐条输入，结果相同（`-batch` 表示命令跑完自动退出）。

## 2. GDB 的启动

### 2.1 三种启动方式

| 方式 | 命令 | 用途 |
| ---- | ---- | ---- |
| 调试新进程 | `gdb ./prog` | 最常用；程序以被调试状态启动，停在入口前等待命令 |
| 附加已运行进程 | `gdb -p PID`（或 `gdb ./prog PID`） | 程序已经在跑，中途接管；附加成功后进程暂停，`continue` 恢复运行 |
| 调试崩溃现场 | `gdb ./prog core` | 加载 core dump 文件离线分析崩溃 |

常用选项：`-q` 不打印版本与版权横幅；`help 命令名` 在 GDB 里随时查某条命令的用法；调试结束用 `detach` 让进程脱离调试器继续运行。

> [!warning] 附加操作可能被系统拒绝
> Linux 默认启用 yama ptrace 保护（`/proc/sys/kernel/yama/ptrace_scope` 为 1）时，`gdb -p` 附加"不是自己子进程"的程序会被拒绝，报错信息提示检查 ptrace_scope。解决办法：以 root 运行 GDB、把 ptrace_scope 临时改为 0，或者由被调试进程的父进程来启动 GDB。WSL 的默认内核就是这种配置，附加前先想到这一层。

### 2.2 传参：set args 与 run 的参数

被调试程序的命令行参数不是写给 gdb 的。两种给法：

- `set args hello 42`：先设好，之后每次 `run` 都带这组参数；`show args` 查看。
- `run hello 42`：只给这一次。

标准输入重定向跟在 `run` 后面：`run < in.txt`（06 章 PWN 流程里一直在用）。

```c
/* args.c —— 检查 argv 的内容 */
#include <stdio.h>

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);
    return 0;
}
```

```bash
gdb -q -batch -ex "set args hello 42" -ex "show args" -ex run ./args
```

输出：

```
Argument list to give program being debugged when it is started is "hello 42".
argv[1]=hello
argv[2]=42
[Inferior 1 (process 538) exited normally]
```

### 2.3 run、start、starti 的区别

| 命令 | 行为 |
| ---- | ---- |
| `run`（`r`） | 从程序入口完整运行，直到撞上断点或程序结束；没有断点就一口气跑完。再次 `run` 用同样的参数重启程序 |
| `start` | 先在 main 的第一条语句上设一个临时断点再运行——停在 main 开头，适合从入口开始跟 |
| `starti` | 同 `start`，但停在第一条**指令**上；动态链接的程序停在动态链接器 ld.so 的入口 |

```bash
gdb -q -batch -ex start ./step     # step.c 源码见 5.2 节
```

输出：

```
Temporary breakpoint 1 at 0x401162: file step.c, line 12.

Temporary breakpoint 1, main () at step.c:12
12	    r = add3(1, 2, 3);
```

```bash
gdb -q -batch -ex run ./step
```

输出：

```
6
[Inferior 1 (process 525) exited normally]
```

`start` 的输出里写明 Temporary breakpoint：临时断点命中一次后自动删除，下一次 `run` 不会再停在这里。`starti` 则停在更靠前的位置：

```bash
gdb -q -batch -ex starti ./step
```

输出：

```
Program stopped.
0x00007ffff7fe3340 in _start () from /lib64/ld-linux-x86-64.so.2
```

停在 ld.so 的 `_start`：动态链接程序的进程入口其实是加载器，之后才轮到程序自己的入口。

## 3. 断点

断点是动态调试的核心操作：先让程序停在可疑位置，才有后面的查看与单步。

### 3.1 软件断点：break 与 0xCC

`break`（缩写 `b`）四种下法：

```bash
b main           # 按函数名，停在函数序言之后（06 章讲过）
b *0x401171      # 按指令地址，必须带 *
b crackme.c:22   # 按源码行号，需要 -g 编译出的调试信息
tbreak main      # 临时断点：命中一次后自动删除
```

- 按函数名断会自动跳过序言，停在第一条"干活"的指令上；要停在函数第一个字节就用 `b *地址`。
- 行号断点依赖调试信息；strip 过的二进制只剩 `b *地址` 可用（地址从 IDA 或 objdump 里拿）。
- `tbreak` 的参数格式与 `break` 完全相同，区别只在命中一次后自动删除——2.3 节的 `start` 内部就是 tbreak main + run。

`b main` 之后 GDB 做的事：查出目标指令的地址，把该指令首字节备份，改写成 `0xCC`。`0xCC` 是 x86 的 int3 指令（单字节），CPU 执行到它就触发 3 号陷阱，控制权交回调试器；GDB 随即恢复原字节、把 rip 回退一条指令，程序停在原指令处，效果等同于从未修改过。==整个过程中磁盘上的程序文件一个字节没变，被改的只是内存里的进程镜像==。弱点也在这里：改内存这件事可以被代码段校验和发现，见 [[#3.4 硬件断点：hbreak|3.4 节]]。

### 3.2 断点的查看与管理

`info breakpoints`（缩写 `info b`）列出全部断点与观察点：

```
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x000000000040116d in main at watch.c:11
	breakpoint already hit 1 time
2       hw watchpoint  keep y                      secret
```

各列含义：Num 编号（后续管理命令用它指代）；Type 类型（breakpoint 软件断点、hw watchpoint 硬件观察点等）；Disp 处置方式（keep 一直保留，del 命中即删）；Enb 是否启用（y/n）；What 位置与命中计数。==`breakpoint already hit 1 time` 这样的命中计数是排障入口==：断点一直不生效，先看计数——计数为 0 说明程序根本没执行到那个位置，应该检查断点是不是下在了执行路径之外。

管理命令（N 为断点编号）：

| 命令 | 作用 |
| ---- | ---- |
| `disable N` | 停用该断点（Enb 变 n），不删除 |
| `enable N` | 恢复启用 |
| `delete N` | 删除该断点；不带编号的 `delete` 删除全部 |
| `clear 行号` | 删除该行上的断点 |

在 cond.c（源码见 3.3 节）上完整演示一遍：

```bash
# v_bp.gdb
break 8
break 9
tbreak 10
info breakpoints
disable 1
info breakpoints
enable 1
delete 2
info breakpoints
```

```bash
gdb -q -batch -x v_bp.gdb ./cond
```

输出：

```
Breakpoint 1 at 0x401152: file cond.c, line 8.
Breakpoint 2 at 0x401190: file cond.c, line 9.
Temporary breakpoint 3 at 0x4011a4: file cond.c, line 10.
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000401152 in main at cond.c:8
2       breakpoint     keep y   0x0000000000401190 in main at cond.c:9
3       breakpoint     del  y   0x00000000004011a4 in main at cond.c:10
Num     Type           Disp Enb Address            What
1       breakpoint     keep n   0x0000000000401152 in main at cond.c:8
2       breakpoint     keep y   0x0000000000401190 in main at cond.c:9
3       breakpoint     del  y   0x00000000004011a4 in main at cond.c:10
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000401152 in main at cond.c:8
3       breakpoint     del  y   0x00000000004011a4 in main at cond.c:10
```

三段输出依次对应：三个断点刚下完（第 3 个 Disp 是 del，即 tbreak）；`disable 1` 后第 1 行的 Enb 变 n；`delete 2` 后列表里只剩 1 和 3。

### 3.3 条件断点

完整语法：`break 位置 if 条件`。条件是 C 表达式，可以用变量、寄存器（`$rax`、`$rdi`）和强制类型转换。命中断点后 GDB 先求值，为真才停，为假则自动继续。对已经存在的断点补条件用 `condition 编号 条件`，`condition 编号`（不带条件）则取消条件。

```c
/* cond.c —— 十万次循环，条件断点只停一次 */
#include <stdio.h>

int main(void)
{
    int acc = 0;
    for (int i = 0; i < 100000; i++)
        acc += i * 3 % 7;
    printf("acc = %d\n", acc);
    return 0;
}
```

命令文件三步，十万次循环只在 i 等于 99997 那一趟停下：

```bash
# v_cond.gdb
break 8 if i == 99997
run
print i
print acc
```

输出：

```
Breakpoint 1 at 0x401152: file cond.c, line 8.

Breakpoint 1, main () at cond.c:8
8	        acc += i * 3 % 7;
$1 = 99997
$2 = 299988
acc = 300001
```

停在循环体第 8 行时，i 已是 99997，acc = 299988 是此前 99997 次累加的结果。==给比较函数的断点附加条件==是这套语法在逆向里最常见的用法，[[#10.3 换条路：断在 strcmp@plt 上|10.3 节]]有一条实战级的。

> [!warning] 条件断点不要下在 for 那一行
> `break 7 if i == 99997` 一次都不会停。用 `info line` 查两行各自对应的指令范围：
>
> 输出：
>
> ```
> Line 7 of "cond.c" starts at address 0x401149 <main+19> and ends at 0x401150 <main+26>.
> Line 8 of "cond.c" starts at address 0x401152 <main+28> and ends at 0x40115b <main+37>.
> ```
>
> 第 7 行（for 语句）对应的是初始化 `i = 0` 一类的指令，整个循环只执行一次，条件永远等不到 i 变成 99997；第 8 行（循环体）才会每次迭代都执行。==断循环要断循环体那一行==。`info line 行号` 可以查任意一行源码对应的地址范围。

### 3.4 硬件断点：hbreak

软件断点要改写内存字节，两个场景绕不开：程序对代码段做校验和自检（改动会被发现）；目标内存是只读页（改不了）。硬件断点不碰内存：地址写进 CPU 的调试寄存器 DR0–DR3，CPU 取指时由硬件比对地址，命中即触发陷阱交回调试器。DR0–DR3 一共 4 个寄存器，==硬件断点最多同时下 4 个==。除"执行到该地址"外，调试寄存器还支持"写入该地址时触发"，这正是观察点的实现基础（见 [[#4. 观察点：watch、rwatch、awatch|第 4 节]]）。

```bash
hbreak *0x401171   # 参数格式与 b *地址 相同
```

硬件断点依赖内核把调试寄存器接口提供给 ptrace。在没有提供的内核上（常见的 WSL 默认内核就是），会直接报错：

```
hb.gdb:3: Error in sourced command file:
No hardware breakpoint support in the target.
```

普通 Linux 真机和 VMware 虚拟机里硬件断点正常可用；x64dbg 的硬件断点走同一套寄存器，Windows 上可以直接使用。

## 4. 观察点：watch、rwatch、awatch

逆向中的高频问题：这个值在哪里被改的？观察点（watchpoint）盯住一个变量或一块内存，==被写入（或读取）的那一刻程序停下==，停下位置所在的函数就是修改者。

### 4.1 三种观察点与两种写法

| 命令 | 触发条件 |
| ---- | ---- |
| `watch 表达式` | 表达式的值**被写入**（发生改变）时停 |
| `rwatch 表达式` | **被读取**时停 |
| `awatch 表达式` | 被读取**或**写入时停 |

表达式的两种写法：

- `watch secret`：按变量名，GDB 从调试信息拿到类型和地址。
- `watch *(unsigned int *)0x404018`：按地址，指针类型决定一次盯几个字节（`long` 8 字节、`int` 4 字节、`char` 1 字节）。程序 strip 过、没有符号名时只能用这种写法。

### 4.2 实验：谁改了 secret

```c
/* watch.c —— secret 到底被谁改了 */
#include <stdio.h>

int secret = 0x1111;

void decoy(void)   { secret = secret + 1; }
void culprit(void) { secret = 0xbeef; }

int main(void)
{
    decoy();
    culprit();
    printf("secret = %x\n", secret);
    return 0;
}
```

```bash
# watch.gdb
break main
run
watch secret
continue
continue
continue
```

输出：

```
Hardware watchpoint 2: secret

Old value = 4369
New value = 4370
decoy () at watch.c:6
6	void decoy(void)   { secret = secret + 1; }
#0  decoy () at watch.c:6
#1  0x0000000000401172 in main () at watch.c:11

Hardware watchpoint 2: secret

Old value = 4370
New value = 48879
culprit () at watch.c:7
7	void culprit(void) { secret = 0xbeef; }
#0  culprit () at watch.c:7
#1  0x0000000000401177 in main () at watch.c:12
secret = beef
```

逐段读输出：

- `Old value = 4369`（十六进制 0x1111）→ `New value = 4370`：写入前与写入后的值。
- 停下的位置就是执行写入的函数：第一次停在 decoy 的第 6 行，第二次停在 culprit 的第 7 行。
- 每次停下 GDB 自动附上 `bt` 形式的两行栈（\#0 当前帧、\#1 调用者 main），==修改者是谁、从哪里调用过来，一次停下全部可见==。帧的概念见 [[#7. 栈与调用帧：bt、frame、info frame|第 7 节]]。

按地址写法盯同一个变量，不依赖符号名：

```bash
# watch.gdb —— 地址形式
break main
run
print &secret
watch *(unsigned int *)&secret
continue
continue
continue
```

输出：

```
Breakpoint 1 at 0x40116d: file watch.c, line 11.

Breakpoint 1, main () at watch.c:11
11	    decoy();
$1 = (int *) 0x404018 <secret>
Hardware watchpoint 2: *(unsigned int *)&secret

Hardware watchpoint 2: *(unsigned int *)&secret

Old value = 4369
New value = 4370
decoy () at watch.c:6
6	void decoy(void)   { secret = secret + 1; }

Hardware watchpoint 2: *(unsigned int *)&secret

Old value = 4370
New value = 48879
culprit () at watch.c:7
7	void culprit(void) { secret = 0xbeef; }
secret = beef
[Inferior 1 (process 499) exited normally]
```

`p &secret` 给出地址 0x404018（带符号名 `<secret>`），`watch *(unsigned int *)&secret` 按该地址盯 4 个字节，触发行为与按名写法一致。

两个限制要记：

> [!warning] 观察点的数量与作用域
> 观察点靠调试寄存器实现，==最多 4 个==；超出后 GDB 退回软件方式逐条指令比对，速度明显变慢，不要大量使用。另外盯局部变量时，函数返回、变量出作用域，观察点就自动失效（`info breakpoints` 里被标成 deleted）——要盯局部变量，先断进函数内部再下，或者改盯全局变量、堆地址。

碰到"输入进去之后中间值就没了"的题，第一反应就是 watch。

## 5. 单步执行

### 5.1 五个单步命令

| 命令 | 缩写 | 语义 |
| ---- | ---- | ---- |
| `next` | `n` | 执行到当前函数的**下一行源代码**；这一行里的函数调用整体执行完，不进入 |
| `step` | `s` | 执行到下一行源代码；这一行里有函数调用就**进入**，停在函数第一行 |
| `nexti` | `ni` | 执行**一条机器指令**；这条是 call 时把被调函数整个执行完，停在 call 的下一条 |
| `stepi` | `si` | 执行一条机器指令；这条是 call 时**进入**被调函数，停在第一条指令 |
| `finish` | — | 把**当前函数**剩余部分执行完，停在调用者的下一条指令，并打印返回值 |

区分方法：带 `i` 的是指令级，不带 `i` 的是源码级；next 类跨过调用，step 类进入调用；`finish` 只往外走。命令后面可以跟数字，`ni 5` 连续执行 5 条。有源码时用 `n`/`s`，逆向读汇编时用 `ni`/`si`。

### 5.2 实验：一次函数调用的进与出

```c
/* step.c —— 单步命令实验 */
#include <stdio.h>

int add3(int a, int b, int c)
{
    return a + b + c;
}

int main(void)
{
    int r;
    r = add3(1, 2, 3);
    printf("%d\n", r);
    return 0;
}
```

先用 objdump 找到 main 里调用 add3 的 call 指令地址 0x401171。x86-64 Linux / System V AMD64 ABI 下，调用前参数依次装入 edi、esi、edx（1、2、3）。

第一轮：断在 call 上，用 `ni` 跨过去。

```bash
# ni.gdb
break *0x401171
run
ni
print $rax
```

输出：

```
Breakpoint 1, 0x0000000000401171 in main () at step.c:12
12	    r = add3(1, 2, 3);
=> 0x401171 <main+27>:	call   0x401136 <add3>
0x0000000000401176	12	    r = add3(1, 2, 3);
=> 0x401176 <main+32>:	mov    DWORD PTR [rbp-0x4],eax
$1 = 6
```

`=>` 标记当前指令。`ni` 执行后 rip 从 0x401171 到 0x401176：call 整条执行完，add3 已经运行过，rax 里是返回值 6。

第二轮：同一位置改用 `si` 进入，再 `finish` 出来。

```bash
# si.gdb
break *0x401171
run
si
finish
print $rax
```

输出：

```
Breakpoint 1, 0x0000000000401171 in main () at step.c:12
12	    r = add3(1, 2, 3);
add3 (a=0, b=0, c=0) at step.c:5
5	{
=> 0x401136 <add3>:	endbr64
0x0000000000401176 in main () at step.c:12
12	    r = add3(1, 2, 3);
Value returned is $2 = 6
$3 = 6
=> 0x401176 <main+32>:	mov    DWORD PTR [rbp-0x4],eax
```

三个现象对应三个命令的语义：`si` 后停在 add3 的第一条指令 endbr64（0x401136）；`finish` 跑完 add3 剩余部分，停在调用者下一条指令 0x401176，并打印 `Value returned is $2 = 6`；最后 `$3 = 6` 是 `print $rax` 的结果——==返回值在 RAX，finish 的打印与直接读 RAX 互相印证==。

> [!warning] 停在函数第一条指令时，GDB 显示的参数是 0
> 上面输出里的 `add3 (a=0, b=0, c=0)`，实际传的参数是 1、2、3。原因：`si` 停在函数第一个字节，==序言（把寄存器实参存进栈槽的指令）还没执行==，GDB 按调试信息到栈槽里读，读到的是尚未写入的 0。用 `b add3` 按函数名断（停在序言之后）就没有这个现象。看到 GDB 报的参数全是 0，先确认自己停在哪条指令上。

跟踪一次函数调用的完整动作：断在 call → `si` 进入 → `ni` 逐条走 → `finish` 出来，从入口到返回一个来回。

### 5.3 continue 与断点自动化：commands

`continue`（缩写 `c`）从当前位置继续运行，直到下一个断点。断点还可以携带一段自动命令：每次命中先执行这段命令。逆向里用它自动打日志、自动放行。

语法：

```
break 位置 [if 条件]
commands
silent
命令……
continue        ← 通常以 continue 结尾：处理完自动放行
end
```

`silent` 让 GDB 不打印默认的断点命中提示，输出只剩自己定义的内容。

在 cond.c 上演示：每 25000 次循环打印一次进度，程序全程不停。

```bash
# v_cmd.gdb
break 8 if i % 25000 == 0
commands
silent
printf "i = %d, acc = %d\n", i, acc
continue
end
run
```

```bash
gdb -q -batch -x v_cmd.gdb ./cond
```

输出：

```
Breakpoint 1 at 0x401152: file cond.c, line 8.
i = 0, acc = 0
i = 25000, acc = 75000
i = 50000, acc = 149999
i = 75000, acc = 224997
acc = 300001
[Inferior 1 (process 647) exited normally]
```

四次命中（i = 0、25000、50000、75000）都由 commands 块打印后自动 continue，程序一路跑到结束。

## 6. 查看数据：print、x、display

### 6.1 print 与寄存器

`print`（缩写 `p`）对 C 表达式求值并打印，操作数可以是变量、寄存器、指针解引用和算式：

```bash
p input          # 变量：显示地址和内容（char 数组按字符串显示）
p $rdi           # 寄存器（默认十进制）
p/x $rdi         # 寄存器（十六进制）
p *buf           # 指针解引用
p buf[0] ^ 0x42  # 任意 C 表达式
```

格式后缀控制显示进制：不带后缀按声明类型显示，`p/x` 十六进制、`p/d` 有符号十进制、`p/u` 无符号十进制、`p/t` 二进制、`p/c` 字符。

在 crackme（[[#10.1 靶子与静态侦察|10.1 节]]的靶子，断在 check 入口）上：

```bash
# v_p.gdb
break check
run < in.txt
print input
print $rdi
print/x $rdi
info registers rdi rsi rdx
```

```bash
gdb -q -batch -x v_p.gdb ./crackme
```

输出：

```
Breakpoint 1 at 0x401266: file crackme.c, line 19.

Breakpoint 1, check (input=0x7fffffffe0c0 "1234567890") at crackme.c:19
19	{
$1 = 0x7fffffffe0c0 "1234567890"
$2 = 140737488347328
$3 = 0x7fffffffe0c0
rdi            0x7fffffffe0c0      140737488347328
rsi            0xa                 10
rdx            0x0                 0
```

三个注意点：`p input` 直接给出数组地址和字符串内容；`p $rdi` 打印的是**十进制** 140737488347328，==看地址一律加 `/x`==；`info registers` 后面跟寄存器名就只显示指定的几个（不带名字显示全部通用寄存器），两列分别是十六进制和十进制。x86-64 Linux / System V AMD64 ABI 下，函数前 6 个整型/指针参数在 RDI、RSI、RDX、RCX、R8、R9（[[04-汇编语言精要|04 章]]整章在讲），==断在函数入口扫一眼这几个寄存器，实参直接可见==。

再补一組 print 格式演示（cond.c 停在循环体内）：

```bash
# v_cond2.gdb
break 8 if i == 99997
run
print i
print/x i
print/u i
print/t i
```

输出：

```
Breakpoint 1 at 0x401152: file cond.c, line 8.

Breakpoint 1, main () at cond.c:8
8	        acc += i * 3 % 7;
$1 = 99997
$2 = 0x1869d
$3 = 99997
$4 = 11000011010011101
```

同一个值的十进制、十六进制、无符号、二进制四种显示。

### 6.2 x 命令完整语法

`print` 需要符号名，`x`（examine）只要一个地址——面对 strip 过、只剩地址的二进制，主要靠它。06 章给过速记，这里把语法讲全：

```
x/数量宽度格式 地址          例：x/16xb 0x7fffffffe080
```

三段修饰符可以组合，习惯按"数量、宽度、格式"的顺序写：

| 修饰段 | 取值 | 含义 |
| ---- | ---- | ---- |
| 数量 | 正整数 | 显示多少个**单元**；总读取字节数 = 数量 × 宽度 |
| 宽度 | `b` / `h` / `w` / `g` | 每单元 1 / 2 / 4 / 8 字节（byte、halfword、word、giant） |
| 格式 | `x` / `d` / `u` / `t` / `c` / `s` / `i` | 十六进制 / 有符号十进制 / 无符号十进制 / 二进制 / 字符 / 字符串 / 反汇编指令 |

常用组合：

| 命令 | 读到的东西 |
| ---- | ---- |
| `x/s 地址` | 按 NUL 结尾的字符串 |
| `x/16xb 地址` | 16 个字节，逐字节十六进制，看原始数据 |
| `x/6gx 地址` | 6 个 8 字节单元，共 48 字节；看栈用 `x/8gx $rsp` |
| `x/4xw 地址` | 4 个 4 字节字，共 16 字节 |
| `x/4i 地址` | 从地址反汇编 4 条指令 |

地址的写法：寄存器要加 `$`（`x/s $rax`）；有符号名的变量直接写名字；数字按字面地址。

新手最容易写错的三处：

1. ==寄存器漏 `$`==：`x/s rax` 不行，必须 `x/s $rax`。
2. ==数量 × 宽度算错总长==：想看 16 字节却写成 `x/16xw`，实际读 64 字节，后半段全是无关内存。
3. ==省略修饰段==：数量、宽度、格式都可省略，省略时沿用该段**上一次**使用的值——输出与预期不符的常见原因。建议三段写全。

第三点的实际效果，在 crackme 的密钥缓冲区上看（断在 build_key 返回后，`$rax` 指向拼好的密钥）：

```bash
# v_x.gdb
break build_key
run < in.txt
finish
x/s $rax
x/16xb $rax
x/6gx $rax
x/16x $rax
```

```bash
gdb -q -batch -x v_x.gdb ./crackme
```

输出：

```
Breakpoint 1 at 0x4011c6: file crackme.c, line 6.

Breakpoint 1, build_key (buf=0x7fffffffe080 "") at crackme.c:6
6	{
check (input=0x7fffffffe0c0 "1234567890") at crackme.c:22
22	    return strcmp(input, key) == 0;
Value returned is $1 = 0x7fffffffe080 "flag{dyn4m1c}"
0x7fffffffe080:	"flag{dyn4m1c}"
0x7fffffffe080:	0x66	0x6c	0x61	0x67	0x7b	0x64	0x79	0x6e
0x7fffffffe088:	0x34	0x6d	0x31	0x63	0x7d	0x00	0x00	0x00
0x7fffffffe080:	0x6e79647b67616c66	0x0000007d63316d34
0x7fffffffe090:	0x0000000001300000	0x0000000001300000
0x7fffffffe0a0:	0x0000000000000000	0x7bfac1d8c2040700
0x7fffffffe080:	0x6e79647b67616c66	0x0000007d63316d34
0x7fffffffe090:	0x0000000001300000	0x0000000001300000
0x7fffffffe0a0:	0x0000000000000000	0x7bfac1d8c2040700
0x7fffffffe0b0:	0x00007fffffffe110	0x000000000040130a
0x7fffffffe0c0:	0x3837363534333231	0x00007fffff003039
0x7fffffffe0d0:	0x000000b700000006	0x0000000000000000
0x7fffffffe0e0:	0x0000000000000000	0x0000000000000000
0x7fffffffe0f0:	0x0000000000000000	0x0000000000000000
```

逐段读：

- `x/s`：按字符串读，flag{dyn4m1c}。
- `x/16xb`：逐字节十六进制。0x66 0x6c 0x61 0x67 就是 f、l、a、g 的 ASCII；第 14 字节 0x00 是字符串结束符，其后两个 0x00 是栈上的相邻数据——==读多少由"数量 × 宽度"决定，读出来的不一定都属于目标数据==。
- `x/6gx`：每行 2 个 8 字节单元。第一个单元显示为 0x6e79647b67616c66，内存里字节序是 66 6c 61 67 7b 64 79 6e——==x86-64 是小端序，低字节在低地址==，按地址顺序读出来才是 "flag{dyn"。
- 最后的 `x/16x` 没写宽度，沿用了前一条 `x/6gx` 的 `g`，所以输出是 16 个 **8 字节**单元（128 字节）而不是 16 个字节——这就是"省略修饰段沿用上一次"的后果。

### 6.3 display：每次停下自动打印

`display/格式 表达式` 设置一个自动显示项：之后每次程序停下（断点命中、单步）都自动打印一次。跟踪循环变量、盯着 rip 附近的指令时，不用反复敲 print 或 x。

```bash
# v_disp.gdb
break step.c:12
run
display/i $pc
nexti
nexti
stepi
undisplay 1
nexti
```

```bash
gdb -q -batch -x v_disp.gdb ./step
```

输出：

```
Breakpoint 1 at 0x401162: file step.c, line 12.

Breakpoint 1, main () at step.c:12
12	    r = add3(1, 2, 3);
0x0000000000401167	12	    r = add3(1, 2, 3);
1: x/i $pc
=> 0x401167 <main+17>:	mov    $0x2,%esi
0x000000000040116c	12	    r = add3(1, 2, 3);
1: x/i $pc
=> 0x40116c <main+22>:	mov    $0x1,%edi
0x0000000000401171	12	    r = add3(1, 2, 3);
1: x/i $pc
=> 0x401171 <main+27>:	call   0x401136 <add3>
0x0000000000401176	12	    r = add3(1, 2, 3);
```

`display/i $pc` 是最常用的组合：`$pc` 就是 rip，每次停下显示下一条要执行的指令（`=>` 标记）。前三次单步都自动带出一行反汇编；`undisplay 1`（编号是显示项编号，`info display` 可以列出）删除该项后，最后一次单步就只剩停住位置的提示行。

## 7. 栈与调用帧：bt、frame、info frame

程序每次函数调用都会在栈上压一个**帧**（frame）：返回地址、保存的寄存器、参数与局部变量都放在里面。GDB 把最内层（当前正执行的函数）编号为第 0 帧，外层依次加一。

### 7.1 bt：回溯调用栈

`backtrace`（缩写 `bt`）显示全部调用帧：每行一个，当前函数在最上（第 0 帧），往下依次是各层调用者。`bt full` 在每帧下面附加该帧的参数和局部变量当前值。

### 7.2 frame、up、down：切换当前帧

print、info frame 这类命令作用于"当前帧"。`frame N` 切换到第 N 帧；`up` / `down` 向外层 / 内层移动一层；不带参数的 `frame` 显示当前在哪个帧。

### 7.3 info frame：当前帧的详细信息

```bash
# v_frame.gdb
break add3
run
bt
bt full
info frame
frame 1
bt
down
finish
```

```bash
gdb -q -batch -x v_frame.gdb ./step
```

输出：

```
Breakpoint 1 at 0x401147: file step.c, line 6.

Breakpoint 1, add3 (a=1, b=2, c=3) at step.c:6
6	    return a + b + c;
#0  add3 (a=1, b=2, c=3) at step.c:6
#1  0x0000000000401176 in main () at step.c:12
#0  add3 (a=1, b=2, c=3) at step.c:6
No locals.
#1  0x0000000000401176 in main () at step.c:12
        r = 0
Stack level 0, frame at 0x7fffffffe110:
 rip = 0x401147 in add3 (step.c:6); saved rip = 0x401176
 called by frame at 0x7fffffffe130
 source language c.
 Arglist at 0x7fffffffe100, args: a=1, b=2, c=3
 Locals at 0x7fffffffe100, Previous frame's sp is 0x7fffffffe110
 Saved registers:
  rbp at 0x7fffffffe100, rip at 0x7fffffffe108
#1  0x0000000000401176 in main () at step.c:12
12	    r = add3(1, 2, 3);
#0  add3 (a=1, b=2, c=3) at step.c:6
#1  0x0000000000401176 in main () at step.c:12
#0  add3 (a=1, b=2, c=3) at step.c:6
6	    return a + b + c;
0x0000000000401176 in main () at step.c:12
12	    r = add3(1, 2, 3);
Value returned is $1 = 6
```

逐段读：

- `bt`：两行。第 0 帧 add3（函数名断点停在序言后，参数显示正常：a=1、b=2、c=3），第 1 帧是 main。
- `bt full`：第 0 帧没有局部变量（No locals）；第 1 帧显示 `r = 0`——此刻 add3 还没返回，main 的 r 尚未赋值，这是栈上遗留的旧值。==bt full 显示的是"此刻"的值，不是"执行完之后"的值==。
- `info frame`（当前在第 0 帧）逐项：
  - `Stack level 0, frame at 0x7fffffffe110`：当前是第 0 帧，0x7fffffffe110 是该帧在栈上的边界地址。
  - `rip = 0x401147 in add3 (step.c:6)`：执行停在哪个地址、对应哪一行源码。
  - `saved rip = 0x401176`：==返回地址==——add3 执行 ret 后回到 main 的 0x401176。
  - `called by frame at 0x7fffffffe130`：调用者（第 1 帧）的帧位置。
  - `source language c.`：这一帧对应的源码语言。
  - `Arglist at 0x7fffffffe100, args: a=1, b=2, c=3`：参数信息存放的栈位置与参数值。
  - `Locals at 0x7fffffffe100, Previous frame's sp is 0x7fffffffe110`：局部变量区位置与上一帧的栈顶。
  - `Saved registers: rbp at 0x7fffffffe100, rip at 0x7fffffffe108`：序言压栈的调用者 rbp 与返回地址各自的存放地址。==手工分析栈布局、计算返回地址的偏移时，这两个地址就是直接依据==（PWN 的栈溢出正是围绕返回地址展开）。
- `frame 1` 切到 main 帧（GDB 打印该帧信息与当前源码行）；`bt` 不受当前帧影响，仍显示全部两帧；`down` 切回第 0 帧；`finish` 从 add3 跑出去并打印返回值。

逆向中的应用：断点停在关键函数后，`bt` 确认它从哪里被调用（哪条路径触发）；`bt full` 看各层帧的局部变量；`info frame` 拿到返回地址在栈上的确切位置。

## 8. GDB 插件：pwndbg、gef、peda

本章用的都是 GDB 原生命令。三个常用插件在原生命令之上提供更短的别名、彩色界面和一批封装好的命令：

| 插件     | 定位                                                                          | 代表功能                                                                                                |
| ------ | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| pwndbg | PWN 方向使用最广，本库默认安装（[[01-Linux环境与CTF实验环境搭建#5.2 pwntools 与 GDB 插件\|01 章 5.2]]） | 每次停下自动刷出上下文面板（寄存器、栈、反汇编同屏）；`search` 按字节/字符串搜内存；`cyclic` 生成模式串并反查偏移                                  |
| gef    | 单文件插件，一个 gef.py 写进 `~/.gdbinit` 即用                                          | `checksec` 查看二进制保护；`pattern create` / `pattern offset` 模式串生成与偏移反查；`format-string-helper` 格式化字符串漏洞辅助 |
| peda   | 老牌插件，稳定                                                                     | `checksec`；`pattern` 模式串；`xinfo 地址` 显示地址所属模块与偏移                                                     |

三家的断点、单步、读内存与原生命令是同一套机制，==先把原生命令练熟，插件是效率增强，不是另一套东西==。安装方式见 01 章 5.2，本章不重复。

## 9. strace 与 ltrace：观察程序行为

GDB 要下断点才停；strace 和 ltrace 不停程序，==把程序发起的每一次系统调用 / 库函数调用逐条记录==，适合回答"程序碰了哪些文件、连了哪些端口、收发了什么数据"。

### 9.1 strace：记录系统调用

[[04-汇编语言精要#10. 系统调用：程序开口找内核办事|04 章 10 节]]讲过系统调用机制并用 strace 看过 hello world。常用参数：

| 参数 | 作用 |
| ---- | ---- |
| （无参数） | 记录全部系统调用 |
| `-e trace=openat` | 只记录指定系统调用，逗号分隔多个：`-e trace=openat,read,write`；另有现成类别 `-e trace=file`（文件相关）、`-e trace=network`（网络相关） |
| `-f` | 跟随 fork 出的子进程与线程一起记录 |
| `-p PID` | 附加到已运行的进程（同样受 [[#2.1 三种启动方式\|2.1 节]]的 ptrace 限制） |
| `-c` | 不逐条打印，程序结束后输出统计表：每种调用的次数与出错次数 |
| `-o 文件` | 记录写入文件而不是标准错误 |

crackme 的文件打开记录：

```bash
strace -e trace=openat ./crackme < in.txt
```

输出：

```
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
key: Wrong key
+++ exited with 0 +++
```

统计模式：

```bash
strace -c ./crackme < in.txt
```

输出：

```
key: Wrong key
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
  0.00    0.000000           0         2           read
  0.00    0.000000           0         1           write
  0.00    0.000000           0         2           close
  0.00    0.000000           0         4           fstat
  0.00    0.000000           0         1           lseek
  0.00    0.000000           0         8           mmap
  0.00    0.000000           0         3           mprotect
  0.00    0.000000           0         1           munmap
  0.00    0.000000           0         3           brk
  0.00    0.000000           0         2           pread64
  0.00    0.000000           0         1         1 access
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         1           arch_prctl
  0.00    0.000000           0         1           set_tid_address
  0.00    0.000000           0         2           openat
  0.00    0.000000           0         1           set_robust_list
  0.00    0.000000           0         1           prlimit64
  0.00    0.000000           0         1           getrandom
  0.00    0.000000           0         1           rseq
------ ----------- ----------- --------- --------- ----------------
100.00    0.000000           0        37         1 total
```

（这两条输出用 9.2 节的免安装方式取得，命令形式与安装版相同。）

输出怎么读：

- 每行格式 `系统调用(参数) = 返回值`。返回 fd 的调用（如 openat）返回文件描述符编号，后续 read/write 用它指代同一个文件；read/write 返回实际读写的字节数。
- `= -1` 是失败的调用，尾部跟 errno 名与描述，例如 `openat(...) = -1 ENOENT (No such file or directory)` 表示文件不存在。==排查"程序为什么找不到文件"就搜 `= -1`==。
- `+++ exited with 0 +++` 表示进程结束，末尾是退出码。
- 程序自己的输出（key: Wrong key）和 strace 的记录会混在终端上：strace 的记录走标准错误，程序的输出走标准输出。
- `-e trace=openat` 的输出里只有两条：读 ld.so.cache（动态链接器的库路径缓存）、打开 libc.so.6——程序自己没有打开任何文件，只有加载器在工作。==列表里出现可疑路径才值得追查==。
- `-c` 统计表里共 37 次调用、1 次失败（errors 列的 1 来自 access，是加载器探测 /etc/ld.so.preload，属正常现象）。

### 9.2 无法安装时的免安装运行

标准装法 `sudo apt install strace ltrace`。没有 root 权限时，可以只下载 deb 包解包使用，不写入系统目录。思路与 [[01-Linux环境与CTF实验环境搭建#2.4 对齐目标程序的 glibc 版本|01 章 2.4]]的"借 loader 跑程序"相同，方向相反：借系统加载器直接指定库路径，运行解包出来的 strace：

```bash
cd /tmp && mkdir s6 && cd s6
apt-get download strace libunwind8 liblzma5
dpkg-deb -x strace_*.deb pkg && dpkg-deb -x libunwind8_*.deb pkg \
  && dpkg-deb -x liblzma5_*.deb pkg
/lib64/ld-linux-x86-64.so.2 \
  --library-path pkg/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu \
  pkg/usr/bin/strace ./crackme < in.txt
```

输出（中段省略若干行 libc 装载的 openat/mmap；execve 参数里的长路径已截断）：

```
execve("/mnt/c/.../crackme", ["./crackme"], 0x7ffce9a2b4a0 /* 29 vars */) = 0
read(0, "1234567890\n", 4096)           = 11
write(1, "key: Wrong key\n", 15)        = 15
exit_group(0)                           = ?
```

四行就是这次运行的完整轮廓：execve 启动程序；从标准输入读了 11 个字节（输入 10 个字符加换行）；向标准输出写了 15 个字节——`printf("key: ")` 没有换行符，内容留在缓冲区里，程序退出时与 puts 的输出合并成一次 write；exit_group 结束进程。==strace 跑完没看到可疑调用时，先确认程序真的执行到了那一步、输入喂对了没有==。

### 9.3 ltrace：记录库函数调用

ltrace 记录的是**库函数**这一层的调用，每行格式同样是 `函数(参数) = 返回值`，例如 strcmp 的两个参数会原样显示——输入串和正确答案并排出现，这就是逆向里它最常用的场景。常用参数与 strace 对应：`ltrace ./prog` 全量记录、`-e strcmp` 只看某个函数、`-p PID` 附加、`-f` 跟随子进程。

原理与局限：ltrace 在库函数的 PLT 项上下断点拦截调用，==静态链接的程序、不经过 PLT 的调用看不到==；高频调用时程序明显变慢。遇到记录不完整的程序，改用 GDB 直接断 `函数名@plt`（[[#10.3 换条路：断在 strcmp@plt 上|10.3 节]]）。

### 9.4 怎么选

| 要回答的问题 | 工具与命令 |
| ---- | ---- |
| 程序打开、写了哪些文件 | `strace -e trace=file` |
| 程序连了哪些地址和端口 | `strace -e trace=network` |
| 传给某个库函数的参数 | `ltrace -e 函数名`，或 GDB 断 `函数名@plt` |
| 程序卡在哪里、哪类调用最多 | `strace -c`；卡住的进程用 `-p` 附加再看 |
| 函数内部每一步的中间值（寄存器、内存级） | GDB——本章全部内容 |

==strace 和 ltrace 只能看到程序与库、内核的边界；要断进函数内部读寄存器和内存，仍然靠 GDB==。

> [!warning] strace 与 GDB 同源：ptrace
> strace 和 GDB 的附加依赖同一个内核机制 ptrace，被跟踪的进程可以感知自己正在被跟踪。遇到"一调试就退出"的反调试题，根源就在这里，处理方法属于反调试专题。

## 10. 实战：动态 dump 出密钥

### 10.1 靶子与静态侦察

一个"输入密钥"的 crackme，设计成密钥运行时才组装：seed 数组逐字节异或 0x42 写进栈缓冲区，源码和二进制里都搜不到明文：

```c
/* crackme.c —— 密钥运行时异或组装，源码里搜不到明文 */
#include <stdio.h>
#include <string.h>

char *build_key(char *buf)
{
    unsigned char seed[] = {
        0x24, 0x2E, 0x23, 0x25, 0x39, 0x26, 0x3B, 0x2C,
        0x76, 0x2F, 0x73, 0x21, 0x3F, 0x00
    };
    int i;
    for (i = 0; seed[i] != 0; i++)
        buf[i] = seed[i] ^ 0x42;
    buf[i] = '\0';
    return buf;                    /* 返回指针，rax 指着刚拼好的密钥 */
}

int check(char *input)
{
    char key[32];
    build_key(key);
    return strcmp(input, key) == 0;
}

int main(void)
{
    char input[64];
    printf("key: ");
    if (scanf("%63s", input) != 1)
        return 1;
    if (check(input))
        puts("Correct!");
    else
        puts("Wrong key");
    return 0;
}
```

编译：`gcc -O0 -g -no-pie -fno-pie crackme.c -o crackme`。`-O0` 关闭优化，机器码顺序与源码对应；`-g` 生成调试信息；`-no-pie -fno-pie` 关闭地址随机化，代码段固定从 0x400000 起，GDB 和 IDA 看到的地址一致。

先静态侦察：strings 只列出提示符和格式串（截取相关行），密钥不在磁盘上：

```bash
strings crackme
```

输出：

```
key: 
%63s
```

按 [[R05-静态分析工具链IDA与Ghidra|R05]]的流程，反编译里能看到两个业务函数：`check`（校验）和 `build_key`（组装密钥）。二进制没有 strip，`nm crackme` 就能列出符号；strip 过的程序用 IDA 找到地址，`b *0x40xxxx` 照样能断。校验逻辑在 check、密钥在 build_key 里成形，断点就下在这两个函数上。

### 10.2 四步流程：断点、回溯、finish、dump

完整命令文件（in.txt 内容是一行故意错误的输入 1234567890）：

```bash
# dump.gdb
break check
run < in.txt
x/s $rdi
bt
break build_key
continue
finish
x/s $rax
x/14xb $rax
continue
```

输出：

```
Breakpoint 1, check (input=0x7fffffffe0c0 "1234567890") at crackme.c:19
19	{
0x7fffffffe0c0:	"1234567890"
#0  check (input=0x7fffffffe0c0 "1234567890") at crackme.c:19
#1  0x000000000040130a in main () at crackme.c:31

Breakpoint 2, build_key (buf=0x7fffffffe080 "") at crackme.c:6
6	{
check (input=0x7fffffffe0c0 "1234567890") at crackme.c:22
22	    return strcmp(input, key) == 0;
Value returned is $1 = 0x7fffffffe080 "flag{dyn4m1c}"
0x7fffffffe080:	"flag{dyn4m1c}"
0x7fffffffe080:	0x66	0x6c	0x61	0x67	0x7b	0x64	0x79	0x6e
0x7fffffffe088:	0x34	0x6d	0x31	0x63	0x7d	0x00
key: Wrong key
[Inferior 1 (process 473) exited normally]
```

逐命令讲解：

1. `break check`：在校验函数入口下断点。选 check 而不是 main——校验发生时密钥已经就位。
2. `run < in.txt`：启动程序，标准输入来自 in.txt。命中断点，停在 crackme.c:19。
3. `x/s $rdi`：x86-64 Linux / System V AMD64 ABI 下第一个参数在 RDI。rdi 指向输入的字符串 1234567890——确认停对了位置、参数传对了。
4. `bt`：两行调用栈，check 由 main 的 0x40130a 调用。==回溯调用栈==，确认校验函数的触发路径。
5. `break build_key`：密钥在这个函数里组装，补第二个断点。
6. `continue`：从 check 入口继续运行，停在 build_key 入口。
7. `finish`：把 build_key 剩余部分执行完，停在调用者 check 里。==观察输入变换==到此完成——GDB 打印返回值 `Value returned is $1 = 0x7fffffffe080 "flag{dyn4m1c}"`：返回值是密钥缓冲区的地址，GDB 按字符串类型显示了内容。
8. `x/s $rax`：从返回值地址读字符串，拿到 flag{dyn4m1c}。
9. `x/14xb $rax`：按原始字节读 14 个——0x66 0x6c 0x61 0x67 是 "flag" 的 ASCII，结尾 0x7d 0x00 是 `}` 加结束符。==dump 内存==完成：密钥确实是一段栈上字节，由 strcmp 与输入比较。
10. `continue`：程序跑完输出 Wrong key——输入是错的，不影响已经拿到的密钥。

==密钥从未写入磁盘，它只存在于这次函数调用期间的栈内存里；动态调试恰好停在这段时间窗口内，所以能读到==。

### 10.3 换条路：断在 strcmp@plt 上

另一条路：校验必经 strcmp，直接断在 strcmp 的 PLT 项上。条件 `$rsi > 0x7ffffff00000` 是地址过滤——栈地址以 0x7ffffffe… 开头，libc 内部地址以 0x7ffff7… 开头；glibc 启动过程自己也会调 strcmp，这个条件把它们滤掉，只停在校验输入的那一次。

```bash
# plt.gdb
break strcmp@plt if $rsi > 0x7ffffff00000
run < in.txt
info registers rdi rsi
x/s $rdi
x/s $rsi
bt
```

输出：

```
Breakpoint 1, 0x00000000004010c0 in strcmp@plt ()
rdi            0x7fffffffe0c0      140737488347328
rsi            0x7fffffffe080      140737488347264
0x7fffffffe0c0:	"1234567890"
0x7fffffffe080:	"flag{dyn4m1c}"
#0  0x00000000004010c0 in strcmp@plt ()
#1  0x0000000000401294 in check (input=0x7fffffffe0c0 "1234567890") at crackme.c:22
```

比较发生的那条指令处停下：rdi 是输入，rsi 是正确答案，==一次断点同时拿到两个操作数==。

> [!warning] break strcmp 不命中：库函数要断在 PLT 上
> 直接 `break strcmp` 时，GDB 把断点解析到 libc 内部的某个具体实现符号上。glibc 用 IFUNC 机制在启动时按 CPU 支持挑选 strcmp 的实现变体（sse2、avx2 等），实际执行的变体很可能不是断点所在的那个——断点不报错、也不命中。==库函数断点断 `函数名@plt`==：PLT 是主程序自己的跳板段，所有对库函数的调用必经此处。备选方法：`objdump -d` 找到 `call strcmp@plt` 指令的地址，`b *地址` 断在 call 上看寄存器，效果相同。

### 10.4 用密钥通过校验

```
$ printf 'flag{dyn4m1c}\n' | ./crackme
key: Correct!
```

通过。这道题从头到尾没有读过校验算法本身——动态调试四个命令（断点、bt、finish、x）足够直接取回答案。

## 11. 静态与动态怎么选

同一个 crackme 也可以纯静态解。`objdump -d -M intel crackme` 读 build_key：seed 数组被编译成两条 movabs 立即数，循环体里逐字节异或（汇编节选，x86-64 Linux / System V AMD64 ABI）：

```asm
4011d5:	48 b8 24 2e 23 25 39 26 3b 2c  	movabs rax,0x2c3b263925232e24
4011df:	48 89 45 ea                    	mov    QWORD PTR [rbp-0x16],rax
4011e3:	48 b8 3b 2c 76 2f 73 21 3f 00  	movabs rax,0x3f21732f762c3b
401204:	83 f0 42                       	xor    eax,0x42
```

读到 `xor eax,0x42`，得知变换是逐字节异或 0x42，把 14 个 seed 字节抄进 Python 计算：

```
$ python3 -c "print(bytes(b ^ 0x42 for b in [0x24,0x2E,0x23,0x25,0x39,0x26,0x3B,0x2C,0x76,0x2F,0x73,0x21,0x3F]))"
b'flag{dyn4m1c}'
```

两条路得到同一个答案。这道题动态更快；如果变换换成 TEA 这类分组算法、循环十几轮，静态手推就不再有优势，动态读中间结果更直接。

| 场面 | 选哪条路 |
| ---- | ---- |
| 反编译伪代码一眼能看懂 | 静态读完直接写脚本 |
| 位运算多层嵌套、大循环、查表、逐字节变换 | 动态：断点读中间结果；或静态认出算法、动态验证结果 |
| 带反调试的程序 | 先静态读懂反调试逻辑，处理掉再动态调 |

==判断标准一句话：静态读得懂就读，读不懂就断==。动态的基本功是 [[#10.2 四步流程：断点、回溯、finish、dump|10.2 节]]的四步流程；后续逆向章节里两条路会交替使用。

## 12. x64dbg：Windows 下的动态调试

CTF 的 Windows 逆向题（多为 crackme.exe）常用 x64dbg。它的断点、单步机制与 GDB 相同——软件断点同样是 int3、单步同样是单步陷阱——差异在界面与平台约定。

### 12.1 安装、版本选择与界面

官网 x64dbg.com 下载，zip 解压即用，没有安装程序。release 目录下有两个调试器：==release/x64/x64dbg.exe 调试 64 位程序，release/x32/x32dbg.exe 调试 32 位程序==。位数不匹配时无法加载目标，动手前先用 `file prog.exe` 或文件属性确认位数再选。

界面五个分区，与 GDB 的对应关系：

| x64dbg 分区 | 对应 GDB | 内容 |
| ---- | ---- | ---- |
| 中间反汇编窗（CPU 窗口） | `disass` | 当前 rip 附近的指令 |
| 右上寄存器窗 | `info registers` | 全部寄存器实时刷新，刚变化的项高亮 |
| 左下内存 dump 窗 | `x` 命令 | 按地址读内存，可在字节/文本视图间切换 |
| 右下栈窗 | `x/8gx $rsp` | 当前栈顶内容 |
| 底部命令栏 | 命令行本身 | 可以直接输命令，如 `bp 地址` 下断点、`dc 地址` 按字符读内存 |

### 12.2 键位表

| 按键 | 作用 | 对应 GDB |
| ---- | ---- | ---- |
| F2 | 在光标地址设置/取消软件断点 | `b *地址` |
| F9 | 运行，到下一个断点停 | `continue` |
| F8 | 步过一条指令，不进入 call | `nexti`（ni） |
| F7 | 步入，进入 call | `stepi`（si） |
| F4 | 运行到光标所在地址 | 临时断点 + continue |
| Ctrl+F9 | 运行到当前函数返回 | `finish` |

### 12.3 字符串引用搜索定位校验函数

以"输入序列号"类 crackme 为例，目标：找到比较输入与正确答案的代码。完整操作路径（GUI 操作，无可复制的固定输出）：

1. File → Open 打开 crackme.exe。程序先停在系统断点（ntdll 里）——这是调试器接管进程时的正常现象，按 F9 运行到程序自己的界面。
2. 反汇编窗口右键 → Search for → All referenced strings，列出程序内全部静态字符串及其被引用的地址。
3. 找可疑串（"Wrong"、"Correct"、"成功"、"失败"这类提示语），双击跳到引用它的指令处。
4. 向上滚动到函数入口（`push rbp` 一类序言附近），按 F2 下断点。
5. F9 放行，在程序界面随便输入一串字符并提交，程序在断点处停下。
6. F8 步过、F7 步入，盯右上寄存器窗；走到比较指令（cmp/test）时，在寄存器上右键 → Follow in Dump，内存窗直接显示字符串内容。输入串与正确答案通常分别在两个寄存器里。
7. 运行时才解密的字符串在步骤 2 的列表里搜不到：改搜内存——Ctrl+G 跳到地址，右键 → Search for → Pattern 按字节序列搜；或先断在解密函数的出口再读。

### 12.4 GDB 到 x64dbg 概念对照

本章的 GDB 操作在 x64dbg 里全部有对应项（断点上右键 → Edit condition 可以像 `break N if` 一样设条件）：

| GDB（本章/06 章） | x64dbg | 备注 |
| ---- | ---- | ---- |
| `b *0x401171` | 选中地址按 F2 | 软件断点，同为 int3 |
| `si` / `ni` | F7 / F8 | 步入 / 步过 |
| `finish` | Ctrl+F9（Execute till return） | 跑完当前函数 |
| `info registers` | 右上寄存器窗 | 实时刷新 |
| `x/s 地址` | 内存 dump 窗 Ctrl+G 跳地址 | 右键切换字节/文本视图 |
| `watch 变量` | 内存窗右键 → Breakpoint on Write | 硬件观察点，同样最多 4 个 |
| `bt` | Call Stack 标签页 | 回溯调用栈 |
| `info proc mappings` | Memory Map 标签页 | 模块基址与页权限 |

> [!warning] 调用约定换成 Windows x64
> Windows x64 的前四个整型/指针参数走 RCX、RDX、R8、R9，更多参数走栈，调用方还要预留 32 字节 shadow space；返回值仍在 RAX（[[04-汇编语言精要#7. 函数调用：call / ret / 序言尾声|04 章 7 节]]）。在 Linux 下养成的"第一个参数看 rdi"，到 x64dbg 里要换成 rcx。==读寄存器之前先确认平台与调用约定==。

插件一句话：官方插件仓库提供 ScyllaHide（反反调试，隐藏调试器痕迹）等扩展，放进 release 同级的 plugins 目录重启生效。插件扩展的是界面与功能，==断点、单步、读内存的底层机制与 GDB 相同==。

## 13. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 断点下了程序不停 | 先看 `info breakpoints` 的命中计数；断在动态库加载前的地址要 `run` 之后再补断；PIE 程序每次基址不同，按函数名断更稳 |
| `break strcmp` 这类库函数断点不命中 | glibc 的 IFUNC 机制使实际执行的实现不是断点位置（[[#10.3 换条路：断在 strcmp@plt 上\|10.3]]）；改断 `函数名@plt` |
| 条件断点一次不停或极慢 | 条件永远为假（for 行的坑见 [[#3.3 条件断点\|3.3]]）或断点不在执行路径上；百万级循环每次命中都要评估表达式，改用观察点或把断点挪到函数边界 |
| `print x` 报 No symbol | 程序 strip 过没有调试信息，改用 `x` 按地址看；地址从 IDA/objdump 拿 |
| watch 一上就报 deleted | 盯的是局部变量，出了作用域就失效；改盯全局变量、堆地址，或先断在函数内部再 watch |
| `finish` 直接跑飞 | 在 main 里 finish 会一路跑回 libc 的启动函数；想停在自己的调用点，先在调用点下断 |
| run 后地址和 IDA 对不上 | GDB 默认关 ASLR，no-pie 程序基址固定，两者应一致；PIE 程序用 `info proc mappings` 查实际基址再换算 |
| `gdb -p` 附加被拒绝 | yama ptrace_scope 限制（[[#2.1 三种启动方式\|2.1]]）；以 root 运行或临时调低 ptrace_scope |
| hbreak 报 No hardware breakpoint support | 当前内核没有把调试寄存器接口提供给 ptrace（如 WSL 默认内核）；用软件断点，或换真机/虚拟机 |
| `x/s` 输出一长串乱码 | 地址不是字符串或缺少 NUL 结束符；改用 `x/16xb` 看原始字节再判断 |
| x64dbg 打不开目标程序 | 32/64 位版本选反了；或目标是 .NET 程序，换 dnSpy 之类专用工具 |
| x64dbg 搜不到目标字符串 | 字符串运行时才解密；先 F9 跑起来再搜，或按字节 Pattern 搜内存 |

