---
chapter: PWN
section: 前置基础：C、汇编与 Linux
order: 302
tags:
  - CTF
  - PWN
publish: true
---

# P2 前置基础：C、汇编与 Linux
## C, Assembly & Linux Prerequisites for PWN

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[P01-PWN导论与缓解机制全景|P1]] · [[02-C语言与内存模型|通用基础 02 章]] · [[04-汇编语言精要|通用基础 04 章]]
> **本章目标**：把已有基础换到利用视角——认全危险函数并给每个配上安全写法；弄清编译选项怎样改变栈布局、符号与保护；用 /proc/pid/maps 把进程五区和 ASLR 对上号；看懂 SUID 在题里的意义与 shellcode 的形态；最后把本地实验环境和题目环境对齐。

## 1. 同一套地基，换个方向用

[[01-Linux环境与CTF实验环境搭建|通用基础 01 章]]到 [[07-Linux进阶操作与Shell脚本|07 章]]站在写代码的立场教 C、汇编和 Linux：怎么编、怎么调、怎么用命令行。PWN 拿同一套知识回答另一类问题——程序哪里能被灌进超出预期的数据、灌进去之后能不能变成控制权。[[P01-PWN导论与缓解机制全景|P1]]的五步流程里，第 2 步"找漏洞点"靠危险函数清单，第 1 步"查保护"靠编译选项知识，第 3 步"算偏移"靠栈布局与 ASLR——本章把这三块地基从利用视角补齐。

| 已有章节 | 那边讲的 | PWN 里要回答的问题 |
| ---- | ---- | ---- |
| [[01-Linux环境与CTF实验环境搭建\|01 章]] | 装环境、命令行 | 题目附件的 libc 与本地对不上怎么办（7.3） |
| [[02-C语言与内存模型\|02 章]] | C 的内存模型、危险函数清单 | 清单逐个长什么样、编译器什么时候报警告（第 2 节） |
| [[04-汇编语言精要\|04 章]] · [[R03-x86与x64汇编精要复习\|R03]] | 读汇编 | 优化等级怎样改变栈布局与偏移（3.1） |
| [[07-Linux进阶操作与Shell脚本\|07 章]] | rwx 位、SUID、信号 | 题目二进制带 SUID 时，getshell 意味着什么（第 5 节） |

重叠的部分（C 语法、内存四区、序言尾声、rwx 位）一律一句带过配双链，不重讲。

## 2. 危险函数清单：逐个过一遍

[[02-C语言与内存模型#8. 字符串与危险函数|通用基础 02 章第 8 节]]给过清单和判断原则：==看输入长度是否受控，而不是只看函数名==。本节是这份清单的展开版——每个函数给"危险写法 vs 安全写法"，再看 `gcc -Wall` 什么时候报警告。全部程序都是最小可编译示例，用 `gcc -Wall -Wextra` 编译。

### 2.1 gets：完全没有长度上限

```c
/* 危险：char buf[16];
   gets(buf);                     —— 读到换行才停，buf 多大它不知道 */
char buf[16];
fgets(buf, sizeof buf, stdin);    /* 安全：容量是显式参数 */
```

`gets` 的参数里没有缓冲区大小，返回值也不含长度信息，==想检查也无从检查==。溢出的机理 [[P01-PWN导论与缓解机制全景#4. 危险函数初览：gets 为什么危险|P1 第 4 节]]已经拆过。工具链对它的表态只有一处：链接器警告 `the 'gets' function is dangerous and should not be used`（P1 5.1 的输出），`-Wall` 本身不再多话。C11 起它被移出语言标准，新版头文件不再提供声明，但 libc 里的实现还在，赛题附件里照样能用。

> [!info]- gets 的历史
> gets 是 C 语言历史上最著名的教训：1988 年的莫里斯蠕虫就利用它溢出 `fingerd`。C11 标准正式删除了它，glibc 从 2.16 起在链接时永久警告。==判断依据始终是"长度受不受控"==：把 gets 换成任何不带上限的读入方式，问题原样保留。

### 2.2 strcpy / strcat：只认 `\0` 的拷贝

两个函数都只知道源串的 `\0` 在哪，不知道目标槽有多大。`strcat` 更隐蔽：==目标里已有的内容也算进总长==，先找旧串结尾、再把源串整个接上去。

```c
/* 危险 */
char buf[16];
strcpy(buf, src);                 /* src 来自输入，长度不可控 */

/* 安全：自己算边界 */
strncpy(buf, src, sizeof buf - 1);
buf[sizeof buf - 1] = '\0';
```

源串恰好是字面量时，长度编译期就能算出来，gcc 会直接点名。编译 `dang_strcpy.c`（`buf2[16]` 装一个 31 字符的字面量）：

```bash
gcc -O0 -Wall -Wextra dang_strcpy.c -o dang_strcpy
```

输出：

```
dang_strcpy.c: In function ‘main’:
dang_strcpy.c:11:5: warning: ‘__builtin_memcpy’ writing 32 bytes into a region of size 16 overflows the destination [-Wstringop-overflow=]
   11 |     strcpy(buf2, "a name far beyond sixteen bytes");   /* 31 字节写进 16 字节槽 */
      |     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
dang_strcpy.c:10:10: note: destination object ‘buf2’ of size 16
   10 |     char buf2[16];
      |          ^~~~
```

警告把两件事都报了：要写 32 字节（31 个字符加 `\0`），目标只有 16。`strcat` 同族（`msg2[16]` 里已有 `user:`，再接 17 个字符）：

```bash
gcc -O0 -Wall -Wextra dang_strcat.c -o dang_strcat
```

输出：

```
dang_strcat.c: In function ‘main’:
dang_strcat.c:11:5: warning: ‘__builtin_memcpy’ writing 18 bytes into a region of size 16 overflows the destination [-Wstringop-overflow=]
   11 |     strcat(msg2, "alexandra-johnson");    /* 5 + 17 + 1 = 23，超出 16 */
      |     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
dang_strcat.c:10:10: note: destination object ‘msg2’ of size 16
   10 |     char msg2[16] = "user:";
      |          ^~~~
```

追加的部分是 18 字节（17 个字符加 `\0`），叠在已有 5 字节之后，需要 23，槽只有 16。==注意警告成立的前提：源串是编译期可知的字面量==。src 从参数或输入来时，同样的调用一行警告都没有——2.8 汇总。

### 2.3 sprintf / vsprintf：格式化结果没有上限

`sprintf` 把格式化结果写进缓冲区，总长由"格式串 + 每个参数展开后的长度"决定，==没有一个参数负责说"最多写多少"==。`vsprintf` 是它的 `va_list` 版本，同样无上限；带 `n` 的 `snprintf` 是安全替代（2.7）。

```c
/* 危险 */
char line[32];
sprintf(line, "player %s score %d", user_name, score);   /* user_name 多长都收 */

/* 安全 */
snprintf(line, sizeof line, "player %s score %d", user_name, score);
```

`dang_sprintf.c`（`line[32]` 装 32 字符的名字）：

```bash
gcc -O0 -Wall -Wextra dang_sprintf.c -o dang_sprintf
```

输出（节选）：

```
dang_sprintf.c: In function ‘main’:
dang_sprintf.c:12:27: warning: ‘%s’ directive writing up to 32 bytes into a region of size 25 [-Wformat-overflow=]
   12 |     sprintf(line, "player %s score %d", long_name, score);
      |                           ^~            ~~~~~~~~~
dang_sprintf.c:12:5: note: ‘sprintf’ output between 19 and 51 bytes into a destination of size 32
   12 |     sprintf(line, "player %s score %d", long_name, score);
      |     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

gcc 把输出长度的区间都算出来了（19 到 51 字节），上界超出 32。`sprintf` 还有第二重身份：==格式串本身被外部控制时，是格式化字符串漏洞的入口==，那是 [[P09-格式化字符串漏洞|P9]] 的主题，本节只管"写多长"。

### 2.4 scanf：`%s` 无宽度、`%d` 配错缓冲区

`scanf("%s", buf)` 与 gets 等价——遇到空白字符就停，==宽度完全不受限==。修法是加宽度：`scanf("%15s", buf)` 最多收 15 个字符，留 1 字节给 `\0`。

```c
/* 危险 */
char name[16];
scanf("%s", name);               /* 无宽度：输入多长写多长 */

/* 安全：宽度 = 容量 - 1 */
scanf("%15s", name);
```

第二类错法是格式符与缓冲区配错。`%d` 要求 `int *`，指向的目标必须恰好装下一个 int；给它一个 `char` 的地址，就会往 1 字节的槽里写 4 字节，==紧挨着的 3 个字节一起被改写==：

```c
/* 危险 */
char c = 0;
scanf("%d", &c);                 /* %d 要 int*，给的是 char* */

/* 安全 */
int d = 0;
scanf("%d", &d);
```

这类错不依赖输入长度，gcc 任何优化等级都能查出来：

```bash
gcc -O0 -Wall -Wextra dang_scanf.c -o dang_scanf
```

输出：

```
dang_scanf.c: In function ‘main’:
dang_scanf.c:12:13: warning: format ‘%d’ expects argument of type ‘int *’, but argument 2 has type ‘char *’ [-Wformat=]
   12 |     scanf("%d", &c);              /* %d 要 int*，给的是 char*：往 1 字节槽写 4 字节 */
      |            ~^   ~~
      |             |   |
      |             |   char *
      |             int *
      |            %hhd
```

警告末尾顺手给出正确写法：配 `char *` 的是 `%hhd`。与 2.2、2.3 不同，==`scanf("%s")` 没有任何边界警告==——输入多长在编译期完全未知，gcc 只在返回值被忽略时提一句（`-Wunused-result`，开优化后可见）。审题时看到 `%s` 就要下意识找宽度。

### 2.5 read / fgets：函数安全，参数用错照样溢出

`read` 和 `fgets` 本身都带长度参数，是推荐的安全函数；==错法是把长度给错==。`read` 的第三个参数想给成"buf 的两倍"，`fgets` 的第二个参数是总容量而不是"还能读多少"，给成两倍都直接越界：

```c
/* 危险：两个参数都给成 buf 的两倍 */
char buf[16];
read(0, buf, sizeof(buf) * 2);
fgets(buf, sizeof(buf) * 2, stdin);

/* 安全：容量写 sizeof，让编译器去算 */
read(0, buf, sizeof buf);
fgets(buf, sizeof buf, stdin);
```

长度写成了能算出来的表达式，新版 gcc 连这种错都能在编译期指出：

```bash
gcc -O0 -Wall -Wextra dang_readfgets.c -o dang_readfgets
```

输出（节选）：

```
dang_readfgets.c: In function ‘main’:
dang_readfgets.c:8:5: warning: ‘read’ writing 32 bytes into a region of size 16 overflows the destination [-Wstringop-overflow=]
    8 |     read(0, buf, sizeof(buf) * 2);        /* 想一次读多点：长度给了 buf 的两倍 */
      |     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~
dang_readfgets.c:9:5: warning: ‘fgets’ writing 32 bytes into a region of size 16 overflows the destination [-Wstringop-overflow=]
    9 |     fgets(buf, sizeof(buf) * 2, stdin);   /* 同样的错法：第二个参数是总容量，不是剩余空间 */
      |     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

每条警告后面还跟一行 note，说明依据是函数声明上的 `access (write_only, 1, 2)` 这类属性——库头文件提前告诉编译器"这个参数是往哪里写、写多大"。==前提依旧是长度可算==：长度来自变量时，这两行警告同样消失。

### 2.6 memcpy：长度外部可控

`memcpy(dst, src, n)` 是三个参数里最干净的设计：长度明明白白是第三个参数。==危险与否完全取决于 n 从哪来==：

```c
/* 危险：n 从输入来 */
void load_record(char *dst, const char *src, unsigned int len) {
    memcpy(dst, src, len);         /* len 来自输入，dst 只有一格 */
}

/* 安全：钳住上限再拷 */
void load_record_safe(char *dst, const char *src, unsigned int len) {
    if (len > sizeof dst)
        len = sizeof dst;
    memcpy(dst, src, len);
}
```

这类写法编译器完全安静——任何警告都不会出现：

```bash
gcc -O2 -Wall -Wextra dang_memcpy.c -o dang_memcpy
```

输出：

```
（编译通过，无任何警告）
```

"先检查再拷贝"的模式还藏着一层：==长度变量本身的算术缺陷会让检查失效==——减法回绕、有符号无符号混比、截断，[[02-C语言与内存模型#9. 整型转换陷阱|02 章第 9 节]]列过三类，落到题目上就是 [[P10-整数溢出与off-by-one|P10]] 的内容。另一个事实值得记住：[[R02-C语言与内存模型回顾#4. 指针与数组|R02]]说过，==反汇编里不存在"这个缓冲区多大"这个信息==，长度只能从读写范围反推——这就是审题时"找输入长度、找缓冲区大小"这两件事的难度所在。

### 2.7 安全替代：fgets、snprintf、strlcpy

三个替代有一个共同点：==容量必须显式出现在参数里==。

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char name[16];
    if (fgets(name, sizeof name, stdin) == NULL)   /* 三个参数：容量显式在场 */
        return 0;
    printf("name: %s", name);

    char line[32];
    int n = snprintf(line, sizeof line, "player %s score %d",
                     "alexandra-von-johnson-smithfield", 9527);
    printf("n = %d, stored = %zu: %s\n", n, strlen(line), line);

    char dst[8];
    size_t need = strlcpy(dst, "a very long source string", sizeof dst);
    printf("dst(%zu): %s, need %zu\n", strlen(dst), dst, need);
    return 0;
}
```

```bash
gcc -O2 safe_write.c -o safe_write
echo alice | ./safe_write
```

输出（编译的警告节选加运行结果）：

```
safe_write.c: In function ‘main’:
safe_write.c:12:49: warning: ‘%s’ directive output truncated writing 32 bytes into a region of size 25 [-Wformat-truncation=]
   12 |     int n = snprintf(line, sizeof line, "player %s score %d",
      |                                                 ^~
   13 |                      "alexandra-von-johnson-smithfield", 9527);
      |                      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
name: alice
n = 50, stored = 31: player alexandra-von-johnson-sm
dst(7): a very , need 25
```

逐行读：

- `fgets` 连换行符一起收进 `name`（打印 `alice` 后自带换行）——做题时这反而是便利：以 `\n` 结尾的输入正好喂给 gets 类漏洞点；要去掉换行手动处理。
- `snprintf` 的返回值 n 是==本想写多长==（不含 `\0`）：完整输出要 50 字节，`line` 只装下 31 个字符加 `\0`，截断发生但越界没有发生。编译时的 `-Wformat-truncation` 是同一条信息的另一种形式：==截断是 snprintf 的设计行为，不是漏洞，要看的是返回值==。
- `strlcpy` 拷贝并保证 `\0` 结尾：`dst[8]` 装下 7 个字符，返回值 need = 25 告诉你源串实际需要 25 字节的空间，==空间够不够由调用者据此判断==。

> [!info]- strlcpy 的可用性
> strlcpy 起源于 BSD，glibc 直到 2.38 才收编。老系统的 glibc 里没有声明，跨平台代码常见自带实现；题目源码里见到 `size_t strlcpy(char *, const char *, size_t)` 的手工实现，行为以 BSD 语义为准：截断加 `\0` 结尾，返回源串长度。

### 2.8 编译器警告能帮你多少

把前面各次的编译结果汇总成一张表（同一份代码，长度可知与长度来自输入两种形态对比）：

| 危险点 | 长度编译期可知时 gcc 的反应 | 长度来自输入时 |
| ---- | ---- | ---- |
| `gets` | 只有链接器警告 dangerous（P1 5.1 的输出） | 同左 |
| `strcpy` / `strcat` | `-Wstringop-overflow`，报出写字节数与目标大小 | 无警告 |
| `sprintf` / `vsprintf` | `-Wformat-overflow`，算出输出长度区间 | 无警告 |
| `scanf("%s")` 无宽度 | 无边界警告（仅返回值提醒） | 同左 |
| `scanf("%d")` 配错缓冲区 | `-Wformat` 类型不匹配，任何等级都报 | 同左（类型错，不依赖长度） |
| `read` / `fgets` 参数给错 | 长度是常量表达式时报 `-Wstringop-overflow` | 无警告 |
| `memcpy` 长度外部可控 | 无警告 | 无警告 |

> [!warning] 警告只覆盖"算得出来"的那一小块
> 赛题里的溢出点全部是"长度来自输入"的形态——出题人编译时一声不吭，你拿到的二进制上也没有任何标记。找漏洞点靠这份清单加反编译（[[R05-静态分析工具链IDA与Ghidra|R05]]），==不能指望工具链替你把关==。反过来，自己写练习程序时把 `-Wall -Wextra` 开成习惯，至少类型配错和字面量超长这类低级错当场暴露。

> [!info]- gcc 为什么抓得到这些
> 依据有两层。一层是库头文件里的函数属性：`access(write_only, …)` 声明"第几个参数是写入目标、大小由第几个参数决定"，编译器据此做边界分析，`-Wstringop-overflow`、`-Wformat-overflow`、`-Wformat-truncation` 都是它的产物。另一层是 FORTIFY_SOURCE：发行版默认开启，把 `strcpy`、`printf` 族、`read` 等调用在编译期换查运行期带检查的 `_chk` 版本，溢出发生时程序直接中止而不是静默写穿——它同时让"长度错"在编译期多一层警告。机制细节 [[P04-Linux安全缓解机制|P4]] 归拢。做题视角只要记住一条：==`_chk` 版本拦得住的是"长度参数与目标明显不符"，拦不住"长度本身合法但内容越界"的构造==。

## 3. 编译选项对利用的影响

[[02-C语言与内存模型#2.2 PWN 学习必会的编译选项|通用基础 02 章 2.2]]列过选项表，这里讲它们对利用脚本意味着什么。同一份源码，选项不同，产物就不同——==偏移、符号、保护全是产物的属性，不是源码的属性==。

### 3.1 `-O0` 与 `-O2`：布局会变，偏移要重新量

实验程序一个：`static` 的小函数 `vuln` 里放 64 字节缓冲区，`main` 调它。

```c
#include <stdio.h>
#include <unistd.h>

static void vuln(void) {
    char buf[64];
    read(0, buf, 64);
    write(1, buf, 64);
}

int main(void) {
    vuln();
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie layout.c -o layout_O0
gcc -O2 -fno-pie -no-pie layout.c -o layout_O2
```

输出：

```
layout.c: In function ‘vuln’:
layout.c:6:5: warning: ignoring return value of ‘read’ declared with attribute ‘warn_unused_result’ [-Wunused-result]
    6 |     read(0, buf, 64);
      |     ^~~~~~~~~~~~~~~~
layout.c:7:5: warning: ignoring return value of ‘write’ declared with attribute ‘warn_unused_result’ [-Wunused-result]
    7 |     write(1, buf, 64);
      |     ^~~~~~~~~~~~~~~~~
```

两条只是"返回值没看"的提醒，与本节无关。拆开对比（x86-64 Linux / System V AMD64 ABI，Intel 语法）：

```bash
objdump -d -M intel layout_O0
```

输出（节选，main 与 vuln 两个函数）：

```
00000000004011d4 <main>:
  4011d4:	f3 0f 1e fa          	endbr64
  4011d8:	55                   	push   rbp
  4011d9:	48 89 e5             	mov    rbp,rsp
  4011dc:	e8 95 ff ff ff       	call   401176 <vuln>
  4011e1:	b8 00 00 00 00       	mov    eax,0x0
  4011e6:	5d                   	pop    rbp
  4011e7:	c3                   	ret

0000000000401176 <vuln>:
  401176:	f3 0f 1e fa          	endbr64
  40117a:	55                   	push   rbp
  40117b:	48 89 e5             	mov    rbp,rsp
  40117e:	48 83 ec 50          	sub    rsp,0x50
  401182:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  401189:	00 00 
  40118b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  40118f:	31 c0                	xor    eax,eax
  401191:	48 8d 45 b0          	lea    rax,[rbp-0x50]
  401195:	ba 40 00 00 00       	mov    edx,0x40
  40119a:	48 89 c6             	mov    rsi,rax
  40119d:	bf 00 00 00 00       	mov    edi,0x0
  4011a2:	e8 d9 fe ff ff       	call   401080 <read@plt>
  4011a7:	48 8d 45 b0          	lea    rax,[rbp-0x50]
  4011ab:	ba 40 00 00 00       	mov    edx,0x40
  4011b0:	48 89 c6             	mov    rsi,rax
  4011b3:	bf 01 00 00 00       	mov    edi,0x1
  4011b8:	e8 a3 fe ff ff       	call   401060 <write@plt>
  4011bd:	90                   	nop
  4011be:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4011c2:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
  4011c9:	00 00 
  4011cb:	74 05                	je     4011d2 <vuln+0x5c>
  4011cd:	e8 9e fe ff ff       	call   401070 <__stack_chk_fail@plt>
  4011d2:	c9                   	leave
  4011d3:	c3                   	ret
```

`-O0` 的形状 [[R03-x86与x64汇编精要复习|R03]]熟过：帧指针在，`buf` 落在 `rbp-0x50`，序言取 `fs:0x28` 往 `rbp-0x8` 放 Canary——发行版自带的 gcc 默认就开栈保护，所以连"关保护的练习"之外的默认编译也带这一套。换 `-O2`：

```bash
objdump -d -M intel layout_O2
```

输出（节选，只剩一个函数）：

```
0000000000401090 <main>:
  401090:	f3 0f 1e fa          	endbr64
  401094:	48 83 ec 58          	sub    rsp,0x58
  401098:	31 ff                	xor    edi,edi
  40109a:	64 48 8b 14 25 28 00 	mov    rdx,QWORD PTR fs:0x28
  4010a1:	00 00 
  4010a3:	48 89 54 24 48       	mov    QWORD PTR [rsp+0x48],rdx
  4010a8:	ba 40 00 00 00       	mov    edx,0x40
  4010ad:	48 89 e6             	mov    rsi,rsp
  4010b0:	e8 cb ff ff ff       	call   401080 <read@plt>
  4010b5:	ba 40 00 00 00       	mov    edx,0x40
  4010ba:	48 89 e6             	mov    rsi,rsp
  4010bd:	bf 01 00 00 00       	mov    edi,0x1
  4010c2:	e8 99 ff ff ff       	call   401060 <write@plt>
  4010c7:	48 8b 44 24 48       	mov    rax,QWORD PTR [rsp+0x48]
  4010cc:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
  4010d3:	00 00 
  4010d5:	75 07                	jne    4010de <main+0x4e>
  4010d7:	31 c0                	xor    eax,eax
  4010d9:	48 83 c4 58          	add    rsp,0x58
  4010dd:	c3                   	ret
  4010de:	e8 7f fe ff ff       	call   401070 <__stack_chk_fail@plt>
```

三处变化：

1. ==`vuln` 没了==：`static` 且调用点唯一，-O2 直接内联进 main。符号表里也查不到了——`nm layout_O0 | grep vuln` 还有一行 `0000000000401176 t vuln`（小写 t 表示局部符号），换到 `layout_O2` 上一无所获；
2. ==帧指针没了==：没有 `push rbp; mov rbp,rsp`，一切以 rsp 为基准；
3. ==buf 的位置变了==：`mov rsi,rsp` 说明 buf 现在就压在 rsp 上，Canary 挪到 `rsp+0x48`。

从 buf 起点到返回地址：`-O0` 是 `0x50 + 8` = 88 字节，`-O2` 是 `0x58` = 88 字节——==这次恰好相等，纯属巧合==：布局由编译器按选项重新安排，换函数、换变量个数、换优化等级就不再重合。所以 [[02-C语言与内存模型#6.3 一个可以背下来的栈帧|02 章]]的警告在这里兑现成操作规程：==本地调好的偏移换一份二进制就要用 cyclic 重量（P1 5.4），利用脚本里不写死"源码推出来的偏移"，只写"这份产物量出来的偏移"==。

> [!info]- -O2 还会带来什么
> 除内联外：参数不再落栈（寄存器直传），少一批 `mov [rbp-x], edi`；没人调用的 `static` 函数被整体删除——出题人要让 `win` 活到运行期，通常给它外部链接或显式引用；指令重排与合并让 `-O2` 产物和源码的对应变松，[[R03-x86与x64汇编精要复习|R03]]的"代码形状"识别在 -O0 练，在 -O2 用。

### 3.2 `-g`：调试信息给谁看

`-g` 不改一行代码，只往产物里加 `.debug_*` 调试节（节视角，[[05-ELF文件格式与链接|通用基础 05 章]]）。有无 `-g`，GDB 里是两种体验：

```bash
gcc -O0 -g layout.c -o layout_g
gdb -q -batch -ex 'break main' -ex run -ex 'list' ./layout_g
```

输出：

```
Breakpoint 1 at 0x11ef: file layout.c, line 11.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main () at layout.c:11
11	    vuln();
6	    read(0, buf, 64);
7	    write(1, buf, 64);
8	}
9	
10	int main(void) {
11	    vuln();
12	    return 0;
13	}
```

去掉 `-g` 重编再跑：

```bash
gcc -O0 layout.c -o layout_nog
gdb -q -batch -ex 'break main' -ex run -ex 'list' ./layout_nog
```

输出：

```
Breakpoint 1 at 0x11ef
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x00005555555551ef in main ()
warning: 1	./elf/<built-in>: No such file or directory
```

带 `-g`：断点带文件名和行号，`list` 直接翻出源码，`ptype` 能看类型。不带：只有裸地址，源码无从谈起。==`-g` 对利用没有任何影响，影响的是调试效率==——赛题二进制不带源码也不带调试信息，`-g` 用在自己编译的练习程序和还原出的源码上。

### 3.3 静态与动态：gadget 的贫富差距

```c
#include <stdio.h>
int main(void) { puts("hello, pwn"); return 0; }
```

```bash
gcc -O0 hello.c -o hello_dyn
gcc -O0 -static hello.c -o hello_static
ls -l hello_dyn hello_static
file hello_dyn | cut -d: -f2
file hello_static | cut -d: -f2
```

输出：

```
-rwxrwxrwx 1 hua hua  15952 Oct 21 09:06 hello_dyn
-rwxrwxrwx 1 hua hua 816936 Oct 21 09:06 hello_static
 ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=39511a90540e1b49151626b0c153707ef72f0cfb, for GNU/Linux 3.2.0, not stripped
 ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=e201bcd4caa95cef1e7f96123e6138e38309badc, for GNU/Linux 3.2.0, not stripped
```

`ldd` 把差别说得更直白：

```bash
ldd hello_dyn
ldd hello_static
```

输出：

```
	linux-vdso.so.1 (0x00007284a0656000)
	libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (0x00007284a0400000)
	/lib64/ld-linux-x86-64.so.2 (0x00007284a0658000)

	not a dynamic executable
```

（第一条列出了三个动态依赖；`ldd hello_static` 的全部输出只有最后那行 `not a dynamic executable`。）对利用的影响数出来——ROPgadget 数一遍两个产物里"以 ret 结尾的指令片段"（gadget，[[02-C语言与内存模型#5.2 节（section）与段（segment）|02 章 5.2]]提过这个词）：

```bash
ROPgadget --binary hello_dyn | tail -1
ROPgadget --binary hello_static | tail -1
```

输出：

```
Unique gadgets found: 55
Unique gadgets found: 37667
```

（数目随工具链版本变，量级关系不变。）PWN 视角三条：

- ==静态题没有"libc 版本对不上"的问题==：libc 的代码全部在文件里，函数地址能直接从符号表查，不需要泄露外部 libc——动态题的版本识别与匹配是 [[P03-ELF链接与延迟绑定|P3]] 的事；
- ==gadget 多到不用愁==：整份 libc 的代码都在，几万个 gadget 任选，ROP 链好凑（[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]、[[P08-ROP进阶与SROP|P8]]）；
- 代价是文件大几十倍，`strings`、反编译的噪音也大，`file` 输出里的 `statically linked` 是第一眼的判别标记。

### 3.4 保护相关旗子：先会用，P4 讲原理

旗子与 checksec 各行的对应关系，一次编出来对号。同一份源码，默认选项编一份、保护全关编一份：

```bash
gcc -O0 dang_readfgets.c -o v_default
pwn checksec v_default
gcc -O0 -fno-stack-protector -z execstack -no-pie -fno-pie dang_readfgets.c -o v_loose
pwn checksec v_loose
```

输出（编译时的两条返回值提醒略）：

```
[*] '/home/hua/pwn/p2/v_default'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[*] '/home/hua/pwn/p2/v_loose'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

旗子与行的对应：

| 编译选项 | 控制的行 | 从默认值变成 |
| ---- | ---- | ---- |
| `-fno-stack-protector` | `Stack` | `Canary found` → `No canary found` |
| `-z execstack` | `NX` 与 `RWX` | 栈所在页变为可执行，checksec 报 `Stack: Executable` 加 `RWX segments` |
| `-no-pie -fno-pie` | `PIE` | `PIE enabled` → `No PIE (0x400000)`，程序固定装载在 0x400000 |

发行版自带的 gcc 默认把保护全开（PIE、Canary、NX、Full RELRO），P1 5.1 那组关保护的参数就是从默认值逐项往回退。RELRO 的两档由链接选项控制（`-z relro` / `-z now`），原理与绕过 [[P04-Linux安全缓解机制|P4]] 展开；[[P01-PWN导论与缓解机制全景|P1]]已经在用这组旗子，本章之后你会知道每面旗子改变了内存里的什么。

## 4. 进程内存布局：PWN 视角

### 4.1 五区与增长方向

[[02-C语言与内存模型#5. 进程内存布局|通用基础 02 章第 5 节]]讲过各区放什么，这里按运行期的五区收拢成一张表，并补上 PWN 视角：

| 区域 | 放什么 | 权限 | 位置与增长方向 |
| ---- | ---- | ---- | ---- |
| text | 机器指令（.rodata 的字符串常量在旁边只读页） | `r-x` | 装载时定死；无 PIE 时 0x400000 一带 |
| data | 已初始化的全局 / 静态变量 | `rw-` | 紧跟代码区 |
| bss | 未初始化或零值的全局 / 静态变量 | `rw-` | 紧跟 data；文件里不占空间（[[05-ELF文件格式与链接\|通用基础 05 章]]） |
| heap | malloc 的内存 | `rw-` | `[heap]`，向高地址增长 |
| stack | 局部变量、函数参数、返回地址 | `rw-` | `[stack]`，向低地址增长（[[02-C语言与内存模型#5.3 栈向低地址增长\|02 章 5.3]]） |

节与段的区分、栈增长方向决定溢出方向，[[02-C语言与内存模型#5.2 节（section）与段（segment）|02 章]]都讲过。PWN 视角每区的用途一句话：==text 是函数地址与 gadget 的产地==（无 PIE 时这些地址写进 payload 就能用）；==data/bss 是可写又有确定地址的空地==，写 shellcode、摆伪造结构都落在这里；==heap 是堆利用的主场==（P1 第 6 节分类表的后期专题）；==stack 是入门期全部战场==（P6–P11）。

### 4.2 /proc/pid/maps：把五区对到地址上

`/proc/<pid>/maps` 列出一个进程的全部内存映射，每行六列：起止地址、权限（rwx 加 p/s）、文件内偏移、设备号、inode、路径。写个小程序，把自己的地址打出来，再打印自己 maps 里的关键行：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int g_data = 1;
int g_bss;

int main(void) {
    int local = 0;
    char *heap = malloc(32);

    printf("main    = %p\n", (void *)main);
    printf("&g_data = %p\n", (void *)&g_data);
    printf("&g_bss  = %p\n", (void *)&g_bss);
    printf("heap    = %p\n", (void *)heap);
    printf("local   = %p\n", (void *)&local);

    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    while (fgets(line, sizeof line, f))
        if (strstr(line, "maps") || strstr(line, "[heap]") ||
            strstr(line, "[stack]") || strstr(line, "libc.so.6"))
            fputs(line, stdout);
    fclose(f);
    free(heap);
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie -g maps.c -o maps
./maps
```

输出：

```
main    = 0x401236
&g_data = 0x404058
&g_bss  = 0x40406c
heap    = 0x39604010
local   = 0x7ffe68bef27c
00400000-00401000 r--p 00000000 08:30 41521                              /home/hua/pwn/p2/maps
00401000-00402000 r-xp 00001000 08:30 41521                              /home/hua/pwn/p2/maps
00402000-00403000 r--p 00002000 08:30 41521                              /home/hua/pwn/p2/maps
00403000-00404000 r--p 00002000 08:30 41521                              /home/hua/pwn/p2/maps
00404000-00405000 rw-p 00003000 08:30 41521                              /home/hua/pwn/p2/maps
39604000-39625000 rw-p 00000000 00:00 0                                  [heap]
7f72f2a00000-7f72f2a28000 r--p 00000000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7f72f2a28000-7f72f2bc0000 r-xp 00028000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7f72f2bc0000-7f72f2c0e000 r--p 001c0000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7f72f2c0e000-7f72f2c12000 r--p 0020e000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7f72f2c12000-7f72f2c14000 rw-p 00212000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7ffe68bd1000-7ffe68bf2000 rw-p 00000000 00:00 0                          [stack]
```

逐行对号入座：

- `main = 0x401236` 落在 `00401000-00402000 r-xp` ——==这就是 text==，唯一可执行的一页；
- `&g_data`、`&g_bss` 落在 `00404000-00405000 rw-p` ——data 加 bss；`00402000` 起的两页 `r--p`，一页是 `.rodata`，一页是启动后被改成只读的重定位区（RELRO，[[P04-Linux安全缓解机制|P4]]）；
- `heap = 0x39604010` 落在 `[heap]`——起点加 0x10，开头那点被 malloc 的管理结构占用；
- `local = 0x7ffe...` 落在 `[stack]`；
- libc 也是按段权限映射的，五段里 `r-xp` 那段是它的代码——==ret2libc 要跳的 `system` 就在这段里==，基址见 4.3。

GDB 里同一种信息的另一份呈现是 `info proc mappings`，[[R02-C语言与内存模型回顾#2. 内存四区：先对完地址再谈别的|R02 第 2 节]]贴过，两份表可以互相印证。

### 4.3 ASLR 开关：地址在变什么

ASLR 是操作系统层面的随机化（[[P01-PWN导论与缓解机制全景#3. 现代缓解机制全景|P1 第 3 节]]的表），开关由内核参数控制：

```bash
cat /proc/sys/kernel/randomize_va_space
```

输出：

```
2
```

| 取值 | 含义 |
| ---- | ---- |
| 0 | 关闭：所有区域每次装载在固定位置 |
| 1 | 保守随机化：栈、共享库映射、vdso |
| 2 | 全开：在 1 的基础上再加堆（brk）——发行版默认 |

同一程序连跑两次（上面 4.2 是第一次，这是第二次）：

```bash
./maps
```

输出（节选，程序自身五行的映射没变，略）：

```
heap    = 0x101fc010
local   = 0x7ffc8483d36c
101fc000-1021d000 rw-p 00000000 00:00 0                                  [heap]
7de7c8600000-7de7c8628000 r--p 00000000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7de7c8628000-7de7c87c0000 r-xp 00028000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7de7c87c0000-7de7c880e000 r--p 001c0000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7de7c880e000-7de7c8812000 r--p 0020e000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7de7c8812000-7de7c8814000 rw-p 00212000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7ffc8481f000-7ffc84840000 rw-p 00000000 00:00 0                          [stack]
```

读法：==main、g_data、g_bss 三行纹丝不动==（无 PIE，程序自身的装载地址不归 ASLR 管），==heap、libc、stack 全换了位置==。把随机化对这一个进程关掉再连跑两次：

```bash
setarch -R ./maps
```

输出：

```
main    = 0x401236
&g_data = 0x404058
&g_bss  = 0x40406c
heap    = 0x405010
local   = 0x7fffffffdf7c
00400000-00401000 r--p 00000000 08:30 41521                              /home/hua/pwn/p2/maps
00401000-00402000 r-xp 00001000 08:30 41521                              /home/hua/pwn/p2/maps
00402000-00403000 r--p 00002000 08:30 41521                              /home/hua/pwn/p2/maps
00403000-00404000 r--p 00002000 08:30 41521                              /home/hua/pwn/p2/maps
00404000-00405000 rw-p 00003000 08:30 41521                              /home/hua/pwn/p2/maps
00405000-00426000 rw-p 00000000 00:00 0                                  [heap]
7ffff7c00000-7ffff7c28000 r--p 00000000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7c28000-7ffff7dc0000 r-xp 00028000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7dc0000-7ffff7e0e000 r--p 001c0000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7e0e000-7ffff7e12000 r--p 0020e000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7e12000-7ffff7e14000 rw-p 00212000 08:30 13605                      /usr/lib/x86_64-linux-gnu/libc.so.6
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
```

```bash
setarch -R ./maps
```

输出（第二次运行，地址打印部分）：

```
main    = 0x401236
&g_data = 0x404058
&g_bss  = 0x40406c
heap    = 0x405010
local   = 0x7fffffffdf7c
```

两次逐行相同：heap 紧贴 bss 之后（0x405000 起），栈回到 `0x7ffffffde000`，libc 落在 `0x7ffff7c00000`。`setarch -R` 只对它启动的那个进程生效（原理是给子进程关掉 ADDR_NO_RANDOMIZE 个性位），不需要 root，==调试时的救命开关==；`randomize_va_space` 是系统级开关，写它需要 root，读者环境里只读即可。GDB 默认就关 ASLR——[[R02-C语言与内存模型回顾#2. 内存四区：先对完地址再谈别的|R02]]那张每次都一样的映射表，原因在此。

> [!warning] 本地关了 ASLR，远程没有
> ==setarch 或 GDB 里调通的"写死地址"，换到远程就可能失效==：远程服务开着 ASLR，栈、libc 地址每次连接都变。P1 的 ret2win 能直接打远程，是因为它只用程序自身地址而题目没开 PIE——"哪些地址仍然有效"看 4.4 的表。

### 4.4 地址确定性对利用的意义

把 4.2、4.3 的现象收拢成三档：

| 场景 | 固定的东西 | 利用脚本的做法 |
| ---- | ---- | ---- |
| 无 PIE 且 ASLR 关（调试态：GDB 默认、`setarch -R`） | 全部 | 地址随便写死，最适合学原理 |
| 无 PIE 且 ASLR 开（无 PIE 的老题） | 程序自身（text/data/bss） | ret2win 一类写死可用；libc、栈地址要靠泄露 |
| PIE 且 ASLR 开（现代赛题默认） | 什么都不固定 | 全靠泄露与相对计算，[[P04-Linux安全缓解机制\|P4]] |

P1 五步流程的第 1 步查保护，查的就是落进哪一档；从第二档到第三档，利用脚本从"一次打完"变成"先泄露、再构造"的两段式——那是要到 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]]、[[P09-格式化字符串漏洞|P9]] 才展开的形态。

## 5. 文件权限与 SUID

### 5.1 rwx 与三个特殊位

rwx 三组九位与数字写法 [[07-Linux进阶操作与Shell脚本#2.1 rwx 三组九位|通用基础 07 章 2.1]]讲过，这里只补九位之前的那一位——三个特殊位：

| 位 | 八进制 | ls -l 显示 | 含义 |
| ---- | ---- | ---- | ---- |
| SUID（set uid） | 4 | 属主的 `x` 变 `s` | 程序运行时 euid = 文件属主的 uid |
| SGID（set gid） | 2 | 属组的 `x` 变 `s` | 运行时 egid = 文件属组的 gid；目录上是新文件继承目录属组 |
| sticky | 1 | 其他人的 `x` 变 `t` | 目录上：里面的文件只有属主能删（`/tmp` 就是 `drwxrwxrwt`） |

系统里最熟悉的 SUID 例子是 `/usr/bin/passwd`（4755 root，[[07-Linux进阶操作与Shell脚本#2.2 SUID：借谁的身份证|07 章 2.2]]拆过它为什么必须如此）。

### 5.2 SUID 在 PWN 题里的意义

uid 是"你是谁"，euid 是"内核此刻按谁的身份给你授权"。普通程序两者相同；带 SUID 的程序运行时 ==euid 变成文件属主==，权限检查（读文件、起进程）按 euid 走。

对 PWN 题，这意味着一条等式：

> ==题目二进制属主是 root 且带 SUID，getshell 拿到的 shell 就是 root 的==。

远程部署常见两种形态：socat / xinetd 直接把题目二进制挂成服务（P1 5.6 的 serve.py 就是这个形态的本地版，无 SUID，shell 权限就是服务账号）；或者题目目录里放一个 SUID root 的二进制，服务以低权账号跑——这时 getshell 只是进门，==真正的 flag（通常只有 root 可读）要靠这个 SUID 程序的漏洞提一步==。拿到 shell 后的第一件事是 `id` 看清 uid/euid，再 `find / -perm -4000` 把 SUID 程序列出来（07 章 2.2 的命令）。

### 5.3 chmod u+s 亲眼看一次

小程序打印自己的两个身份：

```c
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("uid=%d euid=%d\n", getuid(), geteuid());
    return 0;
}
```

在 Linux 原生目录里（`/mnt/c` 的 Windows 挂载盘不认这些位，[[07-Linux进阶操作与Shell脚本#7. 常见问题|07 章常见问题]]提过）编译、加执行位、运行：

```bash
gcc -O0 whoami_prog.c -o whoami_prog
chmod 755 whoami_prog
ls -l whoami_prog
./whoami_prog
```

输出：

```
-rwxr-xr-x 1 hua hua 16048 Oct 21 09:07 whoami_prog
uid=1000 euid=1000
```

加 SUID 位再看：

```bash
chmod u+s whoami_prog
ls -l whoami_prog
stat -c '%a' whoami_prog
```

输出：

```
-rwsr-xr-x 1 hua hua 16048 Oct 21 09:07 whoami_prog
4755
```

`x` 的位置变成了 `s`，数字表示从 755 变成 4755。这个文件属主是自己，SUID 之后 euid 还是 1000，运行结果看不出变化——==SUID 的效果取决于属主是谁==：属主是 root 时，任何执行者的 euid 都变成 0。无 root 的环境演示不了这最后一步，机制如上；把它放到题目里就是 5.2 的等式。

> [!info]- 为什么 shell 脚本不吃 SUID
> 内核对 `#!` 开头的解释器脚本不赋予 SUID 特权：真正被执行的是解释器，内核不把属主身份传给它。这是早期 Unix 就定下的安全设计——否则"setuid 的 shell 脚本"会带来难以收敛的竞态问题。==所以提权点只可能出现在二进制上==，`find -perm -4000` 的结果里也全是 ELF。

## 6. shellcode：注入的机器码

### 6.1 定义与 execve("/bin/sh") 的形态

shellcode 是一段==拿到执行权后被直接执行==的机器码，功能几乎总是同一件事：调 `execve("/bin/sh", 0, 0)` 把当前进程换成 shell。[[04-汇编语言精要#10. 系统调用：程序开口找内核办事|通用基础 04 章第 10 节]]讲过系统调用约定，这里的调用号正是那张表里的 59 号。用 pwntools 生成标准形态并反汇编看它（脚本 sc.py）：

```python
from pwn import *

context.arch = 'amd64'
sc = asm(shellcraft.sh())
print('length:', len(sc))
bad = sorted({b for b in sc if b in (0x00, 0x0a)})
print('bytes equal to 0x00 or 0x0a:', bad if bad else 'none')
print(disasm(sc))
```

```bash
python3 sc.py
```

输出：

```
length: 48
bytes equal to 0x00 or 0x0a: none
   0:   6a 68                   push   0x68
   2:   48 b8 2f 62 69 6e 2f 2f 2f 73   movabs rax, 0x732f2f2f6e69622f
   c:   50                      push   rax
   d:   48 89 e7                mov    rdi, rsp
  10:   68 72 69 01 01          push   0x1016972
  15:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp], 0x1010101
  1c:   31 f6                   xor    esi, esi
  1e:   56                      push   rsi
  1f:   6a 08                   push   0x8
  21:   5e                      pop    rsi
  22:   48 01 e6                add    rsi, rsp
  25:   56                      push   rsi
  26:   48 89 e6                mov    rsi, rsp
  29:   31 d2                   xor    edx, edx
  2b:   6a 3b                   push   0x3b
  2d:   58                      pop    rax
  2e:   0f 05                   syscall
```

逐段读（x86-64 Linux，syscall 约定：调用号在 rax，参数依次 rdi、rsi、rdx）：

- 前 4 条：`push 0x68` 先把结尾的 `h` 连同随后的 0 压上栈；`movabs` 的 8 字节立即数按小端落进内存，拼出的是 `/bin///s`——两截连起来正好 `/bin///sh\0`。==路径里多余的 `/` 不影响解析，换来的是整段机器码里没有一个 `\0` 字节==。`mov rdi, rsp` 让第一参数指向这串字符；
- 中间一段：`push 0x1016972` 后异或 `0x1010101` 得到 `"sh\0\0"`——==想要含 `\0` 的数据又不直接写 `\0` 字节，就用异或现场造==；随后在栈上就地摆出 argv 数组（指向 `"sh"` 的指针加 NULL 结尾），装进第二参数 rsi；
- 最后四条：rdx 清零（第三参数 envp 为空），`push 0x3b; pop rax` 把调用号 59 装进 rax，`syscall` 开门。

==48 字节，没有一个 `\x00` 或 `\x0a`==——这不是巧合，是 shellcode 的设计约束，原因见下一小节。

### 6.2 badchar：`\x00` 与 `\x0a` 截断

**badchar** 指 payload 里不能出现的字节。来源有两类：

1. ==截断类输入路径==：`gets` 以 `\n`（`\x0a`）结束、`scanf("%s")` 遇空白结束、`strcpy` 拷到 `\x00` 停。payload 要经过哪条路到达漏洞点，那条路上的"终点字节"就是 badchar——第 2 节的函数清单在这里换了个身份：==它们既是漏洞入口，也是 payload 的过滤器==；
2. ==地址自身的字节==：64 位地址打包后常带 `\x00`——`p64(0x4011f6)` 是 `f6 11 40 00 00 00 00 00`，尾部五个 `\x00`。`read` 这类按字节数收的函数照单全收，但走 strcpy 类路径的 payload 会被 `\x00` 当场截断。

判断方法：先看漏洞点用的哪个输入函数（决定哪条过滤规则生效），再检查 payload 的字节集合。6.1 输出里 `bytes equal to 0x00 or 0x0a: none` 就是这类检查。遇到 badchar 的绕法（等价指令替换、异或编码、分段写入）[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]、[[P08-ROP进阶与SROP|P8]] 实操。

> [!note] badchar 因题而异
> `read(0, buf, n)` 不在 `\x00` 或 `\x0a` 停——它只认字节数。所以==没有全局的 badchar 表==，每道题先确认输入路径，再列自己的禁止字节。gets 的 payload 只需避开 `\x0a`；strcpy 路径的连 `\x00` 都要避开。

### 6.3 pwntools shellcraft 预览

上面用到的 `shellcraft` 是 pwntools 的 shellcode 模板库：`shellcraft.sh()` 给出 execve("/bin/sh") 的汇编模板，`asm()` 编成机器码，`disasm()` 反着验一遍；按架构切（`context.arch = 'i386'` / `'amd64'`）同一套代码出两种产物。[[04-汇编语言精要#10.4 PWN 为什么盯着它|04 章 10.4]]里那串十六进制开头就是它的产物。更多模板（读 flag 的 orw 链等）[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 用到；把 shellcode 真正注入运行的前提是那块内存可执行——也就是 `-z execstack` 对应的 NX 关闭态（3.4）。

## 7. 实验环境对齐：本地、Docker 与题目附件

### 7.1 本地 WSL

[[01-Linux环境与CTF实验环境搭建|通用基础 01 章]]装好的 WSL 加工具链就是日常训练场：gcc 编译、gdb 调试、pwntools 写脚本。本章各节的命令与输出都以此为基准，你本地装的版本若不同，个别输出细节会有出入；`pwn checksec`、`pwn cyclic`、`shellcraft` 这些命令行入口属于 pwntools，系统化梳理在 [[P05-pwntools与GDB插件工具链|P5]]。

### 7.2 Docker

题目附带 Dockerfile 时，`docker build` 出来的容器就是出题环境本体——glibc 版本、题目自带的 libc、服务启动方式全部一致，不再靠猜。镜像、容器与赛题环境的对应关系 [[13-Docker与赛题环境|通用基础 13 章]]展开。

### 7.3 题目给的 libc/ld 与 patchelf

动态题目的附件常见两件套：`libc.so.6` 和动态链接器 `ld-linux-x86-64.so.2`。==原因是远程服务器的 libc 版本多半与本地不同==：函数在 libc 内的偏移、堆管理结构的行为都随版本变，本地一套地址、远程一套地址，利用脚本必然打架。[[01-Linux环境与CTF实验环境搭建#2.4 对齐目标程序的 glibc 版本|通用基础 01 章 2.4]]给过两种对齐方式：命令行直接用题目的 loader 运行，或者用 patchelf 把二进制的 interpreter 与 rpath 永久改指向题目附件（`sudo apt install patchelf`，01 章的工具链清单里已含）。本地版本怎么确认（`ldd --version`）、题目 libc 版本怎么识别匹配，[[P03-ELF链接与延迟绑定|P3]] 展开。

> [!info]- interpreter 与 rpath 是什么
> 动态链接的程序在程序头表里有一个 INTERP 段（`readelf -l` 可见），记录动态链接器的路径，默认是 `/lib64/ld-linux-x86-64.so.2`；运行期按 rpath、LD_LIBRARY_PATH 等顺序搜索 `libc.so.6` 这类依赖库。`patchelf --set-interpreter` 改前者，`--set-rpath` 改后者——两者都指向题目附件目录后，本地跑的就是"远程那一套 libc"。链接与延迟绑定的背景知识在 [[P03-ELF链接与延迟绑定|P3]]、[[R04-可执行文件格式ELF与PE|R04]]。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| `-O2` 下 GDB 显示变量 `<optimized out>`、断点行号乱跳 | 优化后变量进寄存器、语句重排。调试用 `-O0 -g` 重编（3.1、3.2） |
| 换了一份编译产物，脚本打不通 | 偏移是产物的属性：对新产物重新 cyclic（3.1） |
| `scanf("%s")` 编译没有警告，以为安全 | 警告只覆盖编译期算得出长度的形态；按清单逐个对（2.8） |
| GDB 里地址每次都一样，远程每次都变 | GDB 默认关 ASLR，远程开着；需要泄露的手法 P7 起（4.3） |
| payload 发过去没反应 | badchar：确认漏洞点的输入函数对 `\x0a`、`\x00` 的处理（6.2） |
| 本地复现不出题目行为 | 本地与远程 libc 版本不一致：用题目附件 libc/ld 跑（7.3） |
| `chmod u+s` 成功但权限没变化 | 文件属主是自己时 euid 本来就是自己，无可见效果；SUID 的意义看属主（5.3） |
| 附件二进制 `Permission denied` | 没有执行位：`chmod +x`；或文件在 `/mnt/c` 且挂载选项不认执行位，挪到 Linux 原生目录（[[07-Linux进阶操作与Shell脚本#7. 常见问题\|07 章常见问题]]） |
| `gcc -static` 报 `cannot find -lc` 等 | 缺静态库：`sudo apt install libc6-dev` 后重试；老系统另需 `glibc-static` 一类包 |

