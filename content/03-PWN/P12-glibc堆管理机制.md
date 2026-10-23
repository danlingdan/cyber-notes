---
chapter: PWN
section: glibc 堆管理机制：ptmalloc2
order: 312
tags:
  - CTF
  - PWN
  - 堆
publish: true
---

# P12 glibc 堆管理机制
## glibc Heap Management: ptmalloc2

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L3 堆上利用期 ｜ **前置要求**：[[P05-pwntools与GDB插件工具链|P5]] · [[P03-ELF链接与延迟绑定|P3]] · [[R02-C语言与内存模型回顾|R02]]
> **本章目标**：把 glibc 堆管理器的 chunk 结构与 bins 家族逐字段讲透，走通 malloc/free 的主干流程与合并切分，并用一套自写的 GDB 堆观察脚本把每一步看在眼里，为 [[P13-基础堆漏洞|P13]] 起的堆利用打地基。

## 1. 为什么堆是现代 PWN 的主战场

[[P01-PWN导论与缓解机制全景|P1]] 到 [[P11-Canary绕过与GOT攻击|P11]] 的利用都发生在栈上。堆是另一大战场：程序调用 `malloc`/`free` 申请与释放的内存区（[[R02-C语言与内存模型回顾#2. 内存四区：先对完地址再谈别的|R02 第 2 节]]的内存四区之一），由 glibc 的分配器实现 ptmalloc2 管理。典型的堆题是一个菜单程序——new 分配、edit 编辑、free 释放、show 打印——漏洞几乎都出在编辑与释放的逻辑上。

堆成为主战场的原因，一句话：==快捷方式没有了，剩下的路都要穿过堆管理器本身==。早年 glibc 提供 `__malloc_hook` / `__free_hook` 两个函数指针，写一个地址进去，下一次 malloc/free 就会调用它——控制执行流只需要一次任意写。==glibc 2.34 把这组 hook 整体移除==，这类打法随之绝迹；此后的堆利用转向两条主线：

- **打管理器的数据结构**：tcache、smallbin、largebin 这些链表就记录在堆内容里，篡改它们可以让 malloc 把任意地址"分配"出来（[[P13-基础堆漏洞|P13]]、[[P14-tcache与fastbin利用|P14]]、[[P15-House系列攻击技术|P15]]）；
- **转向 stdio**：伪造 IO_FILE 结构挂进标准库的文件结构链，在退出或打印时劫持控制流，这条路叫 FSOP，[[P16-FSOP与HouseofApple2|P16]] 整章都在做这件事。

两条主线的共同前提，是本章要建立的东西：==管理器把元数据记在哪里，哪里能被写坏，写坏之后它按什么路径出错==。本章按 glibc 2.43 的行为讲解——2.42 与 2.43 两年里 malloc 被大幅重写（fastbin 移除、tcache 扩容、结构调整），与大量老资料的差异集中列在 [[#9. glibc 2.43 行为注记|第 9 节]]的对照表里，读老题解时先查那张表。

> [!info]- 管理器的两个身份
> 对程序来说，malloc/free 只是"给我内存""还回去"；对攻击者来说，管理器是一个"堆上自带复杂指针网络的解释器"：chunk 头里的 size、空闲块里的 fd/bk、tcache 的链表头，全是它逐字节信任的数据。==堆漏洞的本质是让"用户数据"和"管理器元数据"重叠，再用编辑能力改写元数据==。本章先看清元数据长什么样，后三章再谈怎么重叠。

## 2. chunk：堆内存的基本单位

堆被切成一个个 chunk 管理。`malloc` 返回的地址（mem）与 chunk 的关系是==mem = chunk + 0x10==：每个 chunk 头部有 16 字节的管理信息，malloc 跳过它们。64 位下的完整布局：

```text
        低地址
       ┌────────────────────────────────────────┐
       │ prev_size      8 字节                   │ ← 前一个块空闲时存前块大小；
       ├────────────────────────────────────────┤   前块在用时这里归前块的数据用
chunk→ │ size           8 字节                   │ ← 本块大小，低 3 位是标志位
       ├────────────────────────────────────────┤
       │ fd             8 字节                   │ ← 空闲时是链表指针；
       ├────────────────────────────────────────┤   在用时归用户数据
       │ bk             8 字节                   │ ← 空闲时是链表指针
       ├────────────────────────────────────────┤
       │ fd_nextsize    8 字节                   │ ← 只在 largebin 里的块有意义
       ├────────────────────────────────────────┤
       │ bk_nextsize    8 字节                   │ ← 只在 largebin 里的块有意义
       ├────────────────────────────────────────┤
       │ 用户数据（在用）或链表指针（空闲）…        │ ← mem 从这里开始
       ├────────────────────────────────────────┤
       │ 下一个 chunk 的 prev_size               │ ← 本块在用时归本块的数据用
       └────────────────────────────────────────┘
        高地址
```

逐字段说明：

- **prev_size**：==只有前一个块空闲时才有意义==，存放前块大小（合并时用它定位前块）。前块在用时，这 8 字节归前块的用户数据用——所以 chunk 头部"常驻"的只有 size 一格，其余都能被用户数据征用。
- **size**：本块的总大小，==永远是 0x10 的倍数==，因此低 4 位腾出来当标志位，实际使用低 3 位：

| 位 | 名称 | 含义 |
| ---- | ---- | ---- |
| 0 | PREV_INUSE | 前一个块能否被合并：1 = 前块在用（或不可合并），0 = 前块空闲 |
| 1 | IS_MMAPPED | 本块由 mmap 单独映射而来，free 时整个 munmap |
| 2 | NON_MAIN_ARENA | 本块属于非主线程的 arena（多线程才有，本章演示程序不涉及） |

  读取靠 `&` 与 `>>` 运算，从原始值里剥出各部分：

```c
raw      = *(size_t *)(chunk + 8);   /* 读 size 槽的原始值           */
size     = raw & ~0xF;               /* 剥出真实大小：清掉低 4 位     */
prev     = raw & 1;                  /* PREV_INUSE                   */
mmapped  = (raw >> 1) & 1;           /* IS_MMAPPED                   */
non_main = (raw >> 2) & 1;           /* NON_MAIN_ARENA               */
```

  [[#8. 一条 malloc/free 序列的全程跟踪|第 8 节]]的输出里有三组现成例子：`0x21` = 0x20 的块 + PREV_INUSE；`0x301` = 0x300 的块 + PREV_INUSE；`0xb31` = 0xb30 的块 + PREV_INUSE。
- **fd 与 bk**：空闲块的链表指针（forward / backward）。==块在用时这两个位置就是普通的用户数据==，只有进 bin 之后才被管理器接管。tcache 的链表也复用 fd 这个位置，但存的是 safe-linking 加密值（[[#3. bins：释放后的 chunk 都去哪里|第 3 节]]）。
- **fd_nextsize 与 bk_nextsize**：只在 largebin 里使用，把同一 bin 里"不同大小的块"再串成一条环（[[#3. bins：释放后的 chunk 都去哪里|第 3 节]]）。其他位置的块上，它们是用户数据。

> [!warning] PREV_INUSE 记录的是"可否合并"，不是"在不在用"
> 块被放进 tcache 之后，邻居的 PREV_INUSE 位==不会==被清掉——tcache 里的空闲块在 size 链上看起来与在用块毫无区别（第 8 节 D 阶段会看到 16 个已释放的块全部显示"在用"）。只有进入合并路径的 free（smallbin、unsorted）才会清掉下一个块的 PREV_INUSE。==读堆时不能只看 PREV_INUSE 判断空闲==，要配合 tcache 的链表头一起看。

> [!info]- 为什么 mem = chunk + 0x10，最小块为什么是 0x20
> 空闲块至少要有 fd、bk 两个指针（双链）加 size 一格，加上对齐就是 0x10 的头 + 至少 0x10 的体 ==0x20 是一块的最小体积==，这个值叫 MINSIZE。malloc 返回 mem = chunk + 0x10，让用户数据正好从 fd 的位置开始：块在用时 fd/bk 归用户，空闲时用户数据已经被搬走、这两个位置让给链表——==同一块内存两种身份，靠状态切换，不额外占空间==。这也是堆漏洞的经典成因之一：块刚被 free 时用户指针还指着原位置（悬垂指针），编辑它就是编辑 fd/bk（[[P13-基础堆漏洞|P13]] 的主题）。另外，size 槽低 4 位里最低 3 位是标志位、第 3 位恒为 0（大小是 0x10 的倍数），有些资料按 `raw & ~7` 取大小，效果相同。

## 3. bins：释放后的 chunk 都去哪里

free 掉的块必须登记起来，下次 malloc 同尺寸才能复用。登记的地方统称 bins，分布在两处：libc 数据段的 **main_arena**（全局一份，[[P03-ELF链接与延迟绑定|P3]]的 libc 视角——它属于 libc 的可写数据，==拿到 main_arena 的地址就等于拿到 libc 泄露==）和堆上每线程一份的 **tcache 结构**。全景一张表：

| 去处 | 结构 | 进的时机 | 出的时机 | chunk 大小范围 |
| ---- | ---- | ---- | ---- | ---- |
| tcache | 单链 LIFO | free 时第一优先 | malloc 时第一优先 | 0x20–0x410，每档默认 16 个 |
| smallbin | 双链 FIFO | free 合并路径（tcache 已满，块 < 0x400） | malloc 精确命中 | 0x20–0x3f0 |
| largebin | 双链 + nextsize 双链 | malloc 遍历 unsorted 时搬入 | malloc 最佳适配 | ≥ 0x400 |
| unsorted | 单条双链 | 合并后的块 ≥ 0x400 的第一站 | malloc 遍历时精确取/切分/搬移 | 中转站 |
| top chunk | 独占堆尾 | 相邻的 free 直接并入 | malloc 在各 bin 都无法满足时切分 | —— |
| fastbin（历史） | 单链 LIFO | ≤2.42：tcache 满后的小块 | malloc 在 tcache 之后查 | 0x20–0x80 |

### 3.1 tcache：第一优先的线程缓存

tcache（thread caching）是每线程一份的缓存：==同尺寸的块 free 再 malloc，不出线程、不碰任何链表，两次指针操作完成==。2.43 的结构本体：

```c
typedef struct tcache_entry {
    struct tcache_entry *next;   /* 单链指针：safe-linking 加密存放 */
    uintptr_t key;               /* double-free 检测：随机值 */
} tcache_entry;

typedef struct tcache_perthread_struct {
    uint16_t num_slots[76];      /* 每档剩余容量，默认 16 */
    tcache_entry *entries[76];   /* 每档链表头，明文指针 */
} tcache_perthread_struct;
```

要点逐条：

- **76 档 = 64 个小档 + 12 个大档**。小档覆盖 chunk 0x20–0x410（申请值 0x408 封顶，0x409 就进不来了）；大档为最大 4 MB 的块准备，==默认关闭==，要用 tunable `glibc.malloc.tcache_max` 打开。
- **tcache_perthread_struct 本体也是堆上的一个 chunk**：76×2 + 76×8 = 760 字节，落在 0x300 的 chunk 里。==2.43 起它在第一次 free 时才被分配==，不再固定是堆上第一个块（第 8 节 A/B 阶段的现场对比）。
- **num_slots 是剩余容量**，每档初始 16（tunable `glibc.malloc.tcache_count` 可改），每入队一个减一、出队一个加一，减到 0 这一档就"满"了。老版本用 `counts` 记"已用几个"、上限 7——语义方向相反，读老题解注意换算。
- **链表是单链 LIFO**：free 把块头插进 `entries[idx]`，malloc 从头取。==后 free 的先回来==（第 8 节 F 阶段的地址对照）。
- **safe-linking**：链上的 `next` 不是明文地址，存储值为 `(存储位置 >> 12) ^ 下一块地址`。链为空时存储值是 `自身位置 >> 12`——一个很小的数，例如第 8 节 B 阶段 fd 槽里的 `0x405`。==看到堆块 fd 槽里有个"不像指针的小数"，那就是 safe-linking 的空链==。攻击视角的推演 [[P14-tcache与fastbin利用|P14]] 展开。
- **key**：入队时写入一个进程内随机的 64 位值。free 时若发现待释放块的 key 等于这个随机值，就遍历全表确认是否重复释放，确认后直接终止：

```text
free(): double free detected in tcache 2
```

  ==连续 free 同一块，程序当场 abort==——这是 [[P10-整数溢出与off-by-one|P10]] 之后新手在堆题上撞到的第二堵墙，绕过思路 [[P14-tcache与fastbin利用|P14]] 展开。

### 3.2 smallbin：精确尺寸的双链

chunk 0x20–0x3f0 的每一档各有一条双链（fd/bk 串起来）。==free 走到合并路径的小块不再经过 unsorted，直接挂进对应档的双链==（glibc 2.41 起的行为，注释原话是"don't pollute the unsorted bin"）。malloc 时精确命中直接取，==同档余下的块会被顺手搬进 tcache==（见第 4 节步骤 3）。进出各走一头：free 从 fd 侧头插，malloc 从 bk 侧尾取，整体是 FIFO——与 tcache 的 LIFO 相反。

### 3.3 largebin：按大小排序的双链

chunk ≥ 0x400 的块尺寸太杂，一档一档放不下，每个 largebin 内部==按大小排序==。因此这里的块多出两个指针：fd/bk 把同 bin 的块串成一条，fd_nextsize/bk_nextsize 把"每种尺寸的第一个块"再串成一条环，malloc 沿 nextsize 环跳着找"能装下请求的最小块"。第 8 节末尾会看到一块独占 bin 的现场：四个指针里 fd、bk 指向 bin 头，fd_nextsize、bk_nextsize 指向自己。

### 3.4 unsorted bin：大块的中转站

全库只有一条，双链循环（头尾都在 main_arena 里）。==free 合并出来的大块先进这里登记，不直接进大 bin==；等下一次 malloc 触发遍历时再分配去处：能精确给的给掉，合适的切一刀，剩下的搬进 smallbin/largebin。这个"先集中登记、用时再分流"的设计让刚释放的大块有机会被立刻复用。fd/bk 指向 main_arena 的空闲块就是它——==unsorted 链上的块是 libc 泄露的经典来源==（第 8 节 H 阶段，[[P13-基础堆漏洞|P13]] 把它变成攻击步骤）。

### 3.5 top chunk：堆尾的余料

堆末端永远有一块 top，是堆和内核之间的缓冲。malloc 在所有 bin 都无法满足请求时切 top；free 的块若与 top 相邻则直接并入，不进任何 bin。==堆的扩容（brk）与回收（trim）都发生在 top 上==。

### 3.6 fastbin：已经退场的经典机制

≤2.42 的教材与题解里，fastbin 与 tcache 并列：单链 LIFO、只收 chunk 0x20–0x80、free 时 tcache 满了才轮到它、不清邻居的 PREV_INUSE、不参与合并——一组小尺寸块的快速缓存。==glibc 2.43 把 fastbin 整体移除==：tcache 每档扩到 16 个、小块 free 又改为直进 smallbin，fastbin 夹在中间不再有存在价值，代码里连 `global_max_fast` 都没有了。读老题解时把"free 进 fastbin / malloc 查 fastbin"的步骤跳过即可，机制本身仍值得认识——[[P14-tcache与fastbin利用|P14]] 会按版本分别讲它的利用。

## 4. malloc 的主干流程

入口先做一次换算：malloc 按 chunk 大小管理内存，申请值要换算成够用且 0x10 对齐的 chunk 大小（记作 nb）：

$$\text{nb} = \max\left(0x20,\ \left\lfloor \dfrac{\text{申请值} + 8 + 15}{16} \right\rfloor \times 16\right) \tag{12.1}$$

加 8 是因为下一个 chunk 的 prev_size 可以借给本块的用户数据用（第 2 节的布局），再向上取整到 0x10 的倍数，下限 0x20。几个关键值（全部能在第 8 节的输出里对上号）：

| 申请值 | nb | 说明 |
| ---- | ---- | ---- |
| 0x18 | 0x20 | 最小块 |
| 0x28 | 0x30 | |
| 0x68 | 0x70 | |
| 0x1f8 | 0x200 | |
| 0x408 | 0x410 | ==tcache 收纳的最后一档== |
| 0x409 | 0x420 | 超出 tcache 默认范围 |
| 0x500 | 0x510 | 直接走合并路径 |

之后的流程按顺序尝试，每一步都标注"什么时候走到这"：

| 步 | 做什么 | 什么时候走到这 |
| ---- | ---- | ---- |
| 1 | 查 tcache 对应档，非空就弹出头结点返回 | nb ≤ 0x410 且该档有货——最常见路径 |
| 2 | 查 smallbin 精确档，命中就取走，并把同档余块批量搬进 tcache | nb < 0x400、tcache 空、smallbin 有货 |
| 3 | 遍历 unsorted：能精确给的给掉；小块请求且链上只有 last_remainder 时切分；其余搬进各自的 smallbin/largebin | 前两步落空、unsorted 非空 |
| 4 | 最佳适配：从 largebin / binmap 位图里找"装得下的最小块"，切分，余块塞回 unsorted 并记为 last_remainder | 没有精确档，但有大块可用 |
| 5 | 切 top chunk，余下部分成为新 top | 所有 bin 都无法满足这次请求 |
| 6 | sysmalloc：nb ≥ 0x20000（128 KB）直接 mmap 一块新内存；否则 brk 扩堆、重切 top | top 也不够用 |

三条补充：

- **第 6 步的 0x20000 是 mmap 阈值**：小于它的请求宁可扩堆也不单独映射；大于它的直接 mmap，free 时整个 munmap，与主堆完全无关。第 8 节 L 阶段把两者放在一起对照。
- **last_remainder** 是"上一次切分剩下的那块"：连续的小请求会反复切同一块大余料，==这个设计让顺序分配在地址上连续==，第 8 节 K 阶段的第二次 malloc 就是走它。
- **binmap** 是 main_arena 里的一张位图，记录哪些 bin 非空，第 4 步用它跳过空 bin 的逐一检查。

> [!info]- 精确命中也会先进 tcache
> 第 3 步 unsorted 遍历遇到尺寸正好相等的块时，若这是个小档请求且 tcache 该档没满，管理器先把块塞进 tcache（记下"已经缓存了"）继续遍历，遍历完再从 tcache 取出返回——多绕一层的目的是让 tcache 尽量满，后续同尺寸请求直接走第 1 步。另有一个 `tcache_unsorted_limit` 限制单次遍历中塞 tcache 的数量，默认不限制。

> [!note] 老版本的流程里 fastbin 在哪一步
> ≤2.42 的流程图上，fastbin 检查位于第 1、2 步之间：tcache 空了先查 fastbin，命中还会顺手把同档剩余块搬进 tcache。2.43 没有这一步，==读老题解时把"fastbin"相关步骤理解为"2.43 里由 tcache 的 16 容量 + smallbin 直进接管"即可==。

## 5. free 的主干流程

free 比 malloc 多出一层关卡：它必须拒绝坏的输入，因为堆被写坏时最先暴露的就是 free。流程按顺序：

| 步 | 做什么 | 什么时候走到这 |
| ---- | ---- | ---- |
| 1 | `free(NULL)` 什么都不做 | |
| 2 | 对齐检查：mem 对应的 chunk 不是 0x10 对齐 → `free(): invalid pointer` 终止 | 指针被改坏 |
| 3 | 块在 tcache 档位范围内（nb < 0x411）时查 key：命中随机值就全表核查，确认重复 → `free(): double free detected in tcache 2` 终止 | 同块二次 free |
| 4 | 该档 num_slots > 0 → 写 key、加密 fd、头插进 tcache，==结束== | 该档没满（默认 16）——最常见出口 |
| 5 | tcache 结构还没分配（本线程第一次 free）→ 先 malloc 出 0x300 的结构块，再重走第 4 步 | 首次 free |
| 6 | 溢出检查 → `free(): invalid size` 终止 | size 字段被改得离谱 |
| 7 | 合并检查组：本块是不是 top、next 是否越界、next 的 PREV_INUSE 是否为 0、next 的 size 是否合法，任一不满足即终止 | 走到合并路径（tcache 满或大块） |
| 8 | 后向合并：自己的 PREV_INUSE 为 0 就把前块并进来（unlink）；前向合并：next 是 top 就并入 top，next 空闲就把它 unlink 进来 | 邻居空闲 |
| 9 | 入链：块 < 0x400 直接进对应 smallbin；≥ 0x400 进 unsorted | 收尾 |

> [!warning] tcache 没满就没有合并
> 第 4 步在合并检查之前——==只要 tcache 档没满，free 根本不看邻居==。相邻两块会各自躺在 tcache 里互不合并，碎片按档位堆积；装满一档之后（默认要 16 个），同档的 free 才开始走合并路径。堆题的"堆风水"布局（[[P17-堆风水与通用利用思路|P17]]）就是在算这笔账：先堆满 tcache，再让目标块按合并规则就位。

> [!info]- ≤2.42 的 fastbin 分支去哪了
> 老流程里第 4 步之后还有一支：tcache 满且块 ≤ 0x80 时进 fastbin（单链头插、不清邻居 PREV_INUSE、不合并，但有"同块不能连 free 两次"的单档检查）。2.43 移除了这一整支，==tcache 满后的小块直接落入第 7–9 步的合并路径==，这正是第 8 节 E 阶段演示的行为。

## 6. 合并与切分

### 6.1 后向合并：PREV_INUSE 为 0 时吃掉前块

free 一块时若发现==自己==的 size 槽里 PREV_INUSE 是 0，说明前块空闲（已在某条 bin 上）：从自己的 prev_size 读出前块大小，定位前块，把它从 bin 上摘下来（unlink），两块合成一块，起点前移。unlink 在源码里就做两件事，外加两道检查：

```c
if (fd->bk != p || bk->fd != p)
    malloc_printerr ("corrupted double-linked list");
fd->bk = bk;
bk->fd = fd;
```

==链表的一对邻居必须互相指回来==，外加"前块的 size 要等于自己的 prev_size"的检查。伪造一个假块骗 unlink，就要同时让这三处自洽——这道题 [[P14-tcache与fastbin利用|P14]] 会完整解一遍。

### 6.2 前向合并：邻居空闲或挨着 top

再看 next 块：由 next 的 size 槽读出"next 的下下块"的 PREV_INUSE，为 0 说明 next 空闲 → unlink(next) 并进来。若 next 就是 top，整个块并入 top，不进任何 bin。前向合并完成后，还会把 next 的下一块的 PREV_INUSE 清 0，宣告"我空闲了"。==每一块是否空闲，都记录在它的下一个块里==——第 2 节那条 PREV_INUSE 语义的由来。

```text
合并前（C、D 相邻且都空闲，B、E 在用）：
  [ B 在用 ][ C 空闲 ][ D 空闲 ][ E 在用 ]
                 ↑PREV_INUSE=0    ↑PREV_INUSE=0

后向 + 前向合并后：
  [ B 在用 ][ C+D 合并块，进 smallbin/unsorted ][ E 在用 ]
                             ← E 的 PREV_INUSE 被清 0
```

### 6.3 切分：malloc 从大块上裁一刀

malloc 选中的块若比请求大得多（超过 MINSIZE 的余量），就原地切两半：前 nb 字节交付（head 写上 `nb | PREV_INUSE`），剩下的作余块——head 记 `剩余大小 | PREV_INUSE`（前块刚被分配，当然在用），prev_size 写上前块大小，然后进入 unsorted bin 并登记为 last_remainder。==切分只发生在 malloc 的路径上==，free 只合不切。

```text
切分前：[ 空闲块 0xf30 ]                    ← unsorted 里
切分后：[ 交付块 0x200 ][ 余块 0xd30 ]      ← 余块回到 unsorted，成为 last_remainder
```

## 7. 调试方法：GDB 原生加自写堆观察脚本

堆调试的信息全部在内存里：chunk 头、fd/bk、tcache 的两条数组。GDB 原生命令（[[R06-动态调试GDB与x64dbg|R06]]）加 python API 就能把这些信息整理成一张表，==不装任何插件==。pwndbg 的 `vis_heap_chunks` 做的是同一件事（装法见 [[01-Linux环境与CTF实验环境搭建#5.2 pwntools 与 GDB 插件|01 章 5.2]]）——先把原生的脚本写明白，再看插件的面板，每一行都知道它是算出来的（[[P05-pwntools与GDB插件工具链|P5]] 对插件作用的定位）。

下面这份 `heapview.py` 提供四条命令，本节逐块讲解，第 8 节全部用上：

```text
heapview                从堆头遍历主堆上的所有 chunk
heapview <表达式>       从指定 chunk 地址开始遍历（如 mmap 出来的块）
tcacheview              定位 tcache 结构，打印各 bin 的剩余容量与链
chunk <表达式>          打印单个 chunk 的全部字段
```

### 7.1 公共部分：读内存与找堆区

```python
import gdb
import struct

def rd(addr):
    """读 addr 处的 8 字节，按无符号整数返回"""
    return int(gdb.parse_and_eval("*(unsigned long *)%d" % int(addr)))

def heap_range():
    """从进程映射表里取 [heap] 区间的起点与终点"""
    out = gdb.execute("info proc mappings", to_string=True)
    for line in out.splitlines():
        if line.rstrip().endswith("[heap]"):
            parts = line.split()
            return int(parts[0], 16), int(parts[1], 16)
    raise gdb.GdbError("没有 [heap] 映射：第一次 malloc 还没发生")

def flag_names(bits):
    names = []
    if bits & 1: names.append("PREV_INUSE")
    if bits & 2: names.append("IS_MMAPPED")
    if bits & 4: names.append("NON_MAIN_ARENA")
    return "|".join(names) if names else "0"
```

- `rd` 把 `*(unsigned long *)地址` 交给 GDB 求值，一次读 8 字节——与手工 `x/gx` 等价，但返回值能直接参与运算。
- `heap_range` 解析 `info proc mappings` 的输出找 `[heap]` 行（[[R02-C语言与内存模型回顾#2. 内存四区：先对完地址再谈别的|R02 第 2 节]]用过这张表），拿到堆的起止地址。遍历要有边界，不然 size 被写坏时会跑到未映射内存。
- `flag_names` 把低 3 位翻译成可读的标志名（第 2 节的表）。

### 7.2 heapview：沿 size 链走一遍

```python
class HeapView(gdb.Command):
    """heapview [起始地址]：沿 size 链逐个遍历 chunk"""
    def __init__(self):
        super(HeapView, self).__init__("heapview", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        lo, hi = heap_range()
        addr = int(gdb.parse_and_eval(arg)) if arg.strip() else lo
        i = 0
        while True:
            raw = rd(addr + 8)
            size = raw & ~0xF
            bits = raw & 7
            if bits & 2:                       # IS_MMAPPED：不在主堆链上
                print("[%2d] %#x size %#06x %-24s <- mmap 块，free 时整个 munmap"
                      % (i, addr, size, flag_names(bits)))
                return
            line = "[%2d] %#x size %#06x %-24s" % (i, addr, size, flag_names(bits))
            nxt = addr + size
            if nxt >= hi:                      # 顶到堆尾：这是 top chunk
                print(line + " <- top")
                return
            if rd(nxt + 8) & 1:                # 下一个块的 PREV_INUSE=1：本块不参与合并
                print(line + " 在用（或在 tcache 里）")
            else:                              # 下一个块的 PREV_INUSE=0：本块空闲可合并
                fd, bk = rd(addr + 0x10), rd(addr + 0x18)
                extra = "  (fd/bk 指向 libc 的 main_arena)" if not (lo <= fd < hi) else ""
                print(line + " 空闲可合并 fd %#x bk %#x%s" % (fd, bk, extra))
            addr = nxt
            i += 1
```

逐行拆开核心逻辑：

- **chunk 的登记方式是"隐式链表"**：堆上没有"下一个块在哪"的指针字段，下一个 chunk = 本 chunk + 本 chunk 的 size。所以整个脚本只有一条推进语句 `addr = nxt`，只要 size 没被写坏，就能从堆头走到堆尾。
- **size 从 `addr + 8` 读**（prev_size 之后），`& ~0xF` 剥出真实大小，`& 7` 拿标志位——第 2 节那组 `&` 运算。
- **IS_MMAPPED 块单独打印后停止**：它不在主堆的 size 链上，下一个 chunk 的坐标没有意义。
- **`nxt >= hi` 判定 top**：一路顶到堆尾的块就是 top。
- **本块是否空闲，看的是下一个块的 PREV_INUSE**（`rd(nxt + 8) & 1`）——第 2 节强调过的语义。空闲块的 fd/bk 一并打出；若 fd 不落在堆区间内，它多半指向 main_arena，追加一句标注。
- **状态栏写"在用（或在 tcache 里）"而不是"在用"**：tcache 里的空闲块顶着 PREV_INUSE 不放，从 size 链上无法与在用块区分——是描述的边界，不是脚本偷懒。

### 7.3 tcacheview：定位结构并还原加密链

```python
TCACHE_OFF_ENTRIES = 0x98    # num_slots[76] 共 152 字节，之后是 entries[76]

class TcacheView(gdb.Command):
    """tcacheview：在堆里定位 tcache_perthread_struct，打印各 bin 的剩余容量与链"""
    def __init__(self):
        super(TcacheView, self).__init__("tcacheview", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        lo, hi = heap_range()
        inf = gdb.selected_inferior()
        buf = bytes(inf.read_memory(lo, hi - lo))
        base = None
        addr = lo
        while addr + 0x300 <= hi:
            off = addr - lo
            size = struct.unpack_from("<Q", buf, off + 8)[0] & ~0xF
            if size == 0:
                break
            if size == 0x300:                  # 结构体固定 760 字节 -> 0x300 的 chunk
                slots = struct.unpack_from("<76H", buf, off + 0x10)
                if max(slots) <= 16 and slots.count(16) >= 60:
                    base = addr + 0x10
                    break
            addr += size
        if base is None:
            print("堆上没有 tcache 结构：glibc 2.43 在第一次 free 时才分配它")
            return
        print("tcache 结构 @ %#x（chunk %#x，size 0x300）" % (base, base - 0x10))
        shown = False
        for idx in range(64):
            slots = int(gdb.parse_and_eval("*(unsigned short *)%d" % (base + idx * 2)))
            pos = rd(base + TCACHE_OFF_ENTRIES + idx * 8)
            if pos == 0 and slots == 16:       # 默认容量且为空的一档不打印
                continue
            shown = True
            chain = []
            while pos and lo <= pos < hi and len(chain) < 32:
                chain.append("%#x" % pos)
                pos = rd(pos) ^ (pos >> 12)    # REVEAL_PTR：异或 (存储位置>>12) 还原
            print("tcache[%#05x] 剩余容量 %-2d 链(%d): %s"
                  % (0x20 + idx * 0x10, slots, len(chain), " -> ".join(chain)))
        if not shown:
            print("各 bin 均为空（剩余容量均为默认值 16）")
```

- **定位结构靠内容特征**：2.43 里它不再固定是堆上第一个块，但体积固定——760 字节落在 0x300 的 chunk 里，且前 152 字节是 76 个 `uint16` 的剩余容量（默认都是 16，只会更小）。"size 0x300 + 76 个不大于 16 的半字、其中至少 60 个是 16"，两个条件同时成立才认定。用 `read_memory` 整块读入后在 Python 字节串里扫描，比逐地址求值快得多。
- **链的走法体现 safe-linking**：`entries[idx]` 里的头指针是==明文==，之后每一跳的地址存在上一块的 mem 处，存储值要 `异或 (存储位置 >> 12)` 还原——脚本里 `pos = rd(pos) ^ (pos >> 12)` 就是解密公式本身，链上还原出的地址可以直接与程序打印的指针对照。
- **每档打印两个数**：剩余容量（num_slots）与链上块数，两者之和恒为该档容量（默认 16）——用这个恒等式能当场发现"块不见了"或"多出来了"。

### 7.4 chunk：单块的字段明细

```python
class ChunkCmd(gdb.Command):
    """chunk <地址表达式>：打印单个 chunk 的全部字段"""
    def __init__(self):
        super(ChunkCmd, self).__init__("chunk", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        addr = int(gdb.parse_and_eval(arg))
        raw = rd(addr + 8)
        size = raw & ~0xF
        bits = raw & 7
        loc = addr + 0x10
        print("chunk = %#x" % addr)
        print("size  = %#x（原始值 %#x）" % (size, raw))
        print("flags = %#x（%s）" % (bits, flag_names(bits)))
        print("mem   = %#x（chunk+0x10，malloc 返回的就是它）" % loc)
        print("fd    = %#x（若在单链上，safe-linking 还原 = %#x）"
              % (rd(loc), rd(loc) ^ (loc >> 12)))
        print("bk    = %#x（tcache 场景下这个位置是 key）" % rd(addr + 0x18))

HeapView()
TcacheView()
ChunkCmd()
```

参数是 **chunk 地址**（不是 malloc 返回的 mem 地址，差 0x10）。fd 行同时给出还原值——块不在单链上时，fd 是用户数据，还原值无意义；块在 tcache 链上时，还原出的就是下一块的 mem 地址（或 0）。bk 行的括号提示：tcache 的 entry 只有两个字段，fd 槽后面那格是 key，正好压在传统 bk 的位置上。

### 7.5 批处理观察模板

脚本写好之后，观察动作固定成 GDB 的"断点 + 命令块"。演示程序里有一个 `mark()` 函数在每个阶段完成后打标记，把断点下在它上面，每次命中先打印阶段名（刚进函数时第一参数还在 rdi 里，System V AMD64 ABI），再跑两条观察命令，然后放行：

```text
# gdb.cmds —— 批处理骨架（跑法：gdb -q -batch -x gdb.cmds ./p12_demo）
set pagination off
set confirm off
source heapview.py
break mark
commands
silent
printf ">>>>> %s\n", (char*)$rdi
heapview
tcacheview
continue
end
run
```

> [!warning] 断点要下在动作完成之后
> 想看"free 之后堆长什么样"，断点必须停在 free 已经执行完的位置。把标记函数写在动作之后、断点下在标记函数入口，是这个模板能成立的关键；把断点直接下在 free 调用行上，看到的永远是 free 之前的状态。

## 8. 一条 malloc/free 序列的全程跟踪

本节用一个小程序把前七节全部走一遍：不同尺寸的分配、按不同顺序的释放、相邻合并、切分与 mmap。程序与脚本在同一目录，编译参数沿用全库惯例：

```bash
gcc -O0 -fno-pie -no-pie -g p12_demo.c -o p12_demo
gdb -q -batch -x gdb.cmds ./p12_demo
```

```c
/* p12_demo.c —— glibc 堆行为演示程序（x86-64 Linux，按 glibc 2.43 行为设计） */
#include <stdio.h>
#include <stdlib.h>

void *x[17];            /* 0x68 档：装满 tcache 一档要 16 个 */
void *y[3];             /* 0x500 档 */
void *z[3];             /* 切分观察块 */
void *sp1, *sp2;        /* 垫块：隔开 top，让 free 走合并路径而不是并进 top */
void *w, *n, *m;        /* 零散观察对象 */

static void mark(const char *s) {
    printf("---- %s ----\n", s);
}

int main(void) {
    setbuf(stdout, NULL);

    w = malloc(0x18);
    printf("w = %p\n", w);
    mark("A：首次 malloc(0x18) 完成");
    free(w);
    mark("B：free(w) 完成");

    for (int i = 0; i < 17; i++) x[i] = malloc(0x68);
    sp1 = malloc(0x28);   /* 0x30 档，tcache 里没有现成的，保证从 top 切出垫在 x[16] 后面 */
    for (int i = 0; i < 17; i++) printf("x[%d] = %p\n", i, x[i]);
    printf("sp1 = %p\n", sp1);
    mark("C：17 个 0x68 与垫块分配完成");
    for (int i = 0; i < 16; i++) free(x[i]);
    mark("D：前 16 个 free 完成，tcache 装满");
    free(x[16]);
    mark("E：第 17 个 free 完成，直接进 smallbin");
    for (int i = 0; i < 17; i++) x[i] = malloc(0x68);
    for (int i = 0; i < 17; i++) printf("x[%d] = %p\n", i, x[i]);
    mark("F：再次要 17 个 0x68 完成");

    for (int i = 0; i < 3; i++) y[i] = malloc(0x500);
    for (int i = 0; i < 3; i++) printf("y[%d] = %p\n", i, y[i]);
    sp2 = malloc(0x28);   /* 同样从 top 切出，垫在 y[2] 后面 */
    printf("sp2 = %p\n", sp2);
    mark("G：三个 0x500 与垫块分配完成");
    free(y[0]);
    mark("H：free(y[0]) 完成");
    free(y[1]);
    mark("I：free(y[1]) 完成，相邻合并");
    free(y[2]);
    mark("J：free(y[2]) 完成，合并成 0xf30");
    z[0] = malloc(0x1f8);
    printf("z[0] = %p\n", z[0]);
    z[1] = malloc(0x1f8);
    printf("z[1] = %p\n", z[1]);
    mark("K：两次 malloc(0x1f8) 完成，unsorted 切分");

    n = malloc(0x1f000);
    printf("n = %p\n", n);
    m = malloc(0x21000);
    printf("m = %p\n", m);
    mark("L：malloc(0x1f000) 与 malloc(0x21000) 完成");
    free(n);
    free(m);
    return 0;
}
```

观察命令文件在 [[#7.5 批处理观察模板|7.5]] 的骨架上再加两处针对性断点（行号是本文件的行号，自己改编时对应调整）：

```text
# gdb.cmds —— P12 堆观察批处理（跑法：gdb -q -batch -x gdb.cmds ./p12_demo）
set pagination off
set confirm off
source heapview.py

# 每个 mark 断点：先打阶段名，再遍历堆、看 tcache
break mark
commands
silent
printf ">>>>> %s\n", (char*)$rdi
heapview
tcacheview
continue
end

# 第 22 行 mark("B...") 调用点：free(w) 刚执行完，看 w 的 tcache entry 字段
break p12_demo.c:22
commands
silent
printf ">>>>> w 的 chunk 字段（free 之后）：\n"
chunk (unsigned long)w-0x10
continue
end

# 第 59 行 free(n) 调用点：看 largebin 残块的字段与 mmap 块头部
break p12_demo.c:59
commands
silent
printf ">>>>> largebin 残块（z[1] 切分后的余块）：\n"
x/6gx (unsigned long)z[1]+0x1f0
printf ">>>>> mmap 块头部：\n"
heapview (unsigned long)m-0x10
continue
end

run
```

下面的输出全部来自同一次运行，按阶段摘录；GDB 默认关闭 ASLR，同一台机器上复现的地址与下文一致，换机器数值会变、形状不变。

### 阶段 A：首次 malloc——堆的诞生

```text
w = 0x405010
>>>>> A：首次 malloc(0x18) 完成
[ 0] 0x405000 size 0x0020 PREV_INUSE               在用（或在 tcache 里）
[ 1] 0x405020 size 0x20fe0 PREV_INUSE               <- top
堆上没有 tcache 结构：glibc 2.43 在第一次 free 时才分配它
```

三个信息一次到齐：堆区从 0x405000 开始（`malloc(0x18)` 触发内核把 [heap] 映射出来，0x21000 字节）；w 的 chunk 在堆头、mem = chunk + 0x10（0x405010 对 0x405000）；==堆上此刻没有 tcache 结构==——2.43 把它的分配推迟到第一次 free，[[#9. glibc 2.43 行为注记|第 9 节]]的对照表有来龙去脉。剩余部分全是 top（0x20fe0 = 0x21000 − 0x20）。

### 阶段 B：free(w)——tcache 结构就位，w 进链

```text
>>>>> w 的 chunk 字段（free 之后）：
chunk = 0x405000
size  = 0x20（原始值 0x21）
flags = 0x1（PREV_INUSE）
mem   = 0x405010（chunk+0x10，malloc 返回的就是它）
fd    = 0x405（若在单链上，safe-linking 还原 = 0x0）
bk    = 0xdc5bdcc14c671494（tcache 场景下这个位置是 key）

>>>>> B：free(w) 完成
[ 0] 0x405000 size 0x0020 PREV_INUSE               在用（或在 tcache 里）
[ 1] 0x405020 size 0x0300 PREV_INUSE               在用（或在 tcache 里）
[ 2] 0x405320 size 0x20ce0 PREV_INUSE               <- top
tcache 结构 @ 0x405030（chunk 0x405020，size 0x300）
tcache[0x020] 剩余容量 15 链(1): 0x405010
```

逐行读：

- **tcache 结构在这里诞生**：0x405020 出现一个 0x300 的 chunk，恰好在 w 之后、top 之前——第 5 节流程第 5 步"首次 free 先分配结构"的现场。top 从 0x20fe0 缩到 0x20ce0，缩掉的 0x300 就是它。
- **w 的 fd 槽存着 0x405**：链为空，存储值 = 自身位置 >> 12 = 0x405010 >> 12 = 0x405——safe-linking 空链的标志形状。脚本按公式还原得到 0（NULL），与"链为空"一致。
- **key 压在 bk 的位置上**：0xdc5bdcc14c671494 是本次运行的随机值（每次运行都不同）。它就是 3.1 的 double-free 检测依据。
- **tcache[0x020] 剩余容量 15**：默认 16 减去刚入队的这一个；链上只有 w 一个。

### 阶段 C：17 个 malloc(0x68)——从 top 上切

```text
x[0] = 0x405330    x[1] = 0x4053a0    x[2] = 0x405410    x[3] = 0x405480
x[4] = 0x4054f0    x[5] = 0x405560    x[6] = 0x4055d0    x[7] = 0x405640
x[8] = 0x4056b0    x[9] = 0x405720    x[10] = 0x405790   x[11] = 0x405800
x[12] = 0x405870   x[13] = 0x4058e0   x[14] = 0x405950   x[15] = 0x4059c0
x[16] = 0x405a30
sp1 = 0x405aa0
>>>>> C：17 个 0x68 与垫块分配完成
[ 0] 0x405000 size 0x0020 PREV_INUSE               在用（或在 tcache 里）
[ 1] 0x405020 size 0x0300 PREV_INUSE               在用（或在 tcache 里）
[ 2] 0x405320 size 0x0070 PREV_INUSE               在用（或在 tcache 里）
  ……（x[1] 到 x[15] 的 0x70 chunk 共 14 行，同型略）
[18] 0x405a20 size 0x0070 PREV_INUSE               在用（或在 tcache 里）
[19] 0x405a90 size 0x0030 PREV_INUSE               在用（或在 tcache 里）
[20] 0x405ac0 size 0x20540 PREV_INUSE               <- top
tcache 结构 @ 0x405030（chunk 0x405020，size 0x300）
各 bin 均为空（剩余容量均为默认值 16）
```

每个相邻地址差 0x70（0x68 经式 12.1 换算），全部从 top 顺序切出——tcache[0x70] 是空的，smallbin、unsorted 也是空的，直接落到第 4 节流程第 5 步。top 一路缩小（17 个 0x70 加 sp1 的 0x30），从 0x20ce0 缩到 0x20540。sp1（0x30 档）也来自 top，垫在 x[16] 后面——==它在阶段 E 防止 x[16] 的 free 与 top 相邻==。

### 阶段 D：16 个 free——tcache 装满

```text
>>>>> D：前 16 个 free 完成，tcache 装满
（heapview 的 21 行与阶段 C 完全相同，略）
tcache 结构 @ 0x405030（chunk 0x405020，size 0x300）
tcache[0x020] 剩余容量 15 链(1): 0x405010
tcache[0x070] 剩余容量 0  链(16): 0x4059c0 -> 0x405950 -> 0x4058e0 -> 0x405870
    -> 0x405800 -> 0x405790 -> 0x405720 -> 0x4056b0 -> 0x405640 -> 0x4055d0
    -> 0x405560 -> 0x4054f0 -> 0x405480 -> 0x405410 -> 0x4053a0 -> 0x405330
```

两件事各占一行。**heapview 一行没变**：16 个块已经 free，但 size 链上它们与在用块毫无区别（[[#7.2 heapview：沿 size 链走一遍|7.2]]说的"在用（或在 tcache 里）"的边界）——tcache 不动邻居的 PREV_INUSE。**tcacheview 讲出真相**：0x70 档剩余容量 0（满了），链上 16 个块按 LIFO 排列——==链头 0x4059c0 是 x[15]，因为它是最后 free 的；链尾 0x405330 是 x[0]，最先 free==。与阶段 C 打印的地址逐个对照即可核对。

### 阶段 E：第 17 个 free——直接进 smallbin

```text
>>>>> E：第 17 个 free 完成，直接进 smallbin
  （前 18 行与阶段 D 相同，略）
[18] 0x405a20 size 0x0070 PREV_INUSE               空闲可合并 fd 0x7ffff7e12b28 bk 0x7ffff7e12b28  (fd/bk 指向 libc 的 main_arena)
[19] 0x405a90 size 0x0030 0                        在用（或在 tcache 里）
  （top 行略）
```

x[16] 的块（0x405a20）终于出现在 size 链上，而且是==空闲可合并==状态：tcache 满了，这次 free 走到第 5 节的合并路径，0x70 < 0x400，==直接挂进 smallbin[0x70]==。fd、bk 都是 0x7ffff7e12b28——main_arena 里 smallbin 头的位置（bin 为空时头尾同址，链上只有这一块）。==指向 main_arena 的 fd/bk 是 libc 基址泄露的原料==，阶段 H 的 unsorted 块会再次出现这个形状。

两处细节：sp1 的 chunk（0x405a90）标志位显示 0——x[16] 空闲了，==下一个块的 PREV_INUSE 被清零==（6.2 的收尾动作）；tcache 两档与阶段 D 相同（0x70 档依然满着 16 个，本轮 free 没有进 tcache）。

### 阶段 F：再要 17 个——tcache 清空后轮到 smallbin

```text
x[0] = 0x4059c0    x[1] = 0x405950    x[2] = 0x4058e0    x[3] = 0x405870
x[4] = 0x405800    x[5] = 0x405790    x[6] = 0x405720    x[7] = 0x4056b0
x[8] = 0x405640    x[9] = 0x4055d0    x[10] = 0x405560   x[11] = 0x4054f0
x[12] = 0x405480   x[13] = 0x405410   x[14] = 0x4053a0   x[15] = 0x405330
x[16] = 0x405a30
>>>>> F：再次要 17 个 0x68 完成
  （heapview：全部回到"在用"，0x70 档从 size 链上消失；略）
tcache[0x020] 剩余容量 15 链(1): 0x405010
```

前 16 个请求按 tcache 的 LIFO 逐个弹出：x[0] 拿回 0x4059c0（阶段 D 的链头，最后 free 的 x[15]），x[15] 拿回 0x405330（链尾，最先 free 的 x[0]）——==free 与 malloc 的顺序正好相反==。第 17 个请求时 tcache 已空，落到 smallbin：0x405a30 正是阶段 E 进 smallbin 的那块。F 结束后 0x70 档恢复默认空置，堆形状与阶段 C 几乎一样。

### 阶段 G：三个 malloc(0x500)——超出 tcache 的档位

```text
y[0] = 0x405ad0    y[1] = 0x405fe0    y[2] = 0x4064f0    sp2 = 0x406a00
>>>>> G：三个 0x500 与垫块分配完成
  （前 20 行同前，略）
[20] 0x405ac0 size 0x0510 PREV_INUSE               在用（或在 tcache 里）
[21] 0x405fd0 size 0x0510 PREV_INUSE               在用（或在 tcache 里）
[22] 0x4064e0 size 0x0510 PREV_INUSE               在用（或在 tcache 里）
[23] 0x4069f0 size 0x0030 PREV_INUSE               在用（或在 tcache 里）
[24] 0x406a20 size 0x1f5e0 PREV_INUSE               <- top
```

0x500 换算成 0x510，超出 tcache 默认上限（0x410），三个块全部从 top 切出，地址连续。sp2 垫在 y[2] 后面，作用同 sp1。

### 阶段 H：free(y[0])——大块进 unsorted

```text
>>>>> H：free(y[0]) 完成
  （前 20 行同前，略）
[20] 0x405ac0 size 0x0510 PREV_INUSE               空闲可合并 fd 0x7ffff7e12ac8 bk 0x7ffff7e12ac8  (fd/bk 指向 libc 的 main_arena)
[21] 0x405fd0 size 0x0510 0                        在用（或在 tcache 里）
  （其余行略）
```

0x510 不在 tcache 范围内，free 直接走合并路径：前后邻居都在用（sp1 的块与 y[1] 都在用），无可合并，0x510 ≥ 0x400 → 进 unsorted。fd、bk 都是 0x7ffff7e12ac8——==unsorted 链头的 main_arena 地址==。注意它和阶段 E smallbin 头的 0x7ffff7e12b28 不同：main_arena 里每个 bin 的头是不同的位置，==看到 fd/bk 指进 libc 就等于看到了"某一个 bin 的头"==。y[1] 的块（0x405fd0）标志位清零，与阶段 E 的 sp1 同理。

### 阶段 I、J：相邻合并——0x510 + 0x510 → 0xa20 → 0xf30

```text
>>>>> I：free(y[1]) 完成，相邻合并
[20] 0x405ac0 size 0x0a20 PREV_INUSE               空闲可合并 fd 0x7ffff7e12ac8 bk 0x7ffff7e12ac8  (fd/bk 指向 libc 的 main_arena)
[21] 0x4064e0 size 0x0510 0                        在用（或在 tcache 里）
  （其余行略）

>>>>> J：free(y[2]) 完成，合并成 0xf30
[20] 0x405ac0 size 0x0f30 PREV_INUSE               空闲可合并 fd 0x7ffff7e12ac8 bk 0x7ffff7e12ac8  (fd/bk 指向 libc 的 main_arena)
[21] 0x4069f0 size 0x0030 0                        在用（或在 tcache 里）
  （其余行略）
```

两次 free 各吃掉一个右邻居：free(y[1]) 时自己的 PREV_INUSE 已是 0（y[0] 空闲）→ 后向合并，0x510 + 0x510 = 0xa20；free(y[2]) 同理并入成 0xf30。两次的 fd/bk 都没变——合并后的大块继续留在 unsorted，链上始终只有这一块。y[2] 右边的 sp2 标志位清零。==unsorted bin 里 0x405ac0 一个地址覆盖了三个 y 的位置==：起点不变，size 长大。

### 阶段 K：两次 malloc(0x1f8)——unsorted 的切分

```text
z[0] = 0x405ad0
z[1] = 0x405cd0
>>>>> K：两次 malloc(0x1f8) 完成，unsorted 切分
  （前 20 行同前，略）
[20] 0x405ac0 size 0x0200 PREV_INUSE               在用（或在 tcache 里）
[21] 0x405cc0 size 0x0200 PREV_INUSE               在用（或在 tcache 里）
[22] 0x405ec0 size 0x0b30 PREV_INUSE               空闲可合并 fd 0x7ffff7e12ac8 bk 0x7ffff7e12ac8  (fd/bk 指向 libc 的 main_arena)
  （其余行略）
```

两次请求都没命中 tcache/smallbin 的精确档，于是触发 unsorted 遍历（第 4 节第 3、4 步）。第一次：链上的 0xf30 不是精确尺寸，被搬进 largebin，随后按最佳适配被 unlink、切出前 0x200 交付（z[0] = 0x405ad0），余块 0xd30 回到 unsorted 并登记为 last_remainder。第二次：unsorted 里恰好只有 last_remainder，直接按 6.3 再切一刀——z[1] = 0x405cd0，余块缩到 0xb30。==地址上 z[0]、z[1] 紧挨着==，6.3 说的"顺序分配地址连续"就是这条 last_remainder 路径的效果。

### 阶段 L：malloc(0x1f000) 与 malloc(0x21000)——top 切分与 mmap

```text
n = 0x406a30
m = 0x7ffff7f89010
>>>>> L：malloc(0x1f000) 与 malloc(0x21000) 完成
  （前 22 行同前，略）
[22] 0x405ec0 size 0x0b30 PREV_INUSE               空闲可合并 fd 0x7ffff7e13078 bk 0x7ffff7e13078  (fd/bk 指向 libc 的 main_arena)
[23] 0x4069f0 size 0x0030 0                        在用（或在 tcache 里）
[24] 0x406a20 size 0x1f010 PREV_INUSE               在用（或在 tcache 里）
[25] 0x425a30 size 0x05d0 PREV_INUSE               <- top
>>>>> largebin 残块（z[1] 切分后的余块）：
0x405ec0:	0x0000000000000000	0x0000000000000b31
0x405ed0:	0x00007ffff7e13078	0x00007ffff7e13078
0x405ee0:	0x0000000000405ec0	0x0000000000405ec0
>>>>> mmap 块头部：
[ 0] 0x7ffff7f89000 size 0x21ff0 IS_MMAPPED               <- mmap 块，free 时整个 munmap
```

三个对象三个去处，把 malloc 流程的收尾三个分支各演示一遍：

- **n（0x1f000 → nb 0x1f010）**：0xb30 装不下这个请求，unsorted 遍历时被搬进 largebin，binmap 扫描确认没有更大的块，落到 top——切出 0x406a20 的 0x1f010，top 从 0x1f5e0 缩到 0x5d0。第 4 节第 5 步的现场。
- **0xb30 的搬迁在输出里有直接痕迹**：阶段 K 里它的 fd/bk 是 0x7ffff7e12ac8（unsorted 头），本次变成 0x7ffff7e13078（largebin 头）——==块没动，只是换了登记处，看 fd/bk 就知道它在哪条链上==。`x/6gx` 的六个字段与第 2 节布局图逐一对上：size 原始值 0xb31（0xb30 + PREV_INUSE），fd、bk 指向 largebin 头，fd_nextsize、bk_nextsize 都是自己——bin 里唯一的块，尺寸环退化为自环。
- **m（0x21000 → nb 0x21010）**：超过 mmap 阈值 0x20000，sysmalloc 直接 mmap 了一整段独立内存（0x7ffff7f89010，与堆区无关的另一段映射）。`heapview` 用起始参数跳过去看它的头：IS_MMAPPED 置位。size 显示 0x21ff0——mmap 块的 size 记录"映射总长减头"，0x21ff0 + 0x10 恰好是按页对齐后的 0x22000。==free(m) 不进任何 bin，整段 munmap 归还内核==。

### 全程对照表

| 阶段 | 演示的机制 | 对应节 |
| ---- | ---- | ---- |
| A | 堆的诞生；2.43 的 tcache 结构不在场 | 第 2 节、9 |
| B | tcache 结构就位；safe-linking 空链形状；key 随机值 | 3.1 |
| C | top 切分；式 12.1 的换算 | 第 4 节 |
| D | tcache 装满（16 个）；PREV_INUSE 不动 | 3.1、5 |
| E | tcache 满后直进 smallbin；main_arena 地址出现 | 3.2、5 |
| F | tcache LIFO 弹出；smallbin 供块 | 3.1、3.2 |
| G | 超 tcache 档位直走 top | 4 |
| H | 大块进 unsorted | 3.4 |
| I、J | 后向合并 | 6.1 |
| K | unsorted 遍历、largebin 搬入、切分与 last_remainder | 6.3、4 |
| L | top 再切；largebin 搬迁；mmap 阈值 | 4、3.3 |

## 9. glibc 2.43 行为注记

本章按 glibc 2.43 讲解。malloc 在 2.41–2.43 三个版本里被大幅重写，市面资料大多停留在 2.3x–2.40 的行为，对照表逐条列清：

| 行为 | 2.43 现状 | 版本节点 | 影响 |
| ---- | ---- | ---- | ---- |
| tcache | 默认开启，64 个小档覆盖 chunk 0x20–0x410 | 2.26 引入 | free/malloc 的第一站 |
| tcache 每档上限 | 默认 16 个 | 2.43（此前是 7） | ==装满一档要 16 次 free==，堆布局的步距变了 |
| 每档计数 | `num_slots`（剩余容量，16 递减） | 2.42 | 取代老 `counts`（已用数，0 递增），语义相反 |
| tcache 大档 | 76 档（多 12 个大档，默认关闭，`tcache_max` 可开到 4 MB） | 2.42 | 默认行为与老版一致 |
| tcache 结构分配时机 | ==第一次 free 时==，0x300 的 chunk | 2.43（此前在首次 malloc 时，固定是堆上第一块） | "堆上第一个 chunk 是 tcache 结构"不再成立 |
| tcache key | 进程内随机值，double-free 全表核查 | 2.29 引入检测（2.34 起值为随机数） | 同块二次 free 直接 abort，绕过 [[P14-tcache与fastbin利用\|P14]] |
| safe-linking | 单链指针加密常态化 | 2.32 | fd/next 槽里看到的不是真地址，[[P14-tcache与fastbin利用\|P14]] 展开 |
| fastbin | ==整体移除== | 2.43（2.42 及以前存在，收 0x20–0x80） | 老题解的 fastbin 步骤在本机不可复现 |
| 小块 free 去向 | tcache 满后直接进对应 smallbin | 2.41 | 不再经过 unsorted，"unsorted 里堆满小块"的景象消失 |
| `__malloc_hook` / `__free_hook` | 不存在 | 2.34 移除 | 改 hook 的路线绝迹，转 FSOP（[[P15-House系列攻击技术\|P15]]、[[P16-FSOP与HouseofApple2\|P16]]） |
| mmap 阈值 | 0x20000 起，动态上调 | 恒定行为 | ≥ 0x20000 的请求走 mmap（第 8 节 L 阶段） |

> [!note] 读老资料的换算法
> 老题解里的"free 7 个装满 tcache"→ 本机改 16 个；"counts 数组"→ `num_slots`，计数方向相反；"第 8 个 free 进 fastbin"→ 本机直接进 smallbin；"tcache 结构是堆上第一个块，偏移 0x10 处打 counts"→ 结构仍在堆上，但位置不固定，先定位再打。这些差异不改变攻击思路的骨架，只改变布点与步长——[[P14-tcache与fastbin利用|P14]] 起全部按 2.43 实际行为推演。

## 10. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| `heapview` 报"没有 [heap] 映射" | 断点停在第一次 malloc 之前，堆区还没诞生。断点后移（7.5 的 mark 模板天然避开） |
| `tcacheview` 报"堆上没有 tcache 结构" | 本线程还没 free 过任何块——2.43 的结构在首次 free 时才分配（第 8 节 A 阶段），不是脚本坏了 |
| heapview 显示"在用"的块，tcacheview 却能在链上找到它 | PREV_INUSE 记录"可否合并"，tcache 不清这个位（第 2 节的 warning）；看 tcache 要用 tcacheview |
| `chunk` 命令读出的 size 是天文数字 | 参数传成了 malloc 返回的 mem 地址，chunk 地址要再减 0x10 |
| `x/1gx` 看到的 size 末尾带 1 或 2 | 低 3 位是标志位，`& ~0xF` 之后才是块大小（第 2 节） |
| 两次运行的堆地址对不上 | GDB 默认关闭 ASLR，会话之内稳定；换会话、换机器都会变，以形状与相对关系为准（[[P04-Linux安全缓解机制\|P4]]） |
| free 一个块两次，程序直接 Aborted | tcache key 的 double-free 检测（3.1），输出 `free(): double free detected in tcache 2`；绕过思路 [[P14-tcache与fastbin利用\|P14]] |
| 按老题解 free 8 个却看不到块离开 tcache | 2.43 每档上限是 16 不是 7，[[#9. glibc 2.43 行为注记\|第 9 节]]对照表 |
| 想 free 相邻两块看合并，却什么都没发生 | 两块都进了 tcache，没满就没有合并（第 5 节的 warning）；先装满该档 |
| `malloc(0x30000)` 返回的地址与堆区无关 | 超过 mmap 阈值，走独立映射（第 8 节 L 阶段），free 它时整段归还 |
| fd 还原出来的值不像地址 | 该块不在单链上：在用块的 fd 是普通数据，还原无意义（7.4 的括号说明） |

## 11. 配套练习与延伸阅读

> [!note] 实战任务：在 GDB 里完整跟踪 10 次 malloc/free
> 把 `p12_demo.c` 复制一份改成自己的序列：10 次 malloc（尺寸从 0x18 到 0x500 自选）加 10 次 free（释放顺序与分配顺序刻意不同），每个操作之间插一个 `mark()`。写 payload 之前先动笔：
> ① 每次操作前在纸上写下预测——这个块从哪来（tcache 某档 / smallbin / top）、free 后去哪（tcache / smallbin / unsorted / 并进 top）、会不会触发合并；
> ② 用 [[#7. 调试方法：GDB 原生加自写堆观察脚本|第 7 节]]的 `heapview` + `tcacheview` 逐阶段对照预测，地址全部要能对上号；
> ③ 记录三类反直觉现象：tcache 里的块在 size 链上"看起来在用"、小块 free 后直接出现在 smallbin、相邻两块 free 了却不合并；
> ④ 把一次请求改成 0x408 与 0x409 各试一遍，用式 12.1 解释行为分界；
> ⑤ 最后追加一次 `malloc(0x20000)`，用 `heapview 表达式` 确认它落在 mmap 区。
> 全部预测与现场一致，这部分就掌握了；对不上的每一处，回到对应小节重读。

延伸阅读按用途分三档：

- **源码**：glibc 的 `malloc/malloc.c`（2.43 的 tcache、_int_malloc、_int_free_merge_chunk 都在这一个文件里）、`malloc/arena.c`（多线程 arena）。遇到本章没写的细节，源码注释是第一手资料。
- **社区仓库**：shellphish 的 how2heap（GitHub）按攻击技术组织最小示例，[[P13-基础堆漏洞|P13]] 起会频繁引用；其中多数示例基于旧版 glibc，跑之前先对一遍 [[#9. glibc 2.43 行为注记|第 9 节]]的表。
- **后续章节**：悬垂指针与越界写如何破坏本章的结构 → [[P13-基础堆漏洞|P13]]；tcache 与 fastbin 的攻击 → [[P14-tcache与fastbin利用|P14]]；House 系列与 largebin 攻击 → [[P15-House系列攻击技术|P15]]；FSOP → [[P16-FSOP与HouseofApple2|P16]]；把堆布局当成解题工具 → [[P17-堆风水与通用利用思路|P17]]。
