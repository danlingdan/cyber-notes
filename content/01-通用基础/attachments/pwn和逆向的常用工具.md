---
publish: true
---

# 二进制常用工具大全

## 一、静态分析 / 反汇编 / 反编译

==**IDA Pro**== — 行业标准反汇编器，配合 Hex-Rays 反编译器可生成可读的伪代码。拥有最成熟的 IDAPython 脚本生态，是商业逆向工程的事实标准。

**Ghidra** — 美国国土安全局开源的逆向工程框架，内置反编译器，支持协作分析和 P-code 中间表示。免费且功能完整，是 IDA Pro 的主要开源替代品。

**objdump / ndisasm / readelf** — GNU binutils 中的基础工具，用于快速查看反汇编、节表、符号表等信息，轻量。==一般性在Linux各大发行版中预装==，适合脚本化和快速排查。

**radare2 / rizin / Cutter** — 开源逆向分析框架。radare2 以命令行为主，rizin 是其社区分支，Cutter 是基于 rizin 的图形界面。

## 二、动态调试

**GDB** — Linux 下最核心的动态调试器。通过 `.gdbinit` 配置可以显著提升调试体验，例如设置 Intel 语法、关闭分页、保存历史记录等。

==**pwndbg**== — 专为 Pwn 和逆向设计的 GDB 插件，提供可视化的堆块信息（`heap` 命令）、内存映射（`vmmap`）、递归指针解析（`telescope`）等功能，在堆漏洞分析时尤其有用。它还支持 QEMU 模拟和与 Ghidra 的集成。

**GEF** — 另一个 GDB 增强插件，功能与 pwndbg 类似，但在某些场景下更轻量。常与 pwndbg 并列作为 Pwn 工具链的标准组件。

**WinDbg**  — Windows 平台调试器。WinDbg 适合内核和驱动调试。

==**x64dbg**== — x64dbg 是开源的用户态调试器，界面友好。

## 三、漏洞利用开发（Pwn 专属）

==**pwntools**== — Python 编写的 CTF 框架和 exploit 开发库。封装了进程/远程连接、ELF 解析、ROP 链生成、格式化字符串 payload 构造等功能。常用函数包括 `cyclic()` 定位偏移、`fmtstr_payload()` 生成格式化字符串利用、`ROP(elf)` 自动生成 ROP 链。

**ROPgadget / ropper** — 从二进制中搜索 ROP gadgets 的工具。ROPgadget 支持 ELF/PE/Mach-O，ropper 在 gadget 搜索和链构造方面功能更丰富。两者常配合使用，先用 ROPgadget 收集 gadgets，再用 ropper 构造链。

**one_gadget** — Ruby 编写的工具，用于在 libc 中查找可以直接执行 `execve("/bin/sh", ...)` 的 magic gadget，是 ret2libc 场景下的常用辅助工具。

**libc-database** — 通过泄露的 libc 函数地址反查 libc 版本的数据库工具。在远程 exploit 开发中，当远程环境使用与本地不同的 libc 时，这个工具用于确定目标 libc 版本。

**seccomp-tools** — 用于分析和绕过 seccomp 沙箱规则的工具。在 CTF 中常用于查看程序施加了哪些系统调用限制。

**checksec** — 随 pwntools 附带，快速检查二进制启用的保护机制（NX、Canary、PIE、RELRO 等）。

## 四、符号执行与约束求解（部分适用于密码学/Misc）

**angr** — 基于 Python 的二进制分析平台，支持符号执行、控制流恢复和漏洞发现。在逆向工程中常用于自动化求解 CTF 中的复杂校验逻辑。

**Z3** — 微软开发的 SMT（可满足性模理论）求解器。**angr 内部依赖 Z3 进行约束求解**，在逆向逆向数学校验、约束恢复等场景中也可以独立使用。

**Triton** — 动态二进制分析框架，支持符号执行和污点分析，适合对指令级语义进行建模。

## 五、懒人选择

如果不想手动逐个配置，可以考虑使用现成的 Docker 镜像。**pwndocker-reverse** 集成了 45+ 工具，包括 7 个反汇编/反编译工具（Ghidra、IDA Free、Binary Ninja Free、Cutter、radare2、rizin、retdec）和 3 个 GDB 插件（可即时切换）。