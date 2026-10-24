---
chapter: 通用基础
section: Linux 环境与 CTF 实验环境搭建
order: 101
tags:
  - CTF
  - 通用基础
  - Linux
  - 环境搭建
publish: true
---

# 01 Linux 环境与 CTF 实验环境搭建
## Linux Environment & CTF Lab Setup

> [!info]- 章节信息
> **所属方向**：通用基础 ｜ **难度阶段**：L0 预备期 ｜ **前置要求**：无
> **本章目标**：从零搭建一套可用于 PWN 与逆向学习的 Linux 实验环境，并掌握后续学习必备的命令行操作。

## 1. 为什么需要独立实验环境

CTF 的 PWN 与逆向学习会频繁编译、调试、攻击可执行文件。如果直接在日常主力系统上操作，一旦误操作可能损坏系统；更重要的是，所有漏洞利用技术**只能在你自己拥有或获得明确授权的环境中练习**。

> [!warning] 法律与伦理红线
> 本知识库讲授的全部技术仅适用于个人实验环境、授权靶场与 CTF 比赛平台。对未授权系统进行扫描、入侵或破坏，属于犯罪行为。请始终遵守"先授权、再测试"原则，做建设性的安全研究者。==孩子们，不要把牢底坐穿了==

## 2. 环境方案选型

### 2.1 推荐配置

| 项目    | 推荐方案                             | 说明             |
| ----- | -------------------------------- | -------------- |
| 宿主机   | Windows / macOS / Linux 均可       | 日常使用不受影响       |
| 虚拟化平台 | WSL 或 VMware Workstation Pro     | 优先前者           |
| 客户机系统 | **Ubuntu 24.04 LTS 或 26.04 LTS** | 理由见 2.2        |
| 内存    | ≥ 4 GB（建议 8 GB）                  | 同时运行虚拟机与宿主机的下限 |
| 磁盘    | ≥ 40 GB                          | 后续安装工具链与题库环境   |

### 2.2 系统版本与 glibc

PWN 利用手法与 glibc 版本==强绑定==。

> [!info] glibc是什么
> **glibc = GNU C Library**，是 GNU 项目实现的 **C 标准库**，也是 Linux 上最常用的 `libc` 实现。
> - 是用户态程序与 Linux 内核之间的基础库。
> - 实现 ISO C 标准、POSIX 接口，以及部分 GNU 扩展。
> - 提供 `printf`、`malloc`、`fopen`、`pthread`、数学函数等常见功能。
> 
> >[!warning] 注意
> >题目难了有可能给你非glibc实现，如`musl`、`uClibc`、Android 的 `Bionic`。


**Ubuntu LTS 与 glibc 版本对照**：

| Ubuntu 版本 | glibc | 标准支持 |
|-------------|-------|----------|
| 20.04 | 2.31 | 2025 年已结束（仅剩 Ubuntu Pro ESM 扩展维护） |
| 22.04 | 2.35 | 2027 年 |
| 24.04 | 2.39 | 2029 年 |
| **26.04（当前最新 LTS）** | **2.43** | 2031 年 |

**glibc 演进中的关键节点**：

| glibc 版本 | 变化 | 受影响的手法 |
|------------|------|--------------|
| 2.26 | 引入 tcache | tcache poisoning 可用 |
| 2.29 | smallbin / tcache stashing 检查变化 | stashing unlink 需满足新条件 |
| 2.32 | safe-linking（tcache fd 指针异或加密） | tcache / fastbin 的 fd 需先解密 |
| 2.34 | 移除 `__free_hook` / `__malloc_hook` | hook 覆盖失效，转向 FSOP / House of Apple 2 / setcontext |
| 2.39+ | 持续加固 | 利用链整体上移 |

> [!note] 版本确认方法
> ```bash
> ldd --version                                              # 查看 glibc 版本
> strings /lib/x86_64-linux-gnu/libc.so.6 | grep GLIBC_      # 查看 libc 提供的符号版本
> ```

### 2.3 虚拟机网络模式

> [!warning] 本文仅讨论VMware 和 WSL3版本两个软件的网络模式

> [!info] VMware 网络模式
> | 模式  | 连通性                  | 适用场景            |
> | --- | -------------------- | --------------- |
> | NAT | 虚拟机可访问外网，外网不能主动访问虚拟机 | 日常刷题、下载工具（默认推荐） |
> | 桥接  | 虚拟机与宿主机同级，可互相访问      | 与宿主机联调、AWD 练习   |
> | 仅主机 | 虚拟机只能与宿主机通信          | 完全隔离的样本分析环境     |
> > [!info] VMware 中如果需要使用代理，需要自己配置，否则不会生效！

> [!info] WSL 3 网络模式
> | 模式                 | 连通性                                                                                             | 适用场景                              |
> | ------------------ | ----------------------------------------------------------------------------------------------- | --------------------------------- |
> | NAT（默认）            | WSL 拥有独立内部 IP，通过 Windows 主机 NAT 访问外网。代理：不自动继承 Windows 系统代理；需把代理指向 WSL 中看到的宿主机 IP（即默认网关），并允许局域网连接。        | 日常开发、上网，不需要局域网直接访问 WSL。           |
> | mirrored           | WSL 与 Windows 共享网络栈和 IP，`localhost` 双向互通。代理：==可自动继承 Windows 的 HTTP/HTTPS 系统代理。==                 | 需要局域网互访、VPN 兼容、自动继承系统代理。          |
> | bridged（已弃用）       | WSL 像局域网独立设备获取 IP；官方已弃用。                                                                        |                                   |
> | consomme（WSL 3 新增） | 专为 WSL 3 的 Linux 容器设计，容器流量经 Windows 进程路由、DNS 和端口映射。代理：可继承 Windows 主机的网络策略/企业代理，个人系统代理继承取决于具体实现。 | 在 WSL 3 中运行 Linux 容器，尤其要遵循企业网络策略。 |
> | none               | 完全断开网络。                                                                                         | 安全测试、完全离线环境。                      |

### 2.4 对齐目标程序的 glibc 版本

CTF 题目会随附件提供远程服务所用的 `libc.so.6` 与动态链接器 `ld-linux-x86-64.so.2`。本地直接用题目组件即可：

```bash
# 方式一：以题目自带 loader 直接运行
./ld-linux-x86-64.so.2 --library-path . ./pwn

# 方式二：用 patchelf 把目标程序的 interpreter 与 rpath 永久指向题目组件
sudo apt install patchelf
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./pwn
./pwn
```

若题目附带 Dockerfile，`docker build && docker run` 可完整复现出题环境；日常练习也可借助 glibc-all-in-one / libc-database 快速取得各版本 libc。**先确认目标 glibc 版本，再决定使用哪套手法**，这是 PWN 解题的第一步。
> [!info] Docker
> Docker 是一个用于**构建、打包、分发、运行容器化应用**的开源平台。它把应用及其依赖打包成标准化的**镜像**，然后在任何支持 Docker 的环境中运行成**容器**。
> > [!info] 容器
> 容器是一种**轻量级、可移植、进程级隔离**的运行环境。容器里的进程看起来像运行在一台独立机器上，但==实际上它和宿主机共享同一个 Linux 内核==，所以Windows下常与WSL集成。

## 3. 安装步骤

### 3.1 方案 A：WSL 3

在 Windows PowerShell（管理员）中执行：

```powershell
wsl --install                    # 默认安装最新 LTS（当前为 26.04）
wsl --list --online              # 查看可选发行版
wsl --install -d Ubuntu-24.04    # 如需指定版本
```

### 3.2 方案 B：VMware 完整虚拟机

1. 从 ubuntu.com 下载 Ubuntu 24.04 LTS 或 26.04 LTS 桌面版 ISO。
2. 在 VMware Workstation Pro 中新建虚拟机，分配内存与磁盘。
3. 挂载 ISO 启动，按向导完成安装。

两种方案装好后都执行系统更新：

```bash
sudo apt update
sudo apt upgrade -y
```

## 4. Linux 命令行基础速查

后续所有章节都建立在命令行操作之上。

### 4.1 文件与目录

| 命令                               | 作用                               |
| -------------------------------- | -------------------------------- |
| `ls -la`                         | 列出目录全部内容（含隐藏文件与权限）               |
| `cd /path`                       | 切换目录（`cd ~` 回到用户根目录，`cd ..` 上一级） |
| `cp -r src dst`                  | 递归复制                             |
| `mv src dst`                     | 移动 / 重命名                         |
| `rm -rf dir`                     | 递归强制删除（**高危，执行前确认路径**）           |
| `find / -name "*.c" 2>/dev/null` | 按名称查找文件                          |
| `grep -rn "flag" .`              | 递归搜索文本内容                         |

### 4.2 权限与用户

| 命令 | 作用 |
|------|------|
| `id` | 查看当前用户与所属组 |
| `chmod 755 file` | 修改权限（rwx 对应三位八进制） |
| `chmod u+s file` | 设置 SUID（见第 6 节说明） |
| `sudo cmd` | 以 root 身份执行 |

### 4.3 进程与二进制文件

| 命令                 | 作用                    |
| ------------------ | --------------------- |
| `ps aux`           | 查看进程列表                |
| `kill -9 PID`      | 强制结束进程                |
| `file ./target`    | **识别文件类型（逆向分析第一课必用）** |
| `strings ./target` | 提取可打印字符串（寻找 flag 线索）  |

### 4.4 网络

| 命令              | 作用               |
| --------------- | ---------------- |
| `ip addr`       | 查看网卡与 IP 地址      |
| `nc -v IP PORT` | 连接远程服务（PWN 交互基础） |
| `ssh user@IP`   | 远程登录             |

## 5. 安装 CTF 基础工具链

以下为 PWN 与逆向共用的最小工具集，在 Linux 终端中依次执行。
> [!info] 更加完整工具链见[[pwn和逆向的常用工具]]
### 5.1 编译与调试

```bash
sudo apt update
sudo apt install -y gcc gdb git python3 python3-pip \
  binutils file checksec gcc-multilib netcat-openbsd patchelf
```

| 工具 | 用途 |
|------|------|
| `gcc` | 编译 C 程序；`gcc-multilib` 提供 32 位编译支持 |
| `gdb` | 调试器，PWN 核心工具 |
| `binutils` | 提供 `objdump`、`readelf`、`strings` 等二进制分析命令 |
| `checksec` | 一键查看程序保护机制（NX / Canary / PIE / RELRO） |

### 5.2 pwntools 与 GDB 插件

```bash
# pwntools：Python 漏洞利用开发框架
python3 -m pip install pwntools

# pwndbg：GDB 增强插件
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

> [!note] 插件选型
> GDB 插件三家（pwndbg / gef / peda）功能重叠，**选一个即可**，本知识库默认使用 pwndbg。安装后启动 GDB 应看到增强界面，否则检查 `~/.gdbinit` 配置。

### 5.3 其他常用工具（随用随装）

| 工具           | 安装方式                                                   | 用途                              |
| ------------ | ------------------------------------------------------ | ------------------------------- |
| ROPgadget    | `python3 -m pip install ROPgadget`                     | 搜索 ROP gadget                   |
| one_gadget   | `sudo apt install ruby && sudo gem install one_gadget` | 一键定位 `execve("/bin/sh")` gadget |
| LibcSearcher | `python3 -m pip install LibcSearcher`                  | 根据泄露地址匹配 libc 版本                |


## 6. 常见问题

| 现象                         | 原因与解决                                                         |
| -------------------------- | ------------------------------------------------------------- |
| `gcc: error: missing -m32` | 未装 32 位支持：`sudo apt install gcc-multilib`                     |
| GDB 无 pwndbg 界面            | `~/.gdbinit` 未生效，重跑 `pwndbg/setup.sh` 或检查配置                   |
| pip 安装 pwntools 报错         | 加 `--user` 参数：`python3 -m pip install --user pwntools`        |
| 虚拟机无法联网                    | 检查网络模式是否为 NAT；VMware 中确认虚拟网络编辑器正常                             |
| `nc: command not found`    | `sudo apt install netcat-openbsd`                             |
| WSL 中 apt 安装异常             | 确认发行版已完成首次初始化（需创建用户）；WSL 内核用 `wsl --update`（在 PowerShell 中）更新 |

