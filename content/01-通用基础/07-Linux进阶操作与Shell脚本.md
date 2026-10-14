---
chapter: 通用基础
section: Linux 进阶操作与 Shell 脚本
order: 107
tags:
  - CTF
  - 通用基础
  - Linux
  - Shell
publish: true
---

# 07 Linux 进阶操作与 Shell 脚本
## Advanced Linux & Shell Scripting

> [!info]+ 章节信息
> **所属方向**：通用基础 ｜ **难度阶段**：L0 预备期 ｜ **前置要求**：[[01-Linux环境与CTF实验环境搭建|01 Linux 环境与 CTF 实验环境搭建]]
> **本章目标**：理解权限位和信号机制；能熟练组合管道、重定向和三剑客处理文本；能写出可复用的 Shell 脚本。
> **已核验说明**：本章全部命令输出来自 WSL Ubuntu 26.04 实跑结果（权限位在原生 ext4 文件系统上测得，/mnt/c 这类 Windows 挂载盘不遵循 POSIX 权限，测出来全是 777）。

## 1. 从敲命令到串命令

01 说了装环境和基本命令，前几章的编译、调试、跑 exp 也都是命令行操作。这一章说一下系统层的四件事：权限、信号、管道重定向、文本批处理三剑客，最后把它们大合集成脚本。

CTF 里这些的出场方式：改 exp 权限、看 SUID 提权点、脚本卡住了 kill 掉、日志里 grep flag、把 100 个文件的输出 awk 汇总。

## 2. 权限与用户

### 2.1 rwx 三组九位

`ls -l` 的第一列是权限位，三组各三位：**属主 / 属组 / 其他人**，各是 `r`(4) `w`(2) `x`(1) 的和。数字写法就是三个八进制位：

| 命令 | 结果 | 读法 |
| ---- | ---- | ---- |
| `chmod 644 f` | `-rw-r--r--` | 属主读写，其他人只读：文件默认 |
| `chmod u+x f` | `744` | 只给属主加执行位 |
| `chmod 755 f` | `-rwxr-xr-x` | 脚本、程序的典型权限 |
| `chmod 4755 f` | `4755` | 首位 4 = **SUID**，往下看 |

==`x` 对目录的含义是"能否进入"==，`chmod 644 dir` 之后连 `cd` 都进不去 —— 遇到 Permission denied 先看是文件没 `x` 还是目录没 `x`。

### 2.2 SUID：借谁的身份证

SUID 位（`4xxx`）让程序以**文件属主**的身份运行而不是执行者。系统里最典型的：

```bash
stat -c '%a %U' /usr/bin/passwd     # 4755 root
find /usr/bin -perm -4000           # 列出全系统 SUID 程序，实测有 su、mount……
```

`passwd` 要改 `/etc/shadow`（只有 root 能写），普通用户却能改自己的密码，靠的就是这个位。==PWN 题的提权逻辑同款：SUID 程序里藏一个溢出，拿到的 shell 就是 root 的==。`find -perm -4000` 是拿到 shell 后第一件事之一。

### 2.3 用户存在哪

`/etc/passwd` 一行一个用户，七个字段冒号分隔：

```
root:x:0:0:root:/root:/bin/bash
 │   │ │ │    │     │      └ 登录 shell
 │   │ │ │    │     └ 家目录
 │   │ │ │    └ GECOS 备注
 │   │ │ └ GID（组 ID）
 │   │ └ UID（用户 ID，0 就是 root）
 │   └ 密码占位（真密码在 /etc/shadow）
 └ 用户名
```

`sudo` 的授权在 `/etc/sudoers`（用 `visudo` 编辑，直接改会拒载）。自己虚拟机里把日常用户加进 sudo 组即可，别拿 root 当日常账号 —— exp 写错一个 `rm` 就==🔴完蛋辣==。

## 3. 进程与信号

### 3.1 看、杀、后台

```bash
ps aux | grep vuln          # aux = 全系统进程 + 资源占用；grep 过滤
./vuln &                    # 直接丢后台
jobs                        # 看当前 shell 的后台任务：[1]+  Running  sleep 3 &
fg %1                       # 拉回前台；ctrl+Z 挂起后 bg %1 丢回后台
kill 12345                  # 发 SIGTERM（默认），进程可以礼貌拒绝
kill -9 12345               # 发 SIGKILL，内核直接回收，无法拦截
nohup ./server &            # 挂断终端也活着，AWD 起服务常用
```

`kill %1` 杀的是**当前 shell 的 1 号后台任务**，`kill 1` 是给 PID 1 发信号 —— 完全两码事，混用会出事故。

### 3.2 信号表

信号是内核通知进程的异步事件，`kill -l` 列全表（实测 62 个）。CTF 常打交道的六个：

| 信号 | 编号 | 触发 | 能否被捕获 |
| ---- | ---- | ---- | ---------- |
| SIGINT | 2 | Ctrl+C | 能，可被脚本忽略 |
| SIGTERM | 15 | `kill` 默认 | 能，"请你退出" |
| SIGKILL | 9 | `kill -9` | **不能**，直接处决 |
| SIGSEGV | 11 | 非法访存 | 能，但默认就是崩 |
| SIGSTOP | 19 | 挂起 | 不能（SIGKILL/STOP 不可捕获是硬规定） |
| SIGCHLD | 17 | 子进程结束 | 能，server 收尸用 |

两个编号要形成条件反射：==`Segmentation fault` 就是 SIGSEGV==，04 章的 ret2win 崩在这、06 章 `io.wait()` 后读 coredump 也靠它 —— 程序"崩了"不是坏消息，RIP 指向哪全写在 coredump 里。`trap` 可以自己做清理：

```bash
trap 'echo caught SIGINT' INT    # 实测 Ctrl+C / kill -INT $$ 时打印这行
```

## 4. 管道与重定向

每个进程自带三条标准流：stdin(0)、stdout(1)、stderr(2)。Shell 的重定向符就是在拨这三根线：

```bash
./vuln > out.txt              # stdout 覆盖写文件（1 可省略：1> 同义）
./vuln >> out.txt             # 追加
./vuln 2> err.txt             # 只收 stderr
./vuln > all.txt 2>&1         # stdout 进文件，stderr 并入 stdout —— 顺序不能反
./vuln < payload.bin          # 文件当 stdin，喂 exp 输入神器
./vuln <<< "text"             # here-string：字符串当 stdin
cmd1 | cmd2                   # cmd1 的 stdout 接 cmd2 的 stdin
make 2>&1 | tee build.log     # tee：边看边存，编译报错不漏
```

`2>&1` 的顺序是经典问题：==它是"把 2 重定向到 1 当前指向的地方"，所以必须写在 `> file` 之后==。写反了 stderr 会打到屏幕而不是文件。

管道两头是并发的，没有中间文件。配合 `xargs` 把"一列东西"变成"一条条命令"：

```bash
cat targets.txt | xargs -n1 ./scan            # 每行跑一次
ls *.pcap | xargs -I{} tshark -r {} -Y "http" # {} 占位
```

## 5. 文本批处理三剑客

`grep` 找行、`sed` 改行、`awk` 拆字段。三者都以行为单位吃 stdin/文件：

### 5.1 grep：按模式筛行

```bash
grep flag log.txt            # 含 flag 的行（区分大小写）
grep -i flag log.txt         # 忽略大小写，实测 2 行变 3 行
grep -n -i flag log.txt      # 带行号：1:flag{a1}
grep -c flag log.txt         # 只数行数：2
grep -r "system(" ./src/     # 递归搜目录 —— 审源码找危险函数
grep -E "flag\{[0-9a-f]{8}\}" log.txt   # 扩展正则
grep -A3 -B1 "panic" dmesg.txt          # 匹配行后 3 行前 1 行
```

### 5.2 sed：按规则改行

```bash
sed 's/c.t/X/g' f            # 实测 cat cut cot → X X X；s/旧/新/g 全局替换
sed '1s/^/# /' f             # 第 1 行行首加 #；默认会把所有行打出来
sed -n '2p' f                # -n 关掉默认输出，p 只打印第 2 行
sed -i.bak 's/127.0.0.1/0.0.0.0/' conf   # -i 原地改，.bak 留备份
```

`-i` 直接改文件，先 `.bak` 或先跑一遍不带 `-i` 的看输出。

### 5.3 awk：按列算账

```bash
awk '{s+=$2} END {print NR" rows, avg = "s/NR}' scores.txt
# 实测：3 rows, avg = 82.3333   （NR 行数，$2 第二列）
awk -F: '{print $1, $7}' /etc/passwd     # -F 指定分隔符：用户名和 shell
awk '{print $NF}' f                       # $NF 最后一列
```

`$1` `$2` 是列，`NR` 是行号，`NF` 是列数，模式-动作对 `{...}` 前可以加条件如 `$2 > 80`。日志统计、dump 汇总一类活，awk 一行顶十行 Python。

## 6. 脚本自动化

### 6.1 语法骨架

```bash
#!/bin/bash                     # shebang：用哪个解释器跑
set -e                          # 出错即停，脚本标配（set -x 打印每条命令，调试用）

name=ctf                        # 赋值两边不能有空格
echo "hello, $name"             # 实测：hello, ctf
echo $((6 * 7))                 # 算术：42；命令替换用 $(date +%s)

[ -f /etc/hostname ] && echo exists     # -f 文件存在 -d 目录 -z 空串 -eq -lt 数字比较
for i in 1 2 3; do printf '%s' "$i"; done; echo    # 实测：123
seq 1 100 | awk '{t+=$1} END {print t}'            # 实测：5050

f() { echo "arg1=$1 count=$#"; }          # $1 起是参数，$# 是个数
f abc def                                 # 实测：arg1=abc count=2
true; echo $?                             # $? 上一条退出码，0 为成功
```

`bash script.sh` 直接能跑；要 `./script.sh` 就得 `chmod +x`（见 [[#2. 权限与用户|权限一节]]）。

### 6.2 一个实用的批量脚本

批量编译、批量看保护，做题时常备：

```bash
#!/bin/bash
# batch.sh：对目录下每个 .c 编译 + 打印保护摘要
set -e
for src in *.c; do
    bin="${src%.c}"                                   # 去后缀
    gcc -O0 -fno-stack-protector -no-pie "$src" -o "$bin" 2>/dev/null \
        && echo "== $bin ==" && checksec --file="$bin" | grep -E 'RELRO|Canary|NX|PIE'
done
```

把 06 章的 exploit 也照这个思路参数化（`./exp.py host port`，`sys.argv` 取参），一场比赛的基本盘就有了。

## 7. 常见问题

| 现象 | 原因与解决 |
| ---- | ---------- |
| `Permission denied` 跑不了脚本 | 没执行位：`chmod +x`；或是目录没 `x` 进不去 |
| 脚本报 `/bin/bash^M: bad interpreter` | Windows 换行符 `\r\n` 带进来了：`sed -i 's/\r$//' script.sh` 或 `dos2unix` |
| `cmd > f 2>&1` 文件里没有报错 | 写成 `cmd 2>&1 > f` 了，顺序反了：先定位 1 再借道给 2 |
| `kill 1` 差点出大事 | 那是给 PID 1 发信号；杀后台任务用 `kill %1` |
| 脚本 Ctrl+C 停不下来 | 里面起了子进程在收尾，用 `kill -9` 进程组：`kill -9 -PGID` |
| `grep` 明明有就是搜不到 | 大小写（加 `-i`）、正则元字符没转义（`.` `*` `{}`）、或文件是 UTF-16 编码（`file` 先看） |
| `sed -i` 把文件改坏了 | 没备份；下次 `-i.bak`，或先不带 `-i` 预览输出 |
| `awk` 取不到想要的列 | 分隔符不对，默认是连续空白；CSV 之类用 `-F,` |
| `chmod 644` 之后还是 777 | 文件在 `/mnt/c` 等 Windows 挂载盘上，DrvFS 不支持 POSIX 权限，挪到 Linux 原生目录再改 |
| `变量=值` 报 command not found | 赋值两边写了空格：`name=ctf` 中间不能有空格 |
