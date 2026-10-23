---
chapter: 逆向工程
section: 代码混淆：花指令与 OLLVM
order: 211
tags:
  - CTF
  - 逆向工程
  - RE
  - 混淆
publish: true
---

# R11 代码混淆：花指令与 OLLVM
## Code Obfuscation: Junk Code & OLLVM

> [!info]- 章节信息
> **所属方向**：逆向工程 ｜ **难度阶段**：L3 进阶专题期 ｜ **前置要求**：[[R09-加壳与脱壳|R09]] · [[R06-动态调试GDB与x64dbg|R06]] · [[R03-x86与x64汇编精要复习|R03]]
> **本章目标**：认全五类常见花指令并写出批量清理脚本；能用纯 C 构造控制流平坦化结构，在反汇编里认出它，并用动态 trace 恢复真实执行顺序；能识别不透明谓词与 MBA 恒等式替换这两类 OLLVM 标志性产物；会用 D810 等去混淆工具；拿到混淆程序时能判断"静态强解还是转动态"。

## 1. 混淆的坐标：四层手段与 OLLVM

混淆（obfuscation）：不改变程序行为，只改变程序形态，让静态分析读不懂。它与壳的分工一句话说清：==壳把代码藏起来，混淆把代码变难看==。[[R09-加壳与脱壳#6. 花指令初步|R09 第 6 节]]讲过的花指令是最初级的一种——几字节垃圾加一条跳转，让线性反汇编错位；壳的 stub 里也常用它（[[R09-加壳与脱壳#6.1 是什么|R09 6.1]]）。本章把混淆按"动的是哪一层"排成四层，逐层展开：

| 层级 | 手段 | 对静态分析的破坏 | 本章位置 |
| ---- | ---- | ---- | ---- |
| 汇编层 | 花指令：垃圾字节 + 跳转 | 反汇编错位、伪代码残缺 | [[#2. 花指令模式族：五种常见形态\|第 2 节]]、[[#3. 实战：手写花指令程序与批量清理脚本\|第 3 节]] |
| 控制流层 | 控制流平坦化（CFF） | 函数结构打散成一堆等价块 | [[#4. 控制流平坦化：手工构造与识别\|第 4 节]]、[[#5. 去平坦化：动态 trace 状态变量\|第 5 节]] |
| 控制流层 | 虚假控制流（BCF）+ 不透明谓词 | 插入大量静态无法排除的假分支 | [[#6. 不透明谓词与虚假控制流\|第 6 节]] |
| 指令层 | 指令替换 / MBA | 一条指令变成一串位运算 | [[#7. 指令替换与 MBA\|第 7 节]] |
| 代码虚拟化 | 自定义虚拟机指令集 | 连"指令是什么"都不认识 | [[R12-虚拟机保护VM逆向\|R12]] 专门展开 |

**OLLVM** 是这套手段的代名词：obfuscator-llvm 项目（GitHub 开源，基于 LLVM 的混淆分支）把三道变换做成了编译器 pass——控制流平坦化（FLA，Flattening）、虚假控制流（BCF，Bogus Control Flow）、指令替换（SUB，Substitution），三道变换共同依赖[[#6. 不透明谓词与虚假控制流|不透明谓词]]。赛题里说"这题上了 OLLVM"，指的就是产物带这三种痕迹。

> [!note] 本章立场：手工构造等价结构，不装编译器
> 本章不依赖 OLLVM 编译器：三道变换的原理，各用一段普通 gcc 就能编译的 C（或 nasm 汇编）构造出**形态一致**的等价结构，每一处都注明"OLLVM 自动生成的形态与此一致"。区别只有一处——==OLLVM 的变换发生在编译管线内部，先优化、再混淆，产物不会被 -O2 拉直==；手工版会被拉直，[[#4.5 一个诚实的观察：-O2 会拉直手工平坦化|4.5 节]]专门对照。学会手工构造，再去看真实 OLLVM 样本时，识别与去混淆方法原样适用（[[#11. 配套练习与延伸阅读|第 11 节]]给实战指引）。

## 2. 花指令模式族：五种常见形态

[[R09-加壳与脱壳#6. 花指令初步|R09 第 6 节]]已经讲过：花指令的原理是"真执行流走跳转、垃圾字节轮不到被执行，而线性反汇编不执行跳转、按地址顺序硬解"，并在 6.2 节给了 **0xE8 假 call** 的完整例子与 nop 清理。本节把模式族讲全，每种给出字节形状；下一节把"逐个手工 nop"升级成批量清理脚本。以下汇编块均为本章示例程序（[[#3.1 靶子：nasm 手写的花指令 ELF|3.1 节]]）的真实片段，x86-64 Linux / Intel 语法。

### 2.1 模式一：0xE8 假 call

```asm
; x86-64 Linux · Intel 语法（objdump 输出，带符号时的形态）
  401000:	eb 01            jmp    401003
  401002:	e8               .byte 0xe8     ; 垃圾：call 的操作码
  401003:	b8 01 00 00 00   mov    eax,0x1 ; 真实代码
```

`jmp` 跨过 1 个字节；这 1 字节取 `0xE8`。线性反汇编读到它时，把 `e8` 与**后面 4 字节的真实指令**并成一条 5 字节的假 call，目标地址按 4 字节随机位移算出——荒谬目标（R09 6.2 的对照表就是这一种）。

### 2.2 模式二：jz/jnz 互补对跳

```asm
; x86-64 Linux · Intel 语法（objdump 输出）
  40101b:	74 03   je     401020    ; 条件成立：跳过垃圾
  40101d:	75 01   jne    401020    ; 条件不成立：也跳过去，目标相同
  40101f:	e9      .byte 0xe9      ; 垃圾：jmp rel32 的操作码
  401020:	b8 01 00 00 00  mov eax,0x1
```

`je` 与 `jne` 条件互补，无论标志位是什么，==两条里必有一条成立==，两条目标又相同——真实执行永远到不了 40101f，垃圾字节横在静态反汇编的必经之路上。这里的垃圾取 `0xE9`（jmp rel32 操作码），线性解码把它和后面 4 字节并成一条 `jmp 0x4011dc`。识别特征：==相邻两条跳转目标相同且条件互补==。jz/jnz 可以换成 jz/jns、jc/jnc 等任意互补对。

### 2.3 模式三：永真条件跳转

```asm
; x86-64 Linux · Intel 语法（objdump 输出）
  401038:	31 c0   xor    eax,eax   ; 结果为 0，ZF=1
  40103a:	74 01   je     40103d    ; 必跳
  40103c:	f0      .byte 0xf0      ; 垃圾：lock 前缀
  40103d:	b8 01 00 00 00  mov eax,0x1
```

只用一条跳转，"必跳"靠**前面的指令把标志位定死**：`xor eax,eax` 结果为 0，ZF=1，`je` 永远成立。与互补对跳的区别在隐蔽性：互补对跳扫一眼跳转就能认出，永真跳转要沿数据流推一遍标志位才能确定——单看 `je` 本身没有任何问题。定标志的写法一族：`xor eax,eax`、`sub eax,eax`、`cmp` 一个恒成立比较、`test` 已知值等，jcc 也可换成 js/jo 等其他单标志跳转（[[R03-x86与x64汇编精要复习#4. 条件跳转：jcc 家族|R03 第 4 节]]的标志表是判断依据）。

### 2.4 模式四：无效前缀

垃圾字节不一定是操作码，也可以是**前缀**。`0xF0` 是 lock 前缀，合法位置只有"读-改-写"内存指令（`add DWORD PTR [mem],reg` 一族）之前；跟在 `mov` 立即数之前就是畸形序列。上例里它被模式三保护着，线性解码给出的显示是 `lock mov eax,0x1`——objdump 容忍这种组合照常打印，IDA 会标红。段前缀（`2e`/`3e`/`64`/`65`）、操作数宽度前缀 `66` 当垃圾同理。识别特征：==前缀出现在不该出现的位置==，或前缀后跟一条不可能带该前缀的指令。

### 2.5 模式五：jmp 穿越数据块与自修改代码

```asm
; x86-64 Linux · Intel 语法（objdump 输出）
  401055:	eb 05   jmp    40105c
  401057:	27      (bad)            ; 5 字节数据
  401058:	37      (bad)
  401059:	06      (bad)
  40105a:	2f      (bad)
  40105b:	d7      xlat  BYTE PTR [rbx]
  40105c:	b8 3c 00 00 00  mov eax,0x3c
```

`jmp` 跨过 5 字节数据。线性解码把数据当代码硬解：`27`/`37`/`06`/`2f` 在 64 位模式是非法操作码，objdump 直接报 `(bad)`（无法识别）；`d7` 恰好是合法的 xlat，被解成一条带隐式 rbx 的指令。数据换成任意字节都行——==垃圾不需要"长得像指令"，解乱就行==。

更进一步是**自修改代码**：运行时把数据区改写成指令再执行（ELF 配 `mprotect` 改页权限，PE 配 `VirtualProtect`），静态反汇编读到的永远不是运行时执行的形态。[[R09-加壳与脱壳#6.5 更多花指令模式|R09 6.5]]的折叠框提过它，属于混淆器与壳 stub 的进阶手段，手工对抗需动态调试；本章实战用"jmp 穿越数据块"这个静态表亲。

### 2.6 识别信号

[[R09-加壳与脱壳#6.3 识别|R09 6.3]]给过三条信号，本节扩充成五条，命中其一就该怀疑花指令：

1. **错位与 (bad)**：反汇编出现吞并后续字节的指令（假 call/假 jmp）、`(bad)`、目标落在代码节之外的 call/jmp；
2. **前缀错位**：lock、段前缀出现在无意义位置；
3. **执行流对不上**：[[R06-动态调试GDB与x64dbg|R06]]单步走一遍，凡真执行流没经过的"指令"都可疑；
4. **IDA 红块**：图形视图出现灰色/红色不可分析块、函数边界识别失败、F5 报错或缺代码（[[R05-静态分析工具链IDA与Ghidra#3.7 F5 伪代码：能力与局限|R05 3.7]]的 sp-analysis failed 常由它引起）；
5. **反常但合法的模式**：相邻互补跳转、明显永真的标志组合、同一字节序列反复出现在函数开头。

> [!warning] 带符号的 objdump 会掩盖错位
> objdump 在每个符号处重新开始解码。本章示例用 nasm 手写，局部标签（`.p1_real` 等）成了符号表条目，垃圾字节与真实代码之间正好隔着符号，objdump 便把垃圾单独显示成 `.byte 0xe8`、错位没有扩散——[[#3.2 构建与两种反汇编视图|3.2 节]]有前后对比。真实赛题程序是 stripped 的，或垃圾字节藏在函数内部（[[R09-加壳与脱壳#6.2 一个带花指令的程序|R09 6.2]]正是如此），没有这层保护，错位会一路延伸到恰好重新对齐为止。==看花指令要 strip 后看，或直接进 IDA==。

## 3. 实战：手写花指令程序与批量清理脚本

本节完整走一遍"构造 → 观察 → 模式匹配 → 定位 → patch → 复核"的批量清理流程。靶子用 nasm 手写，四种花指令模式各保护一段真实代码。

### 3.1 靶子：nasm 手写的花指令 ELF

```nasm
; junk_demo.asm —— 花指令演示 · x86-64 Linux（freestanding，直接系统调用，无 libc）
BITS 64

section .rodata
msg1:   db "step1", 10
len1    equ $ - msg1
msg2:   db "step2", 10
len2    equ $ - msg2
msg3:   db "step3", 10
len3    equ $ - msg3

section .text
global _start

_start:
    ; ---- 模式一：jmp 跨过一个 0xE8 ----
    jmp .p1_real
    db 0xE8
.p1_real:
    mov eax, 1              ; sys_write
    mov edi, 1
    lea rsi, [rel msg1]
    mov edx, len1
    syscall

    ; ---- 模式二：jz/jnz 互补对跳 ----
    jz .p2_real
    jnz .p2_real
    db 0xE9
.p2_real:
    mov eax, 1
    mov edi, 1
    lea rsi, [rel msg2]
    mov edx, len2
    syscall

    ; ---- 模式三：永真条件跳转 ----
    xor eax, eax            ; ZF=1，jz 必跳
    jz .p3_real
    db 0xF0                 ; 无效前缀
.p3_real:
    mov eax, 1
    mov edi, 1
    lea rsi, [rel msg3]
    mov edx, len3
    syscall

    ; ---- 模式四：jmp 穿越数据块 ----
    jmp .p4_real
    db 0x27, 0x37, 0x06, 0x2F, 0xD7
.p4_real:
    mov eax, 60             ; sys_exit
    xor edi, edi
    syscall
```

程序逻辑极简：三次 write 打印 step1/step2/step3，然后 exit(0)。汇编标注：x86-64 Linux，直接走系统调用（rax=1 为 write、rax=60 为 exit），参数按 System V AMD64 ABI 顺序放 rdi/rsi/rdx。构建并运行：

```bash
nasm -f elf64 junk_demo.asm -o junk_demo.o
ld -o junk_demo junk_demo.o
./junk_demo
```

输出：

```
step1
step2
step3
```

程序行为完全正常——花指令不改变执行，只改变反汇编视图（[[R09-加壳与脱壳#6.2 一个带花指令的程序|R09 6.2]]的结论）。

### 3.2 构建与两种反汇编视图

先看带符号时的 objdump（只看模式一附近）：

```bash
objdump -d -M intel junk_demo | sed -n '/<_start>:/,/^$/p' | head -5
```

输出：

```
0000000000401000 <_start>:
  401000:	eb 01           	jmp    401003 <_start.p1_real>
  401002:	e8              	.byte 0xe8
```

垃圾字节被隔离成一行 `.byte 0xe8`——[[#2.6 识别信号|2.6 节]]warning 说的符号同步现象。strip 掉符号再看，这才是赛题程序的常态：

```bash
strip junk_demo
objdump -d -M intel junk_demo | sed -n '/Disassembly of section .text:/,$p'
```

输出：

```
Disassembly of section .text:

0000000000401000 <.text>:
  401000:	eb 01                	jmp    0x401003
  401002:	e8 b8 01 00 00       	call   0x4011bf
  401007:	00 bf 01 00 00 00    	add    BYTE PTR [rdi+0x1],bh
  40100d:	48 8d 35 ec 0f 00 00 	lea    rsi,[rip+0xfec]        # 0x402000
  401014:	ba 06 00 00 00       	mov    edx,0x6
  401019:	0f 05                	syscall
  40101b:	74 03                	je     0x401020
  40101d:	75 01                	jne    0x401020
  40101f:	e9 b8 01 00 00       	jmp    0x4011dc
  401024:	00 bf 01 00 00 00    	add    BYTE PTR [rdi+0x1],bh
  40102a:	48 8d 35 d5 0f 00 00 	lea    rsi,[rip+0xfd5]        # 0x402006
  401031:	ba 06 00 00 00       	mov    edx,0x6
  401036:	0f 05                	syscall
  401038:	31 c0                	xor    eax,eax
  40103a:	74 01                	je     0x40103d
  40103c:	f0 b8 01 00 00 00    	lock mov eax,0x1
  401042:	bf 01 00 00 00       	mov    edi,0x1
  401047:	48 8d 35 be 0f 00 00 	lea    rsi,[rip+0xfbe]        # 0x40200c
  40104e:	ba 06 00 00 00       	mov    edx,0x6
  401053:	0f 05                	syscall
  401055:	eb 05                	jmp    0x40105c
  401057:	27                   	(bad)
  401058:	37                   	(bad)
  401059:	06                   	(bad)
  40105a:	2f                   	(bad)
  40105b:	d7                   	xlat   BYTE PTR [rbx]
  40105c:	b8 3c 00 00 00       	mov    eax,0x3c
  401061:	31 ff                	xor    edi,edi
  401063:	0f 05                	syscall
```

六行假指令，逐行对照（真实指令按源码核对）：

| objdump 显示 | 实际是什么 |
| ---- | ---- |
| `401002: call 0x4011bf` | 假 call：垃圾 `e8` 吞掉 `mov eax,1`（`b8 01 00 00`）当 4 字节位移。0x4011bf 远在本程序代码之外——全部真实代码到 0x401066 为止 |
| `401007: add BYTE PTR [rdi+0x1],bh` | 错位残余：真实指令 `mov eax,1` 只剩首字节 `00`，与 `mov edi,1` 的 `bf 01 00 00 00` 拼成一条 6 字节假指令 |
| `40101f: jmp 0x4011dc` | 假 jmp：垃圾 `e9`（互补对跳的垃圾）吞掉后 4 字节当 rel32 |
| `401024: add BYTE PTR [rdi+0x1],bh` | 同样的错位残余，模式二版 |
| `40103c: lock mov eax,0x1` | 永真跳的垃圾 `f0`（lock 前缀）挂在 `mov` 立即数前——2.4 说的无效前缀 |
| `401057–40105a: (bad)` × 4 | 穿越的数据块被硬解：64 位模式的非法操作码；`d7` 恰好合法，解成 xlat |

注意错位的"寿命"：三处错位各吞掉一条指令后，恰好都在真实指令边界上重新对齐——`add` 那条 6 字节假指令的末尾正是下一条真实 `lea` 的开头。==错位延伸多远取决于垃圾字节与后续真实指令的长度组合==，可能两条就重对齐，也可能一路乱到函数尾；IDA 的线性分析同样如此，多处错位叠加会让函数边界识别失败。

### 3.3 清理脚本：模式匹配 → 定位 → patch → 复核

思路与 [[R09-加壳与脱壳#6.4 清理：nop 填充|R09 6.4]]相同：垃圾字节改成 `0x90`（nop，单字节无副作用），前提是确认它不在真执行流上。升级点在批量：把每种模式的**完整字节签名**写进脚本，一个文件里有多少处就清多少处。

```python
#!/usr/bin/env python3
"""clean_junk.py —— 花指令批量清理：模式匹配 → 定位 → patch → 复核
用法：python3 clean_junk.py 输入文件 输出文件
按完整字节签名匹配已知的花指令模式，垃圾字节全部改写成 0x90（nop）。
"""
import sys

src = open(sys.argv[1], "rb").read()

# (完整签名, 垃圾字节在签名内的偏移列表, 模式名)
patterns = [
    (bytes.fromhex("eb01e8"),        [2],           "jmp 跨 0xE8（假 call）"),
    (bytes.fromhex("74037501e9"),    [4],           "jz/jnz 互补对跳"),
    (bytes.fromhex("31c07401f0"),    [4],           "xor eax,eax + jz 永真跳"),
    (bytes.fromhex("eb052737062fd7"), [2, 3, 4, 5, 6], "jmp 穿越数据块"),
]

out = bytearray(src)
patched = 0
for sig, offs, name in patterns:
    start = 0
    while True:
        i = out.find(sig, start)
        if i < 0:
            break
        print(f"[+] {name}: 签名在文件偏移 0x{i:x}，垃圾字节:", end=" ")
        for off in offs:
            print(f"0x{i + off:x}(0x{out[i + off]:02x})", end=" ")
            out[i + off] = 0x90
            patched += 1
        print()
        start = i + 1

open(sys.argv[2], "wb").write(out)
print(f"[*] 共改写 {patched} 个垃圾字节 -> {sys.argv[2]}")
```

四条签名各对应一节的一个模式，垃圾字节在签名内的偏移由模式结构决定。以互补对跳 `74 03 75 01 e9` 为例：`je` 在签名偏移 0–1、`jne` 在 2–3、垃圾 `e9` 在偏移 4，两条跳转的目标都是签名之后第 0 字节——`je` 从偏移 2 起跳 3 字节、`jne` 从偏移 4 起跳 1 字节，落到同一点。

```bash
python3 clean_junk.py junk_demo junk_demo_clean
chmod +x junk_demo_clean
```

输出：

```
[+] jmp 跨 0xE8（假 call）: 签名在文件偏移 0x1000，垃圾字节: 0x1002(0xe8)
[+] jz/jnz 互补对跳: 签名在文件偏移 0x101b，垃圾字节: 0x101f(0xe9)
[+] xor eax,eax + jz 永真跳: 签名在文件偏移 0x1038，垃圾字节: 0x103c(0xf0)
[+] jmp 穿越数据块: 签名在文件偏移 0x1055，垃圾字节: 0x1057(0x27) 0x1058(0x37) 0x1059(0x06) 0x105a(0x2f) 0x105b(0xd7)
[*] 共改写 8 个垃圾字节 -> junk_demo_clean
```

文件偏移与虚拟地址的换算沿用 [[R04-可执行文件格式ELF与PE|R04]]式 (4.1)：本例 .text 的虚拟地址 0x401000 对应文件偏移 0x1000，偏移 0x1002 即地址 0x401002，与 3.2 输出里的假 call 位置一致。`chmod +x` 是因为 Python 写出的新文件没有可执行位。

> [!info]- 为什么用完整签名匹配
> 只匹配 `eb 01` 两字节就 patch，可能误伤：真实指令的字节序列里也可能出现 `eb 01`，改错了程序就坏。完整签名（模式结构 + 垃圾字节取值）把误伤概率压到接近零。代价是签名表只认见过的写法——垃圾字节换一个值、跳转距离变一变，就要扩表。==脚本只能负责已知模式==：认不全时回到逐个分析（动态单步确认执行流 → 手工 nop），人工兜底未知的。

### 3.4 清理结果复核

```bash
objdump -d -M intel junk_demo_clean | sed -n '/Disassembly of section .text:/,$p'
```

输出：

```
Disassembly of section .text:

0000000000401000 <.text>:
  401000:	eb 01                	jmp    0x401003
  401002:	90                   	nop
  401003:	b8 01 00 00 00       	mov    eax,0x1
  401008:	bf 01 00 00 00       	mov    edi,0x1
  40100d:	48 8d 35 ec 0f 00 00 	lea    rsi,[rip+0xfec]        # 0x402000
  401014:	ba 06 00 00 00       	mov    edx,0x6
  401019:	0f 05                	syscall
  40101b:	74 03                	je     0x401020
  40101d:	75 01                	jne    0x401020
  40101f:	90                   	nop
  401020:	b8 01 00 00 00       	mov    eax,0x1
  401025:	bf 01 00 00 00       	mov    edi,0x1
  40102a:	48 8d 35 d5 0f 00 00 	lea    rsi,[rip+0xfd5]        # 0x402006
  401031:	ba 06 00 00 00       	mov    edx,0x6
  401036:	0f 05                	syscall
  401038:	31 c0                	xor    eax,eax
  40103a:	74 01                	je     0x40103d
  40103c:	90                   	nop
  40103d:	b8 01 00 00 00       	mov    eax,0x1
  401042:	bf 01 00 00 00       	mov    edi,0x1
  401047:	48 8d 35 be 0f 00 00 	lea    rsi,[rip+0xfbe]        # 0x40200c
  40104e:	ba 06 00 00 00       	mov    edx,0x6
  401053:	0f 05                	syscall
  401055:	eb 05                	jmp    0x40105c
  401057:	90                   	nop
  401058:	90                   	nop
  401059:	90                   	nop
  40105a:	90                   	nop
  40105b:	90                   	nop
  40105c:	b8 3c 00 00 00       	mov    eax,0x3c
  401061:	31 ff                	xor    edi,edi
  401063:	0f 05                	syscall
```

六行假指令全部消失，线性反汇编与真实执行流完全一致。剩余的 `jmp`/`je`/`jne` 是花指令剩下的跳转指令——真执行流本来就经过它们，跳过的只是几个 nop，不必清理。运行复核：

```bash
./junk_demo_clean
```

输出：

```
step1
step2
step3
```

> [!warning] patch 是改文件，改前先确认执行流
> 与 [[R09-加壳与脱壳#6.4 清理：nop 填充|R09 6.4]]同一原则：动手前用动态单步把执行流走一遍，确认目标字节"只有反汇编会读、运行不会执行"；改完立刻运行对比行为。批量脚本更要把每处命中打印出来人工过目。

## 4. 控制流平坦化：手工构造与识别

### 4.1 原理：一个状态变量打散整个函数

控制流平坦化（Control Flow Flattening，OLLVM 的 FLA pass）把函数的正常结构（顺序、分支、循环）全部拆掉，改造成这样的等价形式：

```c
/* 语义示意 */
state = 初始块号;
while (1) {
    switch (state) {
    case 块A: <原来 A 块的语句>; state = 后继块号; break;
    case 块B: <原来 B 块的语句>; state = 后继块号; break;
    ...
    }
}
```

三个零件：**状态变量**记录"下一步执行哪个块"；**外层死循环**每圈把控制权交回 `switch`；**分发器**（switch）按状态变量跳到对应块。每个真实块的末尾不再顺序执行、也不直接跳到后继，而是**给状态变量赋后继块号**，然后回到分发器。顺序变成"赋值"，分支变成"赋不同的值"，循环变成"把状态赋回自己"——==控制流被编码进数据（状态变量的取值序列）里==，静态读代码只能看到一堆平铺的块，看不出谁先谁后。

OLLVM 的 FLA 在 LLVM IR 上自动完成这件事：给每个基本块分配一个随机块号（所以块号不连续、无规律），生成同样的 dispatcher 结构。下一节手工构造一个形态一致的版本。

### 4.2 手工 demo：纯 C 的平坦化函数

```c
/* cff.c —— 手工控制流平坦化 demo（check_flat 与 check_plain 计算等价） */
#include <stdio.h>

/* 状态常量故意取不连续的值，模仿混淆器给基本块分配的随机块号 */
enum {
    B_INIT = 0x2F51,
    B_LOOP = 0x7A3C,
    B_CMP  = 0x4D07,
    B_END  = 0x91B6
};

static int check_plain(int x)            /* 原始逻辑：三条语句 */
{
    int y = x * 3 + 7;
    for (int i = 0; i < 3; i++)
        y = (y + i) ^ 0x5A;
    return y == 0x133;
}

static unsigned state;                   /* 状态变量：平坦化的枢纽 */

static int check_flat(int x)
{
    int y = 0, i = 0, r = 0;
    state = B_INIT;
    while (1) {
        switch (state) {
        case B_INIT:
            y = x * 3 + 7;
            i = 0;
            state = B_LOOP;
            break;
        case B_LOOP:
            if (i < 3) {
                y = (y + i) ^ 0x5A;
                i++;
                state = B_LOOP;          /* 回到同一状态：循环变成自环 */
            } else {
                state = B_CMP;
            }
            break;
        case B_CMP:
            r = (y == 0x133);
            state = B_END;
            break;
        case B_END:
            return r;
        }
    }
}

int main(void)
{
    printf("plain(117)=%d flat(117)=%d flat(118)=%d\n",
           check_plain(117), check_flat(117), check_flat(118));
    return 0;
}
```

`check_plain` 是原始逻辑；`check_flat` 把它拆成 4 个块（INIT 计算、LOOP 循环体、CMP 比较、END 返回），块号 `0x2F51`、`0x7A3C`、`0x4D07`、`0x91B6` 故意不连续。运行确认两者等价：

```bash
gcc -O0 -g -fno-pie -no-pie cff.c -o cff
./cff
```

输出：

```
plain(117)=1 flat(117)=1 flat(118)=0
```

### 4.3 分发器的反汇编形态

```bash
objdump -d -M intel cff | awk '/<check_flat>:/,/^$/' | head -70
```

输出（x86-64 Linux / System V AMD64 ABI，objdump -d -M intel）：

```asm
0000000000401180 <check_flat>:
  401180:	f3 0f 1e fa          	endbr64
  401184:	55                   	push   rbp
  401185:	48 89 e5             	mov    rbp,rsp
  401188:	89 7d ec             	mov    DWORD PTR [rbp-0x14],edi
  40118b:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
  401192:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
  401199:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  4011a0:	c7 05 72 2e 00 00 51 	mov    DWORD PTR [rip+0x2e72],0x2f51        # 40401c <state>
  4011a7:	2f 00 00 
  4011aa:	8b 05 6c 2e 00 00    	mov    eax,DWORD PTR [rip+0x2e6c]        # 40401c <state>
  4011b0:	3d b6 91 00 00       	cmp    eax,0x91b6
  4011b5:	0f 84 93 00 00 00    	je     40124e <check_flat+0xce>
  4011bb:	3d b6 91 00 00       	cmp    eax,0x91b6
  4011c0:	77 e8                	ja     4011aa <check_flat+0x2a>
  4011c2:	3d 3c 7a 00 00       	cmp    eax,0x7a3c
  4011c7:	74 39                	je     401202 <check_flat+0x82>
  4011c9:	3d 3c 7a 00 00       	cmp    eax,0x7a3c
  4011ce:	77 da                	ja     4011aa <check_flat+0x2a>
  4011d0:	3d 51 2f 00 00       	cmp    eax,0x2f51
  4011d5:	74 09                	je     4011e0 <check_flat+0x60>
  4011d7:	3d 07 4d 00 00       	cmp    eax,0x4d07
  4011dc:	74 54                	je     401232 <check_flat+0xb2>
  4011de:	eb ca                	jmp    4011aa <check_flat+0x2a>
  4011e0:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
  4011e3:	89 d0                	mov    eax,edx
  4011e5:	01 c0                	add    eax,eax
  4011e7:	01 d0                	add    eax,edx
  4011e9:	83 c0 07             	add    eax,0x7
  4011ec:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
  4011ef:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
  4011f6:	c7 05 1c 2e 00 00 3c 	mov    DWORD PTR [rip+0x2e1c],0x7a3c        # 40401c <state>
  4011fd:	7a 00 00 
  401200:	eb 51                	jmp    401253 <check_flat+0xd3>
  401202:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
  401206:	7f 1e                	jg     401226 <check_flat+0xa6>
  401208:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
  40120b:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
  40120e:	01 d0                	add    eax,edx
  401210:	83 f0 5a             	xor    eax,0x5a
  401213:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
  401216:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
  40121a:	c7 05 f8 2d 00 00 3c 	mov    DWORD PTR [rip+0x2df8],0x7a3c        # 40401c <state>
  401221:	7a 00 00 
  401224:	eb 2d                	jmp    401253 <check_flat+0xd3>
  401226:	c7 05 ec 2d 00 00 07 	mov    DWORD PTR [rip+0x2dec],0x4d07        # 40401c <state>
  40122d:	4d 00 00 
  401230:	eb 21                	jmp    401253 <check_flat+0xd3>
  401232:	81 7d f4 33 01 00 00 	cmp    DWORD PTR [rbp-0xc],0x133
  401239:	0f 94 c0             	sete   al
  40123c:	0f b6 c0             	movzx  eax,al
  40123f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
  401242:	c7 05 d0 2d 00 00 b6 	mov    DWORD PTR [rip+0x2dd0],0x91b6        # 40401c <state>
  401249:	91 00 00 
  40124c:	eb 05                	jmp    401253 <check_flat+0xd3>
  40124e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  401251:	eb 05                	jmp    401258 <check_flat+0xd8>
  401253:	e9 52 ff ff ff       	jmp    4011aa <check_flat+0x2a>
  401258:	5d                   	pop    rbp
  401259:	c3                   	ret
```

对照 4.1 的三个零件，每个都能指到具体指令：

- **分发器**在 4011aa：重读 `state`（`mov eax,[rip+…]`），然后一条**比较链**——`cmp eax,0x91b6; je`、`cmp eax,0x7a3c; je`、`cmp eax,0x2f51; je`、`cmp eax,0x4d07; je`。这是 gcc 把 switch 降级成的形态（状态常数不连续，生成不了跳转表）；中间夹的重复 `cmp`+`ja` 是范围检查，`jmp 4011aa` 收尾对应源码里省略的 default——不匹配就绕回循环头重读 state。
- **真实块**散落在比较链之后：4011e0 起是 INIT 块（`x*3+7` 编译成两次 `add eax,eax` 加一条 `add eax,0x7`，[[R03-x86与x64汇编精要复习#3.2 lea：算地址的指令|R03 3.2]]的乘法形状），401202 起是 LOOP 块，401232 起是 CMP 块。
- **每块尾部**都是同一个形状：`mov DWORD PTR [rip+…],块号`（给 state 赋后继）+ `jmp 401253`，而 401253 只有一条 `jmp 4011aa`——所有块的两跳汇成回到分发器的回边。

OLLVM 自动生成的形态与此一致：比较链换成跳转表或二分比较（块多时），块号随机化，真实块掺入[[#6. 不透明谓词与虚假控制流|BCF]]的假块。

### 4.4 识别特征

| 特征 | 在反汇编里看到什么 |
| ---- | ---- |
| 外层死循环 | 函数体内没有通向 ret 的正常结构，所有路径汇回同一个分发点（`jmp 4011aa`） |
| 大 switch 分发器 | 一长串 `cmp eax,大常数` + `je`，常数彼此无规律、不连续（0x2f51、0x7a3c、0x4d07、0x91b6） |
| 状态变量赋值 | 每个块尾部 `mov [state],常数` 后接跳回分发器的 jmp |
| 真实块号不连续 | 状态常数与块的执行顺序无关；地址顺序 ≠ 执行顺序 |

> [!note] IDA / Ghidra 里的形态
> 图形视图的形状在逆向社区有个俗称叫"鸡冠头"：分发器节点在下方居中，各真实块在上方排成一排，每个块都有一条边跳回分发器，整个函数图形看起来像一把竖起的鸡冠。函数图从"几条清晰的路径"变成"中心辐射的一团"。Ghidra 的 Function Graph 同样呈现这个形态。伪代码里则是一层 `while` 包一个大 `switch`，与 4.1 的源码示意同构。

### 4.5 一个诚实的观察：-O2 会拉直手工平坦化

```bash
gcc -O2 -fno-pie -no-pie cff.c -o cff_o2
objdump -d -M intel cff_o2 | awk '/<check_flat>:/,/^$/'
```

输出：

```asm
0000000000401180 <check_flat>:
  401180:	8d 44 7f 07          	lea    eax,[rdi+rdi*2+0x7]
  401184:	31 d2                	xor    edx,edx
  401186:	01 d0                	add    eax,edx
  401188:	83 c2 01             	add    edx,0x1
  40118b:	83 f0 5a             	xor    eax,0x5a
  40118e:	83 fa 03             	cmp    edx,0x3
  401191:	75 f3                	jne    401186 <check_flat+0x6>
  401193:	c7 05 7f 2e 00 00 b6 	mov    DWORD PTR [rip+0x2e7f],0x91b6        # 40401c <state>
  40119a:	91 00 00 
  40119d:	3d 33 01 00 00       	cmp    eax,0x133
  4011a2:	0f 94 c0             	sete   al
  4011a5:	0f b6 c0             	movzx  eax,al
  4011a8:	c3                   	ret
```

-O2 把整个状态机**拉直**了：循环恢复成普通回边（`jne 401186`），分发器消失，只剩最后一处对 `state` 的写（`mov [state],0x91b6`，因为 state 是全局变量、写必须保留）。这暴露了手工构造与真实 OLLVM 的本质差异：==手工版是"先优化管线的普通代码"，优化器看得见全貌就能拉直；OLLVM 的 FLA 是优化管线**之后**插入的变换==，产物不再被优化，平坦化形态保留到最终二进制。教学构造用 -O0 读结构没问题（结构与 OLLVM 产物形态一致），但==分析真实样本时不要期待优化器替你化简混淆==。

## 5. 去平坦化：动态 trace 状态变量

### 5.1 思路

平坦化把控制流编码成了状态变量的取值序列，而==运行时这个序列必然真实发生==。去平坦化的最短路径：在分发器处下断点，每次命中记录状态变量，跑一轮输入就得到**真实块执行顺序**；按这个顺序把各块的语句重新拼回直序代码，函数逻辑就还原了。全程用 [[R06-动态调试GDB与x64dbg|R06]]的基本功：断点 + 断点自动化（[[R06-动态调试GDB与x64dbg#5.3 continue 与断点自动化：commands|R06 5.3]]的 commands 语法）。

### 5.2 trace 状态变量

用 4.2 的 -O0 构建（带 -g，可以按行号下断点；27 行是 `switch (state)`，即分发点）。命令文件：

```bash
# trace.gdb —— 在分发点记录状态变量轨迹
break cff.c:27
commands
silent
printf "dispatcher: state=0x%x\n", state
continue
end
run
```

```bash
gdb -q -batch -x trace.gdb ./cff
```

输出：

```
Breakpoint 1 at 0x4011aa: file cff.c, line 27.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
dispatcher: state=0x2f51
dispatcher: state=0x7a3c
dispatcher: state=0x7a3c
dispatcher: state=0x7a3c
dispatcher: state=0x7a3c
dispatcher: state=0x4d07
dispatcher: state=0x91b6
dispatcher: state=0x2f51
dispatcher: state=0x7a3c
dispatcher: state=0x7a3c
dispatcher: state=0x7a3c
dispatcher: state=0x7a3c
dispatcher: state=0x4d07
dispatcher: state=0x91b6
plain(117)=1 flat(117)=1 flat(118)=0
[Inferior 1 (process 508) exited normally]
```

断点解析到 0x4011aa——正是 4.3 里分发器的第一条指令（重读 state 处）。main 调了两次 check_flat，所以轨迹循环了两遍；取一遍：

```
0x2f51 → 0x7a3c → 0x7a3c → 0x7a3c → 0x7a3c → 0x4d07 → 0x91b6
```

### 5.3 轨迹解读与重排

对照 4.2 的 case 常量，轨迹翻译成块序列：

```
INIT → LOOP → LOOP → LOOP → LOOP → CMP → END
```

四个 `0x7a3c` 就是循环：前三次命中时执行循环体（i = 0、1、2），第四次命中时 `i == 3` 走转出分支（对照 4.3 的 `cmp DWORD PTR [rbp-0x8],0x2; jg`）——==平坦化后循环不再是回边，而是"同一个状态出现多次"==，trace 轨迹里一眼可见。按块序列重排，得到的就是 `check_plain` 的语句顺序：`y = x*3+7` → 三轮 `y = (y+i)^0x5A` → `return y == 0x133`。重排的正确性由运行输出印证：`plain(117)=1 flat(117)=1 flat(118)=0`，两个函数等价。

> [!info]- 真实样本上的三个变通
> - **没有行号**：strip 过的二进制不能 `break cff.c:27`，改 `b *0x40xxxx`——地址从 objdump 或 IDA 里拿（分发器的特征见 [[#4.4 识别特征|4.4]]）。
> - **状态变量不落内存**：-O2 或 OLLVM 产物常把 state 缓在寄存器里，`printf "...", state` 打印不到。改在分发器首指令断点，打印对应寄存器（`printf "state=0x%x\n", $eax`）。
> - **状态常数被加密**：OLLVM 变种给块号套一层运算（如 `state = 后继 ^ 密钥`）。trace 记录的原始值序列照样反映转移关系——分发器结构在，去平坦化就仍然可行；想全自动重建控制流图，把状态转移当约束交给符号执行，[[R14-自动化分析angr与z3|R14]] 正是干这个的。

trace 得到执行序后，把伪代码里各 case 的语句按序重排、删掉 state 赋值和 `break`，就得到可读的等价代码。这一步可以手工做，也可以交给工具——[[#8. 去混淆工具：D810 与 Ghidra 侧生态|第 8 节]]。

## 6. 不透明谓词与虚假控制流

### 6.1 定义

不透明谓词（opaque predicate）：一个表达式，**值在运行期可以算出来，但静态上（读代码的人、反编译器、有时还包括优化器）无法轻易证明**。分三类：恒真、恒假、恒定值。它本身不破坏任何东西，价值在于当**分支条件**用——把 `if (永不成立)` 插进代码，静态分析必须认真对待这个分支（因为证明不了它假），假分支里的垃圾代码就成了有效干扰。OLLVM 的 BCF pass 把每个真实块克隆一份，入口插一个不透明谓词：真走原块（运行时永远如此），假走克隆块（静态无法排除）。识别特征：同一个谓词表达式在多个函数反复出现；成对的块内容相同或一块全是无用运算；谓词引用的变量从不影响程序结果。

### 6.2 手工 demo：一个 -O2 也消不掉的恒真式

经典恒真式：`(x * (x - 1)) % 2 == 0`。依据：x 与 x-1 是相邻整数，必然一奇一偶，乘积是偶数。从位运算看更本质：乘积的最低位 = x 的最低位 与 (x-1) 的最低位 之积，而这两个最低位必有一个是 0——==低位性质不受 32 位回绕影响==，所以这个恒真在无符号回绕语义下依然成立（混淆器工作的正是这个语义）。

```c
/* mba.c 节选 —— 不透明谓词与 MBA 恒等式检查 */
#include <stdio.h>

/* 不透明谓词：x 与 x-1 是相邻两整数，乘积必为偶数，表达式恒为真 */
int opaque_true(int x)
{
    return (x * (x - 1)) % 2 == 0;
}

int main(void)
{
    volatile int v = 0;                     /* volatile：强制运行期求值 */
    int bad = 0;
    for (int x = -1000; x <= 1000; x++) {
        v = x;
        if (!opaque_true(v))
            bad++;
    }
    printf("opaque_true counterexamples: %d\n", bad);
    return 0;
}
```

扫描 [-1000, 1000] 内全部整数（`volatile` 强制每次运行期求值，模拟"输入是运行期才知道的值"的真实处境）：

```bash
gcc -O0 -fno-pie -no-pie mba.c -o mba_o0
gcc -O2 -fno-pie -no-pie mba.c -o mba_o2
./mba_o0
./mba_o2
```

输出（两次运行相同）：

```
opaque_true counterexamples: 0
MBA mismatches: 0
```

零反例。再看 -O2 对 `opaque_true` 函数本身做了什么：

```bash
objdump -d -M intel mba_o2 | awk '/<opaque_true>:/,/^$/'
```

输出：

```asm
; x86-64 Linux · System V AMD64 ABI · Intel 语法
0000000000401260 <opaque_true>:
  401260:	f3 0f 1e fa          	endbr64
  401264:	8d 47 ff             	lea    eax,[rdi-0x1]
  401267:	0f af c7             	imul   eax,edi
  40126a:	f7 d0                	not    eax
  40126c:	83 e0 01             	and    eax,0x1
  40126f:	c3                   	ret
```

-O2 把 `%2 == 0` 改写成等价的 `~p & 1`（判最低位），乘法与判位仍然全部保留在运行期——==连 `return 1` 都没被化出来==。"相邻整数之积必偶"是数论推理，不在编译器的化简规则里。这就是"不透明"二字的分量：**人能证明，但要么费一番推导，要么根本想不到去证**。阅读伪代码时遇到莫名的 `% 2 == 0`、`((x|1)&1)==1` 一类条件，先别埋头手算，按恒真/恒假处理再动态确认。

> [!info]- 常见不透明谓词速查
>
> | 表达式 | 恒值 | 依据 |
> | ---- | ---- | ---- |
> | `(x * (x - 1)) % 2 == 0` | 真 | 相邻整数一奇一偶，乘积偶 |
> | `(x * (x + 1)) % 2 == 0` | 真 | 同上 |
> | `((x \| 1) & 1) == 1` | 真 | 与 1 按位或把最低位置 1 |
> | `(x & 1) == ((x + 2) & 1)` | 真 | 加 2 不改变奇偶 |
> | `y > 10 && 100 / y > 10` | 假 | y > 10 时 100 / y < 10（OLLVM 原论文使用的形式） |
>
> 构造思路：从低位（奇偶）性质、范围推理里找"显然恒定却不易静态证明"的表达式。OLLVM 的 BCF 每处插入的谓词从这一族里取，所以==同一个式子会在伪代码里反复出现==，这是识别 BCF 的第一信号。

### 6.3 BCF 的完整形态

把 6.2 的谓词接进控制流，BCF 的样子就是：

```c
/* 语义示意 —— BCF 克隆块 */
if ((x * (x - 1)) % 2 == 0) {
    /* 真实块：运行时永远走这里 */
    原逻辑();
} else {
    /* 克隆块：静态无法排除，内容是原块的复制品或无用运算 */
    垃圾运算();
}
```

静态读代码的人看到的是"两块都可能执行"，必须两块都分析；反编译器会把两块的语句都揉进伪代码，伪代码体积成倍膨胀。对付它的顺序：先认出谓词（反复出现是信号）→ 确认恒值（推导或动态）→ 按"谓词为真"折叠掉假分支。D810 之类的工具把"认 + 折"做成了自动化（[[#8. 去混淆工具：D810 与 Ghidra 侧生态|第 8 节]]）。

## 7. 指令替换与 MBA

### 7.1 原理

指令替换（Substitution，OLLVM 的 SUB pass）：把一条简单指令换成**功能等价的一组位运算**。等价关系来自混合布尔算术（Mixed Boolean-Arithmetic，MBA）——把算术运算（加减乘）和位运算（与或非异或）混在同一个恒等式里。一条 `add` 换成三四条位运算，一层不够就嵌套两层三层，人读伪代码时每行都变成位运算表达式串。

### 7.2 恒等式速查表

八条高频恒等式，全部用无符号回绕语义（回绕安全）：

$$a + b = (a \oplus b) + 2\,(a \& b) \tag{11.1}$$

$$a - b = (a \oplus b) - 2\,(\sim a \& b) \tag{11.2}$$

$$a \oplus b = (a | b) - (a \& b) \tag{11.3}$$

$$a \oplus b = (a \& \sim b) | (\sim a \& b) \tag{11.4}$$

$$a | b = (a \& b) + (a \oplus b) \tag{11.5}$$

$$\sim a = -a - 1 \qquad (-a = \sim a + 1) \tag{11.6}$$

$$a + 1 = -\sim a \tag{11.7}$$

$$a \& b = \bigl((a + b) - (a \oplus b)\bigr) / 2 \tag{11.8}$$

> [!info]- (11.1) 的来历：竖式加法
> 按位看加法：每一位上，本位结果 = 两个 bit 的异或（相同为 0、不同为 1），进位 = 两个 bit 的与（都为 1 才进位）。所以 a+b = "无进位的和" + "进位的两倍" = $(a \oplus b) + 2(a \& b)$，这就是 (11.1)。其余各条都能由它和基本运算律推出：(11.5) 把 a|b 拆成"两处都为 1 的位（a&b）"加"恰有一处为 1 的位（a^b）"两块互不重叠的部分；(11.8) 是 (11.1) 的移项；(11.6) 是补码定义；(11.7) 由 (11.6) 代入 a+1 得到。逆向时见到异或、与、移位组合出的加减法，查这张表往回代。

### 7.3 demo：替换、等价性与 -O2 的态度

四条恒等式各写一个函数，与原生运算对拍（mba.c 的其余部分）：

```c
/* 四条 MBA 恒等式，全部用无符号 32 位运算（回绕安全） */
unsigned add_mba(unsigned a, unsigned b) { return (a ^ b) + 2 * (a & b); }
unsigned sub_mba(unsigned a, unsigned b) { return (a ^ b) - 2 * (~a & b); }
unsigned xor_mba(unsigned a, unsigned b) { return (a | b) - (a & b); }
unsigned neg_mba(unsigned a)             { return ~a + 1; }

int main(void)   /* mba.c 的对拍部分 */
{
    int mism = 0;
    for (unsigned a = 0; a < 1000; a++)
        for (unsigned b = 0; b < 1000; b++) {
            if (add_mba(a, b) != a + b)   mism++;
            if (sub_mba(a, b) != a - b)   mism++;
            if (xor_mba(a, b) != (a ^ b)) mism++;
            if (neg_mba(a) != 0u - a)     mism++;
        }
    printf("MBA mismatches: %d\n", mism);
    return 0;
}
```

百万组组合全部一致：

```bash
./mba_o0 && ./mba_o2
```

输出：

```
opaque_true counterexamples: 0
MBA mismatches: 0
opaque_true counterexamples: 0
MBA mismatches: 0
```

（mba.c 同时含第 6 节的谓词检查，所以每个二进制输出两行；-O0 与 -O2 结果相同。）再对比 -O0 与 -O2 对 `add_mba` 的翻译：

```bash
objdump -d -M intel mba_o0 | awk '/<add_mba>:/,/^$/'
```

输出（x86-64 Linux / System V AMD64 ABI）：

```asm
0000000000401159 <add_mba>:
  401159:	f3 0f 1e fa          	endbr64
  40115d:	55                   	push   rbp
  40115e:	48 89 e5             	mov    rbp,rsp
  401161:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
  401164:	89 75 f8             	mov    DWORD PTR [rbp-0x8],esi
  401167:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  40116a:	33 45 f8             	xor    eax,DWORD PTR [rbp-0x8]
  40116d:	89 c2                	mov    edx,eax
  40116f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  401172:	23 45 f8             	and    eax,DWORD PTR [rbp-0x8]
  401175:	01 c0                	add    eax,eax
  401177:	01 d0                	add    eax,edx
  401179:	5d                   	pop    rbp
  40117a:	c3                   	ret
```

```bash
objdump -d -M intel mba_o2 | awk '/<add_mba>:/,/^$/'
```

输出：

```asm
0000000000401270 <add_mba>:
  401270:	f3 0f 1e fa          	endbr64
  401274:	89 f8                	mov    eax,edi
  401276:	31 f7                	xor    edi,esi
  401278:	21 f0                	and    eax,esi
  40127a:	8d 04 47             	lea    eax,[rdi+rax*2]
  40127d:	c3                   	ret
```

-O2 只是合并了冗余搬运、把"乘 2 加"折进 lea——==恒等式 (11.1) 的异或形态原样保留，没有被化简回 `add`==。`sub_mba` 同理（`not`/`and`/`xor`/`add`/`sub` 全部保留）。但有一个例外值得专门看到：

```bash
objdump -d -M intel mba_o2 | awk '/<xor_mba>:/,/^$/'
```

输出：

```asm
00000000004012a0 <xor_mba>:
  4012a0:	f3 0f 1e fa          	endbr64
  4012a4:	89 f8                	mov    eax,edi
  4012a6:	31 f0                	xor    eax,esi
  4012a8:	c3                   	ret
```

恒等式 (11.3)（`(a|b) - (a&b)`）被 -O2 **直接化简成了 `xor`**——这一条在编译器的化简规则库里。结论两条：==不是所有替换都碰巧化不回去==，真实混淆器偏爱 (11.1)、(11.2) 一族的异或形式正因此；==单层替换挡不住嵌套==——OLLVM 的 SUB 会把替换结果再替换、掺进死代码，模式匹配逐层失效后，人读到的就是七八条位运算的一长串。

### 7.4 遇到 MBA 的化简策略

按成本从低到高三档：

1. **代数化简**：拿 7.2 的表从内向外往回代。见到 `2*(a&b)` 就联想到 (11.1) 的右半，另一半是 `a^b`，合并回去就是一次加法。适合一两层的替换。
2. **查表**：化简不动时，不猜公式——断点取几组输入输出对，或直接把函数当黑盒调用。位运算表达式再长，行为等价于一条指令，几组输入输出就能锁定它是 add/sub/xor 中的哪个。
3. **符号执行**：把表达式交给求解器与目标运算等价性比对，自动完成化简——[[R14-自动化分析angr与z3|R14]] 的标准应用场景之一。

判断标准与 [[R07-编码与算法识别还原|R07]] 认算法相同：==能认出"这一串等价于一条 add"就够了，不必逐位推演==。

## 8. 去混淆工具：D810 与 Ghidra 侧生态

手工构造 + 手工 trace 学的是原理；样本一大，重复劳动交给工具。

**D810**（IDA 插件）：工作在 Hex-Rays 的微码（microcode）层——伪代码生成前的中间表示。它内置一组规则，把不透明谓词化简成常量判断、按规则删掉假分支，对 OLLVM 的 BCF 与 SUB 效果直接体现在 F5 伪代码的干净程度上；对平坦化能恢复一部分，重度 FLA 仍要配合 [[#5. 去平坦化：动态 trace 状态变量|第 5 节]]的 trace。装法：IDA 9.0 起已官方收录（随 Hex-Rays 反编译器附带）；老版本从 GitHub 仓库（igogo-x86/D810，见延伸阅读）下载，把 `d810.py` 与 `d810` 目录拷进 IDA 的 `plugins` 目录，重启后 Edit → Plugins → D810 启动，选择规则集后照常 F5。

**Ghidra 侧**：没有与 D810 等价的现成插件，靠脚本生态补——Ghidra 的 P-Code 中间表示适合做表达式化简，社区维护着一批针对 OLLVM 的去平坦化脚本（[[R05-静态分析工具链IDA与Ghidra#4.4 脚本基础|R05 4.4]]讲过脚本怎么装怎么跑；搜关键词 `deflat`、`ollvm` 能找到主流实现）。思路与本章一致：识别分发器 → 收集状态转移 → 按真实顺序重建控制流。

> [!note] 与符号执行的分工
> 去平坦化、MBA 化简、不透明谓词判定，三件事都可以形式化成"约束求解"问题，angr 与 z3 是这套方法的标准载体——一句话带过，展开在 [[R14-自动化分析angr与z3|R14]]。

## 9. 静态强解还是转动态：成本判断

混淆不是每层都值得静态强解。判断依据是两类成本：静态强解 = 认模式、清垃圾、重排、化简的时间，随混淆强度指数上升；动态 = 下断点读中间值的时间，几乎不随混淆变——==混淆加高的是静态阅读成本，运行时该算的照样算，答案照样经过寄存器和内存==。

| 混淆形态 | 静态强解成本 | 动态成本 | 建议 |
| ---- | ---- | ---- | ---- |
| 花指令 | 低：签名清理几分钟（第 3 节） | —— | 清掉再静态读 |
| 轻度平坦化（状态明文） | 中：手工重排逐块抄 | 低：trace 一轮得执行序（第 5 节） | trace 去平坦化，伪代码恢复后静态读 |
| OLLVM 三件套叠加 | 高：BCF 膨胀 + MBA 嵌套 + FLA 打散 | 低：断点 + 观察点直接取中间值 | ==转向动态==：[[R06-动态调试GDB与x64dbg#10.2 四步流程：断点、回溯、finish、dump\|R06 四步流程]]原样适用 |
| 混淆与反调试叠加 | 还要先解反调试 | 中：先 patch 检测点 | 按 [[R10-反调试与反分析对抗\|R10]] 处理完检测点，再动态调试 |
| 虚拟机保护 | 极高：指令集不认识 | 视实现而定 | [[R12-虚拟机保护VM逆向\|R12]] 专门方法 |

==多数情况应转向动态==：目标通常是拿 flag 或看清一个关键判断，不是还原全函数。[[R06-动态调试GDB与x64dbg#11. 静态与动态怎么选|R06 第 11 节]]"静态读得懂就读，读不懂就断"在混淆场景下的推论：==读不懂先怀疑混淆，确认混淆后直接断==。静态手段仍然保留两个不可替代的用途：定位动态该断哪里（分发器地址、校验函数、比较点），以及动态拿到关键值之后回静态写清楚逻辑。[[R08-CrackMe经典题型|R08]]的题在无混淆时静态动态皆可，上了混淆后动态一侧的权重明显上升。

## 10. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 带符号时 objdump 看着干净，strip 后全是乱码 | objdump 在符号处重新对齐解码（[[#2.6 识别信号\|2.6]] 的 warning）；看花指令要 strip 后看，或直接进 IDA |
| 清理脚本 patch 后程序坏了 | 签名匹配误伤，改到真执行流上的字节；用完整签名匹配，patch 前打印每处命中人工过目（3.3 的 info 框） |
| 找不到已知花指令模式，但反汇编明显错乱 | 模式变体（垃圾字节换值、跳距变化）；回到逐个分析：动态单步确认执行流后手工 nop，脚本只负责已知模式 |
| IDA 函数识别失败 / F5 报 sp-analysis failed | 花指令干扰了函数边界（[[R05-静态分析工具链IDA与Ghidra#3.7 F5 伪代码：能力与局限\|R05 3.7]]）；在垃圾字节上 U（取消定义）再 C（转代码），必要时 P 重设函数 |
| 自己写的 CFF demo 被 -O2 拉直 | 手工版在优化管线内，优化器看得见全貌（4.5）；教学读结构用 -O0，不要期待优化器化简真实混淆 |
| gdb trace 断点不命中或打印不出 state | 行号断点要求 -g 且未 strip，否则按地址断；state 在寄存器里时打印对应寄存器（5.3 的 info 框） |
| trace 命中次数巨大，输出刷屏 | 大循环里的分发点每次都命中；加条件（`break ... if 计数`）采样，或只 trace 关键输入区间 |
| 伪代码里满屏同款怪条件（如 `% 2 == 0`） | 不透明谓词反复出现，BCF 的信号（6.3）；确认恒值后按永真/永假折叠假分支 |
| D810 启用后伪代码没变化 | 规则集未覆盖样本的谓词形式，或需要重新 F5；D810 覆盖不了所有变体，剩余部分按第 5、7 节手工 |
| MBA 表达式太长，代数化简推不动 | 改查表：断点取几组输入输出锁定等价运算（7.4）；或交给符号执行（R14） |
| 混淆程序一调试就退出 | 混淆与反调试叠加，先按 [[R10-反调试与反分析对抗\|R10]] 处理检测点再动态 |

## 11. 配套练习与延伸阅读

> [!note] 实战任务：分析 1–2 个 OLLVM 保护程序
> 平台指引：BUUCTF（buuoj.cn）与攻防世界（adworld.xctf.org.cn）的 reverse 分区里筛使用 OLLVM 的题目（特征：伪代码呈"鸡冠头"结构、满屏位运算表达式、同款怪条件反复出现）；GitHub 搜 `ollvm crackme`、`flattening` 也有现成样本。流程按本章顺序走一遍：IDA/Ghidra 确认形态（第 4 节）→ 断分发器 trace 状态变量恢复执行序（第 5 节）→ 谓词与 MBA 按第 6、7 节折叠化简，需要伪代码时上 D810（第 8 节）→ 静态卡住就转动态取中间值（第 9 节）。==目标是拿到 flag 或看清关键判断，不是还原出与源码一致的 C==。

配套练习：

1. 给 junk_demo.asm 再加一种花指令模式（例如把垃圾字节换成段前缀 `0x65`），扩展 clean_junk.py 的签名表，走一遍"观察错位 → 清理 → 复核"。
2. 把 cff.c 的 check_plain 换成 [[R08-CrackMe经典题型|R08]] 某道题的校验函数，手工做一遍平坦化 + trace 重排，体验"去平坦化前后伪代码可读性"的差距。
3. 用 6.2 的谓词给 check_flat 的每个 case 入口插一个假分支（BCF 手工版），再思考：trace 状态变量的方法受不受影响？（答案：不受——假分支不经过分发器赋值，轨迹里天然不出现。）

延伸阅读：

- obfuscator-llvm 项目仓库（OLLVM 原实现，三大 pass 的源码）：GitHub `obfuscator-llvm/obfuscator`
- 论文《Obfuscator-LLVM: Software Protection for the Masses》（Junod 等，2015）：三大变换的原始定义与设计动机
- D810 插件仓库与文档：GitHub `igogo-x86/D810`（规则集写法、微码级去混淆的深入材料）
- 虚拟机保护的下一步：[[R12-虚拟机保护VM逆向|R12]]；符号执行自动化：[[R14-自动化分析angr与z3|R14]]
