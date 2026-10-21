---
chapter: 逆向工程
section: 静态分析工具链：IDA Pro 与 Ghidra
order: 205
tags:
  - CTF
  - 逆向工程
  - RE
  - IDA
  - Ghidra
publish: true
---

# R05 静态分析工具链：IDA Pro 与 Ghidra
## Static Analysis Toolchain: IDA Pro & Ghidra

> [!info] 章节信息
> **所属方向**：逆向工程 ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[R03-x86与x64汇编精要复习|R03]] · [[R04-可执行文件格式ELF与PE|R04]]
> **本章目标**：能独立完成"字符串检索 → 定位校验函数 → 阅读伪代码 → 逆推 key"的静态分析流程；能用交叉引用回溯调用链；掌握 IDA 的视图、快捷键、伪代码修正与 FLIRT；掌握 Ghidra 的项目、窗口与脚本；能按场景在 IDA、Ghidra、radare2 之间选型。

## 1. 静态分析工具做什么

静态分析指不运行程序，直接分析文件内容。[[R03-x86与x64汇编精要复习|R03]]给出了读汇编的方法，[[R04-可执行文件格式ELF与PE|R04]]给出了认文件格式的知识；静态分析工具把两件事合到同一个界面里完成：载入文件 → 识别函数 → 反汇编 → 把汇编翻译成类 C 伪代码。objdump 只输出线性的文本流；工具在同样的反汇编结果上增加了函数边界识别、可点击的导航和伪代码。

三个核心能力：

| 能力 | 做的事 | 背后的知识 |
| ---- | ---- | ---- |
| 反汇编 | 字节 → 指令，划分函数边界，标注符号名 | [[R04-可执行文件格式ELF与PE\|R04]] 的节区与符号表 |
| 导航 | 字符串窗口、导入表、交叉引用，点击即跳转 | "这段数据被哪些指令引用" |
| 反编译 | 汇编 → 伪代码（IDA 的 F5 / Ghidra 的 Decompile） | [[R03-x86与x64汇编精要复习\|R03]] 的代码形状 |

工具完成定位与初步翻译后，剩下的核心工作是==读懂逻辑，推出变换，算出 key==。

本章第 2 节先用一条纯命令行流程完成"从拿到程序到求出 key"，第 3、4 节再看同样的步骤对应 GUI 工具里的哪些窗口和快捷键。先走一遍命令行，GUI 里每个窗口对应哪一步就清楚了。

## 2. 命令行最小分析流程

分析对象自己编译：一个典型的"变换比较型"crackme。程序读入 key，逐字节做变换后与常量表比较，全部相等时输出由 key 派生的 flag。flag 内容依赖输入，无法靠猜得到，只能逆推。

### 2.1 准备分析对象

```c
/* crackme.c —— 变换比较型 crackme 的最小骨架 */
#include <stdio.h>
#include <string.h>

static const unsigned char enc[8] = {
    0xD3, 0xE0, 0xDB, 0x05, 0xEE, 0xE9, 0x05, 0xDD   /* 常量表：校验用的 8 字节密文 */
};

int main(void) {
    unsigned char buf[24];
    printf("key: ");
    fflush(stdout);
    scanf("%23s", buf);
    if (strlen((char *)buf) != 8) {
        puts("flag{nice_try_but_fake}");              /* 诱饵：长度不对时的输出，不参与真实校验 */
        return 1;
    }
    for (int i = 0; i < 8; i++) {
        if ((unsigned char)((buf[i] ^ 0xAB) + 0x11) != enc[i]) {
            puts("nope, wrong key");
            return 1;
        }
    }
    printf("flag{%s_x0r_4dd}\n", buf);                /* flag 由正确的 key 派生 */
    return 0;
}
```

程序逻辑分三段：`scanf` 读入最多 23 字节到 `buf`；长度不是 8 时输出诱饵字符串 `flag{nice_try_but_fake}`；否则对每个字节执行 `(buf[i] ^ 0xAB) + 0x11`，与常量表 `enc[i]` 比较，8 个字节全部相等时输出 `flag{<key>_x0r_4dd}`。

```bash
gcc -O0 -fno-pie -no-pie crackme.c -o crackme
file crackme
```

输出：

```
crackme: ELF 64-bit LSB executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f8b062e7..., not stripped
```

这行输出确定了三件事：架构是 x86-64，[[R03-x86与x64汇编精要复习|R03]]的寄存器与调用约定按此对应；not stripped 表示符号表还在，函数有名字；dynamically linked 表示库函数经 PLT 跳转进动态库——反汇编里所有 `xxx@plt` 都是库函数调用，不是题目的逻辑（[[R04-可执行文件格式ELF与PE|R04]]讲过这条跳转链）。

### 2.2 strings：提取字符串线索

```bash
strings -t x crackme | grep -E "flag|key|nope"
```

输出：

```
   2010 key: 
   201b flag{nice_try_but_fake}
   2033 nope, wrong key
   2043 flag{%s_x0r_4dd}
```

`-t x` 同时打印字符串在文件中的偏移（十六进制）。四条线索：程序把输入称为 key；真实 flag 的形状是 `flag{key_尾巴}`；存在校验失败分支的提示 `nope, wrong key`；`flag{nice_try_but_fake}` 是诱饵字符串——它只在长度检查失败的分支输出，与真实校验无关。做题时先区分哪些字符串在真实校验路径上。==strings 给出的是线索，不是答案==：哪条字符串真的被校验逻辑引用，要看代码；校验用的常量表是二进制字节，strings 不显示。

### 2.3 objdump：定位 main 并读出校验逻辑

```bash
objdump -d -M intel crackme | sed -n '/<main>:/,/^$/p'
```

`sed` 截取 main 那一段（[[04-汇编语言精要|01 库 04 章]]的用法）。这个程序自定义函数只有 main，其余都是 `@plt` 库函数，关键逻辑必然在 main。主干如下（省略栈维护与 canary 等噪声指令，过滤方法见 [[04-汇编语言精要|04 章]] 9.2 的清单）：

```asm
  4011f1:  mov    edi,0x402010               ; "key: " 的地址 → 第 1 参数
  4011fb:  call   4010c0 <printf@plt>
  401216:  mov    edi,0x402016               ; "%23s"
  401220:  call   4010d0 <__isoc23_scanf@plt> ; 输入落进 [rbp-0x20]
  401231:  cmp    rax,0x8                    ; strlen 结果 != 8 ?
  401235:  je     401248
  401237:  mov    edi,0x40201b               ; 诱饵字符串地址
  40123c:  call   401090 <puts@plt>

  401248:  mov    DWORD PTR [rbp-0x24],0x0   ; i = 0
  40124f:  jmp    401286                     ; 先跳到判断条件（04 章的 for 循环形状）
  401251:  mov    eax,DWORD PTR [rbp-0x24]
  401254:  cdqe                              ; i 符号扩展进 rax
  401256:  movzx  eax,BYTE PTR [rbp+rax*1-0x20] ; eax = buf[i]
  40125b:  xor    eax,0xffffffab             ; ^ 0xAB（立即数符号扩展，低字节才是 0xAB）
  40125e:  lea    edx,[rax+0x11]             ; edx = 上一步 + 0x11（04 章：lea 也可用于算术）
  401261:  mov    eax,DWORD PTR [rbp-0x24]   ; 再取 i（edx 保留了变换结果）
  401264:  cdqe
  401266:  movzx  eax,BYTE PTR [rax+0x402008] ; eax = 常量表[i]，表在 0x402008
  40126d:  cmp    dl,al                      ; 只比低 8 位：unsigned char 截断在这
  40126f:  je     401282                     ; 相等 → 继续循环
  401271:  mov    edi,0x402033               ; "nope, wrong key"
  401276:  call   401090 <puts@plt>
  401282:  add    DWORD PTR [rbp-0x24],0x1   ; i++
  401286:  cmp    DWORD PTR [rbp-0x24],0x7   ; i <= 7 ?
  40128a:  jle    401251
  401293:  mov    edi,0x402043               ; "flag{%s_x0r_4dd}\n"
  40129d:  call   4010c0 <printf@plt>
```

校验逻辑还原为一个式子：

$$\text{enc}[i] = (\text{unsigned char})\big((\text{key}[i] \oplus \text{0xAB}) + \text{0x11}\big) \tag{1}$$

注意 `cmp dl,al`：C 里的 `(unsigned char)` 强转没有生成单独的指令，编译器直接实现为"只比较低 8 位"，效果相同。读汇编时看到字节级 `cmp` 配 `movzx` 装载，可以判断对应变量是 `unsigned char`。

### 2.4 objdump -s：读取常量表

常量表地址 `0x402008` 在 `.rodata` 节里（[[R04-可执行文件格式ELF与PE|R04]]的节区知识）。`objdump -s` 按字节打印节内容：

```bash
objdump -s -j .rodata crackme
```

输出：

```
 402000 01000200 00000000 d3e0db05 eee905dd  ................
 402010 6b65793a 20002532 33730066 6c61677b  key: .%23s.flag{
 402020 6e696365 5f747279 5f627574 5f66616b  nice_try_but_fak
 402030 657d006e 6f70652c 2077726f 6e67206b  e}.nope, wrong k
 402040 65790066 6c61677b 25735f78 30725f34  ey.flag{%s_x0r_4
 402050 64647d0a 00                          dd}..
```

三列依次是地址、十六进制字节、ASCII 对照。strings 找到的四条线索全在 ASCII 列（`key: ` 在 0x402010，诱饵字符串在 0x40201b）；`enc` 的 8 字节 `d3 e0 db 05 ee e9 05 dd` 在表头 0x402008，这段在 ASCII 列显示为乱码。==strings 扫不到的字节常量，要用 `objdump -s` 这类命令直接读节内容==。偏移也吻合：strings 给出的 0x2010 加上非 PIE 默认基址 0x400000（[[R04-可执行文件格式ELF与PE|R04]]讲过）正好是 0x402010，两份输出指向同一份数据。

### 2.5 逆推 key 并验证

式 (1) 的每一步都可逆：异或的逆是异或本身，加 0x11 的逆是减 0x11。按相反顺序执行：先减 0x11，再异或 0xAB。减法可能得到负数，`& 0xFF` 把结果收回 0–255，与比较时发生的字节截断一致。

```python
# solve.py —— 从常量表逆推 key
enc = [0xD3, 0xE0, 0xDB, 0x05, 0xEE, 0xE9, 0x05, 0xDD]       # 2.4 读出的常量表
key = "".join(chr(((e - 0x11) & 0xFF) ^ 0xAB) for e in enc)  # 逐字节逆变换后拼接
print(len(key), key)
```

逐段说明：

- `enc = [...]`：从 2.4 的输出里抄出的 8 字节常量表。
- `((e - 0x11) & 0xFF) ^ 0xAB`：式 (1) 的逆，运算顺序与加密相反——先减 0x11，`& 0xFF` 处理减出负数的情况，最后异或 0xAB（异或两次等于没异或）。
- `"".join(chr(...) for e in enc)`：对 8 个字节各算出对应字符，再拼成一个字符串。

```bash
python3 solve.py
```

输出：

```
8 ida_vs_g
```

key 是 `ida_vs_g`，共 8 字节。运行程序验证：

```bash
echo ida_vs_g | ./crackme
```

输出：

```
key: flag{ida_vs_g_x0r_4dd}
```

第 2 节的完整流程共六步：`file` 认格式 → `strings` 提取线索 → `objdump -d` 读出变换式 → `objdump -s` 读常量表 → 逆变换算 key → 运行验证。第 3、4 节的 GUI 工具覆盖其中每一步。

### 2.6 符号被剥掉时如何定位 main

很多题目发布时会剥掉符号表。`gcc -s` 在链接时完成剥离：

```bash
gcc -O0 -fno-pie -no-pie -s crackme.c -o crackme_stripped
file crackme_stripped
readelf -h crackme_stripped | grep "Entry point"
objdump -d -M intel --start-address=0x4010f0 --stop-address=0x401116 crackme_stripped
objdump -d -M intel crackme | grep "<main>:"
```

输出：

```
crackme_stripped: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4a6c09e08edbe78017c6ddbf21fc1d64ab79853f, for GNU/Linux 3.2.0, stripped
  Entry point address:               0x4010f0
crackme_stripped:     file format elf64-x86-64


Disassembly of section .text:

00000000004010f0 <.text>:
  4010f0:	f3 0f 1e fa          	endbr64
  4010f4:	31 ed                	xor    ebp,ebp
  4010f6:	49 89 d1             	mov    r9,rdx
  4010f9:	5e                   	pop    rsi
  4010fa:	48 89 e2             	mov    rdx,rsp
  4010fd:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401101:	50                   	push   rax
  401102:	54                   	push   rsp
  401103:	45 31 c0             	xor    r8d,r8d
  401106:	31 c9                	xor    ecx,ecx
  401108:	48 c7 c7 d6 11 40 00 	mov    rdi,0x4011d6
  40110f:	ff 15 c3 2e 00 00    	call   QWORD PTR [rip+0x2ec3]        # 403fd8 <fflush@plt+0x2ef8>
  401115:	f4                   	hlt
00000000004011d6 <main>:
```

`file` 显示 stripped；`objdump -d` 里自定义函数的 `<main>` 标号消失（PLT 桩的标注来自动态符号表，所以 `printf@plt` 之类仍然可见）。定位方法：C 程序的入口不是 main，而是 `_start`（[[R04-可执行文件格式ELF与PE|R04]]讲过这条启动链）。入口地址从 `readelf -h` 的 Entry point 拿到（本例 0x4010f0），从那里开始反汇编，`_start` 把 main 的地址装进 rdi，随后调用 `__libc_start_main`——上例中就是 `mov rdi,0x4011d6` 这条。最后一行验证了这一点：未剥符号的同一个程序里，main 正是起始于 0x4011d6。==找 main 的通用方法：看入口函数传给 `__libc_start_main` 的第一个参数==。在 IDA 里对应 `G` 跳到该地址再按 `P` 建函数（快捷键见 3.4），Ghidra 里对应右键 → Create Function。

### 2.7 命令行动作与 GUI 操作的对应

| 第 2 节的命令行动作      | IDA 里              | Ghidra 里                             |
| ---------------- | ------------------ | ------------------------------------ |
| `file` 认架构       | 载入时自动选 loader      | Import File + Auto Analyze           |
| `strings` 提取线索   | `Shift+F12` 字符串窗口  | Window → Defined Strings             |
| 查谁引用了这个字符串       | 字符串上按 `X`          | 右键 → References → Show References to |
| `objdump -d` 读汇编 | 图形视图，`Space` 切文本视图 | Listing 窗口                           |
| （命令行没有对应物）       | `F5` 伪代码           | Decompile 窗口                         |
| python 逆变换       | 照常开终端跑             | 照常开终端跑                               |

==伪代码把逐行读汇编变成读类 C 代码==，这是 GUI 工具相对第 2 节的主要增益；逆变换那一步任何工具都替代不了，终端始终开着。

## 3. IDA Pro

### 3.1 版本与安装

Hex-Rays 出品，商业软件，按年订阅。两条路：

- **IDA Free**：官网 <https://hex-rays.com/ida-free> 直接下载，支持 x86/x64，带==云端版 F5==（伪代码在 Hex-Rays 服务器生成，需要联网）。学习阶段够用。
- **IDA Pro**：本地反编译器 + 全架构（ARM/MIPS/RISC-V 等），通过购买、学校授权或公司授权获得。

Windows 下安装包默认安装，启动 ida64。本章快捷键全部按 Windows 默认键位写。

### 3.2 载入流程与视图种类

把 crackme 拖进窗口 → 弹出加载对话框（loader 自动识别 ELF/PE，默认选项直接 OK）→ 自动分析开始，底部 Output window 输出日志，结束时显示 "The initial autoanalysis has been finished."。左侧 Functions 窗口列出全部函数（符号没剥就带真名），双击跳转。

四种视图各自看什么：

| 视图 | 打开方式 | 看什么 |
| ---- | ---- | ---- |
| 图形视图（Graph view） | 默认视图，`Space` 往返切换 | 函数内控制流图：基本块为节点，`cmp` 的两个出口各引一条箭头，分支走向直观 |
| 文本视图（Text view） | `Space` 往返切换 | 地址 + 指令 + 注释的线性列表，与 `objdump -d` 输出同构，适合通读完整代码 |
| 伪代码视图（Pseudocode） | `F5` | 当前函数的类 C 代码，抓逻辑用（见 3.7） |
| 十六进制视图（Hex dump） | View → Open subviews → Hex dump | 原始字节，核对常量表、查看补丁字节时用 |

### 3.3 分析结果存哪里：.i64 数据库

IDA 不修改原二进制。自动分析的产物、后续每一次改名和注释，全部写入数据库文件，默认与被分析文件同目录：64 位程序对应 `.i64`，32 位对应 `.idb`。

- 保存：`Ctrl+W`（或 File → Save）；关闭程序时也会提示保存。
- 下次打开 `.i64` 直接恢复全部进度，不需要重新分析；数据库可以脱离原二进制单独打开。
- 把分析进度转移给他人或另一台机器，拷 `.i64` 文件即可。

> [!info]- 数据库文件的内部形态
> 打包保存前，同目录会先出现 `.id0`、`.id1`、`.nam`、`.til` 几个组件文件（分别存放不同类别的分析数据）；选择打包（Pack database）后合并为单个 `.i64`。看到这几个散件说明数据库还没打包，拷贝时要么全部带走，要么先打包。

### 3.4 快捷键表

| 键 | 作用 | 使用场景 |
| ---- | ---- | ---- |
| `Space` | 图形/文本视图切换 | 想线性通读代码时切文本视图 |
| `F5` | 生成伪代码 | 定位到目标函数后的第一个动作 |
| `Shift+F12` | 打开字符串窗口 | 每道题的第一步 |
| `X` | 列出交叉引用 | 拿到字符串/函数后问"谁引用它" |
| `N` | 重命名 | 每读懂一个函数/变量就按一次 |
| `;` | 添加行注释 | 记录"这一行在做什么"（反汇编与伪代码窗口都可用） |
| `G` | 跳转到地址 | 拿到 `strings -t x` 的偏移或已知地址后精确定位（如 2.6 拿到 main 地址） |
| `Y` | 修改函数/变量/数据类型 | 伪代码类型不对时 |
| `Ctrl+W` | 保存数据库 | 阶段性成果随手存（见 3.3） |
| `Esc` | 回退浏览历史 | 跳过头了往回走 |
| `P` | 在光标位置创建函数 | strip 程序手动恢复函数（见 2.6） |
| `*` | 把数据定义为数组 | 光标放在常量表起始地址，填元素个数与大小（见 3.8） |
| `D` | 定义为数据 | 连续按在 byte/word/dword 间切换 |
| `C` | 定义为代码 | 把未被识别的字节按指令解析 |
| `U` | 取消定义 | 撤销错误的自动识别 |
| `Shift+F1` | 打开 Local Types 窗口 | 定义结构体等本地类型（见 3.8） |
| `Ctrl+F` | 当前列表窗口内过滤 | 字符串窗口搜 flag、函数窗口搜 main |
| `Alt+T` | 反汇编中搜索文本 | 搜指令助记符或立即数 |

这十几个键覆盖日常静态分析的绝大部分操作，其余功能用到时再查菜单。

### 3.5 字符串窗口与导入表窗口

**字符串窗口**（`Shift+F12`）：列出自动分析识别出的全部字符串，列有地址、长度、类型、内容。`Ctrl+F` 过滤；双击跳到字符串数据本体；在行上按 `X` 查看引用。中文乱码在右键 Setup 里调编码与最短长度。

**导入表窗口**（View → Open subviews → Imports）：列出程序从动态库导入的全部函数，双击跳到对应 PLT 表项——2.1 输出里的 `printf@plt` 之类后缀在这里与条目一一对应。==导入表是程序对外能力的完整清单==：看到 `system`/`execve` 留意命令执行，看到 `mmap`/`mprotect` 留意自修改代码，看到 socket 系列基本是网络题。动态链接题先扫一遍导入表，题型基本可以判断。静态链接的程序导入表为空——库函数代码被复制进了文件，此时改用 FLIRT 识别（3.9）。Ghidra 里对应 Symbol Tree 的 Imports 分支（4.3）。

### 3.6 交叉引用（xref）：代码引用与数据引用

交叉引用记录"哪个地址的指令引用了哪个地址"，分两类：

- **代码引用（code reference）**：`call`/`jmp` 指向函数。光标在函数名上按 `X`，列出全部调用者与被调用者，列表标注 Call/Jump。
- **数据引用（data reference）**：指令读取或写入某个数据地址。光标在字符串或全局变量上按 `X`，列出全部引用位置，列表标注 Read/Write。

两个标准用法：

- ==关键字符串 → `X` → 引用它的函数==：对 `flag`、`correct`、`wrong` 这类字符串按 `X`，双击引用行跳进校验函数。第 2 节里 grep 字符串再翻 main 干的是同一件事。
- **回溯调用链**：题目的校验逻辑常常分层（如 `main` 调 `check`，`check` 调 `transform`）。光标放在最内层函数名上按 `X` 找到调用者，逐层向上；配合 `N` 给每层改名，调用链保持可读。`Esc` 沿浏览历史回退。

分析"全局变量被谁修改"这类问题，在数据引用列表里筛 Write，即可锁定嫌疑函数。

### 3.7 F5 伪代码：能力与局限

`F5` 调用 Hex-Rays 反编译器，把当前函数翻译成类 C 代码。伪代码窗口与反汇编联动：光标点伪代码某一行，图形/文本视图里对应汇编高亮，反过来也一样。

**能力**：控制流还原为 `if`/`for`/`while`；寄存器与栈变量还原为具名局部变量；函数调用还原为"函数名 + 参数"；字节操作还原为类型转换表达式。2.3 节四十行汇编被压缩成一行 `(buf[i] ^ 0xAB) + 0x11`。

**局限**：

- 编译时丢失的信息不会还原：无符号性（可能显示成带符号比较）、数组边界、宏展开。
- 变量类型推断错误时，输出充满 `dword_402008`、`*(_DWORD *)` 强转，可读性明显下降——修复手段见 3.8。
- 不可信情形：花指令与混淆、手写汇编破坏栈指针平衡（报 sp-analysis failed）、间接跳转或跳转表识别错误。这些情况下伪代码可能缺分支、漏逻辑，甚至翻译错。

> [!warning] 伪代码不是源码
> F5 的输出是反编译器的翻译结果，不是原始 C 代码。==结论拿不准时，回到图形/文本视图核对原汇编==；2.3 节的读汇编能力是校验伪代码的手段。

### 3.8 改名、类型、数组与结构体

- **改名与注释**：`N` 改名、`;` 注释；伪代码窗口里右键变量有同样的菜单。所有标注写入数据库（3.3），重新打开仍在。函数一多，题目的可读性取决于这些标注，读懂一处就标一处。
- **修类型**：`Y`。参数实际是 `unsigned char *` 却显示 `char *` 时改过来，伪代码里多余的强转随之消失。
- **定义数组**：反汇编里光标放在数据起始地址，按 `*` 弹出数组设置，填元素个数与元素大小。把 0x402008 处的 8 字节定义为"元素大小 1、个数 8"的数组后，数据区按 `enc[0]`…`enc[7]` 显示，伪代码中对应访问也呈数组形式，而不是 `*(_BYTE *)(0x402008 + i)`。
- **定义结构体**：`Shift+F1` 打开 Local Types 窗口，直接写 C 定义：

```c
struct session {
    unsigned seq;
    char name[16];
    unsigned flags;
};
```

回到伪代码，把对应变量 `Y` 成 `struct session *`，`dword_402000` 式的访问就变成 `s->seq`。crackme 用不上结构体；协议包解析、文件格式、游戏存档这类固定布局数据必须靠它。

### 3.9 FLIRT：库函数签名识别

静态链接的二进制把 libc 代码整个复制进文件：导入表为空，几千个函数全部叫 `sub_XXXX`，没法直接读。FLIRT（Fast Library Identification and Recognition Technology）用预置的签名库逐个比对函数字节模式，认出 `printf`、`memcpy`、`malloc` 等库函数并自动改名。

- 入口：File → Load file → FLIRT signature file...，选择 `.sig` 文件。IDA 自带主流 Windows 编译器的签名；Linux gcc 静态库的签名用官方 FLAIR 工具自行生成。
- 价值：==FLIRT 认出的是库函数，可以整段跳过不读；剩下的 `sub_XXXX` 才是题目的手写逻辑==。静态链接题先跑签名识别再读代码。

Ghidra 的对应物是 Function ID，支持自建签名库，对比见第 5 节。

### 3.10 IDA 完整流程

1. 拖入 crackme，等 Output window 显示分析完成。
2. `Shift+F12` 开字符串窗口，`Ctrl+F` 搜 flag：真实 flag、诱饵字符串、`key: `、`nope` 全部列出。双击 `flag{%s_x0r_4dd}` 跳到字符串本体。
3. 在字符串行上按 `X`：列出全部引用位置，双击跳过去，落在 main 里引用该字符串的指令上。
4. 光标留在 main 里按 `F5`。伪代码大致如下（示意——变量名与类型细节随版本有出入，以实际显示为准）：

```c
int main()
{
  char buf[24];

  printf("key: ");
  fflush(stdout);
  __isoc23_scanf("%23s", buf);
  if ( strlen(buf) != 8 )
  {
    puts("flag{nice_try_but_fake}");
    return 1;
  }
  for ( int i = 0; i <= 7; ++i )
  {
    if ( (unsigned char)((buf[i] ^ 0xAB) + 0x11) != enc[i] )
    {
      puts("nope, wrong key");
      return 1;
    }
  }
  return printf("flag{%s_x0r_4dd}\n", buf);
}
```

对照 2.3 节的汇编：变换、截断、循环被压缩进 `(unsigned char)((buf[i] ^ 0xAB) + 0x11)` 一行。

5. 读懂后当场标注：`N` 把 `buf` 改名 `key`，`;` 在关键行添加注释，`Y` 修正类型。结果随 `Ctrl+W` 存进数据库（3.3），重新打开不丢。
6. 切到终端跑 2.5 的 solve.py 算出 `ida_vs_g`，运行程序验证。

## 4. Ghidra

### 4.1 安装（JDK 21）

NSA 开源，Java 编写，Windows/Linux/macOS 跨平台，解压即用。Ghidra 11.x/12.x 要求 **JDK 21**：

```bash
# 1. 装 JDK 21
sudo apt install openjdk-21-jdk        # Windows 去 Adoptium 下载 Temurin 21

# 2. 官方 Releases 下载 zip（github.com/NationalSecurityAgency/ghidra）
unzip ghidra_11.*_PUBLIC.zip -d ~/tools/

# 3. 启动
~/tools/ghidra_11.*_PUBLIC/ghidraRun    # Windows 双击 ghidraRun.bat
```

### 4.2 项目与工具概念

- **项目（Project）**：分析成果的存储单位，对应磁盘上一个 `.gpr` 项目文件和同名目录，里面放导入的程序与全部分析结果。建议一个比赛或一批题建一个项目。
- **工具（Tool）**：一组窗口布局与插件配置。默认工具是 CodeBrowser，双击文件时用它打开；也可以为不同类型的工作保存不同工具配置。

标准流程：File → New Project（选 Non-Shared，本地项目）→ File → Import File 导入二进制 → 在项目树里双击它 → 弹窗 "Analyze now?" 选 Yes → CodeBrowser 打开，默认分析器开始自动分析。分析结果保存在项目里，下次打开直接恢复，与 IDA 的 `.i64` 数据库（3.3）思路相同。

### 4.3 CodeBrowser 各窗口

- **Symbol Tree**（左）：Functions / Labels / Classes / Strings / Imports 分支，点击条目即跳转；找 main、浏览函数从这里进。Imports 分支等价 IDA 的导入表窗口（3.5）。
- **Listing**（中）：反汇编主视图，等价 IDA 的文本视图。Window → Function Graph 可打开函数控制流图，等价 IDA 的图形视图。
- **Decompile**（右）：伪代码窗口，等价 IDA 的 `F5`。选中变量按 `L` 重命名；右键 → Retype Variable 改类型；Listing 与 Decompile 双向联动高亮。

第 2 节的动作在这里全部有对应：Window → Defined Strings 等价 `Shift+F12`；右键 → References → Show References to（`Ctrl+Shift+E`）等价 IDA 的 `X`；`G` 跳地址两边通用。同一个 crackme 放进 Ghidra，Decompile 窗口给出的伪代码与 3.10 的示意基本一致；差距出现在复杂函数（优化、混淆样本）上，那里 Hex-Rays 更稳，对比见第 5 节。

### 4.4 脚本基础

Ghidra 的功能都有公开 API，分析流程可以写成脚本执行。

**脚本放在哪、怎么跑**：Window → Script Manager 打开脚本管理器。脚本目录在 Manager 的 Script Directories 里配置，默认包含用户脚本目录 `~/ghidra_scripts`（Windows 是 `%USERPROFILE%\ghidra_scripts`）。新建脚本：在 Manager 里右键 → Create New Script → Python，输入文件名后自动用编辑器打开；写完保存，回到 Manager 选中脚本，点工具栏的 Run，输出显示在底部 Console。内置上百个官方示例脚本（Python/Java），可以直接搜索、直接运行。

最小示例——遍历当前程序的全部函数，打印函数名与入口地址：

```python
# list_funcs.py —— 打印当前程序全部函数的名称与入口地址
func = getFirstFunction()                 # 取函数列表里的第一个函数
while func:
    print(func.getName(), func.getEntryPoint())
    func = getFunctionAfter(func)         # 取地址顺序的下一个函数；取不到时返回 None，循环结束
```

逐行说明：`getFirstFunction()`、`getFunctionAfter()` 是脚本环境预置的全局函数（flat API），不需要 import，作用对象是当前在 CodeBrowser 里打开的程序；`getName()` 返回函数名，`getEntryPoint()` 返回入口地址。Console 会按地址顺序逐行输出"函数名 入口地址"。

> [!info]- 脚本语言与更多 API
> 脚本默认走 Jython（Python 语法），但不是完整的 Python 3：第三方 Python 3 库不能直接 import，复杂的数据处理导出后用外部 python 做。需要类型安全和性能时用 Java 写脚本。全部 API 见 Ghidra 安装目录的 javadoc，CodeBrowser 里按 F1 也能查；Script Manager 里的官方示例是最好的参考。

**headless 批量**：不开界面，命令行一次完成"导入 + 分析 + 跑脚本"：

```bash
<ghidra 安装目录>/support/analyzeHeadless <项目目录> <项目名> -import <二进制> -postScript list_funcs.py
```

一次处理几十上百个样本时用它。

## 5. 选型对比

| 维度   | IDA Pro / Free                    | Ghidra              | radare2 / Cutter            |
| ---- | --------------------------------- | ------------------- | --------------------------- |
| 价格   | Pro 商业订阅；Free 免费，仅 x86/x64，F5 走云端 | 免费开源（NSA 维护）        | 免费开源                        |
| 伪代码  | Hex-Rays，业界标杆，复杂函数最稳              | 内置引擎，日常够用           | r2 本体没有；Cutter 集成 Ghidra 引擎 |
| 函数签名 | FLIRT 成熟，静态链接 libc 自动认名           | FunctionID 可自建，自带库少 | 无对应物                        |
| 插件生态 | 最大，新工具多先出 IDA 版                   | 增长快，API 全开放         | 命令行脚本强，GUI 靠 Cutter         |
| 典型场景 | Windows 逆向，长期主力工具                 | 零成本起步、多架构、批量脚本化     | 自动化流水线、命令行环境                |

选型建议：==零基础起步直接 Ghidra；主攻 Windows 逆向或预算到位再补 IDA；radare2 排最后==。

### 5.1 radare2 常用命令

radare2 是命令行逆向框架，没有传统界面，交互靠短命令，适合脚本化与自动化。发行版仓库的版本一般偏旧，要最新版从源码安装：

```bash
sudo apt install radare2
# 最新版：
# git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh
```

```bash
r2 -A ./crackme    # 载入并执行全量分析（等价进入交互后手敲 aaa）
aaa                # 全量分析：识别函数、生成交叉引用
afl                # 列出识别出的全部函数
s main             # 把当前地址切换到 main（s = seek）
pdf                # 反汇编当前函数（p = print，d = disassemble，f = function）
izz~flag           # 列出整个文件里的字符串，并用 ~ 过滤含 flag 的行
q                  # 退出
```

`afl` 对应 `objdump -d` 里的函数列表，`pdf` 对应单函数版的 `objdump -d`，`izz` 对应 `strings`——第 2 节的每一步在 r2 里都有对应命令。交互中输入 `?` 查看帮助。

Cutter 是 radare2 的官方图形前端，集成 Ghidra 反编译引擎，需要界面时直接用它。

## 6. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| IDA 打开全是 sub_XXXX | 程序被 strip。按 [[#2.6 符号被剥掉时如何定位 main\|2.6]] 的方法从入口函数传给 `__libc_start_main` 的参数拿到 main 地址，`G` 跳过去按 `P` 建函数 |
| F5 报 sp-analysis failed | 栈指针平衡分析失败，多由手写汇编或花指令造成。图形视图确认函数边界后按 `P` 重建函数；仍失败时按函数设置忽略栈指针变化，或直接读汇编 |
| Ghidra 启动闪退 | 缺 JDK 21 或版本不对；装好后 ghidraRun 会提示指定 JDK 路径 |
| Decompile 窗口空白 | 光标不在函数体内，或地址没被识别成代码：Listing 里按 `D` 反汇编、`F` 建函数，再回看 |
| 伪代码满屏 dword_402000 | 工具不知道那是什么。`N` 补名字、`Y` 补类型；一整块缓冲区按 `*` 定义成数组，或定义结构体（[[#3.8 改名、类型、数组与结构体\|3.8]]） |
| 字符串窗口中文乱码 | 编码识别问题：字符串窗口右键 Setup，Options → ASCII strings 里改编码集 |
| IDA 地址和 GDB 对不上 | PIE 程序加载基址随机，IDA 显示文件视角的地址；非 PIE 才能直接对号（[[05-ELF文件格式与链接\|01 库 05 章]]的同类问题） |
| Ghidra 首次分析特别慢 | 分析器里 Decompiler Parameter ID 最耗时，小程序可以取消勾选；分析结果存项目，跑一次长期复用 |
| 伪代码读着"很对"，跑起来不对 | 被反编译器的翻译误差误导（见 [[#3.7 F5 伪代码：能力与局限\|3.7]] 的 warning）；回汇编视图核对，或改用动态调试 |

