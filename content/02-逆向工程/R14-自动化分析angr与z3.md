---
chapter: 逆向工程
section: 自动化分析：angr 与 z3
order: 214
tags:
  - CTF
  - 逆向工程
  - RE
  - 符号执行
publish: true
---

# R14 自动化分析：angr 与 z3
## Automated Analysis: angr & z3

> [!info]- 章节信息
> **所属方向**：逆向工程 ｜ **难度阶段**：L3 进阶专题期 ｜ **前置要求**：[[R07-编码与算法识别还原|R07]] · [[R03-x86与x64汇编精要复习|R03]] · [[R05-静态分析工具链IDA与Ghidra|R05]]
> **本章目标**：能讲清符号执行"符号变量 → 路径约束 → 求解器"三步原理；会用 z3 对校验逻辑手工建模并求解；会用 angr 的 explore / avoid 自动求出 crackme 的输入，并从 state 上读出路径约束转交 z3；知道什么时候自动求解更快、什么时候手逆更快。

## 1. 符号执行：把"猜输入"变成"解方程"

[[R05-静态分析工具链IDA与Ghidra|R05]]的流程终点是"读懂校验逻辑，逆变换算出 key"；[[R07-编码与算法识别还原|R07]]的流程终点是"认出算法，用 Python 逆推"。两条路都要求人读懂逻辑。符号执行（symbolic execution）把这一步交给框架：输入不再是一个具体值，而是一个==符号变量==（"未知的 8 字节"）；程序照常逐条执行，走到条件分支时==两条路都保留==，并把"走这条路必须满足的条件"抄录下来；走到目标位置（比如打印 Correct 的那条路）时，把抄录下来的全部条件交给==约束求解器==，由它算出"什么样的输入能走通这条路"。

三步拆开：

1. **符号化**：把输入变成符号变量 `k`。此后程序里所有依赖 `k` 的中间值都变成"含 `k` 的表达式"，而不是具体数。
2. **收集路径约束**：执行到 `if` 时，走 true 分支就记下"条件成立"，走 false 分支就记下"条件不成立"。一个 crackme 逐字节比较 8 次，走到正确出口时就积累下 8 个（加上长度检查等共十来个）方程。
3. **求解**：把方程组交给求解器，返回一组让所有方程同时成立的赋值——这就是 key。

### 1.1 与"爆破"的本质区别

爆破（brute force）也解"什么输入能通过校验"，但方式是把输入空间逐个试完。两者不在一个量级上：

| | 爆破 | 符号执行 |
| ---- | ---- | ---- |
| 搜索对象 | 枚举整个输入空间（8 字节就是 $2^{64}$ 个候选） | 沿程序路径推进，每个分支条件变成一条方程 |
| 条件间关系 | 逐个候选完整跑一遍校验 | 求解器代数化地同时满足全部约束 |
| 单字节、无耦合（`buf[i]^0x37`） | 256 次尝试，够快 | 也能解，但没优势 |
| 字节间耦合（`s[0]*s[1]==10670`） | 候选间没有信息可复用，$2^{16}$ 次 | 求解器直接解方程 |
| 前提 | 校验必须能被反复执行 | 校验必须能被表达成可求解的约束 |

==爆破搜输入空间，符号执行搜路径空间==。分支少而耦合深的校验，是符号执行的适用场景。反过来，校验里出现哈希、多轮分组加密这类==不可逆或难逆的原语==时，求解器同样解不动——那条路还是要回到 [[R07-编码与算法识别还原|R07]]的手逆。

### 1.2 术语表

本章和所有 angr 资料共用的五个词：

| 术语 | 含义 | 在工具里对应 |
| ---- | ---- | ---- |
| 符号变量（symbol） | 占位的未知数，如"8 位未知整数" | `claripy.BVS("k", 8)`（z3 里是 `BitVec`） |
| 状态（state） | 某一时刻的 CPU 寄存器 + 内存 + 已收集约束的快照 | angr 的 `SimState` |
| 路径（path） | 一次符号执行走过的指令序列 | state 的历史（`state.history`） |
| 约束（constraint） | "走到这里必须满足"的条件表达式 | `state.solver.constraints`，一个布尔表达式列表 |
| 求解器（solver） | 解约束的引擎 | angr 内置的 `claripy.Solver`，底层是 z3 |

约束的全体是一个方程组；求解器返回的==一组同时满足全部约束的赋值叫模型（model）==。约束不足时模型不唯一，求解器只承诺"这是一个可行解"，不承诺"这是唯一的解"——[[#2.4 实战：异或 + 加法方程组的纯 z3 求解|2.4 节]]会看到这条规则的实际后果。

> [!note] 两个工具的分工
> **z3** 是纯粹的约束求解器：给它方程，它给解，不懂程序。**angr** 是符号执行框架：它负责把程序跑出约束（模拟 CPU、内存、库函数），求解这一步转手交给 z3。angr 里的表达式层叫 claripy，是 z3 表达式的封装。所以本章先讲 z3——会手工把校验逻辑翻译成约束，是使用 angr 前必须具备的能力，也是 angr 求不出结果时最可靠的备用手段。

## 2. z3：先会求解器

安装：`pip3 install z3-solver`，`import z3` 即用。本章脚本按 z3-solver 5.1 的 API 编写。

### 2.1 第一个方程：Solver、check、model

z3 的固定三件套：==建变量 → `Solver()` 里 `add()` 约束 → `check()` 后取 `model()`==。

```python
# z1.py —— z3 起步：一元方程
from z3 import *

x, y = Ints('x y')
s = Solver()
s.add(x * 5 - 3 == 42)
print("check :", s.check())
print("model :", s.model())

s.add(x > 0)                       # 追加约束，解被进一步收紧
print("加约束后:", s.check(), s.model())

s2 = Solver()
s2.add(x * x < 0)                  # 平方非负，此方程无解
print("无解方程 check:", s2.check())

print("simplify(x + y - x) =", simplify(x + y - x))
print("simplify(And(x > 0, 0 < x)) =", simplify(And(x > 0, 0 < x)))
```

输出：

```
check : sat
model : [x = 9]
加约束后: sat [x = 9]
无解方程 check: unsat
simplify(x + y - x) = y
simplify(And(x > 0, 0 < x)) = Not(x <= 0)
```

四条契约：

- `check()` 返回 `sat`（有解）/ `unsat`（无解）/ `unknown`（解不动）。==`model()` 只在 `sat` 之后合法==，没 check 就取模型是最常见的报错来源。
- `Solver` 是增量式的：`add()` 可以一直追加，每次 `check()` 都对当前全部约束求值。
- 无解就是信息：`unsat` 说明你写的约束互相矛盾，常意味着建模抄错了常数。
- `simplify()` 做表达式化简，核对"我写的约束化简后是什么形状"时有用。

`Int` 是数学整数，无限宽、不回绕。逆向面对的是机器字，主角是下一节的 `BitVec`。

### 2.2 BitVec：定宽与回绕

`BitVec('b', 8)` 是一个 8 位机器字。==定宽运算按 $2^8$ 取模回绕==，这正是 CPU 里加法的行为，也是 Python 手写 `& 0xFF` 在模拟的事：

```python
# z2b.py —— 定宽回绕：BitVec 与 Int 的差别
from z3 import *

b = BitVec('b', 8)
s = Solver()
s.add(b - 1 == 255)
print('BitVec8: check =', s.check(), ' 解 =', s.model()[b])

x = Int('x')
s2 = Solver()
s2.add(x - 1 == 255, x >= 0, x <= 255)
print('Int(限 0..255): check =', s2.check())

print('simplify(BitVecVal(200,8) + 100) =', simplify(BitVecVal(200, 8) + 100))
```

输出：

```
BitVec8: check = sat  解 = 0
Int(限 0..255): check = unsat
simplify(BitVecVal(200,8) + 100) = 44
```

8 位世界里 `0 - 1` 就是 255、`200 + 100` 就是 44——`b - 1 == 255` 的解是 `b = 0`，而同样的方程在 `Int` 上无解。==逆向建模一律用 BitVec，宽度对齐 C 的类型==：`unsigned char` 用 8 位、`uint32_t` 用 32 位。BitVec 定宽运算自动回绕，Python 侧那些 `& 0xFF` 全部不用手写。

两个配套操作，对应 C 的整型语义：

| z3 操作 | 对应的 C 行为 |
| ---- | ---- |
| `ZeroExt(n, b)` / `SignExt(n, b)` | 小整型参与 int 运算时的零扩展 / 符号扩展（[[R02-C语言与内存模型回顾\|R02]]的整型提升） |
| `Extract(高, 低, b)` / 切片 `b[高:低]` | 取子寄存器、取某个字节（区间左闭右开下标从高位写起） |

> [!warning] BitVec 比较默认按有符号
> z3 里 BitVec 的 `<`、`<=`、`>`、`>=` 默认按**补码有符号数**解释；无符号比较要用 `ULT` / `ULE` / `UGT` / `UGE`。C 里 `unsigned char` 的比较是无符号的，建模时对应关系别接反：

```python
# z2c.py —— 有符号与无符号
from z3 import *
s = Solver(); s.add(BitVecVal(200, 8) < BitVecVal(10, 8))
print('200 < 10（< 默认语义）  :', s.check())    # 200 按补码是 -56，-56 < 10 成立
s2 = Solver(); s2.add(ULT(BitVecVal(200, 8), BitVecVal(10, 8)))
print('ULT(200, 10)（无符号）  :', s2.check())  # 200 > 10，不成立
```

输出：

```
200 < 10（< 默认语义）  : sat
ULT(200, 10)（无符号）  : unsat
```

### 2.3 多约束与枚举全部解

真实校验是一组方程。z3 一次接受整组，返回其中一个解；把已找到的解排除掉再 `check()`，循环到 `unsat`，就枚举出了全部解——==判断"key 是否唯一"就靠这个习惯==：

```python
# z3multi.py —— 多约束不等式组与枚举全部解
from z3 import *

x = Int('x')
s = Solver()
s.add(x > 100, x < 200)
s.add(x % 7 == 3)
s.add(x % 5 == 2)
print("check :", s.check())
print("第一个解:", s.model()[x])

print("枚举全部解：")
n = 0
while s.check() == sat:
    v = s.model()[x]
    print("  x =", v)
    n += 1
    s.add(x != v)                  # 排除已找到的解，继续找下一个
print("共", n, "个解")
```

输出：

```
check : sat
第一个解: 122
枚举全部解：
  x = 122
  x = 157
  x = 192
共 3 个解
```

==`model()` 给的是第一个可行解，不是全部解==；需要"唯一 key"这种结论时，必须按上面的循环枚举到 `unsat`。

### 2.4 实战：异或 + 加法方程组的纯 z3 求解

一个字节间互相耦合、无法逐字节逆推的 crackme。校验逻辑如下（反汇编/伪代码里读出来的形状，来源程序 `zm.c` 的校验部分；`ta`、`tb` 是 `.rodata` 里的常量表，读法见 [[R05-静态分析工具链IDA与Ghidra#2.4 objdump -s：读取常量表|R05 2.4]]）：

```c
/* zm.c 的校验逻辑 —— k 是 8 字节输入，argv[1] 传入 */
if (strlen((const char *)k) != 8) { puts("no"); return 1; }
for (int i = 0; i < 7; i++)
    if ((unsigned char)(k[i] ^ k[i + 1]) != ta[i]) { puts("no"); return 1; }  /* 异或链 */
if ((unsigned char)(k[0] ^ 0x55) != 0x2F) { puts("no"); return 1; }           /* 锚点 */
if ((unsigned char)(k[2] + k[5]) != tb[0]) { puts("no"); return 1; }          /* 加法方程 */
if ((unsigned char)(k[4] + k[7]) != tb[1]) { puts("no"); return 1; }

/* 常量表（节选）：
   ta[7] = { 0x49, 0x6C, 0x2C, 0x43, 0x5C, 0x1A, 0x45 };
   tb[2] = { 0xCB, 0x63 }; */
```

> [!info]- zm.c 全文（供复现）
> ```c
> /* zm.c —— 异或 + 加法方程组 crackme（8 字节 key 从 argv[1] 传入） */
> #include <stdio.h>
> #include <string.h>
>
> static const unsigned char ta[7] = {
>     0x49, 0x6C, 0x2C, 0x43, 0x5C, 0x1A, 0x45   /* 相邻字节异或的右端 */
> };
> static const unsigned char tb[2] = { 0xCB, 0x63 }; /* 指定字节对相加的右端 */
>
> int main(int argc, char **argv) {
>     if (argc < 2) { puts("usage: ./zm <key>"); return 1; }
>     const unsigned char *k = (const unsigned char *)argv[1];
>     if (strlen((const char *)k) != 8) { puts("no"); return 1; }
>     for (int i = 0; i < 7; i++)
>         if ((unsigned char)(k[i] ^ k[i + 1]) != ta[i]) { puts("no"); return 1; }
>     if ((unsigned char)(k[0] ^ 0x55) != 0x2F) { puts("no"); return 1; }
>     if ((unsigned char)(k[2] + k[5]) != tb[0]) { puts("no"); return 1; }
>     if ((unsigned char)(k[4] + k[7]) != tb[1]) { puts("no"); return 1; }
>     puts("Correct!");
>     return 0;
> }
> ```

异或链 `k[i] ^ k[i+1]` 把相邻字节耦合在一起，加法方程再跨字节关联——逐字节逆推在这里失效，而手工解 8 个未知数的异或方程组也不现实。这类方程组正适合交给求解器。建模就是把上面每一条 `if` 原样翻译成 `add()`：

```python
# z3solve.py —— 从伪代码手工建模：异或 + 加法方程组的纯 z3 求解
from z3 import *

ta = [0x49, 0x6C, 0x2C, 0x43, 0x5C, 0x1A, 0x45]   # 伪代码里抄出的两个常量表
tb = [0xCB, 0x63]

k = [BitVec(f"k{i}", 8) for i in range(8)]        # 8 个未知字节
s = Solver()
s.add(k[0] ^ 0x55 == 0x2F)                        # 锚点：把 k[0] 定死
for i in range(7):
    s.add(k[i] ^ k[i + 1] == ta[i])               # 异或链
s.add(k[2] + k[5] == tb[0])                       # BitVec 定宽运算自动按 2^8 回绕
s.add(k[4] + k[7] == tb[1])

print("check:", s.check())
m = s.model()
key = bytes(m[k[i]].as_long() for i in range(8))
print("key =", key.decode())
print("自检: 异或链全部成立 =", all((key[i] ^ key[i + 1]) == ta[i] for i in range(7)),
      "加法方程成立 =", (key[2] + key[5]) % 256 == tb[0] and (key[4] + key[7]) % 256 == tb[1])
```

输出：

```
check: sat
key = z3_s0lv3
自检: 异或链全部成立 = True 加法方程成立 = True
```

喂回原程序：

```bash
gcc -O0 -fno-pie -no-pie zm.c -o zm
./zm wrongkey_
./zm z3_s0lv3
```

输出：

```
no
Correct!
```

建模要点回顾：未知数是 8 个 8 位 BitVec；每条 `if` 对应一条 `add()`；==加法不用再写 `& 0xFF`==，BitVec 自己回绕。`model()` 返回的每个值用 `as_long()` 转回 Python 整数再拼成 bytes。

> [!info]- 锚点删掉会怎样：约束不足时模型不唯一
> 把锚点那条 `add()` 删掉再解，z3 照样返回 `sat`，但给出一串完全不同的字节：
>
> 输出：
>
> ```
> sat [k3 = 242,
>  k5 = 237,
>  k7 = 178,
>  k0 = 251,
>  k6 = 247,
>  k1 = 178,
>  k2 = 222,
>  k4 = 177]
> ```
>
> 异或链只约束"相邻字节的差"，`k[0]` 自由，整条链随 `k[0]` 平移出 256 组解；两条加法方程收不掉全部自由度。这组解喂回 `zm` 会在锚点检查处得到 `no`——==z3 只对"你写进模型的约束"负责，模型漏了一条，解就不再是程序的解==。建模出错时，把程序里每条校验逐一对照 `add()` 列表，是唯一系统的排错方法。

## 3. angr：框架与核心对象

z3 要求人读懂逻辑后手工建模。angr 把"读懂"也接管了：它模拟执行程序，==约束由程序自己跑出来==。安装：`pip3 install angr`（会带上依赖）。本章脚本按 angr 10 的 API 编写。

### 3.1 Project 与自动加载

```python
import angr
proj = angr.Project("./a1", auto_load_libs=False)
```

`Project` 载入一个二进制，完成 ELF 解析与初始分析（[[R04-可执行文件格式ELF与PE|R04]]的知识在这里全部由框架完成识别）。`auto_load_libs=False` 不把 libc 等动态库载入分析：程序对库函数的调用由 angr 预置的==替身实现（SimProcedure）==接管——`strlen` 的替身会按符号内容逐字节找 0 并把长度变成约束，`puts` 的替身把字符串写进 state 的输出缓冲。crackme 类题目都用这个配置，状态数量少、跑得快；`printf`/`scanf`/`strlen`/`memcpy` 这些常见函数的替身都是现成的。

### 3.2 factory：状态从哪来

`proj.factory` 负责制造分析起点：

| 调用 | 得到什么 |
| ---- | ---- |
| `factory.entry_state(args=[...])` | 从 ELF 入口开始的状态，走完 angr 模拟的启动流程后进入 main；`args` 里放符号量（BitVec）就是符号输入 |
| `factory.blank_state(addr=...)` | 从指定地址直接起跑，寄存器和内存默认是符号量，参数要自己设置。能跳过启动流程，但初始化行为随版本变化较大，本章一律用 `entry_state` |

`entry_state` 的典型用法——把"8 字节未知 key"作为 argv[1] 传入：

```python
c = angr.claripy                       # angr 10 起 claripy 打包进 angr（旧版是独立模块 import claripy）
argv1 = c.Concat(c.BVS("key", 8 * 8), c.BVV(b"\x00", 8))
init = proj.factory.entry_state(args=["./a1", argv1])
```

`BVS(name, bits)` 造符号量，`BVV(值, bits)` 造立即数（V = value，S = symbol）。末尾拼一个 0 字节是给 `strlen` 的替身一个确定的结束符，让"长度等于 8"这条约束有明确形状。

### 3.3 SimulationManager 与状态分类

`proj.factory.simgr(state)` 造出 SimulationManager（simgr），负责管理==一组并行推进的状态==：符号执行不断分叉，状态按处境分进各个**stash**（仓库）：

| stash | 装什么 |
| ---- | ---- |
| `active` | 还在执行、尚未归入终点仓库的状态 |
| `found` | 满足了 `find` 条件的状态（命中目标） |
| `avoid` | 满足了 `avoid` 条件、被主动丢弃的状态 |
| `deadended` | 正常走到底（程序退出）的状态 |
| `unconstrained` | 跳转目标成了符号量、无法继续的状态（PWN 里找溢出点时才有用） |
| `errored` | 执行中出错的状态 |

`simgr.step()` 单步：active 里每个状态各走一条指令，分叉就分裂成多个状态。`simgr.explore(find=..., avoid=...)` 是 step 的自动化：==一直跑到 active 里再没有状态，或所有状态都进了 found / avoid / deadended 等终点仓库==。`find`、`avoid` 都给函数，收一个 state、返回 True/False，最常用的写法是检查输出缓冲：

```python
simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1),
              avoid=lambda s: b"decoy" in s.posix.dumps(1))
```

`s.posix.dumps(1)` 返回该 state 已写到文件描述符 1（stdout）的全部字节。`explore` 结束后从 `simgr.found` 里取状态。

### 3.4 claripy：angr 的表达式层，底下是 z3

angr 里一切"值"都是 claripy 表达式：`BVS` 是符号量，`BVV` 是常量，比较产生 Bool 表达式，`state.solver.constraints` 就是 Bool 表达式的列表。它和 z3 的关系一句话：==claripy 是 z3 的封装，`state.solver` 的每次求值都是一次 z3 求解==。所以 claripy 的定宽回绕、有符号/无符号语义与 [[#2.2 BitVec：定宽与回绕|2.2 节]]完全一致，z3 的建模经验在 angr 里全部适用。

直接拿 claripy 独立求解也可以，适合单步验证某个约束的形状：

```python
# c1.py —— claripy：angr 的表达式层
import angr
c = angr.claripy

a = c.BVS('a', 8)
print('无约束      :', c.Solver().eval(a ^ 0xFF, 3))
s = c.Solver()
s.add(a > 100)
print('加 a > 100  :', s.eval(a ^ 0xFF, 3))
s.add(a < 103)
print('再加 a < 103:', s.eval(a ^ 0xFF, 3))
```

输出：

```
无约束      : [255, 254, 252]
加 a > 100  : [154, 26, 24]
再加 a < 103: [153, 154]
```

`eval(expr, n)` 给出 n 个互不相同的可行值：约束不足时符号量是一族值（第一批 3 个）；约束收紧后族缩小；`a < 103` 加上后只剩 `{101, 102}`，异或出来恰好两个值。==state.solver 的 `eval` / `eval_upto` / `eval_one` 都是同一机制在 state 上的便捷入口==（第 5 节用到）。

### 3.5 CFG 与函数识别

angr 也能做静态分析：`proj.analyses.CFGFast()` 不执行程序、按代码模式恢复全程序控制流图，配合 `proj.kb.functions` 可以按地址取函数：

```python
import logging, time
logging.getLogger("angr").setLevel(logging.ERROR)   # angr 默认输出大量日志，先调低级别；排错时删掉这行
import angr

proj = angr.Project("./a1", auto_load_libs=False)
t0 = time.time()
cfg = proj.analyses.CFGFast()
print("CFGFast: %.1f 秒，%d 个节点" % (time.time() - t0, len(list(cfg.graph.nodes()))))
print("main 入口:", hex(proj.loader.find_symbol("main").rebased_addr))
```

输出：

```
CFGFast: 0.0 秒，76 个节点
main 入口: 0x401156
```

本章的 crackme 用不到 CFG——`explore` 按条件收敛的流程直接从入口跑。上规模的程序（静态链接、几十 MB）做全量分析时，CFGFast 和带模拟执行的 CFGEmulated 才是耗时的主要来源，分钟级很常见。

> [!info]- 本章两个可复用的小脚本习惯
> ① 开头 `logging.getLogger("angr").setLevel(logging.ERROR)`：angr 默认打一屏 WARNING 级日志，那是日志不是错误；脚本行为异常时删掉这行看详情。② 符号输入从 argv 进，绕开了 stdin 符号化的接口差异——stdin、文件、网络同样能符号化，但相关接口在 angr 大版本间调整频繁，用时查官方文档对应版本。

## 4. 实战一：explore 一次求解出 key

靶子是[[R08-CrackMe经典题型|R08]]同款的多分支校验 crackme——真实赛题里这段逻辑藏在反编译视图后面（[[R05-静态分析工具链IDA与Ghidra|R05]]的流程负责把它找出来），这里直接给源码：

```c
/* a1.c —— 多分支校验 crackme：key 从 argv[1] 传入，每个分支定死一个字节 */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) { puts("usage: ./a1 <key>"); return 1; }
    const unsigned char *s = (const unsigned char *)argv[1];
    if (strlen((const char *)s) != 8) { puts("Wrong"); return 1; }
    if ((s[0] ^ 0x24) != 0x57)        { puts("Wrong"); return 1; }
    if (s[1] + 0x11 != 0x8A)          { puts("Wrong"); return 1; }
    if (s[2] - 3 != 0x6A)             { puts("Wrong"); return 1; }
    if ((s[3] ^ 0x0F) != 0x50)        { puts("Wrong"); return 1; }
    if (s[4] + 0x1C != 0x81)          { puts("Wrong"); return 1; }
    if ((s[5] ^ 0x1F) != 0x67)        { puts("Wrong"); return 1; }
    if (s[6] - 0x0A != 0x5B)          { puts("Wrong"); return 1; }
    if ((s[7] ^ 0xAA) != 0xC9)        { puts("Wrong"); return 1; }
    puts("Correct!");
    return 0;
}
```

每个分支都能手逆（第 1 个字节 `0x57 ^ 0x24`，第 2 个 `0x8A - 0x11`，……），8 个分支手算 8 次也能出答案。angr 的用法是把"读逻辑 + 建模 + 求解"全部交给框架：

```python
# a1.py —— angr 求解 a1
import logging, time
logging.getLogger("angr").setLevel(logging.ERROR)   # 调低 angr 日志级别，排错时可删掉这行

import angr

c = angr.claripy                      # angr 10 起 claripy 打包进 angr（旧版为独立模块）

t0 = time.time()
proj = angr.Project("./a1", auto_load_libs=False)
argv1 = c.Concat(c.BVS("key", 8 * 8), c.BVV(b"\x00", 8))
init = proj.factory.entry_state(args=["./a1", argv1])
simgr = proj.factory.simgr(init)
simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1))
print("耗时 %.1f 秒" % (time.time() - t0))
print("found 状态数:", len(simgr.found))

f = simgr.found[0]
print("程序输出:", f.posix.dumps(1).decode().strip())
key = f.solver.eval(argv1, cast_to=bytes)[:8]
print("key =", key.decode())
```

输出：

```
耗时 0.2 秒
found 状态数: 1
程序输出: Correct!
key = sym_exec
```

逐段说明：

- `c.Concat(c.BVS("key", 64), c.BVV(b"\x00", 8))`：符号 key 加结束符，共 9 字节，作为 `args[1]` 传给 entry_state。
- `explore(find=...)`：angr 从入口开始模拟，`strlen` 替身、8 个比较分支全部按符号语义执行，约束自动落进每个 state；只要 stdout 出现 `Correct` 就把该状态移入 `found`。耗时在秒级，随机器浮动。
- `f.solver.eval(argv1, cast_to=bytes)`：对这个 state 的约束组求解，把符号量代成具体字节；`[:8]` 去掉末尾的结束符。

喂回程序收尾：

```bash
gcc -O0 -fno-pie -no-pie a1.c -o a1
./a1 sym_exec
```

输出：

```
Correct!
```

==angr 交付的输入直接就是可执行文件认的 key==。这个流程对校验逻辑的变化不敏感：把异或加法换成乘除混合、字节互换、查表，脚本一行不用改——分支照常执行、约束照常收集、求解器照常求解。

## 5. 实战二：假分支、avoid 与约束提取

### 5.1 假分支与 avoid

出题人常放"条件好满足、输出像 flag"的假路径，诱使爆破和自动化工具命中。靶子 `a2.c`：第一个字节是 `'A'` 就输出假 flag，真校验藏在后面，两条路都以 `flag{` 开头输出：

```c
/* a2.c —— 假分支 + 真校验：两条路径都以 flag{ 开头输出 */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) { puts("usage: ./a2 <key>"); return 1; }
    const unsigned char *s = (const unsigned char *)argv[1];
    if (strlen((const char *)s) != 4) { puts("Wrong"); return 1; }
    if (s[0] == 'A') {                          /* 条件好满足的假分支 */
        printf("flag{decoy_n0t_re4l}\n");
        return 0;
    }
    if ((s[0] * s[1]) != 10670) { puts("Wrong"); return 1; }  /* 真校验：乘法耦合 s0 与 s1 */
    if ((s[1] - s[0]) != 13)    { puts("Wrong"); return 1; }
    if ((s[2] ^ 0x16) != 0x71)  { puts("Wrong"); return 1; }
    if ((s[3] - 11) != 103)     { puts("Wrong"); return 1; }
    printf("flag{%c%c%c%c_w0n}\n", s[0], s[1], s[2], s[3]);
    return 0;
}
```

真校验里 `s[0] * s[1] == 10670` 是字节间乘法耦合，`s[0]`、`s[1]` 谁大谁小未知，逐字节逆推失效——上一节的 z3 或这一节的 angr 都能解。先看 find 不排除假分支时会发生什么：

```python
# a2.py —— 假分支：find 只认 flag{ 会命中假 flag，加 avoid 才到真路径
import logging
logging.getLogger("angr").setLevel(logging.ERROR)

import angr

c = angr.claripy                      # angr 10 起 claripy 打包进 angr（旧版为独立模块）

proj = angr.Project("./a2", auto_load_libs=False)
key = c.BVS("key", 4 * 8)
argv1 = c.Concat(key, c.BVV(b"\x00", 8))

def run(find, avoid=None):
    init = proj.factory.entry_state(args=["./a2", argv1])
    simgr = proj.factory.simgr(init)
    kw = {"find": find}
    if avoid is not None:
        kw["avoid"] = avoid
    simgr.explore(**kw)
    return simgr

# 第一轮：find 只认 "flag{" —— 假分支也输出 flag{，看它命中哪条路
s1 = run(lambda s: b"flag{" in s.posix.dumps(1))
f1 = s1.found[0]
print("第一轮 found 状态数:", len(s1.found))
print("  输入:", f1.solver.eval(key, cast_to=bytes))
print("  输出:", f1.posix.dumps(1).decode().strip())

# 第二轮：avoid 把假分支从状态集里剔掉
s2 = run(lambda s: b"w0n" in s.posix.dumps(1),
         avoid=lambda s: b"decoy" in s.posix.dumps(1))
f2 = s2.found[0]
print("第二轮（加 avoid）:")
print("  输入:", f2.solver.eval(key, cast_to=bytes))
print("  输出:", f2.posix.dumps(1).decode().strip())
print("  各 stash 剩余:", {k: len(v) for k, v in s2.stashes.items() if v})
```

输出：

```
第一轮 found 状态数: 1
  输入: b'A\xff\xff\xff'
  输出: flag{decoy_n0t_re4l}
第二轮（加 avoid）:
  输入: b'angr'
  输出: flag{angr_w0n}
  各 stash 剩余: {'active': 3, 'deadended': 2, 'found': 1, 'avoid': 1}
```

两轮对照把 avoid 的机制讲全了：

- 第一轮的 find 条件 `b"flag{"` 太宽：假分支只需约束一个字节（`s[0] == 'A'`），路径最短，先被找到——拿到的是假 flag 和一个以 `'A'` 开头的"key"。
- 第二轮 `avoid` 把输出含 `decoy` 的状态当场移入 `avoid` 仓库，==不再从这些状态继续分裂==；find 收紧到真输出特有的 `w0n`。最后各 stash 的分布就是 [[#3.3 SimulationManager 与状态分类|3.3 节]]那张表的样子：1 个命中、1 个假分支被剔、3 个还在执行、2 个正常退出。
- `avoid` 还有地址写法：`avoid=[0x4011xx]`（假分支打印函数的入口地址，从 objdump/IDA 拿），命中该地址的状态同样被剔除。条件简单时用地址更快，输出特征更稳时用 lambda。

喂回验证两条路都真实存在：

```bash
gcc -O0 -fno-pie -no-pie a2.c -o a2
./a2 angr
./a2 Axyz
```

输出：

```
flag{angr_w0n}
flag{decoy_n0t_re4l}
```

### 5.2 第二条路：读出约束，转交 z3

angr 不必一步到位。==explore 找到的 state 身上就挂着完整的约束列表==，把它读出来，就能回到 [[#2. z3：先会求解器|第 2 节]]的手工 z3 流程——这是 angr 求不出结果时的备用路，也是理解符号执行最直接的方式：

```python
# a3.py —— 第二条路：读出真路径上的约束，转交 z3 人工求解
import logging
logging.getLogger("angr").setLevel(logging.ERROR)

import angr

c = angr.claripy                      # angr 10 起 claripy 打包进 angr（旧版为独立模块）

proj = angr.Project("./a2", auto_load_libs=False)
key = c.BVS("key", 4 * 8)
argv1 = c.Concat(key, c.BVV(b"\x00", 8))

init = proj.factory.entry_state(args=["./a2", argv1])
simgr = proj.factory.simgr(init)
simgr.step()                                  # 只走一步：看看状态是怎么分类的
print("step 一次后:", {k: len(v) for k, v in simgr.stashes.items() if v})

simgr.explore(find=lambda s: b"w0n" in s.posix.dumps(1),
              avoid=lambda s: b"decoy" in s.posix.dumps(1))
f = simgr.found[0]

print()
print("真路径 state 上收集到的约束，共", len(f.solver.constraints), "条：")
for c in f.solver.constraints:
    s = str(c)
    print("  ", s if len(s) <= 84 else s[:60] + " ……（strlen 的建模，太长，截断）")

print()
print("angr 自己的读法:")
print("  eval(key) =", f.solver.eval(key, cast_to=bytes))
print("  eval_one(key[31:24]) =", f.solver.eval_one(key[31:24]))
print("  eval_upto(key[31:24], 10) =", f.solver.eval_upto(key[31:24], 10))
```

输出：

```
step 一次后: {'active': 1}

真路径 state 上收集到的约束，共 7 条：
   <Bool (if key_0_32[31:24] == 0 then 0x7ffffffeffd5 else (if  ……（strlen 的建模，太长，截断）
   <Bool strlen_3_64 == 0x4>
   <Bool key_0_32[31:24] != 65>
   <Bool (0#24 .. key_0_32[31:24]) * (0#24 .. key_0_32[23:16]) == 0x29ae>
   <Bool (0#24 .. key_0_32[23:16]) - (0#24 .. key_0_32[31:24]) == 0xd>
   <Bool key_0_32[15:8] == 103>
   <Bool key_0_32[7:0] == 114>

angr 自己的读法:
  eval(key) = b'angr'
  eval_one(key[31:24]) = 97
  eval_upto(key[31:24], 10) = [97]
```

七个约束逐条对照源码读：

1. 那条被截断的长约束 + 第 2 条：`strlen` 替身的建模——"逐字节找 0，0 的位置决定长度"，落地成嵌套 if 表达式，长度必须等于 4。==库函数不是被跳过，而是被翻译成了约束==。
2. `key[31:24] != 65`：65 就是 `'A'`——==避开假分支这件事本身也是一条约束==（走 true 分支的状态全被 avoid 了，剩下的都带这条）。
3. `(0#24 .. key[31:24]) * (0#24 .. key[23:16]) == 0x29ae`：`0x29ae` 即 10670；`0#24 ..` 表示"24 个 0 拼接 8 位"，正是 C 整型提升里 `unsigned char` 升 int 的零扩展（[[#2.2 BitVec：定宽与回绕|2.2 节]]的 `ZeroExt`）。
4. 差为 13；最后两条已被求解器化简成 `== 103`、`== 114`（103 ^ 0x16 反推、114 - 11 合并）。

`key_0_32` 是 angr 把 4 字节符号量按 32 位统一存放的内部表示，`[31:24]` 是 claripy 的切片写法（高位在前），即第 1 个字节。末尾三个读取接口：`eval` 给一个可行解（`b'angr'`）；`eval_one` 只在解唯一时返回单个值，多解时报 `Concretized ... must be exactly 1`；`eval_upto(x, 10)` 列出至多 10 个可行值——这里返回 `[97]`，==同时证明了 s[0] 在该路径下唯一==。

把转储里的校验约束手工翻成 z3（只翻校验本身，strlen 的形状不必复刻，补一个长度范围即可）：

```python
# b3.py —— 把上面读出的校验约束手工翻成 z3
import z3

k = [z3.BitVec(f"k{i}", 8) for i in range(4)]
s = z3.Solver()
# C 里 s[0]*s[1] 是 int 乘法（整型提升），不会按 8 位回绕：
# 对应做法是把字节零扩展成 16 位再乘
s.add(z3.ZeroExt(8, k[0]) * z3.ZeroExt(8, k[1]) == 10670)
s.add(k[1] - k[0] == 13)
s.add((k[2] ^ 0x16) == 0x71)
s.add(k[3] - 11 == 103)
print("check:", s.check())
m = s.model()
key = bytes(m[k[i]].as_long() for i in range(4))
print("key =", key.decode())
```

输出：

```
check: sat
key = angr
```

与 angr 的 `eval` 结果一致。==两条路的分工：angr 负责"把约束收集出来"，z3 负责"把约束解出来"==；angr 自带的 `state.solver` 就是把这两步焊在一起的便捷层。约束导出还有第三种形态——直接把 claripy 表达式转成 z3 表达式丢给 Solver，但它依赖 claripy 的内部后端接口，在新版本里可用性不稳定，跨版本脚本别依赖它，==手抄约束建模才是可移植的备用方案==。

> [!info]- claripy 表达式与 z3 表达式的转换（老版本接口）
> angr 9.x 的独立 claripy 提供 `claripy.backends.z3.convert(expr)`，能把路径约束原样变成 z3 表达式，接进自己的 `z3.Solver` 做增量求解或优化。angr 10 起 claripy 并入 angr（`angr.claripy`），该后端接口不再暴露。遇到老题库脚本报 `no attribute 'backends'`，就是这个原因；改写成 b3.py 的手抄建模即可，几条约束的建模成本通常低于修补接口。

## 6. unicorn：单独执行一个函数

z3 解方程，angr 跑整个程序，夹在中间还有第三种需求：==不跑整个程序，只把某个函数的机器码执行一遍==——比如"这个变换函数输入 `0x12345678` 之后返回什么"。unicorn 是 CPU 模拟器：它只模拟 CPU（取指、译码、执行、寄存器、内存映射），没有 ELF 加载、没有系统调用、没有 libc。给它字节，它执行指令。

安装：`pip3 install unicorn`，`from unicorn import Uc` 即用。本章按 unicorn 2.1 的 API 编写。

### 6.1 准备：自编译函数与机器码抠取

目标函数带一个 8 轮循环和两个大常数，逻辑读起来不轻松，但作为纯函数它不碰任何外部资源——正好是 unicorn 的适用形态：

```c
/* fn.c —— 目标函数 fn + 一个打印对照结果的 main */
#include <stdio.h>

unsigned long long fn(unsigned long long x) {
    unsigned long long h = x ^ 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < 8; i++) {
        h ^= h >> 13;
        h *= 0x2545F4914F6CDD1DULL;
        h ^= h >> 32;
    }
    return h;
}

int main(void) {
    printf("%llx\n", fn(0x1234567890ABCDEFULL));
    printf("%llx\n", fn(1));
    return 0;
}
```

编译后用 objdump 抠出 `<fn>` 的机器码（[[R05-静态分析工具链IDA与Ghidra#2.3 objdump：定位 main 并读出校验逻辑|R05 2.3]]的定位手法，x86-64 Linux，`gcc -O0`）：

```bash
gcc -O0 -fno-pie -no-pie fn.c -o fn
objdump -d -M intel fn | sed -n '/<fn>:/,/^$/p'
```

输出：

```asm
0000000000401136 <fn>:
  401136:	f3 0f 1e fa          	endbr64
  40113a:	55                   	push   rbp
  40113b:	48 89 e5             	mov    rbp,rsp
  40113e:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
  401142:	48 b8 15 7c 4a 7f b9 	movabs rax,0x9e3779b97f4a7c15
  401149:	79 37 9e 
  40114c:	48 33 45 e8          	xor    rax,QWORD PTR [rbp-0x18]
  401150:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  401154:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
  40115b:	eb 32                	jmp    40118f <fn+0x59>
  40115d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401161:	48 c1 e8 0d          	shr    rax,0xd
  401165:	48 31 45 f8          	xor    QWORD PTR [rbp-0x8],rax
  401169:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  40116d:	48 ba 1d dd 6c 4f 91 	movabs rdx,0x2545f4914f6cdd1d
  401174:	f4 45 25 
  401177:	48 0f af c2          	imul   rax,rdx
  40117b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  40117f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401183:	48 c1 e8 20          	shr    rax,0x20
  401187:	48 31 45 f8          	xor    QWORD PTR [rbp-0x8],rax
  40118b:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
  40118f:	83 7d f4 07          	cmp    DWORD PTR [rbp-0xc],0x7
  401193:	7e c8                	jle    40115d <fn+0x27>
  401195:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401199:	5d                   	pop    rbp
  40119a:	c3                   	ret
```

两个事实决定了"抠出来单独跑"可行：这个函数只访问栈（`[rbp-0x18]` 一带的局部槽）和立即数，不碰任何全局数据、不调用任何函数；参数与返回值全按寄存器走（[[R03-x86与x64汇编精要复习|R03]]的 System V AMD64 ABI：第 1 参数 rdi，返回值 rax）。

### 6.2 映射、执行、读返回值

```python
# u1.py —— 从 objdump 抠出 fn 的机器码，用 unicorn 映射执行
import re
import subprocess

out = subprocess.run(["objdump", "-d", "-M", "intel", "./fn"],
                     capture_output=True, text=True).stdout

seg = re.search(r"<fn>:\n(.*?)\n\s*\n", out, re.S).group(1)   # 截取 <fn> 到空行
chunks = []
for line in seg.splitlines():
    m = re.match(r"\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )*[0-9a-f]{2})", line)
    if m:
        chunks.append(m.group(2).replace(" ", ""))
code = bytes.fromhex("".join(chunks))
base = int(re.search(r"^([0-9a-f]+) <fn>:", out, re.M).group(1), 16)
print("fn 的机器码共", len(code), "字节，入口地址", hex(base))

from unicorn import Uc
from unicorn import UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RDI, UC_X86_REG_RAX

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(base & ~0xFFF, 0x4000)          # 代码页（按页对齐映射，沿用原地址）
mu.mem_write(base, code)

STACK_TOP = 0x7FFF0000
mu.mem_map(STACK_TOP - 0x100000, 0x200000) # 划 2 MB 当栈用
TRAP = base + 0x2000                       # 假返回地址：预放一条 ret 当停止点
mu.mem_write(TRAP, b"\xc3")

def call(x):
    rsp = STACK_TOP - 0x1000
    rsp -= 8                                # 按调用约定压入返回地址
    mu.mem_write(rsp, TRAP.to_bytes(8, "little"))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RDI, x)         # 第 1 参数走 rdi（System V AMD64 ABI）
    mu.emu_start(base, TRAP)                # 跑到"返回地址"即停（停在此之前）
    return mu.reg_read(UC_X86_REG_RAX)      # 返回值在 rax

print("fn(0x1234567890ABCDEF) =", hex(call(0x1234567890ABCDEF)))
print("fn(1)                  =", hex(call(1)))
```

输出：

```
fn 的机器码共 101 字节，入口地址 0x401136
fn(0x1234567890ABCDEF) = 0xa9e2f8a91a225535
fn(1)                  = 0x7747d72b53e1385b
```

与原生的结果对照——`./fn` 直接运行，两个值逐字符相同：

```bash
./fn
```

输出：

```
a9e2f8a91a225535
7747d72b53e1385b
```

流程拆解：

- **映射**：`mem_map` 以页为单位划分内存。代码页沿用原地址（`base & ~0xFFF` 对齐到页首），这样机器码里的相对跳转原样成立；栈区另划 2 MB。
- **调用约定手工摆**：`rsp` 指向的位置写上 8 字节的"返回地址"，`rdi` 放第 1 参数——这就是 call 指令在真实机器上做的事，unicorn 不会替你做。
- **停止点**：`emu_start(begin, until)` 执行到 rip 等于 `until` 时停下。把 until 设为预放了 `ret`（`b"\xc3"`）的假返回地址：fn 自己的 `ret` 弹出这个地址跳过去，==到达停止点、那条 ret 还没执行时模拟已停==，此时 rax 里就是返回值。
- 机器码的抠取用正则解析 objdump 的指令字节列；把对象换成真实赛题时，也可以从 IDA/反编译工具里按地址导出字节。

> [!info]- unicorn 的能力边界
> 模拟的 CPU 之外什么都没有：函数里出现对外部库的调用（`call printf@plt`）、系统调用、全局数据访问，就需要自己补映射（把目标页构造好）或用 unicorn 的 hook 机制拦截地址伪造行为。所以它最适合==自包含的算法函数==（校验变换、哈希轮函数、解码器）。angr 内部也集成了 unicorn 作为具体执行的引擎之一（`angr.options` 里以 `UNICORN` 开头的选项控制其行为）；在 angr 之外单独用 unicorn，就是只借用它"执行指令"这一层能力。

## 7. 局限与工程判断：什么时候不用自动化

### 7.1 路径爆炸与求解成本

符号执行的成本由两个量决定：

- **路径数量**：每个依赖符号输入的条件分支让状态数翻倍，$b$ 个这样的分支理论上界是 $2^b$ 条路径。逐字节比较的 crackme 每字节省一次分叉，8 字节是可控的几十个状态；但循环里带数据相关分支时，每圈翻倍，几十圈就到天文数字。==大循环、复杂哈希、逐轮加密是路径爆炸的高发场景==。
- **单个约束的求解难度**：约束是线性异或、加减法时 z3 瞬时出解；出现乘法、除法混合时明显变慢；出现密码学原语（AES 轮函数、哈希压缩）时==等价于要求求解器破译算法，实际上无解==。

缓解手段按代价从低到高：find/avoid 条件收紧（少留无用状态）；把输入长度在符号化时就定死（消灭 strlen 一族建模）；对超长循环改用手工 z3 建模（只建模一轮，外层循环自己写）；最后才是回到 [[R06-动态调试GDB与x64dbg|R06]]——断点读中间值，或 [[R07-编码与算法识别还原|R07]]手逆算法。

### 7.2 决策表

| 局面 | 首选 | 理由 |
| ---- | ---- | ---- |
| 逐字节独立、线性可逆（`^ 0x37` 一类） | 手逆（[[R05-静态分析工具链IDA与Ghidra\|R05]] / [[R07-编码与算法识别还原\|R07]]） | 抄公式直接算，比搭框架快 |
| 字节间耦合、乘除混合 | z3 手工建模 | 读懂伪代码后建模直白，求解瞬时 |
| 分支多、不想逐个读逻辑 | angr explore | 框架代劳收集约束 |
| 多轮哈希、分组加密当校验 | 手逆算法或动态调试（[[R06-动态调试GDB与x64dbg\|R06]]） | 求解器解不动密码学原语 |
| 假分支、诱饵输出 | angr find + avoid | 在状态层剔除，不用改程序 |
| 算法函数只想看输出 | unicorn 单函数模拟 | 不跑整个程序，不碰反分析 |
| 去平坦化混淆 | 先处理控制流（[[R11-代码混淆花指令与OLLVM\|R11]]）再上 angr | 控制流展平后分支条件还原成真实比较，angr 收集到的约束才有干净形状 |
| VM 保护 | 先手逆解释器（[[R12-虚拟机保护VM逆向\|R12]]），字节码语义交给 z3 | angr 直接探索 VM 循环，每条虚拟指令一次分叉，路径立刻爆炸 |

与对抗技术的衔接各一句：[[R10-反调试与反分析对抗|R10]]的 ptrace 类反调试对 angr 天然无效（angr 不启动真实进程，`ptrace` 有预置替身）；但"检测到调试器就走上当分支"的逻辑仍会被符号执行走到，照 [[#5.1 假分支与 avoid|5.1 节]]的办法 avoid 或让对应替身返回假值即可。[[R11-代码混淆花指令与OLLVM|R11]]去平坦化是 angr 的前置工序，[[R12-虚拟机保护VM逆向|R12]]的手逆产物（虚拟指令的语义）是 z3 建模的原料——==在攻防链的哪个环节使用自动化工具，比工具本身更重要==。

> [!warning] 版本差异是 angr 的第一坑
> angr 迭代快，博客与题库脚本常与当前版本脱节。本章按 angr 10、z3-solver 5.1、unicorn 2.1 的 API 编写，三处高频差异提前声明：① claripy 从 `angr.claripy` 导入，老脚本的 `import claripy` 会报 `ModuleNotFoundError`；② 老版本独立的 `claripy.backends` 转换接口在 angr 10 不存在（见 5.2 的折叠框）；③ `blank_state` 系列的内存端序等初始化行为与旧教程出入较大，本章全程用 `entry_state` 规避。遇到 API 报错，先核对 `pip3 show angr` 的版本，再对照官方文档（docs.angr.org）对应章节。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| explore 一直不出结果 | 路径爆炸或 find 条件永远不满足。先手动运行程序确认输出串真的存在；再用 avoid 剔除明显无关的分支；把输入长度提前定死；仍不行按 [[#7.2 决策表\|7.2]]的决策表换路 |
| `simgr.found` 是空的 | find 条件写错（检查的是 stdin 而非 `dumps(1)`）、字符串不匹配（Correct 大小写）、或状态全进了 `deadended`/`unconstrained`。打印 `{k: len(v) for k, v in simgr.stashes.items()}` 看分布 |
| 解出的输入喂回程序是 Wrong | 建模漏约束（见 [[#2.4 实战：异或 + 加法方程组的纯 z3 求解\|2.4]]的锚点教训）；或取解时切错了字节（`eval` 结果含结束符/长度不同）；把 `state.solver.constraints` 逐条对照程序校验 |
| `state.solver.eval_one` 报 `Concretized ... must be exactly 1` | 该符号量在当前约束下有多个可行解——这正是程序的真实行为。换 `eval_upto` 列出全部，再补约束区分 |
| angr 启动刷一屏 WARNING | 是日志不是错误；`logging.getLogger("angr").setLevel(logging.ERROR)` 调低级别，排错时删掉 |
| `import claripy` 报 ModuleNotFoundError | angr 10 起 claripy 并入主包，改 `angr.claripy`（见 [[#7.2 决策表\|7.2]]的版本差异声明） |
| z3 `check()` 返回 unknown | 约束超出求解器能力，常见于 `Int` 上的非线性乘除。改用定宽 `BitVec` 建模，多数机器字问题都在其能力圈内 |
| z3 的解"差一点" | 三查：漏 `& 0xFF`（用了 `Int` 而非 BitVec）、有符号无符号接反（`<` 默认有符号，无符号用 `ULT`）、常量抄错位序（小端读取的表项见 [[R05-静态分析工具链IDA与Ghidra#2.4 objdump -s：读取常量表\|R05 2.4]]） |
| unicorn 报 Invalid memory read / write | 访问了没映射的页：栈没划、全局数据没写、停止点没放。按 [[#6.2 映射、执行、读返回值\|6.2]]的三步映射逐一核对函数实际访问的地址（对照反汇编里的内存操作数） |
| angr 分析大程序极慢 | 全量 CFG 与大规模 explore 的正常代价。crackme 思路改为：定位校验函数（[[R05-静态分析工具链IDA与Ghidra\|R05]]），只对它手工建模（z3）或从该函数地址起跑分析 |
| `pip3 install angr` 装不上 | 无 root 时用 `pip3 install --user --break-system-packages angr z3-solver unicorn`；angr 依赖多，装一次长期用 |

## 9. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **angr 复现（赛题一）**：angr 官方练习库 angr_ctf（GitHub 仓库 `angr/angr_ctf`，含配套讲义）按关卡递进，完成 `00_angr_find` 与 `02_angr_avoid` 两关——分别对应本章实战一、实战二的题型，做完再对照官方 solution 目录里的参考脚本。
> 2. **z3 复现（赛题二，约束题）**：picoCTF（picoctf.org，免费注册，picoGym 常年开放）的 Reverse Engineering 分类有著名的 vault-door 系列（vault-door-training 起、编号递增）：先反编译读出逐字符变换伪代码，再把变换写成 z3 约束求解。任选两关，其中至少一关不用手逆、纯 z3 建模通过。
> 3. **改错实验**：把 [[#2.4 实战：异或 + 加法方程组的纯 z3 求解|2.4 节]]`z3solve.py` 的锚点约束删掉重解，把解喂回 `./zm`，复现"模型少一条约束，解就不是程序的解"。
> 4. **unicorn 实验**：把 [[#6. unicorn：单独执行一个函数|第 6 节]]的 `fn` 换成任一 [[R07-编码与算法识别还原|R07]]里的自实现算法函数（如 TEA 的加密函数），抠机器码、映射执行，与 Python 复现版对照输出。

延伸阅读：

- angr 官方文档：<https://docs.angr.org>——核心概念（Project / SimState / SimulationManager / 探索技术）与版本 API 的第一参考。
- z3 官方教程：Z3 API in Python（Microsoft 的 z3guide）——位向量、量词、优化器（Optimize）等本章未展开的能力。
- Unicorn 引擎文档：<https://docs.unicorn-engine.org>——内存映射、hook、多架构支持。
- angr_ctf 讲义：第 5、6 关之后涉及符号寄存器与内存，是本章流程的自然续篇。
