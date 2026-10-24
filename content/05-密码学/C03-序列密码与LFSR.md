---
chapter: 密码学
section: 序列密码与 LFSR
order: 703
tags:
  - CTF
  - 密码学
  - 序列密码
  - LFSR
publish: true
---

# C03 序列密码与 LFSR
## Stream Ciphers & LFSR

> [!info]- 章节信息
> **所属方向**：密码学 ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[09-密码学基础|09 章]]
> **本章目标**：回答 [[09-密码学基础|09 章]] XOR 加密留下的那个问题——密钥流从哪来，以及它怎么被攻破。具体包括：手写 n 级 LFSR 流密码加密器并用 2n 位已知明文配 GF(2) 高斯消元恢复抽头；掌握 Berlekamp-Massey 算法，在不知道级数与抽头时直接从密钥流恢复最短线性递推，并与 sage 的实现对照；用相关性攻击攻破 Geffe 组合器；手写 RC4 并复盘 WEP 的死因；认识 ChaCha20/Salsa20 为什么至今没有被攻破。

## 1. 从 XOR 到流密码

[[09-密码学基础#3.1 XOR 与一次一密|09 章 3.1]] 给过 XOR 加密的安全上限：密钥与明文等长、真随机、只用一次的一次一密（OTP），唯一被数学证明绝对安全的方案。[[09-密码学基础#3.2 密钥重用即死刑|09 章 3.2]] 则演示了重用的后果：同一个密钥异或两次后，密钥在两次异或里消掉，攻击者直接得到两段明文的 XOR。OTP 无法工程化的原因只有一条——密钥与明文等长且必须真随机。流密码（stream cipher）的思路是把"真随机长密钥"换成"短密钥 + 确定性生成器"：

$$c_i = m_i \oplus z_i, \qquad z_0, z_1, z_2, \dots = G(K) \tag{3.1}$$

$K$ 是很短的密钥（几十字节量级），$G$ 是公开的确定性算法，把 $K$ 扩展成任意长的==密钥流== $z$。解密方用同一个 $K$ 生成同一条 $z$，再异或一次即得明文。

==流密码把安全性全部压在密钥流生成器 $G$ 上==。$G$ 满足的要求只有一条：不知道 $K$ 时，看到 $z$ 的任意长一段也推不出下一位。本章的主角 LFSR 是历史上最著名的一族 $G$，本章也将逐层展示它的致命缺陷——纯线性。种子与随机性来源另一侧的攻防（种子怎么被猜、状态怎么被恢复）在 [[C04-随机数攻防]] 展开，本章只假定种子（即密钥 $K$）本身安全。

按密钥流是否依赖明文，流密码分两类，各记一句即可：

- **同步流密码**（synchronous）：密钥流只由 $K$ 决定，与明文密文无关。通信双方必须保持位同步，丢一位之后全部错位。本章的 LFSR、RC4、ChaCha20 都是这一类。
- **自同步流密码**（self-synchronizing）：每一位密钥流由 $K$ 和前若干位密文共同决定，密文丢一位后接收方能自动恢复同步。分组密码的 CFB 模式是这种构造的代表。

CTF 里的 XOR 类流密码题绝大多数是同步的：出题人一口气生成整条密钥流再加密，攻击也只针对密钥流本身。

## 2. LFSR：线性反馈移位寄存器

### 2.1 结构与递推

LFSR（Linear Feedback Shift Register，线性反馈移位寄存器）由 $n$ 个单元组成，每个单元存一个 GF(2) 位。GF(2) 是只含 0 和 1 的域：加法即异或，乘法即与，减法与加法相同。本章全部运算都在 GF(2) 上进行。

寄存器保存最近的 $n$ 位输出 $s_{k-1}, \dots, s_{k-n}$，称为**状态**。每个时钟周期按固定规则算出下一 位：

$$s_k = c_1 s_{k-1} \oplus c_2 s_{k-2} \oplus \cdots \oplus c_n s_{k-n} \tag{3.2}$$

$c_1, \dots, c_n$ 是固定的 0/1 系数，称为**抽头**（tap）：值为 1 的位置参与异或，值为 0 的位置不参与。初始状态 $s_0, \dots, s_{n-1}$ 就是密钥——算法与抽头公开，只有这 $n$ 位保密。

递推 (3.2) 对应两个多项式，后文会反复出现：

- **连接多项式** $C(x) = 1 + c_1 x + c_2 x^2 + \cdots + c_n x^n$（升幂）；
- **特征多项式** $f(x) = x^n + c_1 x^{n-1} + \cdots + c_n$（降幂）。

两者互为倒数（$x^n \cdot C(1/x) = f(x)$），描述同一颗 LFSR。=="c 系数列表"与"多项式系数"方向相反是 LFSR 题最常见的笔误来源==，本章代码统一采用"$c_1$ 配最新的 $s$"这一种约定，遇到 sage 输出时的方向换算见 [[#4.4 与 sage 对照：两个靶子|4.4]]。

> [!info]- sage 对照：本章用到的特征多项式都是本原的
> 本章 5 颗 LFSR 的特征多项式先用 sage 确认本原性（判定方法见 [[#2.2 周期与 m 序列|2.2]]）：
>
> ```bash
> sage poly_check.sage
> ```
>
> 输出：
>
> ```
> x^8 + x^6 + x^5 + x^4 + 1 -> 本原: True
> x^10 + x^3 + 1 -> 本原: True
> x^5 + x^2 + 1 -> 本原: True
> x^7 + x + 1 -> 本原: True
> x^8 + x^4 + x^3 + x^2 + 1 -> 本原: True
> ```
>
> `poly_check.sage` 全文：
>
> ```python
> # poly_check.sage —— 本章用到的 GF(2) 特征多项式对照
> R.<x> = GF(2)[]
> for f in [x^8 + x^6 + x^5 + x^4 + 1,
>           x^10 + x^3 + 1,
>           x^5 + x^2 + 1,
>           x^7 + x + 1,
>           x^8 + x^4 + x^3 + x^2 + 1]:
>     print(f, "-> 本原:", bool(f.is_primitive()))
> ```
>
> sage 与 pycryptodome 的安装配置见 [[C01-密码学导论与工具链]]。

### 2.2 周期与 m 序列

状态共 $2^n$ 种。全零状态经递推 (3.2) 后仍是全零——0 异或 0 还是 0，寄存器死在原地，所以==初始状态必须非零==，可用状态 $2^n - 1$ 个，序列周期不超过 $2^n - 1$。

==当特征多项式 $f(x)$ 是 $n$ 次本原多项式时，任何非零初始状态的周期都恰好是 $2^n - 1$，这样的输出序列称为 m 序列（最大长度序列）==。"本原"指 $n$ 次不可约、且在 GF(2) 上整除 $x^{2^n-1}+1$ 而不整除任何更小指数的同次幂；不可约与阶的严格定义在数论进阶一章（C02-数论进阶与原根）展开，本章直接取用"本原多项式可以查表或用 sage 判定"这个结论。

m 序列的统计性质相当好：一个周期内 1 比 0 恰好多一个，自相关函数取值集中。单看统计指标，m 序列接近随机序列。==统计指标合格不等于密码学安全==——第 3、4 节会利用它的代数性质直接解出整颗寄存器。

### 2.3 实现与靶子

一颗 $n$ 级 LFSR 的加密器，`c` 是抽头列表、`seed` 是初始状态，几十行以内：

```python
# lfsr_demo.py —— 8 级 LFSR：递推实现、周期统计、加密靶子
# 约定：密钥流是 GF(2) 序列 s_0, s_1, s_2, ...，初始状态 seed = [s_0, ..., s_{n-1}]
#       递推 s_k = c1*s_{k-1} + c2*s_{k-2} + ... + cn*s_{k-n}（GF(2) 加法即异或）

def lfsr_bits(c, seed, length):
    """c = [c1..cn] 反馈系数，seed = [s_0..s_{n-1}]，返回前 length 位"""
    s = list(seed)
    n = len(c)
    while len(s) < length:
        nxt = 0
        for i in range(n):                  # c_{i+1} 配 s_{k-i-1}
            nxt ^= c[i] * s[-1 - i]
        s.append(nxt)
    return s[:length]

def bytes_to_bits(data):
    """字节串 -> 位串（每字节高位在前）"""
    return [(b >> (7 - i)) & 1 for b in data for i in range(8)]

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)

# 8 级，特征多项式 f(x) = x^8 + x^6 + x^5 + x^4 + 1（本原，sage 对照见 2.1）
c8 = [0, 1, 1, 1, 0, 0, 0, 1]               # [c1..c8]：s_k = s_{k-2}+s_{k-3}+s_{k-4}+s_{k-8}
seed8 = [1, 0, 0, 1, 1, 1, 0, 1]            # 初始状态 = 密钥（必须非零）

# —— 周期：状态窗口 [s_t, ..., s_{t+7}] 首次回到 seed ——
s = lfsr_bits(c8, seed8, 2 ** 8 + 8)
period = next(t for t in range(1, 2 ** 8) if s[t:t + 8] == seed8)
print("周期 =", period, "（2^8 - 1 =", 2 ** 8 - 1, "）")
print("一个周期内 1 的个数 =", sum(s[:period]), "，0 的个数 =", period - sum(s[:period]))

# —— 靶子：用这颗 LFSR 加密 flag，发布密文与已知明文片段 ——
flag = b"flag{lfsr_1s_l1n34r}"
ks = bits_to_bytes(lfsr_bits(c8, seed8, 8 * len(flag)))
ct = bytes(a ^ b for a, b in zip(flag, ks))
print("密文(hex):", ct.hex())
print("攻击者已知: 明文以 b'flag{' 开头")
```

```bash
python3 lfsr_demo.py
```

输出：

```
周期 = 255 （2^8 - 1 = 255 ）
一个周期内 1 的个数 = 128 ，0 的个数 = 127
密文(hex): fbfe0113f54c4a096dbb188603749da5c4afcb2f
攻击者已知: 明文以 b'flag{' 开头
```

周期 255 与 2.2 的结论一致；一个周期内 1 的个数 128、0 的个数 127 正是 m 序列的平衡性质。后半段是本章的第一个靶子：抽头 $c_8$ 与种子 $seed_8$ 都不公开，攻击者拿到的只有 20 字节密文，外加"明文以 `flag{` 开头"这条常识。第 3 节的目标就是只用这些信息解出 flag。

> [!warning] 初始状态给全零，LFSR 停在全零
> 全零状态是递推 (3.2) 的不动点：反馈位算出来还是 0，寄存器永远输出全零，密钥流退化成一条零串。凡是手写 LFSR（包括做题时代替出题人补全加密脚本），先检查种子非零；反过来，遇到"密钥流全是 0、密文就是明文"的题，第一反应是种子被置零了。

> [!info]- 硬件视角：LFSR 为什么流行
> (3.2) 在硬件上就是 n 个触发器加若干个异或门：移位是时钟驱动的自然动作，抽头决定了把哪些位引回输入端。没有乘法、没有查表、没有进位链，几个门电路就能产出周期 $2^n-1$ 的序列——这是 LFSR 从 20 世纪 50 年代起被大量用于扩频、CRC、 scrambler 与流密码的原因，也是 GSM 加密（A5/1）、蓝牙加密（E0）当年都以 LFSR 为骨架的原因。软件世界里它同样廉价：本章的 `lfsr_bits` 每生成一位只做 $n$ 次与和异或。

## 3. 已知明文恢复 LFSR：GF(2) 方程组与高斯消元

### 3.1 第一步：从已知明文拿到密钥流

XOR 的自反性（[[09-密码学基础#3.1 XOR 与一次一密|09 章 3.1]]）给出攻击起点：$m \oplus c = m \oplus m \oplus z = z$。==已知明文与密文异或，剩下的就是密钥流==。靶子里已知明文以 `flag{` 开头，5 个字节 = 40 位密钥流到手。这个 crib 来源与 [[09-密码学基础#3.2 密钥重用即死刑|09 章 3.2]] 的 crib dragging 是同一套资源库：flag 前缀、协议头、JSON 字段名、常见英文词。

### 3.2 方程组与 GF(2) 高斯消元

8 级 LFSR 的未知量只有 $c_1, \dots, c_8$ 共 8 个 GF(2) 未知数。递推 (3.2) 对每个 $k \ge n$ 给出一条线性方程，从 40 位已知密钥流里取 $k = 8, \dots, 15$ 这 8 条就够：

$$\begin{pmatrix} s_8 \\ s_9 \\ \vdots \\ s_{15} \end{pmatrix} = \begin{pmatrix} s_7 & s_6 & \cdots & s_0 \\ s_8 & s_7 & \cdots & s_1 \\ \vdots & \vdots & & \vdots \\ s_{14} & s_{13} & \cdots & s_7 \end{pmatrix} \begin{pmatrix} c_1 \\ c_2 \\ \vdots \\ c_8 \end{pmatrix} \tag{3.3}$$

这就是著名的结论：==n 级 LFSR 只需要 2n 位密钥流即可完全解出——n 位当初态，n 位解抽头==。解方程用高斯消元，GF(2) 版比实数版还简单：行变换只有"交换"和"异或"两种（减法即加法），选主元就是找该列为 1 的行，不存在主元绝对值大小的问题。

### 3.3 完整攻击

```python
# lfsr_attack.py —— 已知明文恢复 8 级 LFSR：GF(2) 方程组 + 高斯消元
def lfsr_bits(c, seed, length):
    s = list(seed)
    n = len(c)
    while len(s) < length:
        nxt = 0
        for i in range(n):
            nxt ^= c[i] * s[-1 - i]
        s.append(nxt)
    return s[:length]

def bytes_to_bits(data):
    return [(b >> (7 - i)) & 1 for b in data for i in range(8)]

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)

ct = bytes.fromhex("fbfe0113f54c4a096dbb188603749da5c4afcb2f")  # lfsr_demo.py 的输出
known = b"flag{"                              # 已知明文片段，5 字节 = 40 位
ks = [a ^ b for a, b in zip(bytes_to_bits(known), bytes_to_bits(ct))]   # 密钥流前 40 位
n = 8
print("拿到的密钥流位数:", len(ks), " 解方程需要 2n =", 2 * n, "位")

# 方程组：对 k = n..2n-1，s_k = c1*s_{k-1} + ... + cn*s_{k-n}（增广列放最右）
rows = [[ks[k - 1 - i] for i in range(n)] + [ks[k]] for k in range(n, 2 * n)]
for r in rows:
    print("  ", r)

# GF(2) 高斯消元：加减法都是异或，主元 = 该列上的 1
for col in range(n):
    piv = next(r for r in range(col, n) if rows[r][col])
    rows[col], rows[piv] = rows[piv], rows[col]
    for r in range(n):
        if r != col and rows[r][col]:
            rows[r] = [a ^ b for a, b in zip(rows[r], rows[col])]
c = [rows[i][n] for i in range(n)]
print("恢复的反馈系数 [c1..c8] =", c)

ok = all(sum(c[i] * ks[k - 1 - i] for i in range(n)) % 2 == ks[k] for k in range(n, len(ks)))
print("已知 40 位验算递推全部成立:", ok)

stream = lfsr_bits(c, ks[:n], 8 * len(ct))    # 初态 = 密钥流前 8 位
flag = bytes(a ^ b for a, b in zip(ct, bits_to_bytes(stream)))
print("解密:", flag)
```

```bash
python3 lfsr_attack.py
```

输出：

```
拿到的密钥流位数: 40  解方程需要 2n = 16 位
   [1, 0, 1, 1, 1, 0, 0, 1, 1]
   [1, 1, 0, 1, 1, 1, 0, 0, 0]
   [0, 1, 1, 0, 1, 1, 1, 0, 0]
   [0, 0, 1, 1, 0, 1, 1, 1, 1]
   [1, 0, 0, 1, 1, 0, 1, 1, 0]
   [0, 1, 0, 0, 1, 1, 0, 1, 0]
   [0, 0, 1, 0, 0, 1, 1, 0, 1]
   [1, 0, 0, 1, 0, 0, 1, 1, 0]
恢复的反馈系数 [c1..c8] = [0, 1, 1, 1, 0, 0, 0, 1]
已知 40 位验算递推全部成立: True
解密: b'flag{lfsr_1s_l1n34r}'
```

逐段读：

- 40 位已知密钥流远超 2n = 16 位的最低要求，只用前 16 位列方程，余下 24 位留作验算；
- 解出的 $[0, 1, 1, 1, 0, 0, 0, 1]$ 正是第 2 节设定的真实抽头，且 40 位验算全过——方程组在这个密钥流下非奇异、解唯一。极少数种子会使系数矩阵奇异（解不唯一），此时多补几位已知明文再解即可；
- 初态不需要另外恢复：密钥流的前 8 位 $s_0, \dots, s_7$ 本身就是初态。抽头加初态到齐，整条密钥流重生，密文异或回去，flag 出来。

==攻击代价随 n 线性增长（解 n 元方程组），而密钥空间是 $2^n - 1$==。n = 64 时密钥空间 $2^{64} - 1$ 不可穷举，但 128 位已知明文照样能让方程组直接解出——级数再长也救不了纯线性递推，==LFSR 的死因就是"线性"两个字==。

> [!note] 已知位不足 2n 时
> 方程欠定、解不唯一：自由变量的每一组取值对应一颗都能拟合已知段的 LFSR，外推即出错。处理办法还是 crib——回头从协议格式、文件头里再抠几位明文。这也解释了为什么出题人常用 `flag{` 当前缀：它正好是攻击者可以直接使用的已知明文。

## 4. Berlekamp-Massey：从密钥流直接恢复最短线性递推

### 4.1 要解决的问题

第 3 节有一个隐藏假设：攻击者知道 LFSR 的级数 n。实际题目里 n 未必写在脸上——加密脚本可能混淆过、可能用了很多级、可能输出自多颗寄存器之和。Berlekamp-Massey 算法（下称 BM）把这最后一个假设也拿掉：

==给定一段序列，BM 输出能生成它的**最短**线性递推——级数 L 与系数 $c_1, \dots, c_L$==。序列若真出自 n 级 LFSR，只要给出的位数 $\ge 2n$，BM 就返回那颗寄存器（准确说：返回该序列的**最小多项式**对应的递推）。BM 是解 LFSR 问题的标准武器，也是"线性复杂度"这个指标的定义工具，时间复杂度 $O(N^2)$，N 为序列长度。

### 4.2 算法：初始化、不一致度、更新

BM 逐位消化序列，维护这些量（全部在 GF(2) 上）：

| 量 | 含义 |
| --- | --- |
| $C(x) = 1 + c_1 x + \cdots + c_L x^L$ | 当前连接多项式，即"当前认为的递推" |
| $L$ | 当前级数 |
| $B(x)$ | 上一次 $L$ 跳变时 $C$ 的备份 |
| $b$ | 上一次 $L$ 跳变时的不一致度 |
| $m$ | 自上次跳变以来已连续消化多少位 |

初始化：$C(x) = B(x) = 1$，$L = 0$，$m = 1$，$b = 1$。然后对每一位 $s_N$ 循环：

1. **算不一致度**：

$$d = s_N + c_1 s_{N-1} + \cdots + c_L s_{N-L} \tag{3.4}$$

   $d = 0$ 说明当前 $C(x)$ 已经能解释第 $N$ 位，什么都不用改，$m$ 加一，进入下一位；
2. **不一致时更新系数**：

$$C(x) \leftarrow C(x) + x^m \cdot B(x) \tag{3.5}$$

   即把备份 $B(x)$ 平移 $m$ 位后异或进 $C(x)$。GF(2) 上 $d/b$ 恒等于 1（加减同号、1 的逆是 1），一般域版本里的系数缩放在这里消失——这是 GF(2) 版 BM 特别简洁的原因；
3. **判断是否跳级**：若 $2L \le N$，则 $L \leftarrow N + 1 - L$，把旧 $C(x)$ 存入 $B(x)$，记 $b = d$、$m = 1$；否则只更新系数、$m$ 加一。

$B(x)$ 与 $x^m$ 平移的分工：$B(x)$ 是上一次"解释不了"时那版还能用的递推，平移 $m$ 位让它的修正作用恰好对齐当前的失配点。跳级条件 $2L \le N$ 保证每加一级，手里至少有 $2L$ 位支撑——这正是 4.1 里"$2n$ 位确定 $n$ 级"的算法内体现。

### 4.3 手写实现

```python
# bm_attack.py（上半：Berlekamp-Massey 本体）
def berlekamp_massey(s):
    """返回 (L, c)：s_k = c1 s_{k-1} + ... + cL s_{k-L}（GF(2)）
    对应连接多项式 C(x) = 1 + c1 x + ... + cL x^L"""
    n = len(s)
    C = [1] + [0] * n                       # 当前连接多项式的系数
    B = [1] + [0] * n                       # 上一次 L 跳变前的备份
    L, m, b = 0, 1, 1
    for N in range(n):
        d = s[N]                            # 不一致度 d = s_N + C1 s_{N-1} + ... + CL s_{N-L}
        for i in range(1, L + 1):
            d ^= C[i] * s[N - i]
        if d == 0:                          # C 已拟合到第 N 位，窗口右移
            m += 1
        else:
            shift = [0] * (n + 1)
            for i in range(n - m + 1):
                shift[i + m] = B[i]         # x^m * B(x)
            if 2 * L <= N:                  # 级数跳变：加长 L，备份旧 C
                T = C[:]
                C = [x ^ y for x, y in zip(C, shift)]
                L, B, b, m = N + 1 - L, T, d, 1
            else:                           # 级数不变，只改系数
                C = [x ^ y for x, y in zip(C, shift)]
                m += 1
    return L, C[1:L + 1]
```

系数列表按"$C(x) = 1 + c_1 x + \cdots$"的升幂存放，`C[0]` 恒为 1，返回时切掉。

### 4.4 与 sage 对照：两个靶子

驱动脚本（同文件下半）先打第 3 节的靶，再造一个级数、抽头都不同的新靶现场攻击；位串辅助函数与 `lfsr_bits` 与第 3 节相同，不再重复：

```python
# bm_attack.py（下半：靶场驱动）
def check(c, ks):
    L = len(c)
    return all(sum(c[i] * ks[k - 1 - i] for i in range(L)) % 2 == ks[k]
               for k in range(L, len(ks)))

known = b"flag{"

# —— 靶 1：第 3 节的 8 级 LFSR 密钥流 ——
ct1 = bytes.fromhex("fbfe0113f54c4a096dbb188603749da5c4afcb2f")
ks1 = [a ^ b for a, b in zip(bytes_to_bits(known), bytes_to_bits(ct1))]
L1, c1r = berlekamp_massey(ks1)
print("靶 1: BM 恢复 L =", L1, " 抽头 =", c1r, " 递推复现全部已知位:", check(c1r, ks1))
s1 = lfsr_bits(c1r, ks1[:L1], 8 * len(ct1))
print("靶 1 解密:", bytes(a ^ b for a, b in zip(ct1, bits_to_bytes(s1))))

# —— 靶 2：10 级 LFSR，f(x) = x^10 + x^3 + 1；级数与抽头对攻击者未知 ——
flag2 = b"flag{bm_n0_t4ps}"
c10 = [0, 0, 0, 0, 0, 0, 1, 0, 0, 1]        # 真实抽头，只在出题时用：s_k = s_{k-7} + s_{k-10}
seed10 = [1, 1, 0, 1, 0, 0, 1, 0, 1, 1]
ct2 = bytes(a ^ b for a, b in zip(flag2, bits_to_bytes(lfsr_bits(c10, seed10, 8 * len(flag2)))))
print("靶 2 密文(hex):", ct2.hex())
ks2 = [a ^ b for a, b in zip(bytes_to_bits(known), bytes_to_bits(ct2))]
L2, c2r = berlekamp_massey(ks2)
print("靶 2: BM 恢复 L =", L2, " 抽头 =", c2r, " 递推复现全部已知位:", check(c2r, ks2))
s2 = lfsr_bits(c2r, ks2[:L2], 8 * len(ct2))
print("靶 2 解密:", bytes(a ^ b for a, b in zip(ct2, bits_to_bytes(s2))))

import json
json.dump([{"name": "target1", "bits": ks1, "taps": c1r},
           {"name": "target2", "bits": ks2, "taps": c2r}],
          open("bm_data.json", "w"))
print("bm_data.json 已写出，供 sage 对照")
```

```bash
python3 bm_attack.py
```

输出：

```
靶 1: BM 恢复 L = 8  抽头 = [0, 1, 1, 1, 0, 0, 0, 1]  递推复现全部已知位: True
靶 1 解密: b'flag{lfsr_1s_l1n34r}'
靶 2 密文(hex): b4bd770e33a1dadd8b43e4ede1aeb95b
靶 2: BM 恢复 L = 10  抽头 = [0, 0, 0, 0, 0, 0, 1, 0, 0, 1]  递推复现全部已知位: True
靶 2 解密: b'flag{bm_n0_t4ps}'
bm_data.json 已写出，供 sage 对照
```

两个靶双命中：靶 1 恢复的递推与第 3 节高斯消元的结果一致；靶 2 换了级数（10 级）和抽头个数（2 个），BM 在不知道级数的前提下给出 $L = 10$ 与正确的两个抽头，解密同样到手。BM 手写版再用 sage 的 `berlekamp_massey` 对照一遍：

```python
# bm_sage.sage —— sage 的 berlekamp_massey 对照
import json
from sage.matrix.berlekamp_massey import berlekamp_massey

data = json.load(open("bm_data.json"))
for item in data:
    bits = [GF(2)(x) for x in item["bits"]]
    f = berlekamp_massey(bits)
    L = f.degree()
    a = f.list()                            # 升幂系数 [f_L, ..., f_1, 1]
    taps = [int(a[L - i]) for i in range(1, L + 1)]   # 降幂读出 c1..cL
    print(item["name"], ": sage 最小多项式 f(x) =", f, " L =", L)
    print("   按 f(x) = x^L + c1 x^(L-1) + ... + cL 降幂读出的抽头 =", taps,
          " 与手写版一致:", taps == item["taps"])
```

```bash
sage bm_sage.sage
```

输出：

```
target1 : sage 最小多项式 f(x) = x^8 + x^6 + x^5 + x^4 + 1  L = 8
   按 f(x) = x^L + c1 x^(L-1) + ... + cL 降幂读出的抽头 = [0, 1, 1, 1, 0, 0, 0, 1]  与手写版一致: True
target2 : sage 最小多项式 f(x) = x^10 + x^3 + 1  L = 10
   按 f(x) = x^L + c1 x^(L-1) + ... + cL 降幂读出的抽头 = [0, 0, 0, 0, 0, 0, 1, 0, 0, 1]  与手写版一致: True
```

两处对照全部一致，且两个最小多项式正是靶子的特征多项式。==sage 返回的是特征多项式形式（降幂），手写版返回的是递推系数列表（c1 配最新的 s），两者互为倒数，比较前必须统一方向==——[[#2.1 结构与递推|2.1]] 埋的那处方向坑，这里是它的标准现场。

> [!warning] BM 只承诺"最短线性递推"，不承诺"出题人的原设计"
> BM 的输出是能生成**所给那段**序列的最短线性递推，两条边界要记住：
>
> - 密钥流不足 $2L$ 位时，BM 可能收敛到一条假递推——它能复现已给的每一位，外推一步就错。用 BM 结果解密之前，先像 4.4 那样验算"用恢复的递推重新生成整段已知密钥流"，验算不过就继续补 crib；
> - 序列的特征多项式若可约（出题人没选本原多项式），序列的最小多项式可能是它的真因子，BM 给出 $L < n$ 是**正确**结果——此时用 $L$ 级递推照样重生密钥流，攻击不受影响。
>
> 顺带得到流密码体检的第一指标：BM 输出的 $L$ 就是序列的**线性复杂度**（linear complexity）。==一条要当密钥流用的序列，线性复杂度必须接近其长度的一半==；任何 $L$ 明显偏小的序列，BM 都能直接接管。

## 5. 非线性组合与相关性攻击：Geffe 生成器

### 5.1 单 LFSR 之后：非线性组合器

第 3、4 节把"LFSR 当密钥流"判了死刑，症结在纯线性。设计者的自然反应：保留 LFSR 的廉价周期，在输出端加**非线性**——用 $r$ 颗 LFSR 加一个非线性布尔函数 $f: \mathrm{GF}(2)^r \to \mathrm{GF}(2)$ 合并输出，这样的结构叫**组合器**（combiner）。理想中，$f$ 的非线性把 3.3 的方程组与 BM 都挡在门外。

Geffe 生成器是这个思路最早也最出名的尝试：三颗 LFSR，$X$ 做控制位，$Y$、$Z$ 被选择，输出规则是一个二选一开关：

$$out_k = X_k \cdot Y_k \oplus (1 \oplus X_k) \cdot Z_k \tag{3.6}$$

$X_k = 1$ 时输出 $Y_k$，$X_k = 0$ 时输出 $Z_k$。三个密钥空间是乘起来的，看起来"结构复杂度"上了一个台阶。

### 5.2 3/4 相关：开关的统计偏差

盯着 (3.6) 数概率（$X$ 均匀，$Y$、$Z$ 互相独立且与 $X$ 独立）：

- $P(out = Y) = P(X = 1) \cdot 1 + P(X = 0) \cdot P(Y = Z) = \tfrac{1}{2} + \tfrac{1}{2} \cdot \tfrac{1}{2} = \tfrac{3}{4}$；
- 同理 $P(out = Z) = \tfrac{3}{4}$；
- $P(out = X)$ 逐情况枚举恰为 $\tfrac{1}{2}$，$X$ 藏得最好。

==输出与 $Y$、$Z$ 各有 1/4 的统计偏差==。组合器每输出一位，输出与 $Y$（或 $Z$）的一致概率就偏离 $1/2$ 四分之一。这就是**相关性攻击**的入口：不再把三颗寄存器当整体攻（联合密钥空间 $2^{L_X + L_Y + L_Z}$），而是逐个击破——穷举 $Y$ 的全部 $2^{L_Y} - 1$ 个初始状态，数每个候选序列与密钥流的一致位数，真初态的一致率会落在 3/4 附近，错误初态停留在 1/2 附近。代价从 $2^{L_X+L_Y+L_Z}$ 降到三次 $2^L$ 量级。

### 5.3 打靶：小规模 Geffe

靶子参数：$X$ 5 级（$x^5+x^2+1$，周期 31）、$Y$ 7 级（$x^7+x+1$，周期 127）、$Z$ 8 级（$x^8+x^4+x^3+x^2+1$，周期 255），本原性见 [[#2.1 结构与递推|2.1]] 的 sage 对照。明文是 30 字节已知协议头加 16 字节 flag，攻击者有 240 位密钥流：

```python
# geffe.py（上半：出题）—— 算法公开，三个寄存器的初始状态就是密钥
def lfsr_bits(c, seed, length):
    s = list(seed)
    n = len(c)
    while len(s) < length:
        nxt = 0
        for i in range(n):
            nxt ^= c[i] * s[-1 - i]
        s.append(nxt)
    return s[:length]

def bytes_to_bits(data):
    return [(b >> (7 - i)) & 1 for b in data for i in range(8)]

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)

seedX, seedY, seedZ = [1, 0, 1, 1, 0], [1, 1, 0, 0, 1, 0, 1], [0, 1, 1, 1, 0, 0, 1, 0]
cX, cY, cZ = [0, 0, 1, 0, 1], [0, 0, 0, 0, 0, 1, 1], [0, 0, 0, 1, 1, 1, 0, 1]
pt = b"USER=danling;CMD=LOGIN;APPEND;flag{geffe_c0rr}"
N = 8 * len(pt)
X = lfsr_bits(cX, seedX, N)
Y = lfsr_bits(cY, seedY, N)
Z = lfsr_bits(cZ, seedZ, N)
ks = [(x & y) ^ ((1 ^ x) & z) for x, y, z in zip(X, Y, Z)]
ct = bytes(a ^ b for a, b in zip(pt, bits_to_bytes(ks)))
print("明文长度 %d 字节，已知头部 %d 字节 = %d 位密钥流" % (len(pt), len(pt) - 16, N - 128))
print("密文(hex):", ct.hex())
```

攻击部分（同文件下半）：先按 5.2 的思路恢复 $Y$，再用同一招恢复 $Z$，最后 $X$ 走恒等式——把 (3.6) 展开：

$$out \oplus Z = X \cdot Y \oplus X \cdot Z = X \cdot (Y \oplus Z) \tag{3.7}$$

GF(2) 上 $(Y \oplus Z)^2 = Y \oplus Z$，两边同乘 $Y \oplus Z$ 得 $X = (out \oplus Z)(Y \oplus Z)$：凡 $Y \ne Z$ 的位置，$X$ 被直接读出，不需要统计。对 $X$ 的 31 个候选初态在这些可判定位上核对即可。

```python
# geffe.py（下半：相关性攻击）
ksk = [a ^ b for a, b in zip(bytes_to_bits(pt[:-16]), bytes_to_bits(ct))][:N - 128]
M = len(ksk)
print("可用密钥流位数 =", M, "（若 out 与某寄存器不相关，一致率应约 1/2）")

# 1) 相关性攻击恢复 Y：穷举 127 个非零初始状态，数与密钥流的一致位数
scores = []
for v in range(1, 128):
    st = [(v >> (6 - i)) & 1 for i in range(7)]
    y = lfsr_bits(cY, st, M)
    agree = sum(a == b for a, b in zip(y, ksk))
    scores.append((agree, st))
scores.sort(reverse=True)
print("\n对 Y 穷举 127 个非零初态，一致率前 5 名：")
for agree, st in scores[:5]:
    print("   初态 %s  一致 %3d/%d = %.3f" % (st, agree, M, agree / M))
rest = [a for a, _ in scores[5:]]
print("其余 122 个初态的一致率范围: %.3f ~ %.3f" % (rest[-1] / M, rest[0] / M))
Yr = lfsr_bits(cY, scores[0][1], N)

# 2) 同法恢复 Z
scores = []
for v in range(1, 256):
    st = [(v >> (7 - i)) & 1 for i in range(8)]
    z = lfsr_bits(cZ, st, M)
    agree = sum(a == b for a, b in zip(z, ksk))
    scores.append((agree, st))
scores.sort(reverse=True)
print("对 Z 穷举 255 个非零初态，前 2 名：")
for agree, st in scores[:2]:
    print("   初态 %s  一致 %3d/%d = %.3f" % (st, agree, M, agree / M))
Zr = lfsr_bits(cZ, scores[0][1], N)

# 3) 由 out + Z = X*(Y+Z)，在 Y≠Z 的位置直接读出 X 的位
Xest = [None] * M
for i in range(M):
    if Yr[i] != Zr[i]:
        Xest[i] = ksk[i] ^ Zr[i]
npos = sum(1 for b in Xest if b is not None)
scores = []
for v in range(1, 32):
    st = [(v >> (4 - i)) & 1 for i in range(5)]
    x = lfsr_bits(cX, st, M)
    agree = sum(1 for a, b in zip(x, Xest) if b is not None and a == b)
    scores.append((agree, st))
scores.sort(reverse=True)
print("对 X 穷举 31 个非零初态（可判定位共 %d 个），前 2 名：" % npos)
for agree, st in scores[:2]:
    print("   初态 %s  命中 %d/%d" % (st, agree, npos))
Xr = lfsr_bits(cX, scores[0][1], N)

# 4) 三个寄存器到齐，再生整条密钥流，解出含 flag 的完整明文
ksr = [(x & y) ^ ((1 ^ x) & z) for x, y, z in zip(Xr, Yr, Zr)]
recovered = bytes(a ^ b for a, b in zip(ct, bits_to_bytes(ksr)))
print("解密全文:", recovered.decode())
```

```bash
python3 geffe.py
```

输出：

```
明文长度 46 字节，已知头部 30 字节 = 240 位密钥流
密文(hex): 97f8ce90311567f6429c761874601269a833cb23e3bc4bfa297cd51690b9fb5b4713cff73c833bb18754a9c7eba1
可用密钥流位数 = 240 （若 out 与某寄存器不相关，一致率应约 1/2）

对 Y 穷举 127 个非零初态，一致率前 5 名：
   初态 [1, 1, 0, 0, 1, 0, 1]  一致 178/240 = 0.742
   初态 [1, 1, 0, 0, 1, 1, 1]  一致 134/240 = 0.558
   初态 [1, 1, 0, 0, 0, 0, 1]  一致 133/240 = 0.554
   初态 [0, 1, 1, 0, 1, 1, 1]  一致 133/240 = 0.554
   初态 [1, 0, 0, 0, 1, 0, 1]  一致 132/240 = 0.550
其余 122 个初态的一致率范围: 0.438 ~ 0.546
对 Z 穷举 255 个非零初态，前 2 名：
   初态 [0, 1, 1, 1, 0, 0, 1, 0]  一致 166/240 = 0.692
   初态 [1, 0, 0, 0, 0, 0, 1, 0]  一致 139/240 = 0.579
对 X 穷举 31 个非零初态（可判定位共 136 个），前 2 名：
   初态 [1, 0, 1, 1, 0]  命中 136/136
   初态 [1, 0, 1, 0, 1]  命中 72/136
解密全文: USER=danling;CMD=LOGIN;APPEND;flag{geffe_c0rr}
```

读数与 5.2 的理论逐条对应：$Y$ 的真初态以 0.742 排在首位（3/4 = 0.75，240 位样本下有正常波动），错误初态全部落在 1/2 附近，最高 0.558；$Z$ 的真初态 0.692 同样与第二名拉开 0.11；$X$ 按恒等式 (3.7) 在 136 个可判定位上被唯一候选全中。三颗寄存器到齐，整条密钥流重生，完整明文连 flag 一起出来。240 位已知明文就够了——对比第 3 节的 16 位，相关攻击消耗的是统计样本而不是方程，需要的已知明文量大得多。

> [!warning] 靶子参数里的两处讲究
> **寄存器周期必须长于统计窗口**。把 $Y$、$Z$ 换成 4 级寄存器（周期 15）时，240 位窗口里序列重复了十几轮，$Y$ 与 $Z$ 的局部一致率偏离 1/2 很远，3/4 的峰被压扁、甚至可能被某个错误初态越过——相关攻击的前提"候选与密钥流无关部分一致率约 1/2"被短周期相关性破坏。本靶特意选了周期 127、255 大于窗口的 7、8 级寄存器。
> **已知明文量按偏差估算**。偏差是 $\varepsilon = 1/4$，要靠"一致位数"区分真初态与 $2^L - 2$ 个错误初态，位数必须多到让 $\pm\varepsilon$ 的信号盖过 $\sqrt{N}/2$ 量级的随机波动。经验上几百位起步，寄存器越长（候选越多）需要越多；按第 3 节"2n 位"的直觉准备 Geffe 的已知明文，一定不够。

### 5.4 设计教训

==输出与任何单个内部序列存在可测相关，是流密码设计的大忌==。Geffe 的 3/4 相关不是实现 bug，是选择函数本身的性质——相关性攻击连密钥流都不用看完就能逐个击破。组合器要合格，其布尔函数必须做到**相关免疫**（correlation immunity）：输出与任何单个输入序列的一致概率严格保持 1/2，任何偏差都会被 5.3 的穷举放大成突破口。

> [!info]- 真实世界的组合器
> - **A5/1**（GSM 手机加密，1987）：3 颗 19/22/23 级 LFSR 用"多数时钟"不规则步进，2000 年代被穷举-查表与相关攻击在分钟级实用化攻破；
> - **E0**（蓝牙，1999）：4 颗 25/31/33/39 级 LFSR 加有限状态机复合，2005 年的相关攻击把恢复密钥所需的数据量降到实际可收集的规模；
> - **Trivium**（eSTREAM 硬件组入选，2005）：80 位密钥、3 个 20 级非线性反馈寄存器迭代初始化后输出，至今没有比穷举 $2^{80}$ 更好的攻击；
> - **ZUC/祖冲之**（3GPP，2011）：LFSR 驱动非线性函数 F 产出密钥流，用于 4G/5G 机密性保护，公开分析未见实用攻击。
>
> 对比清楚：活下来的设计，共性是输出端有足够的非线性与状态扰动；死掉的设计，都死在 5.2 那类统计偏差上。

## 6. RC4：手写实现与 WEP 之死

### 6.1 算法与实现

RC4（Rivest Cipher 4，1987）是字节制流密码：密钥长度 1–256 字节可变，内部状态是一张 256 字节的重排表 $S$。分两步：

1. **KSA**（Key Scheduling Algorithm）：用密钥把 $S$ 从初态 $[0, 1, \dots, 255]$ 搅乱；
2. **PRGA**（Pseudo-Random Generation Algorithm）：每产出一位密钥流，先交换两个表项，再按表选出输出字节。

```python
# rc4_demo.py —— RC4：KSA + PRGA 手写实现
def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):                      # KSA：用密钥搅乱 S 表
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:                            # PRGA：每步交换一次，取一个密钥流字节
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

flag = b"flag{rc4_w3ak}"
ct = rc4(b"secret", flag)
print("密文(hex):", ct.hex())
print("解密:", rc4(b"secret", ct), " 与原文一致:", rc4(b"secret", ct) == flag)

# 同一密钥对全零明文加密 = 裸露的密钥流；两次生成完全相同
ks1 = rc4(b"secret", bytes(16))
ks2 = rc4(b"secret", bytes(16))
print("同一密钥两次生成的密钥流相同:", ks1 == ks2)
print("密钥流前 16 字节:", ks1.hex())
```

```bash
python3 rc4_demo.py
```

输出：

```
密文(hex): 8b5ab37bf9d6b5926dbc88bd989b
解密: b'flag{rc4_w3ak}'  与原文一致: True
同一密钥两次生成的密钥流相同: True
密钥流前 16 字节: ed36d21c82a4d6a632cbbbdcf3e6f537
```

加密解密是同一个函数：PRGA 只产出密钥流，异或方向天然对称。与 LFSR 对照，RC4 有一个代数上的优点：==密钥流字节由被密钥搅乱的表选出，不存在第 3 节那种线性递推，BM 与方程组都无处下手==。它有一个与 LFSR 共通的弱点：==同一密钥永远生成同一条密钥流==——输出块最后一行就是证据。所以真实协议必须给每条消息配 IV/nonce 并保证不重用，重用即回到 [[09-密码学基础#3.2 密钥重用即死刑|09 章 3.2]] 的死刑判决。RC4 的死因恰好出在这个弱点的补丁环节。

### 6.2 WEP 之死

WEP（Wired Equivalent Privacy，1997）是 802.11 Wi-Fi 的第一代加密，构造是"RC4 + IV"：每发一个包，把 24 位 IV 拼在共享密钥前面，`key = IV ‖ shared_secret`，拿去跑 RC4。24 位只有约 1680 万个取值，繁忙网络几小时内必然重用；不少实现还在重启后把 IV 清零重新计数。IV 与密钥的组合一旦重演，密钥流原样重来，两段密文的异或就是两段明文的异或——[[09-密码学基础#3.2 密钥重用即死刑|09 章 3.2]] 的判决在无线链路上被批量执行，攻击者还可以利用 IV 重用做包注入加速收集。

2001 年的 **FMS 攻击**（Fluhrer-Mantin-Shamir）则指向 RC4 自身：KSA 的结构里存在一批"弱 IV"，使密钥流第一个字节以明显高于随机的概率泄露密钥首字节的取值，被动收集足够多的包后按统计逐字节恢复整个密钥；aircrack-ng 及其后继把这套统计做成一键工具，WEP 的密钥进入分钟级可恢复区间。IEEE 最终用 WPA2（AES-CCMP）整体替换 WEP。RC4 本体的记录同样不可挽回：密钥流前若干字节的取值分布存在可测偏差（第二字节的相对偏差在 $2^{-8}$ 量级），长程输出各位也有统计偏差；2013–2015 年，TLS 中 RC4 流量被这些偏差结合海量样本实际攻破，RFC 7465（2015）明令禁止 RC4 进入 TLS。今天 RC4 只在旧协议兼容层和 CTF 复古题里出现——考法集中在密钥流重用（多条密文异或后 crib dragging）与弱密钥构造上，本章的实现加第 3 节的 crib 手法即可覆盖。

> [!warning] "弃用 RC4"弃的是算法，不是明文
> 存在一个常见误区：以为避开某些敏感明文、或给 RC4 换一套自己的 IV 规则就能继续用。被 RFC 7465 弃用的是 RC4 算法本身连同"密钥拼 IV"这类用法——偏差在密钥流里，与明文内容无关；自造 IV 规则若挡不住重用，只会重演 WEP。CTF 里遇到 RC4 题，攻击入口照例先看：密钥/IV 是否重用、密钥是否可猜可算。

## 7. 现代流密码：ChaCha20 与 Salsa20

RC4 之后，流密码换了一代。**Salsa20**（Bernstein，2005）与其继任 **ChaCha20**（2008）的内核是 ARX 结构：模 $2^{32}$ 加法（Add）、固定长度的循环移位（Rotate）、异或（Xor）三种运算组成的轮函数，迭代 20 轮。密钥 256 位，每条消息配 96 位 nonce，密钥流按块（64 字节）生成。pycryptodome 直接可用：

```python
# chacha_demo.py —— ChaCha20（pycryptodome）
from Crypto.Cipher import ChaCha20
from os import urandom

key = urandom(32)                 # 256 位密钥
nonce = urandom(12)               # 96 位 nonce，每条消息换新
ct = ChaCha20.new(key=key, nonce=nonce).encrypt(b"flag{chacha20_w1ns}")
pt = ChaCha20.new(key=key, nonce=nonce).decrypt(ct)
print("密文(hex):", ct.hex())
print("解密:", pt)

ks = ChaCha20.new(key=key, nonce=nonce).encrypt(bytes(32))   # 全零明文 = 密钥流
print("密钥流前 32 字节:", ks.hex())
```

```bash
python3 chacha_demo.py
```

输出：

```
密文(hex): b2fbe78b2ab0ab97823caee35d2ca9688e7472
解密: b'flag{chacha20_w1ns}'
密钥流前 32 字节: d49786ec51d3c3f6e154cfd16d73de59e0070f02445501db7f279ab94cd5f15e
```

它们取代 RC4 的原因在第 6 节已经列全：输出统计偏差与密钥流重用事故。反过来回答"ChaCha20 被攻破了吗"——==至今没有==。本章列出的死因，它一条都不占：

- **非线性与扩散**：ARX 轮函数不是 GF(2) 线性映射，不存在 BM 能抓的线性递推，输出也没有 RC4 那类已知的统计偏差；
- **nonce 纪律**：协议层强制每消息唯一 nonce，堵死密钥流重用（nonce 重用之后果的攻击面在 [[C04-随机数攻防]] 展开）；
- **常数时间**：软件实现不查表、不分支依赖秘密，天生免疫缓存侧信道——没有 AES 硬件加速的移动设备上，ChaCha20-Poly1305 常是 TLS 1.3 里的性能首选（RFC 8439）。

==被替换的是 RC4，不是流密码这个体制==。eSTREAM 工程选出的硬件向代表 Trivium、软件向代表 ChaCha20 与本章 5.4 的对照组摆在一起，界线分明：现代流密码的安全来自非线性轮函数与严格的 nonce 纪律，而不是来自线性递推的长度。与分组密码的边界也只生成器内部结构这一条：分组密码配 CTR 模式同样是"生成密钥流再异或"，AES 的内部结构在 [[C05-分组密码内部]] 展开。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 恢复的抽头总是对不上已知多项式 | 系数方向反了：$f(x)=x^n+c_1x^{n-1}+\cdots+c_n$ 与 $C(x)=1+c_1x+\cdots+c_nx^n$ 的 $c_1$ 都配"最新的 s"，但一个降幂一个升幂；sage 返回 f 形式、手写 BM 返回系数列表，比较前先统一方向（[[#4.4 与 sage 对照：两个靶子\|4.4]]） |
| 高斯消元解出后外推全错 | 已知明文不足 2n 位，方程组欠定，解不唯一；补 crib（协议头、JSON 字段名）再解；或把位数按字节当位算错了——40 字节是 320 位不是 40 位 |
| BM 给出的 L 比预期小，解密是乱码 | 密钥流少于 $2L$ 位，BM 收敛到假递推：能复现已给段、外推即错；先验算"恢复递推重生整段已知密钥流"，不过就补 crib（[[#4. Berlekamp-Massey：从密钥流直接恢复最短线性递推\|第 4 节]]） |
| 明明出自 n 级 LFSR，BM 却给出更短的递推 | 特征多项式可约时，序列的最小多项式可以是它的真因子，BM 给出 $L<n$ 是正确结果，短递推照样重生密钥流；出题选本原多项式即可避免歧义（[[#2.2 周期与 m 序列\|2.2]]） |
| LFSR 一启动密钥流全是 0 | 初始状态取了全零：全零状态自锁，必须用非零种子（[[#2. LFSR：线性反馈移位寄存器\|第 2 节]]） |
| Geffe 攻击峰值不明显，甚至被错误状态越过 | 两查：已知明文位数不够——偏差 1/4 需要几百位起步，按"2n 位"的直觉准备已知明文必不够；寄存器周期太短——周期小于统计窗口时多周期互相关会压扁峰（[[#5.3 打靶：小规模 Geffe\|5.3]]） |
| Geffe 只恢复了一颗寄存器，整条密钥流再生不出来 | 三颗缺一不可；控制位 X 与输出不相关、无法用一致率挑，但由恒等式 (3.7) 在 Y≠Z 的位置直接读出（[[#5.3 打靶：小规模 Geffe\|5.3]]） |
| RC4 题换了明文还是被解出 | 误区：被弃用的是 RC4 算法与"密钥拼 IV"用法（RFC 7465），偏差在密钥流里、与明文无关；RC4 题的入口是密钥/IV 重用与弱密钥，不是换明文 |
| 两条 ChaCha20 密文相同 | key + nonce 重用：同一组合恒生成同一密钥流；nonce 每消息唯一是硬性要求，随机 nonce 的碰撞余量要按消息数估算（[[C04-随机数攻防]]） |

## 9. 配套练习与延伸阅读

配套练习：

1. 把第 3 节的攻击改成"已知明文只有 3 字节"（24 位，不足 2n）：方程组欠定，观察解出的抽头不止一组、其中只有一组能通过全部 40 位验算；再补 1 个字节 crib 重解。
2. 自选一个 7 级本原多项式（用 2.1 的 sage 对照确认），造一颗新 LFSR 靶子加密 flag，分别用第 3 节的高斯消元与第 4 节的 BM 各解一次，核对两条路给出的抽头一致。
3. 用第 4 节的 `berlekamp_massey` 测第 5 节 Geffe 输出的线性复杂度，再测单颗 LFSR 输出的线性复杂度，对照两者——理解"线性复杂度接近 N/2"为什么是密钥流的第一道体检指标。
4. 把第 5 节的攻击改写为先恢复 Z、再恢复 Y 的版本，并给 Z 的穷举打印完整排行表；思考：哪一步的结果会因交换顺序而变化，哪一步不会。
5. WEP 生日问题小算术：24 位 IV 共 $2^{24}$ 个取值，计算发出 4096 包与 10000 包后 IV 至少重用一次的概率（$p \approx 1 - e^{-n^2/2N}$），对照"繁忙网络几小时内必然重用"的说法。

延伸阅读：

- 教材与书目：流密码与 LFSR 的进阶讲法（Berlekamp-Massey 的一般域版本、相关免疫布尔函数）在系统性密码学教材里各有一章，书目与检索关键词见 [[02-书单与Wiki]]；本章工具（sage、pycryptodome）的速查见 [[03-工具清单]]，练习平台按难度递进的推荐见 [[01-练习平台索引]]。
- RFC 8439：ChaCha20 与 Poly1305 的标准文本（含测试向量），<https://datatracker.ietf.org/doc/html/rfc8439>；
- RFC 7465：TLS 禁用 RC4 的标准文本，WEP 与 RC4 弃用时间线的权威落点，<https://datatracker.ietf.org/doc/html/rfc7465>；
- eSTREAM 项目页：Trivium、ChaCha20（以 HC-128 等同批算法）的设计文档与分析汇总，<https://www.ecrypt.eu.org/stream/>；
- 下一站：[[C04-随机数攻防]] 从种子侧继续这条战线——密钥流生成器再强，种子可猜则全盘皆输；[[C05-分组密码内部]] 进入分组密码与 CTR 一类"流式用法"的内部结构。
