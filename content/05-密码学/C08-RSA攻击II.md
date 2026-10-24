---
chapter: 密码学
section: RSA 攻击 II
order: 708
tags:
  - CTF
  - 密码学
  - RSA
  - Coppersmith
publish: true
---

# C08 RSA 攻击 II：Coppersmith 与格
## RSA Attacks II: Coppersmith & Lattices

> [!info]- 章节信息
> **所属方向**：密码学 ｜ **难度阶段**：L2 核心漏洞期 ｜ **前置要求**：[[09-密码学基础|09 章]] · [[C02-数论进阶与原根|C02]] · [[C07-RSA攻击I|C07]]
> **本章目标**：补上 [[09-密码学基础|09 章]]留下的那个口子——"m³ 略大于 n 时小明文攻击失效，要用 Coppersmith"；掌握"知道一部分"类 RSA 题的统一形态：找模 N（或模 p）多项式的小根；懂格与 LLL 的最小必要知识，能用 fpylll/sympy 手工实现一版教学 Coppersmith，再用 sage 的 `small_roots` 解真实尺寸的靶；会写 Franklin-Reiter 的多项式 gcd 和 Håstad 广播攻击的 CRT 组合，并用 RsaCtfTool 对全部结论做交叉对照。

## 1. 从"开不动方"到"找小根"

[[09-密码学基础|09 章]] 5.3 的 e=3 小明文攻击有一条硬前提：$m^3 < n$，此时取模等于没取，密文就是 $m^3$ 本身，整数开立方直接还原。那一节的原话是：真实 2048 位 n 下"m³ 略大于 n"的残余情况要用 Coppersmith。本章就来做这件事，并且不止这一件事——Coppersmith 框架覆盖一族攻击，==凡"明文/素数的大部分已知、只剩一小块未知"的题，都能化成同一个数学问题：找模 N 多项式的整数小根==。

先看这类题长什么样：

| 已知什么 | 未知什么 | 多项式 | 除子 |
| ---- | ---- | ---- | ---- |
| 明文的固定前缀（报文格式、协议字段） | 低位一小块 | $(P + x)^e - c$ | N 本身 |
| 素数 p 的高位比特（泄露、侧信道） | 低位一小块 | $x + p_{hi}$ | p（N 的因子） |
| 明文中间一段已知、两端未知 | 夹在中间的小块 | $(Ax + B)^e - c$ | N 本身 |

三种形态共用一个解法。本章接下来按"原理 → 手工利用 → 自动化 → 自建靶实战"的顺序把每一类各打一遍。先回答一个自然的问题：m³ 超出 n 不多时，能不能用笨办法救——把 $c + k \cdot n$ 逐个开方试过去？$m^3 = k \cdot n + c$，k 是明文超出 n 的倍数。造两个靶子对比：

```python
# t0_naive.py —— 为什么 c + k*n 暴力救不了"知道一部分"型题目
from sympy import nextprime
from Crypto.Util.number import bytes_to_long
import gmpy2

p = nextprime(10**21)
q = nextprime(10**21 + 10**15)
N = p * q
e = 3
print("N 的比特数 =", N.bit_length(), "  N^(1/3) = 2^%.1f" % (N.bit_length() / 3))

# ---------- 场景一：纯小明文，m0 略超 N^(1/3) ----------
m0 = 2**47 + 12345                       # 48 比特，刚超界
c0 = pow(m0, e, N)
k_true = (m0**e - c0) // N
print()
print("场景一: m0 = 2^47 + 12345（%d 比特）" % m0.bit_length())
print("  m0^3 // N = %d  <- 只超出 N 一点点" % k_true)
found = None
for k in range(1000):
    r, exact = gmpy2.iroot(c0 + k * N, e)
    if exact:
        found = (k, r)
        break
print("  试 k = 0..999，在 k = %d 处开尽，恢复 m0 正确: %s" % (found[0], int(found[1]) == m0))

# ---------- 场景二：带前缀的 stereotyped 靶 ----------
prefix = b"CTS{c0pper_"
unknown = b"sm31"
P = bytes_to_long(prefix) << 32
m = P + bytes_to_long(unknown)
c = pow(m, e, N)
k_true = (m**e - c) // N
print()
print("场景二: 明文 = 11 字节前缀 + 4 字节未知")
print("  m^3 // N 的比特数 = %d  <- 倍数 k 本身就是天文数字" % k_true.bit_length())
hits = 0
for k in range(0, 10**6):
    r, exact = gmpy2.iroot(c + k * N, e)
    if exact:
        hits += 1
print("  试 k = 0..10^6：开尽次数 =", hits)
```

输出：

```
N 的比特数 = 140   N^(1/3) = 2^46.7

场景一: m0 = 2^47 + 12345（48 比特）
  m0^3 // N = 2  <- 只超出 N 一点点
  试 k = 0..999，在 k = 2 处开尽，恢复 m0 正确: True

场景二: 明文 = 11 字节前缀 + 4 字节未知
  m^3 // N 的比特数 = 215  <- 倍数 k 本身就是天文数字
  试 k = 0..10^6：开尽次数 = 0
```

场景一里明文刚超界，$m_0^3$ 只是 $2n$ 略多一点，扫到 k=2 就开尽——这一段属于 [[09-密码学基础|09 章]]攻击的自然延伸。场景二前缀一进来，$k = \lfloor m^3/N \rfloor$ 本身就是 215 比特的数，候选空间彻底不可枚举。==暴力搜索失败的原因是"未知被前缀抬高"，而前缀信息本身是已知的==——要一个能把"已知前缀"用进方程的算法，这就是 Coppersmith。

> [!note] 攻击不需要 d
> e=3 时若 $\gcd(e, \varphi(n)) \neq 1$，私钥 d 根本不存在（[[09-密码学基础|09 章]]常见问题里的那条）。本章全部攻击只用公开的 n、e、c——"解不出 d"与"攻不破"是两回事。

## 2. 格的最小必要知识

Coppersmith 的实现工具是格上找短向量。本节只讲后面用到的部分：向量与基、行列式与密度、LLL，以及 fpylll / sympy 两条跑法。格密码的完整展开在本库后续章节（第 10 节末尾有预告），这里所有概念都服务于同一件事：把手里的多项式放进一个格。

### 2.1 向量、基与格

**它是干嘛的**：格（lattice）是一组基向量的全部整数线性组合构成的点集。给 d 个线性无关的向量 $b_1, \dots, b_d \in \mathbb{Z}^n$，它们的全部整数线性组合构成一个格：

$$L = \left\{ \sum_{i=1}^{d} a_i b_i \;\middle|\; a_i \in \mathbb{Z} \right\} \tag{2.1}$$

这组向量叫格的**基**，d 是格的**维度**。同一个格有无穷多组基——把基向量互相加减整数倍，张出的点集不变。本章统一用"行向量"约定：一个 $d \times n$ 的整数矩阵，**每一行是一个基向量**。fpylll 和 sympy 的格接口都按这个约定读输入。

### 2.2 行列式与格的密度

**它是干嘛的**：行列式回答"这个格的点铺得有多密"。方阵基（d = n）时，格的行列式就是基矩阵行列式的绝对值；它等于基向量张成的平行体体积。行列式是格的不变量——换基不改变行列式，比较不同的格时用的就是它。

由行列式派生出的量是 $det^{1/d}$，读作"典型间距"：格点在 d 维空间里铺开，相邻格点的平均距离就是这个量。行列式越大格越稀，短向量存在的余地越大。一个经验估计（Gaussian 启发式）：随机格中最短向量的长度在 $\sqrt{d/(2\pi e)} \cdot det^{1/d}$ 附近。==一个格的构造能否找到足够短的向量，可以直接用典型间距估计==。

### 2.3 短向量与 LLL

**它是干嘛的**：给定基，找格中最短的非零向量（SVP）是难问题——正是格密码的安全来源。但"近似最短"有多项式时间算法：**LLL**（Lenstra–Lenstra–Lovász）格基约减。它输出一组新基，满足两条性质：每行都短（约减后基向量长度接近典型间距）、相互接近正交。第一条的定量保证：LLL 输出的第一个基向量满足

$$\|b_1\| \;\le\; 2^{\frac{d-1}{4}} \cdot det^{1/d} \tag{2.2}$$

指数里的 $d/4$ 是 LLL 的近似代价，维度越高越粗糙；但只要格的 det 足够小（格足够密），这个上界就小于我们需要的阈值——Coppersmith 的全部构造就是在算这笔账。

### 2.4 第一跑：fpylll 的 LLL

**它是干嘛的**：fpylll 是 LLL 的工业实现（fplll 库的 Python 绑定），调用两行。造一个 3×3 的例子：三行看不出明显结构，行列式却只有 90，典型间距 $90^{1/3} \approx 4.5$——按 2.2 的密度估计，这个格里应当藏着范数在 5 附近的短向量。跑一遍看 LLL 输出什么：

```python
# t1_lll.py —— 3x3 格：fpylll 与 sympy 各跑一遍 LLL
from fpylll import IntegerMatrix, LLL

B = [
    [3, 1, 4],
    [22, 12, 37],
    [-3, 23, 29],
]

def norm(v):
    return sum(x * x for x in v) ** 0.5

print("输入基（逐行 = 一个基向量）:")
for r in B:
    print("  ", r, "  范数 %.2f" % norm(r))

det = (B[0][0] * (B[1][1] * B[2][2] - B[1][2] * B[2][1])
       - B[0][1] * (B[1][0] * B[2][2] - B[1][2] * B[2][0])
       + B[0][2] * (B[1][0] * B[2][1] - B[1][1] * B[2][0]))
print("行列式 =", det, "  det^(1/3) = %.2f" % abs(det) ** (1 / 3))

A = IntegerMatrix.from_matrix(B)          # 行 = 基向量
LLL.reduction(A)
rows_fplll = [[A[i, j] for j in range(A.ncols)] for i in range(A.nrows)]
print("fpylll LLL 输出:")
for r in rows_fplll:
    print("  ", r, "  范数 %.2f" % norm(r))

from sympy.polys.matrices import DomainMatrix
from sympy import ZZ
DM = DomainMatrix(B, (3, 3), ZZ)
L = DM.lll().to_list()
print("sympy DomainMatrix.lll 输出:")
for r in L:
    r = [int(x) for x in r]
    print("  ", r, "  范数 %.2f" % norm(r))

print("fpylll 每行范数排序后 =", sorted(round(norm(r), 2) for r in rows_fplll))
print("sympy  每行范数排序后 =", sorted(round(norm([int(x) for x in r]), 2) for r in L))

def det3(M):
    return (M[0][0] * (M[1][1] * M[2][2] - M[1][2] * M[2][1])
            - M[0][1] * (M[1][0] * M[2][2] - M[1][2] * M[2][0])
            + M[0][2] * (M[1][0] * M[2][1] - M[1][1] * M[2][0]))
print("|det(fpylll 输出)| =", abs(det3(rows_fplll)), " |det(sympy 输出)| =", abs(det3(L)))
```

输出：

```
输入基（逐行 = 一个基向量）:
   [3, 1, 4]   范数 5.10
   [22, 12, 37]   范数 44.69
   [-3, 23, 29]   范数 37.13
行列式 = -90   det^(1/3) = 4.48
fpylll LLL 输出:
   [1, 1, -4]   范数 4.24
   [4, 2, 0]   范数 4.47
   [-1, 5, 1]   范数 5.20
sympy DomainMatrix.lll 输出:
   [1, 1, -4]   范数 4.24
   [4, 2, 0]   范数 4.47
   [-1, 5, 1]   范数 5.20
fpylll 每行范数排序后 = [4.24, 4.47, 5.2]
sympy  每行范数排序后 = [4.24, 4.47, 5.2]
|det(fpylll 输出)| = 90  |det(sympy 输出)| = 90
```

三件事：输入基的三行范数 5.1 / 44.7 / 37.1，LLL 输出的三行全部压到 4.2–5.2，正好贴着典型间距 4.48；行列式绝对值在约减前后都是 90——格没变，换了一组更好的基；fpylll 与 sympy 两条独立实现给出逐行相同的结果。==约减不改变格，只改变基的形状==，这是后面所有格构造的合法性来源：可以随意构造（甚至很差的）基，LLL 从中找出短向量。

### 2.5 sympy 对照与行、列约定

sympy 的入口是 `DomainMatrix`：`DomainMatrix(rows, (行数, 列数), ZZ).lll()`，rows 是"每行一个基向量"的列表，与 fpylll 的 `IntegerMatrix.from_matrix` 约定一致。两套实现可以互相验算——本库后续所有格相关的脚本都用这个组合：fpylll 跑主路，sympy 做对拍。

> [!warning] 行与列不能混
> 把基矩阵转置后再喂进去，fpylll 照常运行、不报任何错，但约减的是另一个格——用 2.4 那个矩阵的转置跑 LLL，输出第一行是 `[1, 0, 0]`，与正确定向的结果毫无关系。sympy 这边稍好：`DomainMatrix` 要显式传形状，行列数写反直接抛 `DMBadInputError`。==拿到一段别人的格构造脚本，第一件事是确认"行"到底是多项式还是系数位置==。

## 3. Howgrave-Graham 与手工 Coppersmith

工具就位。本节把"找模 N 多项式的小根"从定理讲到格构造，再用 fpylll 手工实现一版教学 Coppersmith，在一个自造的 140 位 N 的靶上把根完整解出来，最后用 sympy 和 sage 各对照一遍。

### 3.1 定理：找模 N 多项式的小根

**Coppersmith 定理**（单变量）：N 未知分解，f 是模 N 的首一多项式、次数为 $\delta$。给定 $\beta \in (0, 1]$，可以多项式时间找出全部满足

$$f(x_0) \equiv 0 \pmod{b}, \qquad |x_0| \le N^{\beta^2/\delta}, \qquad b \ge N^{\beta} \tag{3.1}$$

的整数 $x_0$，其中 b 是 N 的某个未知因子。

读法：b 是"模的对象"。取 b = N（此时任意 $\beta$ 都满足 $N \ge N^\beta$，取 $\beta = 1$），条件变成 $f(x_0) \equiv 0 \pmod N$、$|x_0| < N^{1/\delta}$——==e 次幂的多项式能找回不超过 $N^{1/e}$ 的未知块，这就是 stereotyped 攻击的边界来源==。取 b = p ≈ $N^{1/2}$（$\beta = 1/2$、$\delta = 1$），条件是 $|x_0| < N^{1/4}$——这是素数高位攻击的边界。两类题在 4、5 两节各打一个真实尺寸的靶。

定理是存在性陈述（"可以找到"），实现靠下一节的引理加 LLL。

### 3.2 Howgrave-Graham 引理

把"找根"转成"找短向量"的转换步骤如下。设 f 是首一多项式，次数 $\delta$，f(x₀) ≡ 0 (mod N)。取整数 m ≥ 1，构造辅助多项式格 L：基向量是下面这组多项式的系数向量（次数从 0 到 $\delta(m+1)-1$，每个系数乘上 $X^k$，X 是根的上界）：

$$g_{i,j}(x) = N^{m-i} \cdot f(x)^i \cdot x^j, \qquad i = 0, \dots, m, \quad j = 0, \dots, \delta-1 \tag{3.2}$$

每个 $g_{i,j}$ 在 x₀ 处都 ≡ 0 (mod $N^m$)（i=0 的项带 $N^m$；i≥1 的项里 $f(x_0)^i$ 贡献 $N^i$，合起来恰好 $N^m$）。于是格里的**每一个**向量——系数向量的任意整数组合——对应的多项式 g 都满足 g(x₀) ≡ 0 (mod $N^m$)。

**Howgrave-Graham 引理**：若格中某个向量足够短，具体地，对应多项式 g 满足

$$\|g(xX)\| \;<\; \frac{N^m}{\sqrt{\dim}}, \qquad \|g(xX)\| = \sqrt{\textstyle\sum_k (c_k X^k)^2} \tag{3.3}$$

其中 $c_k$ 是 g 的系数，则 $g(x_0) = 0$ 在整数上严格成立（不只是模 $N^m$）。

证明一行：$|g(x_0)| \le \sum |c_k| |x_0|^k \le \sqrt{\sum (c_k X^k)^2} \cdot \sqrt{\dim} < N^m$（用到 $|x_0| < X$），一个绝对值小于 $N^m$ 的数又是 $N^m$ 的倍数，只能是 0。

于是流程闭合：==格中足够短的向量 ⟹ 整系数多项式 ⟹ 它的整数根里就有 x₀==。而"找短向量"正是 LLL 的任务（式 2.2）——只要 LLL 输出的向量满足式 (3.3)，问题就解了。

### 3.3 格构造与参数 m

剩下的只有一笔账：式 (3.3) 何时成立。格 L 由式 (3.2) 的 $(m+1)\delta$ 个多项式张成，维度 $\dim = (m+1)\delta$，行列式是每个基行对应 $N^{m-i} X^{\deg}$ 的连乘：

$$\det(L) \;=\; N^{\delta\frac{m(m+1)}{2}} \cdot X^{\;\delta^2\frac{m(m+1)}{2} \;+\; (m+1)\frac{\delta(\delta-1)}{2}} \tag{3.4}$$

LLL 保证第一条向量长度不超过式 (2.2)，把它和式 (3.3) 连起来，攻击可行的充分条件是

$$2^{\frac{\dim-1}{4}} \cdot \det(L)^{1/\dim} \;<\; \frac{N^m}{\sqrt{\dim}} \tag{3.5}$$

固定 $\delta = 3$（e=3 的场景），对 m 从 1 到 5 算出每档的上界：

```python
# t2_mtable.py —— 单变量 Coppersmith 教学格的参数表（delta=3）
# 基：N^(m-i) * f^i * x^j, i=0..m, j=0..2；Howgrave-Graham 条件 det^(1/dim) < N^m
from fractions import Fraction

delta = 3
print("m  dim  det 里 N 的幂  det 里 X 的幂   X 上界")
for m in range(1, 6):
    dim = (m + 1) * delta
    n_exp = delta * m * (m + 1) // 2                      # sum_i sum_j (m-i)
    x_exp = delta * delta * m * (m + 1) // 2 + (m + 1) * delta * (delta - 1) // 2
    alpha = Fraction(m * dim - n_exp, x_exp)              # X < N^alpha
    print("%d  %3d  %8d  %12d   N^(%d/%d) = N^%.4f" %
          (m, dim, n_exp, x_exp, alpha.numerator, alpha.denominator, float(alpha)))
```

输出：

```
m  dim  det 里 N 的幂  det 里 X 的幂   X 上界
1    6          3            15   N^(1/5) = N^0.2000
2    9          9            36   N^(1/4) = N^0.2500
3   12         18            66   N^(3/11) = N^0.2727
4   15         30           105   N^(2/7) = N^0.2857
5   18         45           153   N^(5/17) = N^0.2941
```

m 越大，上界指数越接近定理的 $1/\delta = 1/3$，代价是格的维度线性涨、LLL 变慢。m 是用计算量换边界的参数。按 m=3（上界 $N^{3/11}$）选参数，再看几个 N 尺寸下能找回多大的未知块：

| N 的比特数 | $N^{1/3}$ | m=3 时可恢复的未知上界 $N^{3/11}$ |
| ---- | ---- | ---- |
| 128 | $2^{42.7}$ | $2^{34.9}$ |
| 140 | $2^{46.7}$ | $2^{38.1}$ |
| 1024 | $2^{341.3}$ | $2^{280.4}$ |
| 2048 | $2^{682.7}$ | $2^{560.8}$ |

> [!info]- 再快一点：t 参数
> 式 (3.2) 的基只用了"每个幂次 $f^i$ 配 δ 个 x 平移"。标准构造还会追加 $h_i(x) = x^i \cdot f(x)^m$（i = 0..t−1）这组"顶层平移"，t 加大能让上界指数以更小的维度逼近 $1/\delta$。sage 的 `small_roots` 内部就是按给定的 beta、epsilon 挑一对 (m, t)：epsilon 是"离理论边界还差多少"，越小 (m, t) 越大、格越高、算得越久。手写版取 t = 0 已经够教学靶用，知道这层就够读 sage 的参数了。

### 3.4 手工实现：fpylll 版

自造靶：p、q 各约 70 位（N 共 140 比特），e=3，明文 15 字节 = 11 字节已知前缀 + 4 字节未知低位（32 比特）。32 < 38.1（m=3 的上界），攻击应当成功：

```python
# t2_hand_copper.py —— 教学版 Coppersmith：fpylll 手搓
# 靶：N ~ 2^140，e=3，明文 = 11 字节已知前缀 + 4 字节未知低位
from sympy import nextprime
from Crypto.Util.number import bytes_to_long, long_to_bytes
from fpylll import IntegerMatrix, LLL

# ---------- 自造靶 ----------
p = nextprime(10**21)
q = nextprime(10**21 + 10**15)
N = p * q
e = 3
prefix = b"CTS{c0pper_"
unknown = b"sm31"
m_true = bytes_to_long(prefix + unknown)
c = pow(m_true, e, N)
print("N = %d" % N)
print("N 的比特数 = %d,  N^(1/3) = 2^%.1f" % (N.bit_length(), N.bit_length() / 3))
print("c = %d" % c)

# ---------- 多项式 f(x) = (P + x)^e - c mod N，系数从低次到高次 ----------
# 前缀占高位：P 要左移到未知段左侧（P·256^4），不是直接用前缀的整数值
P = bytes_to_long(prefix) << (8 * len(unknown))
f = [(-c + P**3) % N, (3 * P * P) % N, (3 * P) % N, 1]

# ---------- 格构造：g_{i,j} = N^(m-i) * f^i * x^j, i=0..m, j=0..2 ----------
X = 1 << 32          # 未知低位的上界（4 字节）
mp = 3               # 重数 m
delta = 3
dim = (mp + 1) * delta

def polymul(a, b, mod):
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                r[i + j] = (r[i + j] + ai * bj) % mod
    return r

Nm = N**mp
rows = []
for i in range(mp + 1):
    fi = [1]
    for _ in range(i):
        fi = polymul(fi, f, Nm)        # 只能 mod N^m，不能 mod N
    for j in range(delta):
        g = [0] * j + fi               # x^j * f^i
        row = []
        for k in range(dim):
            coef = g[k] if k < len(g) else 0
            row.append(coef * N**(mp - i) * X**k)   # 代入 x -> xX 并乘 N^(m-i)
        rows.append(row)

A = IntegerMatrix.from_matrix(rows)
LLL.reduction(A)

# ---------- 从约减后的行还原多项式并找整数根 ----------
import sympy
xsym = sympy.symbols("x")
found = None
for rowidx in range(3):
    coeffs = []
    ok = True
    for k in range(dim):
        v = A[rowidx, k]
        if v % X**k != 0:              # 还原 g 的系数必须整除 X^k
            ok = False
            break
        coeffs.append(v // X**k)
    if not ok:
        continue
    poly = sympy.Poly(list(reversed(coeffs)), xsym)   # sympy 按高次在前
    for r in poly.real_roots():         # 精确隔离实根，避免大系数下的浮点精度问题
        rv = r.evalf(50)
        cand = int(sympy.re(rv).round())
        if 0 <= cand < X and pow(P + cand, e, N) == c:
            found = (rowidx, cand)
            break
    if found:
        break

rowidx, x0 = found
print("LLL 第 %d 行还原出的多项式有根 x0 = %d = %r" % (rowidx, x0, long_to_bytes(x0)))
print("验算: (P + x0)^e mod N == c ->", pow(P + x0, e, N) == c)
print("恢复的完整明文:", long_to_bytes(P + x0))
```

输出：

```
N = 1000001000000000000138000117000000000002457
N 的比特数 = 140,  N^(1/3) = 2^46.7
c = 988175331284217857938250338887190512421295
LLL 第 0 行还原出的多项式有根 x0 = 1936536369 = b'sm31'
验算: (P + x0)^e mod N == c -> True
恢复的完整明文: b'CTS{c0pper_sm31'
```

32 比特的未知块从 140 比特的模数里被完整找回。逐段读脚本里的三个关键点：

- **前缀的数值位置**：`bytes_to_long(prefix + unknown)` 等于 $P \cdot 256^4 + x$，所以多项式是 $(P \cdot 256^4 + x)^e - c$——前缀的整数值必须左移到未知段左侧。写成 $(P + x)^e$ 不报任何错，只是 $f(x_0)$ 不再 ≡ 0 (mod N)，格上的 Howgrave-Graham 条件全部落空，攻击直接失效。
- **f 的幂只能 mod N^m**：构造 $f^2, f^3$ 时若每步系数都对 N 取模，多项式在整数上求值的高次 N 因子就被丢掉了——$g_{i,j}(x_0) \equiv 0 \pmod{N^m}$ 不再成立，Howgrave-Graham 引理的前提不满足。要么全程不取模，要么统一对 $N^m$ 取模（脚本取后者，控制系数规模）。
- **找根的容错**：LLL 只保证第一行最短，目标多项式不总在第一行，所以按行循环多试几行；每行先用"系数能否整除 $X^k$"筛一遍（整除不成立说明这行对应的不是合格的多项式组合），求根用 `real_roots()` 做精确隔离——系数是几百位的大数，`nroots` 默认精度会报收敛失败或给出错根，取整后的候选必须回代 `pow(P + cand, e, N) == c` 验算。

> [!warning] 失效不报错
> 上面两个构造错误（前缀没移位、幂次 mod N）都不会让程序报错，LLL 照样输出一组"变短了"的基，只是任何一行都还原不出合法的根。排查固定三步：验算 $f(x_0) \bmod N$ 是否为 0（用真根试）；抽查任意一行在真根处的整数值是否 ≡ 0 (mod $N^m$)；核对 X 的比特数是否真的小于 3.3 节的上界。

### 3.5 sympy 与 sage 对照

同一格换 sympy 约减（在脚本末尾追加）：

```python
# 追加到 t2_hand_copper.py 末尾：sympy DomainMatrix.lll 对照
from sympy.polys.matrices import DomainMatrix
from sympy import ZZ
L = DomainMatrix(rows, (dim, dim), ZZ).lll().to_list()
coeffs = [L[0][k] // X**k for k in range(dim)]
poly = sympy.Poly(list(reversed(coeffs)), xsym)
for r in poly.real_roots():
    rv = r.evalf(50)
    cand = int(sympy.re(rv).round())
    if 0 <= cand < X and pow(P + cand, e, N) == c:
        print("sympy 路径找到同一根:", cand, long_to_bytes(cand), pow(P + cand, e, N) == c)
        break
```

输出：

```
sympy LLL 第一行可整除还原: True
sympy 路径找到同一根: 1936536369 b'sm31' True
```

再用 sage 的 `small_roots` 解同一个靶。sage 的多精度整数环自带完整实现，五行走完：

```python
# t2_sage_check.sage —— 同一个教学靶，sage small_roots 一段式解出
N = 1000001000000000000138000117000000000002457
e = 3
c = 988175331284217857938250338887190512421295
P = Integer(int.from_bytes(b"CTS{c0pper_", "big")) << 32

R.<x> = PolynomialRing(Zmod(N))
f = (P + x)^e - c
roots = f.small_roots(X=2^32, beta=1.0)
print("small_roots =", roots)
from Crypto.Util.number import long_to_bytes
x0 = Integer(roots[0])
print("x0 =", x0, "->", long_to_bytes(int(x0)))
print("恢复的完整明文 =", long_to_bytes(int(P + x0)))
print("验算:", power_mod(Integer(P + x0), e, N) == c)
```

输出：

```
small_roots = [1936536369]
x0 = 1936536369 -> b'sm31'
恢复的完整明文 = b'CTS{c0pper_sm31'
验算: True
```

==fpylll 手写版、sympy 版、sage 的 `small_roots` 三条路给出同一个根==。手写版的价值在调试：sage 版失败时，用手写版拆开格看每一行，能定位是构造错了还是参数不够。sage 的安装路径与用法见 [[C01-密码学导论与工具链|C01]] 第 5 节；fpylll 是系统 python3 的包，`import fpylll` 即用。

## 4. 素数高位已知：small_roots 与 beta

### 4.1 问题形态与攻击原理

第二类"知道一部分"：攻击者拿到 p 的高位比特。来源包括内存泄露、共享密钥的错误擦除、部分密钥文件残骸——题目里通常直接给 `p_high = p >> k << k` 这种"低 k 位置零"的值。设 p = p_hi + x，未知部分 x < $2^k$。这仍是 3.1 的形态，只是模的对象从 N 换成它的因子 p：

$$f(x) = x + p_{hi}, \qquad f(x) \equiv 0 \pmod{p}, \qquad \delta = 1 \tag{4.1}$$

除子 b = p 未知大小，用 $\beta$ 表达"p 大约有多大"：$p \ge N^\beta$。代进 3.1 定理，可恢复的上界是

$$X \;<\; N^{\beta^2} \tag{4.2}$$

平衡密钥（p、q 各占 N 的一半比特）取 $\beta = 1/2$，上界 $N^{1/4}$。这个量的直观：$N^{1/4} \approx \sqrt{p}$，==未知部分不超过 $\sqrt p$，也就是 p 的高半段比特必须已知==——已知不到一半，式 (4.2) 给不出空间，这是这类题的适用边界。$\beta$ 可以取小一点（如 0.49）表示对 p 占比的保守估计；sage 的 `small_roots(X, beta, epsilon)` 三个参数分别对应根上界、除子下界的指数、以及离理论边界的距离（3.3 折叠框里的 (m, t) 参数）。

### 4.2 自建靶实战

造 512 位的 N（p、q 各 256 位），泄露 p 的高 156 位、留 100 位未知。100 < $N^{1/4} \approx 2^{127.8}$，且 100 < 当前参数能力（见 4.3），攻击应当成功：

```python
# t3_highbits.sage —— 素数高位已知：small_roots 的 beta 与 epsilon
from Crypto.Util.number import long_to_bytes, bytes_to_long
set_random_seed(2026)

# ---------- 自造靶：512 位 N，p 高 156 位已知，低 100 位未知 ----------
p = random_prime(2^256, lbound=2^255)
q = random_prime(2^256, lbound=2^255)
N = p * q
e = 65537
m = bytes_to_long(b"flag{kn0w_h4lf_1s_3n0ugh}")
c = power_mod(m, e, N)

UNK = 100
p_hi = (p >> UNK) << UNK
print("N =", N)
print("e =", e, " c =", c)
print("泄露的 p 高位 p_hi =", p_hi)
print("p 的比特数 = %d, N 的比特数 = %d" % (p.nbits(), N.nbits()))
print("p 在 N 中的占比 ~= N^%.4f" % (RR(p.nbits()) / RR(N.nbits())))

# ---------- 攻击 ----------
R.<x> = PolynomialRing(Zmod(N))
f = x + p_hi
roots = f.small_roots(X=2^UNK, beta=0.49, epsilon=0.03)
print("small_roots(X=2^100, beta=0.49, epsilon=0.03) =", roots)
p_rec = p_hi + Integer(roots[0])
print("恢复的 p 与真值一致:", p_rec == p, " p 是素数:", is_prime(p_rec))
print("p*q == N:", p_rec * (N // p_rec) == N)

# 完整解密链
d = inverse_mod(e, (p_rec - 1) * (N // p_rec - 1))
print("解密 =", long_to_bytes(int(power_mod(c, d, N))))

# ---------- 边界一：X=2^120 超出默认参数的能力，先用默认 epsilon 再显式调小 ----------
p_hi2 = (p >> 120) << 120
f2 = x + p_hi2
print("small_roots(X=2^120, beta=0.49)               =", f2.small_roots(X=2^120, beta=0.49))
print("small_roots(X=2^120, beta=0.49, epsilon=0.01) =", f2.small_roots(X=2^120, beta=0.49, epsilon=0.01))

# ---------- 边界二：未知 140 位，超过 N^(beta^2) ≈ 2^127.8 的硬上界 ----------
p_hi3 = (p >> 140) << 140
f3 = x + p_hi3
print("small_roots(X=2^140, beta=0.49, epsilon=0.01) =", f3.small_roots(X=2^140, beta=0.49, epsilon=0.01))
```

输出：

```
N = 4178219412819179041475779761586578249272227054207956589687378416965984563508465613360112584788370523216660690212217736435971663023415828824163812281377843
e = 65537  c = 3195976499341684991064534579055237917100731974313319882974427118426896702875782765807011439217058808550323586601228497145269383886371149551259981072837120
泄露的 p 高位 p_hi = 58685108804515238140761323095099493016436139628785601062781195588863721996288
p 的比特数 = 256, N 的比特数 = 511
p 在 N 中的占比 ~= N^0.5010
small_roots(X=2^100, beta=0.49, epsilon=0.03) = [911941728322027504027705054681]
恢复的 p 与真值一致: True  p 是素数: True
p*q == N: True
解密 = b'flag{kn0w_h4lf_1s_3n0ugh}'
small_roots(X=2^120, beta=0.49)               = []
small_roots(X=2^120, beta=0.49, epsilon=0.01) = [1091038627594360118619482052398454233]
small_roots(X=2^140, beta=0.49, epsilon=0.01) = []
```

攻击主线：100 位未知从 511 位的 N 里被找回，p 还原后接标准解密链拿到明文。同一个根 `911941728322027504027705054681` 与 p 的真实低位一致，`p_rec * (N // p_rec) == N` 与素性检查双重确认。

### 4.3 三条边界

输出里三个失败/成功的对照把 `small_roots` 的参数语义讲全：

1. **硬上界（式 4.2）**：未知 140 位 > $N^{\beta^2} \approx 2^{127.8}$，任何参数都返回空——这不是调参问题，是信息不够。
2. **参数能力**：未知 120 位在硬上界之内，但默认 epsilon 下返回空；显式 `epsilon=0.01` 后返回真根，代价是格的维度大幅上升、耗时明显变长。epsilon 调小让 sage 用更高的格（更大的 m、t）换更接近 $N^{\beta^2}$ 的边界，==返回空列表时先减 X，再减 epsilon，最后才怀疑 beta==。
3. **beta 的方向**：beta 是"除子 ≥ $N^\beta$"的**下界**承诺。本靶 p 占比 $N^{0.5010}$，写 0.5 也成立；若密钥生成让 p 略小于 $N^{1/2}$（比如取 $\text{nextprime}(2^{255})$ 这类贴下界的素数），$\beta = 0.5$ 就是高估，攻击不保证成立——写 0.49 这类保守值。

> [!note] 已知低位也一样
> 泄露 p 的低 k 位（$p = x \cdot 2^k + p_{lo}$，未知在高位）时，把 f 写成 $f(x) = 2^k x + p_{lo}$ 即可，仍是首一化的一次式——先乘上 $2^k$ 的模逆化成 $x + p_{lo} \cdot 2^{-k}$，或直接交给 `small_roots`（它要求首一，用 `.monic()` 一行转换）。

## 5. 已知明文格式：stereotyped message

### 5.1 问题形态与攻击原理

第三类：明文结构固定，只有尾部一小块未知。典型场景——报文带固定模板（JSON 字段名、协议头）、时间戳可预测、id 短随机。这就是本章开头表格的第一行，也是 1 节场景二里暴力失败的那个靶：

$$f(x) = (P \cdot 256^s + x)^e - c, \qquad f(x) \equiv 0 \pmod N \tag{5.1}$$

其中 s 是未知段的字节数。多项式首一（$x^e$ 系数为 1），除子就是 N（$\beta = 1$），式 (3.1) 给出边界：

$$X \;<\; N^{1/e} \tag{5.2}$$

e=3 时可恢复 n 比特数的三分之一。这个边界同时决定了另一件事：==e=65537 的正常密钥下 $N^{1/e}$ 不足 1 比特，stereotyped 攻击只对小 e 有意义==——看到题目用 e=3 加密"格式化报文"，这攻击就该进入候选清单。

### 5.2 自建靶实战与边界

靶一用正常尺寸：1024 位 N、e=3，明文 = 17 字节前缀 + 8 字节未知（$X = 2^{64}$，远小于 $N^{1/3} = 2^{341}$）。靶二故意卡边界：192 位 N、同样 12 字节未知（$2^{96}$），$2^{96} \gg 2^{64}$，应当失败：

```python
# t4_stereo.sage —— stereotyped message：e=3，明文 = 已知前缀 + 未知低位
from Crypto.Util.number import long_to_bytes, bytes_to_long
set_random_seed(8)

# ---------- 靶一：正常尺寸，1024 位 N ----------
p = random_prime(2^512, lbound=2^511)
q = random_prime(2^512, lbound=2^511)
N = p * q
e = 3
prefix = b"flag{kn0wn_pr3f1x_"
unknown = b"u_r_c08!"
P = Integer(int.from_bytes(prefix, "big"))
m = P * 256^8 + Integer(int.from_bytes(unknown, "big"))
c = power_mod(m, e, N)
print("N 的比特数 =", N.nbits(), "  N^(1/3) = 2^%.0f" % (RR(N.nbits()) / 3))
print("N =", N)
print("未知部分 8 字节 = 2^64  <<  N^(1/3)，攻击可行")
print("c =", c)

R.<x> = PolynomialRing(Zmod(N))
f = (P * 256^8 + x)^e - c
roots = f.small_roots(X=2^64, beta=1.0)
print("small_roots(X=2^64, beta=1.0) =", roots)
print("未知部分 =", long_to_bytes(int(roots[0])))
print("恢复的完整明文 =", long_to_bytes(int(P * 256^8 + Integer(roots[0]))))

# ---------- 靶二：N 太小，未知超过 N^(1/3) ----------
p2 = random_prime(2^96, lbound=2^95)
q2 = random_prime(2^96, lbound=2^95)
N2 = p2 * q2
prefix2 = b"tiny_n!_"
unknown2 = b"12bytes_long"
m2 = Integer(int.from_bytes(prefix2, "big")) * 256^12 + Integer(int.from_bytes(unknown2, "big"))
assert m2 < N2
c2 = power_mod(m2, e, N2)
print()
print("靶二: N2 的比特数 =", N2.nbits(), " N2^(1/3) = 2^%.0f" % (RR(N2.nbits()) / 3),
      " 未知 12 字节 = 2^96  >>  N2^(1/3)")
f2 = (Integer(int.from_bytes(prefix2, "big")) * 256^12 + x)^e - c2
roots2 = f2.small_roots(X=2^96, beta=1.0, epsilon=0.02)
print("small_roots(X=2^96, beta=1.0, epsilon=0.02) =", roots2, "  <- 空，攻击失败")
print("m2 < N2 成立，明文本身合法，输在未知部分太大")
```

输出：

```
N 的比特数 = 1023   N^(1/3) = 2^341
N = 79570318139457338664315466006212891086657109485636557383535197790824494228025107051495064089661693346814199462208824299719737996966188812034227051603317908736757230614370836124818265909010138121752327366740060119132482748794243281254619111776358572893179055090956870792017570037858831059817975621264875854181
未知部分 8 字节 = 2^64  <<  N^(1/3)，攻击可行
c = 4458558515803227773073572688400855413263478025047657123687639522743071895533893809542138614414067118080786007929289702537696204252695491530172776793144386985848295037768541608466766836833
small_roots(X=2^64, beta=1.0) = [8457604379236644897]
未知部分 = b'u_r_c08!'
恢复的完整明文 = b'flag{kn0wn_pr3f1x_u_r_c08!'

靶二: N2 的比特数 = 192  N2^(1/3) = 2^64  未知 12 字节 = 2^96  >>  N2^(1/3)
small_roots(X=2^96, beta=1.0, epsilon=0.02) = []   <- 空，攻击失败
m2 < N2 成立，明文本身合法，输在未知部分太大
```

靶二的失败值得注意：明文 $m_2 < N_2$ 完全合法，RSA 加解密本身没有任何问题，==输的是"未知部分超出 $N^{1/e}$"这条信息量边界==——与 4.3 的硬上界同性质。写题解时先算一遍 $X < N^{1/e}$ 再动手，能省掉整轮调试。

> [!note] 未知在中间：M = A·x + B
> 未知块被夹在两段已知之间时，明文是 $M = A \cdot x + B$ 的形状（A = $256^{s}$，s 是未知块**后面**的字节数）。$(Ax + B)^e$ 依旧首一，`small_roots` 照常用；下一节 8.2 里 RsaCtfTool 打印的 `A=1, B=…` 就是同一个分解。A 的模逆存在时也可以先 `.monic()` 化简。

> [!info]- 恢复 8 字节未知至少要多大的 N
> 式 (5.2) 反过来用：要恢复 $X = 2^{64}$，需要 $N^{1/3} > 2^{64}$，即 N > $2^{192}$（p、q 各 96 位以上）。教学靶常用 128 位 N，此时可恢复的未知不足 6 字节——靶子造出来"打不动"时，先查这个换算，再查参数。

## 6. 相关消息：Franklin-Reiter

### 6.1 原理

前三类攻击都在 Coppersmith 框架里；接下来两个是独立工具。Franklin-Reiter 处理"相关消息"：同一把密钥（同 n、同 e）加密了两条线性相关的明文：

$$m_2 = a \cdot m_1 + b \tag{6.1}$$

a、b 已知（最常见的是 a=1，两条消息差一个固定增量）。考虑模 N 的两个多项式：

$$g_1(x) = x^e - c_1, \qquad g_2(x) = (ax + b)^e - c_2 \tag{6.2}$$

$x = m_1$ 同时是两者的根：$g_1(m_1) \equiv 0$、$g_2(m_1) = (am_1 + b)^e - c_2 = m_2^e - c_2 \equiv 0$（均 mod N）。于是 $x - m_1$ 整除 $\gcd(g_1, g_2)$。e 很小时这个 gcd 几乎总是恰好一次式，==它的根就是 $m_1$==——两条密文比一条多出的那点关系，足以唯一确定 $m_1$。

### 6.2 手写多项式 gcd 与工具对照

模 N 的多项式欧几里得要用到首项系数的逆元，纯 Python 五十行写完（e=3，两条消息差 4919）：

```python
# t5_franklin.py —— Franklin-Reiter：同一 n、同一 e、m2 = m1 + delta
from sympy import nextprime
from Crypto.Util.number import bytes_to_long, long_to_bytes

# ---------- 自造靶：512 位 N，e=3 ----------
p = nextprime(2**255 + 2**100)
q = nextprime(2**255 + 3**90)
N = p * q
e = 3
m1 = bytes_to_long(b"flag{r3l4t3d_m3ss4g3s}")
delta = 0x1337
m2 = m1 + delta
c1 = pow(m1, e, N)
c2 = pow(m2, e, N)
print("N 的比特数 =", N.bit_length())
print("m2 = m1 + %d" % delta)
print("c1 =", c1)
print("c2 =", c2)

# ---------- 模 N 多项式运算（系数低->高） ----------
def deg(a):
    d = len(a) - 1
    while d > 0 and a[d] == 0:
        d -= 1
    return d

def polymod(a, b, N):
    """b 已化为一首一多项式时，求 a mod b"""
    a = a[:]
    da, db = deg(a), deg(b)
    while da >= db:
        c = a[da]
        if c:
            for i in range(db + 1):
                a[da - db + i] = (a[da - db + i] - c * b[i]) % N
        da = deg(a)
    while len(a) > 1 and a[-1] == 0:      # 去掉尾随零
        a.pop()
    return a

def polygcd(a, b, N):
    """多项式欧几里得，每步把 b 归一化成首一（系数逆元）"""
    while b != [0]:
        inv = pow(b[-1], -1, N)
        b = [coef * inv % N for coef in b]
        a, b = b, polymod(a, b, N)
    return a

g1 = [(-c1) % N, 0, 0, 1]                        # x^3 - c1
g2 = [(delta**3 - c2) % N, (3 * delta**2) % N, (3 * delta) % N, 1]   # (x+delta)^3 - c2
g = polygcd(g1, g2, N)
print("gcd(g1, g2) =", [str(v) for v in g], " （次数 %d，一次式）" % deg(g))
m_rec = (-g[0]) % N                              # x + g[0] 的根：x = -g[0]
print("恢复的 m1 =", m_rec, " 与真值一致:", m_rec == m1)
print("明文 =", long_to_bytes(m_rec))
```

输出：

```
N 的比特数 = 511
m2 = m1 + 4919
c1 = 2350226159231781735582609668179626578898804341497832509749582629610943553882189417543965647795977591863714211892703545421532948592093779959659286793258977
c2 = 2350226159231781735582609668179626578898804363168618769852298632966643271651773891133118624952769296274618670214233478822680851920133032250877590205347516
gcd(g1, g2) = ['3351951982485649274893506249551462037184409623250022699809605699084727529520601617135190624102760794054817010600785298229327273525485957094209574331021072', '1']  （次数 1，一次式）
恢复的 m1 = 38321129010651471588283885253116799175462888169239421  与真值一致: True
明文 = b'flag{r3l4t3d_m3ss4g3s}'
```

同一靶喂给 RsaCtfTool（`--fr-a`、`--fr-b` 就是式 (6.1) 的 a、b，两条密文逗号分隔）：

```bash
RsaCtfTool -n 3351951982485649274893506249551462037184409623250022699809605699084727529520601617135190624102760794093138139611436769817611158778602756269672462500260493 \
           -e 3 \
           --decrypt 2350226159231781735582609668179626578898804341497832509749582629610943553882189417543965647795977591863714211892703545421532948592093779959659286793258977,2350226159231781735582609668179626578898804363168618769852298632966643271651773891133118624952769296274618670214233478822680851920133032250877590205347516 \
           --attack franklin_reiter --fr-a 1 --fr-b 4919
```

输出：

```
[*] Performing franklin_reiter attack on /tmp/tmppb5uzdx0.
[*] Franklin-Reiter parameters received: fr_a=1, fr_b=4919
[+] Franklin-Reiter attack recovered related messages
[+] m1 = 38321129010651471588283885253116799175462888169239421
[+] m2 = 38321129010651471588283885253116799175462888169244340
[*] Attack success with franklin_reiter method !

Results for /tmp/tmppb5uzdx0:

Decrypted data :
HEX : 0x666c61677b72336c347433645f6d337373346733737d
INT (big endian) : 38321129010651471588283885253116799175462888169239421
utf-8 : flag{r3l4t3d_m3ss4g3s}
STR : b'flag{r3l4t3d_m3ss4g3s}'
```

m1 与手写版完全一致。

> [!note] sage 的 gcd 帮不上忙
> 在 sage 里对 `Zmod(N)[x]`（N 为合数）的两个多项式直接调 `gcd` 会抛 `NotImplementedError`——sage 的多项式 gcd 只对域实现。所以 6.2 的手写欧几里得不是教学姿态，它就是这道题在生产里的写法。顺带一提：归一化首项时若 `pow(lead, -1, N)` 报不可逆，按 [[09-密码学基础|09 章]] 2.2 的结论，gcd(lead, N) 不是 1 就是 N 的因子——直接得到 N 的分解。

> [!warning] e 一大就不实用
> 多项式次数是 e，gcd 的代价随 e 平方级上涨。e=3、e=5 秒出；e=65537 时光是写下 $g_1$ 就要 65537 个系数。相关消息攻击与 5 节的 stereotyped 一样，都是小 e 专属。

## 7. 广播：Håstad

### 7.1 原理

Franklin-Reiter 需要"同一密钥、两条相关消息"；Håstad 广播攻击反过来——==同一条消息、e 个不同密钥==。发送方把同一个 m 用 e 个接收者的公钥 $(N_i, e)$ 分别加密广播。每个 $c_i = m^e \bmod N_i$ 单独看都是安全的（$m^e > N_i$，开不了方），但把 e 份凑齐，用 [[09-密码学基础|09 章]] 2.4 的中国剩余定理就能把 e 条同余式拼成一条：

$$X \equiv m^e \pmod{N_1 N_2 \cdots N_e}, \qquad X = m^e \;\;(\text{因为 } m^e < \textstyle\prod N_i) \tag{7.1}$$

m 小于每个 $N_i$，故 $m^e < \prod N_i$：CRT 拼出的 X 就是 $m^e$ 本身，取模等于没取（[[09-密码学基础|09 章]] 5.3 的小明文攻击在这一步重现），整数开 e 次方即可还原 m。条件两条：模数两两互质（不同密钥天然满足，出题人复用素数时先 gcd 排查）、参与组合的份数不少于 e。

### 7.2 手写实现与变形

三把 512 位密钥、e=3、同一条明文：

```python
# t6_hastad.py —— Håstad 广播：同一明文、e=3、三组不同模数
from sympy import nextprime
from Crypto.Util.number import bytes_to_long, long_to_bytes
import gmpy2

# ---------- 自造靶：三把密钥，同一明文 ----------
keys = []
for salt in range(3):
    p = nextprime(2**255 + salt * 2**200 + 7 * 10**6)
    q = nextprime(2**255 + salt * 2**210 + 11 * 10**6)
    keys.append((p, q))

e = 3
m = bytes_to_long(b"flag{h4st4d_br04dc4st}")
assert m < min(p for p, q in keys)
cs = [pow(m, e, p * q) for p, q in keys]
for i, (p, q) in enumerate(keys):
    print("N%d = p%d*q%d，%d 比特,  c%d = %d" % (i + 1, i + 1, i + 1, (p * q).bit_length(), i + 1, cs[i]))

# ---------- CRT 组合 + 整数开立方 ----------
def crt(rs, ms):
    M = 1
    for mm in ms:
        M *= mm
    x = 0
    for r, mm in zip(rs, ms):
        Mi = M // mm
        x += r * Mi * pow(Mi, -1, mm)
    return x % M

X = crt(cs, [p * q for p, q in keys])
print("CRT 组合结果的比特数 =", X.bit_length(), "  N1*N2*N3 的比特数 =", sum((p * q).bit_length() for p, q in keys))
r, exact = gmpy2.iroot(X, e)
print("整数开三次方开尽 =", exact)
print("恢复的明文 =", long_to_bytes(int(r)))
print("验算 pow(r,3) == X:", int(r) ** e == X)
```

输出：

```
N1 = p1*q1，511 比特,  c1 = 2350226144246572682596323540608913885523635313971790392251029189167677171877892032577336788652070271698747289360457079287346187112570675818322773595279177
N2 = p2*q2，511 比特,  c2 = 2350226142645648174940449615832966760329576197050737858620095460414703609157472406735640201343592039646826223962776827096220393109181121212081830854537809
N3 = p3*q3，511 比特,  c3 = 2350226141044723667284575602274558802729969246491651794955879998547667610573777988352525278366453049937578761030549060156002723815263131677387949017078057
CRT 组合结果的比特数 = 525   N1*N2*N3 的比特数 = 1533
整数开三次方开尽 = True
恢复的明文 = b'flag{h4st4d_br04dc4st}'
验算 pow(r,3) == X: True
```

CRT 组合结果 525 比特、远小于模数乘积的 1533 比特，开方开尽标志为真——三重信号确认 X 就是 $m^3$ 本身。

> [!info]- 份数不够 e 时：与 Coppersmith 的衔接
> 只拿到 k < e 份密文时，$m^e \ge \prod_{i \le k} N_i$，开方开不尽。若明文带已知格式，把每条密文写成 $(A_i x + B_i)^e - c_i$（未知 x 是那一小块），k 个多项式对同一个根 x₀，联立后用 Coppersmith 的多变量推广仍可恢复——这正是 Håstad 广播攻击的完整定理形态（带 padding 的广播），细节属于格方法进阶，本章先记下"份数不够时接 Coppersmith"这条对应关系。

> [!warning] 开不尽先查两件事
> `iroot` 返回 exact=False 时：组数是否少于 e（$m^e$ 超出乘积）；模数是否两两互质（CRT 阶段的 `pow(Mi, -1, mm)` 会先报逆元不存在）。都正常还开不尽，说明有接收方加了填充，密文不是 $m^e \bmod N$ 本身——那是另一道题。

## 8. 工具对照

### 8.1 三条路的一致性

本章每个结论都至少走过两条独立路径：教学靶的根 `1936536369` 由 fpylll 手写版、sympy 版、sage `small_roots` 三方一致确认（3.4、3.5）；Franklin-Reiter 的 m1 手写 gcd 与 RsaCtfTool 一致（6.2）。做题时同样建议保留一条"慢但透明"的手写路径——工具报错或结果可疑时，它是唯一能拆开看内部状态的版本。

### 8.2 RsaCtfTool 三连

剩下三个攻击各打一个自造靶。靶材由一个生成脚本备好：hastad 靶是三份 512 位广播公钥 PEM（`/tmp/c08/hastad_pub1..3.pem`，同一明文 `flag{h4st4d_br04dc4st}`）；lattice 靶是 512 位 N 配一份"部分私钥"PEM（`/tmp/c08/partial.pem`，标准 RSA 私钥 DER 的 9 个 INTEGER 字段，其中 p 字段的低 120 位被置零）：

> [!info]- lattice 靶的参数
> ```
> N = 3351951982485649274893506249551461531871146494263854582811911447544690631550471239799496055756081618047753176226507565509612104605801748248956116964962499
> e = 65537
> c = 1700550200935880515234240915418684534668232542639605041125629651688589691461509430667199028149908620033039359117350718243072335153971043952505742648372606
> ```

**stereotyped_message**（打 5.2 的靶一，`--sm-len` 给未知字节数、`--sm-prefix` 给前缀）：

```bash
RsaCtfTool -n 79570318139457338664315466006212891086657109485636557383535197790824494228025107051495064089661693346814199462208824299719737996966188812034227051603317908736757230614370836124818265909010138121752327366740060119132482748794243281254619111776358572893179055090956870792017570037858831059817975621264875854181 \
           -e 3 \
           --decrypt 4458558515803227773073572688400855413263478025047657123687639522743071895533893809542138614414067118080786007929289702537696204252695491530172776793144386985848295037768541608466766836833 \
           --attack stereotyped_message --sm-len 8 --sm-prefix 'flag{kn0wn_pr3f1x_'
```

输出：

```
[*] Performing stereotyped_message attack on /tmp/tmp5aq0kbj3.
[*] Stereotyped message parameters: A=1, B=164587995846535011112736454312167023982603259224805915838382080, X=18446744073709551616
[+] Stereotyped message recovered: b'flag{kn0wn_pr3f1x_u_r_c08!'
[*] Attack success with stereotyped_message method !

Results for /tmp/tmp5aq0kbj3:

Decrypted data :
HEX : 0x666c61677b6b6e30776e5f7072336631785f755f725f63303821
utf-8 : flag{kn0wn_pr3f1x_u_r_c08!
STR : b'flag{kn0wn_pr3f1x_u_r_c08!'
```

参数行 `A=1, B=164587995846535011112736454312167023982603259224805915838382080` 正是 5.2 节 note 里的 $M = A \cdot x + B$ 分解：A=1（未知在尾部），B = 前缀左移 8 字节的数值；`X=18446744073709551616` 即 $2^{64}$。结果与 sage `small_roots` 一致。

**hastads**（multi_keys 攻击，公钥用通配符给、密文逗号分隔，顺序一一对应）：

```bash
RsaCtfTool --attack hastads \
           --publickey '/tmp/c08/hastad_pub*.pem' \
           --decrypt 2350226144246572682596323540608913885523635313971790392251029189167677171877892032577336788652070271698747289360457079287346187112570675818322773595279177,2350226142645648174940449615832966760329576197050737858620095460414703609157472406735640201343592039646826223962776827096220393109181121212081830854537809,2350226141044723667284575602274558802729969246491651794955879998547667610573777988352525278366453049937578761030549060156002723815263131677387949017078057
```

输出：

```
[*] Multikey mode using keys: /tmp/c08/hastad_pub1.pem, /tmp/c08/hastad_pub2.pem, /tmp/c08/hastad_pub3.pem
[*] Performing hastads attack.
[*] Attack success with hastads method !

Results for /tmp/c08/hastad_pub1.pem,/tmp/c08/hastad_pub2.pem,/tmp/c08/hastad_pub3.pem:

Decrypted data :
HEX : 0x666c61677b6834737434645f6272303464633473747d
INT (big endian) : 38321129010648070131481768434109736969517944156681341
utf-8 : flag{h4st4d_br04dc4st}
STR : b'flag{h4st4d_br04dc4st}'
```

**lattice**（素数高位已知，对应第 4 节；它需要"部分私钥"PEM——n、e 之外还带一个低位被置零的 p 字段，`--partial` 声明按部分私钥解析）：

```bash
RsaCtfTool --partial --key /tmp/c08/partial.pem --attack lattice \
           --decrypt 1700550200935880515234240915418684534668232542639605041125629651688589691461509430667199028149908620033039359117350718243072335153971043952505742648372606
```

输出：

```
[*] Performing lattice attack on /tmp/c08/partial.pem.
[*] Attack success with lattice method !

Decrypted data :
HEX : 0x666c61677b7034727431346c5f6b33797d
utf-8 : flag{p4rt14l_k3y}
STR : b'flag{p4rt14l_k3y}'
```

内部调的就是第 4 节的数学（Coppersmith 找回被置零的 120 位）。RsaCtfTool 另有 `partial_p` 攻击走同一数学，参数直接挂命令行（`--p-high` 给置零后的 p、`--p-unknown-bits` 给未知位数），不必构造 PEM；二选一即可。

> [!note] Coppersmith 系攻击的 sage 依赖
> RsaCtfTool 的 `stereotyped_message`、`lattice`、`partial_p` 都要 `import sage.all`：apt 方式安装的 sage 对系统 python 直接可见，开箱即用；conda/独立安装的 sage 需要把 RsaCtfTool 放到 sage 的解释器下跑，并给 sage 环境补齐 RsaCtfTool 的普通依赖（tqdm、pycryptodome、cryptography 等）。缺依赖时的报错是 `requires Sage dependency` 或 `ModuleNotFoundError: tqdm`，与攻击本身无关。

## 9. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 手写 Coppersmith 跑完没有任何行能还原出根 | 前缀的数值位置写错：`bytes_to_long(prefix + unknown)` 是 $P \cdot 256^s + x$，多项式必须写 $(P \cdot 256^s + x)^e - c$，直接写 $(P + x)^e$ 时 $f(x_0)$ 不再 ≡ 0 (mod N)，整格失效且不报错（[[#3.4 手工实现：fpylll 版\|3.4]]） |
| LLL 约减"成功"（第一行明显变短）但找不到根 | $f^i$ 的系数在逐步乘法里对 N 取了模，整数求值时的高次 N 因子被丢掉，$g_{i,j}(x_0) \equiv 0 \pmod{N^m}$ 不再成立；$f^i$ 只能不取模或统一 mod $N^m$（[[#3.4 手工实现：fpylll 版\|3.4]]） |
| 想覆盖更大的未知块 X，m 怎么调都不够 | 先查 N 本身：m=3 时 X 必须 < $N^{3/11}$，N 增大比调参划算得多；$N^{1/3}$ 的换算表见 [[#3.3 格构造与参数 m\|3.3]] |
| `small_roots` 返回空列表 | 依次查三处：X 是否超过 $N^{\beta^2/\delta}$ 硬上界（信息不够，无解）；X 是否超出当前参数能力（调小 epsilon 重试）；beta 是否高估了除子占比（[[#4.3 三条边界\|4.3]]） |
| `small_roots` 默认参数失败，调小 epsilon 后成功 | 默认 epsilon = beta/8，(m, t) 随之偏小；epsilon 每减一档格的维度涨一截、耗时变长，这是"接近理论边界"的固定代价（[[#4.3 三条边界\|4.3]]） |
| beta 照抄 0.5 却不收敛 | beta 是"除子 ≥ $N^\beta$"的下界承诺，p 略小于 $N^{1/2}$ 时 0.5 就是高估；按 p 的真实占比取保守值（[[#4.1 问题形态与攻击原理\|4.1]]） |
| fpylll 与 sympy 的 LLL 结果对不上 | 两者都按"行 = 基向量"读输入；矩阵被转置后 fpylll 照跑不报错但约减的是另一个格，`DomainMatrix` 形状给错直接抛 `DMBadInputError`（[[#2.5 sympy 对照与行、列约定\|2.5]]） |
| 还原多项式时系数除不尽 $X^k$ | 该行不是合格的 Howgrave-Graham 多项式组合，跳过换下一行；目标根不总在 LLL 第一行，按行循环并把候选全部回代验算（[[#3.4 手工实现：fpylll 版\|3.4]]） |
| `nroots` 报 convergence to root failed 或给出错根 | 系数是几百位大数，默认精度不够；改用 `real_roots()`（精确隔离实根），取整后的候选必须回代 `pow(P + cand, e, N) == c` 确认（[[#3.4 手工实现：fpylll 版\|3.4]]） |
| sage 里 `gcd(x^3 - c1, (x+delta)^3 - c2)` 报 NotImplementedError | sage 的多项式 gcd 只对域实现，`Zmod(N)`（N 合数）没有；Franklin-Reiter 的手写欧几里得就是正解（[[#6.2 手写多项式 gcd 与工具对照\|6.2]]） |
| 多项式 gcd 跑一半报 `base is not invertible` | 余式的尾随零没去掉，对零多项式的"首项"求逆；每次余式算完先 trim 再判空（[[#6.2 手写多项式 gcd 与工具对照\|6.2]]） |
| stereotyped 的 `--sm-len` 多给 1 字节就拒绝执行 | $X = 256^{sm\text{-}len}$，工具先查 $\text{pow}(X, e) \ge n$，触线即拒；这就是式 (5.2) 的边界（[[#5.2 自建靶实战与边界\|5.2]]） |
| RsaCtfTool 报 `requires Sage dependency` 或 `ModuleNotFoundError: tqdm` | Coppersmith 系攻击直接 `import sage.all`：apt 的 sage 开箱即用，conda 的 sage 要把依赖装进 sage 环境并用其解释器启动（[[#8.2 RsaCtfTool 三连\|8.2]]） |
| Håstad 的 `iroot` 返回 exact=False | 组数少于 e（$m^e$ 超出模数乘积），或某接收方加了填充使密文不是 $m^e \bmod N$ 本身；先核组数与互质性（[[#7.2 手写实现与变形\|7.2]]） |

## 10. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **自造靶全链路**：按本章套路自造一道 stereotyped 题——p、q 取 512 位，e=3，明文 = 16 字节固定报文头 + 6 字节随机尾部，只发布 n、e、c 和报文模板。分别用 sage `small_roots` 和 RsaCtfTool `--attack stereotyped_message` 解出，两边明文必须逐字节一致。
> 2. **边界扫描**：把 4.2 的靶改成泄露 p 的高 128、120、112、104 位各跑一次，记录每组在默认与调小 epsilon 后的成败与耗时，画出"已知比特数 vs 可行性"的成功率边界。
> 3. **相关消息变体**：把 6.2 的关系改成 $m_2 = 3 \cdot m_1 + 7$（a ≠ 1），改写 $g_2$ 并重解；再确认 a、b 取大数时式 (6.1) 依旧成立——手写 gcd 一行不用改。
> 4. **广播边界**：把明文换成 60 字节（此时 $m^3$ 超过两个 512 位模数之积），只广播两份（k=2 < e=3），确认 `iroot` 开不尽；再补齐第三份恢复成功。用这组数据解释式 (7.1) 里 $m^e < \prod N_i$ 这一条的具体含义。

配套练习：

1. 把 3.4 的手写版推广到 e=5：多项式次数、格的维度、m 的选择跟着式 (3.4) 重算一遍，并在同一个 140 位 N 上解一个 5 次的靶；对照 sage `small_roots` 的结果。
2. 给 5.2 加一个"未知在中间"的变体：明文 = 8 字节前缀 + 6 字节未知 + 4 字节后缀，写出 A、B 并确认 `small_roots` 依旧一次解出。
3. 用 sympy 的 `DomainMatrix.lll` 对拍 4.2 的靶：把 3.4 的手写版改造成除子版——Howgrave-Graham 的阈值从 $N^m$ 提到 $N^{\beta m}$（$\beta = 0.49$，b ≥ $N^\beta$），加大 m 直到式 (3.5) 在 $X = 2^{100}$ 下成立，看能否找回同一个 p。
4. 把本章四个攻击写成四个可插拔的 `solve` 片段（输入 n、e、密文与已知信息，输出明文），挂到 [[C01-密码学导论与工具链|C01]] 第 6 节的工作流模板上，作为 Stage 2 RSA 攻击工具箱的收尾。

延伸阅读：

- Boneh, *Twenty Years of Attacks on the RSA Cryptosystem*（Notices of the AMS, 1999）：RSA 已知攻击的最佳综述，Coppersmith 一族在本章 3 至 5 节的位置可以在文中找到对应；
- Coppersmith, *Finding a Small Root of a Univariate Modular Equation*（EUROCRYPT 1996）：单变量情形的原始论文，式 (3.1) 的出处；
- facthacks.cr.yp.to：一组短小的 sage 格攻击脚本（含 lattice.sage 的原型），适合逐行对照 3.4 的手写版；
- [[02-书单与Wiki|书单与 Wiki]]：数论与格方向的入门书条目；
- 下一站：格的完整理论（LLL 的正确性、LWE、格密码体制 NTRU/Kyber）以及多变量 Coppersmith，在本库后续的格密码章节（C13 起）展开——本章的 2、3 两节正是那边的直接地基。
