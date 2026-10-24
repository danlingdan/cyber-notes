---
chapter: 密码学
section: 格密码与 LLL
order: 713
tags:
  - CTF
  - 密码学
  - 格密码
  - LLL
publish: true
---

# C13 格密码与 LLL
## Lattices & the LLL Algorithm

> [!info]- 章节信息
> **所属方向**：密码学 ｜ **难度阶段**：L3 进阶期 ｜ **前置要求**：[[09-密码学基础|09 章]] · [[C02-数论进阶与原根|C02]] · [[C08-RSA攻击II|C08]]
> **本章目标**：把 [[C08-RSA攻击II#2. 格的最小必要知识|C08 §2]] 的最小必要知识展开成完整的一套：会算行列式、会做 Gram-Schmidt、能手写一版 LLL 并与 fpylll / sympy / sage 三方对拍；说清 SVP、CVP、SIP 三个核心问题谁难、LLL 近似解的是什么；会用高斯约简精确解二维 SVP、用 Babai 最近平面在约减基上解 CVP；能看懂"已知高位补全数对"这类格靶的构造思路，为下一章的密码分析应用打底。

## 1. 格：点集、基与行列式

[[C08-RSA攻击II#2. 格的最小必要知识|C08 §2]] 给过定义：格（lattice）是一组线性无关的基向量 $b_1, \dots, b_d \in \mathbb{Z}^n$ 的全部**整数**线性组合构成的点集，本章统一按行向量约定写基矩阵（每一行是一个基向量）：

$$L = \left\{ \sum_{i=1}^{d} a_i b_i \;\middle|\; a_i \in \mathbb{Z} \right\} \tag{1.1}$$

本节补上当时一句带过的两件事：同一格有无穷多组基，以及行列式为什么是格的不变量。

### 1.1 好基与坏基

取二维的两组基：$B_g = \{(3,1), (1,2)\}$ 与 $B_b = \{(3,1), (28,11)\}$。第二组的第二行是第一行加 9 倍第一行得来的：$(1,2) + 9 \cdot (3,1) = (28,11)$——基向量互相加减整数倍，张出的点集不变，所以两组基张出**同一个格**。但两组基的"形状"天差地别：

```python
# s1_basis.py —— 同一格的两组基；换基不变量：行列式
import math

def norm(v):
    return math.sqrt(sum(x * x for x in v))

g = [(3, 1), (1, 2)]                       # 好基：两个短向量，夹角 45 度
b = [(3, 1), (28, 11)]                     # 坏基：第二个向量 = 第一个 + 9 倍第一个

for name, B in [("好基", g), ("坏基", b)]:
    print("%s: %s" % (name, [tuple(r) for r in B]))
    for r in B:
        print("    %s  范数 %.2f" % (tuple(r), norm(r)))
    ang = math.degrees(math.acos((B[0][0]*B[1][0] + B[0][1]*B[1][1]) / (norm(B[0]) * norm(B[1]))))
    det = abs(B[0][0] * B[1][1] - B[0][1] * B[1][0])
    print("    两向量夹角 %.1f 度   |det| = %d" % (ang, det))
```

输出：

```
好基: [(3, 1), (1, 2)]
    (3, 1)  范数 3.16
    (1, 2)  范数 2.24
    两向量夹角 45.0 度   |det| = 5
坏基: [(3, 1), (28, 11)]
    (3, 1)  范数 3.16
    (28, 11)  范数 30.08
    两向量夹角 3.0 度   |det| = 5
```

好基的两个向量都短、夹角接近直角；坏基里有一个又长又斜的向量。==换基不动格本身，动的只是基向量的坐标形状==。后面两节的所有算法都围绕同一个目标：**从坏基出发，把好基找回来**。

把"整数倍加减"写成矩阵：$B_b = U \cdot B_g$，其中 $U$ 是整数矩阵且 $|\det U| = 1$（这样的 $U$ 叫 **unimodular 矩阵**，初等行变换"整行加整数倍另一行"与"换行"每步都保持 $|\det| = 1$）。行列式乘法公式给出不变性：

$$|\det B_b| = |\det U| \cdot |\det B_g| = |\det B_g| \tag{1.2}$$

### 1.2 行列式：格的不变量

方阵基（$d = n$）时，$|\det B|$ 等于基向量张成的平行体（二维是平行四边形，三维是平行六面体）的体积，这块区域取半开边界就是格的**基本域**——每个基本域里恰好平均落着一个格点，所以 $1/|\det B|$ 就是格点密度。$\det^{1/d}$（[[C08-RSA攻击II#2. 格的最小必要知识|C08 §2]] 的"典型间距"）由此而来：格点在 $d$ 维空间里的平均间距。行列式是格的坐标无关属性，换任何基都不变，下面把这件事在 3 维和 4 维各过一遍：

```python
# s1_det.py —— unimodular 换基，行列式不变
import random
import sympy

def norm(v):
    return sum(x * x for x in v) ** 0.5

def matmul(A, Bm):
    return [[sum(A[i][k] * Bm[k][j] for k in range(len(Bm)))
             for j in range(len(Bm[0]))] for i in range(len(A))]

def detn(M):
    return abs(int(sympy.Matrix(M).det()))

G3 = [[2, 0, 1], [1, 3, 0], [0, 1, 4]]
U = [[1, 0, 0], [5, 1, 0], [-3, 7, 1]]     # 下三角，det = 1
B3 = matmul(U, G3)
print("三维：坏基 = U·好基")
for r in B3:
    print("   %s  范数 %.2f" % (tuple(r), norm(r)))
print("|det(好基)| = %d   |det(坏基)| = %d" % (detn(G3), detn(B3)))

def rand_unimod(n, steps=8, big=9):
    U = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    for _ in range(steps):
        i, j = random.sample(range(n), 2)
        k = random.randint(-big, big)      # k 只抽一次：整行乘同一个系数才是初等行变换
        U[i] = [x + k * y for x, y in zip(U[i], U[j])]
    if random.random() < 0.5:              # 随机换两行，det 翻成 -1
        U[0], U[1] = U[1], U[0]
    return U

random.seed(13)
G4 = [[random.randint(-9, 9) for _ in range(4)] for _ in range(4)]
print()
print("四维随机基，随机 unimodular 换基 50 次:")
print("  原基 |det| =", detn(G4))
ok = True
for t in range(50):
    Bu = matmul(rand_unimod(4), G4)
    if detn(Bu) != detn(G4):
        ok = False
    if t in (0, 1, 49):
        print("  第 %2d 次换基后各行范数: %s" % (t + 1, ["%.0f" % norm(r) for r in Bu]))
print("50 次换基 |det| 全部不变:", ok)
```

输出：

```
三维：坏基 = U·好基
   (2, 0, 1)  范数 2.24
   (11, 3, 5)  范数 12.45
   (1, 22, 1)  范数 22.05
|det(好基)| = 25   |det(坏基)| = 25

四维随机基，随机 unimodular 换基 50 次:
  原基 |det| = 902
  第  1 次换基后各行范数: ['150', '146', '23', '39']
  第  2 次换基后各行范数: ['5', '35', '15', '66']
  第 50 次换基后各行范数: ['37102', '6185', '150219', '18385']
50 次换基 |det| 全部不变: True
```

三维例子里坏基的最长行是 22，比好基的 4.12 长了五倍，行列式纹丝不动；四维随机换基 50 次，基向量最长被换到十几万，$|\det|$ 仍是 902。==比较不同的格用行列式，比较同一格的不同基用范数==。

> [!note] 行列式与体积
> "行列式"和"体积"在方阵基下是一回事，但说法有别：det 是基矩阵的属性（带符号），体积是格的属性（恒正），混用时记得取绝对值。基不是方阵（比如 3 行 4 列）时没有普通行列式，要用格拉姆矩阵行列式开方 $\sqrt{\det(BB^T)}$——Coppersmith 的构造里格"高瘦"（行数多于多项式系数个数），那条路才用得上，本章的例全是方阵基。

## 2. 三个核心问题：SVP、CVP、SIP

格上的计算问题就三个，全章的算法都围着它们转：

| 问题 | 输入 | 输出 | 一句话 |
| ---- | ---- | ---- | ---- |
| SVP（最短向量） | 格的基 | 非零格点 $v$ 使 $\|v\| = \lambda_1$ | 格里最短的非零向量有多短、是什么 |
| CVP（最近向量） | 格的基 + 目标 $t$ | 格点 $v$ 使 $\|t - v\|$ 最小 | 离目标最近的格点是哪个 |
| SIP（整数关系） | 实数 $x_1, \dots, x_n$ | 非零整数组 $(a_i)$ 使 $\sum a_i x_i = 0$ | 这组数之间的整系数线性关系 |

前两个的定量定义：

$$\lambda_1 \;=\; \min_{v \in L \setminus \{0\}} \|v\| \tag{2.1}$$

$$\mathrm{dist}(t, L) \;=\; \min_{v \in L} \|t - v\| \tag{2.2}$$

SIP 看着不像格问题，把它排进表里是因为一条经典转换：把 $x_1, \dots, x_n$ 放进格构造（每行是 $x_i$ 的放大取整加一个单位坐标），短向量就编码了小系数关系——LLL 论文当年用它做实系数多项式的精确分解。CTF 里"这串数是不是满足某条线性递推"一类问题，落点就是 SIP。

难度分层是本章的地图：

- **精确解**：CVP 精确解是 NP 难的（van Emde Boas, 1981）；SVP 精确解在随机归约意义下 NP 难（Ajtai, 1998），近似到足够小的因子依旧难。==高维格上"精确找短/找近"没有已知的高效算法==，这也是 LWE、NTRU、Kyber 这类格密码体制敢把安全性押在它上面的原因；
- **近似解**：LLL 在多项式时间给出近似比 $2^{\frac{n-1}{2}}$ 的 SVP 解（第 4 节拆这个数的含义），Babai 最近平面给出 CVP 的近似解（第 5 节）；
- **低维例外**：2 维的 SVP 和 CVP 都能**精确**解——高斯在 19 世纪就给出了算法（第 6 节）。

==格攻击的全部艺术，在于把题目里的未知数安排成某个格的短向量，再用近似算法把它"钓"出来==。安排得好不好，直接决定近似算法够不够用。

## 3. Gram-Schmidt 与手写 LLL

### 3.1 Gram-Schmidt 正交化

LLL 的全部几何语言建立在 Gram-Schmidt（GS）正交化上。对基 $b_1, \dots, b_n$ 依次做投影剥离：

$$b_i^* \;=\; b_i - \sum_{j<i} \mu_{i,j}\, b_j^*, \qquad \mu_{i,j} \;=\; \frac{\langle b_i,\, b_j^* \rangle}{\langle b_j^*,\, b_j^* \rangle} \tag{3.1}$$

$b_i^*$ 是 $b_i$ 垂直于前 $i-1$ 个正交化向量的分量，$\mu_{i,j}$ 是 $b_i$ 在 $b_j^*$ 方向上的坐标。GS 只改坐标形状不改张成空间：$b_1, \dots, b_i$ 与 $b_1^*, \dots, b_i^*$ 张成同一个实向量空间——但 $b_i^*$ 一般**不是**格向量（系数不再是整数），它只是几何参考系。用手写小数不放心，下面的实现全程用 `Fraction` 精确有理数：

```python
# s3_gs.py —— Gram-Schmidt（精确有理数）与手写教学版 LLL
from fractions import Fraction

def dot(u, v):
    return sum(a * b for a, b in zip(u, v))

def rnd(x):
    """Fraction 四舍五入到最近整数（floor(x + 1/2)，避开 Python round 的银行家舍入）"""
    return (2 * x.numerator + x.denominator) // (2 * x.denominator)

def gso(B):
    """返回正交向量组 bs 与系数 mu：mu[i][j] = <b_i, b_j*> / <b_j*, b_j*>"""
    n = len(B)
    bs, mu = [], [[Fraction(0)] * n for _ in range(n)]
    for i in range(n):
        v = [Fraction(x) for x in B[i]]
        for j in range(i):
            mu[i][j] = dot(v, bs[j]) / dot(bs[j], bs[j])
            v = [v[k] - mu[i][j] * bs[j][k] for k in range(len(v))]
        bs.append(v)
    return bs, mu

B2 = [(3, 1), (28, 11)]
bs, mu = gso(B2)
print("基 =", B2)
for i in range(2):
    print("  b%d* = (%s)  |b%d*|^2 = %s" % (i + 1, ", ".join(str(x) for x in bs[i]),
                                            i + 1, dot(bs[i], bs[i])))
print("  mu[2][1] = %s" % mu[1][0])
```

输出：

```
基 = [(3, 1), (28, 11)]
  b1* = (3, 1)  |b1*|^2 = 10
  b2* = (-1/2, 3/2)  |b2*|^2 = 5/2
  mu[2][1] = 19/2
```

坏基的 $\mu_{2,1} = 19/2$：第二个基向量几乎整个压在第一个方向上，垂直分量只剩长度平方 $5/2$——这就是"长而斜"的定量形状。

### 3.2 size reduce 与 Lovász 条件

LLL 是两步操作的循环，都对着 GS 坐标做：

1. **size reduce**（消系数）：若 $|\mu_{i,j}| > 1/2$，取 $r = \text{round}(\mu_{i,j})$，令 $b_i \leftarrow b_i - r\, b_j$。减的是基向量的整数倍，格不变；效果是把 $\mu_{i,j}$ 拉回 $[-1/2, 1/2]$；
2. **Lovász 交换**：若相邻两条满足

$$\|b_i^*\|^2 \;\ge\; \left(\delta - \mu_{i,i-1}^2\right) \cdot \|b_{i-1}^*\|^2 \tag{3.2}$$

就往前走；否则交换 $b_i$ 与 $b_{i-1}$ 并回退。$\delta$ 是质量参数，经典取 $3/4$，工程实现常用 $0.99$。

式 (3.2) 的读法：交换的触发条件是 $b_{i-1}$ 的垂直分量"吃掉了太多" $b_i$ 的垂直分量，交换后这团长分量会挪到靠前的位置，让整组基的垂直分量趋于均衡——垂直分量均衡，就是"接近正交"。循环到所有位置都满足 (3.2) 且所有 $|\mu_{i,j}| \le 1/2$ 为止，输出的就是一组约减基。

### 3.3 手写教学版 LLL

上面两步装进循环，完整实现如下（连 GS 一起 40 行出头；`trace=True` 时打印每步，供对拍与调试）：

```python
# s3_lll.py —— 教学版 LLL（接 s3_gs.py 的 dot / rnd / gso）
def lll(B, delta=Fraction(99, 100), trace=False):
    B = [list(row) for row in B]
    n = len(B)
    i = 1
    while i < n:
        bs, mu = gso(B)
        for j in range(i - 1, -1, -1):                  # size reduce：消去 mu
            r = rnd(mu[i][j])
            if r:
                B[i] = [B[i][k] - r * B[j][k] for k in range(len(B[i]))]
                bs, mu = gso(B)
                if trace:
                    print("    reduce: b%d -= %d * b%d -> %s" % (i + 1, r, j + 1, B[i]))
        lhs = dot(bs[i], bs[i])
        rhs = (delta - mu[i][i - 1] ** 2) * dot(bs[i - 1], bs[i - 1])
        if lhs >= rhs:                                  # Lovasz 条件成立，前进
            if trace:
                print("    Lovasz 通过：|b%d*|^2 = %s >= (%s - mu^2) * |b%d*|^2 = %s"
                      % (i + 1, lhs, delta, i, rhs))
            i += 1
        else:                                           # 不成立，交换后回退
            if trace:
                print("    Lovasz 失败：|b%d*|^2 = %s < %s，交换 b%d <-> b%d"
                      % (i + 1, lhs, rhs, i + 1, i))
            B[i], B[i - 1] = B[i - 1], B[i]
            i = max(i - 1, 1)
    return B

BAD = [(3, 1), (28, 11)]
print("手写 LLL 逐步 trace，输入基 =", BAD)
out2 = lll(BAD, trace=True)
print("输出基 =", out2)
print("输出各行范数 = %s" % ["%.4f" % (dot(r, r) ** 0.5) for r in out2])
```

输出：

```
手写 LLL 逐步 trace，输入基 = [(3, 1), (28, 11)]
    reduce: b2 -= 10 * b1 -> [-2, 1]
    Lovasz 失败：|b2*|^2 = 5/2 < 37/5，交换 b2 <-> b1
    reduce: b2 -= -1 * b1 -> [1, 2]
    Lovasz 通过：|b2*|^2 = 5 >= (99/100 - mu^2) * |b1*|^2 = 99/20
输出基 = [[-2, 1], [1, 2]]
输出各行范数 = ['2.2361', '2.2361']
```

四步看完整个算法：先 size reduce 把 $(28,11)$ 削成 $(-2,1)$（$\mu_{2,1} = 19/2$，取整 10）；Lovász 检查发现 $b_1$ 的垂直分量太大，交换；再 size reduce 一次得到 $(1,2)$；条件满足，终止。输出两行范数都是 $\sqrt5 = 2.2361$——正是这个格的最短向量（第 6 节证明二维能精确做到）。

> [!warning] 三个手写坑
> **一，`round()` 的银行家舍入**：Python 的 `round(0.5) = 0`、`round(1.5) = 2`、`round(2.5) = 2`——偶数优先。LLL 的 size reduce 在 $\mu$ 恰为半整数时会被它带偏，`floor(x + 1/2)` 才是"四舍五入"。
> **二，用 float 做 GS**：格攻击的格动辄几百位大数，float 只有 53 位精度，$\mu$ 算出来是噪声；教学版用 `Fraction` 慢但精确，工程上交给 fpylll。
> **三，忘更新 GS**：size reduce 之后 $b_i$ 变了，对应的 $\mu_{i,j}$ 必须重算（或按增量公式更新）；交换后受影响的三组系数同理。工业实现全用增量更新省时间，教学版每次重算 `gso()`——慢，但不会漏。手写版"死循环"或"约不动"，先查这三处。

### 3.4 四路对拍

同一组输入，四条独立实现应当给出同一个（本质相同的）约减基。造一个 4 维坏基——好基经 12 步随机 unimodular 变换，行范数从个位数膨胀到几百上千万：

```python
# s3_check.py —— 手写 / fpylll / sympy 三路对拍（sage 见下）
import random
import sympy
from fractions import Fraction
from fpylll import IntegerMatrix, LLL
from sympy.polys.matrices import DomainMatrix
from sympy import ZZ
from gmpy2 import mpq

def detn(M):
    return abs(int(sympy.Matrix(M).det()))

def check_same_lattice(Bout, Bin):
    """Bout 的每一行都能用 Bin 的行整数组合表出，且变换矩阵 |det| = 1"""
    Bo, Bi = sympy.Matrix(Bout), sympy.Matrix(Bin)
    U = (Bo * Bi.inv()).applyfunc(sympy.nsimplify)
    ints = all(c == int(c) for c in U)
    return ints and abs(int(U.det())) == 1

rng = random.Random(2026)
def rand_unimod(n, steps, big, rng):
    U = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    for _ in range(steps):
        i, j = rng.sample(range(n), 2)
        k = rng.randint(-big, big)
        U[i] = [x + k * y for x, y in zip(U[i], U[j])]
    if rng.random() < 0.5:
        U[0], U[1] = U[1], U[0]
    return U

G4 = [[2, 1, 0, 3], [1, 3, 2, 0], [0, 1, 4, 2], [3, 0, 1, 5]]
U4 = rand_unimod(4, 12, 9, rng)
B4 = [[sum(U4[i][k] * G4[k][j] for k in range(4)) for j in range(4)] for i in range(4)]
print("输入基（各行范数）:", [round(sum(x*x for x in r) ** 0.5, 1) for r in B4])

results = {}
results["手写"] = lll(B4)                                  # s3_lll.py 的实现

A = IntegerMatrix.from_matrix(B4)
LLL.reduction(A, delta=0.99)
results["fpylll"] = [[A[i, j] for j in range(A.ncols)] for i in range(A.nrows)]

L = DomainMatrix(B4, (4, 4), ZZ).lll(delta=mpq(99, 100))
results["sympy"] = [[int(x) for x in row] for row in L.to_list()]

print("手写   LLL 输出:", results["手写"])
print("fpylll LLL 输出:", results["fpylll"])
print("sympy  LLL 输出:", results["sympy"])
for name, R in results.items():
    keys = sorted(round(sum(x * x for x in r) ** 0.5, 6) for r in R)
    print("  %-7s 范数多重集: %s  同格检查: %s  |det| = %d"
          % (name, keys, check_same_lattice(R, B4), detn(R)))
```

输出：

```
输入基（各行范数）: [435.2, 67059.3, 7153.9, 66166.2]
手写   LLL 输出: [[-1, 1, 0, 1], [2, 1, -1, 0], [1, -1, 1, 2], [0, 1, 3, -1]]
fpylll LLL 输出: [[-1, 1, 0, 1], [2, 1, -1, 0], [1, -1, 1, 2], [0, 1, 3, -1]]
sympy  LLL 输出: [[-1, 1, 0, 1], [2, 1, -1, 0], [1, -1, 1, 2], [0, 1, 3, -1]]
  手写      范数多重集: [1.732051, 2.44949, 2.645751, 3.316625]  同格检查: True  |det| = 35
  fpylll  范数多重集: [1.732051, 2.44949, 2.645751, 3.316625]  同格检查: True  |det| = 35
  sympy   范数多重集: [1.732051, 2.44949, 2.645751, 3.316625]  同格检查: True  |det| = 35
```

三条路逐行一致：输入最长 67059，输出全部压到 1.7–3.3，$|\det| = 35$ 未变。第四路换 sage——sage 的矩阵自带 `LLL` 方法，同一组数一行调完：

```python
# s3_sage.sage —— 同一 4 维坏基，sage 的 M.LLL()
B4 = [[-230, -151, -152, -301], [35424, 23275, 23452, 46372],
      [3779, 2483, 2502, 4947], [34934, 22962, 23171, 45754]]
M = Matrix(ZZ, B4)
L = M.LLL(delta=0.99)
print("sage M.LLL() 输出:")
print(L)
norms = sorted(float(sqrt(sum(RR(x)^2 for x in row))) for row in L.rows())
print("各行范数排序后:", [round(v, 2) for v in norms])
print("|det| =", abs(M.det()))
```

输出：

```
sage M.LLL() 输出:
[-1  1  0  1]
[ 2  1 -1  0]
[ 1 -1  1  2]
[ 0  1  3 -1]
各行范数排序后: [1.73, 2.45, 2.65, 3.32]
|det| = 35
```

四条独立实现给出同一个基。高维同样跑得通：8 维随机坏基上，手写版、fpylll、sympy 三路的输出范数多重集一致（`7.48, 10.05, 12.49, 12.92, 13.11, 14.7, 15.1, 17.52`），$|\det|$ 与输入基相同（318132792）。

> [!note] 判等要按"格 + 范数多重集"，不要逐行比
> LLL 输出基的**行序与每行符号不固定**：交换路径不同、消元顺序不同，完全合法的两份约减基可能行序颠倒、个别行差一个负号。比较两份输出，比较的是（a）$|\det|$ 相同、（b）每行的范数多重集相同、（c）互相整系数表出且变换矩阵 $|\det| = 1$——三条合起来才是"同一个约减基"。本例四路逐行一致是运气好的小例子，别把它当判等标准。

> [!info]- 三个实现的默认参数不同
> fpylll 的 `LLL.reduction` 默认 $\delta = 0.99$；sympy 的 `DomainMatrix.lll` 默认 $\delta = 3/4$；sage 的 `M.LLL` 签名是 `delta=None`，缺省值交给底层 fpLLL（同为 0.99）。多数小例子对不同 $\delta$ 给出相同结果，但边界例子会分叉——对拍时给所有实现**显式传同一个 $\delta$**（fpylll 与 sage 收 float，sympy 收 `mpq`：`DomainMatrix(...).lll(delta=mpq(99, 100))`，`mpq` 从 `gmpy2` 导入）。另外 sympy 的 `DomainMatrix` 行数据要用普通 `int`，传 `sympy.Integer` 元素会在内部类型转换处报 `TypeError: mpq() requires numeric or string argument`。

> [!info]- 高维时手写版就是玩具
> 教学版每步重算 GS，单轮代价约 $O(n^3)$ 再乘轮数，8 维毫秒级、几十位大数也撑得住；但 100 维、上千位的 Coppersmith 格会让它跑 minutes 到 hours，fpylll（C 实现，带浮点与剪枝优化）是秒级。分工固定：==手写版用来理解和调试，fpylll/sage 用来干活==——[[C08-RSA攻击II#3. Howgrave-Graham 与手工 Coppersmith|C08 §3]]的手写 Coppersmith 在 sage `small_roots` 失败时拆格排错，就是这套方法的实战形态。

## 4. LLL 的近似保证与边界

LLL 输出的第一条向量有两条等价形式的保证：

$$\|b_1\| \;\le\; 2^{\frac{n-1}{4}} \cdot \det^{1/n} \tag{4.1}$$

$$\|b_1\| \;\le\; 2^{\frac{n-1}{2}} \cdot \lambda_1(L) \tag{4.2}$$

式 (4.1) 是 [[C08-RSA攻击II#3. Howgrave-Graham 与手工 Coppersmith|C08 §3]] 式 (2.2)，Howgrave-Graham 引理判"够不够短"用的就是它；式 (4.2) 是同一保证相对真最短向量的说法——两个指数是同一枚硬币：把 $\lambda_1 \approx \det^{1/n}$（随机格的典型情形）代入式 (4.2) 就回到式 (4.1)。

两个式子共享同一个要害：**指数里有 $n$**。$2^{\frac{n-1}{2}}$ 意味着最坏情形下 LLL 找到的向量可以是真最短向量的 $2^{\frac{n-1}{2}}$ 倍长：8 维时 11 倍、32 维时 4.6 万倍、64 维时 30 亿倍。落到攻击设计的账本上：要让 LLL **保证**钓出目标向量，目标得比 $\det^{1/n}$ 短得多，而"得多"这个余量随维度指数膨胀——==维度每上一档，"合格短"的门槛就指数级抬高==。[[C08-RSA攻击II#3.3 格构造与参数 m|C08 §3.3]]的参数表（m 越大上界越接近 $N^{1/\delta}$，代价是格维度线性涨）正是这笔账的具体形态。

看数字。随机格上扫一遍维度：第二列是保证系数 $2^{(n-1)/4}$，第三列是 LLL 实际交付的质量（$\|b_1\|/\det^{1/n}$，5 个随机格平均），最右列是经验线 $1.02^n$；第二张表再用精确 SVP 把 $\lambda_1$ 算出来量一次：

```python
# s4_bounds.py —— LLL 保证随维度怎么变；BKZ 换质量
import math, random
import sympy
from fpylll import IntegerMatrix, LLL, SVP, BKZ

rng = random.Random(7)
def norm(v):
    return math.sqrt(sum(x * x for x in v))

print("n    2^((n-1)/4) 上界系数   平均 ||b1||/det^(1/n)   1.02^n 参考")
for n in (8, 16, 24, 32, 40):
    ratios = []
    for _ in range(5):
        B = [[rng.randint(1, 10**4) for _ in range(n)] for _ in range(n)]
        A = IntegerMatrix.from_matrix(B)
        LLL.reduction(A)
        r0 = [A[0, j] for j in range(A.ncols)]
        det = abs(int(sympy.Matrix(B).det()))
        ratios.append(norm(r0) / det ** (1.0 / n))
    print("%-4d %-18.3e %.3f   %.2f"
          % (n, 2 ** ((n - 1) / 4), sum(ratios) / 5, 1.02 ** n))

print()
print("n    ||b1||/lambda1   2^((n-1)/2) 最坏上界")
for n in (8, 16, 24, 32):
    ratios = []
    for _ in range(5):
        B = [[rng.randint(1, 10**4) for _ in range(n)] for _ in range(n)]
        A = IntegerMatrix.from_matrix(B)
        LLL.reduction(A)
        r0 = [A[0, j] for j in range(A.ncols)]
        lam = SVP.shortest_vector(IntegerMatrix.from_matrix(B))
        ratios.append(norm(r0) / math.sqrt(sum(int(x) ** 2 for x in lam)))
    print("%-4d %.4f   %.3e" % (n, sum(ratios) / 5, 2 ** ((n - 1) / 2)))

print()
print("同一个 40 维随机格：LLL vs BKZ(block_size=20)")
B = [[rng.randint(1, 10**4) for _ in range(40)] for _ in range(40)]
det = abs(int(sympy.Matrix(B).det()))
A = IntegerMatrix.from_matrix(B)
LLL.reduction(A)
b1_lll = [A[0, j] for j in range(A.ncols)]
BKZ.reduction(A, BKZ.Param(block_size=20))
b1_bkz = [A[0, j] for j in range(A.ncols)]
print("det^(1/40) = %.1f" % det ** (1 / 40))
print("LLL 第一行范数     = %.1f   （系数 %.3f）" % (norm(b1_lll), norm(b1_lll) / det ** (1 / 40)))
print("BKZ(20) 第一行范数 = %.1f   （系数 %.3f）" % (norm(b1_bkz), norm(b1_bkz) / det ** (1 / 40)))
```

输出：

```
n    2^((n-1)/4) 上界系数   平均 ||b1||/det^(1/n)   1.02^n 参考
8    3.364e+00          0.984   1.17
16   1.345e+01          1.088   1.37
24   5.382e+01          1.327   1.61
32   2.153e+02          1.537   1.88
40   8.611e+02          1.670   2.21

n    ||b1||/lambda1   2^((n-1)/2) 最坏上界
8    1.0000   1.131e+01
16   1.0080   1.810e+02
24   1.0183   2.896e+03
32   1.0050   4.634e+04

同一个 40 维随机格：LLL vs BKZ(block_size=20)
det^(1/40) = 11745.2
LLL 第一行范数     = 20837.1   （系数 1.774）
BKZ(20) 第一行范数 = 19216.3   （系数 1.636）
```

三段读法：

- 上界系数从 3.4 涨到 861（$n$: 8 → 40），指数曲线；实际交付的 $\|b_1\|/\det^{1/n}$ 在 1 附近缓慢上爬，与经验线 $1.02^n$ 同量级（$n=8$ 的 0.984 是小维度波动）。==保证很悲观，交付相当好==——这就是格攻击在"保证不成立"的维度上仍然能打的原因；
- 随机格上 $\|b_1\|/\lambda_1$ 几乎是 1：随机格的短向量不孤立，LLL 随手就能摸到。真正难的是**结构化格**（攻击构造出来的格）：短向量是精心埋进去的孤立点，这时近似保证才算数——设计攻击时要按最坏情形留余量；
- BKZ 在同一个格上把第一行又压短了 8%：==BKZ 用 block size 换质量==——块越大输出越短、耗时指数涨，是 LLL 之后"再挤一点"的标准旋钮（fpylll 里 `BKZ.reduction(A, BKZ.Param(block_size=…))` 一行）。

> [!info]- 保证与交付的差距为什么这么大
> LLL 的证明走最坏路径：每次交换都按最不利方式估算垂直分量的衰减。真实格的交换路径远没有这么倒霉，经验上 LLL 的输出满足 $\|b_1\| \approx 1.021^n \cdot \det^{1/n}$（根 Hermite 因子 $\approx 1.021$），BKZ 随 block size 把这个因子压向 $1.01^n$ 甚至更低。密码分析里的"格攻击可行维度"估算，用的都是这些经验因子而不是最坏界——但写题解时先用式 (4.1) 做必要条件筛查，再上手跑，能省掉整轮无效调试。

## 5. Babai 最近平面：把 CVP 解出来

### 5.1 算法

SVP 找"格里的最短"，CVP 找"离目标最近的"（式 2.2）。LLL 不直接解 CVP，但它给出了一组接近正交的基，在这组基上做投影取整就是 Babai 最近平面（nearest plane）算法：

```python
# s5_babai.py —— Babai 最近平面（接 s3 的 gso / rnd / lll）
def babai(B, t):
    """在基 B 上解 CVP，返回离 t 最近的格点（整数组合向量）"""
    n = len(B)
    bs, mu = gso(B)
    b = [Fraction(x) for x in t]
    coeff = [0] * n
    for i in range(n - 1, -1, -1):                       # 从最后一维向前
        c = rnd(dot(b, bs[i]) / dot(bs[i], bs[i]))
        coeff[i] = c
        b = [b[k] - c * bs[i][k] for k in range(len(b))]
    return [sum(int(coeff[i]) * B[i][k] for i in range(n)) for k in range(len(B[0]))]
```

每一步把目标在当前维度的 GS 坐标四舍五入、减掉、继续处理剩余部分；系数 $c_i = \mathrm{round}(\langle b,\, b_i^* \rangle / \|b_i^*\|^2)$ 逐个确定，最后用**原基向量**按系数组合出格点（GS 向量本身不是格点，不能直接返回）。在 LLL 基上、目标足够靠近某格点时，它返回那个格点；保证界是 $\|t - \text{输出}\| \le \tfrac12 \sqrt{\sum_i \|b_i^*\|^2}$——==先约减、再 Babai==，顺序反了什么都保不住。

### 5.2 靶：三条取整路径对比

用 §1 的二维格造一个"隐藏最近格点"靶：藏起 $v = (1,2)$，目标取 $t = v + (0.1, -0.1)$。解法有三条路，两条走错：

```python
# s5_target.py —— 坏基取整失败，LLL 基上 Babai 成功
G = [(3, 1), (1, 2)]                       # 好基
BAD = [(3, 1), (28, 11)]                   # 坏基（同一格）
v = (1, 2)                                 # 隐藏的最近格点
t = (Fraction(11, 10), Fraction(19, 10))   # 目标 = v + (0.1, -0.1)
print("目标 t = (1.1, 1.9)   隐藏格点 v =", v)

# 路一：坏基上解方程后按坐标取整
D = Fraction(3 * 11 - 1 * 28)                       # 行列式 5
alpha = (t[0] * 11 - t[1] * 28) / D
beta = (3 * t[1] - 1 * t[0]) / D
ra, rb = rnd(alpha), rnd(beta)
pt = (ra * 3 + rb * 28, ra + rb * 11)
d2 = sum((a - b) ** 2 for a, b in zip(t, pt))
print("路一  坐标取整: alpha = %s, beta = %s -> 取整 (%d, %d)，格点 %s，距离 %.2f"
      % (alpha, beta, ra, rb, pt, float(d2) ** 0.5))

# 路二：LLL 约减后 Babai 最近平面
red = lll(BAD)
cp = babai(red, t)
d2 = sum((Fraction(a) - Fraction(b)) ** 2 for a, b in zip(t, cp))
print("路二  LLL + Babai: LLL 基 = %s -> 解出 %s，距离 %.4f"
      % (red, tuple(cp), float(d2) ** 0.5))

# 路三：坏基上直接跑 Babai（不约减）
cp_bad = babai(BAD, t)
d2 = sum((Fraction(a) - Fraction(b)) ** 2 for a, b in zip(t, cp_bad))
print("路三  坏基直接 Babai -> %s，距离 %.2f" % (tuple(cp_bad), float(d2) ** 0.5))
```

输出：

```
目标 t = (1.1, 1.9)   隐藏格点 v = (1, 2)
路一  坐标取整: alpha = -411/50, beta = 23/25 -> 取整 (-8, 1)，格点 (4, 3)，距离 3.10
路二  LLL + Babai: LLL 基 = [[-2, 1], [1, 2]] -> 解出 (1, 2)，距离 0.1414
路三  坏基直接 Babai -> (31, 12)，距离 31.56
```

同一个人造靶，三种命运：坏基上按坐标取整差了 22 倍（$\alpha$ 的真值是 $-8.22$，四舍五入成 $-8$ 就已经错了）；坏基上直接跑 Babai 更糟（$(31,12)$ 离谱地远）；只有"LLL 约减 → 最近平面"精确命中 $(1,2)$。==CVP 的正确姿势永远是先约减==。

### 5.3 自建三维靶：自解自验

把流程升到 3 维：坏基取 §1 的 $U \cdot G_3$，LLL 约减，在约减基上藏一个小系数组合当格点，加噪声，再让 Babai 找回来：

```python
# s5_3d.py —— 三维 CVP 靶：藏一个格点、加噪声、再解出来
BAD3 = [[2, 0, 1], [11, 3, 5], [1, 22, 1]]   # 第 1 节的 U·G3
red3 = lll(BAD3)
print("坏基 =", BAD3)
print("LLL 基 =", red3)
coef = (2, -1, 1)
v3 = [sum(coef[i] * red3[i][k] for i in range(3)) for k in range(3)]
e3 = [Fraction(a, 10) for a in (2, -3, 1)]               # 噪声 (0.2, -0.3, 0.1)
t3 = [v3[k] + e3[k] for k in range(3)]
print("隐藏格点 2*g1 - g2 + g3 =", v3)
print("目标 t3 =", [float(x) for x in t3])
cp3 = babai(red3, t3)
print("Babai 解出 =", cp3, " 与隐藏格点一致:", cp3 == v3)
```

输出：

```
坏基 = [[2, 0, 1], [11, 3, 5], [1, 22, 1]]
LLL 基 = [[2, 0, 1], [1, 3, 0], [-2, 1, 3]]
隐藏格点 2*g1 - g2 + g3 = [1, -2, 5]
目标 t3 = [1.2, -2.3, 5.1]
Babai 解出 = [1, -2, 5]  与隐藏格点一致: True
```

"藏点 → 加噪 → 求解 → 对答案"这个闭环就是下一章所有格靶的微缩模型：真实题目里藏的是密钥/明文的编码，噪声来自题目参数，求解器是同一个 Babai（或它的变体）。

> [!info]- CVP 化 SVP：嵌入法
> 手里只有 LLL（解 SVP）而问题是 CVP 时，标准做法是把目标并进格：加一行 $(0, \dots, 0, t_1, \dots, t_m, \tau)$（前段放基的形状，末段放目标，$\tau$ 是权衡权重的常数），格维度加一。若 $t$ 离格点 $v$ 很近，则组合 $v - t$ 对应的向量（末位 $\pm\tau$）是嵌入格里特别短的一条，LLL 会把它约减出来——CVP 变 SVP。§7 的应用靶用的就是这招。注意嵌入向量的整体符号不定（LLL 可能给出取负后的版本），取用前按某个已知坐标的符号统一翻转。

> [!warning] Babai 会返回次优解
> 最近平面是近似算法：保证界 $\tfrac12\sqrt{\sum\|b_i^*\|^2}$ 之外的"精确命中"没有理论承诺。噪声的范数明显小于格的典型间距 $\det^{1/n}$ 时（本节两个靶都是），精确命中是常态；噪声一大或格的形状很歪（GS 垂直分量一路上翘），它就会落在错误的格点上——§7 会看到真实的坏例子。解出来之后必须回代验算（向量是否等于藏的点、方程是否成立），不能默认正确。

## 6. 二维特例：高斯约简

LLL 给的是近似；2 维是例外——**高斯约简**（Gaussian reduction）能在二维格里拿到**精确**最短向量。算法与 LLL 同构，只是交换条件换成更简单的形式：反复把较短者换到 $v_1$、从 $v_2$ 里减去 $v_1$ 的整数倍，直到 $v_2$ 的垂直分量再也削不动（$\langle v_1, v_2\rangle / \|v_1\|^2$ 四舍五入后为 0）：

```python
# s6_gauss.py —— 二维高斯约简：2 维 SVP 的精确解
from fractions import Fraction
import math, random

def dot2(u, v):
    return u[0] * v[0] + u[1] * v[1]

def rnd(x):
    return (2 * x.numerator + x.denominator) // (2 * x.denominator)

def gauss_reduce(v1, v2, trace=False):
    v1, v2 = list(v1), list(v2)
    while True:
        if dot2(v2, v2) < dot2(v1, v1):
            v1, v2 = v2, v1                     # 保持 v1 更短
            if trace:
                print("    交换 -> v1 = %s" % (tuple(v1),))
        mu = Fraction(dot2(v1, v2), dot2(v1, v1))
        r = rnd(mu)
        if r == 0:
            return v1, v2                       # v2 与 v1 的垂直分量已无法再削
        v2 = [v2[0] - r * v1[0], v2[1] - r * v1[1]]
        if trace:
            print("    v2 -= %d * v1 -> %s" % (r, tuple(v2)))

def brute_svp(B, lim=12):
    """小系数枚举：2 维 SVP 的暴力真值"""
    best, bv = None, None
    for a in range(-lim, lim + 1):
        for b in range(-lim, lim + 1):
            if a == 0 and b == 0:
                continue
            v = (a * B[0][0] + b * B[1][0], a * B[0][1] + b * B[1][1])
            n = dot2(v, v)
            if best is None or n < best:
                best, bv = n, v
    return bv, math.sqrt(best)

BAD = [(3, 1), (28, 11)]
print("输入坏基 =", BAD)
print("逐步过程:")
u, w = gauss_reduce(*BAD, trace=True)
print("高斯约简输出: u = %s, w = %s   |u| = %.4f" % (u, w, math.sqrt(dot2(u, u))))
bv, bnorm = brute_svp(BAD)
print("暴力枚举（系数 -12..12）最短向量: %s, 范数 %.4f" % (bv, bnorm))
print("两者一致:", math.sqrt(dot2(u, u)) == bnorm)

rng = random.Random(21)
ok = total = skipped = 0
for _ in range(100):
    B = [(rng.randint(-30, 30), rng.randint(-30, 30)) for _ in range(2)]
    if B[0] == (0, 0) or B[1] == (0, 0):
        skipped += 1
        continue
    M = abs(B[0][0] * B[1][1] - B[0][1] * B[1][0])
    if M == 0:
        skipped += 1
        print("剔除两行共线的样本:", B)
        continue
    total += 1
    u1, _ = gauss_reduce(*B)
    bv, bn = brute_svp(B)
    if math.sqrt(dot2(u1, u1)) == bn:
        ok += 1
print("随机样本剔除 %d 个退化样本后，%d 个二维格全部命中: %d/%d"
      % (skipped, total, ok, total))
```

输出：

```
输入坏基 = [(3, 1), (28, 11)]
逐步过程:
    v2 -= 10 * v1 -> (-2, 1)
    交换 -> v1 = (-2, 1)
    v2 -= -1 * v1 -> (1, 2)
高斯约简输出: u = [-2, 1], w = [1, 2]   |u| = 2.2361
暴力枚举（系数 -12..12）最短向量: (-2, 1), 范数 2.2361
两者一致: True
剔除两行共线的样本: [(5, 1), (30, 6)]
随机样本剔除 1 个退化样本后，99 个二维格全部命中: 99/99
```

主靶的约简过程与 §3 的 LLL trace 几乎逐行相同（LLL 本来就是高斯约简的高维推广），输出一致：$(-2,1)$ 与 $(1,2)$，范数都是 $\sqrt5$——与暴力枚举的真值相等。随机 99 个二维格上，约简第一行的范数与枚举真值全部相等：==二维的 SVP 可以精确解，这是维度给小格留的唯一后门==。CTF 里见到 2 维或 3 维的小格（未知数只有两三个），先想高斯约简或直接小系数枚举，不必动用 LLL。

> [!info]- 为什么二维能精确、高维不能
> 高斯约简的终止条件（$\mu \in [-1/2, 1/2]$ 且 $\|w\| \ge \|u\|$）在二维恰好把基逼成"既短又正交"的极小构型，其中第一条必然是 $\lambda_1$ 的实现；三维起，"局部最优"不再蕴含"全局最短"——这正是 LLL 只能承诺近似的原因。固定维度内 SVP 有精确算法（Kannan 型枚举：维度进指数、输入规模上是多项式），但枚举的开销随维度爆炸，CTF 里真正高频的精确场景就是 2 维——高斯约简或直接小系数枚举都够。

## 7. 应用预演：三张入场券

本节给三个"题目形状 → 格靶"的转换样本。每个都只搭骨架，完整攻击在下一章展开。

### 7.1 已知高位的数对：补全 p、q 转 CVP

[[C08-RSA攻击II#4. 素数高位已知：small_roots 与 beta|C08 第 4 节]]解过"p 的高位已知"：Coppersmith 找模 p 小根。现在换一个形状——**p、q 的高位各知道一部分**（比如两者都由同一个可预测的模式生成），未知的是各自的低位 $a, b$：

$$n = (p_{hi} + a)(q_{hi} + b) = p_{hi}\,q_{hi} + p_{hi}\,b + q_{hi}\,a + a\,b \tag{7.1}$$

移出已知量：

$$D \;=\; n - p_{hi}\,q_{hi} \;=\; q_{hi}\,a + p_{hi}\,b + a\,b \tag{7.2}$$

未知数只有一对小的 $(a, b)$，方程 (7.2) 是"带小误差项 $ab$ 的线性方程"——正是 CVP 的形状。把它写成 3 行 4 列的嵌入格（§5 折叠框的技巧；$W$ 是权衡权重的常数）：

$$\begin{pmatrix} W & 0 & q_{hi} & 0 \\ 0 & W & p_{hi} & 0 \\ 0 & 0 & D & W \end{pmatrix}, \qquad a\,r_1 + b\,r_2 - r_3 = (\,aW,\; bW,\; -ab,\; -W\,) \tag{7.3}$$

右端四个分量都是"未知数规模"的量：$a, b < 2^{30}$、$ab < 2^{60}$，取 $W = 2^{20}$ 后坐标项压到 $2^{50}$、误差项 $ab$ 与权重项 $W$ 封顶 $2^{60}$；而这条嵌入格的 $\det^{1/4} \approx 2^{79}$——目标短向量比典型间距低二十个数量级，LLL 把它钓出来没有悬念。自造靶全链路：

```python
# s7_app.py —— p、q 双高位已知：补全数对转 CVP（lll 沿用 s3_lll.py 的实现）
from sympy import nextprime
from Crypto.Util.number import long_to_bytes
import math

# ---------- 自造靶：p、q 各 256 位，低 30 位未知 ----------
K = 30
p = nextprime(((2**225 + 10**15) << K) + 0x5C13B7)   # 高位对齐 + 固定低位后取下一个素数
q = nextprime(((2**225 + 3**20) << K) + 0x1D29C4)
n = p * q
p_hi = p >> K << K
q_hi = q >> K << K
print("p = p_hi + a, q = q_hi + b, a、b 均小于 2^%d" % K)
print("n 的比特数 =", n.bit_length())
print("p_hi =", p_hi)
print("q_hi =", q_hi)

# ---------- 建模与求解：式 (7.3) 的嵌入格 ----------
D = n - p_hi * q_hi
W = 1 << 20
L = [[W, 0, q_hi, 0],
     [0, W, p_hi, 0],
     [0, 0, D, W]]
print()
print("D = n - p_hi*q_hi 的比特数 =", D.bit_length())
red = lll(L)
norms = [math.sqrt(sum(x * x for x in r)) for r in red]
print("LLL 输出各行范数（log2）: %s" % ["%.1f" % math.log2(v) for v in norms])
short = min(red, key=lambda r: sum(x * x for x in r))
if short[3] > 0:                    # 目标组合是 a*r1 + b*r2 - r3，末位是 -W：统一符号
    short = [-x for x in short]
a, b = short[0] // W, short[1] // W
print("最短向量 -> (a, b) = (%d, %d)" % (a, b))
p_rec, q_rec = p_hi + a, q_hi + b
print("p_rec * q_rec == n:", p_rec * q_rec == n)

# ---------- 收尾：接回标准解密链 ----------
e = 65537
m = int.from_bytes(b"flag{d0ubl3_hi_CVP}", "big")
c = pow(m, e, n)
phi = (p_rec - 1) * (q_rec - 1)
d = pow(e, -1, phi)
print("用恢复的 p、q 解密:", long_to_bytes(pow(c, d, n)))
```

输出：

```
p = p_hi + a, q = q_hi + b, a、b 均小于 2^30
n 的比特数 = 511
p_hi = 57896044618658097711785492504343953926634992332820283093470616003956564819968
q_hi = 57896044618658097711785492504343953926634992332820282019732535910199189307392

D = n - p_hi*q_hi 的比特数 = 278
LLL 输出各行范数（log2）: ['43.6', '78.8', '195.5']
最短向量 -> (a, b) = (6034711, 1911405)
p_rec * q_rec == n: True
用恢复的 p、q 解密: b'flag{d0ubl3_hi_CVP}'
```

LLL 输出的三条向量里，最短一条范数 $2^{43.6}$，正是式 (7.3) 右端那条组合向量；其余两条在 $2^{78}$ 开外——短向量一眼可辨。三条向量范数的乘积 $2^{43.6} \cdot 2^{78.8} \cdot 2^{195.5} \approx 2^{318}$，恰等于 $W^2 \cdot D$ 对行列式的估计，账目闭合。分解出来 $(a, b) = (6034711, 1911405)$，回乘验证 $p \cdot q = n$ 通过，标准解密链直接吐出 flag。注意手写版 LLL 连 511 位大数的格也照跑不误（3 行小格，毫秒级）；实战里换 fpylll 或 sage 一行调用。

> [!warning] 这道题 Babai 直接做不动
> 若不加权重、直接在 2 行格 $\{(a, b,\ a\,q_{hi} + b\,p_{hi})\}$ 上对目标 $(0, 0, D)$ 跑最近平面，答案错得离谱：这个格的两条基向量在三维里几乎平行（第三坐标都是 $2^{76}$ 量级，前两坐标是 1），约减后的垂直分量仍旧巨大，Babai 的保证界 $\tfrac12\sqrt{\sum\|b_i^*\|^2}$ 落在 $10^{52}$ 量级——比目标到格点的真距离（$ab$ 一项，约 $2^{43}$）长了约四十个数量级，它只能保证"落点差在 $10^{52}$ 以内"，而需要的是"分毫不差"。加权与嵌入就是在修这个形状：把"误差必须为 0"的分量放大到与未知数同量级，短向量才会孤立出来。==构造格时先估 det 与目标向量的量级差，差得不够多就调权重==。

### 7.2 背包与低密度攻击（一句）

子集和问题：公开 $a_1, \dots, a_n$ 与 $s = \sum \varepsilon_i a_i$，未知的是 0/1 向量 $\varepsilon$。把每行写成 $(1, 0, \dots, 0, a_1), \dots$ 的格（单位坐标段 + 权重放大过的 $a_i$ 列），$\varepsilon$ 向量就是格里的一条短向量——SIP 的直系应用。可行性的刻度是密度 $d = n / \log_2(\max a_i)$：$d < 0.9408$ 时低密度攻击（CJLOSS 格）多项式时间可解。构造与权重选取的完整账在下一章。

### 7.3 截断 LCG（一句）

[[C04-随机数攻防|C04]] 的世界里 LCG（线性同余生成器）是常客；当题目只公开每个输出的**高位**（低位截断），连续几个输出就给出一组"带未知低位的线性方程"：状态转移 $x_{i+1} = A x_i + C \bmod M$ 里，未知的低位碎块拼成一个小向量，方程组就是格的行。这和 §7.1 是同一类靶——"带小噪声解线性方程组"，完整解法（含权重设计）在下一章展开。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 手写 LLL 死循环或输出明显不短 | 三处按序查：`round()` 的银行家舍入（半整数被带偏，用 `floor(x + 1/2)`，[[#3.3 手写教学版 LLL\|3.3]]）；GS 用了 float 被大数噪声污染（用 `Fraction`）；size reduce 或交换后忘了重算/更新 $\mu$（[[#3.2 size reduce 与 Lovász 条件\|3.2]]） |
| 两份 LLL 输出"不一致"，怀疑有实现错了 | 行序与行符号本来就不定，逐行比对必然误报；按行列式（取绝对值）、范数多重集、互相整系数表出三条判等（[[#3.4 四路对拍\|3.4]]） |
| fpylll 与 sympy 对拍结果偶尔分叉 | 两家默认 $\delta$ 不同（fpylll 0.99，sympy 3/4）；对拍时显式传同一个 $\delta$（sympy 侧用 `gmpy2.mpq`，[[#3.4 四路对拍\|3.4]] 折叠框） |
| fpylll 报 `NotImplementedError: Type '<class 'float'>' not supported` | `IntegerMatrix` 只收整数：构造 `from_matrix` 与逐格赋值 `A[i, j] = …` 都不能传浮点；目标向量带小数时先按分母放大成整数 |
| sympy 的 `.lll()` 打印出来不是矩阵 | 返回的是 `DomainMatrix`，要 `.to_list()`（拿普通列表）或 `.to_matrix()`（拿 sympy 矩阵）再取行 |
| `DomainMatrix` 报 `mpq() requires numeric or string argument` | 行数据里混进了 `sympy.Integer` 元素；传普通 `int` 列表（[[#3.4 四路对拍\|3.4]] 折叠框） |
| 换基之后行列式"变了" | 先查符号（unimodular 交换两行 det 翻负，取绝对值），再查是否真的做了整数行变换——非整数倍行变换会真的换掉格 |
| 高维或大数时手写版跑不动 | 教学版每步重算 GS 的代价是平方级的再乘轮数；维度上百或系数上千位时换 fpylll / sage（[[#3.4 四路对拍\|3.4]] 折叠框） |
| LLL 输出的第一行不是最短向量 | 那是近似保证的本义：第一行长度上界是真最短向量的 $2^{(n-1)/2}$ 倍，维度越高越松；要更短换 BKZ 加大 block size，或确认格的构造是否给短向量留了足够余量（[[#4. LLL 的近似保证与边界\|4]]） |
| Babai 解出的格点明显不对 | 目标离格点太远（噪声超过 Babai 保证界 ½·√Σ（GS 垂直分量长度平方和）的量级）、基没先约减、或格的形状太歪（垂直分量一路上翘）；先 LLL，再用权重/嵌入修形状，解完必须回代验算（[[#5.2 靶：三条取整路径对比\|5.2]]、[[#7.1 已知高位的数对：补全 p、q 转 CVP\|7.1]]） |
| 嵌入格解出向量的坐标符号全反 | LLL 可能返回目标组合的取负；按某个已知符号的分量（如嵌入位的 $\tau$）整体翻转后再取数（[[#7.1 已知高位的数对：补全 p、q 转 CVP\|7.1]]） |
| 把矩阵转置后喂给 LLL，结果全变 | 约减的是另一个格且不报错；拿到任何格脚本先确认"行 = 基向量"的定向（[[C08-RSA攻击II#2.5 sympy 对照与行、列约定\|C08 §2.5]]） |
| 2 维小格也在跑 LLL | 2 维有精确算法：高斯约简或直接小系数枚举，比 LLL 更可靠（[[#6. 二维特例：高斯约简\|6]]） |
| 解密出来是乱码但 $p \cdot q = n$ 成立 | 检查素数构造：`nextprime(X) + 常数` 会破坏素性，应先加常数再 `nextprime`；$\varphi(n)$ 错则 $d$ 错，解密必错（[[#7.1 已知高位的数对：补全 p、q 转 CVP\|7.1]]） |

## 9. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **自造格靶全链路**：把 §7.1 的靶换成自己的参数重造一遍——`K` 改成 40（低位 40 比特），重新走"建模 → LLL → 验算 → 解密"，并算一次 $\det^{1/4}$ 与目标向量范数的量级差，解释为什么 $K = 40$ 时 $W$ 应该调大。
> 2. **CVP 暴力对拍**：写一个二维 CVP 的暴力枚举器（格点范围 $|a|, |b| \le 20$），随机生成 200 组"格点 + 噪声"靶，统计 Babai 最近平面的命中率；找出失败样本，检查失败时噪声范数与 $\det^{1/2}$ 的比值。
> 3. **平台练习**：CryptoHack（<https://cryptohack.org>）Lattices 分类的前几题（Vectors、Grid Computing、Find the Lattice），把每题的"未知数安排"写进错题本：未知向量是谁、格怎么搭、权重在哪。
> 4. **BKZ 边界**：把 §4 的 BKZ 实验换成 `block_size = 10, 20, 30, 40` 各跑一次同一格，记录第一行范数与耗时，画出"block size → 质量/耗时"的对照。

配套练习：

1. 给 §3 的手写 LLL 加一个返回值：同时输出变换矩阵 $U$（满足 $B_{out} = U \cdot B_{in}$，$|\det U| = 1$），并用 §3.4 的 `check_same_lattice` 思路自查。这是读 Coppersmith 类格构造时最需要的中间量。
2. 把 §5.3 的三维靶升级：藏的系数改成 $(3, -2, 2)$，逐步加大噪声（$0.1$ 倍 → $0.5$ 倍 → $1.0$ 倍典型间距），记录 Babai 开始出错的噪声档位，与 $\tfrac12\sqrt{\sum\|b_i^*\|^2}$ 的实际数值对照。
3. 用 [[C08-RSA攻击II#3. Howgrave-Graham 与手工 Coppersmith|C08 §3]] 的 Howgrave-Graham 条件回看式 (4.1)：对一个 e=3 的 stereotyped 靶，先按式 (4.1) 估算"LLL 保证能解"的 m，再按经验因子 $1.021^n$ 估算"实际能解"的 m，与 C08 §3.3 的参数表对照。
4. 把本章四个实现（手写 LLL、fpylll、sympy、sage）封装成 [[C01-密码学导论与工具链|C01]] 工作流里的可插拔 `reduce` 片段（输入基矩阵与 $\delta$，输出约减基），给下一章的格攻击脚本当地基。

延伸阅读：

- Lenstra, Lenstra, Lovász, *Factoring polynomials with rational coefficients*（Math. Annalen, 1982）：LLL 原始论文，§3 的算法与式 (4.2) 的出处；
- Babai, *On Lovász' lattice reduction and the nearest lattice point problem*（Combinatorica, 1986）：最近平面算法与保证界的原文；
- fpylll 文档：<https://fpylll.readthedocs.io>——`LLL` / `BKZ` / `SVP` / `CVP` 接口与参数的第一参考；
- [[02-书单与Wiki|书单与 Wiki]]：数论与格方向的入门书条目（Cohen 的 *A Course in Computational Algebraic Number Theory* 覆盖高斯约简与 LLL 的完整证明）；
- 下一站：把这些零件装成武器——HNP（隐藏数问题）、带 padding 的 Håstad、NTRU 与 knapsack 变体的完整格攻击，在下一章按"构造 → 估界 → 求解 → 验算"的固定流程逐个展开。
