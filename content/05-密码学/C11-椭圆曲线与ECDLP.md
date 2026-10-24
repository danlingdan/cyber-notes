---
chapter: 密码学
section: 椭圆曲线与 ECDLP
order: 711
tags:
  - CTF
  - 密码学
  - ECC
  - 椭圆曲线
publish: true
---

# C11 椭圆曲线与 ECDLP
## Elliptic Curves & the ECDLP

> [!info]- 章节信息
> **所属方向**：密码学 ｜ **难度阶段**：L3 进阶期 ｜ **前置要求**：[[09-密码学基础|09 章]] · [[C02-数论进阶与原根|C02]]
> **本章目标**：把椭圆曲线从方程讲到攻击——会手写模 p 点加法与标量乘并用 sage 对拍；懂点的阶、曲线的阶与 Hasse 界；把 [[C02-数论进阶与原根|C02]] 的 BSGS/Pollard rho/Pohlig-Hellman 移植成曲线版解 ECDLP；完整打一遍异常曲线上的 Smart's attack（自造 96 比特曲线、13.5 毫秒恢复私钥）；用一个最小服务靶打一遍无效曲线攻击提 d；认识 secp256k1、P-256、Curve25519 三条标准曲线和 pycryptodome / gp / sage 三套工具入口。

[[09-密码学基础|09 章]]用"分解 n 难"撑起了 RSA，[[C02-数论进阶与原根|C02]]把"离散对数难"讲到了 BSGS 和 Pohlig-Hellman。本章把离散对数搬到另一族群上：椭圆曲线的点集。动机一句话——==同等安全强度下，椭圆曲线密钥比 RSA 短一个数量级==（128 位安全强度对应 256 比特的曲线、却要 3072 比特的 RSA 模数），所以现代协议（TLS、比特币、Signal）几乎都迁到了它上面。[[C01-密码学导论与工具链|C01]] 5.4 已经用 sage 建过一次曲线、算过一次 `2P`，本章把那几行背后的全部数学补齐。

与 [[C02-数论进阶与原根|C02]] 的分工：那边的阶、原根、BSGS、Pollard rho、Pohlig-Hellman 全部保留，本章只做"移植"——把整数乘法换成点加法，公式结构不变，移植前先花两节把"点加法"本身讲清楚。

## 1. 曲线方程与点的集合

**它是干嘛的**：椭圆曲线是一族满足特定方程的点的集合，配上一个加法规则之后构成交换群。密码学只用在素数域 $\mathrm{GF}(p)$ 上（p 为大素数，坐标是模 p 的整数），实数上的图像只是帮助记忆的草稿——真正的运算全是模 p 整数运算。

### 1.1 Weierstrass 方程

素数 p 上的短 Weierstrass 方程：

$$y^2 \equiv x^3 + ax + b \pmod p \tag{1.1}$$

曲线就是满足式 (1.1) 的全部点 $(x, y)$ 加上一个特殊点 $O$（1.2 讲它为什么必须存在）。参数不是随便取的，要求：

$$4a^3 + 27b^2 \not\equiv 0 \pmod p \tag{1.2}$$

式 (1.2) 的左边叫**判别式**。它的作用是保证 $x^3 + ax + b$ 无重根：有重根的地方"切线"会退化，2.1 的加法规则在那里失效。出题人给的曲线参数都满足它，自己造曲线时（4.4 就要造）别忘验一遍。

本章反复用同一条教学曲线：p = 97，a = 2，b = 3。判别式 $4 \cdot 8 + 27 \cdot 9 = 275 \equiv 81 \pmod{97}$，非零，可用。

### 1.2 无穷远点 O：加法单位元从哪来

**它是干嘛的**：无穷远点 $O$ 是曲线群里被补充进来的那个点，承担加法单位元的角色。需要它有两个原因，一个来自几何，一个来自代数。

几何侧：加法规则（2.1）依赖"过两点的直线与曲线交出第三点"。直线与三次曲线按重数恰有三个交点（Bézout 定理的结论），但**竖线**是例外——由式 (1.1)，若 $(x, y)$ 在曲线上，$(x, -y)$ 也在，竖线 $x = c$ 与曲线只交出 $P = (x, y)$ 和 $-P = (x, -y)$ 两个仿射点，第三个交点在有限平面里不存在。解决办法是把所有竖线的公共交点——射影平面上的 $[0:1:0]$——补进点的集合，记作 $O$。补完之后每条竖线都凑满三个交点：$P$、$-P$、$O$。

代数侧：群必须有单位元 $e$，满足 $P + e = P$。把 $O$ 定为单位元最合适——它已经和"竖线"绑定，而 $P + (-P)$ 走的正是竖线，于是：

$$P + (-P) = O, \qquad P + O = P \tag{1.3}$$

负元的坐标规则也来自对称性：$-P = (x, -y \bmod p)$；$-O = O$。

### 1.3 模 97 的小曲线：把所有点列出来

p = 97 足够小，可以直接把式 (1.1) 的全部点枚举出来——对每个 y 算平方表，对每个 x 算右端，能开平方的组合收进来：

```python
# enum_points.py —— 枚举 y^2 = x^3 + 2x + 3 (mod 97) 的全部点
p, A, B = 97, 2, 3
disc = (4 * pow(A, 3, p) + 27 * pow(B, 2, p)) % p
print("判别式 4a^3+27b^2 mod p =", disc)

squares = {y * y % p for y in range(p)}
pts = [(x, y) for x in range(p)
       for y in range(p) if (pow(x, 3, p) + A * x + B) % p == y * y % p]
zero_x = [x for x in range(p) if (pow(x, 3, p) + A * x + B) % p == 0]
print("仿射点数 =", len(pts), "  其中 y=0 的点(每 x 一个):", zero_x)
for i in range(0, len(pts), 6):
    print("  " + "  ".join("(%2d,%2d)" % pt for pt in pts[i:i + 6]))
print("加上无穷远点 O, 曲线共", len(pts) + 1, "个点")
print("(x,-y) 随点集封闭:", all((x, (p - y) % p) in set(pts) for (x, y) in pts))
```

```bash
python3 enum_points.py
```

输出：

```
判别式 4a^3+27b^2 mod p = 81
仿射点数 = 99   其中 y=0 的点(每 x 一个): [30, 68, 96]
  ( 0,10)  ( 0,87)  ( 1,43)  ( 1,54)  ( 3, 6)  ( 3,91)
  ( 4,47)  ( 4,50)  (10,21)  (10,76)  (11,17)  (11,80)
  (12, 3)  (12,94)  (17,10)  (17,87)  (20,34)  (20,63)
  (21,24)  (21,73)  (22, 5)  (22,92)  (23,24)  (23,73)
  (24, 2)  (24,95)  (25,35)  (25,62)  (27, 7)  (27,90)
  (28,34)  (28,63)  (29,43)  (29,54)  (30, 0)  (32, 7)
  (32,90)  (37,22)  (37,75)  (38, 7)  (38,90)  (39, 6)
  (39,91)  (44,20)  (44,77)  (46,25)  (46,72)  (47,18)
  (47,79)  (49,34)  (49,63)  (50,19)  (50,78)  (52,29)
  (52,68)  (53,24)  (53,73)  (54,12)  (54,85)  (55, 6)
  (55,91)  (56, 8)  (56,89)  (59,32)  (59,65)  (65,32)
  (65,65)  (67,43)  (67,54)  (68, 0)  (70,32)  (70,65)
  (73,14)  (73,83)  (74,20)  (74,77)  (76,20)  (76,77)
  (80,10)  (80,87)  (83,23)  (83,74)  (84,37)  (84,60)
  (85,26)  (85,71)  (86,28)  (86,69)  (87,27)  (87,70)
  (88,41)  (88,56)  (91,39)  (91,58)  (92,16)  (92,81)
  (95,31)  (95,66)  (96, 0)
加上无穷远点 O, 曲线共 100 个点
(x,-y) 随点集封闭: True
```

三件事值得读出来：

1. **每个 x 给 0、1 或 2 个点**。右端 $x^3+2x+3$ 是二次剩余时给两个点（$\pm y$），非剩余时给零个，恰好为 0 时给一个——97 个 x 里 48 个给两点、3 个（y = 0）给一点，$48 \times 2 + 3 = 99$；
2. **关于 x 轴对称**：$(x, -y)$ 与 $(x, y)$ 同在点集里，这就是负元规则；
3. **点的个数是 100，非常接近 p + 1 = 98**。这不是巧合——固定 x 时右端开得了方的概率约是一半（[[C02-数论进阶与原根|C02]] 第 2 节的二次剩余），期望点数就是 $p/2 \times 2 = p$，再加 $O$ 一个。3.2 的 Hasse 界把这个直觉变成定理。

> [!info]- 枚举的成本，以及大曲线怎么数
> 这段枚举是 $O(p^2)$ 的（p 个 x 配 p 个 y），p 到 $10^6$ 还能跑，密码学尺度的 p（256 比特）完全不可行。数大曲线的点数有专门算法（Schoof-Elkies-Atkin，SEA），复杂度是 $\log p$ 的多项式，sage 的 `E.order()` 和 gp 的 `ellcard` 内部就是它（[[#3.2 曲线的阶与 Hasse 界|3.2]]），直接调用即可。

## 2. 点加法与群律

### 2.1 几何规则：弦、切线、竖线

**它是干嘛的**：点加法回答"曲线上两点相加得哪一点"。规则全部来自一张几何图——两点连弦、单点作切，取第三交点再翻到 x 轴另一侧：

1. **P ≠ Q（弦）**：过 $P$、$Q$ 的直线与曲线交出第三点 $R$，定义 $P + Q = -R$；
2. **P = Q（切线）**：过 $P$ 作切线，切点按重数算两次，与曲线的"第三交点"是 $P$ 自身之外的另一点 $R'$，定义 $2P = -R'$；
3. **P + (−P)（竖线）**：连线是竖线，第三交点是 $O$（1.2），故 $P + (-P) = O$；
4. **含 O**：$P + O = O + P = P$。

四种情况拼出一个交换群：单位元是 $O$、负元是 $(x, -y)$、交换律一眼可见（连线不分方向）。结合律 $(P+Q)+R = P+(Q+R)$ 在图上看不出来，2.4 直接用代码查。

### 2.2 模 p 的代数公式

**它是干嘛的**：把几何规则翻译成坐标公式，模 p 执行。设 $P = (x_1, y_1)$，$Q = (x_2, y_2)$，$P + Q = (x_3, y_3)$。

$P \neq Q$ 时直线斜率是 $\frac{y_2 - y_1}{x_2 - x_1}$，$P = Q$ 时切线斜率是 $\frac{3x_1^2 + a}{2y_1}$（对 $y^2 = x^3+ax+b$ 隐函数求导而来）。统一记作：

$$\lambda = \begin{cases} \dfrac{y_2 - y_1}{x_2 - x_1} \pmod p, & P \neq Q \\[2mm] \dfrac{3x_1^2 + a}{2y_1} \pmod p, & P = Q \end{cases} \tag{2.1}$$

把直线（或切线）与曲线的第三交点记作 $R = (x_R, y_R)$，把 $R$ 翻到 x 轴另一侧（取负）就是 $P + Q$。代入 $\lambda$ 化简后得到直接的坐标公式：

$$x_3 = \lambda^2 - x_1 - x_2 \pmod p \tag{2.2}$$

$$y_3 = \lambda(x_1 - x_3) - y_1 \pmod p \tag{2.3}$$

模 p 里的"除法"是乘逆元（[[09-密码学基础#2.2 GCD 与扩展欧几里得|09 章 2.2]]的 exgcd，Python 里就是三参数 `pow(分母, -1, p)`）。

两个具体例子（曲线仍是 $y^2 = x^3+2x+3 \bmod 97$）：

$P = (3, 6)$，$Q = (4, 47)$，$P \neq Q$：$\lambda = (47-6)/(4-3) = 41$；$x_3 = 41^2 - 3 - 4 = 1674 \equiv 25$；$y_3 = 41 \times (3 - 25) - 6 = -908 \equiv 62$。所以 $P + Q = (25, 62)$。

$2P$，$P = (3, 6)$：$\lambda = (3 \times 9 + 2)/(12) = 29 \times 12^{-1}$，$12^{-1} \equiv 89 \pmod{97}$，$\lambda \equiv 59$；$x_3 = 59^2 - 6 = 3475 \equiv 80$；$y_3 = 59 \times (3 - 80) - 6 = -4549 \equiv 10$。所以 $2P = (80, 10)$。

> [!warning] 三个特例必须在进公式之前拦下
> 式 (2.1)–(2.3) 只在"普通情况"成立，写代码时先判三个分支：一，$P = O$ 或 $Q = O$，直接返回另一个；二，$x_1 = x_2$ 且 $y_1 \equiv -y_2$，这是竖线，返回 $O$——不拦截的话分母 $x_2 - x_1 \equiv 0$，逆元不存在；三，$P = Q$ 且 $y_1 = 0$（1.3 里那三个 y = 0 的点），切线竖直，$2P = O$，同样返回 $O$。漏掉任何一个，轻则算出无意义的点，重则 `pow(0, -1, p)` 直接抛异常。

### 2.3 手写实现

O 用 `None` 表示，四个函数齐了：负元、点加（含全部特例）、标量乘：

```python
# ec.py —— 模 p 椭圆曲线点运算：y^2 = x^3 + A*x + B (mod p)
p, A, B = 97, 2, 3

def neg(P):
    """负元：(x, y) -> (x, -y)；O -> O"""
    if P is None:
        return None
    return (P[0], (-P[1]) % p)

def add(P, Q):
    """点加法，O 用 None 表示"""
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None                          # 竖线：P = -Q -> O
    if P == Q:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, p) % p   # 切线
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p          # 弦
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def mul(k, P):
    """标量乘 k*P：double-and-add，从低位到高位"""
    R = None
    while k:
        if k & 1:
            R = add(R, P)
        P = add(P, P)                        # 倍点
        k >>= 1
    return R
```

`mul` 就是 double-and-add：把 k 写成二进制，从低位到高位，遇 1 累加当前倍点，每轮倍点翻番——和三参数 `pow` 的快速幂（[[09-密码学基础|09 章]]第 2 节）结构完全相同，2.1 的切线对应"平方"、弦对应"乘"。标量是 256 比特时，点乘只要几百次点加，这就是椭圆曲线体制能跑的原因。

### 2.4 自洽检查与 sage 对拍

群律是不是真的成立，代码说了算。用 1.3 枚举出的全部 99 个仿射点做检查——单位元、逆元、交换律查全体，结合律查 2000 组随机三元组，标量乘查 `$n \cdot P = (n-1) \cdot P + P$`：

```python
# check_group.py —— 群律自洽检查（复用 ec.py 的 add / neg / mul）
import random
random.seed(11)

squares = {y * y % p for y in range(p)}
pts = [(x, y) for x in range(p)
       for y in range(p) if (pow(x, 3, p) + A * x + B) % p == y * y % p]
print("仿射点数 =", len(pts), " 加 O 共", len(pts) + 1)

ok_id = all(add(P, None) == P and add(None, P) == P for P in pts)
ok_inv = all(add(P, neg(P)) is None for P in pts)
print("P + O = O + P = P 全体成立:", ok_id, " P + (-P) = O 全体成立:", ok_inv)
print("交换律 P+Q = Q+P 全体成立:",
      all(add(P, Q) == add(Q, P) for P in pts for Q in pts))

triples = [(random.choice(pts), random.choice(pts), random.choice(pts))
           for _ in range(2000)]
print("结合律 2000 组抽查成立:",
      all(add(add(P, Q), R) == add(P, add(Q, R)) for P, Q, R in triples))

orders = {}
for P in pts:                                # 逐点乘到 O，数出阶
    R, n = add(P, P), 2
    while R is not None:
        R = add(R, P)
        n += 1
    orders[P] = n
import collections
print("各点的阶分布:", dict(collections.Counter(orders.values())))

ok_mul = all(mul(n, P) == add(mul(n - 1, P), P) and mul(orders[P], P) is None
             and mul(orders[P] - 1, P) == neg(P)
             for P in pts[:20] for n in (2, orders[P]))
print("n*P = (n-1)*P + P、阶*P = O、(阶-1)*P = -P 抽查:", ok_mul)

P1, Q1 = (3, 6), (4, 47)
print("P=(3,6)  Q=(4,47)  P+Q =", add(P1, Q1))
print("2*(3,6) =", mul(2, P1), "   5*(3,6) =", mul(5, P1), "  20*(3,6) =", mul(20, P1))
print("(3,6) 的阶 =", orders[P1], "   (0,10) 的阶 =", orders[(0, 10)])
```

```bash
python3 check_group.py
```

输出：

```
仿射点数 = 99  加 O 共 100
P + O = O + P = P 全体成立: True  P + (-P) = O 全体成立: True
交换律 P+Q = Q+P 全体成立: True
结合律 2000 组抽查成立: True
各点的阶分布: {50: 60, 5: 4, 25: 20, 10: 12, 2: 3}
n*P = (n-1)*P + P、阶*P = O、(阶-1)*P = -P 抽查: True
P=(3,6)  Q=(4,47)  P+Q = (25, 62)
2*(3,6) = (80, 10)    5*(3,6) = None   20*(3,6) = None
(3,6) 的阶 = 5    (0,10) 的阶 = 50
```

2.2 的两个手算例子和代码输出逐位一致。再换 sage 独立实现算一遍同一组值——sage 的点存成射影坐标 $(x : y : z)$，$z = 1$ 就是仿射点，$O$ 打印成 $(0 : 1 : 0)$：

```bash
# sage_check.sage
E = EllipticCurve(GF(97), [2, 3])
P = E(3, 6)
Q = E(4, 47)
print("P+Q =", P + Q)
print("2P  =", 2 * P)
print("5P  =", 5 * P)
print("P 的阶 =", P.order())
```

```bash
sage sage_check.sage
```

输出：

```
P+Q = (25 : 62 : 1)
2P  = (80 : 10 : 1)
5P  = (0 : 1 : 0)
P 的阶 = 5
```

两边完全一致，$5P = (0:1:0)$ 正是 $O$——$(3,6)$ 的阶是 5，与手写实现的结论对上。

## 3. 阶与曲线的结构

### 3.1 点的阶与拉格朗日定理

**它是干嘛的**：点的阶回答"一个点自加多少次第一次回到 $O$"，记 $\text{ord}(P)$。它和 [[C02-数论进阶与原根|C02]] 3.1 的元素阶是同一个概念——把"$g$ 自乘"换成"$P$ 自加"。2.4 的检查里已经顺手算出：$(3,6)$ 阶 5、$(0,10)$ 阶 50，全部 99 个点的阶分布是 $\{50{:}\,60,\ 25{:}\,20,\ 10{:}\,12,\ 5{:}\,4,\ 2{:}\,3\}$。

两条结构性结论，[[C02-数论进阶与原根|C02]] 3.1 原样移植：

- ==每个点的阶整除曲线的点数== $100 = 2^2 \cdot 5^2$——分布里的 2、5、10、25、50 全部整除 100，这是拉格朗日定理（子群阶整除群阶）；
- 阶的最大值是 50，**没有**阶 100 的点——这条曲线的群不是循环群。sage 能直接给出结构：

```bash
# structure.sage
E = EllipticCurve(GF(97), [2, 3])
print("E.order() =", E.order())
print("群结构:", E.abelian_group())
print("生成元:", E.gens())
E2 = EllipticCurve(GF(9739), [497, 1768])    # C01 5.4 建过的那条
print("9739 曲线: order =", E2.order(), " 结构 =", E2.abelian_group())
```

```bash
sage structure.sage
```

输出：

```
E.order() = 100
群结构: Additive abelian group isomorphic to Z/50 + Z/2 embedded in Abelian group of points on Elliptic Curve defined by y^2 = x^3 + 2*x + 3 over Finite Field of size 97
生成元: ((86 : 28 : 1), (30 : 0 : 1))
9739 曲线: order = 9735  结构 = Additive abelian group isomorphic to Z/9735 embedded in Abelian group of points on Elliptic Curve defined by y^2 = x^3 + 497*x + 1768 over Finite Field of size 9739
```

一般结论：椭圆曲线群要么是循环群 $\mathbb{Z}/n$，要么是两因子之积 $\mathbb{Z}/n_1 + \mathbb{Z}/n_2$（$n_1 \mid n_2$）。mod 97 的教学曲线是非循环的 $\mathbb{Z}/50 + \mathbb{Z}/2$，[[C01-密码学导论与工具链|C01]]那条 9739 曲线是循环的 $\mathbb{Z}/9735$。==密码学标准曲线都把 $\#E$ 选成素数或近素数，此时群必循环、几乎任何非 $O$ 点都能当基点==。

### 3.2 曲线的阶与 Hasse 界

**它是干嘛的**：曲线的阶 $\#E$ 是曲线上点的总个数（含 $O$）。它是整条曲线最重要的参数——点的阶整除它（拉格朗日），ECDLP 的难度由它决定（第 4 节），1.3 已经枚举出教学曲线的 $\#E = 100$。

$\#E$ 不能随便是什么数，它被**Hasse 界**夹在 $p+1$ 附近：

$$\left|\#E - (p+1)\right| \le 2\sqrt{p} \tag{3.1}$$

1.3 的直觉（每个 x 以约一半概率给出点，期望点数 $p$）就是式 (3.1) 的来源，Hasse 定理把"约"定量化。随机换几条曲线、几个尺度的 p 看这个界：

```bash
# hasse.sage —— 不同尺度下 |ord-(p+1)| 与 2*sqrt(p) 的对照
set_random_seed(7)
for p in [97, next_prime(10 ^ 12), next_prime(10 ^ 18), next_prime(2 ^ 48), next_prime(2 ^ 95)]:
    Ep = EllipticCurve(GF(p), [2, 3])
    n = Ep.order()
    bound = 2 * RR(p).sqrt()
    print("  p = %-21d ord = %-21d |ord-(p+1)| = %-8d 2*sqrt(p) = %.1f  内 = %s"
          % (p, n, abs(n - (p + 1)), bound, abs(n - (p + 1)) <= bound))
```

```bash
sage hasse.sage
```

输出：

```
  p = 97                    ord = 100                   |ord-(p+1)| = 2        2*sqrt(p) = 19.7  内 = True
  p = 1000000000039         ord = 1000000769568         |ord-(p+1)| = 769528   2*sqrt(p) = 2000000.0  内 = True
  p = 1000000000000000003   ord = 999999998531533032    |ord-(p+1)| = 1468466972 2*sqrt(p) = 2000000000.0  内 = True
  p = 281474976710677       ord = 281474984363086       |ord-(p+1)| = 7652408  2*sqrt(p) = 33554432.0  内 = True
  p = 39614081257132168796771975177 ord = 39614081257132041603696035598 |ord-(p+1)| = 127193075939580 2*sqrt(p) = 398065729532860.8  内 = True
```

$\#E$ 始终落在 $[p+1-2\sqrt{p},\ p+1+2\sqrt{p}]$ 里。式 (3.1) 的两个用途：算 ECDLP 难度时用 $\#E \approx p$ 估步数（$\sqrt{\#E} \approx 2^{128}$ 对 256 比特曲线）；4.4 的异常曲线攻击要先确认 $\#E$ 精确等于 p。

> [!info]- sage 怎么把 96 比特曲线的阶瞬间数出来
> `E.order()` 走的是 Schoof-Elkies-Atkin（SEA）算法：用"弗罗贝尼乌斯自同态在除子多项式上的作用"逐个素数 l 确定 trace $t = p + 1 - \#E$ 模 l，最后 CRT 拼出精确的 t（[[09-密码学基础#2.4 中国剩余定理|09 章 2.4]]的 CRT 又一次出场）。复杂度约 $O(\log^4 p)$，256 比特曲线毫秒到秒级。gp 的 `ellcard` 同源（PARI 实现）。

### 3.3 循环、非循环与 supersingular

$\#E$ 的因子里藏着曲线的安全性质，CTF 视角记三种：

- **素数阶**（如标准曲线）：循环、无小子群，==选曲线的首选==；
- **光滑阶**（素因子都小）：ECDLP 被 Pohlig-Hellman 秒（4.3），出题人造弱曲线用；
- **supersingular**：trace $t = 0$，$\#E = p + 1$ 的特殊族。一个可复现的识别法：p ≡ 2 (mod 3) 时，$y^2 = x^3 + b$ 形状的曲线全是 supersingular：

```bash
# supersing.sage
p = next_prime(10 ^ 18)
while p % 3 != 2:
    p = next_prime(p + 1)
E = EllipticCurve(GF(p), [0, 1])
print("p =", p, " p mod 3 =", p % 3)
print("#E =", E.order(), " p+1 =", p + 1, " 相等:", E.order() == p + 1)
```

```bash
sage supersing.sage
```

输出：

```
p = 1000000000000000031  p mod 3 = 2
#E = 1000000000000000032  p+1 = 1000000000000000032  相等: True
```

supersingular 本身不让 ECDLP 变容易（$\#E = p+1$ 照样是 256 比特级），它的攻击面在"配对"（pairing）——能把曲线 DLP 降到有限域乘法群上的 DLP，那是进阶题的内容，本章不展开。真正让 ECDLP 塌缩的是下一节的异常曲线。

## 4. ECDLP 与攻击

### 4.1 问题定义

**它是干嘛的**：ECDLP（elliptic curve discrete logarithm problem）是 [[C02-数论进阶与原根|C02]] 第 4 节离散对数的曲线版：已知基点 $G$ 和 $Q = nG$，求标量 n。乘法变点加，指数变标量：

$$Q = \underbrace{G + G + \cdots + G}_{n \text{ 个}} = nG \tag{4.1}$$

正向算 nG 只要 $\log n$ 次点加（double-and-add），反向从 Q 求 n，已知最好的通用攻击是 $\sqrt{\text{ord}(G)}$ 步——==这个不对称就是 ECC 的安全来源==。对照表：

| | 整数 DLP（C02） | ECDLP（本章） |
| ---- | ---- | ---- |
| 群 | 模 p 乘法群 $\{1, \dots, p-1\}$ | 曲线点集 $E(\mathrm{GF}(p))$ |
| 正向 | $g^x \bmod p$ | $x \cdot G$（double-and-add） |
| 逆向 | BSGS / Pollard rho / PH | 同一套，乘法换点加 |
| 已知通用复杂度 | $O(\sqrt{\text{ord}})$ | $O(\sqrt{\text{ord}})$ |

因为两边的群结构一样（交换群），[[C02-数论进阶与原根|C02]] 的全部算法==都能直接移植==——下面两节做这件事，4.4 再看一个"结构异常导致整体塌缩"的特例。

### 4.2 BSGS 的曲线版

**它是干嘛的**：把 $\sqrt{\text{ord}}$ 步的 meet-in-the-middle 搬到曲线上。设 $\text{ord}(P) = N$，按 [[C02-数论进阶与原根|C02]] 4.2 的拆法把待求的 d 写成两段：

$$d = i \cdot m + j, \qquad 0 \le j < m = \lceil\sqrt{N}\rceil \tag{4.2}$$

两边乘 P 并移项：

$$Q - i \cdot (mP) = jP \tag{4.3}$$

小步 $jP$（j < m）全部存表，大步 $Q, Q - mP, Q - 2mP, \dots$ 逐个查表——命中即得 $d = i \cdot m + j$。代码只比整数版多一个减法：

```python
# bsgs_ecc.py —— 曲线版 BSGS：解 d*P = Q（靶曲线换到 mod 1000003）
from math import isqrt
import time

p, A, B = 1000003, 2, 3          # ec.py 的 p/A/B 改到这里，add/neg/mul 复用
# ……（neg / add / mul 与 2.3 完全相同，省略）……

def is_qr(u):                     # 二次剩余判据（C02 欧拉判据）
    return u != 0 and pow(u, (p - 1) // 2, p) == 1

t0 = time.perf_counter()
cnt_two = sum(1 for x in range(p) if is_qr((x**3 + A * x + B) % p))
cnt_one = sum(1 for x in range(p) if (x**3 + A * x + B) % p == 0)
print("枚举得 #E =", 1 + 2 * cnt_two + cnt_one,
      " 耗时 %.1f s" % (time.perf_counter() - t0))

P = (145646, 571538)              # 阶 499854 的点（群结构 Z/499854 + Z/2 的最大阶）
d_true = 654321
Q = mul(d_true, P)
print("P =", P, "  d =", d_true, "  Q = d*P =", Q)

def bsgs_ecc(P, Q, order):
    """解 d*P = Q（d < order）：小步存 j*P，大步 Q - i*(m*P) 查表"""
    m = isqrt(order) + 1
    table = {}
    T = None
    for j in range(m):            # 小步：j*P
        if T not in table:
            table[T] = j
        T = add(T, P)
    M = mul(m, P)                 # 大步单位 m*P
    R = Q
    for i in range(m + 1):        # 大步：Q - i*(m*P)
        if R in table:
            return (i * m + table[R]) % order
        R = add(R, neg(M))
    return None

t0 = time.perf_counter()
d = bsgs_ecc(P, Q, 499854)
t1 = time.perf_counter() - t0
print("BSGS 解得 d = %d  (P 的阶 499854；真解 654321 = %d + 1*499854)" % (d, d))
print("验算 %d*P == Q:" % d, mul(d, P) == Q, "  验算 654321*P == Q:", mul(654321, P) == Q)
print("耗时 %.1f ms  (m = %d 步)" % (t1 * 1000, isqrt(499854) + 1))
```

```bash
python3 bsgs_ecc.py
```

输出：

```
枚举得 #E = 999708  耗时 0.6 s
P = (145646, 571538)   d = 654321   Q = d*P = (803849, 876606)
BSGS 解得 d = 154467  (P 的阶 499854；真解 654321 = 154467 + 1*499854)
验算 154467*P == Q: True   验算 654321*P == Q: True
耗时 0.6 ms  (m = 708 步)
```

> [!note] 解只对模 ord(P) 唯一
> BSGS 返回 154467 而真私钥是 654321，两个都验算通过——因为 $654321 - 154467 = 499854$ 恰好是 $\text{ord}(P)$，$n \equiv n + \text{ord}(P)$ 给出同一个点。==ECDLP 的解天然只差一个群的阶==，拿到解后按 $\text{ord}(P)$ 归约就是标准答案（sage 的 discrete_log 也返回归约后的值）。

sage 复核同一道题：

```bash
# dlog_check.sage
E = EllipticCurve(GF(1000003), [2, 3])
P = E(145646, 571538)
Q = E(803849, 876606)
d = discrete_log(Q, P, ord=P.order(), operation='+')
print("sage discrete_log 解得 d =", d, " 验算 d*P == Q:", d * P == Q)
```

```bash
sage dlog_check.sage
```

输出：

```
sage discrete_log 解得 d = 154467  验算 d*P == Q: True
```

规模天花板和整数版一样：$\sqrt{N}$ 步、$\sqrt{N}$ 项表。$\text{ord} \approx 2^{128}$ 的标准曲线上，表要 $2^{64}$ 项（约 $10^{19}$ 字节），==通用攻击对正常参数的曲线完全无望==，能打的只有"结构不正常"的曲线——4.3 与 4.4。

### 4.3 Pollard rho 与光滑阶：移植即用

两条 [[C02-数论进阶与原根|C02]] 4.3 的结论原样搬到曲线：

- **Pollard rho**：期望 $O(\sqrt{\text{ord}})$ 时间、常数内存——把"指数序列进圈找碰撞"换成"点序列进圈找碰撞"，其余推导不动。内存受限而 BSGS 表开不下时用它；
- **Pohlig-Hellman**：$\text{ord}(G)$ 光滑（素因子都小）时，把阶按因子拆开、每个小因子上做一道微型 ECDLP、再用 CRT（[[09-密码学基础#2.4 中国剩余定理|09 章 2.4]]）拼回 d。==CTF 曲线题里最常被埋的弱点就是"阶光滑"==——拿到曲线先 `E.order()`，再 `factor()` 看一眼。

小阶曲线是最极端的光滑：mod 97 曲线 $\#E = 100$，解 ECDLP 直接试乘——从 $G$ 逐次加点，最多 100 次必命中 Q，连 BSGS 都不用。5.2 的无效曲线攻击正是把服务"骗"到这种小阶曲线上。

### 4.4 Smart's attack：异常曲线上的一步除法

**它是干嘛的**：Smart's attack（ISS，anomalous curve attack）打的是**异常曲线**——满足 $\#E = p$ 的曲线。此时 ECDLP 被一步模 p 除法解开：已知 $G$、$Q = dG$，直接恢复 d。==检查异常只花一次点数：`E.order() == p` 成立，这道题就结束了==。

原理三步，全部发生在 p 进数世界 $\mathbb{Q}_p$（sage 的 `Qp`）：

1. **提升**：把曲线搬到 $\mathbb{Q}_p$ 上——$a, b$ 各加一个 $p$ 的倍数（模 p 后还原原曲线），点 $P = (x, y)$ 也提升为提升后曲线上与 $(x, y)$ 模 p 同余的点；
2. **进形式群**：把提升后的点乘 p。$p$ 倍后的点模 p 归约到 $O$——落进"形式群"（单位元附近的邻域）。这个邻域里有现成的对数函数：**形式对数**，坐标形式 $\log(x, y) = x/y + O(p^2)$，一个除法；
3. **除法出解**：形式对数把点加变成数乘（对数把"加"变"乘"），于是 $Q = dG$ 两边取 log：

$$\log(Q) = d \cdot \log(G) \quad\Longrightarrow\quad d \equiv \frac{\log(Q)}{\log(G)} \pmod p \tag{4.4}$$

两个对数都只精确到模 p（对数映射的像落在 pZp 里，公共因子 p 约掉），模 p 做一次除法就直接得到 d——不再有 $\sqrt{\;}$，==攻击复杂度 $O(1)$，和参数大小无关==。

先看靶子怎么来（完整脚本在折叠框）：找一个 96 比特素数 p 使 $p = \frac{3s^2+1}{4}$（s 为奇数），然后扫曲线族 $y^2 = x^3 + b$，$b$ 从 1 起，直到 $\#E = p$ 命中：

```bash
# anomalous_build.sage —— 自造一条 96 比特异常曲线
s = 2^48 + 1
while True:
    p = (3 * s^2 + 1) // 4
    if p.nbits() == 96 and is_prime(p):
        break
    s += 2
print("s =", s)
print("p = (3*s^2+1)/4 =", p, "  (%d 比特)" % p.nbits())

for b in range(1, 25):
    Eb = EllipticCurve(GF(p), [0, b])
    if Eb.order() == p:
        E = Eb
        print("b =", b, " 时 #E = p，命中")
        break
print("验算 E.order() == p:", E.order() == p)
G = E.gens()[0]
print("生成元 G =", G.xy())
print("ord(G) =", G.order(), " 等于 #E(=p):", G.order() == p)
```

```bash
sage anomalous_build.sage
```

输出：

```
s = 281474976710695
p = (3*s^2+1)/4 = 59421121885714719481295537269   (96 比特)
b = 6  时 #E = p，命中
验算 E.order() == p: True
生成元 G = (53720398686963871728652025094, 44671658880403369256740033201)
ord(G) = 59421121885714719481295537269  等于 #E(=p): True
```

曲线 $E: y^2 = x^3 + 6$ over $\mathrm{GF}(p)$，$p = 59421121885714719481295537269$，$\#E = p$。攻击脚本全量贴出（生成元与私钥沿用上面构造的 G，随机数种子固定以便复现）：

```bash
# smart_attack.sage —— 异常曲线 ECDLP：Smart's attack 一步恢复私钥
import time

p = 59421121885714719481295537269          # 96 位素数（构造见上一脚本）
E = EllipticCurve(GF(p), [0, 6])           # y^2 = x^3 + 6
print("#E == p:", E.order() == p)

set_random_seed(2024)
G = E.gens()[0]                            # 基点，阶 p
d = ZZ.random_element(1, p)                # 私钥
Q = d * G                                  # 公钥
print("d(私钥) =", d)
print("Q = d*G =", Q.xy())

def smart_attack(P, R, p):
    """异常曲线上解 R = n*P，返回 n mod p"""
    Ep = P.curve()
    # 1) 曲线提升到 Qp(p,2)：a4, a6 各加一个随机 p 的倍数
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + (0 if i < 3 else ZZ.random_element(1, p) * p)
                                   for i, t in enumerate(Ep.a_invariants())])
    # 2) 点提升：x 不动，取 y 与原点模 p 同余的那个提升
    Ps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for Pt in Ps:
        if GF(p)(ZZ(Pt.xy()[1])) == P.xy()[1]:
            break
    Rs = Eqp.lift_x(ZZ(R.xy()[0]), all=True)
    for Rt in Rs:
        if GF(p)(ZZ(Rt.xy()[1])) == R.xy()[1]:
            break
    # 3) 乘 p 进形式群（模 p 归约为 O），log(x,y) = x/y，比值即 d
    pP = p * Pt
    pR = p * Rt
    return ZZ((pR.xy()[0] / pR.xy()[1]) / (pP.xy()[0] / pP.xy()[1])) % p

set_random_seed(9)
t0 = time.time()
d_hat = smart_attack(G, Q, p)
t1 = time.time()
print("Smart 解得 d =", d_hat, " 与真私钥相等:", d_hat == d, "  耗时 %.1f ms" % ((t1 - t0) * 1000))
print("验算 d_hat*G == Q:", d_hat * G == Q)
print("对照: BSGS 需要 ~2*sqrt(p) = %.2e 步" % (2 * float(sqrt(p))))
```

```bash
sage smart_attack.sage
```

输出：

```
#E == p: True
d(私钥) = 20346488935168368987513436820
Q = d*G = (28105196152610189411418199343, 40677676847475113963650186462)
Smart 解得 d = 20346488935168368987513436820  与真私钥相等: True   耗时 13.5 ms
验算 d_hat*G == Q: True
对照: BSGS 需要 ~2*sqrt(p) = 4.88e+14 步
```

96 比特的私钥，13.5 毫秒，精确恢复；同一参数下 BSGS 需要 $5 \times 10^{14}$ 量级的表项，两者差十五个数量级——这就是"结构塌缩"的力度。

> [!warning] 前提是 #E = p 精确成立
> Smart's attack 只打 $\#E = p$ 的异常曲线。这一步"乘 p 进形式群"依赖 $\text{ord}(P) = p$：$p$ 倍的提升点模 p 才归约到 $O$。$\#E = p + 1$（supersingular）、$\#E = p \pm k$（k 为小量）时 $p \cdot P \not\equiv O \pmod p$，点根本没进形式群，$x/y$ 不是对数，除法结果就是错的。动手前先 `E.order()` 一次：等于 p 才用这套，否则回到 4.2/4.3 的通用路线。反过来，==出题人给出曲线后，第一件事就是看 $\#E$ 是否恰好等于 p==——CTF 里"白送的 96 比特曲线"经常就是异常曲线。

> [!info]- 为什么扫 b 一定能命中：构造原理
> 式 (3.1) 把 $\#E$ 写成 $p + 1 - t$（t 叫 Frobenius trace）。要 $\#E = p$ 即 $t = 1$。取 $p = \frac{3s^2+1}{4}$ 时 $4p = 1 + 3s^2$，这是判别式 $D = 3$ 的 CM（复乘）表示——$y^2 = x^3 + b$ 这一族（j = 0）的曲线带 $D = 3$ 的复乘，它 mod p 的六个扭折（twist）的 trace 恰好取遍 $\pm 1, \pm\frac{1+3s}{2}, \pm\frac{1-3s}{2}$（都满足 Hasse 界），所以六个扭折里必有一条 $t = \pm 1$，取 $t = 1$ 的那条就是异常曲线。脚本扫 b 就是在逐个试这六个扭折的等价类，所以 b 很小（本例 b = 6）就命中。要造更大参数的同型曲线，换 s 继续找素数 p 即可，方法不变。

## 5. 无效曲线与小子群：协议层攻击预演

### 5.1 攻击形态

**它是干嘛的**：无效曲线攻击（invalid curve attack）打的不是数学，是**实现**：ECDH 一类协议里，一方收到对端的点 $(x, y)$ 后直接做 $d \cdot P$——如果它不检查这个点是否真的在曲线上，攻击者就能送来**别的曲线**上的点，让 d 的秘密在一条"攻击者选好的、阶光滑"的曲线上被拆出来。

关键机制一句话：2.2 的点加与倍点公式里==只出现参数 $a$，参数 $b$ 完全不参与==。所以只要攻击者的曲线和服务方的曲线共用同一个 $a$（记 $a = 2$，服务曲线 $y^2 = x^3 + 2x + 3$，攻击曲线 $y^2 = x^3 + 2x + b_j$），服务照着公式算，运算就始终保持在攻击者那条曲线的群里——而那条曲线的阶是攻击者挑的，光滑、因子小。

攻击循环：

1. 攻击者选一条同 $a$ 异 $b$ 的曲线 $E_j$，找一个小素数 $k \mid \#E_j$ 和一个 $k$ 阶点 $Q_j$；
2. 把 $Q_j$ 当成"对端公钥"发给服务，服务回 $d \cdot Q_j$；
3. $Q_j$ 的阶是 k，所以 $d \cdot Q_j$ 只暴露 $d \bmod k$——爆破 k 个候选（k 很小）即得碎片 $d \equiv t \pmod k$；
4. 换多条曲线、多个 k，攒够碎片，CRT（[[09-密码学基础#2.4 中国剩余定理|09 章 2.4]]）拼出完整 d。

同族的还有**小子群攻击**：曲线的 $\#E = h \cdot n$（n 为大素数，h 叫余因子 cofactor）时，群里有 h 阶的小子群，一个落在小子群里的公钥同样只暴露 $d \bmod h$ 形状的碎片——形态与无效曲线一致，只是"错误曲线"换成了"正确曲线的错误子群"。防御是同一行代码，5.3 讲。

### 5.2 最小服务靶与完整攻击

靶子是一个 48 比特曲线上的标量乘服务：曲线 $y^2 = x^3 + 2x + 3 \bmod 140737488355483$，秘密标量 d（不公开），监听 7201 端口。协议：连接后服务先发一行 `PUB qx qy`（它的公钥 $dG$）；之后每行发两个整数 `x y`，服务返回 $d \cdot (x, y)$——**没有任何 on-curve 校验**：

```python
# server.py —— invalid-curve 靶：收点做标量乘返回结果，不校验点是否在曲线上
import json, socket

with open("params.json") as f:
    prm = json.load(f)
p, A = prm["p"], prm["A"]
d = prm["d"]

def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def mul(k, P):
    R = None
    while k:
        if k & 1:
            R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 7201))
srv.listen(1)
print("[靶] 监听 127.0.0.1:7201，等待连接 ...", flush=True)

conn, addr = srv.accept()
with conn:
    qx, qy = prm["Q"]
    conn.sendall(("PUB %d %d\n" % (qx, qy)).encode())
    print("[靶] 客户端 %s 已连接，已发公钥" % addr[0], flush=True)
    buf = b""
    while True:
        data = conn.recv(4096)
        if not data:
            break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            x, y = map(int, line.split())
            R = mul(d, (x, y))            # 不做 on-curve 校验，直接标量乘
            if R is None:
                conn.sendall(b"O\n")
            else:
                conn.sendall(("%d %d\n" % R).encode())
            print("[靶] 收 (%d, %d) -> %s" % (x, y, R), flush=True)
print("[靶] 连接结束", flush=True)
```

> [!info]- 参数与碎片的生成（sage，攻击前离线做）
> 攻击端的碎片用 sage 离线搜：对每个小素数 k，从 b = 1 起找同 a 异 b 的曲线 $y^2 = x^3 + 2x + b$ 使 $k \mid \#E_j$，取一个 k 阶点；同一段脚本顺便生成服务参数（秘密 d 取得小于碎片乘积，保证 CRT 后解唯一）。搜索脚本每个 k 平均试几十条曲线，总耗时 0.2 s：
>
> ```python
> # build_frags.sage —— 服务参数与每个小素数 k 对应的 (b, k 阶点)
> import time
>
> p = next_prime(2^47)
> while p % 4 != 3:
>     p = next_prime(p + 1)
> A, B = 2, 3
> E = EllipticCurve(GF(p), [A, B])
> G = E.gens()[0]
> N = G.order()
> print("p =", p, " (%d bits, p%%4=%d)" % (p.nbits(), p % 4))
> print("#E =", E.order(), "  G =", G.xy(), "  N = ord(G) =", N)
>
> t0 = time.time()
> frags = []
> for k in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43]:
>     for bj in range(1, 600):
>         if bj == B: continue
>         Ej = EllipticCurve(GF(p), [A, bj])
>         if Ej.order() % k != 0: continue
>         R = (Ej.order() // k) * Ej.gens()[0]
>         if R.is_zero() or k * R != Ej(0): continue
>         x, y = R.xy()
>         frags.append({"k": int(k), "b": int(bj), "x": int(x), "y": int(y)})
>         print("k=%-3d b=%-4d 命中" % (k, bj))
>         break
> print("碎片搜索耗时 %.1f s" % (time.time() - t0))
>
> prod = 1
> for f in frags: prod *= f["k"]
> print("素数个数 =", len(frags), " 乘积 =", prod, " 乘积 > min(p, N) :", prod > min(p, N))
>
> set_random_seed(2026)
> d = ZZ.random_element(2, min(prod - 1, int(min(p, N)) - 1))   # 秘密标量 < 碎片乘积
> Q = d * G
> print("d(秘密) =", d)
> print("Q = d*G =", Q.xy())
> ```
>
> 输出：
>
> ```
> p = 140737488355483  (48 bits, p%4=3)
> #E = 140737484589330   G = (81713734878048, 94866305565066)   N = ord(G) = 140737484589330
> k=3   b=1    命中
> k=5   b=2    命中
> k=7   b=16   命中
> k=11  b=13   命中
> k=13  b=1    命中
> k=17  b=2    命中
> k=19  b=7    命中
> k=23  b=80   命中
> k=29  b=58   命中
> k=31  b=5    命中
> k=37  b=12   命中
> k=41  b=65   命中
> k=43  b=58   命中
> 碎片搜索耗时 0.2 s
> 素数个数 = 13  乘积 = 6541380665835015  乘积 > min(p, N) : True
> d(秘密) = 85368934798811
> Q = d*G = (126254999251313, 42337782162326)
> ```
>
> 13 个碎片素数的乘积 $6541380665835015 > d$，CRT 后解唯一。碎片清单（b、k 阶点坐标）随脚本一并存进 `frags.json`，k 与 b 的对应：3→1、5→2、7→16、11→13、13→1、17→2、19→7、23→80、29→58、31→5、37→12、41→65、43→58。

攻击端复用 2.3 的点运算做本地爆破，逐碎片问服务、CRT 拼合、最后用服务自己的公钥验算：

```python
# attack.py —— invalid-curve 攻击：小阶点提 d mod k，CRT 拼回 d
import json, socket

with open("frags.json") as f:
    frags = json.load(f)
with open("params.json") as f:
    prm = json.load(f)
p, A = prm["p"], prm["A"]
G = tuple(prm["G"])
Qpub = tuple(prm["Q"])

# ……（add / mul 与 2.3 完全相同，省略）……

sock = socket.create_connection(("127.0.0.1", 7201))
banner = sock.makefile().readline().split()
pub = (int(banner[1]), int(banner[2]))
print("[攻] 拿到服务公钥 PUB = d*G =", pub, " 与本地 Qpub 一致:", pub == Qpub)

def ask(x, y):
    sock.sendall(("%d %d\n" % (x, y)).encode())
    line = sock.makefile().readline().strip()
    if line == "O":
        return None
    a, b = map(int, line.split())
    return (a, b)

res, mods = [], []
for fr in frags:
    k = fr["k"]
    Qj = (fr["x"], fr["y"])               # 阶 k 的点，在非法曲线 y^2=x^3+2x+fr["b"] 上
    R = ask(*Qj)                          # 服务回 d*Qj（仍在这条非法曲线上）
    t, T = 0, None
    for i in range(k):                    # 爆破 t：t*Qj == R -> d ≡ t (mod k)
        if T == R:
            t = i
            break
        T = add(T, Qj)
    print("[攻] k=%-3d (b=%-3d): d ≡ %2d (mod %d)" % (k, fr["b"], t, k))
    res.append(t)
    mods.append(k)
sock.close()

def crt(remainders, moduli):              # 09 章 2.4 的最小 CRT
    N = 1
    for m in moduli: N *= m
    x = 0
    for r, m in zip(remainders, moduli):
        Ni = N // m
        x += r * Ni * pow(Ni, -1, m)
    return x % N

d_hat = crt(res, mods)
print("[攻] CRT 拼出 d_hat =", d_hat)
print("[攻] 验算 d_hat*G == PUB:", mul(d_hat, G) == pub)
```

服务端先行，攻击端随后（靶在 127.0.0.1:7201）：

```bash
python3 server.py &          # 终端 1
python3 attack.py            # 终端 2
```

服务端日志（13 条收发同型，节选）：

```
[靶] 监听 127.0.0.1:7201，等待连接 ...
[靶] 客户端 127.0.0.1 已连接，已发公钥
[靶] 收 (9844389941846, 94551825673505) -> (9844389941846, 46185662681978)
……（中间 10 条同类日志略）……
[靶] 收 (124007337875431, 9821147851055) -> (71661169640072, 48518211931834)
[靶] 连接结束
```

攻击端输出：

```
[攻] 拿到服务公钥 PUB = d*G = (126254999251313, 42337782162326)  与本地 Qpub 一致: True
[攻] k=3   (b=1  ): d ≡  2 (mod 3)
[攻] k=5   (b=2  ): d ≡  1 (mod 5)
[攻] k=7   (b=16 ): d ≡  6 (mod 7)
[攻] k=11  (b=13 ): d ≡  4 (mod 11)
[攻] k=13  (b=1  ): d ≡  1 (mod 13)
[攻] k=17  (b=2  ): d ≡ 15 (mod 17)
[攻] k=19  (b=7  ): d ≡  7 (mod 19)
[攻] k=23  (b=80 ): d ≡ 14 (mod 23)
[攻] k=29  (b=58 ): d ≡ 23 (mod 29)
[攻] k=31  (b=5  ): d ≡  8 (mod 31)
[攻] k=37  (b=12 ): d ≡ 36 (mod 37)
[攻] k=41  (b=65 ): d ≡ 17 (mod 41)
[攻] k=43  (b=58 ): d ≡ 27 (mod 43)
[攻] CRT 拼出 d_hat = 85368934798811
[攻] 验算 d_hat*G == PUB: True
```

13 次询问（每次只做不超过 43 次点加的爆破），48 比特的 d 完整恢复，`d_hat·G` 与服务的公钥逐位一致。==服务没有任何一行数学是错的——错的是少了一行检查==。

### 5.3 防御

两行校验，缺一不可：

- **on-curve 校验**：收到点 $(x, y)$ 先验证 $y^2 \equiv x^3 + ax + b \pmod p$（1 ≤ x < p），不过就拒绝——无效曲线攻击当场失效；
- **子群校验**：验证 $n \cdot P = O$（n 是基点的阶），或实现里主动做 cofactor 清除（乘一次 h 把点赶进大素数阶子群）——小子群攻击失效。

现实协议（TLS 1.3、Noise、JOSE）的实现都带这两道检查；CTF 里见到"接收曲线参数的 ECDH 服务"，先按 5.1 的形态试一次再换思路。

## 6. 标准曲线与工具对照

### 6.1 secp256k1、P-256、Curve25519

**它是干嘛的**：标准曲线是"参数公开、来历可查"的曲线，实际协议都用它们。CTF 题里见到这三个名字，按表定位：

| 曲线 | 域 | 方程形状 | 备注与出处 |
| ---- | ---- | ---- | ---- |
| secp256k1 | $\mathrm{GF}(p)$，p 为 256 比特素数 | $y^2 = x^3 + 7$（a = 0） | 比特币 / 以太坊签名用；参数极简 |
| NIST P-256 | $\mathrm{GF}(p)$，p 为 256 比特素数 | 一般 Weierstrass | pycryptodome、浏览器、TLS 的默认 |
| Curve25519 | $\mathrm{GF}(2^{255}-19)$ | 蒙哥马利形 $y^2 = x^3 + 486662x^2 + x$ | X25519 密钥交换 / Ed25519 签名的底座 |

为什么 Curve25519 成了新协议的默认：它的每个常数都有解释（486662 是按"抗攻击 + 实现简单"逐条论证的），p = $2^{255}-19$ 让模运算特别快，蒙哥马利形的阶梯实现天然适合恒定时间代码；而 P-256 的随机参数无法逐条解释，这也是当年社区换曲线的主要理由。secp256k1 的常数可以用 sage 当场核一遍——阶 n 是素数、非常接近 p：

```bash
# secp.sage —— secp256k1 常数核对
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
E = EllipticCurve(GF(p), [0, 7])
G = E(Gx, Gy)
print("n 是素数:", is_prime(n))
print("E.order() == n:", E.order() == n)
print("2G =", (2 * G).xy())
print("|p - n| =", p - n)
```

```bash
sage secp.sage
```

输出：

```
n 是素数: True
E.order() == n: True
2G = (89565891926547004231252920425935692360644145829622209833684329913297188986597, 12158399299693830322967808612713398636155367887041628176798871954788371653930)
|p - n| = 432420386565659656852420866390673177326
```

$\#E = n$ 是素数——循环群、无小子群、异常攻击（$\#E \neq p$）与光滑阶全都不适用，这就是"参数正常"的样子。$\#E$ 与 p 相差 $4.3 \times 10^{38}$，相对差约 $4 \times 10^{-4}$，仍被 Hasse 界罩着。

### 6.2 pycryptodome 的 ECC 模块

日常脚本层用 `Crypto.PublicKey.ECC`：生成密钥、取公私钥、做 ECDH 共享，几行的事：

```python
# ecc_demo.py —— pycryptodome：P-256 密钥对与两方 ECDH
from Crypto.PublicKey import ECC

alice = ECC.generate(curve='P-256')
bob   = ECC.generate(curve='P-256')
print("曲线:", alice.curve)
print("alice.d 位数:", alice.d.bit_length(), "比特")
print("alice 公钥 Q = (", hex(alice.pointQ.x)[:20], "..., ...)")
print("alice 导出公钥前几行:")
print(alice.public_key().export_key(format='OpenSSH')[:60], "...")

# ECDH：各自拿对方公钥乘自己的私钥
S1 = alice.public_key().pointQ * int(bob.d)
S2 = bob.public_key().pointQ * int(alice.d)
print("S1 == S2:", S1 == S2)
print("共享秘密 x 坐标 =", hex(S1.x)[:24], "...")
```

```bash
python3 ecc_demo.py
```

输出（每次运行 d 与 Q 不同，S1 == S2 恒为 True）：

```
曲线: NIST P-256
alice.d 位数: 256 比特
alice 公钥 Q = ( 0x3a5cdce59776eca747 ..., ...)
alice 导出公钥前几行:
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz ...
S1 == S2: True
共享秘密 x 坐标 = 0x826c42810ff08637cc8e73 ...
```

两边算出同一个共享点（取 x 坐标进 KDF），这就是 X25519 / ECDH 的工作方式。两个注意：pycryptodome 只带 NIST 系列（secp256k1 要换 ecdsa 库或 sage）；私钥 d 必须来自密码学安全的随机源——`random` 模块生成的"私钥"是 [[C04-随机数攻防|C04]] 的靶子。曲线签名（ECDSA/Ed25519）在 [[C12-数字签名|C12]] 展开。

### 6.3 gp 的 ell 函数对照

轻量核对用 gp 的 `ell` 一族，与 sage 的对应关系一条一条对得上：

```
E = ellinit([2,3], 97);
P = [3,6];
print("ellmul 2P  = ", ellmul(E, P, 2));
print("ellmul 3P  = ", ellmul(E, P, 3));
print("ellmul 5P  = ", ellmul(E, P, 5));
print("ellcard    = ", ellcard(E));
Q = ellmul(E, P, 3);
print("elllog(Q,P)= ", elllog(E, Q, P));
print("elladd     = ", elladd(E, [3,6], [4,47]));
quit
```

```bash
gp -q --default colors=no ell_demo.gp
```

输出：

```
ellmul 2P  = [Mod(80, 97), Mod(10, 97)]
ellmul 3P  = [Mod(80, 97), Mod(87, 97)]
ellmul 5P  = [0]
ellcard    = 100
elllog(Q,P)= 3
elladd     = [Mod(25, 97), Mod(62, 97)]
```

对照：`ellinit([a,b], p)` 建 $y^2 = x^3+ax+b$ 曲线（sage `EllipticCurve(GF(p),[a,b])`）；`ellmul` 标量乘（sage `n*P`）；`ellcard` 数点（sage `E.order()`）；`elllog(E, X, P)` 解 ECDLP（sage `discrete_log(X, P, operation='+')`），`ellmul(E,P,5) = [0]` 与 2.4 的 $5P = O$ 一致，`elllog` 把 $3P$ 认回 3。点坐标打印成 `Mod(80, 97)` 是 gp 的域元素格式，读法同模 97 余数。工具安装与定位见 [[03-工具清单|工具清单]]。

## 7. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 手写点加偶尔抛 ZeroDivisionError 或算出坏点 | 漏了三个特例分支：P=O、P=−Q（竖线）、P=Q 且 y=0（切线竖直），见 [[#2.2 模 p 的代数公式\|2.2]] 的 warning；先把分支判完再进公式 |
| 标量乘结果时对时错 | double-and-add 位序错了：`k & 1` 取低位、`k >>= 1` 右移是低位优先；混用高位优先的表驱动写法会错。用 $nP = (n{-}1)P + P$ 抽查（[[#2.4 自洽检查与 sage 对拍\|2.4]]） |
| sage 里把 int 直接当坐标建点报错 | 先建域再建点：`E(x, y)` 的坐标走 GF(p) 元素；反过来取坐标用 `ZZ(P.xy()[0])` 转回整数（[[#4.4 Smart's attack：异常曲线上的一步除法\|4.4]] 的用法） |
| sage 点打印成 `(25 : 62 : 1)` 三个数 | 射影坐标，z = 1 即仿射点；`(0 : 1 : 0)` 是 O（[[#2.4 自洽检查与 sage 对拍\|2.4]]） |
| Smart's attack 算出的 d 不对 | 前提 $\#E = p$ 不成立：先用 `E.order() == p` 判定再动手（[[#4.4 Smart's attack：异常曲线上的一步除法\|4.4]] 的 warning）；另外点提升要选 y 模 p 同余的那个分支，选错分支结果同样不对 |
| BSGS 解出的 d 与"真值"不等但验算通过 | 解只对模 ord(P) 唯一，两解差 ord(P) 的整倍数（[[#4.2 BSGS 的曲线版\|4.2]] 的 note）；按 ord(P) 归约 |
| 无效曲线攻击拿到的响应对不上任何 t | 服务的曲线参数 a 与你用的不一致——倍点斜率含 a，运算没有保持在你的曲线上；选同 a 异 b 的曲线（[[#5.1 攻击形态\|5.1]]），或先确定服务曲线的 a 再造碎片 |
| 想找阶等于 #E 的生成元却找不到 | 曲线未必循环（mod 97 教学曲线是 Z/50 + Z/2，最大阶 50）；`E.gens()[0]` 给的是最大阶（指数）点，非循环时它到不了 #E（[[#3.1 点的阶与拉格朗日定理\|3.1]]） |
| gp 的 `elllog` 报错 | 参数顺序 `elllog(E, X, P)` 求 n 使 n·P = X；曲线要 `ellinit([a,b], p)` 先建好（[[#6.3 gp 的 ell 函数对照\|6.3]]） |
| pycryptodome 找不到 secp256k1 | 它只带 NIST 系列；secp256k1 用 ecdsa 库或 sage 手建参数（[[#6.1 secp256k1、P-256、Curve25519\|6.1]]） |
| 大素数 p 上手枚举 #E 跑不完 | 枚举是 $O(p^2)$，只适合教学曲线；直接 `E.order()`（SEA）或 gp `ellcard`（[[#1.3 模 97 的小曲线：把所有点列出来\|1.3]] 折叠框） |
| Curve25519 的点在 sage 里建不出来 | 它是蒙哥马利形 $y^2 = x^3 + 486662x^2 + x$，要用 `EdwardsCurve`/专用接口或按 x-only ladder 手算，短 Weierstrass 的 `EllipticCurve` 入口装不下它（[[#6.1 secp256k1、P-256、Curve25519\|6.1]]） |

## 8. 配套练习与延伸阅读

> [!note] 实战任务
> CryptoHack（cryptohack.org，见 [[01-练习平台索引|练习平台索引]]）的 Elliptic Curves 分类与本章逐节对应：Point Negation、Point Addition、Scalar Multiplication 对应第 2 节（先用库函数、再用 2.3 的手写实现各解一遍，两边必须一致）；Curves and Logs、Efficient Exchange 对应第 4 节的 BSGS 与 ECDH；Montgomery's Ladder 是 2.3 标量乘的常量时间版。全部做完后，把异常曲线一题用 [[#4.4 Smart's attack：异常曲线上的一步除法|4.4]] 的脚本框架重打一遍。

配套练习：

1. 把 2.3 的仿射实现改成射影坐标版（消除每步逆元），对同一批 1000 对随机点与仿射版对拍一致，再对 256 比特曲线各做一次 `mul(k, P)` 计时，比较倍率；
2. 写曲线版 Pohlig-Hellman：取一条 #E 光滑的曲线（sage 里筛到 factor(#E) 全是小素数为止），用 5.2 的"逐小素数提 d mod k + CRT"结构完整解一道 ECDLP，最后与 `discrete_log(Q, P, operation='+')` 对拍；
3. 把 5.2 的靶子升级成"服务每回合换 d"——攻击端先问一次合法点拿 $d \cdot G$ 与 $d \cdot 2G$ 恢复本回合 d，再按原流程打碎片，体会"碎片必须对齐同一个 d"；
4. 用 sage 核对 P-256 的公开参数（p、n、Gx、Gy 来自 SECG/ NIST 文档），复现 6.1 对 secp256k1 做过的三件事：n 素性、`E.order() == n`、基点阶。

延伸阅读：

- [[C12-数字签名|C12]] 把本章的曲线群做成签名体制：ECDSA 的验算方程就立在 $nG$ 之上，随机数 k 复用的崩溃方式与 [[C03-序列密码与LFSR|C03]] 的密钥重用同构；
- [[C08-RSA攻击II|C08]] 讲格与 LLL——sage 里做格的那套入口（`matrix(ZZ,...).LLL()`）与本章同一运行环境，两章工具互通；
- Wikipedia 条目 Elliptic curve point multiplication、BSGS、Smart's attack、Invalid curve attack：本章四块内容的完整版，含各攻击的原始论文引文；
- [[02-书单与Wiki|书单与 Wiki]] 里 Recommended 的密码学教材（如 *Understanding Cryptography* 的椭圆曲线章）与 *Pairing for Beginners*（supersingular 曲线的配对方向，3.3 的伏笔）；
- gp 手册 `ell` 一族（`ellinit`、`ellcard`、`ellmul`、`elllog`、`ellsea`）是 sage 之外最轻的曲线计算入口（[[#6.3 gp 的 ell 函数对照|6.3]]）。
