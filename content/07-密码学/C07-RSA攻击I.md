---
chapter: 密码学
section: RSA 攻击 I
order: 707
tags:
  - CTF
  - 密码学
  - RSA
publish: true
---

# C07 RSA 攻击 I：参数与分解
## RSA Attacks I: Parameters & Factoring

> [!info]- 章节信息
> **所属方向**：密码学 ｜ **难度阶段**：L2 核心漏洞期 ｜ **前置要求**：[[09-密码学基础|09 章]] · [[C01-密码学导论与工具链|C01]] · [[C02-数论进阶与原根|C02]]
> **本章目标**：拿到 $(n, e, c)$ 会按一张"特征 → 攻击"决策表分流；会手写 Fermat 分解与 Wiener 攻击的完整利用链，并知道各自的确切适用边界；会处理 $e$ 与 $\varphi(n)$ 不互素、$p=q$、多素数、共享素数这些密钥生成事故；会按特征在 factordb / yafu / gmp-ecm / sage / RsaCtfTool 之间选对工具；最后知道正确的密钥该怎么生成。

[[09-密码学基础|09 章]]第 5 节讲了 RSA 的手写加解密和三种攻击：$e=3$ 小明文、共模、dp 泄露（[[09-密码学基础#5.3 弱点套路清单|09 章 5.3]]）。本章在这个基线上做第一卷系统展开，对象是==参数与分解==：攻击不看密文内容，只看公钥参数长什么样。四种局面按节展开——p、q 相近（Fermat）、d 过小（Wiener）、e 与 φ 不互素（d 不存在）、素数本身有问题（p=q、多素数、共享素数、后门素数）；每一节都按"原理 → 手写利用 → 自建靶验证 → 现成工具对照"的顺序走。分解工具链与 RsaCtfTool 的全自动流程收拢在第 6 节。

## 1. 攻击者视角：先看参数，再选攻击

### 1.1 拿到 (n, e, c) 的体检清单

[[09-密码学基础|09 章]]的三步法第一步是读脚本——==弱点几乎总写在脚本里，不写在密文里==。但总有只给参数不给脚本的题（线上服务只吐出 n、e、c；附件是纯输出文件），这时按固定顺序体检参数本身：

1. **n 的位数**。几十位十进制（三百比特以内）直接进分解流程（第 6 节）；几百位且参数无其他弱点时，==分解不在算力内，突破口只能回到读脚本==。
2. **n 的形状**。是不是完全平方数（`isqrt(n)**2 == n`，p = q）；试除一百万以内的小因子；同批给了多条 n 就两两 gcd（第 5 节）。
3. **e 的形态**。65537 是常规取值，本身无弱点；e 偏小（3、17 一类）先想小明文开方，再看 e 与 φ 是否互素（第 4 节）；==e 长到与 n 同量级，往往就是 d 被刻意选小的影子==——e 是 d 在模 φ 下的逆元，d 小则 e 大（第 3 节）。
4. **密钥生成代码**（有的话）。`q = nextprime(p)` 或 `nextprime(p + 常数)`，进 Fermat（第 2 节）；`random.seed(...)` 之后生成素数，进 [[C04-随机数攻防|C04]] 的种子攻击。
5. **多组公钥**。同一 n 配两组 (e, c) 是共模（[[09-密码学基础#5.3 弱点套路清单|09 章 5.3]]）；多条不同 n 可能共享素数（第 5.3 节）。

这份清单写成脚本就是 30 秒的事：

```python
# rsa_recon.py —— 拿到 (n, e) 后的 30 秒体检
from math import isqrt, gcd
from sympy import nextprime


def trial_small_factor(n, bound=10**6):
    """试除找 bound 以内的小因子，返回最小因子或 None"""
    for p in (2, 3, 5):
        if n % p == 0:
            return p
    f = 7
    while f < bound:
        if n % f == 0:
            return f
        f += 2
    return None


def recon(n, e, others=()):
    print("--- n = %d" % n)
    print("    %d bit / %d 位十进制" % (n.bit_length(), len(str(n))))
    if e == 65537:
        print("    e = 65537：常规取值，e 本身没有弱点，突破口在 n 或密钥生成")
    elif e.bit_length() <= 17:
        print("    e = %d：偏小。若明文也短，先试 09 章 5.3 的小明文开方；再看 gcd(e, phi) 是否 > 1（第 4 节）" % e)
    else:
        print("    e 有 %d bit：偏大。d 被刻意选小时 e 就长这样，进入 Wiener 适用范围（第 3 节）" % e.bit_length())
    s = isqrt(n)
    if s * s == n:
        print("    n 是完全平方数：p = q = isqrt(n)（第 5.1 节）")
    f = trial_small_factor(n)
    if f:
        print("    试除命中 %d 位小因子: %d（第 6.3 节的 ecm 能抓更大的）" % (len(str(f)), f))
    for n2 in others:
        g = gcd(n, n2)
        if g != 1:
            print("    与同批另一条 n 有 %d bit 公因子：共享素数（第 5.3 节）" % g.bit_length())
    print()


# 三条事故 n：A 混进一位 6 位十进制的素数；B 是 p*q（p=q）；C/D 同批共享素数
pa = 999983
qa = nextprime(2**127 + 987654321)
pc = nextprime(2**127)
shared = nextprime(2**126 + 555555)
nA, eA = pa * qa, 65537
nB, eB = pc * pc, 3
nC, nD = shared * nextprime(2**127 + 111111), shared * nextprime(2**127 + 222222)

recon(nA, eA)
recon(nB, eB, others=[nC, nD])
recon(nC, 65537, others=[nA, nB, nD])
```

```bash
python3 rsa_recon.py
```

输出：

```
--- n = 170138291060350403754747865032708573421075903
    147 bit / 45 位十进制
    e = 65537：常规取值，e 本身没有弱点，突破口在 n 或密钥生成
    试除命中 6 位小因子: 999983（第 6.3 节的 ecm 能抓更大的）

--- n = 28948022309329048855892746252171976973185684807117356450302259617499560543049
    255 bit / 77 位十进制
    e = 3：偏小。若明文也短，先试 09 章 5.3 的小明文开方；再看 gcd(e, phi) 是否 > 1（第 4 节）
    n 是完全平方数：p = q = isqrt(n)（第 5.1 节）

--- n = 14474011154664524427946373126086092476799102850622878016565317305319036560411
    254 bit / 77 位十进制
    e = 65537：常规取值，e 本身没有弱点，突破口在 n 或密钥生成
    与同批另一条 n 有 127 bit 公因子：共享素数（第 5.3 节）
```

三条体检结果分别指向第 6.3、5.1、5.3 节的攻击，解法到对应节展开。

### 1.2 特征 → 攻击决策表

把 [[09-密码学基础#5.3 弱点套路清单|09 章 5.3]] 的小清单按本章范围扩容成一张总表。==先分流，再写脚本==——每行"第一动作"的成本都在秒级：

| 你看到（特征） | 说明 | 第一动作 | 出处 |
| ---- | ---- | ---- | ---- |
| n 只有几十位十进制 | 分解在算力内 | factordb → yafu | [[#6. 分解工具链实战\|第 6 节]] |
| factordb 状态 FF | 这条 n 早被分解过 | 拿因子接标准解密 | [[#6.1 factordb：先查有没有人分解过\|6.1]] |
| n 是完全平方数 | p = q | isqrt(n) 直接分解 | [[#5.1 p = q：n 是完全平方数\|5.1]] |
| 同批给了多条 n | 可能共享素数 | 两两 gcd | [[#5.3 共享素数：多条 n 两两 gcd\|5.3]] |
| e 偏小且明文短 | $m^e$ 可能没取模 | 整数开方 | [[09-密码学基础#5.3 弱点套路清单\|09 章 5.3]] |
| gcd(e, phi) > 1 | d 不存在 | 分域取根 + CRT | [[#4. e 与 φ 不互素：d 不存在的时候\|第 4 节]] |
| e 与 n 同量级（几百位） | d 可能被选小了 | Wiener | [[#3. Wiener 攻击：d 过小\|第 3 节]] |
| 脚本里 q = nextprime(p) 或 nextprime(p+k) | p、q 相近 | Fermat | [[#2. Fermat 分解：p、q 相近\|第 2 节]] |
| 脚本里 random.seed(...) 后生成素数 | 素数可复现 | 扫种子 | [[C04-随机数攻防\|C04]] |
| 同一 n 配两组 (e, c) | 共模 | exgcd 合并指数 | [[09-密码学基础#5.3 弱点套路清单\|09 章 5.3]] |
| 泄露了 dp / dq / 部分 d | 密钥碎片 | gcd 挖 p | [[09-密码学基础#5.3 弱点套路清单\|09 章 5.3]] |

表里共模、小明文开方、dp 泄露三行的攻击本体在 [[09-密码学基础#5.3 弱点套路清单|09 章 5.3]]，random.seed 一行的去处是 [[C04-随机数攻防|C04]]，本章不重讲；其余各行对应的内容在下面各节展开。

## 2. Fermat 分解：p、q 相近

### 2.1 原理：把 n 写成平方差

设 $n = pq$。构造两个数：

$$a = \frac{p+q}{2}, \qquad b = \frac{p-q}{2} \tag{2.1}$$

则

$$n = pq = a^2 - b^2 \tag{2.2}$$

==费马分解就是从 $\lceil\sqrt{n}\rceil$ 起逐个加大 $a$，检查 $a^2 - n$ 是不是完全平方数==；一旦是，$b = \sqrt{a^2-n}$，$a-b$ 与 $a+b$ 就是 $p$、$q$。要走的步数是 $a$ 从 $\sqrt{n}$ 走到 $(p+q)/2$ 的距离：

$$\frac{p+q}{2} - \sqrt{pq} \approx \frac{(p-q)^2}{8\sqrt{n}} \tag{2.3}$$

式 (2.3) 决定一切：==轮数只看 $|p-q|$ 与 $\sqrt{n}$ 的比值==。$|p-q|$ 与 $\sqrt{n}$ 相比是小量时轮数就是个位数；按 2.2 节靶子的尺度（256 比特的 n），$|p-q|$ 到 $2^{70}$ 也只是几百轮，到 $2^{100}$ 量级就要 $10^{20}$ 轮往上——从可行到不可行的过渡带在 $n^{1/4}$ 附近。

> [!note] 检测线索
> p、q 相近不是性质攻击，是==生成代码写坏了==：`q = nextprime(p)`（连号素数）、`q = nextprime(p + 2**64)`（同源小偏移）、或 p、q 从同一段随机数附近取。附件里有出题脚本时，看到 nextprime 套 nextprime 就直接进本节。

### 2.2 手写实现与弱钥靶

```python
# fermat.py —— Fermat 分解
import time
from math import isqrt
from sympy import nextprime
from Crypto.Util.number import bytes_to_long, long_to_bytes


def fermat(n, max_iter=100000):
    """从 ceil(sqrt(n)) 起，逐个 a 试 a^2 - n 是否完全平方数。返回 (小因子, 大因子, 轮数) 或 None"""
    a = isqrt(n)
    if a * a < n:
        a += 1
    for i in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b, i + 1
        a += 1
    return None


e = 65537
m = bytes_to_long(b"flag{c1053_pr1m3s}")

# 靶：q = nextprime(p + 2^70)，n 为 256 比特
p = nextprime(2**127 + 12345678901234567890)
q = nextprime(p + 2**70)
n = p * q
c = pow(m, e, n)
print("n =", n)
print("c =", c)
print("|p-q| 位数:", (q - p).bit_length(), "bit   n 位数:", n.bit_length(), "bit")
pred = (q - p) ** 2 // (8 * isqrt(n))
print("按 (p-q)^2/(8*sqrt(n)) 预测轮数约:", pred)

t0 = time.perf_counter()
fp, fq, iters = fermat(n)
print("fermat: 第 %d 轮命中, 耗时 %.3f s" % (iters, time.perf_counter() - t0))
assert fp * fq == n
d = pow(e, -1, (fp - 1) * (fq - 1))
print("p =", fp)
print("q =", fq)
print("解密:", long_to_bytes(pow(c, d, n)))
```

```bash
python3 fermat.py
```

输出：

```
n = 28948022309329049060961018622303751082199878917975292011488366563728803124303
c = 24336193075339757801323069603577419710465404107673382723353521130588139165198
|p-q| 位数: 71 bit   n 位数: 255 bit
按 (p-q)^2/(8*sqrt(n)) 预测轮数约: 1023
fermat: 第 1024 轮命中, 耗时 0.000 s
p = 170141183460469231744032982617118673623
q = 170141183460469232924624603334529977161
解密: b'flag{c1053_pr1m3s}'
```

式 (2.3) 的预测与实际命中轮数差 1——预测公式就是攻击的可行性判据：==先估轮数再开跑==。$|p-q|$ 为 $2^{70}$、n 为 255 比特时是千轮级；同一尺度下 $|p-q|$ 换成 $2^{100}$，轮数到 $2^{69} \approx 5.9\times10^{20}$，跑不完。

### 2.3 next_prime 型出题为什么必中

最极端的写坏方式是 p、q 连号：

```python
p2 = nextprime(2**127)
q2 = nextprime(p2)
n2 = p2 * q2
print("n =", n2)
print("q - p =", q2 - p2)
fp, fq, iters = fermat(n2)
print("fermat: 第 %d 轮命中" % iters)
print("还原因子:", fp, "x", fq)
```

输出：

```
n = 28948022309329048855892746252171976975907943742484864158009256476953706235161
q - p = 16
fermat: 第 1 轮命中
还原因子: 170141183460469231731687303715884105757 x 170141183460469231731687303715884105773
```

相邻素数的间隙平均约 $\ln p$，这个尺度下间隙是几十的量级，代入式 (2.3) 后轮数恒为个位数——==只要出题人用 nextprime 把 p、q 串起来，费马第一轮附近就命中==，与密钥位数无关。这也是"next_prime 型出题必中"的准确含义。

### 2.4 变形：高位相近、比值非 1:1

p、q 的**高位**相近但比值不是 1:1 时（比如 $p \approx 2\times10^{38}$、$q \approx 3\times10^{38}$），$|p-q|$ 与 $\sqrt{n}$ 同量级，式 (2.3) 的轮数是天文数字，普通费马追不上。变形是==把 $n$ 乘一个小系数 $k$ 再跑==：若 $p/q \approx u/v$（小整数比），取 $k = uv$，则

$$k \cdot n = (u \cdot p)(v \cdot q)$$

右端两个因子相近，对 $k \cdot n$ 跑同一套平方差就能合拢，再用 gcd 剥掉混进来的 $u$、$v$：

```python
from math import gcd

p3 = nextprime(2 * 10**38)
q3 = nextprime(3 * 10**38)
n3 = p3 * q3
print("n =", n3)
print("|p-q| 位数:", (q3 - p3).bit_length(), "bit")
r3 = fermat(n3, max_iter=100000)
print("普通费马（10 万轮上限内）:", "第 %d 轮命中" % r3[2] if r3 else "未命中")

def fermat_scan(n, kmax=30, max_iter=100000):
    """倍乘费马：对 k*n 逐个 k 试，命中后用 gcd 剥掉 k"""
    for k in range(1, kmax + 1):
        r = fermat(k * n, max_iter=max_iter)
        if r:
            A, B, iters = r
            p, q = gcd(A, n), gcd(B, n)
            if p * q == n:
                return p, q, k, iters

p_rec, q_rec, k_hit, iters_hit = fermat_scan(n3)
print("k = %d 时命中（第 %d 轮）" % (k_hit, iters_hit))
print("gcd 还原: p =", p_rec)
print("          q =", q_rec)
assert p_rec * q_rec == n3
c3 = pow(bytes_to_long(b"flag{mult_fermat}"), 65537, n3)
d3 = pow(65537, -1, (p_rec - 1) * (q_rec - 1))
print("解密:", long_to_bytes(pow(c3, d3, n3)))
```

输出：

```
n = 60000000000000000000000000000000000010300000000000000000000000000000000000391
|p-q| 位数: 127 bit
普通费马（10 万轮上限内）: 未命中
k = 24 时命中（第 1 轮）
gcd 还原: p = 300000000000000000000000000000000000017
          q = 200000000000000000000000000000000000023
解密: b'flag{mult_fermat}'
```

$p/q = 2/3$，平方差合拢需要 $u=2, v=3$，$k = uv = 6$；扫描却是在 $k = 24$ 命中的——这里有一个奇偶性陷阱。

> [!warning] $k \cdot n \equiv 2 \pmod 4$ 的 k 永远打不中
> $a^2 - b^2$ 模 4 只能取 0、1、3；$kn \equiv 2 \pmod 4$ 时方程无整数解，费马循环跑多少轮都不会命中。$p$、$q$ 都是奇素数时 $n$ 是奇数，$k=6$ 使 $kn \equiv 2 \pmod 4$，恰好落进死区；$k=24$ 时 $4 \mid kn$，对应的因子对 $(6p, 4q)$ 同为偶数，同余方程有解。写扫描时不用逐个分析：==命中判据里加一道 `p * q == n` 的验算，打不中的 k 自然被跳过==，扫描本身会替你找到能命中的那个。

> [!info]- RsaCtfTool 对照
> C01 5.3 用 `--attack fermat` 解过同型靶（[[C01-密码学导论与工具链#5.3 RsaCtfTool：弱点自动尝试|C01 5.3]]）；RsaCtfTool 的 SQUFOF 攻击与费马同属平方差家族，对 p、q 相近的靶同样命中。倍乘扫描它没有现成入口，2.4 的手写版是补位。

## 3. Wiener 攻击：d 过小

### 3.1 连分数与收敛子

连分数把分数 $x/y$ 写成整数序列：每次记下整数部分 $a_0 = \lfloor x/y \rfloor$，对倒数 $y/(x - a_0 y)$ 重复。$17/7 = 2 + 3/7 = 2 + 1/(2 + 1/3)$，部分商序列就是 $[2, 2, 3]$。截取前若干个部分商组成的分数叫**收敛子**：$[2] = 2/1$，$[2,2] = 5/2$，$[2,2,3] = 17/7$——收敛子逐个逼近真值，且==每个收敛子都是与 $x/y$ 最接近的分数（分母不超过它的范围里没有更近的）==。连分数理论里这个性质叫最佳逼近，它是 Wiener 攻击的引擎：要找"最接近某个无理数的小分母分数"，逐个收敛子试就是完整搜索。

```python
# wiener.py —— 连分数与收敛子
def cont_frac(x, y):
    """x/y 的连分数部分商序列"""
    while y:
        a = x // y
        yield a
        x, y = y, x - a * y


def convergents(seq):
    """部分商的收敛子序列 [(分子, 分母), ...]"""
    res = []
    h0, h1, k0, k1 = 0, 1, 1, 0
    for a in seq:
        h0, h1 = h1, a * h1 + h0
        k0, k1 = k1, a * k1 + k0
        res.append((h1, k1))
    return res


print("部分商:", list(cont_frac(17, 7)))
print("收敛子:", convergents(cont_frac(17, 7)))
```

输出：

```
部分商: [2, 2, 3]
收敛子: [(2, 1), (5, 2), (17, 7)]
```

512 比特的 $e/n$ 同样这么展开，只是部分商更多更长；`convergents` 的递推式（分子分母各由前两个收敛子线性组合）保证每一步只有两次大数乘法。

### 3.2 攻击原理：k/d ≈ e/n

RSA 满足 $e \cdot d \equiv 1 \pmod{\varphi(n)}$，即存在整数 $k$ 使

$$e \cdot d - k \cdot \varphi(n) = 1 \tag{3.1}$$

两边除以 $d\,\varphi(n)$：

$$\frac{e}{\varphi(n)} - \frac{k}{d} = \frac{1}{d\,\varphi(n)} \tag{3.2}$$

右端极小，所以 $\frac{k}{d}$ 是 $\frac{e}{\varphi(n)}$ 的极好近似；又 $\varphi(n) = n - (p+q) + 1 \approx n$，==用公开的 $e/n$ 替换 $e/\varphi(n)$，误差仍然盖不过 $k/d$ 的近似精度==。$d$ 越小，近似精度要求越高、满足精度的分数越少，而收敛子恰好是全部候选——于是有 Wiener 定理：

> [!note] Wiener 定理
> $n = pq$（$q < p < 2q$）且 $d < \frac{1}{3}n^{1/4}$ 时，$k/d$ 必然出现在 $e/n$ 的收敛子序列里。攻击就是==枚举收敛子、逐个验证==，多项式时间完成。

验证一个候选 $(k, d)$ 的完整链条：

1. $(e \cdot d - 1)$ 必须被 $k$ 整除，除出 $\varphi' = (e \cdot d - 1) / k$；
2. 由 $p + q = n - \varphi(n) + 1$，看二次方程 $x^2 - (n - \varphi' + 1)x + n = 0$ 有没有整数根（判别式 $\Delta = (n - \varphi' + 1)^2 - 4n$ 是完全平方数）；
3. 有——$(k, d)$ 就是真解，$\varphi'$ 就是真的 $\varphi(n)$；没有——换下一个收敛子。

### 3.3 完整攻击脚本与边界对照

确定性靶：p、q 无结构（不相近、比值不接近小分数，费马系分解打不动），d 被故意压到 100 比特；此时 $e = d^{-1} \bmod \varphi$ 长到 510 比特——==大 e 是小 d 的影子==，体检清单第 3 条说的就是它。靶的两个素数相差约 3.5 倍，略超定理 $q < p < 2q$ 的假设——实战里这一档多数照样命中，下一档对照会看到边界外的失效。

```python
# wiener.py —— 完整攻击（接 3.1 的两个函数）
import time
from math import isqrt
from sympy import nextprime
from Crypto.Util.number import bytes_to_long, long_to_bytes


def wiener(e, n, verbose=False):
    """枚举 e/n 的收敛子，逐个当 (k, d) 验证。返回 (d, 命中位置) 或 (None, 全部长度)"""
    tried = 0
    for k, d in convergents(cont_frac(e, n)):
        tried += 1
        if k == 0 or (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1                 # x^2 - s*x + n = 0 的两根为 p、q
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = isqrt(disc)
        if r * r == disc and (s + r) % 2 == 0:
            if verbose:
                print("  第 %d 个收敛子命中" % tried)
            return d, tried
    return None, tried


def make_target(dbits):
    """确定性靶：p、q 无结构；d 取 dbits 位的固定素数；e = d^-1 mod phi"""
    p = nextprime(2**254 + 12345678901234567890)
    q = nextprime(10**77 + 98765432109876543210987654321)
    d = nextprime(2**(dbits - 1) + 20240707)
    phi = (p - 1) * (q - 1)
    e = pow(d, -1, phi)
    return p, q, e, d, phi


m = bytes_to_long(b"flag{sm4ll_d_1s_d4ng3r}")

p, q, e, d, phi = make_target(100)
n = p * q
c = pow(m, e, n)
print("n =", n)
print("e =", e)
print("c =", c)
print("d 位数: %d   边界 n^0.25/3 位数: %d   边界内: %s"
      % (d.bit_length(), (isqrt(isqrt(n)) // 3).bit_length(), d < isqrt(isqrt(n)) // 3))

t0 = time.perf_counter()
d_rec, tried = wiener(e, n, verbose=True)
print("恢复 d 用时 %.4f s，与生成时的 d 相等: %s" % (time.perf_counter() - t0, d_rec == d))
print("解密:", long_to_bytes(pow(c, d_rec, n)))

for dbits in (120, 135):
    p, q, e, d, phi = make_target(dbits)
    n = p * q
    c = pow(m, e, n)
    print()
    print("== 靶 %d 比特 d（边界 %d bit）==" % (dbits, (isqrt(isqrt(n)) // 3).bit_length()))
    t0 = time.perf_counter()
    d_rec, tried = wiener(e, n)
    if d_rec is not None:
        print("命中（第 %d 个收敛子，%.4f s），d 相等: %s" % (tried, time.perf_counter() - t0, d_rec == d))
        print("解密:", long_to_bytes(pow(c, d_rec, n)))
    else:
        print("扫完全部 %d 个收敛子未命中（%.3f s）——超出 Wiener 边界" % (tried, time.perf_counter() - t0))
```

```bash
python3 wiener.py
```

输出：

```
n = 2894802230932904885589274625217197696331749616643873164919781397852496678526708605511121932128089101508120192899855200733095093041855581211938982069372437
e = 710145315056341747025914353398682520866770872013536333978058184588906497409786343797119460359013685439557463968955751255849408889005244522904367070262531
c = 1256774717621273884889802497398442557752981583906063155208058613657175141525292779906882468534994802083250508827602613017296710321019402291167085891123762
d 位数: 100   边界 n^0.25/3 位数: 126   边界内: True
  第 68 个收敛子命中
恢复 d 用时 0.0001 s，与生成时的 d 相等: True
解密: b'flag{sm4ll_d_1s_d4ng3r}'

== 靶 120 比特 d（边界 126 bit）==
命中（第 74 个收敛子，0.0001 s），d 相等: True
解密: b'flag{sm4ll_d_1s_d4ng3r}'

== 靶 135 比特 d（边界 126 bit）==
扫完全部 277 个收敛子未命中（0.000 s）——超出 Wiener 边界
```

三档对照把边界讲全了：510 比特的 n 对应边界 $\frac{1}{3}n^{1/4} \approx 2^{126}$，==100、120 比特的 d 都命中，135 比特把 277 个收敛子扫完也没有一个是真解==。边界附近（$d$ 在 $n^{1/4}$ 量级上下浮动）命中与否随具体密钥浮动，定理只保证 $d < n^{1/4}/3$ 之内必然命中；边界外还值得试的升级是 Boneh–Durfee（适用到约 $n^{0.292}$，RsaCtfTool 里有 `boneh_durfee` 攻击，依赖格归约）。

> [!warning] 恢复出的 d 不必与"出题人的 d"逐位相等
> $e \cdot d \equiv 1 \pmod{\varphi(n)}$ 的解是 $d + t\,\varphi(n)$ 一整族。攻击枚举收敛子时可能先命中族里较大的那个成员——它同样是合法的解密指数。验证攻击结果的标准不是"和某个 d 相等"，而是==解密结果可读==（或 `e * d % phi == 1`，前提是你已经从分解里算出了 φ）。

### 3.4 RsaCtfTool 对照

3.3 的靶值直接喂给 RsaCtfTool，指定 `--attack wiener`：

```bash
RsaCtfTool -n 2894802230932904885589274625217197696331749616643873164919781397852496678526708605511121932128089101508120192899855200733095093041855581211938982069372437 \
           -e 710145315056341747025914353398682520866770872013536333978058184588906497409786343797119460359013685439557463968955751255849408889005244522904367070262531 \
           --decrypt 1256774717621273884889802497398442557752981583906063155208058613657175141525292779906882468534994802083250508827602613017296710321019402291167085891123762 \
           --attack wiener
```

输出：

```
[*] Testing key /tmp/tmpohac22ov.
[*] Performing wiener attack on /tmp/tmpohac22ov.
[*] Attack success with wiener method !

Results for /tmp/tmpohac22ov:

Decrypted data :
HEX : 0x666c61677b736d346c6c5f645f31735f64346e6733727d
INT (big endian) : 9810209026726883501117729886360128804554482467426497149
INT (little endian) : 12015349003865821013412029178059362071228963179712310374
utf-8 : flag{sm4ll_d_1s_d4ng3r}
STR : b'flag{sm4ll_d_1s_d4ng3r}'
```

与手写版结论一致，0.2 秒内完成。==知道原理的价值在于知道它什么时候不适用==：d 不够小时工具扫完就是扫完，此时能判断"该换路了"的只有懂边界的人。

## 4. e 与 φ 不互素：d 不存在的时候

### 4.1 判定与总体思路

$d = e^{-1} \bmod \varphi(n)$ 存在当且仅当 $\gcd(e, \varphi(n)) = 1$。生成密钥时的 `assert gcd(e, phi) == 1` 失败、或解题时 `pow(e, -1, phi)` 抛 `ValueError`，都是这个局面。==这不是题目坏了，是出题人故意选了不互素的 e==——常见形态是 $e = 2$（φ 必为偶数）或 $e = 3$ 而 $p \equiv q \equiv 1 \pmod 3$。

没有 d，"解密"变成解方程：已知 $m^e \equiv c \pmod n$，求全部 $m$ 候选。[[C02-数论进阶与原根|C02]]第 2 节的工具在这里接上：==把方程拆到每个素因子域上分别取根，再用 CRT 把根组合回 mod n==。模素数 $p$ 时 $x^e \equiv c$ 的根恰好 $\gcd(e, p-1)$ 个，候选总数是各域根数的乘积，最后按可读性筛出明文。

### 4.2 e = 2：从直接开方到分域取根

$e = 2$ 就是 [[C02-数论进阶与原根|C02]]开头讨论的 Rabin 型映射。明文短到 $m^2 < n$ 时取模没有发生，密文就是 $m^2$ 本身，整数开方直接还原（[[09-密码学基础#5.3 弱点套路清单|09 章 5.3]] 的整数开方）：

```python
# ephi.py —— e 与 phi 不互素
from math import isqrt, gcd
from sympy import nextprime
from sympy.ntheory.residue_ntheory import nthroot_mod
from Crypto.Util.number import bytes_to_long, long_to_bytes


def crt2(r1, m1, r2, m2):
    """两条同余式 x≡r1 (mod m1), x≡r2 (mod m2) 的 CRT 拼合（09 章 2.4 的双模版）"""
    return (r1 + m1 * ((r2 - r1) * pow(m1, -1, m2) % m2)) % (m1 * m2)


# 靶 1：e=2，明文短到 m^2 < n
p = nextprime(2**63 + 12345)
q = nextprime(2**63 + 98765)
n = p * q
m = bytes_to_long(b"flag{e2}")
c = pow(m, 2, n)
print("n =", n, "  e = 2")
print("c =", c)
print("m^2 < n:", m * m < n)
r = isqrt(c)
print("整数开方:", r, isqrt(c) ** 2 == c, long_to_bytes(r))
```

输出：

```
n = 85070591730235641172772756783461623011   e = 2
c = 54470023504904040513549522016239292681
m^2 < n: True
整数开方: 7380380986433155709 True b'flag{e2}'
```

$m^2 > n$ 时密文是真·带模平方，直接开方开不回，走分域取根。取 $p \equiv q \equiv 3 \pmod 4$ 的靶，开方用 [[C02-数论进阶与原根#2.3 开方捷径：p ≡ 3 mod 4|C02 2.3]] 的一行公式 $r = c^{(p+1)/4} \bmod p$：

```python
# 接上：p、q 都取 mod 4 = 3
s = 2**63
while True:
    s = nextprime(s)
    if s % 4 == 3:
        p = s
        break
while True:
    s = nextprime(s)
    if s % 4 == 3:
        q = s
        break
n = p * q
m = bytes_to_long(b"flag{e2_big}")
c = pow(m, 2, n)
print("p =", p)
print("q =", q)
print("m 位数: %d bit   m^2 位数: %d bit   n 位数: %d bit   m < n: %s   m^2 > n: %s"
      % (m.bit_length(), (m * m).bit_length(), n.bit_length(), m < n, m * m > n))
try:
    pow(2, -1, (p - 1) * (q - 1))
except ValueError as ex:
    print("pow(2, -1, phi) 抛 ValueError:", ex)

rp = pow(c, (p + 1) // 4, p)            # C02 2.3 的开方捷径
rq = pow(c, (q + 1) // 4, q)
print("模 p 的根:", rp, "验算:", rp * rp % p == c % p, " 另一根:", p - rp)
print("模 q 的根:", rq, "验算:", rq * rq % q == c % q, " 另一根:", q - rq)
print("CRT 组合 2x2 = 4 个候选：")
for x in (rp, p - rp):
    for y in (rq, q - rq):
        b = long_to_bytes(crt2(x, p, y, q))
        print("   ", b if b.startswith(b"flag") else "(乱码，丢弃)")
```

输出：

```
p = 9223372036854775907
q = 9223372036854775931
m 位数: 95 bit   m^2 位数: 190 bit   n 位数: 127 bit   m < n: True   m^2 > n: True
pow(2, -1, phi) 抛 ValueError: base is not invertible for the given modulus
模 p 的根: 8891568084328255955 验算: True  另一根: 331803952526519952
模 q 的根: 8891568001846070915 验算: True  另一根: 331804035008705016
CRT 组合 2x2 = 4 个候选：
    b'flag{e2_big}'
    (乱码，丢弃)
    (乱码，丢弃)
    (乱码，丢弃)
```

四个候选里只有一个是真明文，另外三个是 $\pm$ 组合出的合法平方根——==平方根成对出现正是二次剩余的结构性质==，判定与求根见 [[C02-数论进阶与原根#2.1 定义与欧拉判据|C02 2.1]]。

> [!warning] 先查 m < n，再谈攻击
> 分域取根恢复的是 $m \bmod n$。明文一旦超过 n（比如 flag 写得太长），CRT 拼出的永远是 $m - kn$，怎么筛都是乱码。[[09-密码学基础#5.2 手写加解密|09 章 5.2]] 的警告在本节同样生效：==解题脚本第一行先 assert 明文长度不超过模数==。

### 4.3 e = 3：每个素域多个根，CRT 组合

$e = 3$ 且 $p \equiv q \equiv 1 \pmod 3$ 时，$\gcd(3, p-1) = \gcd(3, q-1) = 3$，每个素域有 3 个根，mod n 下共 9 个候选。模素数开 k 次方根用 sympy 的 `nthroot_mod`（[[C02-数论进阶与原根#2.5 Tonelli-Shanks：p ≡ 1 mod 4 的一般开方|C02 2.5]] 开平方的一般化）：

```python
# 接上：e=3，p ≡ q ≡ 1 (mod 3)
s = 2**62
while True:
    s = nextprime(s)
    if s % 3 == 1:
        p = s
        break
while True:
    s = nextprime(s)
    if s % 3 == 1:
        q = s
        break
n = p * q
phi = (p - 1) * (q - 1)
print("p mod 3 =", p % 3, "  q mod 3 =", q % 3, "  gcd(3, phi) =", gcd(3, phi))
m = bytes_to_long(b"flag{e3}")
c = pow(m, 3, n)
print("m 位数: %d bit   m < n: %s   m^3 位数: %d bit" % (m.bit_length(), m < n, (m**3).bit_length()))
print("c =", c)
try:
    pow(3, -1, phi)
except ValueError as ex:
    print("pow(3, -1, phi) 抛 ValueError:", ex)

rp = nthroot_mod(c, 3, p, all_roots=True)
rq = nthroot_mod(c, 3, q, all_roots=True)
print("模 p 的 3 次根:", rp, "（%d 个）" % len(rp))
print("模 q 的 3 次根:", rq, "（%d 个）" % len(rq))
hits = []
for x in rp:
    for y in rq:
        b = long_to_bytes(crt2(x, p, y, q))
        if b.startswith(b"flag"):
            hits.append(b)
print("CRT 组合 %d 个候选，命中:" % (len(rp) * len(rq)), hits)
```

输出：

```
p mod 3 = 1   q mod 3 = 1   gcd(3, phi) = 3
m 位数: 63 bit   m < n: True   m^3 位数: 189 bit
c = 15320913276522662399202294107536056064
pow(3, -1, phi) 抛 ValueError: base is not invertible for the given modulus
模 p 的 3 次根: [2768694968005767926, 3047985708590325986, 3406691360258682166] （3 个）
模 q 的 3 次根: [32105427795440505, 1810885622626179692, 2768694968005767884] （3 个）
CRT 组合 9 个候选，命中: [b'flag{e3}']
```

g = 3、两个素域，候选数 $3 \times 3 = 9$；e 更大或素因子更多时组合数按乘法增长，但筛可读前缀的写法不变。

> [!info]- 盲化：随机化候选
> 分域取根要写出全部根再筛选。另一种思路是**盲化**：任取随机数 $u$，令 $c' = c \cdot u^e \bmod n$，解 $x^e \equiv c'$ 的任意一个根 $x'$，则 $x' \cdot u^{-1} \bmod n$ 是原方程的根之一。每换一个 $u$，命中的根随之变化，重复即可遍历全部候选。它更大的用处是对付"有解密服务但拒绝可疑输入"的题：把想解的密文盲化后递给服务，绕开对明文的检查。

## 5. 素数选择的事故

前面四节攻击的是"参数怎么用"，这一节攻击的是"素数怎么选"。每一类都对应一种写坏的生成代码。

### 5.1 p = q：n 是完全平方数

生成代码里两次取样之间没去重（或直接写了 `n = p * p`），n 就是完全平方数。检测与分解都是一行：

```python
# primes.py —— p = q
from math import isqrt
from sympy import nextprime
from Crypto.Util.number import bytes_to_long, long_to_bytes

e = 65537
p = nextprime(2**127 + 123456789)
n1 = p * p
c1 = pow(bytes_to_long(b"flag{p_eq_q}"), e, n1)
print("n =", n1)
print("isqrt(n)^2 == n:", isqrt(n1) ** 2 == n1)
p_rec = isqrt(n1)
print("p = q =", p_rec)
phi1 = p_rec * (p_rec - 1)              # n = p^2 的欧拉函数
d1 = pow(e, -1, phi1)
print("phi = p*(p-1) =", phi1)
print("解密:", long_to_bytes(pow(c1, d1, n1)))
```

输出：

```
n = 28948022309329048855892746252213987177288712213381677162094270279425690147801
isqrt(n)^2 == n: True
p = q = 170141183460469231731687303716007562651
phi = p*(p-1) = 28948022309329048855892746252213987177118571029921207930362582975709682585150
解密: b'flag{p_eq_q}'
```

两个细节：分解是 `isqrt` 一行（完全平方数的平方根就是因子）；==$\varphi(p^2) = p(p-1)$，不是 $(p-1)^2$==——$1..p^2$ 里与 $p^2$ 不互素的恰是 p 的倍数共 $p$ 个。

### 5.2 多素数 n：φ 按因子个数改

多素数 RSA（pycryptodome 的 `RSA.generate(bits, e, ...)` 支持指定素数个数）的解密公式：$n = \prod p_i$ 时

$$\varphi(n) = \prod_i (p_i - 1) \tag{5.1}$$

因子个数从 2 变成 3、4，公式形状不变，==漏乘任何一个 $(p_i - 1)$ 解密就是乱码==：

```python
# primes.py —— 三素数 n = p*q*r（接 5.1 的导入）
from sympy import factorint

ps = [nextprime(2**48 + 111111 * i) for i in range(1, 4)]
n2 = 1
for x in ps:
    n2 *= x
print("n =", n2, " （%d 位）" % len(str(n2)))
fac = factorint(n2)
print("factorint(n) =", {int(k): v for k, v in fac.items()})
r1, r2, r3 = fac.keys()
phi_ok = (r1 - 1) * (r2 - 1) * (r3 - 1)
phi_bad = (r1 - 1) * (r2 - 1)           # 漏掉第三个因子：常见写错
m2 = bytes_to_long(b"flag{m4ny_pr1m3s}")
c2 = pow(m2, e, n2)
d_ok = pow(e, -1, phi_ok)
d_bad = pow(e, -1, phi_bad)
print("phi(全因子) 解密:", long_to_bytes(pow(c2, d_ok, n2)))
print("phi(只算两个) 解密:", long_to_bytes(pow(c2, d_bad, n2)))
```

输出：

```
n = 22300745251358931978175302464956370579310557  （44 位）
factorint(n) = {281474976932939: 1, 281474976821809: 1, 281474977044007: 1}
phi(全因子) 解密: b'flag{m4ny_pr1m3s}'
phi(只算两个) 解密: b'O>\x8e\xbe0\x80\xdc\xa2\xc6e\xd8\xc2}\xc1\xc15P\x1d'
```

攻击侧没有新数学：分解（本例 44 位，`factorint` 秒级；更大的进第 6 节）之后按式 (5.1) 算 φ，标准解密。

> [!info]- λ(n)：另一本账
> 一些实现与题目给的不是 φ(n) 而是 Carmichael 函数 λ(n)：$n = pq$ 时 $\lambda(n) = \mathrm{lcm}(p-1, q-1)$，多素数时对全部 $(p_i-1)$ 取最小公倍数。$e \cdot d \equiv 1 \pmod{\lambda(n)}$ 与 $\pmod{\varphi(n)}$ 都给出能解密的 d（[[C02-数论进阶与原根#2.3 开方捷径：p ≡ 3 mod 4|C02 2.3]] 的推导在模 λ 下同样成立）。看到附件里的参数叫 `lambda`，不要再按 φ 代入。

### 5.3 共享素数：多条 n 两两 gcd

出题人批量生成密钥时复用了同一个素数——两条 $n_1 = p \cdot a$、$n_2 = p \cdot b$ 并排给出。==$\gcd(n_1, n_2) = p$ 是一行就完成的分解==，RSA 的安全前提（不知道因子）当场失效：

```python
# primes.py —— 共享素数（接 5.2 的导入）
from math import gcd

shared = nextprime(2**127 + 555555)
pa, pb = nextprime(2**127 + 111111), nextprime(2**127 + 222222)
pc, pd = nextprime(2**127 + 333333), nextprime(2**127 + 444444)
ns = [pa * shared, pb * shared, pc * pd]   # 前两条共用 shared，第三条独立
ms = [bytes_to_long(b"flag{sh4r3d_p_1}"), bytes_to_long(b"flag{sh4r3d_p_2}"), bytes_to_long(b"n0t_vuln3r4b13")]
cs = [pow(m, e, n) for m, n in zip(ms, ns)]
for i in range(len(ns)):
    print("n%d =" % (i + 1), ns[i])
print()
for i in range(len(ns)):
    for j in range(i + 1, len(ns)):
        g = gcd(ns[i], ns[j])
        print("gcd(n%d, n%d) = %s" % (i + 1, j + 1,
              "一条 %d bit 的公因子 <== 命中共享素数" % g.bit_length() if g != 1 else 1))

print()
g = gcd(ns[0], ns[1])
for idx in (0, 1):
    pi, qi = g, ns[idx] // g
    phi = (pi - 1) * (qi - 1)
    d = pow(e, -1, phi)
    print("n%d 分解为 %d x %d, 解密: %s" % (idx + 1, min(pi, qi), max(pi, qi),
          long_to_bytes(pow(cs[idx], d, ns[idx]))))
```

输出：

```
n1 = 28948022309329048855892746252172090405972415535033213502764272390062851461211
n2 = 28948022309329048855892746252172109328394275274579289774099442455891342713227
n3 = 28948022309329048855892746252172109300150838820141397306639350039079181801457

gcd(n1, n2) = 一条 128 bit 的公因子 <== 命中共享素数
gcd(n1, n3) = 1
gcd(n2, n3) = 1

n1 分解为 170141183460469231731687303715884216911 x 170141183460469231731687303715884661301, 解密: b'flag{sh4r3d_p_1}'
n2 分解为 170141183460469231731687303715884328127 x 170141183460469231731687303715884661301, 解密: b'flag{sh4r3d_p_2}'
```

三条 n 里前两条同时被分解，第三条安然无恙——==共享素数攻击一次打掉所有涉事的密钥，与素数本身多强无关==。

> [!info]- 大批量 n 的共享素数：batch GCD
> 几千条 n 两两 gcd 是 $O(k^2)$ 次大数运算，数量上来后改用 batch GCD：把全部 n 连乘成积 $z$，对每条 $n_i$ 算 $z \bmod n_i^2$，再与 $n_i$ 求 gcd——两次全量遍历代替两两比较。2012 年对全网 RSA 公钥的普查（"Mining your Ps and Qs"）用这批方法查出了大量因熵不足而共享素数的设备密钥。CTF 里十条八条 n 直接两两 gcd 就够。

### 5.4 后门素数与弱随机源素数

> [!info]- 后门素数：ROCA 事件
> 2017 年披露的 ROCA（Return of Coppersmith's Attack）：某厂商芯片库生成的素数满足 $p = k\cdot M + (65537^a \bmod M)$ 的受限结构（M 是前若干个素数之积），候选素数空间被压缩到极小，配合 Coppersmith 型方法可在可接受时间内分解 512～1024 比特的 n。检测思路：素数落在受限同余类里，等价于 $n \bmod M$ 落在一个可枚举的小集合——公开检测工具与 RsaCtfTool 的 `--attack roca` 都按这个判据工作。CTF 里遇到"素数来源可疑"的 n，factordb 之外可以补一次 roca 检测。

> [!info]- 弱随机源素数与"系统素数"
> 更常见的事故在随机源：出题人用 `random` 模块播种生成素数（种子空间小，可扫），或直接取用了某个固定列表里的素数。RsaCtfTool 的 `system_primes_gcd`、`pastctfprimes`、`rapid7primes` 等攻击维护着一份"历史事故素数"清单，本质都是拿 n 与已知素数表求公因子。种子可猜的素数生成器怎么攻，[[C04-随机数攻防|C04]] 整章展开。

## 6. 分解工具链实战

第 1–5 节的攻击都有明确特征；特征没有、n 又在可分解尺度时，剩下的是纯算力活。工具选用的固定顺序：==factordb（零成本）→ 特征攻击（第 2–5 节）→ yafu / gmp-ecm（真要分解）→ RsaCtfTool（兜底）==。[[C01-密码学导论与工具链#5. 外部工具流|C01 5 节]]讲过各工具的入口与安装，本节每个工具真实跑一条 50–60 位量级的任务。

### 6.1 factordb：先查有没有人分解过

查一条有历史 Record 的 n——RSA-129，1994 年被分解的挑战数（分解它的论文标题里有那句著名的明文 "The Magic Words are Squeamish Ossifrage"）：

```bash
curl -s --noproxy '*' 'http://factordb.com/api?query=114381625757888867669235779976146612010218296721242362562561842935706935245733897830597123563958705058989075147599290026879543541'
```

输出：

```
{"id":1100000000020360893,"status":"FF","factors":[["3490529510847650949147849619903898133417764638493387843990820577",1],["32769132993266709549961988190834461413177642967992942539798288533",1]]}
```

`status: FF` 表示完全分解，两个 64/65 位的素因子直接给出。命中后接回 [[09-密码学基础|09 章]]的标准解密就是完整解题（C01 5.1 讲过 `FactorDB` 类的用法，这里走全流程）：

```python
# solve_factordb.py —— factordb 命中后接回标准解密（09 章 6.2 的骨架）
from factordb.factordb import FactorDB
from Crypto.Util.number import bytes_to_long, long_to_bytes

N = 114381625757888867669235779976146612010218296721242362562561842935706935245733897830597123563958705058989075147599290026879543541   # RSA-129
e = 65537
c = pow(bytes_to_long(b"flag{db_h1t}"), e, N)     # 题面给的密文（此处自造）

f = FactorDB(N)
f.connect()
p, q = f.get_factor_list()
print("状态:", f.get_status())
assert p * q == N
d = pow(e, -1, (p - 1) * (q - 1))
print(long_to_bytes(pow(c, d, N)))
```

```bash
python3 solve_factordb.py
```

输出：

```
状态: FF
b'flag{db_h1t}'
```

### 6.2 yafu：本地分解

靶是两个 30 位素数的 60 位半素数。yafu 按规模自动调度：先跑 P−1、ECM 一族预测试打小因子，没打中再转 SIQS：

```bash
cd /opt/tools/yafu
echo 'factor(100000000000000000000222222249700000000000121932659507697159)' | ./yafu
```

输出（进度行省略）：

```
fac: job type determined to be siqs
pm1: starting B1 = 150K, B2 = gmp-ecm default on C60

starting SIQS on c60: 100000000000000000000222222249700000000000121932659507697159

SIQS elapsed time = 1.1304 seconds
Total factoring time = 2.4680 seconds

***factors found***
P30 = 100000000000000000000123456817
P31 = 1000000000000000000000987654327
```

60 位半素数 2.5 秒完成。与 [[C01-密码学导论与工具链#4.3 sympy 的边界|C01 4.3]] 的标定放在一起读：同量级任务 sympy 秒级到十秒级，yafu 一到几秒，且 n 越大差距越大。

### 6.3 gmp-ecm：专抓小因子

ECM（椭圆曲线分解）对"n 有一个相对小的素因子"这类结构效率最高。靶：12 位小因子 × 41 位大因子，B1 = 10000、跑 20 条曲线：

```bash
echo 1000000000190000000000000000000000000012100000002299 | ecm -c 20 1e4
```

输出：

```
GMP-ECM 7.0.6 [configured with GMP 6.3.0, --enable-asm-redc] [ECM]
Input number is 1000000000190000000000000000000000000012100000002299 (52 digits)
Using B1=10000, B2=1873422, polynomial x^1, sigma=1:743794203
Step 1 took 2ms
Step 2 took 5ms
********** Factor found in step 2: 100000000019
Found prime factor of 12 digits: 100000000019
Prime cofactor 10000000000000000000000000000000000000121 has 41 digits
```

毫秒级命中 12 位因子。ECM 的参数语义一句话：==B1 与曲线条数共同决定"大概率能抓到的因子位数"==，B1 固定后多跑曲线提高命中概率；想稳定抓更大的因子，按 gmp-ecm 手册的 B1–位数表上调 B1 与曲线数。

> [!warning] ecm 命中因子时以非零码退出
> gmp-ecm 找到因子时退出码非零（本例是 14），"什么都没找到"时反而退出 0。把 `ecm` 接进脚本时==不能拿退出码判成败==，要解析输出里的 `Factor found` 行。yafu 内部也调用 ECM 做 pretest，6.2 输出里的 `pm1`/`ecm` 进度行就是这一段。

### 6.4 sage 一句

sage 的 `factor` 一行完成分解（内部同样是一套自动调度），对 5.2 的三素数 n：

```bash
sage -c 'print(factor(22300745251358931978175302464956370579310557))'
```

输出：

```
163482437839541 * 253729398624041 * 281163529049489
```

日常分解用 yafu 已足够；sage 的位置在格与 Coppersmith 一类后续内容（[[C01-密码学导论与工具链#5.4 sage：重型数论|C01 5.4]]），届时它才是主战场。

### 6.5 RsaCtfTool：定向与全自动

定向攻击已在 3.4 演示（`--attack wiener`，0.2 秒）。不指定攻击名、把已知攻击全部排队的是 `--attack all`。靶换成 2.1 note 里"同源小偏移"形态的弱钥：`p = nextprime(2**255 + 314159265358979323846)`、`q = nextprime(2**255 + 271828182845904523536)`，相差 $2^{66}$、相对差距只有 $2^{-190}$，c 是对 `b"flag{a11_1n_0ne}"` 的标准加密（造靶与 2.2 同款）：

```bash
RsaCtfTool -n 3351951982485649274893506249551461531869841455148098344464816716377684563794722166467912273547362961238757416628268955518094246564539813122744180683613357 \
           -e 65537 \
           --decrypt 3062858158021526798199450919174625175058325737821187618621271580604978416349855673812024807030870197500935403022993306721659367321378900868953109360251652 \
           --attack all
```

输出（中间多行未命中攻击与素数表加载略）：

```
[*] Testing key /tmp/tmp9hda6swp.
[*] Performing dp_leak attack on /tmp/tmp9hda6swp.
[*] Performing factordb attack on /tmp/tmp9hda6swp.
[!] Composite not in factordb, couldn't factorize...
[*] Performing system_primes_gcd attack on /tmp/tmp9hda6swp.
[*] Performing SQUFOF attack on /tmp/tmp9hda6swp.
[*] Attack success with SQUFOF method !
[+] Total time elapsed min,max,avg: 0.0007/0.4943/0.0670 sec.

Results for /tmp/tmp9hda6swp:

Decrypted data :
utf-8 : flag{a11_1n_0ne}
STR : b'flag{a11_1n_0ne}'
```

读法三则。一，==攻击按"先便宜后贵"排队==：素数表比对、factordb 查询（唯一一次网络访问，0.49 秒）都在最前，重的分解攻击垫后；这条靶的 p、q 相对极近，第一批快速攻击里的 SQUFOF——平方差家族——就命中了。二，全自动有明确的边界：把 3.3 那种 p、q 无结构的靶交给 `--attack all`，快速批全数落空，接下来排队的是一堆对 510 比特 n 无望的重量级分解，==部分攻击连 `--timeout` 都拦不住，可能长时间不返回==——3.4 的定向 wiener 只要 0.2 秒，全模式却等不到 wiener 执行。所以==有特征先指定 `--attack`，`--attack all` 留给"完全没头绪、n 又不大"的场合==。三，攻击名清单在 `RsaCtfTool --help` 里，本章各节对应的名字：fermat、wiener、factordb、comfact_cn（共享素数）、cube_root（e=3）、roca、system_primes_gcd。

## 7. 防御：密钥生成怎么写才不出这些洞

本章每类攻击都对应一条生成侧的纪律，汇总成对照表：

| 事故 | 生成侧的纪律 |
| ---- | ---- |
| p、q 相近（Fermat） | p、q 各自独立采样；不用 nextprime 从一个素数派生另一个 |
| d 过小（Wiener） | d 从与 p、q 同量级的随机数生成（按 $ed \equiv 1 \bmod \varphi$ 反解 e），不人为选短 d |
| e 与 φ 不互素 | 生成时保留 `assert gcd(e, phi) == 1`，失败就重新采样，不是可选检查 |
| p = q | 生成后检查 `p != q`（完全平方检测一行的事） |
| 多素数 φ 算错 | 除非确有性能理由，不用多素数 RSA；用时 φ 严格按式 (5.1) 全因子相乘 |
| 共享素数 | 每条密钥独立采样；批量生成后两两 gcd 自查一遍 |
| 弱随机源素数 | 素数候选来自密码学安全随机源（`os.urandom` / `secrets`），[[C04-随机数攻防\|C04]] |

两条原则收拢：==素数生成全程用密码学安全随机数，任何两个参数之间不留代数关系==；==生成完自检==——`p != q`、`gcd(e, φ) == 1`、`p` 与 `q` 距离和比值随手一算，三行 assert 挡掉本章全部事故。强素数（p−1 有大素数因子）针对的是 p−1 光滑结构的分解算法（[[C02-数论进阶与原根#1.4 确定性底数与素数生成|C02 1.4]] 的伏笔），2048 比特的随机素数一般不强求，出题人造小尺寸靶时才需要考虑。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| 对 e=65537 的正常密钥跑 Wiener 没结果 | d 小则 e 必大；e 常规时 d 接近 φ 量级，不在 Wiener 适用范围内。e 小 d 大是正常密钥，不是攻击对象 |
| d 在 n^0.25 附近时 Wiener 时灵时不灵 | 定理只保证 d < n^0.25/3 必命中；边界外命中与否随密钥浮动（[[#3.3 完整攻击脚本与边界对照\|3.3]] 的 135 比特靶）。显著超出后换 Boneh–Durfee（约 n^0.292 内适用）或回读脚本找别的弱点 |
| Wiener 恢复的 d 和出题脚本的 d 不相等 | e·d ≡ 1 (mod φ) 的解是一整族，攻击可能命中族里较大的成员，解密照样成立（[[#3.3 完整攻击脚本与边界对照\|3.3]] 的 warning） |
| Fermat 跑满 max_iter 没命中 | 先按式 (2.3) 估轮数再看该不该跑；p、q 高位相近但比值非 1:1 的，普通费马永远追不上，用倍乘扫描（[[#2.4 变形：高位相近、比值非 1:1\|2.4]]） |
| 倍乘费马把 k 扫了一圈全不中 | k·n ≡ 2 (mod 4) 的 k 无整数解，属于死区（[[#2.4 变形：高位相近、比值非 1:1\|2.4]] 的 warning）；扫描配 `p * q == n` 验算，能命中的 k 会自然出现 |
| 多素数 n 解密出乱码 | φ 漏了因子：φ = 全部 (pᵢ−1) 的乘积（[[#5.2 多素数 n：φ 按因子个数改\|5.2]]）；另外确认拿到的不是 λ(n) |
| `pow(e, -1, phi)` 报 not invertible | gcd(e, φ) > 1 时 d 本就不存在——先确认是不是出题人故意的（[[#4. e 与 φ 不互素：d 不存在的时候\|第 4 节]] 走取根）；若本该互素，则 φ 算错了 |
| CRT 组合出的候选全是乱码 | 明文超过 n，恢复的只是 m mod n（[[#4.2 e = 2：从直接开方到分域取根\|4.2]] 的 warning）；先核对 m < n |
| `nthroot_mod(c, e, p)` 返回空 | c 不是模 p 的 e 次剩余。题目里 c = m^e 必是剩余，返回空说明 c 或模数抄错了 |
| factordb 查不到（状态 C） | 库里没有这条记录。回特征攻击或 yafu；状态 CF（部分分解）的记录也能直接拿已知因子用 |
| yafu 换目录跑就报错 | yafu 读同目录配置文件，cd 进安装目录再运行（[[C01-密码学导论与工具链#5.2 yafu：本地分解\|C01 5.2]]） |
| 脚本里调 ecm，退出码非零就当失败 | ecm 命中因子时退出码非零（[[#6.3 gmp-ecm：专抓小因子\|6.3]]）；解析输出里的 `Factor found` 行判成败 |
| RsaCtfTool `--attack all` 对大 n 跑不完 | 全量扫描会把重量级分解攻击排队，部分攻击连 `--timeout` 都拦不住、长时间不返回（[[#6.5 RsaCtfTool：定向与全自动\|6.5]]）；按特征指定 `--attack`，全量留给小 n |

## 9. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **自建弱钥靶场**：分别造三把钥匙——nextprime 连号靶（256 比特）、d = 64 比特的 Wiener 靶、五条 n 两两部分共享的共享素数靶——全部先用手写脚本解出，再用 RsaCtfTool 定向攻击对拍，两边结果必须一致。
> 2. **Wiener 边界测量**：固定 3.3 的 p、q，把 d 从 100 比特逐级加到 140 比特，每个尺寸造十把钥匙统计命中率，验证命中率的塌陷点在 126 比特附近。
> 3. **e=5 的分域取根**：造 p ≡ q ≡ 1 (mod 5) 的靶，`nthroot_mod(c, 5, p, all_roots=True)` 后 CRT 组合 25 个候选，筛出明文；体会候选数随 gcd(e, φ) 的增长。
> 4. **倍乘费马自动化**：把 2.4 的扫描写成对 p:q ≈ 3:5 的靶的完整解题脚本，从扫 k 到 gcd 剥离再到解密一条龙。

配套练习：

1. 给 1.1 的 `rsa_recon.py` 补两条检测：n 与 2^k ± 小常数的接近程度（检测"素数贴近 2 的幂"的生成习惯）、多条 n 的 batch GCD 版本（[[#5.3 共享素数：多条 n 两两 gcd\|5.3]] 折叠框）。
2. 把第 6 节的四个工具对同一个 55 位半素数各跑一遍并记录耗时，整理成 [[C01-密码学导论与工具链#4.3 sympy 的边界|C01 4.3]] 表格的续行。
3. 用 5.2 的多素数靶做反面教材：写一个"看起来对"的 φ 计算（漏一个因子），让它在 assert `p * q == n` 类检查之外静默出错，体会分段 assert 的位置为什么重要（[[C01-密码学导论与工具链#6.2 solve.py 的标准骨架|C01 6.2]]）。

延伸阅读：

- Boneh, *Twenty Years of Attacks on the RSA Cryptosystem*（NOTICES OF THE AMS, 1999）：Wiener、共模、Coppersmith 三大族的经典综述，本章 Wiener 一节的推导出处；
- gmp-ecm 手册（`man ecm`）的 B1–位数对应表：按目标因子位数选 B1 与曲线数；
- ROCA 事件的原始论文 *The Return of Coppersmith's Attack: Practical Factorization of Widely Used RSA Moduli*（CCS 2017）；
- [[02-书单与Wiki|书单与 Wiki]] 与 [[03-工具清单|工具清单]]：本章工具的安装与同类替代；
- RSA 攻击的第二卷在后续章节：低指数攻击的完整形态（Coppersmith）、泄露碎片的格方法与更多参数事故，都在本章的决策表上加行。
