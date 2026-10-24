---
chapter: 密码学
section: RSA 攻击 III
order: 709
tags:
  - CTF
  - 密码学
  - RSA
  - 侧信道
publish: true
---

# C09 RSA 攻击 III：私钥相关与 oracle
## RSA Attacks III: Private Key & Oracles

> [!info]- 章节信息
> **所属方向**：密码学 ｜ **难度阶段**：L2 核心漏洞期 ｜ **前置要求**：[[09-密码学基础|09 章]] · [[C07-RSA攻击I|C07]] · [[C08-RSA攻击II|C08]]
> **本章目标**：把 RSA 攻击从"看参数、看明文"推进到"看实现"：会打部分 d 已知（LSB 碎片 + 位提升 + Coppersmith 收尾）的完整利用链；理解 Boneh-Durfee 把 Wiener 边界从 $n^{0.25}$ 推到 $n^{0.292}$ 依靠什么，能在两个边界之间的地带选对攻击；会打 RSA-CRT 签名的单故障分解（Bellcore）；把 Bleichenbacher padding oracle 的四步算法在自建 HTTP 靶上完整执行一遍，并明白 Manger 的 OAEP 变体为什么把询问数压到百次级；最后知道实现侧的对应防御。

## 1. 本章的三类目标

[[09-密码学基础|09 章]]第 5 节、[[C07-RSA攻击I|C07]] 与 [[C08-RSA攻击II|C08]] 构成 RSA 攻击的前两卷：[[C07-RSA攻击I|C07]] 看公钥参数（分解、Wiener、素数事故），[[C08-RSA攻击II|C08]] 看明文与素数的已知碎片（Coppersmith 一族）。本章是第三卷，攻击对象换成三样东西：

| 攻击对象 | 你手里有什么 | 出处 |
| ---- | ---- | ---- |
| 私钥的碎片 | d 的低 t 位（侧信道、内存残页、题目直接给）；d 整体偏小但 Wiener 够不着 | 第 2、3 节 |
| 实现中的故障 | 一条"算错了"的 RSA-CRT 签名 | 第 4 节 |
| 解密服务的报错 | 服务端把"填充对不对"单独说出口 | 第 5、6 节 |

三类的共同点：==RSA 的数论一个字都没变，变的是实现多说了话==——多返回了一个错误码、多输出了一条算错的签名、多泄露了私钥的一角。dp 泄露（[[09-密码学基础#5.3 弱点套路清单|09 章 5.3]]）是"私钥碎片"的最小案例：dp 单独泄露就能分解 n，靠的是"在模 p 下成立、在模 q 下不成立的差值里 gcd 挖出 p"。本章反复回到这一招：第 2 节把碎片从 dp 换成 d 的任意低位段，第 3 节处理 d 整体偏小但 Wiener 够不着的中间带，第 4 节把"碎片"换成"故障"，第 5、6 节的 oracle 攻击则拿服务的报错差异当信息源。

> [!note] 本章靶场约定
> 第 5、6 节的 oracle 靶是本地 HTTP 服务，监听 `127.0.0.1:6901`（Bleichenbacher）与 `127.0.0.1:6902`（Manger）。密钥与填充全部确定性生成，所以询问数、区间轨迹每次一致。curl 一律带 `--noproxy '*'`。命令与输出成对给出，输出块标题写"输出："。

## 2. 部分 d 已知：从 dp 泄露到 Coppersmith

### 2.1 问题形态与方程锚点

d 的碎片从哪来：计时与缓存的侧信道能带出低位、密钥文件的残页能留下几段、CTF 题目干脆直接给 `d & ((1 << t) - 1)`。设已知 d 的低 t 位 $d_0 = d \bmod 2^t$。攻击的方程锚点还是那一条：

$$e \cdot d - 1 = k \cdot \varphi(n) = k\,(n + 1 - p - q) \tag{2.1}$$

$k = (ed-1)/\varphi(n)$ 是 $1 \le k \le e-1$ 之间的整数（$d < \varphi(n)$）。==e 越小，k 的候选越少==：e = 3 时 k 只有 1、2 两个取值。把 $q = n/p$ 代入式 (2.1) 并乘上 p，p 是唯一的未知数：

$$k \cdot p^2 + \big(e \cdot d - 1 - k(n+1)\big) \cdot p + k \cdot n = 0 \tag{2.2}$$

式 (2.2) 在整数上恒成立（代入 $ed-1 = k(n+1-p-q)$ 直接归零）。它是"关于 p 的二次方程"，但系数里藏着不知道的 d。==模 $2^t$ 之后 d 恰好被已知低位 $d_0$ 替换==：

$$k \cdot p^2 + \big(e \cdot d_0 - 1 - k(n+1)\big) \cdot p + k \cdot n \equiv 0 \pmod{2^t} \tag{2.3}$$

对每个候选 k，式 (2.3) 是模 $2^t$ 的二次同余式，p 模 $2^t$ 的值是它的根。解法是**位提升**（Hensel lifting）：先解 mod 2 的根（最多 2 个），再把每个根逐位提升——若 $r$ 满足 mod $2^j$，则 mod $2^{j+1}$ 的解只有 $r$ 与 $r + 2^j$ 两个候选，代回去筛。t 轮之后得到 p 模 $2^t$ 的全部候选 $p_0$。

最后一步接 [[C08-RSA攻击II|C08]] 第 4 节的素数碎片形态：$p = p_0 + 2^t \cdot y$，未知的高位 $y < 2^{n/2 - t}$，多项式 $f(y) = 2^t \cdot y + p_0$ 模 p 有根，交给 `small_roots`。按式 (4.2)（[[C08-RSA攻击II|C08]]），$\beta = 1/2$ 时可恢复的未知量至多 $N^{1/4}$：

$$2^{n/2 - t} \;<\; N^{1/4} \quad\Longleftrightarrow\quad t \;\ge\; n/4 \tag{2.4}$$

==已知低约四分之一的比特就够==，这是这一族攻击的边界（原论文 Boneh–Durfee–Frankel 针对 e = 3 给出）。靶子里取 $t = n/3$，给 sage 的默认参数留余量。

> [!note] 与 dp 泄露的分工
> [[09-密码学基础#5.3 弱点套路清单|09 章 5.3]] 的 dp 泄露走的是"指数碎片"：$c^{dp}$ 与 m 在模 p 下同余，一次 gcd 完成。本节的碎片是"d 的低位"，得多走两步（位提升 + Coppersmith），但换来的好处是碎片形态自由——dp 泄露要求拿到的恰是 $d \bmod (p-1)$，本节只要 d 的任意低 t 位。

### 2.2 手工利用：位提升与 small_roots 收尾

确定性靶：p、q 各 256 位、e = 3、泄露 d 的低 170 位（$n/3$）：

```python
# t1_pd_gen.py —— 部分 d 已知（LSB）靶：e=3 的 512 位 RSA，泄露 d 的低 1/3 比特
# 另造一把 partial 私钥 PEM（d 字段换成已知低位 d0），给 RsaCtfTool --attack partial_d 用
from sympy import nextprime
from Crypto.Util.number import bytes_to_long, long_to_bytes
from math import gcd
import base64

# ---------- 确定性靶：p、q 各 256 位，e = 3 ----------
s = 2**255
while True:
    s = nextprime(s)
    if s % 3 != 1:                      # gcd(3, phi)=1 要求 p、q 都不 ≡ 1 (mod 3)
        p = s
        break
s = 10**77 + 98765432109876543210987654321
while True:
    s = nextprime(s)
    if s % 3 != 1:
        q = s
        break
n = p * q
phi = (p - 1) * (q - 1)
assert gcd(3, phi) == 1
e = 3
d = pow(e, -1, phi)

t = n.bit_length() // 3               # 已知低 t 位（理论下限约 n/4，靶里多留余量）
B = 1 << t
d0 = d & (B - 1)                      # d 的低 t 位

m = bytes_to_long(b"flag{p4rt14l_d}")
c = pow(m, e, n)

open("pd_n.txt", "w").write(str(n))
open("pd_e.txt", "w").write(str(e))
open("pd_c.txt", "w").write(str(c))
open("pd_d0.txt", "w").write(str(d0))
open("pd_t.txt", "w").write(str(t))

print("p =", p)
print("q =", q)
print("n =", n, "(%d bit)" % n.bit_length())
print("e =", e)
print("d 的低 %d 位 = n 的 %.4f，理论下限约 1/4" % (t, t / n.bit_length()))
print("d0 =", d0)
print("c =", c)
print("自检: 解密 =", long_to_bytes(pow(c, d, n)))

# ---------- partial 私钥 PEM：9 个 INTEGER，d 字段换成已知低位 d0 ----------
dp, dq = d % (p - 1), d % (q - 1)
qi = pow(q, -1, p)

def enc_len(v):
    if v < 128:
        return bytes([v])
    b = v.to_bytes((v.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def enc_int(v):
    b = v.to_bytes(max((v.bit_length() + 7) // 8, 1), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + enc_len(len(b)) + b

fields = [0, n, e, d0, p, q, dp, dq, qi]      # 真实 d 字段位置上放 d0
body = b"".join(enc_int(v) for v in fields)
der = b"\x30" + enc_len(len(body)) + body
b64 = base64.b64encode(der).decode()
pem = "-----BEGIN RSA PRIVATE KEY-----\n" + \
      "\n".join(b64[i:i+64] for i in range(0, len(b64), 64)) + \
      "\n-----END RSA PRIVATE KEY-----\n"
open("pd_partial.pem", "w").write(pem)
print("partial PEM 已写出（d 字段 = d0，共 %d 位已知）" % t)
```

```bash
python3 t1_pd_gen.py
```

输出：

```
p = 57896044618658097711785492504343953926634992332820282019728792003956564820109
q = 100000000000000000000000000000000000000000000000098765432109876543210987654943
n = 5789604461865809771178549250434395392663499233287746329837093659924746443429517459499788902821417446592063298393148309573465342822449998992211770559648787 (511 bit)
e = 3
d 的低 170 位 = n 的 0.3327，理论下限约 1/4
d0 = 1027836154788353540700474017939595128561315170758043
c = 150409620528255041001996603550338254636140977145783698342505832053743693386899953664470862719595235107232101
自检: 解密 = b'flag{p4rt14l_d}'
partial PEM 已写出（d 字段 = d0，共 170 位已知）
```

攻击脚本两段式：`hensel` 解式 (2.3) 的二次同余，`partial_d_lsb` 对每个 (k, p₀) 组合做 Coppersmith：

```python
# t1_pd_attack.sage —— 部分 d 已知（LSB）手工攻击
# 方程链：e·d - 1 = k·phi = k·(n + 1 - p - q)，pq = n
#   => k·p^2 + (e·d - 1 - k(n+1))·p + k·n = 0（整数上恒成立）
#   mod 2^t（d 换成已知低位 d0）：k·p^2 + (e·d0 - 1 - k(n+1))·p + k·n ≡ 0 (mod 2^t)
# 位提升解出 p mod 2^t 的候选 p0；再对 f(y) = 2^t·y + p0 用 Coppersmith（模 p，beta≈1/2）
# 找回 p 的未知高位，gcd 验证后分解 n。

def hensel(a, b, c, bits, cap=64):
    """解 a·x^2 + b·x + c ≡ 0 (mod 2^bits)：从 mod 2 逐位提升到 mod 2^bits"""
    roots = [r for r in (0, 1) if (a*r*r + b*r + c) % 2 == 0]
    for j in range(1, bits):
        m2 = 1 << (j + 1)
        nxt = []
        for r in roots:
            for delta in (0, 1 << j):
                cand = r + delta
                if (a*cand*cand + b*cand + c) % m2 == 0:
                    nxt.append(cand)
                    if len(nxt) > cap:
                        raise RuntimeError("根数超过上限：同余式在 2 的幂上退化")
        roots = nxt
        if not roots:
            return []
    return roots


def partial_d_lsb(n, e, d0, t):
    B = 1 << t
    nbits = n.bit_length()
    R.<y> = PolynomialRing(Zmod(n))
    for k in range(1, e):                    # k = (e·d-1)/phi < e；e=3 时只有 1、2
        a, b, c = k, e*d0 - k*(n + 1) - 1, k*n
        roots = hensel(a, b, c, t)
        print("k = %d: mod 2^%d 的二次同余有 %d 个根" % (k, t, len(roots)))
        for p0 in roots:
            f = (B*y + p0).monic()           # 乘 2^t 的逆元化首一
            X = 2^(nbits//2 - t)             # p 的未知高位至多 n/2 - t 位
            rs = f.small_roots(X=X, beta=0.49)
            for r in rs:
                g = gcd(B*int(r) + p0, n)
                if 1 < g < n:
                    return g, n // g, k
    return None


n  = Integer(open('pd_n.txt').read().strip())
e  = Integer(open('pd_e.txt').read().strip())
c  = Integer(open('pd_c.txt').read().strip())
d0 = Integer(open('pd_d0.txt').read().strip())
t  = Integer(open('pd_t.txt').read().strip())
print("n %d bit, e = %d, 已知 d 低 %d 位" % (n.nbits(), e, t))

res = partial_d_lsb(n, e, d0, t)
if res:
    p, q, k = res
    print("命中 k = %d" % k)
    print("恢复 p =", p)
    print("恢复 q =", q)
    print("p*q == n :", p*q == n)
    phi = (p - 1)*(q - 1)
    d = inverse_mod(e, phi)
    from Crypto.Util.number import long_to_bytes
    print("解密:", long_to_bytes(int(power_mod(c, d, n))))
else:
    print("失败")
```

```bash
sage t1_pd_attack.sage
```

输出：

```
n 511 bit, e = 3, 已知 d 低 170 位
k = 1: mod 2^170 的二次同余有 4 个根
k = 2: mod 2^170 的二次同余有 8 个根
命中 k = 2
恢复 p = 57896044618658097711785492504343953926634992332820282019728792003956564820109
恢复 q = 100000000000000000000000000000000000000000000000098765432109876543210987654943
p*q == n : True
解密: b'flag{p4rt14l_d}'
```

170 比特的碎片换回完整的分解，总共 12 个候选 $p_0$、每个一次 `small_roots`。输出里的根数值得看一眼：==模 $2^t$ 的二次同余根数不固定==——k = 1 的同余式有 4 个根，k = 2 的同余式因二次项系数为偶数而退化，根翻到 8 个。写脚本时不能假设"每 k 两个根"，根数上限要设防（`cap`），退化的候选过不了 `small_roots` 就让它自然落空。

### 2.3 e 大的时候与高半已知的时候

e = 65537 时式 (2.1) 的 k 要扫过 65536 个候选。每个 k 的第一道检查很便宜（二次同余在 mod 8 上无根即可丢弃），过滤后剩余的候选再进 Coppersmith——仍然是多项式级的工作量，但常数已经不小。==现成工具普遍给 k 设上限==：RsaCtfTool 的 `partial_d` 把 k 截到 1000，只有真 k 恰好小于上限时命中。CTF 里这类题基本配小 e，看到 `e=3` 加 `d>>?<<?` 形态的碎片就往本节走。

> [!info]- 高半已知（MSB 型）为什么难
> 已知 $d$ 的**高**半段（$d = d_{hi} \cdot 2^s + x$，x 是未知低位）时，式 (2.1) 在模 $2^s$ 下不再"只剩 p"——未知低位 x 与 k、$p+q$ 同场出现，式 (2.2) 的消元套路失效，单变量 Coppersmith 化不动。经典结论（Boneh–Durfee–Frankel 的 MSB 情形）是需要更多的已知比特（约一半），且解法走向多元格。CTF 里 MSB 型题目远少于 LSB 型；遇到高半碎片，先回头读脚本找别的信息源（明文格式、dp、nonce），再考虑多元格工具。

### 2.4 RsaCtfTool 对照

RsaCtfTool 的 `partial_d` 攻击与 2.2 的手工链同构（k 循环 + 位提升 + Coppersmith），入口是"部分私钥 PEM"：标准 RSA 私钥 DER 的 9 个 INTEGER 字段，==d 字段的位置上放已知低位 $d_0$==，再用 `--d-known-bits` 显式声明位数（否则按 $d_0$ 自身的位长算，$d_0$ 带前导零时会算少）。2.2 的生成脚本已把 `pd_partial.pem` 备好：

```bash
RsaCtfTool --partial --key pd_partial.pem --attack partial_d --d-known-bits 170 \
           --decrypt 150409620528255041001996603550338254636140977145783698342505832053743693386899953664470862719595235107232101
```

输出：

```
private argument is not set, the private key will not be displayed, even if recovered.
[*] Performing partial_d attack on pd_partial.pem.
[*] Attack success with partial_d method !

Decrypted data :
HEX : 0x666c61677b7034727431346c5f647d
utf-8 : flag{p4rt14l_d}
STR : b'flag{p4rt14l_d}'
```

与手工版解出同一明文。

## 3. Boneh-Durfee：Wiener 抓不住的小 d

### 3.1 问题形态：从 Wiener 的方程到二元多项式

[[C07-RSA攻击I|C07]] 第 3 节的 Wiener 攻击在 $d < \frac{1}{3}n^{1/4}$ 时必中。这条线之上还有一段地带：$d$ 在 $n^{0.25}$ 到 $n^{0.292}$ 之间时，Wiener 的收敛子扫完也不会命中，而 1998 年起==Boneh–Durfee 的格方法把适用边界推到 $d < n^{0.292}$==。1024 位模数上，这两个边界分别是 254 比特与 299 比特——45 比特的中间带，就是本节的战场。

起点还是式 (2.1)。对 e 取模（$ed \equiv 0$）：

$$k\,(n + 1 - (p+q)) + 1 \equiv 0 \pmod e \tag{3.1}$$

把它写成模 e 的二元多项式：

$$f(x, y) = x \cdot (n + 1 + y) + 1, \qquad f(x_0, y_0) \equiv 0 \pmod e \tag{3.2}$$

小根是 $(x_0, y_0) = (k,\; -(p+q))$，界的量级 $|x_0| < n^{\delta}$（$\delta = \log_n d$）、$|y_0| < 3\sqrt{n}$。==Wiener 的连分数本质上就是这个方程的一维解法==；Boneh–Durfee 把它放回 [[C08-RSA攻击II|C08]] 的格框架，用二元 Coppersmith 求这两个小根，从 $(x_0, y_0)$ 直接恢复 $\varphi'(n) = n + 1 + y_0$，进而 $d = (1 + x_0\,\varphi')/e$。

### 3.2 多元格的直观：单变量那套照搬为什么不行

[[C08-RSA攻击II|C08]] 第 3 节的单变量三件套——$e^{m-u} f^u x^v$ 式的基、Howgrave-Graham 引理、LLL——在二元情形的对应物是：基取 $e^{m-u} f^u x^v$（x-shifts）与 $y^j f^u e^{m-u}$（y-shifts），短向量还原成整系数二元多项式，两个多项式取**结式**（resultant）消掉 y 得一元方程求根。引理本身一个字不用改。

但把 x-shifts 铺满的格直接装上靶，Howgrave-Graham 的行列式条件不成立。原因可以算出来：y 的界（约 $\sqrt{n}$）远大于 x 的界（$n^{0.29}$），y 方向的 $Y^u$ 因子把行列式推得过大——m 加得越大，缺口拉得越开。把这笔账写成脚本（对基本格逐档 m 算 $2^{(\dim-1)/4}\det^{1/\dim}$ 与 $e^m/\sqrt{\dim}$ 的对比）：

```python
# t2_bd_bound.sage —— 基本格（x-shifts）的 Howgrave-Graham 条件数值表
# 条件：2^((dim-1)/4) · det^(1/dim) < e^m / sqrt(dim)
nbits = 1023
E = 1023        # |e| 的比特数
Xb = 264        # log2 X
Yb = 514        # log2 Y

for m in range(3, 13):
    dim = (m + 1) * (m + 2) // 2
    log_det = 0
    for u in range(m + 1):
        for v in range(m - u + 1):
            log_det += (m - u) * E + (v + u) * Xb + u * Yb
    lhs = (dim - 1) / 4 + log_det / dim
    rhs = m * E - 0.5 * log(dim, 2)
    print("m = %2d  dim = %3d  2^(%.1f) vs e^m/√dim = 2^(%.1f)  条件%s"
          % (m, dim, lhs, rhs, "成立" if lhs < rhs else "不成立"))
```

```bash
sage t2_bd_bound.sage
```

输出：

```
m =  3  dim =  10  2^(3090.2) vs e^m/√dim = 2^(3067.3)  条件不成立
m =  4  dim =  15  2^(4120.8) vs e^m/√dim = 2^(4090.0)  条件不成立
m =  5  dim =  21  2^(5151.7) vs e^m/√dim = 2^(5112.8)  条件不成立
m =  6  dim =  28  2^(6182.8) vs e^m/√dim = 2^(6135.6)  条件不成立
m =  7  dim =  36  2^(7214.1) vs e^m/√dim = 2^(7158.4)  条件不成立
m =  8  dim =  45  2^(8245.7) vs e^m/√dim = 2^(8181.3)  条件不成立
m =  9  dim =  55  2^(9277.5) vs e^m/√dim = 2^(9204.1)  条件不成立
m = 10  dim =  66  2^(10309.6) vs e^m/√dim = 2^(10227.0)  条件不成立
m = 11  dim =  78  2^(11341.9) vs e^m/√dim = 2^(11249.9)  条件不成立
m = 12  dim =  91  2^(12374.5) vs e^m/√dim = 2^(12272.7)  条件不成立
```

每加一档 m，缺口扩大约 100 比特——==铺满的格永远到不了条件成立的那天==。Boneh–Durfee 的推进不靠"更大的格"，靠两处**结构性**改造：

1. **只留"有用"的行**。对角线项 $\ge e^m$ 的行只会抬高行列式、破坏 Howgrave-Graham 条件，把这类行连同对应单项式删掉，格变小、行列式变小，条件反而成立。删完剩下的形状是论文里那张 **L 形子格**，它把边界从 0.25 推到 0.284；
2. **y-shifts 的挑选与代入**（Herrmann–May 的优化）。y-shifts 不是每个 $y^j f^u e^{m-u}$ 都收，只在 $u \ge \lfloor m/t \rfloor \cdot j$ 时收；配合 $u = xy + 1$ 的代入把双线性单项式折回线性界。这一步把边界推到 0.292。

> [!info]- 公开实现的结构清单
> Boneh–Durfee 不必从零手推，公开实现就是上面两条改造的直译。RsaCtfTool 附带的 `boneh_durfee.sage`（源自 mimoo 的 RSA-and-LLL-attacks）的结构，读源码时按这份清单对号：
>
> 1. **配置**：`delta`（目标的 $d/N$ 估计）、`m`（shift 重数）、`t`（y-shifts 条数）；`strict` 开关决定 det 条件不满足时是严格放弃还是照跑；
> 2. **代入**：`QuotientRing` 里做 $u = xy + 1$ 替换，多项式变回 $x, u, y$ 三元的线性组合形态；
> 3. **x-shifts**：$x^i \cdot e^{m-k} \cdot f^k$，$k = 0..m$、$i = 0..m-k$；
> 4. **y-shifts**：$y^j \cdot f^k \cdot e^{m-k}$，只收 $k \ge \lfloor m/t \rfloor \cdot j$ 的那些；
> 5. **删行**：`remove_unhelpful` 从最后一行起递归——对角线 $\ge e^m$ 且只影响一个别人的行，或"两条一起删更划算"的行对，删行同时删对应单项式；
> 6. **LLL + det 检查**，然后从短向量恢复多项式对，结式消元出候选 $x_0 = 2k$；
> 7. **验证**：每个候选 d 用 RSA.construct 重建密钥、验一致性，通过者返回。
>
> 打靶时只需要调 m 与 t：靶越贴近 0.292，需要的 (m, t) 越大、LLL 越慢。==格维度在几十的量级，秒级到分钟级出结果==，这与单变量 Coppersmith 的成本结构一致（[[C08-RSA攻击II|C08]] 第 3.3 节的 m 表是同一笔账）。

### 3.3 自建靶实战：边界带上的对照

造两个靶把边界演示出来：A 的 d 取 250 比特（$d/N \approx 0.244$，Wiener 界内），B 的 d 取 260 比特（$d/N \approx 0.254$，Wiener 界外、BD 界内）。==B 靶就是本章的教学点==：Wiener 对它无能为力，能解它的只有 Boneh-Durfee。

```python
# t2_bd_gen.py —— 两个小 d 靶：A 压在 Wiener 边界内，B 卡在 Wiener 之外、Boneh-Durfee 之内
# 1024 位 n：Wiener 上限 d < n^0.25/3 ≈ 254 比特，BD 上限 d < n^0.292 ≈ 299 比特
from sympy import nextprime
from Crypto.Util.number import bytes_to_long, long_to_bytes

def make_target(dbits, msg):
    p = nextprime(2**511 + 12345678901234567890)
    q = nextprime(10**154 + 98765432109876543210987654321)
    n = p * q
    phi = (p - 1) * (q - 1)
    while True:
        d = nextprime(2**(dbits - 1) + 20260924)
        try:
            e = pow(d, -1, phi)          # d 与 phi 不互素时换下一个 d
            break
        except ValueError:
            d = nextprime(d)
    m = bytes_to_long(msg)
    c = pow(m, e, n)
    return p, q, n, phi, e, d, m, c

for tag, dbits, msg in [("A", 250, b"flag{w13n3r_w1ns}"),
                        ("B", 260, b"flag{b0neh_durf33}")]:
    p, q, n, phi, e, d, m, c = make_target(dbits, msg)
    ratio = d.bit_length() / n.bit_length()
    print("靶%s: n %d bit, d %d bit, d/n ≈ %.4f" % (tag, n.bit_length(), d.bit_length(), ratio))
    print("  e 的比特数 = %d（e 长是 d 小的影子）" % e.bit_length())
    open(f"bd{tag}_n.txt", "w").write(str(n))
    open(f"bd{tag}_e.txt", "w").write(str(e))
    open(f"bd{tag}_c.txt", "w").write(str(c))
    open(f"bd{tag}_d.txt", "w").write(str(d))
print()
print("边界参考: n^0.25 = %.1f bit, Wiener 上限 n^0.25/3 = %.1f bit, BD 上限 n^0.292 = %.1f bit"
      % (0.25 * 1024, (0.25 * 1024) - 1.585, 0.292 * 1024))
```

```bash
python3 t2_bd_gen.py
```

输出：

```
靶A: n 1023 bit, d 250 bit, d/n ≈ 0.2444
  e 的比特数 = 1023（e 长是 d 小的影子）
靶B: n 1023 bit, d 260 bit, d/n ≈ 0.2542
  e 的比特数 = 1023（e 长是 d 小的影子）

边界参考: n^0.25 = 256.0 bit, Wiener 上限 n^0.25/3 = 254.4 bit, BD 上限 n^0.292 = 299.0 bit
```

先用 [[C07-RSA攻击I|C07]] 第 3 节的 Wiener 攻击（连分数收敛子逐个验证，函数原样搬来）过一遍两个靶：

```python
# t2_wiener_check.py —— C07 第 3 节的 Wiener 打两个新靶：A 命中，B 落空
from math import isqrt
from Crypto.Util.number import long_to_bytes


def cont_frac(x, y):
    while y:
        a = x // y
        yield a
        x, y = y, x - a * y


def convergents(seq):
    res = []
    h0, h1, k0, k1 = 0, 1, 1, 0
    for a in seq:
        h0, h1 = h1, a * h1 + h0
        k0, k1 = k1, a * k1 + k0
        res.append((h1, k1))
    return res


def wiener(e, n):
    for k, d in convergents(cont_frac(e, n)):
        if k == 0 or (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = isqrt(disc)
        if r * r == disc and (s + r) % 2 == 0:
            return d
    return None


for tag in ("A", "B"):
    n = int(open(f"bd{tag}_n.txt").read())
    e = int(open(f"bd{tag}_e.txt").read())
    c = int(open(f"bd{tag}_c.txt").read())
    d_true = int(open(f"bd{tag}_d.txt").read())
    bound = isqrt(isqrt(n)) // 3
    print("靶%s: d %d bit, Wiener 边界 n^0.25/3 = %d bit, 边界内: %s"
          % (tag, d_true.bit_length(), bound.bit_length(), d_true < bound))
    d_rec = wiener(e, n)
    if d_rec is not None:
        print("  Wiener 命中，解密:", long_to_bytes(pow(c, d_rec, n)))
    else:
        print("  扫完全部收敛子未命中 —— 超出 Wiener 边界，换 Boneh-Durfee")
    print()
```

```bash
python3 t2_wiener_check.py
```

输出：

```
靶A: d 250 bit, Wiener 边界 n^0.25/3 = 255 bit, 边界内: True
  Wiener 命中，解密: b'flag{w13n3r_w1ns}'

靶B: d 260 bit, Wiener 边界 n^0.25/3 = 255 bit, 边界内: False
  扫完全部收敛子未命中 —— 超出 Wiener 边界，换 Boneh-Durfee
```

Wiener 在 B 靶上把全部收敛子扫完落空。接下来交给 RsaCtfTool 的 `boneh_durfee`（内部就是 3.2 折叠框的那套实现）：

```bash
# t2_bd_gen.py 已把靶 B 的参数落盘 bdB_n/e/c.txt
N=$(cat bdB_n.txt); E=$(cat bdB_e.txt); C=$(cat bdB_c.txt)
time RsaCtfTool -n "$N" -e "$E" --decrypt "$C" --attack boneh_durfee
```

输出：

```
private argument is not set, the private key will not be displayed, even if recovered.

[*] Testing key /tmp/tmpyivsy8k9.
[*] Performing boneh_durfee attack on /tmp/tmpyivsy8k9.
[*] Attack success with boneh_durfee method !

Results for /tmp/tmpyivsy8k9:

Decrypted data :
HEX : 0x666c61677b62306e65685f6475726633337d
INT (big endian) : 8922333133091689807853348914090684265476989
INT (little endian) : 10906458464746558747398947276115691163446374
utf-8 : flag{b0neh_durf33}
utf-16 : 汦条扻渰桥摟牵㍦紳
STR : b'flag{b0neh_durf33}'

real	0m1.158s
user	0m4.147s
sys	0m0.203s
```

全程约 1.2 秒（其中大半是 sage 启动）。两个靶合起来就是完整的分流依据：==e 与 n 同量级时先算 $d$ 的估计边界，$d/N < 0.25$ 交给 Wiener，$0.25 \le d/N < 0.292$ 交给 Boneh-Durfee，再往上这条路就断了==。

> [!warning] 小 d 靶不要造在 Wiener 界内
> 想演示 Boneh-Durfee 的靶，d 必须先过 Wiener 这一关：$d/N$ 压在 0.25 以下时 Wiener 先命中，BD 的演示失去对照意义。造靶先算 $d$ 的比特数落在 1024 位模数的 255 到 299 之间（512 位模数则是 128 到 149 之间），再动手。

## 4. Bellcore：签名错一位，模数当场分解

### 4.1 CRT 签名与故障模型

工程实现里的 RSA 签名不走 $s = m^d \bmod n$——先把 d 拆成两半：

$$s_p = m^{d_p} \bmod p, \qquad s_q = m^{d_q} \bmod q, \qquad d_p = d \bmod (p-1),\; d_q = d \bmod (q-1) \tag{4.1}$$

再用 [[09-密码学基础#2.4 中国剩余定理|09 章 2.4]] 的中国剩余定理合成：

$$s = \big(s_p \cdot q \cdot q^{-1}_p + s_q \cdot p \cdot p^{-1}_q\big) \bmod n \tag{4.2}$$

两次 256 位模幂比一次 511 位模幂便宜数倍（模幂的代价随位数三次方涨），==所有性能敏感的 RSA 实现都这么算==。

**故障模型**：计算过程中某一侧发生位翻转——电压毛刺、激光注入、时钟毛刺都可能造成，CTF 题里则由靶子直接模拟。设故障落在 q 侧：$s_q$ 算错成 $s_q'$，其余流程原样，输出 $s'$。关键性质是==模 p 那一路完全没被污染==：式 (4.2) 的第一项在模 p 下就是 $s_p$（$q \cdot q^{-1}_p \equiv 1 \pmod p$），第二项带因子 p 在模 p 下是 0，所以无论 $s_q'$ 错成什么，

$$s' \equiv s_p \equiv s \pmod p \qquad\Longrightarrow\qquad (s')^e \equiv m \pmod p \tag{4.3}$$

而模 q 那一路，$(s')^e \equiv (s_q')^e \ne m$ 一般成立。==同一个差值，模 p 成立、模 q 不成立==——[[09-密码学基础#5.3 弱点套路清单|09 章 5.3]] 的 dp 泄露在这一刻重现：gcd 挖出 p。

$$\gcd\big((s')^e \bmod n - m,\; n\big) = p \tag{4.4}$$

一次故障、一次 gcd，n 当场分解。这条攻击 1996 年由 Bellcore 的研究人员提出（Boneh–DeMillo–Lipton 论文与 Lenstra 的备忘录），针对的正是当时用 CRT 签名的智能卡。

### 4.2 自建靶：一次故障的完整利用链

```python
# t3_bellcore.py —— RSA-CRT 签名故障攻击：q 侧翻转一位，一次故障分解 n
from sympy import nextprime
from Crypto.Util.number import bytes_to_long, long_to_bytes
from math import gcd

msg = b"fault@rsa-crt"
m = bytes_to_long(msg)

p = nextprime(2**255 + 12345678901234567890)
q = nextprime(10**77 + 98765432109876543210987654321)
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
dp, dq = d % (p - 1), d % (q - 1)            # CRT 签名的两半

# ---- 正常签名：两半分别算，CRT 合成 ----
sp = pow(m, dp, p)
sq = pow(m, dq, q)
qinv_p = pow(q, -1, p)
pinv_q = pow(p, -1, q)
s = (sp * q * qinv_p + sq * p * pinv_q) % n
print("n 的比特数 =", n.bit_length())
print("正常签名 s =", hex(s))
print("验签 pow(s, e, n) == m :", pow(s, e, n) == m)

# ---- 注入故障：q 侧的中间结果翻转一个位，其余流程不变 ----
sq_fault = sq ^ (1 << 100)                   # 翻转 sq 的第 100 位
s_bad = (sp * q * qinv_p + sq_fault * p * pinv_q) % n
print("故障签名 s'=", hex(s_bad))
print("验签 pow(s', e, n) == m :", pow(s_bad, e, n) == m)

# ---- 一次故障分解：s' 的 p 侧没有坏，s'^e ≡ m (mod p)；q 侧不成立 ----
f = gcd(pow(s_bad, e, n) - m, n)
print("gcd(pow(s',e,n) - m, n) =", f)
print("分解成功，等于 p :", f == p)
q_rec = n // f
print("q =", q_rec, "  n//f == q :", q_rec == q)
phi2 = (f - 1) * (q_rec - 1)
print("拿分解重算 d 解密自检:", long_to_bytes(pow(pow(m, e, n), pow(e, -1, phi2), n)))

# ---- 防御对照：签名后先验签再输出 ----
print("先验签再输出能拦住故障签名 :", pow(s_bad, e, n) != m)

# ---- RsaCtfTool 对照用的参数落盘 ----
open("bc_n.txt", "w").write(str(n))
open("bc_e.txt", "w").write(str(e))
open("bc_msg.txt", "w").write(str(m))
open("bc_sbad.txt", "w").write(str(s_bad))
```

```bash
python3 t3_bellcore.py
```

输出：

```
n 的比特数 = 511
正常签名 s = 0x4f250ecdbe650191488ed367a4d8459393b12dea1ec6b60b26d6a7bb33f9b08388be155b7b984840b14c026504c63599fce575af69ac192f1e326b2e24e88a65
验签 pow(s, e, n) == m : True
故障签名 s'= 0x328b4ea4d84950fed95543b2293190a1cc233c6940bf892d6f41eccd655a28bcbbfffb6dfcfef5df15ab5cea2dc8e8b99937756bb8edb7b92bfcd9c71a032140
验签 pow(s', e, n) == m : False
gcd(pow(s',e,n) - m, n) = 57896044618658097711785492504343953926634992332820282019741137682857799388037
分解成功，等于 p : True
q = 100000000000000000000000000000000000000000000000098765432109876543210987654753   n//f == q : True
拿分解重算 d 解密自检: b'fault@rsa-crt'
先验签再输出能拦住故障签名 : True
```

链路三步：故障签名验签不过（防御方据此识别异常）、gcd 一次挖出 p、拿分解重算 d 解密闭环。==故障位的位置无关紧要==：只要错在 q 侧的半程结果上，式 (4.3) 都成立，翻第 5 位和翻第 200 位效果一样。

> [!warning] 故障必须落在"半程结果"上
> 翻转的位置决定攻击成败：翻在 $s_q$（模 q 的半程结果）或 $d_q$ 的中间值上，攻击成立；翻在 CRT 合成**之后**的 s 上，两侧同错，$(s')^e - m$ 与 p、q 都不互素得恰到好处，gcd 通常挖出 n 本身或 1；两侧各翻一位则可能两边都"坏"，攻击同样落空。写故障靶时把翻转点放在单侧半程输出上，模拟的才是真实注障场景。

### 4.3 工具对照与防御

同一个靶喂给 RsaCtfTool（`--attack bellcore` 收故障签名与原始消息，一行 gcd 完成分解）：

```bash
# t3_bellcore.py 已把 n、e、消息与故障签名落盘 bc_n/e/msg/sbad.txt
N=$(cat bc_n.txt); E=$(cat bc_e.txt); M=$(cat bc_msg.txt); SB=$(cat bc_sbad.txt)
RsaCtfTool -n "$N" -e "$E" --attack bellcore --fault-sig "$SB" --fault-msg "$M"
```

输出：

```
[*] Testing key /tmp/tmplqnii2f5.
[*] Performing bellcore attack on /tmp/tmplqnii2f5.
[+] bellcore attack found factorization
[*] Attack success with bellcore method !
```

防御从输出端入手：==签名输出前先验签==（一次 $s^e \bmod n$ 的代价，换掉整类故障攻击，4.2 输出的最后一行就是这道检查）；更重的场合用双路计算（同一半程算两遍比对）。另一个相关手段是**盲化**（blinding）：签名前把消息乘上随机数 $r^e$、签完除掉——它本是计时侧信道的对策，顺带让中间值不可预测，故障注入的落点也跟着失去控制。

> [!note] 签名侧的下文
> 本节攻击的是签名的**计算过程**；签名的**编码与验证逻辑**（PKCS#1 v1.5 签名填充、摘要封装）是另一族攻击面，在 [[C12-数字签名|C12]] 展开。

## 5. Bleichenbacher：padding oracle（本章核心）

### 5.1 PKCS#1 v1.5 编码与 oracle 的形态

PKCS#1 v1.5 的加密填充把消息 D 包成 k 字节（k 是模数的字节数）的编码块：

$$\texttt{EM} = \texttt{00} \,\|\, \texttt{02} \,\|\, \texttt{PS} \,\|\, \texttt{00} \,\|\, \texttt{D} \tag{5.1}$$

PS 是至少 8 字节的**非零**随机填充，D 是消息（至多 $k-11$ 字节）。加密就是把 EM 当整数做 RSA：$c = \texttt{EM}^e \bmod n$。解密方拿到 c 先算 $\texttt{EM}' = c^d \bmod n$，检查结构（首字节 00、次字节 02、PS 非零、有 00 分隔符），通过才交出 D。

==检查失败时实现"怎么说"决定生死==。如果填充错误、长度错误、格式错误各自有独立的错误码、报文或时序，攻击者就拿到了一个一比特的应答器——**padding oracle**：递一个密文，问"填充对不对"，得到 true/false。1998 年 Bleichenbacher 证明：==仅仅这一个比特，就足以解出任意密文==。他打的是 SSL/TLS 的 RSA 密钥交换；2017 年的 ROBOT 扫描显示大量实现仍能被区分出"填充错"与其他错。

### 5.2 攻击原理：把明文一步步夹进单点

记 $B = 2^{8(k-2)}$（第三字节的权重），"结构合法"等价于 $\texttt{EM}' \in [2B, 3B)$。攻击者任选整数 s，把 $c \cdot s^e \bmod n$ 递给 oracle——解出来的值是 $m \cdot s \bmod n$（m 是目标明文）。==乘 $s^e$ 就是给明文乘 s==，在模 n 的世界里平移。oracle 回答 true 当且仅当存在整数 r 使

$$r \cdot n + 2B \;\le\; m \cdot s \;\le\; r \cdot n + 3B - 1 \tag{5.2}$$

两边除以 s，==每个 true 的 s 都把 m 夹进一组小区间==：

$$m \in \left[ \frac{r n + 2B}{s},\; \frac{r n + 3B - 1}{s} \right] \quad (\text{对某个整数 } r) \tag{5.3}$$

攻击就是反复"找 true 的 s → 收窄区间集"，四步循环：

1. **初始区间**：密文本身合法，所以 $m \in [2B, 3B-1]$，区间集 $M$ 从这一条起步。合法的 s 从 1 起就存在（s = 1 时 c 自己就合法，但由式 (5.3)，区间宽度约 $B/s$，s 太小等于没收窄），==s 从 $\lceil n/(3B) \rceil$ 起向上扫，为的是第一个命中的 s 尽量大、一次把区间砍到最窄==；这一步通常吃掉总询问数的大头；
2. **找下一个合法 s**：
   - 2a（首轮）：如上；
   - 2b（只剩一个区间 $[a, b]$）：r 从 $\lceil 2(b \cdot s_{\text{prev}} - 2B)/n \rceil$ 起步，候选窗口 $\left[\lceil (2B + rn)/b \rceil,\; \lfloor (3B - 1 + rn)/a \rfloor\right]$ 内逐个试，窗口扫完无 true 则 r 加一——对真 r，这个窗口**保证**含合法 s，扫的成本从"全空间碰运气"降到窗口长度；
   - 2c（多个区间）：$s$ 从上一轮值加一继续扫；
3. **收窄**：对每个 $[a,b] \in M$、每个候选 $r \in \left[\lceil (as - 3B + 1)/n \rceil,\; \lfloor (bs - 2B)/n \rfloor\right]$，取式 (5.3) 的区间与 $[a,b]$ 的交；全部交叠区间合并成新 $M$；
4. **终止**：$M$ 收敛成单点 $[m, m]$，用 $m^e \equiv c \pmod n$ 验算后剥填充。

每轮的区间宽度约从 $W$ 缩到 $B/s$，而 $s$ 每轮大约是 $n/W$ 的量级——==宽度每轮除以约 $n/B$==，几十轮内收敛。每个随机 s 回答 true 的概率约为 $(B/n) \cdot P(\text{分隔符位置合法})$：511 位模数上是 $2^{-18}$ 量级，这就是首轮要扫上万次的原因，也是这类攻击的询问成本来源。

### 5.3 自建 oracle 靶

靶是一个只回答"填充是否合法"的 HTTP 服务。判定函数忠实模拟 PKCS#1 v1.5 的结构检查；HTTP 层用原始 socket 手写（keep-alive + TCP_NODELAY），因为几十万次询问撑不起标准库逐请求解析的开销；模幂走 gmpy2：

```python
# t4_bb_server.py —— Bleichenbacher oracle 靶：/decrypt 只回答 PKCS#1 v1.5 填充是否合法
# 原始 socket 写最小 HTTP/1.1（keep-alive + TCP_NODELAY）：http.server 的逐请求解析开销
# 撑不起几十万次询问。密钥与填充全部确定性生成，输出可复现。
import socket
import threading
from sympy import nextprime
import gmpy2
from Crypto.Util.number import bytes_to_long

E = 65537
s_ = 2**255 + 12345678901234567890
while True:
    s_ = nextprime(s_)
    if s_ % 65537 != 0:
        P = s_
        break
s_ = 10**77 + 98765432109876543210987654321
while True:
    s_ = nextprime(s_)
    if s_ % 65537 != 0:
        Q = s_
        break
N = P * Q
D = pow(E, -1, (P - 1) * (Q - 1))

K = 64                                   # 模数字节数，EM 与密文都是 64 字节
MSG = b"flag{bl31ch3n_98}"               # 17 字节明文，PS 44 字节

def pad_v15(msg: bytes, k: int) -> bytes:
    """PKCS#1 v1.5 type 2：00 02 PS 00 D，PS 全部非零且至少 8 字节"""
    ps_len = k - 3 - len(msg)
    ps = bytes(((i * 167 + 29) % 255) + 1 for i in range(ps_len))   # 确定性非零 PS
    return b"\x00\x02" + ps + b"\x00" + msg

EM = pad_v15(MSG, K)
M_INT = bytes_to_long(EM)
C_TARGET = pow(M_INT, E, N)

QUERIES = 0
LOCK = threading.Lock()

def check_padding(c_int: int) -> bool:
    """解密并校验填充：00 开头、次字节 02、非零 PS 至少 8 字节后跟 00 分隔"""
    em = int(gmpy2.powmod(gmpy2.mpz(c_int), gmpy2.mpz(D), gmpy2.mpz(N))).to_bytes(K, "big")
    if em[0] != 0x00 or em[1] != 0x02:
        return False
    idx = em.find(b"\x00", 2)
    return idx >= 10

def handle(conn):
    global QUERIES
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    buf = b""
    while True:
        while b"\r\n\r\n" not in buf:
            data = conn.recv(65536)
            if not data:
                return
            buf += data
        head, buf = buf.split(b"\r\n\r\n", 1)
        reqline = head.split(b"\r\n")[0]
        if reqline.startswith(b"POST /decrypt"):
            cl = 0
            for h in head.split(b"\r\n")[1:]:
                if h.lower().startswith(b"content-length:"):
                    cl = int(h.split(b":")[1])
            while len(buf) < cl:
                buf += conn.recv(65536)
            body, buf = buf[:cl], buf[cl:]
            c_int = int(body[body.index(b":") + 1: body.rindex(b"}")])
            with LOCK:
                QUERIES += 1
            payload = b'{"padding_ok": %s}' % (b"true" if check_padding(c_int) else b"false")
        elif reqline.startswith(b"GET /pubkey"):
            payload = ('{"n": %d, "e": %d, "k": %d}' % (N, E, K)).encode()
        elif reqline.startswith(b"GET /target"):
            payload = ('{"c": %d}' % C_TARGET).encode()
        elif reqline.startswith(b"GET /stats"):
            with LOCK:
                payload = ('{"queries": %d}' % QUERIES).encode()
        else:
            payload = b'{"hint": "POST /decrypt {\\"c\\": <int>} | GET /pubkey /target /stats"}'
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)
        conn.sendall(resp)

if __name__ == "__main__":
    open("bb_c.txt", "w").write(str(C_TARGET))   # 目标密文落盘，供演示与脚本读取
    open("bb_m.txt", "w").write(str(M_INT))      # 服务端明文真值，调试比对用
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 6901))
    srv.listen(256)
    print("bleichenbacher oracle listening on 127.0.0.1:6901  (n %d bit, k = %d)"
          % (N.bit_length(), K), flush=True)
    print("服务端 EM =", EM.hex(), flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
```

起靶之后先"问"两次，看 oracle 的形态——目标密文 true，胡乱编的密文 false：

```bash
python3 t4_bb_server.py > bb_server.log 2>&1 &
sleep 3
C=$(cat bb_c.txt)
curl -s --noproxy '*' -X POST http://127.0.0.1:6901/decrypt -d "{\"c\": $C}"
curl -s --noproxy '*' -X POST http://127.0.0.1:6901/decrypt -d '{"c": 123456789012345678901234567890}'
```

输出：

```
{"padding_ok": true}
{"padding_ok": false}
```

服务端启动日志里有攻击结束时用来对账的那份 EM：

输出：

```
bleichenbacher oracle listening on 127.0.0.1:6901  (n 511 bit, k = 64)
服务端 EM = 00021ec56d15bc640cb35b03aa52f9a149f09840e78f37de862ed57d25cc741cc36b13ba620ab15901a850f79f4700666c61677b626c33316368336e5f39387d
```

### 5.4 完整攻击脚本与真实输出

攻击脚本按 5.2 的四步组织。s 的线性扫描是唯一的热点，交给 24 个工作线程分块并发——按提交顺序消费、首个命中即最小者，==并发只改速度，不改算法的每一步==：

```python
# t4_bb_attack.py —— Bleichenbacher 1998 完整攻击
# oracle 只回答"PKCS#1 v1.5 填充是否合法"。四步循环：定初始区间 -> 找下一个合法 s ->
# 用 s 把明文夹进更小的区间集 -> 区间收敛为单点即明文。s 的线性扫描分块并发。
import json
import socket
import threading
import time
import http.client
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from Crypto.Util.number import long_to_bytes

HOST, PORT = "127.0.0.1", 6901
WORKERS = 24
CHUNK = 128                              # 每个工作线程一次认领的候选 s 数

local = threading.local()
stop = threading.Event()
client_queries = 0
C_INT = None                             # 目标密文，main() 里装载
N_MOD = None
E_EXP = None

def new_conn():
    c = http.client.HTTPConnection(HOST, PORT)
    c.connect()
    c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return c

def ask(s_int: int) -> bool:
    """问一次 oracle：c * s^e mod n 解出来填充是否合法"""
    global client_queries
    conn = getattr(local, "conn", None)
    if conn is None:
        conn = local.conn = new_conn()
    ct = C_INT * pow(s_int, E_EXP, N_MOD) % N_MOD
    body = json.dumps({"c": ct})
    for _ in range(3):                   # 并发下偶发连接重置，重试兜底
        try:
            conn.request("POST", "/decrypt", body, {"Content-Type": "application/json"})
            resp = json.loads(conn.getresponse().read())
            client_queries += 1
            return resp["padding_ok"]
        except (http.client.HTTPException, ConnectionError, OSError):
            try:
                conn.close()
            except Exception:
                pass
            conn = local.conn = new_conn()
    raise RuntimeError("oracle 连接失败")

def probe_chunk(s_start: int, count: int):
    """试探 [s_start, s_start+count)；stop 置位时立即收工，命中返回该 s"""
    for s in range(s_start, s_start + count):
        if stop.is_set():
            return None
        if ask(s):
            return s
    return None

def search_from(s_start: int, pool, pending) -> int:
    """找 >= s_start 的第一个合法 s：按块并发提交、按提交顺序消费，首个命中即最小者"""
    next_start = s_start
    while True:
        while len(pending) < WORKERS * 4:
            pending.append(pool.submit(probe_chunk, next_start, CHUNK))
            next_start += CHUNK
        hit = pending.popleft().result()
        if hit is not None:
            stop.set()                   # 让还在飞的块立即退出，把浪费压到线程数量级
            return hit

def search_bounded(s_start: int, s_end: int, pool, pending) -> int:
    """在 [s_start, s_end] 里找第一个合法 s，找不到返回 None（step 2b 的窗口扫描）"""
    next_start = s_start
    while next_start <= s_end:
        while len(pending) < WORKERS * 4 and next_start <= s_end:
            pending.append(pool.submit(probe_chunk, next_start, min(CHUNK, s_end - next_start + 1)))
            next_start += CHUNK
        hit = pending.popleft().result()
        if hit is not None:
            stop.set()
            return hit
    return None

def merge(intervals):
    out = []
    for a, b in sorted(intervals):
        if out and a <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]

def ceil_div(x, y):
    return -(-x // y)

def main():
    conn = http.client.HTTPConnection(HOST, PORT)
    conn.request("GET", "/pubkey")
    pub = json.loads(conn.getresponse().read())
    conn.request("GET", "/target")
    c = json.loads(conn.getresponse().read())["c"]
    n, e, k = pub["n"], pub["e"], pub["k"]
    global C_INT, N_MOD, E_EXP
    C_INT, N_MOD, E_EXP = c, n, e
    B = 2 ** (8 * (k - 2))
    print(f"n {n.bit_length()} bit, k = {k} 字节, B = 2^{8 * (k - 2)}")

    pool = ThreadPoolExecutor(max_workers=WORKERS)
    pending = deque()

    # 第 1 步：目标密文本身合法 => 明文 m ∈ [2B, 3B)，这就是初始区间集
    M = [(2 * B, 3 * B - 1)]
    s = 0
    t0 = time.perf_counter()
    i = 0
    while True:
        # 第 2 步：搜下一个合法 s（首轮 2a；单区间 2b；多区间 2c）
        pending.clear()
        stop.clear()
        if i == 0:
            s = search_from(ceil_div(n, 3 * B), pool, pending)            # 2a
        elif len(M) == 1:
            a, b = M[0]                                                    # 2b
            r = ceil_div(2 * (b * s - 2 * B), n)
            s_hit = None
            while s_hit is None:
                lo = max(ceil_div(2 * B + r * n, b), s + 1)
                hi = (3 * B - 1 + r * n) // a
                if lo > hi:
                    r += 1
                    continue
                s_hit = search_bounded(lo, hi, pool, pending)
                r += 1
            s = s_hit
        else:
            s = search_from(s + 1, pool, pending)                          # 2c

        # 第 3 步：对每个区间枚举 r，把 m 夹进更小的子区间
        newM = []
        for a, b in M:
            rmin = ceil_div(a * s - 3 * B + 1, n)
            rmax = (b * s - 2 * B) // n
            for r in range(rmin, rmax + 1):
                lo = max(a, ceil_div(2 * B + r * n, s))
                hi = min(b, (3 * B - 1 + r * n) // s)
                if lo <= hi:
                    newM.append((lo, hi))
        M = merge(newM)
        i += 1

        if i <= 3 or i % 40 == 0 or (len(M) == 1 and M[0][0] == M[0][1]):
            w = M[0][1] - M[0][0] if len(M) == 1 else M[-1][1] - M[0][0]
            print(f"第 {i:>3} 轮: s = {s}, |M| = {len(M)}, 区间宽 2^{w.bit_length()}, 累计 {client_queries} 次")

        # 第 4 步：区间缩成单点，明文到手
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = M[0][0]
            assert pow(m, e, n) == c, "还原值未通过 RSA 验算"
            em = long_to_bytes(m).rjust(k, b"\x00")
            print("还原 EM =", em.hex())
            sep = em.index(b"\x00", 2)
            print("剥离填充 =", em[sep + 1:].decode())
            print("总询问(客户端计) =", client_queries)
            conn2 = http.client.HTTPConnection(HOST, PORT)
            conn2.request("GET", "/stats")
            stats = json.loads(conn2.getresponse().read())
            conn2.close()
            print("总询问(服务端计) =", stats["queries"])
            print(f"耗时 {time.perf_counter() - t0:.1f} s")
            return

if __name__ == "__main__":
    main()
```

```bash
time python3 -u t4_bb_attack.py
```

输出（中间轮次有节选）：

```
n 511 bit, k = 64 字节, B = 2^496
第   1 轮: s = 26696, |M| = 1, 区间宽 2^482, 累计 18623 次
第   2 轮: s = 240253, |M| = 1, 区间宽 2^479, 累计 18902 次
第   3 轮: s = 520547, |M| = 1, 区间宽 2^478, 累计 18926 次
第  40 轮: s = 87603835962982521, |M| = 1, 区间宽 2^440, 累计 19379 次
第  80 轮: s = 96321436279265437703100785972, |M| = 1, 区间宽 2^400, 累计 19889 次
第 120 轮: s = 105906539193137402326513612911236577734721, |M| = 1, 区间宽 2^359, 累计 20279 次
第 160 轮: s = 116445471300369246880453191975056499880154995911804498, |M| = 1, 区间宽 2^319, 累计 20767 次
第 200 轮: s = 128033149696612482067378299185069392572798368474220566747338158337, |M| = 1, 区间宽 2^280, 累计 21168 次
第 240 轮: s = 140773936832210670710982723445753982103233098700527296837223220766332917319668, |M| = 1, 区间宽 2^240, 累计 21606 次
第 280 轮: s = 154782580434819755541989341496454600497959796424577238495016439972656112175995828444590588, |M| = 1, 区间宽 2^200, 累计 22009 次
第 320 轮: s = 170185246965258319285135097986009141526395555933792504310294494378215714828904826727130574199922764110, |M| = 1, 区间宽 2^159, 累计 22512 次
第 360 轮: s = 187120657914231738757524824266666170473703534974816652099239395707722841605992567370130568220254765941946773586831, |M| = 1, 区间宽 2^119, 累计 23151 次
第 400 轮: s = 205741339173792996077768907298170466594334082743406004316785395466104929108461105785289604545508132994251783077942561947518771, |M| = 1, 区间宽 2^79, 累计 23669 次
第 440 轮: s = 226214994735791252077535674749772255911865698375958207536800792928600920838461154876368703849402975977556470863219077768342161256388593143, |M| = 1, 区间宽 2^39, 累计 24159 次
第 478 轮: s = 62181504272322277654778097876708148645734773303612212098133767814093377154347235786265248401350085820715435030444981011091855790985457007931862606112, |M| = 1, 区间宽 2^0, 累计 24747 次
还原 EM = 00021ec56d15bc640cb35b03aa52f9a149f09840e78f37de862ed57d25cc741cc36b13ba620ab15901a850f79f4700666c61677b626c33316368336e5f39387d
剥离填充 = flag{bl31ch3n_98}
总询问(客户端计) = 24747
总询问(服务端计) = 24749
耗时 4.8 s
```

三笔账读这份输出：

- **478 轮、24747 次询问**。首轮扫 s 占掉 18623 次（75%），与 5.2 的概率估算一致；后期每轮区间很窄，2b 的窗口按公式直接算到命中附近，一轮只补一两次询问——输出的后半段每 40 轮只涨几十次；
- **区间宽度的收敛轨迹**。$2^{482} \to 2^{440} \to 2^{359} \to \dots \to 2^0$，前几轮每轮除掉约 $n/B \approx 2^{15}$，与式 (5.3) 的几何收窄一致；
- **攻击者全程没碰过私钥**。还原的 EM 与服务端启动日志逐字节一致，剥离出的 flag 就是这条链路的终点。

> [!info]- 并发与吞吐的工程细节
> 攻击的算法本体是串行的四步循环，并发只作用在"扫 s"这个线性段上：24 个线程各自持有 keep-alive 连接，按 CHUNK=128 认领候选段；消费端按提交顺序取结果，首个命中立即置 stop 让在飞的段退出，浪费压到线程数量级。服务端三件套缺一不可：原始 socket 手写 HTTP（标准库 http.server 逐请求解析约 1ms，撑不住每秒数千次询问）、TCP_NODELAY 两侧都开（否则 Nagle 算法与延迟确认叠加出几十毫秒的尾延迟）、模幂用 gmpy2（纯 Python 的 pow 在这个尺寸下慢数倍）。另注意 ask 里必须送 $c \cdot s^e \bmod n$ 而不是 s 本身——==送错对象不报任何错，oracle 只会对每个 s 都答 false==。

> [!info]- 从教学靶到真实服务
> 真实服务不会送 JSON，信号藏在更细处：TLS 的 RSA 密钥交换里，填充错与其他错可能对应不同的 alert 类型、不同的时序、甚至"是否断开连接"；2017 年的 ROBOT 研究正是按这些差异把几十个实现重新分类打穿。Bardou 等人在 2012 年给出了区间合并的优化版（Bleichenbacher 论文的原版在部分轮次允许区间分裂），把 1024 位密钥的典型询问数从百万级压到二十万级——硬件加密盒也挡不住。防御侧见第 7 节。

## 6. Manger：OAEP 的 oracle，同一招式的快版

### 6.1 OAEP 编码与判据

PKCS#1 v2.0 的 OAEP 填充把 EM 排成：

$$\texttt{EM} = \texttt{00} \,\|\, \texttt{maskedSeed}_{(20)} \,\|\, \texttt{maskedDB}_{(k-21)} \tag{6.1}$$

解密的第一道检查只有一条：==解出的整数必须小于 $B = 2^{8(k-1)}$==（首字节 00），否则立即报 decryption error。如果这个报错能和其后的 OAEP 解码错误区分开，攻击者同样拿到一比特 oracle：问 $c \cdot s^e \bmod n$ 解出来"首字节是不是 00"。2001 年 Manger 证明这一比特同样致命，而且==攻击的询问数只随模数字节数线性涨==。

三步骨架（oracle 记 $O(c')$ = "解出值 $< B$"）：

1. **找 $f_1$**：从 2 起逐次倍增，到第一个 $O(c \cdot f_1^e)$ 为假。假意味着 $B \le m \cdot f_1 < 2B$（前一次倍增时还 $< B$），于是 $f_1/2$ 满足 $\frac{B}{2} \le m \cdot \frac{f_1}{2} < B$；
2. **找 $f_2$**：从 $\lfloor (n+B)/B \rfloor \cdot \frac{f_1}{2}$ 起步、每次加 $\frac{f_1}{2}$——每步让 $m \cdot f_2$ 增加不足一个 B，==第一次跨过 n 的整数倍时必然落进 $[rn,\; rn+B)$==（oracle 转真），步数不超过约 $2n/B \le 2^9$；
3. **折半**：此时 $m \in \left[\lceil n/f_2 \rceil,\; \lfloor (n+B)/f_2 \rfloor\right]$。设宽 $= m_{max} - m_{min}$，取 $f_{tmp} = \lfloor 2B/\text{宽} \rfloor$、$r = \lfloor f_{tmp} \cdot m_{min}/n \rfloor$、$f_3 = \lceil r \cdot n / m_{min} \rceil$：$m \cdot f_3$ 的散布被压在一个 $2B$ 的窗里，oracle 的一次回答区分"落在窗的下半"（真，$m_{max} \leftarrow \lfloor (rn+B)/f_3 \rfloor$）还是"上半"（假，$m_{min} \leftarrow \lceil (rn+B)/f_3 \rceil$）——==每问一次区间砍半==，从 $B$ 量级的宽度砍到 1 约需 $8k$ 次。

与 Bleichenbacher 的本质差别在信息获取方式：==BB 每轮的 s 是线性扫描"找"出来的（命中率 $2^{-18}$），Manger 每一步的乘子由当前区间直接"算"出来==——没有 rejection，询问数从 $2^{20}$ 量级掉到几百。

### 6.2 自建靶与对比

靶与 5.3 同构，只换两处：判据函数只看首字节（`em_int < B`）；EM 布局按式 (6.1) 排（教学靶用确定性字节占位，攻击只依赖整数值）。端口 6902：

```python
# t5_mg_server.py —— Manger oracle 靶（OAEP 判据），与 t4_bb_server.py 只差两处：
#   1) 判据：check_leading_zero 只检查解出整数 < B = 2^(8(k-1))
#   2) EM 布局：EM = 00 || maskedSeed(20) || maskedDB(k-21)
#   其余（密钥生成、HTTP 服务、/pubkey /target /stats）原样，监听 127.0.0.1:6902。
def check_leading_zero(c_int: int) -> bool:
    """解密结果的整数 < B = 2^(8(k-1)) <=> 首字节为 00；实现把它单独回成一种错误"""
    return pow(c_int, D, N) < (1 << (8 * (K - 1)))
```

攻击脚本全文（串行即可，总共几百次询问）：

```python
# t5_mg_attack.py —— Manger 2001 完整攻击（串行即可：总询问只有几百次）
# oracle：ask(s) = True 表示 c·s^e 解出来首字节为 00（整数值 < B = 2^(8(k-1))）
import json
import socket
import time
import http.client
from Crypto.Util.number import long_to_bytes

HOST, PORT = "127.0.0.1", 6902

def ceil_div(x, y):
    return -(-x // y)

queries = 0
C_INT = None                             # 目标密文，main() 里装载
N_MOD = None
E_EXP = None

def ask(s_int: int) -> bool:
    """问一次 oracle：c * s^e mod n 解出来首字节是否为 00"""
    global queries
    ct = C_INT * pow(s_int, E_EXP, N_MOD) % N_MOD
    conn = http.client.HTTPConnection(HOST, PORT)
    conn.connect()
    conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.request("POST", "/decrypt", json.dumps({"c": ct}), {"Content-Type": "application/json"})
    resp = json.loads(conn.getresponse().read())
    conn.close()
    queries += 1
    return resp["leading_zero"]

def main():
    conn = http.client.HTTPConnection(HOST, PORT)
    conn.request("GET", "/pubkey")
    pub = json.loads(conn.getresponse().read())
    conn.request("GET", "/target")
    c = json.loads(conn.getresponse().read())["c"]
    n, e, k = pub["n"], pub["e"], pub["k"]
    global C_INT, N_MOD, E_EXP
    C_INT, N_MOD, E_EXP = c, n, e
    B = 2 ** (8 * (k - 1))
    print(f"n {n.bit_length()} bit, k = {k} 字节, B = 2^{8 * (k - 1)}")
    t0 = time.perf_counter()

    # 第 1 步：f1 从 2 起逐次倍增，找第一个 f1·m mod n >= B 的 f1（oracle 转 False）
    f1 = 1
    while True:
        f1 *= 2
        if not ask(f1):
            break
    f1_2 = f1 // 2                          # f1_2·m ∈ [B/2, B)
    print(f"第 1 步: f1 = {f1} = 2^{f1.bit_length() - 1}, 询问 {queries} 次")

    # 第 2 步：f2 从 floor((n+B)/B)·f1_2 起步、每次加 f1_2（增量 < B），
    #         直到 f2·m 跨过 n 的整数倍、落进 [r·n, r·n+B)（oracle 转 True）
    f2 = ((n + B) // B) * f1_2
    while True:
        if ask(f2):
            break
        f2 += f1_2
    print(f"第 2 步: f2 步进到命中, 询问累计 {queries} 次")
    print(f"第 3 步: m ∈ [n/f2, (n+B)/f2]，折半收窄")

    # 第 3 步：每次询问把区间砍一半，直到单点
    m_min = ceil_div(n, f2)
    m_max = (n + B) // f2
    rounds = 0
    while m_min < m_max:
        f_tmp = (2 * B) // (m_max - m_min)
        r = (f_tmp * m_min) // n
        f3 = ceil_div(r * n, m_min)
        if ask(f3):                          # f3·m ∈ [r·n, r·n+B) => m < (r·n+B)/f3
            m_max = (r * n + B) // f3
        else:                                # f3·m ∈ [r·n+B, r·n+2B) => m >= (r·n+B)/f3
            m_min = ceil_div(r * n + B, f3)
        rounds += 1
        if rounds <= 3 or rounds % 100 == 0:
            print(f"  第 {rounds:>3} 次折半: 区间宽 {m_max - m_min}, 累计 {queries} 次")

    m = m_min
    assert pow(m, e, n) == c, "还原值未通过 RSA 验算"
    em = long_to_bytes(m).rjust(k, b"\x00")
    print("还原 EM =", em.hex())
    print("剥离填充 =", em[21:].lstrip(b"\x00").decode())
    print("第 3 步折半次数 =", rounds)
    print("总询问 =", queries, f"  耗时 {time.perf_counter() - t0:.1f} s")

main()
```

```bash
python3 -u t5_mg_attack.py
```

输出（折半过程有节选）：

```
n 511 bit, k = 64 字节, B = 2^504
第 1 步: f1 = 16 = 2^4, 询问 4 次
第 2 步: f2 步进到命中, 询问累计 87 次
第 3 步: m ∈ [n/f2, (n+B)/f2]，折半收窄
  第   1 次折半: 区间宽 16960573097907470829083884439521239130656176404368211344473012269928154385516448470897772499097949000781796290816373424918224127180753331882531231032, 累计 88 次
  第   2 次折半: 区间宽 8021917214751644787953414269498139421384637806571309217296191607578515917543797232465106106819361107135954981816708648814557583349913526340855716370, 累计 89 次
  第   3 次折半: 区间宽 4069772511687998250511019022985558098461396762954737434660174000876529751096714013963346077749158030874966295538619151151003175053041185988335099861, 累计 90 次
  第 100 次折半: 区间宽 34013392231932466905581375742437437066880281624343440299427892365522691697399439669870606264760249590257348933874571526, 累计 187 次
  第 200 次折半: 区间宽 50678421110703921561775642804260545255988302036622190606699419613550653869499118417207993, 累计 287 次
  第 300 次折半: 区间宽 55406509196643287790401843615297854786732244456382782115976, 累计 387 次
  第 400 次折半: 区间宽 70372069698308972600213069728, 累计 487 次
还原 EM = 00126bc41e77d02a83dc368fe8429bf44ea7015ab30000000000000000000000000000000000000000000000000000666c61677b6d346e6733725f306165707d
剥离填充 = flag{m4ng3r_0aep}
第 3 步折半次数 = 497
总询问 = 584   耗时 0.6 s
```

两个靶同尺寸（511 位模数），账对在一起看：

| 对比项 | Bleichenbacher（第 5 节） | Manger（本节） |
| ---- | ---- | ---- |
| 针对的填充 | PKCS#1 v1.5（加密） | OAEP（PKCS#1 v2.0） |
| oracle 判据 | 完整结构（00 02 … 00 分隔） | 首字节 == 00 |
| 下一个乘子怎么来 | 线性扫描，命中率约 $2^{-18}$ | 由当前区间直接计算 |
| 询问量级 | $2^{20}$ 上下（1024 位） | 约 $9k$（k 为模数字节数） |
| 本靶数字 | 24747 次 / 4.8 s | 584 次 / 0.6 s |
| 修复 | 统一报错、恒定时间、弃用 v1.5 | 统一报错 |

> [!note] Manger 攻击不是 OAEP 的罪状
> 攻击利用的是"首字节检查单独报错"这个实现行为，不是 OAEP 的数学。==所有实现把解密失败统一成一个不可区分的错误==，两个 oracle 就同时消失。OAEP 在这个前提下仍是标准选择，第 7 节收拢。

## 7. 检测与防御

四类攻击、两条防线。第一条==不让错误可区分==，第二条==不让中间值可观测==：

| 攻击 | 依赖的"多说的一句话" | 防御 |
| ---- | ---- | ---- |
| 部分 d / 小 d（第 2、3 节） | 私钥碎片经侧信道外泄 | d 与 p、q 同量级随机生成（[[C07-RSA攻击I\|C07]] 第 7 节的生成纪律）；恒定时间模幂 |
| Bellcore（第 4 节） | 输出了没验算过的签名 | 签名后验签再输出；双路计算；盲化 |
| Bleichenbacher（第 5 节） | 填充错误有独立报文/时序 | 解密失败统一报错且恒定时间；用 OAEP 替代 v1.5 |
| Manger（第 6 节） | 首字节检查单独报 decryption error | 同上——统一报错后 oracle 消失 |

==统一报错是加密侧的核心纪律==：解密函数无论在填充、长度还是格式上失败，对外都只给同一个错误、同一耗时、同一行为，攻击者的一比特应答器不复存在。pycryptodome 的 `PKCS1_OAEP` 在解密失败时统一抛 `ValueError`，用它替代 `PKCS1_v1_5` 是应用侧最省事的一步：

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.import_key(open("priv.pem").read())
cipher = PKCS1_OAEP.new(key)
pt = cipher.decrypt(ct)          # 填充/格式失败统一 ValueError，无类型区分
```

TLS 侧的修复一句话：TLS 1.3 起移除了 RSA 密钥交换，前向的 RSA 解密面（Bleichenbacher/Manger 的经典攻击面）随之消失；存量服务则退而求其次——统一报错加恒定时间。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| oracle 对任何 s 都答 false | 递给服务端的是 s 本身而不是 $c \cdot s^e \bmod n$；程序不报错、区间永远不动，每轮先自检 oracle 对目标密文的应答应为 true（[[#5.4 完整攻击脚本与真实输出\|5.4]]） |
| Bleichenbacher 攻击中途区间集变空 | 收窄公式抄错或区间合并丢真值：r 范围是 $[\lceil (as-3B+1)/n \rceil, \lfloor (bs-2B)/n \rfloor]$，合并前先排序（[[#5.2 攻击原理：把明文一步步夹进单点\|5.2]]）；自建靶有真值，每轮断言真值在 M 内能立刻定位是哪一轮丢的 |
| 轮次里 s 不前进、反复同一批值 | 2b 的候选窗口起点没和上一轮的 s 取 max，扫回旧区间；`lo = max(ceil((2B+rn)/b), s+1)`（[[#5.4 完整攻击脚本与真实输出\|5.4]]） |
| oracle 靶打不动，每秒只有一两百次询问 | 标准库 http.server 的逐请求解析与 Nagle 延迟叠加：原始 socket + keep-alive + 两侧 TCP_NODELAY + gmpy2 模幂（[[#5.3 自建 oracle 靶\|5.3]]） |
| curl 打本地靶走了代理或超时 | 代理拦了 127.0.0.1：一律 `--noproxy '*'`（[[#5.3 自建 oracle 靶\|5.3]]） |
| 故障靶的 gcd 出来是 n 或 1 | 故障翻在了 CRT 合成之后的 s 上（两侧同错）或两侧都翻；翻转点必须落在单侧的半程结果上（[[#4.2 自建靶：一次故障的完整利用链\|4.2]] 的 warning） |
| 位提升的根数失控爆内存 | 二次同余在 2 的幂上退化（k 为偶数时常见）：每级根数设上限，超限的 k 候选直接跳过（[[#2.2 手工利用：位提升与 small_roots 收尾\|2.2]]） |
| partial_d 想打 e=65537 的靶却总是失败 | k 要扫到 e−1，工具内部把 k 截到 1000，真 k 在其外则不可能命中（[[#2.3 e 大的时候与高半已知的时候\|2.3]]）；这类碎片题基本配小 e，先确认题目形态 |
| RsaCtfTool `--attack partial_d` 提示 only for partial private keys | 该攻击吃部分私钥 PEM（d 字段放已知低位），不是 `-n/-e` 公钥；`--partial --key xx.pem` 加 `--d-known-bits` 声明位数（[[#2.4 RsaCtfTool 对照\|2.4]]） |
| 想演示 Boneh-Durfee，Wiener 却先命中了 | d/N 造到了 0.25 以下：1024 位模数把 d 造在 255–299 比特，512 位造在 128–149 比特（[[#3.3 自建靶实战：边界带上的对照\|3.3]] 的 warning） |
| boneh_durfee 报 `requires Sage dependency` 或 `ModuleNotFoundError: tqdm` | RsaCtfTool 的 sage 系攻击要在 sage 环境里有全部普通依赖：conda 安装的 sage 用其解释器跑并补装 tqdm/pycryptodome/cryptography（[[C01-密码学导论与工具链\|C01]] 第 5 节） |
| 照抄单变量的 Coppersmith 造 BD 格，条件永远不成立 | y 的界（$\sqrt n$）把行列式推得过大，铺满的格到不了 Howgrave-Graham 条件（[[#3.2 多元格的直观：单变量那套照搬为什么不行\|3.2]] 的数值表）；用带删行与 y-shifts 挑选的公开实现，调 m/t 即可 |
| Manger 第 3 步的区间不减半 | $f_3$ 必须向上取整（$\lceil r n / m_{min} \rceil$）：取成向下取整会让窗口整体偏低，oracle 的回答区分不出上下半（[[#6.1 OAEP 编码与判据\|6.1]]） |
| Wiener/BD 恢复的 d 与生成脚本里的不同 | $e \cdot d \equiv 1$ 的解是一整族，命中族里另一个成员解密照样成立（[[C07-RSA攻击I\|C07]] 第 3 节的 warning） |

## 9. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **边界扫描**：把 3.3 的靶生成器改成 d 从 250 比特逐档加到 305 比特、每档五把钥匙，分别用 Wiener 与 `boneh_durfee` 打，记录命中率曲线，核对两个塌陷点是否落在 $n^{0.25}$ 与 $n^{0.292}$。
> 2. **故障位扫描**：把 4.2 的翻转位从第 100 位换成 0、5、200、255 各跑一遍，再交换翻转对象为 sp 侧，记录每组 gcd 的结果，验证"翻单侧半程必中、翻合成之后必失效"。
> 3. **询问量的尺寸账**：给 5.3 的靶换 48 字节模数（k=48）重打一次，对比总询问数与首轮占比，验证询问成本主要由 $n/B$ 的密度决定。
> 4. **防御还原**：给 5.3 的靶加"统一报错"模式（所有失败都返回同一响应与固定延时），确认 5.4 与 6.2 的两个攻击脚本再也拿不到可区分的应答；再把 6.2 的首字节判据并回统一的解密错误，重打一次验证 oracle 消失。

配套练习：

1. 把 2.2 的位提升推广到"已知 d 的低 t 位、e = 65537"的形态：实现同余式在 mod 8 上的快速过滤，统计 65536 个 k 里通过过滤的比例，评估这条链在正常 e 下的真实成本。
2. 给 5.4 的攻击脚本把并发换成 Manger 式的"按公式直接算 s"：对照 Bardou 等人的优化（延伸阅读）实现区间合并改进版，比较同一靶上的总询问数与轮数。
3. 写一个"错误可区分性检测器"：给定任意解密服务，枚举填充错/长度错/格式错/解密超时的响应指纹（状态码、报文、时序），输出是否存在可用的 oracle——它是第 7 节防御的检验器。
4. 把本章四个 solve 片段（partial d、boneh_durfee 调用、bellcore、BB/Manger 客户端）挂到 [[C01-密码学导论与工具链|C01]] 第 6 节的工作流模板上，特征列补进 [[C07-RSA攻击I|C07]] 1.2 的决策表。

延伸阅读：

- D. Bleichenbacher, *Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1*（CRYPTO '98）：式 (5.2)–(5.3) 与四步循环的原始出处，第 5 节的算法与此逐条对应；
- J. Manger, *A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding*（CRYPTO 2001）：第 6 节三步骨架与"约 $9k$ 次询问"的出处；
- D. Boneh, R. DeMillo, R. Lipton, *On the Importance of Checking Cryptographic Protocols for Faults*（EUROCRYPT '97）：故障攻击的原始论文，第 4 节的模型与防御讨论在此；
- D. Boneh, G. Durfee, *Cryptanalysis of RSA with Private Key d Less Than N^0.292*（IEEE Trans. Inf. Theory, 2000）与 Boneh–Durfee–Frankel 的部分密钥泄露论文（EUROCRYPT '98）：第 2、3 节两族攻击的原始文献；
- ROBOT（Return of Bleichenbacher's Oracle Threat, 2017）：第 5.1 节"2017 复活"的系统研究，含可区分信号的分类；
- R. Bardou et al., *Efficient Padding Oracle Attacks on Cryptographic Hardware*（CRYPTO 2012）：区间合并优化，把询问数再压一个量级；
- [[02-书单与Wiki|书单与 Wiki]] 与 [[03-工具清单|工具清单]]：本章工具的条目与同类替代；
- 下一章 [[C10-哈希进阶|C10]] 转向哈希函数的内部与碰撞；签名侧的编码攻击与签名格式的下文在 [[C12-数字签名|C12]] 展开。
