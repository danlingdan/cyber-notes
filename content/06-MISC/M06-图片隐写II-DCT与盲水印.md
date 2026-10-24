---
chapter: MISC
section: 图片隐写 II：DCT 与盲水印
order: 806
tags:
  - CTF
  - MISC
  - 隐写
publish: true
---

# M06 图片隐写 II：DCT 与盲水印
## DCT Steganography & Blind Watermarking

> [!info]- 章节信息
> **所属方向**：MISC ｜ **难度阶段**：L2 核心期 ｜ **前置要求**：[[12-隐写与流量取证|12 章]] · [[M03-文件格式深拆II-JPEG与GIF|M03]] · [[M05-图片隐写I-LSB与位平面|M05]]
> **本章目标**：把隐写从像素层搬进频率层：理解 JPEG 上为什么只能做系数域隐写、写入点为什么选中频；掌握 steghide 的参数、容量与探测行为，跑通 stegseek 口令爆破全流程；认识 outguess / F5 / J-Phide 同族工具的识别线索；手撕一个 8×8 分块 DCT 盲水印（量化索引调制），再用 blind_watermark 库跑通工业级流程。

## 1. 从空域到频域：LSB 在 JPEG 上活不下去

[[M05-图片隐写I-LSB与位平面|M05]]结尾埋了一个伏笔：空域 LSB 这条路在 JPEG 上走不通。原因藏在 [[M03-文件格式深拆II-JPEG与GIF|M03]]第 4 节的编码管线里，用一句话收拢：==JPEG 文件里没有像素，只有 DCT 系数==。空域 LSB 的全部操作对象是像素最低位，而 JPEG 的文件体是"系数 → 量化 → Huffman 编码"的产物，压根不存在可以翻动的像素字节。

把一张藏好 LSB 的 PNG 转存成 JPEG 会发生什么：编码器重新分块、DCT、量化。量化是有损的——每个系数除以量化表数值再四舍五入，原来写在像素最低位的信息在这一步被抹掉，个别位碰巧活下来也不可靠。所以 JPEG 隐写只有一条正路：==把信息写进它真正存储的东西里，也就是 DCT 系数==。

写入位置选在**中频**。[[M03-文件格式深拆II-JPEG与GIF|M03]]4.1 量过能量分布：自然图像的能量集中在系数矩阵左上角的低频区，高频系数接近 0。三个区各自的命运：

| 区域 | 特点 | 改动后果 |
| ---- | ---- | ---- |
| 低频（左上角） | 系数大、能量集中，人眼敏感 | 改一点整块画面就变形，画质毁掉 |
| 高频（右下角） | 数值小、量化表数值大 | 本来就要被量化抹成 0，藏进去的信息活不过一次重压缩 |
| 中频 | 两头都不占 | ==画质牺牲可控，存活率可观==，隐写的固定写入区 |

强度与画质是一对直接互换的量：改动幅度大，抗压缩强、画质差；幅度小，画质好、一压就没。到 5.4 节这个取舍会变成一个具体的参数 Δ。先对照着把两条路线摆在一起：

| | 空域 LSB（M05） | 频域 DCT（本章） |
| ---- | ---- | ---- |
| 容器 | BMP / PNG 等无损图 | JPEG |
| 写入对象 | 像素最低位 | 中频 DCT 系数 |
| 抗转码 | 转存即毁 | 幅度够大就能扛住再压缩 |
| 代表工具 | zsteg、stegsolve | steghide、outguess、F5 |

## 2. steghide 深入

[[12-隐写与流量取证|12 章 5.3]]给过 steghide 三条命令的一眼用法：embed 嵌入、info 探测、extract 提取，外加两句必背知识点——只支持 JPEG/BMP/WAV/AU，PNG 不在列。本节把参数补全、行为摸清。JPEG 容器仍然是主战场，PNG 依旧不碰。

### 2.1 参数全家福

| 参数 | 用于 | 作用 |
| ---- | ---- | ---- |
| `-cf 文件` | embed | cover file，载体 |
| `-ef 文件` | embed | embed file，要藏的文件 |
| `-sf 文件` | embed / extract | stego file：embed 时指定输出文件名，**缺省则覆写载体**；extract 时指定从哪个文件提 |
| `-xf 文件` | extract | 提取结果落盘文件名 |
| `-p 口令` | 全部 | 口令；不写则交互式询问，直接回车等于空口令 |
| `-e 算法` | embed | 加密算法：aes-128（默认）/ aes-192 / aes-256 / blowfish / none |
| `-z 级别` | embed | 压缩级别 1–9，默认压缩开启 |
| `-Z` | embed | 完全关闭压缩 |

一道完整的嵌入与提取（口令 ctf2026，输出文件单独指定，不覆写载体）：

```bash
steghide embed -cf cover_q95.jpg -ef flag.txt -sf stego.jpg -p ctf2026
steghide extract -sf stego.jpg -xf back.txt -p ctf2026
cat back.txt
```

输出：

```
embedding "flag.txt" in "cover_q95.jpg"... done
writing stego file "stego.jpg"... done
wrote extracted data to "back.txt".
flag{dct_st3g0_2026}
```

空口令与加密、压缩参数都能自由组合。用 `-e none -Z` 关掉加密和压缩，info 报出的嵌入参数会跟着变：

```bash
steghide embed -cf cover_q95.jpg -ef flag.txt -sf stego_open.jpg -p "" -e none -Z
steghide info stego_open.jpg -p ""
```

输出：

```
"stego_open.jpg":
  format: jpeg
  capacity: 5.1 KB
  embedded file "flag.txt":
    size: 20.0 Byte
    encrypted: no
    compressed: no
```

==口令不决定"藏在哪里"，它派生出密钥流，把秘密加密后按伪随机顺序散布进 DCT 系数==；文件里另存一个种子，提取端用同一口令重现同一个系数序列，散开的比特才收得回来。

> [!info]- 内部结构再往下两层
> steghide 把口令做密钥派生，秘密默认用 AES-128-CBC 加密（info 里显示为 rijndael-128, cbc），再用一个存在文件里的种子驱动伪随机序列选出要写入的 DCT 系数；写入时不是逐位替换，而是在系数对之间做交换，把改动摊平到整幅图（论文里叫图论嵌入）。理解到"口令 → 选位置 + 加密"这层就够做题，再往下一层是隐写检测（隐写分析）的事，[[M15-隐写进阶与隐写分析|M15]]回头接。

> [!warning] 别拿原题附件当 -cf
> embed 不写 `-sf` 时直接覆写载体文件。做题时先 `cp` 一份副本再操作，原题附件改坏了就没了（[[M01-MISC导论与工具箱|M01]]的目录纪律）。

### 2.2 容量与质量

容量 = 载体能吞下多少秘密。steghide 的写入空间来自 DCT 系数的可改动余量，余量由量化表决定：质量越高、量化步长越小、可改动的系数越多。固定口令、`-Z` 关压缩、塞随机数据（随机数据不可再压，多大就是多大），逐档二分出最大可嵌入量：

| quality | JPEG 文件大小 | 可嵌入（随机载荷上限） |
| ---- | ---- | ---- |
| 30 | 10426 字节 | 438 字节 |
| 60 | 14295 字节 | 634 字节 |
| 95 | 87211 字节 | 5125 字节 |

==质量越高，容量越大==——q30 档连半 KB 都塞不下，q95 档能塞 5 KB 出头（info 报的 capacity 5.1 KB 与二分结果 5125 字节一致）。拿到一张又小又糊的 JPEG 时，出题人的秘密文件必然也很小，而 flag 文本恰好就是这个量级。超容量时 embed 直接拒绝：

```bash
steghide embed -cf cover_q95.jpg -ef big.bin -sf out.jpg -p ctf2026 -Z
```

输出：

```
steghide: the cover file is too short to embed the data.
```

> [!note] 塞不下的两个杠杆
> ① 确认压缩开着（没写 `-Z`），文本类载荷压完小得多；② 换更大、更高质量的载体。两个杠杆都不行，说明秘密相对载体太大——2.2 的容量表就是帮你建立这个直觉的。

### 2.3 info 探测的三种结果

info 先报格式与容量，再用给定口令尝试提取一次来探测有没有货。同一批文件的三种对照：

```bash
steghide info cover_q95.jpg -p anything     # 干净载体
steghide info stego.jpg    -p wrongpass     # 有货，口令错
steghide info stego.jpg    -p ctf2026       # 有货，口令对
```

输出：

```
"cover_q95.jpg":
  format: jpeg
  capacity: 5.1 KB
steghide: could not extract any data with that passphrase!
"stego.jpg":
  format: jpeg
  capacity: 5.1 KB
steghide: could not extract any data with that passphrase!
"stego.jpg":
  format: jpeg
  capacity: 5.1 KB
  embedded file "flag.txt":
    size: 20.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

前两种的报错一字不差——==info 报出 embedded file 才算探明有货；报 could not extract 证明不了任何事==：可能没货，也可能口令错。所以 info 的价值是"确认有货 + 顺手拿到嵌入参数"，不是"排除嫌疑"；口令未知时直接上 stegseek。不带 `-p` 时 info 走交互：先问口令，再问 `Try to get information about embedded data ? (y/n)`。

## 3. stegseek：口令爆破全流程

原理一句话：stegseek 把 steghide 的"提取尝试"包装成多线程爆破，逐口令调 steghide 的提取例程，提取成功即口令命中。

先造靶：把 flag 塞进 q60 档的载体（命令同 2.1，`-cf cover_q60.jpg -sf target.jpg -p ctf2026`），再备一个小字典 dict.txt——20 行常见弱口令（123456、password、qwerty 一类），正确口令 ctf2026 混在中间。

```bash
stegseek target.jpg dict.txt
```

输出：

```
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "ctf2026"
[i] Original filename: "flag.txt".
[i] Extracting to "target.jpg.out".
```

逐行读：

- `Found passphrase`：口令命中。
- `Original filename`：嵌入时 `-ef` 的原始文件名——steghide 把它存进了文件，这里直接吐出来。
- `Extracting to`：提取出的秘密默认落盘为原文件名加 `.out`，`cat` 出来就是 flag。

```bash
cat target.jpg.out
```

输出：

```
flag{dct_st3g0_2026}
```

参数形式（对照 `stegseek --help`）：位置参数 `stegseek [stego文件] [字典]` 等价于 `stegseek --crack -sf target.jpg -wl dict.txt`，`-xf` 另指定提取落盘名，`-t` 控制线程数，`-c` 命中后继续跑（一个文件可以藏多份秘密）。另有 `--seed` 模式：不试口令，穷举嵌入参数本身——用来检测"这文件是不是 steghide 处理过"；若嵌入时没加密，它甚至能直接把秘密抠出来。

真实赛题里字典换成 rockyou：Kali 自带 `/usr/share/wordlists/rockyou.txt.gz`，解压即用；Windows 侧从 GitHub 的弱口令字典仓库下载。stegseek 不给字典参数时默认去找这个路径，找不到就报错（见本章常见问题）。

## 4. outguess 与 F5：JPEG 隐写工具谱系

steghide 只是 JPEG 隐写工具族的一员。四个常见工具摆在一起：

| 工具 | 原理 | 识别线索 |
| ---- | ---- | ---- |
| steghide | 口令派生密钥，秘密加密后散布写入 DCT 系数 | stegseek 爆破命中即实锤；info 能报出嵌入参数 |
| outguess | RC4 流密码加密，嵌入时刻意保持 DCT 系数的统计分布 | stegseek 无果时的第一候选；老题常见 |
| F5 | 矩阵编码：n 个系数里改至多 1 个来表达 k 位，把每比特的改动摊薄；java 工具 | 口令只决定散布顺序；嵌入率可调 |
| J-Phide | 写入 DCT 系数，嵌入率压得极低、逐块伪随机散布（口令保护） | 系数改动少而散，统计检测才有戏 |

量化表本身也能当暗格：交换 DQT 段里两张表的位置、或改写表值，图能打开但画质与统计特性异常——用 [[M03-文件格式深拆II-JPEG与GIF|M03]]第 1 节的段解析器看一眼 DQT 就能发现。

排查顺序固定：==stegseek（rockyou）无果不等于没隐写==，它只覆盖 steghide 一种工具。命中无望就按上表的识别线索换工具再提，还无果则回到结构层（COM、APPn、DQT、段异常）。

> [!info]- outguess 与 F5 的提取模板
> Ubuntu 26.04 的 apt 没有 outguess 包；Kali 或老版本系统可直接 `apt install outguess`，或从源码编译（github.com/resurrecting-open-source-projects/outguess）。F5 是 java 工程，clone github.com/matthewgao/F5-steganography 后在工程目录内运行。两个模板都备着，口令空着和填上都试一遍：
>
> ```bash
> outguess -r stego.jpg out.txt                    # 无口令提取
> outguess -k "口令" -r stego.jpg out.txt          # 带口令提取
> java Extract stego.jpg -p 口令                   # F5 提取，输出以工程内说明为准
> ```

## 5. 盲水印手撕：量化索引调制

### 5.1 从 LSB 水印到频域水印

水印 = 把一张图（或一段比特）藏进另一张图。用 [[M05-图片隐写I-LSB与位平面|M05]]的 LSB 也能做水印：把水印图的比特写进载体像素最低位。这类水印的死穴和 LSB 隐写一样——载体一经转码，像素一变，水印跟着毁。

频域水印把比特写进 DCT 系数：==改的是整块的"频率成分"，不是某一个像素==。一个系数的变化摊到块内 64 个像素上，每个像素只动一点；反过来，转码带来的整块像素扰动，在频域也只体现为系数的小幅漂移——只要当初的写入步长够大，写入的信息就能撑过这些处理。

具体写法是**量化索引调制**（QIM）：每个 8×8 块选一个中频系数，把系数除以步长 Δ 四舍五入得到量化索引 q，==规定 q 的奇偶就是水印比特==（偶为 0、奇为 1）；不符合就把 q 挪一步（系数加减 Δ）。提取端对每个块做同样的 DCT、同样的除法，读奇偶拼回比特——==提取全程不需要原图==，这就是"盲"字的含义。

### 5.2 embed 与 extract

完整实现如下，坐标 `POS = (4, 2)` 是选定的中频位置（DCT 系数矩阵的第 5 行第 3 列，左上低频、右下高频的中间地带）：

```python
# dct_wm.py —— 8x8 分块 DCT 盲水印：量化索引调制
import numpy as np
from PIL import Image
from scipy.fft import dct, idct

POS = (4, 2)          # 每个块选定的中频系数位置

def dct2(b):
    return dct(dct(b, axis=0, type=2, norm="ortho"), axis=1, type=2, norm="ortho")

def idct2(c):
    return idct(idct(c, axis=0, type=2, norm="ortho"), axis=1, type=2, norm="ortho")

def embed_wm(cover, out, wm_bits, delta):
    """把 wm_bits 逐位写进载体亮度通道每个 8x8 块的中频系数"""
    img = Image.open(cover).convert("YCbCr")
    Y, Cb, Cr = img.split()
    Y = np.asarray(Y, dtype=np.float64)
    H, W = Y.shape
    k = 0
    for by in range(0, H - 7, 8):
        for bx in range(0, W - 7, 8):
            if k >= len(wm_bits):
                break
            c = dct2(Y[by:by + 8, bx:bx + 8] - 128)  # 减 128 是 JPEG 的规定（M03 4.1）
            q = int(np.floor(c[POS] / delta + 0.5))  # 量化索引
            if q % 2 != wm_bits[k]:                  # 奇偶不符合就挪一步
                q = q + 1 if q >= 0 else q - 1
            c[POS] = q * delta
            Y[by:by + 8, bx:bx + 8] = idct2(c) + 128
            k += 1
    Y8 = np.clip(np.round(Y), 0, 255).astype(np.uint8)
    Image.merge("YCbCr", (Image.fromarray(Y8), Cb, Cr)).convert("RGB").save(out)
    return k

def extract_wm(path, nbits, delta):
    """按同一位置读量化索引的奇偶，拼回比特"""
    Y = np.asarray(Image.open(path).convert("YCbCr").split()[0], dtype=np.float64)
    bits = []
    for by in range(0, Y.shape[0] - 7, 8):
        for bx in range(0, Y.shape[1] - 7, 8):
            if len(bits) >= nbits:
                break
            q = int(np.floor(dct2(Y[by:by + 8, bx:bx + 8] - 128)[POS] / delta + 0.5))
            bits.append(q % 2)                       # 奇偶即比特
    return np.array(bits, dtype=np.uint8)

def psnr(a, b):
    """峰值信噪比：衡量嵌入前后的画质差，定义见 5.4 式 (5.1)"""
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    return 10 * np.log10(255.0 ** 2 / np.mean((a - b) ** 2))
```

三个要点：

1. 只动亮度通道 Y：JPEG 也把细节放在亮度上（[[M03-文件格式深拆II-JPEG与GIF|M03]]第 1 节），色度 Cb/Cr 原样带走。
2. 嵌入端两处取整（`np.round`、`np.clip`）是误差源头：写好的系数经逆变换变回像素时被四舍五入，5.4 的 Δ 选型就是冲它去的。
3. 块数必须不小于比特数：768×512 的载体有 96×64 = 6144 块，装 64×64 = 4096 位绰绰有余；不够时缩小水印或加大载体。

### 5.3 双图靶与视觉确认

载体是一张 768×512 的色块风景图（PIL 画天空、远山和田块，叠加一层 ±4 的细颗粒纹理让系数分布接近真实照片，手法同 [[M01-MISC导论与工具箱|M01]]3.1）；水印是 64×64 的 "FLAG" 二值图，拉平成 4096 位。

```python
wm = Image.open("wm_icon.png")
wm_bits = (np.asarray(wm) > 127).astype(np.uint8).ravel()
cover = np.asarray(Image.open("cover.png").convert("RGB"))

embed_wm("cover.png", "stego_wm.png", wm_bits, delta=24)
stego = Image.open("stego_wm.png").convert("RGB")
back = extract_wm("stego_wm.png", len(wm_bits), delta=24)
print("嵌入后 PSNR = %.2f dB" % psnr(cover, np.asarray(stego)))
print("提取还原一致:", (back == wm_bits).all())
```

输出：

```
嵌入后 PSNR = 43.46 dB
提取还原一致: True
```

4096 位全部还原。把位阵按 64×64 摆回图像、裁到文字区域打印（`#` 是笔画），肉眼确认内容：

```python
def show_wm(bits):
    """把 64x64 的水印位阵裁到文字区域，2x2 合并打印"""
    m = bits.reshape(64, 64)
    ys, xs = np.where(m == 1)
    for i in range(max(ys.min() - 4, 0), min(ys.max() + 5, 64), 2):
        line = ""
        for j in range(max(xs.min() - 4, 0), min(xs.max() + 5, 64), 2):
            line += "#" if m[i:i + 2, j:j + 2].any() else "."
        print(line)

show_wm(back)
```

输出：

```
..............................
..............................
..#####.##.......##....####...
..#.....##......###...##..##..
..#.....##......#.##.##....#..
..#####.##.....##.##.##.......
..#.....##.....#####.##..###..
..#.....##.....#...####...##..
..#.....########...##.######..
..#.....########....#..###.#..
..............................
..............................
```

FLAG 四个字母与 wm_icon.png 里的原图一致。

### 5.4 强度 Δ 的取舍

Δ 同时决定两件事：改动的可见度（画质）与提取的容错半径。==系数允许漂移 Δ/2 而奇偶不变==——Δ 越大容错越强，画质越差。画质用峰值信噪比（PSNR）量化：

$$\mathrm{PSNR} = 10 \cdot \log_{10}\left(\frac{255^2}{\mathrm{MSE}}\right),\qquad \mathrm{MSE} = \frac{1}{H \times W}\sum_{x,y}\left(I(x,y) - I'(x,y)\right)^2 \tag{5.1}$$

拿两种 Δ 各嵌一遍，分别从无损 PNG 和 JPEG quality=75 重存后的图里提取：

```python
for delta in (8, 24):
    embed_wm("cover.png", "st_tmp.png", wm_bits, delta)
    st = np.asarray(Image.open("st_tmp.png").convert("RGB"))
    acc = (extract_wm("st_tmp.png", len(wm_bits), delta) == wm_bits).mean()
    Image.open("st_tmp.png").save("st_tmp.jpg", quality=75)
    acc_j = (extract_wm("st_tmp.jpg", len(wm_bits), delta) == wm_bits).mean()
    print(f"delta={delta:<3} PSNR={psnr(cover, st):.2f} dB  "
          f"PNG 提取一致率 {acc:.4f}   JPEG q75 重存后 {acc_j:.4f}")
```

输出：

```
delta=8   PSNR=44.11 dB  PNG 提取一致率 1.0000   JPEG q75 重存后 0.9285
delta=24  PSNR=43.46 dB  PNG 提取一致率 1.0000   JPEG q75 重存后 0.9998
```

两种 Δ 在无损 PNG 上都能 100% 还原。Δ=8 画质略好（PSNR 高 0.65 dB），但 JPEG q75 重存后丢了约 7% 的位——对 64×64 的图就是近三百个像素点被翻转，水印出现雪花；Δ=24 牺牲不到 1 dB，重存后 4096 位只错 1 位。

> [!warning] Δ 太小等于没写
> YCbCr 与 RGB 互转加像素取整，会让系数漂移典型在 ±2 上下（个别块更大）。Δ 必须显著大于这个量：同一组资产把 Δ 降到 2，无损 PNG 的提取一致率只有 0.5134——一半的位是错的，跟没藏一样。经验值从 Δ=12 起步，按画质与抗压缩需求上调。

## 6. blind_watermark 库

手撕 QIM 是最小可用的频域水印；成熟的库在变换与嵌入上做得更细。blind_watermark（`pip install blind-watermark`）走 DWT-DCT-SVD 三级变换：图像先做小波变换，再分块 DCT，把比特写进块奇异值里——设计目标就是抗压缩这类处理，鲁棒性比单系数 QIM 高一档，是 CTF 里最常见的盲水印库。

嵌入三步：建 WaterMark 对象、读载体、读水印、embed。两个口令参数保持默认即可，但==嵌入与提取两端必须给同一组值==：

```python
import os
os.environ["OPENCV_LOG_LEVEL"] = "ERROR"  # 压掉库内部写图时的 OpenCV 深度回退警告

import blind_watermark
blind_watermark.bw_notes.close()          # 关闭首次运行的一次性提示
from blind_watermark import WaterMark

wm2d = np.asarray(Image.open("wm_icon.png")) > 127     # 64x64 二值真值

bwm = WaterMark(password_img=1, password_wm=1)
bwm.read_img("cover.png")                 # 载体 768x512
bwm.read_wm("wm_icon.png")                # 水印 64x64 二值图
bwm.embed("bw_out.png")
print("水印位数 =", len(bwm.wm_bit))
```

输出：

```
水印位数 = 4096
```

提取时==必须知道水印尺寸==：`wm_shape` 用于把取出的比特序列 reshape 回图像，错了就是一片雪花。extract 的返回值就是还原出的水印数组：

```python
bwm2 = WaterMark(password_img=1, password_wm=1)
ext = bwm2.extract("bw_out.png", wm_shape=(64, 64), out_wm_name="bw_ext.png")
ext = np.asarray(ext)
print("返回数组 shape =", ext.shape)
print("提取一致率:", ((ext > 127) == wm2d).mean())

ys, xs = np.where(wm2d)
for i in range(ys.min() - 4, ys.max() + 5, 2):
    line = ""
    for j in range(xs.min() - 4, xs.max() + 5, 2):
        line += "#" if ext[i:i + 2, j:j + 2].max() > 127 else "."
    print(line)
```

输出：

```
返回数组 shape = (64, 64)
提取一致率: 1.0
..............................
..............................
..#####.##.......##....####...
..#.....##......###...##..##..
..#.....##......#.##.##....#..
..#####.##.....##.##.##.......
..#.....##.....#####.##..###..
..#.....##.....#...####...##..
..#.....########...##.######..
..#.....########....#..###.#..
..............................
..............................
```

与手撕版同一张 FLAG。库里还支持字符串水印：`read_wm("flag{...}", mode='str')` 嵌入、`extract(..., wm_shape=位数, mode='str')` 取回。

最后是必踩的坑——把带水印的图存成 JPEG：

```python
for q in (95, 75):
    Image.open("bw_out.png").convert("RGB").save(f"bw_out_q{q}.jpg", quality=q)
    w = WaterMark(password_img=1, password_wm=1)
    extj = np.asarray(w.extract(f"bw_out_q{q}.jpg", wm_shape=(64, 64), out_wm_name="bw_ext_j.png"))
    print(f"quality={q}  重存后提取一致率: {((extj > 127) == wm2d).mean():.4f}")
```

输出：

```
quality=95  重存后提取一致率: 0.9893
quality=75  重存后提取一致率: 0.9775
```

一致率不再是从无损容器里读出的 1.0：quality=95 时 4096 个像素点里 44 个被翻转，水印出现肉眼可见的噪点；quality=75 时错到 92 个。质量越低毁得越狠。==带水印的图一律用 PNG 做容器==，这也是题面给"水印图"时的默认判断。

> [!note] 库也有容量上限
> 库要求载体块数严格多于水印位数，超出时 embed 直接报溢出。512×512 的载体最多容纳 4095 位——64×64 的水印恰好塞不进去，本章的载体才做成 768×512。报这种错就把载体放大一号，或把水印缩小。

## 7. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| stegseek 报 `could not open the wordlist "/usr/share/wordlists/rockyou.txt"` | 没给字典参数时它默认找这个路径。显式指定：`stegseek stego.jpg 字典路径`；rockyou 从 Kali 的 /usr/share/wordlists（gz 解压）或 GitHub 弱口令字典仓库获取 |
| steghide embed 报 `the cover file is too short to embed the data` | 容量不够：载荷太大或载体质量太低（2.2 的容量表）。换更小的载荷、更高质量/更大的载体，确认压缩没被 `-Z` 关掉；提取端报 could not extract any data 才是口令错或不是 steghide 嵌的 |
| steghide info 永远不报 embedded file | info 对"没货"和"口令错"给一模一样的报错（2.3 节）。报出 embedded file 才算有货；确认有货靠 stegseek 爆破命中或出题人提示 |
| blind_watermark extract 出来是雪花 | 两头 wm_shape 不一致（reshape 对不上），或图被存成 JPEG（见第 6 节）。wm_shape 用嵌入时的水印尺寸；容器一律 PNG |
| 手撕 QIM 提取一多半是错的 | Δ 太小（低于像素取整噪声，5.4 的警告）或图被再压缩/缩放过——缩放会挪动 8×8 网格，块对不上原位置就无解了。Δ 从 12 起步 |
| zsteg 扫 JPEG 一个输出都没有 | 正常：zsteg 只扫 PNG/BMP 这类无损容器的位平面，JPEG 里没有像素可扫。JPEG 的路数是本章的 DCT 工具族 |

## 8. 配套练习与延伸阅读

配套练习：

1. 把 2.2 的容量实验换一张自己的照片重跑：三档质量的容量表跟图的细节丰富程度对得上吗？细节越多的图，可用系数是不是越满。
2. 造靶互测：用 steghide 把一个 flag 塞进 JPEG（口令自定），字典里混入正确口令交给同学，看对方几步破出来；再只给 5 行字典重试一次，体会字典质量比字典大小更重要。
3. 手撕 QIM 换写入位置：把 `POS` 从 (4, 2) 改成 (1, 1)（低频）和 (7, 7)（高频）各跑一遍 5.4 的对照表，用 [[M03-文件格式深拆II-JPEG与GIF|M03]]的能量集中现象解释 PSNR 与 JPEG 存活率的变化。
4. 用 blind_watermark 的字符串水印走一圈：`read_wm("flag{...}", mode='str')` 嵌入，`extract(..., wm_shape=位数, mode='str')` 取回，确认 flag 原样回来。

练习场：

- [[01-练习平台索引|练习平台索引]]：MISC 分区里 DCT 隐写与盲水印各有对应题目，按本章流程逐题过
- [[03-工具清单|工具清单]]：steghide、stegseek、blind_watermark 的安装方式与同类替代

延伸阅读：

- Hetzl 与 Mutzel 的论文 A Graph-Theoretic Approach to Steganography：steghide 在系数对之间做交换以压低改动量的出处
- Westfeld 与 Pfitzmann 的 F5 论文：矩阵编码的原始设计
- blind_watermark 仓库（github.com/guofei9987/blind_watermark）：DWT-DCT-SVD 流程与参数说明
- [[M03-文件格式深拆II-JPEG与GIF|M03]]：DCT、量化表与 zigzag 的字节级地基
- [[M05-图片隐写I-LSB与位平面|M05]]：空域 LSB 全解，与本章对照着读
- [[M08-音频隐写|M08]] 预告：steghide 对 WAV/AU 用同一套命令，音频上的口令隐写在那一章展开
