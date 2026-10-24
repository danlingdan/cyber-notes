---
chapter: MISC
section: 文件格式深拆 II：JPEG 与 GIF
order: 803
tags:
  - CTF
  - MISC
  - 文件格式
publish: true
---

# M03 文件格式深拆 II：JPEG 与 GIF
## JPEG & GIF Format Deep Dive

> [!info]- 章节信息
> **所属方向**：MISC ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[12-隐写与流量取证|12 章]] · [[03-计算机组成与数据表示|03 章]] · [[M02-文件格式深拆I-PNG全解|M02]]
> **本章目标**：把 JPEG 与 GIF 两种格式拆到字节级——JPEG 会读段结构、认 COM 与 APPn、区分基线与渐进式、看懂 DCT 与量化；GIF 会读块结构、拆帧、读帧延迟、带延迟重组。[[12-隐写与流量取证|12 章]]讲过的魔数、补头补尾、binwalk 分离、exiftool、steghide 不再重讲，需要时直接引用。

## 1. JPEG 段结构总览

[[M02-文件格式深拆I-PNG全解|M02]]拆过 PNG：一个 8 字节签名，后面全是同构的 chunk，每块自带长度和 CRC。JPEG 的组织方式不同：文件由**段**（segment）组成，段里放格式信息——版本、量化表、Huffman 表；图像数据以压缩流的形态夹在 SOS 和 EOI 之间，没有长度字段，只能按规则扫描到文件尾。

### 1.1 marker 一览

每个段以两字节 marker 开头：第一字节固定 `FF`，第二字节区分类型。常用的就这几个：

| 标记 | 字节 | 干什么 |
| ---- | ---- | ---- |
| SOI | `FF D8` | 图像开始，每个 JPEG 的第一对字节 |
| APP0 | `FF E0` | 通常存 JFIF 头（版本、密度单位） |
| APP1 | `FF E1` | 通常存 EXIF / XMP 元数据 |
| APPn | `FF E0`~`FF EF` | 应用自定义段，内容随写入方 |
| COM | `FF FE` | 注释段，内容任意，flag 常住地 |
| DQT | `FF DB` | 量化表，第 4 节展开 |
| SOF0 | `FF C0` | 基线 JPEG 帧头：精度、宽高、分量数 |
| SOF2 | `FF C2` | 渐进式 JPEG 帧头，第 3 节 |
| DHT | `FF C4` | Huffman 表 |
| DRI | `FF DD` | 定义重启间隔，之后扫描数据里定期出现 RST |
| RST0~7 | `FF D0`~`FF D7` | 重启标记，供解码出错时重新同步 |
| SOS | `FF DA` | 扫描头，其后紧跟压缩图像数据 |
| EOI | `FF D9` | 图像结束 |

### 1.2 段的通用布局

SOI、EOI、RSTn 是裸标记，后面不跟数据；其余段都是 ==`FF` + marker + 2 字节大端长度 + 数据==。长度字段把**它自身的 2 字节也算进去**，但不包括 marker 的 2 字节。读到非 SOS 的 marker 后，向前跳 `长度 - 2` 字节就是下一个 marker——除非这个 marker 是 SOS，原因见 1.4。

### 1.3 熵编码数据里的 0xFF00 填充

SOS 之后、下一个 marker 之前是**熵编码数据**（Huffman 压缩后的图像系数）。JPEG 规定：==数据里出现 `FF` 时，下一个字节必定是 `00`（转义填充）或 `D0`~`D7`（重启标记）==，解码时把这个 `00` 丢掉。反过来推：熵编码数据里不可能出现 `FF D9`，==扫描中遇到 `FF D9` 就是真正的 EOI==。

> [!warning] 最常见的解析器 bug
> 把 SOS 当普通段处理：读完长度就接着读下一个"段"。SOS 的长度只覆盖扫描头那十几个字节，后面是成千上万字节的压缩数据，里面到处是伪 `FF` 序列，逐段读必然错位。正确做法是进 SOS 后切换到逐字节扫描：`FF` 后面是 `00` 或 `D0`~`D7` 就继续走，是其他值就是下一个 marker。

### 1.4 段解析器

把上面的规则合起来，一个文件写完整个解析器。存成 `jpeg_parse.py`，第 2、3 节会 import 它：

```python
# jpeg_parse.py —— JPEG 段解析器（第 2、3 节会 import 复用）
import struct


def mname(m):
    NAMES = {0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2", 0xC4: "DHT", 0xDB: "DQT",
             0xDD: "DRI", 0xDA: "SOS", 0xD9: "EOI", 0xFE: "COM"}
    if m in NAMES:
        return NAMES[m]
    if 0xE0 <= m <= 0xEF:
        return f"APP{m - 0xE0}"
    return f"FF{m:02X}"


def parse_jpeg(data):
    """返回 [(marker 偏移, 标记名, payload 字节)]；SOI/EOI 的 payload 为空"""
    segs = []
    assert data[:2] == b"\xff\xd8"                # SOI
    segs.append((0, "SOI", b""))
    pos = 2
    while pos < len(data):
        while data[pos] == 0xFF:                  # marker 前允许有填充 FF
            pos += 1
        m = data[pos]
        pos += 1
        if m == 0xD9:                             # EOI：解析终点
            segs.append((pos - 1, "EOI", b""))
            return segs
        ln = struct.unpack(">H", data[pos:pos + 2])[0]
        payload = data[pos + 2:pos + ln]
        segs.append((pos - 1, mname(m), payload))
        pos += ln
        if m == 0xDA:                             # SOS 之后是熵编码数据
            while pos + 1 < len(data):
                nxt = data[pos + 1]
                # FF 00 是填充，FF D0~D7 是重启标记，都不算真 marker
                if data[pos] == 0xFF and nxt != 0x00 and not 0xD0 <= nxt <= 0xD7:
                    break                         # 真 marker：交回外层循环
                pos += 1
    return segs


def describe(name, p):
    if name in ("SOI", "EOI"):
        return ""
    if name == "APP0":
        return "JFIF" if p[:4] == b"JFIF" else "?"
    if name == "APP1":
        return p[:4].rstrip(b"\x00").decode(errors="replace")
    if name == "COM":
        return f"注释 {p!r}"
    if name == "DQT":
        ids, i = [], 0
        while i < len(p):
            ids.append(p[i] & 0x0F)
            i += 1 + 64 * (1 if p[i] >> 4 == 0 else 2)
        return "量化表 id " + "、".join(map(str, ids))
    if name in ("SOF0", "SOF1", "SOF2"):
        h, w = struct.unpack(">HH", p[1:5])
        return f"{p[0]}bit {p[5]} 分量 {w}x{h}"
    if name == "DHT":
        n, i = 0, 0
        while i < len(p):
            i += 1 + 16 + sum(p[i + 1:i + 17])
            n += 1
        return f"{n} 张 Huffman 表"
    if name == "SOS":
        return f"{p[0]} 个分量，之后进入扫描数据"
    return ""


if __name__ == "__main__":
    from PIL import Image

    # 自造一张 JPEG
    im = Image.new("RGB", (48, 32))
    px = im.load()
    for y in range(32):
        for x in range(48):
            px[x, y] = (x * 5 % 256, y * 8 % 256, (x + y) * 3 % 256)
    im.save("demo.jpg", quality=85)
    data = open("demo.jpg", "rb").read()
    print(f"demo.jpg 共 {len(data)} 字节")

    segs = parse_jpeg(data)
    print(f"{'偏移':>6}  {'标记':<6}{'长度':>4}  说明")
    for i, (off, name, p) in enumerate(segs):
        info = describe(name, p)
        if name == "SOS":                         # 顺带统计熵编码数据的长度
            sos_end = off + len(p) + 4
            info += f"，熵编码数据 {segs[i + 1][0] - sos_end} 字节"
            print(f"{off:6d}  {name:<6}{len(p) + 2:>4}  {info}")
        elif p:
            print(f"{off:6d}  {name:<6}{len(p) + 2:>4}  {info}")
        else:
            print(f"{off:6d}  {name:<6}   -  {info}")
```

输出：

```
demo.jpg 共 825 字节
    偏移  标记      长度  说明
     0  SOI      -  
     3  APP0    16  JFIF
    21  DQT     67  量化表 id 0
    90  DQT     67  量化表 id 1
   159  SOF0    17  8bit 3 分量 48x32
   178  DHT     31  1 张 Huffman 表
   211  DHT    181  1 张 Huffman 表
   394  DHT     31  1 张 Huffman 表
   427  DHT    181  1 张 Huffman 表
   610  SOS     12  3 个分量，之后进入扫描数据，熵编码数据 200 字节
   824  EOI      -  
```

逐行读这张表：两张 DQT（亮度、色度各一张）；SOF0 里的"3 分量"——JPEG 先把 RGB 转成 YCbCr，亮度和两个色度分量各自编码；4 张 DHT 按 DC/AC × 亮度/色度分成四张；SOS 只占 12 字节，其后 200 字节才是扫描数据本体；EOI 收尾。825 字节里段占了六百多，图越小"说明书"比重越高，图越大压缩数据的比重越大。段没有 CRC，哪一段被改坏都不会立刻报错——排查段损坏就用这个解析器看长度和偏移是否连续。

## 2. COM 注释段与 APPn

COM 段是 JPEG 里唯一"内容随便写"的段：`FF FE` + 大端长度 + 任意字节。出题人往里塞 flag、塞提示、塞下一层附件都常见。[[12-隐写与流量取证#5.2 EXIF：图片的简历|12 章 5.2]]里 `exiftool -Comment=...` 写入 JPEG 时，写进文件的就是一个 COM 段。

造靶：PIL 存一张图，把 COM 段手工拼进字节流（插在 APP0 之后），再用第 1 节的解析器和 exiftool 各读一遍：

```python
# b_com.py —— 手工插入 COM 段，再对照 exiftool
import struct
import subprocess
from jpeg_parse import parse_jpeg

data = open("demo.jpg", "rb").read()          # 第 1 节造的 demo.jpg

com = b"flag{in_com_segment}"
seg = b"\xff\xfe" + struct.pack(">H", len(com) + 2) + com   # marker + 大端长度 + 内容
app0 = data.find(b"\xff\xe0")                               # APP0 起始偏移
app0_end = app0 + 2 + struct.unpack(">H", data[app0 + 2:app0 + 4])[0]
com_jpg = data[:app0_end] + seg + data[app0_end:]           # 插在 APP0 之后
open("demo_com.jpg", "wb").write(com_jpg)
print(f"插入 COM 段 {len(seg)} 字节，位置：APP0 之后（偏移 {app0_end}）")

for off, name, p in parse_jpeg(com_jpg):
    if name == "COM":
        print(f"解析器读到 COM：偏移 {off}，长度 {len(p) + 2}，内容 {p!r}")

out = subprocess.run(["exiftool", "-Comment", "demo_com.jpg"],
                     capture_output=True, text=True).stdout
print(out.strip())
```

输出：

```
插入 COM 段 24 字节，位置：APP0 之后（偏移 20）
解析器读到 COM：偏移 21，长度 22，内容 b'flag{in_com_segment}'
Comment                         : flag{in_com_segment}
```

两条路读到同一个字符串：解析器按字节切，exiftool 按语义报。做题先 exiftool 扫一遍 Comment / Artist / Description，这是 [[12-隐写与流量取证#5.2 EXIF：图片的简历|12 章 5.2]]定下的习惯；解析器的好处是不依赖 exiftool 的字段名，段里有什么都能看到。

APP0 与 APP1 的分工一句讲清：APP0 里的 JFIF 头声明版本号和分辨率单位，几乎所有软件生成的 JPEG 都有；APP1 装 EXIF（相机、时间、GPS）或 XMP。EXIF 的字段与读法见 [[12-隐写与流量取证#5.2 EXIF：图片的简历|12 章 5.2]]。

> [!note] 元数据会被转码剥掉
> COM 和 EXIF 都住在头部段里。微信传输、截图、格式转换、PIL 重存，任何一步重编码都会把不需要的段整段剥掉。元数据里找不到东西时，先确认手里是不是出题人给的原始文件，再往下查。

## 3. 渐进式 JPEG

同一张图，JPEG 有两种编码方式：

| 方式 | 帧头 | 扫描 | 特点 |
| ---- | ---- | ---- | ---- |
| 基线（baseline） | SOF0 | 1 个 SOS，从上到下编一遍 | 兼容性最好 |
| 渐进式（progressive） | SOF2 | 多个 SOS，每个编一部分系数 | 先出轮廓再出细节 |

PIL 转存只差一个参数：`im.save("prog.jpg", progressive=True)`。下面的脚本把同一张图存成两种，用 `file` 对照、再用第 1 节解析器数扫描：

```python
# c_progressive.py —— 基线 vs 渐进式
import subprocess
from PIL import Image
from jpeg_parse import parse_jpeg

im = Image.new("RGB", (64, 48))
px = im.load()
for y in range(48):
    for x in range(64):
        px[x, y] = (x * 4 % 256, y * 5 % 256, (x + y) * 2 % 256)
im.save("base.jpg", quality=85)
im.save("prog.jpg", quality=85, progressive=True)      # 只多这一个参数

out = subprocess.run(["file", "base.jpg", "prog.jpg"],
                     capture_output=True, text=True).stdout
print(out.strip())
print()

for fn in ("base.jpg", "prog.jpg"):
    data = open(fn, "rb").read()
    segs = parse_jpeg(data)
    sof = [n for _, n, _ in segs if n.startswith("SOF")]
    scans = []
    for _, name, p in segs:
        if name == "SOS":
            k = 1 + 2 * p[0]                # 分量表之后是 Ss、Se、Ah/Al
            scans.append((p[k], p[k + 1], p[k + 2] >> 4, p[k + 2] & 0xF))
    print(f"{fn}: SOF = {'+'.join(sof)}，SOS 扫描 ×{len(scans)}")
    if len(scans) > 1:
        for i, (ss, se, ah, al) in enumerate(scans, 1):
            print(f"    扫描 {i}: Ss={ss} Se={se} Ah={ah} Al={al}")
```

输出：

```
base.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 64x48, components 3
prog.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, progressive, precision 8, 64x48, components 3

base.jpg: SOF = SOF0，SOS 扫描 ×1
prog.jpg: SOF = SOF2，SOS 扫描 ×10
    扫描 1: Ss=0 Se=0 Ah=0 Al=1
    扫描 2: Ss=1 Se=5 Ah=0 Al=2
    扫描 3: Ss=1 Se=63 Ah=0 Al=1
    扫描 4: Ss=1 Se=63 Ah=0 Al=1
    扫描 5: Ss=6 Se=63 Ah=0 Al=2
    扫描 6: Ss=1 Se=63 Ah=2 Al=1
    扫描 7: Ss=0 Se=0 Ah=1 Al=0
    扫描 8: Ss=1 Se=63 Ah=1 Al=0
    扫描 9: Ss=1 Se=63 Ah=1 Al=0
    扫描 10: Ss=1 Se=63 Ah=1 Al=0
```

`file` 输出里 `baseline` 与 `progressive` 直接标明形态；解析器数出基线 1 个扫描、渐进式 10 个。每个 SOS 扫描头尾部有三个参数：Ss/Se 是本次扫描编哪些频率系数（**谱选择**）——扫描 1 只有 `Ss=0 Se=0`，即只编 DC 系数，等于全图的低分辨率版；Ah/Al 是**逐次逼近**的位平面序号，先编高位再补低位。10 个扫描拼起来才是完整图像，[[M02-文件格式深拆I-PNG全解|M02]]里"读一张表就能定位"的 PNG 便利在 JPEG 的扫描数据这里不存在。

> [!info]- 为什么出题人爱用渐进式
> 浏览器对渐进式 JPEG 边下载边渲染，画面从模糊到清晰分十层出现，完整显示需要全部 10 个扫描都解码。三个可利用点：① 有的查看器、老版本解码库只渲染第一个扫描，画面永远糊——数据其实都在后续扫描里，别急着判定文件损坏；② 少数工具对 SOF2 直接报错打不开，`file` 的 `progressive` 字样是第一提示；③ "能打开"和"能完整解码"可以是两件事，只破坏后期扫描时，简陋查看器毫无察觉。

## 4. DCT 域：压缩与隐写的藏身处

JPEG 的编码管线一行走完：RGB 转 YCbCr → 8×8 分块 → 每块做 DCT → 量化 → zigzag 排序 → Huffman 熵编码。存进文件的是最后一步的产物，==JPEG 文件里没有像素，只有系数==。这句话决定了 JPEG 隐写与 PNG 隐写的分野，本节末尾收束。

### 4.1 DCT：把 8×8 像素块拆成 64 个频率系数

DCT（离散余弦变换）把一个 8×8 像素块表示成 64 个频率分量的叠加：

$$F(u,v) = \frac{1}{4}C(u)C(v)\sum_{x=0}^{7}\sum_{y=0}^{7} f(x,y)\cos\frac{(2x+1)u\pi}{16}\cos\frac{(2y+1)v\pi}{16},\quad C(0)=\frac{1}{\sqrt{2}},\ C(k)=1 \tag{4.1}$$

不用手推：`scipy.fft.dct(type=2, norm='ortho')` 沿行、列各做一次就是正交归一的 2D DCT，与式 (4.1) 等价。拿一个平滑的 8×8 小坡跑一遍：

```python
# d_dct.py —— 8x8 块的 DCT 与能量集中
import numpy as np
from scipy.fft import dct

im = [[128 + 2 * x + y for x in range(8)] for y in range(8)]   # 一个平滑小坡
block = np.asarray(im, dtype=float) - 128                      # JPEG 里像素先减 128
coef = dct(dct(block, axis=0, type=2, norm="ortho"), axis=1, type=2, norm="ortho")

np.set_printoptions(precision=1, suppress=True, linewidth=100)
print("8x8 像素块（已减 128）：")
print(block)
print("DCT 系数矩阵：")
print(coef)
E = coef ** 2
print(f"左上 2x2 系数的能量占比: {100 * E[:2, :2].sum() / E.sum():.1f}%")
print(f"右下 4x4 系数的能量占比: {100 * E[4:, 4:].sum() / E.sum():.2f}%")
```

输出：

```
8x8 像素块（已减 128）：
[[ 0.  2.  4.  6.  8. 10. 12. 14.]
 [ 1.  3.  5.  7.  9. 11. 13. 15.]
 [ 2.  4.  6.  8. 10. 12. 14. 16.]
 [ 3.  5.  7.  9. 11. 13. 15. 17.]
 [ 4.  6.  8. 10. 12. 14. 16. 18.]
 [ 5.  7.  9. 11. 13. 15. 17. 19.]
 [ 6.  8. 10. 12. 14. 16. 18. 20.]
 [ 7.  9. 11. 13. 15. 17. 19. 21.]]
DCT 系数矩阵：
[[ 84.  -36.4   0.   -3.8  -0.   -1.1  -0.   -0.3]
 [-18.2   0.    0.    0.    0.    0.    0.    0. ]
 [  0.    0.    0.    0.    0.    0.    0.    0. ]
 [ -1.9   0.    0.    0.    0.    0.    0.    0. ]
 [  0.    0.    0.    0.    0.    0.    0.    0. ]
 [ -0.6   0.    0.    0.    0.    0.    0.    0. ]
 [  0.    0.    0.    0.    0.    0.    0.    0. ]
 [ -0.1   0.    0.    0.    0.    0.    0.    0. ]]
左上 2x2 系数的能量占比: 99.8%
右下 4x4 系数的能量占比: 0.00%
```

64 个系数绝大多数是 0——==自然图像的能量集中在左上角低频区，高频系数接近 0==。坐标 `[0][0]` 叫 DC 系数，等于整块像素的平均值；其余 63 个叫 AC 系数，对应不同方向的"变化快慢"。变换前减 128 是 JPEG 的规定：把无符号的 0~255 平移到 -128~127 再变换。

### 4.2 量化：把小系数抹成 0

压缩的关键一步：==每个系数除以量化表里对应位置的值，再四舍五入==。量化表在低频区数值小、高频区数值大，本就接近 0 的高频系数一除一舍就变成 0，之后只需编码左上那一小撮数。质量参数改的就是这张表：质量低 → 表数值大 → 抹掉的系数多。

PIL 能把文件里的量化表读出来（`img.quantization` 属性）。对比三个质量档：

```python
# d_quant.py —— 从真实 JPEG 里读量化表
from PIL import Image
from jpeg_parse import parse_jpeg

im = Image.new("RGB", (32, 32))
px = im.load()
for y in range(32):
    for x in range(32):
        px[x, y] = (x * 8 % 256, y * 8 % 256, (x + y) * 4 % 256)

for q in (30, 75, 95):
    im.save(f"q{q}.jpg", quality=q)
    tab = Image.open(f"q{q}.jpg").quantization[0]      # 亮度量化表
    print(f"quality={q:<3} 亮度表前 8 个值（行优先）: {list(tab[:8])}")

tab = Image.open("q75.jpg").quantization
print()
print("quality=75 的亮度表完整 64 值（PIL 已排成行优先）：")
print(list(tab[0]))

# 同一张表的文件原始字节：DQT 段里按 zigzag 顺序存
for _, name, p in parse_jpeg(open("q75.jpg", "rb").read()):
    if name == "DQT" and p[0] == 0x00:
        print("DQT 段里亮度表前 8 个值（文件存储顺序，zigzag 序）:", list(p[1:9]))
        break
```

输出：

```
quality=30  亮度表前 8 个值（行优先）: [27, 18, 17, 27, 40, 66, 85, 101]
quality=75  亮度表前 8 个值（行优先）: [8, 6, 5, 8, 12, 20, 26, 31]
quality=95  亮度表前 8 个值（行优先）: [2, 1, 1, 2, 2, 4, 5, 6]

quality=75 的亮度表完整 64 值（PIL 已排成行优先）：
[8, 6, 5, 8, 12, 20, 26, 31, 6, 6, 7, 10, 13, 29, 30, 28, 7, 7, 8, 12, 20, 29, 35, 28, 7, 9, 11, 15, 26, 44, 40, 31, 9, 11, 19, 28, 34, 55, 52, 39, 12, 18, 28, 32, 41, 52, 57, 46, 25, 32, 39, 44, 52, 61, 60, 51, 36, 46, 48, 49, 56, 50, 52, 50]
DQT 段里亮度表前 8 个值（文件存储顺序，zigzag 序）: [8, 6, 6, 7, 6, 5, 8, 7]
```

quality 从 30 到 95，表数值缩到接近 1——除以 1 几乎无损，这就是"高质量"的含义。注意最后两行的对照：DQT 段的原始字节是 **zigzag（之字形）顺序**——量化后的 64 个系数按之字形从左上走到右下排成一维，低频在前高频在后，长串的 0 交给后续游程编码合并；PIL 读出后已经转回行优先，两个顺序前 8 个值不同，看到 `8,6,6,7,...` 是文件序，看到 `8,6,5,8,...` 是行优先。

### 4.3 隐写藏在系数里

==JPEG 隐写的藏身处是 DCT 系数，不是像素==。[[12-隐写与流量取证#5.3 steghide：口令隐写|12 章 5.3]]的 steghide 就在 DCT 域写入，F5、Outguess 是同一族工具——它们改的是系数矩阵。PNG 的 LSB 思路（找像素最低位）对 JPEG 无处施展：文件里根本没有像素，[[M02-文件格式深拆I-PNG全解|M02]]第 3.3 节"解压 IDAT 拿像素"的路径到这里不存在。具体工具的用法与对比在后续章节展开。

> [!info]- 逆变换与"为什么是 8×8"
> 解码端做逆 DCT（IDCT）：量化值乘回量化表（近似还原），再按式 (4.1) 的逆过程把 64 个系数合回 8×8 像素。四舍五入不可逆，所以 JPEG 是有损压缩，同一张图每重存一次质量就掉一点。块取 8×8 是标准折中：块太小压缩率差，块太大块与块的边界更明显——放大低质量 JPEG 时看到的格子，就是 8×8 块的边界。

## 5. JPEG 尾夹带与修复

### 5.1 EOI 之后粘文件

查看器读到 EOI 就停，`file` 也只解析头部段——EOI 之后粘什么都改变"还能打开"这个状态。[[12-隐写与流量取证#8.1 binwalk / foremost：分离嵌套文件|12 章 8.1]]的 binwalk 按签名扫全文件，专治这种夹带；手抠只需要一个 `rfind`：

```python
# e_tail.py —— EOI 之后粘 zip、手抠切割、补头补尾
import io
import subprocess
import zipfile

data = open("demo.jpg", "rb").read()          # 第 1 节造的 demo.jpg

# [1] 尾部粘一个 zip
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("secret.txt", "flag{hidden_after_eoi}")
zbytes = buf.getvalue()
open("demo_tail.jpg", "wb").write(data + zbytes)

out = subprocess.run(["file", "demo_tail.jpg"], capture_output=True, text=True).stdout
print(out.strip())
print(f"demo.jpg = {len(data)} 字节，粘上 zip 后 = {len(data) + len(zbytes)} 字节")

# [2] rfind 手抠切割
tail = open("demo_tail.jpg", "rb").read()
end = tail.rfind(b"\xff\xd9") + 2            # 最后一个 EOI 的下一字节
open("carved.zip", "wb").write(tail[end:])
print(f"rfind(FF D9) + 2 = {end}，其后 {len(tail) - end} 字节切出为 carved.zip")
print("carved.zip 里读出:", zipfile.ZipFile("carved.zip").read("secret.txt").decode())
print()

# [3] 补头补尾：去掉 SOI 和 EOI 再原样补回
body = data[2:-2]
open("demo_broken.jpg", "wb").write(body)
out = subprocess.run(["file", "demo_broken.jpg"], capture_output=True, text=True).stdout
print(out.strip())

fixed = b"\xff\xd8" + body + b"\xff\xd9"
open("demo_fixed.jpg", "wb").write(fixed)
out = subprocess.run(["file", "demo_fixed.jpg"], capture_output=True, text=True).stdout
print(out.strip())
print("与原文件逐字节一致:", fixed == data)
```

输出：

```
demo_tail.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 48x32, components 3
demo.jpg = 825 字节，粘上 zip 后 = 965 字节
rfind(FF D9) + 2 = 825，其后 140 字节切出为 carved.zip
carved.zip 里读出: flag{hidden_after_eoi}

demo_broken.jpg: data
demo_fixed.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 48x32, components 3
与原文件逐字节一致: True
```

尾部多了 140 字节的 zip，`file` 输出没有任何变化——它只看头部。`rfind(b"\xff\xd9") + 2` 定位最后一个 EOI 的下一字节，把后面的字节全切出来就是完整的 zip，能直接解出 secret.txt。zip 结构本身的拆法在 [[M04-压缩包全解|M04]]。

> [!warning] FF D9 可能不止一个
> `FF D9` 在单个 JPEG 的结构里唯一（1.3 节的推论），但尾部粘的内容里可能恰好有这两个字节，伪 EOI 会让 `rfind` 切多或切少。切出来的文件打不开时，改用第 1 节的解析器按结构走到 EOI（它天然不受伪 EOI 影响），或用 binwalk 列出所有签名偏移再切（[[12-隐写与流量取证#8.1 binwalk / foremost：分离嵌套文件|12 章 8.1]]）。

### 5.2 补 SOI 与 EOI

[[12-隐写与流量取证|12 章 2.2]]讲过补头补尾的通用方法，JPEG 的版本只有两行——把开头 2 字节（SOI）和结尾 2 字节（EOI）删掉，再原样补回：

```python
fixed = b"\xff\xd8" + body + b"\xff\xd9"   # body = 去掉首尾各 2 字节的中间部分
open("demo_fixed.jpg", "wb").write(fixed)
```

输出（接 5.1 脚本的后半段）：

```
demo_broken.jpg: data
demo_fixed.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 48x32, components 3
与原文件逐字节一致: True
```

`file` 对残缺文件报 `data`，补上两对字节后恢复成 JPEG，且与原文件逐字节一致。头尾都完好还打不开，就是段内部的问题，回到第 1 节的解析器逐段排查。

## 6. GIF 结构全解

GIF 的组织方式比 JPEG 平整：从头到尾一条字节流，块一个接一个，每块自带边界。==所有多字节整数都是小端==（字节序见 [[03-计算机组成与数据表示|03 章]]，PNG/JPEG 的长度字段是大端，注意切换）。

| 区块 | 大小 | 内容 |
| ---- | ---- | ---- |
| 文件头 | 6 字节 | `GIF87a` 或 `GIF89a`，[[12-隐写与流量取证\|12 章]]魔数表里的 `47 49 46 38` 就在这里 |
| 逻辑屏幕描述块 | 7 字节 | 画布宽高、全局色表标志、背景色索引、像素宽高比 |
| 全局色表 | 3×2^(N+1) 字节 | 可选，每色 3 字节 RGB |
| 块序列 | 若干 | 图像描述符 / 扩展块 |
| 结尾 | 1 字节 | `3B` |

逻辑屏幕描述块的 packed 字节是位域：bit7 是全局色表标志，bit0–2 是色表大小 N（色数 = 2^(N+1)），bit3 是排序标志，bit4–6 是颜色分辨率。宽高各占 2 字节小端，背景色索引指向全局色表，像素宽高比几乎总是 0。

块序列里有四种东西，靠前缀字节区分：

| 前缀 | 名称 | 内容 |
| ---- | ---- | ---- |
| `2C` | 图像描述符 | 帧 left/top/宽高（各 2 字节小端）+ packed（bit7 局部色表、bit6 交织、bit0–2 局部色表大小）；其后 1 字节 LZW 最小码长 + 一串数据子块 |
| `21 F9 04` | 图形控制扩展 GCE | 处置方法、延迟时间（1/100 秒）、透明色索引，作用于紧跟它的那一帧 |
| `21 FE` | 注释扩展 | 任意文本，flag 常住地 |
| `21 FF` | 应用扩展 | 自定义；最常见的 `NETSCAPE2.0` 存循环次数 |

数据子块的格式在图像和扩展里通用：==1 字节长度 + 该长度的数据，重复，直到长度字节为 0==。GCE 的延迟时间占 2 字节小端，单位 1/100 秒；透明索引只在 packed 的 bit0 为 1 时有效。`NETSCAPE2.0` 的数据是一个子块 `03 01` + 循环次数（2 字节小端，0 表示无限循环）。LZW 压缩本身不展开，解码交给 PIL/ffmpeg；要认识的是"最小码长 + 子块"这个形态，以及帧在文件里可以只占画布的一小块——left/top/宽高不是装饰，6.2 节会用到。

### 6.1 纯 Python 解析器

```python
# gif_parse.py —— 纯 Python GIF 块结构解析器（第 7 节会 import 复用）
import struct


def read_subblocks(data, pos):
    """读一串数据子块：每块 = 长度字节 + 数据，长度 0 表示结束"""
    chunks = []
    while data[pos] != 0:
        n = data[pos]
        chunks.append(data[pos + 1:pos + 1 + n])
        pos += 1 + n
    return b"".join(chunks), pos + 1


def parse_gif(data, verbose=True):
    """顺序解析 GIF 的块结构，返回每帧的延迟（单位 1/100 秒）"""
    def say(msg):
        if verbose:
            print(msg)

    assert data[:3] == b"GIF"
    ver = data[:6].decode()
    w, h = struct.unpack("<HH", data[6:10])
    packed, bg, ar = data[10], data[11], data[12]
    pos = 13
    gct = 2 ** ((packed & 0x07) + 1) if packed & 0x80 else 0
    say(f"头部: {ver}   逻辑屏幕: {w}x{h}  packed=0x{packed:02X}"
        f"（全局色表 {'有' if gct else '无'} {gct} 色）  背景色索引={bg}  像素比={ar}")
    if gct:
        say(f"偏移 0x{pos:03X}  全局色表，{gct * 3} 字节")
        pos += gct * 3

    frame, delays = 0, []
    while True:
        off = pos
        b = data[pos]
        if b == 0x3B:                                   # 结束符
            say(f"偏移 0x{off:03X}  结束符 3B")
            return delays
        if b == 0x21:                                   # 扩展块
            label = data[pos + 1]
            payload, pos = read_subblocks(data, pos + 2)
            if label == 0xF9:                           # 图形控制扩展
                pk = payload[0]
                delay = struct.unpack("<H", payload[1:3])[0]
                trans = payload[3] if pk & 1 else None
                say(f"偏移 0x{off:03X}  图形控制扩展 GCE: 处置方法={pk >> 2 & 7}"
                    f" 延迟={delay}/100 秒 透明索引={trans}")
                delays.append(delay)
            elif label == 0xFE:                         # 注释扩展
                say(f"偏移 0x{off:03X}  注释扩展: {payload!r}")
            elif label == 0xFF:                         # 应用扩展
                say(f"偏移 0x{off:03X}  应用扩展: 标识 {payload[:11]!r}"
                    f"  数据 {payload[11:]!r}")
            else:
                say(f"偏移 0x{off:03X}  扩展 0x{label:02X}: {len(payload)} 字节")
        elif b == 0x2C:                                 # 图像描述符
            left, top, iw, ih = struct.unpack("<HHHH", data[pos + 1:pos + 9])
            pk = data[pos + 9]
            pos2 = pos + 10
            if pk & 0x80:
                pos2 += 3 * 2 ** ((pk & 0x07) + 1)
            mcs = data[pos2]                            # LZW 最小码长
            lzw, pos2 = read_subblocks(data, pos2 + 1)
            say(f"偏移 0x{off:03X}  图像 #{frame}: 位置({left},{top}) {iw}x{ih}"
                f" 交织={'是' if pk & 0x40 else '否'}"
                f" 局部色表={'有' if pk & 0x80 else '无'}"
                f" | LZW 最小码长={mcs} 压缩数据 {len(lzw)} 字节")
            frame += 1
            pos = pos2
        else:
            say(f"偏移 0x{off:03X}  未知块 0x{b:02X}，停止")
            return delays


if __name__ == "__main__":
    from PIL import Image

    # 自造一个 4 帧动图
    colors = ((228, 75, 74), (55, 138, 221), (126, 188, 111), (250, 210, 90))
    frames = [Image.new("RGB", (48, 48), c) for c in colors]
    frames[0].save("demo.gif", save_all=True, append_images=frames[1:],
                   duration=50, loop=0)

    data = bytearray(open("demo.gif", "rb").read())
    print(f"demo.gif 共 {len(data)} 字节")

    # PIL 不写注释扩展，手工在结尾 3B 前插一段：21 FE + 长度字节 + 数据 + 00
    note = b"made by M03"
    comment = b"\x21\xfe" + bytes([len(note)]) + note + b"\x00"
    data = data[:-1] + comment + data[-1:]
    open("demo.gif", "wb").write(bytes(data))

    parse_gif(bytes(data))
```

输出：

```
demo.gif 共 481 字节
头部: GIF89a   逻辑屏幕: 48x48  packed=0x81（全局色表 有 4 色）  背景色索引=0  像素比=0
偏移 0x00D  全局色表，12 字节
偏移 0x019  应用扩展: 标识 b'NETSCAPE2.0'  数据 b'\x01\x00\x00'
偏移 0x02C  图形控制扩展 GCE: 处置方法=0 延迟=5/100 秒 透明索引=None
偏移 0x034  图像 #0: 位置(0,0) 48x48 交织=否 局部色表=无 | LZW 最小码长=8 压缩数据 79 字节
偏移 0x090  图形控制扩展 GCE: 处置方法=0 延迟=5/100 秒 透明索引=1
偏移 0x098  图像 #1: 位置(0,0) 48x48 交织=否 局部色表=有 | LZW 最小码长=8 压缩数据 79 字节
偏移 0x100  图形控制扩展 GCE: 处置方法=0 延迟=5/100 秒 透明索引=1
偏移 0x108  图像 #2: 位置(0,0) 48x48 交织=否 局部色表=有 | LZW 最小码长=8 压缩数据 79 字节
偏移 0x170  图形控制扩展 GCE: 处置方法=0 延迟=5/100 秒 透明索引=1
偏移 0x178  图像 #3: 位置(0,0) 48x48 交织=否 局部色表=有 | LZW 最小码长=8 压缩数据 79 字节
偏移 0x1E0  注释扩展: b'made by M03'
偏移 0x1EF  结束符 3B
```

对照前文读：`packed=0x81` → bit7 置 1（有全局色表），低 3 位是 001，色数 = 2^(1+1) = 4，与"12 字节 = 4 色 × 3 字节"吻合。应用扩展的数据 `b'\x01\x00\x00'`：首字节 01 是子块编号，后两字节是循环次数 0，即无限循环。每帧的 GCE 都在图像描述符前面——它只作用于紧跟的那一帧。帧 #0 没有透明索引，帧 #1 起出现局部色表和透明索引：PIL 为省空间把后续帧按"局部色表 + 与前一帧的差异"编码，这就是 6.2 的增量帧。

### 6.2 增量帧：处置方法

GCE 的处置方法规定"这一帧显示完，画布怎么办"：0 不指定（保留画布）、1 不处置（下一帧直接叠在当前画布上）、2 恢复背景色、3 恢复到这一帧显示之前的样子。处置方法为 0 或 1 时，后续帧可以只描述变化区域——下面造一个第二帧只改右下角 15×15 的 GIF：

```python
# h_delta.py —— 增量帧：处置方法=1 时第二帧只描述变化区域
from PIL import Image
from gif_parse import parse_gif

base = Image.new("RGB", (60, 60), (255, 255, 255))
d2 = base.copy()
d2.paste((228, 75, 74), (45, 45, 60, 60))          # 只改右下角 15x15
base.save("delta.gif", save_all=True, append_images=[d2], duration=500, disposal=1)

delays = parse_gif(open("delta.gif", "rb").read())
g = Image.open("delta.gif")
g.seek(1)
print("delta.gif 第 2 帧读出的 (5,5) 像素:", g.getpixel((5, 5)), "（左上角，第 1 帧画过）")
print("delta.gif 第 2 帧读出的 (52,52) 像素:", g.getpixel((52, 52)), "（右下角，第 2 帧才画）")
```

输出：

```
头部: GIF89a   逻辑屏幕: 60x60  packed=0x81（全局色表 有 4 色）  背景色索引=0  像素比=0
偏移 0x00D  全局色表，12 字节
偏移 0x019  图形控制扩展 GCE: 处置方法=1 延迟=50/100 秒 透明索引=None
偏移 0x021  图像 #0: 位置(0,0) 60x60 交织=否 局部色表=无 | LZW 最小码长=8 压缩数据 98 字节
偏移 0x090  图形控制扩展 GCE: 处置方法=1 延迟=50/100 秒 透明索引=2
偏移 0x098  图像 #1: 位置(45,45) 15x15 交织=否 局部色表=有 | LZW 最小码长=8 压缩数据 26 字节
偏移 0x0CB  结束符 3B
delta.gif 第 2 帧读出的 (5,5) 像素: (255, 255, 255) （左上角，第 1 帧画过）
delta.gif 第 2 帧读出的 (52,52) 像素: (228, 75, 74) （右下角，第 2 帧才画）
```

解析器显示第二帧在文件里只有 15×15、位于 (45,45)；PIL 读第二帧时自动把第一帧的画布叠上来，左上角读到白色、右下角读到红色。==叠加是读帧的一方做的，文件里的帧本身是残缺的==。

> [!info]- "只有第一帧有内容"的真相
> 不少在线拆帧工具和小脚本不做画布叠加，把每帧的图像描述符单独渲染：增量帧变成一块小图或一张透明图，看起来"GIF 只有第一帧有内容，后面全是空白"。不是文件坏了，是工具没做叠加。用 PIL（新版自动处理）或 ffmpeg 拆帧就正常；手工处理时按图像描述符的 left/top/宽高把帧贴回画布即可。

## 7. 拆帧、帧延迟与合成

下面三段是同一个脚本 `g_frames.py` 的三个部分，依次处理：帧延迟靶、PIL 拆帧、ffmpeg 与往返重组。

### 7.1 帧延迟靶

GIF 每帧的显示时长写在 GCE 里，单位 1/100 秒——一个现成的数值通道。造靶：15 帧，第 i 帧的 duration 设为 `ord(FLAG[i]) × 10` 毫秒，GIF 里落盘的延迟值恰好是 `ord(FLAG[i])`：

```python
# g_frames.py 第 1 部分 —— 帧延迟靶：每帧 duration = ord(c) * 10 毫秒
import os
import shutil
import subprocess
from PIL import Image, ImageSequence
from gif_parse import parse_gif

FLAG = "flag{g1f_d3lay}"
frames = [Image.new("RGB", (48, 48), ((i * 37) % 256, (i * 71) % 256, (i * 113) % 256))
          for i in range(len(FLAG))]
frames[0].save("flag.gif", save_all=True, append_images=frames[1:],
               duration=[ord(c) * 10 for c in FLAG], loop=0)
delays = parse_gif(open("flag.gif", "rb").read(), verbose=False)
print(f"flag.gif 帧延迟序列（1/100 秒）: {delays}")
print("逐帧 chr 拼回:", "".join(chr(d) for d in delays))
print()
```

输出：

```
flag.gif 帧延迟序列（1/100 秒）: [102, 108, 97, 103, 123, 103, 49, 102, 95, 100, 51, 108, 97, 121, 125]
逐帧 chr 拼回: flag{g1f_d3lay}
```

`parse_gif(..., verbose=False)` 关掉打印、只取返回的延迟序列，102 是 `f`、108 是 `l`，逐帧 `chr` 拼回 flag。拆帧之前，延迟就已经是答案——==先读元信息，再拆帧==。

> [!warning] 读 delay 必须在拆帧之前
> PNG/JPG 帧没有时长字段，delay 只活在 GIF 结构里，拆成 PNG 的那一刻它就没了。拿到动图先读 delay，再动手拆。

### 7.2 PIL：n_frames、seek、ImageSequence

PIL 侧的入口就三个：`g.n_frames` 给帧数，`g.seek(i)` 跳到第 i 帧，`ImageSequence.Iterator` 把 seek 循环封装成迭代器；当前帧的延迟在 `g.info["duration"]`（毫秒，等于 GCE 延迟 × 10）。迭代一遍，延迟读走，帧顺手存 PNG：

```python
# g_frames.py 第 2 部分 —— PIL 拆帧：ImageSequence 迭代；第 3 帧单独存 PNG
g = Image.open("flag.gif")
print("n_frames =", g.n_frames)
frames, durs = [], []
for frame in ImageSequence.Iterator(g):
    durs.append(frame.info["duration"])
    frames.append(frame.convert("RGB"))
frames[2].save("frame003.png")
print("每帧 duration（毫秒）:", durs)
print("除以 10 还原 chr:", "".join(chr(d // 10) for d in durs))
print(f"第 3 帧已存为 frame003.png（{os.path.getsize('frame003.png')} 字节）")
print()
```

输出：

```
n_frames = 15
每帧 duration（毫秒）: [1020, 1080, 970, 1030, 1230, 1030, 490, 1020, 950, 1000, 510, 1080, 970, 1210, 1250]
除以 10 还原 chr: flag{g1f_d3lay}
第 3 帧已存为 frame003.png（132 字节）
```

### 7.3 ffmpeg：拆帧与合成的延迟陷阱

ffmpeg 两条命令搞定拆帧与合成，但有两个坑：拆帧默认按 25 帧/秒重采样，长延迟的帧会被复制成多张 PNG；重合成用固定 `-framerate`，所有帧延迟被拍平：

```python
# g_frames.py 第 3 部分 —— ffmpeg 拆帧与合成、PIL 往返重组
# [3] ffmpeg 拆帧：默认 25fps 重采样 vs 逐帧直出
for d in ("frames", "frames2"):
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", "flag.gif",
                "frames/%03d.png"], check=True)
print("ffmpeg -i flag.gif frames/%03d.png   ->", len(os.listdir("frames")), "张 PNG")
subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", "flag.gif", "-vsync", "0",
                "frames2/%03d.png"], check=True)
print("ffmpeg 加 -vsync 0（每 GIF 帧 1 张）  ->", len(os.listdir("frames2")), "张 PNG")
print()

# [4] 固定 10 fps 重合成：延迟被拍平
subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", "10",
                "-i", "frames2/%03d.png", "rebuilt.gif"], check=True)
out = subprocess.run(["file", "rebuilt.gif"], capture_output=True, text=True).stdout
print(out.strip())
delays = parse_gif(open("rebuilt.gif", "rb").read(), verbose=False)
print("rebuilt.gif 帧延迟:", delays[:8], f"... 共 {len(delays)} 帧，取值只有 {set(delays)}")
print("chr 拼接结果:", repr("".join(chr(d) for d in delays)))
print()

# [5] PIL 往返重组：把 duration 一起带走
frames[0].save("rt.gif", save_all=True, append_images=frames[1:],
               duration=durs, loop=0)
delays = parse_gif(open("rt.gif", "rb").read(), verbose=False)
print("rt.gif 帧延迟:", delays)
print("与原 GIF 的延迟一致:", delays == [d // 10 for d in durs])
print("chr 拼接结果:", "".join(chr(d) for d in delays))
```

输出：

```
ffmpeg -i flag.gif frames/%03d.png   -> 289 张 PNG
ffmpeg 加 -vsync 0（每 GIF 帧 1 张）  -> 15 张 PNG

rebuilt.gif: GIF image data, version 89a, 48 x 48
rebuilt.gif 帧延迟: [10, 10, 10, 10, 10, 10, 10, 10] ... 共 15 帧，取值只有 {10}
chr 拼接结果: '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'

rt.gif 帧延迟: [102, 108, 97, 103, 123, 103, 49, 102, 95, 100, 51, 108, 97, 121, 125]
与原 GIF 的延迟一致: True
chr 拼接结果: flag{g1f_d3lay}
```

同一个 15 帧的 GIF：默认参数拆出 289 张 PNG（25fps 采样，1 秒多的一帧被复制成二十多张），加 `-vsync 0` 才是一帧一张的 15 张。固定 10fps 重合成的 rebuilt.gif 里延迟全变成 10，`chr` 拼出来是一串换行——flag 被合成步骤抹掉了。PIL 往返重组把 duration 列表一起传给 `save()`，rt.gif 的延迟与原 GIF 完全一致。

> [!note] 路线选择
> flag 藏在某一帧画面里 → 拆帧看图（`-vsync 0` 或 PIL）；flag 编码在延迟、注释、色表里 → 别拆帧，直接解析结构（第 6 节的解析器、PIL 的 info 字典）；要交付还原的动图 → PIL 带 duration 重存，不要用固定 framerate 的 ffmpeg 合成。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| JPEG 打不开，`file` 报 `data` | 头或尾被改被删。补 `FF D8` 开头、`FF D9` 结尾，方法同 [[12-隐写与流量取证\|12 章 2.2]]；内部段没坏就能打开 |
| JPEG 打得开但下半截灰屏、截断 | 扫描数据被截断，EOI 缺失或位置不对。用第 1 节解析器看 EOI 偏移是否等于文件长度减 2 |
| 渐进式 JPEG 在某些工具里打不开、或画面永远模糊 | 多扫描格式，老库只解码第一个扫描（第 3 节）。换新版解码库或浏览器确认；后续扫描里可能有内容 |
| 尾部切出来的 zip 打不开 | 文件里有伪 EOI（尾上粘了别的内容）。改用解析器按结构走到 EOI 再切，或 binwalk 看签名偏移（[[12-隐写与流量取证#8.1 binwalk / foremost：分离嵌套文件\|12 章 8.1]]） |
| 自写解析器跑到半路报 IndexError | 熵编码没扫完就撞上文件尾，或把伪 `FF` 序列当了 marker——检查 SOS 分支是否按 1.4 的规则处理 `FF 00` 与 RSTn |
| GIF 拆帧后 delay 丢了 | delay 只活在 GIF 结构里，PNG/JPG 帧没有时长。拆帧前用 PIL 的 `info["duration"]` 或解析器读走（7.1 的警告） |
| GIF 拆出来只有第一帧有内容 | 处置方法 0/1 的后续帧是增量，工具没做画布叠加（6.2 节）。换 PIL/ffmpeg，或按描述符的 left/top/宽高手工贴回画布 |
| GIF 某几帧颜色不对、发灰 | 帧描述符 bit7=1 的帧要用它自己的局部色表，错拿全局色表解析就串色；PNG 转 GIF 是 256 色量化，颜色变少属于正常损耗 |
| COM/EXIF 字段读不到了 | 文件被微信、截图、格式转换重编码，头部段被剥掉（第 2 节）。找出题人给的原始文件 |
| steghide 提取 JPEG 失败 | 口令错或不是 steghide 嵌的。先 `steghide info` 探测，字典攻击用 stegseek（[[12-隐写与流量取证#5.3 steghide：口令隐写\|12 章 5.3]]）；PNG 容器不走这条路 |

## 9. 配套练习与延伸阅读

配套练习：

1. 把第 1 节解析器的目标换成一张手机拍摄的照片：数 APPn 段、读 SOF0 的宽高、看有没有 COM；再把 demo.jpg 用 `quality=20` 重存一次，对比 DQT、DHT 与熵编码数据长度的变化。
2. 用第 2 节的方法把一段提示写进 COM 段发给同学；再用 6.1 的写法把同一段话写进 GIF 注释扩展——两种容器的注释段都亲手插入并读回一次。
3. 同一张图存基线和渐进式各一份，删掉文件名后缀，只用 `file` 和第 1 节解析器把它们区分开，并数出渐进式的扫描数。
4. 造一个帧延迟靶（7.1）丢给同学，附一张提示图，图上只写"duration × 10 ms"。如果他先拆了帧再找 flag，让他对照 7.1 的警告框复盘。
5. 三层尾：JPEG + zip + 一张完整小 JPEG 粘在一起，先用 `rfind` 切，再用解析器切，对比两个结果——把 5.1 警告框的内容走一遍。

练习场：

- [[01-练习平台索引|练习平台索引]]：MISC 分区按工具与套路分类，本章每种手法都有对应题目
- [[03-工具清单|工具清单]]：exiftool、binwalk、steghide、ffmpeg 与 PIL 的安装方式与同类替代

延伸阅读：

- ITU-T T.81（JPEG 标准）：段语法、DCT、量化与 Huffman 编码的权威定义，附录 K 有示例量化表
- ITU-T T.871（JFIF 规范）：APP0 段的版本与密度字段的准确定义
- W3C 存档的 GIF89a 规范：块结构、GCE、应用扩展与交织显示的出处
- [[12-隐写与流量取证#5.2 EXIF：图片的简历|12 章 5.2]]：EXIF 与 Comment 字段的元数据读法
- [[12-隐写与流量取证#5.3 steghide：口令隐写|12 章 5.3]]：steghide 在 JPEG/WAV 上的用法
- [[12-隐写与流量取证#8.1 binwalk / foremost：分离嵌套文件|12 章 8.1]]：签名扫描与自动分离
- [[M02-文件格式深拆I-PNG全解|M02]]：PNG chunk 与 CRC 修复，与本章"段无校验"的 JPEG 对照
- [[M04-压缩包全解|M04]]：本章尾部粘的 zip、7z 的完整拆法
