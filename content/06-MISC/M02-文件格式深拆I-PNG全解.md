---
chapter: MISC
section: 文件格式深拆 I：PNG 全解
order: 802
tags:
  - CTF
  - MISC
  - 文件格式
publish: true
---

# M02 文件格式深拆 I：PNG 全解
## PNG Format Deep Dive

> [!info]- 章节信息
> **所属方向**：MISC ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[12-隐写与流量取证|12 章]] · [[03-计算机组成与数据表示|03 章]] · [[M01-MISC导论与工具箱|M01]]
> **本章目标**：把 PNG 拆到字段级——IHDR 的十三个字节逐字段读；chunk 类型名的命名规则、辅助块的手造与解析；任意 chunk 的 CRC 定位与修复；宽高爆破完整脚本；APNG 的三种帧块与抽帧；IEND 之后夹带物的精确切割。[[12-隐写与流量取证|12 章 3 节]]讲过的 chunk 四字段布局、IHDR/IDAT/IEND 三件套、逐块解析脚本、zlib 解 IDAT 不再重讲，需要时直接引用。

## 1. IHDR 逐字段全解

[[12-隐写与流量取证|12 章 3 节]]给出了 PNG 的骨架：8 字节签名 + 一串 chunk，每块四段（长度/类型/数据/CRC），必备三件套 IHDR、IDAT、IEND。本节把骨架的第一块拆到字节：IHDR 数据区固定 13 字节，每个字节都有明确含义，MISC 题里大量手段（改宽高、改颜色类型、造假块）都落在这 13 字节上。

先造一张贯穿全章的样本图，并读出 IHDR：

```python
# ihdr_fields.py —— 造 demo.png 并逐字段读 IHDR
import struct
from PIL import Image, ImageDraw

im = Image.new("RGB", (64, 48), (252, 252, 251))
d = ImageDraw.Draw(im)
d.rectangle([4, 4, 30, 22], fill=(55, 138, 221))     # 蓝块
d.rectangle([34, 10, 60, 26], fill=(226, 75, 74))    # 红块
d.rectangle([12, 28, 44, 44], fill=(126, 188, 111))  # 绿块
im.save("demo.png")

png = open("demo.png", "rb").read()
print(f"demo.png 共 {len(png)} 字节")
print("IHDR 数据区 13 字节:", png[16:29].hex(" "))

w, h = struct.unpack(">II", png[16:24])
bd, ct, comp, filt, inter = png[24:29]
print(f"宽={w}  高={h}  位深={bd}  颜色类型={ct}  压缩方法={comp}  滤波方法={filt}  交织方法={inter}")

pos = 8
while pos < len(png):
    ln = struct.unpack(">I", png[pos:pos+4])[0]
    t = png[pos+4:pos+8].decode()
    print(f"  偏移 {pos:>3}  {t:<5} 数据 {ln} 字节")
    pos += 12 + ln
```

输出：

```
demo.png 共 231 字节
IHDR 数据区 13 字节: 00 00 00 40 00 00 00 30 08 02 00 00 00
宽=64  高=48  位深=8  颜色类型=2  压缩方法=0  滤波方法=0  交织方法=0
  偏移   8  IHDR  数据 13 字节
  偏移  33  IDAT  数据 174 字节
  偏移 219  IEND  数据 0 字节
```

### 1.1 十三字节逐字段

IHDR 数据区起点在文件偏移 16（签名 8 + 长度 4 + 类型 4），13 字节逐字段：

| 字段 | 大小 | demo.png 的值 | 说明 |
| ---- | ---- | ---- | ---- |
| 宽 | 4 字节 | 64 | 无符号大端整数（字节序见 [[03-计算机组成与数据表示\|03 章]]） |
| 高 | 4 字节 | 48 | 同上 |
| 位深 | 1 字节 | 8 | 每通道每像素的位数 |
| 颜色类型 | 1 字节 | 2 | 决定通道组成，见 1.2 |
| 压缩方法 | 1 字节 | 0 | 恒为 0（deflate/inflate），其他值非法 |
| 滤波方法 | 1 字节 | 0 | 恒为 0；每行数据另有 1 字节滤波类型，见 1.3 |
| 交织方法 | 1 字节 | 0 | 0 逐行，1 Adam7 交织，见 1.3 |

==IHDR 之后的 4 字节 CRC 只保护这 13 字节本身==，IDAT 的完整性由 IDAT 自己的 CRC 负责——每个 chunk 自带校验，这是 PNG 与 JPEG 段结构（[[M03-文件格式深拆II-JPEG与GIF|M03]]）最大的差别。

### 1.2 颜色类型与位深：合法组合与每像素字节数

颜色类型只有五种取值，每种允许的位深由规范定死：

| 颜色类型 | 含义 | 允许的位深 | 每像素位数 |
| ---- | ---- | ---- | ---- |
| 0 | 灰度 | 1、2、4、8、16 | 位深 × 1 |
| 2 | RGB | 8、16 | 位深 × 3 |
| 3 | 调色板 | 1、2、4、8 | 位深 × 1（字节里存的是调色板索引号） |
| 4 | 灰度 + alpha | 8、16 | 位深 × 2 |
| 6 | RGBA | 8、16 | 位深 × 4 |

组合不在表内的文件，解码器直接拒收。拿到可疑 PNG，先对照这张表查一遍 IHDR：颜色类型被改过的文件，宽高爆破的公式也跟着变。

每像素字节数速查表（8/16 位深时每像素才是整数个字节）：

| 颜色类型 | 位深 8 | 位深 16 |
| ---- | ---- | ---- |
| 0 灰度 | 1 | 2 |
| 2 RGB | 3 | 6 |
| 3 调色板 | 1 | — |
| 4 灰度+A | 2 | 4 |
| 6 RGBA | 4 | 8 |

==宽高爆破的长度公式"每行 = 1 字节滤波类型 + 宽 × 每像素字节数"只对 8/16 位深成立==，位深 1/2/4 的一般式放折叠框：

> [!info]- 位深 1/2/4：像素打包进字节
> 颜色类型 0 和 3 允许位深 1、2、4，此时连续多个像素挤进同一个字节（位深 4 时 2 像素 1 字节，位深 1 时 8 像素 1 字节），没有整数的"每像素字节数"。行长按位算，统一公式：每行数据字节数 = 1 + (宽 × 每像素位数 + 7) // 8，前面的 1 是滤波类型字节。8/16 位深代入即退化为 1 + 宽 × 每像素字节数。第 4 节的爆破脚本用的是这一般式，对全部合法组合成立。

### 1.3 压缩、滤波与交织

压缩方法恒 0，滤波方法恒 0——注意"滤波方法"是字段名，真正的滤波发生在每行：解压后每行数据的第一个字节声明本行用了哪种滤波，共五种：

| 类型值 | 名称 | 编码时的计算方式 |
| ---- | ---- | ---- |
| 0 | None | 原样保留 |
| 1 | Sub | 当前字节减去左边一个像素的同通道字节 |
| 2 | Up | 减去上一行同位置字节 |
| 3 | Average | 减去左字节与上字节的平均值 |
| 4 | Paeth | 减去由左、上、左上三字节按 Paeth 规则预测出的值 |

解码时反向加回来还原像素。[[12-隐写与流量取证|12 章 3.3]]解出的 IDAT 首字节 `00`，就是"本行 None 滤波"的声明字节。

> [!info]- 滤波对隐写的意义
> 滤波类型不是 0 时，解压出的字节流不等于像素值，中间隔着一层逆滤波。zsteg、stegsolve 的 Data Extract 内置了逆滤波，所以能直接处理文件里的 IDAT；自己手写"解压 → 取最低位"的脚本时，先想清楚操作对象是解压字节流还是像素——两者差一层逆滤波，混用取到的位全错。[[12-隐写与流量取证|12 章 5.1]] 的 PNG LSB 练习里"跳过每行首的滤波字节"，跳的就是这个声明字节。

交织方法取值 0 或 1。0 是常规逐行；1 是 Adam7 交织——把图像按 8×8 网格拆成 7 遍扫描，先隔 8 行 8 列取点，再逐遍加密，解压后的字节按 7 遍依次排布。

> [!warning] 交织图的字节布局不是逐行连续
> Adam7 解压后的数据是 7 个子图依次排开，不是"第 0 行、第 1 行……"的顺序。对交织 PNG 直接套用逐行取字节的 LSB 脚本，取出来的是乱码。固定处理办法：先用 PIL 打开重存一次（`im.save("x.png")` 默认写非交织），再按 [[12-隐写与流量取证|12 章 5.1]] 的方法取位。`file` 输出里的 `interlaced` 字样是第一提示。

## 2. chunk 命名规则与辅助块全家福

### 2.1 类型四字节的 bit5 语义

chunk 类型是 4 个 ASCII 字节，每个字节的 bit5（值 0x20）为 1 时显示为小写。四个位置的小写各有独立含义，合起来描述这个块的性质：

| 字节位置 | 管什么 | 大写（bit5 = 0） | 小写（bit5 = 1） |
| ---- | ---- | ---- | ---- |
| 第 1 字节 | 关键 / 辅助 | critical：解码必需，缺了图就废 | ancillary：补充信息，可以忽略 |
| 第 2 字节 | 公开 / 私有 | public：规范定义，人人认识 | private：自定义含义，只有写入方知道 |
| 第 3 字节 | 保留位 | 必须大写，小写是非法文件 | 无合法取值 |
| 第 4 字节 | 复制安全 | 不可复制：修改图像时必须丢弃本块 | safe-to-copy：修改图像时可原样带走 |

拿三个真实类型核对：`IHDR` 四个大写——关键/公开/合规/不可复制；`tEXt`——辅助/公开/合规/可安全复制；自造的 `flAg`（f、l 小写，A 大写，g 小写）——辅助/私有/合规/可安全复制，四个 bit5 全部合规，是合法的私有块。检查代码就是按位与：`t[0] & 0x20, t[1] & 0x20, t[2] & 0x20, t[3] & 0x20`。

关键块只有四种：IHDR、IDAT、IEND、PLTE（调色板图的调色板表）。其余规范块全是辅助块——解析器对不认识的辅助块的正确动作是跳过，这正是辅助块能夹带私货的原因。

### 2.2 常见辅助块一览

| 块 | 数据区内容 | CTF 视角 |
| ---- | ---- | ---- |
| tEXt | keyword `\0` text，Latin-1 编码 | 最常见文本块，exiftool 直接显示 |
| zTXt | keyword `\0` 压缩方法（1 字节，恒 0）+ zlib 压缩的正文 | strings 扫不到正文，要剥一层 zlib |
| iTXt | keyword `\0` 压缩标志 `\0` 压缩方法 `\0` 语言标签 `\0` 翻译关键字 `\0` 正文（UTF-8） | 国际化文本块；压缩标志为 1 时正文是 zlib |
| pHYs | 横、纵每米像素数（各 4 字节）+ 单位（1 字节） | 物理分辨率，PIL 有时会写 |
| tIME | 年（2 字节）、月日时分秒（各 1 字节） | 最后修改时间，出题人可能留痕 |
| gAMA / cHRM / sRGB | 色彩特性声明 | 无藏货价值，解析时跳过 |
| iCCP | 配置文件名 `\0` 压缩方法 `\0` zlib 压缩的 ICC 配置 | 剥 zlib 层后是二进制色彩档案 |
| bKGD | 背景色（内容随颜色类型变） | 无藏货价值 |
| eXIf | EXIF 数据（TIFF 结构） | 相机信息，exiftool 读取 |

文本三兄弟 tEXt/zTXt/iTXt 是 flag 的常住地，三者内容格式不同但都满足"keyword `\0` 后跟正文"的开头，正文是否 zlib 压缩看各自的压缩标志。exiftool 显示的 Comment、Description 等字段名，就是块内 keyword。

### 2.3 手造辅助块与解析回来

chunk 的构造规则 12 章已给（长度 + 类型 + 数据 + CRC32），把它封成函数，五类辅助块一次造齐，塞进 demo.png 再逐块解析回来：

```python
# text_chunks.py —— 手造辅助块塞进 PNG，再逐块解析回来
import struct, subprocess, zlib
from PIL import Image

png = open("demo.png", "rb").read()          # 第 1 节造的 demo.png

def make_chunk(ctype, data):
    """通用 chunk 构造：长度 + 类型 + 数据 + CRC32"""
    return (struct.pack(">I", len(data)) + ctype + data
            + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF))

# 类型四字节的 bit5（0x20）：置 1 即小写，四个位置各有含义
for t in (b"IHDR", b"tEXt", b"flAg"):
    a = "辅助" if t[0] & 0x20 else "关键"
    b = "私有" if t[1] & 0x20 else "公开"
    c = "保留位非法" if t[2] & 0x20 else "保留位合规"
    dd = "可安全复制" if t[3] & 0x20 else "改图须丢弃"
    print(f"{t.decode():<5} {a} / {b} / {c} / {dd}")
print()

chunks = b"".join([
    # tEXt：keyword \0 text，都是 Latin-1
    make_chunk(b"tEXt", b"Comment\x00flag{in_text_chunk}"),
    # zTXt：keyword \0 压缩方法(恒 0)，其后是 zlib 压缩的正文
    make_chunk(b"zTXt", b"Description\x00\x00" + zlib.compress(b"flag{in_ztxt_chunk}")),
    # iTXt：keyword \0 压缩标志 \0 压缩方法 \0 语言标签 \0 翻译关键字 \0 正文(UTF-8)
    make_chunk(b"iTXt", b"Note\x00\x01\x00zh\x00\x00" + zlib.compress("flag{in_itxt_chunk}".encode())),
    # pHYs：横向、纵向每米像素数 + 单位（1 = 米）
    make_chunk(b"pHYs", struct.pack(">IIB", 3780, 3780, 1)),
    # 自定义私有块：辅助 / 私有 / 保留合规 / 可安全复制
    make_chunk(b"flAg", b"flag{private_chunk}"),
])
new = png[:33] + chunks + png[33:]           # 插在 IHDR 之后（签名 8 + IHDR 块 25 = 33）
open("demo_meta.png", "wb").write(new)
print(f"塞入 5 个辅助块共 {len(chunks)} 字节：{len(png)} -> {len(new)} 字节")
print()

data = open("demo_meta.png", "rb").read()
pos = 8
while pos < len(data):
    ln = struct.unpack(">I", data[pos:pos+4])[0]
    t = data[pos+4:pos+8]
    body = data[pos+8:pos+8+ln]
    if t == b"tEXt":
        k, v = body.split(b"\x00", 1)
        print(f"tEXt  keyword={k.decode('latin-1')}  text={v.decode('latin-1')}")
    elif t == b"zTXt":
        k, rest = body.split(b"\x00", 1)
        print(f"zTXt  keyword={k.decode('latin-1')}  压缩方法={rest[0]}  zlib 剥层后={zlib.decompress(rest[1:]).decode('latin-1')}")
    elif t == b"iTXt":
        k, rest = body.split(b"\x00", 1)
        cflag, cmethod = rest[0], rest[1]
        lang, rest = rest[2:].split(b"\x00", 1)
        trans, text = rest.split(b"\x00", 1)
        if cflag == 1:
            text = zlib.decompress(text)
        print(f"iTXt  keyword={k.decode('latin-1')}  压缩标志={cflag}  语言={lang.decode() or '(空)'}  正文={text.decode('utf-8')}")
    elif t == b"pHYs":
        x, y, u = struct.unpack(">IIB", body)
        print(f"pHYs  {x} x {y} 像素/米（约 {round(x * 0.0254)} DPI）")
    elif t == b"flAg":
        print(f"flAg  私有块，内容={body.decode('latin-1')}")
    pos += 12 + ln
print()

out = subprocess.run(["exiftool", "demo_meta.png"], capture_output=True, text=True)
print(out.stdout.strip())

im = Image.open("demo_meta.png")
im.load()
print()
print(f"PIL 打开 demo_meta.png：{im.size} {im.mode}，私有块不影响解码")
```

输出（ExifTool 版本号与文件时间戳几行略去）：

```
IHDR  关键 / 公开 / 保留位合规 / 改图须丢弃
tEXt  辅助 / 公开 / 保留位合规 / 可安全复制
flAg  辅助 / 私有 / 保留位合规 / 可安全复制

塞入 5 个辅助块共 193 字节：231 -> 424 字节

tEXt  keyword=Comment  text=flag{in_text_chunk}
zTXt  keyword=Description  压缩方法=0  zlib 剥层后=flag{in_ztxt_chunk}
iTXt  keyword=Note  压缩标志=1  语言=zh  正文=flag{in_itxt_chunk}
pHYs  3780 x 3780 像素/米（约 96 DPI）
flAg  私有块，内容=flag{private_chunk}

File Name                       : demo_meta.png
File Size                       : 424 bytes
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 64
Image Height                    : 48
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Comment                         : flag{in_text_chunk}
Description                     : flag{in_ztxt_chunk}
Note                            : flag{in_itxt_chunk}
Pixels Per Unit X               : 3780
Pixels Per Unit Y               : 3780
Pixel Units                     : meters
Image Size                      : 64x48

PIL 打开 demo_meta.png：(64, 48) RGB，私有块不影响解码
```

三条读法对照着看：手写解析器逐字节拆，zTXt/iTXt 的 zlib 剥层自己动手；exiftool 按语义归档，zTXt 解压后和 tEXt 平起平坐地显示；而 ==exiftool 的输出里没有 `flAg` 这一节——私有块它不认==，这正是私有块适合藏东西的原因。插入位置：辅助块可以放在 IHDR 之后、IEND 之前的任意位置，唯一硬规矩是 IDAT 必须连续；PIL 打开完全不受私有块影响。

> [!note] 解析辅助块时先看类型再解内容
> 判断顺序固定：类型四字节 → 按 2.1 的 bit5 定性质 → 规范块按 2.2 的表解字段 → 不认识的块（尤其首字母小写的私有块）直接打印原始字节。CTF 里冒出的任何生僻块名，先看字节再下结论。

## 3. CRC 校验与 pngcheck

[[12-隐写与流量取证|12 章 3.1]]的解析器已经能对每块报 OK/BAD，[[12-隐写与流量取证|12 章 3.2]]修过一次 IHDR 的 CRC。本节把修复做成对任意 chunk 通用的三步——定位、重算、写回——并引入 PNG 的专用校验器 pngcheck。

```python
# crc_repair.py —— pngcheck 对照、任意 chunk 的 CRC 定位与修复
import struct, subprocess, zlib
from PIL import Image

def pngcheck(*args):
    r = subprocess.run(["pngcheck", *args], capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()

def walk_chunks(data):
    """[(块偏移, 类型, 数据)]，走到文件尾或残块为止"""
    pos, out = 8, []
    while pos + 12 <= len(data):
        ln = struct.unpack(">I", data[pos:pos+4])[0]
        t = data[pos+4:pos+8]
        out.append((pos, t, data[pos+8:pos+8+ln]))
        pos += 12 + ln
    return out

print("[1] 正常文件")
print(pngcheck("-v", "demo.png"))
print()

print("[2] 把 tEXt 内容里一个字节改成 0xFF（只动内容，不动 CRC）")
data = bytearray(open("demo_meta.png", "rb").read())
for pos, t, body in walk_chunks(bytes(data)):
    if t == b"tEXt":
        data[pos+8+12] = 0xFF            # 数据区第 12 字节，"flag{...}" 的 'l'
        break
open("demo_bad.png", "wb").write(bytes(data))
print(pngcheck("-v", "demo_bad.png"))
print()

print("[3] 通用修复：定位 BAD 块 -> 重算 CRC -> 写回")
bad = bytes(data)
fixed = bytearray(bad)
for pos, t, body in walk_chunks(bad):
    calc = zlib.crc32(t + body) & 0xFFFFFFFF
    stored = struct.unpack(">I", bad[pos+8+len(body):pos+12+len(body)])[0]
    if stored != calc:
        print(f"  定位：{t.decode()} 偏移 {pos}  存储 {stored:08x}  重算 {calc:08x}")
        off = pos + 8 + len(body)        # 该块 CRC 字段的位置
        fixed[off:off+4] = struct.pack(">I", calc)
open("demo_repaired.png", "wb").write(bytes(fixed))
print(pngcheck("-v", "demo_repaired.png"))

im = Image.open("demo_repaired.png"); im.load()
for pos, t, body in walk_chunks(bytes(fixed)):
    if t == b"tEXt":
        k, v = body.split(b"\x00", 1)
        print(f"  PIL 正常打开：{im.size}；但 tEXt 内容已是 {v!r}")
```

输出：

```
[1] 正常文件
File: demo.png (231 bytes)
  chunk IHDR at offset 0x0000c, length 13
    64 x 48 image, 24-bit RGB, non-interlaced
  chunk IDAT at offset 0x00025, length 174
    zlib: deflated, 32K window, default compression
  chunk IEND at offset 0x000df, length 0
No errors detected in demo.png (3 chunks, 97.5% compression).

[2] 把 tEXt 内容里一个字节改成 0xFF（只动内容，不动 CRC）
File: demo_bad.png (424 bytes)
  chunk IHDR at offset 0x0000c, length 13
    64 x 48 image, 24-bit RGB, non-interlaced
  chunk tEXt at offset 0x00025, length 27, keyword: Comment
  CRC error in chunk tEXt (computed fd69bfa0, expected 39922a78)
ERRORS DETECTED in demo_bad.png

[3] 通用修复：定位 BAD 块 -> 重算 CRC -> 写回
  定位：tEXt 偏移 33  存储 39922a78  重算 fd69bfa0
File: demo_repaired.png (424 bytes)
  chunk IHDR at offset 0x0000c, length 13
    64 x 48 image, 24-bit RGB, non-interlaced
  chunk tEXt at offset 0x00025, length 27, keyword: Comment
  chunk zTXt at offset 0x0004c, length 40, keyword: Description
  chunk iTXt at offset 0x00080, length 38, keyword: Note
    compressed, language tag = zh
    no translated keyword, 28 bytes of UTF-8 text
  chunk pHYs at offset 0x000b2, length 9: 3780x3780 pixels/meter (96 dpi)
  chunk flAg at offset 0x000c7, length 19
    unknown private, ancillary, safe-to-copy chunk
  chunk IDAT at offset 0x000e6, length 174
    zlib: deflated, 32K window, default compression
  chunk IEND at offset 0x001a0, length 0
No errors detected in demo_repaired.png (8 chunks, 95.4% compression).
  PIL 正常打开：(64, 48)；但 tEXt 内容已是 b'flag\xffin_text_chunk}'
```

pngcheck 的高频输出整理成速查表：

| pngcheck 输出 | 含义 |
| ---- | ---- |
| `No errors detected in ...` | 结构与全部 CRC 干净 |
| `CRC error in chunk XXX (computed A, expected B)` | XXX 块被改过没修 CRC；A 是按当前内容重算的值，B 是文件里存的值 |
| `additional data after IEND chunk` | IEND 之后有夹带，见第 6 节与 [[M01-MISC导论与工具箱\|M01 5.3]] |
| `unknown private, ancillary, safe-to-copy chunk` | 自定义私有块：不报错，只登记一笔（上面输出的 `flAg` 行） |
| 宽高与数据量不匹配 | 不报——pngcheck 没有这项检查，见第 4 节 |

修复流程已经泛化：walk_chunks 逐块重算 CRC，对不上就定位类型与偏移，把重算值写回 CRC 字段。12 章 3.2 修 IHDR 的三行代码，是这套流程在"块位置固定为 IHDR"时的特例。

> [!warning] 修 CRC 只修登记，不修内容
> demo_bad.png 的 tEXt 被改了一个字节：修完 CRC，pngcheck 干净、PIL 照常打开，但那行文本已经是乱码。CRC 能定位"哪一块被动过"，不能恢复被改的内容。IDAT 被改时更麻烦：zlib 流自带 adler32 校验，内容坏了修好 CRC 也解不开——修完 CRC 打不开图，说明坏的是数据本身，不是登记。

## 4. 宽高爆破完整脚本

### 4.1 原理：长度公式

[[12-隐写与流量取证|12 章 3.2]]给出公式、[[12-隐写与流量取证|12 章 3.3]]给出解法：IDAT 解压后的总字节数由宽高唯一决定——

==总字节 = 高 × (1 + 宽 × 每像素字节数)==（8/16 位深；一般式每行字节数 = 1 + (宽 × 每像素位数 + 7) // 8，见 1.2 折叠框）

出题人把宽高改小时，IDAT 一个字节没动，解压后的总字节数是现成的已知量。枚举宽、按公式整除出高，就得到全部候选；再从候选里挑出真值。整个爆破三段：解压数长度 → 枚举候选 → 筛选还原。

### 4.2 完整脚本与靶子

造两个靶：宽高 64×48 改成 16×16，靶 A 按规矩重算了 CRC（主流出题方式），靶 B 没修。脚本一并完成造靶、pngcheck 对照、爆破与还原：

```python
# dim_crack.py —— 宽高爆破：改小宽高造靶 -> 爆破还原 -> 渲染确认
import io, struct, subprocess, zlib
from PIL import Image

def pngcheck(*args):
    r = subprocess.run(["pngcheck", *args], capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()

def set_dims(data, w, h, fix_crc=True):
    out = bytearray(data)
    out[16:20] = struct.pack(">I", w)          # IHDR 数据区前 4 字节是宽
    out[20:24] = struct.pack(">I", h)          # 接着 4 字节是高
    if fix_crc:
        out[29:33] = struct.pack(">I", zlib.crc32(bytes(out[12:29])) & 0xFFFFFFFF)
    return bytes(out)

def walk_chunks(data):
    pos, out = 8, []
    while pos + 12 <= len(data):
        ln = struct.unpack(">I", data[pos:pos+4])[0]
        t = data[pos+4:pos+8]
        out.append((pos, t, data[pos+8:pos+8+ln]))
        pos += 12 + ln
    return out

orig = Image.open("demo.png")
orig_bytes = orig.tobytes()
png = open("demo.png", "rb").read()

# 造两个靶：宽高 64x48 -> 16x16
open("target_a.png", "wb").write(set_dims(png, 16, 16))                 # CRC 已修（主流）
open("target_b.png", "wb").write(set_dims(png, 16, 16, fix_crc=False))  # CRC 没修

for fn in ("target_a.png", "target_b.png"):
    print(f"pngcheck -v {fn}")
    print(pngcheck("-v", fn))
    print()

def crack(fn, orig_bytes):
    data = open(fn, "rb").read()
    fake_w, fake_h = struct.unpack(">II", data[16:24])
    bd, ct = data[24], data[25]
    bits = {0: bd, 2: 3 * bd, 3: bd, 4: 2 * bd, 6: 4 * bd}[ct]   # 每像素位数
    idat = b"".join(body for _, t, body in walk_chunks(data) if t == b"IDAT")
    raw = zlib.decompress(idat)
    L = len(raw)
    # 长度约束：L = h × (1 + (w × bits + 7) // 8)
    cands = []
    for w in range(1, 2049):
        row = 1 + (w * bits + 7) // 8
        if L % row == 0:
            h = L // row
            if 1 <= h <= 4096:
                cands.append((w, h))
    print(f"{fn}: 伪装宽高 {fake_w}x{fake_h}  解压后 {L} 字节  长度匹配 {len(cands)} 个: {cands}")

    stored_crc = struct.unpack(">I", data[29:33])[0]
    cur_crc = zlib.crc32(data[12:29]) & 0xFFFFFFFF
    if stored_crc != cur_crc:
        # 作者没修 CRC：存储值就是原始 IHDR 的 CRC，直接拿候选匹配
        for w, h in cands:
            body = struct.pack(">II", w, h) + data[24:29]
            if zlib.crc32(b"IHDR" + body) & 0xFFFFFFFF == stored_crc:
                print(f"  阶段 1 存储 CRC 命中：原宽高 {w}x{h}")
                return w, h
    else:
        # 作者修了 CRC：滤波字节预筛 + PIL 渲染比对
        ok = []
        for w, h in cands:
            row = 1 + (w * bits + 7) // 8
            if all(raw[k * row] <= 4 for k in range(h)):   # 每行首字节必须是滤波类型 0-4
                ok.append((w, h))
        print(f"  阶段 1 滤波字节预筛后剩 {len(ok)} 个: {ok}")
        for w, h in ok:
            cand = set_dims(data, w, h)
            try:
                im = Image.open(io.BytesIO(cand)); im.load()
            except Exception:
                continue
            if im.tobytes() == orig_bytes:
                print(f"  阶段 2 渲染比对命中：{w}x{h}，与原图逐像素一致")
                return w, h

for fn in ("target_a.png", "target_b.png"):
    w, h = crack(fn, orig_bytes)
    fixed = set_dims(open(fn, "rb").read(), w, h)
    open("restored.png", "wb").write(fixed)
    im = Image.open("restored.png")
    print(f"  还原 -> restored.png：{im.size}，逐像素等于原图: {im.tobytes() == orig_bytes}")
    print()
```

输出：

```
pngcheck -v target_a.png
File: target_a.png (231 bytes)
  chunk IHDR at offset 0x0000c, length 13
    16 x 16 image, 24-bit RGB, non-interlaced
  chunk IDAT at offset 0x00025, length 174
    zlib: deflated, 32K window, default compression
  chunk IEND at offset 0x000df, length 0
No errors detected in target_a.png (3 chunks, 69.9% compression).

pngcheck -v target_b.png
File: target_b.png (231 bytes)
  chunk IHDR at offset 0x0000c, length 13
    16 x 16 image, 24-bit RGB, non-interlaced
  CRC error in chunk IHDR (computed 90916836, expected 2e29eb48)
ERRORS DETECTED in target_b.png

target_a.png: 伪装宽高 16x16  解压后 9264 字节  长度匹配 5 个: [(1, 2316), (5, 579), (64, 48), (257, 12), (1029, 3)]
  阶段 1 滤波字节预筛后剩 3 个: [(64, 48), (257, 12), (1029, 3)]
  阶段 2 渲染比对命中：64x48，与原图逐像素一致
  还原 -> restored.png：(64, 48)，逐像素等于原图: True

target_b.png: 伪装宽高 16x16  解压后 9264 字节  长度匹配 5 个: [(1, 2316), (5, 579), (64, 48), (257, 12), (1029, 3)]
  阶段 1 存储 CRC 命中：原宽高 64x48
  还原 -> restored.png：(64, 48)，逐像素等于原图: True
```

先看 pngcheck 的两行结论：靶 A 报 `No errors detected`。==pngcheck 不校验宽高与数据量的匹配==——它按 IHDR 宣称的行数解到够数就停，多余的数据不追问；把高度反过来改大到 128（数据不足）也是同样待遇：

```python
# pngcheck_tall.py —— 宽高改大（数据不足）方向，pngcheck 的真实反应
import struct, subprocess, zlib

def set_dims(data, w, h, fix_crc=True):
    out = bytearray(data)
    out[16:20] = struct.pack(">I", w)
    out[20:24] = struct.pack(">I", h)
    if fix_crc:
        out[29:33] = struct.pack(">I", zlib.crc32(bytes(out[12:29])) & 0xFFFFFFFF)
    return bytes(out)

png = open("demo.png", "rb").read()
open("target_tall.png", "wb").write(set_dims(png, 64, 128))   # 高度 48 -> 128，CRC 已修
r = subprocess.run(["pngcheck", "-v", "target_tall.png"], capture_output=True, text=True)
print((r.stdout + r.stderr).strip())
```

输出：

```
File: target_tall.png (231 bytes)
  chunk IHDR at offset 0x0000c, length 13
    64 x 128 image, 24-bit RGB, non-interlaced
  chunk IDAT at offset 0x00025, length 174
    zlib: deflated, 32K window, default compression
  chunk IEND at offset 0x000df, length 0
No errors detected in target_tall.png (3 chunks, 99.1% compression).
```

所以宽高爆破不能指望 pngcheck 报警，必须自己解压 IDAT 数长度。两个靶走了两条筛选路线：

- 靶 B（CRC 没修）：文件里存的 CRC 还是原始 IHDR 的，把候选宽高逐个代入重算、对上存储值即锁定，无需渲染——阶段 1 直接命中。
- 靶 A（CRC 已修）：长度公式把 9264 字节筛成 5 个候选；再按"每行首字节必须是滤波类型 0–4"预筛（1.3 节），最后把幸存候选逐个写回 IHDR、交给 PIL 渲染，与原图逐像素比对——阶段 2 锁定 64×48。==多解的收口手段就这两类：结构自洽检查（滤波字节）与渲染比对==。

> [!note] 实战没有原图时
> 渲染比对需要参照物，自造靶能逐像素对比；实战中候选通常只剩个位数，逐个写回存成文件肉眼看，画面正常的那张就是答案。另外先试 CRC 没修的分支——出一半手滑没修 CRC 的题不少见，命中就是零成本。

## 5. APNG：一个文件装多帧

APNG（Animated PNG）在普通 PNG 的骨架上加三种块，让一个文件按顺序播放多帧。

### 5.1 三种新块的结构

三种块的数据区结构：

acTL（数据区 8 字节，全文件一个，必须在 IDAT 之前）：

| 字段 | 大小 | demo_apng 的值 | 说明 |
| ---- | ---- | ---- | ---- |
| num_frames | 4 字节 | 4 | 帧数 |
| num_plays | 4 字节 | 0 | 播放次数，0 = 无限循环 |

fcTL（数据区 26 字节，帧控制块，每帧一个）：

| 字段 | 大小 | 第一个 fcTL 的值 | 说明 |
| ---- | ---- | ---- | ---- |
| sequence_number | 4 字节 | 0 | 全文件递增序号 |
| width / height | 4 + 4 字节 | 64 / 48 | 本帧区域大小 |
| x_offset / y_offset | 4 + 4 字节 | 0 / 0 | 本帧画到画布的位置 |
| delay_num / delay_den | 2 + 2 字节 | 1 / 5 | 显示时长 = num ÷ den 秒（0.2 秒） |
| dispose_op | 1 字节 | 0 | 显示完怎么处理画布：0 不指定、1 保留、2 清回背景色 |
| blend_op | 1 字节 | 0 | 0 覆盖画布、1 与画布做 alpha 混合 |

fdAT（帧数据块）：前 4 字节 sequence_number，其后是本帧的 zlib 数据——除开头的序号，与 IDAT 同构。首帧不走 fdAT：它的像素仍是普通 IDAT，前面放一个 fcTL 声明帧参数。

### 5.2 造一个 APNG 并逐块确认

```python
# apng_demo.py —— PIL 造 APNG，逐块拆 acTL/fcTL/fdAT，再抽帧
import struct
from PIL import Image, ImageDraw

frames = []
for i in range(4):
    f = Image.new("RGB", (64, 48), (252, 252, 251))
    d = ImageDraw.Draw(f)
    d.rectangle([6 + i * 14, 16, 26 + i * 14, 36], fill=(55, 138, 221))
    frames.append(f)
frames[0].save("demo_apng.png", save_all=True, append_images=frames[1:],
               duration=200, loop=0)

png = open("demo_apng.png", "rb").read()
print(f"demo_apng.png 共 {len(png)} 字节，逐块：")
pos, n_fctl, n_fdat = 8, 0, 0
while pos < len(png):
    ln = struct.unpack(">I", png[pos:pos+4])[0]
    t = png[pos+4:pos+8]
    body = png[pos+8:pos+8+ln]
    if t == b"acTL":
        nf, npl = struct.unpack(">II", body)
        print(f"  acTL  帧数={nf}  循环={npl}（0=无限）")
    elif t == b"fcTL":
        n_fctl += 1
        seq, w, h, x, y, dn, dd = struct.unpack(">IIIIIHH", body[:24])
        print(f"  fcTL  seq={seq}  区域 {w}x{h}@({x},{y})  delay={dn}/{dd}  dispose={body[24]}  blend={body[25]}")
    elif t == b"fdAT":
        n_fdat += 1
        seq = struct.unpack(">I", body[:4])[0]
        print(f"  fdAT  seq={seq}  帧数据 {ln - 4} 字节")
    else:
        print(f"  {t.decode():<5} 数据 {ln} 字节")
    pos += 12 + ln
print(f"  （fcTL 共 {n_fctl} 个，fdAT 共 {n_fdat} 个）")

g = Image.open("demo_apng.png")
print()
print(f"is_animated={g.is_animated}  n_frames={g.n_frames}")
for i in range(g.n_frames):
    g.seek(i)
    g.convert("RGB").save(f"apng_frame{i}.png")
    got = g.getpixel((11 + i * 14, 26))
    want = frames[i].getpixel((11 + i * 14, 26))
    print(f"  第 {i} 帧 (11+14i, 26) 像素 {got}  应为 {want}  一致: {got == want}")
```

输出：

```
demo_apng.png 共 522 字节，逐块：
  IHDR  数据 13 字节
  acTL  帧数=4  循环=0（0=无限）
  fcTL  seq=0  区域 64x48@(0,0)  delay=1/5  dispose=0  blend=0
  IDAT  数据 115 字节
  fcTL  seq=1  区域 35x21@(6,16)  delay=1/5  dispose=0  blend=0
  fdAT  seq=2  帧数据 44 字节
  fcTL  seq=3  区域 35x21@(20,16)  delay=1/5  dispose=0  blend=0
  fdAT  seq=4  帧数据 44 字节
  fcTL  seq=5  区域 30x21@(34,16)  delay=1/5  dispose=0  blend=0
  fdAT  seq=6  帧数据 42 字节
  IEND  数据 0 字节
  （fcTL 共 4 个，fdAT 共 3 个）

is_animated=True  n_frames=4
  第 0 帧 (11+14i, 26) 像素 (55, 138, 221)  应为 (55, 138, 221)  一致: True
  第 1 帧 (11+14i, 26) 像素 (55, 138, 221)  应为 (55, 138, 221)  一致: True
  第 2 帧 (11+14i, 26) 像素 (55, 138, 221)  应为 (55, 138, 221)  一致: True
  第 3 帧 (11+14i, 26) 像素 (55, 138, 221)  应为 (55, 138, 221)  一致: True
```

逐块输出与结构表对上：acTL 宣告 4 帧；4 个 fcTL（首帧的 seq=0、区域 64×48，后续 seq 递增）；首帧像素在 IDAT，第 2 帧起改用 fdAT。两个值得注意的细节：duration=200（毫秒）落盘成了 delay=1/5；Pillow 把后续帧裁成了 35×21@(6,16) 这样的增量帧——只有相对上一帧变化的矩形参与编码，与 [[M03-文件格式深拆II-JPEG与GIF|M03 6.2]]的 GIF 增量帧同一思路。

### 5.3 抽帧与第一帧陷阱

抽帧的入口就是输出后半段用到的三个成员：`is_animated` 报告是否多帧，`n_frames` 给帧数，`seek(i)` 跳到第 i 帧，之后 `save()`、`getpixel()` 操作的都是当前帧：

```python
g = Image.open("demo_apng.png")
for i in range(g.n_frames):
    g.seek(i)
    g.convert("RGB").save(f"apng_frame{i}.png")   # 逐帧转存 PNG
```

输出即 5.2 输出块的后半段：4 帧各转存一张，色块位置逐帧核对一致。fdAT 帧由 Pillow 自动解码，与 IDAT 帧在使用上无差别。

> [!warning] 第一帧陷阱
> 不少查看器、聊天软件的缩略图组件只渲染第一帧；zsteg 和多数逐 chunk 的隐写脚本也只扫 IDAT——后续帧的数据在 fdAT 里，名字都不叫 IDAT。flag 藏在第 2 帧起的画面里时，看图、zsteg、常规 LSB 脚本会全部空手。固定动作：`n_frames` 大于 1 就逐帧 `seek` 转存，对每一帧单独跑隐写流程。

## 6. IEND 之后的夹带

IEND 数据区长度恒为 0，块本体定长 12 字节：长度 4 + 类型 4 + CRC 4，CRC 恒为 `ae426082`。查看器与解码库读到 IEND 就停手，==IEND 之后的所有字节都是夹带物==，粘什么都不影响"能打开"。

定位与切割两步走：按结构走到 IEND 拿到结束偏移，其后的字节整体切下。手造一个"PNG 尾粘 ZIP"的靶并切回：

```python
# tail_carve.py —— IEND 之后粘 ZIP，按结构精确定位并切割
import io, struct, zipfile
from PIL import Image

png = open("demo.png", "rb").read()          # 第 1 节造的 demo.png
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("secret.txt", "flag{hidden_after_iend}")
zbytes = buf.getvalue()
open("target_tail.png", "wb").write(png + zbytes)

data = open("target_tail.png", "rb").read()
pos = 8
while True:
    ln = struct.unpack(">I", data[pos:pos+4])[0]
    t = data[pos+4:pos+8]
    pos += 12 + ln
    if t == b"IEND":
        break
print(f"IEND 结束于偏移 {pos}，文件共 {len(data)} 字节，其后 {len(data) - pos} 字节是夹带物")
print(f"IEND 块本体 12 字节：{data[pos-12:pos].hex(' ')}")

carved = data[pos:]
open("carved.zip", "wb").write(carved)
print("切出内容与粘入的 zip 逐字节一致:", carved == zbytes)
print("carved.zip 读出:", zipfile.ZipFile("carved.zip").read("secret.txt").decode())
im = Image.open("target_tail.png"); im.load()
print(f"target_tail.png PIL 仍正常打开：{im.size}")
```

输出：

```
IEND 结束于偏移 231，文件共 374 字节，其后 143 字节是夹带物
IEND 块本体 12 字节：00 00 00 00 49 45 4e 44 ae 42 60 82
切出内容与粘入的 zip 逐字节一致: True
carved.zip 读出: flag{hidden_after_iend}
target_tail.png PIL 仍正常打开：(64, 48)
```

结构走到 IEND 得到精确偏移，切出的字节与粘入的 zip 逐字节一致，解出 flag。想快一点可以用快捷式 `end = data.rfind(b"IEND") + 8`（IEND 四字节 + CRC 四字节）：

> [!warning] "IEND" 四个字符可能不止出现一次
> 夹带物里也可能恰好出现 `49 45 4E 44`，`rfind` 会切多或切少。按 chunk 结构走到 IEND 的方法不受伪串影响——伪串没有合法的长度与 CRC 结构，天然被跳过。这与 [[M03-文件格式深拆II-JPEG与GIF|M03 5.1]]的伪 EOI 是同一类问题。

工具化的路子两条：pngcheck 直接点名 `additional data after IEND chunk`；binwalk 列出全部签名偏移、`binwalk -e` 自动分离（[[12-隐写与流量取证|12 章 8.1]]），从 `file` 到 `dd` 的完整工具链流程见 [[M01-MISC导论与工具箱|M01 5.3]]。切出来的压缩包怎么拆，在 [[M04-压缩包全解|M04]]。

## 7. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| pngcheck 报 `CRC error in chunk XXX` | XXX 块被改过没修 CRC。第 3 节三步修复：定位 → 重算 → 写回 |
| 修完 CRC 还是打不开 | CRC 只保证登记一致，内容本身可能坏了：zlib 流的 adler32 过不了、滤波数据越界，都修不回来（第 3 节警告框） |
| 宽高被改小，pngcheck 却说 No errors | pngcheck 不校验宽高与数据量的匹配。自己解压 IDAT 数长度跑爆破（第 4 节） |
| 宽高爆破候选太多 | 长度匹配后先筛"每行首字节 ≤ 4"，再多解就逐个写回渲染、肉眼挑正常的（第 4 节） |
| zTXt/iTXt 读出乱码 | 正文被 zlib 压过：zTXt 恒压缩，iTXt 看压缩标志，剥层再读（第 2 节） |
| exiftool 看不到任何可疑内容，图却有问题 | 私有块 exiftool 不认。用解析器逐块打印类型与原始字节（第 2 节） |
| APNG 只看到第一帧，zsteg 也扫不出东西 | 查看器与 zsteg 都只处理第一帧的 IDAT，后续帧在 fdAT 里。PIL 逐帧 seek 转存再各自分析（第 5 节） |
| 交织 PNG 的 LSB 提取出来全是乱码 | Adam7 的字节按 7 个子图排布，不是逐行连续。PIL 重存成非交织再提取（第 1 节警告框） |
| 调色板图 zsteg 结果像乱码 | 像素字节是调色板索引不是颜色值，位平面含义完全不同。`im.convert("RGB")` 重存后再扫（[[M01-MISC导论与工具箱\|M01 3.1]]） |
| PIL 打不开，`file` 却认得出是 PNG | file 只看头部魔数，内部结构可以烂掉。pngcheck -v 定位坏块（第 3 节） |
| `file` 报 interlaced，后续分析全不对劲 | 交织文件。所有逐行假设（LSB、宽高爆破的行长公式）都要先重存解除交织（第 1 节） |

## 8. 配套练习与延伸阅读

配套练习：

1. 把 2.3 的脚本改成命令行工具：参数收文件名、keyword 和正文，往任意 PNG 塞一个 tEXt 块（注意插入位置与 CRC），再用解析器读回确认。
2. 把 demo.png 用 `im.convert("P")` 转成调色板图重存，对照第 1 节的两张表读它的 IHDR（颜色类型、位深各是多少），并找到新增的 PLTE 块；对这张图跑 zsteg，体会常见问题表里"调色板图"那一行。
3. 造一张 8 位灰度靶（颜色类型 0、位深 8）走一遍宽高爆破，核对每像素字节数速查表里灰度对应的取值；再把它的位深改成 16、连 CRC 一起修好，确认 pngcheck 的态度与第 4 节一致。
4. 造一个 3 帧 APNG，把 flag 画在第三帧，第一帧留白；交给同学时只说"图能打开，但内容不止看到的这些"。
5. 三层夹带：PNG 尾粘 zip，zip 里再放一张 PNG 的 base64 文本。按第 6 节切出 zip，解压后对文本解码，再对解出的 PNG 走一遍 [[M01-MISC导论与工具箱|M01 5.2]]的固定动作清单。

练习场：

- [[01-练习平台索引|练习平台索引]]：MISC 分区按工具与套路分类，本章每种手法都有对应题目
- [[03-工具清单|工具清单]]：pngcheck、exiftool、binwalk 与 PIL 的安装方式与同类替代

延伸阅读：

- PNG 规范（w3.org/TR/png/）：IHDR 合法组合表、chunk 命名规则、五种滤波与 Adam7 的权威出处
- APNG 规范（wiki.mozilla.org/APNG_Specification）：acTL/fcTL/fdAT 的字段定义与 dispose_op、blend_op 取值
- [[12-隐写与流量取证|12 章 3 节]]：chunk 四字段、改宽高修 CRC 与 zlib 解 IDAT 的入门版，本章的地基
- [[M03-文件格式深拆II-JPEG与GIF|M03]]：JPEG 的段没有 CRC，与本章"每块自校验"对照；GIF 的块结构与增量帧
- [[M04-压缩包全解|M04]]：本章尾部粘出的 zip、7z 的完整拆法
