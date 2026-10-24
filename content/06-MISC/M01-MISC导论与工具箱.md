---
chapter: MISC
section: MISC 导论与工具箱
order: 801
tags:
  - CTF
  - MISC
  - 工具链
publish: true
---

# M01 MISC 导论与工具箱
## MISC Introduction & Toolbox

> [!info]- 章节信息
> **所属方向**：MISC ｜ **难度阶段**：L1 筑基期 ｜ **前置要求**：[[12-隐写与流量取证|12 章]] · [[08-编码与古典密码|08 章]] · [[06-Python与CTF脚本基础|06 章]]
> **本章目标**：配齐并逐个验收 MISC 方向的工具箱；装上 PIL / numpy / scipy 三件套；补齐 struct 与二进制正则的基本功；立起"拿到附件先干什么"的固定工作流。M02 之后的每个专题都在这套底座上展开。

## 1. 定位：从 12 章到 MISC 系列

[[12-隐写与流量取证|12 章]]走完了 MISC 的最小闭环：认魔数、修文件头、拆 PNG、抠 LSB、翻流量包——每类工具都见过一次，知道什么时候用。但"见过一次"和"能独立解赛题"之间还有距离：出题人稍作变形，chunk 里塞进自定义块、JPEG 的分段被重排、ZIP 换了压缩方式，照搬套路就会断路。套路断的地方，只有结构能接上。

本系列在 12 章之上逐类拆容器内部结构，把"跟着套路做题"推进到"对着结构解题"：

| 章 | 阶段 | 主题 | 解决什么 |
| ---- | ---- | ---- | ---- |
| 本章 | 筑基 · 文件与压缩包 | 导论与工具箱 | 装环境、备齐三件套、练字节与正则基本功、立工作流 |
| [[M02-文件格式深拆I-PNG全解\|M02]] | 筑基 · 文件与压缩包 | 文件格式深拆 I：PNG 全解 | chunk、滤波、压缩层的结构与每一层的藏身处 |
| [[M03-文件格式深拆II-JPEG与GIF\|M03]] | 筑基 · 文件与压缩包 | 文件格式深拆 II：JPEG 与 GIF | 分段与帧结构、损坏修复、动图拆帧 |
| [[M04-压缩包全解\|M04]] | 筑基 · 文件与压缩包 | 压缩包全解 | ZIP/RAR/7z 结构、加密与伪加密、爆破与明文攻击 |
| M05 | 隐写与流量 | 位平面隐写 | LSB 全解：zsteg / stegsolve 背后的通道与位序 |
| M06 | 隐写与流量 | 变换域隐写 | DCT 域嵌入（steghide 系）的原理与口令爆破 |
| M07 | 隐写与流量 | 音频隐写 | 频谱、LSB、回声等音频载体套路 |
| M08 | 隐写与流量 | 文档与视频隐写 | Office / PDF / MP4 容器的夹带与解析 |
| M09 | 隐写与流量 | 流量分析 I | 协议分层拆包，HTTP / ICMP / DNS 套路系统化 |
| M10 | 隐写与流量 | 流量分析 II | USB 键鼠、隧道、加密流量的拆法 |
| M11 | 取证 | 磁盘取证 | 镜像解析、文件系统、删除恢复 |
| M12 | 取证 | 内存取证 | Volatility 全流程与常用插件 |
| M13 | 取证 | 日志取证 | EVTX 与系统日志的时间线还原 |
| M14 | 取证 | 加密介质与口令恢复 | LUKS / BitLocker / 哈希的口令攻击 |
| M15 | 进阶与综合 | 冷门编码大全 | 长尾编码的识别与解码 |
| M16 | 进阶与综合 | 图像处理辅助 | OpenCV 运算、OCR、拼图与二维码修复 |
| M17 | 进阶与综合 | 隐写进阶与检测 | 自适应隐写与统计检测 |
| M18 | 进阶与综合 | 取证综合演练 | 磁盘 + 内存 + 日志的联合作业 |
| M19 | 进阶与综合 | 自动化与脚本工程 | 识别、分流、批量提取的流水线 |
| M20 | 进阶与综合 | 综合实战 | 成套真题全流程：从附件到 flag |

四个阶段各管一段：文件与压缩包是 MISC 的"语法"，后面所有载体都要套在这层结构上；隐写与流量把 12 章 5–7 节的每条套路展开成章；取证把 12 章 8 节"一瞥"过的磁盘与内存各自补成体系；最后从编码、图像一路走到成套真题。

本章是地基：工具箱装调、Python 三件套、字节与正则基本功、工作流工程化。==工具只提供动作，解题水平体现在选哪条路、在哪一层下手==——后续每章都在这四件事之上展开。

## 2. 工具箱装调：两套系统与四条渠道

### 2.1 两套系统的分工

MISC 工具分居两个系统。命令行工具是 Linux 生态的原生工具，全部按"输入文件、输出文本"设计，适合写进脚本批量执行；图形工具不是 Windows 独占就是靠界面吃饭——010 Editor 的结构模板、Wireshark 的点选分析、Audacity 的频谱视图，命令行给不了。两套系统在一台机器上靠 WSL 互通：文件放在 Windows 盘里两侧都能访问，[[01-Linux环境与CTF实验环境搭建|01 章]]已把这套环境搭好。

| 侧 | 定位 | 常驻工具 |
| ---- | ---- | ---- |
| WSL 命令行 | 主战场：识别、拆层、批处理、可复现 | file / xxd / strings、exiftool、pngcheck、binwalk / foremost、tshark、steghide / stegseek / zsteg、bkcrack、7z / unzip / john、vol、evtx_dump、ffmpeg / sox、fls / testdisk |
| Windows 图形界面 | 交互式分析：看图、点选、试听 | 010 Editor（模板化十六进制编辑）、Wireshark（点选式流量分析）、Audacity（波形与频谱视图）、ARCHPR（压缩包口令爆破） |
| 两侧皆可 | 依赖 Java 运行时 | stegsolve.jar（`java -jar stegsolve.jar` 启动，哪边有 Java 哪边跑） |

分工的判断标准只有一条：==要跑很多遍、要接脚本的动作放 WSL；要看、要点、要听的动作放图形界面==。stegsolve 的 Data Extract 对话框两侧体验一致，放哪边都行。

### 2.2 四条安装渠道

工具按发行方式分六组装，渠道认官方推荐的一种，混装容易出现半旧版本：

| 渠道 | 工具 | 验收方式 |
| ---- | ---- | ---- |
| apt | exiftool、steghide、tshark、pngcheck、sox、ffmpeg、testdisk、foremost、qrencode、zbar-tools、aircrack-ng、sleuthkit、python3-opencv、python3-scapy | 逐个报版本行 |
| pip | volatility3（入口命令 vol）、python-evtx | vol -h 首行、evtx_dump 在 PATH |
| gem | zsteg | gem list zsteg |
| .deb | stegseek | stegseek --version |
| 源码编译 | bkcrack | bkcrack -h 首行 |
| jar | stegsolve | java -version 出版本行 |

```bash
# apt 一批：包管理器一次装完（exiftool 的包名叫 libimage-exiftool-perl）
sudo apt install libimage-exiftool-perl steghide tshark pngcheck sox ffmpeg \
    testdisk foremost qrencode zbar-tools aircrack-ng sleuthkit \
    python3-opencv python3-scapy

# pip 一批：volatility3 的入口命令是 vol，不是 vol.py
# 新版 Ubuntu 的 pip 受系统保护，报 externally-managed-environment 时加 --break-system-packages
pip install volatility3 python-evtx

# gem 一件：zsteg 是 Ruby 程序
sudo gem install zsteg

# deb 一件：stegseek，从 GitHub Releases 下载后安装
# https://github.com/RickdeJager/StegSeek/releases
sudo apt install ./stegseek_0.6-1.deb

# 源码一件：bkcrack，cmake 编译
git clone https://github.com/kimci86/bkcrack.git
cd bkcrack
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j        # 产物在 build/src/cli/bkcrack
```

装完逐个验收。apt 组十件，一人一行：

```bash
exiftool -ver
pngcheck -h | head -1
tshark --version | head -1
steghide --version
sox --version
ffmpeg -version | head -1
qrencode --version | head -1
zbarimg --version
fls -V
testdisk --version | head -1
```

输出：

```
13.50
PNGcheck, version 4.0.1,
TShark (Wireshark) 4.6.4.
steghide version 0.5.1
sox:      SoX_ng v14.7.0.9
ffmpeg version 8.0.1-3ubuntu2 Copyright (c) 2000-2025 the FFmpeg developers
qrencode version 4.1.1
0.23.93
The Sleuth Kit ver 4.12.1
TestDisk 7.2, Data Recovery Utility, February 2024
```

其余四组：

```bash
vol -h | head -1                              # pip：volatility3
which vol evtx_dump                           # pip：两个入口命令
gem list zsteg                                # gem
stegseek --version 2>&1 | head -1             # deb
cd bkcrack && build/src/cli/bkcrack -h | head -1    # 源码编译
java -version 2>&1 | head -1                  # jar：stegsolve 只依赖 Java
```

输出：

```
Volatility 3 Framework 2.28.2
/usr/local/bin/vol
/usr/local/bin/evtx_dump
zsteg (0.2.14)
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek
bkcrack 1.8.1 - 2025-10-25
openjdk version "21.0.12.1" 2026-08-18
```

版本行没有统一格式：exiftool 只报数字，zbarimg 连工具名都不带，stegseek 的版本行附带仓库地址。验收只看一条：命令存在且能自报版本。stegsolve 再用 `java -jar stegsolve.jar` 打开一次，出窗口即完成。

> [!warning] volatility3 的入口是 vol，不是 vol.py
> 网上大量教程写 `vol.py -f mem.raw imageinfo`，那是 v2 的用法。pip 装的 v3 入口是 `vol`，插件全部换成 `windows.` 前缀（如 `windows.pslist`），也不再需要 `--profile`。[[12-隐写与流量取证#8. 磁盘与内存取证一瞥|12 章 8 节]]那三条命令是 v2 语法，写脚本时别混。

## 3. Python 三件套：PIL、numpy、scipy

命令行工具负责识别与提取，很多题目还差最后一步"按题意变形"：像素要批量加减、音频要合成分析、位要成组搬动。三件套按数据形态分工：

| 库 | 管什么 | 代表入口 |
| ---- | ---- | ---- |
| PIL（Pillow） | 图像的打开、模式转换、通道、缩放、保存 | `Image.open` / `convert` / `split` / `merge` / `resize` |
| numpy | 把图像、音频变成数组做算术 | `np.array` / `shape` / `packbits` |
| scipy | WAV 读写与频谱分析 | `scipy.io.wavfile` / `scipy.fft` |

安装走 `pip install pillow numpy scipy`（apt 的 python3-pil / python3-numpy / python3-scipy 同样可用，import 名一致）。

### 3.1 PIL：图像的打开与变形

```python
from PIL import Image

img = Image.new("RGB", (4, 2))
img.putdata([(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0),
             (128, 128, 128), (255, 255, 255), (0, 0, 0), (16, 200, 64)])
img.save("demo.png")                     # 扩展名决定保存格式
print(img.size, img.mode)

gray = img.convert("L")                  # 转灰度：按亮度公式加权
print(gray.getpixel((0, 0)), gray.getpixel((2, 0)), gray.getpixel((3, 0)))

rgba = img.convert("RGBA")               # 加透明通道
print(rgba.getpixel((0, 0)))

pal = img.convert("P")                   # 调色板模式：像素存索引号
print(pal.getpixel((0, 0)), pal.convert("RGB").getpixel((0, 0)))

r, g, b = img.split()                    # 拆通道
merged = Image.merge("RGB", (r, g, b))   # 合通道
print(merged.tobytes() == img.tobytes())

print(img.resize((8, 4)).size)           # 缩放
```

输出：

```
(4, 2) RGB
76 29 226
(255, 0, 0, 255)
15 (255, 0, 0)
True
(8, 4)
```

常用五种模式：

| 模式 | 含义 | 像素取值 |
| ---- | ---- | ---- |
| `1` | 1 位黑白 | 0 或 255 |
| `L` | 8 位灰度 | 0–255 |
| `P` | 8 位调色板 | 索引号，真彩色存在调色板里 |
| `RGB` | 24 位真彩 | (r, g, b) 三元组 |
| `RGBA` | 真彩加透明 | (r, g, b, a) 四元组 |

灰度那行输出值得看一眼：纯红 76、纯蓝 29、纯黄 226——L 不是三通道平均，是按人眼敏感度加权的亮度公式。`split` 拆出的每个通道都是 L 模式的灰度图，`merge` 按给定顺序装回去；隐写里"只看 R 通道"这个动作，对应的就是 `img.split()[0]`。

> [!warning] convert 是带换算的转换，不是重解释
> `convert("L")` 按亮度公式加权，`convert("P")` 会重新生成调色板，像素值都会变。需要"字节一个不动、只换一种读法"的场合，用下一节的 `np.array` 拿原始数组。

### 3.2 numpy：图像变数组

```python
import numpy as np
from PIL import Image

arr = np.array(Image.open("demo.png"))   # 沿用 3.1 存下的 demo.png
print(arr.shape, arr.dtype)
print(arr[0, 0], arr[1, 2])

a = np.array([200], dtype=np.uint8)
print(a + 100)                           # 回绕：200 + 100 = 44

bright = np.clip(arr.astype(np.int16) + 100, 0, 255).astype(np.uint8)
print(arr[0, 0], "->", bright[0, 0])     # 升位算术 + 截断

print(255 - arr[0, 0])                   # 广播：一行写完整幅负片

bits = np.unpackbits(np.array([0xB9], dtype=np.uint8))
print(bits)                              # 一个字节拆成 8 个位
print(np.packbits(bits))                 # 拼回去
print(np.packbits(np.unpackbits(np.frombuffer(b"OK", dtype=np.uint8))).tobytes())
```

输出：

```
(2, 4, 3) uint8
[255   0   0] [0 0 0]
[44]
[255   0   0] -> [255 100 100]
[  0 255 255]
[1 0 1 1 1 0 0 1]
[185]
b'OK'
```

五个要点：

1. shape 是 (高, 宽, 通道)，**行在前**：4 宽 2 高的图 shape 是 (2, 4, 3)，下标 `arr[行, 列, 通道]`。
2. dtype 是 uint8，取值 0–255。==uint8 的算术满了就回绕==：200 + 100 得 44，不是 300。提亮这类运算要先 `astype` 升位（int16 或 uint16），算完 `np.clip` 截到 0–255，再转回 uint8。
3. `255 - arr` 整行搞定负片，这是 numpy 的广播：标量与数组直接运算，逐元素生效。
4. `unpackbits` 把字节拆成 8 个位（高位在前），`packbits` 拼回去，`frombuffer` 让 bytes 直接变数组。[[12-隐写与流量取证#5. 图片隐写|12 章 5 节]]手撕 BMP 时用字符串拼位，这一套就是它的向量化版本。
5. 位平面分析（每个位单独提出来看）是后续隐写章的主题；zsteg 一键扫描时试的各种通道与位序组合，试的就是这类开关——这里先把工具装上。

### 3.3 scipy：WAV 与频谱

```python
import numpy as np
from scipy.io import wavfile
from scipy.fft import rfft, rfftfreq

fs = 8000
t = np.linspace(0, 1, fs, endpoint=False)
tone = (np.sin(2 * np.pi * 440 * t) * 20000).astype(np.int16)
wavfile.write("tone440.wav", fs, tone)   # int16 数组落成 WAV 文件

fs2, data = wavfile.read("tone440.wav")  # 读回：采样率 + 数组
print(fs2, data.shape, data.dtype)
print(data[:4])

spec = np.abs(rfft(data.astype(np.float64)))     # FFT 算频谱
freqs = rfftfreq(len(data), 1 / fs2)
print(freqs[np.argmax(spec)])                    # 主频

mix = (np.sin(2 * np.pi * 440 * t) * 12000
       + np.sin(2 * np.pi * 1200 * t) * 20000).astype(np.int16)
spec2 = np.abs(rfft(mix.astype(np.float64)))
print(sorted(round(f) for _, f in sorted(zip(spec2, freqs), reverse=True)[:2]))
```

输出：

```
8000 (8000,) int16
[    0  6774 12748 17214]
440.0
[440, 1200]
```

`wavfile.write` 和 `wavfile.read` 是 WAV 的两端：写入的是 int16 数组加采样率，读回也是这两样——int16 就是 PCM 采样值的存储类型。`rfft` 把时域信号变成频域：440 Hz 的正弦波频谱上只有一根峰，`argmax` 一找一个准；两种频率混合后，频谱上两根峰各占其位。Audacity 的频谱图视图就是这件事的图形界面（[[12-隐写与流量取证#6. 音频隐写|12 章 6 节]]）；需要批量处理音频、自动统计频率成分时，用 scipy 直接算。

## 4. 字节与正则基本功

### 4.1 struct 的完整用法

[[06-Python与CTF脚本基础#3. 字节串与打包|06 章 3 节]]给过 B/H/I/Q/x/s 的小表和 `<` 前缀，[[12-隐写与流量取证|12 章]]解析 PNG 时用过 `>I`。这里把表补全，之后所有格式深拆章都直接用：

| 格式符 | C 类型 | 大小 |
| ---- | ---- | ---- |
| `b` / `B` | signed / unsigned char | 1 |
| `h` / `H` | signed / unsigned short | 2 |
| `i` / `I` | signed / unsigned int | 4 |
| `q` / `Q` | signed / unsigned long long | 8 |
| `f` / `d` | float / double | 4 / 8 |
| `s` | 定长字节串（`4s` 占 4 字节） | 1×n |
| `x` | 填充字节 | 1 |

前缀 `<` 小端、`>` 大端，省略时按本机字节序（x86 上等于 `<`），CTF 里一律写显式前缀。大小端的原则在 [[03-计算机组成与数据表示|03 章]]说过：内存是小端、网络字节序是大端；文件格式两边都有——PNG 的长度字段是大端，BMP 头的字段是小端。

```python
import struct, zlib

print(struct.pack(">I", 13).hex(" "), "|", struct.pack("<I", 13).hex(" "))
be = bytes.fromhex("0000000d")
print(struct.unpack(">I", be)[0], "|", struct.unpack("<I", be)[0])
print(int.from_bytes(be, "big"), "|", int.from_bytes(be, "little"))
print(b"flag{struct}".hex(), "->", bytes.fromhex("666c61677b7374727563747d"))

data13 = struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0)    # 宽8 高8 位深8 颜色类型2(RGB)
crc = zlib.crc32(b"IHDR" + data13) & 0xFFFFFFFF
chunk = struct.pack(">I", 13) + b"IHDR" + data13 + struct.pack(">I", crc)
print(chunk.hex(" "))

head = struct.pack("<IHHI", 822, 0, 0, 54)
print(struct.calcsize("<IHHI"), head.hex(" "), struct.unpack("<IHHI", head))
```

输出：

```
00 00 00 0d | 0d 00 00 00
13 | 218103808
13 | 218103808
666c61677b7374727563747d -> b'flag{struct}'
00 00 00 0d 49 48 44 52 00 00 00 08 00 00 00 08 08 02 00 00 00 4b 6d 29 dc
12 36 03 00 00 00 00 00 00 36 00 00 00 (822, 0, 0, 54)
```

第 1 行是同一个数 13 的两种字节顺序，按小端去解大端的字节就得 218103808——解出数字离谱地大时，先查字节序。中间那次打包现场拼出了一个合法的 IHDR 块，和 [[12-隐写与流量取证#3. PNG 内部结构：拆开看|12 章 3 节]]解析过的那块完全一致：CRC 只由"类型 + 数据"决定，同样的宽高参数必然得到同一个 `4b6d29dc`。最后一行的 `<IHHI` 是 [[12-隐写与流量取证#5. 图片隐写|12 章 5 节]]手撕 BMP 用过的文件头格式，`calcsize` 算出总长 12 字节。

单字段的转换不必动 struct：`bytes.hex()` 与 `bytes.fromhex()`、`int.from_bytes(b, "big")` 与 `n.to_bytes(长度, "big")` 两条轻量路径覆盖大多数场合，struct 留给多字段混排。

### 4.2 二进制里的正则打靶

两个高频检索模式，先立住：

| 模式 | 抓什么 |
| ---- | ---- |
| `rb"flag\{[^}]{1,64}\}"` | 明文 flag：`[^}]` 排除右括号防越界，`{1,64}` 防止一路匹配到文件尾 |
| `rb"[A-Za-z0-9+/]{16,}={0,2}"` | base64 候选：长度 16 起步过滤噪声，结尾最多两个 `=` |

`rb` 前缀不能省：bytes 模式配 bytes 数据，str 模式撞上 bytes 数据直接 TypeError。拿一个混入明文 flag 和 base64 的二进制 blob 打靶：

```python
import base64, re

secret = b"flag{regex_in_bytes}"
b64 = base64.b64encode(secret)
noise = bytes((i * 37 + 11) % 256 for i in range(24))
blob = (noise
        + b"\x00junk around " + b64 + b" around\x00"
        + noise[::-1]
        + b"xxflag{found_in_blob}yy"
        + bytes(range(0, 32)))
open("blob.bin", "wb").write(blob)
blob = open("blob.bin", "rb").read()

for m in re.finditer(rb"flag\{[^}]{1,64}\}", blob):
    print("[flag]", m.group().decode(), "@", m.start())

for m in re.finditer(rb"[A-Za-z0-9+/]{16,}={0,2}", blob):
    cand = m.group()
    fixed = cand + b"=" * (-len(cand) % 4)          # 补齐到 4 的倍数
    try:
        dec = base64.b64decode(fixed, validate=True)
    except Exception:
        continue
    if b"flag" in dec:
        print("[base64]", cand.decode(), "->", dec.decode(), "@", m.start())

print(base64.b64decode(b"hZ3tyZWdleF9pbl9"))        # 对齐错位的片段：解出乱码
```

输出：

```
[flag] flag{found_in_blob} @ 99
[base64] ZmxhZ3tyZWdleF9pbl9ieXRlc30= -> flag{regex_in_bytes} @ 37
b'\x85\x9d\xed\xc9\x95\x9d\x95\xe1}\xa5\xb9}'
```

三处细节：

1. `-len(cand) % 4` 算出该补几个 `=`：base64 编码长度必须是 4 的倍数（[[08-编码与古典密码|08 章]] 2 节）。
2. `validate=True` 让字母表之外的字符直接抛异常，不再静默忽略；候选越脏越要开。
3. 最后一行是从 base64 串中间切 16 字节的下场：不报错，解出来全是乱码。==解码不是终点，解出可读内容才是==——拿到解码结果先检查是不是可见字符。

两个模式值得留在工具箱里常驻，任何附件都可以先扫一遍再谈别的；`m.start()` 给出的偏移还能直接喂给 dd 切片。

## 5. 工作流工程化

### 5.1 目录组织

一道 MISC 题的工作目录固定四件：

```
misc01/
├── challenge/          # 题目附件，只读，实验一律在副本上做
│   └── target.png
├── extracted/          # 拆出来的一切中间产物
│   ├── hidden.zip
│   └── secret.txt
├── solve.py            # 解题脚本：命令行的长跑版
└── notes.md            # 笔记：试过什么、看到什么、下一步是什么
```

三条纪律：challenge/ 只读——出题人的附件改坏了，原题就没了；extracted/ 收留一切拆出的产物，套娃拆出的东西全部落盘，不用内存里一闪而过的对象；notes.md 记录过程——卡题放下再捡起时，它是唯一可靠的记忆，赛后整理 writeup 也靠它。solve.py 的定位是"同一组动作要在多个文件上重跑"时的载体，比如批量拆缩略图、批量试参数。

### 5.2 固定动作清单

拿到附件，不看题目描述先把前四步跑完：

1. **file 问真身**——后缀不算数（[[12-隐写与流量取证#1. MISC 解题总流程：先验身份证|12 章 1 节]]）
2. **xxd 看头尾**——头是否完好，尾部有没有夹带（[[12-隐写与流量取证#2. 文件格式与魔数|12 章 2 节]]）
3. **strings 扫可见串**——成本一秒，未压缩的内容直接现形（[[12-隐写与流量取证#1. MISC 解题总流程：先验身份证|12 章 1 节]]）
4. **pngcheck / binwalk 查结构**——PNG 报 IEND 之后的追加数据，binwalk 列出全部嵌入文件（[[12-隐写与流量取证#8. 磁盘与内存取证一瞥|12 章 8.1]]）
5. **按真身进对应工具拆层**——图片 exiftool / stegsolve，压缩包 7z / unzip，音频 sox / ffmpeg
6. **每拆出一个文件，回到第 1 步**

==清单的价值在于前四步的成本低到可以无条件执行==。多数签到题在第 2、3 步就结束；剩下的题目靠它搭梯子。4.2 的两个正则写成一个 scan.py，就是第 3 步的加强版。

### 5.3 一条龙拆解

造一个标准靶子：PNG 尾部粘 ZIP，ZIP 里的 secret.txt 藏着 base64 后的 flag。PNG 解析到 IEND 为止，之后粘什么查看器都当没看见，这正是"尾部夹带"成立的前提。

```python
# build_target.py —— 造靶：PNG 尾部粘 ZIP，ZIP 里 secret.txt 藏 base64(flag)
import base64, io, zipfile
from PIL import Image

img = Image.new("RGB", (128, 128))
for y in range(128):
    for x in range(128):
        img.putpixel((x, y), ((x * x + y * y) % 256, (x * 2 + y) % 256, (x + y * 3) % 256))
buf = io.BytesIO()
img.save(buf, "PNG")
png = buf.getvalue()

flag = "flag{png_zip_full_chain}"
content = base64.b64encode(flag.encode())
mem = io.BytesIO()
with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("secret.txt", content)
zip_bytes = mem.getvalue()

open("challenge/target.png", "wb").write(png + zip_bytes)
print(len(png), len(zip_bytes), len(png + zip_bytes))
print(content.decode())
```

输出：

```
9841 152 9993
ZmxhZ3twbmdfemlwX2Z1bGxfY2hhaW59
```

`io.BytesIO` 是内存里的文件对象，PIL 和 zipfile 都直接收。靶子就位，按 5.2 清单从头走。

第 1 步，file 只看文件开头，尾部粘了什么它都不报：

```bash
file challenge/target.png
```

输出：

```
challenge/target.png: PNG image data, 128 x 128, 8-bit/color RGB, non-interlaced
```

第 2 步，xxd 看尾巴，ASCII 列里躺着 `secret.txt` 和 `PK`——ZIP 的痕迹：

```bash
xxd challenge/target.png | tail -3
```

输出：

```
000026e0: 0000 0080 0100 0000 0073 6563 7265 742e  .........secret.
000026f0: 7478 7450 4b05 0600 0000 0001 0001 0038  txtPK..........8
00002700: 0000 004a 0000 0000 00                   ...J.....
```

同一层还有个专用探测器：pngcheck 是 PNG 自家的校验器，直接点名 IEND 之后有追加数据：

```bash
pngcheck challenge/target.png
```

输出：

```
challenge/target.png  additional data after IEND chunk
ERROR: challenge/target.png
```

第 3 步，strings 扫可见串。文件名露了头，内容却是乱码——ZIP 用 deflate 压缩过，strings 只看得见没压缩的部分：

```bash
strings challenge/target.png | tail -4
```

输出：

```
IEND
secret.txt
2.)O
secret.txtPK
```

第 4 步，binwalk 定位嵌入文件：

```bash
binwalk challenge/target.png
```

输出：

```

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 128 x 128, 8-bit/color RGB, non-interlaced
41            0x29            Zlib compressed data, default compression
9841          0x2671          Zip archive data, at least v2.0 to extract, compressed size: 34, uncompressed size: 32, name: secret.txt
9971          0x26F3          End of Zip archive, footer length: 22
```

表里 0x29 那行 zlib 是 PNG 自己的 IDAT 流，被顺带认出来；真正的货是 0x2671 的 ZIP，起点 9841。binwalk 的报告要人工分辨哪些是容器自身结构、哪些是夹带。

第 5 步，dd 从偏移 9841 切到文件尾（[[12-隐写与流量取证#8. 磁盘与内存取证一瞥|12 章 8.1]]的手法），解包：

```bash
dd if=challenge/target.png of=extracted/hidden.zip bs=1 skip=9841
file extracted/hidden.zip
unzip -o extracted/hidden.zip -d extracted/
cat extracted/secret.txt
```

输出：

```
152+0 records in
152+0 records out
152 bytes copied, 0.00015125 s, 152 kB/s
extracted/hidden.zip: Zip archive data, made by v2.0 UNIX, extract using at least v2.0, last modified Oct 24 2026 18:34:08, uncompressed size 32, method=deflate
Archive:  extracted/hidden.zip
  inflating: extracted/secret.txt
ZmxhZ3twbmdfemlwX2Z1bGxfY2hhaW59
```

第 6 步，对拆出的文件回到第 1 步——这次直接解码，flag 出来：

```bash
base64 -d extracted/secret.txt
```

输出：

```
flag{png_zip_full_chain}
```

六步，每步一条命令，全程没有一步靠猜。真实赛题的套娃比这深：ZIP 里再粘 PNG，最里层是 LSB 图或频谱音频——流程不变，[[#5.2 固定动作清单|5.2]] 的清单循环执行。PNG 的结构层在 [[M02-文件格式深拆I-PNG全解|M02]] 拆透，JPEG 与 GIF 在 [[M03-文件格式深拆II-JPEG与GIF|M03]]，压缩包的加密与攻击在 [[M04-压缩包全解|M04]] 展开。

## 6. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| file 什么都不认识，报 data | 魔数不在 file 的表里，或头几个字节被改。先 xxd 看前 16 字节查魔数表（[[12-隐写与流量取证#2. 文件格式与魔数\|12 章 2 节]]），头损坏按 12 章 2.2 的方法补回 |
| pip 装了包，import 却找不到或版本不对 | apt 的 python3-xxx 和 pip 的同名包装了两份，import 到哪份取决于 sys.path 顺序。用 `python3 -c "import 模块; print(模块.__file__)"` 查实际加载路径，同一模块只留一条渠道 |
| vol 报错，和 12 章的 vol.py 用法对不上 | [[12-隐写与流量取证#8. 磁盘与内存取证一瞥\|12 章 8.2]]写的是 v2 语法；pip 装的 v3 入口是 vol，插件用 `windows.` 前缀，不再需要 --profile |
| stegsolve 双击没反应，WSL 里开不出窗口 | 缺 Java 运行时或无图形环境。`java -version` 验 Java；WSL 里要有 WSLg 才能开窗，也可以把 jar 挪到 Windows 侧用 `java -jar` 跑 |
| /mnt/c 下处理文件特别慢 | WSL 访问 Windows 盘走 DrvFS，IO 开销大。把附件复制到 WSL 原生目录（~/）再处理，结果再拷回 |
| Git Bash 里给 WSL 传命令，变量和引号被吞 | 外层 shell 先解释了一遍参数。把命令写进脚本文件，`wsl -- bash /mnt/c/.../x.sh` 整体执行，不在命令行里拼 `$` |
| re 报 TypeError: cannot use a string pattern on a bytes-like object | str 模式配了 bytes 数据。模式加 `rb` 前缀，两侧类型对齐 |
| base64 解码报 Incorrect padding | 长度不是 4 的倍数。补 `=` 或属编码剥层问题，见 [[08-编码与古典密码#9. 常见问题\|08 章常见问题]] |

## 7. 配套练习与延伸阅读

配套练习：

1. 对照 2.2 把工具箱过一遍：六条渠道逐个验收，缺哪个装哪个，十行版本行全部跑齐。
2. 把 3 节三件套各改一个参数重跑：demo.png 换尺寸、提亮量换成 200、tone440 换成 528 Hz——每处输出变化都要能解释。
3. 造一个"JPEG 尾部粘 ZIP"的靶子（尾部魔数见 [[12-隐写与流量取证#2. 文件格式与魔数\|12 章 2 节]]的魔数表），按 5.2 清单从头拆到 flag。
4. 把 4.2 的两个正则写进 scan.py：命令行参数收文件名，命中就打印偏移与内容——它就是清单第 3 步的加强版。

延伸阅读：

- [[01-练习平台索引|练习平台索引]]：按难度挑 MISC 入门题，每题都按 5.2 清单走一遍；
- [[03-工具清单|工具清单]]：本章工具的同类替代与装法一览；
- [[12-隐写与流量取证|12 章]]：套路速查的原版，本系列每章都会回头引它；
- 下一站：[[M02-文件格式深拆I-PNG全解|M02]] 把 PNG 从签名到像素层拆透——本章的 PIL 数组、struct 打包、CRC 拼块，都要在它身上用透。
