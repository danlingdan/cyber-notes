---
chapter: MISC
section: 文档与 Office 隐写
order: 807
tags:
  - CTF
  - MISC
  - 隐写
publish: true
---

# M07 文档与 Office 隐写
## Document & Office Steganography

> [!info]- 章节信息
> **所属方向**：MISC ｜ **难度阶段**：L2 核心期 ｜ **前置要求**：[[12-隐写与流量取证|12 章]] · [[M04-压缩包全解|M04]] · [[M01-MISC导论与工具箱|M01]]
> **本章目标**：把文档类附件的四类容器（OOXML、PDF、纯文本、老格式 OLE2）的隐写面各过一遍：unzip 手抠 docx 的白字、隐藏文字、批注与媒体夹带；exiftool 读文档元数据并分清字段名；纯 Python 手写最小 PDF，对照 pdftotext 与对象区的差异，掌握未引用对象、增量更新、附件、元数据四种藏法；手撕零宽字符的编码与解码；用 olefile 翻 OLE2 复合文档的流。最后落成文档题的固定解题顺序。

## 1. 文档容器总览与解题顺序

图片和压缩包之后，MISC 的第三大类附件是文档：`docx`、`pdf`、`txt`，以及老题里常见的 `doc`/`xls`/`ppt`。[[12-隐写与流量取证|12 章]]的通用手法对它们全部适用——`file` 认真身、`strings` 扫可见串、`binwalk`/`foremost` 分离嵌套文件；`exiftool` 在图片上读 EXIF，在文档上读的是另一套字段，钥匙不变、锁孔换了。本章讲文档容器自己的结构面。

四类容器各有一个隐写面清单：

| 容器 | file 报真身 | 隐写面 | 去处 |
| ---- | ---- | ---- | ---- |
| OOXML（docx/xlsx/pptx） | `Microsoft Word 2007+` | XML 内容层（白字、隐藏文字）、批注、docProps 元数据、word/media/ 嵌入媒体、run 里的零宽字符 | 2、3、5 节 |
| PDF | `PDF document` | 未引用对象、增量更新、附件、Info 元数据、内嵌图片 | 4 节 |
| 纯文本（txt/md/网页片段） | `Unicode text, UTF-8 text` | 零宽字符与不可见 Unicode | 5 节 |
| 老格式 OLE2（doc/xls/ppt） | `Composite Document File V2 Document` | 流结构、流里藏文件 | 6 节 |

解题顺序固定，和 [[M01-MISC导论与工具箱|M01]]的附件清单是同一套思路的文档版：

1. `file` 问真身；
2. 是 OOXML：`unzip -l` 列结构，`exiftool` 读元数据，再细看 document.xml / comments.xml / media；
3. 是 PDF：`pdftotext` 提正文，`pdfinfo` 看元数据，`strings` 和正则扫对象区；
4. 是文本：文件大小与可见字符数对不上，就扫不可见码点（5.3 节）；
5. 拆出的每个文件，回到第 1 步。

本章四节各造一个靶子，正好对应上表四行。对四个靶子跑一遍 `file`：

```bash
file demo.docx demo.pdf cover.txt fake.doc
```

输出：

```
demo.docx: Microsoft Word 2007+
demo.pdf:  PDF document, version 1.4, 1 page(s)
cover.txt: Unicode text, UTF-8 text, with no line terminators
fake.doc:  Composite Document File V2 Document, Cannot read section info
```

第一行 `Microsoft Word 2007+` 不是 file 认出了 Word，而是它认出了 ZIP 里面写着 Word 的登记表——这正是下一节的主题。

## 2. OOXML 就是 ZIP

`file` 报 `Microsoft Word 2007+` 的文件，本质是一个 ZIP：把扩展名改成 `.zip`，一个字节都不用动，unzip 直接开。[[M04-压缩包全解|M04]]拆过 ZIP 的字段级结构——本地文件头、中央目录、EOCD——那些知识在这里全部适用。OOXML 做的事，只是在 ZIP 里规定了必须有哪些成员、每个成员扮演什么角色。==拿到文档类附件，先 unzip 再谈别的==。

### 2.1 内部结构

用 zipfile 把八个成员装成一个 docx（构建要点见本节末尾的折叠框），`unzip -l` 看清单：

```bash
unzip -l demo.docx
```

输出：

```
Archive:  demo.docx
  Length      Date    Time    Name
---------  ---------- -----   ----
      857  2026-10-24 09:00   [Content_Types].xml
      593  2026-10-24 09:00   _rels/.rels
      993  2026-10-24 09:00   word/document.xml
      289  2026-10-24 09:00   word/_rels/document.xml.rels
      304  2026-10-24 09:00   word/comments.xml
      747  2026-10-24 09:00   docProps/core.xml
      358  2026-10-24 09:00   docProps/app.xml
      137  2026-10-24 09:00   word/media/badge.png
---------                     -------
     4278                     8 files
```

每个成员的角色：

| 成员 | 角色 |
| ---- | ---- |
| `[Content_Types].xml` | 全包登记表：声明每种扩展名、每个部件的内容类型 |
| `_rels/.rels` | 包级关系表：入口部件（word/document.xml）与元数据部件的位置 |
| `word/document.xml` | 正文内容层：全部文字与格式，隐写主战场 |
| `word/_rels/document.xml.rels` | 文档级关系表：批注、图片等部件的挂载记录 |
| `word/comments.xml` | 批注内容 |
| `docProps/core.xml`、`docProps/app.xml` | 元数据（3 节） |
| `word/media/` | 嵌入媒体目录：图片的默认住址，也是夹带的热门住址 |

> [!info]- xlsx 与 pptx 的对应位置
> 三个格式共用同一套布局，只是目录名不同：xlsx 的单元格数据在 `xl/worksheets/sheet1.xml`，但文字常被收进 `xl/sharedStrings.xml` 统一存放——查 xlsx 时这个文件必须单独 grep；pptx 的每页在 `ppt/slides/slide1.xml`，媒体在 `ppt/media/`。看清入口靠 `_rels/.rels` 和各目录的 `.rels`，与 docx 同理。

### 2.2 三种文字藏法与 XML 特征

document.xml 里的最小文字单元是 run：`<w:r>` 包属性 `<w:rPr>` 与文本 `<w:t>`。三种藏法全部发生在 run 这一层：

| 藏法 | XML 特征 | 肉眼效果 | 内容位置 |
| ---- | ---- | ---- | ---- |
| 白字 | run 属性里有 `<w:color w:val="FFFFFF"/>` | 白色文字叠在白色页面上，屏幕与打印都看不见 | word/document.xml |
| 隐藏文字 | run 属性里有 `<w:vanish/>` | 默认不显示、不打印 | word/document.xml |
| 批注 | 正文里只有 `commentRangeStart/End` 两个标记 | 正文流里没有这段文字，悬浮面板里才有 | word/comments.xml |

靶子里三个藏点的原文（word/document.xml 节选）：

```xml
<!-- 白字：颜色属性写 FFFFFF，文字照常在 w:t 里 -->
<w:r><w:t>Total budget approved.</w:t></w:r>
<w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>flag{white_on_white}</w:t></w:r>

<!-- 隐藏文字：w:vanish 一枚标记，整段 run 从视图消失 -->
<w:r><w:rPr><w:vanish/></w:rPr><w:t>flag{vanish_run}</w:t></w:r>

<!-- 批注：正文挂起止标记，内容本体在 comments.xml -->
<w:r><w:t>Reviewed by two editors.</w:t></w:r>
<w:commentRangeStart w:id="0"/><w:r><w:t>Needs a second look.</w:t></w:r>
<w:commentRangeEnd w:id="0"/><w:r><w:commentReference w:id="0"/></w:r>
```

批注内容本体在 `word/comments.xml`，unzip 一条命令全部倒出：

```bash
unzip -p demo.docx word/comments.xml
```

输出：

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:comment w:id="0" w:author="Reviewer" w:date="2026-10-24T09:30:00Z" w:initials="R">
<w:p><w:r><w:t>flag{comments_xml}</w:t></w:r></w:p>
</w:comment>
</w:comments>
```

两种 run 级藏法不翻文件也可以先扫特征，grep 直接报：

```bash
unzip -p demo.docx word/document.xml | grep -oE '<w:color w:val="[^"]*"/>|<w:vanish/>'
```

输出：

```
<w:color w:val="FFFFFF"/>
<w:vanish/>
```

> [!info]- 从零手写最小 OOXML
> 最小可用的 docx 只需三个成员：`[Content_Types].xml`、`_rels/.rels`、`word/document.xml`。前两个是固定模板，照抄即可：
>
> ```xml
> <!-- [Content_Types].xml -->
> <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
>   <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
>   <Default Extension="xml" ContentType="application/xml"/>
>   <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
> </Types>
> ```
>
> ```xml
> <!-- _rels/.rels -->
> <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
>   <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
> </Relationships>
> ```
>
> 在此之上按需追加：批注要在 `[Content_Types].xml` 加 comments 部件的 Override、在 `word/_rels/document.xml.rels` 加一条关系；媒体夹带加一条 png 的 Default。zipfile 装包时 `[Content_Types].xml` 惯例放第一个成员。本章的造靶脚本就是按这份清单装配的，用 `zipfile` 与 `re` 的基本功（[[06-Python与CTF脚本基础|06 章]]）即可完成。

### 2.3 定位与取出

提取脚本对 document.xml 逐 run 检查属性：属性里有 `FFFFFF` 判白字、有 `<w:vanish/>` 判隐藏文字；批注单独读 comments.xml；媒体夹带读前四字节验魔数（`PK\x03\x04` 是 ZIP 本地头，[[M04-压缩包全解|M04]]讲过；PNG 自己的签名 `89 50 4E 47` 在 [[M02-文件格式深拆I-PNG全解|M02]]拆过）：

```python
# find_docx_secrets.py —— 解析 word/document.xml，定位白字与隐藏文字
import re
import zipfile

z = zipfile.ZipFile("demo.docx")
xml = z.read("word/document.xml").decode()

for m in re.finditer(r"<w:r>(?:(?P<rpr><w:rPr>.*?</w:rPr>))?(?P<body>.*?)</w:r>", xml, re.S):
    rpr = m.group("rpr") or ""
    text = "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", m.group("body")))
    marks = []
    if 'w:val="FFFFFF"' in rpr:
        marks.append("白字")
    if "<w:vanish/>" in rpr:
        marks.append("隐藏文字")
    if marks:
        print("+".join(marks), "->", text)

cxml = z.read("word/comments.xml").decode()
print("批注 ->", "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", cxml)))

badge = z.read("word/media/badge.png")
print("badge.png 前 4 字节:", badge[:4], "—— 不是 PNG 签名")
```

```bash
python3 find_docx_secrets.py
```

输出：

```
白字 -> flag{white_on_white}
隐藏文字 -> flag{vanish_run}
批注 -> flag{comments_xml}
badge.png 前 4 字节: b'PK\x03\x04' —— 不是 PNG 签名
```

三面旗一次收齐。白字与隐藏文字的特征是写死的（`FFFFFF`、`w:vanish`），真实赛题里出题人可能换颜色（浅灰 `F5F5F5`、同底色）或组合多个属性，判据放宽成"属性里出现颜色/vanish 就打印"即可。

### 2.4 媒体夹带

`word/media/` 名义上是图片目录，但 ZIP 不检查成员内容——塞进去什么它就存什么。把 badge.png 取出来看真身：

```bash
unzip -p demo.docx word/media/badge.png > badge.bin
file badge.bin
unzip -o -q badge.bin -d badge_out
cat badge_out/flag.txt
```

输出：

```
badge.bin: Zip archive data, made by v2.0 UNIX, extract using at least v2.0, last modified Oct 24 2026 09:00:00, uncompressed size 21, method=deflate
flag{media_stowaway}
```

==media 里的文件先抽出来再 `file`，扩展名不作数==。顺带一提，unzip 抽出的成员还可以直接给 binwalk 接力——那是 [[12-隐写与流量取证|12 章]]的老手法。

> [!warning] 手改 XML 的两个坑
> 一是标签不闭合、命名空间丢失，文档直接打不开：`unzip -t` 只能验 ZIP 层的完整性，验不出 XML 层的语法错，改完 XML 用 `lxml` 解析一遍或用软件开一次再交付；二是 Word 的"检查文档"功能会清掉批注、隐藏文字和一部分元数据——分析附件前别顺手点它，也别指望清理过的文件里还能找到原始批注。

## 3. 文档元数据：docProps

2.1 的成员表里有两个 `docProps` 部件，它们就是文档的"简历"：`core.xml` 存标题、作者、时间这类核心属性，`app.xml` 存应用与公司信息。exiftool 一条命令全倒出来（文件系统的时间行略去）：

```bash
exiftool demo.docx
```

输出：

```
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0
Zip Compression                 : Deflated
Zip Modify Date                 : 2026:10:24 09:00:00
Zip CRC                         : 0x5f87be89
Zip Compressed Size             : 299
Zip Uncompressed Size           : 857
Zip File Name                   : [Content_Types].xml
Title                           : Quarterly Report
Subject                         : Budget review
Creator                         : Administrator
Keywords                        : review; draft
Description                     : flag{core_xml_description}
Last Modified By                : Admin
Create Date                     : 2026:10:24 09:00:00Z
Modify Date                     : 2026:10:24 10:30:00Z
Application                     : Microsoft Office Word
Company                         : CTF Workshop
App Version                     : 16.0000
```

文档字段与 XML 元素的对照：

| docProps/core.xml 元素 | exiftool 字段 | Word 界面叫法 |
| ---- | ---- | ---- |
| `dc:title` | Title | 标题 |
| `dc:subject` | Subject | 主题 |
| `dc:creator` | Creator | 作者 |
| `cp:keywords` | Keywords | 关键字 |
| `dc:description` | Description | 备注 |
| `cp:lastModifiedBy` | Last Modified By | 最后修改者 |
| `dcterms:created` / `dcterms:modified` | Create Date / Modify Date | 创建/修改时间 |

docProps/app.xml 的 `Application`、`Company`、`AppVersion` 对应 exiftool 的 Application、Company、App Version。`Zip` 开头的一组字段不是文档属性，是 ZIP 层第一个成员（`[Content_Types].xml`）的压缩信息，别当成藏东西的地方。

两个做题要点。第一，==docx 没有 Comment 字段==：图片的 EXIF Comment（[[12-隐写与流量取证|12 章]] 5.2 的常客）在 docx 上对应的字段叫 Description，元素是 `dc:description`——exiftool 找不到 Comment 不是工具坏了。单抠字段值：

```bash
exiftool -s -Description demo.docx
exiftool -b -Description demo.docx
```

输出：

```
Description                     : flag{core_xml_description}
flag{core_xml_description}
```

`-s` 显示内部字段名（`LastModifiedBy` 不带空格），`-b` 只输出值、方便接进脚本。第二，元数据的原文就是 XML，直接看最清楚：

```bash
unzip -p demo.docx docProps/core.xml
```

输出：

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>Quarterly Report</dc:title>
<dc:subject>Budget review</dc:subject>
<dc:creator>Administrator</dc:creator>
<cp:keywords>review; draft</cp:keywords>
<dc:description>flag{core_xml_description}</dc:description>
<cp:lastModifiedBy>Admin</cp:lastModifiedBy>
<dcterms:created xsi:type="dcterms:W3CDTF">2026-10-24T09:00:00Z</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">2026-10-24T10:30:00Z</dcterms:modified>
</cp:coreProperties>
```

> [!warning] 另存会重写元数据
> 用 Word 或 LibreOffice 打开后另存，修改时间、应用版本、统计字段全部刷新，`dc:description` 这类字段还可能被清空。分析只读原件；要修改验证结论，在副本上做（[[M01-MISC导论与工具箱|M01]]的目录纪律）。

## 4. PDF 对象结构

PDF 是纯文本语法加二进制流的混合体：整个文件由对象拼成，用记事本打开就能读语法。poppler 套件的四个工具分工明确——`pdftotext` 提正文、`pdfinfo` 看元数据、`pdfdetach` 提附件、`pdfimages` 提图片。

### 4.1 最小 PDF 的组成

```
%PDF-1.4                       ← 头：版本号
1 0 obj  …  endobj             ← 对象区：catalog、pages、page、内容流、字体……
xref                           ← 交叉引用表：每个对象在文件里的字节偏移
trailer
<< /Size 11 /Root 1 0 R /Info 6 0 R >>
startxref
<xref 的字节偏移>
%%EOF                          ← 结束标记，允许有多个
```

对象从 1 号起编，编号允许不连续；`/Root` 指向 catalog，是整棵对象树的入口；`/Info` 指向 Info 字典，即元数据。页面文字写在内容流里（`BT … Tj ET` 之间的文本指令），==pdftotext 只读这些内容流，对象区里其他地方的文字它一概不碰==。

> [!info]- xref 与增量更新的语法细节
> xref 的每个条目固定 20 字节：10 位偏移、空格、5 位代号、空格、`n`（在使用）或 `f`（空闲）、空格加换行；0 号条目是空闲哨兵。PDF 允许在 `%%EOF` 之后追加内容做"增量更新"：新对象接在后面，配第二段 xref 与 trailer，trailer 里的 `/Prev` 指回上一段 xref 的偏移——阅读器按这条链把所有版本拼起来。判断文件是否被追加过，数 `%%EOF` 的个数即可。

### 4.2 自造靶：一处页面、四处私货

纯 Python 手写一个最小 PDF，正常页面之外塞进四种东西：Info 字典里藏一个 flag、一个未引用对象、一对附件、以及 `%%EOF` 之后的增量更新：

```python
# make_pdf.py —— 手写最小 PDF：正常页面 + Info 元数据 + 附件 + 未引用对象 + 增量更新
objs = {}
objs[1] = (b"<< /Type /Catalog /Pages 2 0 R "                    # catalog：对象树入口
           b"/Names << /EmbeddedFiles << /Names [(flag.txt) 7 0 R] >> >> >>")
objs[2] = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
objs[3] = (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
           b"/Resources << /Font << /F1 5 0 R >> /XObject << /Im1 10 0 R >> >> "
           b"/Contents 4 0 R >>")

content = (b"BT /F1 18 Tf 72 720 Td (Team meeting notes - budget approved.) Tj ET\n"
           b"q 120 0 0 120 72 480 cm /Im1 Do Q")
objs[4] = (b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
           + content + b"\nendstream")

objs[5] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
objs[6] = (b"<< /Author (Admin) /Producer (handwritten.py) "     # Info 字典：元数据
           b"/Subject (flag{pdf_info_dict}) /CreationDate (D:20261024090000Z) >>")

payload = b"flag{pdf_attachment}"
objs[7] = b"<< /Type /Filespec /F (flag.txt) /EF << /F 8 0 R >> >>"   # 附件登记
objs[8] = (b"<< /Type /EmbeddedFile /Length " + str(len(payload)).encode()
           + b" >>\nstream\n" + payload + b"\nendstream")             # 附件本体

objs[9] = b"(flag{unreferenced_object})"     # 没有任何对象引用它

pixels = bytes(v for y in range(8) for x in range(8)          # 8x8 RGB 原始采样
               for v in ((x * 32) % 256, (y * 32) % 256, 128))
objs[10] = (b"<< /Type /XObject /Subtype /Image /Width 8 /Height 8 "
            b"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Length "
            + str(len(pixels)).encode() + b" >>\nstream\n" + pixels + b"\nendstream")

out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
offsets = {}
for n in sorted(objs):
    offsets[n] = len(out)
    out += str(n).encode() + b" 0 obj\n" + objs[n] + b"\nendobj\n"

xref1 = len(out)
out += b"xref\n0 11\n0000000000 65535 f \n"
for n in range(1, 11):
    out += ("%010d 00000 n \n" % offsets[n]).encode()
out += (b"trailer\n<< /Size 11 /Root 1 0 R /Info 6 0 R >>\nstartxref\n"
        + str(xref1).encode() + b"\n%%EOF\n")

upd_off = len(out)                           # 增量更新：EOF 之后追加对象 11
out += b"11 0 obj\n(flag{appended_after_eof})\nendobj\n"
xref2 = len(out)
out += b"xref\n11 1\n" + ("%010d 00000 n \n" % upd_off).encode()
out += (b"trailer\n<< /Size 12 /Root 1 0 R /Info 6 0 R /Prev " + str(xref1).encode()
        + b" >>\nstartxref\n" + str(xref2).encode() + b"\n%%EOF\n")

open("demo.pdf", "wb").write(bytes(out))
```

四个 PDF 工具对这个靶子各报各的：

```bash
file demo.pdf
pdfinfo demo.pdf
```

输出：

```
demo.pdf: PDF document, version 1.4, 1 page(s)
Subject:         flag{pdf_info_dict}
Author:          Admin
Producer:        handwritten.py
CreationDate:    Sat Oct 24 17:00:00 2026 CST
Custom Metadata: no
Metadata Stream: no
Tagged:          no
UserProperties:  no
Suspects:        no
Form:            none
JavaScript:      no
Pages:           1
Encrypted:       no
Page size:       612 x 792 pts (letter)
Page rot:        0
File size:       1676 bytes
Optimized:       no
PDF version:     1.4
```

`/Subject` 里的 flag 第一步就现形。`pdftotext` 是另一副面孔：

```bash
pdftotext demo.pdf -
```

输出：

```
Team meeting notes - budget approved.
```

只有内容流里那一行。==pdftotext 提取不出，不等于文件干净==——未引用对象、附件、增量更新里的 flag 本来就不在页面文字里。

### 4.3 四种隐藏法与发现手段

| 藏法 | 什么样子 | 发现与提取 |
| ---- | ---- | ---- |
| 未引用对象 | 对象区里有对象，但没有任何对象引用它 | strings / 正则扫关键词，pdftotext 不显示 |
| 增量更新 | 多个 %%EOF，第二个 trailer 带 /Prev | 数 %%EOF，看两段之间的追加内容 |
| 附件 | /Filespec + /EmbeddedFile，登记在 catalog 的 /Names 下 | pdfdetach -list / -saveall |
| 元数据 | Info 字典的 /Author /Producer /Subject | pdfinfo、exiftool |

附件走 pdfdetach：

```bash
pdfdetach -list demo.pdf
pdfdetach -saveall demo.pdf
cat flag.txt
```

输出：

```
1 embedded files
1: flag.txt
flag{pdf_attachment}
```

未引用对象与增量更新的私货，strings 先扫一遍：

```bash
strings demo.pdf | grep flag
```

输出：

```
<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(flag.txt) 7 0 R] >> >> >>
<< /Author (Admin) /Producer (handwritten.py) /Subject (flag{pdf_info_dict}) /CreationDate (D:20261024090000Z) >>
<< /Type /Filespec /F (flag.txt) /EF << /F 8 0 R >> >>
flag{pdf_attachment}
(flag{unreferenced_object})
(flag{appended_after_eof})
```

要偏移和配对信息，用 [[M01-MISC导论与工具箱|M01]]4.2 的 flag 正则手撕对象区：

```python
# pdf_grep.py —— 正则扫 flag，数 %%EOF
import re

data = open("demo.pdf", "rb").read()
for m in re.finditer(rb"flag\{[^}]{1,64}\}", data):
    print(m.start(), m.group().decode())

eofs = [m.start() for m in re.finditer(re.escape(b"%%EOF"), data)]
print("%%EOF 出现次数:", len(eofs), "偏移:", eofs)
```

输出：

```
621 flag{pdf_info_dict}
808 flag{pdf_attachment}
855 flag{unreferenced_object}
1534 flag{appended_after_eof}
%%EOF 出现次数: 2 偏移: [1518, 1670]
```

两个 %%EOF，第二个落在文件尾部——增量更新的实锤，追加段从偏移 1518 之后开始。

内嵌图片走 pdfimages：

```bash
pdfimages -list demo.pdf
pdfimages -png demo.pdf ex
file ex-000.png
python3 -c "from PIL import Image; print('提取图尺寸:', Image.open('ex-000.png').size)"
```

输出：

```
page   num  type   width height color comp bpc  enc interp  object ID x-ppi y-ppi size ratio
--------------------------------------------------------------------------------------------
   1     0 image       8     8  rgb     3   8  image  no        10  0     5     5  192B 100%
ex-000.png: PNG image data, 8 x 8, 8-bit/color RGB, non-interlaced
提取图尺寸: (8, 8)
```

`-list` 先报清单（页码、尺寸、对象号），`-png` 提出成 PNG。提出来的图接 [[M02-文件格式深拆I-PNG全解|M02]]与 [[M05-图片隐写I-LSB与位平面|M05]]的图片隐写流程。

> [!info]- strings 扫不到对象的时候
> 较新的 PDF 会把对象装进压缩的对象流（ObjStm）或用 FlateDecode 压内容，strings 与正则直接扫是空的；poppler 系工具解析时自己解压，pdftotext / pdfdetach / pdfimages 照常工作。需要逐对象深拆时，用 qpdf 的 `--qdf` 参数展开成未压缩副本再看。

排查顺序固定：`pdftotext` 看正常文本 → `pdfinfo` 看元数据 → `pdfdetach` 试附件 → strings 与正则扫全文件 → 数 `%%EOF`。

## 5. 零宽字符

前面几节的载体都是文件结构，纯文本文件的隐写面只有字符本身。[[08-编码与古典密码|08 章]]的编码（base64、hex）落在可见字符上，一眼可辨；零宽字符是一类**宽度为零、不占排版空间**的 Unicode 字符——肉眼完全不可见，文本编辑器里也看不见，但字节真实存在，能随文本一起被复制、存储、塞进任何收文本的容器（txt、docx 的 run、PDF 的文本对象）。

### 5.1 五个码点与编码方案

| 码点 | 名称 | UTF-8 字节 | 本章方案中的角色 |
| ---- | ---- | ---- | ---- |
| U+200B | ZERO WIDTH SPACE（零宽空格） | `E2 80 8B` | 编码 00 |
| U+200C | ZERO WIDTH NON-JOINER（零宽不连字） | `E2 80 8C` | 编码 01 |
| U+200D | ZERO WIDTH JOINER（零宽连字） | `E2 80 8D` | 编码 10 |
| U+2060 | WORD JOINER（词连接符） | `E2 81 A0` | 编码 11 |
| U+FEFF | ZERO WIDTH NO-BREAK SPACE（即 BOM） | `EF BB BF` | 结束符 |

==四个码点各携带 2 个位，U+FEFF 标记隐藏串结束==。一个 ASCII 字符 8 位，编码成 4 个零宽字符；一个 flag 加一个结束符，69 个不可见字符就装下了。题目也常用每字符一位的两码点方案，识别与解码思路相同：把文本按码点过一遍，把不属于正常内容的码点全收走，再按映射还原。

### 5.2 编码：塞进一段正常文本

```python
# zw_encode.py —— 零宽编码：4 码点各带 2 位，U+FEFF 作结束符
PAIRS = ["\u200b", "\u200c", "\u200d", "\u2060"]   # 00 / 01 / 10 / 11

def zw_encode(msg: str) -> str:
    out = []
    for ch in msg:
        v = ord(ch)
        for sh in (6, 4, 2, 0):        # 每字符 8 位拆成 4 组，高位在前
            out.append(PAIRS[(v >> sh) & 3])
    out.append("\ufeff")
    return "".join(out)

vis = "This note looks completely normal."
stego = vis + zw_encode("flag{zwsp_hidden}")
open("cover.txt", "w", encoding="utf-8").write(stego)

print("可见部分:", len(vis), "字符；全文:", len(stego),
      "字符；多出:", len(stego) - len(vis), "个不可见字符")
blob = stego[len(vis):]
print("开头 24 字节 (UTF-8):", blob[:8].encode("utf-8").hex(" "))
```

输出：

```
可见部分: 34 字符；全文: 103 字符；多出: 69 个不可见字符
开头 24 字节 (UTF-8): e2 80 8c e2 80 8d e2 80 8c e2 80 8d e2 80 8c e2 80 8d e2 81 a0 e2 80 8b
```

17 个字符的 flag 变成 68 个零宽字符加 1 个结束符。开头的字节序列 `e2 80 8c` 就是 U+200C 的 UTF-8 签名——码点表右列就是这么来的。cover.txt 在 file 眼里只是一段普通 UTF-8 文本：

```bash
file cover.txt
wc -c cover.txt
```

输出：

```
cover.txt: Unicode text, UTF-8 text, with no line terminators
241 cover.txt
```

### 5.3 发现与解码

发现靠两条：一是账目对不上——可见字符 34 个，文件却有 241 字节，多出的字节去哪了；二是直接数不可见码点。解码脚本把 5 个码点从文本里收走，按 5.1 的映射还原，顺手把 2 节 docx 的正文 run 里那份也解了（2 节造靶时在最后一个段落里塞了一段零宽串）：

```python
# zw_decode.py —— 零宽解码：从任意文本里收 5 个码点，还原隐藏串
from collections import Counter
import re
import zipfile

PAIRS = ["\u200b", "\u200c", "\u200d", "\u2060"]
INV = {ord(c): i for i, c in enumerate(PAIRS)}
NAMES = {0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0x2060: "WORD JOINER", 0xFEFF: "BOM"}

def zw_decode(text: str) -> str:
    buf, out = [], []
    for ch in text:
        cp = ord(ch)
        if cp in INV:
            buf.append(INV[cp])
        elif cp == 0xFEFF:                     # 结束符：整组还原
            for i in range(0, len(buf) - 3, 4):
                v = (buf[i] << 6) | (buf[i + 1] << 4) | (buf[i + 2] << 2) | buf[i + 3]
                out.append(chr(v))
            buf = []
    return "".join(out)

text = open("cover.txt", encoding="utf-8").read()
print("肉眼看到的全文:", text[:34])
cnt = Counter(NAMES[ord(c)] for c in text if ord(c) in NAMES)
print("不可见码点统计:", dict(cnt))
print("解码结果:", zw_decode(text))

xml = zipfile.ZipFile("demo.docx").read("word/document.xml").decode()
body = "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", xml))
print("docx 正文里解出:", zw_decode(body))
```

输出：

```
肉眼看到的全文: This note looks completely normal.
不可见码点统计: {'ZWNJ': 28, 'ZWJ': 17, 'WORD JOINER': 15, 'ZWSP': 8, 'BOM': 1}
解码结果: flag{zwsp_hidden}
docx 正文里解出: flag{zw_in_docx}
```

五个码点各自计数，末尾一个 BOM 正是结束符；两份载荷分别还原成两个 flag。解码对任何容器都一样：先把文本抽出来（txt 直接读，docx 走 document.xml，PDF 走 pdftotext 或对象区），再过同一套码点过滤。

> [!warning] 复制与转存会丢零宽字符
> 聊天工具、富文本编辑器、部分网页输入框在转存文本时会剥掉不可见字符。==解码要用原始文件，不要用"从聊天窗口复制出来再粘贴"的文本==——少几个码点就整段还原不出来。反过来，自己出题或把 flag 发给队友之前，先在本地解出明文再手打，别直接复制零宽串。

> [!note] 检测直觉
> 一段文本"看着正常但文件偏大""全选后的字数统计与行内容对不上"，就跑 5.3 的码点统计。U+FEFF 出现在文件开头是 BOM 属正常，出现在文件中间就是载荷的一部分；U+2060 与 U+200D 在正常排版里几乎不出现，出现即异常。

## 6. 老格式一瞥：OLE2 复合文档

`.doc`/`.xls`/`.ppt` 是 OLE2 复合文档（Compound File Binary），魔数 `D0 CF 11 E0`。它把文件内部划成 512 字节的扇区，目录项组成一棵树：树杈是"存储桶"（相当于文件夹），叶子是"流"（相当于文件）——==容器套流的结构与文件系统同构==。Python 的 olefile 库负责解析，pip 装法 `pip3 install olefile`。

手写一个最小 CFB 当靶子：512 字节的头（魔数、扇区尺寸、FAT 位置）+ 一张 FAT + 一页目录（根存储 + 一个名为 Payload 的流）+ 流数据。有个绕坑的技巧：==流做到 4096 字节以上==，就住在常规扇区里；小于 4096 字节会被放进"迷你流"，要额外经过一套 64 字节小扇区的 MiniFAT，手写解析时容易踩（细节见下折叠框）。

```bash
python3 make_ole.py
file fake.doc
xxd fake.doc | head -1
```

输出：

```
fake.doc written, payload = 4432 bytes
fake.doc: Composite Document File V2 Document, Cannot read section info
00000000: d0cf 11e0 a1b1 1ae1 0000 0000 0000 0000  ................
```

`Cannot read section info` 是 file 在找文档属性流（SummaryInformation）没找到——不影响识别，魔数已经说话了。olefile 三个动作：列流、抽流、看内容：

```python
# ole_read.py —— 用 olefile 读 CFB：列流、抽流、解内层 ZIP
import io
import zipfile
import olefile

ole = olefile.OleFileIO("fake.doc")
print("流清单:", ole.listdir())
data = ole.openstream("Payload").read()
print("Payload 大小:", len(data), "字节，前 4 字节:", data[:4])

z = zipfile.ZipFile(io.BytesIO(data))
print("内层文件:", z.namelist())
print(z.read("flag.txt").decode().strip())
```

输出：

```
流清单: [['Payload']]
Payload 大小: 4432 字节，前 4 字节: b'PK\x03\x04'
内层文件: ['blob.bin', 'flag.txt']
flag{ole_stream_stowaway}
```

Payload 流的前四字节是 `PK\x03\x04`——一个完整 ZIP 住在 OLE2 的一个流里，抽出来接 [[M04-压缩包全解|M04]]的解包流程。老格式题的常见形态就是这一手：`.doc` 的某个流里藏 ZIP、藏图片、藏脚本；逐流 dump 用 `ole.openstream` 加循环即可。这套"容器套流"的概念还会在 [[M14-磁盘与文件系统取证|M14]]的注册表 hive 里再遇到——hive 同样是分桶的层级容器。

> [!info]- 迷你流与手写 CFB 的固定件
> CFB 规定 4096 字节以下的流放进迷你流：迷你流本身是根存储的一条流，内部按 64 字节小扇区切分，用另一张 MiniFAT 索引——解析多一层间接，手写时最容易错的就是这里。把流写大（≥ 4096 字节）可整体绕开。手写最小 CFB 的固定件清单：512 字节头（魔数、主次版本、512/64 两种扇区尺寸、FAT 扇区数、首目录扇区、迷你流上限 4096、DIFAT 数组）；一张 FAT（自身标记 `FFFFFFFD`、链尾 `FFFFFFFE`）；一页目录（每项 128 字节，名字用 UTF-16LE，类型 5 为根存储、2 为流）。本章的 make_ole.py 按这份清单写，olefile 能正常读出。

## 7. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| docx 打不开，报"内容有问题" | XML 被手改过：标签没闭合或命名空间丢失。`unzip -t` 只验 ZIP 层；用 `lxml` 解析定位语法错，改回合法再存 |
| pdftotext 提取不出"隐藏内容" | 本来就不该提出来：pdftotext 只走页面内容流（4.1 节）。私货在对象区、附件、元数据里，按 4.3 的总表换工具 |
| 文本看着正常，怀疑藏了东西 | 跑 5.3 的码点统计；或 xxd 直接找 `e2 80 8b`/`e2 80 8c`/`e2 81 a0`/`ef bb bf` 的字节签名 |
| 零宽解码全是乱码 | 文本经过转存被剥掉了部分码点（5.3 的警告）；对原始文件解。映射与出题人不一致时，先统计用了哪些码点再推映射 |
| exiftool 在 docx 上找不到 Comment | 图片才有 Comment；docx 的对应字段叫 Description（`dc:description`），`exiftool -b -Description` 取值（3 节） |
| unzip -l 列不出 word/ 目录 | 附件不是 OOXML：`file` 重看真身；扩展名伪装的纯 ZIP 按 [[M04-压缩包全解\|M04]]的套路走 |
| PDF 阅读器打开报错，但 strings 有内容 | xref 或对象区被改过；poppler 工具会尝试自动重建 xref，修不了的按 4.3 的正则手撕对象区 |
| file 报 Composite Document File V2 Document | OLE2 复合文档（魔数 `D0 CF 11 E0`）：olefile 列流，逐流 dump 再验真身（6 节） |
| word/media/ 里的图片打不开 | 先 `unzip -p` 抽出来再 `file`——很多是改了名的 ZIP 或其他文件（2.4 节） |
| exiftool 报一堆 Zip 字段 | 那是 ZIP 层第一个成员的压缩信息，不是文档属性（3 节） |

## 8. 配套练习与延伸阅读

配套练习：

1. 给 2 节的 docx 加一种藏法：把一个 flag 拆成"正文白字一半 + 批注一半"，用 2.3 的脚本分别取回并拼出完整 flag；再把颜色从 `FFFFFF` 换成浅灰 `F0F0F0`，确认提取脚本放宽判据后照样命中。
2. 改造 4 节的 PDF：删掉 Info 字典里的 flag、再追加一份附件，然后按 4.3 的排查顺序完整走一遍，确认 `pdfdetach -list` 报出两份、`%%EOF` 计数与正则扫描的结论一致。
3. 设计自己的零宽映射（比如三码点加一个分隔符的方案），写出配套编解码器与同学互测：对方只拿 5.3 的统计脚本，能不能指出你用了哪几个码点。
4. 找一个真实的 `.doc` 老文档（或用旧版 Office 另存一份），olefile 列出全部流，逐流 dump 前几字节并验真身——Word 自己的属性流（SummaryInformation）里也常有可读信息。

练习场：

- [[01-练习平台索引|练习平台索引]]：MISC 分区里文档与 PDF 类题目不少，按本章的解题顺序逐题过
- [[03-工具清单|工具清单]]：poppler 四件、exiftool、olefile 的安装方式与同类替代

延伸阅读：

- ISO/IEC 29500：OOXML 的规范原文，document.xml 元素与属性的权威定义
- ISO 32000-1（PDF 规范）：对象、xref、增量更新与 EmbeddedFiles 的完整语法
- MS-CFB 规范：OLE2 复合文档的二进制布局，6 节手写 CFB 的出处
- [[M04-压缩包全解|M04]]：ZIP 的字段级结构——OOXML 与大量文档题的底层
- [[M08-音频隐写|M08]] 预告：载体从文本换到波形，steghide 对 WAV/AU 用的是 2 节之外另一套频域写入
