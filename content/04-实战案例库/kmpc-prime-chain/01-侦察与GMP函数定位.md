---
title: 侦察与 GMP 函数定位
tags:
  - 实战案例
  - REV
  - GMP
created: 2026-10-16
status: 已核验
order: 200
publish: true
---

这道题的侦察阶段只花三步：`file`/`ldd` 看身份，`readelf -r` 对导入表，`nm -C` 收函数名。三步做完，算法库、函数清单、容器类型全部到手，剩下的只是反汇编细读。

> [!info]- 侦察的意义
> 拿到二进制先别急着反汇编。符号表、导入表、只读数据段这些"元信息"成本极低（每条命令几秒钟），却决定了你后面几个小时怎么花。信息没收全就开始啃汇编，是逆向新手最常见的时间黑洞。

## file / ldd：先看它链接了谁

```bash
$ file KMPC
KMPC: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
      interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=de2417ad2a641d9f1e7e9b5e8425d28570416865,
      for GNU/Linux 3.2.0, not stripped          ← 注意这里

$ ldd KMPC
	linux-vdso.so.1
	libgmp.so.10 => /usr/lib/x86_64-linux-gnu/libgmp.so.10   ← 大数库
	libstdc++.so.6 => ...        ← C++ 程序
	libgcc_s.so.1 / libc.so.6 / libm.so.6
```

> [!info]- file 输出怎么读
> - **pie executable**：位置无关，运行时基址随机。本题不做内存攻击，这一项无视
> - **not stripped**：符号表没剥，函数名都还在。下一步 `nm` 直接收名字
> - **dynamically linked**：依赖系统的共享库，`ldd` 列出来的就是它要用的
> - **for GNU/Linux 3.2.0**：glibc 符号版本要求很低，任何近十年的 Linux 都能跑

> [!tip]- 链接了 GMP 等于交代了半张底牌
> GMP（GNU Multiple Precision）是 Linux 世界的标准大数运算库，密码学题目的常客。看到 `libgmp.so.10` 就该列一份"待认领清单"：`mpz_init`、`mpz_set`、`mpz_mul`、`mpz_add`、`mpz_probab_prime_p`、`mpz_nextprime`……这些都是 GMP 的文档函数，名字即语义。接下来要做的只是把"哪个调用点用了哪个函数"对上号——导入表会替你做一半。

## readelf -r：导入表点名

`.rela.plt` 一共 38 项，去掉 C++ 运行时和 libc 的杂项，GMP 函数 11 个：

```bash
$ readelf -r KMPC | grep gmpz
000000006f00  R_X86_64_JUMP_SLO __gmpz_clear
000000006f38  R_X86_64_JUMP_SLO __gmpz_init_set_ui
000000006f50  R_X86_64_JUMP_SLO __gmpz_init
000000006f58  R_X86_64_JUMP_SLO __gmpz_set_ui
000000006f68  R_X86_64_JUMP_SLO __gmpz_mul_ui
000000006f70  R_X86_64_JUMP_SLO __gmpz_set
000000006f78  R_X86_64_JUMP_SLO __gmpz_get_str
000000006f90  R_X86_64_JUMP_SLO __gmpz_nextprime
000000006f98  R_X86_64_JUMP_SLO __gmpz_add_ui
000000006fa0  R_X86_64_JUMP_SLO __gmpz_probab_prime_p
000000006fd0  R_X86_64_JUMP_SLO __gmpz_get_ui
```

> [!info]- 函数名前缀为什么是 `__gmpz_` 而不是 `mpz_`
> `mpz_*` 是 GMP 头文件里的宏/内联包装，真正的库符号带 `__g` 前缀（`__gmpz_*`），历史原因。查 man 手册时用 `mpz_nextprime`，查符号表时看到 `__gmpz_nextprime`，同一个东西。

这 12 个名字基本能脑补出算法形状：`init`/`set`（初始化赋值）、`mul_ui`/`add_ui`（乘加小整数）、`probab_prime_p`（素性检验）、`nextprime`（下一个素数）、`get_ui`/`get_str`（取出来当整数/字符串）。有 nextprime 有 probab_prime，又有 mul_ui + add_ui——"素数生成/素数链"的味道已经出来了。

GMP 函数是走 PLT 调用的，反汇编里看到的是桩地址。把桩地址和 GOT 槽位对上（`.plt.sec` 里每个桩 `jmp *GOT槽`），得到本文反复引用的对照表：

| 桩地址 | GOT 槽 | 函数 | 语义 |
|---|---|---|---|
| `0x22a0` | `0x6ea8` | `std::getline` | 整行读入 |
| `0x22b0` | `0x6eb0` | `operator<<(unsigned long)` | 输出小整数 |
| `0x22c0` | `0x6eb8` | `rand` | 随机数 |
| `0x2340` | `0x6ef8` | `time` | 时间种子 |
| `0x2350` | `0x6f00` | `mpz_clear` | 释放 |
| `0x2360` | `0x6f08` | `srand` | 播种 |
| `0x2370` | `0x6f10` | `operator<<(const char*)` | 输出字符串 |
| `0x23b0` | `0x6f30` | `ofstream` 构造 | **打开文件** |
| `0x23c0` | `0x6f38` | `mpz_init_set_ui` | t = 小整数 |
| `0x23f0` | `0x6f50` | `mpz_init` | 初始化 |
| `0x2400` | `0x6f58` | `mpz_set_ui` | 赋小整数 |
| `0x2410` | `0x6f60` | `operator delete[]` | 释放 get_str 的缓冲 |
| `0x2420` | `0x6f68` | `mpz_mul_ui` | 大数 × 小整数 |
| `0x2430` | `0x6f70` | `mpz_set` | 大数赋值 |
| `0x2440` | `0x6f78` | `mpz_get_str` | 大数转十进制字符串 |
| `0x2460` | `0x6f88` | `ofstream::close` | 关文件 |
| `0x2470` | `0x6f90` | `mpz_nextprime` | 下一个素数 |
| `0x2480` | `0x6f98` | `mpz_add_ui` | 大数 + 小整数 |
| `0x2490` | `0x6fa0` | `mpz_probab_prime_p` | **素性检验** |
| `0x24b0` | `0x6fb0` | `string::length` | 取长度 |
| `0x24f0` | `0x6fd0` | `mpz_get_ui` | 大数取回 64 位 |

> [!info]- PLT/GOT 一分钟版
> 程序调用动态库函数时不直接跳过去，而是跳到一段"桩"代码（PLT），桩再从一张表（GOT）里取出函数真实地址跳过去。链接/懒加载的细节见 [[llama-rpc-pwn/04-利用链与EXP|llama-rpc 实战]] 的 GOT 详解——那篇讲怎么利用 GOT，这篇只需要"桩地址 → 符号名"这层映射。`readelf -r` 给出 GOT 槽位和符号，`objdump -d -j .plt.sec` 给出"桩地址 → GOT 槽位"，两张表一拼就是上面的对照表。

> [!info]- endbr64 是什么
> 反汇编里每个函数和 PLT 桩开头都有一条 `endbr64`。它是 Intel CET（控制流强制技术）的标记指令，正常执行时是空操作，作用是声明"这里是合法的跳转目标"。看到它就知道二进制开了 `-fcf-protection`，与算法无关，但读汇编时要习惯跳过它。

## nm -C：三个函数名是符号表给的

```bash
$ nm -C KMPC | grep -E ' [tT] ' | grep -v std:: | head
0000000000002787 T pad_message(std::__cxx11::basic_string<...> const&)
00000000000025e9 T bytes_to_long(unsigned long&, unsigned char const*, unsigned long)
000000000000264f T KMPC(__mpz_struct*, int, unsigned long)
```

`nm -C` 的 `-C` 把 C++ 修饰名翻译回可读形式（原理见 [[llama-rpc-pwn/01-背景与静态侦察|llama-rpc 实战]] 的名字修饰一节）。三个业务函数全在，连签名都白送：

- `KMPC(__mpz_struct*, int, unsigned long)`——第一个参数是 mpz 的指针（`__mpz_struct` 就是 mpz_t 的本体类型），第二个 `int` 显然是步数，第三个 `unsigned long` 是起点。链的形状在签名里已经露了一半
- `bytes_to_long(unsigned long&, const unsigned char*, unsigned long)`——把一段字节变成整数，输出是引用

顺带一提，符号表里还有 `std::vector<unsigned long, ...>` 和 `std::vector<__mpz_struct [1], ...>` 的模板实例化——**容器类型也泄露了**：程序拿 `vector<unsigned long>` 装 diff，拿 `vector<mpz_t>` 装 20 个链尾大整数。这跟 `result.txt` 的两行结构完全对得上。

> [!tip]- 模板实例化是 C++ 逆向的信息富矿
> C++ 的模板是按需实例化的，程序里用过 `vector<mpz_t>`，符号表里就会出现 `std::vector<__mpz_struct [1], std::allocator<...> >` 一整套成员函数。不 strip 的 C++ 二进制里，翻一遍 `nm -C | grep vector` 常常能把所有数据结构清单收齐，比从汇编里硬认快得多。

## .rodata：提示串自己交代输出方式

```bash
$ objdump -s -j .rodata KMPC
 5000 01000200 00000000 696e7075 7420796f  ........input yo
 5010 7572206d 65737361 67653a20 00726573  ur message: .res
 5020 756c742e 74787400 5b002c20 005d0a5b  ult.txt.[., .].[
 5030 005d0a00 456e6372 79707469 6f6e2066  .]..Encryption f
 5040 696e6973 6865642e 0a000000 00000000  inished.........
```

逐个认领：

| 地址 | 字符串 | 用途 |
|---|---|---|
| `0x5008` | `input your message: ` | 输入提示——喂输入用管道即可 |
| `0x501d` | `result.txt` | **密文写进这个文件**，不是 stdout |
| `0x5028` | `[` | 第一行开头 |
| `0x502a` | `, ` | 分隔符 |
| `0x502d` | `]\n[` | 上一行结尾 + 换行 + 下一行开头 |
| `0x5031` | `]\n` | 第二行结尾 |
| `0x5034` | `Encryption finished.\n` | 结束语 |

`]\n[` 这根字符串值得看一眼：它是两个字面量（`]` + 换行 + `[`）被编译器**合并**后的产物——两行列表之间的边界正好共用一段字节。从这组串能直接还原输出格式：`[a, b, ...]\n[大数, 大数, ...]\n`，和 `result.txt` 的两行一模一样。

> [!info]- 字符串合并（tail merging）
> 编译器发现 `"]\n["` 的结尾和 `"]\n"` 开头重叠时，会在只读段里只存一份字节、让多个指针指向不同偏移。所以 .rodata 里的字符串经常"连成一坨"，读的时候要认出哪些是独立字面量、哪些只是别的串的尾巴。这也是 `strings` 输出看起来乱七八糟的原因。

侦察到此结束：函数清单、调用对照、容器类型、输出格式全部到位，还一行汇编没读。[[02-还原加密算法]] 开始逐函数还原。

---
[[00-导读|← 返回导读]] · [[02-还原加密算法|下一篇：还原加密算法 →]]
