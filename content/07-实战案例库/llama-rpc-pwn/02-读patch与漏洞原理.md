---
title: 读 patch 与漏洞原理
tags:
  - 实战案例
  - PWN
  - 代码审计
created: 2026-10-16
status: 已核验
order: 300
publish: true
---

## EDIT_BUFFER：后门本体

`diff.patch` 只有 143 行，核心是新增一条命令：

```diff
 enum rpc_cmd {
     COPY_TENSOR,
     GRAPH_COMPUTE,
     GET_DEVICE_MEMORY,
+    EDIT_BUFFER,
 };
```

> [!info]- diff 文件怎么读
> diff 是"两个版本的差异记录"：开头有空格的行是**没变的上下文**，`-` 开头是**删掉的行**，`+` 开头是**加上的行**。读 patch 的技巧：只盯 `+` 行（作者写了什么新东西），再看 `-` 行（作者删了什么能力）。enum 里 `EDIT_BUFFER` 排在 `GET_DEVICE_MEMORY` 后面，而枚举值从 0 开始数：COPY_TENSOR=0、GRAPH_COMPUTE=1、GET_DEVICE_MEMORY=2、**EDIT_BUFFER=3**——注意这是上游原版 enum 的编号，题目编译用的 ggml-rpc 还有别的命令，实际命令号以第 4 篇逆出来的跳转表为准（EDIT_BUFFER=11）。

```c
bool rpc_server::edit_buffer(const std::vector<uint8_t> & input) {
    // serialization format: | buf_ptr (8 bytes) | edit_size (8 bytes) | edit_data (edit_size bytes) |
    uint64_t edit_buf;
    memcpy(&edit_buf, input.data(), sizeof(edit_buf));              // ① 目标地址：网络来的
    uint64_t edit_size;
    memcpy(&edit_size, input.data() + sizeof(uint64_t), sizeof(edit_size));  // ② 长度：网络来的
    if (input.size() < sizeof(uint64_t) + sizeof(uint64_t) + edit_size) {
        return false;
    }
    const char *data = (const char *)(input.data() + sizeof(uint64_t) + sizeof(uint64_t));
    memcpy((char*)edit_buf, data, edit_size);                       // ③ 拿到什么写什么
    return true;
}
```

> [!info]- std::vector 的 data() 和 size()
> `std::vector<uint8_t>` 是 C++ 的动态数组（长度可变的字节数组），这里装的就是网络上收到的原始字节。`input.data()` 返回**指向第一个字节的裸指针**，`input.size()` 返回字节个数。特殊值要记住：**vector 为空时 `data()` 返回 `nullptr`（0 地址）**——这不是无意义的细节，本文后面"先读后校验"的段错误就是它导致的。
>
> [!info]- memcpy 与"8 个字节就是一个数"
> `memcpy(目的, 源, 字节数)` 是 C 的内存拷贝函数：从源地址抄 N 个字节到目的地址，没有任何类型检查——你让它抄哪儿它抄哪儿。`memcpy(&edit_buf, input.data(), 8)` 是"从收到的数据开头抄 8 个字节，当作一个 64 位整数"。为什么 8 字节能当整数？x86-64 是**小端序**：整数在内存里低位字节在前，收到的 8 个字节原样解释成 `uint64_t`。这也意味着你在 Python 里构造 payload 时要用 `p64()` 把整数按小端打包，顺序反了地址就完全不对。

> [!tip]- 代码形状识别：任意地址写（AAW）
> 目标地址、长度、内容全部来自网络，且没有任何"地址是否在合法区间""长度是否越界"的检查——看到这个形状，当场在纸上写下 AAW。
> 再注意一处：①② 在长度校验**之前**执行，本身又是一个洞，见 [[#先读后校验：空输入就是段错误]]。
> 这个"形状"值得单独记：**从输入取指针 + 从输入取长度 + 无校验地 memcpy/strcpy/赋值**。不管出现在哪个项目里，都是同一个漏洞。

## patch 里另外两处改动

```diff
 // 1) 分配上限：不允许你申请巨大 buffer
+    if (size >= 0x200) {
+        char res[] = "alloc size too big!";
+        output.resize(strlen(res), 0);
+        memcpy(output.data(), res, strlen(res));
+        return false;
+    }

 // 2) 把 set_tensor 失效
-    ggml_backend_tensor_set(tensor, data, offset, size);   // 原本会往张量里写
-    ...
+    char res[] = "no set_tensor!";
+    output.resize(sizeof(res), 0);
+    memcpy(output.data(), res, sizeof(res));
     return true;
-    // 原始实现整段被注释掉
```

> [!important]- 两个改动各说了一句话
> `alloc` 卡在 0x1ff：这个数字就是 payload 的空间上限（[[04-利用链与EXP#第⑥步：payload 容量上限|第⑥步]] 会用到）。
> `set_tensor` 被砍、`get_tensor` 完好：原本能往合法 buffer 里写的路被堵死，逼你走 `EDIT_BUFFER`；反过来，**任意读是作者默认留给你的一半原语**。
> 出题人"顺手关掉的功能"是高价值情报：它同时告诉你"哪条路走不通"和"出题人希望你走哪条"。

## 用汇编验证 patch

patch 只用来指路，最终以二进制为准：

```bash
$ objdump -d --demangle --no-show-raw-insn --start-address=0xd1c62 --stop-address=0xd1d1e libggml.so
```

```asm
00000000000d1c62 <rpc_server::edit_buffer(std::vector<...> const&)>:
  d1c8c: call  vector::data() const
  d1c91: mov   (%rax),%rax          ; edit_buf  = *(u64*)input.data()
  d1c9f: call  vector::data() const
  d1ca8: mov   0x8(%rax),%rax       ; edit_size = *(u64*)(input.data()+8)
  d1cb6: call  vector::size() const
  d1cbb: mov   -0x18(%rbp),%rdx
  d1cbf: add   $0x10,%rdx
  d1cc3: cmp   %rdx,%rax            ; input.size() < 16 + edit_size ?
  d1cfd: call  memcpy@plt           ; memcpy((char*)edit_buf, input.data()+16, edit_size)
  d1d02: mov   $0x1,%eax
```

和 patch 完全一致（x86-64 Linux，AT&T 语法，System V ABI）。

> [!info]- C++ 成员函数在汇编里长什么样
> `rpc_server::edit_buffer(const std::vector<uint8_t>&)` 这种"属于某个类的函数"叫成员函数，编译后它其实比声明多收一个隐藏参数——对象自己的地址（`this`），放在 `rdi`。所以汇编里 `rsi` 才是那个 `input` vector 的地址：`call vector::data()` 返回的指针在 `rax`，`mov (%rax),%rax` 是"从这个地址取 8 字节"= 读出 `edit_buf`；`mov 0x8(%rax),%rax` 是"偏移 8 字节再取"= `edit_size`。
> objdump 参数顺带解释：`-d` 反汇编，`--demangle` 翻译 C++ 修饰名，`--no-show-raw-insn` 不显示机器码字节（省地方），`--start/--stop-address` 只反汇编这个区间——精确摘一个函数出来用，比翻几万行舒服。

## GET_TENSOR 为什么是任意读

把 `deserialize_tensor` + `get_tensor` 串起来看，"合法"判定只覆盖一半字段：

```asm
; ① 客户端给的 buffer 字段：只校验"是否登记过"
d119c: call unordered_set<ggml_backend_buffer*>::end()
d11c6: call unordered_set<ggml_backend_buffer*>::find(&tensor->buffer)
d11dd: call operator==(it, end)
d11e2: test %al,%al
d11f6: mov  $0x0,%eax            ; 没登记 → return nullptr（拒绝）
; ② 客户端给的 data 字段：直接塞进 ggml_tensor->data
d1253: mov 0xdc(%rax),%rax
d1261: mov %rdx,0x100(%rax)      ; ggml_tensor.data = 线上地址
```

```asm
; ggml_backend_tensor_get：边界检查用的 nbytes 也是我们自己填的 ne/nb 算出来的
96383: cmpq $0x0,0x100(%rbp)     ; tensor->data 必须非空
96398: call ggml_nbytes
9639d: cmp  %rax,%r15            ; offset+size <= nbytes ?
...
; 最终 CPU 后端：
956a4: add  0x100(%rsi),%rcx     ; memcpy 的源 = tensor->data + offset
956b4: jmp  memcpy@plt
```

> [!info]- unordered_set：一张"登记表"
> `unordered_set` 是 C++ 的哈希集合，这里当**登记表**用：服务端每分配一个 buffer，就把它的地址记进集合；之后客户端报上来的 `buffer` 字段，服务端只问一句"这个地址我登记过吗"（`find` 找得到就放行）。它防的是"拿着没登记的假句柄来操作"，但完全没管 `data` 字段——半个门卫。
>
> [!info]- nbytes 为什么形同虚设
> 读数据前服务端会检查"你读的 offset+size 别超过这张张量的总大小 nbytes"。问题在于 nbytes 不是服务端算的，是用 `ggml_nbytes()` 按张量的 `ne/nb`（维度和步长）现场算的，而 `ne/nb` 是**我们从网上填的**。`ne[0]` 填个巨大的数，nbytes 就巨大，检查永远通过。用"攻击者自己填的值"做边界检查，等于没查。

`data` 想读哪读哪 → **任意地址读（AAR）**。

> [!tip]- 安全审查原则：盯住"部分校验"
> 这里只查了 `buffer` 有没有登记，`data` 一路裸奔。上游这么写是因为它假设"客户端就是同一个可信程序"。凡是"部分校验"的地方，没被校验的那个字段就是洞。

## 先读后校验：空输入就是段错误

```c
memcpy(&edit_buf, input.data(), 8);       // input 为空时 input.data() == nullptr
memcpy(&edit_size, input.data() + 8, 8);  // 1<=size<16 时读过界
if (input.size() < 16 + edit_size) return false;
```

实测（`aux/check_secondary_bug.py`）：

```
cmd=EDIT_BUFFER input_size= 0 -> recv b''  (服务端已崩)
$ 1772 Segmentation fault  ./rpc-server --host 127.0.0.1 --port 50077
```

> [!warning]- 校验必须放在使用之前
> 发一个长度为 0 的 `EDIT_BUFFER` 命令：`input.data()` 返回 `nullptr`（空 vector 的特征，见前面的折叠说明），`memcpy` 从 0 地址读内存 → CPU 触发非法访问 → 进程直接死。这就是一次 **DoS**（拒绝服务）：没拿到任何权限，但把服务打挂了。
> 顺带一个实战用途：这个 bug 可以当"命令号打没打对"的探针——服务端死了说明命令确实送达并被处理了。

## 原语总表

| 原语 | 靠什么 | 怎么调 | 得到什么 |
|---|---|---|---|
| 堆地址泄漏 | `ALLOC_BUFFER` | `cmd=0 + u64 size(≤0x1ff)` | `[u64 buffer句柄][u64 buffer->size]` |
| 任意读 | `GET_TENSOR` | `cmd=7 + 0x128 字节 rpc_tensor(data=任意地址) + u64 off + u64 size`（总长 0x138） | `size` 字节内存 |
| 任意写 | `EDIT_BUFFER` | `cmd=11 + u64 dst + u64 len + 数据` | 任意地址写上任意内容 |
| 触发 | `FREE_BUFFER` | `cmd=4 + u64 buffer句柄` | `free(buffer->context)` |

> [!info]- "原语"（primitive）这个词
> 原语指利用达到的**基础能力等级**：能读任意内存（AAR）、能写任意内存（AAW）、能让程序跳去任意地址。把漏洞一步步转化成更强的原语，最后由原语拼出"执行命令"，是现代 pwn 的标准思路——这一步就叫"原语化"。

> [!note]- glibc 2.31 留的窗口
> 四个原语凑齐后，剩下的就是标准 glibc 利用问题：glibc 2.31 还保留 `__free_hook`（2.34 删除），所以"改 hook → free 变 system"这条最省事的路通。具体怎么串，看 [[04-利用链与EXP]]。

---
[[01-背景与静态侦察|← 上一篇]] · [[03-协议逆向与调试环境|下一篇：协议逆向与调试环境 →]]
