---
chapter: 逆向工程
section: CrackMe 经典题型详解
order: 208
tags:
  - CTF
  - 逆向工程
  - RE
  - CrackMe
publish: true
---

# R8 CrackMe 经典题型
## Classic CrackMe Challenges

> [!info] 章节信息
> **所属方向**：逆向工程 ｜ **难度阶段**：L2 核心题型期 ｜ **前置要求**：[[R05-静态分析工具链IDA与Ghidra|R05]] · [[R06-动态调试GDB与x64dbg|R06]] · [[R03-x86与x64汇编精要复习|R03]]
> **本章目标**：拿到任意一个入门级 crackme，能按分流决策判断题型并选第一条路；对明文比较、变换比较、注册机求解、patch 绕过四类各有一条从识别到拿 flag 的完整路径；认得六种典型汇编模式，会解四类数学约束，能处理逐字符、校验和、时间与次数限制变体，并用三遍学习法把每道题沉淀进错题本。

## 1. CrackMe 是什么

### 1.1 与 CTF 赛题的关系

crackme 是一类练习程序：作者写一个带校验逻辑的小程序并公开，解题者要找出能让程序认可的输入（key、serial、密码），或者把被校验挡住的"成功"功能打开。这类程序来自逆向社区的练习文化，crackmes.one 网站收录了大量带难度分级的作品，是逆向新人公认的练习场。

CTF 逆向题的内核就是一套校验逻辑：读输入、做变换或算术、比较、输出结果。赛题在这套内核外面再包几层——壳、反调试、编码链、特定的 flag 格式——[[R09-加壳与脱壳|R09]] 与 [[R10-反调试与反分析对抗|R10]] 处理外层，[[R07-编码与算法识别还原|R07]] 处理成型的编码与算法。==crackme 练的是内核：定位校验、还原逻辑、算出输入==，这步能力决定了后面所有章节的上限。

> [!note] 本章的实验设定
> 全部实例都是自建的 Linux ELF，编译命令统一 `gcc -O0 -fno-pie -no-pie`：`-O0` 让源码与汇编逐行对应，`-fno-pie -no-pie` 把加载地址固定在 0x400000 一带（[[R03-x86与x64汇编精要复习|R03]] 第 1 节的编译基线）。真实赛题可能是 Windows PE、开 PIE、开优化——读法不变，地址形态与寄存器约定变（Windows x64 的约定见 [[R06-动态调试GDB与x64dbg|R06]] 第 12 节）。汇编示例默认 x86-64 Linux / System V AMD64 ABI。

### 1.2 通用分流决策

拿到一个 crackme，按固定顺序做四步，然后按观察结果选第一条路：

1. **`file`**：确认平台、位数、动态/静态链接、符号是否被剥（[[R04-可执行文件格式ELF与PE|R04]]），据此确定工具与调用约定；
2. **`strings`**：扫可读字符串。有像答案的串，直接试（第 2 节）；只有 Correct/Wrong 类提示，把它们当路标（[[R05-静态分析工具链IDA与Ghidra|R05]] 2.2 讲过 strings 的用法与局限）；
3. **定位校验函数**：从提示字符串按 `X` 查交叉引用，或从 main 开始读，F5 出伪代码（[[R05-静态分析工具链IDA与Ghidra|R05]] 3.10 的完整流程）；
4. **读伪代码分型**：按第 6 节的模式表认形状，从下面四类里选一个，进入对应节的解题路径。

| 你看到 | 优先动作 | 入口 |
| ---- | ---- | ---- |
| strings 里有像答案的字符串 | 直接喂给程序试 | 第 2 节 |
| strings 只有提示语，伪代码里 strcmp 直接比 | 明文比较型 | 第 2 节 |
| 伪代码是常量表 + 逐字节变换循环 | 变换比较型，逆变换 | 第 3 节 |
| 输入是数字 serial，校验是算术约束 | 注册机求解型，正着算 | 第 4 节 |
| 校验难逆（哈希、大空间搜索）或逆不划算 | patch 绕过型，改程序 | 第 5 节 |
| strings 全是乱码，入口都找不到 | 加壳嫌疑 | [[R09-加壳与脱壳\|R09]] |
| 一调试就退出、一运行就自毁 | 反调试嫌疑 | [[R10-反调试与反分析对抗\|R10]] |
| 答案运行时才在内存里成形 | 动态 dump | [[R06-动态调试GDB与x64dbg#10. 实战：动态 dump 出密钥\|R06 第 10 节]] |

> [!warning] 分流是选第一条路，不是终审判决
> 读到一半发现判断错了——以为能逆变换，实际是非线性哈希——换路就是，前面的定位工作不白做。分流的训练目标不是"猜对"，而是==让第一条路尽量是短的那条==；准确度随第 6 节的模式识别熟练度自然上升。

## 2. 类型一：明文比较型

校验就是一次字符串比较，正确答案以明文形式存在程序里。这是四类里最轻的一类，也是"strings 一步定位"的适用场景。

### 2.1 实例程序

```c
/* cm1_plain.c —— 明文比较型：strcmp 直接比输入 */
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[32];
    printf("serial: ");
    fflush(stdout);
    scanf("%31s", buf);
    if (strcmp(buf, "EZ-PWND-2026") == 0)
        puts("Correct! flag{pl4in_1s_e4sy}");
    else
        puts("Wrong serial");
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie cm1_plain.c -o cm1_plain
file cm1_plain
```

输出：

```
cm1_plain: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f9375e25..., not stripped
```

not stripped 表示符号表还在，main 有名字（符号被剥时的定位方法见 [[R05-静态分析工具链IDA与Ghidra#2.6 符号被剥掉时如何定位 main|R05 2.6]]）。

### 2.2 strings 一步定位

```bash
strings -t x cm1_plain | grep -E 'serial|Correct|Wrong|flag'
```

输出：

```
   2004 serial: 
   2012 EZ-PWND-2026
   201f Correct! flag{pl4in_1s_e4sy}
   203c Wrong serial
```

四条串里，`EZ-PWND-2026` 是唯一"形似答案"的串：提示语（serial:）、成功输出、失败输出都一眼可辨，剩下的那条就是嫌疑对象。它是不是真的被校验逻辑引用，两条路确认：直接喂给程序看反应，或者按 [[R05-静态分析工具链IDA与Ghidra#3.6 交叉引用（xref）：代码引用与数据引用|R05 3.6]] 的方法查引用它的指令。偏移也对得上：strings 给的文件偏移 0x2012 加上非 PIE 基址 0x400000，正是反汇编里引用它的立即数 0x402012（[[R05-静态分析工具链IDA与Ghidra#2.4 objdump -s：读取常量表|R05 2.4]] 讲过这层换算）。

```bash
echo AAAA-BBBB-1234 | ./cm1_plain
echo EZ-PWND-2026 | ./cm1_plain
```

输出：

```
serial: Wrong serial
serial: Correct! flag{pl4in_1s_e4sy}
```

> [!note] scanf 的 %s 读到空白为止
> 输入 `EZ PWND`（中间有空格）时，`%s` 只读到 `EZ`，程序照样报错。赛题要求提交的串里含空格时，要么程序用的是 `fgets`/`gets`，要么答案本身不含空格——喂输入先看程序怎么读。

### 2.3 反汇编读校验

```bash
objdump -d -M intel cm1_plain | sed -n '/<main>:/,/^$/p'
```

主干如下（序言、canary 与收尾的噪声指令已省略，过滤方法见 [[R03-x86与x64汇编精要复习|R03]] 第 8 节）：

```asm
; x86-64 Linux · System V AMD64 ABI · Intel 语法（objdump -d -M intel 输出，省略噪声）
  40120f:  lea    rax,[rbp-0x30]           ; buf 的地址
  401213:  mov    rsi,rax                  ; 第 2 参数
  401220:  call   4010c0 <__isoc23_scanf@plt>
  401225:  lea    rax,[rbp-0x30]
  401229:  mov    esi,0x402012             ; 第 2 参数 = "EZ-PWND-2026" 的地址
  40122e:  mov    rdi,rax                  ; 第 1 参数 = 输入
  401231:  call   4010d0 <strcmp@plt>
  401236:  test   eax,eax                  ; strcmp 返回 0 即相等
  401238:  jne    401246 <main+0x70>       ; 不等 → 跳去失败分支
  40123a:  mov    edi,0x40201f             ; "Correct! ..."
  40123f:  call   401090 <puts@plt>
  401244:  jmp    401250 <main+0x7a>       ; 跳过失败分支
  401246:  mov    edi,0x40203c             ; "Wrong serial"
  40124b:  call   401090 <puts@plt>
```

两个固定形状：`strcmp` 两个参数是"输入 + 明文串"，答案直接写在指令的立即数里；`test eax,eax` 后接 `jne`，==jcc 跳走的那条边是"不满足"的情况==，想还原源码条件要反着读（[[R03-x86与x64汇编精要复习#7.2 形状二：比较与跳转|R03 7.2]]）。strcmp 返回 0 表示相等，所以 `test eax,eax` + `je` 走成功分支、`jne` 走失败分支。

### 2.4 解法与边界

明文比较型的解法就是**复制粘贴**：strings 找到串，喂给程序。它的价值在识别——见到这类题不要去逆什么，30 秒结束。

> [!warning] 明文答案也可能不是真答案
> 两类情况要分辨：一是**诱饵字符串**，程序里放一个形如 flag 的串引人上当，真实校验在别处（[[R05-静态分析工具链IDA与Ghidra#2.1 准备分析对象|R05 2.1]] 的 `flag{nice_try_but_fake}` 就是设计好的例子）；二是**半明文**，程序里只放答案的一半或一段密文，需要再走第 3 节的变换。==判据只有一条：哪条串在真实校验路径上，看引用，不看长相==。

> [!info]- strings 还有一层编码开关
> `strings` 默认只扫 ASCII（单字节）串。UTF-16LE 编码的串（Windows 程序常见）要用 `strings -e l`（little-endian 16 位）才扫得到。Linux 题几乎都是 ASCII，Windows 题扫不到串时先想起这个开关，再怀疑加壳。

## 3. 类型二：变换比较型

输入的每个字节做一组变换，与程序里的常量表比较。变换通常由异或、加减、移位、下标运算拼成，每一步都可逆——==整类题的核心动作是逆变换==：从常量表出发，按相反顺序把每步变换撤掉。[[R05-静态分析工具链IDA与Ghidra#2.5 逆推 key 并验证|R05 2.5]] 走过一遍单字节变换的完整流程；本节换一个**下标参与变换、且倒序取字符**的实例，重点放在逆变换的两个新坑：方向和顺序。

### 3.1 实例程序

```c
/* cm2_transform.c —— 变换比较型：倒序取字符 + 异或 0x37 + 加下标 */
#include <stdio.h>
#include <string.h>

static const unsigned char enc[9] = {
    0x04, 0x5B, 0x06, 0x47, 0x49, 0x09, 0x47, 0x0B, 0x4D
};

int main(void) {
    unsigned char buf[24];
    printf("key: ");
    fflush(stdout);
    scanf("%23s", buf);
    if (strlen((char *)buf) != 9) {
        puts("wrong length");
        return 1;
    }
    for (int i = 0; i < 9; i++) {
        if ((unsigned char)((buf[8 - i] ^ 0x37) + i) != enc[i]) {
            puts("wrong key");
            return 1;
        }
    }
    printf("Correct! flag{%s_r3v}\n", buf);
    return 0;
}
```

flag 内容依赖正确的 key（`%s` 打印输入），猜不出来，只能逆推。

### 3.2 读出变换式

```bash
gcc -O0 -fno-pie -no-pie cm2_transform.c -o cm2_transform
strings -t x cm2_transform | grep -E 'key|wrong|Correct'
```

输出：

```
   2010 Mkey: 
   201c wrong length
   2029 wrong key
   2033 Correct! flag{%s_r3v}
```

strings 里没有答案，只有格式串——校验对象是常量表，strings 扫不到二进制字节（首行的 `M` 不是乱码，是常量表最后一个字节 0x4D，紧挨着 "key: " 被一起扫了出来）。读循环段：

```bash
objdump -d -M intel cm2_transform | sed -n '/<main>:/,/^$/p'
```

输出（objdump -d -M intel，省略噪声）：

```asm
; x86-64 Linux · System V AMD64 ABI · Intel 语法
  401248:  mov    DWORD PTR [rbp-0x24],0x0      ; i = 0
  40124f:  jmp    40128f                        ; 先跳判断区（for 的标准形状，R03 7.3）
  401251:  mov    eax,0x8                       ; ┐ eax = 8 - i：
  401256:  sub    eax,DWORD PTR [rbp-0x24]      ; ┘ 倒序下标
  401259:  cdqe                                 ; 符号扩展进 rax（R03 7.4）
  40125b:  movzx  eax,BYTE PTR [rbp+rax*1-0x20] ; eax = buf[8-i]
  401260:  xor    eax,0x37                      ; ^ 0x37
  401263:  mov    edx,eax
  401265:  mov    eax,DWORD PTR [rbp-0x24]      ; 再取 i
  401268:  add    edx,eax                       ; edx = (buf[8-i]^0x37) + i
  40126a:  mov    eax,DWORD PTR [rbp-0x24]
  40126d:  cdqe
  40126f:  movzx  eax,BYTE PTR [rax+0x402008]   ; eax = enc[i]，表在 0x402008
  401276:  cmp    dl,al                         ; 只比低 8 位
  401278:  je     40128b <main+0xb5>            ; 相等 → 继续
  40127a:  mov    edi,0x402029                  ; "wrong key"
  40127f:  call   401090 <puts@plt>
  40128b:  add    DWORD PTR [rbp-0x24],0x1      ; i++
  40128f:  cmp    DWORD PTR [rbp-0x24],0x8      ; i <= 8 ?
  401293:  jle    401251 <main+0x7b>
```

校验逻辑还原为一个式子：

$$\text{enc}[i] = (\text{unsigned char})\big((\text{key}[8-i] \oplus \text{0x37}) + i\big) \tag{1}$$

三处细节：`mov eax,0x8; sub eax,[i]` 是倒序下标 `8-i` 的来源，漏看它整条 key 全错；`(unsigned char)` 强转没有单独指令，落在 `cmp dl,al` 的"只比低 8 位"上；常量表在 0x402008，字节内容用 `objdump -s -j .rodata` 读（[[R05-静态分析工具链IDA与Ghidra#2.4 objdump -s：读取常量表|R05 2.4]] 的方法）。

### 3.3 逆变换与验证

式 (1) 的每一步都可逆：异或的逆是自身，加 i 的逆是减 i。按**相反顺序**撤，并把结果收回 0–255：

$$\text{key}[8-i] = \big((\text{enc}[i] - i)\ \&\ \text{0xFF}\big) \oplus \text{0x37} \tag{2}$$

```python
# solve2.py —— 由常量表逆推 key：变换是 (buf[8-i] ^ 0x37) + i，逆着做
enc = [0x04, 0x5B, 0x06, 0x47, 0x49, 0x09, 0x47, 0x0B, 0x4D]
key = [0] * 9
for i, e in enumerate(enc):
    key[8 - i] = ((e - i) & 0xFF) ^ 0x37   # 先减 i，再异或 0x37；倒序写入
print(bytes(key).decode())
```

```bash
python3 solve2.py
```

输出：

```
r3v3rs3m3
```

```bash
echo aaaaaaaaa | ./cm2_transform
echo r3v3rs3m3 | ./cm2_transform
```

输出：

```
key: wrong key
key: Correct! flag{r3v3rs3m3_r3v}
```

> [!warning] 逆变换的两个坑：顺序与截断
> ==先加后异或，逆过来就得先减后异或==——顺序抄反，结果整体不对。减法可能出负数，`& 0xFF` 把它收回 0–255，正好对上比较时发生的字节截断（`cmp dl,al` 只看低 8 位）。这两条在 [[R05-静态分析工具链IDA与Ghidra#2.5 逆推 key 并验证|R05 2.5]] 的例子里同样出现，是整类题的通用动作。

> [!info]- 倒序不改变逆变换的写法
> 循环从 enc[0] 遍历到 enc[8]，每项对应的输入字符是 key[8-i]。脚本里用 `key[8-i] = ...` 按原下标写入即可，不需要把 enc 先反转再算——反转和倒序下标是同一件事的两种写法，选一种用熟。

## 4. 类型三：注册机求解型

校验是数学约束：程序读入 name 和数字 serial，用 name 算出一个期望值与 serial 比较。==这一类不需要逆变换，而是正着算==——把校验逻辑原样抄进脚本，对任意 name 算出能通过的 serial。产出的脚本叫注册机（keygen）。

### 4.1 实例程序

```c
/* cm3_keygen.c —— 注册机求解型：serial 是由 name 正着算出的数学约束 */
#include <stdio.h>
#include <string.h>

int main(void) {
    char name[32];
    unsigned int serial;
    printf("name: ");
    fflush(stdout);
    scanf("%31s", name);
    printf("serial: ");
    fflush(stdout);
    scanf("%u", &serial);

    unsigned int sum = 0;
    for (size_t i = 0; i < strlen(name); i++)
        sum += (unsigned char)name[i] * (unsigned int)(i + 1);

    if (serial == (sum * 0x1337u + 0x5A5Au) % 100000u)
        puts("Correct! license accepted.");
    else
        puts("Wrong serial");
    return 0;
}
```

### 4.2 读出约束

```bash
gcc -O0 -fno-pie -no-pie cm3_keygen.c -o cm3_keygen
objdump -d -M intel cm3_keygen | sed -n '/<main>:/,/^$/p'
```

输出（objdump -d -M intel，省略输入与噪声）：

```asm
; x86-64 Linux · System V AMD64 ABI · Intel 语法
  40126a:  lea    rdx,[rbp-0x30]               ; ┐ name[i]
  40126e:  mov    rax,QWORD PTR [rbp-0x38]     ; │
  401272:  add    rax,rdx
  401275:  movzx  eax,BYTE PTR [rax]
  401278:  movzx  eax,al
  40127b:  mov    rdx,QWORD PTR [rbp-0x38]
  40127f:  add    edx,0x1                      ; │ i + 1
  401282:  imul   eax,edx                      ; │ name[i] * (i+1)
  401285:  add    DWORD PTR [rbp-0x3c],eax     ; ┘ sum += ...
  401288:  add    QWORD PTR [rbp-0x38],0x1     ; i++（size_t，无符号）
  401294:  call   4010a0 <strlen@plt>
  401299:  cmp    QWORD PTR [rbp-0x38],rax
  40129d:  jb     40126a <main+0x94>           ; i < strlen(name)：jb 是无符号一族（R03 4 节）
  40129f:  mov    eax,DWORD PTR [rbp-0x3c]     ; eax = sum
  4012a2:  imul   eax,eax,0x1337               ; sum * 0x1337
  4012a8:  lea    edx,[rax+0x5a5a]             ; + 0x5A5A（R03：lea 兼职算术）
  4012ae:  mov    eax,edx
  4012b0:  shr    eax,0x5                      ; ┐ 除以 100000 的乘法魔数：
  4012b3:  mov    eax,eax                      ; │ imul 一个大常数再取高位
  4012b5:  imul   rax,rax,0xa7c5ac5            ; │ 商 ≈ (x * 0xa7c5ac5) >> 37
  4012bc:  shr    rax,0x20                     ; ┘
  4012c0:  shr    eax,0x7
  4012c3:  imul   ecx,eax,0x186a0              ; 商 × 100000（0x186a0）
  4012c9:  mov    eax,edx
  4012cb:  sub    eax,ecx                      ; 被除数 − 商×100000 = 余数
  4012cd:  mov    edx,DWORD PTR [rbp-0x40]     ; serial
  4012d0:  cmp    eax,edx                      ; 期望值 == serial ?
  4012d2:  jne    4012e0 <main+0x10a>
```

约束还原为一个式子（L 是 name 长度，name[i] 按字节值参与运算）：

$$\text{serial} = \Big(\big(\textstyle\sum_{i=0}^{L-1} \text{name}[i]\cdot(i+1)\big)\times \text{0x1337} + \text{0x5A5A}\Big) \bmod 100000 \tag{3}$$

识别要点：`imul eax,eax,0x1337` 与 `lea edx,[rax+0x5a5a]` 直接给出乘法与加法常数；后面一串"imul 大常数 + shr 取高位 + 乘回去 + sub"是编译器算**除以常数**的固定套路——==它不是新算法，就是 `% 100000`==（[[R03-x86与x64汇编精要复习#3.5 乘法与除法|R03 3.5]] 讲过移位除法的原理，非 2 的幂的常数用乘法魔数实现，思想相同）。0x186a0 换算成十进制正是 100000，与源码对上。

### 4.3 注册机与验证

```python
# keygen3.py —— 注册机：对任意 name 正着算 serial
import sys

name = sys.argv[1]
s = 0
for i, ch in enumerate(name):
    s += ord(ch) * (i + 1)          # 与校验函数同一个加权求和
print((s * 0x1337 + 0x5A5A) % 100000)
```

```bash
python3 keygen3.py crackme
python3 keygen3.py neo
printf 'crackme\n37420\n' | ./cm3_keygen
printf 'neo\n95885\n' | ./cm3_keygen
```

输出：

```
37420
95885
name: serial: Correct! license accepted.
name: serial: Correct! license accepted.
```

两个不同的 name 都通过——==keygen 的验收标准是对任意 name 都给出能过的 serial==，这也正是注册机型与变换比较型的分水岭：变换比较型的答案是一个固定串，注册机型的答案是"一个函数"。

> [!warning] 抄校验要保持宽度语义
> C 的 `unsigned int` 乘法会回绕（结果对 2³² 取模），Python 的整数不会。抄校验逻辑进脚本时注意中间结果是否超出 2³²——本例对短 name 不会超，但赛题里 `sum * 大常数` 完全可能回绕，脚本要补 `& 0xFFFFFFFF` 与程序保持一致。逆变换与正着算都受这条约束（整型转换在反汇编里的痕迹见 [[R02-C语言与内存模型回顾#8. 整型溢出在反汇编里留下的痕迹|R02 第 8 节]]）。

## 5. 类型四：patch 绕过型

前三类都在求"能让程序点头的输入"，这一类改程序本身：==把校验改成永远通过==。适用场景：校验难逆（哈希、大空间搜索、非线性约束）、逆的代价比改字节大、或你只需要拿到 flag 不需要理解算法。patch 是正当的解题手段，赛题里也常考"给一个逆不动的校验，考你补丁下得准不准"。

### 5.1 实例与补丁点

```c
/* cm4_patch.c —— patch 绕过型：校验是 31 进制折叠哈希，不想逆就改程序 */
#include <stdio.h>

static unsigned char fold(const char *s) {
    unsigned char h = 0;
    for (int i = 0; s[i]; i++)
        h = (unsigned char)(h * 31 + s[i]);
    return h;
}

int main(void) {
    char buf[32];
    printf("license: ");
    fflush(stdout);
    scanf("%31s", buf);
    if (fold(buf) == 0x5B)
        puts("license accepted. flag{p4tch_th3_jcc}");
    else
        puts("license rejected");
    return 0;
}
```

校验条件 `fold(buf) == 0x5B` 是一个哈希原像问题：fold 是逐字符 `h = h*31 + c` 的折叠哈希，找原像要枚举或约束求解。strings 扫一遍只有提示语，校验用的 0x5B 不可见：

```bash
gcc -O0 -fno-pie -no-pie cm4_patch.c -o cm4_patch
strings -t x cm4_patch | grep -E 'license|flag'
```

输出：

```
   2008 license: 
   2018 license accepted. flag{p4tch_th3_jcc}
   203e license rejected
```

反汇编 main 与 fold（噪声已省略）：

```bash
objdump -d -M intel cm4_patch | sed -n '/<fold>:/,/<main>/p'
```

输出（objdump -d -M intel）：

```asm
; x86-64 Linux · System V AMD64 ABI · Intel 语法
00000000004011b6 <fold>:
  4011cf:  movzx  edx,BYTE PTR [rbp-0x5]       ; h
  4011d3:  mov    eax,edx
  4011d5:  shl    eax,0x5                      ; h × 32
  4011d8:  sub    eax,edx                      ; h × 32 − h = h × 31
  4011dc:  mov    ecx,eax
  ……（取 s[i] 的几条 mov/movsxd/add，省略）……
  4011ec:  add    eax,ecx                      ; h×31 + s[i]
  4011ee:  mov    BYTE PTR [rbp-0x5],al        ; 写回低 8 位：截断
  4011f1:  add    DWORD PTR [rbp-0x4],0x1      ; i++
  401205:  test   al,al                        ; s[i] == 0 ?
  401207:  jne    4011cf <fold+0x19>           ; 非 0 → 下一轮
  401209:  movzx  eax,BYTE PTR [rbp-0x5]       ; 返回 h

000000000040120f <main>:
  40125e:  lea    rax,[rbp-0x30]
  401262:  mov    rdi,rax
  401265:  call   4011b6 <fold>                ; al = fold(buf)
  40126a:  cmp    al,0x5b                      ; 与 0x5B 比
  40126c:  jne    40127a <main+0x6b>           ; 不等 → 失败分支
  40126e:  mov    edi,0x402018                 ; "license accepted. ..."
  401273:  call   401080 <puts@plt>
  401278:  jmp    401284 <main+0x75>
  40127a:  mov    edi,0x40203e                 ; "license rejected"
  40127f:  call   401080 <puts@plt>
```

补丁点就是 0x40126a 起的四个字节。patch 流程三步：**定位**（虚拟地址）、**算字节**（改哪个字节成什么）、**落盘**（虚拟地址换算成文件偏移再写入）。第三步需要换算关系：

```bash
objdump -h cm4_patch | grep '\.text'
```

输出：

```
 12 .text         000001cf  00000000004010d0  00000000004010d0  000010d0  2**4
```

`.text` 的虚拟地址 0x4010d0 对应文件偏移 0x10d0：==非 PIE 下虚拟地址减 0x400000 就是文件偏移==。所以 0x40126a 落在文件偏移 0x126a。写之前先看一眼原始字节：

```bash
xxd -g1 -s 0x126a -l 4 cm4_patch
```

输出：

```
0000126a: 3c 5b 75 0c                                      <[u.
```

`3c 5b` 是 `cmp al,0x5b`，`75 0c` 是 `jne +0x0c`（跳去失败分支）。`-g1` 让每个字节单独成组，方便 sed 按字节替换。

补丁字节用 nasm 算：写一个只有补丁指令的汇编文件，`-f bin` 产出纯机器码。

```nasm
; fix_a.asm —— 与 jne 等长的两条 nop
bits 64
times 2 nop
```

```bash
nasm -f bin fix_a.asm -o fix_a.bin
xxd fix_a.bin
```

输出：

```
00000000: 9090                                     ..
```

补丁就是 `90 90` 两个字节。下面三个补丁各走一遍完整流程，都用同一套命令形状：`cp` 出副本 → `xxd -g1` 整文件转储 → `sed` 改字节 → `xxd -r` 转回二进制 → `cmp -l` 确认改动范围 → 运行验证。

### 5.2 补丁 A：nop 掉 jcc

把 `jne 40127a` 换成两条 nop：比较照做，但"不等就跳失败"这条路被拆除，无论输入是什么都落到成功分支。

```bash
cp cm4_patch cm4_nop
xxd -g1 cm4_nop > a.hex
sed -i 's/75 0c/90 90/' a.hex      # 补丁点字节在整份转储中唯一
xxd -r a.hex > cm4_nop
cmp -l cm4_patch cm4_nop
echo hello | ./cm4_nop
echo AAAA | ./cm4_nop
```

输出：

```
 4717 165 220
 4718  14 220
license: license accepted. flag{p4tch_th3_jcc}
license: license accepted. flag{p4tch_th3_jcc}
```

`cmp -l` 按字节列出两份文件的差异：第一列是 1 起算的字节序号（4717、4718 对应文件偏移 0x126c、0x126d），后两列是两份文件里该字节的**八进制**值——165(八进制) = 0x75 换成了 220(八进制) = 0x90，14(八进制) = 0x0c 同样换成 0x90。任意输入都通过，行为符合预期。

### 5.3 补丁 B：改跳转目标

不拆掉这条跳转，改它的**目标**：`jne +0x0c` 原本跳去失败分支，把偏移改成 0，就跳到紧跟的下一条指令——恰好是成功分支的第一条 `mov edi,0x402018`。

```bash
cp cm4_patch cm4_jmp
xxd -g1 cm4_jmp > j.hex
sed -i 's/75 0c/75 00/' j.hex      # 目标偏移 0x0c → 0x00
xxd -r j.hex > cm4_jmp
cmp -l cm4_patch cm4_jmp
echo whatever | ./cm4_jmp
```

输出：

```
 4718  14   0
license: license accepted. flag{p4tch_th3_jcc}
```

只动了 1 个字节（14(八进制) = 0x0c → 0）。本例里目标改 0 与 nop 效果相同，因为成功分支紧挨着；==改跳转目标的真正用武之地是多重校验==：失败跳转落在校验链中间，把它的目标改成**最终成功块**的地址，一次跳过全部校验——这时 nop 做不到，只能改目标。改目标前先在 objdump 里量好新目标的地址，换算 rel8/rel32 偏移；偏移字节用 nasm 写更省事（见 5.5）。

### 5.4 补丁 C：改比较值

第三条路：不改控制流，改**答案**。把比较常数 0x5B 换成手头某个输入的哈希值，这个输入就成了合法答案。先算 `fold("AAAA")`：

```bash
python3 -c "
def fold(s):
    h = 0
    for c in s: h = (h * 31 + ord(c)) & 0xFF
    return h
print(hex(fold('AAAA')), hex(fold('[')))
"
```

输出：

```
0x40 0x5b
```

`fold("AAAA") = 0x40`。用 nasm 组装新的比较指令确认编码：

```nasm
; fix_c.asm —— cmp al, 0x40
bits 64
cmp al, 0x40
```

```bash
nasm -f bin fix_c.asm -o fix_c.bin
xxd fix_c.bin
```

输出：

```
00000000: 3c40                                     <@
```

补丁字节 `3c 40`，与原指令 `3c 5b` 等长：

```bash
cp cm4_patch cm4_cmp
xxd -g1 cm4_cmp > c.hex
sed -i 's/3c 5b/3c 40/' c.hex      # 答案从 0x5B 改成 0x40
xxd -r c.hex > cm4_cmp
cmp -l cm4_patch cm4_cmp
echo AAAA | ./cm4_cmp
echo "[" | ./cm4_cmp
```

输出：

```
 4716 133 100
license: license accepted. flag{p4tch_th3_jcc}
license: license rejected
```

`AAAA` 通过（133(八进制) = 0x5b 换成 100(八进制) = 0x40）；原来的通行证 `[` 失效——==改比较值后，"正确答案"换成了你指定的那个==。

### 5.5 补丁规范

> [!warning] 三条铁律
> **等长**：新指令的字节数必须与原指令一致——改长了会把下一条指令劈断，程序直接崩。nop 填充、选等价指令（`call time@plt` 5 字节 → `mov eax, imm32` 5 字节）都是为了等长。
> **先副本后验证**：`cp` 出副本再改，原文件留底对照；改完先 `objdump -d` 反汇编补丁点，确认每条指令仍合法，再运行。
> **量准文件偏移**：虚拟地址 ≠ 文件偏移。非 PIE 减 0x400000（用 `objdump -h` 核对），PIE 与 PE 的换算各有一套，动手前先算对。

> [!info]- 哈希校验未必真的难逆
> 本例的 fold 存在单字符原像：`fold("[") = 0x5B`（0×31 + 91 = 91），输入 `[` 就能通过原版程序——上面的运行记录可以复现。哈希校验的输入空间小时，枚举/约束求解的成本可能远低于 patch；==先估一下逆的代价，再决定改输入还是改程序==，这正是分流能力的核心。判断错了也不亏：patch 的字节还能改回来。

> [!info]- nasm 还能帮你算跳转偏移
> 5.3 的目标偏移是手算的。跳得远时用 nasm 的 `org` 伪指令：`bits 64` + `org 0x40126c`（补丁点虚拟地址）+ `jmp 0x40126e`（新目标），`nasm -f bin` 会按 org 自动算出 rel8/rel32 编码，产出的字节直接可用。手册在 nasm.us，常用的就 `db`、`times`、`org` 三条。

## 6. 典型汇编模式速查

四类题型在反汇编与伪代码里有固定形状。下表左列全部摘自本章实例的真实产物（省略序言与 canary），右列是 IDA F5 之后对应的伪代码形态（[[R05-静态分析工具链IDA与Ghidra#3.7 F5 伪代码：能力与局限|R05 3.7]]）：

| 校验源码形状 | 汇编形状（本章实例产物） | IDA 伪代码形态 |
| ---- | ---- | ---- |
| strcmp 明文比较 | `call strcmp@plt` → `test eax,eax` → `jne 失败` | `if ( strcmp(input, "EZ-PWND-2026") != 0 )` |
| 常量表逐字节变换 | `movzx eax,BYTE PTR [rbp+rax*1-0x20]` → `xor eax,0x37` → `add edx,eax` → `movzx eax,BYTE PTR [rax+0x402008]` → `cmp dl,al` | `if ((unsigned char)((key[8-i] ^ 0x37) + i) != enc[i])` |
| 自定义变换函数 | `lea rax,[rbp-0x30]` → `mov rdi,rax` → `call fold` → `cmp al,0x5b` → `jne 失败` | `if ( fold(input) != 0x5B )` |
| 加权和 + 乘常数 + 取模 | `imul eax,edx`（循环内）→ `imul eax,eax,0x1337` → `imul rax,rax,0xa7c5ac5` → `shr` → `imul ecx,eax,0x186a0` → `cmp eax,edx` | `if ( serial != (sum * 0x1337 + 0x5A5A) % 100000 )` |
| 逐字符立即数比较 | `movzx eax,BYTE PTR [rbp-0x20]` → `cmp al,0x43` → `jne 失败` | `if ( input[0] != 'C' )` |
| 累加校验和 + 取模 | `movzx eax,BYTE PTR [rbp+rax*1-0x20]` → `add [rbp-0x28],eax` →（循环）→ `imul rax,rax,0x828cbfbf` → `shr` → `imul edx,eax,0xfb` → `cmp eax,0x64` | `if ( sum % 251 != 100 )` |

读的心法一句话：==顺着数据流走，从输入入口走到比较落点==。输入从 `scanf`/`read`/argv 进来，记下它所在栈槽或寄存器；沿着 `mov`/`movzx`/算术指令/`call` 走，每一步问"这个值现在是什么"；在 `cmp`/`test` 处落地，配的 jcc 决定成败方向（[[R03-x86与x64汇编精要复习#4. 条件跳转：jcc 家族|R03 第 4 节]]）。伪代码里同一条链就是变量的赋值传播。链上任何一环出现看不懂的常数，先换算十进制再下结论。

## 7. 数学约束求解工具箱

注册机型的约束、多层校验的关卡，拆开看常是四类基础数学。本节把它们各配一个校验形状、一个解法与可运行的脚本。四个校验放在同一个程序里：

```c
/* constraints.c —— 四类数学约束的校验形状，各占一个函数 */
#include <stdio.h>
#include <string.h>

int sum_check(int n) {              /* 各位数字之和为 25，且 n 是 97 的倍数 */
    int s = 0, m = n;
    while (m > 0) { s += m % 10; m /= 10; }
    return s == 25 && n % 97 == 0;
}

int xor_check(const unsigned char *buf) {   /* 8 字节全体异或等于 0x2C */
    if (strlen((const char *)buf) != 8) return 0;
    unsigned char x = 0;
    for (int i = 0; i < 8; i++) x ^= buf[i];
    return x == 0x2C;
}

int linear_check(int x, int y) {    /* x + y = 2663 且 x - y = 897 */
    return x + y == 2663 && x - y == 897;
}

int mod_check(unsigned int s) {     /* 349525 * s ≡ 12345 (mod 104729) */
    return (unsigned long long)349525u * s % 104729u == 12345u;
}

int main(void) {
    int n; char buf[16]; int x, y; unsigned int s;
    if (scanf("%d %15s %d %d %u", &n, buf, &x, &y, &s) != 5) return 1;
    printf("%d %d %d %d\n",
           sum_check(n), xor_check((const unsigned char *)buf),
           linear_check(x, y), mod_check(s));
    return 0;
}
```

F5 之后看到的伪代码与上面源码同形。四个函数对应四类解法。

### 7.1 整数和

`sum_check` 形状的约束（各位数字之和 + 一个整除条件）通常不唯一解，题面要么问"最小解"，要么任何解都行——枚举即可：从 97 起按 97 步进，逐个验数字和。

```python
n = 97
while True:
    if sum(int(c) for c in str(n)) == 25:
        print(n)
        break
    n += 97
```

输出：

```
3589
```

最小解 3589 = 97×37，3+5+8+9=25。`n % 10` 取个位、`n / 10` 去掉个位，程序里拼数字和的循环在反汇编里就是 [[R03-x86与x64汇编精要复习#7.3 形状三：循环|R03 7.3]] 的循环形状加 [[R03-x86与x64汇编精要复习#3.5 乘法与除法|R03 3.5]] 的除法形状。

### 7.2 异或和

`xor_check` 形状的约束只定"全体异或值"，解空间巨大，用**构造法**：前 7 个字节任取，最后一个字节用异或的性质补齐。设前 7 个都取 'A'（0x41），奇数个 0x41 异或还是 0x41：

$$x_7 = \text{0x2C} \oplus x_0 \oplus x_1 \oplus \cdots \oplus x_6 \tag{4}$$

```python
x = 0x41
for _ in range(6):
    x ^= 0x41          # 七个 'A' 的异或仍是 0x41
print(chr(0x2C ^ x))   # 补上第 8 个字节
```

输出：

```
m
```

构造出 `AAAAAAAm`，与 7.4 之后的程序验证一致。

### 7.3 线性方程

`linear_check` 形状是两个未知数两条方程，直接消元：

$$x = \frac{S+D}{2},\qquad y = \frac{S-D}{2} \tag{5}$$

```python
print((2663 + 897) // 2, (2663 - 897) // 2)
```

输出：

```
1780 883
```

约束比未知数少时是多解问题，回到 7.2 的构造思路任取一组。

### 7.4 模逆

`mod_check` 形状要解 $a \cdot s \equiv c \pmod{m}$。若 $a^{-1}$ 是 $a$ 模 $m$ 的逆（$a \cdot a^{-1} \equiv 1 \pmod m$），则：

$$s \equiv c \cdot a^{-1} \pmod{m} \tag{6}$$

==扩展欧几里得在求 gcd(a, m) 的同时把 ax + my = g 的一组系数带出来，x mod m 就是 a 模 m 的逆==。Python 3.8 起 `pow(a, -1, m)` 直接给逆，两种写法一起验证：

```python
# solve_math.py —— 四类约束逐个解（节选模逆部分，前三类见正文推导）
def ext_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, p, q = ext_gcd(b, a % b)
    return g, q, p - (a // b) * q

def modinv(a, m):
    g, x, _ = ext_gcd(a % m, m)
    assert g == 1
    return x % m

a, m, c = 349525, 104729, 12345
s2 = c * modinv(a, m) % m
print("mod_check:", s2, "verify:", a * s2 % m == c)
print("pow shortcut:", c * pow(a, -1, m) % m)
```

四个解全部喂回程序：

```bash
echo "3589 AAAAAAAm 1780 883 82345" | ./constraints
echo "1 xxxxxxxx 1 1 1" | ./constraints
```

输出：

```
1 1 1 1
0 0 0 0
```

四项校验全过。四类约束的解（3589、`AAAAAAAm`、1780 与 883、82345）都由上面的枚举、构造、消元、模逆四条固定路径产生，赛题里更复杂的约束只是把这四类叠起来。

> [!warning] 模逆存在的前提
> `a` 与 `m` 必须互素（`ext_gcd` 返回的 g == 1），否则逆不存在，约束要么无解要么多解。校验里出现模运算时，先看模数是不是素数或与系数互素——不是的话，改用枚举或回到 z3 一类约束求解器。

## 8. 多层校验与限制类变体

真实题目常把前四类拆开重组。三个常见变体：答案被拆散的逐字符校验、只约束统计量的循环校验和、以及校验对象根本不是输入的时间与次数限制。

### 8.1 逐字符校验

答案被拆成一条条立即数比较，strings 一无所获：

```c
/* cm5_chars.c —— 逐字符校验：答案被拆成一条条立即数比较，strings 搜不到 */
#include <stdio.h>

int main(void) {
    char buf[16];
    printf("key: ");
    fflush(stdout);
    scanf("%15s", buf);
    if (buf[0] == 'C' && buf[1] == '7' && buf[2] == 'F' && buf[3] == '_' &&
        buf[4] == '2' && buf[5] == '0' && buf[6] == '2' && buf[7] == '6' &&
        buf[8] == '\0')
        puts("Correct! flag{ch4r_b4_ch4r}");
    else
        puts("Wrong key");
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie cm5_chars.c -o cm5_chars
strings -t x cm5_chars | grep -E 'key|flag|Correct|Wrong'
```

输出：

```
   2004 key: 
   200f Correct! flag{ch4r_b4_ch4r}
   202b Wrong key
```

只有提示语，没有答案——但答案就写在指令里：

```bash
objdump -d -M intel cm5_chars | sed -n '/<main>:/,/^$/p'
```

输出（objdump -d -M intel，截取比较链头尾）：

```asm
; x86-64 Linux · System V AMD64 ABI · Intel 语法
  401205:  movzx  eax,BYTE PTR [rbp-0x20]   ; buf[0]
  401209:  cmp    al,0x43                   ; 'C'
  40120b:  jne    401259 <main+0xa3>        ; 失败分支
  40120d:  movzx  eax,BYTE PTR [rbp-0x1f]   ; buf[1]
  401211:  cmp    al,0x37                   ; '7'
  401213:  jne    401259 <main+0xa3>
  ……（0x46 0x5f 0x32 0x30 0x32 0x36 依次排开，共 8 个字符）……
  401245:  movzx  eax,BYTE PTR [rbp-0x18]   ; buf[8]
  401249:  test   al,al                     ; == '\0' ?
  40124b:  jne    401259 <main+0xa3>
```

把每条 `cmp al, 立即数` 的立即数按 ASCII 解码（0x43 0x37 0x46 0x5f 0x32 0x30 0x32 0x36），拼出 `C7F_2026`，最后的 `test al,al` 要求第 9 字节是 `\0`，即长度恰好 8：

```bash
echo aaaaaaaaaaaa | ./cm5_chars
echo C7F_2026 | ./cm5_chars
```

输出：

```
key: Wrong key
key: Correct! flag{ch4r_b4_ch4r}
```

> [!info]- 首错即退的校验还能用动态调试逐字节恢复
> 本例的 `&&` 链编译后第一个错字符就直接跳失败。更强的校验（逐字符循环、错误返回特殊值）存在时序差异，可以逐字节爆破；不测时间也有更直接的路——[[R06-动态调试GDB与x64dbg#10.3 换条路：断在 strcmp@plt 上|R06 10.3]] 的思路搬过来，断在比较指令上，输入随便给，从寄存器里读期望字符。属于同一件工具的两用。

### 8.2 循环校验和

校验只约束输入的统计量（字节和、异或和、长度），合法输入是一整个集合，任取一个即可：

```c
/* cm6_checksum.c —— 循环校验和：只约束字节之和，答案不唯一 */
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char buf[16];
    printf("key: ");
    fflush(stdout);
    scanf("%15s", buf);
    unsigned int s = 0;
    for (int i = 0; i < (int)strlen((char *)buf); i++)
        s += buf[i];
    if (strlen((char *)buf) == 6 && s % 251 == 100)
        puts("Correct! flag{5um_ch3ck}");
    else
        puts("Wrong key");
    return 0;
}
```

反汇编的循环累加段（噪声已省略）与 [[#6. 典型汇编模式速查|第 6 节]]表末行同形；`imul rax,rax,0x828cbfbf` + `shr` + `imul edx,eax,0xfb` + `cmp eax,0x64` 又是乘法魔数：0xfb = 251、0x64 = 100，即 `s % 251 == 100`。解法照 7.2 的构造思路——枚举 6 个小写字母找满足条件的组合：

```python
# solve6.py —— 校验和约束只定数学条件，任取一组满足条件的小写字母
import itertools
import string

for combo in itertools.product(string.ascii_lowercase, repeat=6):
    if sum(map(ord, combo)) % 251 == 100:
        print("".join(combo))
        break
```

```bash
python3 solve6.py
echo aaaaau | ./cm6_checksum
```

输出：

```
aaaaau
key: Correct! flag{5um_ch3ck}
```

`aaaaau` 六个字节之和 602，602 mod 251 = 100。多解型校验的题，==输出任何一组满足条件的输入都算解==。

### 8.3 时间与次数限制

这一族变体的校验对象不是输入，而是环境：系统时钟、运行次数、使用期限。典型形状：

```c
/* cm7_time.c —— 时间限制变体：校验对象是系统时间，不是输入 */
#include <stdio.h>
#include <time.h>

int main(void) {
    time_t t = time(0);
    if (t > 2000000000)
        puts("license valid. flag{t1me_p4tch}");
    else
        puts("license expired");
    return 0;
}
```

```bash
gcc -O0 -fno-pie -no-pie cm7_time.c -o cm7_time
./cm7_time
./cm7_time
objdump -d -M intel cm7_time | sed -n '/<main>:/,/^$/p'
```

输出：

```
license expired
license expired
```

输出（objdump -d -M intel，main 全文——这个函数没有数组，连 canary 都没有）：

```asm
; x86-64 Linux · System V AMD64 ABI · Intel 语法
0000000000401156 <main>:
  401162:  mov    edi,0x0                        ; time(NULL)
  401167:  call   401060 <time@plt>              ; 返回值在 rax
  40116c:  mov    QWORD PTR [rbp-0x8],rax        ; t
  401170:  cmp    QWORD PTR [rbp-0x8],0x77359400 ; t 与 2000000000 比（2033 年的时间戳）
  401178:  jle    401186 <main+0x30>             ; ≤ → 过期分支（jle 是有符号一族，time_t 带符号）
  40117a:  mov    edi,0x402008                   ; "license valid. ..."
  40117f:  call   401050 <puts@plt>
  401184:  jmp    401190 <main+0x3a>
  401186:  mov    edi,0x402028                   ; "license expired"
  40118b:  call   401050 <puts@plt>
```

两条路。**动态路**：断在 0x40116c（call 返回后），`set $rax=2100000000` 伪造 time 的返回值再放行，操作见 [[R06-动态调试GDB与x64dbg|R06]] 第 10 节的四步流程。**静态路**：把 `call time@plt`（5 字节）整体替换成"给 eax 装一个大数"的等长指令。用 nasm 算字节：

```nasm
; fix_t.asm —— 与 call time@plt 等长的 5 字节补丁：mov eax, 2100000000
bits 64
mov eax, 2100000000
```

```bash
nasm -f bin fix_t.asm -o fix_t.bin
xxd fix_t.bin
```

输出：

```
00000000: b800 752b 7d                             ..u+}
```

`b8 00 75 2b 7d` 正是 5 字节（0x7D2B7500 = 2100000000；写 eax 会把 rax 高 32 位清零，但 2100000000 在 32 位以内，无影响）。应用补丁：

```bash
cp cm7_time cm7_fix
xxd -g1 cm7_fix > t.hex
sed -i 's/e8 f4 fe ff ff/b8 00 75 2b 7d/' t.hex
xxd -r t.hex > cm7_fix
cmp -l cm7_time cm7_fix
./cm7_fix
./cm7_fix
objdump -d -M intel cm7_fix | sed -n '/<main>:/,/^$/p' | sed -n '6,12p'
```

输出：

```
 4456 350 270
 4457 364   0
 4458 376 165
 4459 377  53
 4460 377 175
license valid. flag{t1me_p4tch}
license valid. flag{t1me_p4tch}
  401162:	bf 00 00 00 00       	mov    edi,0x0
  401167:	b8 00 75 2b 7d       	mov    eax,0x7d2b7500
  40116c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  401170:	48 81 7d f8 00 94 35 	cmp    QWORD PTR [rbp-0x8],0x77359400
  401177:	77 
  401178:	7e 0c                	jle    401186 <main+0x30>
```

五个字节换成补丁（350(八进制) = 0xe8 → 270(八进制) = 0xb8，依此类推），程序从此永远读到 2100000000，校验通过；补丁后的反汇编确认 `mov eax,0x7d2b7500` 落位、后续指令完好（`cmp` 的 7 字节立即数在 objdump 里有换行续行，第 401177 行那个孤立的 `77` 就是它的第 7 个字节）。

次数限制同族。典型形状（语义示意）：

```asm
; 语义示意 · x86-64 Linux · Intel 语法 · 次数限制的典型形状
; 伪代码：if (++tries > 3) reject;
  add    DWORD PTR [tries],0x1        ; tries++
  cmp    DWORD PTR [tries],0x3        ; 与上限比
  jg     reject                       ; 超过 → 拒绝
```

两个改法与时间类一致：改比较常数（把上限改成大数）或 nop 掉 `jg`。计数变量存哪里决定补丁对象——存在程序全局区就照本节改字节；存在注册表、存档文件、远端服务器，就得先定位存储（[[R06-动态调试GDB与x64dbg#4. 观察点：watch、rwatch、awatch|观察点]]盯写入者），再改环境或伪造存储内容。命令行 crackme 一次运行一个进程，次数限制少见；GUI 程序的试用版逻辑常见，思路完全一致。

## 9. 三遍学习法与错题本

crackme 题量大、题型重复率高，是唯一适合"刷"的逆向品类，但==刷的价值不在数量，在每道题被消化到什么程度==。固定做三遍：

**第一遍：独立做。** 按 1.2 的分流决策走完全程，不查题解。卡住时先记录卡点（在哪一步、当时在想什么、试了什么），最多看一次提示，然后继续。第一遍的产出是"我的解法"和"卡点清单"。

**第二遍：对比多篇 WriteUp。** 找两三篇别人的解法，逐段对比：他先 strings 还是先 F5？定位校验走的哪条路？逆变换手推还是脚本？有没有走你没想到的短路（你逆了半天哈希，他直接 patch）？每处差异都指向一种你没启动的思路，记进错题本。

**第三遍：脱稿复现。** 合上所有参考材料，从 `file` 到拿 flag 全程重做一遍，产出一个能跑的 solve 脚本。复现时卡壳的地方，就是第一遍其实没学会的地方——回章节重读那一段。

三遍对应的训练目标不同：第一遍练独立判断，第二遍补视角盲区，第三遍把"看到形状 → 想到动作"固化成反应。

每道题做完立刻补一条错题本记录，模板四列：

| 字段 | 填什么 | 示例 |
| ---- | ---- | ---- |
| 题目 | 平台 / 题名 / 难度 | crackmes.one / EasyLicense / ★1 |
| 卡点 | 停在哪一步、卡了多久 | strings 搜不到答案，没想到答案被拆成立即数 |
| 关键一步 | 打破僵局的那条命令或那行伪代码 | `objdump -d` 里看到 `cmp al,0x43` 链 |
| 对应章节 | 本库的入口 | [[#8.1 逐字符校验\|R08 8.1]] |

> [!note] 错题本的用法
> 每题一条，当天补完。周末回看：同一类卡点出现第三次，说明对应章节没吃透，回头把那一节按第三遍的方式重做一遍例题。坚持 20 道后，卡点类型会明显收敛——那之后新题的用时就是分流熟练度的直接度量。

## 10. 常见问题

| 现象 | 原因与解决 |
| ---- | ---- |
| strings 找不到任何像答案的串 | 答案被拆成逐字符立即数（[[#8.1 逐字符校验\|8.1]]）、运行时才解密拼装（[[R06-动态调试GDB与x64dbg#10. 实战：动态 dump 出密钥\|R06 第 10 节]]）、或程序加壳（[[R09-加壳与脱壳\|R09]]）；按这个顺序排查 |
| 逆变换算出的 key 程序不认 | 逆变换的顺序抄反，或漏了字节截断——严格按正变换的相反顺序撤，每步 `& 0xFF`（见 [[#3. 类型二：变换比较型\|第 3 节]]） |
| keygen 对本题的 name 能过，换一个就错 | 抄校验时漏了 C 的宽度语义：`unsigned` 回绕、`size_t` 与 `int` 混用；脚本补 `& 0xFFFFFFFF` 对齐程序行为（见 [[#4. 类型三：注册机求解型\|第 4 节]]） |
| patch 后程序闪退或无输出 | 补丁不等长改断了指令；重新 `objdump -d` 补丁点，确认每条指令仍完整合法（[[#5.5 补丁规范\|5.5]]） |
| 补丁只改了一处，行为却没变 | 校验有多条路径（多重 if、循环内判断），另一条失败边还在；把所有 `jcc 失败` 列出来逐个处理 |
| 输入完全正确仍提示失败 | 成功输出混着诱饵字符串；从 `puts` 的交叉引用确认哪条输出在真实校验路径上（[[R05-静态分析工具链IDA与Ghidra#3.6 交叉引用（xref）：代码引用与数据引用\|R05 3.6]]） |
| 反汇编里的 0x77359400、0x186a0 看不懂 | 魔数先换十进制再下结论：0x77359400=2000000000、0x186a0=100000、0xfb=251（[[R03-x86与x64汇编精要复习\|R03]] 7.2 同款提醒） |
| 伪代码里找不到 `%`，只有一串 imul + shr | 除以常数不生成除法指令：乘法魔数 + 取高位就是除法/取模，乘回去再相减的是余数（见 [[#4.2 读出约束\|4.2]]） |
| 时间限制题两次运行结果不同 | 校验对象是时钟不是输入；GDB 改返回值或 patch `call time@plt`（见 [[#8.3 时间与次数限制\|8.3]]） |
| 模逆脚本报逆不存在或结果不对 | a 与 m 不互素时逆不存在；先算 gcd 确认，再考虑无解/多解的处理（[[#7.4 模逆\|7.4]]） |
| `xxd -r` 后文件没有执行权限 | 在 `cp` 出的副本上改；`ls -l` 查权限，必要时 `chmod +x` 补回 |
| F5 伪代码看着对，程序行为不符 | 反编译器翻译误差；回汇编视图核对，或用动态调试验证（[[R05-静态分析工具链IDA与Ghidra#3.7 F5 伪代码：能力与局限\|R05 3.7]]） |

