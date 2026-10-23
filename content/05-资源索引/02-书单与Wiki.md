---
chapter: 资源索引
section: 书单与 Wiki
order: 502
tags:
  - CTF
  - 资源索引
  - 书单
publish: true
---

# 书单与 Wiki

> [!info]- 章节信息
> **所属方向**：资源索引 ｜ **难度阶段**：全阶段 ｜ **前置要求**：无
> **本章目标**：Wiki、系统教程与书单集中索引，每项标注与本库章节的对应关系，按需取用。

## 1. Wiki 与系统教程

| 名称 | 链接 | 用途 | 本库对应 |
| ---- | ---- | ---- | ---- |
| [CTF Wiki](https://ctf-wiki.org/) | ctf-wiki.org | 中文最全入门体系，建议第一遍通读 | 与全库章节互为对照 |
| [how2heap](https://github.com/shellphish/how2heap) | github.com/shellphish/how2heap | 堆利用技术合集，每种技术一个最小 demo | [[P12-glibc堆管理机制\|P12]]–[[P17-堆风水与通用利用思路\|P17]] |
| [pwn.college](https://pwn.college/) | pwn.college | 系统化二进制课程（ASU），视频+关卡 | [[P01-PWN导论与缓解机制全景\|P1]]–[[P11-Canary绕过与GOT攻击\|P11]] |
| [OST2](https://p.ost2.fyi/) | p.ost2.fyi | 免费逆向工程课程（OpenSecurityTraining2） | [[R03-x86与x64汇编精要复习\|R03]]、[[R05-静态分析工具链IDA与Ghidra\|R5]] 深化 |
| [LiveOverflow](https://liveoverflow.com/) | liveoverflow.com | 二进制安全视频博客，直觉建立 | [[P06-栈溢出原理与ret2win\|P6]] 起的 PWN 直觉 |
| 一步一步 ROP | 搜索"一步一步 ROP" | 中文 ROP 链式学习经典 | [[P07-ret2libc-ret2syscall-ret2shellcode\|P7]]、[[P08-ROP进阶与SROP\|P8]] |
| SploitFun | 搜索"SploitFun linux x86" | 经典漏洞利用系列（英文） | [[P06-栈溢出原理与ret2win\|P6]] |
| Trail of Bits CTF Field Guide | 搜索"trail of bits ctf field guide" | 英文 CTF 知识手册 | 全库对照 |

> [!note] 用法
> Wiki 用于第一遍通读建立全局观；how2heap 和 pwn.college 在对应阶段当练习场；教程类读完即归档，不必反复重读。

## 2. 书单

| 书名 | 适用阶段 | 用途 | 本库对应 |
| ---- | ---- | ---- | ---- |
| 《鸟哥的 Linux 私房菜》 | L0 | Linux 基础 | [[01-Linux环境与CTF实验环境搭建\|通用基础 01 章]]、[[07-Linux进阶操作与Shell脚本\|通用基础 07 章]] |
| 《汇编语言（王爽）》 | L1 | 16 位汇编零基础入门 | [[04-汇编语言精要\|通用基础 04 章]] 前置 |
| 《C 和指针》 | L1 | C 语言与指针深化 | [[02-C语言与内存模型\|通用基础 02 章]] |
| 《深入理解计算机系统（CSAPP）》 | L1–L2 | 程序机器级表示与内存体系 | [[03-计算机组成与数据表示\|通用基础 03 章]]、[[R02-C语言与内存模型回顾\|R2]] |
| 《程序员的自我修养：链接、装载与库》 | L2 | ELF 与动态链接原理 | [[05-ELF文件格式与链接\|通用基础 05 章]]、[[P03-ELF链接与延迟绑定\|P3]] |
| 《逆向工程核心原理》 | L2–L3 | Windows 逆向体系化 | [[R05-静态分析工具链IDA与Ghidra\|R5]]、[[R09-加壳与脱壳\|R9]]、[[R10-反调试与反分析对抗\|R10]] |
| 《有趣的二进制》 | L2 | 逆向与安全入门轻读物 | [[R08-CrackMe经典题型\|R8]] |
| 《0day 安全：软件漏洞利用分析》 | L2–L3 | Windows 漏洞利用经典 | [[P06-栈溢出原理与ret2win\|P6]]、[[P19-多平台PWN\|P19]] |
| 《恶意代码分析实战》 | L3–L4 | 恶意样本分析方法论 | [[R15-恶意代码分析基础\|R15]] |
| 《Practical Binary Analysis》 | L3–L4 | 二进制分析框架化（英文） | [[R14-自动化分析angr与z3\|R14]]、[[R12-虚拟机保护VM逆向\|R12]] |

## 3. 读法建议

> [!note] 三条原则
> ① 书是参考不是课程——==遇到对应知识点的卡点时翻对应章节==，比从头通读有效；② 旧书（如《0day 安全》）的技术细节过时，读思路不抄代码；③ 英文书先读目录挑章节，不必全读。
