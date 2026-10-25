---
title: 侦察与 RAID0 盘序推定
tags:
  - 实战案例
  - MISC
  - raid-restore
  - 磁盘取证
created: 2026-10-25
status: 已核验
order: 200
publish: true
---

侦察阶段做三件事：清点附件、逐盘扫签名、解析文件系统参数。三步做完，阵列容量、分区表、文件系统几何全部到手，剩下的盘序推定只是一次带约束的拟合。

> [!info]- 为什么先扫签名而不是先拼盘
> 盘序未知的阵列里，任何一块盘上的字节都可能属于阵列坐标系的任何位置。但有些结构的位置是**写死的**：GPT 主头永远在阵列 LBA 1，备份头永远在最后一个 LBA，XFS 的 AG 超级块副本永远在分区起点加整数倍 AG 大小处。这些结构出现在哪块盘的哪个偏移，就等于泄露了一个"阵列坐标 → 盘内坐标"的样本点。样本攒够，参数就解出来了。

## 附件清点

解包后先看清单：每块盘多大、有几块，直接决定阵列容量。

```bash
unzip -l diskresuce-raid0.zip | tail -4
unzip -l diskresuce-raid5.zip | tail -4
```

输出：

```
 16777216  2021-10-07 00:00   wlOUASom2fI.img
 16777216  2021-10-07 00:00   1GHGGrmaMM0.img
 ---------                     -------
134217728                     8 files
 33554432  2021-10-07 00:00   QjTgmgmwXAM.img
 33554432  2021-10-07 00:00   3RlmViivyG8.img
 ---------                     -------
167772160                     5 files
```

> [!info]- 从容量读阵列形状
> - RAID 0 包：总字节 134217728 = 128 MiB = 8 × 16 MiB，正好是 8 块盘的容量和——RAID 0 无冗余，阵列容量等于盘容量之和
> - RAID 5 包：总字节 167772160 = 160 MiB = 5 × 32 MiB，但阵列容量只有 4 × 32 MiB = 128 MiB——每个条带有一块盘存校验
> - 两问的阵列容量同为 128 MiB，后面 GPT 里的分区表也几乎相同，这不是巧合：出题人把同一个磁盘镜像分别按两种阵列拆开

## 逐盘扫签名

对每块盘搜两组特征串：GPT 头的 `EFI PART` 和 XFS 超级块的 `XFSB`，记录落点：

```python
# 扫描脚本核心：对每块盘记录特征串的全部落点（字节偏移）
def hits(data, pat):
    out, i = [], data.find(pat)
    while i != -1:
        out.append(i)
        i = data.find(pat, i + 1)
    return out
```

RAID 0 包 8 块盘的扫描结果：

```bash
python3 scan.py dl/raid0
```

输出：

```
1GHGGrmaMM0.img  EFI PART at: []            XFSB at: []
5qiSQnlrA4Y.img  EFI PART at: []            XFSB at: [8511488]
ID7sM2RWkyI.img  EFI PART at: [16776704]    XFSB at: []
RApjvIxRlu0.img  EFI PART at: []            XFSB at: []
d3Be7V0EVKo.img  EFI PART at: []            XFSB at: [8440408]
eRL2MQSdOjo.img  EFI PART at: []            XFSB at: [4321280]
jCC60mutgoE.img  EFI PART at: []            XFSB at: [12701696]
wlOUASom2fI.img  EFI PART at: [512]         XFSB at: [131072]
```

> [!info]- 怎么读这份落点表
> - **`EFI PART` 只有两处**：512 字节处（扇区 1）与 16776704 字节处（扇区 32767 = 16 MiB 的最后一个扇区）。这正是 GPT 主头与备份头的标准位置——主头在阵列 LBA 1，备份头在阵列最后一个 LBA。于是阵列的第一块盘是 `wlOUASom2fI`，最后一块是 `ID7sM2RWkyI`
> - **`XFSB` 有五处，但只有四处可信**：131072、4321280、8511488、12701696 都是 512 的整数倍；8440408 不是。XFS 的所有元数据块都扇区对齐，非对齐命中只能是某个文件的内容（XFSB 恰好四个字节，文件数据里撞上不奇怪），筛掉
> - 真正的锚点是四个扇区对齐的 `XFSB`：它们要么是分区起点上的主超级块，要么是 AG 副本——下一节解析

## 解析 GPT 与 XFS 参数

锚点要换算成阵列坐标，需要两份参数：GPT 给出分区起点，XFS 超级块给出 AG 间隔。

```bash
python3 parse_meta.py dl/raid0/wlOUASom2fI.img 131072
```

输出：

```
signature=b'EFI PART'  revision=0x10000
current_lba=1  backup_lba=262143
first_usable_lba=34  last_usable_lba=262110
part0: type=0fc63daf-8483-4772-8e79-3d69d8477de4
       first_lba=2048  last_lba=262110  name='My Disk'
magic=b'XFSB'  blocksize=4096  dblocks=32507
agblocks=8127  agcount=4
logstart(ino)=16390  rootino=128
versionnum=0xb4a5  sectorsize=512
```

GPT 声明阵列共 262144 个 LBA（`backup_lba` 262143 是最后一个）= 128 MiB，与 8 × 16 MiB 一致；唯一的分区从 LBA 2048 开始——文件系统在阵列坐标 1 MiB 处，131072 字节处的 `XFSB` 就是它的主超级块。

> [!info]- 这几个字段决定锚点位置
> - `blocksize=4096`、`sectorsize=512`：XFS 以 4 KiB 块、512 字节扇区工作
> - `agcount=4`、`agblocks=8127`：4 个 AG，每个 8127 块 = 33288192 字节 = 65016 扇区。主超级块在分区起点，三个副本分别在此后 65016、130032、195048 扇区处——加上主超级块，阵列坐标系上共有 4 个已知点
> - `dblocks=32507`：文件系统总块数，与分区大小吻合

## 拟合：解出条带大小与盘序

四个文件系统锚点在阵列坐标系的 LBA 已知（2048 + 65016 × k），在盘内的扇区也已观测到（131072 / 4321280 / 8511488 / 12701696 字节 ÷ 512）。剩下的代数问题：找一个条带大小 S 和一个盘序，使 RAID 0 的映射

$$\text{盘序} = \left\lfloor \frac{a}{S} \right\rfloor \bmod 8, \qquad \text{盘内扇区} = \left\lfloor \frac{a}{8S} \right\rfloor \times S + (a \bmod S) \tag{R.1}$$

把每个锚点的阵列 LBA 恰好映射到观测到的（盘，扇区）。`derive_r0.py` 按 34 到 4096 逐个试 S，并用主备 GPT 头的位置（LBA 1 与 262143）做交叉检验：

```bash
ATTACH_R0=dl/raid0 python3 derive_r0.py
```

输出：

```
[1] GPT 头落点（阵列首尾各一个）:
    ID7sM2RWkyI.img: [32767] 扇区
    wlOUASom2fI.img: [1] 扇区
[2] XFS 超级块落点（只取 512 对齐的）:
    5qiSQnlrA4Y.img: [16624] 扇区
    eRL2MQSdOjo.img: [8440] 扇区
    jCC60mutgoE.img: [24808] 扇区
    wlOUASom2fI.img: [256] 扇区
[3] 满足全部锚点的条带大小: 256 扇区（128 KiB）
[4] 盘序表（有锚点的 5 个位置）:
    slot0: wlOUASom2fI.img
    slot1: jCC60mutgoE.img
    slot2: ?                候选 ['1GHGGrmaMM0.img', 'RApjvIxRlu0.img', 'd3Be7V0EVKo.img']（无锚点，由挂载验证定序）
    slot3: 5qiSQnlrA4Y.img
    slot4: ?                候选 ['1GHGGrmaMM0.img', 'RApjvIxRlu0.img', 'd3Be7V0EVKo.img']（无锚点，由挂载验证定序）
    slot5: eRL2MQSdOjo.img
    slot6: ?                候选 ['1GHGGrmaMM0.img', 'RApjvIxRlu0.img', 'd3Be7V0EVKo.img']（无锚点，由挂载验证定序）
    slot7: ID7sM2RWkyI.img
```

条带大小唯一解出：256 扇区 = 128 KiB。8 个盘序位置里 5 个被锚点直接钉死，剩下 3 个位置与 3 块盘一一对应，只有 3! = 6 种组合——交给下一步的挂载验证。

> [!info]- 为什么是"唯一解"
> 四个 AG 锚点的盘内扇区各不相同（256、8440、16624、24808），条带大小稍有偏差，式 (R.1) 算出的落点就会错位到别的扇区。34 到 4096 逐个试过去，只有 256 能同时满足四个锚点加两个 GPT 位置。锚点越多，解越收敛——这也是为什么值得把 AG 副本全部找齐，而不是拿一个锚点碰运气。

---
[[02-组装RAID0与校验取flag|下一篇：组装 RAID 0 与校验取 flag →]]
