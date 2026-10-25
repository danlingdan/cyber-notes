---
title: 组装 RAID0 与校验取 flag
tags:
  - 实战案例
  - MISC
  - raid-restore
  - 磁盘取证
created: 2026-10-25
status: 已核验
order: 300
publish: true
---

盘序推定给了 5 个确定位置和 3 个待定位置。这一章把阵列拼起来：`mdadm --build` 做无元数据组装，挂载验证定下最后 3 块盘的位置，然后跑盘内自带的 `getflag.py` 拿第一个 flag。

> [!info]- mdadm --build 与 mount offset 两个关键参数
> - **`--build`**：mdadm 的"无元数据"模式。正常的 `--assemble` 要从盘上读 RAID 超级块才知道布局，而这批盘是出题人手工拆的，没有超级块；`--build` 严格按照命令行给的盘序与条带拼装，一个字节都不写进盘里，适合拼"别人的"阵列
> - **`offset=1048576`**：分区从阵列 LBA 2048（1 MiB）开始，loop/md 设备不会自动分区扫描，挂载时直接给文件系统所在的字节偏移，跳过分区扫描这一步
> - **`norecovery`**：XFS 的只读挂载选项，挂载时不回写日志。取证场景的标准动作，避免挂载行为改动镜像

## 六种排列的挂载验证

`assemble_r0.sh` 把 8 块盘逐个 `losetup` 成 loop 设备，按 [[01-侦察与RAID0盘序推定|01 章]] 的盘序表拼阵列——5 个已定位置原样填入，3 个待定位置跑 3! = 6 种排列，每组排列都尝试挂载：

```bash
sudo ATTACH_R0=dl/raid0 bash assemble_r0.sh
```

输出：

```
盘序确认: slot2=1GHGGrmaMM0 slot4=d3Be7V0EVKo slot6=RApjvIxRlu0
files
getflag.py
Flag: flag{4857cdeac07d8456fcaedb61d07b0b7d}
```

第一组排列就通过了。挂载成功后阵列根目录只有 `files/` 与 `getflag.py` 两项，flag 由脚本自身打印。

> [!info]- 为什么挂载能当盘序的裁判
> XFS 挂载时会读主超级块、逐个校验 4 个 AG 的超级块副本与根目录。盘序错一种排列，中段的条带就整体错位，AG 副本与目录块全都对不上号，挂载直接报"bad superblock"类错误退出。6 种排列只有 1 种能过，这就是裁决。挂载通过之后 `getflag.py` 的总校验和再补一道全量复核。

## getflag.py：校验和裁判

盘内的 `getflag.py` 是这道题的评分器，逻辑一目了然：

```python
for filepath in sorted(paths):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        # 逐块读入、更新哈希
        ...
    hexdigest = h.hexdigest()
    print(filepath, hexdigest)
    ans += hexdigest
check = hashlib.sha256(ans.encode("utf-8")).hexdigest()
if check == "23d2780ec9917371ae1f366c03a983a64a7d694d1e8a14386fe7f32173730cd7":
    print("Flag:", f"flag{{{hashlib.md5(ans.encode('utf-8')).hexdigest()}}}")
else:
    print("Did you recover my data correctly?")
```

按路径排序遍历 `files/` 下全部文件，每个文件算一个 SHA-256，串接后再算总 SHA-256 与预置值比对；通过就打印总串的 MD5 作为 flag。`files/` 里有 Microscope 位图、PDF、代码仓库、视频等几十个文件，任何一个字节错位都会让总校验和变掉——==这个校验和既是评分器，也是"阵列恢复完全正确"的最终证明==：

```
Flag: flag{4857cdeac07d8456fcaedb61d07b0b7d}
```

RAID 0 问到此收工。整个流程里没有爆破、没有猜测，用到的全部信息都来自文件系统自己留下的结构。

> [!info]- 附件里还藏着什么
> 扫描时那个非 512 对齐的 `XFSB` 命中（`d3Be7V0EVKo.img` 偏移 8440408）属于 `files/` 里某个文件的内容——阵列拼对之后挂载文件系统就能定位到具体文件。它不是解题必需的线索，更像出题人埋的干扰项：如果按"哪里有 XFSB 哪里就是超级块"的思路机械搜索，非对齐命中会污染锚点集合。

---
[[03-RAID5布局求解与终审|下一篇：RAID 5 布局求解与终审 →]]
