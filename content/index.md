---
title: 首页
publish: true
tags:
  - 索引
---

# 🏠 Cyber Notes

这是站点首页的演示内容，可以直接改写本页（`index.md`）。只有带 `publish: true` 属性的笔记才会出现在这个网站上。

> [!tip] 发布流程
> 在 Obsidian 里给笔记加上 `publish: true` 属性 → 在 `.publish/site` 下运行 `npm run publish` → 一分钟后网站自动更新。

## 功能验证

代码高亮（Shiki）：

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *buf = malloc(0x40);
    gets(buf);            // stack overflow demo
    return 0;
}
```

数学公式（MathJax 引擎）：欧拉恒等式 $e^{i\pi} + 1 = 0$，以及

$$
\sum_{n=1}^{\infty} \frac{1}{n^2} = \frac{\pi^2}{6}
$$

双链测试：去 [[示例笔记]] 看图表和任务列表。

## 目录

- [[示例笔记]]
