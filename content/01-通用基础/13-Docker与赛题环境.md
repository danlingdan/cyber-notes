---
chapter: 通用基础
section: Docker 与赛题环境
order: 113
tags:
  - CTF
  - 通用基础
  - Docker
  - 环境
publish: true
---

# 13 Docker 与赛题环境
## Docker for CTF Environments

> [!info]- 章节信息
> **所属方向**：通用基础 ｜ **难度阶段**：L1 入门期 ｜ **前置要求**：[[01-Linux环境与CTF实验环境搭建|01 Linux 环境与 CTF 实验环境搭建]]
> **本章目标**：把「镜像 → 容器」这套动作练熟：一条命令起本地靶机、读懂赛题包里的 docker-compose.yml、给 PWN 题起一个和远程同版本 glibc 的容器。Docker 在这门手艺里的定位是==复现赛题环境的标准答案==，不是运维课。

## 1. 为什么 CTF 需要 Docker

三个场景，一个比一个硬：

**场景一：本地复现 Web/PWN 靶机。** 比赛复盘、vulhub 一类题库练手，人家发的附件就是 Dockerfile 加 docker-compose.yml。不会 Docker，这些题永远停留在"听别人讲过"的状态。

**场景二：给 PWN 题对齐出题环境的 glibc。** [[01-Linux环境与CTF实验环境搭建|01 章]]给过两套方案：题目自带 loader 直接跑、patchelf 改 interpreter 和 rpath。这里补第三种，也是我个人最喜欢的一种——==起一个和远程同版本的容器，把题目整个搬进去==。libc、loader、目录布局全和出题机一致，编译环境顺手就齐，连 patchelf 都省了。

**场景三：AWD gamebox 演练。** AWD 每队一台 gamebox。本地演练用几个容器一拉，攻防两头都有真机可打，比俩人对着空气喊招写实多了。

> [!note] Docker 不是虚拟机
> 容器和宿主机共享同一个 Linux 内核，镜像里装的只是用户态那一层（rootfs、libc、你的程序）。所以启动按秒算、占用按百兆算。代价是==容器里装不进另一个内核==——打内核漏洞那种题，还是回虚拟机上去。

## 2. 三个词：镜像、容器、仓库

| 词 | 是什么 | 一句话记忆 |
| --- | --- | --- |
| 镜像 image | 只读模板，分层存储 | ==类== |
| 容器 container | 镜像跑起来的实例 | ==实例== |
| 仓库 registry | 存镜像、分发镜像的服务，默认 Docker Hub | GitHub，只不过存的不是源码是镜像 |

镜像等于类，容器等于实例。`docker run` 一次就是 new 一个对象，用完就删，删了再 new，零心理负担。

分层存储：镜像不是一整块文件，是一叠只读层。ubuntu 基础层在最底下，往上装 gcc 就再叠几层。==层可以共享、可以缓存==——十个人拉同一个基础镜像，磁盘上基础层只存一份；改一行 Dockerfile 重新 build，没变的层直接复用，这就是第二次 build 快得离谱的原因。容器启动时在顶上盖一层可写层，运行期的所有写入都落在这层，==容器一删，可写层跟着火化==。

tag：`ubuntu:24.04` 里 ubuntu 是镜像名、24.04 是 tag，不打 tag 默认 latest。latest 的真实含义是"打标签的人当时觉得这版最新"，不做任何承诺。==日常使用永远写明版本号==，不然半年后复现环境对不上，别喊冤。

Docker Hub 是默认仓库，`docker pull ubuntu` 不写前缀就去找 `docker.io/library/ubuntu`。国内直连它经常抽风，本章实跑时就被抽中一次（报错原文在第 7 节），所以==配加速是装完 Docker 的第一件事==。

## 3. 八条常用命令

CLI 子命令几十条，CTF 日常翻来覆去就这八条：

| 命令 | 一句话 |
| --- | --- |
| `docker run` | 从镜像创建并启动容器，头号主力 |
| `docker ps` | 列容器，加 `-a` 连退出的也算 |
| `docker exec` | 往运行中的容器里塞一条命令 |
| `docker logs` | 看容器的标准输出，排错第一站 |
| `docker cp` | 宿主 ↔ 容器拷文件 |
| `docker rm` | 删容器，`-f` 强删正在跑的 |
| `docker images` | 列本地镜像 |
| `docker image prune` | 清悬空镜像；`docker system prune` 连停着的容器一起清 |

### 3.1 run 的常用选项

```bash
docker run -d -p 8080:8000 --name web python:3.12-slim python3 -m http.server 8000
```

| 选项 | 干什么 |
| --- | --- |
| `-d` | 后台运行，不然后面的终端就被它吃了 |
| `-p 宿主:容器` | 端口映射，下一节展开 |
| `--name` | 起名，之后 exec / logs / rm 全靠它喊人 |
| `-it` | 分配并接管终端，`docker run -it ubuntu:24.04 bash` 直接落进容器 shell |
| `-v 宿主:容器` | 挂目录，宿主改文件容器里立刻生效 |
| `--rm` | 退出即自毁，一次性任务标配 |

末尾那串 `python3 -m http.server 8000` 是容器启动后执行的命令。==容器 = 镜像 + 一条命令，命令结束容器就退==。这行字是理解一切"容器为什么自己退出"的钥匙，FAQ 里还会回来鞭尸。

### 3.2 其余七条实测

容器就是 3.1 那条命令起的。`docker ps` 实测输出：

```
NAMES      IMAGE              PORTS                                         STATUS
ch13_web   python:3.12-slim   0.0.0.0:8080->8000/tcp, [::]:8080->8000/tcp   Up 2 seconds
```

PORTS 那格把映射写得明明白白：宿主 8080 进来的流量，转发到容器的 8000。

```bash
docker exec ch13_web python3 --version     # Python 3.12.15
docker logs ch13_web
```

```
172.17.0.1 - - [18/Oct/2026 13:02:25] "GET / HTTP/1.1" 200 -
```

172.17.0.1 是宿主在 docker 网桥上的地址，这条 200 的访问日志就是宿主 curl 打进来的（第 4 节干的事）。

```bash
docker cp ./flag.txt web:/tmp/flag.txt     # 宿主 → 容器
docker cp web:/tmp/flag.txt ./flag.txt     # 容器 → 宿主，反向同理
docker rm -f web                           # 删掉，正在跑就加 -f
docker images
```

`docker images` 实测输出（截选）：

```
IMAGE              ID             DISK USAGE   CONTENT SIZE
alpine:3.20        d9e853e87e55       12.2MB         3.71MB
python:3.12-slim   05cda9777409       179MB          45.4MB
mysql:8.4          6ea90827b110       1.12GB          255MB
```

DISK USAGE 和 CONTENT SIZE 差了一个量级，这就是第 2 节分层共享在报表上的样子：基础层被多个镜像共用，真正新增的下载量只有 CONTENT SIZE 那列。

> [!warning] prune 慎用
> `docker image prune` 清悬空镜像没问题，`docker system prune` 会把停着的容器、没被引用的网络一起端了。练手机上镜像乱一点死不了人，把别的项目正在用的容器端掉就尴尬了。想看占用先跑 `docker system df`，心里有数再动手。

## 4. 起一个 CTF 靶机

==一行命令，一个带端口的活靶机==：

```bash
docker run -d -p 8080:8000 --name ch13_web python:3.12-slim python3 -m http.server 8000
```

起完宿主机直接访问 `curl http://localhost:8080/`，实测输出（截选）：

```html
<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Directory listing for /</title>
```

通了。把 `python3 -m http.server 8000` 换成任何一个带洞的 demo 服务（题目附件给什么换什么），它就是一道本地 Web 题。想要 nginx 就 `docker run -d -p 8080:80 --name web nginx:alpine`，一个道理。

### 4.1 -p 到底转发了什么

容器天生隔离：有自己的网络栈、自己的 IP（172.17.x.x 这类），==外部世界摸不到容器里的端口，除非用 -p 打个洞==。`-p 8080:8000` 的意思是宿主机监听 8080，由 Docker 的转发规则把流量递进容器的 8000。`docker ps` 里 `0.0.0.0:8080->8000/tcp` 的箭头就是这个动作的档案。浏览器也好，pwntools 的 `remote('127.0.0.1', 8080)` 也好，打的都是宿主端口，容器内部 IP 是几根本不用关心。

想进容器里亲手看看，exec 带 `-it`：

```bash
docker exec -it ch13_web bash    # 落进容器的 shell，exit 退出
```

> [!note] 容器里的数据会蒸发
> 写进容器的东西全落在可写层，`docker rm` 一下就没了。靶机要持久放 flag、放上传的文件，用 `-v` 把宿主目录挂进去：`-v ./src:/usr/share/nginx/html:ro`，末尾 `:ro` 表示容器内只读。赛题附件几乎都这么干。

## 5. docker-compose 起多容器题

题目一旦带数据库、带多个服务，一条条 run 敲三遍还容易记错。docker-compose 用一个 yml 把"要起哪些容器、什么配置"写成清单，==一条 `docker compose up -d` 全部拉起==。

最小模板（本章实测用例）：

```yaml
services:
  web:
    image: python:3.12-slim
    working_dir: /src
    command: python3 -m http.server 8000
    ports:
      - "8081:8000"
    volumes:
      - ./src:/src:ro
```

同目录放一个 `src/index.html`，然后：

```bash
docker compose up -d
# 实测输出：Container ch13_verify-web-1  Started
curl http://localhost:8081/
# <h1>flag{compose_up_ok}</h1>
docker compose down
# 实测输出：Network ch13_verify_default  Removed
```

up 起来的容器名自动带项目前缀（就是目录名），down 按同样规则连网络一起回收，不留尸体。中途看状态用 `docker compose ps`，看日志用 `docker compose logs -f`，和单容器的 ps / logs 一个用法，只不过作用于整个清单。

### 5.1 怎么读赛题包里的 docker-compose.yml

拿到题目附件先开这个文件，五个字段扫过去：

| 字段 | 看什么 |
| --- | --- |
| `services` | 有几个服务，各自叫什么 |
| `image` / `build` | 用现成镜像还是现场 build（写了 build 就会用到旁边的 Dockerfile） |
| `ports` | 题目暴露在宿主的哪个端口 |
| `volumes` | 挂了什么进去，flag 文件常从这里进容器 |
| `environment` | 环境变量，==flag 也经常直接写在这，先看一眼免得被自己剧透== |

> [!warning] up 之前先看 flag
> 题目包里的 flag 十有八九是 `flag{test_flag}` 这种占位货，也有的比赛包直接带真 flag 明文。本地复现时把它换成自己的，打下来才有对比意义——直接 cat 出来不算解出，这层自觉得有。

## 6. 给 PWN 题对齐环境

[[01-Linux环境与CTF实验环境搭建|01 章]]的 patchelf 和自带 loader 两种方式，解决的是"只差 libc"的场景。第三种最重，也最像：==起一个出题环境同版本的容器，容器就是题目原生环境==。

拿 ubuntu:24.04（glibc 2.39，[[01-Linux环境与CTF实验环境搭建|01 章]]的对照表能对上）走一遍完整流程，全部实测：

```bash
docker run -d --name pwn24 ubuntu:24.04 sleep 900   # sleep 让容器常驻，等人进去布置
docker exec pwn24 ldd --version | head -1
```

```
ldd (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39
```

版本对上，往里装编译环境、塞源码、编译、运行：

```bash
docker exec pwn24 bash -c "apt-get update -qq && apt-get install -y -qq gcc libc6-dev"
# 装完实测：gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
docker cp ./t.c pwn24:/tmp/t.c                    # 宿主的源码塞进去
docker exec pwn24 bash -c "gcc /tmp/t.c -o /tmp/t && /tmp/t"
```

实测输出：

```
compiled inside container
```

这里每一步都发生在容器内的 glibc 2.39 上。拿它编译出的 exploit、算出的偏移、调试时看到的 libc 地址，和远程是同一套坐标系。只是快速查个版本的话，一次性容器更省事：`docker run --rm ubuntu:24.04 ldd --version`，跑完即焚。GDB 要进去也一样：容器里装 gdb 和 gdbserver，`gdbserver :1234 ./t` 起服务，宿主的 GDB `target remote` 连容器映射出来的端口——远程调试的完整玩法 PWN 方向细讲。

### 6.1 三种对齐方案怎么选

| 方案 | 动作 | 适合 | 不爽的地方 |
| --- | --- | --- | --- |
| 题目自带 loader（01 章方式一） | `./ld-linux-x86-64.so.2 --library-path . ./pwn` | 快速跑一把 | gdb attach 别扭，对齐的只有 libc 这一层 |
| patchelf（01 章方式二） | 改 interpreter 和 rpath 指向题目组件 | 本机版本接近时最省事 | ld 和 libc 配错照样段错误，目录、编译器仍是你本机的 |
| 容器对齐（本章） | 起对应版本容器，题目整个搬进去 | ==追求和远程完全一致== | 第一次拉镜像装环境慢，吃磁盘 |

入门期的建议：先用 patchelf 快速验证思路，题目行为诡异（崩得莫名其妙、堆布局对不上）再上容器。两种都得会，PWN 后面全是这两个的组合拳。

> [!warning] 别拿 alpine 当 PWN 容器
> alpine 为了瘦身上的是 musl libc，不是 glibc。实测 alpine:3.20 里 `ldd --version` 输出 `musl libc (x86_64) Version 1.2.5`，动态链接器、堆实现全和 glibc 两套体系。glibc 题的调试环境用 ubuntu / debian 镜像，别问为什么 exploit 在 alpine 里跑不起来，问就是 libc 不是同一族。

## 7. 国内镜像加速与常见坑

### 7.1 registry mirror

Docker Hub 直连抽风是常态，解法是配置里加加速地址。Docker Desktop：Settings → Docker Engine，JSON 里加：

```json
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://docker.1panel.live"
  ]
}
```

Apply & Restart 生效，`docker info` 里能看到 Registry Mirrors 一栏。Linux 原生安装则写 `/etc/docker/daemon.json`，然后 `sudo systemctl restart docker`。加速站时效性强，挂了就换，搜"docker registry mirror 可用"挑最近还活着的。

本章实跑确实撞了一回（裸连、没配 mirror 的状态）：

```
docker: Error response from daemon: failed to resolve reference "docker.io/library/nginx:alpine":
failed to authorize: failed to fetch oauth token: Post "https://auth.docker.io/token": EOF
```

隔几秒重试，同一个镜像就拉下来了。==先重试两次，不行再配 mirror==，这两种毛病的症状长得一模一样。

### 7.2 WSL 里的 Docker 从哪来

两种来源，装之前想清楚：

- **Docker Desktop 的 WSL 集成**（本章环境）：Windows 装 Desktop，WSL 发行版里直接就有 docker 命令，`wsl -d Ubuntu-26.04 -- docker version` 的 Server 一栏写着 Docker Desktop。好处是 Windows 侧和 WSL 侧共用一套镜像和引擎。
- **WSL 内原生安装**：发行版里自己 `apt install` 一套独立的 Docker Engine。想折腾纯 Linux 工作流选这个，代价是和 Windows 侧镜像不互通，用户权限（docker 组）也得自己管。

判断自己属于哪种，跑一眼 `docker version`：Server 段写 Docker Desktop 就是集成模式，写 Engine 就是原生。

### 7.3 Git Bash 的路径改写

我在 Windows 下用 Git Bash 敲 docker cp 时踩过一个坑：容器内路径 `/tmp/flag.txt` 会被 Git Bash 自作主张改写成 `C:/Program Files/Git/tmp/flag.txt`，容器里当然找不到。说白了就是 MSYS 的路径自动转换用力过猛，关掉即可：

```bash
MSYS_NO_PATHCONV=1 docker cp ./flag.txt web:/tmp/flag.txt
```

## 8. 常见问题

| 现象 | 原因与解决 |
| --- | --- |
| pull 卡住 / `failed to fetch oauth token ... EOF` | Docker Hub 直连抽风：先重试两次，仍不行配 registry mirror（第 7 节）；判断网络通不通，先拿 alpine 这种几 MB 的小镜像试 |
| `permission denied ... /var/run/docker.sock` | 当前用户不在 docker 组：`sudo usermod -aG docker $USER` 后重新登录生效（Linux 原生安装场景；Desktop 集成一般没这毛病） |
| 容器秒退，`docker ps` 里找不到 | ==容器 = 镜像 + 命令，命令结束就退==。`docker ps -a` 能看到退出的它，`docker logs` 看它死前说了什么；要常驻就给个不退出的命令：`sleep infinity`、`tail -f /dev/null` |
| `bind: address already in use` | 宿主端口被占：换宿主端口 `-p 8081:80`，或 `docker ps` 找到占着 8080 的旧容器处理掉 |
| `exec: container xxx is not running` | exec 只能进运行中的容器。先 `docker ps -a` 查状态，秒退的往上看一条 |
| `The container name "/web" is already in use` | 同名旧容器还在：`docker rm -f web` 清掉，或换个名字 |
| glibc 题在 alpine 容器里跑不起来 | alpine 用 musl，不是 glibc，换 ubuntu / debian 镜像（第 6 节末） |
| Git Bash 下容器路径变成 `C:/Program Files/Git/...` | MSYS 路径改写，命令前加 `MSYS_NO_PATHCONV=1` |
| WSL 里 `docker: command not found` | Docker Desktop 没集成这个发行版：Settings → Resources → WSL integration 打开对应开关 |
| 删容器后 flag、上传的文件丢了 | 可写层随容器火化。要留的东西用 `-v` 挂载，或者删之前 `docker cp` 抢救出来 |

