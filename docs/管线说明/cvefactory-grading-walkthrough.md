# CVE-Factory 判分：按时间走一遍

本文只解释判分。Agent 怎么写代码、网络代理怎么配，见同目录 `cvefactory-pipeline.md`。
下面用一道虚构但结构真实的题 **autojump / CVE-2013-2012** 做例子。它不是某次已经通过的成绩，只用来看文件在每一步去了哪里。

判分器代码在 `harness/families/cvefactory/grader.py`。导出在 `harness/bundle.py`。

## 一句话

Agent 停手之后，控制器冻结声明式工程。判分器拿它在一台全新 Docker 里重新构建，证明“别人只有这些文件也能搭出漏洞环境，并且 `solution.sh` 能在容器里把漏洞补上”。这一差分通过就是 `reward=1`。正在运行的容器不参与判分。

## 失败有哪几种

判分结果在 `<结果目录>/<题号>/result.json` 的 `failure_class`。
`status=failed` 只有 `agent_semantic` 一种；其余都是 `status=error`，不计入模型答错。


| failure_class    | 含义                                                                                                               | 这道题算模型没做成吗 |
| ---------------- | ---------------------------------------------------------------------------------------------------------------- | ---------- |
| `agent_semantic` | 环境能建起来，测试也真的跑了，但交付不满足契约：功能/漏洞测试不对、`solution.sh` 退出非 0、把 client 容器换掉了、健康检查按模型自己写的命令失败、或者把工程目录挂到了 `/tmp/cdb-tests` | 算          |
| `network`        | 拉镜像、解析域名、代理或仓库连接失败                                                                                               | 不算         |
| `pipeline`       | 我们的运行器或冻结包坏了：考场起不来、交付目录打不开、冻结包里有悬空符号链接、判分容器没清干净                                                                  | 不算         |
| `grader`         | 判分程序自己抛了未分类的异常，或判分进程没写出完整结果                                                                                      | 不算         |


`task_input` 是另一类题目（webexploit）在题目包本身不合法时用的标签。这 40 道 CVE 题的判分器不会写这个值。

`agent_semantic` 只说明判分器看到交付没满足契约。它不能单独证明模型当时做错。冻结时丢掉 Compose 要挂的文件，也会让健康检查失败，并被记成这一种。下一节有已经发生过的例子。

冻结工程本身失败时，不会进入判分，因此没有上面这张表里的结论。这次失败写在 `agent-result.json` 的 `failure_category=export`，批次摘要会沿用这个值。常见原因是 Compose 引用了工程目录以外的路径。它不是一种判分类别。

`agent-result.json` 里的 `failure_category` 是做题阶段的分类。`grading.status=not_run` 表示还没判分。做题超时、交不出规定文件，在那里先记成 `agent_semantic`；考场或启动器故障记成 `pipeline`。

## 例子里有哪些角色

```text
sandbox 宿主          每题一个外层容器，里面有私有 dockerd。Agent 在这里写文件、执行 docker。
client 容器           Compose 里的主应用。autojump 装在 /opt/autojump，当前是有漏洞的版本。
判分器                Agent 结束后另起的程序。它不进 Agent 的容器，也不用 Agent 的镜像缓存。
```

正式判分只使用 client 里的 `/tmp/cdb-tests`。grader 删除这个目录后，把冻结的 `tests/` 复制进去再运行。不要把工程的 `tests/` 挂到这个路径。

## T0. Agent 宣布做完，但还没判分

Agent 必须把环境留在**未修补**的状态。它自己可以先把 `solution.sh` 跑一遍做实验，但交卷前要改回去。

此时 workspace 大致是：

```text
results/<task_id>/workspace/
├── docker-compose.yaml          # 根目录；主服务名 client
├── Dockerfile                   # 也可以在 app/Dockerfile，只要 Compose 声明了
├── solution.sh                  # 给判分器在 client 里面执行的补丁
├── app/
│   └── autojump-src/            # 漏洞版本源码
├── tests/
│   ├── test_func.py             # 正常功能。漏洞态和修复态都要过
│   ├── test_vuln.py             # 漏洞断言。漏洞态必须失败，修复态必须通过
│   └── run-tests.sh             # sh run-tests.sh vulnerable|fixed
└── .env / 构建缓存              # 这些是工程目录里的普通文件，导出时按规则排除
                                 # 数据卷不在这棵树里，见下文
```

同时，sandbox 里已经有一套正在跑的容器，例如：

```text
compose project: cdb-cvefactory-cve-2013-2012-...
└── client    image=autojump-client:v21.5.5    状态 healthy
              里面的 /opt/autojump 仍是漏洞脚本
```

这一步还没有 reward。`agent-result.json` 里的 `grading.status` 会是 `not_run`。

## T1. 控制器冻结 delivery，Agent 不再改文件

控制器把上面的现场收成 `bundle/delivery/`。Agent 自己不提交。

```text
results/<task_id>/bundle/delivery/
├── bundle.json
├── source-inventory.json
└── source/                      # workspace 的声明式副本
    ├── docker-compose.yaml
    ├── Dockerfile
    ├── solution.sh
    ├── app/
    └── tests/
```

`source/` 问的是：只拿这些文件，换一台机器还能构建出漏洞环境吗？补丁脚本还能在容器里生效吗？里面没有 Agent 当时的容器、镜像缓存和卷。

## 冻结和重新构建会不会把文件弄丢

会。这个风险是真的，而且已经发生过一次。判分器也不会发现“文件是我们弄丢的”。source 轨构建失败或健康检查失败时，输出里没有代理、仓库、磁盘这些特征，就默认记成 `agent_semantic`。

2026-10-27 的 autojump 试点：模型当时看到 `healthy`。冻结规则把名叫 `runtime` 的目录整棵丢掉。判分时 Compose 把缺失的 `./runtime/profile.d` 建成空目录，盖住镜像里的脚本，`type j` 失败。`result.json` 写的是 `failure_class=agent_semantic`、`failure_stage=source_up`。这是排除规则造成的误判。这个目录名现在会保留。已经导出的那份旧包里仍然没有它，再判一次仍会同样失败。

下面这些仍会被丢掉的名字，如果工程真的用到，还会以同样方式被记成模型失败。分三层看：声明式文件、容器里改过的文件、数据卷。

### 声明式文件：source 轨重新 build 只用这些

`delivery/source/` 是 workspace 的一份拷贝，不是容器里的现场。随后 `docker compose build --no-cache` 只看这份拷贝。Agent 的镜像缓存、容器可写层、数据卷都不参与这次构建。

会拷走的：Dockerfile、Compose、源码、`solution.sh`、`tests/`、打进镜像所需的依赖目录。`node_modules` 和 `.venv` 会保留，因为它们可能就是构建或测试要用的依赖。

当前只排除导出目录自身、普通文件 `cli-debug.log` 和指向它的软链接。
`.git`、`.env`、`log/`、`logs/`、`*.log`、`__pycache__` 等项目文件都保留；
不会再按目录名或扩展名删除源码。历史过滤规则曾误删 Fiber 的 vendor/log，
当前 `bundle.py` 已有对应回归测试。这里仍不包含容器、镜像和具名卷字节。


历史过滤表曾误删项目源码，现已删除。当前规则见上文和 `harness/bundle.py`。

另外两处也会让“当时能跑、重新构建不能跑”，但不是这张表在删文件：

1. Agent 只在正在跑的 client 里面改了文件，没有写回 Dockerfile 或工程目录。重新构建只执行 Dockerfile。
2. 数据卷。它不是上面那棵目录树里的文件，见下一小节。

指向工程目录以外的 bind、声明成 `external: true` 的卷，冻结直接失败，记在 `agent-result.json` 的 `failure_category=export`，不会进入判分。用了 `tmpfs` 时，snapshot 冷启动拒绝这份现场，判分记成 `export`。这三种是大声失败。

### 数据卷不是 workspace 里的文件

上面那棵 `docker-compose.yaml`、`Dockerfile`、`app/`、`tests/` 是普通文件。数据卷是 Docker 另外拿的一块盘，不出现在这棵树里。

Compose 里如果写：

```yaml
volumes:
  - dbdata:/var/lib/mysql
```

`dbdata` 不是 `workspace/dbdata/`。Agent 往数据库里插入的行，存在这块盘上。重新构建时 Docker 新建一块空盘。镜像或入口脚本如果会自己建表、灌入初始数据，空盘没有影响。漏洞测试如果依赖 Agent 当时插进去的那些行，重新构建后就没有这些行。

bind 才是把树里的目录挂进容器，例如 `./app:/opt/app`。那份内容来自 `delivery/source/`。

一条 Compose 里可以有多个服务。数据库、缓存都会按声明重新构建并启动，不会只启动 `client`。

### 需要编译时，编译器留在哪里

分两次编译，发生的地方不同。

1. **做出漏洞环境。** source 轨会无缓存执行 Dockerfile。编译漏洞版本的编译器、头文件和源码必须写在 Dockerfile 和构建上下文里。判分器不会替它安装编译器。
2. **打补丁。** `solution.sh` 在已经构建好的 `client` 里面以 root 执行。判分器不会在这之后再 build 一次镜像，重启也不会。补丁如果要重新编译，编译器必须已经在 `client` 镜像里；要编译的源码可以是镜像里的，也可以是刚拷进 `/tmp/cdb-solution` 的工程文件。编译结果要写进这个容器里下次启动还会用到的路径。

装在考场宿主上的 `pip install`、`apt install`、`gcc`、`make`、`cargo` 也是这样。它们装在外层沙箱里，不在 client 里，也不会进入 `delivery/source/`。判分换一台全新沙箱，这些包不在。要在验收时可用，安装得写进 client 的 Dockerfile，或者把装好的文件放进工程目录（项目下的 `.venv` 会保留）。

## T2. source 轨：扔掉 Agent 的 Docker，重新构建

判分器启动**另一台**全新的 DinD。不用 Agent 的容器、镜像缓存和卷。

`delivery/source/` 先被整份复制到新沙箱的 `workspace/source/`。这份目录里的文件不会全部自动出现在 client 里面。进 client 只有三条路：

1. **Dockerfile 的 `COPY` / `ADD`。** 构建时从 `workspace/source/` 读文件，写进镜像。构建结束后，这些文件在镜像里。
2. **Compose 的 bind。** `./app:/opt/app` 这种相对路径相对于 `workspace/source/`。容器看到的是这份拷贝。
3. **数据卷。** 新建空盘，不从 `delivery/source/` 拷内容。

没被 `COPY`、也没被 bind 的文件，留在新沙箱的磁盘上，不在 client 里。跑 `solution.sh` 之前，判分器会把整份工程再 `docker cp` 到 client 的 `/tmp/cdb-solution`。那是补丁脚本读工程文件的地方，不是应用平时运行的路径。

然后执行：

```text
docker compose build --no-cache
docker compose up -d --wait
```

构建完成后，新 sandbox 里出现一个新的 client。里面仍是漏洞版本，因为 `solution.sh` 还没运行。

```text
source 轨的新 sandbox
└── client（新容器，新镜像）
    └── /opt/autojump/.../autojump.sh     # 仍含相对路径 custom_install/
```

`docker-compose.yaml` 写得对，只说明声明能被解析。这一步的真实 `build` 才算“可重建”。

## T3. 漏洞态测试：功能要过，漏洞测试要真的失败

判分器把冻结的 `tests/` 复制到 tester 的 `/tmp/cdb-tests`。默认 tester 就是 client。然后执行：

```text
sh /tmp/cdb-tests/run-tests.sh vulnerable
```

它还会单独看两份 pytest，不接受“脚本打印了一句 PASS”。

这一步期望：


| 测试             | 期望     | 例子                                                                                     |
| -------------- | ------ | -------------------------------------------------------------------------------------- |
| `test_func.py` | 全部通过   | `autojump --version`、`j` 能跳转，12 passed                                                 |
| `test_vuln.py` | 断言真实失败 | 在当前目录放 `custom_install/autojump.bash`，source 脚本后证据文件出现了，于是 `assert not exists(...)` 失败 |


`test_vuln` 如果是 0 tests、skip、缺 pytest、或者脚本自己 echo 一段失败文本，都不算。必须是测试真的跑了，并且漏洞断言失败。

通过后，`result.json` 的 `checks.vulnerable.success` 为 true。环境仍是漏洞态。

## T4. 在 client 里面执行 [solution.sh](http://solution.sh)

判分器做的不是在宿主上 `./solution.sh`。它先把整个冻结工程拷进**当前这个 client**：

```text
docker exec <client> sh -c 'rm -rf /tmp/cdb-solution && mkdir -p /tmp/cdb-solution'
docker cp delivery/source/. <client>:/tmp/cdb-solution
docker exec --user root --workdir /tmp/cdb-solution <client> \
    sh /tmp/cdb-solution/solution.sh
```

拷完之后，client 里面是：

```text
client
├── /opt/autojump/etc/profile.d/autojump.sh    # 仍是漏洞脚本，等 solution.sh 去改
└── /tmp/cdb-solution/                         # 刚拷进来的工程，当前目录就是这里
    ├── solution.sh
    ├── fix/fix_autojump_sh.py
    └── app/...
```

所以 `solution.sh` 里的相对路径 `.` 指 `/tmp/cdb-solution`。脚本应当直接改容器里正在用的文件，例如：

```sh
# 概念示例。已经在 client 内，以 root 执行。
python3 /tmp/cdb-solution/fix/fix_autojump_sh.py \
    /opt/autojump/etc/profile.d/autojump.sh
```

它不能假设这里有 `docker`、`sudo`、宿主 workspace，也不能再 `docker exec` 去找 client。脚本退出 0 只说明它自己没报错。漏洞有没有补上，看后面的测试。

如果脚本把 client 容器删掉或换成另一个容器，判分失败。补丁必须发生在原来那个 client 里。

## T5. 重启同一个 client，不重新构建

```text
docker restart <同一个 client 容器 id>
```

然后等到 `healthy`，没有 healthcheck 时至少是 `running`。

这一步**不会** `docker compose build` 一个打过补丁的镜像，也**不会**把源码注入 `/app`。重启是为了确认补丁写进了会在下次启动时加载的文件，而不是只改了一个即将消失的内存状态。

`checks.restart.rebuild_performed` 固定是 false。

## T6. 修复态测试：同一套测试再跑一遍

仍是这个 client，测试入口相同，参数改成 `fixed`：

```text
sh /tmp/cdb-tests/run-tests.sh fixed
```


| 测试             | 期望   | 和 T3 的差别                        |
| -------------- | ---- | ------------------------------- |
| `test_func.py` | 仍然通过 | 补丁不能把正常功能改坏。这是 P2P：pass 保持 pass |
| `test_vuln.py` | 改成通过 | 同样的证据文件不再出现。这是 F2P：fail 变成 pass |


两边的 pytest 输出都留在 `result.json` 的 `checks.vulnerable` 和 `checks.fixed`。只写 `reward: 1` 不算证据。

到这里判分结束，这个 sandbox 被关掉。

## T7. 怎样才算这道题通过

```text
无缓存构建并启动
vulnerable：功能过、漏洞测试失败
client 内 root 执行 solution.sh
restart 同一个 client
fixed：功能仍过、漏洞测试转过
        ↓
reward = 1, status = passed
```

任一步没走完，就不是通过。语义失败（测试不符合、补丁没生效、脚本依赖宿主 docker）是 `reward=0, failure_class=agent_semantic`。构建网络、冻结包损坏、判分器自身故障分别是 `network`、`pipeline`、`grader`，都不算模型没做成。冻结工程本身失败时没有这份判分结果。

## 和 Agent 调试的对应关系

Agent 在交卷前可以自己彩排 source 轨的补丁段，但彩排完要恢复漏洞态：

```text
1. 工程拷到 client:/tmp/cdb-solution
2. 在 client 内以 root 执行 sh /tmp/cdb-solution/solution.sh
3. restart client
4. 跑 fixed 测试
5. 把运行环境改回漏洞版本，确认 vulnerable 测试又变回“功能过、漏洞失败”
6. 停在这一步。不要 export，不要 commit 镜像，不要自己打分
```

宿主上直接 `./solution.sh`，再由脚本调用 `docker compose exec`，只证明宿主那条路能走。判分器不会这样调用它。