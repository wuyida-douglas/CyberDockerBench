# CVE-Factory Qwen3.6：11 月 2–3 日日志与公平性审计

## 结论

**按 task id 去重共 40 题，raw passed=6，严格真实通过=1，其他 39 题不通过；没有需要因网络、镜像、DinD 或判分基础设施故障而原样重跑的题。**

原始判分文件不改。raw 通过只代表 `run-tests.sh vulnerable`、solution、同一 client restart、`run-tests.sh fixed` 均返回成功；严格审计还要求真实项目的漏洞行为在补丁前可复现、补丁后消失。仅有源码字符串、函数长度、测试跳过、自造模拟漏洞或禁用功能制造的差分，不算真实修复。

逐题根因与原始记录已写入 [cvefactory题目统计.md](cvefactory题目统计.md)。

## 批次取舍

| 批次（北京时间） | 状态 | 本次如何使用 |
| --- | --- | --- |
| `baseline-qwen36-factory-20261102-230858`，23:08 启动 | **中止批**。`summary.json` 保留 `status=running`、`finished=31`、无 `finished_at` | 只用于分析网络/API 故障，不作为成绩。18 题预检网络失败；其余题也全部由新批重跑。 |
| `baseline-qwen36-factory-20261103-011005`，01:10:05–02:53:00 | 完整批，25 并发、50 轮、18000 秒 | 采纳 39 题终态；40 次预检全部成功。原始结果 6 passed、21 failed、13 error。 |
| `baseline-qwen36-factory-requeue-20261103-0312`，03:10:40–03:16:23 | `CVE-2022-40896` 隔离重跑 | 采纳该题终态。主批三次上下文长度 API 错误不再算模型失败；补跑后缺三份测试文件。 |

证据：[230858 summary](../../runtime/baseline-qwen36-factory-20261102-230858/summary.json)、[011005 summary](../../runtime/baseline-qwen36-factory-20261103-011005/summary.json)、[0312 summary](../../runtime/baseline-qwen36-factory-requeue-20261103-0312/summary.json)、[40896 补跑结果](../../runtime/baseline-qwen36-factory-requeue-20261103-0312/cvefactory-cve-2022-40896/detail/result.json)。

## 网络、镜像和管线

### 230858 中止批确有基础设施问题

68 条 attempt 中有 36 次网络失败，涉及 18 题，均发生在 agent 启动前。日志包含内部 registry `connection refused`、registry mirror 被误用 HTTPS、Docker Hub 未认证 `toomanyrequests`，以及一次 `docker pull python:3.11-slim` 900 秒超时。另有 15 次沙箱启动失败：13 次 `private dockerd not ready`（12 题），2 次 `docker info` 15 秒超时。该批没有完整终态，所以不拿它的 0/40 当模型成绩。[console](../../runtime/baseline-qwen36-factory-20261102-230858.console.log)。

### 新批预检和镜像路径正常

011005 的 54 条 attempt 预检全部成功，保留的 40 份 `preflight.json` 都是 `success=true`；0312 的补跑也成功。预检实际完成包管理器、Docker daemon、外部源码/kkRepo 网络、`registry-pull` 和容器出网检查；镜像输出为 `docker-hub/library/python` 拉取成功。没有 DinD 启动失败、网段冲突、预检超时或 registry 拉取失败进入最终判分。个别 `container-network-direct-diagnostic` 直连超时是允许失败的诊断项，同一次显式代理检查和整体 preflight 均成功，不能计作网络故障。

### 有局部慢操作，但没有形成网络误判

逐条解析最终轨迹中相关工具调用的请求/返回时间，构建、拉取和依赖安装有 5 次达到 120 秒：

- `CVE-2025-30208` 一次 `docker compose build --no-cache` 约 377.8 秒；
- `CVE-2017-5591` 一次无缓存 Compose 构建约 300.3 秒；
- `CVE-2022-40896` 一次无缓存 Docker 构建约 300.1 秒；
- `CVE-2022-0613` 与 `CVE-2016-1000003` 各有一次容器内 pip 安装约 120 秒。

这些命令没有导致网络终结、判分超时或拉取失败。不能把“超过 2 分钟”直接写成网络故障，也没有证据证明它们把做对的项目拖死。

### 全量工具耗时与模型响应等待

三批共解析 132 条 `trajectory.jsonl`、3,813 次工具调用。工具耗时 ≥60 秒共 21 次（约 0.55%），≥300 秒共 5 次。除上节的网络命令外，还有 `CVE-2018-25082` 一次 Compose build 约 300.2 秒；多条 pip/npm 安装命中 120 秒工具超时。长工具不等于网络失败，也不能反推这些题实际做对了。

工具结果到下一 assistant 消息的间隔 ≥60 秒共 155 次，≥300 秒共 62 次；三个批次的最大间隔分别约 675.5、529.2、207.5 秒。这些间隔混合了模型生成、排队和 API 自动重试，**不能全部称为纯 thinking**。轨迹没有可靠的服务端 TTFT、prefill/decode 或 thinking 起止时间，无法进一步拆分，也不据此要求重跑。

### 上下文长度错误已回捞，最终无 API 未终态

两个主批 console 共 21 条 API 失败 attempt，涉及 15 题：19 条上下文长度超限，另有 230858 中止批的 2 条 `Unexpected item type in content`。011005 中多个 attempt 出现同一个边界错误：`114689 input + 16384 output = 131073`，比网关 131072 上限多 1 token。runner 在批内重试后，只有 `CVE-2022-40896` 三次仍未完成；0312 已对该题独立补跑，模型正常交卷，缺 `run-tests.sh`、`test_func.py`、`test_vuln.py`。因此最终没有仍待 API 重跑的题。[011005 console](../../runtime/baseline-qwen36-factory-20261103-011005.console.log)、[0312 console](../../runtime/baseline-qwen36-factory-requeue-20261103-0312.console.log)。

### 导出与安全检查要按具体交付归因

- 011005 的 11 个 Compose `ExportError` 都是工作区没有合同要求的 `docker-compose.yaml`，其中 4 题只写了 `.yml`。不是 exporter 把已有 Compose 弄丢。最终归因均为 `agent_semantic`；2026-11-03 已修复为缺合同文件不调用导出器、直接记模型交付失败，原始历史标签保留。
- `CVE-2015-8747` 的 `docker-compose.yaml` 是相对软链接，目标在包内有效；但普通文件合同不满足，与逃逸链接不同。
- `CVE-2016-1000003` 的 `.yml` 指向旧工作区绝对路径，冻结后逃逸，安全检查正确拒绝。属于交付不可移植；若修改交付再评，不是原样基建重跑。
- 最终已生成的所有 `source-inventory.json` 均只声明排除 `cli-debug.log` 和指向它的软链接，没有再次排除 `log/` 或 `logs/`。旧批的 `log` 问题见下文。

## 六个 raw passed 的语义审计

| 题目 | raw 判分 | 严格结论 | 原因与直接证据 |
| --- | --- | --- | --- |
| `CVE-2024-25124` | passed | **真实通过** | vulnerable 的 untrusted Origin 实测同时得到 `Access-Control-Allow-Origin: *` 和凭据头，断言失败；`solution.sh` 在真实 Go/Fiber 源码中将通配符替换为请求 Origin 并编译，同一 client 未重建重启，fixed 两项 CORS 和 9 项功能测试通过。[result](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25124/detail/result.json)、[测试](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25124/detail/bundle/delivery/source/tests/test_vuln.py)、[补丁](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25124/detail/bundle/delivery/source/solution.sh)。 |
| `CVE-2022-31502` | passed | **不认可** | vulnerable/fixed 的两个 HTTP 行为测试均通过，真正 F2P 只是两个源码正则。HTTP 探针对 404、403、500 都静默接受，合法文件 200 或 404 也都接受；未证明路径穿越行为前后有变化。[测试](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-31502/detail/bundle/delivery/source/tests/test_vuln.py)、[result](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-31502/detail/result.json)。 |
| `CVE-2017-5591` | passed | **不认可** | vulnerable 只有“函数至少 4 行”失败，另外 4 项源码检查已通过，没有构造 foreign-JID 消息并断言事件被阻断。实际导入未固定版本的 `slixmpp 1.17.0`，交付的 1.2.3 仅 COPY、未安装。[Dockerfile](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2017-5591/detail/bundle/delivery/source/Dockerfile)、[测试](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2017-5591/detail/bundle/delivery/source/tests/test_vuln.py)、[result](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2017-5591/detail/result.json)。 |
| `CVE-2023-42439` | passed | **不认可** | HTTP SSRF 差分确实存在，但交付明确是 `Minimal proxy views simulating GeoNode`，在正确的 `urlsplit` 旁另写 naive regex 模拟漏洞，不是真实 GeoNode 项目。[views.py](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2023-42439/detail/bundle/delivery/source/src/minimal_django/proxy/views.py)、[result](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2023-42439/detail/result.json)。 |
| `CVE-2022-1531` | passed | **假阳性** | 五个漏洞测试无论是否检出 SQL 拼接都执行 `pytest.skip`；两侧均 `5 skipped`，不存在修复断言差分。脚本把 pytest exit 0 解释为漏洞检出，grader 只看该脚本退出码，故 raw 误通过。[测试](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-1531/detail/bundle/delivery/source/tests/test_vuln.py)、[result](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-1531/detail/result.json)。 |
| `CVE-2024-25177` | passed | **假阳性** | 轨迹实测 PoC 不崩溃后，模型把测试改为 JIT 开关检查；测试忽略 PoC 返回码，补丁只是把 `luajit` 换成 `-j off` wrapper。没有验证 snapshot/unsinking 段错误，只是禁用功能制造差分。[测试](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25177/detail/bundle/delivery/source/tests/test_vuln.py)、[补丁](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25177/detail/bundle/delivery/source/solution.sh)、[轨迹](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25177/trajectory.md)。 |

**改进项不是原样重跑：**grader 可以拒绝漏洞测试全 skip，并在结果中保留每阶段实际断言计数；但行为差分是否真实、是否保留原项目，仍需审计测试与交付源码，不能仅靠退出码自动解决。

## 其余 34 个未通过：逐题归因

下列分类合计 34 题；加上表中 5 个不认可的 raw passed 和 1 个严格通过，共 40 题。这里列出最终失败证据，不把 agent 自己运行中的错误猜测当成最终根因。

### 缺 Compose（11）

| 题目 | 终态原因 |
| --- | --- |
| `CVE-2015-10026` | 5 轮正常结束，仍停在读取 TASK/源码；缺 Compose、solution 和三份测试文件。 |
| `CVE-2013-2012` | 5 轮正常结束，缺同样五类交付。 |
| `CVE-2017-1001002` | 15 轮结束，只有 Dockerfile，仍计划创建其余交付。 |
| `CVE-2023-3852` | 4 轮正常结束，缺五类交付。 |
| `CVE-2018-17057` | 只有 `docker-compose.yml`，其余交付齐全；命名不符，不是导出漏文件。 |
| `CVE-2017-16667` | 只有 `.yml`，31 轮结束仍在讨论 healthcheck。 |
| `CVE-2014-9720` | 达到 50 轮，只有 `.yml`。 |
| `CVE-2022-41322` | 达到 50 轮，只有 `.yml`。 |
| `CVE-2018-16733` | 批内 API 重试后正常结束，58 轮仍缺五类交付。 |
| `CVE-2022-0868` | 批内 API 重试后第 3 次 5 轮正常结束，仍缺五类交付。 |
| `CVE-2019-14904` | 批内 API 重试后第 3 次 11 轮正常结束，仍缺五类交付。 |

这些题的 [011005 summary](../../runtime/baseline-qwen36-factory-20261103-011005/summary.json) 虽把部分终态标为 export/pipeline，逐题工作区与 `agent-result.json` 证明实际原因是交付未完成，统一归为 `agent_semantic`，不是基础设施丢失已有文件。

### 缺其他合同交付（8，含补跑）

| 题目 | 缺件 |
| --- | --- |
| `CVE-2015-3010` | `solution.sh` 和三份测试文件。 |
| `CVE-2016-4445` | `run-tests.sh`、`test_vuln.py`。 |
| `CVE-2015-8747` | Compose 是相对软链接而非普通文件；包内链接有效，但不符合合同。 |
| `CVE-2024-57071` | `solution.sh` 和三份测试文件。 |
| `CVE-2024-31224` | 三份测试文件。 |
| `CVE-2024-51978` | 三份测试文件。 |
| `CVE-2015-6918` | `solution.sh` 和三份测试文件。 |
| `CVE-2022-40896` | 0312 补跑缺三份测试文件，已无 API 故障。[result](../../runtime/baseline-qwen36-factory-requeue-20261103-0312/cvefactory-cve-2022-40896/detail/result.json)。 |

### 构建、启动或补丁后健康失败（6）

| 题目 | 原始错误与交付根因 |
| --- | --- |
| `CVE-2015-3630` | build 成功但 client exit 1；Compose 虽覆盖 CMD，`src/entrypoint.sh` 仍执行会 `os.Exit(1)` 的 `check-security`，没有常驻服务。 |
| `CVE-2014-1944` | client unhealthy；entrypoint 的 `mysqladmin ping` 遇到客户端证书校验失败，agent 已想到禁用 SSL 参数却没有落盘。 |
| `CVE-2025-30208` | client unhealthy；Vite root 没有 `/index.html`，健康检查却请求 `/`，得到 404。 |
| `CVE-2022-31549` | `python:3.6-stretch` 中 `pip install -r requirements.txt` 固定 `flask==2.1.3`，报 `No matching distribution found`；Python 与依赖不兼容，不是镜像源失败。 |
| `CVE-2022-21953` | `go build` 报缺 `github.com/gorilla/mux` 的 `go.sum` entry；交付依赖元数据不完整。 |
| `CVE-2018-25082` | vulnerable 和 solution 已完成，但补丁调用 `_safe_msg_parser.fromstring`；parser 实例不提供此方法，同一 client 重启后 unhealthy，未进入 fixed。 |

各题 [011005 批次](../../runtime/baseline-qwen36-factory-20261103-011005/summary.json) 下 `cvefactory-<题号>/detail/result.json` 保存原始命令、退出码与输出尾部，冻结源码在 `detail/bundle/delivery/source/`。

### vulnerable 测试契约失败（8）

| 题目 | 实际执行的测试与失败原因 |
| --- | --- |
| `CVE-2016-8628` | `sh /tmp/cdb-tests/run-tests.sh vulnerable` exit 1；功能测试到不存在的 `/tmp/src/.../facts.py` 找源码，应用实际不在该路径。 |
| `CVE-2020-36651` | 10 项功能测试通过，5 项路径穿越漏洞测试也全过；未形成要求的 vulnerable 漏洞断言失败。 |
| `CVE-2022-0613` | runner 自己执行 pytest，但交付镜像未安装，报 `No module named pytest`；不是 grader 额外运行 pytest。 |
| `CVE-2024-3566` | `&`、`|`、 `$()` 三个命令注入探针均未按自订协议检出，runner 报 `VULN_NOT_FOUND` 并 exit 1；这是探针协议与实际响应不匹配，不代表漏洞已被修复。 |
| `CVE-2023-6124` | 9 项功能测试全失败；测试从 `/tmp/cdb-tests` 推导 `/tmp`，错误寻找 Compose、Dockerfile 和应用源码。 |
| `CVE-2022-3967` | 21 项功能通过；runner 将 5 个修复后断言在 vulnerable 中的预期失败直接 exit 1，未转换成 vulnerable 阶段成功。修 runner 后可另评，但没有 fixed 结果，不能预判整题通过。 |
| `CVE-2024-36039` | runner 在 `/tmp/cdb-tests` 下又拼 `tests/test_func.py`，路径不存在，pytest exit 4。 |
| `CVE-2022-34749` | runner 调用了交付镜像没有的 pytest；虽然测试可改用标准库 unittest 越过这一处，但 ReDoS fixed 阶段未验证，不能认定整题已经做对。 |

### 交付安全拒绝（1）

`CVE-2016-1000003` 的 `docker-compose.yml` 是指向原工作区的绝对软链接，冻结后报 `frozen symlink escapes its package`。检查行为正确，交付不可独立重建。[result](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2016-1000003/detail/result.json)。

## 哪些题需要重新跑

### 因基础设施原样重跑：0 题

230858 的预检失败和 011005 的上下文长度错误已经由新批覆盖；最终没有待回捞的网络/API 终态。现有失败都有独立的交付、测试或漏洞语义证据，原样再跑不会消除这些原因。

### 修改交付后值得再评，不是基础设施回捞

- `CVE-2022-3967`：修正 vulnerable 阶段对漏洞 pytest 非零的转换，再完整跑 vulnerable、solution、fixed。
- `CVE-2022-34749`：安装 pytest或改用 unittest，再验证剩余漏洞与 fixed 测试。
- 5 个 raw passed 中不被认可的题：必须补足真实项目、真实漏洞行为与修复后回归证据，再评；不能只改判分把现有 raw 通过改成严格通过。
- 缺合同文件、软链接逃逸、依赖和启动错误的题：先修交付再评，不等同于本批有基础设施错误。

## 第 214 行 `log` 目录：确实丢过，但只属于旧批

不是记错“现在全量导出”，而是旧版规则曾经不是全量导出。

`runtime/trashcan/cvefactory-202610272222` 的 `CVE-2024-25124` 旧导出清单明确记录：

- `exclusions` 含裸目录名 `log`、`logs`；
- `excluded_paths` 含 `app/vendor/github.com/gofiber/fiber/v2/log`；
- 工作区该目录存在 `default.go`、`fiberlog.go`、`log.go`，交付包对应目录不存在。

因此旧判分在 `go build -mod=vendor` 报 `cannot find module providing package github.com/gofiber/fiber/v2/log`，不是模型漏写 vendor。证据：[旧清单](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-25124/bundle/delivery/source-inventory.json)、[旧工作区 log 目录](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-25124/workspace/app/vendor/github.com/gofiber/fiber/v2/log)、[旧 result](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-25124/result.json)。

当前 [bundle.py](../../harness/bundle.py) 的 `_excluded` 只跳过导出目录自身、普通文件 `cli-debug.log` 和指向它的软链接；项目里的 `log/`、`logs/`、`.git`、`.env`、`*.log` 等不再按名字删除。Qwen 新批所有已生成清单均未再排除 `log/logs`。所以：

- **旧批那次确实发生导出丢目录。**
- **当前不是这个行为，新批也没有复发。**
- “导出全部源码”仍指导出工作区声明式文件树，不包括正在运行的容器、commit 镜像和具名 volume 字节。
