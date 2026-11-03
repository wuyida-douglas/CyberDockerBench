# CVE-Factory 题目状态

## 2026-11-03 · Qwen3.6 最终公平审计（40题）

按 task id 去重，主批 39 题，`CVE-2022-40896` 采用隔离补跑终态。**严格 1 passed / 39 未通过，40/40 有终态，无基础设施待终结题。raw pass=6，其中 5 题没有可信的真实漏洞差分，不计严格通过。**完整批次、网络与逐题证据见 [Qwen3.6 日志与公平性审计](cvefactory-qwen36-20261102-03审计.md)。

这里的“严格通过”要求真实项目的漏洞行为在 vulnerable 中可复现、补丁后同一行为消失，且功能和回归测试通过；仅有退出码、源码字符串、函数行数、跳过测试或自造模拟漏洞不够。严格审计不修改任何原始 `result.json`。

- 唯一严格通过：`CVE-2024-25124`。真实 Go/Fiber 服务在 vulnerable 返回危险 CORS 通配符与凭据组合；同一 client 内修改并编译，未重建，fixed 的行为断言和功能测试均通过。
- 39 个未通过按最终交付的实际原因分为：11 题缺 Compose；8 题缺其余合同交付；6 题自写环境构建/启动/补丁后健康失败；8 题 vulnerable 测试契约失败；1 题交付软链接逃逸；5 题 raw 通过但漏洞语义不成立。这里不声称所有题都走到了漏洞修复差分。
- `CVE-2022-31502`：HTTP 测试在 vulnerable 和 fixed 均通过，F2P 仅来自源码正则，未证明路径穿越行为差分；不计严格通过。
- `CVE-2017-5591`：vulnerable 只有“函数至少 4 行”失败，foreign-JID 行为未测试；实际导入的是未固定版本的 `slixmpp 1.17.0`，而非交付的 1.2.3 源码；不计严格通过。
- `CVE-2023-42439`：HTTP 差分存在，但项目是明确标注“simulating GeoNode”的自造最小 Django，另行植入 naive regex 模拟漏洞，不是实际 GeoNode；不计严格通过。
- `CVE-2022-1531`：五个漏洞测试在两个分支均 `pytest.skip`，raw 差分是空漏洞断言，严格排除。[测试](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-1531/detail/bundle/delivery/source/tests/test_vuln.py)。
- `CVE-2024-25177`：`solution.sh` 仅给 LuaJIT 加 `-j off`，自写测试改为检查 JIT 开关，未修复原漏洞，严格排除。[补丁](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25177/detail/bundle/delivery/source/solution.sh)。
- 11 个 Compose export 缺文件均核对工作区和 agent 正常结束/轮次停止记录，不是导出丢交付，最终归因均为 `agent_semantic`；原始 `pipeline/export` 仅是历史管线标签。2026-11-03 已修复为缺合同文件不调用导出器、直接记模型交付失败。`CVE-2016-1000003` 的软链接逃逸是交付安全检查拒绝；`CVE-2022-40896` 隔离重跑仍缺三份测试文件。原始 pipeline/export 标签不等于基础设施无效。

## 2026-11-03 · Qwen3.6 未微调基线 011005

批次 `baseline-qwen36-factory-20261103-011005`，25 并发、50 轮、18000 秒。

### 真实漏洞修复（1）

| 题目 | 判分时间（北京时间） | 根因与证据 |
| --- | --- | --- |
| CVE-2024-25124 | 01:46:23–01:47:49 | 干净构建和启动成功；vulnerable 的 9 项功能测试通过，危险 CORS `Allow-Origin: *` 与凭据并存断言失败；同一 client 内补丁成功、未重建且重启健康，fixed 的 9 项功能和 2 项漏洞测试全过，P2P/F2P 均通过。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25124/detail/result.json)、[漏洞测试](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25124/detail/bundle/delivery/source/tests/test_vuln.py)。 |

### raw 通过，但不是可信的真实漏洞修复（3，另有 2 题见下表）

| 题目 | 判分时间（北京时间） | 语义审计与证据 |
| --- | --- | --- |
| CVE-2022-31502 | 01:27:16–01:28:28 | 流程全过，但 vulnerable/fixed 的 HTTP 行为测试都是 2 项通过；真正 F2P 是两个源码正则断言。HTTP 探针遇到 404、403、500 都静默通过，合法文件 200 或 404 也都接受，未证明路径穿越行为消失。[测试](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-31502/detail/bundle/delivery/source/tests/test_vuln.py)、[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-31502/detail/result.json)。 |
| CVE-2017-5591 | 01:34:02–01:37:18 | 流程全过，但 vulnerable 仅“函数至少 4 行”失败，另外 4 项源码检查已经通过，没有构造 foreign-JID 消息断言事件阻断。Dockerfile 安装未固定版本的 `slixmpp`，判分实际导入 1.17.0；`COPY src/slixmpp-1.2.3/` 并未安装。[Dockerfile](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2017-5591/detail/bundle/delivery/source/Dockerfile)、[测试](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2017-5591/detail/bundle/delivery/source/tests/test_vuln.py)、[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2017-5591/detail/result.json)。 |
| CVE-2023-42439 | 01:48:20–01:49:26 | HTTP SSRF 差分确实存在，但交付是 `Minimal proxy views simulating GeoNode`；在正确的 `urlsplit` 旁另写 naive regex 模拟漏洞。没有保留真实 GeoNode 项目，不能算修复真实 CVE。[views.py](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2023-42439/detail/bundle/delivery/source/src/minimal_django/proxy/views.py)、[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2023-42439/detail/result.json)。 |

### 模型结束但未交付 Compose（6）

| 题目 | 起止（北京时间） | 根因与证据 |
| --- | --- | --- |
| CVE-2015-10026 | 01:10:05–01:11:24；agent 01:11:12–01:11:22 | 预检成功，模型 5 轮正常结束，尚在说读取 TASK 与源码；缺 `docker-compose.yaml`、`solution.sh` 和三份测试文件。后续 Compose 导出缺文件不是基础设施丢交付。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2015-10026/detail/agent-result.json)、[轨迹](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2015-10026/trajectory.md)。 |
| CVE-2013-2012 | 01:10:05–01:11:25；agent 01:11:12–01:11:22 | 预检成功，模型 5 轮正常结束，缺上述全部合同交付，无 API 或网络错误；导出报 `no such file or directory`。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2013-2012/detail/agent-result.json)、[轨迹](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2013-2012/trajectory.md)。 |
| CVE-2017-1001002 | 01:10:05–01:14:06；agent 01:12:22–01:14:03 | 模型 15 轮正常结束，最后正文仍计划创建交付；缺 Compose、solution 和三份测试文件，未进入判分，不按基础设施重跑。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2017-1001002/detail/agent-result.json)、[轨迹](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2017-1001002/trajectory.md)。 |
| CVE-2023-3852 | 01:22:15–01:22:34（agent） | 模型 4 轮正常结束，仍在说读取 TASK、CVE 与源码；缺 Compose、solution 和三份测试文件，不是 API 或基础设施失败。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2023-3852/detail/agent-result.json)。 |
| CVE-2018-17057 | 01:12:10–01:23:07（agent） | 模型 47 轮结束，正文露出未完成的工具调用标记；缺 `docker-compose.yaml`，其余交付已写出。属于模型交付/格式问题，不按基础设施重跑。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2018-17057/detail/agent-result.json)。 |
| CVE-2017-16667 | 01:11:21–01:23:34（agent） | 模型 31 轮结束，仍在讨论 healthcheck 修改；只有 `.yml`，缺合同要求的 `docker-compose.yaml`，不是导出丢文件。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2017-16667/detail/agent-result.json)。 |

### 模型交付缺文件或功能检查失败（23）

| 题目 | 判分时间（北京时间） | 根因与证据 |
| --- | --- | --- |
| CVE-2015-3010 | 01:20:54 | 冻结交付缺 `solution.sh`、`tests/run-tests.sh`、`test_func.py`、`test_vuln.py`，未进入构建。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2015-3010/detail/result.json)。 |
| CVE-2016-4445 | 01:21:12 | 冻结交付缺 `tests/run-tests.sh` 和 `test_vuln.py`，未进入构建。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2016-4445/detail/result.json)。 |
| CVE-2016-8628 | 01:22:22–01:22:51 | 干净构建与启动成功；`sh /tmp/cdb-tests/run-tests.sh vulnerable` 退出 1，9 项功能检查均因模型测试引用了不存在的 `/tmp/src/ansible_lib_vulnerable/ansible/module_utils/facts.py` 失败，未进入补丁阶段。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2016-8628/detail/result.json)。 |
| CVE-2015-3630 | 01:22:42–01:23:40 | 交付构建成功，但 `docker compose up --wait` 中 client 退出 1，未进入 vulnerable 测试；不是镜像拉取或 DinD 故障。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2015-3630/detail/result.json)。 |
| CVE-2020-36651 | 01:24:11–01:24:40 | 干净构建与启动成功；vulnerable 阶段 10 项功能测试全过，但 5 项路径穿越漏洞测试也全过，未形成漏洞断言失败，`run-tests.sh vulnerable` 退出 1。属于模型未复现漏洞，不是判分或网络错误。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2020-36651/detail/result.json)。 |
| CVE-2014-1944 | 01:25:40–01:28:08 | 交付及数据库构建成功，数据库健康；模型 client 在 Compose `--wait` 期间变为 unhealthy，未进入 vulnerable 测试。无镜像拉取或沙箱错误，不按基础设施重跑。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2014-1944/detail/result.json)。 |
| CVE-2015-8747 | 01:28:31 | 冻结交付有 `docker-compose.yaml -> docker-compose.yml` 相对软链接，包内目标有效，但合同要求 Compose 为普通文件，因此交付检查拒绝，未进入构建。不是软链接逃逸或导出丢文件。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2015-8747/detail/result.json)。 |
| CVE-2022-0613 | 01:28:40–01:29:17 | 干净构建、启动成功；模型交付镜像未安装 pytest，`sh /tmp/cdb-tests/run-tests.sh vulnerable` 在功能测试阶段报 `/usr/bin/python3: No module named pytest` 并退出 1。是模型交付依赖问题，不是判分器额外补跑 pytest。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-0613/detail/result.json)。 |
| CVE-2024-3566 | 01:31:24–01:32:09 | 构建、启动和 5 项功能测试成功，但 vulnerable 的 `&`、`|`、 `$()` 三种命令注入均未检出，模型交付未复现漏洞，脚本退出 1。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-3566/detail/result.json)。 |
| CVE-2022-31549 | 01:31:19–01:32:11 | Python 3.6 Stretch 基础镜像成功拉取，apt 安装成功；模型 Dockerfile 第 39 行 `pip install -r requirements.txt` 要求与该 Python 不兼容的 `flask==2.1.3`，pip 报 `No matching distribution found` 并退出 1，属于交付依赖版本错误，不是镜像源故障。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-31549/detail/result.json)。 |
| CVE-2024-57071 | 01:33:53 | 冻结交付缺 `solution.sh` 及三份测试文件，未进入构建。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-57071/detail/result.json)。 |
| CVE-2024-31224 | 01:36:13 | 冻结交付缺 `tests/run-tests.sh`、`test_func.py`、`test_vuln.py`，未进入构建。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-31224/detail/result.json)。 |
| CVE-2024-51978 | 01:40:00 | 冻结交付缺三份测试文件，未进入构建。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-51978/detail/result.json)。 |
| CVE-2023-6124 | 01:45:01–01:45:42 | 干净构建、启动成功；vulnerable 的 9 项功能测试全失败，模型测试在 `/tmp/cdb-tests` 内错误寻找 Compose、Dockerfile、solution 和应用 `Image.php`，未进入漏洞差分。不是判分器额外补依赖或网络故障。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2023-6124/detail/result.json)。 |
| CVE-2022-3967 | 第2次判分 01:48:59–01:49:37 | 上下文重试后干净构建、启动成功；vulnerable 的 21 项功能测试通过，但漏洞测试 5 项失败、1 项通过，脚本错误要求 vulnerable 状态具有修复后的 `dom_alias` 校验，故退出 1。是模型测试契约错误，不计基础设施失败。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-3967/detail/result.json)。 |
| CVE-2015-6918 | 第2次判分 01:51:40 | 上下文重试后冻结交付缺 `solution.sh` 及三份测试文件，未进入构建。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2015-6918/detail/result.json)。 |
| CVE-2022-1531 | 第2次判分 01:56:52–01:57:58 | **raw passed，不计真实通过**。vulnerable/fixed 两侧 5 项漏洞测试全为 skip，源码检出、SQL 注入检出乃至正常搜索都被模型写成 `pytest.skip`，因此没有任何修复断言失败；当前 grader 只认 `run-tests.sh` 退出码，误将 F2P 标为成功。这是模型交付未有效验证漏洞，同时暴露判分器对 skip 的缺口，不按基础设施重跑。[测试文件](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-1531/detail/bundle/delivery/source/tests/test_vuln.py)、[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-1531/detail/result.json)。 |
| CVE-2024-36039 | 01:57:58–02:00:58 | 干净构建、启动成功；`run-tests.sh` 在 `/tmp/cdb-tests` 下又拼接 `tests/test_func.py`，路径不存在，pytest 退出 4，未进入漏洞差分。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-36039/detail/result.json)。 |
| CVE-2025-30208 | 01:59:31–02:01:01 | Node 镜像和依赖安装、干净构建成功；模型 client 启动后变为 unhealthy，未进入 vulnerable 测试。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2025-30208/detail/result.json)。 |
| CVE-2022-21953 | 第2次 02:06:33–02:07:19 | 上下文重试后干净构建在 `go build` 失败：缺 `github.com/gorilla/mux` 的 `go.sum` 条目，属于交付依赖元数据缺失，不是 Go 模块下载或网络失败。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-21953/detail/result.json)。 |
| CVE-2018-25082 | 01:33:28–01:34:19 | 干净构建、启动、vulnerable 功能与 XXE 复现均成功；`solution.sh` 把 `etree.fromstring` 替换为 `_safe_msg_parser.fromstring`，但后者是 parser 实例，不提供该方法。脚本执行成功且未重建，同一 client 重启后变为 unhealthy，未进入 fixed 测试。不是镜像或网络故障。[补丁](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2018-25082/detail/bundle/delivery/source/solution.sh)、[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2018-25082/detail/result.json)。 |
| CVE-2022-34749 | 第2次 02:18:24–02:18:45 | 上下文重试后干净构建、启动成功；`run-tests.sh` 调用模型交付镜像中不存在的 pytest，vulnerable 功能测试以 `/usr/local/bin/python3: No module named pytest` 退出 1，未进入漏洞差分。不是网络或判分器补依赖问题。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-34749/detail/result.json)。 |
| CVE-2024-25177 | 第2次 02:21:27–02:22:26 | **raw passed，不计真实通过**。模型轨迹明确记录 PoC 不崩溃后改用 JIT 开关作为漏洞指标；测试忽略 PoC 退出码，`solution.sh` 只是把 `luajit` 换成 `-j off` wrapper。没有复现 CVE 描述的段错误，也没有验证 snapshot/unsinking 缺陷是否修复，仅靠禁用 JIT 制造差分，不符合“真实漏洞语义”要求。[测试](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25177/detail/bundle/delivery/source/tests/test_vuln.py)、[补丁](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25177/detail/bundle/delivery/source/solution.sh)、[轨迹](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25177/trajectory.md)、[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2024-25177/detail/result.json)。 |

### 交付含逃逸符号链接，冻结检查拒绝（1）

| 题目 | 时间（北京时间） | 根因与证据 |
| --- | --- | --- |
| CVE-2016-1000003 | 01:33:35 | 模型把 `docker-compose.yml` 链到原工作区 `docker-compose.yaml` 的**绝对路径**；冻结后的链接目标不在交付包内，安全检查按设计报 `frozen symlink escapes its package`，无法独立判分。属于模型交付不可移植，不按基础设施重跑。[result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2016-1000003/detail/result.json)、[轨迹中的绝对链接命令](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2016-1000003/trajectory.md)。 |

### 基础设施隔离重跑已完成（1）

`CVE-2022-40896` 原批第3次尝试仍报 `114689 input + 16384 output > 131072`，原记录保留，不计模型失败。03:12 在新目录 `baseline-qwen36-factory-requeue-20261103-0312` 完成一次干净重跑；模型正常交卷，冻结交付缺 `tests/run-tests.sh`、`test_func.py`、`test_vuln.py`，03:16 标准判分为 `failed / agent_semantic / delivery`，未进入构建。[result.json](../../runtime/baseline-qwen36-factory-requeue-20261103-0312/cvefactory-cve-2022-40896/detail/result.json)。**至此本族40题均有终态：raw passed=6，严格通过=1；另 5 题的漏洞语义审计见上方，不能把 raw 差分直接当真实修复。无待重跑基础设施错误。**

### 模型耗尽轮次或未交付全部合同文件（4，另有 1 题见下）

以下 4 题缺 Compose 之外的其他合同文件。CVE-2022-41322 与其余文件齐全但缺 Compose；连同上面 6 题及这里的 5 题，缺 Compose 合计 11 题，均记为 `agent_semantic`，不需要按基础设施重跑。

| 题目 | 起止（北京时间） | 根因与证据 |
| --- | --- | --- |
| CVE-2014-9720 | 第2次 01:42:15–01:59:18 | 达到 50 轮预算后停止，缺 Compose；不是 API 中断。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2014-9720/detail/agent-result.json)。 |
| CVE-2018-16733 | 第2次 01:49:41–02:00:33 | 会话正常结束但缺全部五类合同交付，`agent.status=incomplete`，实际仍停在搜索源码，不是 API 或沙箱错误。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2018-16733/detail/agent-result.json)。 |
| CVE-2022-0868 | 第3次 02:15:14–02:15:21 | 前两次为上下文超限；第3次会话 5 轮正常结束，仍在重读 TASK，缺全部五类合同交付。不再进行第4次尝试，不计 API 失败。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-0868/detail/agent-result.json)。 |
| CVE-2019-14904 | 第3次 02:21:47–02:23:22 | 前两次为上下文超限；第3次会话 11 轮正常结束，仍计划创建 Compose、solution 和三份测试文件，实际全部缺失。不再进行第4次尝试，不按基础设施重跑。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2019-14904/detail/agent-result.json)。 |

| 题目 | 起止（北京时间） | 根因与证据 |
| --- | --- | --- |
### 轮次耗尽，只缺 Compose（1）

| 题目 | 起止（北京时间） | 根因与证据 |
| --- | --- | --- |
| CVE-2022-41322 | 01:21:54–01:41:58（agent） | 达到 50 轮启动预算后停止，缺合同要求的 `docker-compose.yaml`；`failure_category=export` 只表示导出缺文件，不是 API/网络基础设施错误。[agent-result.json](../../runtime/baseline-qwen36-factory-20261103-011005/cvefactory-cve-2022-41322/detail/agent-result.json)。 |

## 2026-11-02 · Qwen3.6-35B-A3B baseline · 230858 中止批（保留现场）

批次 [baseline-qwen36-factory-20261102-230858](../../runtime/baseline-qwen36-factory-20261102-230858/summary.json)：40 题、25 并发、18000 秒。使用未微调本地模型与真实 Anthropic 工具调用。**该批中止，不作为成绩；40 题已由 011005 与 0312 完整重跑。**

- 开始时间 23:08:58（北京时间），`summary.json` 保留 `status=running`、`finished=31`、`passed=0`，没有正常 `finished_at`；这是中止现场，不表示仍在运行。
- 18 题最终为预检网络失败、agent 未启动。日志包括内部 registry `connection refused`、kkRepo 被误用 HTTPS、Docker Hub `toomanyrequests`，以及一次 900 秒拉取超时。
- 其余记录有上下文长度 API 错误、导出缺交付和 2 个语义失败；不能用这个未完成批次的 0/40 计算通过率。
- 01:10:05 新批的 40 次预检全部成功；这是环境恢复后的新目录完整重跑，不覆盖旧记录。

### 模型提前结束，未交付工程（1）

| 题目 | 起止（北京时间） | 根因与证据 |
| --- | --- | --- |
| CVE-2015-10026 | 23:08:58–23:10:17；agent 23:10:06–23:10:14 | 预检全部成功。模型仅 5 轮即以“Found the TASK.md file. Let me read it.”结束，没有 `docker-compose.yaml`、`solution.sh` 或三份测试文件；后续 compose 导出报 `no such file or directory` 是缺交付的后果，不是网络或已有文件导出丢失。[agent-result.json](../../runtime/baseline-qwen36-factory-20261102-230858/cvefactory-cve-2015-10026/detail/agent-result.json)、[轨迹](../../runtime/baseline-qwen36-factory-20261102-230858/cvefactory-cve-2015-10026/trajectory.md)。 |


## 2026-11-01 修订候选：无操作和无关补丁均被拒绝（6）

这不是新模型批次，不改以下历史成绩。19:37–19:44 UTC，三个修订候选各自执行两次完整干净构建和差分，空补丁／无关文件注释均成功完成 vulnerable 阶段、solution 和同一 client 重启，但 fixed 脚本退出 1；六案全部 `reward=0 / agent_semantic / fixed`。对应预期拒绝，故 6/6 负面对照通过。CVE-2024-0241 fixed 为 5 failed、1 passed；CVE-2024-32962 为 6 failed；CVE-2025-30208 为 4 failed。证据：[汇总](../../delivery/cvefactory-revised-20261101/evidence/negative-controls-summary.json)及每案 `result.json`。

## 2026-10-30 · DeepSeek-V4.1-Flash · 50 轮启动上限

- 批次 [cvefactory-2026103006-ds41flash](../../runtime/cvefactory-2026103006-ds41flash/summary.json)：40 题，20 并发，07:08–07:33（北京时间）全部终态；逐题 `launch.max_turns=50`、`timeout_sec=18000`、`model=deepseek-v4.1-flash`。结果 **33 通过 / 7 未通过**。
- 33 题均取得干净构建、补丁前 vulnerable 测试、原容器内 solution、restart、fixed 测试与 P2P/F2P 通过证据，见批次内 `<题>/detail/result.json`。`summary.requeues=[]`，没有 API、预检或网络失败需要回捞。
- 两道 `ExportError` 都是 agent 达 50 轮启动上限后仍无 Compose，不是导出丢失已有文件；均保留原始结果，不以基建名义重跑。

### 通过（33）

CVE-2013-2012、CVE-2014-1944、CVE-2014-9720、CVE-2015-10026、CVE-2015-3010、CVE-2015-3630、CVE-2015-6918、CVE-2016-4445、CVE-2016-8628、CVE-2017-5591、CVE-2017-16667、CVE-2017-1001002、CVE-2018-17057、CVE-2018-25082、CVE-2019-14904、CVE-2020-36651、CVE-2022-0613、CVE-2022-0868、CVE-2022-1531、CVE-2022-31502、CVE-2022-31549、CVE-2022-34749、CVE-2022-21953、CVE-2022-3967、CVE-2023-3852、CVE-2023-42439、CVE-2024-25124、CVE-2024-31224、CVE-2024-3566、CVE-2024-36039、CVE-2024-51978、CVE-2024-57071、CVE-2025-30208。

### 交付语义失败（5）

| 题目 | 判分证据与原因 |
|---|---|
| CVE-2015-8747 | `agent.status=max_turns`；交付缺 `tests/run-tests.sh`、`test_func.py`、`test_vuln.py`，不是导出丢失。[结果](../../runtime/cvefactory-2026103006-ds41flash/cvefactory-cve-2015-8747/detail/result.json) |
| CVE-2016-1000003 | `agent.status=max_turns`；交付缺 `solution.sh` 及三份测试文件。[结果](../../runtime/cvefactory-2026103006-ds41flash/cvefactory-cve-2016-1000003/detail/result.json) |
| CVE-2018-16733 | 构建、启动成功，但正向功能测试失败：合法 trace range 4..5 报 `debug_traceChain does not exist/is not available`，未进入补丁阶段。[结果](../../runtime/cvefactory-2026103006-ds41flash/cvefactory-cve-2018-16733/detail/result.json) |
| CVE-2022-40896 | 正向测试全过，但 sql+jinja 未终止 macro 输入返回正常 score 0.0，未形成要求的漏洞断言失败，vulnerable 脚本退出 1。[结果](../../runtime/cvefactory-2026103006-ds41flash/cvefactory-cve-2022-40896/detail/result.json) |
| CVE-2022-41322 | vulnerable 功能与漏洞复现均成功；`solution.sh` 报 `report_notification_activated() not found in window.py` 并退出 1，未进入 fixed 阶段。[结果](../../runtime/cvefactory-2026103006-ds41flash/cvefactory-cve-2022-41322/detail/result.json) |

### 50 轮耗尽，未交付 Compose（2）

- CVE-2023-6124、CVE-2024-25177：agent 均 `max_turns`（CLI `num_turns=51`），export 时工作区没有 `docker-compose.yaml`，报 `no such file or directory`。不是 API/网络中断，不回捞；证据在各自 `detail/agent-result.json`。

同题 GLM 50 轮为 27/40，本轮 DS 为 33/40；两者均使用同一份 40 题输入、20 并发、18000 秒，结果目录和失败归因独立保存。

## 2026-10-30 · GLM-5.3 · 50 轮启动上限（本轮）

- 批次 [cvefactory-2026103002-glm53](../../runtime/cvefactory-2026103002-glm53/summary.json)：40 题，20 并发，2026-10-30 02:05 启动，03:06 全部终态；`--max-turns 50`、`--timeout 18000` 已逐题核对。结果 **27 通过 / 13 未通过**。
- 27 个通过项的干净构建、启动、vulnerable 脚本、补丁、原容器 restart、fixed 脚本和 P2P/F2P 均成功，见[本轮通过证据](#20261030-glm-pass)。没有 API 错误、预检失败、网络重试或批间中断，故 **0 道需要 API/网络回捞**。Runner 的 `requeues` 为空。
- 13 道未通过均有真实终态，不把轮次耗尽或语义失败冒充网络失败。旧上方历史表不改。

<a id="20261030-glm-pass"></a>
### 做对了（27）

题目（各题均可点开同目录 `detail/result.json`）：CVE-2013-2012、CVE-2014-1944、CVE-2014-9720、CVE-2015-10026、CVE-2015-3010、CVE-2015-6918、CVE-2017-16667、CVE-2017-1001002、CVE-2018-25082、CVE-2019-14904、CVE-2020-36651、CVE-2022-0613、CVE-2022-0868、CVE-2022-21953、CVE-2022-31502、CVE-2022-31549、CVE-2022-34749、CVE-2022-41322、CVE-2023-3852、CVE-2023-42439、CVE-2024-25124、CVE-2024-31224、CVE-2024-3566、CVE-2024-36039、CVE-2024-51978、CVE-2024-57071、CVE-2025-30208。

例如 [CVE-2022-0613 判题记录](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2022-0613/detail/result.json)：补丁前 14 项正向功能通过、4 项混合大小写 URL 漏洞断言失败；补丁后正向功能仍通过、同 4 项通过，原容器未重建。其余 26 题的同类差分证据均存于该批次 `<题>/detail/result.json`，开始与结束时间以各记录为准。

### 模型结束，判题失败：正向功能或漏洞测试不成立（5）

- CVE-2018-17057：`sh /tmp/cdb-tests/run-tests.sh vulnerable` 退出 1。12 项正向检查有 5 项失败：HTML 渲染未返回 PDF、类型仍是 `text/html`，图像和 stylesheet 路径出现 `chr() expects parameter 1 to be int`。漏洞测试虽报 object injection，正向基线已失败，见[判题输出](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2018-17057/detail/result.json)。
- CVE-2015-8747：同脚本退出 1；`test_put_replaces_existing_item` 断言应有 `SUMMARY:alpha2`，实际仍为 `SUMMARY:alpha`，见[判题输出](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2015-8747/detail/result.json)。
- CVE-2017-5591：同脚本退出 1；XMPP 登录成功但 `carbons_enabled=False`，服务端 carbon 和本端 carbon 都没收到，见[判题输出](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2017-5591/detail/result.json)。
- CVE-2023-6124：同脚本退出 1；19 项正向检查中“本 run 的条目被列出”和“保持原 link payload”两项失败，列表里仅找到 4 条，见[判题输出](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2023-6124/detail/result.json)。
- CVE-2022-1531：正向检查全过，但 UNION SQL 注入返回 HTTP 500 而非内部表名；异常处理随后还因 `P_QUOTES` 未定义触发 `NameError`，见[判题输出](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2022-1531/detail/result.json)。

### 模型交付工程的构建失败：Stretch 的 apt 源写错（1）

- CVE-2018-16733：模型交付的 Dockerfile 第 18 行 `apt-get update; apt-get install python3` 退出 100。Stretch 应用的是通用 `debian`/`debian-security` 路径而非 archive，3 个 Packages 地址均 404；仓库可达、返回明确 404，不是网络断连。证据：[判题记录](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2018-16733/detail/result.json)、[Dockerfile](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2018-16733/detail/bundle/delivery/source/Dockerfile)。

### 轮次结束仍未交付完整工程（7）

- CVE-2016-1000003：`agent.status=max_turns`，工作区已冻结但缺 `solution.sh`、`tests/run-tests.sh`、`test_func.py`、`test_vuln.py`，见[结果](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2016-1000003/detail/result.json)。
- CVE-2015-3630、CVE-2016-4445、CVE-2016-8628、CVE-2022-3967、CVE-2022-40896、CVE-2024-25177：`agent.status=max_turns`，导出时工作区根目录仍没有 `docker-compose.yaml`，报 `no such file or directory`。以 [CVE-2015-3630 agent 结果](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2015-3630/detail/agent-result.json) 为例；沙箱预检均成功，不是导出丢了一个已有 compose。虽记录为 export，归因是轮次内未交付，不按基础设施回捞。

### 轮次计数留痕（不修改历史）

所有 40 题启动配置确实是 50，26 个 `max_turns` 终态记为 51；少数成功会话的 CLI `num_turns` 为 52–63（最高 CVE-2024-31224 的 63），即使启动上限为 50。原始 [CVE-2017-1001002 轨迹](../../runtime/cvefactory-2026103002-glm53/cvefactory-cve-2017-1001002/trajectory.md) 记 `success,num_turns=54`。因此本轮只声称“以 `--max-turns 50` 启动”，不把当前 Claude Code 的 `num_turns` 当成已被独立验证的严格硬截断。该差异另记入修复记录，待 CLI 侧定位，未修改判分或旧结果。

这是 `runtime/cvefactory-202610272222` 的 40 道题。时间是北京时间。启动是这道题自己的进程开始，结束是这道题自己收尾的时刻。

跑完了不是时间到了。这一轮单题时限大约 8.3 小时，轮次上限 180。模型自己结束，是会话记录为 `completed`、轮次没有打满。轮次到了，是打满 181 轮后被停。预检超时是模型还没开始。判题超时是模型已经交卷，判题进程自己超时。

22:17 另开过一轮 `cvefactory-202610272218`，大约四分钟结束，通过数是 0。39 道在创建沙箱网段时撞上 Pool overlaps，模型进程没有起来；CVE-2019-14904 是预检 `docker pull` 超过当时的 240 秒。那一轮没有一道进入判题。22:22 的这一轮是网段占用留出 180 秒之后新开的目录，模型第一次真正做这些题。后来做对的 6 道，在 22:17 那轮的 `summary.json` 里都是 `agent_status=not_started`。今早 `cvefactory-202610280858` 又启动了其中 20 道，杀掉时都还在模型阶段，没有新成绩。

同一类放在一起。新题有了终态，追加到对应的一节，不要按编号插进整张大表。

## 做对了（6）

模型自己结束，判题通过。22:17 那轮这 6 道都还没启动模型。


| 题目             | 启动          | 结束          | 状态                                     |
| -------------- | ----------- | ----------- | -------------------------------------- |
| CVE-2015-10026 | 10-27 22:22 | 10-28 03:14 | 做对了。模型自己结束（121 轮），判题通过                 |
| CVE-2018-25082 | 10-27 22:22 | 10-28 01:12 | 做对了。模型自己结束（90 轮），判题通过                  |
| CVE-2019-14904 | 10-27 22:22 | 10-28 00:48 | 做对了。模型自己结束（77 轮），判题通过。22:17 那轮它死在预检拉镜像 |
| CVE-2022-31549 | 10-27 22:26 | 10-28 01:44 | 做对了。模型自己结束（95 轮），判题通过                  |
| CVE-2024-3566  | 10-28 00:54 | 10-28 02:46 | 做对了。模型自己结束（49 轮），判题通过                  |
| CVE-2024-51978 | 10-28 01:06 | 10-28 03:09 | 做对了。模型自己结束（59 轮），判题通过                  |




## 模型自己结束，判题失败：镜像里没有 pytest（15）

模型自己交卷。当时的判题器在 `run-tests.sh` 退出码 0 之后，又在容器里执行了一次 `python3 -m pytest`。镜像里没有 pytest，测试没跑起来。现在的判题只认 `sh /tmp/cdb-tests/run-tests.sh vulnerable|fixed` 退出码 0，不再另跑 pytest。这 15 道的旧成绩不改，见 [修复记录第 9 节](../修复记录/cvefactory修复记录.md)。


| 题目             | 启动          | 结束          | 轮次  |
| -------------- | ----------- | ----------- | --- |
| CVE-2013-2012  | 10-27 22:22 | 10-28 01:14 | 77  |
| CVE-2014-9720  | 10-27 22:22 | 10-28 03:24 | 122 |
| CVE-2015-3010  | 10-27 22:22 | 10-28 01:08 | 87  |
| CVE-2015-6918  | 10-27 22:22 | 10-28 03:02 | 116 |
| CVE-2015-8747  | 10-27 22:22 | 10-28 00:54 | 80  |
| CVE-2017-5591  | 10-27 22:22 | 10-28 05:16 | 166 |
| CVE-2022-0613  | 10-27 22:22 | 10-28 01:06 | 87  |
| CVE-2022-0868  | 10-27 22:26 | 10-28 00:27 | 58  |
| CVE-2022-40896 | 10-27 22:30 | 10-28 02:16 | 102 |
| CVE-2022-41322 | 10-27 22:30 | 10-28 03:41 | 133 |
| CVE-2023-3852  | 10-27 22:30 | 10-28 03:16 | 146 |
| CVE-2024-25177 | 10-28 00:27 | 10-28 08:48 | 183 |
| CVE-2024-36039 | 10-28 01:04 | 10-28 03:44 | 71  |
| CVE-2024-57071 | 10-28 01:08 | 10-28 04:51 | 101 |
| CVE-2025-30208 | 10-28 01:12 | 10-28 04:41 | 84  |




## 导出把名叫 log 的目录丢掉了（1）

这不是模型没写 vendor。工作区里有 `app/vendor/github.com/gofiber/fiber/v2/log/`，里面是 `default.go`、`fiberlog.go`、`log.go`。22:22 那次导出的排除名单里有目录名 `log` 和 `logs`，所以交付包里这个目录没了。判题用的是丢掉之后的树，`go build -mod=vendor` 才报找不到包。现在的导出不再按目录名丢掉 `log`/`logs`。这道题的旧 `result.json` 不改。


| 题目             | 启动          | 结束          | 根因                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| -------------- | ----------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE-2024-25124 | 10-27 22:34 | 10-28 01:15 | 模型自己结束（79 轮）。判题 `docker compose build --no-cache` 58 秒失败，但这不是模型漏了依赖。工作区 [fiber/v2/log](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-25124/workspace/app/vendor/github.com/gofiber/fiber/v2/log) 里有 `default.go`、`fiberlog.go`、`log.go`。导出清单 [source-inventory.json](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-25124/bundle/delivery/source-inventory.json) 的 `exclusions` 含有目录名 `log` 和 `logs`，`excluded_paths` 只有 `app/vendor/github.com/gofiber/fiber/v2/log`。交付目录里这个 `log/` 不存在，工作区比交付包只多这 3 个文件。判题因此在 Dockerfile 第 54–55 行 `go build -mod=vendor` 退出码 1，原文是 `cannot find module providing package github.com/gofiber/fiber/v2/log: import lookup disabled by -mod=vendor`。`modules.txt` 写了这个包，`-mod=vendor` 不会到网上补。证据：[result.json](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-25124/result.json)，[modules.txt](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-25124/workspace/app/vendor/modules.txt)，[app.go](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-25124/workspace/app/vendor/github.com/gofiber/fiber/v2/app.go)。现在的排除名单在 [bundle.py](../../harness/bundle.py) 的 `_EXCLUSION_RULES` 与 `_excluded`，不再包含 `log`/`logs`。见 [修复记录第 10 节](../修复记录/cvefactory修复记录.md)。 |




## 模型自己结束，判题失败：判题多跑了一次 pytest（1）

模型的 `run-tests.sh` 退出码是 0。当时的判题器没有照着这个脚本验收，而是自己又执行了一次 `python3 -m pytest`。现在已经改成只认脚本退出码，见 [修复记录第 9 节](../修复记录/cvefactory修复记录.md)。这道题的旧成绩不改。


| 题目             | 启动          | 结束          | 根因                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| -------------- | ----------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CVE-2024-31224 | 10-28 00:48 | 10-28 02:49 | 模型自己结束（58 轮）。模型写的 `tests/run-tests.sh` 在易受攻击状态下跑通了：功能测试通过，漏洞测试按预期失败，脚本退出码 0（`checks.vulnerable.runner_succeeded=true`）。判题器接着在容器里另起一次 `python3 -m pytest`，工作目录是 `/tmp/cdb-tests`，不执行 `run-tests.sh`，因此看不到脚本第 33 行导出的 `PYTHONPATH=/opt/gpt_academic`。这次在 `test_func.py:16` 的 `from themes.theme import (...)` 报 `ModuleNotFoundError: No module named 'themes'`。包在镜像里，路径是 `/opt/gpt_academic/themes/theme.py`；Dockerfile 构建时用同一条 import 做过冒烟。这道题当晚的 TASK.md 只写判题会跑 `sh /tmp/cdb-tests/run-tests.sh`。08:57 曾把「判题器会单独跑 pytest」写进说明，后来按验收对齐删掉了，现在判题不再另跑 pytest。这道题的 `result.json` 不改。证据：[result.json](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-31224/result.json) 的 `checks.vulnerable.script` 与 `checks.vulnerable.tests.test_func.py.output_tail`，[run-tests.sh](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-31224/bundle/delivery/source/tests/run-tests.sh)，[Dockerfile](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2024-31224/bundle/delivery/source/Dockerfile)。现在的验收在 [grader.py](../../harness/families/cvefactory/grader.py) 的 `run_tests`，见 [修复记录第 9 节](../修复记录/cvefactory修复记录.md) |




## 轮次到了，缺交付，判题失败（2）

打满 181 轮后被停。工作区和导出包都核对过，缺的是判题点名的那几个文件。两道题都写了 Compose 和 Dockerfile。

当前 prompt（[run_agent.py](../../harness/run_agent.py) 的 `TASK_PROMPT`，也就是模型读到的 `TASK.md`）要求先把 `docker-compose.yaml`、Dockerfile、`solution.sh`、`tests/test_func.py`、`tests/test_vuln.py`、`tests/run-tests.sh` 写进当前工作区，哪怕还构建不了、测试没过，然后再调试。只构建成功、只 commit 容器或只口头描述都不算交付。这句话是后来补上的。这两道题 22:22 看到的 `workspace/TASK.md` 里还没有。


| 题目            | 启动          | 结束          | 根因                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------- | ----------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE-2016-4445 | 10-27 22:22 | 10-28 05:48 | 181 轮。工作区和 `bundle/delivery/source` 里都有 `Dockerfile`、`docker-compose.yaml`，`tests/` 是空目录，没有 `solution.sh`。判题原文：`missing agent delivery files: source/solution.sh, source/tests/run-tests.sh, source/tests/test_func.py, source/tests/test_vuln.py`。`agent-result.json` 的 `missing_deliverables` 是同样四项。证据：[result.json](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2016-4445/result.json)、[agent-result.json](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2016-4445/agent-result.json)、[workspace/tests](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2016-4445/workspace/tests) |
| CVE-2016-8628 | 10-27 22:22 | 10-28 06:17 | 181 轮。`solution.sh`、`docker-compose.yaml`、`Dockerfile.client` 在工作区和导出包里都有。`tests/` 里只有 `cdb_harness.py`，没有 `test_func.py`、`test_vuln.py`、`run-tests.sh`。判题原文：`missing agent delivery files: source/tests/run-tests.sh, source/tests/test_func.py, source/tests/test_vuln.py`。证据：[result.json](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2016-8628/result.json)、[workspace/tests](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2016-8628/workspace/tests)                                                                                                                             |




## 模型没启动：预检拉镜像超时（13）

`docker pull python:3.11-slim` 超过当时的 240 秒。模型没有开始写代码。这是环境问题，不是模型失败。


| 题目               | 启动          | 结束          |
| ---------------- | ----------- | ----------- |
| CVE-2014-1944    | 10-27 22:22 | 10-27 22:26 |
| CVE-2015-3630    | 10-27 22:22 | 10-27 22:26 |
| CVE-2016-1000003 | 10-27 22:22 | 10-27 22:26 |
| CVE-2017-16667   | 10-27 22:22 | 10-27 22:26 |
| CVE-2018-16733   | 10-27 22:22 | 10-27 22:26 |
| CVE-2018-17057   | 10-27 22:22 | 10-27 22:26 |
| CVE-2020-36651   | 10-27 22:22 | 10-27 22:26 |
| CVE-2022-1531    | 10-27 22:26 | 10-27 22:30 |
| CVE-2022-21953   | 10-27 22:26 | 10-27 22:30 |
| CVE-2022-31502   | 10-27 22:26 | 10-27 22:30 |
| CVE-2022-34749   | 10-27 22:26 | 10-27 22:30 |
| CVE-2022-3967    | 10-27 22:26 | 10-27 22:30 |
| CVE-2023-42439   | 10-27 22:30 | 10-27 22:34 |




## 判题进程超时，没有判出对错（2）

模型已经交卷。判题进程自己超时，没有写出对错。这是管线问题，不是模型失败。

外层判题时限是 [run-factory-eval.sh](../../run-factory-eval.sh) 里的 `GRADE_TIMEOUT=1800`。构建命令自己允许 3600 秒（[grader.py](../../harness/families/cvefactory/grader.py) 的 `compose build --no-cache`）。1800 秒到了，父进程把整个判题杀掉，构建还没返回，所以 `result.json` 一直停在 `status=running`，`checks` 里只有交付检查，`grader-console.log` 是 0 字节。构建输出要等命令返回才写入结果，这次没有那份输出。


| 题目               | 启动          | 结束          | 根因                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------- | ----------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE-2017-1001002 | 10-27 22:22 | 10-28 00:34 | 模型自己结束（68 轮），00:34:28 开始判题。判题沙箱的 [docker-commands.log](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2017-1001002/grader-runtime/source-1793118868150059356-1865365/docker-commands.log) 最后一条是 00:34:30 的 `docker compose config`，退出码 0，后面没有 `compose build` 的完成记录。父进程在 1799.999 秒杀掉子进程，见 [batch-error.log](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2017-1001002/batch-error.log)。模型自己用同一份 Dockerfile 做 `--no-cache` 构建时，23:13 发出、23:17 已经在做下一条命令，00:18 到 00:20 大约两分钟，见 [trail.jsonl](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2017-1001002/trail.jsonl)。10-28 17:24 用同一份交付在空 dockerd 上重跑，见 [build.log](../../runtime/trashcan/rebuild-202610281721/cve-2017-1001002/build.log)。680 秒构建成功（[status.txt](../../runtime/trashcan/rebuild-202610281721/cve-2017-1001002/status.txt)）。拉 `node:22-bookworm-slim` 用了 657.6 秒，约 50MB 的那一层多次停在同一个进度，大约每秒几十 KB。apt 7.8 秒，npm 10.2 秒，都走了 kkRepo。这份 Dockerfile 能建成。当晚没有这一层的日志；今天这个速度跨不过 1800 秒，对得上的是当晚这一层拉得更慢或中途停住。模型自己的构建快，是因为那个 dockerd 里已经有这张镜像。 |
| CVE-2023-6124    | 10-27 22:30 | 10-28 06:14 | 打满 181 轮后 06:14:54 开始判题。判题沙箱的 [docker-commands.log](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2023-6124/grader-runtime/source-1793139295191343586-145330/docker-commands.log) 最后一条是 06:15:22 的 `docker compose config`，退出码 0。父进程同样在 1799.999 秒杀掉，见 [batch-error.log](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2023-6124/batch-error.log)。10-28 17:24 用同一份交付重跑，见 [build.log](../../runtime/trashcan/rebuild-202610281721/cve-2023-6124/build.log)。基础镜像大约 66 秒拉完。`RUN sh /docker/build-seed.sh` 里静默安装第一次就写好了 `config.php`（13.8 秒），不是两次 900 秒的 curl。登录地址返回 HTTP 500。脚本用 `curl -fsSL` 再交给 `grep SuiteCRM`，500 时 curl 不输出页面，空等 180 秒后执行 `tail -n 40 /var/log/apache2/error.log`。官方 `php:8.1-apache` 里这个文件指向 `/dev/stderr`。当场看到该 `tail` 停在 `pipe_read`，日志停在 `----- apache error log -----`，直到 15 分钟预算杀掉，见 [status.txt](../../runtime/trashcan/rebuild-202610281721/cve-2023-6124/status.txt)。当晚 1800 秒就是砍在这个不返回的 `tail` 上。脚本见 [build-seed.sh](../../runtime/trashcan/cvefactory-202610272222/cvefactory-cve-2023-6124/bundle/delivery/source/docker/build-seed.sh)。                                                                                             |


## 1754 这一轮：网关把会话掐断，文件还没写完（5）

批次 `runtime/cvefactory-202610281754`，17:54 启动。模型做到一半，接口返回错误，会话记成 `is_error=True`。工作区里还没有 `docker-compose.yaml`，导出跟着失败，所以目录里没有 `result.json`。这不是模型做完被判错。**该历史目录当前不在保留的结果树中，以下仅为当时记录，不再提供失效的证据链接。****该历史目录当前不在保留的结果树中，以下仅为当时记录，不再提供失效的证据链接。**

| 题目 | 结束（UTC） | 根因 |
| --- | --- | --- |
| CVE-2015-3010 | 10:35 | 504 `upstream connection failed`，约 19 轮。当时记录为 `console.log` |
| CVE-2022-21953 | 11:00 | 同上 504。当时记录为 `console.log` |
| CVE-2024-3566 | 11:01 | 同上 504。当时记录为 `console.log` |
| CVE-2015-6918 | 10:27 | 400 `invalid or oversized HTTP request`，约 20 轮。当时记录为 `console.log` |
| CVE-2019-14904 | 10:27 | 同上 400，约 8 轮。当时记录为 `console.log` |

## 1754 这一轮：预检没过，模型没启动（4）

| 题目 | 结束（UTC） | 根因 |
| --- | --- | --- |
| CVE-2016-1000003 | 10:19 | 预检 `docker pull python:3.11-slim` 900 秒超时，退出码 124。当时记录为 `preflight.json` |
| CVE-2022-0613 | 10:14 | 同上，拉 `python:3.11-slim` 超时。当时记录为 `preflight.json` |
| CVE-2022-31549 | 10:24 | 容器出网探测 SSL handshake timeout，模型没启动。当时记录为 `console.log` |
| CVE-2023-42439 | 10:31 | 预检 `curl` SSL connection timeout（exit 28），模型没启动。当时记录为 `console.log` |

## 1754 这一轮：模型交卷，测试没过（3）

判题只跑 `sh /tmp/cdb-tests/run-tests.sh`，退出码不是 0 就失败。镜像都建成了，容器也健康。

| 题目 | 根因 |
| --- | --- |
| CVE-2018-16733 | `vulnerable` 退出码 1。`test_func.py:108` 和 `:130` 报 `KeyError: 'tx_receipt'`，功能测试在取交易回执时崩了。当时记录为 `result.json` |
| CVE-2018-17057 | `vulnerable` 退出码 1。脚本自己打出 `vulnerability REPRODUCED (exit 1) - phase: vulnerable`，`phar://` 反序列化写成了 `/generated/rce-a6449755bbc2.php`。这一阶段要退出码 0，脚本在漏洞还在时退出了 1。当时记录为 `result.json` |
| CVE-2022-31502 | `vulnerable` 通过。`solution.sh` 改了 `/app/app.py` 并重启。`fixed` 退出码 1，功能测试失败一项：`URL alias can be created`。当时记录为 `result.json` |

## 1754 这一轮：判题时容器没等到健康（1）

模型已经交卷并导出。判题执行 `docker compose up -d --wait --wait-timeout 120`，外层 300 秒到了还没返回，记成 `pipeline` / `source_build`。不是测试没过。

| 题目 | 结束（UTC） | 根因 |
| --- | --- | --- |
| CVE-2024-36039 | 11:13 | `TimeoutExpired` after 300 seconds，卡在 `compose up --wait`。模型 10:57 交卷，86 轮。当时记录为 `result.json` |

## 1754 这一轮：最后一道判过（1）

40 道都停了。27 道 `reward=1`，`vulnerable` 和 `fixed` 的 `run-tests.sh` 退出码都是 0，输出不是空的。3 道测试失败，1 道判题 `compose up --wait` 超时，9 道提前停（5 道网关掐断，4 道预检没过）。

| 题目 | 结束（UTC） | 根因 |
| --- | --- | --- |
| CVE-2022-3967 | 11:17 | 模型 141 轮交卷。判题 `vulnerable` 和 `fixed` 都是退出码 0，`solution` 也是 0。当时记录为 `result.json` |

另外 26 道同样是 `reward=1`：两段 `run-tests.sh` 退出码都是 0，两段输出不一样，也不是空日志，`solution` 有输出。题目是 CVE-2013-2012、CVE-2014-1944、CVE-2014-9720、CVE-2015-10026、CVE-2015-3630、CVE-2015-8747、CVE-2016-4445、CVE-2016-8628、CVE-2017-1001002、CVE-2017-16667、CVE-2017-5591、CVE-2018-25082、CVE-2020-36651、CVE-2022-0868、CVE-2022-1531、CVE-2022-34749、CVE-2022-40896、CVE-2022-41322、CVE-2023-3852、CVE-2023-6124、CVE-2024-25124、CVE-2024-25177、CVE-2024-31224、CVE-2024-51978、CVE-2024-57071、CVE-2025-30208。每道的证据在 `runtime/cvefactory-202610281754/cvefactory-<题目>/result.json`。
