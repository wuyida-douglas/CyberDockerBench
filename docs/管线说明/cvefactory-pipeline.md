# CVE-Factory 当前运行管线：输入、Agent、导出与判分

本文以 `harness/run_agent.py`、`harness/run_batch.py`、`harness/bundle.py` 和
`harness/families/cvefactory/grader.py` 为准。旧 recovery、`/app` 哈希恢复、
根目录必须有 Dockerfile 等历史约定不属于本文的当前入口。

## 1. 一图看懂

```text
任务目录
  input/（公开）           gold/（私有，不进入 Agent）
       │
       ▼
每题独立 privileged outer sandbox
  └─ 私有 dockerd（DinD）
      ├─ agent 用户的 Claude Code：构建/调试，把结果写回声明式工程
      └─ client 及 Compose 声明的其他应用服务
       │
       ├─ Agent 完成后冻结 bundle/delivery/source/
       │    声明式工程、补丁、测试和构建资产
       ▼
独立 grader：全新 DinD ── 无缓存构建 ── vulnerable 测试
                    │
          client 内 root 执行 solution.sh
                    │
            restart client ── fixed 测试
                    │
              reward = 1
```

`run_agent.py` 只负责 Agent 与导出，不给 reward。`run_batch.py` 随后对冻结的
`bundle/delivery` 调 grader。历史 `agent-result.json` 中 `grading.status=not_run`
表示尚未判分，不是 reward=0，也不代表已经通过。

## 2. 输入与隔离

公开输入只放在 `tasks/<task_id>/input/`。runner 读取这个任务目录；旁边不再保留
一份同内容的 `inputs/` 归档。

任务目录通常为：

```text
tasks/<task_id>/
├── metadata.yaml
├── instruction.md / TASK.md（公开任务说明，视任务包而定）
└── input/
    ├── CVE.md
    └── src/
```

- `TaskSpec` 从 `metadata.yaml` 解析 `task_id`、`task_type`、`family`；旧
  `bugfix` 映射到 `cvefactory`。`run_batch.py --tasks` 可接收单题、父目录或
  manifest。
- 仅公开 input 和公开说明复制到 Agent workspace。family 的公开契约和
  `TASK_PROMPT` 定义交付要求。`src/` 可变、可能不完整，允许用 Git、上游归档
  和包管理器补全，最终源码不会被初始输入覆盖。
- 不能换成无关项目或伪造漏洞结果。
- Agent 是 sandbox 中的 `agent` 用户，可以使用 sandbox 内 Docker；不会得到宿主
  Docker socket、gold、私有测试、其他任务或模型代理凭据文件。模型凭据只注入
  Claude 进程。
- 早期 CVE-Factory 导入时 `VULNERABILITY.md` 与 `CVE.md` 逐字节重复（去标题），
  系上游 `task.yaml` instruction 的兼容输入；2026-10-29 已全量删除并统一为
  `CVE.md`。`workspace.py` 保留旧路径替换仅为兼容未迁移的历史输入。

## 3. Agent 实际交付什么

| 交付 | 当前契约 |
|---|---|
| `docker-compose.yaml` | 必须在 workspace 根目录；主应用服务叫 `client` |
| Dockerfile 与构建上下文 | 可位于 context 内任意声明路径，不强制根目录 `Dockerfile` |
| `solution.sh` | 在 vulnerable `client` **容器内部**以 root 执行，实际修补运行态 |
| `tests/test_func.py` | vulnerable 和 fixed 均通过的真实功能测试 |
| `tests/test_vuln.py` | vulnerable 上真实漏洞断言失败、fixed 后通过 |
| `tests/run-tests.sh` | POSIX sh；接受 `vulnerable|fixed`，按顺序真实运行测试 |
| 其他服务/资产 | 在 Compose 中声明 sidecar、依赖、卷、bind、配置与测试依赖 |

### Dockerfile 检测与重建

不是搜索“有没有任意一个 Dockerfile”，而是运行 `docker compose config --format json`
解析最终声明，按每个服务的 `build.context` 和可选 `build.dockerfile` 定位。
还检查 additional build contexts、bind、env_file、configs/secrets 的路径闭包，
拒绝指向冻结 workspace 之外的必要资产。`app/Dockerfile`、自定义 Dockerfile
文件名都合法，只要被 Compose 正确声明。递归找到文件本身不构成可重建证明。

source 轨在全新 DinD 中运行 `docker compose build --no-cache`，再
`docker compose up -d --wait`；这一步才是实际可重建验证。Compose 配置并不
替代真实构建。

### 测试依赖与 tester

默认在 `client` 内执行测试。可用 Compose label `cdb.test_service=<service>`
选择专用 tester；可选 `cdb.test_command=<shell-command>` 改变 runner 命令，
环境变量 `CDB_TEST_PHASE=vulnerable|fixed` 标记阶段。grader 仍会分别运行两份
pytest，检查真实 F2P/P2P 证据。Python/pytest/专用 venv 等必须由交付镜像提供，
grader 不临时 pip 安装，也不复制宿主虚拟环境。

测试只有一个路径：tester 内的 `/tmp/cdb-tests`。grader 会先删除这个目录，再把冻结的
`tests/` 复制进去，然后执行 `sh /tmp/cdb-tests/run-tests.sh`。工程不要把 `tests/`
或任何目录挂到 `/tmp/cdb-tests`，否则这次删除会删掉工程里的测试文件。模型自测时
把 `tests/` 复制进容器的这个目录，再跑同一条命令。

### `solution.sh`：为什么宿主执行成功不算通过

**判分契约是 root-in-client，不是 sandbox-host-docker。**

grader 将冻结工程的完整内容复制到 `client:/tmp/cdb-solution`，然后执行：

```text
docker exec --user root --workdir /tmp/cdb-solution <client> \
    sh /tmp/cdb-solution/solution.sh
```

所以脚本中的 `.` 和相对资产路径位于 `/tmp/cdb-solution`。脚本可以使用 client
镜像中声明的 POSIX sh、解释器、补丁文件和应用工具；**不能假设有 `docker` CLI、
sudo、宿主 workspace 或宿主 Docker daemon**。Agent 在 sandbox 宿主运行
`./solution.sh` 再通过 Docker 找 client，是另一种执行环境，不能证明上述命令成功。

模型曾写的“宿主脚本找 client 并修补”就是这里的不匹配：client 镜像内没有
Docker CLI 时，独立 grader 内同样的逻辑无法工作。脚本自己打印 `fixed` 或
退出 0 也不等于真的修补；后续漏洞测试和 restart/健康检查才提供证据。

正确调试方式：用 sandbox Docker 将工程复制到 client 的 `/tmp/cdb-solution`，
按上面的 argv 在 client 内以 root 执行，restart client，再运行 fixed 测试。
调完后恢复声明的 vulnerable 状态并最终保持 vulnerable ready。不要在交付时
留下已修补环境，也不要做 export/commit/grading。当前 grader 和新生成 workspace
的 `TASK.md` 已统一为这一契约，并有对应回归测试。

历史 `runtime/pilot-cve-2013-2012-r1` 的旧 `solution.sh` 仍含宿主侧 Docker
调用，而且记录为 `grading.status=not_run`；它没有用新契约真实复验过，不能
视为已经通过。修改框架不等于改写或验证历史 Agent 交付；若需要复验，应使用
原 bundle 在新的结果目录中单独判分并如实保留失败证据。

## 4. 日志与结果文件

每题结果目录 `<results>/<task_id>/` 主要包含：

| 文件 | 含义 |
|---|---|
| `agent_stdout.jsonl` | Claude CLI 原始 stream-json，保留作故障诊断/离线重建 |
| `trajectory.jsonl` | 紧凑 JSONL，去除 token 计数心跳，保留完整消息和元数据 |
| `trajectory.md` | 实时、易读的思考/正文/工具调用/工具返回/会话结果 |
| `console.log`、`runner-console.log` | runner 阶段和工具名等简要进度 |
| `agent-result.json` | Agent 状态、启动限制、交付缺失、导出及异常；不是 reward |
| `preflight.json` | 真实网络/包下载/镜像/构建检查（若已执行） |
| `bundle/delivery/` | Agent 结束后冻结的声明式 source |
| `result.json` | grader 的 reward、status、failure_class、分阶段 checks |
| `grader-console.log` | 判分过程的控制台输出 |
| `summary.json`（批次根目录） | 本批次状态、完成数及通过数 |

紧凑轨迹每个事件实时 flush，不截断思考、工具参数或工具返回；只省略
`system/thinking_tokens` 计数心跳和 Markdown 展示层的传输签名/重复元数据。
原始 stdout 仍是冗余较大的原始流，不会混回紧凑审计轨迹。

历史结果可由 `python3 harness/compact_trace.py <原始JSONL> --jsonl <新JSONL>
--markdown <新MD>` 离线重建；不要用新结果覆盖原始证据。

## 5. 导出：冻结声明式工程

Agent 停止写工程后，controller 从 sandbox 导出，而不是让 Agent 自己提交：

1. 冻结完整 workspace 为 `delivery/source/`；排除运行时日志、`.git` 和敏感
   配置，保留交付所需的 vendored 依赖/venv 等实际文件。
2. 解析 Compose 并验证声明的路径闭包。指向工程目录以外的 bind 直接失败，
   归类为 export，不能算 Agent 语义失败。
3. 记录 `bundle.json` 和 `source-inventory.json`(路径、权限、大小;不写 SHA256SUMS)。

CVE-Factory 不提交正在运行的镜像、卷或运行版 Compose。正在跑的容器不参与判分。
`harness/bundle.py` 里的镜像提交和 `load_snapshot` 仍留给 WebExploit、CyberGym。

## 6. 判分：干净重建与补丁

1. 只使用冻结 `delivery/source`，启动新的独立 DinD；不复用 Agent 的容器、
   workspace、镜像缓存或卷。
2. 解析 Compose/测试契约，无缓存 build，up 并等待健康状态。
3. 注入冻结测试，运行 `vulnerable`：`test_func` 必须 PASS；`test_vuln`
   必须实际执行漏洞断言并 FAIL。收集失败、缺依赖、0 tests、skip 或伪造文本不算。
4. 复制工程到 client 的 `/tmp/cdb-solution`，root-in-client 执行补丁。
   不得替换 client 容器来伪装 restart。
5. 重启同一 client，检查 running/healthy；**不重建 patched 镜像，不注入 `/app`**。
6. 用相同 tester/命令运行 `fixed`：功能测试仍 PASS，漏洞测试转 PASS，形成
   P2P/F2P 差分证据。

这一差分完成即写 `reward=1,status=passed`。测试不符合语义为
`reward=0,status=failed,failure_class=agent_semantic`。基础设施或 grader
故障单独标为 error，不应混入模型能力失败率。

干净重建的卷是空的。漏洞测试需要的初始数据必须来自镜像或工程文件。

判分证据在 `result.json.checks`：`source`、`vulnerable`、`solution`、`restart`、
`fixed`、`differential`。成功文本、returncode=0 或 reward 字段本身不是充分的
审计证据；需要检查对应命令、测试收集和断言输出。

## 7. 时间、轮次、判分与并发上限

**正常批量启动使用 `run-factory-eval.sh` 的固定默认值；跨模型评测可用 `CDB_MODEL` 显式指定模型，其他运行上限不读取 `CDB_*` 环境变量；
metadata 中的字段不会自动覆盖。**`run_batch.py` 与 `run_agent.py` 顶部的
`DEFAULT_*` 常量是直接调用对应 Python CLI 时的默认值。不使用顶层 `run-factory-eval.sh`
时，模型、题目目录等仍按各自 CLI 的必填参数提供。

| 限制 | 当前默认 | 在哪里改 |
|---|---:|---|
| Agent turns | 50 | `run-factory-eval.sh` 的 `MAX_TURNS` |
| Agent 模型阶段墙钟 | 18000 秒 = 5 小时 | `run-factory-eval.sh` 的 `TIMEOUT`，单位为秒 |
| 单题 runner 外层上限 | Agent timeout + 3600 秒 | `run_batch.py` 的 `RUNNER_GRACE_SECONDS` |
| 判分上限 | 1800 秒 = 30 分钟 | `run-factory-eval.sh` 的 `GRADE_TIMEOUT` |
| 并发 | 20，允许 1–20 | `run-factory-eval.sh` 的 `CONCURRENCY` |
| 模型 | `glm-5.3` | `run-factory-eval.sh` 的 `MODEL` |
| 模型接口 | 由部署方提供 | 在本地 `CDB_MODEL_ENV_FILE` 中设置 `ANTHROPIC_BASE_URL` 与 `ANTHROPIC_AUTH_TOKEN`；配置文件不入库 |
| 题目目录 | `delivery/cvefactory-verified-40-20261026/tasks` | `run-factory-eval.sh` 的 `TASKS` |
| 构建 / 测试 / 补丁 / restart | 3600 / 每步 900 / 900 / 120 秒 | `cvefactory/grader.py` 内部有界步骤 |

Agent 时间与 turns 同时生效，先到先停。turns 是 Claude CLI 的 assistant turn：
一次模型回复算一轮，同一轮里的多次工具调用仍算一轮，不是工具次数上限。
历史 pilot 的 4 小时是当时命令显式指定的 `timeout_sec=14400`，
不是当前默认。某些任务 `metadata.yaml` 中虽有 `timeout_sec/max_turns`，当前
`run_agent`/`run_batch` 并未读取它们作为逐题覆盖值；实际值看
`agent-result.json.launch` 与 Agent command。

超时后 runner 尝试停止本次 scoped exec、冻结实际交付；批量入口可以判这份
已冻结交付，但 Agent timeout 状态仍保留。外层 runner 超时/缺失结果属于
pipeline 错误，不能复用旧 reward。每轮实验使用新结果目录。

## 8. 启动、跑前检查与单独复验

```bash
cd /path/to/CyberDockerBench

# 跑前真实下载、镜像、DinD 和 Docker build 检查；不启动模型
bash ../.cursor/skills/cdb-worker-preflight/scripts/preflight.sh

# 批量跑题。不传目录时，结果落在 runtime/cvefactory-YYYYMMDDHHMM/<题号>/
# 调整上限时编辑 run-factory-eval.sh 的固定默认值，不传 CDB_* 变量
./run-factory-eval.sh runtime/cvefactory-202610272307

# 跨模型评测显式指定模型；SSH 启动路由只透传模型名，不转发凭据
CDB_MODEL=deepseek-v4.1-flash ./run-factory-eval.sh runtime/cvefactory-<新批次>
```

单题入口：

```bash
python3 harness/run_agent.py --task <任务目录> --results <新结果目录> \
  --model <endpoint-model-alias> --max-turns 50 --timeout 18000
```

对已存在的冻结 bundle 单独复验，可用 `harness/run.py grade` 的显式 `--stage`，
或由 controller 通过 `FamilyRegistry` 与 `harness.execution.execute_grade`
调用 `GradeRequest(task, results, stage=<delivery>)`。
必须以 `bundle/delivery` 为 stage，不能拿 Agent 正在修改的 workspace 或宿主
成功日志替代。正式复验使用新的结果目录，避免覆盖原始证据。

独立预检也检查实际 sandbox 挂载、Agent UID/私有 socket、只读网络插件及
inner Docker 配置；清理失败和探测超时会使预检失败并留下结构化证据。

跑前检查不承诺特定老版本包、第三方 key、特定基础镜像一定存在，也不证明
模型 API、Agent 交付或判分会成功；这些以当次真实记录为准。默认预检不启动
模型；真实 Claude streaming/tool smoke 需要独立的显式 opt-in，不能由
`claude --version` 或普通网络探测替代。
