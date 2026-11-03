# CyberDockerBench

面向容器环境合成、漏洞复现与修复的评测框架。共享 Agent/Docker 运行能力，
按 **task family（题型实现）** 扩展任务契约和判分器。

当前已接入 CVE-Factory、CyberGym 和 WebExploit。仓库只包含评测代码与通用
管线说明；运行结果、历史轨迹、题目包、私有 gold、参考答案和模型配置均不
纳入 Git。运行前需在本地准备题目目录、NVMe worker 和 Docker 镜像。

## 快速开始

依赖 Python 3.10+、PyYAML、pytest、Docker 与 Compose。实际跑题和判分必须在
已配置的 NVMe worker 上执行，不能在开发机直接启动评测 Docker。

```bash
python3 -m pytest harness/tests harness/families/webexploit/tests -q
bash -n run-*.sh
```

模型凭据保存在**本地且不入库**的配置文件中，通过 `CDB_MODEL_ENV_FILE` 加载。
仓库不提供模型服务、凭据或可直接使用的默认 endpoint。

```bash
# 在本地创建 config/<name>.env，不要使用真实凭据以外的地方保存或分享它。
# 文件内容（<...> 替换为自己的部署信息）：
ANTHROPIC_BASE_URL=http://<your-model-endpoint>
ANTHROPIC_AUTH_TOKEN=<your-model-token>
ANTHROPIC_MODEL=<model-name>
CDB_MODEL=<model-name>
```

```bash
CDB_MODEL_ENV_FILE="$PWD/config/<name>.env" \
  ./run-factory-eval.sh runtime/<new-factory-batch>

CDB_MODEL_ENV_FILE="$PWD/config/<name>.env" \
  ./run-webexploit-eval.sh --tasks /path/to/tasks --results runtime/<new-web-batch>

CDB_MODEL_ENV_FILE="$PWD/config/<name>.env" \
  ./run-cybergym-eval.sh <new-cybergym-batch> 20 /path/to/task-list
```

同模型三家族批量入口是 `run-baseline-all.sh`；其中本地任务集、worker、网络
和并发配置需按部署环境调整。每轮必须使用新结果目录，不修改历史成绩。

当前判分器主要验证 family 的差分契约。`reward=1` 不等于独立安全审计已证明
漏洞修复语义正确；仍需检查实际漏洞测试、断言计数、真实项目来源和补丁行为。
例如全部跳过的漏洞测试或仅检查源码字符串不能构成可信的真实修复证据。

通用管线说明见 [docs/管线说明/overview.md](docs/管线说明/overview.md)。

## 1. 现在的结构

```text
cyberdockerbench/
├── tasks/<task_id>/
│   ├── metadata.yaml          # task_id / task_type / family（新题建议显式声明）
│   ├── instruction.md         # 公开说明，按题型约定使用
│   ├── input/                 # 公开材料
│   └── gold/                  # 私有答案；不能挂进 agent 沙箱
├── harness/
│   ├── task_api.py            # 稳定 API：TaskSpec / PrepareRequest / GradeRequest
│   ├── registry.py            # 扫描 plugin.json，自动发现 family
│   ├── execution.py           # 跨进程锁、结果规范化、原子写入
│   ├── run.py                 # 统一 families / inspect / prepare / grade 入口
│   ├── docker_sandbox.py      # 共享的每题独立 DinD 与 Agent 容器
│   ├── families/
│   │   └── cvefactory/        # 一个 agent 可独立负责的全部实现
│   │       ├── plugin.json
│   │       ├── plugin.py
│   │       └── README.md
│   ├── families/cvefactory/grader.py # 冻结交付的差分判分实现
│   ├── run_agent.py           # 已有 CVE-Factory agent runner，保留兼容
│   └── tests/                 # 不依赖 Docker 的 API 契约测试
├── results/<batch>/           # 新生成的结果；不写回任务目录
└── archive/                   # 历史结果，不是当前运行入口
```

### 三个概念不要混为一谈

- **source_bench**：题目来自哪个数据集，例如 CyberGym。
- **task_type**：题目做什么，例如 `secbench`、`bugfix`、`ctf`。
- **family**：选择哪套输入、workspace 和判分实现，例如 `cvefactory`。

同一 family 可以处理多个来源；同一 task_type 也可以有不同 family。
新任务建议在 `metadata.yaml` 显式写 `family: <name>`。旧题没有该字段时，
通过 manifest 的 `aliases` 兼容：目前 `task_type: bugfix` 映射到 `cvefactory`。

## 2. 多 agent 并行开发的核心约定

**一个 family 一个目录，一个 owner；共享核心单独评审。**

开发普通题型时，不需要修改注册表，也不需要把其他题型放进一个大
`if/elif` 中。每位 agent 只新增或修改自己负责的：

```text
harness/families/<family>/    # 插件、辅助模块、题型说明、题型测试
tasks/<family>-*/             # 仅在该 agent 被分配题目时修改
```

多个 family 都可以有 `helpers.py`。插件以独立包加载，可以使用相对导入，
不会因文件名相同而互相覆盖。

### 文件所有权

| 范围 | 谁能改 | 规则 |
|---|---|---|
| `harness/families/<自己的 family>/` | 该 family 的 owner | 独立开发、测试、提交 |
| `tasks/<分配给自己的题目>/` | 对应题目 owner | 不覆盖别人的输入和 gold |
| `task_api.py` / `registry.py` / `execution.py` / `run.py` | 核心 owner，经接口评审 | 不为单题硬编码分支 |
| `docker_sandbox.py` / agent 镜像 | 核心 owner，经运行时评审 | 影响所有 family，先跑集成测试 |
| `results/` / `runtime/` | 各次运行自动创建 | 不作为插件代码合并，不手工互相清理 |

**重要：这个目录目前不是 Git 仓库。**代码接口不能替代版本控制。若仍直接
共用该目录，必须按上表分配 owner，不能多个 agent 同时编辑共享文件。
更稳妥的做法是先初始化 Git，每位 agent 使用独立 branch + worktree，各自
运行测试，再按 family 目录合并；如果暂时不能初始化 Git，各自在独立副本或
`CDB_FAMILY_PATH` 指向的外部目录中开发，最后按目录合并。

### 不打架需要同时做到两件事

1. **代码不打架**：不同 family 不共用可变注册表，不互相 import 私有实现，
   不改别人的任务目录。
2. **运行不打架**：每个 `(结果目录, task_id)` 是独立 attempt，有独立输出和
   跨进程锁；Docker 名称必须包含 `request.attempt_id`，不能只用题号。

统一入口会让不同任务并发执行，同一 attempt 拒绝重复执行。已有结果默认
不覆盖；确实重跑时使用 `--force`，或者优先换一个结果目录保留证据。

## 3. 接口

接口定义见 `harness/task_api.py`。每个插件实现：

- `validate_task(task) -> list[str]`：只检查，返回错误列表；空列表表示有效。
- `prepare_workspace(request)`：创建公开 workspace；不得把 gold 暴露给 agent。
- `grade(request) -> Mapping`：判分并返回至少包含 `reward: 0 | 1` 的结果。

插件无需自己写公共字段或加锁。`execution.py` 统一补充：

```json
{
  "schema_version": 1,
  "task_id": "...",
  "family": "...",
  "task_type": "...",
  "source": "gold | submission | explicit",
  "reward": 0,
  "status": "passed | failed | error | invalid | skipped_existing"
}
```

原 grader 的 `checks` 等详细证据保留在结果里。插件抛异常表示
“grader/基础设施错误”，统一记录为 `reward=0, status=error`；不要把它和
“题目语义上未通过”混为一谈，也不要用 `reward=1` 掩盖错误。`status` 是
执行状态，`reward` 是得分；其他状态值不被当作成功，汇总只看 `reward=1`。
插件属于受信任的评测代码，不是给做题 agent 执行的沙箱。

### `TaskSpec`

不可变的任务描述，含 `path`、`task_id`、`family`、`task_type`、`metadata`。
插件不能修改它，也不能在运行中改写原任务包。

### `PrepareRequest`

- `task`：当前题目。
- `workspace`：要新建的 agent 工作区。
- `input_archive`：可选的已校验公开输入副本，绝不是 gold 路径。

默认实现复制 `input/` 和公开 instruction，拒绝逃逸出输入目录的 symlink。
目标已存在时拒绝删除。需要特定交付契约的 family 可以覆盖，如
`cvefactory` 复用原有 `stage_workspace()` 和 `TASK.md`。

### `GradeRequest`

- `task`：当前题目。
- `results`：本次 batch 的结果根目录，实际输出为 `results/<task_id>/`。
- `stage`：`None` 表示私有 gold；提交判分必须是显式的冻结目录。
- `source`：`gold`、`submission` 或 `explicit`。
- `keep_data`：是否保留 DinD 数据卷。
- `options`：family 自己定义并校验的参数。
- `attempt_id`：由结果目录和题号生成的 16 位命名后缀。
- `out_dir`：当前 attempt 的输出目录。

**提交目录必须是不可变快照。**不要让 grader 读取 agent 仍在修改的
workspace。CVE-Factory 使用 `harness/bundle.py` 冻结声明式工程，判分只读取冻结包。

## 4. 新 family 的最小实现

`harness/families/example/plugin.json`：

```json
{
  "api_version": 1,
  "family": "example",
  "description": "Example task family",
  "aliases": ["example-task-type"],
  "entrypoint": "plugin.py",
  "factory": "create_plugin"
}
```

`family` 必须等于目录名，使用小写字母、数字和下划线。`aliases` 只用于旧
`task_type` 路由；新任务直接写 `family`。不同插件不能抢同一个 family/alias。

`harness/families/example/plugin.py`：

```python
from harness.task_api import TaskFamily


class ExampleFamily(TaskFamily):
    family = "example"

    def validate_task(self, task):
        return [] if (task.path / "input").is_dir() else ["missing input/"]

    def grade(self, request):
        # 调用本 family 的实际判分实现，并返回详细证据。
        # 不使用全局项目名；资源名包含 request.attempt_id。
        return {"reward": 0, "status": "failed", "checks": {}}


def create_plugin():
    return ExampleFamily()
```

这个片段只展示接口形状，**不是有效题目或可用判分器**。正式接入至少需要：
有效的公开输入、独立 gold、真实漏洞/功能检查、超时与清理、一份能通过的
gold smoke test 和一份不应通过的负例。

复杂实现可以拆成 `<family>/grader.py`、`<family>/workspace.py`，从
`plugin.py` 使用 `from .grader import ...`。公共代码只放在真正共享的核心，
不要为了复用几行代码让两个 family 相互依赖。

## 5. 命令

在本目录执行，依赖 Python 3.10+ 和 PyYAML；真实 Docker 验收还需要已配置
的 Docker daemon。`inspect` 和契约测试不需要 Docker。

```bash
# 查看已接入的 family；未接入的数据目录不会在这里出现
python3 harness/run.py families

# 检查所有任务：未接入的题型会明确列出，返回非零
python3 harness/run.py inspect

# 只检查某道题
python3 harness/run.py inspect --only cvefactory-cve-2014-1944

# 创建新的公开工作区，不启动 agent，不删除已有 workspace
python3 harness/run.py prepare \
  --results results/dev-prepare \
  --family cvefactory --only cvefactory-cve-2014-1944

# 并行验收私有 gold；失败或无效返回非零
python3 harness/run.py grade \
  --results results/dev-gold --family cvefactory --concurrency 2

# 只跑一道，使用独立的每题 DinD（默认）
python3 harness/run.py grade \
  --results results/dev-gold-one --family cvefactory \
  --only cvefactory-cve-2014-1944 --concurrency 1

# 已可信的 gold 可选择宿主后端；agent 提交不要这么做
python3 harness/run.py grade \
  --results results/dev-gold-host --family cvefactory \
  --only cvefactory-cve-2014-1944 --set backend=host

# 判一个显式冻结的提交，不自动挑选某个旧目录
python3 harness/run.py grade \
  --results results/dev-submission --only cvefactory-cve-2014-1944 \
  --stage /absolute/path/to/frozen/package

# 已按 <root>/<task_id>/ 排好的冻结提交，可以批量指定
python3 harness/run.py grade \
  --results results/dev-submissions --source submission \
  --submission-root /absolute/path/to/frozen-submissions \
  --family cvefactory --concurrency 2
```

`--force` 允许覆盖已有 `result.json`，但同一目录下的 grader 子结果和日志
可能有旧入口的残留。正式实验建议每次使用新的 `results/<batch>`，保留完整
证据，不反复覆盖。

**统一 `grade` 不是 Agent 推理入口。**它只验收 gold 或冻结提交。现有
CVE-Factory 的 agent 执行与监控仍使用：

- `harness/run_agent.py`：运行 agent，并保留原有 workspace/recovery 行为。
- `harness/bundle.py`：冻结提交。
- `harness/families/cvefactory/grader.py`：独立验收冻结提交。

这些旧入口继续保留；新 family 不要求复制它们的 500 行批处理逻辑。后续若
要统一 Agent runner，应在 `TaskFamily` 上新增版本化扩展，而不是把
`stage=None` 当成任意 workspace 来判分。

### 独立开发目录

默认加载 `harness/families/`。额外目录用冒号分隔：

```bash
CDB_FAMILY_PATH=/work/agent-a/families:/work/agent-b/families \
  python3 harness/run.py families
```

单次命令也可传全局参数 `--family-path /work/agent-a/families`；它与内置
目录叠加，不替换内置目录。相同 family 或 alias 冲突会报发现错误，不会
悄悄按加载顺序覆盖。

## 6. 测试与接入门槛

```bash
python3 -m unittest discover -s harness/tests -v
python3 -m compileall -q harness
python3 harness/run.py families
python3 harness/run.py inspect --only cvefactory-cve-2014-1944
```

测试覆盖：旧别名路由、外部插件发现、family 私有相对导入、公开输入隔离、
结果字段规范化、同 attempt 锁、不同 attempt 并行、损坏插件隔离。

每位 family owner 交付时应提供：

1. `plugin.json`、`plugin.py`、必要的辅助模块和 `README.md`。
2. 说明输入、输出、gold 验证阶段、超时、Docker 资源命名和清理方式。
3. 自己的单元测试；不得修改共享测试来逃避失败。
4. 至少一条 gold 端到端命令及真实结果，不能只有 mock 测试。
5. 至少一条负例，证明不是空交付或任何补丁都 reward=1。
6. 两道题并行、同一道题在两个结果目录并行的资源冲突检查。

## 7. 现有题型与迁移状态

| 任务/来源 | metadata 中的类型 | 新接口状态 | 可复用方向 |
|---|---|---|---|
| `cvefactory-*` | `bugfix` | **已接入** `cvefactory` | 现有四阶段 grader、冻结提交、DinD |
| `cybergym-*` | `cybergym` | **已接入** `cybergym` | 漏洞/修复双版本 sanitizer 差分与 PoC 验证 |
| `exploitgym-*` / `exploitbench-*` | `exploit` | 待实现 | 评估后复用 exploit 差分逻辑，注意镜像规模 |
| `exploitweb-*` | `webexploit` | **已接入** `webexploit` | 黑盒差分：重建 + 现场种旗 + PoC 补丁前后差分，见 `docs/管线说明/overview.md` 第 3 节 |
| `ctf-*` | `ctf` | 待实现 | 动态 flag、服务端口和超时控制 |
| `exploit` / `webexploit` 中的 exploit 语义相近者 | 各自类型 | 待评估 | 只有判分契约一致才合并 family |

`harness/README.md` 记录了早期“所有题型共用一个 harness”的设计，部分
路径和 Docker 拓扑与当前实现不一致；它是历史设计说明，不作为当前已接入
功能的证明。当前实际入口以本 README 和代码为准。

## 8. 仍需注意的运行边界

- 统一接口解决插件与结果隔离，**没有自动解决宿主 CPU、内存、磁盘、镜像
  拉取额度或网络拥塞**。按 worker 的内存、NVMe 和预检结果确定并发。
- 不挂载宿主 Docker socket 给做题 agent；私有 `gold/` 和判分测试仍必须
  留在 agent 不可见的评测侧。
- 每个 family 自己定义 Docker 名称时必须包含 `request.attempt_id`。
- 不允许 `down --remove-orphans` 清理别人或整个 daemon 的项目；只能操作
  自己 attempt 拥有的资源。
- `keep_data` 是调试选项，正式运行结束应按 family 的约定清理。
- 跨进程锁覆盖同一个输出 attempt；它不限制任意外部脚本的 Docker 操作。
- 损坏且未选中的插件不会阻止其他 family 加载；`families` 会报告发现问题，
  使用前应先消除这些报告。

旧 `cvefactory` 的运行时代码、目录布局和判分语义均保留。本次没有删除
历史题目、结果或运行时文件。
