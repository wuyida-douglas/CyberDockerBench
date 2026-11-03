# cvefactory：自由调试与声明式重建验收

仅公开 `input/` 和任务说明进入考场；不读取 gold、私有测试或初始源码哈希来判分。

`src/` 可变且可能不完整。Agent 可通过普通 Git、下载、包管理器和 Docker
自由补全源码和依赖，最终工程不会被初始输入还原。不能替换成无关项目。

交付根目录包含 `docker-compose.yaml`、Compose 构建声明所需的全部 Dockerfile、
完整构建上下文和资产、`solution.sh`、`tests/test_func.py`、`tests/test_vuln.py`、
`tests/run-tests.sh`。Dockerfile 不要求位于根目录，也不要求名为 `Dockerfile`；
每个 build 服务的 context 必须可解析，Dockerfile 按 context 内路径定位。
导出时以 `docker compose config --format json` 解析声明，检查构建上下文、
Dockerfile、additional contexts、bind、env_file、configs/secrets 的路径闭包。
source 轨再执行 `docker compose build --no-cache` 验证真实构建，不能仅递归
搜索 Dockerfile 文件名。
主服务名是 `client`。controller 只冻结声明式工程，不提交正在运行的镜像。

判分只使用 agent 测试：声明式工程在新 DinD 构建 vulnerable；`test_func`
通过且 `test_vuln` 失败后才执行 `solution.sh`，在同一 client 内打补丁、
重启并再次运行测试。fixed 不重建镜像。这一差分通过即为 `reward=1`。

判分把冻结测试复制到 tester 的 `/tmp/cdb-tests`，默认执行
`sh /tmp/cdb-tests/run-tests.sh vulnerable|fixed`；`solution.sh` 与工程资产
复制到 client 的 `/tmp/cdb-solution` 后执行。无需重建 client 来挂载测试或补丁。
可用 `cdb.test_service` 选择 tester；自定义 `cdb.test_command` 的环境变量
`CDB_TEST_PHASE` 标记当前漏洞/修复阶段。不把应用复制到第二个 `/app`。

`python3 harness/run_agent.py --task tasks/<id> --results <dir>` 跑单题。
`python3 harness/run_batch.py --tasks <manifest-or-directory> --results <dir>`
默认 20 并发，输出 `summary.json`、逐题结果和轨迹。私有
`goal2_recover.py`、`goal2_batch.py`、`cvefactory_grader.py` 与 `/app` 哈希
重建不属于当前运行路径。
