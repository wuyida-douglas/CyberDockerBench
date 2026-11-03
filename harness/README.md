# CyberDockerBench Harness（历史设计说明）

> 当前多题型插件接口、并行开发约定和可用命令见根目录 `README.md`。
> 本文保留早期设计，部分路径和 Docker 拓扑已经变化，不作为功能现状证明。

最小通用的 docker 合成评测 harness（方案γ §5，参考 Terminal-Bench terminus-2）。

**三原则**：准确性（支持所有 5 类题型的 docker 构建）/ 简洁性（单一 shell + JSON 协议，无自定义工具）/ 通用性（所有题型共用同一个 harness，差异只在任务包内容）。

## 架构

```
模型 (LiteLLM)
   │  prompt: instruction + terminal_state
   │  response: {analysis, plan, commands[], task_complete}
   ▼
┌─────────────────── 宿主机 (agent 控制循环) ───────────────────┐
│  agent_loop.py                                               │
│    ├── task_loader.py      任务包加载 (instruction/metadata)  │
│    ├── protocol_parser.py  宽容 JSON 解析 + 轨迹 jsonl        │
│    ├── shell_channel.py    tmux keystrokes ⇄ pane 回显        │
│    └── container_manager.py 容器生命周期 (DinD via socket)    │
└──────────────────┬───────────────────────────────────────────┘
                   │ docker exec ... tmux send-keys / capture-pane
                   ▼
┌─────────────────── 工作容器 ("考场") ─────────────────────────┐
│  bash + tmux + docker CLI + git + curl + apt + pip (白名单)   │
│  /workspace  模型产出: Dockerfile / compose / run_*.sh        │
│  /materials  任务材料 (只读挂载)                               │
│  /var/run/docker.sock → 宿主机 docker daemon (DinD)           │
│  网络完全放开 (2026-10-24 决定)                                │
└──────────────────────────────────────────────────────────────┘

判分阶段（task_complete 或超时后）：
  tests/ 注入 /tests → graders/<题型>.py 在宿主机侧通过 docker CLI 判分
  → CDB_RESULT: {"reward": 0|1, "details": {...}}
```

## 快速开始

```bash
# 0. 构建工作容器镜像（只需一次）
bash harness/setup_workspace_image.sh

# 1. 跑一道题（Python API）
python3 - <<'EOF'
from harness.task_loader import load_task
from harness.agent_loop import run_episode
import litellm

task = load_task("tasks/<task_id>")

def llm(prompt: str) -> str:
    r = litellm.completion(model="anthropic/claude-...",
                           messages=[{"role": "user", "content": prompt}])
    return r.choices[0].message.content

result = run_episode(task, llm, trajectory_dir="trajectories/")
print(result.reward, result.verify_details)
EOF

# 2. 单元测试
cd /mnt/shared-storage-user/datafactory-share/wuyida/cyberdockerbench
python3 -m pytest harness/tests_unit/ -q
```

## 任务包格式

```
tasks/<task_id>/
├── instruction.md     # 任务描述（模型可见）
├── metadata.yaml      # task_type / cve_id / timeout / grader 配置（模型不可见）
├── materials/         # CVE 描述 / 仓库 URL / base commit（只读挂载进容器）
├── tests/             # test_func.py / test_vuln.py / gold poc（判分时才注入）
└── solution/          # oracle solution（仅调试用）
```

`metadata.yaml` 最小示例（CTF 题型）：

```yaml
task_type: ctf
cve_id: CVE-2024-XXXX
timeout_sec: 3600
max_turns: 200
memory_limit: 4g
cpus: 2.0
grader:
  port: 1337
  gold_exploit: gold_exploit.py
  flag_mode: env
```

## 6 类题型与判分逻辑（方案γ §4.2）

| task_type | grader | 验证逻辑 |
|---|---|---|
| `secbench` | `graders/secbench.py` | GOLD POC 在 vuln build 上触发 sanitizer、patched build 上不触发 |
| `exploit` | `graders/exploit.py` | 动态 flag（每次随机，防硬编码）；或 challenge-response（题目自带 challenge.py） |
| `webexploit` | `graders/webexploit.py` | 2×2 差分（vuln: func PASS + vuln 触发；patched: func PASS + vuln 不触发）+ GOLD POC 二层验证 |
| `bugfix` | `graders/bugfix.py` | test_func + test_vuln + **模型 patch 应用后** vuln 不触发且无回归 |
| `ctf` | `graders/ctf.py` | 动态 flag 注入，GOLD exploit 通过暴露端口拿到 flag |

## 防作弊设计（已实现的）

- **tests 判分阶段才注入**容器，agent 阶段模型看不到
- **动态 flag**（exploit / ctf 题型）：每次评测 `secrets.token_hex(16)`，硬编码无效
- **零智能底线**：空 workspace / 无 Dockerfile 一律 reward=0
- **差分验证**：patched 版本上 vuln 测试必须不触发（防误报/假环境）
- **轨迹落盘**：每轮 prompt/response/terminal 全量写 jsonl，可事后审计
- **compose 项目名隔离**：`docker compose -p cdb-<task>-<rand>`，防多题并发端口冲突
- 判分资源全部打 `cdb.task=<task_id>` label，teardown 时统一清理

## 已知限制（见 issues.md）

- 网络完全放开（用户 2026-10-24 决定），联网搜答案风险记入风险点汇总
- 挂 docker socket = 容器内等价宿主机 root，评测机需跑完即销毁
- challenge-response 模式依赖题目自带 tests/challenge.py，harness 不理解其语义

## 内网部署注意事项（PJLab）

1. **工作镜像构建**：`setup_workspace_image.sh` 用阿里云源 + 集群代理
   （`mirrors.i.h.pjlab.org.cn/ubuntu` 快照过旧与本地 ubuntu:22.04 冲突，
   `/repository/apt-jammy-proxy` 对 Packages 索引 504，均不可用）。
2. **DinD 子镜像构建的网络**：模型在工作容器里 `docker build` 实际走宿主机
   daemon，**不继承工作容器的环境变量**。harness 的 `build_image` 会自动注入
   `--build-arg HTTP_PROXY/HTTPS_PROXY`，模型 Dockerfile 里写 `ARG HTTP_PROXY`
   + `ENV http_proxy=$HTTP_PROXY`（**小写**，apt 不读大写）即可用代理。
3. **判分访问服务**：服务容器与工作容器平级，从工作容器访问目标服务要用
   **宿主网关 IP（/proc/net/route 读出）+ 映射端口**，不能用 localhost。
   grader 已封装 `host_gateway_ip()` 处理。
4. **基础镜像预拉取**：评测 worker 上建议预拉 `ubuntu:22.04` / `python:3.10`
   等白名单基础镜像，避免模型 build 时 docker pull 卡 Docker Hub 匿名限额。
