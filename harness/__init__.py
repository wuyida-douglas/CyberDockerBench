"""CyberDockerBench harness: 最小通用 docker 合成评测 harness。

参考 Terminal-Bench terminus-2 的 mono-tool 设计：
单一 shell 交互 + 结构化 JSON 协议 + 结果驱动判分。

5 个核心组件：
- task_loader:       任务包格式加载器
- container_manager: 容器生命周期管理器（DinD via docker socket）
- shell_channel:     单一交互通道（tmux-based shell）
- protocol_parser:   结构化响应协议 + 宽容解析器
- graders/:          按题型定制的判分器
"""

__version__ = "0.1.0"
