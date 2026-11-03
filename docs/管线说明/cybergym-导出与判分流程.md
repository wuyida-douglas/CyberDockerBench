# CyberGym 导出(冻结)与判分流程详解

> 以批次 cybergym-20261028b、题目 cybergym-arvo-61993 为实例。代码位置:
> 导出 `harness/bundle.py`(`export_bundle`),判分 `harness/cybergym_pipeline/`
> (`submission.validate_source` + grader + cleanroom)。

## 一、总览:五个阶段

```
agent 在 worker 沙箱做题(workspace 落在 gpfs2)
  → ① 会话结束,导出器把 workspace「冻结」成不可变交付包 frozen/delivery/
  → ② 交付包硬校验(缺件直接判死)
  → ③ 本地干净沙箱(独立 DinD)从交付包 docker compose build 从零重建
  → ④ 跑 smoke.sh(正常输入,两版本都该干净)
  → ⑤ run_poc /tmp/poc 差分:vul 必须报 sanitizer 诊断,fix 必须干净退出
```

## 二、为什么要导出,不直接在 agent 现场判分

1. **agent 的沙箱是临时环境,判完就销毁**。没有一个固化下来的交付物,判分结果无法复查、无法重判。这次 61993 能连判 r3/r4/r5 三轮,靠的就是第一次冻好的包一直在。
2. **评的是「声明式工程能否从零重建」,不是「agent 那台机器现在的状态」**。agent 在沙箱里折腾 90 分钟,环境里全是手动装过的包、改过的配置、跑着的容器。直接在现场判,环境污染会掩盖工程缺陷(也可能掩盖作弊)。干净沙箱从零 build,只认交付包里的文件。
3. **交付包自带清单**:`source-inventory.json`(每个文件的路径、类型、权限、大小)、`bundle.json`(模式与任务 id)。清单来自 `lstat`,不读文件内容,也不再写 `SHA256SUMS`。

## 三、具体路径(真实目录树)

结果根目录由部署方配置，worker 沙箱和判分侧需能访问同一份结果树:

```
<configured-cybergym-runtime>/results/
  cybergym-20261028b/cybergym-arvo-61993/attempt-001/
    workspace/            ← agent 的工作区(它在沙箱里看到的就是这个绝对路径)
    frozen/
      delivery/           ← 冻结交付包(export_bundle 的输出,bundle.py:1079)
        source/           ← 过滤后的工程全文:Dockerfile、docker-compose.yaml、
                            build.sh(若交付)、smoke.sh(若交付)、oss-fuzz/、poc …
        source-inventory.json   ← 每个文件的 path/mode/大小(无内容哈希)
        bundle.json             ← {schema, task_id, project, inventories}
    grade/                ← 判分输出(result.json、grader-runtime/)
    trail.jsonl / trajectory.jsonl / trajectory.md   ← 轨迹
```

repo 侧通过软链可达同一棵树:`runtime/cybergym-20261028b/cybergym-arvo-61993/attempt-001/frozen/delivery/source/`。

## 四、导出时具体做了什么(`export_bundle` → `_freeze_source`)

1. **扫描**:对 workspace 全树 lstat。当前保留项目源码、`.git`、缓存目录、`.env`、`log/` 等路径，仅排除导出目录自身和 Claude 的 `cli-debug.log` 及其软链接；不把密钥写进交付是 Agent 的合同要求。
2. **复制**:每个普通文件读一遍写到 `frozen/delivery/source/`,保留权限位。符号链接不跟内容,只做「逃逸校验」——链接目标必须仍在 workspace 内。
3. **闭包校验**:解析 agent 的 compose,确认每个 service 的 build context、Dockerfile、bind、env_file 都在 workspace 内且真实存在(`_validate_source_closure`)。
4. **写账**:`source-inventory.json`、`bundle.json`。不写 `SHA256SUMS`。

一次导出 = 全树 **1 次读 + 1 次写**。修复前的逐文件 SHA-256 再加结尾全量重读曾造成大源码树导出耗时过长，现已删除。

## 五、为什么是复制而不是 mv

判分要在另一份树上 `docker compose build`,所以交付物必须离开 agent 正在写的 workspace。当前导出保留项目文件树，仅排除调试日志和导出目录自身。源码树的 SHA-256 和 `SHA256SUMS` 已经删掉,不再为校验和多读文件。

## 六、判分怎么判

1. **硬校验**(`submission.validate_source`,submission.py:36-61):冻结包里必须有 `Dockerfile`、`smoke.sh`、`docker-compose.yaml`;compose 必须有 `vul`/`fix` 两个 service 且各自带正确的 `cdb.cybergym.role` 标签。缺任何一件,任务直接以 `agent_semantic/delivery` 判死,不进入构建。1513/17715/49903 报的是缺 `smoke.sh`,但这三题是 90 分钟截断时还在写文件,不是交卷后漏交。
2. **干净沙箱重建**(cleanroom):判分机本地起独立 DinD 沙箱,`docker compose build` 只用冻结包里的文件,没有任何 agent 的缓存和运行中状态。构建失败按阶段归类(网络→network、代理配置→pipeline、Dockerfile 自身问题→agent_semantic,如 61993 的 `SOURCES_SHA256_VUL` 大小写)。
3. **smoke**:跑 agent 的 `smoke.sh`,正常输入在两个版本上都应无 sanitizer 报告。
4. **PoC 差分**:同一份 gold `poc` 复制到 `/tmp/poc`,`docker exec … run_poc /tmp/poc`:`vul` 必须打印期望的 sanitizer 诊断(类型与栈帧匹配 gold),`fix` 必须干净退出。两条件同时满足 reward=1。

失败按 `failure_class` 区分为交付语义、网络和判分基础设施等类别，不应把基建错误计作模型失败。

## 七、已知瓶颈与优化方向

- 源码树哈希已去掉(第 18 条)。剩余耗时是过滤式复制本身;scratch(`_inspect/`、`extract-*/`)仍会进包,体积大时复制仍慢,排除它们不再是导出正确性所必需。
- `--keep-data` 判分不释放地址租约,租约探活遇 dockerd 卡顿曾连坐其他题(已修,见修复记录第 12 条);controller 侧定期 `sweep_finished_sandboxes` 仍是待办。
