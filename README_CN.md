# Aegis OS (`aegis-os`)

**[English](README.md) | [简体中文](README_CN.md) | [Aegis OS 官网](https://heurion.org/aegis-os/) | [使用教程](https://heurion.org/aegis-os/tutorial/) | [论文一 (arXiv:2611.08516)](https://arxiv.org/abs/2611.08516) | [论文二 (DOI: 10.5281/zenodo.24170505)](https://doi.org/10.5281/zenodo.24170505) | [技术博客](https://heurion.org/blog) | [云端控制台与 Pro ($29/月)](https://heurion.org/aegis-cloud/dashboard) | [边界审批台](https://heurion.org/aegis-cloud/approve)**

**面向自主编程 Agent（`claude`、`opencode`、`agy`、`hermes`、`codex`）的事务型多租户 Agent OS 运行时 —— 父进程内核沙箱、CoW 影子工作区、A2A 协同与 SHA-256 防 TOCTOU 篡改审批。**

> **强制等级**：`aegis-os install` = **advisory**（进程内 Hook / MCP / 规则；缓解弹窗疲劳，但不是安全边界）。`aegis-os run -- <agent>` = **enforced**（Aegis 作为父进程 OS 监管器；Linux `bwrap --bind-fd` + macOS Seatbelt 内核隔离 + CoW 影子工作区 + 分离式 `.git` 垫片 + L4/L7 `$AOS_SECRET_*` 边界密钥注入代理）。`aegis-os run --isolated` / Aegis Cloud = **isolated**（64GB 云端沙箱 / microVM）。

![Rust](https://img.shields.io/badge/Rust-1.80%2B%20(2021)-orange.svg)
![MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-blue.svg)
![A2A](https://img.shields.io/badge/Protocol-Google%20A2A-34A853.svg)
[![arXiv](https://img.shields.io/badge/arXiv-2611.08516-b31b1b.svg)](https://arxiv.org/abs/2611.08516)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24170505.svg)](https://doi.org/10.5281/zenodo.24170505)
[![Blog](https://img.shields.io/badge/Blog-heurion.org%2Fblog-0A7D52.svg)](https://heurion.org/blog)

---

## 这是什么

- **终结 `--yolo` 凭据裸奔** — 放心运行 `claude --dangerously-skip-permissions`、`codex --full-auto` 或 `agy`，不再把 `~/.ssh`、`~/.aws`、`.env` 与任意外网暴露给被注入的命令；运行 `aegis-os audit-me` 即可 5 秒体检本机风险。
- **砍掉 90.7%–97.9% 的授权确认弹窗** — Agent 在亚毫秒级写时复制（CoW）影子工作区内零逐条确认全速运行，只有落盘到宿主与跨边界操作需要人工审批或 TTL 租约。
- **多 Agent 并行不再静默互踩** — 用任务级文件锁、四级 LCS 自动归并（**98.7%**）与 `Aegis-OS-Verified` 提交审计凭证，替代笨重的 `git worktree` 和存在 **41.2%** 静默覆盖率的共享目录直写。

Aegis OS 把授权边界从「单次工具调用」提升为**事务型工作区边界**。在 enforced 模式下，每个 Agent 获得独立的写时复制（CoW）影子工作区、内核沙箱、身份绑定的出站代理，以及策略 / 审批 broker。工作区内 Agent **零逐条确认**运行；只有落盘到宿主与跨边界操作需要人工审批或 TTL 租约。

它同时替代 Git 分支（滞后冲突爆炸、重型 worktree）与共享目录直写（无协调多 Agent 基准中 **41.2%** 的并发写入被静默覆盖）。它不局限于代码：代码、文档、数据流水线、二进制资产与跨应用状态共用同一套 shadow / claim / verify / commit 内核，领域差异由 profile 决定。**Heurion 2.0 是第一个第一方参考应用。**

## 安全模型

| 模式 | 启动方式 | 强制点 | 能防住什么 | 状态 |
|---|---|---|---|---|
| **Advisory** | `aegis-os install` 后直接运行 Agent | Hook / MCP / 规则 | 诚实 Agent 的误删、误读、授权疲劳 | ✅ 可用（兼容模式） |
| **Enforced** | `aegis-os run -- claude`，或 `aegis-os install --enforce` 后直接运行 `claude` | 父进程内核沙箱（`bwrap` / Seatbelt）+ 双令牌 Broker + L4/L7 出站代理 | Prompt 注入与项目脚本木马（`V1`–`V6`）；宿主越界写入；SSH/Keychain/API Key 窃取；配置与 `.git/config` 远程代码执行；提交时 TOCTOU 掉包 | ✅ 已在 Linux（`bwrap --bind-fd`）与 macOS Seatbelt 上完整实测验证 `claude`、`opencode`、`agy`、`hermes` |
| **Isolated** | `aegis-os run --isolated -- claude` / Aegis Cloud | 远程 64GB 云端工作节点 / microVM | 不可信仓库、多租户团队、宿主级隔离 | ✅ 64GB 云端沙箱已上线；本地 microVM 在 Phase 4 |

**Advisory 不是安全边界。** Hook 和 MCP Server 由 Agent 在开发者自身 UNIX UID 下加载：一旦执行潜伏恶意逻辑的项目脚本（如 `python3 scripts/verify_env.py`），即可绕过正则 Hook、覆写 `.claude/settings.json` / `.mcp.json` / `opencode.json`、借 `git status` 触发 `.git/config` `core.fsmonitor` 代码执行，或经裸 Socket 外泄密钥。Enforced 模式下，Aegis 在 `execve()` 启动子进程前完成 CoW 影子工作区、内核命名空间、只读配置锁、分离式 `.git` 视图、L4/L7 网关与双令牌 `SessionBroker` 装配，Agent 无法绕过或退出。

已实测验证的生产级 CLI 客户端：**Claude Code（`claude`）、OpenCode（`opencode`）、Google Antigravity（`agy`）、Nous Hermes（`hermes`）与 Codex（`codex`）**。在 macOS Seatbelt 下，`aegis-os run` 会自动为 OpenCode 与 Hermes 注入单端口回环绑定及会话随机密钥，并阻断 `SecurityAgent` Keychain 鉴权弹窗（`exit 44` 垫片），同时保留系统 `com.apple.trustd` TLS 证书校验。

## 快速开始

### Advisory 集成

```bash
brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git
brew install aegis-os
aegis-os install
aegis-os audit-me            # 5 秒本地凭据裸奔风险与弹窗疲劳体检（加 --share 导出 Markdown 分享卡）
```

这会为检测到的 Agent 接入 Hook / MCP / 规则，降低授权疲劳，但不承诺抵抗被攻陷的 Agent。

### Enforced 运行时（Linux `bwrap` & macOS Seatbelt）

```bash
aegis-os install --enforce   # 创建 ~/.aegis/bin shim
aegis-os run -- claude       # 或 opencode / agy / hermes / codex

# 查看 JSON / Unified Diff，并通过 SHA-256 哈希锚定提交回宿主机
aegis-os diff --json
aegis-os commit --expected-diff-hash <sha256>
```

Enforced 模式提供：

- **宿主项目只读保护**：所有写入落在每会话独立的 CoW 影子工作区（APFS `clonefile`、`btrfs` `FICLONE`、`ext4` 轻量工作树拷贝）。
- **宿主敏感凭据与 Mach IPC 封堵**：内核级遮蔽 `$HOME` SSH/云凭据，封堵 Keychain CLI / `SecurityAgent` 弹窗、`launchctl` 与 `osascript`；对 `.claude/settings.json`、`.mcp.json`、`opencode.json`、`.gemini/antigravity-cli/settings.json`、`.hermes/config.yaml` 施加单文件只读挂载锁。
- **双平台分离式 `.git` 视图 + `.aegis-bin/git` 加固垫片**：在 Linux 与 macOS 上均将宿主机 `.git` 对象库只读透传（500 MB 打包 Git 仓库在 APFS 上节省 **99.05%** 物理磁盘占用），配合独立会话 `GIT_INDEX_FILE` 并强制锁定 `core.fsmonitor=false` / `core.hooksPath=/dev/null`。
- **L4/L7 双平面出站网关**：模型 API 流量经本地 L7 Base-URL 反向代理（`ANTHROPIC_BASE_URL`、`OPENAI_BASE_URL`、`GOOGLE_GEMINI_BASE_URL`）执行 64 KiB 出站 DLP 扫描并在宿主边界注入真实密钥（沙箱内仅见 `$AOS_SECRET_*` 占位符，**零 TLS MITM 证书破坏**）；常规 HTTPS 走 L4 `CONNECT` 域名白名单。
- **双令牌权限分离 `SessionBroker` 与冻结暂存区（Frozen-Stage）SHA-256 提交门禁**：严格隔离 `agent.token` 与 `human.token`，对 Diff 中的 VT100 CSI / Unicode Bidi 控制字符进行转义防欺骗，落盘前快照至 `commit_frozen_stage` 并运行 6 大 `DomainProfile` 校验器（`code`、`docs`、`data`、`binary`、`app_state`、`memory`）。
- **Fail closed**：缺少 `bwrap`/`sandbox-exec`（或 Ubuntu 24.04 AppArmor 限制未配置 profile）、代理或 broker 时直接拒绝启动，绝不静默降级。

会话与可观测控制：`aegis-os status` · `aegis-os diff --json` · `aegis-os verify` · `aegis-os commit --expected-diff-hash` · `aegis-os discard` · `aegis-os publish` · `aegis-os approvals` · `aegis-os why` · `aegis-os a2a board` · `aegis-os policy watch` · `aegis-os memory ui` · `aegis-os app list` · `aegis-os audit-me --share`。

当前限制：

- **macOS `cwd` 与 Linux 路径重映射差异**：Linux 通过 `bwrap --bind-fd` 将 CoW 影子工作区原位挂载回原宿主路径；macOS Seatbelt 将影子目录作为 `cwd` 并将宿主仓库只读挂载（macOS 完整 FUSE/NFSv3 路径重映射在 Phase 4）。
- **Ubuntu 24.04+ 非特权 userns 限制**：Ubuntu 24.04 默认开启 `kernel.apparmor_restrict_unprivileged_userns=1`；若未安装 `/etc/apparmor.d/bwrap`，`aegis-os run` 会 fail-closed 并打印配置指引。
- **非模型 HTTPS 审计范围**：模型 API 流量走本地 Base-URL L7 反向代理（64 KiB DLP + 密钥注入）；普通白名单第三方 HTTPS 走 L4 `CONNECT` 域名过滤，不做 TLS MITM 解密。

### 其他安装方式

```bash
# 一键签名安装（Linux & macOS）
curl -fsSL https://heurion.org/aegis-cloud/install.sh | sh

# 源码编译
git clone https://github.com/heurion-org/aegis-os.git && cd aegis-os
cargo install --path crates/aos-cli
aegis-os install
```

## 核心能力

- **事务型 CoW VFS** — 0.42ms 元数据派生；1,000 文件工作区 6.28ms / 15.6ms；四级 LCS 自动归并与领域预检门。
- **内核沙箱与出站边界** — Linux `bwrap` 与 macOS Seatbelt enforced launcher；敏感凭据遮蔽；模型 API Base-URL L7 反向代理（DLP + `$AOS_SECRET_*` 注入）与 CONNECT 域名 allowlist。
- **A2A IPC 与 CAS** — 同伴发现、层级任务、任务绑定文件锁、`artifact://sha256` 内容寻址接力。
- **Cedar 策略、租约与审计** — 效果级审批、TTL / 单次租约、`evidence_hash` 锁定、哈希链审计账本，以及 `Aegis-OS-Verified` Commit/PR 审计凭证。
- **云端 PaaS** — 多租户工作区、Git-to-PR、Scale-to-Zero 休眠、网页审批台。

## 关键基准

| 指标 | 结果 |
|---|---|
| V1–V6 绕过载荷失守率（30 项确定性载荷，macOS Seatbelt & Linux `bwrap`） | **0/30 (0.0%)** 对比 Advisory Hook **93.3%** · 厂商自带沙箱 **73.3%–83.3%** · `nerdctl` 容器 **80.0%** |
| 4 款真实生产 CLI Agent 仓库木马沦陷率（`claude`、`opencode`、`agy`、`hermes`，60 格矩阵 54 次真实云端 API 运行） | **0%**（`aegis_enforced`）对比 **100%**（`vendor_default`，含 Claude Opus）· 良性及多文件重构测试通过率 **100% (8/8)** |
| Enforced 内核沙箱启动延迟 | Linux `bwrap` **9.91 ms**（比 `nerdctl` 容器 221.53 ms **快 22.4 倍**）· macOS Seatbelt **20.38 ms** |
| 500 MB 打包 Git 仓库（`git repack -ad`）物理磁盘增量 | APFS **4.76 MB**（**节省 99.05% 物理磁盘**）· `btrfs` **0.00 MB** 净块增量 |
| 本地 L7 出站网关开销与 CLI TOCTOU / 终端转义门禁 | 回环 TTFT 仅 **+0.221 ms**（`0/40` 误报，`25/25` DLP 拦截）· **60/60 (100%)** 掉包攻击全部阻断（各类中位数 **7.54–7.92 ms**） |
| 授权弹窗削减（52 份真实会话，28,087 次工具调用）与多 Agent 归并 | 减少 **90.7%–97.9%** 弹窗 · 四级 LCS 自动归并 **98.7%** · 200 模块回滚 **8.68 ms** |

> 完整复现方法详见 [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md)（论文一多 Agent 与 VFS 基准）以及 [`paper2/ENFORCED_RUNTIME_BENCH_REPORT.json`](paper2/ENFORCED_RUNTIME_BENCH_REPORT.json) + [`scripts/p2_live/README.md`](scripts/p2_live/README.md)（论文二跨平台与真实 CLI Agent 评测套件）。

## 文档

- **Enforced Runtime 设计** — advisory / enforced / isolated 威胁模型、Effect 模型、阶段计划：[`docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md`](docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md)
- **详细架构** — 信任边界、核心 crate、工作区与合并模型、MCP/A2A 接口、领域 profile、云端 PaaS、基准与实施状态：[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **基准报告** — [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md) · [`paper2/ENFORCED_RUNTIME_BENCH_REPORT.json`](paper2/ENFORCED_RUNTIME_BENCH_REPORT.json) · [`scripts/p2_live/README.md`](scripts/p2_live/README.md)
- **论文一（事务型多租户 Agent OS · arXiv:2611.08516）** — [https://arxiv.org/abs/2611.08516](https://arxiv.org/abs/2611.08516)（[PDF](https://arxiv.org/pdf/2611.08516) · 本地副本：[`paper/aegis_os_arxiv_preprint.pdf`](paper/aegis_os_arxiv_preprint.pdf)）
- **论文二（Enforced 内核运行时与插件安全边界 · DOI: 10.5281/zenodo.24170505）** — [https://doi.org/10.5281/zenodo.24170505](https://doi.org/10.5281/zenodo.24170505)（[Zenodo 页面](https://zenodo.org/records/24170505) · 本地副本：[`paper2/aegis_enforced_runtime_arxiv_preprint.pdf`](paper2/aegis_enforced_runtime_arxiv_preprint.pdf) · [LaTeX](paper2/main.tex)）
- **AAP-1.0 应用协议** — [`docs/AEGIS_APPLICATION_PROTOCOL.md`](docs/AEGIS_APPLICATION_PROTOCOL.md)
- **记忆同意 / UOMP** — [`docs/UOMP_MEMORY_CONSENT_MAPPING.md`](docs/UOMP_MEMORY_CONSENT_MAPPING.md)
- **技术专论** — [为什么 Agent 插件不是安全边界](https://heurion.org/blog/from-agent-plugins-to-enforced-runtime) · [超越 Git 分支与共享目录](https://heurion.org/blog/aegis-os-transactional-agent-kernel) · [人机权限与能力对等](https://heurion.org/blog/human-agent-capability-parity-ai-native-software) · [双表面 CRDT](https://heurion.org/blog/dual-surface-crdt-clinical-ai)
- **技术博客总目录** — https://heurion.org/blog

## 引用 (Citation)

如果在研究或工程工作流中使用了 Aegis OS，欢迎引用我们的论文：

```bibtex
@article{zhao2026aegisos,
  title   = {Aegis OS: A Transactional Multi-Tenant Operating System Runtime for Eliminating Authorization Fatigue in Autonomous Coding Agents},
  author  = {Zhao, Hui},
  journal = {arXiv preprint arXiv:2611.08516},
  year    = {2026},
  eprint  = {2611.08516},
  archivePrefix = {arXiv},
  primaryClass  = {cs.OS},
  url     = {https://arxiv.org/abs/2611.08516}
}

@misc{zhao2026enforced,
  title     = {Why Agent Plugins Are Not a Security Boundary: Inverting Control from In-Process Hooks to a Kernel-Enforced Agent Runtime},
  author    = {Zhao, Hui},
  year      = {2026},
  month     = nov,
  publisher = {Zenodo},
  version   = {v1},
  doi       = {10.5281/zenodo.24170505},
  url       = {https://doi.org/10.5281/zenodo.24170505}
}
```

## 遥测与许可证

仅在安装与每日首次会话发送匿名心跳；不包含源码、路径、Prompt 或凭据。设置 `DO_NOT_TRACK=1` / `AOS_TELEMETRY_DISABLED=1`，或 `touch ~/.gemini/aegis-telemetry-opt-out` 即可关闭。详见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

Apache License 2.0，见 [`LICENSE`](LICENSE)。
