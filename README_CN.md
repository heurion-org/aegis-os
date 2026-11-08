# Aegis OS (`aegis-os`)

**[English](README.md) | [简体中文](README_CN.md) | [Aegis OS 官网](https://heurion.org/aegis-os/) | [使用教程](https://heurion.org/aegis-os/tutorial/) | [技术博客](https://heurion.org/blog) | [云端控制台与 Pro 订阅 ($29/月)](https://heurion.org/aegis-cloud/dashboard) | [边界审批台](https://heurion.org/aegis-cloud/approve)**

**面向自主编程 Agent（`agy`、`claude`、`codex`、`opencode`、`hermes`）的事务型多租户 Agent OS 运行时 —— 内核隔离、CoW 影子工作区、A2A 协同与效果级审批。**

> **强制等级**：`aegis-os install` = **advisory**（Hook / MCP / 规则；兼容模式，不是安全边界）。`aegis-os run -- <agent>` = **enforced**（Aegis 作为父进程；内核沙箱 + CoW 影子工作区 + 出站代理；Linux `bwrap` Phase 1 + macOS Seatbelt 启动器 MVP，macOS 完整路径重映射在 Phase 4）。`aegis-os run --isolated` / Aegis Cloud = **isolated**（microVM / 云端沙箱）。

![Rust](https://img.shields.io/badge/Rust-1.80%2B%20(2021)-orange.svg)
![MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-blue.svg)
![A2A](https://img.shields.io/badge/Protocol-Google%20A2A-34A853.svg)
![Paper](https://img.shields.io/badge/Paper-arXiv%20Preprint-b31b1b.svg)
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
| **Enforced** | `aegis-os run -- claude`，或 `aegis-os install --enforce` 后直接运行 `claude` | 内核沙箱 + broker + 出站代理 | 被 Prompt Injection 控制或被攻陷的 Agent；宿主写入；凭据读取；任意出站 | ✅ Linux Phase 1 (`bwrap`)；macOS Seatbelt MVP（完整路径重映射在 Phase 4） |
| **Isolated** | `aegis-os run --isolated -- claude` / Aegis Cloud | microVM + 远程策略 | 不可信仓库、多租户团队、宿主级隔离 | 🟡 云端沙箱可用；本地 `--isolated` 在 Phase 4 |

**Advisory 不是安全边界。** Hook 和 MCP Server 是 Agent 自己加载的；被劫持的 Agent 可以跳过、禁用，或直接使用原生工具。Enforced 模式下，Aegis 在 Agent 启动前创建影子工作区、沙箱、代理与策略会话，Agent 无法选择退出。

Tier A 启动目标：**Claude Code、AGY、Codex、OpenCode（`--standalone`）、Hermes**。Enforced 路径不依赖客户端 Hook；advisory 能力因客户端而异（Codex 目前没有工具级 Hook）。OpenCode 必须使用 `--standalone`，否则其共享后台服务可能绕过沙箱；`aegis-os install` 已内置安装 OpenCode V1 插件（`plugins/opencode-aegis.js`），V2 细粒度工具 Hook 与 Hermes adapter 仍在推进中。

## 快速开始

### Advisory 集成

```bash
brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git
brew install aegis-os
aegis-os install
aegis-os audit-me            # 5 秒本地凭据裸奔风险与弹窗疲劳体检（加 --share 导出 Markdown 分享卡）
```

这会为检测到的 Agent 接入 Hook / MCP / 规则，降低授权疲劳，但不承诺抵抗被攻陷的 Agent。

### Enforced 运行时（Linux `bwrap` Phase 1 & macOS Seatbelt MVP）

```bash
aegis-os install --enforce   # 创建 ~/.aegis/bin shim
aegis-os run -- claude       # 或 codex / agy / opencode --standalone / hermes
```

Enforced 模式提供：

- 宿主项目只读；所有写入落在每会话独立的 CoW 影子工作区。
- `$HOME`、`/root`、`/run`、`/var`、`/tmp`、`/mnt`、`/media`、`/srv` 与宿主 SSH/云凭据被遮蔽。
- 保留 Git 视图（Linux 上宿主 `.git` 只读 + 会话 index 可写；macOS 上使用影子工作目录视图）。
- 身份绑定的本地出站代理：**模型 API Base-URL L7 反向代理**（`ANTHROPIC_BASE_URL`、`OPENAI_BASE_URL`、`GOOGLE_GEMINI_BASE_URL`）支持 L7 请求 DLP 扫描与 `$AOS_SECRET_*` 边界密钥注入；普通 HTTPS 走 CONNECT 域名 allowlist。
- Commit ticket + `evidence_hash` / TOCTOU 防护 + TTL 租约 + `Aegis-OS-Verified` Commit/PR 审计回执。
- **Fail closed**：缺少 `bwrap`/`sandbox-exec`、代理或 broker 时拒绝启动，不静默降级。

会话与可观测控制：`aegis-os status` · `aegis-os diff` · `aegis-os verify` · `aegis-os commit` · `aegis-os discard` · `aegis-os publish` · `aegis-os approvals` · `aegis-os why` · `aegis-os a2a board` · `aegis-os policy watch` · `aegis-os memory ui` · `aegis-os app list` · `aegis-os audit-me --share`。

当前限制：

- **macOS 与 Linux 能力差异**：Linux 通过 `bwrap >= 0.10`（`--bind-fd`）把影子工作区挂载回原宿主路径；macOS `aegis-os run` 已提供 `sandbox-exec` Seatbelt 启动器 MVP（影子 `cwd`、宿主项目只读、敏感凭据路径拒绝、出站代理、PTY 与 TCP broker），但完整路径重映射与全量默认拒绝收敛在 Phase 4。
- **非模型 HTTPS 审计范围**：模型 API 流量已走本地 Base-URL L7 反向代理（DLP + 密钥注入）；任意第三方 HTTPS 仍为 CONNECT 域名 allowlist（通用 opt-in MITM 在 Phase 2）。
- 审批台是本地 CLI/Web；云端 `/approve` 与 TUI 内嵌面板尚未接入 enforced launcher。
- ext4 上 CoW 可能回退到 lazy-copy；OverlayFS / fuse-overlayfs 后端尚未落地。

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
| 授权弹窗减少（52 份真实会话，28,087 次工具调用） | **90.7%–97.9%** |
| 红队攻击成功率（80 项） | **0.0%** |
| CoW 供给（1,000 文件 / 78.1MB） | **6.28ms** APFS · **15.6ms** btrfs |
| 多 Agent 自动归并 | **98.7%** |
| 回滚（200 个损坏模块） | **8.68ms** |

> Monograph 03 中的 `0.42ms` 是主干锚定的元数据派生；`6.28ms` / `15.6ms` 是 1,000 文件工作区的完整供给。完整方法见 [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md)。

## 文档

- **Enforced Runtime 设计** — advisory / enforced / isolated 威胁模型、Effect 模型、阶段计划：[`docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md`](docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md)
- **详细架构** — 信任边界、核心 crate、工作区与合并模型、MCP/A2A 接口、领域 profile、云端 PaaS、基准与实施状态：[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **基准报告** — [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md)
- **论文** — [`paper/aegis_os_arxiv_preprint.pdf`](paper/aegis_os_arxiv_preprint.pdf)
- **AAP-1.0 应用协议** — [`docs/AEGIS_APPLICATION_PROTOCOL.md`](docs/AEGIS_APPLICATION_PROTOCOL.md)
- **记忆同意 / UOMP** — [`docs/UOMP_MEMORY_CONSENT_MAPPING.md`](docs/UOMP_MEMORY_CONSENT_MAPPING.md)
- **技术专论** — [超越 Git 分支与共享目录](https://heurion.org/blog/aegis-os-transactional-agent-kernel) · [人机权限与能力对等](https://heurion.org/blog/human-agent-capability-parity-ai-native-software) · [双表面 CRDT](https://heurion.org/blog/dual-surface-crdt-clinical-ai)
- **技术博客总目录** — https://heurion.org/blog

## 遥测与许可证

仅在安装与每日首次会话发送匿名心跳；不包含源码、路径、Prompt 或凭据。设置 `DO_NOT_TRACK=1` / `AOS_TELEMETRY_DISABLED=1`，或 `touch ~/.gemini/aegis-telemetry-opt-out` 即可关闭。详见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

Apache License 2.0，见 [`LICENSE`](LICENSE)。
