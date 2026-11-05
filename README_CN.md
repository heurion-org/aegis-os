# Aegis OS (`aegis-os`)

**[English](README.md) | [简体中文](README_CN.md) | [Aegis OS 官网概览](https://heurion.org/aegis-os/) | [使用教程](https://heurion.org/aegis-os/tutorial/) | [云端控制台与 Pro 订阅 ($29/月)](https://heurion.org/aegis-cloud/dashboard) | [边界审批台](https://heurion.org/aegis-cloud/approve)**

**面向自主编程 Agent（`agy`、`claude`、`codex`）的事务型多租户操作系统运行时与云端沙箱 PaaS —— 彻底消除授权弹窗疲劳，兼顾零信任内核隔离与多 Agent 协同**

![Rust](https://img.shields.io/badge/Rust-1.80%2B%20(2021)-orange.svg)
![MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-blue.svg)
![A2A](https://img.shields.io/badge/Protocol-Google%20A2A-34A853.svg)
![Paper](https://img.shields.io/badge/Paper-arXiv%20Preprint-b31b1b.svg)

---

## 为什么需要 Aegis OS？

在使用 **Google Antigravity (`agy`)**、**Anthropic Claude Code (`claude`)** 或 **OpenAI Codex CLI (`codex`)** 时，开发者长期面临三大痛点：

1. **严重的授权弹窗疲劳（Authorization Fatigue）**：在多步工程任务中，45%–57% 的工具调用会触发人工确认弹窗，打断思考流。
2. **裸奔模式（`--yolo` / `--dangerously-skip-permissions`）极度危险**：直接关闭确认会让 Agent 暴露在宿主机的 `~/.ssh`、`~/.aws`、`~/.kube` 私钥以及原地误删代码的风险之下。
3. **多 Agent 并行冲突与笔记本算力过载**：同时开启多个 Agent 窗口修改同一目录会导致互相覆盖、编译缓存失效，且重型 `cargo build` / `npm build` 会占满本地 CPU 与内存。

**Aegis OS (`aegis-os`)** 将安全边界从“单次工具调用弹窗”提升为**“事务型写时复制（CoW）工作区边界”**：
- 在工作区内部：Agent 拥有独立的 CoW 影子仓库与 OS 内核沙箱（macOS `Seatbelt` / Linux `bwrap`），**读写代码、跑测试、多 Agent 通信 0 弹窗自动放行（减少 94%–99.8% 弹窗）**；
- 在越界提交时：只有当 Agent 完成任务、调用 `workspace_commit` 将变更合入宿主机仓库（或触碰 `.git/hooks`、`Makefile`、`Cargo.toml` 等构建钩子）时，才触发一次带完整 Diff 与三路合并校验的人工审批（或凭会话租约放行）。

---

## 30 秒快速上手 (Quick Start)

### 方式 A：通过 Homebrew 安装（macOS & Linux）

```bash
# 1. 安装 aegis-os 二进制
brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git
brew install aegis-os

# 2. 一键挂载 Antigravity (agy)、Claude Code (claude) 和 Codex CLI (codex)（全局仅需执行一次）
aegis-os install
```

### 方式 B：一键签名校验安装脚本（Linux & macOS，无需 Homebrew）

自动识别系统架构、下载预编译包并执行 OpenSSH 签名校验（`aegis-os-release@heurion.org`），随后自动完成 `aegis-os install`：

```bash
curl -fsSL https://heurion.org/aegis-cloud/install.sh | sh
# 或直接从 GitHub 拉取：
curl -fsSL https://raw.githubusercontent.com/heurion-org/aegis-os/main/scripts/install.sh | sh
```

### 方式 C：源码编译安装（Rust 1.80+）

```bash
git clone https://github.com/heurion-org/aegis-os.git && cd aegis-os
cargo install --path crates/aos-cli
aegis-os install
```

### 强制隔离模式（Phase 1，Linux 预览）

基于 launcher 的 enforced 模式已可在 Linux 上试用：

```bash
aegis-os --workspace . run -- claude
aegis-os status
aegis-os diff
aegis-os commit          # 人类 CLI 操作；审批流在 Phase 2
aegis-os discard
```

当前已经强制：

- Agent 进程树运行在 `bwrap` 中；宿主项目只读，写入落在每会话独立的 CoW shadow。
- `$HOME`、`/root`、`/run`、`/var`、`/tmp`、`/mnt`、`/media`、`/srv` 与宿主 SSH 私钥被遮蔽；Agent 敏感配置只读。
- Git 视图：宿主 `.git` 只读 + 会话 index 可写，`git status` / `git diff` 可用。
- Agent 状态目录复制进会话 home；OAuth 凭据在退出时原子写回。

Phase 1 限制（暂不要把它当成完整安全边界）：

- 仅 Linux；需要 bubblewrap **>= 0.10**（`--bind-fd`）。macOS 在 Phase 4。
- 网络仍共享：egress proxy / L7 DLP 尚未强制，宿主 loopback 服务可达。
- 审批、租约、`--mode observe`、OpenCode/Hermes adapter 与策略引擎在后续阶段。

### 日常使用方式（零感知自动挂载）

执行过一次 `aegis-os install` 后，日常写代码**完全不需要手动输入 `aegis-os` 命令**：

1. **直接进入任意项目目录启动你的编程 Agent**（运行 `agy`、`claude` 或 `codex`）。
2. **全自动 CoW 影子工作区与内核沙箱守护**：
   - Agent 的所有文件读写（`fs_read`、`fs_write`、`fs_edit`）与命令执行（`proc_exec`）自动在毫秒级克隆的 CoW 影子工作区和内核沙箱中运行，宿主机 `~/.ssh`、`~/.aws` 等敏感凭证被内核强制屏蔽。
   - 当你满意 Agent 的修改并准备落盘时，Agent 调用 `workspace_diff` -> `workspace_commit`，通过 4 层 LCS Diff3 三路合并引擎安全写回宿主机。桌面环境下会自动弹出网页审批台（`/approve`，点击批准后自动续跑），纯终端/SSH 下也可运行 `aegis-os approve`（或简写 `aos approve`）一键放行。
3. **常用运维、审批与云端订阅命令**：
   ```bash
   aegis-os approve                                  # 一键批准当前最新待处理的边界提交（支持 --web 打开网页审批台）
   aegis-os cloud subscribe --plan pro --wait        # 一条命令完成 Pro 订阅 ($29/月)、认领密钥并启用零负载云端沙箱
   aegis-os doctor                                   # 检查 AGY / Claude Code / Codex 挂载状态
   aegis-os top                                      # 终端实时查看多 Agent 协同雷达、A2A 任务与活跃租约
   aegis-os stats                                    # 查看 GitHub 下载量与匿名活跃用户统计看板
   ```
   - **Aegis Cloud 开发者控制台与在线订阅**：[https://heurion.org/aegis-cloud/dashboard](https://heurion.org/aegis-cloud/dashboard)

---

## 五大核心技术支柱

1. **事务型写时复制文件系统与 4 层自动三路合并 (`aos-vfs`)**：
   - 基于 macOS APFS `clonefile`（1,000 文件仅需 `6.28 ms`）与 Linux Btrfs/XFS `ioctl(FICLONE)` reflink（`15.6 ms`）实现零拷贝分支；跨挂载点（如 `ext4 -> tmpfs`）下超大文件回退为完整物理拷贝，而不是指向原路径的符号链接——当 shadow 挂到原项目路径后，该链接会变成自指。ext4 的 O(1) 回退（OverlayFS / fuse-overlayfs）在后续阶段实现。
   - 内置 **4 层 LCS Diff3 三路合并引擎**：支持未修改文件零拷贝快进、不同行并发修改自动拼接、同锚点 `use`/`import`/`mod` 声明自动去重并集，以及 `.aegis/verify.json` / `AOS_VERIFY_CMD` 预提交沙箱语义门禁。
2. **双层 OS 内核沙箱与进程组生命周期控制 (`aos-sandbox`)**：
   - 基于 macOS Seatbelt (`/usr/bin/sandbox-exec`) 与 Linux Bubblewrap (`bwrap --unshare-all`) 强制执行只读根目录与 `$HOME` 默认拒绝（`--tmpfs` 遮蔽并只读回挂 `.rustup` / `.cargo` 工具链），支持 `pause()` / `resume()` / `destroy()` 真实进程组信号管控（`SIGSTOP` / `SIGCONT` / `SIGKILL`）。
3. **零信任出站代理、HTTPS `CONNECT` 隧道与边界密钥注入 (`aos-egress`)**：
   - 沙箱内永远不落盘明文 API Key，仅持有 `$AOS_SECRET_*` 占位符。出站请求经由身份绑定的本地代理，校验目标域名、HTTP 方法与路径前缀后，在网络边界注入真实凭证，并通过 L7 DLP 拦截私钥与 Token 外泄。
4. **声明式 Cedar 5 级策略引擎、防 TOCTOU 哈希锁定与提交投毒守卫 (`aos-policy`)**：
   - 原生解析 [`policy/default.cedar`](policy/default.cedar)（并支持 `AOS_CEDAR_POLICY_FILE` 扩展），支持在免密钥网页审批台（`/approve` 与 `/aegis-cloud/dashboard`）内直接展开语法高亮 Unified Diff 预览（`GET /v1/approvals/diff`）；单次批准（`批准本次 · SHA-256 锁定`）将租约密码学锚定至审批时刻的规范化 Diff 摘要（`sha256:<evidence_hash>`），彻底阻断先审后改的 TOCTOU 调包攻击；即使在拥有 15 分钟 / 1 小时活跃会话租约的情况下，任何触碰 `.git/hooks/*`、`Makefile`、`build.rs`、`Cargo.toml`、`package.json`、`.aegis/*` 的提交仍强制合并生成一张 `workspace_commit_sensitive` 人工审批单（R0b 守卫），且所有已授权租约均可在网页端一键撤销（`POST /v1/leases/revoke`）。
5. **Google A2A 多 Agent 协同基础设施与云端沙箱 PaaS (`aos-ipc`, `aos-mcp-gateway`, `aos-recorder`)**：
   - **Agent-First 零命令协同**：用户始终直接用自然语言与 `agy`、`claude`、`codex` 对话，无需手动输入 CLI 子命令。Agent 自动通过 MCP 完成同伴发现（`ipc_list_peers`）、层级子任务拆解与依赖编排（`ipc_request` 支持 `parent_task_id` 与 `depends_on`，父任务取消时自动递归取消子任务树）、无 Hook 客户端免轮询阻塞等待（`ipc_wait`）以及状态流转。
   - **任务级通配符文件锁 (`coord_claim`) 与并发落盘串行复核**：支持 2D NFA + 真实文件树双重 Glob 交集防撞（如拦截 `src/**` 与 `src/auth/*.rs` 冲突）、`proc_exec` 沙箱脚本越界写软告警（`coordination_warning`），并在 `workspace_commit` 或任务终态时**自动释放文件锁与任务租约**；并发提交由跨进程锁与 `host_commit_epoch` 串行化，若主干在预检期间被同伴更新则自动重跑三路合并与 `verify_cmd`。
   - **SHA-256 防篡改哈希链审计账本**：每一次跨边界操作（锁申请、主干提交、A2A 任务、提权审批）均生成 `prev_hash -> event_hash` 哈希链记录，Agent 可直接调用 `ipc_task_get` / `ipc_task_list` 查验子任务树与 `hash_chain_verified: true` 审计轨迹；同时支持一键切换至零本地算力消耗的 **Aegis Cloud Sandbox Mode**（`aegis-os cloud up`）。

---

## 隐私与匿名遥测说明 (`DO_NOT_TRACK=1`)

为了统计各操作系统与客户端（`agy`、`claude`、`codex`）的兼容性与活跃度，`aegis-os` 仅在执行 `aegis-os install` 及每日首次启动会话时发送一次极简匿名心跳：
- **仅包含**：单向不可逆哈希设备标识（`anon-<16位hex>`）、版本号、操作系统/架构及客户端类型。
- **绝不包含**：任何源代码、文件路径、仓库名称、环境变量、Prompt 内容、用户名或主机名。
- **随时关闭**：设置环境变量 `export DO_NOT_TRACK=1` 或 `export AOS_TELEMETRY_DISABLED=1`，或执行 `touch ~/.gemini/aegis-telemetry-opt-out` 即可完全静默。

更多架构细节、39 个 MCP 工具完整列表、`AAP-1.0` 应用生态与论文基准测试报告请参阅英文主文档：[README.md](README.md)。
