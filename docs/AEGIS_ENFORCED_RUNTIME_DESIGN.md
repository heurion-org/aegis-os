# Aegis Enforced Runtime 产品设计文档

> **副标题**：面向代码、文档、数据流水线与跨应用状态的通用 Agent 事务运行时  
> **版本**：v0.7  
> **日期**：2026-11-09  
> **状态**：核心落地并完成双平台实证评测（Phase 1/2 核心完成，macOS Seatbelt + Linux `bwrap --bind-fd` 均通过 `V1–V6` 30/30 对抗测试与 60 次真实 CLI Agent 评测）  
> **范围**：Aegis OS 从「Agent 加载的安全插件」升级为「启动 Agent 的安全运行时」  
> **关联代码**：`crates/aos-cli/src/routing.rs`、`crates/aos-cli/src/hooks.rs`、`crates/aos-cli/src/installer.rs`、`crates/aos-cli/src/launcher.rs`、`crates/aos-sandbox/src/lib.rs`、`crates/aos-egress/src/lib.rs`、`crates/aos-policy/src/lib.rs`、`crates/aos-mcp-gateway/src/lib.rs`、`crates/aos-vfs/src/lib.rs`、`crates/aos-core/src/effect.rs`  
> **关联文档**：`README.md`、`docs/ARCHITECTURE.md`、`docs/AEGIS_APPLICATION_PROTOCOL.md`、[Paper 2 预印本 (`paper2/aegis_enforced_runtime_arxiv_preprint.pdf`)](../paper2/aegis_enforced_runtime_arxiv_preprint.pdf)、[实证基准数据 (`paper2/ENFORCED_RUNTIME_BENCH_REPORT.json`)](../paper2/ENFORCED_RUNTIME_BENCH_REPORT.json)、[《为什么 Agent 插件不是安全边界》](https://heurion.org/blog/from-agent-plugins-to-enforced-runtime)、[《超越 Git 分支与共享目录》](https://heurion.org/blog/aegis-os-transactional-agent-kernel)

---

## 实施状态与计划（2026-11-06）

| Phase | 状态 | 已完成 | 下一步 |
|---|---|---|---|
| **Phase 0** 说真话与可观测性 | 🟡 部分完成 | `doctor` 现在检查 Aegis 配置条目、PATH shim/enforcement 状态、broker 缺失提示；README 有 Phase 1 limits；`.agents/hooks.json` 可移植 | 公开客户端能力矩阵、Hook 实际加载状态、telemetry |
| **Phase 1** `aos run` Linux MVP | 🟡 MVP 完成，完整交付未完成 | bwrap 进程树、CoW shadow、宿主只读、`$HOME`/系统目录遮蔽、Git 目录视图、状态目录持久化绑定、工具链挂载、CONNECT egress allowlist、PTY + SIGWINCH/SIGTERM/Ctrl-C、退出摘要与 pending 退出码、advisory 降级、bwrap 版本探测 | worktree `.git`、OverlayFS、observe 网络只读 |
| **Phase 2** Effect / 审批 / 租约 | 🟡 部分完成 | `aos-core::effect` + `policy_action` 桥接、commit approval ticket、**统一 `aos_core::compute_diff_evidence` 全量 SHA-256 证据哈希** + TOCTOU、`aos approvals` CLI/Web 与 `AegisPolicyKernel` (`policy_state.json`) + `AegisFlightRecorder` (`flight_recorder.jsonl`) 双端同步、`workspace_commit` 租约（复用 policy matcher）、敏感路径守卫、哈希链 audit/`aos why`、**模型 API Base URL 反向代理 + L7 DLP**、**per-session broker + `AOS_SESSION_TOKEN` + `AOS_CONTROL_SOCKET` + MCP stdio bridge + `aos adapter hello/capabilities/evaluate/effect/heartbeat`**、AdapterManifest / `aos agent add/test`、OpenCode V1 plugin、`aos policy watch` + 桌面通知 | opt-in MITM、DecisionClass/Cedar 属性、OpenCode V2 tool hooks、Hermes plugin、完整 policy broker UI、通用第三方 API L7 |
| **Phase 3** DomainProfile / 预检 / CAS | 🟡 部分完成 | `DomainProfile` 接口 + `.aegis/workspace.json` profile/verify、`aos workspace profile`、read/write claims、文本 LCS、二进制排他锁+基线哈希、`aos verify`、`aos publish` / `artifacts list/fetch`（带 verify 门与 shadow 路径约束）、`aos diff --render`（文本 preview） | docs/data 专用合并器、Office CRDT、Schema/PHI 预置 profile、五客户端 adapter/plugin、章节/分区 claim |
| **Phase 4** macOS / 内核加固 | 🟡 部分完成 | macOS Seatbelt launcher MVP：shadow cwd、宿主只读、credential deny、`.aegis-bin` 只读 Git shim `PATH` 置顶、egress proxy、PTY、broker TCP control、MCP bridge；macOS 已手工验证 | Seatbelt default-deny 收敛、路径重映射、Landlock/seccomp、microVM 试点 |
| **Phase 5** 高级领域 / IDE / 企业 | ⬜ 未开始 | — | Office CRDT、AAP-1.0、UOMP、IDE daemon、MDM |

**当前验证（2026-11-09）**

```text
AEGIS_ALLOW_NESTED_TEST_SANDBOX=1 cargo test -p aos-core -p aos-policy -p aos-vfs -p aos-ipc -p aos-sandbox -p aos-cli --lib   # 75 passed (0 failed)
cargo test -p aos-egress                                                                                                        # 8 passed; 2 ignored (real TLS handshake)
cargo clippy --workspace --all-targets -- -D warnings
```

- **双平台确定性对抗基准（`scripts/p2_live/deterministic_rm_bench.py`）**：macOS 26.3 (`aarch64`, Seatbelt) 与 Ubuntu 24.04 (`aarch64`, Linux 6.8, `bwrap 0.11.0 --bind-fd`) 均实测通过 `V1–V6` 全部 30 项结构性绕过向量（**0/30 绕过，0.0% ASR**；仅插件 Hook 模式为 30/30 绕过），并完成 5 组逐层消融验证；
- **60 次真实云端 API 生产级 CLI Agent 端到端验证（`scripts/p2_live/live_cli_agent_bench.py`）**：覆盖 `Claude Code 2.1.104`、`OpenCode 1.4.3`、`Antigravity (AGY) 0.2.3`、`Hermes Agent 0.8.0` 四款真实客户端 × 3 种运行模式（`native_baseline` / `aegis_advisory_hook` / `aegis_enforced`）× 5 个编码与仓库陷阱任务，良性工程任务 **100% (12/12)** 通过，恶意 `Makefile` / `build.rs` / `.git` 陷阱下宿主失陷率从 **100% (8/8)** 降至 **0% (0/8)**；
- **系统开销实测**：Linux `bwrap` 启动中位数 **9.91 ms**（比 Rootless `nerdctl` 容器 **222.02 ms** 快 **22.4×**），macOS Seatbelt **16.43 ms**；500 MB Git 仓库 APFS `clonefile` 仅 **6.10 ms / 4.74 MB**（省盘 **99.05%**）；L7 模型反向代理首 Token 延迟开销仅 **+0.221 ms**。

**Linux VM 验证（Ubuntu 24.04 aarch64 / bwrap 0.9.0，需关闭 AppArmor unprivileged userns 限制）**：

- `aos run -- /bin/sh` 内 `AOS_SESSION_TOKEN` / `AOS_CONTROL_SOCKET` 可见；
- `aos adapter heartbeat`、`evaluate`、`hello`、`capabilities` 通过只读挂载的 broker socket 工作；
- `aos mcp-bridge` 的 `tools/list` 返回 39 个工具，`fs_write` 只写 shadow，宿主文件未创建；
- `aos agent test sh` 在会话内完成 hello + heartbeat + MCP tools/list，输出 `PASS (live broker)`；
- `aos adapter evaluate shell --input '{"command":"git push origin main"}'` 返回 `ask` + escalation id；
- `script -q -c "aos run -- /bin/sh -c 'tty; stty size'" /dev/null` 在 `aos run` 下得到 PTY：`/dev/console`、`24 80`；
- Agent 正常退出后返回码为 `10`，退出摘要列出 shadow 变更。

**macOS Seatbelt MVP 验证（macOS 27 / aarch64）**：

- `aos run -- /bin/sh` 进入 Seatbelt，cwd 为 shadow，`AOS_HOST_ROOT` 可只读访问宿主项目；
- 写宿主项目、写 `/tmp`、读 `/Users/<user>/.ssh/*` 均返回 `Operation not permitted`；
- `aos adapter heartbeat/session` 通过 loopback TCP broker 工作；
- `aos mcp-bridge` 的 `tools/list`/`fs_write` 正常，MCP 写入只落 shadow；
- `script -q /dev/null ...` 下 `tty` 为 `/dev/ttys006`、`stty size` 为 `24 80`；
- Agent 退出后 shadow 摘要和退出码正常。

**近期计划（按优先级）**

1. **P0：完整 MCP bridge + Adapter hello/capabilities + Hook/plugin 自动接入**
   per-session broker 已提供 `AOS_SESSION_TOKEN` / `AOS_CONTROL_SOCKET`、`adapter.evaluate/effect/heartbeat` 和 human escalation/lease/audit；下一步把 MCP JSON-RPC 桥进 sandbox，并让 Claude/AGY/OpenCode/Hermes adapter 自动声明能力、消费 allow/ask/deny。
   完成标准：Agent 只能通过 session token 调用 broker；未知 MCP server 默认拒绝；TUI 活跃时审批走旁路。

2. **P1：opt-in MITM / 第三方 API L7**
   模型 API 的 Base URL L7 已完成；下一步为不支持 base URL 的第三方 API 做 opt-in MITM（per-session CA、pin 失败回退、明确 L7 不可用）。
   完成标准：列入 `mitm_domains` 的域名可做 method/path/body 审计；未列入域名仍只记录 `net.connect`。

3. **P1：OverlayFS / fuse-overlayfs CoW backend**
   在 ext4 上实现 O(1) shadow 创建，删除第二次 baseline 全量拷贝。
   完成标准：1 GB 数据集启动 P95 < 150 ms，`doctor` 显示 `cow_backend: overlay`。

4. **P1：docs/data profile 深化**
   章节/段落 claim、Schema-aware data merge、PHI/schema verify、CAS + task DAG 接力。
   完成标准：多 Agent 改不同章节成功、同段落冲突、数据 Schema/PHI 失败不落盘、下游只读 CAS 哈希。

5. **P2：macOS Seatbelt + isolated VM**
   macOS Seatbelt launcher MVP 已在实机验证（shadow cwd、broker TCP、credential/token deny、PTY）；仍缺 default-deny 收敛、路径重映射和 isolated VM。
   完成标准：`aos run -- claude` 在 macOS 上完成同样的文件/网络边界测试。

6. **P2：OpenCode plugin / Hermes adapter**
   OpenCode 已有 MCP 配置与 `--standalone` 启动；补齐 install-time plugin 与 Hermes Adapter Protocol。
   完成标准：`aos agent test` 能验证 heartbeat、permission hook、MCP 工具调用。

**已知限制**

- Linux 需要 bubblewrap（`--bind-fd`；当前验证 0.9.0/Ubuntu 24.04）；macOS 使用 `/usr/bin/sandbox-exec`，以 shadow 作为 cwd，不做路径重映射。
- 通用 HTTPS 出站仍是 CONNECT-only 域名 allowlist；模型 API 已走 Base URL 反向代理，可做 method/path/body DLP 与边界密钥注入；opt-in MITM / 任意第三方 API L7 尚未实现。
- `aos run` 已有 per-session broker、`AOS_SESSION_TOKEN` / `AOS_CONTROL_SOCKET`、MCP stdio bridge、`aos adapter hello/capabilities/evaluate/effect/heartbeat`、`aos agent add/test`、OpenCode V1 plugin，以及 Ask 时的 macOS/Linux 桌面通知 + `aos policy watch`；但 OpenCode V2 工具 hook、Hermes plugin、TUI 内嵌审批和完整 AskEach UX 仍未完成。
- observe 目前只保证 shadow 只读 + commit 拒绝；CONNECT 隧道无法做 L7 方法级只读。
- 审批台是本地 CLI/Web，未接入云端 `/approve` 或 TUI 内嵌面板；PTY 已支持真实终端，但审批通知仍没有内嵌状态栏。
- CoW 仍可能回退到 lazy-copy；OverlayFS 尚未落地，`cow_backend` 只报告 `reflink-or-copy`。
- Git 视图只支持 `.git` 目录；worktree/submodule 的 `.git` 文件尚未处理。
- macOS Seatbelt 已有 enforced launcher MVP，但仍是 `allow default` + deny 写/凭据/网络，且使用 shadow 作为 cwd（无路径重映射）；default-deny 收敛、VM 形态、Office CRDT、AAP-1.0、UOMP、IDE 集成和 Hermes adapter 未完成。
- `.agents/hooks.json` 已改为可移植的 `aegis-os` + `--workspace ".."`，不再写死机器路径。
- 默认 runtime 已迁到 `~/.aegis`（可用 `AOS_RUNTIME_DIR` 覆盖）；旧 `/tmp/aegis-os-runtime` 会话不会自动迁移。

---

## 变更记录

- **v0.7**（2026-11-09）：完成跨平台真实 CLI Agent 生产适配加固与 Paper 2 实证评测（`aa36c3c`）：
  - **macOS Seatbelt 真实客户端兼容与硬化**：保留真实 `HOME`（支持 Claude Code / AGY 读取 macOS Keychain OAuth 凭据）同时将 `XDG_CONFIG_HOME` / `XDG_DATA_HOME` / `XDG_STATE_HOME` 重定向至沙箱私有目录；对 Darwin `/var/folders -> /private/var/folders` 执行软链规范化白名单；阻断 `~/.ssh`、`~/.aws`、`~/.gnupg` 与 `human.token` 读取；
  - **Linux `bwrap --bind-fd` 真实客户端与网络修复**：挂载 `/run/systemd/resolve` 保障 `--unshare-net` 命名空间下本地代理解析上游 DNS；按客户端精细化挂载 CLI 运行态目录并对 `settings.json` / `hooks.json` / `config.toml` 施加单文件 `--ro-bind` 只读锁；
  - **CLI 差分哈希锚定与网关测试支持**：新增 `aegis-os diff --json`（输出规范化 `evidence_hash`）与 `aegis-os commit --expected-diff-hash <sha256>` 防 TOCTOU 提交校验；`aos-egress` 新增 `AOS_UPSTREAM_OPENAI_URL` / `AOS_UPSTREAM_ANTHROPIC_URL` / `AOS_UPSTREAM_GEMINI_URL` 上游路由支持；
  - **Paper 2 与可复现基准套件落地**：新增 `paper2/` 完整 14 页论文与 `scripts/p2_live/` 评测套件，完成 macOS + Linux `0/30` 对抗消融与 4 款真实 CLI Agent 共 60 次云端 API 实测。

- **v0.6**（2026-11-06）：按 005edfb..d76fdc9 代码评审修复：
  - evidence hash 统一为 bare hex，修复 launcher `sha256:sha256:` 双前缀；MCP `workspace_commit` 补 `old_sha256` / `new_sha256`；
  - `approve_escalation` 的 OneShot 优先于 TaskScoped；已 Approved/Denied 的票据不可重复审批；批量敏感路径不再残留组合租约；
  - read claim 的 `claim_glob` 贯穿 release / radar / gateway 广播，修复读锁与写锁冲突检测；
  - macOS Seatbelt runtime 只允许当前 workspace/home 读取，禁止读取 `human.token` / `agent.token`；macOS 分支前移 `validate_workspace_roots` 和 OpenCode `--standalone` 检查；
  - routing 拦截 `aos commit` / `aos approvals`，运行时标记覆盖 `~/.aegis` 和 token 文件；Hook broker 输出同时兼容 AGY / Claude；SessionStart 去重修复；
  - Gemini `?key=$AOS_SECRET_*` 在边界替换；L7/转发上游响应改为流式转发，避免大响应全量缓冲；OpenCode plugin 修复 UTF-8 分片；补齐 clippy `unknown_lints`。
  - 仍待收敛：launcher `approval.json` / `audit.jsonl` 与 `AegisPolicyKernel` / `AegisFlightRecorder` 两套账本尚未合并（见 §13 风险与开放问题）。

- **v0.5**（2026-11-06）：按代码评审落地安全与可用性修复：
  - evidence hash 现在绑定 old/new 完整 SHA-256，不再只依赖截断 preview；二进制同尺寸替换会使审批失效；
  - `aos commit` 租约检查复用 policy matcher（org/agent/action/task/`sha256:<evidence>`），并拒绝 observe session；
  - commit 前检查 peer write claims；`coord_claim` 支持 `read` / `write` 模式；
  - launcher 持久化绑定 Agent 状态目录、增加退出摘要、pending=10 退出码、SIGWINCH/SIGTERM 转发、`--no-enforce`/advisory；
  - `aos status` / `doctor` 显示 enforcement、backend、shim、配置条目；默认 runtime 改为 `~/.aegis`；
  - `aos publish` 增加 verify 门与 shadow 路径约束；`aos diff --render` 输出文本 diff preview；
  - 新增模型 API Base URL 反向代理：`ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` / `OPENAI_API_BASE` / `GOOGLE_GEMINI_BASE_URL` 指向 session egress proxy，支持 L7 请求体 DLP、域名/method/path 约束、边界密钥注入和 SSE 流式响应；
  - 新增 per-session broker：`AOS_SESSION_TOKEN` / `AOS_CONTROL_SOCKET`、`adapter.hello|capabilities|evaluate|effect|heartbeat`、`/v1/mcp` JSON-RPC bridge、human escalation/lease/audit 路由，以及 `aos adapter` / `aos mcp-bridge` 客户端；原生 Claude/AGY hook 已接 broker 的 deny/ask；新增 AdapterManifest 与 `aos agent add/test`，OpenCode/Hermes plugin 全量接入仍待补；
  - launcher 在真实终端下使用 `openpty` + `setsid`/`TIOCSCTTY`，保留 TUI raw mode、输入流和 `SIGWINCH` resize；管道/CI 继续使用继承 stdio；
  - 新增 `plugins/opencode-aegis.js` 并随 `aos install` 安装；OpenCode V1 `tool.execute.before/after`、`permission.ask`、`shell.env` 已接 broker，V2 工具 hook 仍待补；
  - broker 在 `ask` 时写 `pending_escalations.jsonl` 并发送 macOS/Linux 桌面通知；新增 `aos policy watch` 旁路监听；
  - 新增 macOS Seatbelt launcher MVP：shadow cwd、宿主只读、credential deny、egress proxy、PTY、TCP control socket + MCP bridge；macOS 已手工验证；
  - 新增 `DomainProfile` 接口、`.aegis/workspace.json` profile/verify 解析、`aos workspace profile`；
  - audit 改为 SHA-256 hash chain；`aos why` 校验链；修复全 workspace clippy 与测试平台门控。

- **v0.4**（2026-11-06）：更新实施状态与计划：
  - Phase 1 Linux 完成；Phase 2/3 部分完成；
  - 新增 commit approval ticket / evidence hash / TOCTOU、租约、`aos approvals` CLI + Web、`aos verify` 预检门、`aos publish` / `artifacts` CAS；
  - `.agents/hooks.json` 改为可移植 `aegis-os` + `--workspace ".."`；
  - 明确剩余项：L7 DLP / Base URL / MITM、专用领域合并器、macOS、Phase 5。

- **v0.3**：根据评审修正 7 个问题：
  1. HTTPS CONNECT 不做 MITM 时只能做 `net.connect`，L7 DLP / method 审计改为 opt-in MITM 或 base URL 反向代理；
  2. 增加 Git 视图映射，解决 shadow 缺 `.git` 导致 Agent / 工具链报错；
  3. Agent 配置目录拆分为「敏感配置只读 + 状态目录可写」，避免 OAuth / 会话记录写失败；
  4. 增加 CoW backend 矩阵：Linux ext4 用 OverlayFS / fuse-overlayfs，移除二次全量 baseline 拷贝；
  5. Linux 读视图改回 `--ro-bind / /` + `--tmpfs` 遮蔽用户数据，兼容 NixOS / Linuxbrew / Snap；
  6. TUI 活跃期间禁止向 PTY 混写审批文本，审批走结构化挂起 / 桌面通知 / 旁路终端；
  7. 收缩 Phase 3：只交付 `DomainProfile` 扩展接口 + 文本 LCS + 排他锁/基线哈希两类合并器，Schema-aware / Office CRDT / PHI / AAP / UOMP 移到 Phase 5。

---

## 目录

- [0. 摘要](#0-摘要)
- [1. 背景与问题](#1-背景与问题)
- [2. 目标与非目标](#2-目标与非目标)
- [3. 威胁模型与安全承诺](#3-威胁模型与安全承诺)
- [4. 核心设计原则](#4-核心设计原则)
- [5. 产品形态与用户旅程](#5-产品形态与用户旅程)
- [6. 总体架构](#6-总体架构)
- [7. 详细设计](#7-详细设计)
- [8. CLI / UX 规范](#8-cli--ux-规范)
- [9. 数据模型与 API](#9-数据模型与-api)
- [10. 实施计划](#10-实施计划)
- [11. 测试与验证](#11-测试与验证)
- [12. 迁移与兼容](#12-迁移与兼容)
- [13. 风险与开放问题](#13-风险与开放问题)
- [14. 附录](#14-附录)
- [15. 决策记录（ADR 摘要）](#15-决策记录adr-摘要)
- [16. OpenCode 集成骨架（实施附录）](#16-opencode-集成骨架实施附录)
- [17. Domain Profile 参考](#17-domain-profile-参考)

---

## 0. 摘要

一句话：**把 Aegis 的信任锚点从 Agent 的插件机制，移到 OS 内核边界。**

当前模式是「用户先启动 Agent，Agent 再加载 Aegis 的 MCP Server 和 Hook」。从权限模型上，这是子进程约束父进程，不可能成为可靠的安全边界。本设计引入 `aegis-os run` 作为 Agent 的父进程和会话监督者：

- **enforced 模式**：Aegis 先创建 CoW 影子工作区、内核沙箱、出站代理和策略会话，再启动 Agent。Agent 进程树从第一毫秒起就只能看到被允许的文件视图、只能写入 shadow、只能通过代理出网。
- **advisory 模式**：保留现有 Hook / MCP / 规则文件集成，用于兼容、降弹窗和审计，但明确标注「不承诺抵抗被劫持的 Agent」。
- **审批模型**：审批对象从「工具名 / 命令字符串」升级为「效果（effect）× 范围（scope）× 可逆性（reversibility）」。只读和读写是其中的一个维度，不是全部。
- **客户端支持**：AGY、Claude Code、Codex、**OpenCode**、**Hermes** 统一接入，并通过 **Agent Adapter Protocol** 覆盖其他 MCP Agent；不同客户端的能力和强制等级公开成矩阵，不把「支持」等同于「保护」。
- **领域无关**：代码只是第一个 `profile`；同一套 shadow / claim / verify / commit 机制覆盖多文件文档、知识库、数据流水线、二进制资产与跨应用状态。领域差异体现在 `DomainProfile`（合并策略、预检门、证据格式、认领粒度），而不是另起一套运行时。

三个不可妥协的决定：

1. **enforced 模式下 Aegis 必须是父进程**，Agent 不能选择是否加载安全层。
2. **安全控制必须在内核和 broker 中**，Hook / Plugin 只负责 UX、路由建议和审计，不承担安全承诺。
3. **审批必须按效果聚合**，不能按命令逐条弹窗；否则用户一定会关掉保护。

---

## 1. 背景与问题

### 1.1 当前信任锚点

当前 `aegis-os install` 做三件事：

- 向 AGY / Claude Code 写入 `PreToolUse` Hook，向 Codex 写入 MCP Server 与 `AGENTS.md`。
- 向客户端注册 `aegis-os mcp-stdio` MCP Server。
- 写入 `GEMINI.md` / `CLAUDE.md` / `AGENTS.md` 规则，引导 Agent 使用 `fs_*`、`proc_exec`、`workspace_commit`。

这些机制都依赖一个前提：**Agent 愿意调用它们**。Hook 是 Agent 主动拉起的子进程，MCP Server 是 Agent 主动拉起的子进程。被 prompt injection 控制的 Agent、升级后改变 Hook 语义的 Agent、用 `--settings` 或项目配置禁用 Hook 的会话，都可以不调用、伪造调用、或者直接执行原生工具。

因此当前模型的实际安全上限是：

- **能挡住**：诚实 Agent 的幻觉、误删、误写、常见凭据路径误读。
- **挡不住**：被完全劫持的 Agent、恶意 Agent 二进制、用户主动绕过、Agent 启动时加载的不可信仓库配置。

### 1.2 代码现状与缺口

| 机制 | 当前实现 | 缺口 |
|---|---|---|
| Hook 路由 | `routing.rs` 的 `RoutingMode::{Enforce, Advise, Off}`；`classify_native_read/write/run_command` | 基于工具名和命令字符串；新工具、未知 MCP Server、`NotebookEdit` 等可漏过；分类可被 `sh -c` / `python -c` / symlink 绕过 |
| Agent 进程 | Agent 在宿主机上以用户权限运行 | 只有 `proc_exec` 进入 bwrap / Seatbelt；Agent 主进程不在沙箱 |
| 沙箱读视图 | Linux `--ro-bind / /` + `--tmpfs $HOME`；macOS Seatbelt 允许默认读、拒绝写和已知凭据 | 宿主根仍大面积可读；只读/读写没有形成真实内核视图差异 |
| 写边界 | shadow 可写；commit 经策略审批 | shadow 内写入全部自动放行，但 `.git/hooks`、`build.rs` 等提交投毒路径的审批发生在 commit 阶段，依赖策略列表 |
| 客户端覆盖 | AGY / Claude 有 Hook；Codex 只有 MCP + `AGENTS.md` | Codex 目前没有工具级强制路由 |
| 配置面 | 项目级 `.claude/settings.json`、`.mcp.json`、`.codex/` 可在启动时生效 | Aegis 保护「提交这些文件」，但不保护「启动时加载这些文件」 |
| 身份 | MCP Server 通过 `--org` / `--agent` 参数取身份 | Agent 可以尝试伪造其他 Agent 的身份；需要 per-session token |
| OpenCode | 尚无集成 | V2 默认使用共享后台服务，工具执行发生在 Server 进程；只包住 TUI 不能保证隔离 |

### 1.3 为什么不能靠继续补 Hook

- Hook 协议是「自愿上报」。恶意 Agent 可以选择不调用。
- Hook 覆盖面是工具名枚举，客户端每加一个新工具就多一个缺口。
- Hook 运行在 Agent 进程树下，Agent 可以杀、可以伪造输入、可以改配置。
- 不同客户端能力不同：Claude / AGY 有 PreToolUse，Codex 当前集成没有工具级 Hook，OpenCode 是插件 + 共享 Server 架构。逐客户端追赶会永远滞后。

结论：**Hook 是兼容层，不是安全层。** 安全层必须由 Aegis 在 Agent 启动之前建立。

### 1.4 从「代码安全」升级为「通用事务协作」

《超越 Git 分支与共享目录》把问题定义得更准确：Aegis 不是「给 Coding Agent 加一个沙箱」，而是**面向代码、文件树、数据流水线与跨边界状态的通用事务协作内核**。文章给出的四类场景必须同时成立：

1. **代码工程**：多 Agent 围绕主干重构，共享构建缓存，按分钟级微事务合入。
2. **文档与知识库**：多章节 Markdown / LaTeX / Word / PPT / PDF、参考文献、矢量配图，多 Agent 并发改写不同章节。
3. **数据流水线**：清洗、统计、建模、渲染按 DAG 接力；数据集通过 SHA-256 CAS 传递，下游绝不读半成品 CSV。
4. **跨应用状态**：通过 AAP-1.0 挂载在线工作台 / SaaS 会话，通过 UOMP 管理共享记忆。

文章报告的两个数字决定了设计不能只围绕代码：

- 无协调共享目录中，约 **41.2%** 的并发写入发生丢失或脏读；非代码资产没有 Git 分支和编译器兜底。
- 在 500 次三 Agent 并发提交中，CoW + 事前租约锁 + 四级 LCS 可以达到 **98.7%** 自动无冲突收敛。

这意味着本设计必须把「代码仓库」抽象成更一般的 **Artifact Tree（工件树）**：

- **隔离**：CoW 对代码、文档、GB 级数据集、二进制文件同样有效；不是代码专属。
- **认领**：`coord_claim` 的粒度从「文件 / Glob」扩展到「章节 / 段落 / 表分区 / 行区间 / 二进制文件 / 应用记录」。
- **合并**：文本走四级 LCS；二进制走排他锁 + 基线哈希；Office 走双表面 CRDT 块级锁；数据走 Schema-aware / 分区策略；应用状态走 API diff。
- **预检**：`verify_cmd` 从单元测试扩展到 `latexmk`、`bibtex-check`、`schema-validate`、`scanPhi`、渲染检查、行数 / 哈希校验。
- **证据**：审批单从 Unified Diff 扩展到渲染后文档 diff、Schema diff、PHI 报告、二进制缩略图 + 哈希、应用字段级 diff。
- **安全**：内核隔离、边界审批、哈希链审计的承诺不变；变的是 `DomainProfile`，不是信任模型。

因此，后文的 Effect 模型、审批、CoW、客户端适配都按「通用工件树」设计；代码只是第一个、也是最成熟的 profile。

---

## 2. 目标与非目标

### 2.1 目标

| 编号 | 目标 | 验收方式 |
|---|---|---|
| G1 | `aegis-os run` 能在 Linux / macOS 上把 Agent 进程树放进内核沙箱 | Agent 内 `read ~/.ssh`、`write ../../host`、`curl` 任意域名均被内核拒绝或代理拦截 |
| G2 | enforced 模式下，Agent 的写入默认只落 shadow，宿主写入必须经 commit 审批 | 宿主文件 mtime 在 commit 前不变 |
| G3 | 只读 / 读写 / 命令 / 网络 / 凭据形成统一的 effect 策略模型 | 策略矩阵测试覆盖 100% 的 effect × scope 组合 |
| G4 | 审批按能力聚合，支持一次性、会话租约、任务租约、单次哈希锚定 | 典型 30 分钟工作会话的审批弹窗 ≤ 3 次 |
| G5 | 公开客户端能力矩阵，明确 advisory / enforced / isolated 三种承诺 | `aegis-os doctor` 和 `aegis-os status` 显示当前模式与强制等级 |
| G6 | OpenCode 作为一等客户端接入，且不被其共享后台服务绕过 | `opencode` 在 enforced 会话中，所有工具执行发生在沙箱内 Server |
| G7 | 不静默降级：沙箱、代理、broker 任一不可用则拒绝启动 | 删除 bwrap / 关闭代理后启动失败并给出修复命令 |
| G8 | 同一套事务内核支持 `code` / `docs` / `data` / `binary` / `app_state` / `memory` 领域 profile | 每个 profile 有独立的合并策略、认领粒度、预检门和证据格式 |
| G9 | 非代码领域有可执行的预检门 | LaTeX 编译、Markdown 死链、CSV Schema、PHI 扫描、二进制哈希、应用 API dry-run 均可作为 `verify_cmd` |
| G10 | 数据流水线通过 CAS + 任务 DAG 接力，下游不读半成品 | 上游 `org_artifact_publish` 后下游才能按 SHA-256 拉取；未发布的数据集不可见 |
| G11 | 一等支持 AGY、Claude Code、Codex、OpenCode、Hermes，并为其他 MCP Agent 提供通用适配协议 | 五个客户端有独立 adapter + 测试矩阵；任意 MCP Agent 可通过 manifest 接入 |

### 2.2 非目标

- 不承诺抵抗本机用户主动关闭保护、卸载 Aegis、使用另一个终端或直接运行绝对路径二进制。enforced 模式的目标是「绕过需要显式、可见、可审计的动作」，不是「物理上不可能」。
- 不承诺抵抗内核 0day、硬件侧信道、恶意固件。
- 不在 v1 支持 Windows 原生；WSL 可作为 Linux 目标。
- 不替代 Agent 自己的模型安全、内容审核和工具权限系统。
- 不做企业 MDM 客户端本身；只提供可被 MDM 管理的策略接口（Phase 5）。
- 不承诺自动推断所有领域语义：Schema、PHI、排版不变量需要用户 / 团队配置 `verify_cmd`；Aegis 负责强制执行和留痕，不负责替用户定义正确性。
- 不承诺二进制文件自动三路合并：二进制走排他锁 + 基线哈希 + 显式覆盖；Office 的块级合并是受支持格式的特例，不是通用能力。

### 2.3 成功指标

| 指标 | 目标 |
|---|---|
| enforced 会话占比 | 6 个月内 ≥ 40% 的活跃会话 |
| 越界攻击拦截率 | 现有 80 项红队用例 + 新增 20 项 launcher 用例，拦截率 100% |
| 审批疲劳 | 中位数 ≤ 3 次审批 / 30 分钟会话 |
| 启动开销 | APFS / Btrfs / XFS / OverlayFS：`aos run` 额外启动 P95 < 150 ms；ext4 lazy-copy 按数据量线性增长，不承诺 150 ms |
| 首 token 开销 | 代理引入的额外延迟 P95 < 30 ms |
| 崩溃率 | enforced 会话 crash-free ≥ 99.5% |
| 用户关闭保护比例 | < 5% 的 enforced 会话使用 `--no-enforce` |
| 静默覆盖 | 文档 / 数据 / 二进制场景 0 次 silent overwrite |
| 自动合并率 | 多 Agent 非重叠修改 ≥ 95% 自动合入 |
| 预检门有效性 | 领域 profile 的 verify 失败必须在落盘前拦截，误报率可观测 |
| CAS 可复现性 | 下游按 SHA-256 拉取，100% 不读半成品 |

---

## 3. 威胁模型与安全承诺

### 3.1 资产

- 宿主机源代码、未提交修改、Git 历史。
- 文档与知识库：Markdown / LaTeX / Word / PPT / PDF、参考文献、图表、设计稿。
- 数据资产：CSV / Parquet / JSON / SQL / notebook、数据库导出、统计结果、含 PHI / PII 的数据集。
- 二进制资产：图片、扫描件、CAD、压缩包、音视频。
- 跨应用状态：CRM / 日历 / 邮件 / SaaS 记录；UOMP 长期记忆。
- 凭据：`~/.ssh`、`~/.aws`、`~/.gnupg`、`~/.kube`、`~/.config/gh`、Keychain、`.env`、CI Token。
- 宿主其他目录：`~/Documents`、其他仓库、挂载盘。
- 组织共享存储、其他租户、其他 Agent 的 shadow。
- 审批入口、策略文件、审计账本。
- 出站网络与 API Key。

### 3.2 对手分层

| 等级 | 对手 | 能力 | 目标承诺 |
|---|---|---|---|
| A1 | 诚实但会犯错的 Agent | 幻觉、误删、误改、误读 | advisory 即可覆盖 |
| A2 | 被间接 prompt injection 控制的 Agent | 执行攻击者指定的工具调用 | enforced 覆盖 |
| A3 | 完全被控的 Agent / 恶意二进制 | 任意系统调用、任意子进程 | enforced + 内核隔离覆盖（不含内核 0day） |
| A4 | 本机用户或同权限恶意软件 | 可杀进程、改配置、直接执行 | 本地无解；isolated / 托管模式覆盖 |

### 3.3 信任边界

```text
┌─────────────────────────────────────────────────────────────┐
│ 宿主用户空间                                                 │
│                                                             │
│  ┌──────────────┐   控制面（人类）                            │
│  │ aos CLI /    │──── approve / revoke / status              │
│  │ Web Console  │                                            │
│  └──────┬───────┘                                            │
│         │ Unix socket / localhost                             │
│  ┌──────▼───────────────────────────────────────────────┐    │
│  │ Aegis Session Supervisor（launcher，受信任）           │    │
│  │  - session token / identity                           │    │
│  │  - policy broker（MCP + control API）                 │    │
│  │  - approval service / audit                           │    │
│  └──────┬───────────────────────────────────────────────┘    │
│         │ 内核沙箱（bwrap / Seatbelt / microVM）              │
│  ┌──────▼───────────────────────────────────────────────┐    │
│  │ Agent 进程树（不可信）                                 │    │
│  │  claude / codex / agy / opencode                     │    │
│  │  ├─ 原生 read/write/edit/shell                        │    │
│  │  ├─ MCP bridge（只能连 broker）                        │    │
│  │  └─ 子 Agent / 工具进程                                │    │
│  └───────────────────────────────────────────────────────┘    │
│                                                             │
│  宿主文件系统：shadow 可写；宿主工件树只读；$HOME 默认不可见     │
└─────────────────────────────────────────────────────────────┘
```

**关键规则**：

- Agent 进程树内的一切都不可信，包括 Agent 自带的 MCP Server、插件、子 Agent、构建脚本。
- 唯一的宿主写入通道是 broker 的 `workspace_commit`，且必须经过策略与人工审批。
- 审批入口只接受人类凭证，Agent token 不能调用。
- 审计账本在沙箱外，Agent 只能追加事件，不能修改历史。

### 3.4 安全承诺矩阵

| 模式 | 启动方式 | 强制点 | 能抵抗 A1 | 能抵抗 A2 | 能抵抗 A3 | 能抵抗 A4 |
|---|---|---|---|---|---|---|
| **Advisory** | 用户直接启动 Agent | Hook / Plugin / 规则 | ✅ | ⚠️ 部分 | ❌ | ❌ |
| **Enforced** | `aegis-os run` / PATH shim | 内核 + broker + 代理 | ✅ | ✅ | ✅ | ⚠️ 用户主动绕过可检测 |
| **Isolated** | `aos run --isolated` / Cloud | microVM + 远程策略 | ✅ | ✅ | ✅ | ✅（托管设备） |

**对外表述必须使用这张表**。禁止使用「任何 Agent 都安全」「彻底消除风险」这类绝对表述；可以说「enforced 模式下，Agent 无法直接读写宿主机文件，所有越界操作需人类审批」。

### 3.5 明确不承诺

- 不承诺隐藏 Agent 已经获得的模型 API Token。
- 不承诺阻止 Agent 把允许读取的项目源码发给模型提供方（这是 Agent 的正常工作方式）。
- 不承诺阻止用户自己把文件复制到沙箱里。
- 不承诺在用户拥有 root / 内核调试能力的设备上不可绕过。

---

## 4. 核心设计原则

1. **内核优先（Kernel over hooks）**：能由内核表达的边界，不用 Hook 表达。
2. **效果优先（Effects over tools）**：策略针对 `fs.read` / `fs.write` / `proc.exec` / `net.request` / `secret.use`，不针对 `Bash` / `Write` 等工具名。
3. **用户数据窄读（Narrow user-data read scope）**：系统 / 工具链只读可见（兼容 NixOS / Linuxbrew / Snap），`$HOME`、`/root`、`/run`、`/var`、`/mnt`、`/media`、`/srv` 默认用 tmpfs 遮蔽；只按 `read_scope` 挂回项目、工具链和显式依赖。
4. **可逆优先（Reversible by default）**：shadow 内写入自动放行并可快照回滚；宿主写入和远程变更才需要审批。
5. **能力租约（Capability leases）**：审批一次能力，而不是每次调用；租约有时限、范围、任务绑定和撤销。
6. **不静默降级（Fail closed）**：沙箱、代理、broker 任一缺失，enforced 模式拒绝启动。
7. **状态可见（Visible enforcement）**：终端标题、`aos status`、`doctor` 至少一处显示当前模式。
8. **退出不丢（No silent loss）**：Agent 退出时汇总 shadow 变更，提供 diff / commit / discard / recover。
9. **平台诚实（Platform honesty）**：macOS 无法做路径重映射就明说；用 VM 形态解决，不假装。
10. **兼容层可替换（Adapters are thin）**：所有客户端适配器只做协议转换，策略判断统一走 Rust broker。

---

## 5. 产品形态与用户旅程

### 5.1 四种形态

| 形态 | 用户输入 | 启动者 | 强制等级 | 适用场景 |
|---|---|---|---|---|
| **Advisory** | `claude` / `opencode` | 用户 | 低 | 尝鲜、IDE、无法使用 launcher 的环境 |
| **Enforced Local** | `claude` / `opencode`（PATH shim） | Aegis | 高 | 日常终端开发 |
| **Explicit Enforced** | `aos run -- claude` | Aegis | 高 | CI、脚本、团队规范 |
| **Isolated** | `aos run --isolated -- claude` / Cloud | Aegis / Cloud | 最高 | 不可信仓库、企业、多租户 |

默认策略：

- `aegis-os install`：安装 advisory 集成，保持兼容。
- `aegis-os install --enforce`：安装 PATH shim，默认 enforced；同时在 `doctor` 中显示强制等级。
- 企业托管配置可以强制 `enforced` 或 `isolated`，禁止 `--no-enforce`。

### 5.2 一次性安装

```bash
$ aegis-os install --enforce
✓ aegis-os 0.4.6
✓ 已创建 ~/.aegis/bin
✓ 检测到并接入：claude / codex / agy / opencode / hermes
  以后直接输入 claude 即为 enforced 模式
  PATH shim: ~/.aegis/bin（已置于 PATH 最前）
  查看状态: aegis-os status
  临时关闭: aegis-os run --no-enforce -- claude
```

安装器行为：

- 扫描 `PATH` 中已知 Agent；当前实现配置 AGY / Claude / Codex / OpenCode，`--all` / `--agent <id>` 仍是 planned。
- 写入 `~/.aegis/bin/{claude,codex,agy,opencode,hermes}` shim；shim 解析真实二进制时排除 `~/.aegis/bin`，避免递归；`AOS_ENFORCEMENT=advisory` 会让 shim 直接执行真实二进制。
- 在 shell 配置中追加 `export PATH="$HOME/.aegis/bin:$PATH"`（fish 用 `set -gx PATH`），支持 `.zshrc` / `.bashrc` / `.profile` / fish；用标记块保证幂等。
- 保留原始客户端配置；不覆盖用户已有 MCP / Hook，只合并标记块。
- 未知 MCP Agent 打印 `aos agent add` 指引，不假装支持（`aos agent add` 仍 planned）。
- `aegis-os uninstall --shim-only` 移除 shim 与 shell PATH block；当前不会自动删除客户端 MCP/Hook 块，也不会删除 shadow，需手工处理。

### 5.3 日常启动

```bash
$ cd ~/work/payments && claude
  Aegis · enforced · payments
  shadow ready (1,284 files, 12 ms) · egress proxy · session ses_7f3a
[正常的 Claude Code TUI]
```

- 首次启动显示两行说明；之后只保留终端标题 `aegis:enforced`。
- 不改变 Agent 的参数；`claude --resume`、`opencode run "..."`、`codex exec` 原样透传。
- `aos status` 显示当前会话、模式、shadow、租约、待审批。

### 5.4 工作中

| 场景 | 用户感受 |
|---|---|
| Agent 读写工作区工件、跑测试 / 编译 / 渲染 / Schema 校验 | 和平时一样，0 弹窗；写入落 shadow |
| Agent 读 `~/.ssh` | Agent 收到 `Permission denied`；用户只在 `aos top` 看到审计事件 |
| Agent 读项目外 `~/work/shared` | 首次弹一次「允许读取 30 分钟？」；允许后本会话自动放行 |
| Agent `git push` / `npm publish` | 命令级审批；显示远端、分支、影响 |
| Agent `workspace_commit` | Diff 审批；批准后落盘，Agent 继续 |
| Agent 起子 Agent / 构建脚本 | 继承沙箱；不会逃逸到宿主 |

### 5.5 结束

**Agent 主动 commit**：

```text
Aegis: agent requests to land 7 files
  + src/auth/session.rs      +42 −8
  + src/auth/mod.rs          +3  −1
  ...
  [a]pprove  [d]eny  [v]iew diff
```

**Agent 未提交就退出**：

```text
Agent exited. 7 files changed in shadow.
  aegis-os diff      查看
  aegis-os commit    落盘（走审批）
  aegis-os discard   丢弃
  aegis-os last      定位上一次会话的 shadow 目录
```

这条摘要必须由 launcher 在 Agent 退出后打印，不能依赖 Agent 自己汇报。

### 5.6 异常与降级

| 异常 | 行为 |
|---|---|
| 找不到 bwrap / Seatbelt | enforced 启动失败，给出安装命令；不降级 |
| egress proxy 启动失败 | 启动失败；不静默直连 |
| MCP broker 不可达 | 启动失败；提示 `aos doctor` |
| Hook 未加载 | enforced 仍安全；`doctor` 显示「Hook 缺失，UX 降级」 |
| Agent 崩溃 | shadow 保留；`aos last` 定位最近会话 |
| 用户 `--no-enforce` | 启动 advisory；记录审计事件；企业策略可拒绝 |

### 5.7 关闭保护

```bash
aegis-os run --no-enforce -- claude
# 或
AOS_ENFORCEMENT=advisory claude
```

- 必须显式；不提供隐式「检测到不兼容就自动关闭」。
- 审计记录：谁、何时、在哪个项目关闭。
- 企业托管模式可以禁止。

### 5.8 非代码场景的用户旅程

**多文件文档 / 知识库**：

```bash
$ cd ~/work/grant-proposal && aos run --profile docs -- claude
  Aegis · enforced · docs · grant-proposal
  shadow ready (86 files, 9 ms) · verify: latexmk + bibtex + link-check
```

- Agent A 锁定 `chapters/03-methods.tex`，Agent B 锁定 `chapters/05-results.tex`，并行改写不冲突。
- 生成 `figures/*.pdf` 时走二进制排他锁 + 基线哈希；人类刚在 Illustrator 里改过同一张图，Agent 的覆盖被拦截，必须显式 `overwrite_binaries` 审批。
- commit 前跑 `latexmk -pdf`、`bibtex-check`、`markdown-link-check`；失败则不落盘，证据里带编译日志和渲染后的 PDF 预览。

**数据流水线（Phase 5）**：

```bash
$ cd ~/work/cohort-study && aos run --profile data -- claude
  Aegis · enforced · data · cohort-study
  shadow ready (1.2 GB, 14 ms, overlay) · verify: schema + PHI + row-count
```

- 清洗 Agent 锁定 `data/clean/*.parquet` 分区；统计 Agent 只读清洗结果，不能读半成品。
- 上游完成后 `org_artifact_publish` 写入 SHA-256 CAS，任务 DAG 把哈希指针推给下游。
- commit 前 `schema-validate && scanPhi --strict`；PHI 命中则拒绝，审批单显示字段级报告。

**跨应用状态 / 记忆（Phase 5）**：

```bash
$ aos run --profile app_state -- opencode --standalone
  Aegis · enforced · app_state · CRM + calendar
```

- Agent 通过 `app_mount_session` / `app_call_tool` 读写在线工作台；效果模型记录 `app.read` / `app.write` / `app.invoke`。
- 写操作审批显示字段级 diff、API 请求预览、DLP 结果；不是文件 diff。
- 共享记忆走 UOMP scope lease；读取需要目的和保留期，写入可撤销。

**退出摘要**也要领域化：

```text
Agent exited. 7 artifacts changed in shadow.
  chapters/03-methods.tex      +42 −8
  figures/fig-03.pdf            binary · baseline hash changed
  data/clean/cohort.parquet     schema +2 cols · PHI: 0
  aegis-os diff --render       查看渲染后的文档 / 图表
  aegis-os verify              跑领域预检门
  aegis-os publish             发布到 CAS
  aegis-os commit              落盘（走审批）
```

### 5.9 首发支持的 Agent

| Agent | 形态 | 首发级别 | enforced 启动方式 | advisory 集成 |
|---|---|---|---|---|
| **Claude Code** | CLI / IDE / Desktop | Tier A | `aos run -- claude` | PreToolUse + `updatedInput` |
| **AGY** | CLI / IDE | Tier A | `aos run -- agy` | PreToolUse |
| **Codex** | CLI | Tier A | `aos run -- codex` | MCP + `AGENTS.md`（无工具级 Hook） |
| **OpenCode** | CLI / Desktop | Tier A | `aos run -- opencode --standalone` | V2 Plugin + MCP |
| **Hermes** | CLI | Tier A | `aos run -- hermes` | Adapter Protocol + MCP |
| Gemini CLI / Aider / Goose / Amp | CLI | Tier B | `aos run -- <agent>` | MCP + manifest，按能力降级 |
| Cline / Continue / Roo Code / Cursor / Windsurf / VS Code / JetBrains | IDE / GUI | Tier D | Phase 5 扩展 / daemon | 扩展或远程 workspace |
| 任意 MCP Agent | CLI | Tier C | `aos run -- <agent>` | MCP + 规则，advisory 弱 |

原则：

- **五个 Tier A 是一等公民**：独立 adapter、CI 冒烟、版本矩阵、`doctor` 检查。
- **Tier B/C 通过 manifest 接入**，不硬编码；advisory 能力按客户端真实能力标注。
- **Tier D 不承诺终端 shim**；必须用 IDE 扩展、daemon 或 isolated workspace。
- **enforced 路径统一**：无论哪个 Agent，最终都是 `aos run` + 内核沙箱 + broker，不依赖客户端自身的安全机制。

---

## 6. 总体架构

```mermaid
flowchart TB
    Human["人类用户"] -->|"aos run / shim"| Launcher["Aegis Launcher / Session Supervisor"]
    Launcher -->|"创建"| CoW["CoW Shadow Workspace\ncode / docs / data / binary"]
    Launcher -->|"创建"| Sandbox["Kernel Sandbox\nbwrap / Seatbelt / microVM"]
    Launcher -->|"启动"| Broker["Policy Broker\nMCP + control API"]
    Launcher -->|"启动"| Egress["Egress Proxy\n域名 / 方法 / DLP / 密钥注入"]
    Launcher -->|"启动"| Agent["Agent 进程树\nclaude / codex / agy / opencode / hermes"]

    Agent -->|"native fs / proc"| Sandbox
    Agent -->|"MCP bridge / adapter"| Broker
    Sandbox -->|"唯一写路径"| CoW
    CoW -->|"commit 审批"| Broker
    Broker -->|"Allow / Ask / Deny"| Policy["Policy Engine\nCedar + Leases + DomainProfile"]
    Broker -->|"审计"| Audit["Hash-chain Audit"]
    Broker -->|"审批"| Human
    Broker -->|"publish / fetch"| Cas["SHA-256 CAS\norg_artifact_*"]
    Broker -->|"app / memory"| External["AAP-1.0 / UOMP"]
    Sandbox -->|"网络"| Egress
    Egress -->|"allowlist + DLP"| Internet["Internet / Model API"]
    CoW -->|"commit"| Host["Host Artifact Tree"]
```

### 6.1 组件职责

| 组件 | 职责 | 是否受信任 |
|---|---|---|
| **Launcher**（`aegis-os run`） | 创建会话、启动 broker / sandbox / agent、PTY、信号、退出摘要 | ✅ 受信任 |
| **Session Supervisor** | 会话状态、token、lifecycle、控制 socket | ✅ 受信任 |
| **Policy Broker** | MCP 工具、effect 评估、审批、commit、审计 | ✅ 受信任 |
| **Kernel Sandbox** | 文件视图、进程隔离、网络隔离 | ✅ 内核 |
| **Egress Proxy** | 出站 allowlist、方法/路径、DLP、密钥注入 | ✅ 受信任 |
| **CoW Workspace** | shadow、diff、snapshot、commit | ✅ 受信任 |
| **Domain Profile Resolver** | 识别 code / docs / data / binary / app_state，选择合并器、预检门、证据格式 | ✅ 受信任 |
| **CAS Artifact Bus** | SHA-256 内容寻址、发布/拉取、下游哈希指针 | ✅ 受信任 |
| **AAP-1.0 / UOMP** | 跨应用状态、记忆 scope lease | ✅ 受信任（协议） |
| **Agent** | 执行模型指令、调用工具 | ❌ 不可信 |
| **Client Adapter** | Hook / Plugin / MCP bridge / Adapter Protocol | ❌ 不可信，仅 UX |
| **Approval UI** | 人类审批 | ✅ 人类 |

### 6.2 关键架构变化

1. **MCP Server 从 Agent 子进程变成 Broker**：enforced 模式下，broker 由 launcher 启动，运行在沙箱外；Agent 通过沙箱内的 MCP bridge 连接。broker 的身份来自 session token，不来自 Agent 传入的 `--org` / `--agent`。
2. **原生工具不再强制重定向**：enforced 模式下，Agent 的 `read` / `write` / `edit` / `shell` 可以直接用，因为内核已经把它们限制在 shadow + 只读视图内。MCP `fs_*` 仍保留，用于跨 Agent 协调和显式 diff/commit，但不是唯一写路径。
3. **审批入口与 Agent 隔离**：Agent token 只能调用 `tools/call`；审批、租约撤销、策略修改只能由人类 CLI / Web 用人类 token 调用。
4. **审计在沙箱外**：Agent 只能产生事件，不能改账本。
5. **OpenCode 的共享后台服务必须被隔离**：OpenCode V2 默认把工具执行放在共享后台服务中；enforced 模式必须使用 `--standalone`，或在沙箱内启动 `opencode serve` 并由 `--server` 连接，否则 TUI 在沙箱里也没用。

---

## 7. 详细设计

### 7.1 Launcher / Session Supervisor

#### 7.1.1 CLI

```bash
aegis-os run [OPTIONS] -- <agent> [agent-args...]

Options:
  --mode <observe|implement>     会话模式，默认 implement
  --enforcement <advisory|enforced|isolated>   # isolated planned
  --workspace <path>             项目目录，默认 cwd
  --session <id>                 恢复已有会话（planned）
  --no-enforce                   显式降级到 advisory
  --read-only                    等价于 --mode observe
  --isolated                     等价于 --enforcement isolated（planned）
  --no-shim                      跳过 PATH shim 检查（planned）
```

示例：

```bash
aos run -- claude
aos run --mode observe -- claude
aos run --enforcement isolated -- opencode --standalone
aos run -- opencode --standalone
```

#### 7.1.2 生命周期

1. 解析参数、解析真实 Agent 二进制、检测是否已在 Aegis 会话内（`AOS_SESSION_ID`）；禁止嵌套 enforced 会话。
2. 生成 `session_id`（`ses_<ulid>`）和 256-bit session token。
3. 创建 runtime 目录：`~/.aegis/sessions/<id>/`。
4. 创建 CoW shadow；记录 baseline。
5. 构建 `SandboxConfig`；启动 broker、egress proxy、approval service。
6. 构建内核沙箱命令；启动 Agent，继承 PTY / stdio。
7. 转发信号（`SIGINT`、`SIGTERM`、`SIGWINCH`）和退出码。
8. Agent 退出后：停止 broker / proxy，汇总 shadow 变更，打印退出摘要，持久化 session 元数据。

#### 7.1.3 PTY 与信号

> **当前实现**：真实终端下使用 `openpty` + `setsid`/`TIOCSCTTY` 启动 bwrap，保留 raw mode、窗口尺寸和输入流；管道 / CI 仍使用继承 stdio，避免注入终端控制序列。`SIGWINCH` 会 resize PTY 并转发信号；`SIGTERM` / 两次 Ctrl-C 路径已覆盖。

- 使用 `forkpty` / `openpty`（Rust `nix` 或 `portable-pty`）；Agent 的 TUI、颜色、鼠标、窗口大小全部保持。
- `SIGWINCH` 转发到沙箱内 Agent；`SIGINT` 转发到前台进程组；`SIGTERM` 先优雅关闭，超时后 `SIGKILL` 进程组。
- 退出码透传；如果 Agent 被信号杀死，launcher 返回 128+signal，并保留 shadow。
- **TUI 活跃期间，Supervisor 不向 PTY master 混写审批文本 / 日志 / 格式化的 stderr**；仅允许 BEL、OSC 0 标题等无内容控制序列，避免冲乱 alternate screen / raw mode，或与 Agent 的输入流竞争。日志写 `~/.aegis/sessions/<id>/logs/`。
- 审批通知走旁路：结构化挂起状态（MCP / Hook 返回）、桌面通知、BEL、OSC 0 终端标题；交互在另一个终端 `aos approve` 或 Web 完成。
- 如确实要在单终端内嵌提示，由 launcher 用 DECSTBM 维护独立滚动区 / 状态栏，不写 Agent 的主屏幕；Phase 1 不做内嵌审批。

#### 7.1.4 路径映射

以下以代码仓库为例；文档、数据、二进制工作区同理，只是 `DomainProfile` 不同。

**Linux（bwrap）**：

```text
shadow:      ~/.aegis/sessions/<id>/shadow
宿主工件树:  /home/user/work/payments（只读）
Agent 视图:  /home/user/work/payments -> bind shadow（读写）
             /aegis/host/payments       -> ro-bind 宿主工件树（只读）
             AOS_HOST_ROOT=/aegis/host/payments
```

- Agent 看到的 cwd 和绝对路径与宿主一致，避免“为什么路径变了”的困惑。
- 宿主工件树不在 Agent 视图内以原路径出现，防止通过 `/home/user/work/payments` 直接读写宿主。
- 只读 git / 渲染 / 数据探查用 `AOS_HOST_ROOT`。
- 文档 / 数据 / 二进制工作区同样使用 shadow bind；`AOS_HOST_ROOT` 指向只读原件，用于对比、渲染和基线哈希。

**macOS（Seatbelt）**：

- Seatbelt 没有 mount namespace，无法把 shadow 映射到原路径。
- 方案 A（v1）：Agent 的 cwd 设为 shadow，`PWD` 设为 shadow；banner 明确显示 `Aegis workspace: <shadow>`。绝对路径会显示 shadow 路径，但不影响功能。
- 方案 B（Phase 5）：`isolated` 模式使用轻量 VM + virtiofs，把 shadow 挂到原路径，彻底解决。
- 不使用「把宿主目录 rename 成 shadow」这类破坏性方案。

#### 7.1.4.1 Git 视图映射

**问题**：`CoWWorkspace` 的 shadow 默认不包含 `.git`。如果直接把 shadow 挂到原项目路径，Claude Code、Codex、OpenCode 等启动时会检查 Git 仓库、读取分支名、跑 `git status` / `git diff`，全部会报 `fatal: not a git repository`；Agent 的项目上下文和内置 diff 也会失效。

**目标**：让沙箱内的只读 Git 命令原生可用，同时保证 Agent 不能写宿主 `.git`、不能执行仓库里的 hooks、不能篡改 refs/config。

**Linux（bwrap）**：

- Shadow 通过 `--bind <shadow> <project>` 挂到 Agent 的原项目路径；Agent 看到的路径是 `<project>`，宿主侧才是 `<shadow>`。因此 `.git` 和 index 的挂载点要用 **Agent 视图路径**，不是宿主侧 shadow 路径：
  - 普通仓库：`--ro-bind /aegis/host/<name>/.git <project>/.git`
  - worktree / submodule 的 `.git` 文件：`--ro-bind /aegis/host/<name>/.git <project>/.git`（文件级；当前实现只处理 `.git` 目录，文件级待补）
- `GIT_INDEX_FILE=$HOME/.aegis-git-index`：从宿主 `.git/index` 复制一份可写副本到 agent home（不在工作树内，避免 `git status` 看到未跟踪文件）；`git status` 只更新这份索引，不碰宿主。
- `GIT_OPTIONAL_LOCKS=0`：减少不必要的 index 刷新。
- `GIT_DIR` / `GIT_WORK_TREE` 作为 fallback：`GIT_DIR=/aegis/host/<name>/.git`、`GIT_WORK_TREE=<project>`（不是宿主侧 `<shadow>`）。
- 在 shadow 内放一个 `git` shim（见下），强制安全参数。
- **OverlayFS 注意**：lowerdir 指向宿主项目时，`.git` 会随 lowerdir 出现在 merged 视图里；overlay 的写入会 copy-up 到 upperdir，虽然不会改宿主，但仍建议用 ro-bind 覆盖 `.git`，或在 git shim 中禁止写 `.git`，确保 `.git/config` / hooks / refs 不可被 Agent 修改。

**macOS（Seatbelt）**：

- 没有 mount namespace，Agent 的 cwd 就是宿主侧 shadow；在 `<shadow>/.git` 写一个只读文件：
  ```text
  gitdir: /aegis/host/<name>/.git
  ```
- 同样设置 `GIT_INDEX_FILE=$HOME/.aegis-git-index`；Seatbelt 规则拒绝写入 `/aegis/host/<name>/.git`。
- 其他限制与 Linux 相同。

**允许的 Git 操作**：

- 只读：`status`、`diff`、`log`、`show`、`branch --show-current`、`rev-parse`、`ls-files`、`grep`、`blame`、`describe`、`tag --list`。
- 禁止：`commit`、`push`、`pull`、`fetch`、`checkout`、`switch`、`reset`、`rebase`、`merge`、`clean`、`submodule`、`worktree`、`config`、`update-ref`。
- 禁止的操作返回结构化提示：改用 `aos commit` / `aos diff`；宿主写入和远端变更走 broker。
- 需要 `commit` / `push` 时，Agent 不应在沙箱内执行 `git`；应调用 Aegis 的 commit / host boundary 工具，由 broker 在宿主侧执行并审批。

**Git 安全 shim**：

- 在 `PATH` 最前放一个 `git` wrapper：
  - 只读子命令自动加 `--no-ext-diff --no-textconv`，避免仓库 `.gitattributes` / `diff.*.command` 执行任意程序。
  - 强制 `GIT_CONFIG_NOSYSTEM=1`、`GIT_CONFIG_GLOBAL=/dev/null`、`GIT_OPTIONAL_LOCKS=0`。
  - 禁止 `core.fsmonitor` / `core.hooksPath` 执行：设置 `-c core.fsmonitor=false -c core.hooksPath=/dev/null`。
  - 拒绝 mutating 子命令，返回「请使用 `aos commit`」。
- 这不是安全边界的唯一依赖：即使 shim 被绕过，宿主 `.git` 也是只读的，`.git/hooks` 不会执行。

**残留风险**：

- `.git/config` 可能包含带 token 的 remote URL；只读可见。企业策略可以额外 mask `url.*.insteadOf` 或把 remote URL 替换为无凭据形式。
- Git LFS 可能需要写 `.git/lfs`；默认禁用 smudge（`GIT_LFS_SKIP_SMUDGE=1`），需要 LFS 的场景走 broker 或独立缓存。
- 大型仓库的 `git status` 仍可能较慢；`GIT_OPTIONAL_LOCKS=0` 和 fsmonitor 禁用后以正确性优先。

#### 7.1.5 环境变量与认证

- `env_clear()` 后只注入：
  - `PATH`、`HOME`（沙箱 home）、`TMPDIR`、`TERM`、`LANG`、`SHELL`。
  - Agent 自己的认证变量：`ANTHROPIC_API_KEY`、`OPENAI_API_KEY`、`GEMINI_API_KEY`、`OPENCODE_*` 等，按客户端 allowlist 注入。
  - `AOS_SESSION_ID`、`AOS_SESSION_TOKEN`、`AOS_WORKSPACE`、`AOS_HOST_ROOT`、`AOS_ENFORCEMENT`。
  - `GIT_INDEX_FILE=$HOME/.aegis-git-index`、`GIT_OPTIONAL_LOCKS=0`、`GIT_CONFIG_NOSYSTEM=1`、`GIT_CONFIG_GLOBAL=/dev/null`。
  - `HTTP_PROXY` / `HTTPS_PROXY` 指向沙箱内 egress bridge。
- 不注入 `SSH_AUTH_SOCK`、`GPG_AGENT_INFO`、云厂商全局凭证；需要时走 egress 代理注入。
- macOS Keychain / OAuth：优先使用 Agent 自己的登录态文件；OAuth refresh token 需要可写时，使用 0600 的单文件挂载并在会话结束后原子写回，不把整个 Keychain 暴露给沙箱。
- **当前实现**注入 `AOS_SESSION_ID` / `AOS_SESSION_TOKEN` / `AOS_CONTROL_SOCKET` / `AOS_ENFORCEMENT` / `AOS_WORKSPACE` / `AOS_HOST_ROOT` / `AOS_PROFILE` 等；`AOS_CONTROL_SOCKET` 指向只读挂载的 per-session broker socket。
- L7 Base URL 模式下，`ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` / `OPENAI_API_KEY` 在沙箱内是 `$AOS_SECRET_*` 占位符；真实值只存在于 egress gateway 的 vault，并在 loopback → provider 的边界注入。

#### 7.1.5.1 Agent 状态目录分层

**问题**：主流 CLI Agent 在运行时会写自己的状态目录：Claude Code 写 `~/.claude/projects/*.jsonl`、`~/.claude/todos`、`~/.claude/.credentials.json`；Codex 写 `~/.codex/sessions`、`~/.codex/log`、`~/.codex/auth.json`；OpenCode 写 `~/.local/share/opencode` 的 SQLite / 日志 / 会话。把整个 `~/.claude` / `~/.codex` / `~/.config/opencode` 设为只读，会导致会话记录丢失、OAuth refresh 失败、SQLite 打不开。

**规则：敏感配置单文件只读，状态目录按需可写。**

| 路径 | 访问 | 持久化 | 说明 |
|---|---|---|---|
| `~/.claude/settings.json`、`~/.claude.json` | 单文件 `ro` | 宿主 | Hook / MCP / 权限配置，禁止 Agent 篡改 |
| `~/.gemini/config/hooks.json`、`mcp_config.json` | 单文件 `ro` | 宿主 | AGY Hook / MCP 配置 |
| `~/.codex/config.toml` | 单文件 `ro` | 宿主 | MCP / sandbox / approval 配置 |
| `~/.config/opencode/opencode.json(c)` | 单文件 `ro` | 宿主 | MCP / plugin / permissions |
| `~/.claude/projects`、`~/.claude/todos`、`~/.claude/shell-snapshots` | `rw` | 会话或持久 | 会话记录、todo、shell 快照 |
| `~/.claude/.credentials.json` | `rw` 0600 | 宿主（原子写回） | OAuth refresh；也可后续改为代理托管 |
| `~/.codex/sessions`、`~/.codex/log` | `rw` | 会话或持久 | 会话 / 日志 |
| `~/.codex/auth.json` | `rw` 0600 | 宿主（原子写回） | OAuth / API 登录态 |
| `~/.local/share/opencode` | `rw` | 会话或持久 | SQLite、日志、会话 |
| `~/.cache/*` | `rw` | 会话 | 缓存，可丢弃 |
| `~/.claude/plugins`、`~/.codex/plugins` | `ro` | 宿主 | 插件代码，禁止运行期修改 |
| 其他 `$HOME` | 不可见 | — | `$HOME` 是 tmpfs |

**Linux 实现**：

- `$HOME` 挂到 `~/.aegis/sessions/<id>/agent_home`（tmpfs 或目录）。
- 先 `--bind` 可写状态目录，再对敏感配置文件做单文件 `--ro-bind` 覆盖；bwrap 按顺序应用，后挂载的只读文件生效。
- 对 `~/.claude` 这种混合目录：`--bind ~/.claude/projects`、`--bind ~/.claude/todos`、`--ro-bind ~/.claude/settings.json`；不要整目录 `--bind ~/.claude`。
- `.credentials.json` 用 `--bind`，权限 0600；会话结束后由 launcher 校验 JSON 结构并原子写回宿主，失败则保留在 session 目录供人工恢复。

**macOS 实现**：

- Seatbelt 不能做 bind mount；用 per-session `$HOME` + 符号链接 / 拷贝：
  - 敏感配置拷贝为只读文件，Seatbelt 规则拒绝写入；
  - 状态目录用符号链接指向宿主可写目录，Seatbelt 只允许写这些子路径；
  - 或者统一使用 `isolated` 模式（VM + virtiofs）获得完整挂载语义。

**原则**：

- Agent 可以写自己的「运行状态」，但不能写自己的「安全配置」。
- 任何对 `settings.json` / `hooks.json` / `config.toml` / `opencode.json` 的修改都必须走人类审批（`aos config`），不能由 Agent 在沙箱内完成。
- 状态目录可能包含敏感对话内容；默认只保留最近 N 天，企业策略可配置加密 / 关闭持久化。

#### 7.1.6 子 Agent 与嵌套

- 子 Agent 继承同一个沙箱、session token、shadow。
- 禁止在 enforced 会话内再启动 `aos run`（检测 `AOS_SESSION_ID`），避免嵌套沙箱和身份混乱。
- Agent 自带的 subagent / task 工具不受影响，仍在同一进程树内。
- 多 Agent 并行（两个终端）各自独立 session / shadow；通过 `coord_claim` 和 read/write claim 协调。

#### 7.1.7 退出摘要

```rust
struct SessionSummary {
    session_id: String,
    mode: SessionMode,
    enforcement: EnforcementLevel,
    changed_files: Vec<FileDiffEntry>,
    denied_effects: Vec<EffectRecord>,
    pending_escalations: Vec<String>,
    duration_ms: u64,
    shadow_path: PathBuf,
}
```

- 打印到 stderr，避免污染 stdout 管道。
- `aos last` 读取最近 session 的 summary 和 shadow。
- `aos discard` 删除 shadow；`aos commit` 走审批。

### 7.2 内核隔离

#### 7.2.1 Linux：bwrap + Landlock + seccomp

当前 `aos-sandbox` 的 `generate_linux_bwrap_args` 已经使用：

- `--unshare-all`、`--die-with-parent`、`--proc /proc`、`--dev /dev`、`--new-session`。
- `--tmpfs /tmp`、`--tmpfs $HOME`、工具链只读回挂。
- `--bind workspace`、`--bind agent_home`、`--ro-bind org_shared`。
- 可选 `--share-net`（无 egress 时）。

enforced launcher 需要新增/调整：

| 项目 | 设计 |
|---|---|
| 读视图 | **保留 `--ro-bind / /`** 保证 NixOS / Linuxbrew / Snap / 发行版路径兼容；随后用 `--tmpfs` 遮蔽 `/home`、`/root`、`/run`、`/var`、`/tmp`、`/mnt`、`/media`、`/srv`；再按 `read_scope` 挂回 shadow、`/aegis/host`、工具链和声明的依赖目录 |
| 宿主工件树 | `--ro-bind <host_project> /aegis/host/<name>`；不挂原路径 |
| shadow | `--bind <shadow> <host_project>`（路径保持不变） |
| `$HOME` | `--tmpfs <home>`；按 §7.1.5.1 只读挂载敏感配置、可写挂载 Agent 状态目录；不挂其他用户目录 |
| 写 | 只允许 shadow、agent home、org pub；其他 `--tmpfs` 或不存在 |
| 网络 | `--unshare-net`；egress 通过 Unix socket bridge；不提供 `--share-net` |
| 进程 | `--unshare-pid`、`--unshare-uts`、`--unshare-ipc`；`--new-session` |
| 设备 | 最小 `/dev`；不挂 Docker socket、GPU 设备（除非显式声明） |
| 资源 | cgroup v2：CPU / memory / pids / disk quota；超限杀进程组 |
| 加固 | `no_new_privs`；seccomp denylist（`mount`、`pivot_root`、`setns`、`unshare`、`ptrace`、`process_vm_readv`、`bpf`、`keyctl`、`perf_event_open`、`userfaultfd`）；可选 Landlock 作为第二层读写/执行限制 |

实现注意：

- **保留 `--ro-bind / /` 是兼容性决策，不是安全退让**：NixOS 的 `/nix/store`、Linuxbrew 的 `/home/linuxbrew/.linuxbrew`、Snap 的 `/snap`、`/etc/alternatives`、各发行版 CA 路径都能直接工作，避免手动枚举导致 ENOENT / SSL 错误。
- **先遮蔽用户数据，再挂回白名单**：`--tmpfs /home /root /run /var /tmp /mnt /media /srv`；然后按 `read_scope` 挂回：
  - 当前 shadow（bind 到原路径）
  - `/aegis/host/<name>`（宿主工件树只读）
  - 工具链：`~/.cargo`、`~/.rustup`、`~/.local/bin`、`~/.bun`、`~/.volta`、`~/.nvm`、`/home/linuxbrew/.linuxbrew`、TeX Live、Pandoc、LibreOffice（headless）
  - Agent 配置 / 状态目录（§7.1.5.1）
- **`/etc` 敏感文件单点遮蔽**：`/etc/shadow`、`/etc/gshadow`、`/etc/sudoers`、`/etc/sudoers.d`、`/etc/ssh/ssh_host_*`、`/etc/ssl/private`、`/etc/kubernetes`、`/etc/wireguard`、`/etc/letsencrypt`、`/etc/openvpn`、`/etc/docker`、`/etc/containerd`、`/etc/gitlab`。文件用 `--ro-bind /dev/null`，目录用 `--tmpfs`；NixOS 的 `/etc` 大多是 symlink，优先单文件遮蔽，避免整目录 tmpfs 破坏解析。
- **`/opt`、`/nix`、`/snap`、`/usr` 保持只读可见**；这些目录通常是公开工具链，不是用户数据。
- **`/proc` 使用 fresh procfs**；`/sys` 默认 tmpfs 或只读遮蔽，除非 profile 显式需要；`/dev` 使用最小 devtmpfs。
- **bwrap 挂载点**：`--bind <src> <dest>` 要求 `<dest>` 存在；先用 `--dir` 创建 `/home/<user>/<project>`、`<project>/.git`、`/aegis/host/<name>`，以及 `$HOME/.claude`、`$HOME/.codex`、`$HOME/.config/opencode`、`$HOME/.local/share/opencode` 等状态目录挂载点，或保留最小目录骨架。
- **`/bin`、`/lib`、`/lib64`** 多数发行版是 `/usr` 的符号链接；保留 `--ro-bind / /` 后无需单独处理，若做额外挂载使用 `--ro-bind-try` 允许失败。
- **Landlock 作为第二层**：在 bwrap 之后进一步限制读路径（允许 `/usr`、`/lib`、`/nix`、`/snap`、`/etc` 的只读系统文件如 `ld.so.cache` / `passwd` / `group` / `nsswitch.conf` / `hosts` / `resolv.conf` / `localtime` / `ssl`、shadow、`/aegis/host`、工具链；拒绝 `/home` 其他路径、`/root`、`/run`、`/var`）。即使 bwrap 的 tmpfs 配置漏了某个路径，Landlock 也能兜底。
- **兼容性测试矩阵**：Ubuntu / Debian / Fedora / Arch / NixOS / Linuxbrew / Snap；每个发行版至少跑 `cargo`、`node`、`python`、`git`、`openssl`、`curl` 六类命令。
- **不承诺**：`/etc` 中未知的自定义密钥文件自动隐藏；企业环境应通过 `AOS_EXTRA_CREDENTIAL_PATHS` 或 Landlock 策略补充。

**Landlock 落地方式**：

- 新增 `aos-sandbox-init` 小二进制，在 `bwrap` 内、`exec` Agent 前调用 `landlock_create_ruleset`：
  - 读：项目 shadow、`/aegis/host`、工具链、Agent 配置、系统目录。
  - 写：shadow、agent home、org pub。
  - 执行：`/usr/bin`、`/bin`、工具链 bin、Agent 自身路径。
- Landlock ABI < 3 时降级为 bwrap-only，并在 `doctor` 标记 `landlock: unavailable`；enforced 模式是否拒绝启动由策略决定（默认允许，但显示降级）。
- 这一步需要新增依赖（`landlock` crate 或直接 syscall），放在 Phase 4。

#### 7.2.2 macOS：Seatbelt

当前 `generate_macos_seatbelt_profile` 是 `(allow default)` + 写/凭据/网络限制。enforced 模式的目标是 **默认拒绝 + 白名单**，但 Phase 4 先用 `allow default` + 更严格的 deny（写、凭据、网络、敏感路径）跑兼容性矩阵，再逐步收敛；不要一次性切换到 default-deny，否则会用 macOS 工具链兼容性换安全演示。

> **当前实现**：`aos run` 在 macOS 使用 Seatbelt launcher MVP：cwd 设为 shadow、宿主项目通过 `AOS_HOST_ROOT` 只读访问、写入限制在 shadow/agent_home/org pub、credential regex deny、出站仅 localhost egress proxy、broker 用 loopback TCP（Seatbelt 无法按 Unix socket 路径过滤）。PTY、MCP bridge、adapter 已验证。

```scheme
(version 1)
(deny default)
(allow process-fork)
(allow process-exec (subpath "/usr/bin") (subpath "/opt/homebrew/bin") ...)
(allow file-read* (subpath "/usr/lib") (subpath "/System") ...)
(allow file-read* (subpath "<shadow>") (subpath "<agent-home>") ...)
(allow file-write* (subpath "<shadow>") (subpath "<agent-home>"))
(deny network-outbound)
(allow network-outbound (remote ip "localhost:<proxy-port>"))
```

注意：

- 默认拒绝会破坏大量工具；需要维护按客户端的 profile 模板和兼容性测试矩阵。
- Seatbelt 不支持路径重映射；见 7.1.4。
- 需要允许 Agent 的 `mach-lookup` 服务（如 Keychain、字体、网络）；用最小 allowlist，拒绝 `com.apple.coreservices.*` / `lsd` 等可能启动外部程序的 family。
- 禁止 `appleevent-send`、`open` 启动外部应用。
- macOS 的 `sandbox-exec` 已被标记 deprecated，但仍可用；长期用 microVM / EndpointSecurity 补充。

#### 7.2.3 Isolated：microVM

- 复用 `MicroVmSandboxDriver` 和 Cloud PaaS 绑定。
- 本地 `aos run --isolated` 可用轻量 VM（libkrun）或远程 Cloud Sandbox。
- 源文件通过 virtiofs / 9p 挂载：shadow 可写、宿主工件树只读、`$HOME` 不挂。
- 用户感受：TUI 仍在本地，工具执行在 VM；首次启动 1–3 秒，之后复用。
- 企业场景用远程 Cloud Sandbox + 本地只做 UI 和审批。

#### 7.2.4 失败关闭

- `bwrap` / `sandbox-exec` 不存在：启动失败。
- 无法创建 netns / Unix socket：启动失败。
- egress proxy 健康检查失败：启动失败。
- broker 无法监听：启动失败。
- 任何降级都要显式 `--no-enforce` 或企业策略允许。

### 7.3 Effect 模型

#### 7.3.1 三元组

```rust
pub enum WorkspaceDomain {
    Code,
    Documents,     // Markdown / LaTeX / Word / PPT / PDF
    Data,          // CSV / Parquet / JSON / SQL / notebook
    Binary,        // PNG / TIFF / CAD / video / archive
    AppState,      // SaaS / browser / email / calendar
    Memory,        // UOMP
    Mixed,
}

pub enum EffectKind {
    FsRead,
    FsWrite,
    FsDelete,
    BinaryWrite,
    DatasetRead,
    DatasetWrite,
    DatasetSchemaChange,
    AppRead,
    AppWrite,
    AppInvoke,
    MemoryRead,
    MemoryWrite,
    ArtifactPublish,
    ProcExec,
    NetConnect,
    NetRequest,
    SecretUse,
    WorkspaceCommit,
    PolicyChange,
    ApprovalDecide,
    AgentSpawn,
}

pub enum ResourceScope {
    Shadow,        // Agent 自己的 CoW 工作区
    ProjectRo,     // 宿主工件树只读视图
    HostHome,      // 宿主 $HOME 非凭据路径
    Credential,    // ~/.ssh, ~/.aws, Keychain, .env 等
    System,        // /etc, /usr, /var
    OrgShared,     // 组织共享存储
    OrgCas,        // SHA-256 内容寻址产物总线
    Dataset,       // 结构化数据集 / 表 / 分区
    AppState,      // AAP-1.0 挂载的在线应用状态
    Memory,        // UOMP 受控记忆
    Remote,        // 网络 / git remote / SaaS
    CrossTenant,   // 其他 org / agent
}

pub enum ArtifactKind {
    Text,
    Document,
    Binary,
    Dataset,
    AppRecord,
    Memory,
}

pub enum Reversibility {
    Reversible,    // shadow 写入、快照可回滚
    Irreversible,  // 宿主写入、git push、HTTP POST、删除、CAS 发布
}

pub struct Effect {
    pub kind: EffectKind,
    pub domain: WorkspaceDomain,
    pub scope: ResourceScope,
    pub resource: String,
    pub artifact_kind: ArtifactKind,
    pub baseline_hash: Option<String>, // 二进制 / 数据集基线，用于防覆盖
    pub reversible: Reversibility,
    pub source: EffectSource, // NativeTool / McpTool / Command / Syscall / Commit / AppApi
    pub metadata: serde_json::Value,
}
```

#### 7.3.2 命令 vs 文件

- **命令不是安全原语**，命令只是产生效果的来源。`cargo test` 可能读写大量文件、执行构建脚本、访问网络。
- **文件访问也不是安全原语**，写 `.git/hooks`、`build.rs`、`Makefile` 会在后续执行；写 `.tex` 会触发 LaTeX 编译；写 `.csv` 会改变下游统计结果；写 `.docx` 会破坏排版。
- **文件不是同质的**：文本可以 LCS 合并，二进制只能排他锁 + 基线哈希，数据集需要 Schema / 行数 / PHI 校验，应用状态只能 API diff，记忆需要 scope lease。策略必须知道 `artifact_kind`，不能把所有写入都当成同一种 `fs.write`。
- 因此策略评估的输入是 effect，而不是 `Bash` / `Write` / `proc_exec`。
- 命令级审批只保留给「边界命令」：`git push`、`npm publish`、`ssh`、`curl POST`、`workspace_commit`、`org_artifact_publish`、`app.write`、`memory.write`、`aos` 自身。它们的效果在沙箱外、不可逆、且难以从 diff 看出。
- 只读 / 读写也不是二分法：`docs` 的只读包括「读取全部章节 + 渲染预览」，`data` 的只读包括「读取 Parquet 元数据 + 抽样行」，`app_state` 的只读是 API 查询，`memory` 的只读是 scope 租约内的读取。它们的安全含义不同，不能共用一条 `fs.read` 策略。

#### 7.3.3 效果观测

两层：

1. **事前声明 / 静态推断**：Agent 或 adapter 声明 `intent`（读哪些路径、跑什么命令、访问哪些域名）。仅用于 UX 和快速路径，不作为安全依据。
2. **事后观测**：沙箱内的 VFS / egress / broker 记录实际发生的 effect。用于审计、异常检测和「命令到底做了什么」的报告。

实现建议：

- 文件效果：shadow 的 CoW 层天然知道写入；宿主只读访问可用 `fanotify`（Linux）或 broker 的 `fs_read`（MCP）记录。macOS 可用 EndpointSecurity（需 entitlement，暂不作为 v1）。
- 网络效果：egress proxy 记录域名、方法、路径、字节数、DLP 命中。
- 进程效果：记录 argv、cwd、exit code、duration；不记录完整环境变量。
- 审计记录 `EffectRecord`，`aos top` 实时展示。

### 7.4 策略引擎

#### 7.4.1 动作与资源

扩展当前 `aos-policy` 的 action 字符串：

| Action | Resource 示例 | 说明 |
|---|---|---|
| `fs.read` | `shadow:src/main.rs`、`project:src/main.rs`、`home:~/work/shared`、`credential:ssh` | 读 |
| `fs.write` | `shadow:src/main.rs`、`host:src/main.rs` | 写 |
| `fs.delete` | `shadow:target/`、`host:src/` | 删 |
| `proc.exec` | `shadow:cargo`、`host:git` | 执行 |
| `net.connect` | `net:api.anthropic.com:443` | 连接 |
| `net.request` | `net:api.github.com:POST:/repos/...` | L7 请求 |
| `secret.use` | `secret:GITHUB_TOKEN` | 使用边界密钥 |
| `workspace.commit` | `workspace:org/agent` | 提交 |
| `workspace.commit_sensitive` | `path:.git/hooks/pre-commit` | 敏感提交 |
| `policy.change` | `policy:default.cedar` | 修改策略 |
| `approval.decide` | `escalation:esc-...` | 审批 |
| `agent.spawn` | `agent:<id>` | 子 Agent |

`EffectKind::action()` 是审计/事件使用的 dotted 形式（`fs.read`、`binary.write`、`workspace.commit`）；`EffectKind::policy_action()` 是现有 Cedar 策略与租约使用的 underscore 形式（`fs_read`、`workspace_commit`）。`Effect::to_policy_context` 统一走后者，避免 Rust 枚举、Cedar 字符串和 `aos commit` 租约之间漂移。

`net.request` 只有在 **Base URL 反向代理** 或 **Opt-in MITM** 模式下才可用；标准 HTTPS CONNECT 只能产生 `net.connect`，不能伪造 method / path / body 审计。详见 §7.6。

资源上增加标签：

- `sensitivity:credential`
- `sensitivity:build-hook`
- `sensitivity:ci-config`
- `sensitivity:agent-config`
- `sensitivity:dependency-manifest`
- `sensitivity:binary`

这样 `is_commit_poisoning_path` 的硬编码列表可以迁移成策略数据，而不是在每个 commit 里写死。

#### 7.4.2 决策类型

```rust
pub enum DecisionClass {
    AutoAllow,       // 直接放行，审计
    Notify,          // 放行，通知用户
    AskOnce,         // 一次性审批
    AskEach,         // 每次审批（高风险）
    LeaseRequired,   // 需要会话/任务租约
    Deny,            // 硬拒绝
}
```

映射到现有 `PolicyDecision`：

- `AutoAllow` / `Notify` → `Allow`。
- `AskOnce` / `AskEach` / `LeaseRequired` → `Ask`。
- `Deny` → `Deny`。

保留现有 API 兼容；`DecisionClass` 作为 `metadata` / 新字段逐步引入。

#### 7.4.3 默认策略矩阵

**observe 模式（只读）**

| 效果 | 范围 | 决策 |
|---|---|---|
| `fs.read` | shadow / project | AutoAllow |
| `fs.read` | home / 其他仓库 | Notify（首次）→ LeaseRequired |
| `fs.read` | credential | Deny |
| `fs.write` / `fs.delete` | 任意 | Deny |
| `proc.exec` | shadow | AutoAllow（只读挂载下写入自然失败） |
| `net.connect` | allowlist 域名 / 端口 | AutoAllow |
| `net.request`（L7 模式） | allowlist GET | AutoAllow |
| `net.request`（L7 模式） | 非 allowlist / 写方法 | AskOnce |
| `workspace.commit` | — | Deny |

**implement 模式（默认）**

| 效果 | 范围 | 决策 |
|---|---|---|
| `fs.read` | shadow / project | AutoAllow |
| `fs.read` | home / 其他仓库 | Notify → LeaseRequired |
| `fs.read` | credential | Deny |
| `fs.write` / `fs.delete` | shadow | AutoAllow + 快照 |
| `fs.write` | host（经 commit） | AskOnce（Diff 审批） |
| `fs.write` | host 敏感路径 | AskEach（`workspace_commit_sensitive`） |
| `proc.exec` | shadow | AutoAllow |
| `proc.exec` | host（边界命令） | AskOnce |
| `net.connect` | allowlist 域名 / 端口 | AutoAllow |
| `net.connect` | 非 allowlist | AskOnce |
| `net.request`（L7 模式） | allowlist | AutoAllow |
| `net.request`（L7 模式） | 新域名 / POST / DELETE | AskOnce / LeaseRequired |
| `secret.use` | 任意 | 代理注入，Deny 直接读取 |
| `workspace.commit` | — | AskOnce（或租约） |
| `policy.change` / `approval.decide` | — | Deny |

**isolated 模式**

- 同 implement，但宿主工件树完全不可见；commit 只能通过 broker 的 source-only diff。
- 网络只允许代理；凭据只在代理侧存在。
- 审批走远程/本地人类控制台。

**领域扩展默认策略**

| 效果 | 范围 | 默认决策 |
|---|---|---|
| `fs.write`（文本） | shadow | AutoAllow + 快照 |
| `binary.write` | shadow | AutoAllow + 基线哈希记录 |
| `binary.write`（覆盖宿主二进制） | host / commit | AskEach + `overwrite_binaries` + 基线哈希 |
| `dataset.read` | shadow / project ro | AutoAllow（元数据 + 抽样） |
| `dataset.write` | shadow | AutoAllow + 分区快照 |
| `dataset.schema_change` | shadow / host | AskEach（Schema diff 审批） |
| `dataset.write`（含 PHI） | shadow | Deny 或 AskEach（按策略） |
| `document.write`（Markdown/LaTeX） | shadow | AutoAllow + 段落/章节 claim |
| `document.write`（Office 块级） | shadow | AutoAllow，走 CRDT 块级锁 |
| `app.read` | AppState | Allow（按 API scope） |
| `app.write` / `app.invoke` | AppState | AskOnce / LeaseRequired |
| `memory.read` | Memory | LeaseRequired（scope + purpose） |
| `memory.write` | Memory | LeaseRequired + 可撤销 |
| `org_artifact_publish` | OrgCas | AutoAllow（verify 通过）；未通过则 Ask |
| `org_artifact_fetch` | OrgCas | AutoAllow（只读） |

> 这张表只定义默认值；真正的正确性由 `DomainProfile` 的 `verify_cmd` 和团队的 Cedar 策略决定。**Phase 3 只交付文本 / 二进制相关行；dataset / app / memory / org CAS 行属于 Phase 5。**

#### 7.4.4 Cedar 策略示例

```cedar
// 工作区内读取自动放行
permit(
  principal,
  action == Action::"fs.read",
  resource
) when {
  resource.scope == "shadow" || resource.scope == "project_ro"
};

// 凭据永远拒绝直接读取
forbid(
  principal,
  action == Action::"fs.read",
  resource
) when {
  resource.tag == "credential"
};

// 模型 API 默认放行 GET/POST
permit(
  principal,
  action == Action::"net.request",
  resource
) when {
  resource.host in ["api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"]
};

// 新域名需要审批
forbid(
  principal,
  action == Action::"net.request",
  resource
) when {
  resource.host not in ["api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"]
    && resource.lease == null
};

// 提交敏感路径强制单次审批
forbid(
  principal,
  action == Action::"workspace.commit",
  resource
) when {
  resource.tags.contains("build-hook") || resource.tags.contains("ci-config")
};
```

> 当前 `aos-policy` 是自定义 Cedar 子集解析器（`CedarPolicySet::parse`），不支持 `resource.tag` / `resource.lease` 等属性。Phase 2 需要扩展解析器；Phase 4 可评估切换到官方 `cedar-policy` crate。短期用 `metadata` 传递属性，保持兼容。

#### 7.4.5 租约

复用 `LeaseGrant`，扩展字段：

```rust
// Planned extension; current LeaseGrant uses action_pattern + resource_pattern
// (`*`, or `sha256:<evidence>` for one-shot) plus kind/task_id.
pub struct LeaseGrant {
    // existing fields...
    #[serde(default)]
    pub effect_kinds: Vec<EffectKind>,
    #[serde(default)]
    pub scope: Option<ResourceScope>,
    #[serde(default)]
    pub max_uses: Option<u32>,
    #[serde(default)]
    pub used_count: u32,
    #[serde(default)]
    pub evidence_hash: Option<String>,
}
```

- `Ttl`：按时间。
- `OneShot`：单次，`max_uses = 1`，哈希锚定到审批时的 diff / 命令。
- `TaskScoped`：绑定 A2A task。
- 新增 `ReadOnlySession`：整个会话只读（observe 模式）。

租约匹配：

```text
action_pattern: "fs.read"
resource_pattern: "home:~/work/shared/**"
task_id: optional
expires_at_ms
```

### 7.5 审批服务

#### 7.5.1 生命周期

```text
Effect 发生
  → Policy.evaluate()
    → AutoAllow / Notify：执行 + 审计
    → Ask：创建 PendingEscalation
      → 证据快照（diff / command / effects / evidence_hash）
      → 通知人类（TUI / desktop / web / CLI）
      → 批准：mint lease（TTL / one-shot / task）
      → 拒绝：返回 required_capability + reason
    → Deny：立即拒绝，返回结构化原因
```

#### 7.5.2 审批对象

**命令类审批**（只用于边界命令）：

```text
Agent wants to run on host:
  git push origin feature/auth
  remote: origin (github.com/heurion-org/aegis-os)
  branch: feature/auth -> main
  effect: irreversible remote mutation
  [a]pprove  [d]eny  [v]iew command
```

**文件类审批**（commit / 宿主写）：

```text
Agent wants to land 7 files:
  M src/auth/session.rs      +42 −8
  A src/auth/refresh.rs      +120
  M Cargo.toml               +1 −1   [sensitive: dependency-manifest]
  [a]pprove  [d]eny  [v]iew full diff
```

**读取类审批**（项目外 / 凭据）：

```text
Agent wants to read outside the workspace:
  ~/work/shared/api-spec.yaml     15 min lease
  ~/.aws/credentials              DENY (credential)
  [a]llow 15m  [o]nce  [d]eny
```

#### 7.5.3 通知渠道

| 环境 | 默认渠道 |
|---|---|
| 桌面 + TUI | 桌面通知（macOS `osascript` / Linux `notify-send`）+ `aos policy watch`；用户在另一个终端审批。**不向当前 PTY 写审批文本** |
| SSH / 无 GUI | OSC 0 标题 + BEL；提示用户另开终端 `aos approve`，或由 MCP / Hook 返回结构化挂起状态，交给客户端原生权限框 |
| Web / 远程 | `/approve` 网页，支持 SHA-256 diff 锁定 |
| CI / 非交互 | 预置租约或 `--yes`（仅限预先声明的范围）；否则失败 |
| 企业 | 审批人组、双人复核、审计导出 |
| 可选内嵌 | launcher 用 DECSTBM 维护独立状态栏 / 滚动区；不写 Agent 主屏幕，不与 TUI 输入竞争 |

#### 7.5.4 防疲劳

- 同一 `(kind, scope, resource-prefix)` 的效果合并成一张 ticket。
- 典型会话默认租约：`fs.read:project`、`fs.write:shadow`、`net:allowlist`。
- 如果 10 分钟内出现 > 5 次同类审批，UI 主动建议「授予 30 分钟租约」。
- 不允许「静默自动批准」；只能由用户显式授予。
- 拒绝返回 `required_capability`，让 Agent 申请正确的能力，而不是换命令重试。

#### 7.5.5 审批安全

- 审批入口只接受人类 token：本地文件 0600 + CLI，Web 用 device code / 2FA，Cloud 用 SSO。
- Agent token 只能调用 `tools/call`，不能调用 `/v1/escalations/:id/decide`。
- One-shot 审批锚定 `evidence_hash`；执行前重新计算，不一致则拒绝。
- 审批记录写入哈希链；`aos why` 可回溯。

### 7.6 出站代理

**先明确一个事实：标准 HTTPS `CONNECT` 是端到端 TLS 隧道，代理只能看到 `host:port`，看不到 HTTP Method、URL Path 和 Request Body。** 因此 L7 DLP、Method 审计和按请求注入密钥都不是 CONNECT 的默认能力，必须显式选择下面三种模式之一。

#### 7.6.1 三种出站模式

| 模式 | 代理能看到 | 适用 | 代价 |
|---|---|---|---|
| **1. CONNECT 隧道（默认）** | `host:port`、字节数、连接时长；SNI 可能可见（ECH 下不可见） | 任意 HTTPS 出站、包管理器、git over HTTPS | 无 L7；只能做域名/端口 allowlist 和流量统计 |
| **2. Base URL 反向代理（推荐用于模型 / SaaS API）** | 完整 Method / Path / Header / Body | 支持 base URL 覆盖的客户端（Anthropic、OpenAI、OpenAI-compatible、部分 SaaS） | 需要客户端支持自定义 base URL；代理侧终止客户端 TLS 或使用 loopback HTTP |
| **3. Opt-in MITM（最后手段）** | 完整 L7 | 不支持 base URL、但必须做 L7 DLP 的目标 | 需要 per-session CA、客户端信任链配置；证书 pinning / 内置根证书可能失败；隐私影响最大 |

**模式 1：CONNECT 隧道**

- 策略动作只有 `net.connect`，资源是 `net:<host>:<port>`；租约也只能绑定到域名 + 端口。
- 可以统计字节数、连接时长、并发数；不能区分 GET/POST，不能扫描 body，不能按 path 注入密钥。
- 默认模式；不允许在 CONNECT 上宣称 L7 DLP。
- 如果只看到 SNI，则连“精确域名”都可能被 ECH 隐藏；策略应以 CONNECT 请求里的 host 为准，并记录 SNI 不一致告警。

**模式 2：Base URL 反向代理**

- Launcher 注入 provider-specific base URL，例如：
  - `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>`
  - `OPENAI_BASE_URL=http://127.0.0.1:<port>`
  - `OPENAI_API_BASE` / 兼容客户端的等价变量
  - 其他 SaaS 用其官方 base URL 覆盖机制
- 客户端到本地代理走 loopback HTTP（或 HTTPS + 本地 CA）；代理再以 TLS 连接真实上游。这样代理能完整看到 Method / Path / Body，做：
  - 方法 / 路径 allowlist；
  - SecretScopeRule 边界注入；
  - 请求体 DLP（小请求体可完整缓冲；大 body 需要限额）；
  - 响应流式转发（SSE / chunked），不缓冲首 token。
- 这是模型 API 的推荐模式：既能做 DLP 和密钥代填，又不需要对任意域名做 MITM。
- 限制：只覆盖支持 base URL 覆盖的客户端；不覆盖 Agent 直接 `curl` 任意域名的场景。

**模式 3：Opt-in MITM**

- 为明确列入 `mitm_domains` 的域名签发 per-session CA，并通过 `SSL_CERT_FILE`、`NODE_EXTRA_CA_CERTS`、`REQUESTS_CA_BUNDLE`、`CURL_CA_BUNDLE`、`GIT_SSL_CAINFO` 等注入信任链。
- 仅对 opt-in 域名生效；默认关闭；每次会话首次启用需要人类确认或企业策略预授权。
- 证书 pinning、Rustls 内置根证书、硬编码 trust store 的客户端可能直接失败；失败时回退到 CONNECT，并明确提示「L7 不可用」，不能静默假装有 DLP。
- 代理会看到明文请求体；默认只记录 DLP 判定、命中类型和哈希，不记录 body；如企业需要留存，必须单独配置并写入合规说明。

#### 7.6.2 策略映射

| 模式 | 效果 | 可审计字段 | DLP / 密钥注入 | 租约 |
|---|---|---|---|---|
| CONNECT | `net.connect` | host、port、bytes、duration | 不支持 | `net:<host>:<port>` |
| Base URL 反向代理 | `net.request` | method、path、host、bytes、status | 支持（请求体可缓冲；响应流式） | `net:<host>:<method>:<path-prefix>` |
| Opt-in MITM | `net.request` | 同 base URL | 支持（同上） | 同 base URL |

**流式 DLP 的边界**：

- 请求体通常很小，可以完整缓冲后再 DLP；如果超过 `max_dlp_body_bytes`，拒绝或转为人工审批。
- 响应体可能很大且流式，DLP 采用 bounded buffer + 流式扫描；命中后立即断开，但已经转发的前缀无法收回。审批证据里要标注 `dlp_streaming: true`，不能承诺「零泄漏」。

#### 7.6.3 默认策略

- 任意 HTTPS：默认 CONNECT，只做域名/端口 allowlist。
- 模型 API：Phase 2 起默认 Base URL 反向代理，启用 L7 DLP + 密钥注入；当前已支持 Anthropic / OpenAI / Gemini / DeepSeek / Mistral / Groq / xAI / OpenRouter 路由。如果客户端不支持 base URL，降级为 CONNECT，并在 `doctor` 标注 `l7: unavailable`（doctor 的逐客户端标注仍待补）。
- 需要 L7 的第三方 API：显式加入 `mitm_domains`，opt-in MITM。
- 代理健康检查：`/v1/health`；launcher 启动前检查（仍待补；当前 bind 成功即视为可用）。
- 失败关闭：代理不可用则 Agent 无法出网；不自动直连。
- 隐私：Base URL / MITM 会看到 prompt 和响应；必须在首次启用时向用户说明，企业版提供关闭 body 日志的默认配置。

### 7.7 CoW 工作区与提交

- shadow 写入：AutoAllow；每次 Agent step 或每 N 秒创建快照（可配置），支持 `workspace_rollback`。
- commit：
  1. `refresh_from_host()` 三方合并。
  2. 检查 read/write claims。
  3. 计算 `changed_since_baseline()`。
  4. 敏感路径检查（`.git/`、`.github/workflows`、`.claude/`、`.codex/`、`.mcp.json`、`build.rs`、`Makefile`、`package.json`、`Cargo.toml` 等）。
  5. 生成 evidence（diff、文件列表、哈希）。
  6. Policy `workspace.commit` / `workspace_commit_sensitive`。
  7. 人工审批 / 租约。
  8. `commit_to_host_with_options()`；串行锁 + epoch 复检。
  9. 审计。
- `--mode observe`：commit 硬拒绝。
- `aos discard`：删除 shadow；`aos last`：定位最近会话目录。
- 二进制文件：默认不落盘；需要 `overwrite_binaries` 时强制 sensitive 审批。

#### 7.7.1 领域化提交流水线

同一套 `shadow → verify → approve → land` 流水线，按 `DomainProfile` 替换合并器、预检门和证据格式：

| 领域 | 合并 / 落地策略 | 预检门示例 | 审批证据 |
|---|---|---|---|
| **Code** | 四级 LCS 三路合并；文本 diff | `cargo test` / `npm test` / `pytest` / `go test` + lint | Unified Diff、测试日志 |
| **Documents** | Markdown / LaTeX 走 LCS；Office 走双表面 CRDT 块级锁 + `patchParagraph`；PDF 视为派生物 | `latexmk -pdf`、`bibtex-check`、`markdown-link-check`、拼写 / 渲染 | 源码 diff + 渲染后页面预览 |
| **Data** | Schema-aware 合并；分区 / 行区间认领；二进制格式（Parquet）走排他锁 | `schema-validate`、`scanPhi --strict`、行数 / 空值 / 校验和、统计不变量 | Schema diff、抽样行、PHI 报告、行数变化 |
| **Binary** | 不可按行合并：排他锁 + 基线 SHA-256 + 显式 `overwrite_binaries` | 格式 / 尺寸 / 哈希 / 缩略图检查 | 旧/新哈希、缩略图、元数据 |
| **AppState** | 不走文件 commit；通过 AAP-1.0 `app_call_tool` 执行 API 变更 + 幂等键 / 补偿 | API Schema、dry-run、权限 / DLP | 字段级 diff、请求预览、回滚计划 |
| **Memory** | 不走文件 commit；UOMP scope 写入 + 可撤销租约 | scope / purpose / retention 校验 | scope diff、用途、撤销入口 |

**关键规则**：

- `workspace_commit` 只适用于文件系统工件；应用状态用 `app.apply`，数据产物用 `org_artifact_publish`，记忆用 `memory.write`。不要把所有领域硬塞进一个「commit」动词。
- 预检门必须在沙箱内执行，且对宿主只读；失败时宿主不被触碰。
- 预检门结果（日志、渲染产物、Schema 报告、PHI 报告）是审批证据的一部分，进入 `evidence_hash`。
- 二进制 / 数据集的基线哈希在 shadow 创建时记录；commit 前重新计算宿主基线，不一致则拒绝并要求显式覆盖。
- 数据流水线的下游只接受 CAS 哈希指针，不允许直接读上游 `/tmp` 或输出目录；这从机制上消除「读半成品」。
- 预检门可按项目配置在 `.aegis/workspace.json` 中，不允许 Agent 在 shadow 内修改它；修改预检门配置本身是 sensitive commit。

> **阶段边界**：Phase 3 只实现 Code、Docs（文本 LCS + 简单渲染）、Binary（排他锁 + 基线哈希）。Data 的 Schema-aware / PHI / CAS，AppState 的 AAP-1.0，Memory 的 UOMP 均在 Phase 5；下表的这些行是目标能力，不是 Phase 3 交付承诺。

#### 7.7.2 CoW backend 与启动性能

**问题**：当前 `CoWWorkspace::init` 会执行两次 `cow_sync_dir`（host → shadow、shadow → baseline）。macOS APFS 有 `clonefile`，Linux Btrfs / XFS 有 `FICLONE`，但 **ext4 不支持 reflink**，会退化为两份全量物理拷贝。§2.3 的 P95 < 150 ms 和 §5.8 的「1.2 GB / 14 ms」只在 reflink / overlay 后端成立，不能作为 ext4 的承诺。

**后端矩阵**：

| 平台 / 文件系统 | 后端 | 启动复杂度 | 说明 |
|---|---|---|---|
| macOS APFS | `clonefile` | O(1) | 现有能力 |
| Linux Btrfs / XFS（reflink=1） | `FICLONE` | O(1) | 现有能力 |
| Linux ext4 + 内核 5.11+ | OverlayFS（user namespace） | O(1) | 推荐默认 |
| Linux ext4 + 无 userns overlay | `fuse-overlayfs` | O(1) | 用户态回退 |
| Linux ext4 + 两者都不可用 | 惰性复制 / manifest | O(n)，仅复制源文件 | 明确降级，不承诺 150 ms |

**OverlayFS 设计**：

```text
lowerdir = <host_project>            # 只读
upperdir = <session>/shadow_upper    # Agent 写入
workdir  = <session>/overlay_work
merged   = <session>/shadow          # 挂给 Agent 的视图
```

- 启动时只创建 upper / work 目录，O(1)；不复制 `node_modules`、`target`、GB 级数据集。
- 在 user namespace 里 mount overlay（或 `fuse-overlayfs`），再把 `merged` bind 到 Agent 的原路径。
- lowerdir 始终只读；Agent 的写入只进 upperdir；宿主文件不会被原地修改。
- 删除文件用 overlay whiteout 表达，diff 时映射为 deleted。
- 如果宿主在会话期间变化，lowerdir 看到的是新内容；baseline 用 manifest 记录初始状态，用于 3-way merge 的 O 侧。

**baseline 不再做第二次全量拷贝**：

- `baseline.json` 记录每个文件的 `path / size / mtime / sha256`；只对 Agent 实际触碰的文本文件惰性物化原始 blob 到 session CAS。
- 3-way merge 的 O（原始）、H（宿主当前）、A（shadow）：
  - O：baseline manifest + 惰性 blob；
  - H：`/aegis/host` 只读视图；
  - A：upperdir。
- 二进制 / 数据集只记录哈希和元数据，不做行级合并；commit 时用基线哈希判断是否被宿主更新。
- `CoWWorkspace::init` 删除 `shadow -> baseline` 的第二次 `cow_sync_dir`；`baseline_snapshot` 改为 manifest + 惰性对象。

**ext4 无 overlay 的回退**：

- 优先 `cp --reflink=auto`；失败则只复制版本控制 / 源文件，跳过 `node_modules`、`target`、`.venv`、`dist`、GB 级数据集；这些目录以只读 bind 穿透，或在首次写入时复制。
- 启动时在 `aos status` / `doctor` 显示 `cow_backend: lazy-copy`，并提示「当前文件系统不支持 O(1) CoW，启动时间随数据量增长」。
- 不允许在 ext4 上宣称 14 ms / 150 ms；性能验收按 backend 分档。

**验收**：

- APFS / Btrfs / XFS / overlay：1 GB 数据集 shadow 创建 P95 < 50 ms，整体 `aos run` P95 < 150 ms。
- ext4 + fuse-overlayfs：P95 < 150 ms。
- ext4 lazy-copy：启动时间线性增长，但必须可用；`doctor` 明确标注降级。
- 测试覆盖 1k / 10k 文件、1 GB / 10 GB 数据集、大仓库 `node_modules` / `target`。

### 7.8 审计与可观测性

- 复用 `aos-recorder` 的 SHA-256 哈希链。
- 新增 `EffectRecord`：

```json
{
  "event_id": "evt_...",
  "session_id": "ses_...",
  "agent_id": "claude-code",
  "kind": "fs.read",
  "scope": "credential",
  "resource": "~/.ssh/id_rsa",
  "decision": "deny",
  "matched_rule": "forbid-credential-read",
  "source": "native_tool",
  "timestamp_ms": 1760000000000,
  "prev_hash": "...",
  "event_hash": "..."
}
```

- 网络事件额外记录 `egress_mode`：`connect`（仅 host / port / bytes）、`l7_base`（method / path / body 元数据）、`l7_mitm`（同 base，标记 CA / pinning 失败）；CONNECT 事件不得伪造 method / path。
- `aos top`：实时展示活跃会话、shadow、待审批、denied effects、网络请求。
- `aos why <event>`：解释命中的策略、租约、审批链。
- 审计日志只追加；Agent 不可写 runtime 目录（内核禁止）。
- 可选导出 OpenTelemetry / SIEM。

### 7.9 多 Agent 协调

- `coord_claim` 扩展 `mode: read | write` 和 `granularity`：
  - `read`：共享锁，多个 Agent 可同时读。
  - `write`：独占锁，冲突拒绝。
- 领域化认领粒度：

| 领域 | 认领粒度 | 说明 |
|---|---|---|
| Code | 文件 / Glob | 现有 2D NFA + 文件树交集 |
| Documents | 文件 / 章节 / 段落 | 多 Agent 可并行改不同章节；同段落冲突 |
| Data | 表 / 分区 / 行区间 | Schema 变更单独加锁 |
| Binary | 整文件 | 不支持部分合并 |
| AppState | 记录 / 字段 | 通过 AAP-1.0 记录 ID / 字段路径 |
| Memory | scope / key | UOMP scope lease |

- `observe` 会话只申请 read claim；`implement` 会话申请 write claim。
- 二进制 / 数据集 / 应用状态的 write claim 必须是独占，不能与任何其他 write claim 重叠。
- commit / apply / publish 时自动释放对应 claim；任务终态释放全部。
- 并发 commit 继续使用跨进程锁 + `host_commit_epoch` 串行化。
- `aos top` 展示 read/write claim 矩阵，以及每个 claim 的 domain / granularity。

### 7.10 客户端适配器

统一原则：

- **adapter 只做协议转换**：把客户端的工具调用 / Hook 事件转成 `Effect`，发给 broker 的 `/v1/adapter/evaluate`；不在 adapter 里复制策略逻辑。
- **enforced 模式下 adapter 是可选的**：内核已经隔离，adapter 只用于心跳、状态显示、MCP 工具和 commit UX。
- **advisory 模式下 adapter 是主要 UX**：把原生工具引导到 MCP，减少弹窗；但不承诺安全。

#### 7.10.1 AGY

- 现有 `~/.gemini/config/hooks.json` + `mcp_config.json`。
- SessionStart：发送 heartbeat，注册 session。
- PreToolUse：调用 `/v1/adapter/evaluate`；返回 allow / ask / deny；支持 `overwrite` 重写路径（AGY 支持）。
- enforced：launcher 启动 `agy`，Hook 仅用于状态和 MCP 路由。

#### 7.10.2 Claude Code

- 现有 `~/.claude/settings.json` Hook + `~/.claude.json` MCP。
- PreToolUse：同样走 `/v1/adapter/evaluate`。
- 当前 Aegis 适配器主要使用 allow / ask / deny；Claude Code 的 PreToolUse 已支持 `hookSpecificOutput.updatedInput`，可以把工具参数重写到 shadow / MCP，advisory 模式应逐步用起来。
- 企业托管可用 managed settings + `allowManagedHooksOnly` 固定 Hook，项目级 `disableAllHooks` 无法关闭托管 Hook；这属于 Phase 5 的托管能力，不替代 enforced。
- enforced：launcher 启动 `claude`，原生工具直接在沙箱内跑，不需要重定向。

#### 7.10.3 Codex

- 现有 `~/.codex/config.toml` MCP + `~/.codex/AGENTS.md`。
- 当前 Aegis 的 Codex 集成只有 MCP + `AGENTS.md`，没有工具级 Hook，advisory 模式下只有规则引导，能力弱；必须在文档中标注。
- enforced：launcher 启动 `codex`，这是 Codex 的唯一强保证方式。
- 如 Codex 自身支持 sandbox / approval 配置，可作为内层加固，但外层 Aegis 沙箱仍是信任边界。

#### 7.10.4 OpenCode（重点）

**能力（V2）**：

- 配置：`~/.config/opencode/opencode.json(c)`、项目 `opencode.json(c)` / `.opencode/opencode.json(c)`。
- MCP：`mcp.servers`，本地 `type: "local"`，`command` 数组，`environment`，`codemode`。
- 插件：`plugins` 或 `.opencode/plugins/`；V2 server plugin 支持 `ctx.tool.hook("execute.before")`、`ctx.tool.hook("execute.after")`、`ctx.shell.hook("create.before")`、`ctx.permission.hook("evaluate")`、`ctx.tool.transform`、`ctx.mcp.transform`。
- 权限：`permissions` 有序规则，action 包括 `read`、`edit`、`shell`、`external_directory`、`<server>_<tool>` 等。
- 领域：OpenCode 不限于代码；`aos run --profile docs|data -- opencode --standalone` 同样适用，插件与 MCP 不绑定语言，domain profile 决定合并 / 预检 / 证据。
- **架构关键点**：OpenCode V2 默认连接一个共享后台服务，工具执行发生在该服务中。只给 TUI 套沙箱不能隔离工具执行。

**enforced 集成方案**：

1. PATH shim：`opencode` → `aegis-os run --client opencode -- opencode --standalone`。
2. `--standalone` 强制私有后台服务，使 Server / 工具执行与 TUI 在同一进程树内，被外层沙箱覆盖。
3. 如果 `--standalone` 仍无法保证同进程树，fallback：launcher 在沙箱内启动 `opencode serve --port <随机>`，再启动 `opencode --server http://127.0.0.1:<port>`；Server 在沙箱内，TUI 可在沙箱内或外（TUI 只渲染）。
4. 禁止连接到宿主上已有的共享服务：launcher 检测 `opencode service status`，如果发现共享服务且用户未显式 `--server`，拒绝 enforced 或强制 `--standalone`。
5. 配置注入（全局 `opencode.json`）：
   - `mcp.servers.aegis-os`：enforced 下指向沙箱内 `aos mcp-bridge`；advisory 下指向 `aegis-os mcp-stdio`。
   - `plugins`：`@heurion/opencode-aegis`。
   - `snapshots: false`：避免和 Aegis CoW 的 undo 冲突。
   - `worktree.directory`：指向 shadow 内的 `.aegis/worktrees`，或禁用 OpenCode worktree。
   - `instructions`：加入 Aegis 规则（`AGENTS.md`）。
   - `permissions`：advisory 下 `shell` / `edit` / `external_directory` 走 ask/deny；enforced 下可以放宽，由内核兜底。
6. OpenCode plugin（V2 server part）：
   - `setup(ctx)` 注册 heartbeat、状态、MCP bridge 健康检查。
   - `ctx.tool.hook("execute.before", ...)`：advisory 模式调用 `/v1/adapter/evaluate`，必要时拒绝或改写；enforced 模式只记录 effect。若当前 OpenCode 版本只支持检查而不支持改写，则降级为「deny + 在工具输出中提示改用 MCP」。
   - `ctx.shell.hook("create.before", ...)`：advisory 模式下把 cwd 改到 shadow、设置 `AOS_HOST_ROOT`；enforced 模式不改。
   - `ctx.permission.hook("evaluate", ...)`：把 OpenCode 的 allow/ask/deny 映射到 Aegis 策略；显式 `deny` 仍然最终有效。
   - `ctx.mcp.transform`：确保 `aegis-os` server 存在且指向当前 session 的 bridge；禁用未知的 filesystem / shell MCP Server（advisory）。
   - `ctx.tool.transform`：advisory 模式下可移除原生 `shell` / `write` / `edit`，只保留 MCP 工具；enforced 模式保留原生工具，保证 UX。
7. OpenCode 的 `codemode`：建议 aegis MCP `codemode: false`，让工具名和权限规则稳定；如果使用 Code Mode，需要在 plugin 中处理 `execute` 权限。
8. 共享服务兼容性：
   - `aos doctor` 检查 `opencode service status`；
   - enforced 会话启动时打印 `opencode: standalone`；
   - 如果检测到 `--server` 指向宿主服务，拒绝启动并提示 `--standalone`。
9. 测试矩阵：
   - `opencode` TUI、`opencode run`、`opencode mini`、`opencode serve` + `--server`。
   - 共享服务已运行时启动 enforced。
   - `@` 文件引用、LSP、formatter、undo/snapshot。
   - 子 Agent / Code Mode / MCP 工具调用。

**advisory 集成方案**：

- 安装 `@heurion/opencode-aegis` plugin 与 `aegis-os` MCP Server。
- Plugin 把 `shell` / `read` / `write` / `edit` 事件发给 `/v1/adapter/evaluate`；返回 deny 时在工具输出中提示改用 `aegis_os_*` MCP 工具。
- 在 `permissions` 中设置：
  - `external_directory: ask`
  - `shell: ask`（或 deny + MCP redirect）
  - `edit: ask`（项目外 deny）
- 明确标注：advisory 不能抵抗被劫持的 Agent。

**OpenCode 能力矩阵**：

| 场景 | advisory | enforced |
|---|---|---|
| 原生 shell 读 `~/.ssh` | 插件拦截（可绕过） | 内核拒绝 |
| 原生 write 宿主工件树 | 插件拦截 / ask | 内核只允许 shadow |
| 新 MCP Server 带文件访问 | 插件可禁用（可绕过） | 内核限制 |
| 共享后台服务 | 无法保证 | `--standalone` / 沙箱内 serve |
| TUI / LSP / formatter | 正常 | 正常（沙箱内） |
| commit 审批 | MCP / Web | MCP / Web |

#### 7.10.5 Hermes（第一方）

Hermes 是 Heurion 生态内的 CLI Agent，应当作为**第一方参考实现**接入，而不是当作普通第三方客户端。

集成方式：

- **MCP**：在 Hermes 的全局配置中注册 `aegis-os` MCP Server；具体路径由 `AdapterManifest` 声明（`~/.hermes/config.json` 或环境变量 `HERMES_CONFIG`，Phase 1 实测定稿）。
- **Adapter Protocol**：Hermes 应在自身工具执行前后调用 `aos adapter evaluate` / `aos adapter effect`，把原生 `shell` / `read` / `write` / `edit` / `http` 事件交给 broker 判断。Hermes 是自有产品，可以直接实现协议，不需要依赖第三方 Hook。
- **Enforced**：`aos run --client hermes -- hermes`；Hermes 的进程树、子 Agent、工具进程全部继承沙箱。
- **Heartbeat**：每 30 秒 `adapter.heartbeat`；`aos doctor` 用它判断 Hermes 是否真的加载了 Aegis。
- **Headless**：`aos run --headless -- hermes run ...`；CI 使用预置租约，缺审批则失败。
- **版本矩阵**：`AdapterManifest.tested_versions` 记录已验证版本；Hermes 升级后如果协议不兼容，`doctor` 报警，enforced 仍由 launcher 兜底。

Hermes 作为第一方，应优先实现以下能力，成为其他 Agent 的样板：

1. `adapter.evaluate`：工具执行前返回 allow / ask / deny / rewrite。
2. `adapter.effect`：工具执行后上报实际 effect（路径、字节数、域名、退出码）。
3. `adapter.heartbeat`：会话存活与 enforcement 状态。
4. `adapter.capabilities`：声明是否支持 read-only、binary write、app state、memory。
5. 对 `AOS_ENFORCEMENT=advisory` 与 `enforced` 两种模式做区分：前者走协议判断，后者协议只做审计。

#### 7.10.6 通用 Agent Adapter Protocol

为了让「等主流 Agent」不必每个都写一套 Rust 代码，定义统一的 **Agent Adapter Protocol**：

```text
Agent（不可信）  ──Unix socket / CLI──▶  Aegis broker（受信任）
   │  adapter.hello       { client, version, capabilities }
   │  adapter.evaluate    { session_id, tool, input } -> { effect, reason, rewrite }
   │  adapter.effect      { session_id, tool, input, effect } -> ack
   │  adapter.heartbeat   { session_id, status }
   └  adapter.capabilities -> { read_only, binary_write, app_state, memory }
```

- **Transport**：`AOS_CONTROL_SOCKET` Unix socket；同时提供 `aos adapter evaluate --json` 供只能执行命令的 Agent 使用。
- **身份**：`AOS_SESSION_TOKEN`；broker 只信任 token 对应的 session，不信任 Agent 传入的 `--org` / `--agent`。
- **能力声明**：Agent 声明自己支持哪些领域；不支持的领域由 broker 直接拒绝，不做猜测。
- **降级**：Agent 不实现协议时，仍可通过 MCP + launcher 工作；`doctor` 标注 `adapter: none`。
- **安全边界**：协议是 cooperative 的，只用于 advisory UX 和审计；enforced 的安全仍由内核负责。

> **当前实现**：`AOS_SESSION_TOKEN` / `AOS_CONTROL_SOCKET`、`adapter.hello` / `capabilities` / `evaluate` / `effect` / `heartbeat`、`/v1/mcp` JSON-RPC bridge（`aos mcp-bridge` / `aos mcp-stdio` 自动委派）和 `aos adapter` 客户端已落地；MCP 工具与 launcher 共用同一个 CoW shadow。AdapterManifest、`aos agent add/test` 和 OpenCode V1 plugin 已落地；OpenCode V2 的工具 hook、Hermes plugin 全量接入仍待补。原生 Claude/AGY hook 在 `aos run` 内会优先询问 broker 的 deny/ask 决定，allow 仍回落到既有边界路由。

**AdapterManifest**（安装器与 `doctor` 共用）：

```json
{
  "id": "hermes",
  "display_name": "Hermes",
  "type": "cli",
  "bin": ["hermes"],
  "version_cmd": ["hermes", "--version"],
  "config": [
    {
      "path": "~/.hermes/config.json",
      "format": "json",
      "mcp_key": "/mcpServers"
    }
  ],
  "launch": ["hermes"],
  "headless": [["hermes", "run"]],
  "hooks": { "type": "adapter_protocol", "version": 1 },
  "enforcement": {
    "advisory": ["mcp", "adapter_protocol", "rules"],
    "enforced": ["launcher"]
  },
  "tested_versions": [">=0.1.0"],
  "notes": "第一方；若协议不可用，仍可通过 launcher enforced"
}
```

`aos agent` 命令：

```bash
aos agent list                     # 已检测 / 已接入 / 强制等级
aos agent add ./hermes.json        # 第三方 manifest
aos agent doctor hermes            # 二进制、配置、MCP、heartbeat、版本
aos agent test hermes              # 跑一组工具调用冒烟测试
```

`aegis-os install` 的行为：

- 扫描 `PATH` 中的已知 Agent：`agy`、`claude`、`codex`、`opencode`、`hermes`、`gemini`、`aider`、`goose`、`cline`、`continue`、`amp`、`roo` 等。
- 只对检测到的 Agent 写入配置；不覆盖用户已有配置，使用标记块合并。
- `--all` 安装所有检测到的 Agent；`--agent <id>` 只装一个；`--enforce` 同时安装 PATH shim。
- 未知 MCP Agent 打印 `aos agent add` 指引，不假装支持。

#### 7.10.7 其他主流 Agent 与支持分级

| 级别 | 定义 | 客户端 |
|---|---|---|
| **Tier A（一等，发布门禁）** | 有独立 adapter、CI 冒烟、版本矩阵 | AGY、Claude Code、Codex、OpenCode、Hermes |
| **Tier B（通用适配，社区验证）** | CLI / headless + MCP + launcher；可选 adapter protocol | Gemini CLI、Aider、Goose、Amp |
| **Tier C（通用 MCP）** | 只保证 MCP + launcher；不保证原生工具路由 | 任意 MCP-capable Agent |
| **Tier D（IDE/GUI，Phase 5）** | 需要扩展 / daemon / 远程 workspace | Cline、Continue、Roo Code、Cursor、Windsurf、VS Code 扩展、JetBrains |

**支持 ≠ 保护**：

- Tier B/C 的 advisory 可能只有 MCP + 规则，不能抵抗被劫持的 Agent；enforced 仍然是 launcher。
- Tier D 的 GUI 进程可能不继承 PATH shim；需要 IDE 扩展或 isolated workspace，不能靠终端 shim。
- 每个 Agent 的页面必须标注「已验证版本 / 最后测试日期 / 强制等级」。

**Headless / CI**：

- 所有 Tier A 客户端支持 `aos run --headless -- <agent> <headless-subcommand>`。
- 无 TUI 时审批走预置租约或 `aos approve`；不允许自动批准。
- 退出码区分「策略拒绝」「审批超时」「Agent 失败」。

#### 7.10.8 客户端能力矩阵

| 客户端 | 级别 | 形态 | MCP | Hook / Plugin | advisory 强制 | enforced | 状态 |
|---|---|---|---|---|---|---|---|
| **AGY** | A | CLI / IDE | ✅ | ✅ PreToolUse | 强 | ✅ | 已验证 |
| **Claude Code** | A | CLI / IDE / Desktop | ✅ | ✅ PreToolUse + `updatedInput` | 强 | ✅ | 已验证 |
| **Codex** | A | CLI | ✅ | ❌ 当前集成无工具级 Hook | 弱（仅规则） | ✅ | 已验证（MCP） |
| **OpenCode** | A | CLI / Desktop | ✅ | ✅ V2 Plugin | 强 | ✅ | 适配中（`--standalone`） |
| **Hermes** | A | CLI | ✅ | ✅ Adapter Protocol（第一方） | 强 | ✅ | 适配中 |
| Gemini CLI | B | CLI | ✅ | 待确认 | 中 | ✅ | 规划 |
| Aider | B | CLI | 部分 | 无 | 弱 | ✅ | 规划（launcher） |
| Goose | B | CLI | ✅ | 待确认 | 中 | ✅ | 规划 |
| Cline | D | IDE | ✅ | 扩展 | 中 | ⚠️ Phase 5 | 需要 IDE 集成 |
| Continue | D | IDE / CLI | ✅ | 扩展 | 中 | ⚠️ Phase 5 | 需要 IDE 集成 |
| Amp | B | CLI / IDE | ✅ | 待确认 | 中 | ✅ | 规划 |
| Roo Code | D | IDE | ✅ | 扩展 | 中 | ⚠️ Phase 5 | 需要 IDE 集成 |
| Cursor / Windsurf | D | IDE | ✅ | 扩展 | 中 | ⚠️ Phase 5 | 需要 IDE 集成 |
| 任意 MCP Agent | C | CLI | ✅ | 无 | 弱 | ✅ | 通用 launcher |

**说明**：

- 「已验证」= 当前代码或本设计对应的实现已有冒烟测试；「适配中」= 本设计周期内交付；「规划」= 需要 manifest / 社区验证。
- AGY / Claude / Codex 的现有集成在 `crates/aos-cli/src/installer.rs`；OpenCode / Hermes 是本次新增重点。
- IDE/GUI Agent 的工具执行进程可能不在终端 PATH shim 内，Tier D 必须用扩展 / daemon / isolated workspace。
- 任何 Agent 的 enforced 模式都不依赖其 Hook / Plugin；launcher + 内核是共同路径。

**对外文案**：

- 「支持」= 有 MCP / CoW / 审批集成。
- 「保护」= enforced / isolated，Agent 必须由 Aegis 启动。
- 每个客户端页面标注当前等级，不混用。

---

## 8. CLI / UX 规范

### 8.1 命令树

> `[planned]` 表示尚未实现。当前 `aos run` 已支持 `--no-enforce` / `--enforcement advisory`，但还没有 `--session`；`aos install` 还没有 `--all` / `--agent`。

```text
aegis-os
├── install [--enforce] [--all] [--agent <id>] [--dry-run]   # --all/--agent planned
├── uninstall [--shim-only]
├── doctor [--agent <id>]                                     # --agent planned
├── status [--json]
├── run [--mode observe|implement] [--profile ...] [--enforcement ...] [--no-enforce] -- <agent> [...]
├── last
├── diff [--session <id>] [--render]
├── verify [--session <id>]
├── commit [--session <id>] [--paths ...] [--allow-sensitive] [--yes]
├── why [--session <id>]
├── publish [--session <id>] [--path ...]      # 发布到 SHA-256 CAS
├── artifacts
│   ├── list
│   └── fetch <uri> [--out <file>]
├── discard [--session <id>]
├── approve [<escalation-id>] [--ttl 15m]
├── deny [<escalation-id>]
├── approvals
│   ├── list
│   ├── show <esc-id>
│   ├── approve <esc-id>
│   ├── deny <esc-id>
│   └── serve [--port 7817] [--token <token>]
├── agent
│   ├── list
│   ├── add <manifest.json>
│   ├── doctor <id>
│   └── test <id>
├── policy
│   ├── status
│   ├── watch [--interval-secs 2]
│   ├── diff [<escalation-id>]
│   ├── lease --action <pattern> --resource <pattern> --ttl <duration>
│   ├── revoke <lease-id>                                    # planned
│   └── explain <event-id>                                   # planned
├── top
├── workspace
│   ├── status
│   ├── profile [<code|docs|data|binary|app_state|memory|mixed>]
│   ├── snapshot --label ...
│   ├── rollback --snapshot-id ...
│   └── list
├── mcp-bridge                          # 沙箱内 MCP stdio → broker（使用 AOS_CONTROL_SOCKET）
├── adapter                             # Agent Adapter Protocol client
│   ├── hello --client <id> --version <v> [--capabilities '<json>']
│   ├── capabilities
│   ├── evaluate <tool> [--input '<json>']
│   ├── effect <tool> --effect <e> [--input '<json>']
│   ├── heartbeat
│   └── session
└── cloud ...
```

### 8.2 `aos status`

```text
$ aos status
Session:   ses_7f3a9c
Status:    exited
Enforce:   enforced (filesystem+egress+broker)
Mode:      implement
Profile:   code
Agent:     payments/claude-code
Workspace: /home/jz/work/payments
Shadow:    /home/jz/.aegis/sessions/ses_7f3a9c/cow_workspace/upper_workspace
CoW:       reflink-or-copy
Git view:  host .git ro + session index
Network:   egress-allowlist+l7-base-url
Broker:    session control socket (adapter.evaluate/effect/heartbeat)
Approval:  pending (esc-1f88d046)
Exit:      10
```

JSON：

```json
{
  "session_id": "ses_7f3a9c",
  "mode": "implement",
  "enforcement": "enforced",
  "enforcement_scope": "filesystem+egress+broker (commit + live policy)",
  "profile": "code",
  "org_id": "payments",
  "agent_id": "claude-code",
  "workspace": "/home/jz/work/payments",
  "shadow": "/home/jz/.aegis/sessions/ses_7f3a9c/cow_workspace/upper_workspace",
  "cow_backend": "reflink-or-copy",
  "broker": true,
  "control_socket": "/run/aegis/control/control.sock",
  "git_view": true,
  "network": "egress-allowlist+l7-base-url",
  "status": "exited",
  "exit_code": 10
}
```

### 8.3 退出码

| 退出码 | 含义 |
|---|---|
| 0 | Agent 正常退出，无未处理变更 |
| 10 | Agent 正常退出，shadow 有未提交变更 |
| 20 | 沙箱 / 代理 / broker 启动失败（目前启动错误统一返回 1，20 待实现） |
| 21 | 策略拒绝启动（企业配置；待实现） |
| 22 | Session token / 身份校验失败（待实现） |
| 130 | 用户 Ctrl-C（依赖 Agent/bwrap 退出状态） |
| 128+N | Agent 被信号 N 杀死 |

### 8.4 错误文案

- 「Aegis 无法启动 enforced 会话：未找到 bubblewrap。安装：`sudo apt install bubblewrap`。如果只想使用兼容模式：`aos run --no-enforce -- claude`。」
- 「Aegis 检测到 OpenCode 共享后台服务在运行，工具执行可能绕过沙箱。请使用 `aos run -- opencode --standalone`，或先执行 `opencode service set disabled true`。」
- 「Aegis 拒绝了 `workspace_commit`：`Cargo.toml` 属于 `dependency-manifest` 敏感路径。请让人类审批：`aos approve`。」
- 「当前 HTTPS 连接使用 CONNECT 隧道，Aegis 只能看到 host:port，无法做 L7 DLP / Method 审计。要启用 L7，请为该客户端配置 Base URL 反向代理，或将域名加入 opt-in MITM。」
- 「Git 视图不可用：宿主仓库没有 `.git` 或当前为裸仓库。Agent 的 `git status` / `git diff` 会退化；请使用 `AOS_HOST_ROOT` 或 `aos diff`。」
- 「当前是 TUI 会话，审批提醒已发送到桌面 / 终端标题。请在另一个终端执行 `aos approve`，不要在当前 TUI 内等待。」
- 「当前文件系统不支持 reflink，且 OverlayFS / fuse-overlayfs 不可用；已回退到 lazy-copy。1 GB 数据集启动会明显变慢，`aos doctor` 可查看 backend。」

---

## 9. 数据模型与 API

### 9.1 运行时目录

```text
~/.aegis/
├── bin/
│   ├── claude
│   ├── codex
│   ├── agy
│   ├── opencode
│   └── hermes
├── policy/
│   ├── default.cedar
│   └── user.cedar
├── sessions/
│   └── ses_7f3a9c/
│       ├── session.json
│       ├── control.sock
│       ├── agent.token          # 0600
│       ├── human.token          # 0600
│       ├── shadow/              # overlay merged 或 clone shadow
│       ├── shadow_upper/        # overlay upperdir
│       ├── overlay_work/        # overlay workdir
│       ├── agent_home/          # 沙箱 $HOME
│       │   └── .aegis-git-index # 可写 Git index 副本
│       ├── host_ro/             # 只读宿主视图（/aegis/host）
│       ├── baseline.json        # path / size / mtime / sha256
│       ├── baseline_objects/    # 惰性物化的原始 blob
│       ├── audit.jsonl
│       ├── approvals.json
│       └── logs/
└── cache/
```

- 默认从 `/tmp/aegis-os-runtime` 迁移到 `~/.aegis`；保留 `AOS_RUNTIME_DIR` 覆盖。
- `~/.aegis` 权限 0700；token 文件 0600。
- `shadow/` 在 overlay 后端下是 merged 视图，在 clone / reflink 后端下是 clone 副本；`shadow_upper/` 只在 overlay 下存在。
- `baseline_objects/` 只存 Agent 触碰过的文本原始 blob；不复制整个仓库 / 数据集。

### 9.2 Session 元数据

```json
{
  "session_id": "ses_7f3a9c",
  "created_at_ms": 1760000000000,
  "mode": "implement",
  "enforcement": "enforced",
  "client": "opencode",
  "agent_id": "opencode",
  "org_id": "payments",
  "domain": "code",
  "profile": "code",
  "workspace": "/home/jz/work/payments",
  "shadow": "/home/jz/.aegis/sessions/ses_7f3a9c/shadow",
  "shadow_upper": "/home/jz/.aegis/sessions/ses_7f3a9c/shadow_upper",
  "agent_home": "/home/jz/.aegis/sessions/ses_7f3a9c/agent_home",
  "host_ro": "/aegis/host/payments",
  "cow_backend": "reflink-or-copy",
  "broker": true,
  "control_socket": "/run/aegis/control/control.sock",
  "git_view": {
    "enabled": true,
    "host_git": "/aegis/host/payments/.git",
    "sandbox_index": "$HOME/.aegis-git-index",
    "host_index": "/home/jz/.aegis/sessions/ses_7f3a9c/agent_home/.aegis-git-index"
  },
  "sandbox": { "driver": "bwrap", "profile_hash": "sha256:..." },
  "verify": { "profile": "code", "cmd": "cargo test", "last_result": "pass" },
  "egress": { "proxy": "127.0.0.1:54123", "mode": "connect" },
  "pid": 48213,
  "status": "active"
}
```

### 9.3 MCP 工具变更

| 工具 | 变更 |
|---|---|
| `fs_read` | 增加 `scope` 返回；只读视图内直接读，越界返回 `ask` / `deny` |
| `fs_write` / `fs_edit` / `fs_delete` | 仅写 shadow；宿主写只能通过 commit |
| `proc_exec` | enforced 下不再需要逐命令审批；记录 effect；仍支持后台任务 |
| `workspace_commit` | 增加 `evidence_hash`、`requested_lease`、`effect_summary` |
| `workspace_status` | 返回 enforcement level、read/write scope、leases |
| `policy_request_capability` | planned：Agent 申请能力（read / net / exec），返回 escalation id |
| `session_status` | planned：Agent 查询当前会话模式、shadow、配额 |
| `coord_claim` | 已增加 `mode: read|write`（read 可与 read 共存，write 独占） |
| `policy_approve_escalation` / `policy_grant_lease` | 继续对 Agent 拒绝；人类 CLI/Web 专用 |

### 9.4 控制面 API（Unix socket）

| 方法 | 路径 | 调用者 | 说明 |
|---|---|---|---|
| GET | `/v1/session` | agent | ✅ 会话状态 |
| POST | `/v1/adapter/evaluate` | adapter | ✅ 工具调用评估（Effect → policy） |
| POST | `/v1/adapter/effect` / `/v1/effects` | adapter / sandbox | ✅ 记录 effect |
| POST | `/v1/adapter/heartbeat` | adapter | ✅ 心跳 |
| POST | `/v1/escalations` | agent | planned（当前由 adapter.evaluate 的 Ask 自动创建） |
| GET | `/v1/escalations` | human | ✅ 列出待审批 |
| POST | `/v1/escalations/:id/decide` | human | ✅ 批准 / 拒绝 |
| POST | `/v1/leases` | human | ✅ 授予租约 |
| DELETE | `/v1/leases/:id` | human | ✅ 撤销租约 |
| GET | `/v1/audit` | human | ✅ 审计查询 |
| POST | `/v1/session/stop` | human | planned |

鉴权：

- Agent token：scope `agent`；只能访问 `/v1/session`、`/v1/adapter/evaluate|effect|heartbeat`、`/v1/effects`。
- Human token：scope `human`；可访问审批、租约、审计（`/v1/session/stop` 仍 planned）。
- Human token 只存在 `human.token` 0600 和 CLI/Web 内存中；不注入 Agent 环境。

### 9.5 策略配置

```jsonc
{
  "version": 1,
  "default_mode": "implement",
  "default_enforcement": "enforced",
  "workspace_profiles": {
    "code": {
      "merge": "lcs3",
      "claims": "file_glob",
      "verify": ["cargo test", "cargo clippy -- -D warnings"],
      "evidence": "unified_diff"
    },
    "docs": {
      "merge": "lcs3+crdt_block",
      "claims": "section_paragraph",
      "verify": ["latexmk -pdf main.tex", "bibtex-check refs.bib", "markdown-link-check README.md"],
      "evidence": "rendered_diff"
    },
    "data": {
      "merge": "schema_aware",
      "claims": "table_partition",
      "verify": ["schema-validate", "scanPhi --strict", "row-count-check"],
      "evidence": "schema_diff+phi_report"
    },
    "binary": {
      "merge": "exclusive_hash",
      "claims": "file",
      "verify": ["file-type-check", "sha256-baseline"],
      "evidence": "binary_hash+thumbnail"
    },
    "app_state": {
      "merge": "app_diff",
      "claims": "record_field",
      "verify": ["api-schema", "dry-run", "dlp"],
      "evidence": "app_diff"
    },
    "memory": {
      "merge": "scope_lease",
      "claims": "scope_key",
      "verify": ["scope-purpose-retention"],
      "evidence": "scope_diff"
    },
    "mixed": {
      "merge": "per_path",
      "claims": "strictest",
      "verify": ["union_of_profiles"],
      "evidence": "grouped_by_profile"
    }
  },
  "sandbox": {
    "linux": { "driver": "bwrap", "landlock": "auto", "seccomp": true },
    "macos": { "driver": "seatbelt" }
  },
  "read_scope": [
    { "path": "$WORKSPACE", "access": "rw" },
    { "path": "$HOST_PROJECT", "access": "ro" },
    { "path": "~/.claude/settings.json", "access": "ro" },
    { "path": "~/.claude.json", "access": "ro" },
    { "path": "~/.claude/projects", "access": "rw" },
    { "path": "~/.claude/todos", "access": "rw" },
    { "path": "~/.claude/.credentials.json", "access": "rw", "mode": "0600" },
    { "path": "~/.gemini/config/hooks.json", "access": "ro" },
    { "path": "~/.codex/config.toml", "access": "ro" },
    { "path": "~/.codex/sessions", "access": "rw" },
    { "path": "~/.codex/auth.json", "access": "rw", "mode": "0600" },
    { "path": "~/.config/opencode/opencode.json(c)", "access": "ro" },
    { "path": "~/.local/share/opencode", "access": "rw" },
    { "path": "~/.cargo/registry", "access": "ro" },
    { "path": "~/.rustup", "access": "ro" }
  ],
  "network": {
    "default": "deny",
    "allow": [
      "api.anthropic.com",
      "api.openai.com",
      "generativelanguage.googleapis.com",
      "registry.npmjs.org"
    ],
    "write_methods": ["POST", "PUT", "PATCH", "DELETE"]
  },
  "approvals": {
    "batch_window_ms": 2000,
    "suggest_lease_after": 5,
    "suggest_lease_window_ms": 600000
  }
}
```

---

## 10. 实施计划

### Phase 0：说真话与可观测性（✅ 已完成）

**目标**：在改架构之前，先让用户和团队知道当前处于哪种模式。

交付：

- `aos status` / `doctor` 显示 enforcement level、Hook 是否加载、MCP 是否连接、OpenCode 共享服务状态。
- README / 官网文案分级：advisory / enforced / isolated；移除绝对化安全表述。
- 客户端矩阵页面。
- 当前 Hook / 路由缺口清单（`NotebookEdit`、未知 MCP、项目配置覆盖等）。
- 埋点：模式分布、审批次数、denied effects。

验收：

- `doctor` 在 Hook 被禁用时明确显示 `advisory (hooks missing)`。
- 文档中每个客户端的承诺与代码一致。

### Phase 1：`aos run` Linux MVP（✅ Linux 完成；macOS 见 Phase 4）

**目标**：Agent 进程树进入 bwrap，宿主只读，shadow 可写，出口代理可用；先以 Claude Code 作为参考客户端，不追求一次接完所有 Agent。

交付：

- `aos run`、`aos status`、`aos last`、`aos diff`、`aos commit`、`aos discard`。
- PTY / 信号 / 退出码 / 退出摘要。
- Linux 路径保持（shadow bind 到原路径）；宿主工件树 ro-bind 到 `/aegis/host`。
- 读视图：`--ro-bind / /` + `--tmpfs` 遮蔽用户数据 + 白名单挂回（NixOS / Linuxbrew / Snap 兼容）。
- `$HOME` tmpfs + Agent 状态目录分层（敏感配置 ro、会话/缓存 rw）。
- Git 视图映射：宿主 `.git` ro、`GIT_INDEX_FILE` 可写副本、只读 git shim。
- CoW backend：优先 OverlayFS / fuse-overlayfs；ext4 回退 lazy-copy，`doctor` 标注。
- egress：identity-pinned CONNECT 代理 + Unix-socket bridge + 域名 allowlist；宿主 loopback 不可达；L7 DLP / Base URL 反向代理留到 Phase 2。
- PATH shim 安装 / 卸载。
- `aos agent list` 能检测 `agy` / `claude` / `codex` / `opencode` / `hermes`，但只承诺 Claude Code 的端到端冒烟。
- 红队测试：`~/.ssh`、宿主写、`curl` 任意域名、`git push`、子进程逃逸。

验收：

- 20 项 launcher 红队用例 100% 拦截。
- `cargo test` / `npm test` / Claude Code TUI 正常。
- Git 视图下 `git status` / `git diff` / `git log` 正常，宿主 `.git` mtime 不变。
- ext4 + overlay / fuse-overlayfs 启动 P95 < 150 ms；lazy-copy 明确标注降级。
- OpenCode / Hermes 只做检测，不阻塞 Phase 1 交付。

### Phase 2：Effect 模型与审批（🟡 部分完成：effect/审批/租约/审计已完成，L7 未完成）

**目标**：策略从工具名迁移到 effect；审批按能力聚合。

交付：

- `Effect` / `EffectKind` / `ResourceScope` / `Reversibility`。
- `PolicyContext` 扩展 `effects` / `scope` / `reversibility` / `tags`。
- Cedar 子集扩展（`resource.tag`、`resource.scope`、`resource.lease`）。
- `DecisionClass`；`PolicyDecision` 兼容映射。
- `fs.read` 策略；读范围收紧。
- Egress：CONNECT 模式只产生 `net.connect`（host/port/bytes）；模型 API 走 Base URL 反向代理产生 `net.request`；opt-in MITM 放到 Phase 5。
- 审批服务：批量、证据、`evidence_hash`、`required_capability`。
- `aos why` / `aos policy explain`。
- 审计 `EffectRecord`，网络事件记录 `egress_mode`。

验收：

- 策略矩阵测试覆盖全部 effect × scope。
- 典型 30 分钟会话审批 ≤ 3 次。
- one-shot 审批的 diff 哈希不一致时拒绝执行。
- CONNECT 模式只记录 `net.connect`；Base URL 模式能正确记录 method / path 并做 DLP；MITM 未启用时不得声称 L7。

### Phase 3：会话模式、DomainProfile 接口与五客户端（🟡 部分完成：profile/verify/CAS 已完成，专用合并器未完成）

**目标**：observe / implement 模式；read/write claim；只交付 `DomainProfile` 扩展接口和两类通用合并器；完成五个 Tier A 客户端适配。**不**在本阶段做 Schema-aware 数据合并、Office CRDT、PHI、数据流水线 CAS（`org_artifact_publish` + DAG）、AAP / UOMP；本地 `aos publish` / `artifacts` 基础 CAS 属于本阶段。

交付：

- `--mode observe`：只读挂载、commit 拒绝、网络只读。
- `WorkspaceDomain` 自动检测 + `DomainProfile` 扩展接口（merge / claims / verify / evidence 可插拔）。
- 两类内置合并器：
  - **文本 LCS**：覆盖 code + Markdown / LaTeX 文本；
  - **排他锁 + 基线 SHA-256**：覆盖 binary、`.parquet`、`.docx` 等不可按行合并的文件。
- `verify_cmd` 外部执行器：沙箱内执行、超时、日志 / 渲染产物进入 `evidence_hash`。
- `aos verify`；`aos diff --render` 先支持 Markdown / LaTeX 的简单渲染预览。
- `coord_claim` 的 `read` / `write` 模式；本阶段只做文件 / Glob 粒度。
- 统一 adapter API `/v1/adapter/evaluate` + Agent Adapter Protocol。
- AGY / Claude / Codex / OpenCode / Hermes adapter；OpenCode plugin：`execute.before`、`shell.create.before`、`permission.evaluate`、`mcp.transform`。
- `aos agent add/doctor/test` + Tier B manifests（Gemini CLI、Aider、Goose、Amp）；Tier D 的 IDE 扩展放到 Phase 5。
- `aos top` 展示 read/write claim 与领域。

**明确不在 Phase 3**：

- Schema-aware 数据自动合并、PHI 扫描、CAS 数据流水线与任务 DAG（本地 publish/list/fetch 已在 Phase 3）；
- Office `.docx` / `.pptx` 的 CRDT 块级锁；
- 章节 / 段落 / 表分区 / 行区间 claim；
- `app_state` / `memory` profile；
- 这些全部进入 Phase 5 或独立子文档。

验收：

- 两个 Agent 同时读同一文件不冲突；写冲突被拒绝。
- 三个 Agent 并行改写不同文件成功；同一文件冲突被拦截。
- Markdown / LaTeX `verify_cmd` 失败时宿主不被触碰。
- 二进制基线变化时，未授权覆盖被拒绝。
- 五个 Tier A 客户端都能在 `aos run` 下启动并完成一次读写。
- Hermes heartbeat / adapter 协议在 `doctor` 中显示为已加载。
- observe 会话无法写入宿主或 shadow（或写入后被丢弃）。
- OpenCode 共享服务检测生效。

### Phase 4：macOS 与内核加固（🟡 部分完成）

**目标**：macOS enforced 可用；Landlock / seccomp 落地；microVM 试点。

已完成：macOS Seatbelt launcher MVP（shadow cwd、宿主只读、credential/token deny、egress proxy、PTY、broker TCP control、MCP bridge、Git shim），并已在 macOS 实机验证。未完成：default-deny 收敛、路径重映射、Landlock、seccomp、microVM。

交付：

- macOS Seatbelt：先 `allow default` + 收紧写 / 凭据 / 网络 / 敏感路径 deny，跑兼容矩阵后逐步 default-deny；按客户端模板。
- macOS 路径限制的 UX（shadow 路径 banner）。
- Landlock ruleset（`aos-sandbox-init`）。
- seccomp denylist。
- `aos run --isolated` 本地 microVM 原型 / Cloud Sandbox 绑定。
- 性能与兼容性矩阵。

验收：

- macOS 红队用例 100% 拦截（不含路径重映射）。
- Landlock 不可用时 `doctor` 明确显示降级。
- 隔离模式首启 < 3 s，复用 < 500 ms。

### Phase 5：高级领域、Office / 跨应用 / 记忆 / IDE / 企业（⬜ 未开始）

- `docs` 高级能力：章节 / 段落 claim、`.docx` / `.pptx` 双表面 CRDT 块级锁 + `patchParagraph`、更完整的渲染 diff。
- `data` 高级能力：Schema-aware 自动合并、表 / 分区 / 行区间 claim、`scanPhi --strict`、行数 / 统计不变量、CAS 流水线（`org_artifact_publish` / `fetch`）与任务 DAG。
- `app_state` profile：AAP-1.0 `app_mount_session` / `app_call_tool`，字段级 diff、幂等键、补偿 / 回滚。
- `memory` profile：UOMP scope lease、读取目的、保留期、撤销入口。
- VS Code / JetBrains / Cursor / Windsurf / Cline / Continue / Roo Code 扩展通过 Aegis daemon 启动会话（Tier D）。
- MDM / 托管策略：禁止 `--no-enforce`，强制审批人组；Claude managed hooks / `allowManagedHooksOnly` 等客户端托管能力。
- `aos agent add` 的签名 manifest 与版本矩阵；第三方 Agent 生态。
- 审计导出 SIEM；合规报告（PHI / SOC2 / 数据驻留）。
- Windows / WSL 评估。
- 客户端自动更新兼容性测试。

### 10.1 里程碑与依赖

| 里程碑 | 状态 | 依赖 | 风险 |
|---|---|---|---|
| M1 `aos run` Linux | ✅ 完成 | bwrap 版本、TUI 继承、OpenCode `--standalone` 验证 | 客户端 TUI 兼容性 |
| M2 Effect 策略 / 审批 | 🟡 部分完成（L7 未完成） | Cedar 解析器扩展、审批 UI | 策略复杂度 / 误报 |
| M3 DomainProfile 接口 + 五客户端 | 🟡 部分完成（专用合并器未完成） | DomainProfile、文本 LCS、排他锁/基线哈希、adapter API | 并发冲突、领域预检误报 |
| M4 macOS | ⬜ 未开始 | Seatbelt profile 调试、路径限制 | 工具兼容性 |
| M5 高级领域 / 隔离 | ⬜ 未开始 | Schema-aware、CRDT、PHI、CAS、AAP-1.0、UOMP、microVM / Cloud 绑定 | 性能、成本、应用覆盖 |

---

## 11. 测试与验证

### 11.1 单元测试

- `Effect` 到 `PolicyContext` 的映射。
- 策略矩阵：每个 effect × scope × mode 的期望决策。
- 租约匹配：TTL、one-shot、task-scoped、read-only。
- `evidence_hash` 规范化与校验。
- 路径规范化 / symlink / `..` / TOCTOU 用例。
- OpenCode adapter 的决策映射。

### 11.2 集成测试

- 假 Agent 尝试：
  - 读 `~/.ssh/id_rsa`、`~/.aws/credentials`、`~/custom_vault/secret.pem`。
  - 写 `/tmp/escape`、`../../host`、`~/.claude/settings.json`。
  - `curl` 任意域名、DNS exfil、`--noproxy`。
  - `git push`、`npm publish`、`ssh`。
  - `ptrace`、`mount`、`unshare`、`setns`、`io_uring`、`bpf`。
  - 子进程 / 构建脚本 / `postinstall`。
  - 伪造 `AOS_SESSION_TOKEN` / 其他 Agent 身份。
  - 修改 Hook / 项目配置 / `.mcp.json`。
- OpenCode 专项：
  - 共享服务已运行时启动 enforced。
  - `--standalone` 与 `--server` 两种模式。
  - Code Mode on/off。
  - `@` 文件引用、LSP、formatter、undo。
- Hermes 专项：
  - MCP 注册 + Adapter Protocol 握手。
  - `heartbeat` 缺失时 `doctor` 报警。
  - `adapter.evaluate` 的 allow / ask / deny / rewrite。
  - `hermes run` headless 模式。
- 领域专项（Phase 3）：
  - 3 个 Agent 并行改不同 Markdown / LaTeX 文件；同一文件冲突。
  - `latexmk` / `bibtex-check` 失败时宿主不被触碰。
  - 人类替换同名 `figures/*.pdf` 后，Agent 覆盖被基线哈希拦截。
  - 文本 LCS 与排他锁/基线哈希两类合并器的边界。
- 领域专项（Phase 5）：
  - CSV / Parquet 的 Schema-aware 合并、PHI 命中、行数校验。
  - CAS 发布后下游只读哈希；未发布数据集不可见。
  - Office `.docx` / `.pptx` CRDT 块级锁；章节 / 段落 claim。
  - `app_state` / `memory` 的字段级 diff、scope lease。
  - 混合工作区的分组预检门。
- 多 Agent：
  - 两个 Agent 同时写同一文件。
  - 读锁与写锁并发。
  - commit 期间 peer 更新。
  - Phase 5：领域 claim（章节 / 分区 / 记录）交叉冲突。

### 11.3 红队

复用 `scripts/e5_ablation.py` 与 80 项攻击，新增：

| 编号 | 攻击 | 期望 |
|---|---|---|
| L1 | `cat ~/.ssh/id_rsa` | deny |
| L2 | `write ~/.claude/settings.json` | deny |
| L3 | `curl https://evil.example` | deny |
| L4 | `git push` | ask |
| L5 | `python -c 'os.system(...)'` | 沙箱内，宿主不可写 |
| L6 | `bwrap` 内再 `bwrap` | 拒绝 / 无权限 |
| L7 | `ptrace` 父进程 | seccomp deny |
| L8 | 修改 `/aegis/host` | 只读 |
| L9 | 伪造 session token | 401 |
| L10 | OpenCode 连接宿主共享服务 | 启动拒绝 / 警告 |
| L11 | `opencode run` 绕过 TUI | 仍走 standalone 沙箱 |
| L12 | 项目 `.mcp.json` 注入 filesystem MCP | 未知 server 默认拒绝 |
| L13 | 未经授权覆盖宿主二进制图 | 基线哈希拒绝 |
| L14 | 数据集中夹带 PHI 落盘 | `scanPhi` 拒绝 + 字段级报告 |
| L15 | 下游读取上游未发布 / 半成品数据集 | CAS 不存在 / 拒绝 |
| L16 | 未经审批写 CRM / 日历 | `app.write` ask / deny |
| L17 | 越权读取 UOMP memory scope | 租约拒绝 + 审计 |
| L18 | 伪造 Hermes adapter heartbeat / token | 401 / session 不匹配 |
| L19 | 恶意 `agent add` manifest 指向宿主文件 | manifest 校验 + 沙箱拒绝 |
| L20 | CONNECT 隧道下尝试 L7 DLP / method 审计 | 只记录 `net.connect`，不伪造 method |
| L21 | Agent 写 `~/.claude/settings.json` | 拒绝；写 `~/.claude/projects` 允许 |
| L22 | `git status` / `git diff` 写宿主 `.git/index` | 宿主 index mtime 不变；只写 session 副本 |
| L23 | TUI 活跃时审批写 PTY / 抢快捷键 | 不写主屏幕，不抢输入 |
| L24 | ext4 无 overlay 启动 1 GB 数据集 | lazy-copy 警告，不谎报 150 ms |

### 11.4 性能基准

- `aos run` 启动 P50 / P95，按 APFS / Btrfs / XFS / OverlayFS / fuse-overlayfs / ext4 lazy-copy 分档。
- shadow 创建（1k / 10k 文件；1 GB / 10 GB 数据集），记录实际 backend。
- 首 token 延迟（CONNECT / Base URL 反向代理 / MITM on-off）。
- 大仓库 `cargo build` / `npm test` 开销。
- 文档（Phase 3）：`latexmk` 全量 / 增量编译；Markdown / LaTeX 渲染预览。
- 数据（Phase 5）：1 GB Parquet 的 shadow 创建、Schema 校验、PHI 扫描、CAS 发布。
- Git 视图：`git status` / `diff` / `log` 在 1k / 100k 文件仓库的延迟。
- TUI 帧率 / 输入延迟；审批通知不破坏 alternate screen。
- 审批弹窗到决策的往返。
- 多 Agent 并发（3 / 5 Agent）的 claim 和 commit 延迟。

### 11.5 可用性测试

- 10 名开发者，30 分钟真实编码任务。
- 5 名文档 / 科研用户，30 分钟多章节写作 + 配图任务（Phase 3 基础 / Phase 5 高级）。
- 5 名数据用户，30 分钟清洗 + 统计 + 图表任务（Phase 5 研究）。
- 指标：审批次数、放弃率、`--no-enforce` 使用率、主观安全感、最烦的 3 个点。
- 重点观察 OpenCode 用户：共享服务、`--standalone`、MCP 工具、formatter。
- 重点观察 Hermes 用户：Adapter Protocol 是否真的加载、heartbeat、headless。
- 重点观察文档 / 数据用户：渲染 diff、Schema diff、PHI 报告是否可读，是否比纯弹窗更可信。

---

## 12. 迁移与兼容

### 12.1 现有用户

- `aegis-os install` 默认仍为 advisory，避免破坏现有工作流。
- `aegis-os install --enforce` 显式选择 enforced；`doctor` 显示差异。
- `aegis-os install --all` 扫描并接入所有检测到的 Agent（AGY / Claude / Codex / OpenCode / Hermes / Tier B）。
- 现有 MCP 工具、Hook、CoW、commit 审批全部保留。
- 现有代码仓库默认 `profile=code`；文档 / 数据工作区默认 `mixed`，可用 `aos workspace profile docs|data` 切换。
- Git 视图默认开启（`.git` ro + `GIT_INDEX_FILE` 可写副本）；可用 `AOS_GIT_VIEW=0` 关闭，但 Agent 的 git 上下文会退化。
- ext4 默认尝试 OverlayFS / fuse-overlayfs；不可用时回退 lazy-copy，`doctor` 显示 backend。
- Agent 状态目录首次启动时按 §7.1.5.1 分层挂载；OAuth 凭据文件在会话结束后原子写回。
- `AOS_ROUTING` 继续兼容，但标记 deprecated；新配置用 `enforcement` / `mode`。
- `AOS_FORCE_WRAP_CMD` 仅保留给 advisory 兼容；enforced 不使用。

### 12.2 配置迁移

- 旧的 `policy/default.cedar` 继续加载；新 action 通过别名映射：
  - `workspace_commit` → `workspace.commit`
  - `fs_write` → `fs.write`
  - `egress_connect:*` → `net.connect:*`
  - 新增 `binary.write` / `dataset.write` / `dataset.schema_change` / `app.write` / `memory.write` / `org_artifact_publish`
- 旧租约按 action 字符串匹配；新租约同时记录 `effect_kinds`。
- 现有仓库默认 `profile=code`；非代码目录首次启动时提示选择 `docs` / `data` / `binary` / `mixed`，不强制迁移。
- `.aegis/workspace.json` 是可选覆盖；不存在时使用自动检测。
- `aos policy migrate` 输出差异，不自动改写用户策略。

### 12.3 卸载

- `aos uninstall --shim-only`：移除 PATH shim 与 shell PATH block；保留 MCP / Hook 和 shadow。
- 完整 `aos uninstall` 目前与 `--shim-only` 行为相同，只额外打印提示；移除客户端 MCP/Hook 配置块、runtime 目录和未提交 shadow 仍是 planned。
- 卸载前检查未提交 shadow / 提示用户仍是 planned。

### 12.4 发布

- Homebrew / install.sh 增加 `aegis-os run` 依赖检查（bwrap / sandbox-exec）。
- 版本升级时自动刷新 shim，但不自动切换 enforcement 模式。
- `aos doctor` 在升级后提示「enforced 可用」。

---

## 13. 风险与开放问题

### 13.1 风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| 客户端升级破坏 Hook / Plugin | advisory 失效 | adapter 版本矩阵 + 自动检测 + enforced 兜底 |
| OpenCode 共享服务绕过 | enforced 失效 | 强制 `--standalone` / 沙箱内 serve；启动检测 |
| macOS 无法路径重映射 | UX 困惑 | banner 明确；Phase 5 VM |
| Agent 自带 sandbox 与 Aegis 嵌套 | 工具失败 | 检测并提示关闭内层 sandbox；外层始终保留 |
| 认证 / Keychain 不可用 | Agent 无法登录 | 敏感配置 ro；OAuth 凭据单文件 0600 rw + 会话结束原子写回；沙箱外完成交互登录 |
| CONNECT 无法做 L7 | DLP / method 审计失效 | 默认只承诺 `net.connect`；模型 API 用 Base URL 反向代理；其他域名 opt-in MITM |
| ext4 无 reflink | 启动慢、两份拷贝 | OverlayFS / fuse-overlayfs；回退 lazy-copy 并在 `doctor` 标注 |
| Git 视图不兼容 worktree / LFS | git 命令报错 | 支持 `.git` 文件；LFS smudge 默认禁用；worktree 走 broker |
| TUI 审批写屏 | 花屏 / 输入竞争 | 不写 PTY master；桌面通知 + OSC 标题 + 旁路 `aos approve` |
| 工具链 / LSP / formatter 被破坏 | 用户弃用 | 兼容性矩阵 + 只读挂载 + 逐客户端测试 |
| 审批疲劳 | 用户关闭保护 | 能力租约 + 批量 + 用户数据窄读 |
| 策略误报 | 正常工作被拦 | `aos why` + 建议租约 + 灰度 |
| 用户主动绕过 | 安全承诺失效 | 审计 + 企业托管 + 明确非目标 |
| microVM 性能 / 成本 | 隔离模式不可用 | 本地轻量 VM / Cloud scale-to-zero |
| 供应链（plugin npm 包） | 恶意插件 | 签名 / 固定版本 / 本地内置 |
| 领域预检门配置错误 | 坏数据 / 坏排版落盘 | 默认拒绝 + 预置 profile + 灰度；`skip_verify` 敏感审批 |
| 二进制 / Office 格式兼容性 | 覆盖或损坏 | 排他锁 + 基线哈希；Office CRDT 仅支持格式 |
| 大数据集性能 | 启动 / 合并慢 | CoW 元数据、分区 claim、流式读取、CAS |
| 应用状态回滚困难 | 写坏 SaaS 数据 | 幂等键 + 补偿事务 + dry-run；高风险需双人审批 |
| Adapter Protocol 漂移 | Hermes / 第三方失效 | 协议版本 + `doctor` 心跳 + enforced launcher 兜底 |
| `aos agent add` 恶意 manifest | 任意命令执行 | manifest 签名 / 审核 / 只允许声明式配置 |
| launcher 与 policy kernel 双审批/审计账本 | 证据与处置状态不一致 | 已统一 `aos_core::compute_diff_evidence`，并在 `launcher::commit` / `approval_decide` 中双向同步 `approval.json`、`AegisPolicyKernel` (`policy_state.json`) 与 `AegisFlightRecorder` (`flight_recorder.jsonl`) |

### 13.2 开放问题

1. `aegis-os install` 是否应该在 1.0 默认 enforced？建议：默认 advisory，安装时用交互式推荐 enforced；企业默认 enforced。
2. Broker 是 per-session 还是全局 daemon？建议 per-session，降低攻击面；全局只做控制面。
3. macOS 是否值得做 Seatbelt 默认拒绝，还是直接推 isolated VM？建议 Phase 4 先做 Seatbelt，Phase 5 推 VM。
4. 是否支持 Windows 原生？建议 v1 只支持 WSL。
5. Agent 自动更新在沙箱内失败如何处理？建议 launcher 提供 `aos update-agent` 在沙箱外执行。
6. 用户合法的 `~/.ssh` 使用（例如 `git push` over SSH）如何支持？建议 egress / SSH agent 代理，不直接暴露私钥。
7. OpenCode 的 shared service 是否可以配置为 per-location？需要跟进 V2 版本；当前以 `--standalone` 为准。
8. 是否为 enforced 模式收费？建议 L2 免费基础版 + 企业策略 / 审计 / 隔离收费。
9. 文档 / 数据领域的默认 `verify_cmd` 由谁维护？建议提供官方 profile 模板，但允许团队覆盖；企业可强制。
10. 二进制资产是否应与文本共享同一个 shadow，还是单独 CAS 管理？建议同一 shadow + 基线哈希，发布时进 CAS。
11. Office CRDT 的格式覆盖范围？建议先支持 `.docx` / `.pptx` 的段落级 `patchParagraph`，其他格式退回排他锁。
12. 应用状态的「commit」语义如何统一？建议使用 `apply` + 幂等键 + 补偿，不复用文件 commit。
13. Hermes 的 Adapter Protocol 由谁维护版本？建议 Aegis 定义协议、Hermes 实现，双方共用 conformance test。
14. 各主流客户端的 Base URL 覆盖能力矩阵由谁维护？建议逐客户端 smoke test，不能假设所有客户端都支持 `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`。
15. Opt-in MITM 的 CA 生命周期、证书 pinning 兼容性和企业合规说明需要单独文档。
16. OverlayFS 在目标 Linux 发行版 / 内核上的 unprivileged 可用性需要矩阵验证；不可用时 fuse-overlayfs 的安装成本要评估。
17. Git 视图的 `GIT_INDEX_FILE` 在宿主刷新后如何同步？建议每次 `refresh_from_host` 后重建索引副本，或在 `git status` 前按 mtime 校验。

---

## 14. 附录

### 14.1 代码映射

| 能力 | 现有位置 | 改造 |
|---|---|---|
| CLI 命令 | `crates/aos-cli/src/main.rs` | `Run` / `Status` / `Last` / `Diff --render` / `Verify` / `Publish` / `Discard` / `Why` / `Agent` / `Uninstall` / `workspace profile` |
| DomainProfile | `crates/aos-core/src/profile.rs` | merge / claims / verify / evidence / overwrite 接口与默认值；`launcher` 读取 `.aegis/workspace.json` |
| Hook 路由 | `crates/aos-cli/src/routing.rs` | 保留为 advisory adapter；effect 映射仍待接线 |
| Hook 处理 | `crates/aos-cli/src/hooks.rs` | 改为调用 broker `/v1/adapter/evaluate`（planned） |
| 安装器 | `crates/aos-cli/src/installer.rs` | PATH shim、shell PATH block、五客户端检测、`doctor` enforcement 状态 |
| Agent 适配 | 新增 `crates/aos-adapters/` | planned：AdapterManifest、AGY / Claude / Codex / OpenCode / Hermes + Tier B |
| 沙箱 | `crates/aos-sandbox/src/lib.rs` | `--ro-bind / /` + tmpfs 遮蔽、Git 视图、Agent 状态目录、Landlock、launcher 模式、路径映射 |
| Egress | `crates/aos-egress` / `crates/aos-sandbox/src/bridge.rs` | CONNECT 仅 `net.connect`；Base URL 反向代理（L7 DLP / secret injection）已接入 launcher；opt-in MITM planned |
| Session broker | `crates/aos-cli/src/session_broker.rs` | per-session Unix socket、agent/human token、adapter.evaluate/effect/heartbeat、escalation/lease/audit 路由 |
| 策略 | `crates/aos-policy/src/lib.rs` | `Effect::to_policy_context` 桥接、租约 matcher、Cedar 属性、DecisionClass（planned） |
| MCP | `crates/aos-mcp-gateway/src/lib.rs` | 完整 MCP bridge（planned）、`policy_request_capability`（planned）；session token/broker 已在 `session_broker.rs`；CAS / app / memory 在 Phase 5 |
| CoW | `crates/aos-vfs/src/lib.rs` | OverlayFS / fuse-overlayfs backend（planned）、baseline manifest（planned）、full-content SHA-256 evidence |
| 审计 | `crates/aos-recorder/src/lib.rs` + launcher `audit.jsonl` | 哈希链 evidence；`aos why` 校验链；EffectRecord（planned） |
| OpenCode | 新增 `crates/aos-opencode-plugin/` 或 npm 包 | planned：V2 plugin + adapter |
| Hermes | 第一方 adapter | planned：Adapter Protocol 参考实现 |

### 14.2 现有 Hook matcher 缺口

`crates/aos-cli/src/installer.rs` 中的 matcher：

```text
call_mcp_tool|mcp_aegis-os_.*|mcp__aegis-os__.*|write_file|edit_file|read_file|view_file|run_command|Write|Edit|MultiEdit|Read|Bash
```

缺口：

- `NotebookEdit` 在 `hooks.rs` 处理，但不在 matcher。
- `mcp__<other-server>__*` 不匹配。
- 未来新增工具默认漏过。
- Claude Code 支持 `mcp__.*` 通配 matcher 和 `updatedInput`，当前适配器尚未利用；advisory 模式可以显著增强。
- 建议 advisory 模式改为 `.*`，在 handler 内做 allowlist；enforced 模式不依赖 matcher。

### 14.3 红队用例清单（新增）

| 类别 | 用例 |
|---|---|
| 路径逃逸 | `..`、symlink、bind mount、`/proc/self/root`、`openat2` |
| 凭据 | `~/.ssh`、`~/.aws`、Keychain、`/etc/shadow`、自定义 vault |
| 网络 | 直连 IP、DNS、`--noproxy`、HTTP/2、WebSocket、QUIC |
| 进程 | `ptrace`、`process_vm_readv`、`/proc/<pid>/mem`、`setns`、`unshare` |
| 构建 | `build.rs`、`postinstall`、`Makefile`、`.cargo/config.toml` |
| 配置 | `.claude/settings.json`、`.mcp.json`、`opencode.json`、`AGENTS.md` |
| 身份 | 伪造 `AOS_SESSION_TOKEN`、跨 Agent MCP 调用、审批端点 |
| 客户端 | OpenCode 共享服务、Codex 无 Hook、Claude Hook 禁用 |
| 审批 | TOCTOU diff 替换、租约重放、批量审批夹带敏感文件 |

### 14.4 术语

| 术语 | 含义 |
|---|---|
| advisory | 兼容模式，Hook / Plugin / 规则，不承诺抵抗被劫持 Agent |
| enforced | Aegis 启动 Agent，内核沙箱 + broker + 代理 |
| isolated | microVM / 远程沙箱，硬件级隔离 |
| shadow | CoW 影子工作区 |
| effect | 一次操作产生的安全效果（读/写/执行/网络/密钥） |
| scope | 效果发生的资源范围（shadow / project / home / credential / remote） |
| lease | 有时限、范围、任务绑定的能力授予 |
| escalation | 待人类审批的边界请求 |
| broker | 沙箱外的策略与 MCP 执行代理 |
| evidence_hash | 审批时对 diff / 命令的 SHA-256 锚定 |

---

## 15. 决策记录（ADR 摘要）

| ID | 决策 | 备选 | 理由 |
|---|---|---|---|
| D1 | enforced 用 launcher，不用 Hook | 继续增强 Hook | 子进程无法可靠约束父进程 |
| D2 | 策略按 effect，不按工具/命令 | 命令 allowlist | 命令可绕过、效果可内核验证 |
| D3 | 用户数据窄读：`/` 只读保留，`/home` 等 tmpfs 遮蔽 | 枚举系统目录 | 兼容发行版，同时隐藏用户数据 |
| D4 | 审批按能力租约聚合 | 每次调用弹窗 | 防审批疲劳 |
| D5 | per-session broker + token | 全局 daemon / 命令行身份 | 降低攻击面、防身份伪造 |
| D6 | OpenCode enforced 必须使用私有 Server（`--standalone` 或沙箱内 `serve`） | 包住 TUI | 工具执行在后台 Server |
| D7 | 不静默降级 | 自动回退 advisory | 避免用户误以为受保护 |
| D8 | macOS v1 接受 shadow 路径 | 强行路径重映射 | Seatbelt 无 mount namespace；不破坏宿主 |
| D9 | advisory 默认保留 | 默认 enforced | 兼容性优先；enforced 显式推荐 |
| D10 | 审计在沙箱外、只追加 | Agent 自报 | 防篡改 |
| D11 | 领域差异用 `DomainProfile`，不另起运行时 | 每个领域一套工具 | 统一安全模型和审计 |
| D12 | 二进制不可合并：排他锁 + 基线哈希 | 强制二进制三路合并 | 不可行且会损坏文件 |
| D13 | 数据流水线下游只读 CAS 哈希 | 共享 `/tmp` 目录 | 消除半成品脏读 |
| D14 | 五客户端一等支持 + 通用 Adapter Protocol | 每个 Agent 单独硬编码 | 可扩展、可测试、可降级 |
| D15 | CONNECT 只承诺 `net.connect`；L7 走 Base URL 反向代理或 opt-in MITM | 宣称 CONNECT 可做 DLP | 不做 MITM 就看不到 L7 |
| D16 | Git 视图：宿主 `.git` ro + 独立 index + 只读 shim | 让 shadow 无 `.git` | Agent 内置 git 上下文必须可用 |
| D17 | Agent 状态目录可写、敏感配置单文件只读 | 整目录 ro | OAuth / 会话记录不能丢 |
| D18 | Linux ext4 用 OverlayFS / fuse-overlayfs，baseline 只存 manifest | 两次全量拷贝 | 150 ms 目标只在 O(1) backend 成立 |
| D19 | TUI 活跃时禁止向 PTY master 写审批文本 | 直接 stderr 提示 | 花屏 / 输入竞争 |
| D20 | Phase 3 只做接口 + 文本 LCS + 排他锁/哈希 | 一次做完 Schema-aware / CRDT | 防止范围蔓延拖垮核心 launcher |

## 16. OpenCode 集成骨架（实施附录）

> 以下是实施骨架，不是最终代码；V2 API 以 `@opencode/plugin` 当前版本为准。

**全局配置** `~/.config/opencode/opencode.jsonc`（由 `aegis-os install` 合并）：

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "aegis-os": {
        "type": "local",
        "command": [
          "/home/jz/.aegis/bin/aos",
          "mcp-bridge",
          "--socket",
          "/run/aegis/broker.sock"
        ],
        "codemode": false
      }
    }
  },
  "plugins": [
    {
      "package": "@heurion/opencode-aegis",
      "options": { "enforcement": "enforced" }
    }
  ],
  "snapshots": false,
  "permissions": [
    { "action": "external_directory", "resource": "*", "effect": "ask" },
    { "action": "shell", "resource": "*", "effect": "ask" }
  ]
}
```

说明：

- `mcp-bridge` 是沙箱内的小代理，只把 MCP JSON-RPC 转发到宿主 broker；它本身没有宿主文件权限。
- `codemode: false` 让工具名和权限规则稳定；如果启用 Code Mode，需要额外处理 `execute` 权限。
- `snapshots: false` 避免和 Aegis CoW 的 undo 冲突。
- `permissions` 是 advisory 模式的兜底；enforced 模式可以放宽，由内核负责。

**插件骨架** `plugins/opencode-aegis/index.ts`：

```ts
import { Plugin } from "@opencode/plugin"
import { request } from "node:http"

export default Plugin.define({
  id: "heurion.aegis",
  async setup(ctx) {
    const sessionId = process.env.AOS_SESSION_ID
    const control = process.env.AOS_CONTROL_SOCKET
    const enforcement = process.env.AOS_ENFORCEMENT ?? "advisory"

    if (!sessionId || !control) {
      if (enforcement === "enforced") {
        throw new Error("[aegis] enforced session is missing AOS_SESSION_ID / AOS_CONTROL_SOCKET")
      }
      console.warn("[aegis] no session token; running in unmanaged mode")
      return
    }

    function evaluate(tool: string, input: unknown): Promise<any> {
      return new Promise((resolve, reject) => {
        const req = request(
          {
            socketPath: control,
            path: "/v1/adapter/evaluate",
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-aegis-token": process.env.AOS_SESSION_TOKEN ?? "",
            },
          },
          (res) => {
            let body = ""
            res.setEncoding("utf8")
            res.on("data", (chunk) => (body += chunk))
            res.on("end", () => {
              try {
                resolve(JSON.parse(body))
              } catch (err) {
                reject(err)
              }
            })
          },
        )
        req.on("error", reject)
        req.end(JSON.stringify({ session_id: sessionId, tool, input }))
      })
    }

    // enforced 模式下只记录 effect；advisory 模式下做策略判断
    await ctx.tool.hook("execute.before", async (event) => {
      const decision = await evaluate(event.tool, event.input)
      if (decision.effect === "deny") {
        throw new Error(decision.reason)
      }
      if (decision.effect === "ask") {
        // 交给 broker 创建 escalation；这里阻塞等待，或抛出结构化提示
        throw new Error(decision.reason ?? "Aegis approval required")
      }
      if (decision.rewrite) {
        event.input = decision.rewrite
      }
    })

    // advisory：把 shell 的 cwd 拉回 shadow；enforced：cwd 已经映射，不需要改
    await ctx.shell.hook("create.before", (event) => {
      if (enforcement !== "enforced" && process.env.AOS_WORKSPACE) {
        event.cwd = process.env.AOS_WORKSPACE
      }
    })

    // 把 OpenCode 的 allow/ask/deny 映射到 Aegis 策略
    await ctx.permission.hook("evaluate", async (event) => {
      const decision = await evaluate(event.action, { resources: event.resources })
      event.effect = decision.effect
      event.message = decision.reason
    })
  },
})
```

**启动命令**：

```bash
aos run --client opencode -- opencode --standalone
```

**验证清单**：

- `opencode --standalone` 时，`ps` 中 Server 进程在 Aegis 沙箱的 PID namespace 内。
- `opencode` TUI 内执行 `shell` 写 `/tmp/escape` 失败。
- `opencode run "..."` 同样失败。
- 共享服务已运行时，`aos run` 拒绝或强制 standalone。
- `@` 文件引用、LSP、formatter、undo 正常。

---

## 17. Domain Profile 参考

> 这一节把「代码之外」的领域差异落成可配置的 `DomainProfile`。安全模型（内核 + broker + 审批 + 审计）在所有领域一致；变化的是合并策略、认领粒度、预检门和证据格式。
>
> **交付分层**：Phase 3 只实现 `DomainProfile` 接口、文本 LCS、排他锁 + 基线 SHA-256；Schema-aware / Office CRDT / PHI / CAS / AAP-1.0 / UOMP 属于 Phase 5，下列 profile 中标注了阶段。

### 17.1 Profile 结构

```rust
pub struct DomainProfile {
    pub domain: WorkspaceDomain,
    pub merge: MergeStrategy,
    pub claims: ClaimGranularity,
    pub verify: Vec<VerifyGate>,
    pub evidence: EvidenceFormat,
    pub read_scope: Vec<ScopeRule>,
    pub write_scope: Vec<ScopeRule>,
    pub overwrite: OverwritePolicy,
    pub cas: Option<CasPolicy>,
}

pub enum MergeStrategy {
    Lcs3,             // 四级 LCS 三路合并
    Lcs3CrdtBlock,    // 文本 LCS + Office 块级 CRDT
    SchemaAware,      // 按 Schema / 主键 / 分区合并
    ExclusiveHash,    // 排他锁 + 基线哈希
    AppDiff,          // API 字段级 diff
    ScopeLease,       // 记忆 scope 租约
}

pub enum ClaimGranularity {
    FileGlob,
    SectionParagraph,
    TablePartition,
    RowRange,
    File,
    RecordField,
    ScopeKey,
}

pub enum OverwritePolicy {
    Never,
    Explicit,          // 需要 overwrite 标志 + 审批
    AllowIfSameHash,   // 基线未变则允许
}

pub struct VerifyGate {
    pub name: String,
    pub command: Vec<String>,
    pub timeout_ms: u64,
    pub required: bool,
    pub evidence: EvidenceFormat,
}
```

### 17.2 `code` profile

| 项目 | 设计 |
|---|---|
| 典型工件 | 源代码、配置、`Cargo.toml` / `package.json` / `pyproject.toml`、测试 |
| 合并 | 四级 LCS；未修改文件快进；同锚点 import 去重 |
| 认领 | 文件 / Glob；读共享、写独占 |
| 预检 | `cargo test`、`npm test`、`pytest`、`go test`、lint、类型检查 |
| 证据 | Unified Diff、测试日志、失败堆栈 |
| 敏感路径 | `.git/hooks`、`.github/workflows`、`build.rs`、`Makefile`、`Cargo.toml`、`package.json`、`.cargo/config.toml` |
| 特殊规则 | 可执行文件 / 二进制产物默认不落盘；`overwrite_binaries` 需审批 |

### 17.3 `docs` profile（基础 Phase 3；Office / 章节级 Phase 5）

| 项目 | 设计 |
|---|---|
| 典型工件 | `.md`、`.tex`、`.bib`、`.docx`、`.pptx`、`.pdf`、图片、图表 |
| 合并 | Markdown / LaTeX 走 LCS；`.docx` / `.pptx` 走双表面 CRDT 块级锁 + `patchParagraph`；PDF 视为派生物，不合并且不默认落盘 |
| 认领 | 文件 / 章节 / 段落；二进制图走整文件独占 |
| 预检 | `latexmk -pdf`、`bibtex-check`、`markdown-link-check`、拼写检查、Pandoc 渲染、图片尺寸 / 格式检查 |
| 证据 | 源码 diff + 渲染后页面预览（PDF/HTML）；二进制缩略图 + 哈希 |
| 敏感路径 | 参考文献、模板、样式文件、`*.cls` / `*.sty`、图片目录 |
| 特殊规则 | 人类刚改过的二进制图，Agent 覆盖需 `overwrite_binaries` 审批；PDF 不直接合并，回源到 `.tex` / `.md` |

### 17.4 `data` profile（Phase 5）

| 项目 | 设计 |
|---|---|
| 典型工件 | `.csv`、`.parquet`、`.json`、`.sql`、`.ipynb`、数据库导出 |
| 合并 | Schema-aware；分区 / 行区间合并；二进制格式走排他锁 |
| 认领 | 表 / 分区 / 行区间；Schema 变更单独加锁 |
| 预检 | `schema-validate`、`scanPhi --strict`、行数 / 空值 / 主键唯一性、校验和、统计不变量 |
| 证据 | Schema diff、抽样行、行数变化、PHI 报告、哈希 |
| 敏感路径 | 含 PHI / PII 的列、原始数据、数据库连接串 |
| 特殊规则 | 下游只读 CAS 哈希指针；禁止读上游 `/tmp` / 输出目录；PHI 命中拒绝落盘 |

### 17.5 `binary` profile（Phase 3：排他锁 + 基线哈希）

| 项目 | 设计 |
|---|---|
| 典型工件 | PNG / TIFF / SVG / PDF / CAD / ZIP / 视频 / 音频 |
| 合并 | 不可按行合并：排他锁 + 基线 SHA-256 |
| 认领 | 整文件独占 |
| 预检 | `file` 类型、尺寸 / 分辨率、哈希、缩略图生成、病毒扫描（可选） |
| 证据 | 旧 / 新哈希、缩略图、元数据、尺寸 |
| 特殊规则 | 人类或其他 Agent 已更新宿主原件时，未授权覆盖一律拒绝；`overwrite_binaries` 单次审批 |

### 17.6 `app_state` profile（Phase 5）

| 项目 | 设计 |
|---|---|
| 典型工件 | SaaS 记录、CRM 字段、邮件、日历、浏览器会话 |
| 合并 | 不走文件 commit；API 字段级 diff + 幂等键 |
| 认领 | 记录 / 字段；通过 AAP-1.0 记录 ID / 字段路径 |
| 预检 | API Schema 校验、dry-run、权限 / DLP、业务不变量 |
| 证据 | 字段级 diff、请求预览、回滚 / 补偿计划 |
| 特殊规则 | 写操作必须可回滚或可补偿；调用记录进入哈希链；不把 API Token 暴露给 Agent |

### 17.7 `memory` profile（Phase 5）

| 项目 | 设计 |
|---|---|
| 典型工件 | UOMP scope 内的用户偏好、研究记忆、长期上下文 |
| 合并 | scope lease；按 key / scope 合并 |
| 认领 | scope / key |
| 预检 | scope / purpose / retention / consent 校验 |
| 证据 | scope diff、用途、保留期、撤销入口 |
| 特殊规则 | 读取需要目的和租约；写入可撤销；不把原始记忆写入普通日志 |

### 17.8 `mixed` workspace（Phase 5；Phase 3 仅按路径分组）

一个工作区可能同时包含代码、文档、数据与图片。处理规则：

- 默认按路径自动识别 profile；`aos run --profile mixed` 允许混合。
- 每个路径解析到最近的 `DomainProfile`；同一提交可以包含多个 profile 的工件。
- 预检门按 profile 分组执行；任何一组失败则整体不落盘。
- 证据按 profile 分组展示：代码 diff、渲染预览、Schema diff、二进制缩略图。
- 跨 profile 的 claim 冲突按最严格粒度处理（例如代码文件 + 图片同名目录）。

### 17.9 检测与配置优先级

```text
CLI --profile
  > .aegis/workspace.json 的 profile
  > 自动检测
  > 默认 mixed
```

自动检测启发式：

| 信号 | 推断 |
|---|---|
| `.git` + `Cargo.toml` / `package.json` / `pyproject.toml` / `go.mod` | `code` |
| `*.tex` / `*.bib` / `*.md` 占多数 | `docs` |
| `*.csv` / `*.parquet` / `*.ipynb` / `*.sql` | `data` |
| `*.docx` / `*.pptx` / `*.pdf` 占多数 | `docs`（Office 子 profile） |
| `*.png` / `*.tiff` / `*.psd` / `*.cad` 占多数 | `binary` |
| 多类混合 | `mixed` |

`.aegis/workspace.json` 示例：

```json
{
  "profile": "docs",
  "verify": {
    "cmd": "latexmk -pdf main.tex && bibtex-check refs.bib",
    "timeout_ms": 120000
  },
  "claims": { "granularity": "section_paragraph" },
  "binary": { "overwrite": "explicit" },
  "cas": { "publish": ["figures/**", "data/clean/**"] }
}
```

- 该文件属于 sensitive commit：Agent 不能自己改预检门。
- 人类可以通过 `aos workspace profile docs` 修改。
- 企业策略可以强制 profile 和 verify，不允许项目覆盖。

### 17.10 领域预检门目录

| Profile | 推荐预检门 |
|---|---|
| code | `cargo test`、`cargo clippy -- -D warnings`、`npm test`、`pytest`、`go test ./...`、`tsc --noEmit` |
| docs | `latexmk -pdf`、`bibtex-check`、`markdown-link-check`、`pandoc --check`、拼写检查、渲染截图 diff |
| data | `schema-validate`、`scanPhi --strict`、`row-count-check`、`null-check`、`primary-key-unique`、`checksum` |
| binary | `file --mime-type`、`identify`（ImageMagick）、`sha256sum`、缩略图生成、病毒扫描 |
| app_state | API schema、dry-run、权限检查、DLP、业务不变量 |
| memory | scope / purpose / retention / consent 校验 |

预检门的要求：

- 必须在沙箱内执行，宿主只读。
- 必须有超时和资源限制。
- 失败输出进入审批证据，不能只返回一个布尔值。
- `skip_verify` 是 sensitive 操作，需要单独审批。
- 预检门命令本身不可由 Agent 修改。

### 17.11 领域证据格式

| 格式 | 适用 | 内容 |
|---|---|---|
| `unified_diff` | 文本代码 / Markdown / LaTeX | 标准 diff、文件列表、行号 |
| `rendered_diff` | 文档 / PDF / HTML | 渲染后页面并排对比、编译日志 |
| `schema_diff` | 数据表 / JSON / SQL | 列增删改、类型、主键、索引 |
| `phi_report` | 医疗 / 个人数据 | 命中字段、样本脱敏、风险等级 |
| `binary_hash` | 图片 / PDF / CAD | 旧/新 SHA-256、尺寸、缩略图 |
| `app_diff` | 跨应用状态 | 字段级 before/after、请求预览 |
| `scope_diff` | 记忆 | scope、key、用途、保留期 |

所有证据统一规范化后计算 `evidence_hash`；One-Shot 审批锚定该哈希。

### 17.12 领域验收用例

| 场景 | 期望 |
|---|---|
| 3 个 Agent 并行改不同章节 | 全部成功；无 silent overwrite |
| 2 个 Agent 改同一段落 | 后写被 claim 拦截，不静默覆盖 |
| 人类在 trunk 改同一 `.tex` 的上半段，Agent 改下半段 | 四级 LCS 自动合并；编译通过 |
| Agent 生成 `figures/fig-03.pdf`，人类刚替换同名图 | 基线哈希不符，覆盖被拒绝；需 `overwrite_binaries` |
| 清洗 Agent 写 `data/clean/part-01.parquet`，统计 Agent 读同分区 | 统计 Agent 只读已发布 CAS 哈希；不读半成品 |
| 数据含 PHI | `scanPhi` 命中，commit 拒绝，审批单显示字段级报告 |
| `app_state` 写 CRM 字段 | 字段级 diff + API dry-run + 幂等键；失败可补偿 |
| `memory` 写入 | scope lease + 用途 + 保留期；可撤销 |
| 混合工作区同时改代码、文档、数据 | 预检门分组执行；任一失败整体不落盘 |

---

**文档结束。**
