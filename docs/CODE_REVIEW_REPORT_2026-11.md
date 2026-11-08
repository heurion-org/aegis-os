# Aegis OS 代码评审报告（2026-11-05 ~ 2026-11-06 Commits）

> [!NOTE]
> **评审范围**：`005edfb..762c5ab` 及本次收敛修改（共 29+ 个 Commits，36+ 个文件变更，`+14,500+ / -450+` 行）  
> **仓库报告路径**：[docs/CODE_REVIEW_REPORT_2026-11.md](file:///Users/huizhao/Downloads/workspace/aegis-os/docs/CODE_REVIEW_REPORT_2026-11.md)  
> **关联设计文档**：[docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md](file:///Users/huizhao/Downloads/workspace/aegis-os/docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md)

---

## 1. 执行摘要（Executive Summary）

本次评审覆盖了 Aegis OS 最近两天的全部提交，核心演进包含两大主线：

1. **主线 A — 多 Agent 协作内核、哈希链审计与 PreToolUse 路由加固（`6699554..804ebbf`）**
   - **A2A 分层任务树与级联生命周期**：在 [crates/aos-core/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-core/src/lib.rs#L543-L610) 与 [crates/aos-ipc/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-ipc/src/lib.rs#L350-L600) 中引入 `parent_task_id`、`depends_on`、`claimed_paths`、`lease_ids`、`revision` CAS 更新与 `cascade_cancel_descendants`，并新增反应式同步原语 `ipc_wait`（[crates/aos-mcp-gateway/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-mcp-gateway/src/lib.rs#L1149-L1292)）。
   - **防篡改 SHA-256 哈希链审计**：在 [crates/aos-recorder/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-recorder/src/lib.rs#L53-L239) 实现 `prev_hash -> event_hash` 链式签名与 [`AegisFlightRecorder::verify_chain`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-recorder/src/lib.rs#L156-L238)。
   - **Hook 路由与敏感提交收敛**：在 [crates/aos-cli/src/routing.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/routing.rs#L140-L645) 增加 `$()` / 反引号子命令递归拆解（[`extract_subshell_segments`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/routing.rs#L604-L645)）、运行时状态路径拦截（`RUNTIME_STATE_MARKERS`）与批量敏感路径单票据审批（[crates/aos-policy/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-policy/src/lib.rs#L367-L407)）。
2. **主线 B — Enforced Runtime（`aos run`）、Session Broker、Effect 模型与 L7 出站网关（`4107a96..762c5ab`）**
   - **设计规范与通用领域抽象**：新增 [docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md](file:///Users/huizhao/Downloads/workspace/aegis-os/docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md)、统一效果模型 [crates/aos-core/src/effect.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-core/src/effect.rs#L1-L265) 与领域配置 [crates/aos-core/src/profile.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-core/src/profile.rs#L1-L185)。
   - **Enforced Launcher 与 Per-Session Broker**：新增 [crates/aos-cli/src/launcher.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/launcher.rs#L1-L1800)（Linux `bwrap --bind-fd` + macOS Seatbelt + `openpty` TUI 终端保留）、[crates/aos-cli/src/session_broker.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/session_broker.rs#L1-L751)（`human.token` / `agent.token` 双 Token 隔离与 `/v1/adapter/*`、`/v1/mcp` 桥接）、[crates/aos-cli/src/adapter_manifest.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/adapter_manifest.rs#L1-L246) 以及 [plugins/opencode-aegis.js](file:///Users/huizhao/Downloads/workspace/aegis-os/plugins/opencode-aegis.js#L1-L98)。
   - **模型 API Base URL L7 反向代理 + DLP**：在 [crates/aos-egress/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-egress/src/lib.rs#L276-L561) 实现 `/__aegis/base/{anthropic,openai,gemini}` L7 反向代理、请求体 DLP 拦截与边界密钥替换。

### 评审问题统计与当前状态

| 严重级别 | 发现数量 | 已修复与验证 | 待后续架构演进收敛 |
|---|---|---|---|
| **🔴 High（高危安全/核心逻辑）** | 5 | 5 | 0 |
| **🟡 Medium（中危一致性/兼容）** | 4 | 4 | 0 |
| **🟢 Low（低危残留状态/鲁棒性）** | 2 | 2 | 0 |
| **🏗️ 架构收敛项（Evidence & 双账本同步 & macOS PATH）** | 3 | 3 | 0 |

---

## 2. 架构与设计一致性评审（Design Consistency）

### 2.1 `launcher.rs` 与 `aos-mcp-gateway` / `aos-policy` 的审批与审计账本收敛（已修复）
- **关联代码**：
  - [`aos_core::compute_diff_evidence`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-core/src/lib.rs#L199-L227)
  - [`launcher::commit`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/launcher.rs#L938-L1242)、[`launcher::approval_decide`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/launcher.rs#L1960-L2096)、[`launcher::approval_evidence`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/launcher.rs#L2106-L2108)
  - [crates/aos-mcp-gateway/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-mcp-gateway/src/lib.rs#L1152-L1153)
- **评审分析与收敛结果**：
  1. **Canonical Diff Evidence Hash 统一**：
     - 在 [crates/aos-core/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-core/src/lib.rs#L199-L227) 中提取公共函数 [`compute_diff_evidence`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-core/src/lib.rs#L199-L227)，按路径字典序规范化序列化 `FileDiffEntry`（包含完整文件 `old_sha256` / `new_sha256`），使 CLI `aos commit` 与 MCP `workspace_commit` 对同一 CoW 变更产出完全一致的 64 位 hex `evidence_hash`。
  2. **双审批账本与全局哈希链审计同步**：
     - [`launcher::commit`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/launcher.rs#L938-L1242) 与 [`launcher::approval_decide`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/launcher.rs#L1960-L2096) 现已双向同步 `sessions/<id>/approval.json`、`AegisPolicyKernel`（`policy_state.json`）以及 `AegisFlightRecorder`（`audit/flight_recorder.jsonl`），并在提交完成后自动释放该 Agent 持有的关联文件写锁（`release_claims_matching_committed_paths`）。

### 2.2 Linux 与 macOS 启动前置校验及 `.aegis-bin` `PATH` 一致性（已修复）
- **关联代码**：
  - [crates/aos-cli/src/launcher.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/launcher.rs#L2520-L2560)
  - [`build_macos_agent_path`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/launcher.rs#L2941-L2958)
- **评审分析与收敛结果**：
  - `validate_workspace_roots` 与 OpenCode `--server` 拦截 / `--standalone` 自动注入已统一置于 Linux/macOS 分支之前。
  - 在 `run_macos_inner` 中通过 [`build_macos_agent_path`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/launcher.rs#L2941-L2958) 将 `agent_home/.aegis-bin` 置于 `PATH` 首位，确保只读 `git` shim 在 macOS Seatbelt 会话中与 Linux `bwrap` 会话行为一致。

### 2.3 CLI 诊断（`aos doctor`）与会话元数据状态对齐（已修复）
- **关联代码**：
  - [crates/aos-cli/src/installer.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/installer.rs#L821-L878)
  - [crates/aos-cli/src/launcher.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/launcher.rs#L2599)
- **评审分析**：
  - `run_doctor` 输出与 `session.json` 的 `enforcement_scope` 已与实际启用的 per-session broker 和 macOS Seatbelt MVP 保持一致。

---

## 3. 代码质量与安全缺陷逐项清单

### 🔴 High（高危：安全边界与核心策略逻辑）

| 编号 | 模块与位置 | 问题描述与根因 | 状态 |
|---|---|---|---|
| **H1** | [crates/aos-sandbox/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-sandbox/src/lib.rs#L367-L390)<br>[crates/aos-cli/src/routing.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/routing.rs#L252-L263) | **macOS Seatbelt 未遮蔽 `session_dir/human.token` 等控制面凭据**：Seatbelt 原规则对整个 `agent_root` 放行读取，且 `routing.rs` 未拦截 `~/.aegis` 下的 `human.token` / `agent.token`，导致沙箱内 Agent 可读取 `human.token` 调用本地 TCP Broker 自批权限。 | ✅ **已修复**：Seatbelt 改为 `(deny file-read-data (subpath "{runtime}"))` 并仅放行 `{ws}`、`{home}`、`{shared_ro}`、`{org_pub}`、`{org_paas}`；`RUNTIME_STATE_MARKERS` 已加入 `/.aegis/`、`/human.token`、`/agent.token`。 |
| **H2** | [crates/aos-policy/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-policy/src/lib.rs#L964-L972)<br>[crates/aos-policy/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-policy/src/lib.rs#L1046-L1052) | **A2A 任务上下文中「Approve Once (`ttl_secs = 0`)」退化为 15 分钟多次有效租约**：`approve_escalation` 中 `if task_id.is_some()` 排在 `if is_oneshot` 之前，导致生成 `LeaseKind::TaskScoped` 而非 `LeaseKind::OneShot`，单次审批后不会被 `check_active_lease` 消费移除。 | ✅ **已修复**：`if is_oneshot { LeaseKind::OneShot }` 优先于 `task_id.is_some()`，并新增回归测试 `one_shot_wins_over_task_scope_and_approved_ticket_cannot_be_reused`。 |
| **H3** | [crates/aos-policy/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-policy/src/lib.rs#L917-L926)<br>[crates/aos-policy/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-policy/src/lib.rs#L1111-L1117) | **已审批（`Approved`）票据可重复调用 `approve_escalation` 续签租约**：原逻辑仅检查 `Denied` / `Expired`，未要求 `status == EscalationStatus::Pending`；`deny_escalation` 也未校验当前状态。 | ✅ **已修复**：`approve_escalation` 与 `deny_escalation` 均强制校验 `item.status == EscalationStatus::Pending`。 |
| **H4** | [crates/aos-core/src/claims.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-core/src/claims.rs#L313-L345)<br>[crates/aos-mcp-gateway/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-mcp-gateway/src/lib.rs#L741)<br>[crates/aos-cli/src/coord.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/coord.rs#L70-L76) | **共享读锁（`ClaimMode::Read`）内部键分隔符 `\u{1f}<owner>` 泄漏与冲突检测问题**：`release_claims_for_task`、`release_claims_matching_paths`、`coord_release` 及 `compute_radar_delta` 直接使用原始 Map Key 而未调用 `claim_glob()`。 | ✅ **已修复**：全部释放、广播与 Radar 路径均通过 `claim_glob()` 剥离 `\u{1f}<owner>` 后缀，并新增单元测试 `read_claim_keys_are_stripped_from_release_and_overlap_paths`。 |
| **H5** | [crates/aos-cli/src/routing.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/routing.rs#L435-L452) | **新增顶层审批命令未被 `invokes_approval_cli` 拦截**：`aegis-os commit --yes`、`aegis-os approvals approve/deny/serve` 可绕过 `PreToolUse` Shell 路由拦截。 | ✅ **已修复**：`invokes_approval_cli` 已拦截顶层 `commit` 及 `approvals approve|deny|serve`。 |

---

### 🟡 Medium（中危：工具链兼容、Hook 协议与 L7 代理）

| 编号 | 模块与位置 | 问题描述与根因 | 状态 |
|---|---|---|---|
| **M1** | [crates/aos-core/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-core/src/lib.rs#L1135) | **`#[allow(clippy::chunks_exact_to_as_chunks)]` 导致低版本 Rust 编译器 `cargo clippy -- -D warnings` 报错退出**：缺少 `#[allow(unknown_lints)]`。 | ✅ **已修复**：已改为 `#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]`。 |
| **M2** | [crates/aos-cli/src/hooks.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/hooks.rs#L12-L22) | **Hook 拦截响应格式在 AGY 与 Claude Code 间不统一**：Broker 路径仅输出 `hookSpecificOutput`（AGY 不识别），而本地策略拦截仅输出顶层 `decision`（Claude Code 不识别）。 | ✅ **已修复**：统一封装 [`hook_decision(effect, reason)`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/hooks.rs#L12-L22)，同时输出顶层 `decision`/`reason` 与 `hookSpecificOutput`。 |
| **M3** | [crates/aos-cli/src/hooks.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/hooks.rs#L397-L403) | **`SessionStart` 去重守卫 `once_guard` 失效**：原键包含 `std::process::id() / 2`（每次 Hook 子进程 PID 不同），且忽略了 `once_guard` 返回的 `bool`。 | ✅ **已修复**：改为 `format!("SessionStart:{conv_tag}")` 并在返回 `false` 时立即提前返回。 |
| **M4** | [crates/aos-egress/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-egress/src/lib.rs#L299-L410)<br>[crates/aos-egress/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-egress/src/lib.rs#L1059-L1072) | **Gemini L7 边界密钥注入与上游响应流式转发**：Gemini SDK 常通过 URL Query `?key=...` 传递 API Key，原逻辑仅替换 Header；同时上游响应存在全量内存缓冲。 | ✅ **已修复**：已支持 URL Path/Query 中的 `$AOS_SECRET_GEMINI_API_KEY` 边界注入，并在 [`forward_reverse_proxy`](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-egress/src/lib.rs#L401-L408) 与 HTTP 转发路径中统一采用 `8 KiB` 分块流式转发。 |

---

### 🟢 Low（低危：状态整洁度与插件鲁棒性）

| 编号 | 模块与位置 | 问题描述与根因 | 状态 |
|---|---|---|---|
| **L1** | [crates/aos-policy/src/lib.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-policy/src/lib.rs#L985-L1028) | **批量敏感路径审批残留未消费的组合租约**：`workspace_commit_sensitive` 含多个文件时，既插入了 `"a, b#sha256:..."` 组合租约又插入了单文件租约，组合租约永不被消费。 | ✅ **已修复**：当 `parts.len() > 1` 时仅插入拆分后的单文件租约。 |
| **L2** | [plugins/opencode-aegis.js](file:///Users/huizhao/Downloads/workspace/aegis-os/plugins/opencode-aegis.js#L25-L39)<br>[plugins/opencode-aegis.js](file:///Users/huizhao/Downloads/workspace/aegis-os/plugins/opencode-aegis.js#L87)<br>[crates/aos-cli/src/session_broker.rs](file:///Users/huizhao/Downloads/workspace/aegis-os/crates/aos-cli/src/session_broker.rs#L99-L103) | **Node.js Socket UTF-8 跨分片解码与 macOS `SUN_LEN` Unix Socket 路径长度边界**：逐 chunk `.toString("utf8")` 在多字节字符跨包时会产生乱码；深层 `TMPDIR` 下 `control.sock` 超过 macOS 104 字节 `SUN_LEN` 限制。 | ✅ **已修复**：改为 `Buffer.concat(chunks).toString("utf8")`；`SessionBroker::start` 在路径超长时自动回退短名 `c.s`。 |
