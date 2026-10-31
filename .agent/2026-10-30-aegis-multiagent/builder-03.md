# Builder-03 — Task Board (#4) + Task-Scoped Lease (#5)

日期：2026-10-31
范围：`product.md` #4（Task Board）与 #5（task-scoped lease）
状态：代码完成，测试通过，未 commit / push

## 1. Task Board（#4）

### CLI

新增：

```bash
aegis-os a2a board [--all] [--json]
aegis-os a2a show <task-id> [--json]
```

- `board` 读取 `runtime_dir/ipc_state.json`，按当前 `--org` 过滤
- 默认隐藏 24h 前的终态任务；`--all` 显示全部
- `input-required` 置顶并标记 `BLOCKED`
- `stale` 任务标记 `STALE`
- `--json` 输出 `{ "tasks": [...] }`
- `show` 显示 task 元数据、history、artifacts；跨 org 返回 not found

### 测试

手工验证：

```bash
aegis-os --org repo --runtime-dir /tmp/aos-a2a-board a2a board
aegis-os --org repo --runtime-dir /tmp/aos-a2a-board a2a board --json
aegis-os --org repo --runtime-dir /tmp/aos-a2a-board a2a show msg-1
```

## 2. Task-Scoped Lease（#5）

### 数据模型

`crates/aos-core/src/lib.rs`：

- `LeaseKind`：`ttl | one_shot | task_scoped`
- `LeaseGrant.kind` + `LeaseGrant.task_id`
- `PendingEscalation.task_id`
- 旧 `policy_state.json` 通过 `serde(default)` 无损加载

### 策略层

`crates/aos-policy/src/lib.rs`：

- `record_escalation` 从 `ctx.metadata["task_id"]` 继承 task_id
- `approve_escalation`：
  - 有 task_id → `LeaseKind::TaskScoped`
  - `ttl_secs <= 0` → `LeaseKind::OneShot`
  - 否则 → `LeaseKind::Ttl`
- `check_active_lease`：
  - `task_scoped` 必须匹配 `ctx.metadata["task_id"]`
  - `one_shot` 首次命中后删除
  - 旧 `expires_at_ms == -1` 自动按 one-shot 处理
- `revoke_leases_for_task(task_id)`：任务终态时删除绑定 lease

### Gateway

`crates/aos-mcp-gateway/src/lib.rs`：

- `policy_grant_lease` 支持 `task_id`
- `workspace_commit` schema 增加可选 `task_id`
- `ipc_task_update` / `ipc_reply` / `tasks/cancel` 在任务进入终态后调用 `revoke_leases_for_task`
- `ipc_task_update` 的 args 中已有 `task_id`，会进入 policy metadata

### CLI

```bash
aegis-os policy lease --action-pattern workspace_commit --ttl-secs 60 --task-id msg-1
```

输出 lease 包含 `kind: "task_scoped"` 和 `task_id`。

## 3. 验证

```bash
cargo test -p aos-policy
# 7 passed

cargo test -p aos-ipc
# 15 passed

cargo test -p aos-mcp-gateway
# 26 passed

cargo test -p aos-memory
# 10 passed

cargo check --workspace
# Finished
```

新增策略测试：

- `task_scoped_lease_requires_matching_task_id`
  - task-1 lease 只允许 task-1；task-2 / 无 task_id 返回 Ask
- `approving_task_escalation_creates_task_scoped_lease`
- `revoking_task_leases_removes_only_bound_leases`

## 4. 风险 / 未完成

1. **task_id 由工具参数提供**：gateway 目前从 `args["task_id"]` 读取；Agent 可以自填。Phase 0 接受，Phase 1 需要由 sandbox/session 注入可信 task_id。
2. **终态撤销只在 gateway 路径**：`ipc_task_update`、`ipc_reply`、`tasks/cancel` 会调用 `revoke_leases_for_task`；直接调用 `AegisIpcBus::update_task_state` 的 CLI/内部路径不会自动撤销。
3. **没有 `revision`/CAS**：多进程同时更新同一任务仍 last-writer-wins。
4. **没有 operator 身份**：board 是只读的，不需要；未来协调者服务需要。
5. **未做真实 8 进程 × 100 任务 / kill -9 测试**。
6. **`workspace_commit` 的 task_id 仍是可选参数**，不会自动从当前 A2A task 推导。
7. **未 commit / push**。

## 5. 下一步

1. critic 复审 #4/#5。
2. 补 `revision`/CAS + operator 身份。
3. 补真实多进程压测 + kill -9。
4. 进入 #6/#7：UOMP consent 绑定 task_id、撤销传播。
