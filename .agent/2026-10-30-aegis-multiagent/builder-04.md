# Builder-04 — Revision/CAS + Trusted Task Context

日期：2026-10-31
范围：review-builder-03 的 P1-1（可信 task_id）与 P1-3（revision/CAS）
状态：代码完成，测试通过，未 commit / push

## 1. Revision / CAS

`crates/aos-core/src/lib.rs`：

- `A2ATask.revision: u64`（`serde(default)`，旧状态从 0 开始）
- `IpcBus::update_task_state_cas(actor, task_id, expected_revision, state, message, artifacts)`
  - 默认实现委托给 `update_task_state`（兼容其他实现）
  - `AegisIpcBus` 覆盖为真正的 CAS

`crates/aos-ipc/src/lib.rs`：

- `update_task_state_inner` 增加 `expected_revision`
  - `Some(n)` 与当前 revision 不符 → `revision conflict`
  - 真实转移 `revision += 1`
  - 同状态 no-op 不 bump
- `ack` / `reply` 真实转移也 bump revision
- `update_task_state` 保持原签名，内部 `expected_revision=None`
- `update_task_state_cas` 走同一内部实现

`crates/aos-mcp-gateway/src/lib.rs`：

- `ipc_task_update` 支持 `expected_revision`
- A2A `tasks/cancel` 支持 `params.expected_revision`
- `ipc_task_update` schema 增加 `expected_revision`

`crates/aos-cli/src/main.rs`：

- `aegis-os a2a show` 显示 `Revision`

## 2. Trusted task context

`crates/aos-mcp-gateway/src/lib.rs`：

- 新增 `active_task_id(identity)`：
  - 查询该 agent 在当前 org 的非终态、非 stale task
  - 恰好 1 个 → 作为可信 task context
  - 0 或 >1 → 不注入（避免歧义）
- `authorize_and_audit` 在调用 policy 前注入 `metadata["task_id"] = active_task_id`
  - 覆盖 agent 在 args 里自填的 task_id
  - 用于 task-scoped lease 匹配
- `ipc_task_update` 仍然使用 args 的 task_id 执行更新；policy 的 task context 来自 active task
- 如果 args.task_id 与 active task 不一致，`ipc_task_update` 直接拒绝

## 3. 测试

```bash
cargo test -p aos-ipc
# 16 passed

cargo test -p aos-mcp-gateway
# 26 passed

cargo test -p aos-policy
# 7 passed

cargo test -p aos-memory
# 10 passed

cargo test -p aos-cli
# 16 passed

cargo check --workspace
# Finished
```

新增测试：

- `task_revision_cas_rejects_stale_update`
  - revision 0 → ack 后 1
  - CAS(0) 失败
  - CAS(1) 成功，revision 2

## 4. 风险 / 未完成

1. **active_task_id 依赖“恰好一个 active task”**：多任务并行时不会注入 task_id，task-scoped lease 不会匹配；这是安全默认，但需要产品层决定多任务策略。
2. **`ipc_task_update` 的 target task 与 active task 已加一致性校验**：不一致直接拒绝；多 active task 时 active_task_id 为 None，不注入。
3. **默认 CAS 实现忽略 expected_revision**：当前只有 `AegisIpcBus` 实现，后续新增实现必须覆盖。
4. **没有 operator 身份**。
5. **没有真实 8 进程 × 100 任务 / kill -9 测试**。
6. **未做 #6/#7**：UOMP consent 绑定 task_id、撤销传播。
7. **未 commit / push**。

## 5. 下一步

1. 加一致性校验：`ipc_task_update` 的 task_id 必须等于 active task（或显式 operator）。
2. #6：`consent_requests.task_id` / `sessions.task_id`，`memory pending` 显示 task 上下文。
3. #7：cancel task ⇒ revoke memory session；revoke session ⇒ task input-required。
