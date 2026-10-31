# Review — Builder-03（Task Board #4 / Task-Scoped Lease #5）

日期：2026-10-31
审查者：Conductor 复核（Critic 环境受限）
上游：`builder-03.md`
状态：**有条件通过**；#4 可用，#5 核心模型可用，但 task_id 可信注入与终态撤销覆盖面仍需加固

---

## 1. 结论

- **#4 Task Board**：通过。`aegis-os a2a board/show` 可读、可 JSON、可显示 blocked/stale/terminal；跨 org 返回 not found。
- **#5 Task-Scoped Lease**：有条件通过。`LeaseKind`、`task_id`、匹配、审批继承、终态撤销、CLI `policy lease --task-id` 都已落地；策略测试覆盖 task-1/task-2/no-task 与撤销。
- **未 commit / push**。

验证：

```bash
cargo test -p aos-policy          # 7 passed
cargo test -p aos-ipc             # 15 passed
cargo test -p aos-mcp-gateway     # 26 passed
cargo test -p aos-memory          # 10 passed
cargo check --workspace           # Finished
```

手工：

```bash
aegis-os --org repo --runtime-dir /tmp/aos-a2a-board a2a board
aegis-os --org repo --runtime-dir /tmp/aos-a2a-board a2a show msg-1
aegis-os --org repo --agent planner --runtime-dir /tmp/aos-a2a-board \
  policy lease --action-pattern workspace_commit --ttl-secs 60 --task-id msg-1
```

---

## 2. P0

无新增 P0。

---

## 3. P1（发布前建议修）

### P1-1 task_id 仍由工具参数提供

- `policy_grant_lease`、`workspace_commit`、`ipc_task_update` 的 `task_id` 来自 `args`；Agent 可以自填。
- 反例：Agent 持有 task A 的 task-scoped lease，却在执行 task B 时传 `task_id=A`，lease 会匹配。
- 影响：task-scoped 的“任务边界”目前是**声明式**，不是**可信注入**。
- 建议：Phase 1 由 sandbox/session 注入 `AOS_TASK_ID`，gateway 只从可信上下文读取，不接受 Agent 自填；或把 task_id 写进 agent 的短期 capability handle。

### P1-2 终态撤销只覆盖 gateway 路径

- `ipc_task_update`、`ipc_reply`、`tasks/cancel` 会调用 `revoke_leases_for_task`。
- 直接调用 `AegisIpcBus::update_task_state` 的 CLI/内部路径不会自动撤销。
- 影响：如果未来有 daemon/CLI 直接改任务状态，task-scoped lease 可能残留到 TTL。
- 建议：把“任务终态 ⇒ 撤销 task lease”做成 IPC/Policy 的订阅事件，而不是在 gateway 每个 handler 手写。

### P1-3 没有 `revision`/CAS

- 多进程同时更新同一任务仍 last-writer-wins。
- #5 的 task-scoped lease 依赖任务状态判定；没有版本号时，lease 释放与任务终态可能竞争。
- 建议：#6 前补 `A2ATask.revision` + `expected_revision`。

### P1-4 `workspace_commit` 的 task_id 不会自动推导

- 目前必须显式传 `task_id`；Agent 很容易忘记，导致 task-scoped lease 不匹配。
- 建议：从 agent 当前 task context（P1-1 的可信注入）自动填充。

---

## 4. P2（可排期）

1. `a2a board` 没有 workspace_id 列（#1 的 task 模型字段尚未加）。
2. `a2a show` 的 history 时间戳是原始 ms，未格式化。
3. `a2a board` 的 `stale` 由 `list_tasks` 自动 sweep；只读命令会写状态文件，需要文档说明。
4. `LeaseKind` 的旧 `expires_at_ms == -1` 兼容逻辑保留；新代码应只写 `kind`。
5. `policy_grant_lease` 的 tool schema 未显式列出 `task_id`（如果存在独立 schema）。
6. 没有 gateway 级“终态撤销”回归测试；当前只有 policy 层测试。
7. 没有真实 8 进程 × 100 任务 / kill -9 测试。

---

## 5. Gate 决定

**有条件通过。**

- **#4**：可以进入 dogfood；board 只读，不依赖 CAS。
- **#5**：核心模型可用，但进入 #6/#7 前建议先补：
  1. 可信 task_id 注入（P1-1）
  2. 终态撤销事件化（P1-2）
  3. `revision`/CAS（P1-3）
- **#6/#7**：consent 绑定 task_id 与撤销传播可以开始设计，但实现应等 P1-1/P1-2 明确。

---

## 6. 最可能的失败场景

Agent 持有 task A 的 task-scoped lease，执行 task B 时把 `task_id` 填成 A。Policy 看到 `lease.task_id == ctx.task_id == A`，允许 `workspace_commit`；board/audit 却把这次操作记在 task B 的上下文中（或反之）。用户以为 task A 已结束、lease 已撤销，实际 task B 在用 A 的授权。

这不是协议层能解决的，必须由运行时注入可信 task_id，并把 task 终态撤销做成不可绕过的事件。
