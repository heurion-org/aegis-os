# Review — Builder-04（Revision/CAS + Trusted Task Context）

日期：2026-10-31
审查者：Conductor 复核
上游：`builder-04.md`
状态：**有条件通过**；#5 的两个 P1 已补，允许进入 #6/#7

---

## 1. 结论

- **Revision/CAS**：通过。`A2ATask.revision` 单调递增；`update_task_state_cas` 在锁内比较；`ipc_task_update` / `tasks/cancel` 支持 `expected_revision`；CLI `a2a show` 显示 revision。
- **可信 task context**：有条件通过。`authorize_and_audit` 从 active task 注入 `metadata.task_id`，覆盖 agent 自填；`ipc_task_update` 增加 target/active 一致性校验。
- **验证**：`aos-ipc` 16 passed；`aos-mcp-gateway` 26 passed；`aos-policy` 7 passed；`aos-memory` 10 passed；`aos-cli` 16 passed；`cargo check --workspace` 通过。

---

## 2. P0

无新增 P0。

---

## 3. P1

### P1-1 active_task_id 的“恰好一个”假设

- 多 Agent 并行时，一个 agent 可能同时有多个 active task；此时不注入 task_id，task-scoped lease 不会匹配。
- 这是安全默认（宁可不匹配，也不猜），但产品上会导致“多任务并行时 task-scoped lease 不可用”。
- 建议：Phase 1 引入显式 task context（`AOS_TASK_ID` 由 launcher/sandbox 注入），不再依赖“恰好一个”。

### P1-2 终态撤销仍只在 gateway 路径

- `ipc_task_update` / `ipc_reply` / `tasks/cancel` 会撤销 task-scoped lease；直接调用 `AegisIpcBus::update_task_state` 的路径不会。
- 建议：把终态撤销做成 IPC/Policy 事件，或给 `AegisIpcBus` 注入 policy hook。

### P1-3 默认 CAS 实现忽略 expected_revision

- `IpcBus::update_task_state_cas` 默认实现直接调用 `update_task_state`，忽略 expected。
- 当前只有 `AegisIpcBus` 实现；未来新增实现必须覆盖，否则 CAS 静默失效。
- 建议：默认实现改为 `bail!("CAS not supported")`，强制实现者覆盖。

### P1-4 没有 operator 身份

- `ipc_task_update` 要求 target == active task；operator/协调者没有 active task，会被限制。
- 建议：引入显式 `operator:<id>` 身份，允许跨 task 操作并审计。

---

## 4. P2

1. `active_task_id` 每次 tool call 都 `list_tasks`，有额外锁/IO 开销；可缓存或按 task 上下文注入。
2. `a2a board` 未显示 revision；`show` 已显示。
3. `tasks/cancel` 的 `expected_revision` 没有 schema/文档；A2A 0.2.x 客户端未必知道。
4. 没有真实 8 进程 × 100 任务 / kill -9 测试。
5. 没有 gateway 级 CAS 回归测试（目前只有 IPC 层）。
6. `workspace_commit` 的 task_id 仍可被 args 影响，但 policy 会用 active task 覆盖；handler 本身不校验。

---

## 5. Gate 决定

**有条件通过。**

允许进入 **#6/#7**：

- #6：`consent_requests.task_id` / `sessions.task_id`、`memory pending` 显示 task 上下文。
- #7：cancel task ⇒ revoke memory session；revoke session ⇒ task input-required。

但 #6/#7 前建议先明确：

1. memory server 如何验证 task-scoped 撤销（不能用 admin token）。
2. 多 active task 时 task context 如何注入。
3. `sessions` 表加 `org_id` / `task_id` 的迁移策略。

---

## 6. 最可能的失败场景

Agent 同时有 task A、task B 两个 active task。`active_task_id` 返回 None，task-scoped lease 不匹配；Agent 以为“我已经被批准了”，实际每次 `workspace_commit` 都重新 Ask。用户看到审批弹窗反复出现，最后关掉审批或改用 `--yolo`。这不是安全漏洞，是可用性回退；需要在多任务场景下提供显式 task context。
