# Review — Builder-05（#6 Consent task_id / #7 撤销传播）

日期：2026-10-31
审查者：Conductor 复核
上游：`builder-05.md`
状态：**有条件通过**

---

## 1. 结论

- **#6**：通过。`sessions` / `consent_requests` 带 `task_id`；旧 `auth.db` 自动迁移；`memory pending` 显示 task；bridge 从 `UOMP_TASK_ID` 读取。
- **#7**：有条件通过。
  - task 终态 ⇒ `POST /v1/sessions/revoke-by-task`（需 `AOS_MEMORY_URL` + `AOS_MEMORY_BRIDGE_TOKEN`）
  - session revoke ⇒ CLI 读取响应 `task_id`，调用 `request_task_input`
- **验证**：memory-server 1、ipc 17、gateway 26、policy 7、cli 16、`cargo check --workspace` 通过。

---

## 2. P0

无新增 P0。

---

## 3. P1

### P1-1 task→session 撤销依赖共享 bridge token

- Gateway 使用 `AOS_MEMORY_BRIDGE_TOKEN` 调用 `revoke-by-task`。
- 这是用户级/本机共享凭证，不是 task-scoped 凭证。
- 影响：如果 bridge token 泄露，持有者可以撤销任意 task 的 sessions。
- 建议：Phase 1 改为 Aegis 签发的 task-scoped revoke token，memory server 校验 `task_id` 绑定。

### P1-2 session→task 只覆盖 CLI `memory revoke`

- 直接调用 `POST /v1/sessions/:id/revoke`（脚本、未来 UI）不会通知 Aegis。
- 影响：撤销 session 后，task 仍显示 working，直到超时或下次手动操作。
- 建议：memory server 增加可选 webhook/事件，或让 Aegis gateway 轮询 revoked sessions。

### P1-3 没有 audit `task_id`

- memory audit 仍只有 session/agent；task 关联靠 session。
- 影响：`audit trace <task_id>` 无法直接查 memory consent/revoke 事件。
- 建议：`audit_logs` 加 `task_id`，写入 consent/revoke 事件时带上。

### P1-4 `revoke-by-task` 是 best-effort

- Gateway 调用失败不阻塞任务终态，也没有重试/告警。
- 影响：memory session 可能残留到 TTL。
- 建议：加一次重试 + 审计失败事件；或由 memory server 定期 sweep。

### P1-5 没有端到端 gateway 测试

- memory-server 端点有测试；gateway 的 `revoke_memory_for_task` 没有 mock/集成测试。
- 建议：用本地 mock HTTP server 验证 gateway 在 terminal task 后发出请求。

---

## 4. P2

1. `memory sessions` 不支持 `--task-id` 过滤，只显示字段。
2. `memory pending` 输出列没有 header，新增 task_id 后更容易看错。
3. `UOMP_TASK_ID` 需要外部 launcher 设置；`memory setup` 不写 task。
4. `revoke_sessions_for_task` 遍历全部 sessions，未按 task_id 建索引。
5. `request_task_input` 不发 input-required 通知给 requester（只改状态）。
6. 没有真实多进程 / kill -9 测试。
7. `AOS_MEMORY_URL`/`AOS_MEMORY_BRIDGE_TOKEN` 未写入 README 的环境变量表。

---

## 5. Gate 决定

**有条件通过。**

#6/#7 的核心链路已通：

```text
A2A task terminal
  → gateway POST /v1/sessions/revoke-by-task
  → memory sessions revoked
  → next memory call 401

memory revoke <session>
  → response.task_id
  → AegisIpcBus::request_task_input
  → task input-required
```

可以进入收尾：

1. 补 audit task_id。
2. 补 `memory sessions --task-id`。
3. 补 gateway mock 测试。
4. 真实多进程 + kill -9。
5. 分批 commit / push。

---

## 6. 最可能的失败场景

用户通过脚本/未来 UI 调 `POST /v1/sessions/:id/revoke`，session 被撤销，但 Aegis task 仍是 `working`。Agent 的 memory 调用开始 401，task 却一直显示进行中；board 的“活跃任务”与 memory session 状态不一致。需要 P1-2 的事件/轮询来消除。
