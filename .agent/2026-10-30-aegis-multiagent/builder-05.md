# Builder-05 — UOMP Consent ↔ A2A Task (#6) + Revocation Propagation (#7)

日期：2026-10-31
范围：`product.md` #6（consent 绑定 task_id）与 #7（撤销传播）
状态：代码完成，测试通过，未 commit / push

## 1. #6 Consent 绑定 task_id

`crates/aos-memory-server/src/auth_store.rs`：

- `Session.task_id: Option<String>`
- `ConsentRequest.task_id: Option<String>`
- `sessions` / `consent_requests` 新增 `task_id` 列
- `ensure_column()` 兼容旧 `auth.db`（自动 `ALTER TABLE`）
- `create_session(..., task_id)`；`create_consent` 从 session 继承 task_id
- `list_sessions` / `get_session` / `list_consent` 返回 task_id

`crates/aos-memory-server/src/server.rs`：

- `POST /v1/sessions` 接受 `task_id`
- `POST /v1/consent/requests` 接受 `task_id`
- `revoke_session` 响应返回 `task_id`
- 新增 `POST /v1/sessions/revoke-by-task`（bridge token 鉴权）

`crates/aos-cli/src/main.rs`：

- `BridgeSettings.task_id`
- `UOMP_TASK_ID`（env 或 bridge file）随 consent request 发送
- `memory pending` 显示 task_id

## 2. #7 撤销传播

### Task 终态 ⇒ 撤销 memory sessions

`crates/aos-mcp-gateway/src/lib.rs`：

- `AegisRuntimeKernel` 新增 `memory_url` / `memory_bridge_token`
- 从 `AOS_MEMORY_URL` / `AOS_MEMORY_BRIDGE_TOKEN` 读取
- `revoke_memory_for_task(task_id)` 调用
  `POST {AOS_MEMORY_URL}/v1/sessions/revoke-by-task`
- 在 `ipc_task_update` / `ipc_reply` / `tasks/cancel` 终态后调用

### Session 撤销 ⇒ Task input-required

`crates/aos-ipc/src/lib.rs`：

- `AegisIpcBus::request_task_input(task_id, reason)`：
  - 非终态、非 input-required 才生效
  - `state = input-required`
  - `revision += 1`
  - history actor `system:memory`

`crates/aos-cli/src/main.rs`：

- `memory revoke <session-id>` 读取响应里的 `task_id`
- 若存在，调用 `request_task_input(task_id, "memory session revoked")`

## 3. 测试

```bash
cargo test -p aos-memory-server  # 1 passed
cargo test -p aos-ipc             # 17 passed
cargo test -p aos-mcp-gateway     # 26 passed
cargo test -p aos-policy          # 7 passed
cargo test -p aos-cli             # 16 passed
cargo check --workspace           # Finished
```

新增/扩展测试：

- `native_server_auth_consent_memory_staged_payload_audit`
  - consent request 带 `task_id`
  - `GET /v1/sessions` 显示 task_id
  - `POST /v1/sessions/revoke-by-task` 返回 count=1
  - 撤销后 consent token 访问 memory → 401
- `memory_revoke_can_request_task_input`
  - `request_task_input` 将 task 置 `input-required`
  - history actor `system:memory`
  - 重复调用返回 false

## 4. 风险 / 未完成

1. **Gateway 需要 `AOS_MEMORY_URL` + `AOS_MEMORY_BRIDGE_TOKEN`** 才会做 task→session 撤销；未配置时是 no-op。
2. **Bridge token 是共享凭证**：Phase 0 接受；Phase 1 应改为 task-scoped revoke token。
3. **Session 撤销 → Task input-required 只覆盖 CLI `memory revoke`**；直接调用 memory-server API 不会通知 Aegis。
4. **没有 audit `task_id` 字段**：memory audit 事件仍只带 session/agent；task 关联靠 session。
5. **`memory sessions` 不支持按 task 过滤**：只显示 task_id。
6. **`revoke-by-task` 是 best-effort**：gateway 调用失败不会阻塞任务终态。
7. **没有真实多进程 / kill -9 测试**。
8. **未 commit / push**。

## 5. 下一步

1. 把 bridge token 换成 task-scoped revoke token。
2. 给 audit 增加 `task_id`。
3. `memory sessions --task-id` 过滤。
4. 真实多进程 + kill -9 测试。
5. 统一 commit / push。
