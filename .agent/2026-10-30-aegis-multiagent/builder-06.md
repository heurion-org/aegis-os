# Builder-06 — Consent/Revocation 收尾

日期：2026-10-31
范围：review-builder-05 的 P1/P2 收尾
状态：代码完成，测试通过，未 commit / push

## 1. Audit `task_id`

- `audit_logs.task_id` 新增列
- 旧 `auth.db` 自动 `ALTER TABLE`
- `AuthStore::log_audit` 通过 `(SELECT task_id FROM sessions WHERE session_id = ?)` 自动写入
- `list_audit` 返回 `task_id`
- 测试断言 consent allow 事件带 `task_id=task-consent-1`

## 2. `memory sessions --task-id`

```bash
aegis-os memory sessions --task-id task-1
```

- 仍然调用 `GET /v1/sessions`
- 客户端按 `task_id` 过滤
- 输出保持 `{ "sessions": [...] }`

## 3. Task-scoped revoke token

替代共享 bridge token 的首选路径：

- 共享密钥：`AOS_MEMORY_TASK_SECRET`（gateway + memory server 配置同一个值）
- Gateway 生成：
  `task_id:timestamp:hex(HMAC-SHA256(secret, "task_id:timestamp"))`
- Header：`x-aegis-task-token`
- Memory server 校验：
  - task_id 必须匹配 body
  - timestamp 120 秒内
  - HMAC 常量时间比较
- 未配置 secret 时，仍允许 `x-uomp-bridge-token` 作为 legacy fallback

## 4. Gateway mock test

新增 `terminal_task_sends_task_scoped_memory_revoke`：

- 本地 mock TCP server
- 断言 `POST /v1/sessions/revoke-by-task`
- 断言 `x-aegis-task-token: task-1:...`
- 返回 200 后测试结束

## 5. 验证

```bash
cargo test -p aos-memory-server  # 2 passed (lib + integration)
cargo test -p aos-ipc             # 17 passed
cargo test -p aos-mcp-gateway     # 27 passed
cargo test -p aos-policy          # 7 passed
cargo test -p aos-memory          # 10 passed
cargo test -p aos-cli             # 16 passed
cargo check --workspace           # Finished
```

## 6. 仍未完成

1. **真实 8 进程 × 100 任务 / kill -9 测试**：仍是同进程并发测试。
2. **Session revoke → task input-required 只覆盖 CLI `memory revoke`**：直接 API revoke 不通知 Aegis。
3. **`revoke-by-task` 仍是 best-effort**：失败不阻塞终态、无重试。
4. **多 active task 时 task context 不注入**：安全默认，但可用性受限。
5. **未 commit / push**。
