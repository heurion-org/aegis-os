# Dogfood-02 — Gateway `/v1/a2a` 终态 → memory 撤销

日期：2026-10-31
环境：memory server 9481 + Aegis daemon 9482 + 临时 HOME/runtime/workspace
状态：完成，端到端通过

## 1. 场景

```text
memory server: 127.0.0.1:9481  (AOS_MEMORY_TASK_SECRET=dogfood-secret)
Aegis daemon:  127.0.0.1:9482  (--insecure-no-auth, same runtime)
task:          msg-de87a4a4
agent:         dogfood/planner
```

步骤：

1. `aegis-os ipc request` 创建 A2A task
2. `memory mcp` + `UOMP_TASK_ID=msg-de87a4a4` 发起 consent
3. `memory pending` / `approve`
4. MCP 读取成功
5. 通过 daemon `POST /v1/a2a` 调 `tasks/cancel`
6. 验证 task `canceled` + memory session `revoked`
7. 验证 audit 事件带 task_id

## 2. 结果

### Gateway cancel

```json
{
  "jsonrpc": "2.0",
  "result": {
    "id": "msg-de87a4a4",
    "state": "canceled",
    "history": [
      { "state": "submitted", "actor": "dogfood/planner" },
      { "state": "canceled", "actor": "dogfood/planner" }
    ]
  }
}
```

### Memory session

```text
sess-94199d2e-11eb-4422-8ef6-7f9518fc24e4  revoked
```

### Audit

```json
{
  "action": "revoke",
  "reason": "A2A task msg-de87a4a4 reached a terminal state",
  "task_id": "msg-de87a4a4"
}
```

### Board

```text
msg-de87a4a4  canceled  dogfood/planner -> dogfood/worker  Gateway dogfood task
```

## 3. 新增自动化测试

### Gateway 端到端

`a2a_cancel_revokes_memory_sessions_end_to_end`：

- 启动 mock memory server
- 创建 A2A task
- 启动 gateway daemon
- `tasks/cancel`
- 断言 mock 收到 `POST /v1/sessions/revoke-by-task`
- 断言 `x-aegis-task-token: msg-...`
- 断言 task `canceled`

### Consent 过期

`expired_consent_is_marked_expired_and_not_approvable`：

- 创建 consent
- 手动把 `expires_at` 改为过去
- `expire_pending_consents`
- 断言 status=`expired`
- 断言 `approve_consent` 返回 false

## 4. 验证

```bash
cargo test -p aos-mcp-gateway     # 28 passed
cargo test -p aos-memory-server   # 3 passed
cargo test -p aos-ipc             # 17 passed
cargo test -p aos-cli             # 16 passed
cargo check --workspace           # Finished
```

## 5. 结论

Phase 0 的最后两个未覆盖项已补齐：

- task 终态 → memory session 撤销（gateway 真实路径）
- consent 过期状态

剩余是生产化/Phase 1：

1. 真实 design partner
2. 多 active task 的显式 `AOS_TASK_ID`
3. 远程 A2A / Aegis Cloud
4. 团队审计/策略
5. 磁盘满 / NFS / 更大规模压测
