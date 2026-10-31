# Review — Builder-01（A2A 跨租户 / actor 隔离）

日期：2026-10-30
审查者：Critic（独立复审）+ Conductor 复核
上游：`builder-01.md`、`review.md` P0-1/P0-2/P2-6
状态：**有条件通过**；P0 已修，允许进入 #2/#3

---

## 结论

Builder-01 的方向正确：`A2ATask` 参与者模型、`update_task_state` 的 participant/requester 校验、`tasks/get|cancel|list` 与 `/api/status` 的 org 收窄都已落地，且新增了跨 org 回归测试。

Critic 提出的 P0 `/api/status` `default-org` 旁路是真实问题，已在当前工作树修复并加测试。其余 P1/P2 中，`list_tasks` 的“跨 org requester 看不到自己任务”经复核不成立：`list_tasks` 已经用 `from_agent.starts_with("{org}/")` / `to_agent.starts_with("{org}/")` 过滤，requester org 能命中。

**Gate：通过。** 可以进入 #2（状态机全量）与 #3（持久化原子写/锁）；P2 测试补齐随 #2 一起做。

---

## P0（已修复）

### P0-1 `/api/status` 的 `default-org` 租户可放大到 `*`

- **原问题**：`crates/aos-mcp-gateway/src/lib.rs` 中，`org_id == "default-org"` 且请求不带 `org_id` 时，`query_org` 被置为 `*`；虽然 `a2a_tasks` 已单独保护，但 `peers`、`global_peers`、`secrets`、`escalations`、`leases`、`workspaces`、`api_keys`、`tenants` 仍按 `*` 返回。
- **修复**：引入 `effective_org`：
  - 只有 `is_operator || auth_mode == DaemonAuth::Disabled` 可以使用 `requested_scope`（含 `*`）
  - tenant key 始终固定为自己的 `org_id`
  - tenant 的 `global_peers` 返回空数组
- **回归测试**：`a2a_tasks_are_org_scoped_across_http_and_status` 新增 `default-org` key 无参数 `/api/status` 断言：`org_id == "default-org"`，看不到 org-b 的 task/peer，`global_peers` 为空。
- **验证**：`cargo test -p aos-mcp-gateway` 26 passed。

---

## P1（评估后不阻塞）

### P1-1 `list_tasks` 跨 org requester 可见性

Critic 认为 `tasks/list` 只传 identity org，导致跨 org requester 看不到自己发起的 task。复核代码：

```rust
let org_ok = org_id.map_or(true, |o| {
    t.org_id == o
        || t.from_agent.starts_with(&format!("{}/", o))
        || t.to_agent.starts_with(&format!("{}/", o))
});
```

requester org 会通过 `from_agent` 前缀命中，因此该问题不成立。`visible_to_org` 与 `list_tasks` 语义一致；无需修改。

### P1-2 `tasks/cancel` 差异化错误消息

- 跨 org / 非参与者：IPC 层统一 `A2A task '<id>' not found`，不泄露存在性。
- 同 org 的 assignee：收到 “Only the requester may cancel...”，这是参与者可见的角色信息，不是跨租户泄露。
- 结论：可接受；如果未来要求“所有非授权方不可区分”，再把 assignee 的 cancel 拒绝改为通用文案。

### P1-3 `ipc_task_list scope=all` breaking change

- 运行时已拒绝 `scope=all`；schema enum 改为 `["org"]`。
- CLI `main.rs:3765` 是 in-process `list_tasks(None, None)`，不受 gateway 约束；dashboard 未发现调用 `ipc_task_list`；`aegis://a2a/tasks` 走默认 `org`。
- 外部 MCP 客户端硬编码 `scope=all` 会从“拿到全量”变成“报错”。建议后续改为“降级为 org”而不是直接 bail；Phase 0 可接受。

---

## P2（随 #2/#3 补）

1. **`ipc_task_get` 与 `tasks/get` 错误形态不一致**：前者是 MCP 工具错误，后者是 `-32004`。建议统一为 `-32004` 语义，或至少在文档写清。
2. **测试缺口**：
   - legacy 裸 agent id 的 `requester()`/`assignee()` 回退
   - 终态自转移（completed→completed）是否允许
   - 跨 org requester 经 gateway + policy 的端到端
   - `aegis://a2a/tasks` resource 的 org 过滤
3. **agent id 含 `/`**：`split_once('/')` 会把 `a/b/c` 解析为 `org=a, agent=b/c`；需确认 agent id 是否允许 `/`。若允许，改用 `rsplit_once` 或显式编码。
4. **`/api/status` 的 `global_peers`**：tenant 已返回空；operator 仍全量，符合预期。

---

## P3

- `A2ATask::visible_to_org` 与 `list_tasks` 的过滤逻辑重复；建议后续抽成 `task_visible_to(task, org, agent)`，避免漂移。
- `input-required` 通知仍手写 `split_once('/')`；建议复用 `requester()`。
- `ipc_task_list` 的 `scope=all` 拒绝信息可以更友好，提示“operator-only, use scope=org”。

---

## 验证记录（Conductor）

```bash
cargo test -p aos-ipc
# 8 passed; 0 failed

cargo test -p aos-mcp-gateway
# 26 passed; 0 failed

cargo check --workspace
# Finished dev profile
```

> Critic 原始复审因步数限制未能运行 shell；以上结果由 conductor 在当前工作树执行。Critic 的 P0 已修复；P1-1 经复核不成立；其余 P2/P3 已记录。

---

## Gate 决定

**通过。** 允许进入：

1. **#2 状态机全量**：合法转移表、`failure_kind`、终态自转移策略、`canceled` 仅 requester（已完成）。
2. **#3 持久化原子写/锁**：`ipc_state.json` 单写者/文件锁/原子替换、kill -9 恢复、stale 任务清理。

#2 与 #3 可以并行，但都必须基于当前 slice 的 participant/org 模型；不要再引入第二套可见性判断。
