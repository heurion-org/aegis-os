# Builder-01 — A2A 跨租户 / actor 隔离

日期：2026-10-30
范围：`review.md` P0-1、P0-2 的读取/取消部分；`product.md` M10
状态：代码完成，测试通过，未 commit / push

## 改了什么

### 1. `crates/aos-core/src/lib.rs`

在 `A2ATask` 上新增只读访问器（不改结构体字段，旧 `ipc_state.json` 可无损加载）：

- `requester()` / `assignee()`：解析 `<org>/<agent>` 地址，兼容旧数据的裸 agent id（回退到 task 的 `org_id`）
- `is_requester(org, agent)` / `is_assignee(org, agent)`
- `visible_to_org(org_id)`：只有 task owner org / requester org / assignee org 可见

### 2. `crates/aos-ipc/src/lib.rs`

`update_task_state` 增加：

- 只有 requester / assignee 可以修改；其他调用者（含跨 org）统一返回 `A2A task '<id>' not found`，不泄露存在性
- `canceled` 只能由 requester 发起；assignee 放弃任务应走 `failed(reason)`
- 终态不可回退：`t.state.is_terminal() && t.state != state` 拒绝
- 未改 `IpcBus` trait 签名

### 3. `crates/aos-mcp-gateway/src/lib.rs`

- `tasks/get`：`visible_to_org` 过滤；跨 org 返回 `-32004 not found`
- `tasks/cancel`：依赖 IPC 层的 org + requester 校验；跨 org 统一 `-32004`
- `tasks/list`：只返回调用方 org 的任务
- `ipc_task_list`：默认 `scope=org`；`scope=all` 明确拒绝（operator-only）；非法 scope 拒绝；工具 schema 的 enum 改为 `["org"]`
- `ipc_task_get` / `aegis://a2a/tasks`：同样按 org 收窄
- `GET /api/status` 的 `a2a_tasks` / `peers` / `global_peers` / `secrets` / `escalations` / `leases` / `workspaces` / `api_keys` / `tenants`：
  - 引入 `effective_org`：只有 operator 或 `DaemonAuth::Disabled` 可以使用 `requested_scope`（含 `*`）；tenant key 始终固定为自己的 `org_id`
  - 修复 `default-org` 租户在无 `org_id` 参数时被映射为 `*` 的旁路
  - tenant 的 `global_peers` 返回空数组，不再泄露 workstation 全量 peer

## 测试

新增：

- `crates/aos-ipc/src/lib.rs`：`a2a_task_mutation_requires_participant_and_requester_cancel`
  - 跨 org 非参与者不能改任务，错误为 not found
  - 跨 org requester 可以推进任务（保留现有 A2A 跨 org handoff）
  - assignee 不能 cancel
  - requester 可以 cancel
  - 终态不可回退
- `crates/aos-mcp-gateway/src/lib.rs`：`a2a_tasks_are_org_scoped_across_http_and_status`
  - org B 的 task 对 org A key 不可读，错误码与未知 task 一致
  - `tasks/list` 按 org 过滤
  - `/api/status` 的 `a2a_tasks` 按 org 过滤
  - `default-org` 租户无参数 `/api/status` 不会看到 org B 的 task/peer，`global_peers` 为空
  - org A 不能 cancel org B 的 task，状态不变

命令与结果：

```bash
cargo test -p aos-ipc
# 8 passed; 0 failed

cargo test -p aos-mcp-gateway
# 26 passed; 0 failed（含 default-org 旁路回归）

cargo check --workspace
# Finished dev profile
```

## 未覆盖 / 风险

1. **同 org 内 agent 级可见性**：当前只做 org 级。同 org 任意 agent 仍可读同 org 其他 agent 的 task。Phase 0 按 M10 的 org 口径接受；agent 级可见性建议 Phase 0.5/Phase 1。
2. **`ipc_task_list scope=all` 行为变化**：之前默认 `all`，现在默认 `org`，显式 `all` 被拒。CLI 的 `main.rs:3765` 是 in-process 调用，不受 gateway 约束；dashboard 未发现调用 `ipc_task_list`；外部 MCP 客户端硬编码 `scope=all` 会报错。建议后续改为“降级为 org”而不是直接 bail。
3. **`ipc_task_update` 同 org 非参与者现在被拒**：如果有 CLI/board 用“任意 agent 更新任意任务”，会受影响；现有测试未覆盖该用法。
4. **未做 #2 全量状态机**：只加了“终态不可回退 + canceled 仅 requester”，合法转移表（submitted→working→...）仍未完整实现。
5. **未做 #3 持久化**：`ipc_state.json` 仍是整文件读写，无锁/原子替换。
6. **未做 #5 task-scoped lease**：`LeaseGrant` 仍无 `task_id`。
7. **未做 A2A v1.0**：Phase 0 按用户决策保持 0.2.x 兼容层；AgentCard 的 `protocolVersion`/`protocol` 字段一致性仍待修（#9）。
8. **未 commit / push**：等待 critic 复审后再进入下一 slice。

## 下一步建议

1. critic 复审本 slice，重点看：
   - 跨 org requester 仍可推进任务是否符合产品预期
   - `ipc_task_list scope=all` 的行为变化是否破坏现有 CLI/dashboard
   - `/api/status` 的 operator/tenant 分支是否有绕过
2. 复审通过后进入 #2（状态机全量）与 #3（持久化原子写/锁）。
3. 在 #4 之前先定义 `aegis-os a2a board` 的 CLI 契约，避免 board 依赖 `scope=all`。
