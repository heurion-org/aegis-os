# Dogfood-01 — A2A + UOMP 本地闭环

日期：2026-10-31
环境：macOS/Linux 本地，临时 HOME + 临时 runtime + 临时 workspace
状态：完成第一轮 dogfood，发现并修复 3 个问题

## 1. 场景

```text
workspace: /tmp/aos-dogfood-workspace
runtime:   /tmp/aos-dogfood-runtime
HOME:      /tmp/aos-dogfood-home
memory:    http://127.0.0.1:9481
```

步骤：

1. `memory serve` + `memory setup claude --vault`
2. `aegis-os ipc request` 创建 A2A task
3. `a2a board` / `a2a show`
4. `memory mcp` + `UOMP_TASK_ID=<task>` 发起 consent
5. `memory pending` / `approve`
6. MCP 读取记忆
7. `memory sessions --task-id`
8. `memory revoke` 反向传播
9. `a2a board` / `a2a show`
10. `memory audit`

## 2. 结果

### A2A task

```text
msg-cfb412b8  submitted  dogfood/planner -> dogfood/worker  Dogfood A2A task
```

### Consent

`memory pending` 正确显示 task_id：

```text
consent-...  claude  msg-cfb412b8  sess-...  <expires>
```

### MCP 读取

```json
{"items":[{"description":"Plan","key":"note.projects.plan","sensitivity":"low","tags":["notes","notes/projects"]}]}
```

### Session

```text
sess-...  task_id=msg-cfb412b8  status=active
```

### 反向撤销

`memory revoke` 后：

```text
msg-cfb412b8  input-required  BLOCKED
history: system:memory  memory session revoked
revision: 1
```

### Audit

consent / read / revoke 事件都带：

```json
"task_id": "msg-cfb412b8"
```

## 3. 发现并修复

### 问题 1：`ipc request` 不存在

`aegis-os ipc send` 只创建 DirectMessage，不能创建 A2A TaskRequest。

修复：

```bash
aegis-os ipc request --to worker --subject "..." --message "..."
```

### 问题 2：`submitted -> input-required` 被拒

`memory revoke` 反向传播时，task 还在 `submitted`，旧状态机只允许 `working -> input-required`，导致反向传播无效。

修复：

- 允许 `submitted -> input-required`
- 更新 `a2a_task_state_machine_and_failure_kind` 测试
- `memory_revoke_can_request_task_input` 改为不先 ack，覆盖该路径

### 问题 3：`memory revoke` 使用了错误的 runtime

`memory revoke` 反向传播需要与 A2A task 相同的 `--runtime-dir`。dogfood 第一次没有传，task 没变化。

修复：

- 文档补充：自定义 `--runtime-dir` 时必须同时传给 `memory revoke`
- `memory revoke` 仍保持全局 `--runtime-dir` 语义，不隐式猜测

## 4. 未覆盖

1. **task 终态 → memory session 撤销**：dogfood 未走 gateway `/v1/a2a` 路径；已有 mock 测试 + memory-server 端点测试。
2. **过期 consent**：本轮没有等到 expiry；`expire_pending_consents` 已实现，但未做端到端时间测试。
3. **真实多 Agent 并行**：dogfood 是单 task；8 进程压力测试在 `aos-ipc` 集成测试中。
4. **server 升级**：dogfood 第一次用了旧 server 二进制，导致 task_id 未落库；实际升级需要重启 `memory serve`。建议后续加版本/健康检查提示。

## 5. 结论

第一轮 dogfood 证明：

- A2A task 创建、board、show 可用
- UOMP consent 绑定 task_id 可用
- MCP 读取 + session task 过滤可用
- `memory revoke` 反向传播可用
- audit task_id 可用

Phase 0 可以进入第二轮 dogfood 或 design partner。
