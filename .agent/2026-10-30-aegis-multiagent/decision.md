# Decision — Aegis OS 多 Agent 控制平面（G2）

日期：2026-10-30
角色：Conductor
上游：`brief.md`、`research.md`、`product.md`、`review.md`
状态：**G2 已通过（2026-10-30 用户确认）**

---

## 1. 团队运行结果

| Gate | 状态 | 产物 |
|---|---|---|
| G0 定框 | 完成 | `brief.md` |
| G1 研究 | 完成 | `research.md`：A2A v1.0.1 现状、竞品、安全风险 |
| G1 产品 | 完成 | `product.md`：PRD-lite、5 个用户故事、Phase 0 范围、指标、发布策略 |
| G1 审查 | 完成 | `review.md`：4 个 P0、6 个 P1、6 个 P2 |
| G2 方向确认 | **通过** | 用户确认：0.2.x 兼容层；停止新授权动作；6 周完整版 |

**Critic 结论：** 方向正确，但当前不能直接进实现。P0 不是“Phase 0 要补的功能”，而是**当前代码里已经存在的漏洞**。

**用户 G2 决策（2026-10-30）：**
1. A2A 对外策略：**先做 0.2.x 兼容层**；v1.0 升级单列 Phase 0.5。
2. 撤销承诺：**停止新授权动作**，不承诺杀死已启动进程；进程级 suspend 放 Phase 1。
3. Phase 0 范围：**6 周完整版**，包含双向撤销、claim 绑定 task、A2A graph、指标埋点。

---

## 2. 必须先承认的事实

1. **A2A 版本落后两代**：Aegis 仍是 0.2.x 方法名/`agent.json`/7 状态；官方已到 v1.0.1（`agent-card.json`、PascalCase 方法、`AUTH_REQUIRED`、`ListTasks` 分页）。
2. **A2A 能力虚标**：AgentCard 写 `streaming: true` / `pushNotifications: true`，但没有 SSE/push 实现。
3. **A2A 授权缺口是现网漏洞**：
   - `tasks/get` 无 org 过滤
   - `tasks/list` 默认跨 org
   - `/api/status` 的 `a2a_tasks` 返回全量
   - `update_task_state` 无 actor 校验
   - `tasks/cancel` 可跨 org 取消
4. **task-scoped lease 还没有模型**：`LeaseGrant` 没有 `task_id`；one-shot 是“首次命中即删除”；`PolicyContext` 没有 `task_id`。
5. **撤销传播没有跨进程机制**：policy / ipc / memory-server 三处状态，没有事务、事件总线或协调者；≤2s p95 目前不可承诺。
6. **4 周计划偏大**：26 人日 ≈ 单人 5 周；第 3 周同时改 lease/consent/claim/传播，风险过高。

---

## 3. 建议决策（待用户确认）

### D1. Phase 0 的 A2A 对外策略：先做 0.2.x 兼容层

**用户已确认：** Phase 0 不升级 v1.0；对外明确声明“A2A 0.2.x 兼容层”，同时修正 AgentCard 的 `protocolVersion` 与 `protocol` 字段一致。v1.0 升级单列 **Phase 0.5**。

理由：
- Phase 0 用户是本地个人开发者，互操作不是首要痛点。
- v1.0 升级会牵动 Task 结构、方法名、错误码、well-known 路径，4 周内做不完。
- 继续虚标“Google A2A”比“明确 0.2.x”更伤信任。

**代价：** 第三方 v1.0 客户端暂时不能直连；需要文档写清。

---

### D2. Phase 0 的撤销承诺：停止新授权动作，不承诺杀进程

**用户已确认：** Phase 0 明确承诺：

> 撤销后，**不会再有新的授权动作成功**；已启动的 Agent 进程可能继续运行，但它的下一次受控操作会被拒绝或转为 `input-required`。进程级 suspend 放到 Phase 1。

理由：
- 跨进程 kill/suspend 需要进程管理、信号处理、崩溃恢复，Phase 0 做不完。
- 诚实承诺比“看起来能杀进程”更重要。
- 与现有 policy/lease 的“执行点校验”模型一致。

**代价：** 用户可能觉得“撤销不够彻底”；需要在 UI/文档/`--help` 里反复说明。

---

### D3. Phase 0 的 `workspace_id`：逻辑 ID + 物理复用 agent CoW，只做审计不做强制

**建议（用户未反对，按建议执行）：** Phase 0 定义 `workspace_id = agent CoW 路径的规范化 hash`，任务记录该 ID；跨 workspace 的强制 `Deny` 放到 Phase 1。Phase 0 只保证：
- task board 能看到 workspace_id
- 审计能关联 workspace
- 同一 agent 的 CoW 不被其他 agent 直接写

理由：
- PaaS `workspace_id` 与 CoW 影子区不是同一概念；现在强制映射会做出“测试里有个 id、真实路径没校验”的假安全。
- Phase 0 的核心是 task/lease/consent/audit 关联，不是 workspace 强制隔离。

**代价：** M8 的“跨 workspace Deny”验收要降级；需要在 PRD 里写清。

---

## 4. 建议的 Phase 0 修订范围（4 周保守版）

在 Critic 的 7 项 gate 条件基础上，建议砍到 9 个 issue，约 20–21 人日：

| # | 标题 | 类型 | 依赖 | 估时 | 说明 |
|---|---|---|---|---|---|
| 1 | `fix(security): A2A tasks/get / cancel / list / status 跨租户与 actor 隔离` | fix | — | 2d | **第一优先**；403/404 不可区分 |
| 2 | `feat(a2a): 状态机校验 + actor 授权 + failure_kind` | feat | #1 | 2d | 终态不可回退；canceled 仅 requester/operator |
| 3 | `fix(a2a): ipc_state.json 原子写 + 文件锁 + 崩溃恢复` | fix | — | 3d | 8 进程 × 100 任务压测 |
| 4 | `feat(a2a): task 模型加法扩展（workspace_id / parent_task_id / consent_ids / lease_ids）` | feat | #3 | 2d | 旧状态无损加载 |
| 5 | `feat(cli): aegis-os a2a board / show` | feat | #4 | 2d | 不做 graph；`--json` |
| 6 | `feat(policy): LeaseKind + task-scoped lease（task_id 由 gateway 注入）` | feat | #4 | 3d | 废弃 `-1` 魔法值；同 agent 跨 task 不可复用 |
| 7 | `feat(memory): consent_requests.task_id + pending 显示 task 上下文` | feat | #4 | 2d | 只做正向绑定，不做反向撤销 |
| 8 | `feat(audit): task_id/consent_id/workspace_id/lease_id + audit trace` | feat | #2 #6 #7 | 2d | 五环节缺失非零退出 |
| 9 | `fix(a2a): AgentCard 能力诚实化（streaming/push=false）` | fix | — | 0.5d | 与实现一致 |

**明确后移：**
- `#7b` revoke session ⇒ task input-required（需要 task-scoped revoke 鉴权，Phase 1）
- claim 绑定 task + 终态释放（Phase 1；Phase 0 claim 仍是 agent 级）
- `aegis-os a2a graph`
- K1/K2/K9/K10 指标埋点
- A2A v1.0 升级（Phase 0.5）
- browser consent UI

**4 周排期（单人）：**
- 第 1 周：#1 #2 #3
- 第 2 周：#4 #5 #9
- 第 3 周：#6 #7
- 第 4 周：#8 + dogfood + 撤销演练

**双人并行：** 可压到 2.5–3 周；但 #1/#2/#3 必须同一人负责，避免安全逻辑分裂。

---

## 5. G2 用户确认结果

1. **A2A 对外策略**：0.2.x 兼容层。
2. **撤销承诺**：停止新授权动作。
3. **Phase 0 范围**：6 周完整版。

> 其余决策（workspace_id 粒度、K 指标口径、M10 优先）按本文件建议执行。

---

## 6. 风险与后续

- **最大风险**：先做功能、后修 P0，导致“用户以为撤销生效，实际 agent 还在跑”。因此 #1/#2/#3 必须先于 #6/#7。
- **第二大风险**：A2A v1.0 升级被无限期拖延，对外信任受损。Phase 0.5 必须有明确日期。
- **第三大风险**：task-scoped lease 只加字段不加匹配条件，等于没做。M5 验收必须包含“同 agent 跨 task 不可复用”的反例测试。
- **下一步**：用户确认 3 个问题后，进入 G3：
  - builder 先做 #1/#2/#3（安全与可靠性）
  - critic 对 #1/#2/#3 做独立复审
  - 再进入 #4–#9

---

## 7. 实施进度（2026-10-31）

| Slice | 状态 | 产物 | 验证 |
|---|---|---|---|
| #1 A2A 跨租户 / actor 隔离 | 完成 | `builder-01.md`、`review-builder-01.md` | `aos-ipc` 8→10 passed；`aos-mcp-gateway` 26 passed |
| #2 A2A 状态机 | 完成 | `builder-02.md`、`review-builder-02.md` | `can_transition_to`、`failure_kind`、幂等 no-op、reply 校验 |
| #3 IPC 持久化 | 完成（有条件） | 同上 | 进程内 `state_mutex` + 跨进程 `flock` + 原子 rename + 损坏文件保护 |
| #4 Task Board | 完成 | `builder-03.md` | `aegis-os a2a board/show`；手工验证通过 |
| #5 task-scoped lease | 完成（有条件） | `builder-03.md`、`builder-04.md`、`review-builder-04.md` | `LeaseKind`、`task_id`、匹配、审批继承、终态撤销、revision/CAS、active task 注入 |
| #6 consent 绑定 task_id | 完成 | `builder-05.md`、`review-builder-05.md` | `sessions.task_id` / `consent_requests.task_id`、旧库迁移、pending 显示 |
| #7 撤销传播 | 完成（有条件） | 同上 | task 终态 → revoke-by-task；session revoke → task input-required |
| 收尾 | 完成 | `builder-06.md`、`review-builder-06.md` | audit task_id、sessions 过滤、task-scoped revoke token、gateway mock 测试 |
| 真实多进程 | 完成 | `builder-07.md`、`review-builder-07.md` | 8 OS 进程 × 100 task；kill -9 → stale；30s flock deadline |
| Dogfood-01 | 完成 | `dogfood-01.md` | A2A task + consent + MCP read + revoke + audit；修复 ipc request / submitted→input-required / runtime-dir 文档 |
| Dogfood-02 | 完成 | `dogfood-02.md` | Gateway `/v1/a2a` cancel → memory session revoked；consent expiry 测试 |

当前测试：`aos-ipc` 17 + multi_process 1 passed；`aos-mcp-gateway` 28 passed；`aos-policy` 7 passed；`aos-memory` 10 passed；`aos-memory-server` 3 passed；`aos-cli` 16 passed；`cargo check --workspace` 通过。真实 8 进程 × 100 任务 + kill -9 连续 3 次通过（~22s/次）；Gateway `/v1/a2a` cancel → memory revoke 端到端通过。代码未 commit / push。

## 8. 决策记录

| 决策 | 状态 | 理由 |
|---|---|---|
| A2A 是协作总线，不是授权协议 | 已定 | 用户确认 + 研究结论 |
| UOMP 是 Aegis Memory 协议层，不是独立产品 | 已定 | 用户确认 |
| Phase 0 先修 P0 再做功能 | 建议 | Critic gate |
| Phase 0 对外 0.2.x 兼容层 | **已确认** | 用户 G2 |
| 撤销承诺“停止新授权动作” | **已确认** | 用户 G2 |
| Phase 0 6 周完整版 | **已确认** | 用户 G2 |
| workspace_id 只做审计不强制 | 建议 | 见 D3 |
| K1/K2/K9/K10 移出 Phase 0 | 建议 | Critic P2-4 |
