# PRD-lite — Aegis OS 多 Agent 控制平面（Phase 0 / Phase 1）

日期：2026-10-30
角色：Product Partner（G1）
状态：待 critic 审查 + 用户确认（G2）
范围：Phase 0（0–4 周）、Phase 1（1–3 个月）方向
上游：`.agent/2026-10-30-aegis-multiagent/brief.md`

标注约定：**[事实]** = 代码/文档可验证；**[推断]** = 由事实推出但未验证；**[假设]** = 待用户/数据验证；**[观点]** = 产品判断。

---

## 0. 一句话定位

**Aegis OS 是本地多 Agent 控制平面：让一个人安全地同时驱动多个 coding agent 干活——谁在做什么、能碰什么、花了谁的授权、出事怎么撤，全部可看、可停、可审计。**

三层职责边界（不可混用）：

| 层 | 职责 | 不是什么 |
|---|---|---|
| A2A（已实现） | Agent 间协作总线：任务投递、状态机、peer 发现、mailbox | **不是**授权协议，**不能**携带 raw bearer token |
| UOMP（协议层，属 Aegis Memory） | 用户记忆的请求 / 同意 / 撤销 / 审计语义 | **不是**独立产品，**不是**通用授权层 |
| Policy / Lease | 统一授权执行点：Allow / Ask / Deny、TTL 或 one-shot lease | 不是 UI，不是审计存储 |

---

## 1. 目标用户（ICP）与 JTBD

### 1.1 主 ICP（Phase 0 只服务这一层）

**同时运行 2+ 个 coding agent 的个人开发者 / power user**（Claude Code、Codex、Cursor、OpenCode、`agy`），单机、单仓库或 2–3 个仓库，每天 1 小时以上让 agent 改代码。**[假设]**（来自 brief，未经用户访谈）

判定条件（可筛人）：
- 过去 7 天内 ≥3 天同时开过 2 个以上 agent 会话；
- 至少一次因并行改动互相覆盖、或因为怕覆盖而手动串行化；
- 已经在用 `--yolo` / skip-permissions 之类的方式绕过确认弹窗。

### 1.2 次级 ICP（Phase 1 才正式支持）

需要 Agent 治理与审计的小团队（3–15 人）：有人要对“哪个 agent 读了什么、谁批的”负责，但不想上完整 IAM。**[假设]**

### 1.3 明确不服务谁（Phase 0/1 非目标用户）

- 想要**托管式 Agent 编排云**的团队（我们不做 scheduler-as-a-service、不做 DAG 引擎）。
- 需要**跨组织联邦 / 多租户 SaaS 治理**的 enterprise 买家（Phase 2+，且需独立定价与合规工作）。
- 期望**零配置全自动**、不愿做任何一次人工批准的用户——本产品的价值前提是“关键边界上有人在场”。
- Windows 用户（brief 明确不支持）。
- 把 Aegis 当**通用 secrets manager / CI runner / 代码审查工具**的用户。

### 1.4 核心 JTBD

> 当我要把一件多步骤的活交给几个 agent 并行做时，
> 我想让它们各自在隔离环境里干、互不覆盖、需要我的记忆或敏感操作时才来找我，
> 这样我能在不逐条点确认的前提下，仍然知道谁在干什么，并且随时能一键全停。

拆成三条可测量的 job：

| # | JTBD | 现在的凑合方式 | 失败信号 |
|---|---|---|---|
| J1 | 让多个 agent 并行改同一个仓库而不互相覆盖 | 手动分目录、口头约定、串行化、`git stash` 来回倒 | 静默丢失改动、编译缓存错乱、合并时才发现冲突 |
| J2 | 一眼看清“现在有几个任务在跑、卡在哪、谁在等谁” | 在 3 个终端窗口之间来回切、靠 agent 自己复述 | 任务卡在 input-required 无人知、重复派活 |
| J3 | 授权一次就能覆盖一个任务，且能立刻收回 | 全程 `--yolo`，或每条命令点一次确认 | 授权疲劳（点确认点到麻木）或授权过大（一个 token 通吃） |

---

## 2. 现有替代方案与不足

| 替代方案 | 它解决什么 | 缺口（我们的切入点） |
|---|---|---|
| 多开终端 + 各 agent 自带权限模式 | 零成本 | 无隔离、无 claim、无跨 agent 任务视图；`--yolo` 下无边界 |
| `git worktree` + 人工合并 | 文件级隔离 | 无 task 语义、无授权绑定、无撤销传播；冲突靠人 |
| LangGraph / CrewAI / AutoGen 等编排框架 | 有 task graph / 编排 | 面向“我能写代码编排 agent”，不解决**本机执行隔离与用户授权**；无 consent、无 workspace CoW、无审计关联 |
| A2A 参考实现（跨厂商 agent 互通） | 互操作协议 | 只定义协作消息，不定义“谁能碰用户的文件和记忆”；**不能**当授权层 |
| 云沙箱 / 远程 dev container | 隔离强 | 延迟、成本、离线不可用；用户记忆仍在本地，跨边界更麻烦 |

**结论 [观点]**：市场上“编排”和“隔离”各自都有解，缺的是把 **task ↔ 授权 ↔ 工作区 ↔ 审计** 串成一条可撤销的链。这正是 Aegis OS 的差异化，也是本 PRD 的全部范围。

---

## 3. 现状盘点（决定 Phase 0 做什么的事实基础）

已实现、可直接复用 **[事实]**：

- A2A：`agent/card`、`tasks/send` / `message/send`、`tasks/get`、`tasks/cancel`、`tasks/list`；`A2ATask` 状态机 `submitted → working → input-required → completed | failed | canceled | rejected`（`crates/aos-mcp-gateway/src/lib.rs:2407-2540`，`crates/aos-core/src/lib.rs:419-496`）。
- Task 持久化：`ipc_state.json` 全量快照，每次变更前 `reload_from_disk()`（`crates/aos-ipc/src/lib.rs:74-102, 358-423`）。
- Policy/Lease：R0a–R4 五级、`LeaseGrant`（TTL / one-shot）、`PendingEscalation`、人工 CLI 审批，agent 被 PreToolUse hook 禁止自批（`crates/aos-policy/src/lib.rs:468-545`，README:195-203）。
- Claims：`coordination/claims` 组织级 KV，glob 语义，TTL 默认 2h / 上限 24h，CAS 重试，PreToolUse + `workspace_commit` 双重强制（`crates/aos-core/src/claims.rs`，gateway:367-460）。
- 记忆：`sessions` / `consent_requests` / `revoke_session` / audit（`crates/aos-memory-server/src/auth_store.rs`）。
- Workspace：每 agent 一个 CoW 影子工作区 `<runtime>/orgs/<org>/agents/<agent>/cow_workspace/`，4 级合并（README）。

**关键缺口（Phase 0 要补的正是这些）[事实]**：

| 缺口 | 证据 | 后果 |
|---|---|---|
| G1 `A2ATask` 无 `workspace_id` / `parent_task_id` / `consent_id` / `lease_id` | `aos-core/src/lib.rs:481-496` | task board 只能是平表；无法回答“这个任务动了哪个工作区、用了谁的授权” |
| G2 `LeaseGrant` 无 `task_id` | `aos-core/src/lib.rs:775-785` | 授权只能按 agent + action + resource 给，**不能按任务给**；任务结束授权不自动收 |
| G3 `consent_requests` 无 `task_id` | `aos-memory-server/src/auth_store.rs` | 记忆同意与 A2A 任务无关联，撤销任务不会撤销记忆会话 |
| G4 `update_task_state` 无状态机校验、无 actor 授权 | `aos-ipc/src/lib.rs:358-423` | 任何已认证 agent 可把任意任务改成任意状态（含终态回退） |
| G5 `tasks/get` / `tasks/cancel` 无 org 归属校验 | `aos-mcp-gateway/src/lib.rs:2482-2528` | **[推断]** 知道 task_id 的跨租户调用方可读/取消他人任务 |
| G6 持久化是全量文件重写 + 无锁 | `aos-ipc/src/lib.rs:87-102` | 多进程并发写 = last-writer-wins，任务状态可能静默丢失 |
| G7 AgentCard 声明 `streaming: true` / `pushNotifications: true`，但未实现 `message/stream` 与 push config | `aos-core/src/lib.rs:567-573` vs gateway 路由表 | 对外能力虚标，第三方 A2A client 会走进死路 |
| G8 `AuditEvent` 无 `task_id` / `consent_id` / `workspace_id` 一等字段 | `aos-core/src/lib.rs:844-855` | 审计只能靠 `details` 里的自由文本拼，无法可靠回溯 |
| G9 Claim 是 agent 级、非 task 级；任务取消不释放 claim | `claims.rs`（`Claim{owner,expires_at_ms,note}`） | 任务死后 claim 占着文件最多 2 小时，阻塞其他 agent |

> 注：G5 的实际可利用性取决于 `/v1/a2a` 与 `/a2a` 的认证包装层，需 builder/critic 在实现前确认；本 PRD 将其列为 Phase 0 必修项，不论严重性最终定级。

---

## 4. 方案轮廓（不写实现细节）

**一条链，四个可停点：**

```
用户意图
  └─ A2A Task（task_id, workspace_id, parent_task_id）      ← 可停点 1：cancel task
       ├─ 派发给 Agent B（task-scoped lease，不转发 raw token）
       ├─ Agent B 在独立 CoW workspace 执行（claim 绑定 task）
       ├─ 需要用户记忆 → UOMP consent（consent_id 绑定 task_id） ← 可停点 2：revoke consent
       └─ 结束 → 终态（completed/failed/canceled/rejected）
            └─ 审计：task → agent → session → consent → workspace commit ← 可停点 3：audit trace
                                                                        ← 可停点 4：全局 kill switch
```

设计原则（Phase 0 不妥协的三条）：

1. **A2A 只传“我要什么”，不传“我能干什么”。** 授权凭据永不出现在 A2A 消息体、payload、artifact 里。下游 agent 拿到的是 **task-scoped capability handle**（`lease_id` + task 绑定），由本地 policy 在执行点兑换，不是可转发的 bearer token。
2. **每个 task 是一个授权与撤销的原子单位。** 任务终态 ⇒ 其 task-scoped lease 全部失效、其 claim 全部释放、其绑定的 memory session 进入待撤销或撤销。反向亦然：撤销 memory session ⇒ 依赖它的 task 进入 `input-required`（等人）而非静默失败。
3. **撤销是传播，不是删除。** 撤销必须留下审计事件与传播结果（成功/失败/已过期），否则用户无法判断“到底停没停”。

---

## 5. 用户故事与验收标准

> 每条都写成可测试形式。Given/When/Then 中出现的名词若在 Phase 0 新增，均在 §6 范围表中有对应条目。

### US-1 任务看板：我能看到所有在跑的 agent 任务及其阻塞原因

作为同时开 3 个 agent 的开发者，
我想在一个地方看到所有 A2A 任务的当前状态、归属工作区、以及“在等谁”，
这样我不必在终端间切换猜测进度。

验收标准：
- [ ] **AC-1.1** Given 3 个 agent 各自有 1 个进行中任务，When 我运行 `aegis-os a2a board`，Then 输出 3 行，每行含 `task_id`、`from_agent`、`to_agent`、`state`、`workspace_id`、`age`、`last_update`。
- [ ] **AC-1.2** Given 某任务处于 `input-required`，When 我看 board，Then 该任务被标记为 `BLOCKED` 并显示 `blocked_on`（请求方 agent 或 `user`），且排序置顶。
- [ ] **AC-1.3** Given 任务有 `parent_task_id`，When 我看 board，Then 子任务缩进显示在父任务下；无父任务的为顶层。
- [ ] **AC-1.4** Given 一个已进入终态（completed/failed/canceled/rejected）超过 24h 的任务，When 我看默认 board，Then 它被折叠（`--all` 可见），且**不**计入“进行中”计数。
- [ ] **AC-1.5** 同一命令 `--json` 输出可被脚本消费，字段名与 A2A `tasks/list` 返回一致（不引入第二套命名）。

### US-2 派活不转发令牌：子 agent 只能用“这个任务”的权限

作为把任务委派给 Coder agent 的 Planner agent（背后是我），
我希望被委派的 agent 只获得完成该任务所需的、限时的权限，
这样即使它被 prompt injection 操纵，也拿不到我全部的凭证。

验收标准：
- [ ] **AC-2.1** Given Planner 派发 task T 给 Coder，When Coder 执行需要 `workspace_commit` 的操作，Then policy 用 `(task_id=T, agent=Coder, action=workspace_commit)` 匹配 lease；匹配不到则返回 `Ask` 并生成 escalation，**不**返回 `Allow`。
- [ ] **AC-2.2** Given task T 的 A2A 消息 payload 与 artifacts，When 静态扫描其 JSON，Then 不包含任何形如 `ak_live_*`、`aegis_at_*`、JWT（三段 base64）、或 `$AOS_SECRET_*` 解析后的明文值；命中即测试失败。
- [ ] **AC-2.3** Given task T 已 `completed`，When Coder 在 T 结束后重试同一操作，Then 返回 `Deny`（reason 含 `task_terminal`），且不产生新的 escalation。
- [ ] **AC-2.4** Given 用户批准了一条 task-scoped escalation（TTL 30m），When T 在 5 分钟后被取消，Then 该 lease 立即失效，无需等 TTL 到期。
- [ ] **AC-2.5** Given Coder 试图把收到的 `lease_id` 传给第三个 agent，When 第三 agent 用它执行操作，Then 被拒（lease 绑定 agent_id + task_id，不可转移）。

### US-3 记忆同意绑定任务：批准一次，任务结束自动失效

作为把个人笔记交给 agent 参考的用户，
我希望我批准的记忆访问是“为这个任务、这段时间”，
这样任务做完后不用记得手动去撤销。

验收标准：
- [ ] **AC-3.1** Given task T 运行中，Coder 首次请求 `memory.read` scope `tag:notes/projects`，When 我 `aegis-os memory pending`，Then 该请求显示 `task_id=T`、任务 subject、请求 agent、scope、建议 TTL。
- [ ] **AC-3.2** Given 我批准该请求，When 查看 task T 详情，Then 能看到 `consent_id` 与 `session_id` 的关联（`aegis-os a2a show T` 含 `consents: [...]`）。
- [ ] **AC-3.3** Given T 进入终态，When 我查看 `aegis-os memory sessions`，Then T 绑定的 session 状态为 `revoked` 或 `expired`（由策略决定，二者之一），且审计有对应事件。
- [ ] **AC-3.4** Given 我主动 `aegis-os memory revoke <session>`，When T 正在运行且下一步要读记忆，Then T 在 ≤5s 内转为 `input-required`，reason 含 `memory_revoked`；T **不**静默继续。
- [ ] **AC-3.5** Given agent 尝试自己调用 `memory approve`，Then 被 PreToolUse hook 阻断（回归测试，现有行为不得退化）。

### US-4 撤销传播：一键停掉任务及其所有下游影响

作为发现某个 agent 跑偏的用户，
我希望取消任务后，它占的文件、拿的授权、开的记忆会话全部立刻停，
这样我不用逐个去清理。

验收标准：
- [ ] **AC-4.1** Given task T 处于 `working` 且有 2 个 task-scoped lease、1 个 claim、1 个 memory session，When 我 `aegis-os a2a cancel T`，Then 在 **≤2s（p95）** 内：T 状态为 `canceled`；2 个 lease 失效；claim 被释放；session 进入 `revoked`。
- [ ] **AC-4.2** Given 上述撤销完成，When 我 `aegis-os audit trace T`，Then 输出按时间排序的事件链，至少含 `task.canceled`、`lease.revoked ×2`、`claim.released`、`memory.session_revoked`，每条带 `task_id`。
- [ ] **AC-4.3** Given 某个下游 agent 进程已崩溃/失联，When 我取消 T，Then 撤销仍成功（不依赖被撤对象的配合），且审计标记该分支为 `best_effort` 并注明原因。
- [ ] **AC-4.4** Given T 有子任务 T1/T2，When 我取消 T 且未加 `--cascade`，Then 默认**级联**取消子任务（安全默认），board 上子任务显示 `canceled (parent)`。
- [ ] **AC-4.5** Given 撤销过程中某个 lease 已自然过期，When 传播执行，Then 记 `already_expired` 而非报错失败（幂等）。

### US-5 审计可回溯：一次任务到底动了什么

作为要对一次事故复盘的开发者（或团队里的负责人），
我希望用 task_id 一条命令拉出完整链条，
这样我能判断是 agent 的问题、授权给宽了、还是工作区冲突。

验收标准：
- [ ] **AC-5.1** Given task T 完整跑完（含 1 次 commit、2 次 memory read、1 次 escalation 批准），When 我 `aegis-os audit trace T`，Then 输出包含 `task → agent → session → consent → workspace commit` 五个环节，任一环节缺失则命令以非零码退出并列出缺失项。
- [ ] **AC-5.2** Given 我查询审计，When 查看任一条与 T 相关的事件，Then 其 `details` 至少含 `task_id`；涉及授权的事件含 `lease_id`；涉及记忆的含 `consent_id` 与 `session_id`；涉及文件的含 `workspace_id` 与 `snapshot_id`（如有）。
- [ ] **AC-5.3** Given 我尝试用 agent 通道修改或删除审计记录，Then 操作不可能成功（append-only 回归测试）。
- [ ] **AC-5.4** Given 1000 条任务的审计日志，When 我按 `task_id` 查询，Then p95 延迟 ≤300ms（本地 SQLite/JSONL 量级）。

---

## 6. Phase 0 范围（0–4 周）

目标：**把上面 5 条链路打通到“我自己每天愿意用”的程度**，不追求协议完整性、不追求 UI 精美。

### 6.1 必须做（Must — 不做则 Phase 0 失败）

| ID | 条目 | 覆盖缺口 | 验收锚点 | 对应 issue |
|---|---|---|---|---|
| M1 | **A2A task 模型扩展（加法）**：`workspace_id`、`parent_task_id`、`consent_ids[]`、`lease_ids[]`、`depth`、`budget`（可选）；旧 `ipc_state.json` 可无损加载 | G1 | 旧状态文件加载后字段为 `None`/空，不报错；新任务必带 `workspace_id` | #1 |
| M2 | **状态机校验 + actor 授权**：合法转移表；只有 requester / assignee / operator 可改状态；终态不可回退 | G4 | 非法转移返回 `-32602`；终态回退被拒 | #2 |
| M3 | **持久化并发可靠性**：单写者或文件锁 + 原子替换；崩溃后状态可恢复；并发测试 100 任务 × 8 进程无丢失 | G6 | 压测后任务计数与状态一致；kill -9 后重启无 `working` 幽灵任务（或标记 `stale`） | #3 |
| M4 | **Task board 读视图**：`aegis-os a2a board` / `a2a show <id>` / `--json` | G1 | US-1 全部 AC | #4 |
| M5 | **Task-scoped lease**：`LeaseGrant.task_id`；批准时绑定；终态自动失效；**不转发 raw token** | G2 | US-2 AC-2.1/2.3/2.4/2.5 | #5 |
| M6 | **UOMP consent ↔ task 绑定**：`consent_requests.task_id`（可空）；审批视图显示任务上下文；session 继承 task 归属 | G3 | US-3 AC-3.1/3.2 | #6 |
| M7 | **撤销传播（双向）**：cancel task ⇒ 撤 lease / 释放 claim / 撤 session；revoke session ⇒ task 转 `input-required` | G3,G9 | US-4 全部 AC；US-3 AC-3.3/3.4 | #7 |
| M8 | **Workspace 隔离与 claim 绑定任务**：task 必须绑定一个 workspace；跨 workspace 读写在 policy 层 `Deny`；`coord_claim` 可带 `task_id`，任务终态自动释放 | G9 | 跨 workspace 写入被拒；任务取消后 1s 内 claim 释放 | #8 |
| M9 | **审计关联字段**：`AuditEvent` 增加 `task_id`/`consent_id`/`workspace_id`/`lease_id`（进 `details` 亦可，但须有稳定键名）；`audit trace <task_id>` | G8 | US-5 全部 AC | #9 |
| M10 | **跨租户 task 访问控制**：`tasks/get`、`tasks/cancel`、`tasks/list` 按调用方 org 过滤；跨 org 一律 403 | G5 | 用 org A 的 key 读 org B 的 task_id 返回 403（安全回归测试） | #10 |

### 6.2 应该做（Should — 明显提升可用性，可延到 Phase 0 末尾）

| ID | 条目 | 理由 | 对应 issue |
|---|---|---|---|
| S1 | **AgentCard 能力诚实化**：`streaming` / `pushNotifications` 按真实能力声明（当前为 `false` 或加 `experimental` 标记） | 虚标会让第三方 A2A client 卡死；修复成本极低 | #11 |
| S2 | **冲突可见化**：claim 冲突时 board 与 PreInvocation 提示“谁占着、还剩多久、建议找谁” | 已有 `conflict_message`，只需接入 board | #11 |
| S3 | **Task 失败原因分类**：`failed` 必带 `failure_kind`（policy_denied / conflict / timeout / agent_error / revoked） | 直接支撑“任务失败率”指标可解释 | #2 |
| S4 | **孤儿任务清理**：assignee 进程消失超过 N 分钟 ⇒ 标 `stale`，不自动判死 | 本地多进程场景常见 | #3 |
| S5 | **`aegis-os a2a graph`**：task graph 的文本/`--dot` 输出（父→子、依赖） | 支撑“任务图”最小形态；不做可视化 UI | #4 |

### 6.3 不做（Won't — Phase 0 明确排除）

- ❌ A2A `message/stream`（SSE）与 push notification 服务端实现。**Phase 0 只做诚实声明，不做实现。**
- ❌ 完整 A2A conformance suite / 与第三方 A2A 实现的互操作认证。
- ❌ 图形化 Mission Control 改造（现有 `/dashboard` 不改版）。
- ❌ 新的 Agent 编排 DSL / DAG 调度器 / 重试与补偿引擎。
- ❌ 跨机器 / 跨组织 A2A 联邦与任务迁移。
- ❌ 浏览器 consent UI（CLI 审批是 Phase 0 唯一路径）。
- ❌ UOMP 协议变更（只做 Aegis 侧字段扩展，不改规范）。
- ❌ 任何形式的“agent 自批”或“agent 之间互授权限”。
- ❌ 定价、品牌、对外发布材料。

### 6.4 Phase 1 方向（1–3 个月，只定方向不拆 issue）

1. **任务图有依赖**：`depends_on` + 阻塞语义 + 拓扑就绪判定（真正的 task graph，而非只有父子）。
2. **多 agent 并发配额与预算**：每任务 token/时长/工具调用上限，超限转 `input-required`。
3. **团队视图**：跨 org 的只读审计与审批队列（对应次级 ICP）。
4. **A2A 增量流**：`message/stream` 或等价事件订阅，支撑长任务的实时进度（需先确认协议版本与互操作成本）。
5. **记忆同意的任务级模板**：常见任务类型（“review PR”、“写测试”）预置 scope 包，减少逐次审批。

---

## 7. 成功指标

原则：**每个指标先有采集点，再有目标值。** 无基线的标 `TBD-baseline`，Phase 0 第一周只做埋点，不追目标。

| # | 指标 | 精确定义 | 基线 | Phase 0 目标 | Phase 1 目标 | 采集方式 |
|---|---|---|---|---|---|---|
| K1 | **激活率** | 新装用户中，7 天内完成“≥1 个 A2A task 从 `submitted` 走到终态”的比例 | TBD-baseline | ≥40% | ≥55% | 本地匿名事件（opt-in），或 dogfood 手动统计 |
| K2 | **首次多 Agent 任务完成时间（TTFM）** | 从 `aegis-os up` 首次成功 到 第一个跨 agent task 达终态 的中位时长 | TBD-baseline | ≤20 min | ≤10 min | 本地事件时间戳差值 |
| K3 | **Consent 批准率** | 批准的 consent 请求 / 全部 consent 请求（不含过期） | TBD-baseline | 60–85%（**过高=审批无意义，过低=摩擦过大**） | 65–85% | memory server `consent_requests` 表 |
| K4 | **撤销传播延迟** | `cancel task` 或 `revoke session` 发起 → 所有关联资源（lease/claim/session）确认失效的 p95 | 无（当前无传播） | ≤2s | ≤1s | 审计事件时间戳差值 |
| K5 | **撤销传播完整率** | 一次撤销中成功失效的关联资源数 / 应失效数 | 无 | ≥99%（失败必记 `best_effort` 原因） | 100% | `audit trace` 自检脚本 |
| K6 | **审计覆盖率** | 含 `task_id` 的审计事件数 / 应关联审计事件总数（抽样 100 条人工核对） | 0（无字段） | ≥95% | ≥99% | 审计日志抽样 |
| K7 | **任务失败率** | 终态为 `failed` 的任务 / 全部达终态任务（不含 `canceled`，单列） | TBD-baseline | ≤15% | ≤10% | A2A task 表 + `failure_kind` |
| K8 | **任务卡死率** | 处于非终态且 `last_update` 超过 30 min 的任务占比 | TBD-baseline | ≤5% | ≤2% | board 统计 |
| K9 | **7 日留存** | 激活用户中，第 7 天仍有 ≥1 个 A2A task 达终态的比例 | TBD-baseline | ≥35% | ≥45% | 事件回传 / dogfood 日志 |
| K10 | **授权疲劳抑制** | 每任务人工确认次数（escalation 批准数 / 任务数） | 现状 ~45–57% 工具调用需确认（README 引论文） | ≤1.0 | ≤0.5 | policy escalation 计数 |

**指标使用规则 [观点]**：K1/K9 看采用，K3/K10 看“授权设计是否合理”，K4/K5/K6 看“安全承诺是否兑现”，K7/K8 看“多 agent 是否真的更好用”。**任何安全类指标（K4–K6）不达标，Phase 0 不得进入 private beta，即使采用类指标很好看。**

---

## 8. 非目标与风险

### 8.1 非目标（产品层，重复强调）

- 不做通用工作流引擎；不做 agent 的“大脑”，只做“交通与边界”。
- 不做 A2A 的授权扩展（不往 A2A 消息里塞权限声明）。
- 不改 UOMP 规范；只做 Aegis 侧承载字段。
- 不做多租户云治理（Phase 2+）。
- 不做“零审批”模式作为卖点——审批是被压缩，不是被取消。

### 8.2 风险表

| # | 风险 | 类型 | 概率 | 影响 | 缓解 | 负责人 |
|---|---|---|---|---|---|---|
| R1 | **撤销只停“记录”不停“进程”**：lease 失效但 agent 进程仍在跑、仍在写自己的 CoW 工作区 | 安全 | 高 | 高 | 撤销 = 标记失效 + 执行点每次校验 + （Phase 1）进程级 suspend；Phase 0 明确承诺边界：“停止新授权动作”，不含杀进程 | builder + critic |
| R2 | **持久化并发仍是 last-writer-wins**：文件锁实现不当，压测通过但真实多进程仍丢状态 | 可靠性 | 中 | 高 | M3 必须有 kill -9 + 8 进程并发测试；不达标不上 board | builder |
| R3 | **task-scoped lease 表达力不足**：一个任务需要多种 action/resource，`LeaseGrant` 单 pattern 撑不住 | 产品/技术 | 高 | 中 | 沿用现有“一 session 多 lease”模式（UOMP 映射文档 §4.1 已确立），task_id 打在每条 lease 上 | builder |
| R4 | **跨租户 task 泄漏（G5）比预想严重** | 安全 | 中 | 高 | M10 作为 Phase 0 第一周必修；critic 复核 `/v1/a2a` 认证包装 | critic |
| R5 | **AgentCard 虚标导致第三方 client 挂起** | 采用 | 高 | 中 | S1 立即修；对外文档同步 | builder |
| R6 | **审批疲劳反弹**：task-scoped lease 让单次授权范围变大，用户反而更不敢批 | 产品 | 中 | 中 | 审批页必须显示“这个任务要做什么 + 影响哪些文件 + 多久”；K3 监控批准率异常下降 | product |
| R7 | **ICP 判断错误**：真实用户其实是“团队”而非“个人”，Phase 0 的 CLI-only 形态不匹配 | 采用 | 中 | 高 | 前 5 个 design partner 必须至少 2 个是个人开发者画像；每周访谈 | product |
| R8 | **与现有 `/dashboard` 体验割裂**：CLI board 与 Web console 两套真相 | 产品 | 中 | 中 | Phase 0 声明 CLI 为唯一真相源，dashboard 只读复用同一 API | product |
| R9 | **claim 语义被绕过**：agent 直接用 shell 写文件绕过 PreToolUse | 安全 | 中 | 中 | 现有 sandbox 已限制写宿主；CoW 内绕过只影响自己的影子区，commit 时仍校验 claim（需回归测试确认） | critic |
| R10 | **指标采集侵犯隐私 / 用户不愿开** | 采用 | 高 | 低 | 本地优先，默认不上报；dogfood 阶段用人工统计替代 | product |

### 8.3 关键假设（需验证）

| # | 假设 | 验证方式 | 若不成立的后果 |
|---|---|---|---|
| A1 | 个人开发者愿意为“多 agent 安全并行”付出一次配置成本（≤10 min） | 5 次 onboarding 观察 | 整个 ICP 重估 |
| A2 | 用户能理解“task-scoped 授权”这个概念，且比“每次确认”更省心 | 审批页可用性测试（5 人） | 退回 agent-scoped lease，产品价值削弱 |
| A3 | 撤销传播 ≤2s 在本地多进程下可达成 | M3/M7 原型验证 | 指标改口径或引入常驻协调进程 |
| A4 | 现有 A2A 实现足以承载 task graph（不需重写） | builder spike（2 天） | Phase 0 范围需砍到“平表 + 父子” |
| A5 | 记忆同意与任务绑定的需求真实存在（而非我们想象） | 访谈中询问“是否曾希望 agent 别一直能读你的笔记” | 降级为 Should |

---

## 9. 发布策略

### 阶段 0：Dogfood（第 1–3 周）

- 对象：团队内部 2–3 人 + 我本人，每天真实使用。
- 入口：源码构建，`aegis-os a2a board` + `aegis-os audit trace`。
- **退出标准（全部满足才进下一阶段）**：
  1. 连续 5 个工作日，每天 ≥2 个跨 agent 任务达终态；
  2. K4 撤销延迟 p95 ≤2s，K5 完整率 ≥99%（自测脚本，20 次撤销）；
  3. M3 并发压测通过（8 进程 × 100 任务，零丢失）；
  4. M10 跨租户回归测试通过；
  5. 无 P0 级未修复缺陷（critic 判定）。

### 阶段 1：Design Partners（第 4 周 – 第 6 周）

- 对象：3–5 个外部用户，其中 ≥2 个符合主 ICP 画像；签简单使用协议，允许我们观察（不采集代码内容）。
- 交付：Homebrew 安装 + 一页 quickstart + `aegis-os doctor` 自检。
- **退出标准**：
  1. ≥3 个 partner 在无我们陪同的情况下完成首次多 agent 任务（K2 ≤20 min，中位）；
  2. K3 consent 批准率落在 60–85% 区间（说明审批既非无意义也非不可用）；
  3. K7 任务失败率 ≤15%，且每个失败都能归到 `failure_kind`；
  4. 收集到 ≥10 条具体阻断问题，其中 P0/P1 全部修复；
  5. ≥2 个 partner 明确表示“下周还会继续用”。

### 阶段 2：Private Beta（第 7 周 – 第 12 周）

- 对象：邀请制，20–50 人，仍以个人开发者为主。
- 交付：稳定安装包、错误信息可读、`aegis-os a2a` 子命令文档、已知限制清单。
- **退出标准（进入 GA 讨论的门槛）**：
  1. K1 激活率 ≥40%，K9 7 日留存 ≥35%；
  2. K6 审计覆盖率 ≥95%（抽样核对）；
  3. 30 天内无“授权越界 / 跨租户泄漏 / 撤销失效”类安全事故；
  4. K8 卡死率 ≤5%；
  5. 支持负担可控：每用户每周支持请求 ≤0.5 次。

> 每个阶段都有**回滚闸门**：任一安全类指标（K4/K5/K6）连续 3 天不达标 ⇒ 回退到上一阶段，不带着已知安全债前进。

---

## 10. 里程碑

| 里程碑 | 时间 | 交付物 | 判定 |
|---|---|---|---|
| G2 定稿 | 第 0 周 | 本 PRD + research.md + review.md + decision.md | 用户确认 |
| P0-a 骨架 | 第 1 周 | #1 #2 #3 #10 | 压测 + 安全回归通过 |
| P0-b 可看 | 第 2 周 | #4 #11 | 我能每天用 board 干活 |
| P0-c 可控 | 第 3 周 | #5 #6 #7 #8 | 撤销链路端到端跑通 |
| P0-d 可查 | 第 3 周末 | #9 | `audit trace` 五环节齐全 |
| P0 退出 | 第 4 周初 | dogfood 退出标准 5 条 | 全绿 |
| P1 规划 | 第 4 周 | Phase 1 backlog | 基于 dogfood 数据重排优先级 |

---

## 11. Phase 0 Issue 拆分（可直接建 GitHub issues）

> 依赖顺序：`#1 → #2 → #3`，`#1 → #4`，`#1 → #5 → #7`，`#1 → #6 → #7`，`#1 → #8`，`#2/#5/#6 → #9`，`#10` 独立（可并行，优先级最高）。

| # | 标题 | 类型 | 依赖 | 验收（摘要） | 估时 |
|---|---|---|---|---|---|
| 1 | `feat(a2a): task 模型加法扩展（workspace_id / parent_task_id / consent_ids / lease_ids / depth）` | feat | — | 旧 `ipc_state.json` 无损加载；新任务必带 workspace_id；`tasks/get` 返回新字段 | 2d |
| 2 | `feat(a2a): 状态机校验与 actor 授权` | feat | #1 | 非法转移拒绝；终态不可回退；仅 requester/assignee/operator 可改；`failure_kind` 必填于 failed | 2d |
| 3 | `fix(a2a): 持久化并发可靠性（单写者/文件锁 + 原子替换 + 崩溃恢复）` | fix | #1 | 8 进程 × 100 任务零丢失；kill -9 后无幽灵 working；stale 任务可识别 | 3d |
| 4 | `feat(cli): aegis-os a2a board / show / graph` | feat | #1 | US-1 全部 AC；`--json` 字段与 `tasks/list` 一致 | 2d |
| 5 | `feat(policy): task-scoped lease（LeaseGrant.task_id，终态自动失效，禁止 token 转发）` | feat | #1 | US-2 全部 AC；payload 静态扫描无凭据 | 3d |
| 6 | `feat(memory): consent_requests.task_id 与任务上下文展示` | feat | #1 | US-3 AC-3.1/3.2；`memory pending` 显示 task 上下文 | 2d |
| 7 | `feat(revocation): 撤销传播（cancel task ⇄ revoke session 双向，幂等，审计留痕）` | feat | #5 #6 #8 | US-4 全部 AC；US-3 AC-3.3/3.4；p95 ≤2s | 3d |
| 8 | `feat(workspace): task 绑定 workspace、跨 workspace 拒绝、claim 绑定 task 并随终态释放` | feat | #1 | 跨 workspace 写入 Deny；任务取消后 1s 内 claim 释放 | 3d |
| 9 | `feat(audit): 审计关联字段 + aegis-os audit trace <task_id>` | feat | #2 #5 #6 | US-5 全部 AC；缺失环节非零退出 | 2d |
| 10 | `fix(security): A2A tasks/get / cancel / list 跨租户访问控制` | fix | — | 跨 org 一律 403；含回归测试 | 1d |
| 11 | `fix(a2a): AgentCard 能力诚实化 + claim 冲突可见化` | fix | — | `streaming`/`pushNotifications` 与实现一致；冲突提示含 owner/剩余时间/建议动作 | 1d |
| 12 | `chore(metrics): Phase 0 指标埋点（K1–K10 本地事件）` | chore | #4 #9 | 每个指标有明确采集点与可导出格式；默认不上报 | 2d |

合计约 26 人日 ≈ 单人 5 周 / 双人 2.5–3 周。若需压到 4 周，砍 #12（改人工统计）与 #4 的 `graph` 子命令。

---

## 12. 开放问题（按重要性排序，最多 5 个）

1. **撤销的承诺边界到底是“停止新授权动作”还是“停止进程”？**
   前者可实现且诚实，后者体验更好但要引入进程管理。Phase 0 建议明确承诺前者，并在 UI/文档中写清；需要用户拍板，因为这直接决定 R1 的定级与 K4 的口径。

2. **`workspace_id` 的粒度是什么？** 每 agent 一个 CoW 工作区（现状），还是每 task 一个？每 task 更干净但克隆与合并成本上升；每 agent 更省但同 agent 串行任务会共享工作区。建议 Phase 0 = 每 task 一个逻辑 workspace_id、物理上复用 agent CoW，需 builder 确认可行性。

3. **跨 agent 的 task 是否默认允许？** 当前 A2A 是 intra-org auto-allow。是否应要求“首次跨 agent 派活”经过一次人工确认（哪怕只是 yes/no），以建立用户心智？这会影响 K1 激活率与 K3。

4. **Phase 0 是否必须做 `message/stream`？** 不做则长任务只能轮询 `tasks/get`，board 刷新有延迟；做则要碰协议实现与互操作。建议不做，但需确认“轮询间隔多少可接受”（2s？5s？）。

5. **次级 ICP（团队）是否要在 Phase 1 就进入？** 若进入，需要跨 org 只读审计视图与多人审批队列，会挤占 task graph 的工期。建议 Phase 1 只做“单人 + 只读分享链接”，不做多用户 RBAC。

---

## 13. 待 researcher / builder / critic 补的块

- **researcher**：A2A 规范当前版本对 task graph / 依赖 / push 的官方立场；LangGraph、CrewAI、Claude Code subagents 的 task 可视化与授权做法（用于 §2 竞品表补证据）。
- **builder**：G5 跨租户可利用性确认；M3 文件锁方案 spike（2 天）；`workspace_id` 粒度可行性（开放问题 2）。
- **critic**：R1/R2/R9 的对抗性验证；“task-scoped lease 是否真的比 agent-scoped 更安全”的反例构造。
