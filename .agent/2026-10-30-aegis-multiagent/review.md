# Review — Aegis OS 多 Agent 控制平面（Phase 0）

审查者：Critic（G1/G2 对抗性审查）｜日期：2026-10-30
覆盖：`brief.md`、`research.md`、`product.md`，以及 `aos-core`、`aos-ipc`、`aos-mcp-gateway`、`aos-policy`、`aos-memory-server`、`aos-cli/routing.rs` 的定点验证。

> **Conductor 复核（2026-10-30）**
> - A2A v1.0.1 / v1.0.0 的版本与日期已用官方 `CHANGELOG.md`、`v1.0.1` spec 复核；method mapping、`agent-card.json`、`AUTH_REQUIRED` 均已核对。
> - P0-1、P0-2、P0-3、P0-4 的代码证据已逐条复核：`tasks/get` 无 org 过滤、`/api/status` 返回全量 `a2a_tasks`、`update_task_state` 无 actor 校验、one-shot lease 首次命中即删除、`PolicyContext` 无 `task_id`。
> - Critic 的“无法联网”限制已由 conductor 补齐；下文保留其原始判断，但 A2A 版本相关事实不再标“未验证”。
> - Critic 未运行测试/压测；P0-3/P0-4 的运行时结论仍需 builder spike 验证。

## 审查结论（一句话）

方向正确、结构清楚，但**当前状态不能进 G2**：有 3 个未修的安全/正确性缺口被产品当成“Phase 0 待办”而不是“已存在的可利用漏洞”，并且 4 周计划在依赖顺序上自相矛盾（撤销链路依赖持久化重写和 lease 模型重写，而这两项排在最前面）。

## P0（阻塞 G2 / 安全 / 正确性）

### P0-1 `tasks/get` 是跨租户任意读取，且漏洞面比 PRD 描述更大（不止 G5）

- **证据**：
  - `crates/aos-ipc/src/lib.rs:425-428` `get_task` 只按 `task_id` 查，无任何 org/agent 参数。
  - `crates/aos-mcp-gateway/src/lib.rs:2482-2500` `tasks/get` 直接调用 `get_task`，不校验 `identity.org_id`。
  - `crates/aos-mcp-gateway/src/lib.rs:3122` `GET /api/status` 在 `query_org` 为当前 org 时也调用 `list_tasks(None, None)`，**把全 workstation 的 A2A task 返回给任意租户 key**（`api_keys`、`secrets` 虽按 org 过滤，`a2a_tasks` 没有）。
  - `crates/aos-mcp-gateway/src/lib.rs:2383-2385` MCP resource `aegis://a2a/tasks` → `ipc_task_list`，而 `ipc_task_list` 默认 `scope = "all"`（`crates/aos-mcp-gateway/src/lib.rs:1455-1464`），即默认跨 org。
  - `crates/aos-mcp-gateway/src/lib.rs:200-209` `requested_org` 只从 query/body 提取，`tasks/get` 的 `params.id` 不在检查范围，所以现有的 org 隔离层对 `tasks/get` 完全不起作用。
  - 认证模型：`crates/aos-mcp-gateway/src/lib.rs:2980-2999` 只校验 token 属于哪个 org，不限制 agent 身份头（`X-Aegis-Agent` 可自填，`crates/aos-mcp-gateway/src/lib.rs:2941-2948`）；同 org 内任意 agent 可读任意 task。
- **影响**：任何持有 org A 的 `ak_live_*` key 的 agent（包括被 prompt injection 控制的下游 agent）都能枚举并读取 org B 的任务 subject/payload/artifacts/history。PRD 把 G5 标为 **[推断]**（`product.md:99`），实际是**已验证的读泄露**，且比“知道 task_id 才能读”更糟——`tasks/list` 和 `/api/status` 可以直接枚举。
- **修复建议**：M10 从“1d 的 fix”升级为 G2 前必须给出的设计：`get_task(task_id, requester_org, requester_agent)`、`list_tasks` 强制 org、`/api/status` 的 `a2a_tasks` 按 `query_org` 过滤、`ipc_task_list` 默认 `scope=org`。403 与 404 必须不可区分（规范要求不泄露存在性）。

### P0-2 `update_task_state` 无 actor 校验 + `tasks/cancel` 可跨 org 取消任意任务

- **证据**：`crates/aos-ipc/src/lib.rs:358-386` 只做 `get_mut`，任何 state 都能写、任意终态可回退、无 actor 匹配；`crates/aos-mcp-gateway/src/lib.rs:2502-2529` `tasks/cancel` 直接调 `update_task_state(identity, task_id, Canceled, ...)`，没有 org 检查。`ipc_task_update` 工具同样无校验（`crates/aos-mcp-gateway/src/lib.rs:1406-1438`）。
- **影响**：跨租户恶意取消（拒绝服务）+ 同 org 内任意 agent 伪造 `completed`/`failed`，这会直接污染 Phase 0 要建的“审计链”和 K7/K8 指标。更严重：一旦 M5 把“任务终态 ⇒ lease 失效”接上，**任意 agent 只要能把别人的任务改成 `canceled`，就能触发对该任务的撤销传播**——把 DoS 升级成“替用户撤销授权”。
- **修复建议**：M2 与 M10 必须同一周完成；状态转移表外还要加 `actor == from_agent || actor == to_agent || actor == operator`，且 `canceled` 只能由 requester/operator 发起（assignee 取消自己的任务应走 `failed(reason)`）。

### P0-3 `LeaseGrant` 的 one-shot 语义是“第一次匹配即删除”，与 PRD 的 AC-2.3/2.5 冲突

- **证据**：`crates/aos-policy/src/lib.rs:162-168` `expires_at_ms == -1` 被当作 one-shot，**在第一次 `check_active_lease` 命中时就 `remove` 并 flush**。也就是说 one-shot 是“消费一次”，不是“永久有效”。`crates/aos-policy/src/lib.rs:497-505` 批准 escalation 时如果 `ttl_secs <= 0` 就生成 `-1` lease；`crates/aos-policy/src/lib.rs:512-521` 敏感提交还会额外塞一条 `expires_at_ms: -1` 的 `workspace_commit` lease。
- **影响**：product.md 的 `AC-2.3`（task 结束后同一操作返回 `Deny(task_terminal)`）在现状下根本不会走到“task 终态检查”——one-shot lease 在第一次成功使用时就被删了，第二次会走 escalation 而不是 `Deny`。`AC-2.5`（lease 不可转移）也无法靠现有 `LeaseGrant` 表达，因为结构体里没有 `task_id`、没有 `issuer`、没有 `audience`。
- **修复建议**：G2 前明确 lease 的三种生命周期：`ttl`（到期失效）、`one_shot`（消费一次）、`task_scoped`（绑定 task，终态失效）。不要复用 `-1` 这个魔法值；新增 `LeaseKind` 枚举。否则 M5 的验收标准写不出来。

### P0-4 撤销传播的“≤2s p95”在现有架构下没有实现路径（且产品把它当承诺）

- **证据**：`crates/aos-policy/src/lib.rs:142-169` 每次 `check_active_lease` 都 `reload_from_disk()`；`crates/aos-ipc/src/lib.rs:74-102` 每次 `get_task`/`update_task_state`/`send` 都整文件 reload + 整文件 flush；`crates/aos-policy/src/lib.rs:444, 459, 474, 533` 同样是 reload-then-write。撤销传播需要同时改 policy（lease）、ipc（task）、memory-server（session，独立 HTTP 服务 + SQLite，`crates/aos-memory-server/src/auth_store.rs:39-44`）三处状态，**没有跨进程事务、没有事件总线、没有协调者**。
- **影响**：`AC-4.1`（≤2s p95，2 lease + 1 claim + 1 session）在“8 进程并发 + 整文件 flush”下大概率超时或部分失败；`AC-4.2` 要求审计里出现 4 类事件，但 `AuditEvent` 目前无 `task_id`（G8），无法证明“这 4 条属于同一次撤销”。K4/K5 会变成永远不达标的指标。
- **修复建议**：要么把 K4 降级为“≤5s p95，且 best-effort”，要么 M3 必须先落地一个**常驻协调者**（single writer daemon）而不是“文件锁 + 原子替换”。文件锁解决的是不丢写，不解决跨三个存储的传播延迟。

## P1（进入实现前必须解决）

### P1-1 4 周计划的依赖图自相矛盾，26 人日被低估

- **证据**：`product.md:366` 写 `#5 → #7`、`#6 → #7`、`#8 → #7`，但 `#7`（撤销传播）又要求 `#5` 的 lease 模型已经重写、`#8` 的 claim 已经绑定 task。`product.md:355-358` 把 `#5 #6 #7 #8` 全放在第 3 周（P0-c），也就是**一周内同时重写 lease 模型、consent 模型、claim 模型，并完成双向传播**。`product.md:383` 自己算的是 26 人日 ≈ 单人 5 周，却又说“砍 #12 与 graph 可压到 4 周”——砍掉 3 人日只够从 5 周压到 4.4 周。
- **影响**：第 3 周必然出现“lease 字段加了但撤销没接上”的半成品，而这正是最危险的状态（用户以为撤销生效了）。
- **修复建议**：把 `#7` 拆成 `#7a`（cancel task ⇒ 撤 lease/release claim，单向）和 `#7b`（revoke session ⇒ task 转 input-required，反向）。Phase 0 只承诺 `#7a` + `#7b` 的“标记 + 下次执行点校验”，不做跨存储事务。`#8` 的 claim 绑定 task 可以后移到 Phase 0 末尾（S 级），因为 claim 是 agent 级也能工作，只是任务死后占 2 小时。

### P1-2 `workspace_id` 粒度是未定义术语，M1/M8 的验收标准不可执行

- **证据**：`product.md:392` 开放问题自己承认“每 agent 一个 CoW vs 每 task 一个”未定；但 `product.md:210` M1 要求“新任务必带 `workspace_id`”，`product.md:217` M8 要求“跨 workspace 读写 Deny”。代码里 workspace 是 PaaS 概念（`crates/aos-mcp-gateway/src/lib.rs:3398-3438` `POST /v1/workspaces`、`bound_ws_id`），而 CoW 影子区是 `<runtime>/orgs/<org>/agents/<agent>/cow_workspace/`（`product.md:89`），两者不是一回事。
- **影响**：builder 会实现一个“逻辑 workspace_id”，但 policy 的 `target_resource` 是路径前缀（`crates/aos-policy/src/lib.rs:262-276` 只做路径前缀匹配），无法把“逻辑 workspace”映射成可强制执行的 Deny。M8 的 AC 会变成“测试里传了个 id，真实路径没校验”。
- **修复建议**：G2 前二选一：(a) `workspace_id = agent CoW 路径的规范化 hash`，跨 workspace 检查复用现有路径前缀匹配；(b) 明确 Phase 0 不做每 task workspace，只记录 `workspace_id` 用于审计，不做强制。不要两个都要。

### P1-3 “不转发 raw token”只覆盖了 A2A 消息体，没覆盖执行点兑换

- **证据**：`product.md:126` 说下游拿到 `lease_id` + task 绑定，“由本地 policy 在执行点兑换”。但 `crates/aos-policy/src/lib.rs:142-160` 的 lease 匹配只看 `org_id + agent_id + action + resource`，**不看调用者是谁、从哪来**。如果 Coder agent 拿到 `lease_id`，它不需要“兑换”——它只要以自己的身份发起 `workspace_commit`，lease 就自动匹配。也就是说 `AC-2.5`（第三 agent 用 lease 被拒）成立，但 `AC-2.1` 的“匹配不到则 Ask”只在 lease 属于别人时成立；**同一 agent 在另一个 task 里可以复用上一个 task 的 lease**，因为 `LeaseGrant` 没有 `task_id`。
- **影响**：task-scoped 的核心承诺“这个任务结束授权就收”在实现前就有一个明显反例：Planner 派两个 task 给同一个 Coder，task A 批准的 `workspace_commit` lease 会被 task B 复用。M5 如果只加字段不加匹配条件，等于没做。
- **修复建议**：`check_active_lease` 的匹配条件必须加 `lease.task_id == ctx.metadata.task_id`（或 `None` 表示非 task-scoped）。`PolicyContext` 需要 `task_id` 字段，且由 gateway 从可信来源注入，不能由 agent 在 `metadata` 里自填（否则 agent 可以填别人的 task_id 来蹭 lease）。

### P1-4 UOMP consent 的撤销语义与“session 继承 task”冲突

- **证据**：`crates/aos-memory-server/src/auth_store.rs:49-59` `sessions` 表无 `org_id`、无 `task_id`；`crates/aos-memory-server/src/server.rs:355-393` `revoke_session` 是 admin-only，且只改 `sessions.status`；`crates/aos-memory-server/src/server.rs:146-160` 每次请求校验 `is_active(session_id)`。`product.md:171` AC-3.3 要求“T 终态 ⇒ session `revoked` 或 `expired`（由策略决定，二者之一）”——但“由策略决定”没有定义哪个策略、谁执行。
- **影响**：如果 Aegis 侧 task 终态要撤 memory session，需要 Aegis 进程持有 memory-server 的 admin token（`check_admin`），这是**跨服务的管理员凭证**，与“不转发 raw token”原则冲突。另一个反例：同一 agent 在同一 task 里先后请求两个 scope，会产生两个 session 还是一个？AC-3.2 要求 task 详情显示 `consents: [...]`，但 `sessions` 表没有 `task_id`，`consent_requests.task_id` 加了也串不起来。
- **修复建议**：G2 前定义“task 如何持有 memory-server 的撤销能力”：推荐 memory-server 新增 `POST /v1/sessions/:id/revoke?task_id=` 且用 **Aegis 签发的 task-scoped token**（不是 admin token）鉴权；`sessions` 表加 `org_id`、`task_id`。否则 M7 的“双向”只能靠轮询，AC-3.4 的“≤5s”无法保证。

### P1-5 K4/K5/K6 是“自证式”指标，且 K5 的 99% 与“best_effort”自相矛盾

- **证据**：`product.md:262-264` K4/K5/K6 的采集方式是“审计事件时间戳差值”“`audit trace` 自检脚本”“审计日志抽样”。如果撤销传播本身有 bug（漏了一个 lease），**审计里也不会出现那条失败事件**，K5 的分母就是错的。`product.md:263` 目标 ≥99% 且“失败必记 `best_effort`”，但 `product.md:184` AC-4.3 允许“下游失联时标记 best_effort 并注明原因”——一个永远返回“成功或 best_effort”的系统，K5 恒为 100%。
- **影响**：这是典型的 vanity metric：安全承诺的兑现程度由被审查的系统自己上报。K6 的“抽样 100 条人工核对”在 4 周 dogfood 里没有定义谁抽、怎么抽、抽不到怎么办。
- **修复建议**：K5 改为“独立校验”：撤销后由**另一个进程**（CLI `audit verify <task_id>`）主动去 policy/ipc/memory 三处查“是否还有活着的关联资源”，而不是读审计事件。K4 的计时起点必须是“用户按下 cancel 的本地时间”，终点是“独立校验确认三处都失效”，不是“审计里出现事件”。

### P1-6 `AUTH_REQUIRED` 映射被研究结论误导：A2A v1.0 的 `AUTH_REQUIRED` 不是 UOMP 审批队列

- **证据**：`research.md:32` E4 正确指出 `AUTH_REQUIRED` 只表示需要授权；但 `research.md:117` 开放问题 6 又问“A2A 的授权请求与 UOMP 的 consent request 是否共用同一个 escalation/审批队列”。这两者语义不同：A2A 的 `AUTH_REQUIRED` 是**任务执行方要求调用方提供凭证**（通常是 OAuth/API key），UOMP 是**用户对记忆访问的同意**。共用队列会让“agent 要求用户提供 GitHub token”和“agent 要求读用户笔记”混在一起，用户无法判断自己在批什么。
- **影响**：如果 product 按这个方向做，审批页会出现“批准后 agent 拿到的是记忆 token 还是第三方凭证”的歧义，直接违反 no-self-approval 的心智模型。
- **修复建议**：research.md 明确写“`AUTH_REQUIRED` 不进入 UOMP 队列；它只映射到 task board 的 `BLOCKED_ON=external_credential`，由用户手动在 agent 侧处理”。把开放问题 6 改成“是否需要为外部凭证单独做审批视图（Phase 1）”。

## P2（可并行/可后移）

### P2-1 A2A v1.0 升级被产品低估、被研究高估，两边都没给出可执行的版本策略

- **证据**：`research.md:14-15` 说 v1.0 是 breaking release，方法名/路径/TaskState 全变；`product.md:233-234` 把 streaming/push 排除，但**没有把“协议版本升级”本身列进 Phase 0 的 Must 或 Won't**。`product.md:210-219` 的 M1-M10 全是 Aegis 内部模型，没有一条是“对外 A2A 接口兼容 v1.0”。`crates/aos-mcp-gateway/src/lib.rs:3067-3069` 同时响应 `agent.json` 和 `agent-card.json`，但 `protocolVersion` 仍是 `0.2.0`（`crates/aos-mcp-gateway/src/lib.rs:3089`），`agent/card` 返回 `google-a2a/0.2`（`crates/aos-mcp-gateway/src/lib.rs:2419`）。
- **影响**：Phase 0 做完后，Aegis 仍然对外宣称 0.2，v1.0 客户端仍然打穿。研究说“升级应是 Phase 0/1 的协议兼容工作”（`research.md:103`），产品却把它悄悄移出了范围——这是**范围与结论脱节**。反过来，如果把 v1.0 升级塞进 Phase 0，M1-M10 全部要重做（task 结构、方法名、错误码），4 周绝对不够。所以研究高估了“Phase 0 能顺手升级”，产品低估了“不升级的对外成本”。
- **修复建议**：G2 必须明确二选一：(a) Phase 0 对外**降级声明**为“A2A 0.2.x 兼容层”，AgentCard 加 `protocolVersion: "0.2.0"` 且文档不宣称 v1.0；(b) 把 v1.0 升级列为 Phase 0.5 的独立 milestone，不混进 M1-M10。推荐 (a)，因为 Phase 0 的用户是本地个人开发者，互操作不是他们的首要痛点。

### P2-2 研究里“事实”与“推断”的边界有 4 处错标

- **证据**：
  1. `research.md:20` 标 `[事实/推断]` 混用，结论“没有人把四件事串成一条链”是**观点**，且没有穷举竞品（未提 Microsoft Agent Framework、Temporal、Dagger 等），不能当事实。
  2. `research.md:18` 说“A2A 规范把授权留给实现，`GetTask`/`ListTasks`/`CancelTask` 必须做访问控制”——这是**规范要求**，但“Aegis 当前缺 actor 校验/org 过滤”是**代码事实**，两者被合并在同一条 `[事实]` 里，读者会以为“规范要求 = Aegis 已违反”，实际 Aegis 违反的是更基础的“同 org 内也无 actor 校验”。
  3. `research.md:41` E13 标“中高（未在本轮逐条抓取原文）”，但正文 `research.md:74` 把它当“明确禁止 token passthrough”使用。**未抓原文就不能用“明确”**。
  4. `research.md:44` E16 说 AutoGen 已归档、推荐 Microsoft Agent Framework 1.0，标“中高（researcher 核实，未附版本号）”——“已归档”是可验证事实，但“1.0”是版本断言，没版本号就不该写。
- **影响**：product.md 直接引用了这些结论（`product.md:72-73` 竞品表、`product.md:268` K10 的“~45–57% 工具调用需确认”来自 README 引论文），但 product 没有复核。K10 的基线“~45–57%”来源是 README 引用的论文，不是 Aegis 自己的数据——用它当基线会误导。
- **修复建议**：research.md 把 E13/E14/E15/E16/E17/E18/E19/E20 统一降级为 `[未验证]` 或补上版本号/URL/日期；`research.md:20` 改为 `[观点]`；K10 基线改为 `TBD-baseline`，不要用论文数字。

### P2-3 `product.md:99` 把 G5 标为 `[推断]` 是错误定级，会误导优先级

- **证据**：`crates/aos-mcp-gateway/src/lib.rs:2482-2500` + `crates/aos-ipc/src/lib.rs:425-428` 已证明 `tasks/get` 无 org 校验；`crates/aos-mcp-gateway/src/lib.rs:3122` 的 `/api/status` 更是直接 `list_tasks(None, None)`。这不是“取决于认证包装层”的推断，是**读代码就能确认的事实**。
- **影响**：PRD 把它列为“Phase 0 必修项，不论严重性最终定级”，但同时又把它放在 M10（1d，可并行）——如果 builder 按“推断”理解，可能先做 M1-M4，把 M10 拖到第 2 周，而这是当前**唯一可直接利用的跨租户漏洞**。
- **修复建议**：`product.md:99` 改为 `[事实]`，M10 提到 P0-a 第一优先级（与 #3 并列），并在 G2 材料里单独写一段“已知可利用漏洞，修复前不建议对外暴露 `/v1/a2a`”。

### P2-4 K1/K2/K9 在 CLI-only + 默认不上报的前提下不可测

- **证据**：`product.md:259` K1“新装用户中 7 天内完成 ≥1 个 A2A task 达终态的比例”——Phase 0 是源码构建 + dogfood 2–3 人（`product.md:315`），没有“新装用户”基数；`product.md:260` K2“从 `aegis-os up` 首次成功到第一个跨 agent task 达终态”——需要埋点，但 `product.md:297` R10 说“默认不上报，dogfood 用人工统计”。人工统计 2–3 人的 K1/K9 没有统计意义。
- **影响**：K1/K2/K9 在 Phase 0 只能是 `TBD`，却写了 ≥40%/≤20min/≥35% 的目标。这会让 dogfood 退出标准里的“K4/K5”看起来达标，而采用类指标是编的。
- **修复建议**：Phase 0 只保留 K4/K5/K6/K7/K8（可本地测量），K1/K2/K9/K10 标 `Phase 1 才有基线`，从 Phase 0 成功标准里移除。

### P2-5 发布策略的退出标准过严（dogfood）与过松（private beta）并存

- **证据**：`product.md:318` dogfood 要求“连续 5 个工作日，每天 ≥2 个跨 agent 任务达终态”——2–3 人团队、4 周内、还要同时做 M1-M10，这个量级不现实；`product.md:320` 要求“8 进程 × 100 任务零丢失”作为退出标准，但 M3 本身才 3d，等于用最终验收标准卡自己的开发进度。反过来，`product.md:342` private beta 的“30 天内无授权越界/跨租户泄漏/撤销失效类安全事故”是**结果指标**，不是可主动验证的门槛——没有红队测试、没有 fuzzing、没有 conformance suite，这个标准只能靠“没听说出事”。
- **影响**：dogfood 会因为“每天 2 个跨 agent 任务”凑不够而延期；private beta 会因为“没出事”而误判安全。
- **修复建议**：dogfood 改为“每周 ≥5 个跨 agent 任务达终态 + 至少 1 次真实撤销演练”；private beta 的退出标准改为“完成 N 次红队场景（跨租户读/取消、伪造 completed、lease 跨 task 复用、撤销竞态）全部通过”，而不是“30 天没事故”。

### P2-6 `aos-cli/routing.rs` 的审批阻断只覆盖 CLI 字符串，不覆盖 MCP 工具名

- **证据**：`crates/aos-cli/src/routing.rs:293-308` 只匹配 `aegis-os policy approve|lease` 等 shell 命令；但 `crates/aos-mcp-gateway/src/lib.rs:2547-2553` 的 `HUMAN_ONLY_TOOLS` 是另一套名单。两套名单没有共享来源，新增工具（比如 Phase 0 的 `a2a cancel`）容易漏。
- **影响**：如果 Phase 0 新增 `aegis-os a2a cancel`，agent 可能通过 shell 调用它来取消任务——而 `routing.rs` 的匹配列表里没有 `a2a cancel`。这会让“撤销只能由人发起”的假设失效。
- **修复建议**：G2 前确认 `a2a cancel` / `a2a approve` 是否在 `routing.rs` 的阻断列表里；如果是，补测试；如果不是，M7 必须加。

## P3（文档/优化）

- **P3-1** `product.md:157` AC-2.2 的静态扫描正则 `ak_live_*` / `aegis_at_*` / JWT 三段 base64 太宽（JWT 正则容易误报普通 base64），且无法覆盖 `$AOS_SECRET_*` 被 agent 拼接后的变体。建议改为“白名单字段 + 负向测试”，不要只靠正则。
- **P3-2** `product.md:143` AC-1.1 要求 board 输出 `last_update`，但 `A2ATask.updated_at_ms` 是毫秒时间戳（`crates/aos-core/src/lib.rs:495`），`age` 与 `last_update` 的时区/格式没定义；`--json` 要求字段与 `tasks/list` 一致（`product.md:147`），但 `tasks/list` 返回的是 `{tasks: [...]}`，board 是行列表，需要明确“一致”指字段名还是结构。
- **P3-3** `product.md:171` AC-3.3 “session 状态为 `revoked` 或 `expired`（由策略决定，二者之一）”是模糊验收——测试无法同时断言两者。建议改为“`revoked`，且 `expires_at` 不变；若自然过期则 `expired` 且审计记 `already_expired`”。
- **P3-4** `research.md:119` 开放问题 8“是否采用 A2A Rust SDK”是 Phase 1 决策，不应阻塞 Phase 0；建议移到 Phase 1 backlog。
- **P3-5** `product.md:383` “砍 #12 与 graph 可压到 4 周”与 26 人日的算术不符（26 - 3 = 23 人日 ≈ 4.6 周单人），需要重算或明确“双人并行”。
- **P3-6** `product.md:268` K10 基线“现状 ~45–57% 工具调用需确认（README 引论文）”应标注“外部论文，非 Aegis 实测”，否则会被当成 Aegis 的现状。

## 对 product.md 的具体修改建议（逐条）

1. **§3 缺口表 G5**：`[推断]` → `[事实]`，证据补 `aos-mcp-gateway/src/lib.rs:3122`（`/api/status` 的 `a2a_tasks`）与 `aos-mcp-gateway/src/lib.rs:1455-1464`（`ipc_task_list` 默认 `scope=all`）。
2. **§6.1 M10**：从“1d 可并行”改为“P0-a 第 1 周，与 #3 并列”；验收加“`/api/status` 与 `aegis://a2a/tasks` 不泄露跨 org task；403/404 不可区分”。
3. **§6.1 M5**：验收补“同一 agent 在 task B 不能复用 task A 的 lease”；`PolicyContext` 增加 `task_id` 且由 gateway 注入。
4. **§6.1 M2**：验收补“`canceled` 只能由 requester/operator 发起；assignee 取消走 `failed`”。
5. **§6.1 M7**：拆成 `#7a`（cancel ⇒ lease/claim）与 `#7b`（revoke session ⇒ task input-required）；`#7b` 依赖 memory-server 的 task-scoped revoke 鉴权（见 P1-4），否则标为 Phase 0 末尾或 Phase 1。
6. **§6.1 M8**：先回答开放问题 2；若选“逻辑 workspace_id + 物理复用 agent CoW”，则 M8 的“跨 workspace Deny”降级为“审计记录 + 文档说明”，不做强制。
7. **§6.1 新增 M0（或把 M10 拆出）**：**A2A 对外版本策略**——Phase 0 明确“0.2.x 兼容层”，AgentCard 与 `/agent/card` 的 `protocol` 字段一致；v1.0 升级单列 Phase 0.5。
8. **§7 指标**：K1/K2/K9/K10 标 `Phase 1 才有基线`，从 Phase 0 成功标准移除；K5 改为“独立校验脚本”而非“审计事件自检”；K4 计时起点改为“用户按下 cancel 的本地时间”。
9. **§8.2 R1**：把“Phase 0 明确承诺边界：停止新授权动作，不含杀进程”从风险表提升到 **§0 定位与 §5 US-4 的显式文案**，并在 `aegis-os a2a cancel` 的 `--help` 与 board 的撤销确认里重复。
10. **§8.3 A4**：`workspace_id` 粒度从开放问题提升为 A4 的前置条件；A4 的 spike 从 2 天改为“先答粒度，再估工期”。
11. **§9 发布策略**：dogfood 退出标准改为“每周 ≥5 个跨 agent 任务 + 1 次撤销演练”；private beta 退出标准改为“红队场景 N 项全过”，删除“30 天无事故”。
12. **§11 估时**：重算 26 人日；明确“单人 5 周”与“4 周”的差距由谁补（砍范围 or 加人），不要用“砍 #12 与 graph”掩盖。
13. **§12 开放问题 1**：从“需要用户拍板”改为“Phase 0 默认承诺停止新授权动作；进程级 suspend 列为 Phase 1”，减少 G2 的阻塞项。
14. **§13 待补块**：`critic` 的 R1/R2/R9 对抗性验证已在本 review 给出部分结论（P0-1/P0-2/P0-4），builder 只需补 `workspace_id` 粒度与 M3 文件锁 spike。

## 对 research.md 的证据修正

1. **§1 结论 1**：v1.0.1/v1.0.0 的日期与“breaking release”需附 CHANGELOG 行号或 commit hash；conductor 已用官方 CHANGELOG/spec 复核，可去掉“未验证”。
2. **§1 结论 5**：拆成两条——`[事实]` 规范要求访问控制；`[事实]` Aegis 缺 actor 校验（`aos-ipc/src/lib.rs:358-386`）；`[事实]` Aegis `tasks/get` 无 org 校验（`aos-mcp-gateway/src/lib.rs:2482-2500`）；`[事实]` `/api/status` 的 `a2a_tasks` 跨 org（`aos-mcp-gateway/src/lib.rs:3122`）。
3. **§1 结论 7**：`[事实/推断]` → `[观点]`；补一句“未穷举 Microsoft Agent Framework、Temporal、Dagger 等，结论仅限本轮对比表”。
4. **E13**：从“明确禁止 token passthrough”改为“MCP 最佳实践建议避免 token passthrough（未逐条抓取原文，标 `[未验证]`）”。
5. **E16**：删除“1.0”版本号，或补 Microsoft Agent Framework 的 release URL；AutoGen 归档状态需附 README 链接。
6. **E17/E18/E19/E20**：补版本号或改为 `[未验证]`；竞品表里对应的“强项”应注明“基于文档摘要，未做功能验证”。
7. **§6 开放问题 6**：改为“`AUTH_REQUIRED` 不映射到 UOMP 队列；只映射到 task board 的 `BLOCKED_ON=external_credential`”，并说明理由（语义不同，共用会混淆审批对象）。
8. **§7 未验证清单**：补“A2A v1.0 与 0.2.x 的完整兼容矩阵”“`tasks/get` 跨租户可利用性已由 critic 验证为事实，不再是未验证”。

## G2 gate 结论

**不通过。**

必须先补：

1. **M10 的证据与定级**：把 G5 从 `[推断]` 改为 `[事实]`，补 `/api/status` 与 `ipc_task_list` 两个泄露面，M10 提到第 1 周 P0。
2. **M5 的 lease 模型**：明确 `ttl` / `one_shot` / `task_scoped` 三种生命周期，废弃 `expires_at_ms == -1` 的魔法值；`PolicyContext.task_id` 由 gateway 注入。
3. **M7 的可行性**：回答“Aegis 如何在不持有 memory-server admin token 的前提下撤销 session”，否则 `#7b` 不能进 Phase 0。
4. **workspace_id 粒度**：二选一并写进 M1/M8 验收，否则 M8 不可测。
5. **A2A 版本策略**：明确 Phase 0 是“0.2.x 兼容层”还是“v1.0 升级”，不能两者都不说。
6. **K4/K5/K6 的口径**：K5 改为独立校验，K1/K2/K9/K10 移出 Phase 0。
7. **4 周计划重算**：26 人日与 4 周的差距必须显式砍范围或加人。

补完这 7 项后，可进入 G2（有条件通过）。当前状态下进入实现，最可能的结果是：第 3 周做出“lease 有 task_id 但撤销只改了记录”的半成品，用户以为撤销生效，实际 agent 仍在写自己的 CoW 区——这正是 R1 描述的场景，而 R1 的缓解措施（“Phase 0 明确承诺边界”）目前只写在风险表里，没有进入产品文案。

## 最可能的失败场景

Phase 0 第 3 周，M5（task-scoped lease）和 M7（撤销传播）同时收尾。`LeaseGrant` 加了 `task_id` 字段，`check_active_lease` 也加了匹配条件，但 `cancel task` 的传播只改了 `ipc_state.json` 里的 task 状态和 policy 的 lease 文件，**没有通知正在运行的 Coder agent 进程**。Coder 在自己的 CoW 工作区里继续执行 `workspace_commit`，`check_active_lease` 因为 `reload_from_disk` 读到 lease 已删而返回 `Ask`——但 `Ask` 会生成新的 escalation，用户看到“又有新的审批请求”，误以为是新任务，点了批准。于是撤销变成了“重新授权”。同时，`audit trace` 因为 `AuditEvent` 还没有 `task_id` 字段（M9 排在第 3 周末），无法把这次“撤销后又批准”串起来。K5 显示 100%（因为审计里只有 `task.canceled` 和 `lease.revoked`，没有“agent 继续执行”的事件），K4 显示 1.8s（因为计时只到“lease 文件删除”）。dogfood 退出标准全绿，但用户的实际体验是“我按了取消，它还在跑，还找我要权限”。

## 我无法验证的部分

- A2A v1.0.1 规范原文、CHANGELOG、release 日期：conductor 已用官方来源复核；critic 原始审查时无法联网。
- MCP security best practices、CSA MAESTRO、Palo Alto/LevelBlue、LangGraph/CrewAI/OpenAI/Claude SDK 的原文与版本号：research.md 自标“未逐页复核”，需要后续补证。
- 未运行 `cargo test` / 压测 / kill -9 恢复测试；P0-3、P0-4 的结论来自代码阅读，不是运行时验证。
- 未审 `aos-sandbox`、`aos-vfs`、`aos-egress` 的完整实现；R9（claim 绕过）只做了路由层阅读，未验证 sandbox 是否真的阻止宿主写入。
- 未验证 `aos-memory-gateway` 的 token 签发/校验细节；P1-4 的“task-scoped revoke 鉴权”是设计建议，不是现状结论。
- 未验证 `aos-cli` 是否已有 `a2a cancel` 子命令（`routing.rs:293` 的匹配列表只覆盖 `policy approve|lease`、`cloud approve|approver`；P2-6 是“待验证”的担忧，不是结论）。
- `workspace_id` 与 PaaS `POST /v1/workspaces` 的 `workspace_id` 是否同一概念，未在代码里找到映射；P1-2 的结论是“术语未定义”，不是“实现冲突”。

---

**给 conductor 的一句话**：不要把这 4 个 P0 当成“Phase 0 要补的功能”，它们是**当前代码里已经存在的漏洞**；G2 材料应单独列一节“已知可利用漏洞与修复前暴露风险”，否则用户会以为 Phase 0 是从零开始建控制平面，而不是在修一个已经有洞的平面。
