# Research — A2A、多 Agent 编排与 Aegis OS 的产品机会

日期：2026-10-30
角色：Researcher（G1）
上游：`.agent/2026-10-30-aegis-multiagent/brief.md`
状态：供 product / critic / conductor 使用；未做最终取舍

标注约定：**[事实]** = 有官方来源或代码可验证；**[推断]** = 由事实推出但未验证；**[观点]** = 研究判断；**[未验证]** = 需要后续确认。

---

## 1. 结论摘要

1. **[事实]** Google A2A 当前发布版是 **v1.0.1（2026-05-26）**，v1.0.0 发布于 **2026-03-12**。v1.0 是 breaking release：方法名、well-known 路径、TaskState、传输绑定都变了。
2. **[事实]** Aegis OS 的 A2A 实现仍是 **0.2.x 风格**：`tasks/send` / `message/send` / `tasks/get` / `tasks/cancel` / `tasks/list`，`AgentCard.version = "0.2.0"`，well-known 仍是 `agent.json`。对外宣称“Google A2A”会被 v1.0 客户端打穿。
3. **[事实]** Aegis 的 A2A 底座并不薄：AgentCard、Task 状态机、peer registry、mailbox、RPC handoff、pub/sub、file claims、`ipc_state.json` 持久化、`POST /v1/a2a`、tenant API key 都已存在。问题不是“没有 A2A”，而是“协议版本落后 + 产品化不足 + 授权没接上”。
4. **[事实]** Aegis 的 AgentCard 声明 `streaming: true` / `pushNotifications: true`，但代码里没有 SSE、`message/stream`、`SubscribeToTask`、push notification config 实现。这是**能力虚标**，属于协议一致性问题。
5. **[事实]** A2A 规范把授权留给实现：`GetTask` / `ListTasks` / `CancelTask` / push config 都必须做访问控制，不能泄露资源存在性。Aegis 当前 `update_task_state` 缺 actor 校验，`tasks/get` / `tasks/list` 缺 org 过滤，是产品层必须补的安全缺口。
6. **[事实]** `ipc_state.json` 是整文件读写，没有文件锁/原子替换；多 Agent 进程并发更新存在 last-writer-wins 和任务丢失风险。
7. **[事实/推断]** 竞品各有强项，但没有人把“本机执行隔离 + task-scoped 授权 + 用户记忆 consent + 审计”串成一条链。LangGraph/CrewAI 强在编排与持久化 HITL；OpenAI/Claude Agent SDK 强在 Agent 原语与工具权限；A2A 强在互操作。Aegis 的差异化应是**控制平面**，不是再做一个编排框架。
8. **[观点]** A2A 是 Aegis OS 多 Agent 并行的协作总线，不是授权协议。Aegis 的产品护城河在“A2A task ↔ policy/lease ↔ UOMP consent ↔ workspace/audit”的关联，而不是 A2A 本身。

---

## 2. 证据表

| # | 事实 | 来源 | 日期 | 置信度 |
|---|---|---|---|---|
| E1 | A2A v1.0.1 发布；v1.0.0 为 breaking release | [A2A CHANGELOG](https://github.com/a2aproject/A2A/blob/main/CHANGELOG.md)、[v1.0.1 release](https://github.com/a2aproject/A2A/releases/tag/v1.0.1) | 2026-05-26 / 2026-03-12 | 高 |
| E2 | v1.0 方法名：`SendMessage`、`SendStreamingMessage`、`GetTask`、`ListTasks`、`CancelTask`、`SubscribeToTask`、push config CRUD、`GetExtendedAgentCard` | [A2A v1.0.1 spec §5.3 Method Mapping](https://github.com/a2aproject/A2A/blob/v1.0.1/docs/specification.md) | 2026-05-26 | 高 |
| E3 | v1.0 well-known 路径为 `/.well-known/agent-card.json`；0.3.0 起从 `agent.json` 改名 | A2A CHANGELOG 0.3.0；v1.0.1 spec §8.6 | 2025-07-30 / 2026-05-26 | 高 |
| E4 | v1.0 TaskState 含 `TASK_STATE_AUTH_REQUIRED`；`AUTH_REQUIRED` 只表示需要授权，不构成授权本身 | v1.0.1 spec §3.1 / §7.6.4 | 2026-05-26 | 高 |
| E5 | AgentCard 支持 JWS 签名（`AgentCardSignature`）；认证在 HTTP 层，身份不进 payload | v1.0.1 spec §7 / §8.4 | 2026-05-26 | 高 |
| E6 | `GetTask` / `ListTasks` / `CancelTask` 必须做授权与资源可见性控制；不能泄露未授权资源存在性 | v1.0.1 spec §13.1 / §3.3.2 | 2026-05-26 | 高 |
| E7 | Aegis AgentCard `version` 硬编码 `0.2.0`；A2A 方法名为 0.2.x 风格 | `crates/aos-core/src/lib.rs:399-417, 566`；`crates/aos-mcp-gateway/src/lib.rs:2407-2538` | 当前代码 | 高 |
| E8 | Aegis AgentCard 宣称 streaming/push，但无 SSE/push 实现 | `crates/aos-mcp-gateway/src/lib.rs:3091-3092`；grep 无 `text/event-stream` / `SubscribeToTask` / push config | 当前代码 | 高 |
| E9 | Aegis `update_task_state` 无 actor/状态机校验 | `crates/aos-ipc/src/lib.rs:358-423` | 当前代码 | 高 |
| E10 | Aegis `get_task` / `list_tasks` 无 org 过滤；gateway `tasks/list` 调 `list_tasks(None, None)` | `crates/aos-ipc/src/lib.rs:425-459`；`crates/aos-mcp-gateway/src/lib.rs:2532` | 当前代码 | 高 |
| E11 | Aegis `ipc_state.json` 全量读写，无锁/原子替换 | `crates/aos-ipc/src/lib.rs:74-102` | 当前代码 | 高 |
| E12 | A2A 的 streaming 使用 SSE；push notification 使用 webhook + `PushNotificationConfig.authentication` | v1.0.1 spec §3.5 / §4.3 | 2026-05-26 | 高 |
| E13 | MCP 安全最佳实践明确禁止 token passthrough，强调 confused deputy、scope 最小化 | MCP security best practices（2025-06-18 / 2025-11-25） | 2025 | 中高（未在本轮逐条抓取原文） |
| E14 | CSA MAESTRO 威胁模型包含 agent 冒充、消息注入、恶意 A2A server 冒充 | CSA MAESTRO | 2025-04-30 | 中（来自 researcher 检索，未逐页复核） |
| E15 | AgentCard context poisoning、shadowing/typosquatting、能力夸大影响路由 | Palo Alto / LevelBlue 分析 | 2025-2026 | 中（未逐页复核） |
| E16 | AutoGen 已归档，官方推荐迁移到 Microsoft Agent Framework 1.0 | AutoGen README | 2026 | 中高（researcher 核实，未附版本号） |
| E17 | LangGraph 用 `interrupt()` + checkpointer + `thread_id` + `Command(resume=...)` 做持久化 HITL | LangGraph 文档 | 2025-2026 | 中高（版本号未验证） |
| E18 | CrewAI 支持 sequential/hierarchical process、manager_agent、checkpoint/replay、max_rpm、stream | CrewAI 文档 | 2025-2026 | 中高（版本号未验证） |
| E19 | OpenAI Agents SDK 提供 Agents / Handoffs / Guardrails；Sandbox agents 的 UnixLocal 在 Linux 无 OS 级隔离 | OpenAI Agents SDK 文档 | 2026 | 中高（researcher 核实） |
| E20 | Claude Agent SDK 提供 Hooks / Subagents / Permissions / Sessions / MCP；权限是工具级 allow/ask | Claude Agent SDK 文档 | 2026 | 中高（researcher 核实） |

---

## 3. 竞品对比

| 产品/框架 | 强项 | 代价/缺口 | 对 Aegis 的启示 |
|---|---|---|---|
| **LangGraph** | 持久化状态、`interrupt()`、checkpointer、`thread_id`、可恢复 HITL；适合长任务与人工审批 | 需要自己写编排；node 重放要求副作用幂等；不提供本机执行隔离/记忆 consent | 审批/恢复语义值得借鉴；Aegis 的 task board 应支持 input-required 与 resume |
| **CrewAI** | sequential/hierarchical、manager_agent、checkpoint/replay、上手快 | 编排表达力偏“角色 + 任务列表”；隔离与授权不是核心 | 角色/任务抽象适合产品语言；不要复制其“框架”定位 |
| **AutoGen** | 多 Agent 对话/协作研究积累 | **已归档**，官方推荐 Microsoft Agent Framework 1.0 | 不要把它当活跃竞品；关注 Microsoft Agent Framework 的 graph + A2A/MCP 互操作 |
| **OpenAI Agents SDK** | Agents / Handoffs / Guardrails / Sandbox agents；原语清晰 | UnixLocal 在 Linux 无 OS 级隔离；无跨 Agent 授权总线 | Handoff 与 guardrail 的产品表达值得借鉴；Aegis 的差异化是“本机隔离 + 用户 consent” |
| **Claude Agent SDK** | Hooks / Subagents / Permissions / Sessions / MCP；工具级 allow/ask | 权限是工具级，不是跨 Agent 任务级；无统一审计链 | 说明“工具权限”已是基线；Aegis 要做“任务级 + 记忆级”授权 |
| **A2A 参考实现** | 跨厂商 Agent 互操作、AgentCard、Task、Artifact | 授权留给实现；不解决本机隔离/记忆 consent | A2A 是协作总线；Aegis 应做“A2A + 控制平面” |

**结论 [观点]**：不要做“又一个编排框架”。Aegis 的定位应是 **A2A 之上的控制平面**：任务可见、权限可管、撤销可传播、审计可回溯。

---

## 4. A2A 安全风险表

| 风险 | 影响 | 协议层能做什么 | Aegis 运行时/产品层必须做什么 |
|---|---|---|---|
| **AgentCard 伪造 / 冒充** | 任务被派给错误 Agent，数据泄露 | JWS 签名、securitySchemes | AgentCard 信任等级、本地 key 管理、跨 org 默认拒绝 |
| **AgentCard 能力夸大 / poisoning** | 路由选中不靠谱 Agent；上下文被污染 | 规范要求卡片准确，但难强制 | 能力验证、conformance 测试、信任评分、用户可见的 Agent 来源 |
| **Task 注入 / 伪造状态更新** | 未授权改任务状态、伪造完成 | 无内建 actor 模型 | 状态机校验 + actor 授权 + append-only 审计 |
| **Token passthrough** | 子 Agent 获得父 Agent 全部权限 | 明确禁止（MCP 最佳实践） | task-scoped lease；A2A 消息不携带 raw token；执行点兑换 |
| **跨租户 task 读取 / 取消** | 跨 org 数据泄露、恶意取消 | 规范要求授权过滤 | `tasks/get`/`list`/`cancel` 强制 org/agent 过滤；403 不泄露存在性 |
| **Artifact 泄露** | 敏感文件/数据被不该看的 Agent 读取 | 无内建 artifact ACL | artifact ACL、保留策略、脱敏、下载审计 |
| **Push webhook SSRF** | 内网探测/打内网服务 | 规范建议 webhook 认证 | 拒绝私网/loopback/link-local；allowlist；签名 |
| **重放 / 重复副作用** | 重复执行任务、重复写文件 | messageId 可用于幂等 | 幂等键、task 去重、副作用审计 |
| **Task 状态持久化竞争** | 任务丢失/状态错乱 | 无规定 | 单写者/文件锁/原子写；崩溃恢复；stale 清理 |
| **远程 A2A 身份伪造** | 跨机器冒充 Agent | securitySchemes | tenant API key、mTLS、短期凭证、审计 |

**关键判断 [观点]**：A2A 规范把授权留给实现，这不是缺陷，而是 Aegis 的机会。Aegis 应该明确说：“A2A 负责协作，Aegis 负责授权、隔离、撤销、审计。”

---

## 5. 对 Aegis OS 的启示

### 事实

- A2A 底座已存在，不需要从零实现。
- A2A 版本落后两代，且能力声明与实现不一致。
- A2A 的 task 授权/租户隔离/状态机校验有明显缺口。
- 现有持久化方案不适合高并发多 Agent。

### 推断

- 如果 Aegis 继续以 0.2.x 对外宣称 A2A，互操作测试会失败，影响采用。
- 如果 A2A task 不与 policy/lease/UOMP consent 关联，Aegis 就只是“另一个多 Agent 消息总线”，差异化不足。
- 如果 task board / 撤销传播做不好，多 Agent 并行仍然是“终端里开三个窗口”的体验。

### 观点

- **A2A 升级应是 Phase 0/1 的协议兼容工作，不是产品主轴。** 产品主轴是控制平面。
- **task-scoped authorization 是 Aegis 的核心差异化。** 不要把它藏在一个“高级设置”里。
- **不要做通用 DAG 调度器。** 做“任务可见 + 边界可批 + 撤销可传播 + 审计可回溯”。
- **AgentCard 应该成为产品界面的一部分**：用户要能看到“这个 Agent 声称会什么、来自哪里、是否可信”。

---

## 6. 开放问题

1. **A2A 版本策略**：Phase 0 直接升 v1.0，还是先做 0.2/1.0 双兼容？升级会影响现有客户端与测试。
2. **streaming/push 是否进入 Phase 0**：建议先置 false + 轮询；但需要确认 board 的刷新体验是否可接受。
3. **AgentCard 信任模型**：本地是否强制签名？跨 org 是否只接受已注册 key？需要产品/安全共同定。
4. **task-scoped lease 的表达力**：一个 task 需要多种 action/resource 时，是“多 lease 绑定 task”还是“task 级 policy scope”？
5. **远程 A2A 的边界**：Phase 1 是否只做同 org 跨机器，还是直接支持跨 org？后者会引入联邦信任与合规问题。
6. **A2A v1.0 的 `AUTH_REQUIRED` 如何映射到 UOMP**：A2A 的授权请求与 UOMP 的 consent request 是否共用同一个 escalation/审批队列？
7. **指标与隐私**：多 Agent 任务的可观测性需要采集 task/agent 元数据；如何做到本地优先、默认不上报？
8. **A2A Rust SDK 成熟度**：是否采用官方/社区 Rust SDK，还是继续自维护协议层？**[未验证]**

---

## 7. 未验证清单

- LangGraph / CrewAI 的具体版本号与发布日期（本轮只核对文档内容）。
- A2A Rust SDK（如 `a2a-lf`）的成熟度与维护状态。
- CSA MAESTRO / Palo Alto / LevelBlue 的具体页码与原文（本轮为 researcher 检索摘要）。
- MCP security best practices 的逐条原文（本轮引用其结论，未逐页抓取）。
- A2A v1.0 与 0.2.x 的完整兼容矩阵（需要 builder 做一次协议差距表）。
