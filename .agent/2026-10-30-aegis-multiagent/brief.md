# Brief — Aegis OS 多 Agent 控制平面（Phase 0）

日期：2026-10-30
状态：G0 已定框，进入 G1（研究 + 产品并行）

## 1. 背景

- **Aegis OS 是产品**：本地 Agent 控制平面，负责多 Agent 的隔离、权限、协作、审计与生命周期。
- **UOMP 是 Aegis Memory 的协议层**：定义 Agent 如何请求、获得、撤销对用户记忆的访问；不是独立产品。
- **A2A 已经在 Aegis OS 中实现**：AgentCard、A2ATask 生命周期、peer registry、mailbox、RPC handoff、pub/sub、file claims、`POST /v1/a2a`、tenant API key。
- 当前产品主线：让用户安全地让多个 Agent 访问文件、凭证和记忆；A2A 负责 Agent 间协作，UOMP 负责记忆同意，Policy/Lease 负责统一授权，Sandbox/CoW 负责执行隔离。

## 2. 本次团队任务

为 Aegis OS 的“多 Agent 控制平面”形成可执行的 Phase 0 方案，并明确 A2A、UOMP、Policy/Lease 的集成边界。

本轮先完成 G1–G2，不直接改代码：

1. **研究**：Google A2A 规范现状、多 Agent 编排/授权先例、竞品做法、A2A 协议一致性与安全风险。
2. **产品**：PRD-lite，明确 ICP、核心用户故事、Phase 0 范围、验收标准、成功指标、非目标。
3. **技术方向**：A2A task 与 UOMP consent / policy lease / workspace / audit 的关联模型；task-scoped authorization；不转发 raw token。
4. **审查**：critic 对研究、产品、技术方向做对抗性审查，给出 P0–P3。
5. **收敛**：conductor 写 decision.md，形成 Phase 0 backlog；等用户确认后再进入 G3 实现。

## 3. 目标用户与场景（假设，待产品验证）

- 主要 ICP：同时运行 2+ 个 coding agent 的个人开发者 / power user（Claude Code、Codex、Cursor、OpenCode）。
- 次级 ICP：需要 Agent 治理、审计、权限边界的团队。
- 核心场景：
  1. Planner Agent 通过 A2A 把任务委派给 Coder / Reviewer / Tester。
  2. 每个 Agent 在独立 CoW workspace 执行，文件 claim 防止冲突。
  3. Agent 在任务中请求用户记忆；UOMP consent 绑定 task_id。
  4. 用户能看到 task graph、谁在读什么、谁批准了什么。
  5. 撤销 task 或 memory session 后，相关 Agent 立即停止访问。
  6. 审计能串起 task → agent → session → consent → workspace commit。

## 4. 约束

- 主仓库：`/home/jz/workspace/aegis-os`
- 网站/规范：`/home/jz/workspace/uomp`（website/spec only）
- 只保留 `aegis-os` 和 `uomp` 两个活跃 UOMP 相关仓库；`uomp-core` 已归档。
- 不支持 Windows。
- 不破坏现有 UOMP consent / no-agent-self-approval 原则。
- 不把 A2A 当作授权协议；A2A 不能传递 raw bearer token。
- 不在本轮做定价、对外发布、破坏性协议变更。
- 不直接提交/部署；实现需用户确认（G2/G5）。

## 5. 成功标准

- `research.md`：有来源、有置信度、区分事实/推断/观点。
- `product.md`：PRD-lite，包含用户故事、Phase 0 范围、验收标准、指标、非目标。
- `review.md`：P0–P3 风险，明确是否可进入实现。
- `decision.md`：Phase 0 backlog、优先级、依赖、风险、待用户确认项。
- 用户能用这份材料直接开 GitHub issues / milestone。

## 6. 非目标

- 不做完整 A2A conformance suite（本轮只定方向）。
- 不做 Aegis Cloud 商业方案。
- 不做浏览器 consent UI 的完整实现。
- 不修改代码、不提交、不部署。
