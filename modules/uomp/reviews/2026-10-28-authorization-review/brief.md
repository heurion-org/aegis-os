# Brief — UOMP 授权流程信任审查

- 日期：2026-10-28
- 仓库：`/home/jz/workspace/uomp-mvp` @ `93d1b1f`
- 类型：只读审查（不修改代码）
- 主控：conductor

## 目标

找出 UOMP 本地 CLI 授权流程中，最可能让用户**不敢授权**或**授权后被绕过**的设计与实现问题，并给出可执行的修复优先级。

## 非目标

- 不实现修复
- 不审查官网文案
- 不做完整的协议形式化验证
- 不评价代币/经济模型

## 审查路径

1. `uomp authorize <agent>` 展示授权面板
2. `POST /v1/sessions` 创建会话
3. `POST /v1/sessions/:id/grant` 签发 Capability Token
4. Guard 校验 Token 并过滤读写
5. `uomp revoke <sessionId>` / `close` 撤销
6. 审计日志与删除证明

## 关键文件

- `packages/cli/src/commands/authorize.ts`
- `packages/cli/src/commands/sessions.ts`
- `packages/auth/src/index.ts`
- `packages/guard/src/index.ts`
- `packages/token/src/index.ts`
- `packages/core/src/index.ts`（敏感度推断、Scope 类型）
- `docs/cli-sdk-design.md`
- `README.md`
- 产品意图：`/home/jz/workspace/user-memory-prd.md`、`/home/jz/workspace/UOMP-Draft-00.md`

## 成功标准

- 至少 3 个有代码/文档证据的具体问题
- 每个问题说明：用户会看到什么、实际发生什么、为什么危险
- 修复建议是最小可行改动，不要求重构
- critic 给出明确的发布结论（可以 / 有条件可以 / 不可以）

## 约束

- 只读；不改代码、不提交
- 区分事实与推断；推断标注置信度
- 不把“MVP 限制”当借口跳过安全问题；MVP 也要诚实标注风险
- 产物由主控统一写入 `.agent/2026-10-28-authorization-review/`

## 已知证据

- 仓库没有任何 `*.test.ts`
- Auth 与 Guard 使用独立 SQLite 数据库
- `uomp authorize` 的交互面板只处理 read tags；write scope 固定为空
- `grantSession` 默认签发 30 分钟 token，`limits.maxReadQueries = 100`
