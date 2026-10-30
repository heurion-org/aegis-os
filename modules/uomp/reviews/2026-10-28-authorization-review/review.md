# 对抗性审查 — UOMP 本地 CLI 授权链路

- 角色：critic
- 仓库：`/home/jz/workspace/uomp-mvp` @ `93d1b1f`
- 类型：只读静态审查，未运行代码
- 缩写：`guard`=`packages/guard/src/index.ts`，`auth`=`packages/auth/src/index.ts`，`token`=`packages/token/src/index.ts`，`authorize`=`packages/cli/src/commands/authorize.ts`，`cli`=`packages/cli/src/cli.ts`，`sessions`=`packages/cli/src/commands/sessions.ts`

## 结论

**是否可发布：不可以。**

最可能的失败场景：用户发现 Agent 行为异常后执行 `uomp revoke`，CLI 显示成功；但 Guard 从不检查黑名单/会话状态，Agent 继续读取至 Token 过期。更糟的是，同机进程可自行调用未认证的 create/grant 重新签一个含全部高敏 key 的 Token，甚至直接读 `~/.uomp/memory.db` 或签名私钥；用户界面看不到任何异常。

---

## P0（阻断发布）

### 1. 撤销后 Token 仍有效

**证据**

- `guard:269-289` 的 `validateRequest` 只验签和 `exp`，不查黑名单/会话状态
- `auth:315-318` 的黑名单仅供 `/v1/tokens/validate` 使用
- `config:31-33` 显示 Auth 与 Guard 使用独立数据库
- `specs/draft-00.md:550` 明确要求 Guard 每次请求检查黑名单

**影响**：`uomp revoke` 返回成功，Agent 仍可读取至 Token 过期（默认 30 分钟），用户被“已撤销”误导。

**最小修复**：Guard 每次请求读取 auth.db 的 session 状态和 Token 黑名单；会话非 `active` 一律 403。若 Guard 不能访问 auth.db，Auth 必须提供本地 introspection 接口。

### 2. 未认证的 create/grant 可自签任意权限

**证据**

- `auth:98-139` 的 `/v1/sessions` 与 `/v1/sessions/:id/grant` 无鉴权
- `grantSession` 接受任意 `granted_scopes`，不校验是否为 requested 子集（`auth:239-273`）
- `authorize:229-232` 把 Auth 与 Guard 路由合并暴露在 `127.0.0.1:9374`
- `apps/gateway/src/index.ts:175-176` 显式跳过这两条路径的鉴权

**影响**：同机任意进程/Agent 可 `POST /v1/sessions` 后 grant 全部 tag/key，完全绕过授权面板；Gateway 暴露时远程同样可签。

**最小修复**：grant 需用户在场的一次性 nonce/本机确认；校验 `granted ⊆ requested`；Gateway 不代理 create/grant。

### 3. 取消勾选 tag 仍保留 manifest keys

**证据**

- `authorize:166-171,187-193` 无条件带入 `manifest.requestedScopes.read.keys`
- `guard:301-306` 先查 `scope.keys`，命中即放行，早于 tag/denyTags 判断

**影响**：恶意 manifest 可列出高敏 key；用户取消所有 tag，Token 仍能读这些 key，`denyTags` 也挡不住。

**最小修复**：keys 仅来自用户逐项确认，或与选中 tags 求交；不得从 manifest 自动继承。

### 4. 高敏 key 批量自动授权且默认全选

**证据**

- `authorize:206-218` 对一个高敏 tag 自动加入该 tag 下所有现有 key
- 面板只显示 fields/purpose（`authorize:143-151`），不显示 key
- checkbox 默认勾选全部 requested tags（`authorize:155-162`）
- 文档承诺高敏需显式确认（`docs/cli-sdk-design.md:334,516`），`:621` 又承认自动收集

**影响**：一次回车即授权全部高敏 key，与“key 级授权”宣传不符。

**最小修复**：高敏默认不勾选；逐 key/字段确认并显示 key 清单。

---

## P1（发布前必须修）

### 5. audience / profile / limits 均未真正校验

**证据**：`token:103-105` 仅显式校验 EdDSA，无 issuer/audience；`audience` 是自定义 claim 而非标准 `aud`；`auth:250-264` 写入 `profile`、`limits.maxReadQueries=100`，但全仓库无计数器；`allowedEndpoints` 仅 Gateway 检查。

**影响**：为 Gateway/remote 签发的 Token 可重放到本地 Guard；100 次查询上限不存在。

**修复**：签发/校验标准 `aud`/`iss`；Guard 校验 profile 与 audience；限流原子计数，或删除未实现 claims。

### 6. allowedFields 可被聚合查询绕过

**证据**：`guard:71-117` 仅按 tag/key 过滤 item，然后按请求的 `field` 路径聚合；`allowedFields` 只在单条/列表序列化时使用（`guard:337-357`）。

**影响**：仅允许 `symbol` 的 Token 可请求 `avg field=value.cost_basis` 反推成本价。

**修复**：聚合字段也受 `allowedFields` 约束，或先序列化再聚合。

### 7. 删除证明没有验证任何删除

**证据**：`auth:175-200` 只核对 `session_id` 与路径一致，就把 session 置 `closed` 并返回 `accepted`；不验签、不重算 hash、不查 store，也不写黑名单。SDK 的 `proof_value` 只是访问 key 名的自哈希（`packages/sdk/src/session.ts:27-30,39-56`）。

**影响**：任何人可伪造“已删除”证明并关闭任意已知 session；README:602 的“删除证明”名不副实。

**修复**：要求有效 Token 和签名 proof，由 Guard 验证实际删除记录；否则明确标为 self-attestation。

### 8. 审计可越权读取、归属可伪造

**证据**：`guard:242-261` 任意有效 Token 可传任意 `session_id` 读取日志，只对可选的 `agent_id` 比对；`auth:27-31` 的 `agent_id` 由调用方自报；没有 create/grant/revoke 审计事件。

**影响**：知道 session id 即可读他人访问记录；攻击者可创建“受害者 agent”会话，审计日志错误归因，无法用于追责。

**修复**：session 必须属于当前 Token；agent_id 从已验证 manifest 派生；记录授权事件并做防篡改。

---

## P2（应修，可排期）

### 9. 同 UID 本地进程可完全绕过授权

**证据**：私钥明文存于 `~/.uomp/.secrets`（`token:54-69`），memory/audit DB 同目录（`config:30-33`）；同用户 Agent 可直接读私钥伪造任意 Token，或直接读/改数据库。

**影响**：Guard 的 scope 只对“守规矩的 Agent”有效；若威胁模型包含恶意 Agent，全部 P0 仍可被绕过。

**修复**：Agent 独立 UID/沙箱、库加密；至少明确威胁模型。文件实际权限未实测。

### 10. 未认证 close/revoke + 健壮性 + hash/竞态

**证据**：`auth:141-157` 任何人可关闭/撤销已知 session；`guard:140-156` 当 key 在 allowlist 但 item 不存在时 `serializeItem(item!)` 返回 500；`auth:327-336` 使用 32 位 JS hash，碰撞可使 `INSERT OR IGNORE` 跳过黑名单行；`auth:239-276` 先查后写无事务，并发可各发一个 Token、只存最后一个 hash。

**影响**：本地 DoS、撤销完整性弱、并发下多 Token。

**修复**：认证 close/revoke；存在性检查；改用 SHA-256；`UPDATE ... WHERE status='created'` 原子化。

### 11. GPG 身份“验证”是假阳性

**证据**：`identity/index.ts:70-80` 只要 `proofValue` 非空就返回 valid；`authorize:56-60` 打印绿色 “Identity verified via gpg”。

**影响**：用户基于虚假身份信号授权高敏数据。

**修复**：实现真实签名验证，或移除该绿色提示。

---

## P3

### 12. `--scope` 与非交互模式语义误导

**证据**：`cli:76` 称 “Additional”，`authorize:65-67` 却只用它替换 manifest tags 并跳过面板；`--duration` 的 `parseInt` 不校验 NaN/0/负数（`authorize:70`）。

**影响**：脚本授权会静默改变范围；非法时长产生无效或已过期 Token。

**修复**：改为 union 语义；校验时长范围；非交互模式也打印授权摘要。

---

## 未能验证的部分

未运行命令或测试（仓库无 `*.test.ts`，本次只读且 shell 被拒）。以下均未实测：HTTP 实际行为、文件权限、浏览器 CSRF/PNA、SQLite 并发、Gateway/Relay 部署。

P0 1–4 与 P1 5–8 由静态代码确定；P2 9 的实际权限与攻击可行性待验证；DID/GPG 外部解析未验证。
