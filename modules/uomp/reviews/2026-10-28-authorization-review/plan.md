# 实现计划 — P0-A / P0-B 授权可信闭环

- 分支：`fix/auth-revocation-integrity`
- 仓库：`/home/jz/workspace/uomp-mvp`
- 约束：最小改动；不提交、不推送；不修改无关文件
- 验收：`pnpm build`、`pnpm -r typecheck`、`node --test tests/integration/*.test.mjs` 全部通过

## 目标

1. **P0-A**：`revoke` / `close` 后，Guard 立即拒绝该会话的 Token；Guard 不再只依赖 JWT 验签。
2. **P0-B**：HTTP 的 `POST /v1/sessions` 与 `/grant` 需要本机管理员令牌；`grant` 不得超出 `requested_scopes`；Gateway 不再跳过这两条路径的鉴权。
3. 用集成测试固定以上行为。

## 非目标

- P0-C（manifest keys 越权）与 P0-D（高敏默认授权）
- 授权面板改版
- `close` / `deletion-proof` 的完整鉴权
- 32 位 token hash 升级为 SHA-256
- 同 UID 恶意进程 / 私钥保护的威胁模型重构

## 改动清单

### 1. `packages/core/src/index.ts`

新增常量：

```ts
export const ADMIN_TOKEN_FILE_NAME = 'admin-token';
```

### 2. `packages/auth/src/admin.ts`（新文件）

- `loadOrCreateAdminToken(secretsDir: string): string`
- 读取 `secretsDir/admin-token`；不存在则用 `randomBytes(32).toString('hex')` 生成
- 写入时使用 `mode: 0o600`，并对已存在文件 `chmod 0o600`
- 从 `packages/auth/src/index.ts` 导出

### 3. `packages/auth/src/index.ts`

**Options**

```ts
export interface AuthServiceOptions {
  dbPath: string;
  issuer: JWTTokenIssuer;
  defaultDurationMinutes?: number;
  adminToken: string;
}
```

**管理员校验**

- 新增 `requireAdmin(c: Context): Response | null`
- 校验请求头 `x-uomp-admin-token`，使用 `crypto.timingSafeEqual`
- token 为空或未配置时 fail closed
- 应用到：
  - `POST /v1/sessions`
  - `POST /v1/sessions/:id/grant`
  - `POST /v1/sessions/:id/revoke`
- 以下路径保持现状，避免破坏 Agent 自主关闭：
  - `POST /v1/sessions/:id/close`
  - `POST /v1/sessions/:id/deletion-proof`

**Scope 子集校验**

新增并导出：

```ts
export function validateGrantedScopes(requested: Scopes, granted: Scopes): string | null
```

规则：

- `granted.read.tags ⊆ requested.read.tags`
- `granted.read.keys ⊆ requested.read.keys`
- `granted.write.tags ⊆ requested.write.tags`
- `granted.write.keys ⊆ requested.write.keys`
- `granted.denyTags ⊇ requested.denyTags`（不能移除限制）
- `granted.denyKeys ⊇ requested.denyKeys`
- 任一不满足返回可读错误；全部满足返回 `null`

在 `POST /v1/sessions/:id/grant` 中，先读取 session 并校验，再调用 `grantSession`。不满足返回 `400 SCOPE_EXCEEDS_REQUEST`。

### 4. `packages/guard/src/index.ts`

新增接口：

```ts
export interface GuardSessionState {
  status: string;
  expiresAt: string;
}

export interface SessionStateProvider {
  getSession(sessionId: string): GuardSessionState | null;
  isTokenBlacklisted(sessionId: string): boolean;
}
```

`GuardOptions` 新增可选 `sessionStateProvider?: SessionStateProvider`。

`validateRequest` 在 JWT 验签与过期检查之后：

1. 若没有 provider：返回 `503 SESSION_VALIDATION_UNAVAILABLE`（fail closed）
2. `getSession(sessionId)` 为空：`403 SESSION_NOT_FOUND`
3. `status !== 'active'`：`403 SESSION_NOT_ACTIVE`
4. `isTokenBlacklisted(sessionId)`：`403 TOKEN_REVOKED`

保留现有返回结构，带 `sessionId` / `agentId` 以便审计。

### 5. `packages/cli/src/config.ts`

- 新增 `adminToken: string`（`init()` 中通过 `loadOrCreateAdminToken` 加载）
- 所有构造 `AuthService` 的地方传入 `adminToken: config.adminToken`

涉及：

- `packages/cli/src/commands/authorize.ts`
- `packages/cli/src/commands/run.ts`
- `packages/cli/src/commands/sessions.ts`

`audit.ts` 不构造 `AuthService`，无需改动；但它构造的 `MemoryGuard` 不提供 provider 也可，因为只直接调用 `getAuditLogs`，不走 HTTP。

### 6. `apps/server/src/index.ts`

- 加载 `loadOrCreateAdminToken(secretsDir)`
- `AuthService` 传入 `adminToken`
- `MemoryGuard` 传入 `sessionStateProvider: authService`

### 7. `apps/gateway/src/index.ts`

删除 token 中间件中的两条跳过规则：

```ts
if (c.req.path === '/v1/sessions' && c.req.method === 'POST') return next();
if (c.req.path.startsWith('/v1/sessions/') && c.req.path.endsWith('/grant') && c.req.method === 'POST') return next();
```

远程 Agent 不应创建/授予会话；授权由本机 CLI 完成。

### 8. `packages/sdk/src/auth.ts`

- `AuthClient` 支持管理员令牌：构造时读取 `process.env.UOMP_ADMIN_TOKEN`（浏览器环境用 `typeof process` 保护）
- 提供 `setAdminToken(token: string)`
- `createSession` / `grant` / `revoke` 请求带 `x-uomp-admin-token`
- `close` / `validate` 不带

不要求改 `UompClient` 构造签名。

### 9. `tests/integration/auth-integrity.test.mjs`（新文件）

使用 Node 内置 `node:test` + `assert/strict`，导入已构建的 `dist`。

测试用例：

1. **revoke 后立即失效**
   - 创建 AuthService + MemoryGuard + MemoryStore
   - 创建 session、grant、写入一条低敏感 memory
   - 带 token 请求 `/v1/memory/:key` → 200
   - `auth.revokeSession()` 后同一请求 → 403
2. **未激活会话的伪造 token 被拒**
   - 只创建 session、不 grant
   - 用 issuer 手动签一个合法 JWT
   - Guard 请求 → 403 `SESSION_NOT_ACTIVE`
3. **create 无管理员令牌被拒**
   - 直接对 `auth.getApp()` 发 `POST /v1/sessions`，不带 `x-uomp-admin-token` → 401
4. **grant 超出 requested scope 被拒**
   - 带管理员令牌创建 session（requested tags `['portfolio']`）
   - grant 带 `['portfolio','secrets']` → 400 `SCOPE_EXCEEDS_REQUEST`
   - grant 带 `['portfolio']` → 200

测试用临时目录（`mkdtempSync`）并在 `t.after` 清理。

### 10. 根 `package.json`

```json
"test": "pnpm build && node --test tests/integration/*.test.mjs",
"test:integration": "node --test tests/integration/*.test.mjs"
```

## 验收命令

```bash
cd /home/jz/workspace/uomp-mvp
pnpm build
pnpm -r typecheck
node --test tests/integration/*.test.mjs
```

## 风险与注意

- `AuthServiceOptions.adminToken` 变为必填；所有构造点必须更新，否则编译失败（这是有意的）
- `loadOrCreateAdminToken` 使用同步 fs，仅在本机初始化时调用
- Gateway 去掉跳过规则后，远程 `create/grant` 会返回 401；这是预期行为
- Guard 没有 provider 时 fail closed；`audit` 命令只直接读日志，不受影响
- 测试导入 `dist`，因此必须先 build
- 不要修改 `.agent/` 下的审查产物
