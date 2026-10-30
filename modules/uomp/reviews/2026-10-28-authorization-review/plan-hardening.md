# 加固计划 — 第一轮复审后的收尾

- 分支：`fix/auth-revocation-integrity`
- 目标：修掉 critic 的 P1-1 与关键 P2，不扩大功能范围
- 验收：build、typecheck、集成测试全绿

## 1. 更新测试脚本（P1）

`scripts/test-gateway-remote.sh` 与 `scripts/test-stock-analyst.sh` 里的 `POST /v1/sessions` 和 `/grant` 现在需要管理员令牌。

两个脚本都加：

```bash
ADMIN_TOKEN_FILE="${UOMP_ADMIN_TOKEN_FILE:-$HOME/.uomp/.secrets/admin-token}"
ADMIN_TOKEN="$(cat "$ADMIN_TOKEN_FILE" 2>/dev/null || true)"
if [ -z "$ADMIN_TOKEN" ]; then
  echo "Admin token not found at $ADMIN_TOKEN_FILE" >&2
  exit 1
fi
```

并在 create/grant 的 curl 中加：

```bash
-H "x-uomp-admin-token: $ADMIN_TOKEN"
```

`close` 不需要管理员令牌，保持现状。

## 2. 并发状态竞态（P2）

`packages/auth/src/index.ts`

- `grantSession` 的最终 UPDATE 加状态条件：

```sql
UPDATE sessions SET status='active', granted_scopes=?, token_hash=?
WHERE session_id=? AND status='created'
```

检查 `changes === 1`，否则返回 `null`。

- `closeSession`：
  - 若当前已是 `revoked`，直接返回当前记录，不降级为 `closed`
  - UPDATE 加 `AND status IN ('created','active')`
  - 若 `changes===0`，重新读取并返回当前状态

- `revokeSession`：
  - 若当前已是 `revoked`，直接返回当前记录
  - UPDATE 加 `AND status != 'revoked'`

## 3. 字段级子集（P2）

`packages/auth/src/index.ts`

新增并导出：

```ts
export function validateGrantedFields(requested: Scopes, granted?: string[]): string | null
```

规则：

- 若 `requested.read.allowedFields` 为空/未定义：返回 `null`
- 若 requested 有字段限制，而 granted 缺失或为空：返回错误
- granted 中出现 requested 之外的字段：返回错误

在 grant 路由的 scope 校验之后调用；失败返回 `400 SCOPE_EXCEEDS_REQUEST`。

## 4. 输入形状校验（P2）

`packages/auth/src/index.ts`

用 zod 结构化 schema 替换 `z.custom<Scopes>()`：

```ts
const scopeActionSchema = z.object({
  tags: z.array(z.string()).default([]),
  keys: z.array(z.string()).default([]),
  denyTags: z.array(z.string()).default([]),
  denyKeys: z.array(z.string()).default([]),
  allowedFields: z.array(z.string()).optional(),
  fields: z.record(z.array(z.string())).optional(),
  purposes: z.record(z.string()).optional(),
});

const scopesSchema = z.object({
  read: scopeActionSchema,
  write: scopeActionSchema,
});
```

用于 `createSessionSchema.requested_scopes` 与 `grantSessionSchema.granted_scopes`。

## 5. 管理员令牌文件原子创建（P2）

`packages/auth/src/admin.ts`

- `mkdirSync` 后再尝试 `writeFileSync(path, token, { mode: 0o600, flag: 'wx' })`
- `EEXIST` 时 `chmodSync 0600` 并读取
- 读到空内容时抛出明确错误，不静默轮换
- 其他写入错误继续抛出

## 6. 浏览器环境不读 env（P2）

`packages/sdk/src/auth.ts`

```ts
const isNodeRuntime = typeof process !== 'undefined' && typeof process.versions?.node === 'string';
this.adminToken = isNodeRuntime ? process.env?.UOMP_ADMIN_TOKEN ?? '' : '';
```

加一行注释说明浏览器端不应执行管理员操作。

## 7. 补测试（P2）

`tests/integration/auth-integrity.test.mjs` 增加：

1. **错误管理员令牌被拒**：`x-uomp-admin-token: wrong` → 401
2. **HTTP revoke 需要管理员令牌，且撤销后 Guard 403**
   - 无 header → 401
   - 带正确 header → 200
   - 原 token 请求 → 403
3. **denyTags 不能移除**：requested 有 `denyTags:['secrets']`，granted `[]` → 400
4. **write scope 不能超出**：requested write 为空，granted write tags `['x']` → 400
5. **admin token 文件稳定且 0600**：
   - `loadOrCreateAdminToken(dir)` 两次返回相同值
   - `statSync(path).mode & 0o777 === 0o600`

## 验收

```bash
cd /home/jz/workspace/uomp-mvp
pnpm build
pnpm -r typecheck
node --test tests/integration/*.test.mjs
```

## 不做

- P0-C/P0-D
- close/deletion-proof 的完整鉴权
- 同 UID 威胁模型
- 文档大改（脚本修好即可；README 说明留到下一轮）
