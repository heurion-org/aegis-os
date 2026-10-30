# UOMP SDK & CLI 优化方案 v2 — ✅ 已完成

> 全部 4 个 Phase 已实现。净删 102 行，CLI 和 SDK 边界清晰。

---

## 1. 分工边界

```
@uomp/core              ← 类型 + 工具（两方共享）
    ├── CLI ──► AuthService + Guard + Store（进程内 SQLite）
    └── SDK ──► Transport (HTTP) ──► Gateway ──► Guard ──► Store
                       ↑
                Agent / Browser 都用这一套
```

| 层 | CLI 用什么 | SDK 用什么 | 共享什么 |
|------|-----------|-----------|---------|
| 类型 | `@uomp/core` | `@uomp/core` | ✅ 已共享 |
| 工具函数 | 自写（重复） | ❌ 缺失 | ← **移到 core** |
| 数据读写 | `MemoryStore` (SQLite) | `MemoryClient` (HTTP) | 各自独立 |
| 认证 | `AuthService` (进程内) | `AuthClient` (HTTP) | 各自独立 |
| Guard | `MemoryGuard` (进程内) | `MemoryClient` 接收过滤结果 | 各自独立 |

---

## 2. 四个 Phase

### Phase 1：去重 — 共享工具移到 @uomp/core

| # | 做什么 | 改哪里 |
|---|--------|--------|
| 1 | `inferSensitivity()` 移到 core（3 处重复 → 1 处） | `packages/core/src/index.ts` |
| 2 | `loadManifest()`、`normalizeManifest()`、类型定义移到 core（CLI utils + run.ts 两处重复 → 1 处） | `packages/core` |
| 3 | CLI 改用 `@uomp/core` 的版本，删掉本地重复 | 3 个命令文件 + utils/manifest.ts |
| 4 | SDK 导出这些工具函数（Agent 开发者也需要加载 manifest） | `packages/sdk/src/index.ts` |

### Phase 2：SDK 补全 — Agent/浏览器场景

| # | 做什么 | 改哪里 |
|---|--------|--------|
| 5 | `MemoryClient` 增加 `set()`、`delete()` | `packages/sdk/src/memory.ts` |
| 6 | `BrowserSDK.fromWallet()` 接入 PBKDF2 密钥推导（从 dashboard/sdk.js 移植） | `packages/sdk/src/browser.ts` |
| 7 | `BrowserSDK.fromSeedPhrase()` 实现 | 同上 |
| 8 | SDK package.json 增加 `"./browser"` export | `packages/sdk/package.json` |

### Phase 3：CLI 清理

| # | 做什么 | 改哪里 |
|---|--------|--------|
| 9 | 删除 `commands/session.ts`（死代码，从未被 import） | 删除文件 |
| 10 | 删除 `commands/run.ts` 里的重复 `loadManifest`/`normalizeManifest` | `commands/run.ts` |

### Phase 4：Dashboard 用 SDK bundle

| # | 做什么 | 改哪里 |
|---|--------|--------|
| 11 | Dashboard 用 `<script type="module">` import SDK bundle | `public/dashboard/index.html` |
| 12 | 删除 dashboard 内联的 `UompGateway` 类 | 同上 |

---

## 3. 改动量

| Phase | 增 | 删 | 净 |
|-------|----|----|-----|
| 1 | +40 | -60 | -20 |
| 2 | +80 | -5 | +75 |
| 3 | 0 | -80 | -80 |
| 4 | +10 | -40 | -30 |
| **合计** | **+130** | **-185** | **-55** |

净删 55 行，质量提升明显。

---

## 4. 不改的部分

| 保留 | 原因 |
|------|------|
| CLI 直接 import AuthService/Guard/Store | 进程内调用，不适合走 HTTP SDK |
| `apps/gateway`、`apps/relay`、`apps/server` | 功能完整 |
| `UserMemory` 兼容类 | 向后兼容 |
| StoreRouter 独立实现 | 后续重构（Phase 5，暂不包含） |
