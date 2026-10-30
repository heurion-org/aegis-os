# UOMP Store 抽象化设计文档

> 状态：Phase 1-4 全部完成 ✅ Dashboard 已上线 ✅ SDK 优化完成
> 实现进度：✅ IMemoryStore 接口 ✅ AsyncStoreAdapter ✅ Guard 集成 ✅ EncryptedObjectStore (S3) ✅ 浏览器 localStorage 加密存储

---

## 1. 动机

| 问题 | 现状 | 目标 |
|------|------|------|
| 多设备访问 | SQLite 绑定单机文件系统，换电脑 = 数据丢失 | 同一份数据，任意设备可访问 |
| 浏览器模式 | 浏览器无法读 `~/.uomp/memory.db` | 浏览器通过 Gateway → API → Store 后端 |
| 数据主权 | 已满足（数据在本地） | 扩展到云端时保持 E2E 加密 |
| 同步复杂度 | 用户手动 Dropbox/Syncthing 同步 SQLite | 内置同步，无需第三方 |


## 2. 架构

```
                        Guard (不变)
                           │
                    ┌──────┴──────┐
                    │ Store API   │  ← 抽象层（新增）
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────┴─────┐     ┌──────┴──────┐    ┌──────┴──────┐
   │ SQLite   │     │ Encrypted   │    │  IPFS       │
   │ (本地)   │     │ Object      │    │  (去中心化) │
   │ 文件系统 │     │ S3/R2/B2    │    │             │
   └──────────┘     └─────────────┘    └─────────────┘
        │                  │                  │
   ~/.uomp/          s3://bucket/        ipfs://cid
   memory.db         encrypted blobs     content-addressed
```

### 核心原则

1. **Guard 不感知后端**——只调用 Store API
2. **加密在 Guard 层完成**——后端不知道明文
3. **用户持有密钥**——通过 seed phrase 在多设备间共享
4. **本地 SQLite 永远是默认**——`uomp init` 不改变现有体验


## 3. Store API

```ts
// packages/store/src/types.ts
export interface IMemoryStore {
  // Connection
  connect(config: StoreConfig): Promise<void>;
  disconnect(): Promise<void>;

  // CRUD
  get<T = unknown>(key: string): Promise<MemoryItem<T> | null>;
  getByTag<T = unknown>(tag: string): Promise<MemoryItem<T>[]>;
  getAll<T = unknown>(): Promise<MemoryItem<T>[]>;
  set<T = unknown>(item: Omit<MemoryItem<T>, 'createdAt' | 'updatedAt'> & Partial<Pick<MemoryItem<T>, 'createdAt' | 'updatedAt'>>): Promise<boolean>;
  delete(key: string): Promise<boolean>;

  // Metadata
  listTags(): Promise<string[]>;
  count(): Promise<number>;
  stats(): Promise<StoreStats>;

  // Backend info
  readonly backend: string;
  readonly isReady: boolean;
}

export interface StoreConfig {
  backend: 'sqlite' | 'encrypted-object' | 'ipfs';
  sqlite?: { dbPath: string };
  s3?: {
    endpoint: string;
    bucket: string;
    region: string;
    accessKeyId: string;
    secretAccessKey: string;
  };
  ipfs?: { gateway: string };
  encryption?: {
    enabled: boolean;
    keyId?: string;
  };
}

export interface StoreStats {
  itemCount: number;
  totalSizeBytes: number;
  backend: string;
  encryptionEnabled: boolean;
}
```

### 与现有 MemoryStore 的关系

现有 `MemoryStore` 类（`packages/store/src/index.ts`）实现 `IMemoryStore` 接口。SQLite 版本保持不变，新增 `EncryptedObjectStore` 和 `IPFSStore`。


## 4. 加密对象存储后端

### 数据布局

```
s3://uomp-data/user-abc123/
├── meta.json           # 加密（store metadata）
├── items/
│   ├── AAPL           # 加密（单个 Memory Item）
│   ├── TSLA           # 加密
│   └── NVDA           # 加密
├── tags/
│   ├── portfolio:holdings → ["AAPL", "TSLA", "NVDA"]  # 加密
│   └── profile:risk → ["user-risk-profile"]            # 加密
└── index.json         # 加密（item key → blob key 映射）
```

### 加密方案

```
Item 明文 → AES-256-GCM → ciphertext + nonce + tag
                    ↑
           ItemKey = HKDF(masterKey, item.key)
                    ↑
           masterKey = 用户的 Ed25519 seed 派生
```

- 每个 item 独立加密（独立 nonce，独立 key derivation）
- `tags/` 索引也加密（tag 名称是明文的，但内容是加密的 key 列表）
- `meta.json` 存后端配置、schema version、加密参数

### 查询流程

```ts
// GET /v1/memory?tag=portfolio:holdings
// →
// 1. 读 tags/portfolio:holdings（解密 → 得到 key 列表）
// 2. 并发读 items/AAPL, items/TSLA, items/NVDA（解密）
// 3. 返回明文 MemoryItem[]
```

写回 Index 缓存优化：Guard 内存缓存 tag→keys 映射，避免每次读 tags/ 对象。


## 5. 密钥管理（Wallet-Authenticated + Seed Phrase 备用）

用户身份不依赖 UOMP 自己生成的 seed phrase，而是**通过用户已有的钱包签名**派生密钥。

### 5.1 钱包支持矩阵

| 钱包 | 平台 | 签名方法 | 优先级 |
|------|------|---------|--------|
| **MetaMask** | Browser Extension | `personal_sign` (EIP-1193) | P0 |
| **Argent X** | Browser Extension | `starknet_signMessage` | P0 |
| **Braavos** | Browser Extension | `starknet_signMessage` | P0 |
| **Argent Mobile** | iOS / Android | WalletConnect → `starknet_signMessage` | P0 |
| **Braavos Mobile** | iOS / Android | WalletConnect → `starknet_signMessage` | P0 |
| **Seed Phrase** | 无钱包场景 | 12 词 BIP-39 |备用 |

### 5.2 密钥推导（链无关）

```
用户操作                        UOMP SDK
────────                       ────────
1. 连接钱包
   MetaMask: eth_requestAccounts
   Argent X: wallet_requestAccounts

2. 签名固定消息 "UOMP Store v1"
   MetaMask: personal_sign(message)
   Starknet: starknet_signMessage({ domain, message, primaryType, types })

3. 拿到 signature + address

4. masterKey = HKDF-SHA256(
     ikm  = signature[0:32] || keccak256(address),
     salt = "uomp-store-v1",
     info = chain + ":" + address,
     len  = 32
   )

5. 从 masterKey 派生：
   - Ed25519 keypair（Token 签名）
   - AES-256 itemKey（Memory Item 加密）
```

同一钱包同一消息 → 任何设备导出相同 masterKey。

### 5.3 用户身份 ID

```ts
user_id = keccak256(chain + ":" + address.toLower())
// "starknet:0x05afebcea..."
// "ethereum:0xabc..."
```

### 5.4 多设备同步

```
Device A (Desktop + MetaMask)           Device B (Mobile + Argent)
───────────────────────────             ─────────────────────────
1. 打开 Web App                         1. 打开 Argent Mobile App
2. 点击 "Connect Wallet"                2. 扫码 WalletConnect
3. MetaMask 弹窗 → 签名                 3. 确认签名
4. deriveKey → masterKey                4. 同样 masterKey ✅
5. 从 S3 拉取加密数据                   5. 同样数据 ✅
```

### 5.5 命令

```bash
# 钱包方式（推荐）
uomp user init --wallet starknet    # 浏览器签名 → 派生 key
uomp user init --wallet ethereum    # MetaMask 签名

# Seed phrase 备用
uomp user init --seed               # 生成 12 词
uomp user setup                     # 从 seed 恢复
uomp user export                    # 显示 seed

uomp user status                    # 当前 user_id + 关联钱包
```


## 6. 命令行设计

```bash
# Store 管理
uomp store status           # 当前后端 + 数据统计
uomp store switch <backend> # 切换后端（SQLite → S3）
uomp store migrate          # 将数据从当前后端迁移到指定后端

# 同步
uomp sync pull              # 从后端拉取最新数据到本地
uomp sync push              # 推送本地数据到后端
uomp sync auto              # 自动同步（Guard 每次写后 push）

# 配置
uomp config set store.backend encrypted-object
uomp config set store.s3.bucket uomp-data
uomp config set store.s3.region us-east-1
uomp config set store.encryption.enabled true
```

## 7. 与 Guard 的集成

现在 Guard 直接实例化 `MemoryStore`：

```ts
// packages/guard/src/index.ts (现有)
this.store = new MemoryStore({ dbPath: options.memoryDbPath });
```

改为通过 Store 工厂创建：

```ts
// 新
this.store = await createStore(config.store);
```

工厂根据 `~/.uomp/config.json` 的 `store.backend` 选择实现：

```ts
// packages/store/src/factory.ts
export async function createStore(config: StoreConfig): Promise<IMemoryStore> {
  switch (config.backend) {
    case 'sqlite':
      return new SQLiteStore(config.sqlite!);
    case 'encrypted-object':
      return new EncryptedObjectStore(config);
    case 'ipfs':
      return new IPFSStore(config.ipfs!);
    default:
      return new SQLiteStore({ dbPath: join(homedir(), '.uomp', 'memory.db') });
  }
}
```

Guard 接口不变——`get()`, `getByTag()` 签名一致。


## 8. Browser SDK 自动路由（StoreRouter）

浏览器模式下，SDK 根据 Gateway 是否在线自动选择数据通路：

**读操作：Gateway 优先，降级 S3 直读**

```ts
class StoreRouter {
  async getByTag(tag) {
    // 1. 尝试 Gateway
    const gw = await this.tryGateway(`/v1/memory?tag=${tag}`);
    if (gw) return gw.items;

    // 2. Gateway 不可达 → S3 直读 + 浏览器内解密
    const keys = await this.readEncryptedIndex(tag);
    const blobs = await Promise.all(keys.map(k => this.s3.get(`items/${k}`)));
    return blobs.map(b => this.decrypt(b, k));
  }
}
```

**写操作和聚合：必须经过 Gateway**

```ts
async set(key, item) {
  const resp = await fetch(`${gatewayUrl}/v1/memory/${key}`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify(item),
  });
  if (!resp.ok) throw new UompError('WRITE_REQUIRES_GATEWAY');
}
```

**Webapp 开发者体验**

```tsx
const uomp = useUomp({ gatewayUrl: 'https://my-gateway.example.com' });
// 读：Gateway 在线走 Gateway，不在线走 S3 直读（零配置）
// 写：Gateway 必须在线，否则 uomp.isGatewayOnline === false
```

### 8.1 isGatewayOnline

SDK 暴露一个布尔属性，由最近一次请求自动更新：

```ts
uomp.isGatewayOnline: boolean
```

Webapp 据此控制 UI：写入按钮禁用、顶部显示离线 banner。

## 9. UOMP Cloud Relay（公共转发节点，已退役）

> **已退役（2026-10）：** 本节仅保留历史设计。UOMP 不再运营公共 Relay；远程 Agent 使用 Aegis Cloud + Aegis Memory Gateway。

Cloud Relay 是一个**无状态的公共 Gateway**，替代用户本地 Gateway 处理写请求和聚合查询。任何人都可以部署，UOMP 官方运营一个作为默认值。

### 9.1 为什么可以信任 Relay

Relay 全程只过手密文：

```
Browser SDK          Cloud Relay              S3 / Store
───────────          ────────────             ──────────
data                            
  ↓ AES-256-GCM                     
密文 ──────────► 验签名 ──────────► 存密文
                 转发密文
                 
                 Relay 能做的：
                 ✅ 拒绝转发（DoS）
                 ✅ 看到元数据（时间、tag名）
                 ❌ 读明文（没有 masterKey）
                 ❌ 改数据（AES-GCM 认证防篡改）
                 ❌ 冒充用户（签名不匹配）
```

### 9.2 职责拆分

| 职责 | 浏览器自己做 | Cloud Relay 做 |
|------|:----------:|:------------:|
| JWT 验签 | ✅ 用公钥校验 | ✅ 做第二道防线 |
| Scope 过滤 | ✅ denyTags/denyKeys/fields | ✅ 做第二道防线 |
| 加密 / 解密 | ✅ AES-256-GCM | ❌ 没 key |
| 写请求转发 | ❌ 需要 Guard | ✅ 验 Token → 转 Guard |
| 聚合计算 | ❌ 需要 Guard | ✅ 验 Token → 转 Guard |
| 审计日志 | ⚠️ 客户端签名证明 | ✅ 可信日志 |
| 链上锚定 | ✅ 自己签名上链 | ✅ 批量上链 |

### 9.3 部署模式

```
模式 1：默认（用户零安装）
  Browser App ──► Cloud Relay (relay.uomp.org) ──► Guard ──► Store

模式 2：完全自托管（最信任）
  Browser App ──► 自建 Relay (VPS / NAS) ──► Guard ──► Store

模式 3：混合（当前方式，最敏感数据）
  Browser App ──► 用户 Gateway ──► Guard ──► Store
```

### 9.4 开源 Relay 实现

```
apps/relay/                  # 新增
├── src/
│   ├── index.ts             # Hono 服务器
│   ├── verify.ts            # Token 验签（公钥模式）
│   └── forward.ts           # 转发到 Guard
├── Dockerfile
└── README.md
```

和现有 Gateway 的区别：

| | Gateway | Relay |
|------|---------|-------|
| mTLS | 是（用户侧） | 否（公共接入） |
| 知道明文 | 是 | 否（Store 加密） |
| 部署位置 | 用户本地 | 云服务 |
| Token 校验 | 签名 + audience | 签名 + audience + 限流 |
| 适用场景 | 个人自托管 | 公共 / 第三方运营 |

### 9.5 多 Relay 互备

```ts
// SDK 支持多个 Relay，自动故障转移
const uomp = await BrowserSDK.fromWallet({
  relays: [
    'https://relay.uomp.org',
    'https://relay.community-node.io',
    'https://my-own-relay.com',
  ],
  storeConfig: { backend: 'encrypted-object', ... },
});

// 写请求：按顺序尝试 relay，任一连通即可
await uomp.memory.set('AAPL', data);
// → 尝试 relay.uomp.org → 成功
// → 失败？→ 尝试下一个
```

### 9.6 对 Webapp 开发者的影响

```ts
// 零依赖模式：不需要用户装任何东西
const uomp = await BrowserSDK.fromWallet({
  relayUrl: 'https://relay.uomp.org',   // 默认值，可省略
});

// 读：S3 直读 + 客户端验签 → 零服务端依赖
const holdings = await uomp.memory.getByTag('portfolio:holdings');

// 写：自动走 Relay → 加密 → 转发 → Store
await uomp.memory.set('AAPL', newData);

// 审计：读操作客户端签名上链，写操作 Relay 日志
```

## 10. 对规范的影响

| 位置 | 变更 |
|------|------|
| **§4 Terminology** | 新增 `Store Backend` 术语：Memory Store 的可插拔持久化后端 |
| **§4 Memory Store** (新) | 新增一段描述 Store 抽象层、三种后端类型、加密策略 |
| **§5.1 Architecture** | 架构图增加 Store Backend 层（在 Memory Store 下方） |
| **§11 Memory Item** | 无变化 |
| **§11.4 Store Backends** (新) | 定义 SQLite Backend、Encrypted Object Backend、IPFS Backend 的规范要求 |
| **§20 Security Considerations** | 新增 §20.5 Store Backend Security：E2E 加密要求、密钥管理 BEST PRACTICES、seed phrase entropy 要求 |
| **§21 Future Work** | 加 IPFS Backend、去中心化 Store 发现协议 |
| **§8 HTTP API** | GET /v1/store/stats（新增，可选） |
| **§8.4 Error Codes** | 新增 `STORE_MIGRATION_IN_PROGRESS`、`BACKEND_UNAVAILABLE` |
| **附录 A 最小交互示例** | 新增 Store 切换命令 |

### 推荐新增章节草稿

#### §11.4 Store Backends

> UOMP defines a **pluggable store backend** interface. Memory Guard interacts with the store through this interface and is agnostic to the backend implementation.
>
> Implementations MUST support three backend profiles:
>
> **SQLite Backend** (local)
> - Default for Local Profile.
> - Stores Memory Items in a single SQLite file under `~/.uomp/memory.db`.
> - No encryption required at the store layer (disk encryption is the user's responsibility).
>
> **Encrypted Object Backend** (cloud)
> - Each Memory Item is stored as an independently encrypted object (RECOMMENDED: AES-256-GCM).
> - Tag indices MUST also be encrypted.
> - Encryption keys MUST be derived from the user's Ed25519 seed (HKDF).
> - Backend servers MUST NOT have access to plaintext data.
> - RECOMMENDED object stores: S3-compatible, R2, B2.
>
> **IPFS Backend** (decentralized)
> - Memory Items are content-addressed and stored on IPFS.
> - A local index maps tags to CIDs.
> - Encryption at the IPFS layer is OPTIONAL but RECOMMENDED.

#### §20.5 Store Backend Security

> When using a cloud store backend:
> 1. Data MUST be encrypted before leaving the Memory Guard process.
> 2. Each Memory Item MUST use an independent encryption key derived from the item's `key` field.
> 3. The user's seed phrase SHOULD have ≥128 bits of entropy (12-word BIP-39).
> 4. Seed phrases MUST NOT be stored on cloud backends.
> 5. Backend credentials (S3 keys, etc.) SHOULD be stored in `~/.uomp/config.json` with file permissions `0600`.


## 11. SDK 改动

### `@uomp/sdk` 新增

```ts
interface UompClient {
  store: StoreClient;
  identity: IdentityClient;  // ← 新增
}

interface IdentityClient {
  /** Connect via wallet */
  fromWallet(chain: 'ethereum' | 'starknet'): Promise<Identity>;
  /** Recovery via seed phrase */
  fromSeedPhrase(phrase: string): Promise<Identity>;
  /** Get current identity */
  current(): Identity | null;
}

interface Identity {
  userId: string;         // keccak256(chain:address)
  chain: string;
  address: string;
  wallet?: string;        // 'metamask' | 'argent-x' | 'braavos' | 'argent-mobile'
}

// ── Usage ─────────────────────────────────────────────

// Browser: MetaMask
const uomp = new UompClient({ baseUrl: 'https://my-gateway.example.com' });
const id = await uomp.identity.fromWallet('ethereum');
// → MetaMask 弹窗 → 签名 → 派生 masterKey
console.log(id.userId); // "ethereum:0xabc..."

// Browser: Argent X
const id = await uomp.identity.fromWallet('starknet');
// → Argent X 弹窗 → 签名

// Mobile: Argent (via WalletConnect)
const id = await uomp.identity.fromWallet('starknet');
// → 内置 WalletConnect → 扫码连接
```

### Browser SDK 钱包入口

```ts
// packages/sdk/src/browser.ts
import { BrowserSDK } from '@uomp/sdk/browser';

// 一键连接（自动检测可用钱包）
const uomp = await BrowserSDK.fromWallet();
// 内部：
// 1. 检测 window.starknet (Argent X) 或 window.ethereum (MetaMask)
// 2. 请求连接
// 3. 签名 "UOMP Store v1"
// 4. deriveKey → masterKey
// 5. 创建 UompClient
```

### `@uomp/cli` 新增

```
uomp user init / setup / export / status
uomp store status / switch / migrate
uomp sync pull / push / auto
```


## 12. 实施路线

### Phase 1：Store 接口抽象（核心）

| 任务 | 文件 |
|------|------|
| 定义 `IMemoryStore` 接口 | `packages/store/src/types.ts`（新） |
| 现有 `MemoryStore` 实现接口 | `packages/store/src/index.ts`（重构） |
| Store 工厂 `createStore()` | `packages/store/src/factory.ts`（新） |
| Guard 改用工厂 | `packages/guard/src/index.ts`（改 3 行） |
| `uomp store status` 命令 | `packages/cli/src/commands/store.ts`（新） |

### Phase 2：Wallet Auth + Seed Phrase 密钥管理

| 任务 | 文件 |
|------|------|
| HKDF 密钥推导（链无关） | `packages/identity/src/wallet-auth.ts`（新） |
| EIP-1193 provider 封装（MetaMask） | 同上 |
| Starknet provider 封装（Argent X, Braavos） | 同上 |
| WalletConnect 移动端支持 | 同上 |
| `uomp user init --wallet` 命令 | CLI |
| `BrowserSDK.fromWallet()` | SDK |
| `~/.uomp/user.json` 多身份存储 | CLI/SDK 共用 |

### Phase 3：Encrypted Object Backend

| 任务 | 文件 |
|------|------|
| AES-256-GCM 加密/解密层 | `packages/store/src/encryption.ts`（新） |
| S3 客户端封装 | `packages/store/src/backends/s3.ts`（新） |
| 加密 index（tag→keys 映射） | 同上 |
| `uomp store switch encrypted-object` | CLI |

### Phase 3.5：Cloud Relay 公共节点

| 任务 | 文件 |
|------|------|
| Relay 实现（无状态 Gateway） | `apps/relay/src/index.ts`（新）|
| Token 公钥验签（不需要私钥） | `apps/relay/src/verify.ts` |
| 转发到 Guard（验 scope + 写审计） | `apps/relay/src/forward.ts` |
| 限流 + anti-abuse | 同上 |
| SDK 多 Relay 故障转移 | `packages/sdk/src/transport.ts` |
| `uomp relay start` 命令（自建） | CLI |

### Phase 4：浏览器体验

| 任务 | 文件 |
|------|------|
| `uomp user setup` 支持 seed phrase QR 码 | CLI |
| 浏览器 Seed Input UI | 浏览器 SDK |
| S3 后端浏览器直连（绕过 Gateway） | 浏览器 SDK（可选） |


## 13. 向后兼容

- 现有用户：`uomp init` 后默认 `backend: sqlite`，行为完全不变
- `~/.uomp/config.json` 新增 `store` 字段（可选，缺省 = sqlite）
- 已有的 SQLite 用户升级后不受影响
- migration 功能允许从 SQLite 迁移到加密对象存储
