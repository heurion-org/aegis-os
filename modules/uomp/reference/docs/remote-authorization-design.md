> **已退役（2026-10）：** 独立 UOMP Gateway / Cloud Relay 不再维护。远程 Agent 运行时使用 Aegis Cloud，本地入口使用 Aegis Memory Gateway，审批与租约由 Aegis OS 执行。本文档保留为历史设计参考。

# UOMP 远程授权设计文档

> 状态：研究/预览。Phase 1 Gateway + mTLS 原型存在，但远程模式不是当前核心用户工作流；当前主线是本地 CLI + MCP。当前用法见 [README](../README.md#quick-start)。
>
> 目标：定义用户本地 Memory 与远程 Agent 之间的安全授权、通信与 Payload 交付机制。

---

## 1. 背景与目标

UOMP 的标准模型假设 Agent 运行在用户本地或同一台受信机器上。真实场景中，Agent 更可能是：

- 第三方云服务；
- 开源社区托管的 SaaS；
- 用户自己部署在另一台机器/容器中的服务。

这就要求解决三个核心问题：

1. **通信安全**：用户如何与远程 Agent 通信，确保 Manifest、Token、Payload 不泄漏？
2. **授权机制**：如何把本地签发的 Capability Token 安全地交给远程 Agent，同时避免把本地 Memory Guard 直接暴露给外网？
3. **Payload 存储**：Agent 生成的分析报告如何返回给用户，而不长期驻留在第三方服务器上？

本文档提出 **Remote Profile + UOMP Gateway** 的统一方案。

---

## 2. 威胁模型

| 威胁 | 说明 | 防护目标 |
|---|---|---|
| 中间人窃听 Manifest/Token | 攻击者监听用户与 Agent 之间的链路 | TLS 1.3 / DIDComm 端到端加密 |
| Agent 伪造身份 | 恶意 Agent 冒充可信 Agent | DID / GPG / X.509 身份验证 + Registry 校验 |
| Token 被截获后重放 | Token 在传输或 Agent 侧被泄露 | Token 绑定 Gateway、短有效期、Gateway 层撤销 |
| 远程 Agent 直接访问本地 Memory Guard | 用户内网被穿透 | Memory Guard 不直接暴露，所有访问经 Gateway |
| Payload 被第三方长期保存 | 报告留在 Agent 服务器 | E2E 加密 + 临时 Relay + 链上 hash 验证 |
| 用户否认授权或 Agent 否认访问 | 事后无法举证 | 审计日志 + 链上事件锚定 |

---

## 3. 总体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                         远程 Agent 侧                                │
│  ┌──────────────┐   1. 拉取 Manifest   ┌──────────────┐             │
│  │  Agent 服务   │ ◄───────────────────►│  Registry    │             │
│  │ (第三方 SaaS) │   (TLS + 身份验证)    │              │             │
│  └──────┬────────┘                      └──────────────┘             │
│         │                                                           │
│         │  2. 授权协商 (DIDComm / mTLS)                               │
│         │    用户把 Gateway Token 交给 Agent                          │
│         │                                                           │
└─────────┼───────────────────────────────────────────────────────────┘
          │
          ▼  3. 用 Gateway Token 访问 Gateway
┌─────────────────────────────────────────────────────────────────────┐
│                         UOMP Gateway                                 │
│  ┌──────────────┐   校验 Token / 配额   ┌──────────────┐             │
│  │  HTTP API    │ ────────────────────►│  Audit Log   │             │
│  │  /v1/memory  │                      │              │             │
│  │  /v1/payload │                      └──────────────┘             │
│  └──────┬───────┘                                                   │
│         │  4. mTLS / 本地转发                                         │
└─────────┼───────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         用户本地侧                                   │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐             │
│  │ Auth Service │──►│ Memory Guard │──►│ Memory Store │             │
│  └──────────────┘   └──────────────┘   └──────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
```

关键原则：

- **Memory Guard 不直接暴露到公网**；Gateway 是唯一对外入口。
- **Capability Token 的 audience 是 Gateway**，不是 Memory Guard。
- **Payload 必须端到端加密**，Relay 只存储密文。

### 3.1 快速验证

`uomp-mvp` 已提供可运行的 Gateway 参考实现，支持一条命令自动获取公网地址：

```bash
# 1. 确保本地 Auth + Guard 服务已启动
pnpm --filter @uomp/server start

# 2. 启动 Gateway + Cloudflare Tunnel（自动获取公网 URL）
uomp gateway start

# 3. 将输出的 trycloudflare.com URL 作为 Gateway endpoint
# 4. 授权 + 运行（见下方）
```

**无需 Tunnel 的手动模式**：

```bash
# 生成证书
./scripts/generate-gateway-certs.sh

# 把客户端指纹加入 ~/.uomp/remote-profile.json 的 agent_allowlist

# 启动 Gateway（不暴露公网）
node apps/gateway/dist/index.js

# 创建 remote session 并走通 end-to-end
./scripts/test-gateway-remote.sh
```

[其他内容同上，保持已实现的标注]

---

## 4. 通信机制

### 4.1 Agent 发现与 Manifest 获取

用户通过 Registry 或 URL 发现远程 Agent：

```bash
uomp discover registry://stock-analyst
# 或
uomp discover https://agent.example.com/uom.json
```

安全要求：

1. **TLS 1.3 强制**：所有 Manifest 下载必须 HTTPS。
2. **身份验证**：Agent 必须提供可验证身份（DID / GPG / X.509）。
3. **完整性校验**：计算 `uom.json` 的 checksum，与 Registry 或链上记录比对。
4. **不发送用户数据**：发现阶段只传输 Agent ID / URL，不上传任何 Memory 数据。

### 4.2 安全通道选择

| 方案 | 适用场景 | 优缺点 |
|---|---|---|
| **mTLS HTTPS** | 默认推荐 | 成熟、易部署；需要证书分发与吊销机制 |
| **DIDComm v2** | 高安全/去中心化场景 | 端到端加密、无需预共享密钥；生态较新 |
| **Noise + WebSocket** | 实时双向流 | 轻量；需要自定义协议 |

**MVP 推荐 mTLS HTTPS**：

- Agent 在 Registry 中注册其 TLS 客户端证书或证书指纹。
- 用户端 `uomp connect` / `uomp inspect` 时验证 Agent 身份与 Registry 记录一致。
- 后续授权协商与 Token 交付都在该双向 TLS 通道内进行。

### 4.4 DIDComm 迁移路线

长期来看，UOMP 计划从 mTLS 迁移到 **DIDComm v2**，原因：

- 真正的端到端加密，不依赖 TLS 证书机构；
- Agent 与用户无需预先共享密钥；
- 支持异步消息、离线授权、多设备同步。

迁移策略（向后兼容）：

1. **Phase 1（MVP）**：mTLS HTTPS 作为默认通道；DIDComm 作为可选扩展。
2. **Phase 2**：Agent 同时发布 mTLS endpoint 和 DIDComm service endpoint；用户端优先尝试 DIDComm。
3. **Phase 3**：新 Agent 可仅支持 DIDComm；旧 Agent 通过适配层继续支持 mTLS。

DIDComm 消息类型预留：

- `uomp/authorize-request`
- `uomp/authorize-response`
- `uomp/payload-ready`
- `uomp/session-revoked`

### 4.3 Remote Profile

Remote Profile 是用户侧的一份配置，描述如何把本地 Memory 暴露给远程 Agent：

```json
{
  "profile": "remote",
  "version": "1.0",
  "gateway": {
    "endpoint": "https://gateway.user.example",
    "tls": {
      "server_cert_pin": "sha256/...",
      "mtls_required": true
    },
    "agent_allowlist": [
      "did:ethr:0xabc...",
      "stock-analyst@example-org"
    ]
  },
  "encryption": {
    "public_key": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "..."
    }
  },
  "payload": {
    "mode": "gateway-cache",
    "max_size_mb": 10,
    "ttl_seconds": 3600
  },
  "audit": {
    "anchor_chain": "starknet",
    "anchor_contract": "0x..."
  }
}
```

部署方式：

- **默认：用户自托管**。开源 core 实现中，Gateway 由用户自己运行在自己的 VPS、NAS、云服务器或家庭服务器上。
- **推荐（无需公网 IP）**：使用 `uomp gateway start` 一键启动 Cloudflare Tunnel，自动获取 `https://xxx.trycloudflare.com` 公网地址。无需端口转发或公网 IP。
- 也可以使用反向隧道（Cloudflare Tunnel、ngrok）把 Gateway 暴露到公网。
- Gateway 与本地 Memory Guard 之间通过 mTLS 或本地 Unix socket 通信。
- **未来商业化选项**：可提供托管 Gateway 服务，但开源 core 始终保留自托管路径作为默认和信任根。

---

## 5. 授权机制

### 5.1 Gateway 绑定的 Capability Token

用户执行授权时，Token 的 `audience` 指向 Gateway，而非本地 `127.0.0.1`：

```ts
{
  sessionId: 'sess_xxx',
  agentId: 'stock-analyst',
  agentName: '持仓分析助手',
  issuedAt: '2026-07-14T10:00:00Z',
  expiresAt: '2026-07-14T10:30:00Z',
  profile: 'remote',
  audience: 'https://gateway.user.example',
  allowedEndpoints: [
    '/v1/memory/*',
    '/v1/payload/upload'
  ],
  scopes: {
    read: {
      tags: ['portfolio:holdings', 'profile:risk'],
      keys: ['AAPL', 'TSLA', 'NVDA', 'user-risk-profile'],
      denyTags: [],
      denyKeys: []
    },
    write: { tags: [], keys: [], denyTags: [], denyKeys: [] }
  },
  limits: {
    maxReadQueries: 100,
    maxWriteQueries: 0
  }
}
```

### 5.2 Token 流转

```
用户本地 CLI          远程 Agent            UOMP Gateway          Memory Guard
   │                      │                      │                      │
   │  uomp authorize      │                      │                      │
   │ ──────────────────►  │                      │                      │
   │  通过 mTLS 交付 Token │                      │                      │
   │                      │  携带 Token 访问     │                      │
   │                      │ ──────────────────►  │                      │
   │                      │                      │  校验 Token + 转发   │
   │                      │                      │ ──────────────────►  │
   │                      │                      │  返回过滤后的数据    │
   │                      │ ◄──────────────────  │                      │
```

### 5.3 Gateway 校验与转发

Gateway 对每个请求执行：

1. 校验 TLS 客户端证书是否在 allowlist；
2. 校验 `Authorization: Bearer <token>` 的签名、过期时间、撤销状态；
3. 校验请求路径是否在 `allowedEndpoints`；
4. 校验是否超过 `limits` 配额；
5. 把请求转发给本地 Memory Guard；
6. 记录审计日志；
7. 可选：把访问事件锚定到链上。

### 5.4 撤销

用户执行 `uomp revoke sess_xxx` 后：

- 本地 Auth Service 把 session 标记为 `revoked`；
- Gateway 定期同步黑名单，或 Auth Service 向 Gateway 推送撤销事件；
- Gateway 立即拒绝该 Token 的后续请求。

### 5.5 Token 刷新机制

远程 Agent 可能长时间运行（例如后台分析任务），短有效期 Token 需要刷新：

1. 初始授权时，Auth Service 除了签发 `access_token`，还签发一个**刷新 Token（refresh_token）**：
   - 仅用于换取新的 `access_token`；
   - 作用域固定，不能用于读取 Memory；
   - 有效期可配置（默认 7 天）。
2. Agent 在 `access_token` 过期前调用 Gateway 的刷新接口：
   ```http
   POST /v1/sessions/{session_id}/refresh
   Authorization: Bearer <refresh_token>
   ```
3. Gateway 验证 refresh_token 与 session 状态后，向本地 Auth Service 申请新的 `access_token` 并返回。
4. 用户撤销 session 时，refresh_token 同步失效。

> 刷新机制让远程 Agent 不必长期持有同一个 JWT，同时把 Token 生命周期控制权留在用户侧。

---

## 6. Payload 存储与交付

### 6.1 端到端加密

- 用户在 Remote Profile 中提供公钥。
- Agent 生成报告后，用该公钥加密（例如 ECDH-X25519 + AES-GCM-256）。
- 只有用户本地私钥能解密；Relay / Gateway 只存储密文。

**CLI 私钥保护**：

- 解密私钥默认存储在 `~/.uomp/.keystore/` 下，以加密 keyfile 形式保存（密码派生密钥加密）。
- 首次运行 `uomp init` 时生成密钥对，并提示用户设置 keystore 密码。
- 解密 Payload 时，CLI 临时解锁私钥，操作完成后立即从内存清除。
- GUI 应用可使用系统 keychain；CLI 使用 keystore 文件 + 密码。

### 6.2 Payload Relay 方案

| 模式 | 流程 | 适用场景 |
|---|---|---|
| **gateway-cache** | Agent POST 加密 Payload 到 Gateway；用户从 Gateway 拉取 | 同步、小文件（< 10 MB） |
| **presigned-url** | Gateway 给 Agent 一个一次性上传 URL；Agent 上传后返回引用 | 大文件、异步任务 |
| **ipfs-cid** | 密文上 IPFS；链上存 CID + hash | 公开可验证、长期存档 |

推荐默认 **gateway-cache** + 链上 hash 锚定。

### 6.3 Payload Envelope

```json
{
  "payload_id": "pay_xxx",
  "session_id": "sess_xxx",
  "agent_id": "stock-analyst",
  "timestamp": "2026-07-14T10:15:00Z",
  "encryption": {
    "algorithm": "ECDH-X25519-AES256GCM",
    "sender_public_key": "...",
    "nonce": "..."
  },
  "ciphertext": "base64...",
  "format": "text/markdown",
  "size": 2048,
  "hash": "sha256:..."
}
```

用户收到后：

1. 用本地私钥解密；
2. 验证 `hash` 与内容一致；
3. 可选验证链上锚定 hash。

---

## 7. 审计与链上锚定

### 7.1 本地审计

Gateway 把以下事件写入本地 `audit_remote.db`：

| 事件 | 字段 |
|---|---|
| `gateway_access` | session_id, agent_id, endpoint, allowed, reason, timestamp |
| `payload_upload` | payload_id, session_id, agent_id, hash, timestamp |
| `payload_download` | payload_id, timestamp |

### 7.2 链上锚定

为了不可篡改证明，关键事件写入区块链 event：

```solidity
event SessionGranted(bytes32 indexed sessionHash, bytes32 indexed agentHash, uint256 expiresAt);
event GatewayAccess(bytes32 indexed sessionHash, bytes32 indexed agentHash, bytes32 endpointHash, bool allowed);
event PayloadAnchored(bytes32 indexed payloadHash, bytes32 indexed sessionHash);
```

- `sessionHash` = `keccak256(session_id + agent_id + granted_tags)`
- `agentHash` = `keccak256(agent_id)`
- `payloadHash` = `sha256(ciphertext)`

默认支持 **Starknet**（低成本、高频事件），可选 EVM 兼容链。

**批量上链策略**：

- **授权事件**（`SessionGranted`、`SessionRevoked`）：建议实时或近实时上链，数量少、关键性高。
- **访问事件**（`GatewayAccess`）：高频，采用批量上链。Gateway 每 N 分钟或每 M 条事件生成一个 Merkle root，把 root 上链，原始日志保留在本地供事后验证。
- **Payload 锚定**：每个 Payload 生成后单独锚定 hash，因数量相对较少。

```
本地事件 ──► 批量聚合 ──► Merkle root ──► Starknet event
                    │
                    └── 完整日志保留在 Gateway，供审计验证
```

---

## 8. Gateway HTTP API（已实现）

### 8.1 Gateway HTTP API（已实现的 Phase 1）

```http
GET  /v1/health
GET  /v1/memory/{key}              # 转发到 Memory Guard
GET  /v1/memory?tag={tag}          # 转发到 Memory Guard
GET  /v1/audit                     # 转发到 Memory Guard 审计接口
POST /v1/payload/upload            # Agent 上传 Payload（Phase 2 加入 E2E 加密）
GET  /v1/payload/{payload_id}      # 用户下载 Payload
POST /v1/sessions/{session_id}/refresh  # Token 刷新（预留，未实现）
```

所有请求必须携带：

```http
Authorization: Bearer <gateway-token>
X-UOMP-Agent-Id: stock-analyst
```

### 8.2 Agent 侧 SDK 扩展

```ts
const agent = await UompAgent.fromEnv(); // 读取 UOM_TOKEN + UOMP_BASE_URL

// 远程场景：UOMP_BASE_URL 指向 Gateway
const holdings = await agent.memory.readTag('portfolio:holdings');
const report = await agent.analyze(holdings);

// 加密后上传 Payload
await agent.output.upload(report, { encryptTo: remoteProfile.encryption.public_key });
```

---

## 9. MVP 范围建议

### Phase 1：Gateway + mTLS ✅ 已完成

- Remote Profile Schema 定稿
- Gateway 参考实现（Node.js / TypeScript，`apps/gateway`）
- mTLS 双向认证
- Token 校验与 Memory Guard 转发
- 基础审计日志（通过 `/v1/audit`）
- 脚本：`scripts/generate-gateway-certs.sh`、`scripts/test-gateway-remote.sh`
- CLI：`uomp gateway start`（含 Cloudflare Tunnel 自动暴露公网）

### Phase 2：E2E Payload（2 周）

- Payload Envelope 与加密
- Gateway payload-cache 模式
- 用户下载与解密 CLI 命令

### Phase 3：链上锚定（2 周）

- Starknet event 合约
- CLI `uomp audit --chain starknet`

### 未来

- DIDComm v2 通道
- IPFS / 去中心化 Payload Relay
- 多 Gateway 负载均衡

---

## 10. 已确认决策

1. **Gateway 部署**：开源 core 默认用户自托管；未来商业化可提供托管 Gateway 服务。
2. **Token 刷新**：引入 refresh_token，Agent 可在 access_token 过期后申请新 Token。
3. **CLI 私钥保护**：使用 keystore 文件 + 密码派生加密，GUI 使用系统 keychain。
4. **通道迁移**：MVP 默认 mTLS HTTPS，长期迁移到 DIDComm v2，保留兼容层。
5. **链上锚定**：授权事件近实时上链，访问事件批量 Merkle-root 上链，Payload hash 单独锚定。

## 11. 待细化问题

1. refresh_token 的轮换策略：每次刷新是否签发新 refresh_token？
2. DIDComm 消息的持久化与重试语义。
3. Merkle root 批量上链的时间窗口与确认数选择。
4. 托管 Gateway 服务下的密钥托管与合规边界。

---

## 相关文档

- [CLI/SDK 设计](./cli-sdk-design.md)
- [协议规范](../specs/draft-00.md)
- [参考实现](../README.md)
