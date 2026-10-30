# User-Owned Memory Protocol (UOMP)

**版本**：Draft-00<br>
**状态**：草案（Draft）<br>
**发布日期**：2026-07-12<br>
**最后更新**：2026-10-29<br>
**目标**：作为公开 RFC 草案征求意见

### Version History

| Date | Change |
|------|--------|
| 2026-07-12 | Draft-00 initial release. |
| 2026-07-23 | Added Cloud Relay (§15.7), Store abstraction (§0), Payload API (§15.6). Updated `uom.json` schema (§6.2-6.4) with `fields`, `purposes`, `external_data_sources`, `package`. Updated the architecture diagram to include Gateway and Relay. Added FHE to Future Work (§22). Marked on-chain audit as Phase 4. |
| 2026-10-29 | Local-first reference implementation: CLI + stdio MCP path, 0600 session env delivery, Auth + Guard combined service. Reworked §5 architecture and diagrams; Remote remains optional/preview. |
| 2026-10-30 | Remote Agent Profile aligned with Aegis OS: remote Agent runs on Aegis Cloud, local entry is Aegis Memory Gateway. Standalone UOMP Cloud Relay retired. |

---

## 1. Abstract

User-Owned Memory Protocol（UOMP）定义了一种用户主权型授权协议，允许用户将其个人记忆数据（偏好、设置、身份属性等）临时授权给 AI Agent 访问。授权基于会话（Session）生效，按标签（Tag）或键（Key）限定范围，会话结束或撤销后授权立即失效。UOMP 默认运行在本机环境，同时定义远程 Agent 扩展机制。

## 2. Status of This Memo

本文档为 UOMP 协议草案（Draft-00），描述协议设计意图、数据格式、HTTP API 和安全要求。本文档旨在通过公开讨论后演进为正式标准。本文档中的关键词 "MUST"、"MUST NOT"、"REQUIRED"、"SHALL"、"SHALL NOT"、"SHOULD"、"SHOULD NOT"、"RECOMMENDED"、"MAY"、"OPTIONAL" 按照 [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) 解释。

> **参考实现状态（2026-10）：** 当前 `uomp` reference CLI 优先实现 Local Profile：用户运行一次 `uomp setup` 完成导入、客户端配置和后台服务，不预先授权；Agent 第一次请求 tag/key 时打开本地审批页，用户批准后继续。`pending` / `approve` / `deny` 是终端兜底；`connect` 是高级预授权入口，`authorize`、`serve`、`mcp` 是手动/脚本路径。stdio MCP bridge 为实验能力。Remote Agent Profile 是可选能力，参考实现使用 Aegis Cloud + Aegis Memory Gateway；独立 Cloud Relay 已退役。Aegis OS 是执行该协议的参考运行时。

## 3. Introduction

### 3.1 Motivation

当前 AI Agent 在为用户提供服务时，通常需要访问用户的个人数据。现有方案往往要求用户将数据上传至 Agent 提供商的服务器，导致：

- 用户失去对数据的直接控制。
- Agent 可能长期保留用户数据。
- 用户难以审计 Agent 访问了哪些数据。

UOMP 的设计目标是：

- **用户始终拥有记忆数据**。
- **每次访问都需要临时授权**。
- **授权范围最小化**。
- **授权会话结束后立即失效**。
- **所有访问可审计**。

### 3.2 Design Principles

- **Local-first**：默认部署模型下，Memory Guard 运行在本机，仅监听 `127.0.0.1`。
- **Capability-based authorization**：使用短期 Capability Token 表达授权范围。
- **Tag/Key scoping**：授权可按标签或精确键进行。
- **Session-bound**：Token 绑定到具体 Session，Session 结束即失效。
- **Transport-agnostic core**：核心协议基于 HTTP，但可扩展至其他传输。

## 4. Terminology

| 术语 | 定义 |
|------|------|
| **Memory** | 用户个人记忆数据，包括偏好、设置、身份属性等。 |
| **Memory Item** | 单条记忆记录，包含 key、value、tags、sensitivity 等元数据。 |
| **Memory Store** | 持久化存储 Memory Item 的用户侧存储。 |
| **Memory Guard** | 访问代理层，校验授权、过滤数据、记录审计日志。 |
| **Auth Service** | 会话管理组件，负责创建/关闭 Session、签发/校验 Capability Token。 |
| **Session** | 一次 Agent 任务周期，拥有唯一 `session_id`。 |
| **Capability Token** | 会话级授权凭证，标明 Agent 可访问的标签/键范围。 |
| **Agent** | 通过 UOMP 访问用户记忆的程序，可运行在本机或远程。 |
| **MCP bridge** | 可选的 stdio 适配器（`uomp mcp`），把 MCP 工具调用转换为 Guard HTTP 请求。 |
| **uom.json** | Agent 声明文件，描述 Agent 身份和默认请求的记忆范围。 |
| **Local Profile** | 本机部署模式，Memory Guard 监听 `127.0.0.1`；默认且当前实现。 |
| **Remote Agent Profile** | 远程 Agent 经 Aegis Memory Gateway 访问本地 Guard；可选/高级，数据不离开用户设备。 |

## 5. Protocol Overview

### 5.1 Architecture

<img src="https://www.uomp.org/diagrams/spec-architecture-local-zh.svg" alt="本地路径：CLI 授权 → 0600 env 文件 → Agent/MCP 客户端 → Auth + Guard → Store/Audit" class="diagram" />
<img src="https://www.uomp.org/diagrams/spec-architecture-mcp-zh.svg" alt="MCP 路径：MCP 客户端 → stdio bridge → Auth + Guard → Store/Audit" class="diagram" />
<img src="https://www.uomp.org/diagrams/spec-architecture-remote-zh.svg" alt="远程路径（可选）：Remote Agent → Gateway → Guard → Store" class="diagram" />

UOMP 的完整架构包含以下组件：

| 组件 | 位置 | 职责 |
|------|------|------|
| **Memory Store** | 用户本机 | 持久化存储记忆数据。支持可插拔后端（SQLite、加密对象/S3、IPFS），通过 `IMemoryStore` 接口抽象。 |
| **Auth Service** | 用户本机 | 会话管理、Token 签发、身份验证。参考实现中与 Memory Guard 组合为 `uomp serve`。 |
| **Memory Guard** | 用户本机 | Token 校验、scope 过滤、聚合查询、审计日志记录。 |
| **CLI** | 用户本机 | 用户交互：导入、授权、会话、审计、撤销。 |
| **MCP bridge** | 用户本机（可选） | stdio MCP 适配器（`uomp mcp`）：Claude Desktop / Cursor / OpenCode → HTTP Guard。实验能力。 |
| **Aegis Memory Gateway** | 用户本机（可选） | mTLS/Tunnel 入口，把远程 Agent 的已校验请求转发给本地 Guard；参考实现由 Aegis OS 提供。 |
| **Agent** | 任意位置 | 独立进程，携带 Capability Token 通过 Guard 或 Gateway 读取数据。 |

三条访问路径：

1. **本地（默认）**：CLI 完成授权并把 Token 写入 `0600` 会话 env 文件；Agent 直接访问 `127.0.0.1:9374` 上的 Guard。
2. **MCP（本地适配器，实验）**：MCP 客户端通过 stdio 启动 `uomp mcp`；bridge 读取同一个会话 env 文件，再以 HTTP + Token 访问 Guard。MCP bridge 不引入新的信任边界。
3. **远程（可选/高级）**：远程 Agent（参考实现：Aegis Cloud）通过 Aegis Memory Gateway（mTLS + Tunnel）访问本地 Guard；数据留在本机。

Local Profile 和它的 MCP 适配器是当前参考实现的主路径；Remote Agent Profile 是可选扩展，不要求所有实现支持。

### 5.2 Flow

1. Agent 作为独立进程运行，提供 `uom.json` 声明其身份和默认请求的记忆范围。
2. 用户运行一次 `uomp setup`（或手动 `uomp authorize`）。Agent 第一次请求数据时，Auth Service 创建 Session（`created` 状态），UOMP 打开本地审批页；用户确认后签发 Token。Auth Service 可以与 Memory Guard / Store 位于同一机器，也可以由用户选择的可信服务提供。
3. 用户确认或调整授权范围后，Auth Service 签发 Capability Token，并将其写入 `0600` 会话 env 文件（`UOM_TOKEN` + `UOMP_BASE_URL`）。
4. Session 进入 `active` 状态，Agent 或 MCP bridge 加载该 env 文件。
5. Agent 或 MCP bridge 通过 HTTP API 携带 Token 访问 Memory Guard。
6. Memory Guard 校验 Token，按 scope 过滤数据，返回结果并记录审计日志。
7. Agent 任务完成、超时、或用户撤销时，Session 关闭，Token 失效。

Agent 与 UI/CLI 是独立进程。UI/CLI 运行在 Memory Store / Guard 所在的用户本机，负责身份验证、授权决策和 Token 交付；Agent 只负责使用 Token 访问数据，不接触用户私钥。

MCP bridge 遵循同样的步骤 4-6，只是把 Agent 侧传输从直接 HTTP 换成 stdio JSON-RPC。它不改变 Token、scope、撤销或审计语义。

### 5.3 Profiles

UOMP 定义两种部署配置：

| Profile | 默认端口 | 传输 | 认证 | 存储 | 状态 |
|---------|---------|------|------|------|------|
| Local Profile | `127.0.0.1:9374` | HTTP | Capability Token | SQLite（本地） | 默认 / 当前实现 |
| Remote Agent Profile | 用户配置 | HTTPS + mTLS | Capability Token + mTLS | 本地（数据不离开用户设备） | 可选 / 高级；参考实现 Aegis |

Local Profile 为默认且 RECOMMENDED 配置，也是参考实现的主路径。Remote Agent Profile 必须显式开启。

MCP bridge 不是独立 Profile，而是 Local Profile 上的可选 stdio 适配器。

## 6. Agent Manifest: `uom.json`

### 6.1 Location

Agent 必须在可执行文件同级目录或包根目录提供 `uom.json`。

### 6.2 Format

```json
{
  "uomp_version": "1.0",
  "agent": {
    "id": "calendar_agent",
    "name": "日程助手",
    "version": "1.2.0",
    "description": "帮助用户管理日程",
    "publisher": "example-org"
  },
  "package": {
    "checksum": "sha256:abc123...",
    "signature": "ed25519:def456...",
    "source_url": "https://github.com/example/calendar-agent/releases/v1.2.0"
  },
  "requested_scopes": {
    "read": {
      "tags": ["preference", "identity:public"],
      "keys": [],
      "fields": {
        "preference": ["key", "value"],
        "identity:public": ["key", "value", "sensitivity"]
      },
      "purposes": {
        "preference": "读取用户偏好设置以个性化日程建议",
        "identity:public": "获取公开身份信息以匹配用户时区"
      },
      "description": "读取用户偏好和公开身份信息"
    },
    "write": {
      "tags": ["preference"],
      "keys": [],
      "description": "写入与日程相关的偏好设置"
    }
  },
  "required_capabilities": ["memory.read"],
  "optional_capabilities": ["memory.query"],
  "requires_remote": false,
  "external_data_sources": [],
  "data_retention_policy": {
    "max_retention_seconds": 300,
    "deletion_method": "process_termination",
    "proof_required": false,
    "description": "Agent 在任务完成后 5 分钟内清除所有用户数据"
  },
  "identity": {
    "did": "did:ethr:0xabc123...",
    "verification_methods": ["did", "gpg", "x509"],
    "proof": {
      "type": "Ed25519Signature2020",
      "created": "2026-07-12T10:00:00Z",
      "proofValue": "..."
    }
  }
}
```

### 6.3 Fields

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `uomp_version` | string | MUST | 协议版本，当前为 `"1.0"`。 |
| `agent.id` | string | MUST | Agent 唯一标识符。 |
| `agent.name` | string | MUST | 人类可读的名称。 |
| `agent.version` | string | MUST | 语义化版本。 |
| `agent.description` | string | OPTIONAL | 功能描述。 |
| `agent.publisher` | string | OPTIONAL | 发布者名称。 |
| `requested_scopes` | object | MUST | 默认请求的记忆范围。 |
| `required_capabilities` | string[] | OPTIONAL | 必需能力列表。 |
| `optional_capabilities` | string[] | OPTIONAL | 可选能力列表。 |
| `requires_remote` | boolean | OPTIONAL | 是否必须远程连接，默认 `false`。 |
| `external_data_sources` | object[] | OPTIONAL | Agent 需要的外部数据源描述（如行情 API）。 |
| `package` | object | RECOMMENDED | 包的完整性校验信息。 |
| `package.checksum` | string | OPTIONAL | 包哈希（如 `sha256:abc123...`），用于 connect 验证。 |
| `package.signature` | string | OPTIONAL | 发布者对 `checksum` 的数字签名。 |
| `package.source_url` | string | OPTIONAL | 包的来源 URL。 |
| `data_retention_policy` | object | RECOMMENDED | Agent 声明其数据保留策略，见 §6.5。 |
| `identity` | object | OPTIONAL | 发布者身份验证信息。 |

### 6.4 Scope Object

Scope Object 用于 `requested_scopes.read` 和 `requested_scopes.write`：

```json
{
  "tags": ["preference"],
  "keys": ["user.display_name"],
  "deny_tags": ["financial"],
  "deny_keys": ["user.password"],
  "allowed_fields": ["key", "value", "tags", "sensitivity"],
  "fields": {
    "preference": ["key", "value"],
    "identity:public": ["key", "value", "sensitivity"]
  },
  "purposes": {
    "preference": "读取用户偏好设置以个性化建议",
    "identity:public": "获取公开身份信息以匹配用户时区"
  },
  "description": "说明为何需要此范围"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `tags` | string[] | MUST | 请求授权的标签列表。 |
| `keys` | string[] | MUST | 请求授权的具体键列表。 |
| `deny_tags` | string[] | OPTIONAL | 显式拒绝的标签。 |
| `deny_keys` | string[] | OPTIONAL | 显式拒绝的键。 |
| `allowed_fields` | string[] | OPTIONAL | 每个 Memory Item 中允许返回的字段列表。未指定时返回完整 item。 |
| `fields` | object | OPTIONAL | 按 tag 细分的允许字段映射。`{ "tag_name": ["field1", "field2"] }`。比 `allowed_fields` 更精细。 |
| `purposes` | object | OPTIONAL | 按 tag 细分的用途说明。`{ "tag_name": "用途描述" }`。用于授权面板展示。 |
| `description` | string | RECOMMENDED | 总体用途说明，用于授权面板展示。 |

### 6.5 Data Retention Policy

Agent SHOULD 在 `uom.json` 中声明数据保留策略，向用户透明其数据处理方式。UOMP 不会在技术层面强制执行此策略，但会将其展示给用户以供做出知情授权决策。

```json
{
  "data_retention_policy": {
    "max_retention_seconds": 300,
    "deletion_method": "process_termination",
    "proof_required": false,
    "description": "Agent 在任务完成后 5 分钟内清除所有用户数据",
    "third_party_sharing": false,
    "encryption_at_rest": true
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `max_retention_seconds` | number | MUST | Agent 承诺在任务完成后最多保留数据的秒数。`0` 表示执行期间即时丢弃，不持久化。 |
| `deletion_method` | string | MUST | 删除方法：`process_termination`（进程结束后由 OS 回收）、`secure_wipe`（主动覆写）、`ephemeral_storage`（无持久磁盘）。 |
| `proof_required` | boolean | OPTIONAL | 默认 `false`。若为 `true`，Agent MUST 在 Session 关闭前提交删除证明（见 §19）。 |
| `description` | string | RECOMMENDED | 人类可读的保留策略说明。 |
| `third_party_sharing` | boolean | OPTIONAL | 默认 `false`。Agent 是否会将用户数据分享给第三方（如外部 API）。 |
| `encryption_at_rest` | boolean | OPTIONAL | 默认 `false`。Agent 是否对暂存的用户数据做静态加密。 |

**保留级别参考**：

| 级别 | `max_retention_seconds` | `deletion_method` | 适用场景 |
|------|------------------------|-------------------|---------|
| 零保留 | `0` | `process_termination` | 无状态函数/容器，数据不入磁盘 |
| 短保留 | 300–600 | `process_termination` | 单次任务结束后即丢弃 |
| 会话保留 | 与 Token 过期时间一致 | `secure_wipe` | 缓存到 Session 结束 |
| 无保证 | 声明为与 TTL 的较大值 | 任意 | 用户需在授权面板看到红色警告 |

## 7. Capability Token

### 7.1 Format

Capability Token 采用 JWT 格式，由 Auth Service 使用私钥签名。

```json
{
  "version": "1.0",
  "session_id": "sess_abc123",
  "agent_id": "calendar_agent",
  "issued_at": "2026-07-12T10:00:00Z",
  "expires_at": "2026-07-12T10:30:00Z",
  "scopes": {
    "read": {
      "tags": ["preference"],
      "keys": ["user.display_name"],
      "deny_tags": ["financial"],
      "deny_keys": []
    },
    "write": {
      "tags": [],
      "keys": [],
      "deny_tags": ["identity"],
      "deny_keys": []
    }
  },
  "limits": {
    "max_read_queries": 50,
    "max_write_queries": 10
  },
  "profile": "local",
  "audience": "http://127.0.0.1:9374",
  "allowed_endpoints": ["127.0.0.1"],
  "allowed_fields": ["key", "value", "tags", "sensitivity"],
  "aggregation_only": false,
  "task_bound": false
}
```

### 7.2 Claims

UOMP Capability Token 的 JWT payload 使用以下自定义 claims（snake_case）。同时，Auth Service MUST 设置标准 JWT claims `iat`（签发时间）和 `exp`（过期时间）；Memory Guard MUST 同时接受并校验 `exp` 与 `expires_at`。

| Claim | 类型 | 必填 | 说明 |
|-------|------|------|------|
| `version` | string | MUST | Token 格式版本。 |
| `session_id` | string | MUST | 绑定 Session。 |
| `agent_id` | string | MUST | Agent 标识。 |
| `issued_at` | ISO8601 | MUST | 签发时间，与标准 `iat` 保持一致。 |
| `expires_at` | ISO8601 | MUST | 过期时间，与标准 `exp` 保持一致。 |
| `scopes` | object | MUST | 读写授权范围。 |
| `limits` | object | OPTIONAL | 查询次数限制。MVP 中写入但不强制扣除。 |
| `profile` | string | OPTIONAL | `local` 或 `remote`，默认 `local`。 |
| `audience` | string | OPTIONAL | Token 绑定的 Memory Guard 端点。Remote Agent Profile 时 REQUIRED。 |
| `allowed_endpoints` | string[] | OPTIONAL | 允许使用该 Token 的网络位置白名单。 |
| `allowed_fields` | string[] | OPTIONAL | 每个 Memory Item 中允许返回的字段列表。Memory Guard MUST 按此字段过滤返回数据。 |
| `aggregation_only` | boolean | OPTIONAL | 默认 `false`。若为 `true`，仅允许聚合查询，禁止返回单个 Memory Item 原始数据。 |
| `task_bound` | boolean | OPTIONAL | 默认 `false`。若为 `true`，Token 绑定到单次任务，Agent 完成任务后 MUST 提交删除证明并销毁 Token。 |

JWT Header SHOULD 包含 `alg` 与 `kid`，以便 Key 轮换与验证。

### 7.3 Validity

Auth Service 和 Memory Guard 在收到 Token 后 MUST 执行以下校验：

1. Token 签名有效。
2. 当前时间早于 `expires_at` / 标准 `exp` claim。
3. Token 对应的 Session 未被关闭或撤销（MVP 中通过黑名单表实现；生产实现 SHOULD 显式查询 Session 状态）。
4. Token 不在黑名单中。
5. `profile` 与当前部署配置匹配。
6. `audience` 与当前 Memory Guard 端点匹配（Remote Agent Profile 时 REQUIRED）。

任一校验失败，Memory Guard MUST 拒绝请求并返回错误。

## 8. HTTP API

### 8.1 Base URL

- Local Profile: `http://127.0.0.1:9374`
- Remote Agent Profile: 用户配置的 HTTPS URL

### 8.2 Versioning

API 路径包含主版本号：

```
/v1/sessions
/v1/memory/:key
```

### 8.3 Authentication

所有 Agent 请求 MUST 在 HTTP 头中携带 Token：

```http
Authorization: Bearer <capability-token>
```

### 8.4 Error Format

所有错误响应 MUST 使用统一格式：

```json
{
  "error": {
    "code": "ACCESS_DENIED",
    "message": "Key is not within granted scope",
    "session_id": "sess_abc123"
  }
}
```

常见错误码：

| 错误码 | 说明 |
|--------|------|
| `INVALID_TOKEN` | Token 签名无效或格式错误。 |
| `TOKEN_EXPIRED` | Token 已过期。 |
| `SESSION_REVOKED` | Session 已被撤销。 |
| `ACCESS_DENIED` | 请求超出授权范围。 |
| `QUOTA_EXCEEDED` | 查询次数已耗尽。 |
| `WRITE_NOT_AVAILABLE` | MVP 阶段写入接口未启用。 |
| `STORE_UNAVAILABLE` | Memory Store 不可用。 |
| `SESSION_NOT_FOUND` | Session 不存在或已被删除。 |
| `INVALID_REQUEST` | 请求格式或参数不正确。 |

## 9. Auth Service API

### 9.1 Create Session

```http
POST /v1/sessions
Content-Type: application/json
```

Request:

```json
{
  "agent_id": "calendar_agent",
  "agent_name": "日程助手",
  "requested_scopes": {
    "read": {
      "tags": ["preference", "identity:public"],
      "keys": []
    }
  },
  "duration_minutes": 30
}
```

Response:

```json
{
  "session_id": "sess_abc123",
  "status": "created",
  "agent_id": "calendar_agent",
  "requested_scopes": { ... },
  "expires_at": "2026-07-12T10:30:00Z"
}
```

### 9.2 Grant Session

```http
POST /v1/sessions/:id/grant
Content-Type: application/json
```

Request:

```json
{
  "granted_scopes": {
    "read": {
      "tags": ["preference"],
      "keys": ["user.display_name"]
    }
  }
}
```

Response:

```json
{
  "token": "<jwt-capability-token>",
  "token_type": "Bearer",
  "expires_at": "2026-07-12T10:30:00Z"
}
```

### 9.3 Close Session

```http
POST /v1/sessions/:id/close
```

Response:

```json
{
  "session_id": "sess_abc123",
  "status": "closed"
}
```

### 9.4 Revoke Session

```http
POST /v1/sessions/:id/revoke
```

Revoke MUST 使对应 Token 立即失效，并将其加入持久化黑名单。

### 9.5 Validate Token

```http
POST /v1/tokens/validate
Content-Type: application/json
```

Request:

```json
{
  "token": "<jwt-capability-token>"
}
```

Response:

```json
{
  "valid": true,
  "session_id": "sess_abc123",
  "expires_at": "2026-07-12T10:30:00Z"
}
```

### 9.6 Deletion Proof

若 Agent 的 `uom.json` 声明 `proof_required: true`，Agent MUST 在 Session 关闭前提交删除证明。具体格式和流程见 §19。

```http
POST /v1/sessions/{session_id}/deletion-proof
Authorization: Bearer <token>
Content-Type: application/json

{
  "deletion_proof_id": "del_xxx",
  "session_id": "sess_abc123",
  "agent_id": "calendar_agent",
  "deleted_at": "2026-07-12T10:35:00Z",
  "memory_hash": "sha256:abc123...",
  "fields_accessed": ["key", "value"],
  "method": "process_termination",
  "proof_value": "base64-encoded-agent-signature..."
}
```

Response (accepted):

```json
{
  "status": "accepted",
  "deletion_proof_id": "del_xxx"
}
```

Auth Service MUST 校验 `session_id` 与路径一致，并记录审计日志。若 Token 设置了 `task_bound: true`，提交删除证明后 Session 自动关闭。

## 10. Memory Guard API

### 10.1 Endpoints

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/v1/memory/:key` | 按 Key 读取 |
| GET | `/v1/memory?tag=:tag` | 按 Tag 读取 |
| GET | `/v1/memory/aggregate?tag=:tag&op=:op&field=:field` | 聚合查询（sum/avg/count/min/max），不返回原始数据，见 §10.5 |
| GET | `/v1/audit` | 查询审计日志，见 §18 |
| POST | `/v1/memory/query` | 语义查询（未来扩展） |
| PUT | `/v1/memory/:key` | 暂存写入；返回 `202` + `staged_write_id`，用户批准后生效 |
| DELETE | `/v1/memory/:key` | 删除（MVP 返回 `WRITE_NOT_AVAILABLE`） |
| GET | `/v1/staged-writes` | 列出待审批写入（管理员） |
| POST | `/v1/staged-writes/:id/approve` | 批准并应用暂存写入（管理员） |
| POST | `/v1/staged-writes/:id/deny` | 拒绝暂存写入（管理员） |
| POST | `/v1/payload` | 上传加密 payload envelope |
| GET | `/v1/payload/:id` | 读取 payload（同 session 或管理员） |
| GET | `/v1/payload` | 列出 payload 元数据（管理员） |
| DELETE | `/v1/payload/:id` | 删除 payload（管理员） |
| POST | `/v1/remote/requests` | 远程 Agent 发起授权请求（公开，返回 poll secret） |
| GET | `/v1/remote/requests/:id?secret=:poll_secret` | 轮询审批状态；批准后一次性领取 token |

### 10.2 Read by Key

```http
GET /v1/memory/preference.theme
Authorization: Bearer <token>
```

Response:

```json
{
  "key": "preference.theme",
  "value": "dark",
  "tags": ["preference", "ui"],
  "sensitivity": "low",
  "source": "user",
  "updated_at": "2026-07-12T10:00:00Z"
}
```

### 10.3 Read by Tag

```http
GET /v1/memory?tag=preference
Authorization: Bearer <token>
```

Response:

```json
{
  "items": [
    {
      "key": "preference.theme",
      "value": "dark",
      "tags": ["preference", "ui"],
      "sensitivity": "low"
    }
  ]
}
```

### 10.4 Access Control

Memory Guard MUST 按以下顺序判定访问权限：

1. Token 签名有效。
2. Token 未过期（同时校验标准 `exp` claim 与 `expires_at`）。
3. Token 对应的 Session 未被关闭或撤销（MVP 通过黑名单表实现）。
4. Token 不在黑名单。
5. 查询次数未耗尽（MVP 预留，暂不强制）。
5b. 若 Token 的 `aggregation_only` 为 `true`，非聚合路径（`/v1/memory/:key` 或 `/v1/memory?tag=`）MUST 被拒绝。
6. 目标 Key 或 Tag 在对应 action 的授权范围内。
7. 目标 Key 或 Tag 未被显式拒绝（`deny_keys` / `deny_tags` 优先于允许列表）。
8. `sensitivity=high` 的 Memory Item 不能通过 tag 授权访问，必须命中 `keys`。

对于 `GET /v1/memory?tag=:tag`，Guard 首先校验该 tag 是否被允许；对于返回的每个 Memory Item，还须按 key 级规则再次过滤（应用 deny、keys、sensitivity 规则）。

任一检查失败，MUST 返回 `ACCESS_DENIED` 并记录审计日志。

### 10.5 Aggregation Query

当 Token 设置 `aggregation_only: true` 时，Agent 只能调用聚合接口，无法获取单个 Memory Item 原始数据。聚合查询返回的是计算结果（求和、均值、计数、最小值、最大值），不返回任何个体 key 或 value。

```http
GET /v1/memory/aggregate?tag=portfolio:holdings&op=sum&field=value.market_value
Authorization: Bearer <token>
```

Query Parameters:

| 参数 | 必填 | 说明 |
|------|------|------|
| `tag` | MUST | 要聚合的标签。 |
| `op` | MUST | 操作类型：`sum`、`avg`、`count`、`min`、`max`。 |
| `field` | 数值聚合时 REQUIRED | 要聚合的字段路径（如 `value.market_value`）。`count` 操作不需要此参数。 |

Response (`op=sum`):

```json
{
  "op": "sum",
  "field": "value.market_value",
  "result": 39000
}
```

Response (`op=count`):

```json
{
  "op": "count",
  "tag": "portfolio:holdings",
  "result": 10
}
```

Guard MUST 先校验该 tag 的访问授权（与普通 tag 查询一致），然后对授权范围内的 items 执行聚合计算。聚合结果 MUST NOT 泄漏任何单个 item 的 key 或 value。

## 11. Memory Item

### 11.1 Format

```json
{
  "key": "preference.theme",
  "value": "dark",
  "tags": ["preference", "ui"],
  "sensitivity": "low",
  "source": "user",
  "created_at": "2026-07-01T10:00:00Z",
  "updated_at": "2026-07-12T10:00:00Z",
  "description": "用户界面主题偏好"
}
```

### 11.2 Fields

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `key` | string | MUST | 唯一标识符，建议使用点分命名空间。 |
| `value` | any | MUST | 记忆值。 |
| `tags` | string[] | MUST | 标签列表。 |
| `sensitivity` | enum | MUST | `low`、`medium`、`high`。 |
| `source` | string | MUST | `user` 或 `agent`。 |
| `created_at` | ISO8601 | MUST | 创建时间。 |
| `updated_at` | ISO8601 | MUST | 更新时间。 |
| `description` | string | OPTIONAL | 人类可读描述。 |

### 11.3 Sensitivity Rules

- `sensitivity=high` 的 Memory Item 不能通过 tag 授权访问。
- Agent 写入 MUST 进入 Staging，用户批准后生效。
- Agent 写入高敏感项 MUST 被拒绝。

## 12. Memory Import Format

### 12.1 Overview

UOMP 不仅定义了 Agent 如何访问 Memory，也定义了用户如何把外部数据导入 Memory Store。统一的导入格式让不同数据源（CSV、JSON、数据库导出等）能够无歧义地映射为 Memory Item。

### 12.2 Design Goals

- **通用性**：不绑定任何具体应用场景。
- **简单性**：普通用户可以用 CSV/JSON/Markdown 直接导入。
- **可扩展性**：允许实现者定义字段别名和映射规则。
- **安全性**：导入时必须明确指定 tag 和 sensitivity。

### 12.3 Supported Input Formats

- **CSV**：UTF-8 编码，第一行为表头，逗号分隔。
- **JSON**：单个对象或对象数组。
- **Markdown / Obsidian**：单个 `.md` 文件或目录；目录路径和 frontmatter 用于生成 tags，正文作为 value。

### 12.4 CSV Format Requirements

1. 文件编码 MUST be UTF-8。
2. 第一行 MUST be 表头。
3. 分隔符 SHOULD be 英文逗号；实现 MAY 支持其他分隔符。
4. 字段值包含分隔符时 MUST 用双引号包裹。
5. 空行 SHOULD be 忽略。
6. 数值字段 SHOULD NOT 包含货币符号或千分位符号；实现 MAY 自动清洗。
7. 日期字段 SHOULD be ISO8601；实现 MAY 识别常见格式并转换。

### 12.5 JSON Format Requirements

1. 根节点 MAY be 单个对象或对象数组。
2. 每个对象 MAY contain：
   - `key` (string)
   - `value` (object)
   - `tags` (string or string array)
   - `sensitivity` (`low` | `medium` | `high`)
   - `source` (string)
   - `description` (string)
   - `created_at` / `updated_at` (ISO8601)

If `value` is omitted, all non-reserved top-level fields are treated as `value.*`.

### 12.6 Reserved Fields

The following top-level fields have protocol meaning and are NOT part of `value`：

- `key`
- `tags`
- `sensitivity`
- `source`
- `description`
- `created_at`
- `updated_at`

All other top-level fields belong to `value`.

### 12.7 Field Mapping

Implementations SHOULD support canonical field aliases：

| Memory Item Field | Canonical Aliases |
|-------------------|-------------------|
| `key` | `key`, `id`, `item_id`, `record_id` |
| `tags` | `tags`, `tag` |
| `sensitivity` | `sensitivity`, `level` |
| `source` | `source`, `origin` |
| `description` | `description`, `desc` |
| `created_at` | `created_at`, `created` |
| `updated_at` | `updated_at`, `updated` |

Implementations MAY support locale-specific aliases (e.g., Chinese names) and user-defined mappings via `--map` or equivalent configuration.

### 12.8 Sensitivity

Imported data MUST have an explicit sensitivity. If the input does not specify sensitivity, the import tool MUST either：

1. Require the user to specify it via CLI/GUI, or
2. Refuse the import.

Implementations MAY provide application-specific default sensitivity based on tag, but such defaults MUST be clearly communicated to the user.

### 12.9 Validation

Before writing to Memory Store, the import tool MUST validate：

1. `key` is present and non-empty for every record.
2. `key` is unique within the target tag (unless `--replace` is specified).
3. `sensitivity` is one of `low`, `medium`, `high`.
4. `tags` is non-empty.
5. `created_at` and `updated_at`, if present, are valid ISO8601 timestamps.

### 12.10 Markdown / Obsidian

Markdown/Obsidian 导入面向本地知识库，SHOULD 遵循：

1. 输入 MAY 是单个 `.md` 文件或目录；目录 MUST 递归处理。
2. 参考实现 SHOULD 跳过隐藏目录（如 `.obsidian`）和 `node_modules`。
3. 路径 SHOULD 生成稳定的 tag 层级：基础 tag（默认 `notes`）+ 每一级目录名。例如 `projects/uomp/plan.md` 生成 `notes`、`notes/projects`、`notes/projects/uomp`。
4. YAML frontmatter 的 `tags` MUST 保留并合并；`title`、`description`、`sensitivity` SHOULD 映射到 Memory Item 元数据。
5. key SHOULD 由相对路径稳定生成；参考实现使用 `note.<path-with-dots>`（如 `note.projects.uomp.plan`）。
6. 正文 SHOULD 作为 `value.content`，并保留 `value.path` 与 `value.title`。
7. 重复导入 MUST 按 key upsert，而不是重复插入。
8. 实现 SHOULD 提供 dry-run 模式，只报告将新增/更新/跳过的条目，不写入 Store。

### 12.11 示例

#### CSV Example

```csv
key,tags,sensitivity,value.title,value.content
note-1,notes,low,Shopping list,Buy milk
contact-1,contacts,medium,Alice,alice@example.com
```

#### JSON Example

```json
[
  {
    "key": "note-1",
    "tags": ["notes"],
    "sensitivity": "low",
    "value": {
      "title": "Shopping list",
      "content": "Buy milk"
    }
  },
  {
    "key": "contact-1",
    "tags": ["contacts"],
    "sensitivity": "medium",
    "value": {
      "name": "Alice",
      "email": "alice@example.com"
    }
  }
]
```

## 13. Session

### 13.1 States

```
[created] --grant--> [active] --close/timeout/revoke/deletion-proof--> [closed/expired/revoked]
```

### 13.2 Fields

```json
{
  "session_id": "sess_abc123",
  "agent_id": "calendar_agent",
  "status": "active",
  "created_at": "2026-07-12T10:00:00Z",
  "expires_at": "2026-07-12T10:30:00Z",
  "closed_at": null,
  "granted_scopes": { ... },
  "token_hash": "sha256:..."
}
```

### 13.3 Multi-Session Support

UOMP MUST 支持多个独立 Session 同时存在。每个 Session 拥有独立的 Token 和生命周期。不同 Session 的访问 MUST 独立审计。

### 13.4 Real-Time Revocation

Session 撤销后，对应 Token MUST 立即失效。Auth Service MUST 将 Token 加入持久化黑名单，Memory Guard 每次收到请求 MUST 先检查黑名单。

## 14. Local Profile

### 14.1 Requirements

- Memory Guard MUST 默认监听 `127.0.0.1:9374`。
- Memory Guard MUST NOT 默认绑定到 `0.0.0.0` 或公网接口。
- Local Profile 下的 Token `profile` claim MUST 为 `"local"`。

### 14.2 Token Delivery

在 Local Profile 中，Token 由用户本机的 Auth Service/CLI 签发。参考实现默认把 Token 写入权限为 `0600` 的会话 env 文件，再由 Agent/MCP bridge 读取：

```bash
# ~/.uomp/sessions/<session_id>.env
export UOM_TOKEN='<capability-token>'
export UOMP_BASE_URL='http://127.0.0.1:9374'

# Agent 终端
source ~/.uomp/sessions/<session_id>.env
uom-calendar-agent
```

- `UOM_TOKEN`：Capability Token，Agent 凭此访问 Guard。
- `UOMP_BASE_URL`：Guard 端点地址，Local Profile 下默认为 `http://127.0.0.1:9374`。
- 参考 CLI 默认不把完整 JWT 打印到终端；需要显式复制时使用 `--print-token`。

用户 UI（如 CLI）运行在 Memory Store / Guard 所在主机上，负责完成身份验证、授权、Token 签发，再把 Token 交给 Agent。Agent 本身不参与授权决策。MCP bridge 读取同一个 env 文件，并在每次工具调用前重新读取，以支持重新授权后自动生效。

## 15. Remote Agent Profile (optional)

### 15.1 Overview

> Remote Agent Profile 是 OPTIONAL / 高级能力，不是本地优先工作流的必要条件。

Remote Agent Profile 允许 Agent 不在用户本机运行时访问用户记忆。远程 Agent 的运行时 SHOULD 放在 Aegis Cloud 或用户自己的隔离环境；用户本地 MUST 通过 **Aegis Memory Gateway**（或等价的、用户信任的 Gateway）暴露 Memory Guard。Memory Guard MUST NOT 直接暴露到公网。

> **参考实现方向：** Aegis Cloud（远程 Agent 运行时）+ Aegis Memory Gateway（本地入口）+ Aegis policy / lease / approval。UOMP 不再维护独立的 Gateway 或 Cloud Relay 产品线；`apps/gateway` 和 `apps/relay` 仅作为历史参考。

### 15.2 Security Requirements

Remote Agent Profile 实现 MUST 满足：

1. Gateway 与远程 Agent 之间使用 **TLS 1.3**。
2. Gateway SHOULD 使用 **mTLS**，远程 Agent 持有用户或 Registry 签发的客户端证书。
3. 用户本地 Auth Service 签发的 Capability Token：
   - `profile` claim MUST 为 `"remote"`；
   - `audience` claim MUST 绑定到 Gateway 端点，而不是本地 `127.0.0.1`；
   - `allowed_endpoints` claim SHOULD 限制允许访问的 Gateway 网络位置。
4. Gateway MUST 校验 Token 签名、有效期、`audience`、Session 撤销状态以及请求路径。
5. Token 有效期 SHOULD 不超过 10 分钟；需要长期运行的 Agent SHOULD 使用 refresh_token 机制（见 15.5）。
6. 用户 MUST 显式开启 Remote Agent Profile 并确认 Gateway 配置。
7. Gateway 与本地 Memory Guard 之间 SHOULD 通过 mTLS 或本地 Unix socket 通信。
8. 远程 Agent MUST NOT 获得 Memory Store 的直接文件访问；只有经过 Gateway 的 scoped response 可以离开用户设备。
9. Gateway MUST 由用户信任的运行时执行；参考实现使用 Aegis OS 的 policy、lease、sandbox 与 trusted approval。

### 15.3 Deployment Models

推荐部署：

- **远程 Agent：** Aegis Cloud 的隔离 VM / 容器。
- **本地入口：** Aegis Memory Gateway，运行在用户设备上，通过 mTLS / Tunnel 接受远程连接。
- **数据面：** Memory Store 始终留在用户设备；Aegis Cloud 不保存记忆数据。

用户也可以自托管 Gateway（VPS、NAS、家庭服务器），或使用满足本节要求的第三方 Gateway。UOMP 不再提供托管的公共 Cloud Relay；任何第三方 Gateway MUST NOT 成为可读取明文的透明中继。

### 15.4 Aegis Memory Gateway

Aegis Memory Gateway 是 Memory Guard 的受控入口，承担以下职责：

| 职责 | 说明 |
|------|------|
| TLS/mTLS 终止 | 校验远程 Agent 的传输层身份 |
| Token 校验 | 验证 Capability Token 的签名、作用域、有效期、撤销状态 |
| 请求转发 | 把已校验的请求转发给本地 Memory Guard |
| 配额执行 | 根据 Token 的 `limits` 限制请求次数 |
| 审计记录 | 记录 `gateway_access` 事件 |
| Payload 缓存 | 临时存储加密的 Agent 输出（可选） |

Gateway 暴露的 HTTP API SHOULD 至少包含：

```http
GET  /v1/health
POST /v1/sessions/{session_id}/refresh
GET  /v1/memory/{key}
GET  /v1/memory?tag={tag}
GET  /v1/memory/aggregate?tag={tag}&op={op}
GET  /v1/audit?session_id={session_id}
POST /v1/payload
GET  /v1/payload/{payload_id}
POST /v1/sessions/{session_id}/deletion-proof
```

所有请求 MUST 携带：

```http
Authorization: Bearer <gateway-token>
X-UOMP-Agent-Id: <agent_id>
```

> **实现参考：** Aegis OS 的 memory gateway / policy / lease 集成；`uomp-mvp` 的 `apps/gateway` 仅保留为历史实现，不再作为产品入口。

### 15.5 Token Refresh

远程 Agent 可能因长时间运行或 SaaS 重启而需要刷新 Token：

1. 初始授权时，Auth Service 除了签发短期 `access_token`，还签发 `refresh_token`：
   - refresh_token 只能用于换取新的 access_token，不能用于读取 Memory；
   - refresh_token 的 `scopes` claim MUST 为空或仅含 `refresh`；
   - 有效期可配置，默认 7 天。
2. Agent 在 access_token 过期前调用 Gateway：
   ```http
   POST /v1/sessions/{session_id}/refresh
   Authorization: Bearer <refresh_token>
   ```
3. Gateway 验证 refresh_token 和 Session 状态后，向本地 Auth Service 申请新的 access_token 并返回。
4. 用户撤销 Session 时，refresh_token MUST 同步失效。

### 15.6 Payload Delivery

Agent 生成的报告、分析结果等 Payload 不应以明文形式留在远程服务器。Remote Agent Profile 要求：

1. **端到端加密**：Agent 使用 Remote Agent Profile 中用户提供的公钥加密 Payload（推荐 ECDH-X25519 + AES-256-GCM）。
2. **Payload Envelope**：上传的 Payload MUST 使用以下格式：
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
3. **Delivery modes**：
   - `gateway-cache`：Agent POST 到 Gateway，用户从 Gateway 拉取；
   - `presigned-url`：Gateway 提供一次性上传 URL，Agent 上传后返回引用；
   - `object-store`：用户信任的对象存储，密文 + hash。

用户本地私钥 SHOULD 受 keystore 或系统 keychain 保护。

### 15.7 Migration to DIDComm

UOMP 长期计划从 mTLS HTTPS 迁移到 **DIDComm v2** 作为授权协商与 Token 交付通道。MVP 阶段 mTLS HTTPS 为默认通道，DIDComm 作为可选扩展。

迁移策略：

1. Phase 1：Agent 同时声明 mTLS endpoint；DIDComm 为可选。
2. Phase 2：Agent 同时声明 mTLS endpoint 与 DIDComm service endpoint；用户端优先尝试 DIDComm。
3. Phase 3：新 Agent 可仅支持 DIDComm；旧 Agent 通过适配层继续支持 mTLS。

预留 DIDComm 消息类型：

- `uomp/authorize-request`
- `uomp/authorize-response`
- `uomp/payload-ready`
- `uomp/session-revoked`

## 16. Agent Identity Verification

### 16.1 Overview

UOMP 支持多种 Agent 发布者身份验证机制。身份验证由**用户本机上的 UI/CLI** 执行，Agent 进程本身不参与身份验证，也不应接触用户私钥或授权决策。

### 16.2 Supported Methods

| 方法 | 说明 |
|------|------|
| DID | 去中心化标识符，如 `did:ethr`、`did:web`。 |
| GPG | 发布者使用 GPG 密钥签名 `uom.json`。 |
| X.509 | 发布者使用 CA 签发的证书签名。 |
| Registry | ERC8004 等 Registry 提供的验证状态。 |

### 16.3 Verification Process

1. 用户本机的 UI/CLI 读取 `uom.json` 中的 `identity` 字段。
2. 根据 `verification_methods` 选择验证方式。
3. 验证 `uom.json` 的签名或证明。
4. 验证结果展示给用户；只有用户确认后才允许创建 Session 并签发 Token。

### 16.4 Trust Policy

- 用户 MAY 配置信任列表：信任的 DID、GPG Key ID、CA、Registry。
- 未通过身份验证的 Agent MAY 被允许运行，但用户本机的授权面板 MUST 提示"未验证发布者"。
- 企业部署 MAY 强制要求特定验证方式，未通过验证的 Agent MUST NOT 获得 Token。

## 17. Agent Registry

### 17.1 Overview

UOMP 核心协议不定义 Agent Registry。协议参考实现 MAY 支持现有 Registry 标准，如 ERC8004。

### 17.2 Registry Client

MVP 参考实现 SHOULD 提供以下 CLI 命令：

```bash
uomp registry search <keyword>
uomp registry install <agent_id>
```

Registry 客户端 MUST 返回 Agent 元数据和 `uom.json` 位置，但 MUST NOT 参与授权决策。

### 17.3 Registry Independence

- 用户 MUST 能够不通过 Registry 直接安装和运行 Agent。
- 授权决策 MUST 始终在用户本地完成。

## 18. Audit and Logging

### 18.1 Audit Log Entry

```json
{
  "id": "log_xxx",
  "timestamp": "2026-07-12T10:05:00Z",
  "session_id": "sess_abc123",
  "agent_id": "calendar_agent",
  "action": "read",
  "key": "preference.theme",
  "tags": ["preference", "ui"],
  "allowed": true,
  "reason": "scope matched",
  "request_size": 0,
  "response_size": 12,
  "query_count_remaining": 49
}
```

### 18.2 Required Fields

每条审计日志 MUST 包含：

- `timestamp`
- `session_id`
- `agent_id`
- `action`
- `key` 或 `tag`
- `allowed`
- `reason`

### 18.3 Storage

- 审计日志 MUST 与 Memory Store 分开存储。
- 审计日志保留时长 MUST 可配置，默认 90 天。
- 审计日志 SHOULD 加密存储，防止 Agent 篡改。

### 18.4 Blockchain Extension

> **[PLANNED — Phase 4]** 本节所描述的链上审计能力尚未在参考实现中可用。当前审计日志仅存储在本地 SQLite 中。完整设计文档见 `docs/on-chain-audit-design.md`。

UOMP MAY 将授权、撤销和访问事件锚定到 Starknet，利用链的不可篡改性和事件日志的低成本特性。协议本身不强制特定链，但 RECOMMENDED 默认支持 Starknet（低成本、高频事件、原生 paymaster），可选 EVM 兼容链。

#### 18.4.1 Event Types

链上合约 `AuditAnchor` 为纯事件发射器，零 storage write：

```solidity
event Authorization(
  bytes32 indexed sessionId,
  bytes32 indexed agentId,
  string[] scopes,           // ["portfolio:holdings", "profile:risk"]
  string[] allowedFields,    // ["value.market_value", "quantity"]
  uint64  duration,
  uint64  timestamp,
  uint64  nonce
);

event Revocation(
  bytes32 indexed sessionId,
  uint64  timestamp
);

event Access(
  bytes32 indexed sessionId,
  bytes32 indexed agentId,
  string   tag,              // "portfolio:holdings"
  string[] fields,           // ["value.market_value"]
  uint64   timestamp
);
```

- `sessionId` 和 `agentId` 为 `indexed`，支持高效过滤。
- `scopes`、`fields`、`tag` 为明文——链上观察者可看到授权了哪些数据类别，但看不到实际数据值。
- 单次 `Access` 事件的 Starknet L2 gas 费约 600 gas，低于 $0.001。

#### 18.4.2 Indexer & Verification

链下 indexer 扫描链上事件，构建可查询视图：

```
GET /v1/audit/session/{sessionId}
  → { authorization, accesses[], revocation }
```

验证路径：
1. 用户查询 indexer，获取 session 的完整审计记录。
2. 独立验证：直接查询链上 RPC，按 sessionId 过滤 event，验证 indexer 数据一致性。
3. 第三方无需信任用户或 Agent——链是唯一 truth source。

#### 18.4.3 Paymaster

Starknet 原生支持 paymaster（代付 gas）。Agent 或 relay 可 sponsor 交易，用户无需为每次 Access event 付费。授权时用户只需签名一次。

#### 18.4.4 FHE Extension (Future)

当 FHE 集成后（§22），Access event 记录 Agent 访问的密文 tag。Agent 全程只接触密文，持有密文也无法解密。结合链上审计实现完整的 trustless 闭环：用户加密 → Agent 密文计算 → 链上记录 → 用户解密结果。

- **授权事件**（`SessionGranted`、`SessionRevoked`）：数量少、关键性高，SHOULD 近实时上链。
- **访问事件**（`GatewayAccess`）：高频，SHOULD 批量上链。Gateway 每 N 分钟或每 M 条事件聚合为 Merkle tree，把 `merkleRoot` 上链，完整日志保留在本地供事后验证。
- **Payload 锚定**：每个 Payload 生成后 SHOULD 单独锚定其 hash。
- **删除证明**（`DataDeletionProofSubmitted`）：每个 Session 的删除证明 SHOULD 在提交后近实时上链。

```
本地事件 ──► 批量聚合 ──► Merkle root ──► 链上 event
                    │
                    └── 完整日志保留在 Gateway，供审计验证
```

## 19. Data Retention & Deletion Proof

### 19.1 Overview

UOMP 可以通过 Memory Guard 控制 Agent **在访问时刻**能读到什么数据，但无法从技术上保证 Agent 在读取完成后删除数据。本节定义：

1. Agent 如何在 `uom.json` 中声明数据保留策略（§6.5）。
2. 用户如何通过 Capability Token 的 `allowed_fields`、`aggregation_only`、`task_bound` 约束 Agent 的数据暴露面。
3. Agent 如何自愿提交可验证的删除证明。
4. 删除证明如何与审计日志及链上锚定集成。

### 19.2 数据暴露控制

#### allowed_fields

用户在授权时，可通过 Token 的 `allowed_fields` 指定每个 Memory Item 中允许返回的字段。Memory Guard MUST 按此过滤，只返回指定字段：

```json
{
  "allowed_fields": ["key", "value"]
}
```

若未指定 `allowed_fields`，则返回完整 Memory Item。高敏感数据（`sensitivity=high`）的 `allowed_fields` SHOULD 默认排除 `sensitivity`、`source` 等元数据。

#### aggregation_only

当 `aggregation_only: true` 时，Agent 仅被允许调用聚合查询接口（`/v1/memory/aggregate`），返回的是计算结果（求和、均值、计数等），而非单个 Memory Item 原始数据。

```http
GET /v1/memory/aggregate?tag=portfolio:holdings&op=sum&field=value.market_value
```

聚合查询 MUST NOT 返回任何单条 key 或 value。Guard MUST 拒绝 `aggregation_only` Token 对 `/v1/memory/:key` 或 `/v1/memory?tag=` 的非聚合请求。

#### task_bound

当 `task_bound: true` 时，Token 绑定到单次任务。Agent 完成任务后 MUST 调用删除证明接口，Session 自动关闭。该 Token 不可用于后续读取。

### 19.3 删除证明（Deletion Proof）

若 Agent 在 `uom.json` 中声明 `proof_required: true`，则其 MUST 在 Session 关闭前提交删除证明。证明是一个由 Agent 身份密钥签名的结构化声明：

```json
{
  "deletion_proof_id": "del_xxx",
  "session_id": "sess_abc123",
  "agent_id": "calendar_agent",
  "deleted_at": "2026-07-12T10:35:00Z",
  "memory_hash": "sha256:abc123...",
  "fields_accessed": ["key", "value"],
  "method": "process_termination",
  "proof_value": "base64-encoded-agent-signature..."
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `deletion_proof_id` | string | MUST | 本次删除证明的唯一标识。 |
| `session_id` | string | MUST | 数据所属的 Session。 |
| `agent_id` | string | MUST | Agent 标识。 |
| `deleted_at` | ISO8601 | MUST | 完成删除的时间。 |
| `memory_hash` | string | MUST | 所有已访问 Memory Item 的 `key || value` 拼接后的 SHA-256 哈希，用于事后验证 Agent 确实持有过哪些数据。 |
| `fields_accessed` | string[] | RECOMMENDED | Agent 实际读取的字段列表。 |
| `method` | string | MUST | 删除方式，必须与 `data_retention_policy.deletion_method` 一致。 |
| `proof_value` | string | MUST | Agent 使用其身份密钥对标头结构的签名。 |

### 19.4 提交流程与审计集成

Agent 通过以下接口提交删除证明：

```http
POST /v1/sessions/{session_id}/deletion-proof
Authorization: Bearer <token>
Content-Type: application/json
```

Auth Service 或 Gateway 收到后：

1. 使用 Agent 注册的身份公钥校验 `proof_value` 签名。
2. 校验 `deleted_at` ≤ Token 的 `expires_at`。
3. 将证明写入审计日志，`action` 标记为 `deletion_proof`。
4. 若 `task_bound: true`，自动关闭 Session。
5. 可选：将证明哈希锚定到链上（见 §19.6）。

若 Agent 在 Session 过期前未提交删除证明（且 `proof_required: true`），审计日志记录一条 `deletion_proof_missing` 事件。该事件可触发声誉惩罚或保证金罚没。

### 19.5 原子性保证

当 `task_bound: true` 和 `proof_required: true` 同时设置时，删除证明提交是 Session 正常关闭的前置条件。未提交证明的 Session 将被自动标记为异常，Agent 的 Registry 声誉评分下降。这提供了**经济/声誉层面的原子性保证**，作为技术不可行的补偿。

> **未来扩展**：TEE（可信执行环境）可实现技术级原子性——Agent 代码在 enclave 中运行，退出时内存自动清零，且提供硬件级 attestation 证明。

### 19.6 Deletion Proof On-Chain

删除证明可通过 `AuditAnchor` 合约（§18.4）的 `Revocation` event 记录到链上。Agent 调用 `session.finalize()` 后，Auth Service 在发出 `Revocation` 事件的同时附带删除证明哈希，确保"已删除"声明不可篡改。

> 完整链上审计设计见 §18.4 和 `docs/on-chain-audit-design.md`。

## 20. Security Considerations

### 20.1 Token Security

- Capability Token MUST 由 Auth Service 私钥签名。
- Token SHOULD 使用短有效期（默认 30 分钟，Remote Agent Profile 10 分钟）。
- Token MUST NOT 被持久化到 Agent 可任意读取的位置。

### 20.2 Memory Store Security

- Memory Store SHOULD 加密存储。
- 高敏感数据 SHOULD 额外加密。

### 20.3 Communication Security

- Local Profile 使用 HTTP over localhost。
- Remote Agent Profile MUST 使用 TLS 1.3 + mTLS。
- SDK MUST NOT 记录 Token。

### 20.4 Agent Write Restrictions

- Agent 写入 MUST 先进入 Staging，用户确认后才生效。
- Agent MUST NOT 直接修改 Memory Store。
- Agent MUST NOT 写入 `sensitivity=high` 的 Memory Item。
- 暂存写入 MUST 记录发起 Agent、Session、范围、时间和审批人。

## 21. Privacy Considerations

- UOMP 设计目标是最小化 Agent 访问的数据范围。
- 用户 SHOULD 能够查看并撤销任何活跃 Session。
- 审计日志 SHOULD 帮助用户理解 Agent 访问了哪些数据。
- Memory Guard SHOULD 避免返回授权范围外的任何数据，包括存在性信息。

## 22. Future Work

- 链上审计（Phase 4）：Starknet `AuditAnchor` 合约，Authorization / Revocation / Access 事件上链。
- **FHE 集成（Phase 7-9）**：全同态加密。Agent 在密文上计算，永远看不到明文。结合链上审计实现 trustless 数据授权闭环。详见 `docs/on-chain-audit-design.md` §10。
- 语义检索（`query` 接口）。
- 写入版本历史与回滚。
- 策略模板。
- DIDComm v2 授权通道。
- TEE（可信执行环境）Agent 执行，实现硬件级数据保留保证。
- 无状态 Agent（Stateless Agent）执行模型，任务级别隔离。
- Agent 信誉系统与 Registry 集成。

## 23. References

- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels
- [RFC 7519] JSON Web Token (JWT)
- [RFC 8446] The Transport Layer Security (TLS) Protocol Version 1.3
- [ERC8004] Agent Registry on Blockchain

---

## 附录 A: 最小交互示例

> 参考 CLI 的当前本地流程。`setup` 是一次性入口；Agent 在需要数据时发起请求，UOMP 打开审批页。`connect` 是高级预授权入口，`authorize` / `mcp --print-config` 是手动/脚本 fallback；`discover` / `inspect` / `registry` 是默认隐藏的高级命令。

```bash
# MCP 客户端：一次性设置（导入 + 写配置 + 后台服务），不授权
uomp setup claude --vault ~/Obsidian/MyVault
# 重启 Claude Desktop，然后在客户端里请求数据

# Agent 第一次请求时，UOMP 打开审批页；终端兜底：
uomp pending
uomp approve <request-id>
uomp deny <request-id>

# 高级：预授权 / 脚本
uomp connect claude --vault ~/Obsidian/MyVault --scope notes/projects

# Agent 包：授权 + 写会话 env 文件
uomp connect ./examples/calendar-agent --scope preference
source ~/.uomp/sessions/<session-id>.env
node ./examples/calendar-agent/index.js

# 手动 / 不支持的客户端
uomp serve
uomp authorize --scope notes/projects --output ~/.uomp/calendar.env --no-server
uomp mcp --session ~/.uomp/calendar.env --print-config

# 查看会话与审计
uomp sessions
uomp audit --limit 20

# 断开客户端 / 停止后台服务 / 撤销会话
uomp disconnect claude
uomp stop
uomp revoke <session-id>
```

---

## 附录 B: `uom.json` 完整示例

```json
{
  "uomp_version": "1.0",
  "agent": {
    "id": "calendar_agent",
    "name": "日程助手",
    "version": "1.2.0",
    "description": "帮助用户管理日程和待办事项",
    "publisher": "example-org"
  },
  "requested_scopes": {
    "read": {
      "tags": ["preference", "identity:public"],
      "keys": [],
      "description": "读取用户偏好和公开身份信息，以提供个性化日程建议"
    },
    "write": {
      "tags": ["preference"],
      "keys": [],
      "description": "写入与日程相关的偏好设置"
    }
  },
  "required_capabilities": ["memory.read"],
  "optional_capabilities": ["memory.query"],
  "requires_remote": false,
  "data_retention_policy": {
    "max_retention_seconds": 300,
    "deletion_method": "process_termination",
    "proof_required": false,
    "description": "Agent 在任务完成后 5 分钟内清除所有用户数据"
  },
  "identity": {
    "did": "did:ethr:0xabc123...",
    "verification_methods": ["did", "gpg"],
    "proof": {
      "type": "Ed25519Signature2020",
      "created": "2026-07-12T10:00:00Z",
      "proofValue": "..."
    }
  }
}
```
