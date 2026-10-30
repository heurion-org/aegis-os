# User-Owned Memory Protocol (UOMP)

**Version**: Draft-00<br>
**Status**: Draft<br>
**Published**: 2026-07-12<br>
**Last Updated**: 2026-10-29<br>
**Goal**: Public RFC draft for community review

### Version History

| Date | Change |
|------|--------|
| 2026-07-12 | Draft-00 initial release. |
| 2026-07-23 | Added Cloud Relay (§15.7), Store abstraction (§0), Payload API (§15.6). Updated `uom.json` schema (§6.2-6.4) with `fields`, `purposes`, `external_data_sources`, `package`. Updated the architecture diagram to include Gateway and Relay. Added FHE to Future Work (§22). Marked on-chain audit as Phase 4. |
| 2026-10-29 | Local-first reference implementation: CLI + stdio MCP path, 0600 session env delivery, Auth + Guard combined service. Reworked §5 architecture and diagrams; Remote remains optional/preview. |
| 2026-10-30 | Remote Agent Profile aligned with Aegis OS: remote Agent runs on Aegis Cloud, local entry is Aegis Memory Gateway. Standalone UOMP Cloud Relay retired. |

---

## 1. Abstract

The User-Owned Memory Protocol (UOMP) defines a user-sovereign authorization protocol that allows users to temporarily grant AI Agents access to their personal memory data (preferences, settings, identity attributes, etc.). Authorization takes effect on a per-session basis, scoped by Tag or Key, and is revoked immediately when the session ends or is revoked. UOMP runs locally by default and defines an extension mechanism for remote Agents.

## 2. Status of This Memo

This document is the UOMP protocol draft (Draft-00). It describes the protocol design intent, data formats, HTTP API, and security requirements. It is intended to evolve into a formal standard through public discussion. The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

> **Reference implementation status (2026-10):** the current `uomp` reference CLI implements the Local Profile first: the user runs `uomp setup` once to import notes, write the client config, and start the background server without pre-authorizing. The agent's first request for a tag/key opens the local consent page; the user approves and the call continues. `pending` / `approve` / `deny` are the terminal fallback; `connect` is the advanced pre-authorize path, and `authorize`, `serve`, and `mcp` are manual/script paths. The stdio MCP bridge is experimental. Remote Agent Profile is optional; the reference implementation uses Aegis Cloud + Aegis Memory Gateway. The standalone Cloud Relay is retired. Aegis OS is the reference runtime that enforces the protocol.

## 3. Introduction

### 3.1 Motivation

When AI Agents provide services to users, they typically require access to personal data. Existing solutions often require users to upload data to the Agent provider's server, leading to:

- Users losing direct control over their data.
- Agents potentially retaining user data indefinitely.
- Users having difficulty auditing what Agents have accessed.

UOMP's design goals are:

- **Users always own their memory data**.
- **Every access requires temporary authorization**.
- **Authorization scope is minimized**.
- **Authorization expires immediately after the session ends**.
- **All access is auditable**.

### 3.2 Design Principles

- **Local-first**: In the default deployment model, Memory Guard runs on the local machine and only listens on `127.0.0.1`.
- **Capability-based authorization**: Uses short-lived Capability Tokens to express authorization scope.
- **Tag/Key scoping**: Authorization can be granted by tag or exact key.
- **Session-bound**: Tokens are bound to a specific Session and expire when the Session ends.
- **Transport-agnostic core**: The core protocol is based on HTTP but can be extended to other transports.

## 4. Terminology

| Term | Definition |
|------|------------|
| **Memory** | User personal memory data, including preferences, settings, identity attributes, etc. |
| **Memory Item** | A single memory record containing key, value, tags, sensitivity, and other metadata. |
| **Memory Store** | User-side persistent storage for Memory Items. |
| **Memory Guard** | Access proxy layer that validates authorization, filters data, and records audit logs. |
| **Auth Service** | Session management component responsible for creating/closing Sessions and issuing/validating Capability Tokens. |
| **Session** | A single Agent task cycle with a unique `session_id`. |
| **Capability Token** | Session-level authorization credential specifying the Agent's accessible tag/key scope. |
| **Agent** | A program that accesses user memory through UOMP, running locally or remotely. |
| **MCP bridge** | Optional stdio adapter (`uomp mcp`) that translates MCP tool calls into Guard HTTP requests. |
| **uom.json** | Agent manifest file describing the Agent's identity and default requested memory scope. |
| **Local Profile** | Local deployment model where Memory Guard listens on `127.0.0.1`; default and current implementation. |
| **Remote Agent Profile** | Remote Agent reaches local Guard through Aegis Memory Gateway; optional/advanced, data never leaves the user device. |

## 5. Protocol Overview

### 5.1 Architecture

<img src="https://www.uomp.org/diagrams/spec-architecture-local-en.svg" alt="Local path: CLI authorize → 0600 env file → Agent/MCP client → Auth + Guard → Store/Audit" class="diagram" />
<img src="https://www.uomp.org/diagrams/spec-architecture-mcp-en.svg" alt="MCP path: MCP client → stdio bridge → Auth + Guard → Store/Audit" class="diagram" />
<img src="https://www.uomp.org/diagrams/spec-architecture-remote-en.svg" alt="Remote path (optional): Remote Agent → Gateway → Guard → Store" class="diagram" />

UOMP's complete architecture includes the following components:

| Component | Location | Responsibility |
|-----------|----------|----------------|
| **Memory Store** | User's machine | Persistent memory data storage. Supports pluggable backends (SQLite, encrypted object/S3, IPFS) via the `IMemoryStore` interface. |
| **Auth Service** | User's machine | Session management, token issuance, identity verification. Combined with Memory Guard as `uomp serve` in the reference implementation. |
| **Memory Guard** | User's machine | Token validation, scope filtering, aggregate queries, audit logging. |
| **CLI** | User's machine | User interaction: import, authorize, sessions, audit, revoke. |
| **MCP bridge** | User's machine (optional) | stdio MCP adapter (`uomp mcp`): Claude Desktop / Cursor / OpenCode → HTTP Guard. Experimental. |
| **Aegis Memory Gateway** | User's machine (optional) | mTLS/tunnel entry point that forwards validated remote Agent requests to local Guard; reference implementation provided by Aegis OS. |
| **Agent** | Anywhere | Independent process carrying a Capability Token to read data via Guard or Gateway. |

Three access paths:

1. **Local (default)**: the CLI authorizes and writes the token to a `0600` session env file; the Agent accesses Guard directly at `127.0.0.1:9374`.
2. **MCP (local adapter, experimental)**: the MCP client starts `uomp mcp` over stdio; the bridge reads the same session env file and calls Guard over HTTP + Token. The MCP bridge does not add a new trust boundary.
3. **Remote (optional/advanced)**: a remote Agent (reference: Aegis Cloud) reaches local Guard through Aegis Memory Gateway (mTLS + Tunnel); data stays local.

The Local Profile and its MCP adapter are the current reference implementation path. Remote Agent Profile is an optional extension and is not required for all implementations.

### 5.2 Flow

1. The Agent runs as an independent process and provides a `uom.json` declaring its identity and default requested memory scope.
2. The user runs `uomp setup` once (or `uomp authorize` manually). When the agent first requests data, the Auth Service creates a Session in the `created` state and UOMP opens the local consent page; the Token is issued after the user approves. The Auth Service may run on the same machine as the Memory Guard / Store or may be provided by a trusted service chosen by the user.
3. After the user confirms or adjusts the authorization scope, the Auth Service issues a Capability Token and writes it to a `0600` session env file (`UOM_TOKEN` + `UOMP_BASE_URL`).
4. The Session enters the `active` state, and the Agent or MCP bridge loads the env file.
5. The Agent or MCP bridge calls Memory Guard via the HTTP API with the Token.
6. Memory Guard validates the Token, filters data by scope, returns results, and records audit logs.
7. When the Agent task completes, times out, or the user revokes, the Session closes and the Token becomes invalid.

The Agent and UI/CLI are separate processes. The UI/CLI runs on the user's machine where the Memory Store / Guard lives, and is responsible for identity verification, authorization decisions, and Token delivery. The Agent only uses the Token to access data and never touches the user's private keys.

The MCP bridge follows the same steps 4-6, replacing the Agent-side transport with stdio JSON-RPC. It does not change Token, scope, revocation, or audit semantics.

### 5.3 Profiles

UOMP defines two deployment profiles:

| Profile | Default Port | Transport | Authentication | Storage | Status |
|---------|--------------|-----------|----------------|---------|--------|
| Local Profile | `127.0.0.1:9374` | HTTP | Capability Token | SQLite (local) | Default / current implementation |
| Remote Agent Profile | User-configured | HTTPS + mTLS | Capability Token + mTLS | Local (data never leaves the user device) | Optional / advanced; reference: Aegis |

Local Profile is the default and RECOMMENDED configuration, and the reference implementation's primary path. Remote Agent Profile MUST be explicitly enabled.

The MCP bridge is not a separate profile; it is an optional stdio adapter over the Local Profile.

## 6. Agent Manifest: `uom.json`

### 6.1 Location

The Agent MUST provide a `uom.json` in the same directory as the executable or in the package root.

### 6.2 Format

```json
{
  "uomp_version": "1.0",
  "agent": {
    "id": "calendar_agent",
    "name": "Calendar Assistant",
    "version": "1.2.0",
    "description": "Helps manage your schedule",
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
        "preference": "Read user preferences to personalize schedule suggestions",
        "identity:public": "Get public identity info to match user timezone"
      },
      "description": "Read user preferences and public identity info"
    },
    "write": {
      "tags": ["preference"],
      "keys": [],
      "description": "Write schedule-related preferences"
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
    "description": "Agent clears all user data within 5 minutes after task completion"
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

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uomp_version` | string | MUST | Protocol version, currently `"1.0"`. |
| `agent.id` | string | MUST | Unique Agent identifier. |
| `agent.name` | string | MUST | Human-readable name. |
| `agent.version` | string | MUST | Semantic version. |
| `agent.description` | string | OPTIONAL | Function description. |
| `agent.publisher` | string | OPTIONAL | Publisher name. |
| `requested_scopes` | object | MUST | Default requested memory scope. |
| `required_capabilities` | string[] | OPTIONAL | List of required capabilities. |
| `optional_capabilities` | string[] | OPTIONAL | List of optional capabilities. |
| `requires_remote` | boolean | OPTIONAL | Whether remote connection is required, default `false`. |
| `external_data_sources` | object[] | OPTIONAL | External data sources required by the agent (e.g., market data API). |
| `package` | object | RECOMMENDED | Package integrity verification information. |
| `package.checksum` | string | OPTIONAL | Package hash (e.g., `sha256:abc123...`), used by `connect`. |
| `package.signature` | string | OPTIONAL | Publisher's digital signature over the `checksum`. |
| `package.source_url` | string | OPTIONAL | Source URL of the package. |
| `data_retention_policy` | object | RECOMMENDED | Agent declares its data retention policy, see §6.5. |
| `identity` | object | OPTIONAL | Publisher identity verification information. |

### 6.4 Scope Object

The Scope Object is used in `requested_scopes.read` and `requested_scopes.write`:

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
    "preference": "Read user preferences to personalize suggestions",
    "identity:public": "Get public identity info to match user timezone"
  },
  "description": "Why this scope is needed"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tags` | string[] | MUST | List of tags requested for authorization. |
| `keys` | string[] | MUST | List of specific keys requested for authorization. |
| `deny_tags` | string[] | OPTIONAL | Explicitly denied tags. |
| `deny_keys` | string[] | OPTIONAL | Explicitly denied keys. |
| `allowed_fields` | string[] | OPTIONAL | Fields allowed to return per Memory Item. If absent, return the full item. |
| `fields` | object | OPTIONAL | Per-tag field-level allow map. `{ "tag_name": ["field1", "field2"] }`. More granular than `allowed_fields`. |
| `purposes` | object | OPTIONAL | Per-tag purpose descriptions. `{ "tag_name": "purpose text" }`. Displayed on the authorization panel. |
| `description` | string | RECOMMENDED | Overall purpose description for the authorization panel. |

### 6.5 Data Retention Policy

The Agent SHOULD declare a data retention policy in `uom.json` to be transparent to users about its data handling practices. UOMP does not technologically enforce this policy, but surfaces it to users for informed authorization decisions.

```json
{
  "data_retention_policy": {
    "max_retention_seconds": 300,
    "deletion_method": "process_termination",
    "proof_required": false,
    "description": "Agent clears all user data within 5 minutes after task completion",
    "third_party_sharing": false,
    "encryption_at_rest": true
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `max_retention_seconds` | number | MUST | Maximum seconds the Agent promises to retain data after task completion. `0` means no persistence — discarded immediately. |
| `deletion_method` | string | MUST | How data is deleted: `process_termination` (OS reclaims after process exit), `secure_wipe` (active overwrite), `ephemeral_storage` (no persistent disk). |
| `proof_required` | boolean | OPTIONAL | Default `false`. If `true`, the Agent MUST submit a deletion proof before the Session closes (see §19). |
| `description` | string | RECOMMENDED | Human-readable retention policy description. |
| `third_party_sharing` | boolean | OPTIONAL | Default `false`. Whether the Agent shares user data with third parties (e.g., external APIs). |
| `encryption_at_rest` | boolean | OPTIONAL | Default `false`. Whether the Agent encrypts temporarily stored user data at rest. |

**Retention levels**:

| Level | `max_retention_seconds` | `deletion_method` | Use case |
|-------|------------------------|-------------------|----------|
| Zero retention | `0` | `process_termination` | Stateless function/container; data never touches disk |
| Short retention | 300–600 | `process_termination` | Discard after each task |
| Session retention | matches Token expiry | `secure_wipe` | Cached until Session ends |
| No guarantee | large value | any | User sees red warning in authorization panel |

## 7. Capability Token

### 7.1 Format

The Capability Token uses JWT format and is signed by the Auth Service's private key.

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

The UOMP Capability Token JWT payload uses the following custom claims (snake_case). The Auth Service MUST also set the standard JWT claims `iat` (issued at) and `exp` (expiration time); the Memory Guard MUST accept and validate both `exp` and `expires_at`.

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | MUST | Token format version. |
| `session_id` | string | MUST | Bound Session. |
| `agent_id` | string | MUST | Agent identifier. |
| `issued_at` | ISO8601 | MUST | Issue time, consistent with standard `iat`. |
| `expires_at` | ISO8601 | MUST | Expiration time, consistent with standard `exp`. |
| `scopes` | object | MUST | Read/write authorization scope. |
| `limits` | object | OPTIONAL | Query count limits. Written but not enforced in MVP. |
| `profile` | string | OPTIONAL | `local` or `remote`, default `local`. |
| `audience` | string | OPTIONAL | Memory Guard endpoint bound to the Token. REQUIRED for Remote Agent Profile. |
| `allowed_endpoints` | string[] | OPTIONAL | Network location whitelist for Token use. |
| `allowed_fields` | string[] | OPTIONAL | Fields allowed to return per Memory Item. Memory Guard MUST filter results to include only these fields. |
| `aggregation_only` | boolean | OPTIONAL | Default `false`. If `true`, only aggregation queries are permitted; returning individual Memory Item raw data is forbidden. |
| `task_bound` | boolean | OPTIONAL | Default `false`. If `true`, the Token is bound to a single task; the Agent MUST submit a deletion proof after completion and destroy the Token. |

The JWT Header SHOULD include `alg` and `kid` to support key rotation and verification.

### 7.3 Validity

Upon receiving a Token, the Auth Service and Memory Guard MUST perform the following validations:

1. Token signature is valid.
2. Current time is before `expires_at` / standard `exp` claim.
3. The Session bound to the Token has not been closed or revoked (in the MVP this is implemented via a blacklist table; production implementations SHOULD explicitly query Session status).
4. Token is not in the blacklist.
5. `profile` matches the current deployment profile.
6. `audience` matches the current Memory Guard endpoint (REQUIRED for Remote Agent Profile).

If any validation fails, Memory Guard MUST reject the request and return an error.

## 8. HTTP API

### 8.1 Base URL

- Local Profile: `http://127.0.0.1:9374`
- Remote Agent Profile: User-configured HTTPS URL

### 8.2 Versioning

API paths include the major version:

```
/v1/sessions
/v1/memory/:key
```

### 8.3 Authentication

All Agent requests MUST include the Token in the HTTP header:

```http
Authorization: Bearer <capability-token>
```

### 8.4 Error Format

All error responses MUST use a unified format:

```json
{
  "error": {
    "code": "ACCESS_DENIED",
    "message": "Key is not within granted scope",
    "session_id": "sess_abc123"
  }
}
```

Common error codes:

| Error Code | Description |
|------------|-------------|
| `INVALID_TOKEN` | Invalid Token signature or format. |
| `TOKEN_EXPIRED` | Token has expired. |
| `SESSION_REVOKED` | Session has been revoked. |
| `ACCESS_DENIED` | Request exceeds authorized scope. |
| `QUOTA_EXCEEDED` | Query quota exhausted. |
| `WRITE_NOT_AVAILABLE` | Write interface not enabled in MVP. |
| `STORE_UNAVAILABLE` | Memory Store unavailable. |
| `SESSION_NOT_FOUND` | Session does not exist or has been deleted. |
| `INVALID_REQUEST` | Request format or parameters are invalid. |

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
  "agent_name": "Calendar Assistant",
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

Revoke MUST immediately invalidate the corresponding Token and add it to the persistent blacklist.

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

If the Agent declares `proof_required: true` in its `uom.json`, it MUST submit a deletion proof before the Session is closed. See §19 for the full structure and flow.

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
{ "status": "accepted", "deletion_proof_id": "del_xxx" }
```

The Auth Service MUST verify `session_id` matches the path. If the Token has `task_bound: true`, the Session is automatically closed after the proof is accepted.

## 10. Memory Guard API

### 10.1 Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/memory/:key` | Read by key |
| GET | `/v1/memory?tag=:tag` | Read by tag |
| GET | `/v1/memory/aggregate?tag=:tag&op=:op&field=:field` | Aggregation query (sum/avg/count/min/max), no raw data, see §10.5 |
| GET | `/v1/audit` | Query audit logs, see §18 |
| POST | `/v1/memory/query` | Semantic query (not in MVP) |
| PUT | `/v1/memory/:key` | Stage a write; returns `202` + `staged_write_id`; applied after user approval |
| DELETE | `/v1/memory/:key` | Delete (MVP returns `WRITE_NOT_AVAILABLE`) |
| GET | `/v1/staged-writes` | List pending writes (admin) |
| POST | `/v1/staged-writes/:id/approve` | Approve and apply a staged write (admin) |
| POST | `/v1/staged-writes/:id/deny` | Deny a staged write (admin) |
| POST | `/v1/payload` | Upload an encrypted payload envelope |
| GET | `/v1/payload/:id` | Read a payload (same session or admin) |
| GET | `/v1/payload` | List payload metadata (admin) |
| DELETE | `/v1/payload/:id` | Delete a payload (admin) |
| POST | `/v1/remote/requests` | Remote Agent requests access (public; returns a poll secret) |
| GET | `/v1/remote/requests/:id?secret=:poll_secret` | Poll status; retrieve a one-time token after approval |

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

Memory Guard MUST determine access permissions in the following order:

1. Token signature is valid.
2. Token has not expired (validate both the standard `exp` claim and `expires_at`).
3. The Session bound to the Token has not been closed or revoked (MVP uses a blacklist table).
4. Token is not in the blacklist.
5. Query quota has not been exhausted (reserved in MVP, not enforced).
5b. If Token `aggregation_only` is `true`, non-aggregation paths (`/v1/memory/:key` or `/v1/memory?tag=`) MUST be rejected.
6. Target Key or Tag is within the authorized scope for the action.
7. Target Key or Tag is not explicitly denied (`deny_keys` / `deny_tags` take precedence over allow lists).
8. `sensitivity=high` Memory Items cannot be accessed via tag authorization and MUST match `keys`.

For `GET /v1/memory?tag=:tag`, Guard MUST first validate that the tag itself is allowed; each returned Memory Item MUST then be filtered again using key-level rules (applying deny, keys, and sensitivity rules).

If any check fails, MUST return `ACCESS_DENIED` and record an audit log.

### 10.5 Aggregation Query

When the Token has `aggregation_only: true`, the Agent can only call aggregation endpoints — no individual Memory Item raw data is returned.

```http
GET /v1/memory/aggregate?tag=portfolio:holdings&op=sum&field=value.market_value
Authorization: Bearer <token>
```

Query parameters:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tag` | MUST | Tag to aggregate. |
| `op` | MUST | Operation: `sum`, `avg`, `count`, `min`, `max`. |
| `field` | REQUIRED for numeric ops | Field path to aggregate (e.g. `value.market_value`). Not needed for `count`. |

Response (`op=sum`):

```json
{ "op": "sum", "field": "value.market_value", "result": 39000 }
```

Response (`op=count`):

```json
{ "op": "count", "tag": "portfolio:holdings", "result": 10 }
```

The Guard MUST first validate tag access authorization (same as regular tag queries), then compute the aggregation over authorized items. Aggregation results MUST NOT leak any individual key or value.

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
  "description": "User interface theme preference"
}
```

### 11.2 Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key` | string | MUST | Unique identifier, dot-separated namespace recommended. |
| `value` | any | MUST | Memory value. |
| `tags` | string[] | MUST | Tag list. |
| `sensitivity` | enum | MUST | `low`, `medium`, or `high`. |
| `source` | string | MUST | `user` or `agent`. |
| `created_at` | ISO8601 | MUST | Creation time. |
| `updated_at` | ISO8601 | MUST | Update time. |
| `description` | string | OPTIONAL | Human-readable description. |

### 11.3 Sensitivity Rules

- `sensitivity=high` Memory Items cannot be accessed via tag authorization.
- Agent writes MUST enter Staging and take effect only after user approval.
- Agent writes to high-sensitivity items MUST be rejected.

## 12. Memory Import Format

### 12.1 Overview

UOMP defines not only how Agents access Memory, but also how users populate the Memory Store from external data sources. A standard import format allows data from CSV, JSON, database exports, and other sources to be mapped unambiguously to Memory Items.

### 12.2 Design Goals

- **Generality**: Not tied to any specific application domain.
- **Simplicity**: Ordinary users can import using CSV, JSON, or Markdown directly.
- **Extensibility**: Implementations may define field aliases and mapping rules.
- **Security**: The tag and sensitivity of imported data must be explicit.

### 12.3 Supported Input Formats

- **CSV**: UTF-8 encoded, first row is a header, comma-separated.
- **JSON**: A single object or an array of objects.
- **Markdown / Obsidian**: A single `.md` file or a directory; directory paths and frontmatter generate tags, and the body becomes the value.

### 12.4 CSV Format Requirements

1. The file MUST be UTF-8 encoded.
2. The first row MUST be a header row.
3. The delimiter SHOULD be a comma; implementations MAY support other delimiters.
4. Field values containing the delimiter MUST be wrapped in double quotes.
5. Empty lines SHOULD be ignored.
6. Numeric fields SHOULD NOT contain currency symbols or thousand separators; implementations MAY clean them automatically.
7. Date fields SHOULD be ISO8601; implementations MAY recognize common formats and convert them.

### 12.5 JSON Format Requirements

1. The root node MAY be a single object or an array of objects.
2. Each object MAY contain:
   - `key` (string)
   - `value` (object)
   - `tags` (string or string array)
   - `sensitivity` (`low` | `medium` | `high`)
   - `source` (string)
   - `description` (string)
   - `created_at` / `updated_at` (ISO8601)

If `value` is omitted, all non-reserved top-level fields are treated as `value.*`.

### 12.6 Reserved Fields

The following top-level fields have protocol meaning and are NOT part of `value`:

- `key`
- `tags`
- `sensitivity`
- `source`
- `description`
- `created_at`
- `updated_at`

All other top-level fields belong to `value`.

### 12.7 Field Mapping

Implementations SHOULD support canonical field aliases:

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

Imported data MUST have an explicit sensitivity. If the input does not specify sensitivity, the import tool MUST either:

1. Require the user to specify it via CLI/GUI, or
2. Refuse the import.

Implementations MAY provide application-specific default sensitivity based on tag, but such defaults MUST be clearly communicated to the user.

### 12.9 Validation

Before writing to the Memory Store, the import tool MUST validate:

1. `key` is present and non-empty for every record.
2. `key` is unique within the target tag (unless `--replace` is specified).
3. `sensitivity` is one of `low`, `medium`, `high`.
4. `tags` is non-empty.
5. `created_at` and `updated_at`, if present, are valid ISO8601 timestamps.

### 12.10 Markdown / Obsidian

Markdown/Obsidian import targets local knowledge bases and SHOULD follow these rules:

1. Input MAY be a single `.md` file or a directory; directories MUST be processed recursively.
2. The reference implementation SHOULD skip hidden directories (such as `.obsidian`) and `node_modules`.
3. Paths SHOULD produce a stable tag hierarchy: a base tag (default `notes`) plus each directory segment. For example, `projects/uomp/plan.md` produces `notes`, `notes/projects`, and `notes/projects/uomp`.
4. YAML frontmatter `tags` MUST be preserved and merged; `title`, `description`, and `sensitivity` SHOULD map to Memory Item metadata.
5. Keys SHOULD be stable and derived from the relative path; the reference implementation uses `note.<path-with-dots>` (for example `note.projects.uomp.plan`).
6. The body SHOULD become `value.content`, preserving `value.path` and `value.title`.
7. Re-importing MUST upsert by key instead of inserting duplicates.
8. Implementations SHOULD provide a dry-run mode that reports new/updated/skipped items without writing to the Store.

### 12.11 Examples

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

UOMP MUST support multiple independent Sessions existing simultaneously. Each Session has its own Token and lifecycle. Access from different Sessions MUST be audited independently.

### 13.4 Real-Time Revocation

After a Session is revoked, the corresponding Token MUST become invalid immediately. The Auth Service MUST add the Token to the persistent blacklist, and Memory Guard MUST check the blacklist on every request.

## 14. Local Profile

### 14.1 Requirements

- Memory Guard MUST listen on `127.0.0.1:9374` by default.
- Memory Guard MUST NOT bind to `0.0.0.0` or public interfaces by default.
- The Token's `profile` claim MUST be `"local"` under Local Profile.

### 14.2 Token Delivery

In the Local Profile, the Token is issued by the Auth Service / CLI on the user's machine. The reference implementation writes it to a `0600` session env file, which the Agent or MCP bridge then reads:

```bash
# ~/.uomp/sessions/<session_id>.env
export UOM_TOKEN='<capability-token>'
export UOMP_BASE_URL='http://127.0.0.1:9374'

# Agent terminal
source ~/.uomp/sessions/<session_id>.env
uom-calendar-agent
```

- `UOM_TOKEN`: The Capability Token the Agent uses to access Guard.
- `UOMP_BASE_URL`: The Guard endpoint address, defaulting to `http://127.0.0.1:9374` in Local Profile.
- The reference CLI does not print the full JWT by default; use `--print-token` when an explicit copy is needed.

The user UI (e.g. CLI) runs on the same host as the Memory Store / Guard, performs identity verification and authorization, issues the Token, and only then hands the Token to the Agent. The Agent itself does not participate in authorization decisions. The MCP bridge reads the same env file and re-reads it before each tool call so re-authorization takes effect without a client restart.

## 15. Remote Agent Profile (optional)

### 15.1 Overview

> Remote Agent Profile is OPTIONAL / advanced and is not required for the local-first workflow.

Remote Agent Profile allows Agents that do not run on the user's machine to access user memory. The remote Agent runtime SHOULD run in Aegis Cloud or another user-isolated environment; locally, the user MUST expose Memory Guard through an **Aegis Memory Gateway** (or an equivalent, user-trusted Gateway). Memory Guard MUST NOT be exposed directly to the public internet.

> **Reference direction:** Aegis Cloud (remote Agent runtime) + Aegis Memory Gateway (local entry point) + Aegis policy / lease / approval. UOMP no longer maintains a standalone Gateway or Cloud Relay product line; `apps/gateway` and `apps/relay` remain historical references only.

### 15.2 Security Requirements

Remote Agent Profile implementations MUST satisfy:

1. TLS 1.3 between the Gateway and the remote Agent.
2. The Gateway SHOULD use **mTLS**; the remote Agent holds a client certificate issued by the user or a Registry.
3. Capability Tokens issued by the local Auth Service:
   - the `profile` claim MUST be `"remote"`;
   - the `audience` claim MUST bind to the Gateway endpoint, not local `127.0.0.1`;
   - the `allowed_endpoints` claim SHOULD restrict the Gateway network locations the Agent may use.
4. The Gateway MUST validate the Token signature, expiry, `audience`, Session revocation state, and request path.
5. Token lifetime SHOULD NOT exceed 10 minutes; long-running Agents SHOULD use the refresh_token mechanism (see 15.5).
6. The user MUST explicitly enable Remote Agent Profile and confirm the Gateway configuration.
7. The Gateway and local Memory Guard SHOULD communicate over mTLS or a local Unix socket.
8. The remote Agent MUST NOT get direct file access to the Memory Store; only scoped responses through the Gateway may leave the user device.
9. The Gateway MUST run in a user-trusted runtime; the reference implementation uses Aegis OS policy, leases, sandboxing, and trusted approval.

### 15.3 Deployment Models

Recommended deployment:

- **Remote Agent:** an isolated Aegis Cloud VM / container.
- **Local entry point:** Aegis Memory Gateway on the user device, accepting remote connections over mTLS / a tunnel.
- **Data plane:** the Memory Store always stays on the user device; Aegis Cloud does not store memory data.

Users MAY self-host a Gateway (VPS, NAS, home server) or use a third-party Gateway that satisfies this section. UOMP no longer provides a hosted public Cloud Relay; any third-party Gateway MUST NOT become a plaintext-transparent relay.

### 15.4 Aegis Memory Gateway

Aegis Memory Gateway is the controlled entry point for Memory Guard and is responsible for:

| Responsibility | Description |
|------|-------------|
| TLS/mTLS termination | Validate the remote Agent's transport identity |
| Token validation | Verify the Capability Token signature, scope, expiry, and revocation state |
| Request forwarding | Forward validated requests to local Memory Guard |
| Quota enforcement | Enforce request limits from the Token's `limits` |
| Audit | Record `gateway_access` events |
| Payload cache | Temporarily store encrypted Agent output (optional) |

The Gateway SHOULD expose at least:

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

All requests MUST carry:

```http
Authorization: Bearer <gateway-token>
X-UOMP-Agent-Id: <agent_id>
```

> **Reference implementation:** the Aegis OS memory gateway / policy / lease integration; `uomp-mvp/apps/gateway` is kept as a historical implementation and is no longer a product entry point.

### 15.5 Token Refresh

Remote Agents may need to refresh Tokens after long runs or SaaS restarts:

1. At initial authorization, the Auth Service issues a short-lived `access_token` and a `refresh_token`:
   - the refresh_token can only be exchanged for a new access_token and cannot read Memory;
   - the refresh_token `scopes` claim MUST be empty or contain only `refresh`;
   - lifetime is configurable, default 7 days.
2. Before the access_token expires, the Agent calls the Gateway:
   ```http
   POST /v1/sessions/{session_id}/refresh
   Authorization: Bearer <refresh_token>
   ```
3. The Gateway validates the refresh_token and Session state, requests a new access_token from the local Auth Service, and returns it.
4. Revoking the Session MUST also invalidate the refresh_token.

### 15.6 Payload Delivery

Agent-generated reports and analysis results MUST NOT remain as plaintext on remote servers. Remote Agent Profile requires:

1. **End-to-end encryption**: the Agent encrypts the Payload using the public key provided in the Remote Agent Profile (RECOMMENDED: ECDH-X25519 + AES-256-GCM).
2. **Payload Envelope**: uploaded Payloads MUST use:
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
3. **Delivery modes**:
   - `gateway-cache`: Agent POSTs to the Gateway; the user pulls from the Gateway;
   - `presigned-url`: the Gateway gives the Agent a one-time upload URL; the Agent uploads and returns the reference;
   - `object-store`: a user-trusted object store holding ciphertext + hash.

The user's local private key SHOULD be protected by a keystore or system keychain.

### 15.7 Migration to DIDComm

UOMP plans to migrate from mTLS HTTPS to **DIDComm v2** for authorization negotiation and Token delivery in the long term. In MVP, mTLS HTTPS is the default channel, and DIDComm is an optional extension.

Migration strategy:

1. Phase 1: Agents declare an mTLS endpoint; DIDComm is optional.
2. Phase 2: Agents declare both mTLS and DIDComm service endpoints; user clients prefer DIDComm.
3. Phase 3: New Agents MAY support only DIDComm; legacy Agents continue to work through an mTLS adapter.

Reserved DIDComm message types:

- `uomp/authorize-request`
- `uomp/authorize-response`
- `uomp/payload-ready`
- `uomp/session-revoked`

## 16. Agent Identity Verification

### 16.1 Overview

UOMP supports multiple Agent publisher identity verification mechanisms. Identity verification is performed by the **UI/CLI on the user's machine**; the Agent process itself does not perform identity verification and must not have access to user private keys or authorization decisions.

### 16.2 Supported Methods

| Method | Description |
|--------|-------------|
| DID | Decentralized identifier, e.g., `did:ethr`, `did:web`. |
| GPG | Publisher signs `uom.json` with a GPG key. |
| X.509 | Publisher signs with a CA-issued certificate. |
| Registry | Verification status provided by registries such as ERC8004. |

### 16.3 Verification Process

1. The UI/CLI on the user's machine reads the `identity` field in `uom.json`.
2. Select the verification method according to `verification_methods`.
3. Verify the signature or proof of `uom.json`.
4. Present the result to the user; only after user confirmation may a Session be created and a Token issued.

### 16.4 Trust Policy

- Users MAY configure a trust list: trusted DIDs, GPG Key IDs, CAs, Registries.
- Agents that fail identity verification MAY be allowed to run, but the authorization panel on the user's machine MUST prompt "unverified publisher".
- Enterprise deployments MAY mandate specific verification methods; Agents that fail verification MUST NOT receive a Token.

## 17. Agent Registry

### 17.1 Overview

UOMP core protocol does not define an Agent Registry. Protocol reference implementations MAY support existing registry standards such as ERC8004.

### 17.2 Registry Client

The MVP reference implementation SHOULD provide the following CLI commands:

```bash
uomp registry search <keyword>
uomp registry install <agent_id>
```

Registry clients MUST return Agent metadata and `uom.json` location but MUST NOT participate in authorization decisions.

### 17.3 Registry Independence

- Users MUST be able to install and run Agents without using a Registry.
- Authorization decisions MUST always be made locally by the user.

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

Each audit log MUST contain:

- `timestamp`
- `session_id`
- `agent_id`
- `action`
- `key` or `tag`
- `allowed`
- `reason`

### 18.3 Storage

- Audit logs MUST be stored separately from the Memory Store.
- Audit log retention MUST be configurable, default 90 days.
- Audit logs SHOULD be encrypted to prevent Agent tampering.

### 18.4 Blockchain Extension

> **[PLANNED — Phase 4]** The on-chain audit capability described in this section is not yet available in the reference implementation. Audit logs are currently stored in local SQLite only. Full design document: `docs/on-chain-audit-design.md`.

UOMP MAY anchor authorization, revocation, and access events to Starknet, leveraging the chain's immutability and low-cost event logs. The protocol itself does not mandate a specific chain, but Starknet is RECOMMENDED as the default (low cost, high-frequency events, native paymaster), with EVM-compatible chains as an option.

#### 18.4.1 Event Types

The on-chain contract `AuditAnchor` is a pure event emitter with zero storage writes:

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

- `sessionId` and `agentId` are `indexed` for efficient filtering.
- `scopes`, `fields`, and `tag` are plaintext — chain observers can see which data categories were authorized, but not actual data values.
- A single `Access` event on Starknet L2 costs approximately 600 gas, under $0.001.

#### 18.4.2 Indexer & Verification

An off-chain indexer scans chain events and builds a queryable view:

```
GET /v1/audit/session/{sessionId}
  → { authorization, accesses[], revocation }
```

Verification path:
1. User queries the indexer for a session's complete audit record.
2. Independent verification: query chain RPC directly, filter events by sessionId, verify against the indexer.
3. Third parties need not trust the user or Agent — the chain is the single source of truth.

#### 18.4.3 Paymaster

Starknet natively supports paymasters (sponsored gas). Agents or relays can sponsor transactions so users never pay for individual Access events. The user only signs once for authorization.

#### 18.4.4 FHE Extension (Future)

When FHE integration is complete (§22), Access events will record ciphertext tags accessed by the Agent. The Agent only ever touches ciphertext and cannot decrypt even if it retains it. Combined with on-chain audit, this achieves a full trustless lifecycle: user encrypts → Agent computes on ciphertext → chain records → user decrypts results.

- **Authorization events** (`SessionGranted`, `SessionRevoked`): low volume and high criticality, SHOULD be anchored near real-time.
- **Access events** (`GatewayAccess`): high volume, SHOULD be batched. Gateway aggregates events into a Merkle tree every N minutes or every M events, anchors the `merkleRoot` on-chain, and keeps the full log locally for later verification.
- **Payload anchoring**: each Payload SHOULD have its hash anchored individually after generation.
- **Deletion proofs** (`DataDeletionProofSubmitted`): deletion proofs for each Session SHOULD be anchored near real-time after submission.

```
Local events ──► Batch aggregation ──► Merkle root ──► On-chain event
                          │
                          └── Full log retained at Gateway for audit verification
```

## 19. Data Retention & Deletion Proof

### 19.1 Overview

UOMP can control what data an Agent reads **at the point of access** via the Memory Guard, but cannot technologically guarantee the Agent deletes the data afterwards. This section defines:

1. How Agents declare retention policies in `uom.json` (§6.5).
2. How users constrain data exposure via the Capability Token (`allowed_fields`, `aggregation_only`, `task_bound`).
3. How Agents can voluntarily submit verifiable deletion proofs.
4. How deletion proofs integrate with the audit trail and optional blockchain anchoring.

### 19.2 Data Exposure Controls

#### allowed_fields

By specifying `allowed_fields` in the Capability Token, the user (or CLI rules) constrains which fields of each Memory Item are returned. The Memory Guard MUST filter every returned item to include only the specified fields:

```json
{
  "allowed_fields": ["key", "value"]
}
```

If `allowed_fields` is absent, all fields are returned. For high-sensitivity data (`sensitivity=high`), `allowed_fields` SHOULD default to exclude metadata such as `sensitivity` and `source`.

#### aggregation_only

When `aggregation_only: true`, the Agent is only permitted to call aggregation endpoints that return computed results (sum, average, count, etc.), not individual Memory Items:

```http
GET /v1/memory/aggregate?tag=portfolio:holdings&op=sum&field=value.market_value
```

Aggregation queries MUST NOT return any individual key or value. The Guard MUST reject non-aggregation requests (`/v1/memory/:key`, `/v1/memory?tag=`) from `aggregation_only` Tokens.

#### task_bound

When `task_bound: true`, the Token is valid for a single task. After the task completes, the Agent MUST call the deletion proof endpoint and the Session is automatically closed. The Token cannot be used for subsequent reads.

### 19.3 Deletion Proof

If the Agent declares `proof_required: true` in its retention policy, it MUST submit a deletion proof before the Session is closed. The proof is a structured statement signed by the Agent's identity key:

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

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `deletion_proof_id` | string | MUST | Unique identifier for this proof. |
| `session_id` | string | MUST | The Session under which data was accessed. |
| `agent_id` | string | MUST | Agent identifier. |
| `deleted_at` | ISO8601 | MUST | Timestamp when deletion was completed. |
| `memory_hash` | string | MUST | SHA-256 hash of all accessed memory item keys concatenated with their values (used for post-hoc verification of which data the Agent held). |
| `fields_accessed` | string[] | RECOMMENDED | Fields the Agent actually read. |
| `method` | string | MUST | Deletion method; must match `data_retention_policy.deletion_method`. |
| `proof_value` | string | MUST | Agent's cryptographic signature over the proof structure using its identity key. |

### 19.4 Submission & Audit Integration

The Agent submits the deletion proof via:

```http
POST /v1/sessions/{session_id}/deletion-proof
Authorization: Bearer <token>
Content-Type: application/json
```

Upon receipt, the Auth Service or Gateway:

1. Verifies the `proof_value` signature against the Agent's registered identity public key.
2. Validates that `deleted_at` ≤ Token `expires_at`.
3. Records the proof in the audit log with `action: deletion_proof`.
4. If `task_bound: true`, automatically closes the Session.
5. Optionally anchors the proof hash on-chain (§19.6).

If the Agent fails to submit a deletion proof before Session expiration (and `proof_required` was true), the audit log records a `deletion_proof_missing` event. This may trigger reputation penalties or bond forfeiture in any reputation system.

### 19.5 Atomic Guarantee

When both `task_bound: true` and `proof_required: true` are set, deletion proof submission is a prerequisite for normal Session closure. Sessions lacking a proof are marked as abnormal, and the Agent's Registry reputation score degrades. This provides an **economic/reputation-level atomicity guarantee** as compensation for the technological infeasibility.

> **Future extension**: TEE (Trusted Execution Environment) enables hardware-level atomicity — the Agent code runs inside an enclave, memory is automatically zeroed on exit, and hardware attestation is provided.

### 19.6 Deletion Proof On-Chain

Deletion proofs can be recorded on-chain via the `AuditAnchor` contract (§18.4) using the `Revocation` event. When the Agent calls `session.finalize()`, the Auth Service emits the `Revocation` event with a deletion proof hash, ensuring the "deleted" claim is immutable.

> Full on-chain audit design: see §18.4 and `docs/on-chain-audit-design.md`.

## 20. Security Considerations

### 20.1 Token Security

- Capability Tokens MUST be signed by the Auth Service's private key.
- Tokens SHOULD use short lifetimes (default 30 minutes, 10 minutes for Remote Agent Profile).
- Tokens MUST NOT be persisted to locations freely accessible by the Agent.

### 20.2 Memory Store Security

- Memory Store SHOULD be encrypted.
- High-sensitivity data SHOULD be additionally encrypted.

### 20.3 Communication Security

- Local Profile uses HTTP over localhost.
- Remote Agent Profile MUST use TLS 1.3 + mTLS.
- SDKs MUST NOT log Tokens.

### 20.4 Agent Write Restrictions

- Agent writes MUST enter Staging first and take effect only after user confirmation.
- Agents MUST NOT modify the Memory Store directly.
- Agents MUST NOT write `sensitivity=high` Memory Items.
- Staged writes MUST record the Agent, Session, scope, timestamp, and reviewer.

## 21. Privacy Considerations

- UOMP aims to minimize the scope of data accessed by Agents.
- Users SHOULD be able to view and revoke any active Session.
- Audit logs SHOULD help users understand what data Agents accessed.
- Memory Guard SHOULD avoid returning any data outside the authorized scope, including existence information.

## 22. Future Work

- **On-chain audit (Phase 4)**: Starknet `AuditAnchor` contract, Authorization / Revocation / Access events on-chain.
- **FHE integration (Phase 7-9)**: Fully Homomorphic Encryption. Agents compute on ciphertext, never see plaintext. Combined with on-chain audit for complete trustless data authorization. See `docs/on-chain-audit-design.md` §10.
- Semantic retrieval (`query` endpoint).
- Write version history and rollback.
- Policy templates.
- DIDComm v2 authorization channel.
- TEE (Trusted Execution Environment) Agent execution for hardware-level data retention guarantees.
- Stateless Agent execution model with per-task isolation.
- Agent reputation system integrated with Registry.

## 23. References

- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels
- [RFC 7519] JSON Web Token (JWT)
- [RFC 8446] The Transport Layer Security (TLS) Protocol Version 1.3
- [ERC8004] Agent Registry on Blockchain

---

## Appendix A: Minimal Interaction Example

> Current local flow for the reference CLI. `setup` is the one-time entry point; the agent requests data when needed and UOMP opens the consent page. `connect` is the advanced pre-authorize path; `authorize` / `mcp --print-config` are the manual/script fallback; `discover` / `inspect` / `registry` are advanced commands hidden from default help.

```bash
# MCP client: one-time setup (import + config + background server), no access granted
uomp setup claude --vault ~/Obsidian/MyVault
# Restart Claude Desktop, then ask it to read notes

# On the agent's first request, UOMP opens the consent page; terminal fallback:
uomp pending
uomp approve <request-id>
uomp deny <request-id>

# Advanced: pre-authorize / scripts
uomp connect claude --vault ~/Obsidian/MyVault --scope notes/projects

# Agent package: authorize + write the session env file
uomp connect ./examples/calendar-agent --scope preference
source ~/.uomp/sessions/<session-id>.env
node ./examples/calendar-agent/index.js

# Manual / unsupported clients
uomp serve
uomp authorize --scope notes/projects --output ~/.uomp/calendar.env --no-server
uomp mcp --session ~/.uomp/calendar.env --print-config

# View sessions and audit
uomp sessions
uomp audit --limit 20

# Disconnect the client / stop the background server / revoke the session
uomp disconnect claude
uomp stop
uomp revoke <session-id>
```

---

## Appendix B: Complete `uom.json` Example

```json
{
  "uomp_version": "1.0",
  "agent": {
    "id": "calendar_agent",
    "name": "Calendar Assistant",
    "version": "1.2.0",
    "description": "Helps manage your schedule and todos",
    "publisher": "example-org"
  },
  "requested_scopes": {
    "read": {
      "tags": ["preference", "identity:public"],
      "keys": [],
      "description": "Read user preferences and public identity info for personalized schedule suggestions"
    },
    "write": {
      "tags": ["preference"],
      "keys": [],
      "description": "Write schedule-related preferences"
    }
  },
  "required_capabilities": ["memory.read"],
  "optional_capabilities": ["memory.query"],
  "requires_remote": false,
  "data_retention_policy": {
    "max_retention_seconds": 300,
    "deletion_method": "process_termination",
    "proof_required": false,
    "description": "Agent clears all user data within 5 minutes after task completion"
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
