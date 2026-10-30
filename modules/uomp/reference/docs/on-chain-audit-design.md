# On-Chain Audit Design

## 1. Overview

UOMP's local audit log (SQLite) is sufficient for self-hosted verification, but has two trust gaps:

- **User deletes local data** → audit log gone, agent access history lost.
- **Third-party verification** → no way for an external party to independently verify that agent access events happened as claimed.

The solution: anchor authorization, revocation, and access events on Starknet. The chain acts as an immutable timestamped log. Anyone can verify a specific access event against chain data without trusting the user or the agent.

## 2. Events

Three event types, emitted by a thin contract with zero storage writes (event log only for minimal gas).

### 2.1 Authorization

Emitted when a user authorizes a session via `pnpm cli authorize`.

```
event Authorization(
  bytes32 indexed sessionId,
  bytes32 indexed agentId,
  string[] scopes,           // ["portfolio:holdings", "profile:risk"]
  string[] allowedFields,    // ["value.market_value", "quantity"]
  uint64  duration,          // session TTL in seconds
  uint64  timestamp,         // block timestamp
  uint64  nonce              // per-user counter
);
```

`scopes` and `allowedFields` are human-readable for auditability. The chain observer can see **what type of data** was authorized without knowing the actual data values.

### 2.2 Revocation

Emitted when a user revokes a session.

```
event Revocation(
  bytes32 indexed sessionId,
  uint64  timestamp
);
```

### 2.3 Access

Emitted for every agent read operation. Uses event log (not storage) — L2 gas is negligible per event.

```
event Access(
  bytes32 indexed sessionId,
  bytes32 indexed agentId,
  string   tag,              // "portfolio:holdings"
  string[] fields,           // ["value.market_value", "quantity"]
  uint64   timestamp
);
```

`sessionId` is indexed for cheap filtering. An indexer can query all access events for a given session with a single indexed filter.

## 3. Contract

Thin contract — no state written, only events emitted. No upgradeable proxy (immutable by design).

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

contract AuditAnchor {
    uint64 private _nonce;

    event Authorization(
        bytes32 indexed sessionId,
        bytes32 indexed agentId,
        string[] scopes,
        string[] allowedFields,
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
        string   tag,
        string[] fields,
        uint64   timestamp
    );

    function authorize(
        bytes32 sessionId,
        bytes32 agentId,
        string[] calldata scopes,
        string[] calldata allowedFields,
        uint64  duration
    ) external {
        uint64 currentNonce = _nonce++;
        emit Authorization(
            sessionId, agentId, scopes,
            allowedFields, duration,
            uint64(block.timestamp), currentNonce
        );
    }

    function revoke(bytes32 sessionId) external {
        emit Revocation(sessionId, uint64(block.timestamp));
    }

    function logAccess(
        bytes32 sessionId,
        bytes32 agentId,
        string calldata tag,
        string[] calldata fields
    ) external {
        emit Access(sessionId, agentId, tag, fields, uint64(block.timestamp));
    }
}
```

Deployed once. No admin key. No upgradability. The contract is a pure event emitter.

## 4. Gas Analysis (Starknet L2)

| Operation | Estimated gas | USD equivalent |
|-----------|--------------|----------------|
| `authorize` | ~800 | < $0.001 |
| `revoke` | ~500 | < $0.001 |
| `logAccess` | ~600 | < $0.001 |
| 100,000 accesses / month | ~60M gas | < $5 |

Starknet's event emission is extremely cheap compared to EVM L1 where event logs cost 375 + 8 gas per byte. On L2, 100,000 access events per month costs approximately $5.

### Paymaster

To avoid users paying gas for every access, the agent or a relay can sponsor transactions via Starknet's native paymaster. The authorization flow remains: user signs, agent submits, agent pays gas.

## 5. Integration Points

### 5.1 Auth Service (`packages/auth`)

After creating a session, call the contract:

```typescript
// In authorize command handler
await auditContract.authorize(
  hashSessionId(session.id),
  hashAgentId(agentId),
  scopes,          // from uom.json
  allowedFields,   // from token claims
  session.durationSeconds
);
```

### 5.2 Guard (`packages/guard`)

After serving a memory read, emit access event:

```typescript
// In memory guard handler, after successful scope check
await auditContract.logAccess(
  hashSessionId(sessionId),
  hashAgentId(agentId),
  requestedTag,
  requestedFields
);
```

### 5.3 CLI (`packages/cli`)

After revoke command:

```typescript
await auditContract.revoke(hashSessionId(sessionId));
```

### 5.4 Browser Dashboard

Same as CLI — wallet already connected, use the same signer to submit transactions through the in-browser Starknet wallet (Argent X / Braavos).

## 6. Indexer

### 6.1 What it does

Scans blocks for `AuditAnchor` events, builds a relational view:

```
sessions
  ├── authorization (scopes, fields, duration, timestamp)
  ├── accesses[]   (tag, fields, timestamp)
  └── revocation   (timestamp, null if not revoked)
```

### 6.2 API

```
GET /v1/audit/session/{sessionId}
  → { authorization, accesses[], revocation }

GET /v1/audit/session/{sessionId}/accesses?tag=portfolio:holdings&from=...
  → filtered access list

GET /v1/audit/agent/{agentId}/summary
  → { totalSessions, totalAccesses, scopesRequested[] }
```

### 6.3 Implementation options

| Option | Effort | Tradeoff |
|--------|--------|----------|
| Apibara indexer | Medium | Starknet-native, good DX |
| Ponder | Low | EVM-style, decent Starknet support |
| Custom Node.js poller | Low | Simple, less scalable |

Recommended: **Apibara** for production, **custom poller** for MVP.

## 7. Verification Flow

### User verifies agent access

```
1. User queries indexer API: GET /v1/audit/session/{id}
2. Indexer returns structured data from chain events
3. User can independently verify by:
   a. Checking chain explorer for event existence
   b. Computing sessionId = hash(local_session_id) and comparing
```

### Third-party verifier

```
1. Verifier queries chain RPC directly:
   - Filter Access events by sessionId
   - Verify Authorization event exists with matching sessionId
2. Verifier optionally queries indexer for enriched metadata
3. No trust in user or agent required — chain is source of truth
```

## 8. Privacy

### What's public

| Data | Visible on-chain | Risk |
|------|-----------------|------|
| sessionId | Yes (hashed) | None |
| agentId | Yes (hashed) | None |
| scopes | Yes (plaintext) | Observer sees data category |
| fields | Yes (plaintext) | Observer sees field names |
| tag | Yes (plaintext) | Observer sees data category |
| Actual data values | No | — |

### Scope obfuscation (optional, Phase 6)

For users who don't want to expose data categories on-chain, scopes/tags/fields can be hashed:

```
logAccess(
  sessionId,
  agentId,
  hash("portfolio:holdings"),      // not "portfolio:holdings"
  [hash("value.market_value")]      // not "value.market_value"
);
```

The indexer maps hashes back to names. The chain observer sees only opaque hashes. This is an opt-in enhancement for a later phase.

## 9. Rust / Dojo Integration

For Starknet-native deployments using Cairo/Dojo:

```cairo
#[starknet::contract]
mod audit_anchor {
    #[event]
    fn Authorization(
        session_id: felt252,
        agent_id: felt252,
        scopes: Array<ByteArray>,
        allowed_fields: Array<ByteArray>,
        duration: u64,
        timestamp: u64,
        nonce: u64
    ) {}

    #[event]
    fn Revocation(session_id: felt252, timestamp: u64) {}

    #[event]
    fn Access(
        session_id: felt252,
        agent_id: felt252,
        tag: ByteArray,
        fields: Array<ByteArray>,
        timestamp: u64
    ) {}
}
```

Dojo models can wrap these events for game-engine-style indexing, but MVP uses raw events with a standalone indexer.

## 10. FHE: The Trustless Endgame

### 10.1 The Hard Problem

Chain audit proves what an agent read — but it cannot prevent the agent from remembering the data. One plaintext access is enough. This is the fundamental limitation of any data authorization protocol: once you give the key, you give the cabinet.

### 10.2 FHE Changes Everything

**Fully Homomorphic Encryption** lets an agent compute on encrypted data. The agent never sees plaintext — it reads ciphertext, runs analysis on ciphertext, and outputs ciphertext results. Only the user with the private key can decrypt the output.

```
Current Flow:                        FHE Flow:
─────────────                        ────────
holdings.csv (plain)                 holdings.csv → FHE.encrypt → C
     │                                      │
Agent reads plain              Agent reads ciphertext C
     │                                      │
Agent remembers plain          Agent runs fheCompute(C, model)
     │                                      │
User can't revoke memory      Agent uploads ciphertext result
                                      │
                               User decrypts → report
                               Agent's "memory" = garbage bytes
```

The agent can keep the ciphertext forever — without the user's private key, it's useless.

### 10.3 UOMP + FHE Integration

```
1. User encrypts data locally
   → C = FHE.encrypt(holdings, pk_user)
   → Store C in Dropbox (already encrypted at rest)

2. User authorizes agent with FHE eval key
   → pnpm cli authorize --scope portfolio:holdings --fhe
   → UOM_TOKEN + FHE eval_key bundled
   → Chain: Authorization(scopes, fhe_enabled=true)

3. Agent computes on ciphertext
   import { UompClient } from '@uomp/sdk';
   const c = await uomp.memory.getByTag('portfolio:holdings'); // ciphertext
   const result = await uomp.fhe.compute(c, analysisFn);

4. Audit remains meaningful
   → Chain: Access(agent, tag="portfolio:holdings", fhe_mode=true)
   → Proves agent read ciphertext
   → FHE proof proves computation was correct (zkFHE)

5. Deletion proof becomes optional
   → Ciphertext without private key = harmless
   → No urgent need to verify deletion
```

### 10.4 What This Unlocks

| Capability | Without FHE | With FHE |
|-----------|------------|----------|
| Agent reads plaintext | Yes | No |
| Agent can remember data | Yes | No (ciphertext useless) |
| User revokes → data gone | No (agent may have copied) | Yes (revoke means stop decrypting results) |
| Trust model | Trust agent | Trust math |
| Chain audit | Logs what was leaked | Logs what ciphertext was accessed |
| Deletion proof necessity | High | Low |

### 10.5 Real-World Constraints

| Challenge | Status | Mitigation |
|-----------|--------|------------|
| Performance | Slow | Simple aggregates (sum/avg) — ms. Complex models (Sharpe) — seconds to minutes. Acceptable for async agent runs. |
| Library maturity | Good | TFHE-rs (Zama), OpenFHE. WASM bindings emerging for browser. |
| Key management | Careful | eval_key must be distributed securely. Leakage enables partial decryption. Hardware-bound keys (TEE) as defense-in-depth. |
| Agent compute cost | 100-1000x | Agent bears the cost. Acceptable for paid agent services. |
| zkFHE proofs | Early | Verifiable FHE computation — prove the agent ran the right model on ciphertext. Adds another layer of trustlessness. |

### 10.6 Phase Plan (FHE)

| Phase | Scope |
|-------|-------|
| **7** | FHE prototype: encrypt sample holdings, agent runs `sum`/`avg` on ciphertext via TFHE-rs WASM |
| **8** | FHE SDK: `UompClient.fhe` sub-client with `encrypt` / `compute` / `decrypt` |
| **9** | zkFHE integration: verifiable computation proofs on-chain |

### 10.7 Recommended Libraries

- **TFHE-rs** (Zama) — Rust, WASM bindings for browser/Node.js. Best performance for integer arithmetic.
- **OpenFHE** — C++, broader algorithm support. WASM via Emscripten.
- **fhEVM** (Zama) — Confidential smart contracts. Could host the FHE eval key on-chain.

## 11. Phase Plan (Full)

| Phase | Scope | Timeline |
|-------|-------|----------|
| **4a** | Deploy `AuditAnchor` on Starknet Sepolia testnet | 1 day |
| **4b** | Integrate into Auth (authorize), Guard (access), CLI (revoke) | 2-3 days |
| **4c** | Build simple indexer + API | 2-3 days |
| **5a** | Indexer UI (audit panel in browser dashboard) | 2 days |
| **5b** | Paymaster integration (agent pays gas) | 1 day |
| **6** | Scope obfuscation (hash instead of plaintext) | 1 day |
| **7** | FHE prototype (TFHE-rs WASM, sum/avg on ciphertext) | 1-2 weeks |
| **8** | FHE SDK (`UompClient.fhe`) | 1 week |
| **9** | zkFHE verifiable computation proofs | TBD |

## 12. Deliverables

```
packages/
  audit-contract/      # Solidity + Cairo contracts
  audit-indexer/       # Event scanner + REST API
  audit-sdk/           # UompClient.audit.onChain() helper
  fhe-sdk/             # UompClient.fhe (encrypt, compute, decrypt)

apps/
  indexer/             # Deployable indexer service
```
