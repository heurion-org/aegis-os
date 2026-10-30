# UOMP SDK Design Document

> Status: the current SDK focus is the Node.js `UompClient`. Browser export, wallet auth, StoreRouter, and write flows are deferred and are not on the current roadmap.
> Implementation: the Node.js read/aggregate/audit path is available; browser/wallet material is kept as historical design.
> Remote access: the standalone Gateway / Cloud Relay is retired; remote Agents use Aegis Cloud + Aegis Memory Gateway.

---

## 1. Background and Objectives

### 1.1 Current State

`packages/sdk` currently only has a `UserMemory` class with `get()` / `getByTag()` read methods. Agent developers must manually handle:

- mTLS certificate loading (Gateway mode)
- Aggregation queries (manual HTTP requests)
- Payload upload / download
- Deletion proof submission
- Token refresh
- Audit log queries
- Error retry and fallback

### 1.2 Goal

A single **`UompClient`** class that gives Agent developers full UOMP capability in one import:

```ts
import { UompClient } from '@uomp/sdk';

const uomp = new UompClient({
  token: process.env.UOM_TOKEN,
  baseUrl: process.env.UOMP_BASE_URL,
});

const holdings = await uomp.memory.getByTag('portfolio:holdings');
const total = await uomp.aggregate.sum('portfolio:holdings', 'value.market_value');
const payloadId = await uomp.payload.upload(report);
await uomp.session.submitDeletionProof();
const logs = await uomp.audit.query({ limit: 20 });
```

---

## 2. Design Principles

| Principle | Description |
|-----------|-------------|
| **Zero config** | `new UompClient({ token })` works — all else auto-detected |
| **Progressive enhancement** | Use defaults for simple scenarios, configure for advanced ones |
| **Location agnostic** | Same API for Local / Remote / Gateway mTLS |
| **Type safe** | Full TypeScript types with generics |
| **Error friendly** | Structured error codes distinguishing retryable from non-retryable |
| **Lightweight** | Zero runtime dependencies (Node builtins only: `fetch` / `https`) |

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────┐
│                    UompClient                        │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │   memory     │  │  aggregate   │  │  payload  │  │
│  │  get()       │  │  sum()       │  │  upload() │  │
│  │  getByTag()  │  │  avg()       │  │  download()│  │
│  │  getByKey()  │  │  count()     │  │  list()   │  │
│  └──────┬───────┘  └──────┬───────┘  └─────┬─────┘  │
│         │                 │                 │         │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌─────┴─────┐  │
│  │   session    │  │    audit     │  │ transport │  │
│  │  refresh()   │  │  query()     │  │  fetch()  │  │
│  │  deleteProof │  │  get()       │  │  mTLS     │  │
│  │  close()     │  └──────────────┘  │  retry    │  │
│  └──────────────┘                    │  timeout  │  │
│                                      └───────────┘  │
└──────────────────────────────────────────────────────┘
```

### 3.1 Transport Layer

- Auto-detects `baseUrl` protocol (`http://` → direct, `https://` → Gateway mTLS)
- Gateway mode: auto-loads `~/.uomp/.gateway-certs/` client certificates
- Supports custom `fetch` injection (for testing, proxies, etc.)
- Built-in retry with configurable count and backoff
- Request timeout control

### 3.2 Sub-Clients

| Sub-client | Responsibility |
|------------|---------------|
| `memory` | Read/write Memory Items |
| `aggregate` | Aggregation queries (sum, avg, count, min, max) |
| `payload` | Payload upload / download / list |
| `session` | Session management (refresh, deletion proof, close) |
| `audit` | Audit log queries |
| `health` | Health checks |

---

## 4. API Design

### 4.1 UompClient Constructor

```ts
interface UompClientOptions {
  token?: string;
  baseUrl?: string;
  agentId?: string;
  sessionId?: string;
  tls?: {
    certPath?: string;
    keyPath?: string;
    caPath?: string;
    rejectUnauthorized?: boolean;
  };
  transport?: {
    timeout?: number;
    retries?: number;
    retryBackoff?: number;
    fetch?: typeof fetch;
  };
  autoInit?: boolean;
}
```

### 4.2 Memory Sub-Client

```ts
interface MemoryClient {
  get<T = Record<string, unknown>>(key: string): Promise<MemoryItem<T> | null>;
  getByTag<T = Record<string, unknown>>(tag: string): Promise<MemoryItem<T>[]>;
  getByKeys<T = Record<string, unknown>>(keys: string[]): Promise<MemoryItem<T>[]>;
}
```

### 4.3 Aggregate Sub-Client

```ts
type AggregateOp = 'sum' | 'avg' | 'count' | 'min' | 'max';

interface AggregateClient {
  sum(tag: string, field: string): Promise<AggregateResult>;
  avg(tag: string, field: string): Promise<AggregateResult>;
  count(tag: string): Promise<AggregateResult>;
  min(tag: string, field: string): Promise<AggregateResult>;
  max(tag: string, field: string): Promise<AggregateResult>;
  query(tag: string, op: AggregateOp, field?: string): Promise<AggregateResult>;
}
```

### 4.4 Payload Sub-Client

```ts
interface PayloadClient {
  upload(data: string | Buffer | Uint8Array, contentType?: string): Promise<string>;
  download(id: string): Promise<Buffer>;
  info(id: string): Promise<PayloadInfo>;
}
```

### 4.5 Session Sub-Client

```ts
interface SessionClient {
  refresh(refreshToken: string): Promise<{ token: string; expiresAt: string }>;
  submitDeletionProof(opts?: {
    fieldsAccessed?: string[];
    method?: string;
  }): Promise<{ status: string; deletionProofId: string }>;
  close(): Promise<void>;
  isActive(): Promise<boolean>;
}
```

### 4.6 Audit Sub-Client

```ts
interface AuditClient {
  query(options?: AuditQueryOptions): Promise<AuditLogEntry[]>;
  getLastAccess(sessionId?: string): Promise<AuditLogEntry | null>;
}
```

---

## 5. Integration Patterns

### 5.1 Node.js Agent (most common)

```ts
import { UompClient } from '@uomp/sdk';
const uomp = new UompClient(); // reads UOM_TOKEN + UOMP_BASE_URL from env
const holdings = await uomp.memory.getByTag('portfolio:holdings');
```

### 5.2 Gateway mTLS

```ts
const uomp = new UompClient({
  baseUrl: 'https://my-gateway.example.com',
  tls: { autoMtls: true }, // auto-load ~/.uomp/.gateway-certs/
});
```

### 5.3 Browser / Web App (wallet auth + S3 direct + Cloud Relay)

```ts
import { BrowserSDK } from '@uomp/sdk/browser';

// Wallet signature → derive masterKey → auto-connect
const uomp = await BrowserSDK.fromWallet();
// → MetaMask/Argent X popup → sign → done

// Specify chain
const uomp = await BrowserSDK.fromWallet('starknet');

// Seed phrase fallback
const uomp = BrowserSDK.fromSeedPhrase('coral maple ...');

// Read: auto-fallback (Gateway online → Gateway; offline → S3 direct + in-browser decrypt)
const holdings = await uomp.memory.getByTag('portfolio:holdings');

// Write: routed through Cloud Relay
await uomp.memory.set('AAPL', newData);

// Offline state
console.log(uomp.isGatewayOnline); // boolean
```

Browser mode includes built-in **StoreRouter**.

### 5.4 Serverless Agent

```ts
export default async function handler(req) {
  const { token, gatewayUrl } = req.body;
  const uomp = new UompClient({ token, baseUrl: gatewayUrl });
  const holdings = await uomp.memory.getByTag('portfolio:holdings');
  await uomp.session.submitDeletionProof();
  return { analysis };
}
```

---

## 6. Error Handling

```ts
import { UompError, UompErrorCode } from '@uomp/sdk';

try {
  await uomp.memory.getByTag('private');
} catch (err) {
  if (err instanceof UompError) {
    // err.code → ACCESS_DENIED | TOKEN_EXPIRED | INVALID_TOKEN |
    //            AUDIENCE_MISMATCH | QUOTA_EXCEEDED | NETWORK_ERROR
  }
}
```

---

## 7. Backward Compatibility

Existing `UserMemory` class remains functional but marked deprecated:

```ts
// Old (still works)
import { UserMemory } from '@uomp/sdk';

// New (recommended)
import { UompClient } from '@uomp/sdk';
```

---

## 8. Implementation Roadmap

### Phase 1: Core SDK

| Task | File |
|------|------|
| `UompClient` main class | `client.ts` |
| Transport layer (HTTP + mTLS + retry) | `transport.ts` |
| `memory` sub-client | `memory.ts` |
| `aggregate` sub-client | `aggregate.ts` |
| `payload` sub-client | `payload.ts` |
| `session` sub-client | `session.ts` |
| `audit` sub-client | `audit.ts` |
| Type definitions | `types.ts` |
| Error types | `errors.ts` |
| Backward compat (UserMemory) | `index.ts` |

### Phase 2: Advanced Features

- Auto token refresh
- Payload E2E encryption / decryption
- Auto mTLS cert generation
- Connection pooling

### Phase 3: Cross-Platform

- React Native adapter
- Browser Service Worker
- Python SDK port
- CLI SDK refactor to use packages/sdk

---

## 9. File Structure

```
packages/sdk/
├── src/
│   ├── index.ts          # Exports UompClient + deprecated UserMemory
│   ├── client.ts         # UompClient
│   ├── memory.ts         # MemoryClient
│   ├── aggregate.ts      # AggregateClient
│   ├── payload.ts        # PayloadClient
│   ├── session.ts        # SessionClient
│   ├── audit.ts          # AuditClient
│   ├── transport.ts      # HTTP transport (fetch, mTLS, retry)
│   ├── types.ts          # Public types
│   └── errors.ts         # UompError classes
├── package.json
├── tsconfig.json
└── README.md
```

---

## Related Documents

- [CLI/SDK Design (scenario-driven)](./cli-sdk-design.en.md)
- [Remote Authorization Design](./remote-authorization-design.en.md)
- [Protocol Specification](https://www.uomp.org/en/spec/)
