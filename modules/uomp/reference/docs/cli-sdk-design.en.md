# UOMP CLI/SDK Design Document

> **Status: historical design note (pre-CLI-first).** The current path is agent-first: the user runs `uomp setup <client>` once, then the agent requests access when it needs data and UOMP opens the local consent page. `connect` is the advanced pre-authorize path; `authorize` and `mcp --print-config` are the manual/script fallback; `discover`, `inspect`, and `registry` are hidden advanced commands. The remote Gateway / Cloud Relay is retired; remote Agents use Aegis Cloud + Aegis Memory Gateway. See the [README](../README.md#quick-start) for current usage.
>
> The original analysis below is kept as historical context for the stock-analyst scenario.

## Current CLI (2026-10)

```bash
# optional; setup creates this automatically
uomp init

# one-time client setup: import + config + background server, no access granted
uomp setup claude --vault ~/Obsidian/MyVault

# the client requests access; terminal fallback:
uomp pending
uomp approve <request-id>
uomp deny <request-id>

# manage
uomp status
uomp audit
uomp disconnect claude
uomp stop
uomp revoke <session-id>

# advanced: pre-authorize / scripts
uomp connect claude --vault ~/Obsidian/MyVault --scope notes/projects
uomp connect ./examples/stock-analyst --scope portfolio:holdings --allow-key AAPL MSFT
```

Manual fallback (unsupported clients):

```bash
uomp serve
uomp authorize --scope notes/projects --output ~/.uomp/mcp-client.env --no-server
uomp mcp --session ~/.uomp/mcp-client.env --print-config
```

---

> This document uses the **stock analysis agent** as a concrete example to examine whether UOMP's CLI and SDK can meet the needs of such scenarios, identify design gaps, and provide a general CLI/SDK design for this type of agent.
>
> Core conclusions:
> - A stock analysis agent is not the only target; it is the first **acceptance example**.
> - CLI and SDK designs must be **general**, but every general capability must be able to answer the question "Can it make the stock analysis agent run?"
> - Key boundary: **The Agent User's CLI is not responsible for starting the Agent process**; it only performs discovery, connection, and authorization.

---

## 1. Why Use the Stock Analysis Agent as the Acceptance Example

The stock analysis agent is a typical scenario of **highly sensitive data + external agent + local decision-making**:

- **Data sensitivity**: Position information belongs to the user's core financial privacy.
- **Agent is external**: The analysis agent is developed by a third party or open-source community and does not run on the user's local machine.
- **Data mixing**: It needs to access both private user data (positions, risk profile) and public data (market quotes, fundamentals).
- **Output stays local**: Analysis conclusions should remain on the user's local machine and not leak.
- **User controllable**: The user must be able to precisely control what the agent reads, how granular, and for how long.

If the CLI/SDK can support the stock analysis agent well, agents for other scenarios such as calendar, health, and education can follow the same design.

---

## 2. Complete User Story of the Stock Analysis Agent

### 2.1 Roles

- **Xiao Wang**: An ordinary investor who cannot code.
- **stock-analyst**: An open-source stock analysis agent published by example-org.

### 2.2 User Journey

```text
1. Xiao Wang exports his positions from the broker APP as a CSV.
2. He uses uomp import to import the positions into the local Memory Store.
3. He discovers stock-analyst in the Registry or a local directory.
4. He uses uomp inspect to verify the agent's identity and claims.
5. He uses uomp authorize to authorize stock-analyst to read positions and risk profile.
6. The CLI gives him an export UOM_TOKEN=... command.
7. Xiao Wang copies this command into the terminal running the Agent.
   - Phase 1 examples usually run the Agent on the local machine, but the CLI/SDK design does not assume the Agent and user must be the same machine.
   - If the Agent runs on a remote server, the user can expose the Memory Guard via `apps/gateway`; the Token's `audience` points to the Gateway endpoint and `UOMP_BASE_URL` matches the Gateway URL.
8. After the Agent starts:
      - Reads portfolio:holdings and profile:risk through the SDK
      - Calls Yahoo Finance / Alpha Vantage through the SDK to obtain public data
      - Generates a Markdown analysis report locally
9. Xiao Wang sees the Agent actively accessing via uomp sessions.
10. After analysis is complete, Xiao Wang uses uomp revoke to revoke the session.
```

### 2.3 Agent Manifest

```json
{
  "uomp_version": "1.0",
  "agent": {
    "id": "stock-analyst",
    "version": "0.1.0",
    "name": "Position Analysis Assistant",
    "publisher": "example-org"
  },
  "requested_scopes": {
    "read": {
      "tags": ["portfolio:holdings", "portfolio:watchlist", "profile:risk"],
      "fields": {
        "portfolio:holdings": ["symbol", "quantity", "cost_basis", "market_value"]
      },
      "purposes": {
        "portfolio:holdings": "Calculate position weights, industry distribution, and profit/loss analysis"
      }
    }
  },
  "external_data_sources": ["yahoo-finance", "alpha-vantage"],
  "identity": {
    "did": "did:ethr:0xabc123...",
    "verification_methods": ["did", "gpg"],
    "proof": { ... }
  }
}
```

---

## 3. CLI/SDK Requirements Derived from the Example

Breaking down the user story above yields the following requirements:

| Step | Requirement | Corresponding CLI/SDK Capability |
|------|-------------|----------------------------------|
| Import positions CSV | General data import, field mapping, sensitivity labeling | `uomp import` |
| Discover Agent | Find the Agent from the Registry or local path | `uomp discover` / `uomp registry search` |
| Verify Agent | Confirm Agent identity, verify package integrity, assess risk | `uomp inspect` |
| Authorize | Display field-level data exposure summary, support editing/redaction | `uomp connect` / `uomp authorize` |
| Token delivery | Securely hand the Token to the user, without auto-injection | Terminal print + `--output` |
| Agent reads private data | Agent accesses Memory Guard with Token | SDK `agent.memory.read` |
| Agent reads public data | Agent calls external quote APIs | SDK `agent.market.*` |
| Agent outputs report | Save to local file, not write to Memory Store | SDK `agent.output.save` |
| Monitor | User views sessions and audit | `uomp sessions` / `uomp audit` |
| Revoke | User actively ends authorization | `uomp revoke` |
| Developer debugging | Locally verify Agent quickly | `uomp agent run` / `uomp agent test` |

---

## 4. Design Gap Check and Fill

### 4.1 Gap 1: CLI Should Not Start the Agent

**Problem**: Early CLI had `uomp run <agent>`, bundling authorization and Agent startup together. This means the user executes external code immediately after authorization, which feels insecure.

**Fix**: The user CLI only retains `discover`, `connect`, `authorize`. Starting the Agent is the user's own action; the CLI only outputs the Token. Only developers have `uomp agent run`.

### 4.2 Gap 1.5: CLI Should Not Assume Agent and User Are on the Same Machine

**Problem**: If the CLI/SDK design assumes the Agent must run on the local machine, it cannot support remote Agent services (such as stock analysis services deployed in the cloud).

**Fix**:

- Token delivery is location-agnostic: the CLI only outputs `UOM_TOKEN` and `UOMP_BASE_URL`; the user can copy them to any terminal or environment running the Agent.
- `UOMP_BASE_URL` defaults to `http://127.0.0.1:9374`, but the user can configure it as a remote Guard endpoint.
- In remote scenarios, the user can self-host `apps/gateway` (mTLS + Token forwarding) to securely expose the local Memory Guard to remote Agents; helper scripts are `scripts/generate-gateway-certs.sh` and `scripts/test-gateway-remote.sh`.
- Phase 1 examples run the Agent on the local machine for convenience, but the protocol and CLI/SDK design do not restrict the Agent's location; the remote Gateway reference implementation is already available.

### 4.3 Gap 2: Import Command Must Be General and Support Field Mapping

**Problem**: Position CSVs come from different brokers with inconsistent column names (`股票代码`, `symbol`, `Code`, etc.). If the import command requires a strict format, users cannot use it.

**Fix**: `uomp import` is designed as a general importer, supporting:
- Automatic inference of common field aliases
- `--map` custom mapping
- `--tag` / `--sensitivity` explicit labeling
- Multiple formats (CSV/JSON)

### 4.4 Gap 3: Field-Level Summary Required Before Authorization

**Problem**: If the user is only told "The Agent wants to read portfolio:holdings", they do not know the Agent will read sensitive fields such as cost basis and share count.

**Fix**: Highly sensitive tags must display a field-level summary. The Agent declares `fields` and `purposes` in `uom.json`. The CLI authorization panel displays:

```text
portfolio:holdings (8 records)
  Fields: symbol, quantity, cost_basis, market_value
  Purpose: Calculate position weights, industry distribution, and profit/loss analysis
  Redaction option: Keep only symbol and weight
```

### 4.5 Gap 4: Token Delivery Method Must Be Explicit

**Problem**: If the CLI automatically injects the Token into the Agent process, the user loses awareness of where the Token flows.

**Fix**: Phase 1 only supports two delivery methods:
- Terminal prints the `export` command for the user to manually copy.
- `--output` saves to a `.env` file for the user to manually `source`.

### 4.6 Gap 5: Agent SDK Needs Market Data Encapsulation

**Problem**: Stock agents need to call public APIs such as Yahoo Finance / Alpha Vantage. If every Agent writes this itself, development costs are high.

**Fix**: The SDK provides optional `agent.market.*` helper methods, but clearly states:
- This data does not go through Memory Guard.
- The Agent cannot pass user positions as parameters to external APIs.
- The final analysis logic is completed locally.

### 4.7 Gap 6: Output Reports Should Be Saved to Local Files by Default

**Problem**: If the Agent writes the analysis report back to Memory Store, it increases authorization complexity and leakage risk.

**Fix**: In the MVP phase, Agents should not write to Memory Store. The SDK provides `agent.output.save(path, content)` to save directly to the user's local file.

### 4.8 Gap 7: Session Monitoring Needs Sufficient Information

**Problem**: After authorizing, the user needs to know whether the Agent is actually accessing data and what it accessed.

**Fix**: `uomp sessions` displays last access time, accessed endpoint, Agent source IP, and status (active/idle/not started).

---

## 5. CLI Design

### 5.1 Command Overview

#### Agent User Commands

| Command | Purpose |
|---------|---------|
| `uomp import <file>` | Import any private data into Memory Store |
| `uomp data` | View data in the local Memory Store |
| `uomp discover <path-or-registry>` | Discover Agent and display manifest information |
| `uomp setup <client>` | One-time MCP client setup: import + config + background server, no access granted |
| `uomp connect <claude\|cursor\|opencode\|agent>` | Advanced pre-authorize: connect an MCP client or agent package, write config/env, start the server |
| `uomp inspect <agent>` | Verify identity, cache manifest, assess risk |
| `uomp authorize <agent>` | Create Session and issue Token (manual/script fallback) |
| `uomp status` | Show the background server, active sessions, and client config status |
| `uomp start` | Start the UOMP server in the background |
| `uomp stop` | Stop the background UOMP server |
| `uomp disconnect <client>` | Remove the client config entry and revoke its session |
| `uomp pending` | List on-demand consent requests waiting for approval |
| `uomp approve <request-id>` | Approve a request and write its session token |
| `uomp deny <request-id>` | Deny a request and close its session |
| `uomp sessions` | View active sessions |
| `uomp revoke <session-id>` | Revoke session |
| `uomp audit` | View access audit log |
| `uomp config` | Configure default preferences |
| `uomp dry-run <agent>` | Simulate authorization without reading real data |
| `uomp registry search <keyword>` | Search for Agents from the Registry |

> `uomp gateway` is retired; remote Agents use Aegis Cloud + Aegis Memory Gateway.

#### Agent Developer Commands

| Command | Purpose |
|---------|---------|
| `uomp agent init <name>` | Initialize an Agent project |
| `uomp agent validate` | Validate `uom.json` and file structure |
| `uomp agent test` | Debug Agent locally using test data |
| `uomp agent run <agent>` | Developer locally starts Agent (testing only) |
| `uomp agent publish` | Package Agent for publishing |

### 5.2 Core Workflows

#### 5.2.1 Import Private Data

`uomp import` is a general import command that follows the [UOMP Spec §12 Memory Import Format](https://www.uomp.org/spec/).

```bash
# General usage
$ uomp import data.csv --tag <tag> --sensitivity <level>

# Stock example: import positions
$ uomp import holdings.csv --tag portfolio:holdings --sensitivity high

# Stock example: import risk profile
$ uomp import risk.json --tag profile:risk --sensitivity medium
```

#### 5.2.2 Discover Agent

```bash
# Local path
$ uomp discover ./examples/stock-analyst

# Local Registry
$ uomp registry search stock
$ uomp discover registry://stock-analyst
```

Output example:

```text
Agent: stock-analyst v0.1
Publisher: example-org  [DID verified]
Description: Generates investment strategy analysis based on positions and public market information

Requested permissions:
  [High sensitivity] portfolio:holdings   - Current positions
  [Medium sensitivity] portfolio:watchlist - Watchlist
  [Medium sensitivity] profile:risk        - Risk profile

Write permissions: None
```

#### 5.2.3 Inspect Agent

```bash
$ uomp inspect ./examples/stock-analyst
```

"Inspect" completes:

1. Read and parse `uom.json`.
2. Verify publisher identity (DID / GPG / Registry).
3. Verify package integrity (checksum + signature).
4. Cache manifest to `~/.uomp/agents/<agent-id>/<version>/`.
5. Provide risk score.
6. **Do not start the Agent or issue a Token**.

#### 5.2.4 Connect and Authorize Agent

```bash
$ uomp connect ./examples/stock-analyst --scope portfolio:holdings profile:risk --allow-high portfolio:holdings
```

The CLI shows the scope summary; after confirmation it creates a Session, issues a Token, and writes a `0600` session env file (MCP clients also get a client config):

```text
Session granted: sess_abc123
  Scope     portfolio:holdings · profile:risk
  Expires   2026-07-12 10:30 (30 min)

Env file
  /home/me/.uomp/sessions/sess_abc123.env

Revoke with: uomp revoke sess_abc123
```

The token is not printed by default; use `--print-token` when needed.

#### 5.2.5 Edit Scope and Redact

After the user selects `e`, enter interaction:

```text
Select data to authorize this time:
  [x] portfolio:holdings   (Current positions)
  [ ] portfolio:watchlist  (Do not authorize)
  [x] profile:risk         (Risk profile)

High-sensitivity data options:
  [ ] Expose cost basis and specific share count
  [x] Expose only holding code and weight (redaction mode)
```

#### 5.2.6 View Sessions

```bash
$ uomp sessions
```

Output:

```text
Active sessions:
  sess_abc123  stock-analyst  7 minutes remaining   Status: Active
               Authorized: [portfolio:holdings, profile:risk]
               Last access: 10:02:15  /memory/read
               Agent address: 127.0.0.1 (local)
```

#### 5.2.7 Revoke and Audit

```bash
$ uomp revoke sess_abc123
$ uomp audit --agent stock-analyst --today
```

### 5.3 Error Message Design

| Scenario | Output |
|----------|--------|
| Token not authorized for a tag | `Agent requested to read "portfolio:holdings", but the current session is not authorized. Please run: uomp authorize <agent> --include portfolio:holdings` |
| Agent requests write | `The current Agent requested to write data, but UOMP MVP prohibits Agent writes.` |
| Session expired | `Session sess_abc123 has expired. Please run again: uomp authorize <agent>` |
| High sensitivity not confirmed | `"portfolio:holdings" is highly sensitive data and requires explicit user confirmation during authorization.` |

---

## 6. SDK Design

### 6.1 Agent Developer SDK

The Agent Developer SDK is the core, allowing developers to focus on business logic.

```ts
import { UompAgent } from '@uomp/sdk';

const agent = await UompAgent.fromEnv();

// Read data authorized by the user
const holdings = await agent.memory.read({ tags: ['portfolio:holdings'] });
const risk = await agent.memory.read({ tags: ['profile:risk'] });

// Read public market data
const quotes = await agent.market.quotes(['AAPL', 'TSLA']);
const fundamentals = await agent.market.fundamentals(['AAPL']);

// Generate analysis
const report = analyze({ holdings, risk, quotes, fundamentals });

// Save report to local file
await agent.output.save('./output/report.md', report);
```

### 6.2 SDK API Reference

#### `UompAgent`

| Method | Purpose |
|--------|---------|
| `fromEnv()` | Initialize from `UOM_TOKEN` / `UOMP_BASE_URL` |
| `whoami()` | Return current Agent manifest and authorized scope |
| `memory.read(opts)` | Read Memory Guard data |
| `memory.write(opts)` | Write to Memory Store (requires authorization; recommended to disable in MVP) |
| `memory.query(opts)` | Complex query |
| `market.quotes(symbols)` | Get quotes |
| `market.fundamentals(symbols)` | Get fundamentals |
| `market.news(symbols)` | Get news |
| `market.macro(indicators)` | Get macro data |
| `output.save(path, content)` | Save result to local file |
| `audit.log(event)` | Report custom audit event |

#### `UompAgentConfig`

```ts
interface UompAgentConfig {
  token?: string;
  baseUrl?: string;
  manifestPath?: string;
  dataSource?: {
    market?: string;
    apiKey?: string;
  };
}
```

### 6.3 Error Handling

```ts
try {
  await agent.memory.read({ tags: ['portfolio:holdings'] });
} catch (err) {
  if (err.code === 'SCOPE_DENIED') {
    console.log('Please ask the user to authorize portfolio:holdings');
  }
  if (err.code === 'TOKEN_EXPIRED') {
    console.log('Session has expired, please re-authorize');
  }
}
```

### 6.4 Data Redaction Helpers

The SDK provides helper functions to prevent developers from passing sensitive data to external LLMs:

```ts
import { redactHoldings } from '@uomp/sdk/utils';

const safe = redactHoldings(holdings, { keep: ['symbol', 'weight'] });
```

### 6.5 Agent User SDK (for Future GUI)

```ts
import { UompClient } from '@uomp/client';

const client = new UompClient({ dataDir: '~/.uomp' });

await client.memory.import({ file: '~/holdings.csv', tag: 'portfolio:holdings', sensitivity: 'high' });
const manifest = await client.discover('./examples/stock-analyst');
const session = await client.authorize({ agentPath: './examples/stock-analyst', durationMinutes: 10 });
await session.revoke();
```

---

## 7. Registry Design

Phase 1 implements a local Registry index, following the ERC-8004 interface design, and later connects to on-chain contracts.

### 7.1 Agent Packaging Format

```text
stock-analyst-0.1.0/
  uom.json
  dist/
  README.md
  LICENSE
  signature.json
```

### 7.2 Local Registry Index

- Storage location: `~/.uomp/registry/index.json`
- CLI commands: `registry search/list/add/remove/verify/sync`
- Index contains: id, version, publisher, metadata URI, source URL, checksum, signature, verified, tags

### 7.3 Discovery Flow

```text
uomp registry search stock
  -> Read local index
  -> Return matching list
uomp discover registry://stock-analyst
  -> Download/use cache
  -> Verify checksum + signature
  -> uomp inspect completes verification
  -> uomp connect grants authorization
```

### 7.4 Verification Levels

| Level | Verification Content |
|-------|----------------------|
| L1 Local verification | `uom.json`, checksum, signature |
| L2 Registry verification | Registry `isVerified=true` |
| L3 User trust | User has previously authorized the same publisher |

---

## 8. Data Source Design (Using Stocks as an Example)

Stock analysis agents need data divided into user private data and public data.

### 8.1 User Private Data

| Data Item | tag | sensitivity | Import Method |
|-----------|-----|-------------|---------------|
| Current positions | `portfolio:holdings` | high | `uomp import holdings.csv` |
| Watchlist | `portfolio:watchlist` | medium | `uomp import watchlist.csv` |
| Risk profile | `profile:risk` | medium | `uomp import risk.json` |

### 8.2 Public Data

The Agent calls external APIs through SDK `market.*` by itself:

| Data Source | Coverage | Applicable Market |
|-------------|----------|-------------------|
| Yahoo Finance | Quotes, historical K-line | US stocks |
| Alpha Vantage | Quotes, fundamentals | US stocks |
| Tushare | Quotes, fundamentals, macro | A-shares |
| AKShare | A-shares/HK stocks/funds | A-shares |

### 8.3 Data Source Usage Principles

1. User private data must go through Memory Guard.
2. Public data can be obtained by the Agent itself, but must be declared in `uom.json`.
3. The Agent cannot pass user positions as parameters to third-party LLMs or data sources.
4. If a cloud LLM needs to be called, redact positions first.

---

## 9. Security and Privacy Essentials

1. **User CLI does not start Agent**: Avoid "authorization means execution".
2. **Token delivery security**: Terminal print + `--output` file save, no auto-injection.
3. **Field-level exposure summary**: Highly sensitive tags must display fields and purposes.
4. **Comprehensive verification at connect time**: Identity, signature, checksum, Registry, risk score.
5. **Positions default to high sensitivity**: `portfolio:holdings` is marked as high.
6. **Reports saved locally**: Analysis conclusions are written to local files by default, not to Memory Store.
7. **Short-lived sessions**: Default 10-30 minutes.
8. **Complete audit**: Every read, external API call, and report generation must be logged.

---

## 10. Future Extensions: Remote Agent and On-Chain Audit

The current Phase 1 only considers local Agents. In the long term, UOMP must support remote Agent deployment and on-chain audit anchoring.

### 10.1 Remote Agent Deployment

Most Agents will eventually run as **services** on remote servers rather than on the same device as the user:

- The user authorizes via a lightweight CLI or local UI.
- The Agent runs in the cloud or on a third-party server.
- The Agent is not on the same local network as the user's device.

It is worth emphasizing that the CLI/SDK design does not assume the Agent and user are on the same machine from the first phase:

- `uomp authorize` only outputs the Token and Guard URL, and does not start the Agent for the user.
- Token delivery methods (terminal print / file save) are independent of the Agent's location.
- As long as the Agent can access `UOMP_BASE_URL`, it can run anywhere.

This requires UOMP to support a Remote Profile:

1. Memory Guard is exposed via TLS 1.3 + mTLS.
2. The `profile` claim of the Capability Token is `"remote"`, and the `audience` is bound to the remote Guard endpoint.
3. The remote Agent holds a client certificate issued by the user.
4. The user must explicitly enable Remote Profile; it is disabled by default.
5. Remote Guard SHOULD be deployed on the user's self-hosted gateway, reverse tunnel, or trusted service.

### 10.2 Payload Delivery for Remote Agents

When the Agent runs remotely, the analysis reports, notifications, recommendations, and other Payloads it generates need to be securely delivered to the user. Options:

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| End-to-end encryption | Encrypt Payload with user's public key; only user's private key can decrypt | Most secure | Requires user-side key management |
| Secure callback URL | User provides an HTTPS callback endpoint; Agent POSTs Payload | Simple | Callback endpoint may be attacked or leaked |
| Off-chain storage + on-chain hash | Payload stored in IPFS/encrypted cloud; only hash and authorization stored on-chain | Verifiable, auditable | Requires off-chain storage availability |
| Local relay gateway | User self-hosted gateway; Agent POSTs to gateway; user actively pulls | User-controllable | Requires user to have a public network entry |

Recommended long-term solution:

- Default to **end-to-end encryption + local relay gateway**.
- Report-type Payloads are stored in user-specified local or encrypted cloud storage; only the hash is stored on-chain for auditing.
- Instant notification-type Payloads use encrypted callbacks or push channels.

### 10.3 Audit Log On-Chain

MVP audit logs are stored in local SQLite. In the future, audit events need to be recorded directly on the blockchain to achieve tamper-proof audit proofs.

Support two chains:

- **EVM**: Ethereum and compatible chains (Polygon, Base, Arbitrum, etc.).
- **Starknet**: Suitable for high-frequency, low-cost audit events on-chain.

On-chain content:

Audit events are written as on-chain events, mainly including two categories:

1. **Authorization events**: Session creation, granting, revocation.
    - `session_id`
    - `agent_id`
    - `action` (created / granted / revoked / expired)
    - `granted_tags`
    - `granted_keys`
    - `expires_at`
    - `timestamp`

2. **Access events**: Records of Agent reads from Memory Guard.
    - `session_id`
    - `agent_id`
    - `action` (read)
    - `tags`
    - `keys`
    - `allowed`
    - `timestamp`

Notes:

- Full access logs are still kept locally; the on-chain record is an immutable proof of key events.
- For privacy-sensitive fields (such as specific keys), you can choose to use irreversible identifiers or commitments on-chain, but the event itself must be able to prove that authorization and access occurred.
- Use L2 or Starknet to reduce per-event cost.
- Access events can be submitted in batches; authorization events are recommended to be submitted in real time.

Users and regulators can verify through on-chain events:

- Whether a certain Agent has been authorized.
- Authorization scope and validity period.
- Whether the Agent actually performed read operations.

## 11. Implementation Phases

### Phase 1: General CLI/SDK + Stock Example (Implemented)

The reference implementation is located at [`reference`](../README.md); the complete runnable workflow is in [`examples/stock-analyst/README.md`](../examples/stock-analyst/README.md).

Implemented capabilities:

- CLI supports `discover`, `connect`, `authorize`, `sessions`, `revoke`, `audit`, `import`.
- `authorize`/`connect` display a data-exposure summary; high-sensitivity tags are unchecked by default, then require per-key approval. Non-interactive runs need `--allow-key` or `--allow-high`.
- Token delivery: a `0600` session env file; only `--print-token` prints it.
- Local Registry index (`registry search/list/add/remove`).
- Agent Developer SDK (`UompAgent.fromEnv()`, `memory.readTag`, `memory.readKey`, `output.save`).
- Stock analysis Agent demo: import CSV/JSON → authorize → run independently → generate local Markdown report.
- Session and audit queries.

### Phase 2: Experience Polishing (2-3 Weeks)

- `uomp import` field mapping, format recognition, preview
- `uomp dry-run` simulated authorization
- `uomp config` user configuration
- SDK data redaction helper functions
- More friendly error messages
- Developer commands `uomp agent run` / `uomp agent test`
- `uomp registry sync` connecting to on-chain ERC-8004 contract

### Phase 3: Production Readiness (Later)

- Multi-data-source adapters
- Local LLM support
- GUI application

### Phase 4: Remote Agent and On-Chain Audit (Long-Term)

- Remote Profile reference implementation (TLS 1.3 + mTLS)
- Remote Agent Payload delivery solution (end-to-end encryption + local relay gateway)
- Audit events (authorization + reads) recorded on EVM chain
- Audit events recorded on Starknet
- On-chain audit event query and verification tools

---

## 12. Open Issues

1. **Is the field-level summary mandatory?**
    - Recommendation: Highly sensitive tags must display fields and purposes.
2. **Token delivery method**
    - Phase 1 uses terminal print + `--output` file save.
3. **Registry implementation**
    - Phase 1 uses local JSON index, following ERC-8004 interface.
4. **Agent write restrictions**
    - MVP prohibits Agent writes; reports are saved to local files.
5. **Is a Python SDK needed?**
    - Recommendation: Do the TypeScript SDK well first; Python SDK to follow.
6. **Default remote Agent Payload delivery solution?**
    - Candidates: end-to-end encryption, local relay gateway, off-chain storage + on-chain hash.
7. **Audit event on-chain frequency?**
    - Authorization events (created/granted/revoked) are recommended to be submitted on-chain in real time.
    - Read access events can be submitted on-chain in batches to reduce cost.
    - Need to balance real-time, cost, and privacy.

---

## 13. Next Steps

1. Phase 1 has successfully run the stock analysis example; continue polishing error prompts and field mapping experience.
2. Advance Phase 2: `uomp dry-run`, `uomp config`, more complete `import` preview/redaction, and on-chain Registry sync.
3. Add more acceptance examples (calendar, health, education agents) to verify generality.
