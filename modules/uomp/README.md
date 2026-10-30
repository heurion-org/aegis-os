# UOMP module

UOMP (User-Owned Memory Protocol) is the **memory consent module** of Aegis OS.

- **Protocol site:** <https://www.uomp.org/>
- **Protocol spec:** <https://www.uomp.org/spec/>
- **Native crates:**
  - `crates/aos-memory` — scope/lease mapping, deny/field filtering, remote token policy
  - `crates/aos-memory-store` — SQLite data plane and Markdown importer
  - `crates/aos-memory-gateway` — TLS/mTLS remote Agent gateway
- **CLI:** `aegis-os memory ...`
- **Website repository:** the separate `uomp` repository is documentation/website only.
- **Vendored reference:** [`modules/uomp/reference`](./reference) is a temporary copy of the archived `uomp-core` implementation.

## Role in Aegis OS

UOMP defines how an Agent asks for personal memory: scope, duration, revocation, and audit. Aegis OS enforces those semantics with policy, leases, sandboxing, trusted approval, and the memory data plane.

```text
Agent
  │  UOMP request (scope, consent, lease)
  ▼
Aegis OS
  ├─ policy / lease / approval
  ├─ memory gateway (remote Agent entry point)
  ├─ memory store (SQLite + Markdown connector)
  └─ audit
```

## Migration status

The native module is being completed in phases:

1. Policy/lease mapping and gateway — done.
2. Staged writes, payloads, remote device flow — done.
3. Native CLI commands — `status`, `import`, `read`, `list`, `search`, `staged`, `payload`, `mcp` are native; setup/serve/approvals delegate to the UOMP reference CLI.
4. Native data-plane cutover — `aos-memory-store` foundation landed; Gateway still proxies to UOMP Guard.
5. Unified trusted UI — pending.

Until the cutover is complete, the vendored [`reference`](./reference) copy is the compatibility implementation and `uomp` remains the reference/debug CLI. The standalone `uomp-core` repository is archived.
