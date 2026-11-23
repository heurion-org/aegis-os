# Contributing to Aegis OS

Thank you for helping make autonomous coding agents safe by default! Whether you are adding an agent adapter, tightening a Seatbelt/`bwrap` rule, contributing a new red-team bypass test, or fixing a typo, contributions are warmly welcome.

## Quick Local Setup

### Prerequisites

- **Rust** `1.80+` (`rustup update stable`)
- **macOS:** Built-in `/usr/bin/sandbox-exec` (Seatbelt) + APFS for CoW `clonefile` tests
- **Linux:** `bubblewrap` (`bwrap`), `git`, and Python 3 (for benchmark suites)
  - Note for **Ubuntu 24.04+**: `kernel.apparmor_restrict_unprivileged_userns=1` blocks unprivileged `bwrap` unless `/etc/apparmor.d/bwrap` is loaded (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

### Build & Test

```bash
git clone https://github.com/heurion-org/aegis-os.git
cd aegis-os

# Run the full workspace test suite
cargo test --workspace --locked

# Run fast CLI unit tests
cargo test -p aos-cli

# Build release binary
cargo build --release --bin aegis-os
```

> **Note:** Look at [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — CI runs `cargo test --workspace --locked` across `ubuntu-22.04`, `ubuntu-24.04`, and `macos-15`.

## Workspace Architecture (14 Crates)

| Crate | Responsibility |
|---|---|
| `crates/aos-core` | Core domain types, session/org/agent identities, receipts, errors |
| `crates/aos-vfs` | Copy-on-Write shadow workspaces (`clonefile`, `FICLONE`, fallback), 4-tier LCS auto-merge, `OrgVault` encryption |
| `crates/aos-sandbox` | OS kernel confinement backends (Linux `bwrap --bind-fd`, macOS Seatbelt, MicroVM drivers) & split `.git` shim |
| `crates/aos-policy` | Cedar policy engine, TTL/one-shot leases, path/domain rules, TOCTOU evidence verification |
| `crates/aos-egress` | L4 `CONNECT` allowlist, L7 Base-URL model reverse proxy, `$AOS_SECRET_*` injection, outbound DLP & pseudonymization |
| `crates/aos-ipc` | Multi-agent A2A message bus, hierarchical tasks, file claims, SHA-256 content-addressed storage (CAS) |
| `crates/aos-mcp-gateway` | Host `SessionBroker`, External MCP Zero-Trust Firewall, OAuth 2.1 realms, PaaS/approval HTTP server |
| `crates/aos-recorder` | Hash-chained audit ledger, `Aegis-OS-Verified` receipts, session recording |
| `crates/aos-guest-init` | Guest init process for hardware-isolated `--isolated` MicroVMs |
| `crates/aos-memory*` | Self-evolving agent memory kernel, store, gateway, and server (`aos-memory`, `-gateway`, `-store`, `-server`) |
| `crates/aos-cli` | `aegis-os` / `aos` CLI entrypoint, installers, `audit-me`, launcher, upgrade/uninstall |

## High-Impact Areas Welcoming PRs

1. **New Coding Agent Adapters:** First-class support and `aegis-os doctor` / `audit-me` probes for additional terminal/IDE agents (e.g., Aider, Goose, Windsurf CLI, Roo/Cline CLI).
2. **Platform Backends:**
   - Windows / **WSL2** `bwrap` ergonomics and documentation
   - **macOS Phase 4 path-remapping** (FUSE / NFSv3 transparent cwd remapping)
3. **External MCP Firewall Bundles:** Declarative `aegis-mcp-bundle/v1` templates and policy profiles for popular MCP servers.
4. **Red-Team Bypass Payloads:** New reproducible bypass attempts for `scripts/p2_live/deterministic_rm_bench.py` (especially `V7+` edge cases — please report real escapes privately first via [SECURITY.md](SECURITY.md)).
5. **Documentation & Examples:** Workflow recipes, CI integration guides, and minimal demos under `examples/`.

## Pull Request Guidelines

1. Keep PRs focused and include unit/integration tests for behavioral changes.
2. Ensure `cargo test --workspace --locked` and `cargo fmt --check` pass locally before opening a PR.
3. Never commit secrets, real `~/.ssh` / API keys, or non-deterministic local paths into fixtures or benchmarks.
4. For security-sensitive changes (Seatbelt profiles, `bwrap` bind mounts, DLP rules, or `SessionBroker` auth), clearly describe the threat model and verify fail-closed behavior.
