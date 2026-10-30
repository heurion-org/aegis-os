# UOMP Reference Implementation Documentation

This directory contains design and implementation documents for the UOMP reference implementation (`uomp-mvp`). UOMP is an open protocol maintained by Heurion Research; [Aegis OS](https://github.com/heurion-org/aegis-os) is the reference runtime, and this repository is the reference CLI/local implementation. For the protocol-to-runtime design, see the [UOMP → Aegis OS memory consent mapping](https://github.com/heurion-org/aegis-os/blob/main/docs/UOMP_MEMORY_CONSENT_MAPPING.md).

For current usage, start with the [README Quick start](../README.md#quick-start). For the protocol specification, see the [UOMP website/spec](https://www.uomp.org/spec/).

## Current product docs

| Document | 中文 | English |
|----------|------|---------|
| Quick start / CLI / MCP | [`../README.md`](../README.md) | [`../README.md`](../README.md) |
| Protocol draft Draft-00 | [`../specs/draft-00.md`](../specs/draft-00.md) | [`../specs/draft-00.en.md`](../specs/draft-00.en.md) |
| CLI/SDK Design (historical, with current CLI summary) | [`cli-sdk-design.md`](./cli-sdk-design.md) | [`cli-sdk-design.en.md`](./cli-sdk-design.en.md) |
| SDK Design (API & Architecture, Node.js focus) | [`sdk-design.md`](./sdk-design.md) | [`sdk-design.en.md`](./sdk-design.en.md) |

## Advanced / preview / research docs

These documents are useful context, but they are not the current core workflow:

| Document | 中文 | English | Status |
|----------|------|---------|--------|
| Remote Authorization Design | [`remote-authorization-design.md`](./remote-authorization-design.md) | [`remote-authorization-design.en.md`](./remote-authorization-design.en.md) | Deprecated — use Aegis Cloud + Aegis Memory Gateway |
| Deployment Guide | [`deployment-guide.md`](./deployment-guide.md) | — | Local sections current; remote gateway section deprecated |
| Store Abstraction Design | [`store-abstraction-design.md`](./store-abstraction-design.md) | — | Research |
| On-chain Audit Design | [`on-chain-audit-design.md`](./on-chain-audit-design.md) | — | Research |

Remote Agent Profile is now implemented by Aegis Cloud (remote Agent runtime) + Aegis Memory Gateway (local entry point); the standalone UOMP Gateway and Cloud Relay are retired. The core current loop is agent-first: `uomp setup --vault <path>` imports Markdown/CSV/JSON, writes the client config, and starts the local server without granting access. When the agent first asks for a tag or key, UOMP opens a local consent page; the user approves and the same request continues. `uomp status` / `uomp stop` manage the server, `uomp audit` shows access, and `uomp revoke` / `uomp disconnect` remove access. `uomp connect` remains the explicit pre-authorize path for scripts and agent packages; `uomp import`, `uomp authorize`, and `uomp mcp --print-config` remain the manual/script fallback.
