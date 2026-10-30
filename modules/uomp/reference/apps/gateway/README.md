# UOMP Remote Authorization Gateway (deprecated)

> **Deprecated (2026-10).** The standalone UOMP Gateway and Cloud Relay product line is retired. Remote Agents now run on Aegis Cloud and reach local memory through Aegis Memory Gateway, with Aegis policy, leases, and trusted approval. This directory is kept as a historical reference and is no longer wired into the `uomp` CLI.

Historical notes:

- It exposed Memory Guard over mTLS + Capability Tokens.
- It supported Cloudflare Tunnel for zero-config public access.
- It did not hold the Auth Service private key; it only imported the public key to verify tokens.

For the current direction, see [`aegis-os/docs/UOMP_MEMORY_CONSENT_MAPPING.md`](https://github.com/heurion-org/aegis-os/blob/main/docs/UOMP_MEMORY_CONSENT_MAPPING.md) and the UOMP spec §15 (Remote Agent Profile).
