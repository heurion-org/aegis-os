# Security Policy

## Scope & Security Boundaries

Aegis OS has three distinct execution modes. Please understand which modes constitute a security boundary before reporting a bypass:

| Mode | Security Boundary? | Scope |
|---|---|---|
| **Enforced** (`aegis-os run -- <agent>`, `aegis-os install --enforce`) | **Yes** | Parent-process kernel sandbox (Linux `bwrap --bind-fd` / macOS Seatbelt), CoW shadow workspace, split `.git` view, read-only agent/hook config mounts, L4/L7 boundary proxy (`$AOS_SECRET_*` injection + DLP), and dual-token `SessionBroker` with SHA-256 frozen-stage commit gate. |
| **Isolated** (`aegis-os run --isolated -- <agent>` / Aegis Cloud) | **Yes** | Hardware-virtualized zero-NIC MicroVM (`vfkit` / `cloud-hypervisor`) or isolated cloud worker. |
| **Advisory** (`aegis-os install` without `--enforce`) | **No (Compatibility Only)** | In-process hooks, MCP guidance, and rules reduce prompt fatigue and catch honest mistakes, **not** a compromised or prompt-injected agent under the user's ambient UNIX UID. |

A bypass in **Advisory** mode alone is expected and out of scope for security advisories. **Any escape, secret exfiltration, config tampering, `.git` RCE, or commit TOCTOU bypass in `Enforced` or `Isolated` mode is strictly in scope and treated as high priority.**

## Supported Versions

Security fixes are backported to the latest minor release (`0.11.x` / `0.10.x`). Please reproduce issues against the latest GitHub release or `main` branch when possible.

## Reporting a Vulnerability or Sandbox Bypass

**Please do not open public GitHub Issues for undisclosed vulnerabilities or working sandbox bypasses.**

Report privately via either channel:

1. **GitHub Security Advisories (Preferred):** Open a draft advisory at `https://github.com/heurion-org/aegis-os/security/advisories/new`.
2. **Email:** Send encrypted or detailed reports to `security@heurion.org`.

### What to Include

- Aegis OS version (`aegis-os --version`) and OS/architecture (`uname -a`).
- Enforcement backend (`macos-seatbelt`, `linux-bwrap`, or `--isolated` MicroVM).
- Vector classification if applicable (e.g., `V1` host mutation, `V2` egress exfiltration, `V3` credential access, `V4` config tampering, `V5` `.git` RCE, `V6` broker/TOCTOU, or a novel vector).
- Minimal, reproducible proof-of-concept script or payload and observed vs. expected output.

## Response SLA

- **Acknowledgment:** Within **48 hours** of receipt.
- **Triage & Severity Assessment:** Within **5 business days**.
- **Fix & Coordinated Disclosure:** Critical sandbox escapes are prioritized for immediate patch releases, with public credit in release notes and advisory attribution (unless you prefer anonymity).
