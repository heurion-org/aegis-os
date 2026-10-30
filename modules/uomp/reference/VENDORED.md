# Vendored UOMP reference implementation

This directory is a **temporary vendored copy** of the archived `uomp-core` reference implementation.

Why it exists:

- `aegis-os memory` still delegates some commands to the UOMP reference CLI.
- The Aegis Memory Gateway still proxies to the UOMP Guard in the native cutover.
- The integration and E2E tests remain the behavior baseline for the native Rust implementation.

Status:

- **Do not add new product features here.**
- Only migration/security fixes.
- This directory will be removed once `aegis-os memory` and the native data plane reach parity.

Build/test:

```bash
cd modules/uomp/reference
pnpm install
pnpm build
node --test tests/integration/*.test.mjs
```

See [`../README.md`](../README.md) for the module overview and [`../../../docs/MEMORY_DATA_PLANE.md`](../../../docs/MEMORY_DATA_PLANE.md) for the native cutover plan.
