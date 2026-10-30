# Aegis Memory Gateway deployment

This guide puts **Aegis Memory Gateway** in front of a local UOMP Memory Guard so a remote Agent (for example, one running in Aegis Cloud) can read scoped memory without exposing the Guard directly.

```text
Remote Agent (Aegis Cloud)
        │  TLS 1.3 + mTLS
        ▼
Native TLS 1.3 / mTLS  (or Caddy / reverse proxy)
        │  loopback HTTP
        ▼
aegis-os memory-gateway  (127.0.0.1:9443)
        │  session check + scope check + audit
        ▼
UOMP Memory Guard  (127.0.0.1:9374)
        │
        ▼
Memory Store (stays on the user device)
```

The gateway supports native TLS 1.3 / mTLS via `--tls-cert`, `--tls-key`, and `--client-ca`. It can also run as plain HTTP on loopback behind Caddy, nginx, or another trusted proxy. **Do not expose a plain-HTTP listener directly.**

## 1. Prerequisites

- Aegis OS installed (`aegis-os --version`).
- UOMP running locally (`uomp status`), with Memory Guard on `127.0.0.1:9374`.
- The UOMP public JWK, normally at `~/.uomp/.secrets/ed25519-public.jwk`.
- A public hostname for the gateway, for example `memory.example.com`.
- A client certificate authority for remote Agents.

## 2. Start the gateway

```bash
aegis-os memory-gateway \
  --listen 127.0.0.1:9443 \
  --guard-url http://127.0.0.1:9374 \
  --public-key ~/.uomp/.secrets/ed25519-public.jwk \
  --audience https://memory.example.com \
  --allowed-endpoint /v1/memory \
  --audit-log ~/.aegis-os/memory-gateway-audit.jsonl
```

`--audience` must exactly match the `audience` claim in the UOMP remote token. `--allowed-endpoint` can be repeated; omit it only if every memory endpoint should be reachable.

The gateway:

- verifies the UOMP EdDSA JWT;
- calls Guard `POST /v1/tokens/validate` before forwarding;
- enforces the token scope and endpoint allowlist;
- applies a per-session rate limit (60 req/min by default);
- writes `gateway_access` JSONL audit events;
- forwards only `GET /v1/memory` reads.

## 3. Native TLS 1.3 / mTLS

```bash
aegis-os memory-gateway \
  --listen 127.0.0.1:9443 \
  --guard-url http://127.0.0.1:9374 \
  --public-key ~/.uomp/.secrets/ed25519-public.jwk \
  --audience https://memory.example.com \
  --allowed-endpoint /v1/memory \
  --tls-cert /etc/aegis-memory/server.pem \
  --tls-key /etc/aegis-memory/server-key.pem \
  --client-ca /etc/aegis-memory/client-ca.pem \
  --audit-log ~/.aegis-os/memory-gateway-audit.jsonl
```

- `--tls-cert` + `--tls-key` enable TLS 1.3.
- `--client-ca` additionally requires and verifies client certificates (mTLS).
- Bind to `0.0.0.0:9443` only when a firewall restricts access to the public edge.

## 4. Caddy with TLS 1.3 and mTLS (optional)

`/etc/caddy/Caddyfile`:

```caddyfile
memory.example.com {
  tls {
    protocols tls1.3
    client_auth {
      mode require_and_verify
      trusted_ca_cert_file /etc/caddy/client-ca.pem
    }
  }

  reverse_proxy 127.0.0.1:9443
}
```

Reload Caddy:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

The gateway port stays bound to loopback; only Caddy is public.

## 5. systemd user service

`~/.config/systemd/user/aegis-memory-gateway.service`:

```ini
[Unit]
Description=Aegis Memory Gateway
After=network.target

[Service]
ExecStart=%h/.local/bin/aegis-os memory-gateway \
  --listen 127.0.0.1:9443 \
  --guard-url http://127.0.0.1:9374 \
  --public-key %h/.uomp/.secrets/ed25519-public.jwk \
  --audience https://memory.example.com \
  --allowed-endpoint /v1/memory \
  --audit-log %h/.aegis-os/memory-gateway-audit.jsonl
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now aegis-memory-gateway
journalctl --user -u aegis-memory-gateway -f
```

## 6. Test

Use a remote token whose `profile` is `remote` and whose `audience` is `https://memory.example.com`:

```bash
curl --cert client.pem --key client-key.pem \
  "https://memory.example.com/v1/memory?tag=notes/projects" \
  -H "Authorization: Bearer $UOM_TOKEN"
```

Expected:

- valid token + scope → `200` with filtered memory items;
- missing/invalid token → `401`;
- wrong audience, scope, or endpoint → `403`;
- revoked session → `401`;
- too many requests in a minute → `429`.

## 7. Security checklist

- Gateway listens on `127.0.0.1` only.
- Public entry point requires TLS 1.3 + mTLS.
- `--audience` is the public gateway URL, never `127.0.0.1`.
- `--allowed-endpoint /v1/memory` is set unless broader access is intentional.
- UOMP token TTL is short (10 minutes or less for remote).
- Audit log is append-only and outside the Agent sandbox.
- Memory Store and `~/.uomp` are never mounted into the remote Agent environment.
- Revocation is tested: `uomp revoke <session-id>` must make the next gateway request fail.

## 8. Current limits

- The gateway is read-only (`GET /v1/memory`).
- Native TLS 1.3 / mTLS is supported; Caddy remains an optional public edge.
- Payload delivery (`/v1/payload/*`) is not implemented yet.
- Aegis Cloud remote Agent provisioning is a separate step; this guide only covers the local memory entry point.
