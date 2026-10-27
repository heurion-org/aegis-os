# Releasing Aegis OS

Releases are cut by pushing a tag. `.github/workflows/release.yml` then:

1. **build**: tests and builds 4 targets (macOS arm64/x86_64, Linux x86_64/aarch64 on Ubuntu 22.04 for glibc 2.35).
2. **release** (needs approval in the `release` environment): signs every asset with the release key, verifies the signatures against the public key embedded in `scripts/install.sh`, publishes the GitHub Release and opens a PR updating `Formula/aegis-os.rb`.
3. **deploy** (needs approval in the `production` environment): SSHes to the cloud node with a key whose only capability is `aegis-upgrade <tag>`. The node downloads the tag from GitHub, verifies it with its pinned key, swaps the binary, health-checks, rolls back on failure, and refreshes the `releases/` mirror that `install.sh` downloads from.

```bash
git tag v0.4.0 && git push origin v0.4.0
```

## Trust model

- `install.sh` and the node accept only binaries signed by the release key (OpenSSH signature, namespace `aegis-os-release`). Mirrors and CDNs are not trusted.
- The release private key exists only in the `release` environment's secrets. The deploy key can only trigger `aegis-upgrade`, which cannot install anything unsigned.
- Limits: a full compromise of heurion.org can still serve a modified `install.sh`. Users who need more assurance can fetch the installer from GitHub. A signed but older release can be replayed (no rollback protection).

## One-time setup

### 1. Release signing key (on your machine; the private key never leaves your hands except into the secret)

```bash
ssh-keygen -t ed25519 -N "" -C aegis-os-release@heurion.org -f aegis-os-release
```

- Put the public key into `scripts/install.sh` as
  `RELEASE_SIGNER='aegis-os-release@heurion.org ssh-ed25519 AAAA...'` and commit it.
- Store the private key file contents as the `RELEASE_SIGNING_KEY` secret of the `release` environment. Then delete the local copy, or keep it offline.

### 2. Deploy key

```bash
ssh-keygen -t ed25519 -N "" -C github-deploy -f aegis-deploy
ssh-keyscan -t ed25519 95.217.106.25   # -> DEPLOY_KNOWN_HOSTS
```

In the `production` environment:
- `DEPLOY_SSH_KEY` (secret) is the private key.
- `DEPLOY_KNOWN_HOSTS` (secret) is the ssh-keyscan line.
- `DEPLOY_HOST` (variable) is `95.217.106.25`.

### 3. Prepare the node (once, as root)

```bash
scp -r scripts/deploy root@95.217.106.25:/tmp/aegis-deploy
ssh root@95.217.106.25 'bash /tmp/aegis-deploy/bootstrap_server.sh \
  "aegis-os-release@heurion.org ssh-ed25519 AAAA..." "$(cat aegis-deploy.pub)" && systemctl restart aegis-cloud'
```

This installs `/usr/local/sbin/aegis-upgrade` and pins the release key. It moves secrets from the unit into `/etc/aegis-cloud/env` (0600) and adds a stable `AOS_ADMIN_SECRET` (the operator token). It also authorizes the deploy key with the forced command.

### Mail for approver enrollment (optional)

`aegis-os cloud approver enroll --email` needs SMTP on the node. Add to `/etc/aegis-cloud/env`, then `systemctl restart aegis-cloud`:

```
AOS_SMTP_URL=smtps://smtp.gmail.com:465
AOS_SMTP_USER=you@gmail.com
AOS_SMTP_PASS=<app password>
AOS_SMTP_FROM=Aegis Cloud <you@gmail.com>
```

Without it, paid orgs still enroll through the billing claim; email enrollment returns an error.

### 4. Environments

In repo Settings → Environments, create `release` and `production`, each with yourself as required reviewer and restricted to `v*` tags. Protect `v*` tags in Settings → Rules.
