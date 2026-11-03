//! Tenant approvers: a human per org who approves Cloud escalations with a TOTP code (RFC 6238).
//!
//! Agents hold the tenant's API key and can read anything the tenant's CLI can read, so approval
//! needs a factor that never touches that machine: the 6-digit code on the approver's phone.
//! Enrollment hands out the TOTP secret only through channels an agent does not control — the
//! one-time billing claim token, or a link mailed to the org's address and opened in a browser.

use anyhow::{bail, Context};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub const TOTP_STEP_SECS: i64 = 30;
pub const TOTP_DIGITS: u32 = 6;
/// Accept codes from one step before/after the current one (clock skew).
const TOTP_SKEW_STEPS: i64 = 1;

/// 20 random bytes (160 bits, the RFC 4226 recommendation) from OS CSPRNG.
pub fn generate_secret() -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// RFC 4648 base32 without padding, the format authenticator apps expect.
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// HOTP value (RFC 4226) for one counter step.
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([digest[offset] & 0x7f, digest[offset + 1], digest[offset + 2], digest[offset + 3]]);
    code % 10u32.pow(TOTP_DIGITS)
}

pub fn totp_step(unix_secs: i64) -> i64 {
    unix_secs.div_euclid(TOTP_STEP_SECS)
}

/// Returns the step a `code` matches within the skew window, if any.
pub fn match_totp(secret: &[u8], code: &str, unix_secs: i64) -> Option<i64> {
    let code = code.trim();
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let now = totp_step(unix_secs);
    (now - TOTP_SKEW_STEPS..=now + TOTP_SKEW_STEPS)
        .filter(|step| *step >= 0)
        .find(|step| hotp(secret, *step as u64) == wanted)
}

pub fn otpauth_uri(org_id: &str, secret_b32: &str) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
                _ => format!("%{:02X}", b),
            })
            .collect::<String>()
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        enc("Aegis Cloud"),
        enc(org_id),
        secret_b32,
        enc("Aegis Cloud"),
        TOTP_DIGITS,
        TOTP_STEP_SECS
    )
}

/// QR code for an `otpauth://` URI, drawn with half-block characters for a terminal.
pub fn qr_terminal(data: &str) -> String {
    match qrcode::QrCode::new(data.as_bytes()) {
        Ok(code) => code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build(),
        Err(_) => String::new(),
    }
}

/// QR code for an `otpauth://` URI as inline SVG for the enrollment page.
pub fn qr_svg(data: &str) -> String {
    match qrcode::QrCode::new(data.as_bytes()) {
        Ok(code) => code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(220, 220)
            .build(),
        Err(_) => String::new(),
    }
}

/// Plain mailbox check; also rules out header injection (no whitespace or control characters).
pub fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && email.len() <= 254
        && email.chars().all(|c| c.is_ascii_graphic() && !matches!(c, '<' | '>' | '"' | ',' | ';'))
}

/// `a***@example.com`, so status calls do not leak the full address to whoever holds a tenant key.
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        None => "***".to_string(),
    }
}

/// How enrollment links are delivered. Same provider order as Heurion's mailer: standard SMTP
/// first, then the Resend API. Both go through `curl` (already required on cloud nodes) with
/// credentials on stdin, never in argv.
#[derive(Debug, Clone)]
pub enum Mailer {
    /// No mail configured: email enrollment is unavailable.
    Disabled,
    Smtp { host: String, port: u16, secure: bool, user: String, pass: String, from: String },
    Resend { api_key: String, from: String },
    /// Writes each message to a file (tests and local development).
    Directory(PathBuf),
}

pub const DEFAULT_EMAIL_FROM: &str = "Aegis Cloud <no-reply@heurion.org>";

impl Mailer {
    /// `AOS_SMTP_HOST`, `AOS_SMTP_PORT` (465), `AOS_SMTP_SECURE` (implicit TLS; defaults to on for
    /// port 465, otherwise STARTTLS is required), `AOS_SMTP_USER`, `AOS_SMTP_PASS`; or
    /// `AOS_RESEND_API_KEY`. Sender: `AOS_EMAIL_FROM`. `AOS_MAIL_DIR` writes messages to files.
    pub fn from_env() -> Self {
        Self::from_vars(|k| std::env::var(k).unwrap_or_default().trim().to_string())
    }

    pub fn from_vars(var: impl Fn(&str) -> String) -> Self {
        let dir = var("AOS_MAIL_DIR");
        if !dir.is_empty() {
            return Mailer::Directory(PathBuf::from(dir));
        }
        let from = match var("AOS_EMAIL_FROM") {
            f if f.is_empty() || f.contains(['\r', '\n']) => DEFAULT_EMAIL_FROM.to_string(),
            f => f,
        };
        let host = var("AOS_SMTP_HOST");
        if !host.is_empty() {
            let port = var("AOS_SMTP_PORT").parse().unwrap_or(465);
            let secure = match var("AOS_SMTP_SECURE").to_ascii_lowercase().as_str() {
                "1" | "true" => true,
                "0" | "false" => false,
                _ => port == 465,
            };
            return Mailer::Smtp { host, port, secure, user: var("AOS_SMTP_USER"), pass: var("AOS_SMTP_PASS"), from };
        }
        let api_key = var("AOS_RESEND_API_KEY");
        if !api_key.is_empty() {
            return Mailer::Resend { api_key, from };
        }
        Mailer::Disabled
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self, Mailer::Disabled)
    }

    pub fn send(&self, to: &str, subject: &str, body: &str) -> anyhow::Result<()> {
        if !valid_email(to) {
            bail!("invalid recipient address");
        }
        let quote = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        match self {
            Mailer::Disabled => bail!("Email delivery is not configured on this Aegis Cloud node"),
            Mailer::Directory(dir) => {
                std::fs::create_dir_all(dir)?;
                let name = format!("{}-{}.eml", chrono::Utc::now().timestamp_millis(), uuid::Uuid::new_v4().simple());
                std::fs::write(dir.join(name), format!("To: {to}\nSubject: {subject}\n\n{body}"))?;
                Ok(())
            }
            Mailer::Smtp { host, port, secure, user, pass, from } => {
                let from_addr = from
                    .rsplit_once('<')
                    .map(|(_, a)| a.trim_end_matches('>').trim().to_string())
                    .unwrap_or_else(|| from.clone());
                let message = format!(
                    "From: {from}\r\nTo: <{to}>\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n",
                    body.replace('\n', "\r\n")
                );
                let msg = private_temp_file("eml", message.as_bytes())?;
                let scheme = if *secure { "smtps" } else { "smtp" };
                let mut config = format!(
                    "url = \"{scheme}://{}:{port}\"\nmail-from = \"{}\"\nmail-rcpt = \"{}\"\nupload-file = \"{}\"\nssl-reqd\n",
                    quote(host),
                    quote(&from_addr),
                    quote(to),
                    quote(&msg.to_string_lossy())
                );
                if !user.is_empty() {
                    config.push_str(&format!("user = \"{}:{}\"\n", quote(user), quote(pass)));
                }
                let result = run_curl(&config);
                let _ = std::fs::remove_file(&msg);
                result.context("SMTP delivery failed")
            }
            Mailer::Resend { api_key, from } => {
                let payload = serde_json::json!({ "from": from, "to": [to], "subject": subject, "text": body });
                let data = private_temp_file("json", payload.to_string().as_bytes())?;
                let config = format!(
                    "url = \"https://api.resend.com/emails\"\nheader = \"Authorization: Bearer {}\"\nheader = \"Content-Type: application/json\"\ndata-binary = \"@{}\"\nfail-with-body\n",
                    quote(api_key),
                    quote(&data.to_string_lossy())
                );
                let result = run_curl(&config);
                let _ = std::fs::remove_file(&data);
                result.context("Resend delivery failed")
            }
        }
    }
}

/// Runs `curl -K -` with `config` on stdin so secrets never show up in the process list.
fn run_curl(config: &str) -> anyhow::Result<()> {
    let config = format!("{config}silent\nshow-error\nmax-time = 30\n");
    let mut child = Command::new("curl")
        .args(["-K", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run curl")?;
    child.stdin.take().context("curl stdin")?.write_all(config.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "{} {}",
            String::from_utf8_lossy(&out.stderr).trim(),
            String::from_utf8_lossy(&out.stdout).chars().take(300).collect::<String>()
        );
    }
    Ok(())
}

fn private_temp_file(ext: &str, contents: &[u8]) -> anyhow::Result<PathBuf> {
    let path = std::env::temp_dir().join(format!("aegis-mail-{}.{ext}", uuid::Uuid::new_v4().simple()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(&path)?.write_all(contents)?;
    Ok(path)
}

/// Page behind the mailed link. Opening it changes nothing (mail scanners prefetch links); the
/// secret is only issued when the person presses the button.
pub const ENROLL_PAGE_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis Cloud approver</title>
<style>
  :root { --bg:#f7f7f5; --fg:#1d1d1b; --muted:#6b6b66; --card:#fff; --line:#e4e4df; --accent:#1f6f50; }
  @media (prefers-color-scheme: dark) { :root { --bg:#151514; --fg:#ececea; --muted:#9a9a94; --card:#1e1e1c; --line:#2f2f2c; --accent:#5fbf95; } }
  body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui, -apple-system, sans-serif; }
  main { max-width:520px; margin:48px auto; padding:0 16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:24px; }
  h1 { font-size:20px; margin:0 0 8px; }
  p { color:var(--muted); margin:8px 0; }
  button { background:var(--accent); color:#fff; border:0; border-radius:8px; padding:10px 18px; font-size:15px; cursor:pointer; }
  button:disabled { opacity:.6; cursor:default; }
  code { font-family:ui-monospace, monospace; word-break:break-all; background:var(--bg); padding:2px 6px; border-radius:4px; }
  .qr { background:#fff; display:inline-block; padding:12px; border-radius:8px; margin:12px 0; }
  .err { color:#c0392b; }
</style>
</head>
<body>
<main><div class="card" id="card">
  <h1>Become the approver for this Aegis Cloud org</h1>
  <p>You will add a code generator to your authenticator app (Google Authenticator, 1Password, …). Approving an agent's escalation will then require the 6-digit code from that app, on the command line or the web.</p>
  <p>Enrolling replaces any previous approver device for this org.</p>
  <p><button id="go" onclick="enroll()">Enroll my authenticator</button></p>
  <p id="msg"></p>
</div></main>
<script>
  async function enroll() {
    const btn = document.getElementById('go');
    const msg = document.getElementById('msg');
    btn.disabled = true;
    const token = new URLSearchParams(location.search).get('token') || '';
    try {
      const res = await fetch(location.pathname, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      const card = document.getElementById('card');
      card.innerHTML = '';
      const h = document.createElement('h1'); h.textContent = 'Approver enrolled for ' + data.org_id; card.appendChild(h);
      const p1 = document.createElement('p'); p1.textContent = 'Scan this QR code with your authenticator app:'; card.appendChild(p1);
      const qr = document.createElement('div'); qr.className = 'qr'; qr.innerHTML = data.qr_svg; card.appendChild(qr);
      const p2 = document.createElement('p'); p2.append('Or enter this key manually: '); const c = document.createElement('code'); c.textContent = data.secret; p2.appendChild(c); card.appendChild(p2);
      const p3 = document.createElement('p'); const a = document.createElement('a'); a.href = data.otpauth_uri; a.textContent = 'Open in authenticator app (on this phone)'; p3.appendChild(a); card.appendChild(p3);
      const p4 = document.createElement('p'); p4.textContent = 'This key is shown once. Approve escalations in your browser (/approve) or with: aegis-os approve'; card.appendChild(p4);
    } catch (e) {
      msg.className = 'err'; msg.textContent = 'Enrollment failed: ' + e.message; btn.disabled = false;
    }
  }
</script>
</body>
</html>
"##;

/// Interactive Web Approval Console (`GET /approve`).
/// Accepts `#key=<api_key_or_token>` in the URL fragment (stripped immediately via `history.replaceState`)
/// so the CLI or MCP bridge can auto-open a browser tab when an escalation occurs, without needing a second CLI session.
pub const APPROVE_PAGE_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis OS — Boundary Approval</title>
<style>
  :root { --bg:#f7f7f5; --fg:#1d1d1b; --muted:#6b6b66; --card:#fff; --line:#e4e4df; --accent:#1f6f50; --danger:#b83227; --code-bg:#f0f0ec; }
  @media (prefers-color-scheme: dark) { :root { --bg:#151514; --fg:#ececea; --muted:#9a9a94; --card:#1e1e1c; --line:#2f2f2c; --accent:#5fbf95; --danger:#e05a4f; --code-bg:#252522; } }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.55 system-ui, -apple-system, sans-serif; }
  main { max-width:680px; margin:40px auto; padding:0 16px; }
  header { display:flex; align-items:center; justify-content:space-between; margin-bottom:20px; }
  .brand { font-weight:650; font-size:17px; letter-spacing:-0.01em; }
  .badge { font-size:12px; padding:3px 9px; border-radius:99px; border:1px solid var(--line); color:var(--muted); background:var(--card); }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:22px; margin-bottom:16px; }
  h1 { font-size:19px; margin:0 0 6px; }
  h2 { font-size:16px; margin:0 0 8px; }
  p { color:var(--muted); margin:6px 0; }
  code, pre { font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:13px; }
  code { background:var(--code-bg); padding:2px 6px; border-radius:4px; word-break:break-all; }
  pre { background:var(--code-bg); padding:12px; border-radius:8px; overflow-x:auto; margin:10px 0; color:var(--fg); }
  .meta { display:grid; grid-template-columns:110px 1fr; gap:6px 12px; font-size:14px; margin:12px 0; padding:12px; background:var(--bg); border-radius:8px; }
  .meta dt { color:var(--muted); font-weight:500; }
  .meta dd { margin:0; font-family:ui-monospace, monospace; word-break:break-all; }
  .row { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-top:14px; }
  input[type="text"], input[type="password"], input[type="email"] {
    background:var(--bg); color:var(--fg); border:1px solid var(--line); border-radius:8px;
    padding:9px 12px; font-size:14px; outline:none;
  }
  input.totp { width:160px; font-family:ui-monospace, monospace; font-size:16px; letter-spacing:0.15em; text-align:center; }
  button { background:var(--accent); color:#fff; border:0; border-radius:8px; padding:9px 16px; font-size:14px; font-weight:500; cursor:pointer; }
  button.secondary { background:transparent; color:var(--fg); border:1px solid var(--line); }
  button.danger { background:var(--danger); color:#fff; }
  button:disabled { opacity:.55; cursor:default; }
  .ok { color:var(--accent); font-weight:500; }
  .err { color:var(--danger); }
</style>
</head>
<body>
<main>
  <header>
    <div class="brand">Aegis OS · Boundary Approval</div>
    <div style="display:flex;align-items:center;gap:12px;">
      <a id="dash-link" href="dashboard" style="font-size:13px;color:var(--accent);text-decoration:none;font-weight:500;">Dashboard ↗</a>
      <span class="badge" id="mode-badge">Connecting…</span>
    </div>
  </header>

  <div class="card" id="auth-box" style="display:none">
    <h2>Authentication</h2>
    <p>Paste your Aegis API Key (<code>ak_live_…</code>) or Operator Token (<code>aop_…</code>):</p>
    <div class="row">
      <input type="password" id="api-key-input" placeholder="ak_live_... or aop_..." style="flex:1">
      <button onclick="saveKey()">Connect</button>
    </div>
  </div>

  <div class="card" id="enroll-box" style="display:none">
    <h2>1-Time Approver Setup</h2>
    <p>This Cloud org does not have a TOTP authenticator enrolled yet. Enter your email to receive a 1-click QR enrollment link:</p>
    <div class="row">
      <input type="email" id="enroll-email" placeholder="you@company.com" style="flex:1">
      <button onclick="requestEmailEnroll()">Send Enrollment Link</button>
    </div>
    <p id="enroll-msg"></p>
  </div>

  <div id="escalations-root">
    <div class="card"><p>Loading pending escalations…</p></div>
  </div>
</main>
<script>
  const qs = new URLSearchParams(location.search);
  const hashParams = new URLSearchParams(location.hash.replace(/^#/, ''));
  const targetId = qs.get('id') || '';
  const targetOrg = qs.get('org') || '';
  const mode = qs.get('mode') || 'cloud';
  const apiBase = location.pathname.startsWith('/aegis-cloud') ? '/aegis-cloud' : '';
  const dashLink = document.getElementById('dash-link');
  if (dashLink) dashLink.href = apiBase + '/dashboard';
  let authKey = hashParams.get('key') || sessionStorage.getItem('aegis_approve_key') || '';
  if (hashParams.get('key')) {
    sessionStorage.setItem('aegis_approve_key', authKey);
    history.replaceState(null, '', location.pathname + location.search);
  }

  let requireTotp = false;

  function headers() {
    const h = { 'Content-Type': 'application/json' };
    if (authKey) h['Authorization'] = 'Bearer ' + authKey;
    return h;
  }

  function saveKey() {
    authKey = document.getElementById('api-key-input').value.trim();
    if (authKey) sessionStorage.setItem('aegis_approve_key', authKey);
    loadState();
  }

  async function requestEmailEnroll() {
    const email = document.getElementById('enroll-email').value.trim();
    const msg = document.getElementById('enroll-msg');
    if (!email) return;
    try {
      const res = await fetch(apiBase + '/v1/approver/email', {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({ org_id: targetOrg || undefined, email })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      msg.className = 'ok';
      msg.textContent = 'Enrollment link sent to ' + email + '. Open it to scan your QR code, then return here.';
    } catch (e) {
      msg.className = 'err';
      msg.textContent = e.message;
    }
  }

  async function decide(escId, decision, ttlSecs) {
    const totpInput = document.getElementById('totp-' + escId);
    const msgEl = document.getElementById('msg-' + escId);
    const totp = totpInput ? totpInput.value.trim() : '';
    if (requireTotp && !totp) {
      msgEl.className = 'err';
      msgEl.textContent = 'Enter the 6-digit code from your authenticator app.';
      if (totpInput) totpInput.focus();
      return;
    }
    msgEl.className = '';
    msgEl.textContent = 'Submitting decision…';
    try {
      const res = await fetch(apiBase + '/v1/approvals/decide', {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({
          escalation_id: escId,
          decision,
          ttl_secs: ttlSecs,
          totp: totp || undefined,
          approved_by: mode === 'local' ? 'local-web-console' : 'web-approval-console'
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      const card = document.getElementById('card-' + escId);
      card.innerHTML = '';
      const h = document.createElement('h1');
      h.className = decision === 'deny' ? 'err' : 'ok';
      h.textContent = decision === 'deny'
        ? 'Escalation Denied (' + escId + ')'
        : 'Approved (' + escId + ')';
      const p = document.createElement('p');
      p.textContent = decision === 'deny'
        ? 'The blocked operation was rejected.'
        : 'Lease granted. Your agent session will automatically resume and complete the operation — you can close this tab.';
      card.appendChild(h);
      card.appendChild(p);
    } catch (e) {
      msgEl.className = 'err';
      msgEl.textContent = 'Error: ' + e.message;
    }
  }

  function renderEscalation(esc) {
    const card = document.createElement('div');
    card.className = 'card';
    card.id = 'card-' + esc.escalation_id;

    const h = document.createElement('h1');
    h.textContent = esc.action === 'workspace_commit'
      ? 'Approve Host Workspace Commit'
      : 'Approve Boundary Action: ' + esc.action;
    card.appendChild(h);

    const p = document.createElement('p');
    p.textContent = esc.reason || 'Human approval required by Aegis OS policy kernel.';
    card.appendChild(p);

    const dl = document.createElement('dl');
    dl.className = 'meta';
    const fields = [
      ['Escalation', esc.escalation_id],
      ['Agent', (esc.org_id ? esc.org_id + '/' : '') + (esc.agent_id || 'agent')],
      ['Action', esc.action],
      ['Resource', esc.resource || '/workspace']
    ];
    if (esc.metadata && Array.isArray(esc.metadata.paths) && esc.metadata.paths.length > 0) {
      fields.push(['Changed Files', esc.metadata.paths.join(', ')]);
    }
    if (esc.metadata && esc.metadata.host_root) {
      fields.push(['Host Repo', esc.metadata.host_root]);
    }
    for (const [k, v] of fields) {
      const dt = document.createElement('dt'); dt.textContent = k;
      const dd = document.createElement('dd'); dd.textContent = v;
      dl.appendChild(dt); dl.appendChild(dd);
    }
    card.appendChild(dl);

    const row = document.createElement('div');
    row.className = 'row';
    if (requireTotp) {
      const inp = document.createElement('input');
      inp.type = 'text';
      inp.className = 'totp';
      inp.id = 'totp-' + esc.escalation_id;
      inp.placeholder = '000000';
      inp.maxLength = 6;
      inp.autocomplete = 'one-time-code';
      row.appendChild(inp);
    }

    const btnOnce = document.createElement('button');
    btnOnce.textContent = 'Approve Once';
    btnOnce.onclick = () => decide(esc.escalation_id, 'approve', 120);
    row.appendChild(btnOnce);

    const btnHour = document.createElement('button');
    btnHour.className = 'secondary';
    btnHour.textContent = 'Approve for 1 Hour';
    btnHour.onclick = () => decide(esc.escalation_id, 'approve', 3600);
    row.appendChild(btnHour);

    const btnDeny = document.createElement('button');
    btnDeny.className = 'danger';
    btnDeny.textContent = 'Deny';
    btnDeny.onclick = () => decide(esc.escalation_id, 'deny', 0);
    row.appendChild(btnDeny);

    card.appendChild(row);
    const msg = document.createElement('p');
    msg.id = 'msg-' + esc.escalation_id;
    card.appendChild(msg);
    return card;
  }

  async function loadState() {
    const badge = document.getElementById('mode-badge');
    badge.textContent = mode === 'local' ? 'Local Workstation' : (targetOrg ? 'Cloud · ' + targetOrg : 'Cloud');
    const root = document.getElementById('escalations-root');
    try {
      const statusUrl = apiBase + '/v1/status' + (targetOrg ? '?org_id=' + encodeURIComponent(targetOrg) : '');
      const res = await fetch(statusUrl, { headers: headers() });
      if (res.status === 401 || res.status === 403) {
        document.getElementById('auth-box').style.display = 'block';
        root.innerHTML = '<div class="card"><p class="err">Authentication required to view and approve escalations.</p></div>';
        return;
      }
      document.getElementById('auth-box').style.display = 'none';
      const data = await res.json();

      const isOperatorKey = authKey.startsWith('aop_');
      if (mode !== 'local' && !isOperatorKey) {
        const appRes = await fetch(apiBase + '/v1/approver' + (targetOrg ? '?org_id=' + encodeURIComponent(targetOrg) : ''), { headers: headers() });
        if (appRes.ok) {
          const appData = await appRes.json();
          requireTotp = !!appData.enrolled;
          document.getElementById('enroll-box').style.display = (!appData.enrolled && appData.email_delivery) ? 'block' : 'none';
        }
      } else {
        requireTotp = false;
      }

      let list = Array.isArray(data.pending_escalations) ? data.pending_escalations : [];
      if (targetId) {
        const matching = list.filter(e => e.escalation_id === targetId);
        if (matching.length > 0) list = matching;
      }
      root.innerHTML = '';
      if (list.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'card';
        empty.innerHTML = '<h1 class="ok">All clear</h1><p>No pending boundary escalations require approval right now.</p>';
        root.appendChild(empty);
        return;
      }
      for (const esc of list) {
        root.appendChild(renderEscalation(esc));
      }
    } catch (e) {
      root.innerHTML = '<div class="card"><p class="err">Failed to load escalations: ' + e.message + '</p></div>';
    }
  }

  loadState();
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        let secret = b"12345678901234567890";
        let expected = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(secret, counter as u64), *want);
        }
    }

    #[test]
    fn totp_matches_rfc6238_sha1_vectors() {
        // RFC 6238 Appendix B (8-digit values), truncated to our 6 digits.
        let secret = b"12345678901234567890";
        for (t, eight) in [(59i64, 94287082u32), (1111111109, 7081804), (1234567890, 89005924), (2000000000, 69279037)] {
            assert_eq!(hotp(secret, totp_step(t) as u64), eight % 1_000_000);
        }
    }

    #[test]
    fn match_totp_accepts_skew_and_rejects_garbage() {
        let secret = generate_secret();
        let now = 1_800_000_000;
        let code = format!("{:06}", hotp(&secret, (totp_step(now) - 1) as u64));
        assert_eq!(match_totp(&secret, &code, now), Some(totp_step(now) - 1));
        let stale = format!("{:06}", hotp(&secret, (totp_step(now) - 3) as u64));
        assert_eq!(match_totp(&secret, &stale, now), None);
        assert_eq!(match_totp(&secret, "12345", now), None);
        assert_eq!(match_totp(&secret, "abcdef", now), None);
    }

    #[test]
    fn base32_matches_rfc4648() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_encode(b"12345678901234567890"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn email_validation_blocks_header_injection() {
        assert!(valid_email("ops@heurion.org"));
        assert!(!valid_email("ops@heurion.org\r\nBcc: x@y.z"));
        assert!(!valid_email("a b@c.d"));
        assert!(!valid_email("nodomain@"));
        assert!(!valid_email("x@localhost"));
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
    }

    #[test]
    fn mailer_config_follows_heurion_provider_order() {
        let vars = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()).unwrap_or_default()
        };
        assert!(matches!(Mailer::from_vars(vars(&[])), Mailer::Disabled));
        match Mailer::from_vars(vars(&[("AOS_SMTP_HOST", "smtp.163.com"), ("AOS_RESEND_API_KEY", "re_x")])) {
            Mailer::Smtp { port: 465, secure: true, ref from, .. } => assert_eq!(from, DEFAULT_EMAIL_FROM),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            Mailer::from_vars(vars(&[("AOS_SMTP_HOST", "mail"), ("AOS_SMTP_PORT", "587")])),
            Mailer::Smtp { port: 587, secure: false, .. }
        ));
        assert!(matches!(Mailer::from_vars(vars(&[("AOS_RESEND_API_KEY", "re_x")])), Mailer::Resend { .. }));
    }

    #[test]
    fn directory_mailer_writes_message() {
        let dir = tempfile::tempdir().unwrap();
        Mailer::Directory(dir.path().to_path_buf()).send("a@b.co", "Hi", "link").unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }
}
