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
        let reject_ctrl = |label: &str, val: &str| -> anyhow::Result<()> {
            if val.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
                bail!("invalid control character in email {label}");
            }
            Ok(())
        };
        reject_ctrl("subject", subject)?;
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
                reject_ctrl("smtp host", host)?;
                reject_ctrl("smtp user", user)?;
                reject_ctrl("smtp pass", pass)?;
                reject_ctrl("from", from)?;
                let from_addr = from
                    .rsplit_once('<')
                    .map(|(_, a)| a.trim_end_matches('>').trim().to_string())
                    .unwrap_or_else(|| from.clone());
                reject_ctrl("from address", &from_addr)?;
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
                reject_ctrl("resend api_key", api_key)?;
                reject_ctrl("from", from)?;
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

fn resolve_curl_binary() -> &'static str {
    for candidate in ["/usr/bin/curl", "/opt/homebrew/bin/curl", "/usr/local/bin/curl"] {
        if std::path::Path::new(candidate).is_file() {
            return candidate;
        }
    }
    "curl"
}

/// Runs `curl -K -` with `config` on stdin so secrets never show up in the process list.
fn run_curl(config: &str) -> anyhow::Result<()> {
    let config = format!("{config}silent\nshow-error\nmax-time = 30\n");
    let mut child = Command::new(resolve_curl_binary())
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
<title>Aegis Cloud — Approver Enrollment · Heurion Research</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Newsreader:ital,opsz,wght@0,6..72,300;0,6..72,400;1,6..72,300;1,6..72,400&display=swap" rel="stylesheet">
<style>
  /* Heurion Research — Nordic / Scandinavian Editorial Design System (v6) */
  :root {
    --bg: #FAF8F4; --bg-elevated: #FDFCF9; --fg: #151C19; --muted: #4A534E; --line: #DFDAD0;
    --accent: #233E33; --accent-soft: #E3ECE7; --mint: #00C472; --danger: #9E332E;
    --serif: 'Newsreader', Georgia, serif;
    --sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --mono: 'JetBrains Mono', ui-monospace, monospace;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.65 var(--sans); -webkit-font-smoothing: antialiased; }
  .nav { background: rgba(250, 248, 244, 0.92); border-bottom: 1px solid var(--line); padding: 1.1rem 2rem; display: flex; align-items: center; justify-content: space-between; }
  .brand { display: inline-flex; align-items: center; gap: 0.65rem; color: var(--fg); text-decoration: none; font-weight: 700; font-size: 0.9rem; letter-spacing: 0.2em; }
  .brand svg { width: 22px; height: 20px; }
  main { max-width: 580px; margin: 48px auto; padding: 0 20px; }
  .label-caps { font: 0.72rem/1.2 var(--mono); letter-spacing: 0.14em; text-transform: uppercase; color: #646D68; margin: 0 0 8px; }
  .card { background: var(--bg-elevated); border: 1px solid var(--line); padding: 28px; }
  h1 { font: 300 1.65rem/1.25 var(--serif); margin: 0 0 12px; color: var(--fg); }
  p { color: var(--muted); margin: 10px 0; font-size: 0.95rem; }
  button { background: var(--accent); color: #F4F1EA; border: 1px solid var(--accent); border-radius: 0; padding: 11px 22px; font: 500 0.85rem/1.3 var(--sans); letter-spacing: 0.02em; cursor: pointer; }
  button:hover { background: var(--fg); border-color: var(--fg); }
  button:disabled { opacity: .6; cursor: default; }
  code { font: 0.82rem var(--mono); word-break: break-all; background: #EFECE4; padding: 3px 7px; border: 1px solid var(--line); }
  .qr { background: #fff; border: 1px solid var(--line); display: inline-block; padding: 14px; margin: 14px 0; }
  .err { color: var(--danger); }
  a { color: var(--accent); }
</style>
</head>
<body>
<header class="nav">
  <a class="brand" href="https://heurion.org/">
    <svg viewBox="-2 6 96 88" aria-hidden="true">
      <rect fill="#151C19" x="0" y="10" width="18" height="80" rx="9"/>
      <rect fill="#151C19" x="62" y="30" width="18" height="60" rx="9"/>
      <rect fill="#00C472" x="14" y="42" width="52" height="18" rx="9"/>
      <circle fill="#00C472" cx="80" cy="20" r="11"/>
    </svg>
    <span>HEURION</span>
  </a>
  <a href="/aegis-cloud/dashboard" style="font:0.82rem var(--mono);text-decoration:none;color:var(--accent);">Aegis Cloud Console →</a>
</header>
<main><div class="card" id="card">
  <p class="label-caps">AEGIS CLOUD · TOTP APPROVER ENROLLMENT</p>
  <h1>Become the approver for this Aegis Cloud org</h1>
  <p>You will add a code generator to your authenticator app (Google Authenticator, 1Password, …). Approving an agent's escalation will then require the 6-digit code from that app in your browser console or AI coding chat.</p>
  <p>Enrolling replaces any previous approver device for this org.</p>
  <p style="margin-top:18px;"><button id="go" onclick="enroll()">Enroll my authenticator →</button></p>
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
      const lbl = document.createElement('p'); lbl.className = 'label-caps'; lbl.textContent = 'ENROLLED · RFC 6238 TOTP'; card.appendChild(lbl);
      const h = document.createElement('h1'); h.textContent = 'Approver enrolled for ' + data.org_id; card.appendChild(h);
      const p1 = document.createElement('p'); p1.textContent = 'Scan this QR code with your authenticator app:'; card.appendChild(p1);
      const qr = document.createElement('div'); qr.className = 'qr'; qr.innerHTML = data.qr_svg; card.appendChild(qr);
      const p2 = document.createElement('p'); p2.append('Or enter this key manually: '); const c = document.createElement('code'); c.textContent = data.secret; p2.appendChild(c); card.appendChild(p2);
      const p3 = document.createElement('p'); const a = document.createElement('a'); a.href = data.otpauth_uri; a.textContent = 'Open in authenticator app (on this phone)'; p3.appendChild(a); card.appendChild(p3);
      const p4 = document.createElement('p'); p4.textContent = 'This key is shown once. Approve escalations in your browser (/approve or /dashboard) or enter the 6-digit code in chat.'; card.appendChild(p4);
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
<title>Aegis OS — Boundary Approval · Heurion Research</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Newsreader:ital,opsz,wght@0,6..72,300;0,6..72,400;1,6..72,300;1,6..72,400&family=Noto+Serif+SC:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  /* Heurion Research — Nordic / Scandinavian Editorial Design System (v6) */
  :root {
    --bg: #FAF8F4;
    --bg-neutral: #EFECE4;
    --card: #FDFCF9;
    --fg: #151C19;
    --muted: #4A534E;
    --ink-muted: #646D68;
    --line: #DFDAD0;
    --accent: #233E33;
    --accent-soft: #E3ECE7;
    --mint: #00C472;
    --danger: #9E332E;
    --code-bg: #EFECE4;
    --serif: 'Newsreader', 'Noto Serif SC', Georgia, serif;
    --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'PingFang SC', sans-serif;
    --mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  *, *::before, *::after { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.68 var(--sans); -webkit-font-smoothing: antialiased; }
  a { color: inherit; text-decoration: none; transition: color 0.18s ease, border-color 0.18s ease, background 0.18s ease; }
  a:hover { color: var(--accent); }
  .container { max-width: 1220px; margin: 0 auto; padding: 0 3.5rem; }
  .nav {
    position: sticky; top: 0; z-index: 50;
    background: rgba(250, 248, 244, 0.92);
    backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--line);
  }
  .nav-inner {
    max-width: 1220px; margin: 0 auto; padding: 1.2rem 3.5rem;
    display: flex; align-items: center; justify-content: space-between; gap: 1.5rem;
  }
  .brand-group { display: flex; align-items: center; gap: 0.75rem; white-space: nowrap; flex-shrink: 0; }
  .brand { display: inline-flex; align-items: center; gap: 0.7rem; color: var(--fg); white-space: nowrap; flex-shrink: 0; }
  .brand-mark { width: 24px; height: 22px; display: block; flex-shrink: 0; }
  .brand-word { font: 700 0.92rem var(--sans); letter-spacing: 0.22em; text-transform: uppercase; color: var(--fg); }
  .brand-sep { color: var(--line); font-weight: 300; flex-shrink: 0; }
  .brand-sub { font: 0.68rem var(--mono); letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); padding: 0.18rem 0.52rem; background: var(--accent-soft); border: 1px solid rgba(35, 62, 51, 0.2); white-space: nowrap; flex-shrink: 0; }
  .nav-links { display: flex; align-items: center; gap: 1.65rem; flex-wrap: nowrap; }
  .nav-link { font-size: 0.875rem; letter-spacing: 0.02em; color: var(--muted); white-space: nowrap; flex-shrink: 0; }
  .nav-link:hover, .nav-link-active { color: var(--fg); font-weight: 500; }
  .nav-right { display: flex; align-items: center; gap: 0.85rem; white-space: nowrap; flex-shrink: 0; }
  .badge { font: 0.68rem var(--mono); letter-spacing: 0.06em; padding: 0.24rem 0.65rem; border: 1px solid var(--line); color: var(--muted); background: var(--bg); white-space: nowrap; flex-shrink: 0; }
  .nav-cta { font-size: 0.8125rem; font-weight: 500; letter-spacing: 0.03em; padding: 0.52rem 1.15rem; border: 1px solid var(--fg); color: var(--fg); white-space: nowrap; flex-shrink: 0; }
  .nav-cta:hover { background: var(--accent); border-color: var(--accent); color: #F4F1EA; }
  .sec-hero {
    padding: 3.25rem 0 2.75rem;
    background-color: var(--bg);
    background-image:
      linear-gradient(102deg, rgba(250, 248, 244, 0.95) 0%, rgba(250, 248, 244, 0.88) 55%, rgba(239, 236, 228, 0.76) 100%),
      url('https://images.unsplash.com/photo-1542273917363-3b1817f69a2d?auto=format&fit=crop&w=2000&q=80');
    background-size: cover; background-position: center 62%;
    border-bottom: 1px solid var(--line);
  }
  .label-caps { font: 0.75rem var(--mono); letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-muted); margin: 0 0 0.65rem; }
  .heading-1 { font: 300 clamp(1.85rem, 2.6vw, 2.45rem)/1.2 var(--serif); letter-spacing: -0.02em; color: var(--fg); margin: 0 0 0.6rem; }
  .heading-1 em { font-style: italic; font-weight: 400; color: var(--accent); }
  main.approve-main { max-width: 860px; margin: 2.75rem auto 4.5rem; padding: 0 2rem; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 0; padding: 1.75rem 2rem; margin-bottom: 1.25rem; }
  h1 { font: 400 1.38rem/1.3 var(--serif); margin: 0 0 8px; color: var(--fg); }
  h2 { font: 400 1.2rem/1.3 var(--serif); margin: 0 0 8px; color: var(--fg); }
  p { color: var(--muted); margin: 6px 0; font-size: 0.9375rem; }
  code, pre { font-family: var(--mono); font-size: 0.8rem; }
  code { background: var(--code-bg); padding: 2px 6px; border: 1px solid var(--line); word-break: break-all; }
  pre { background: #151C19; color: #F4F1EA; padding: 14px; border: 1px solid #151C19; overflow-x: auto; margin: 10px 0; }
  .meta { display: grid; grid-template-columns: 150px 1fr; gap: 8px 14px; font-size: 0.85rem; margin: 14px 0; padding: 14px 16px; background: var(--bg); border: 1px solid var(--line); }
  .meta dt { font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.08em; text-transform: uppercase; color: var(--ink-muted); }
  .meta dd { margin: 0; font-family: var(--mono); font-size: 0.8rem; color: var(--fg); word-break: break-all; }
  .risk-banner { margin: 12px 0; padding: 10px 14px; background: rgba(161, 44, 44, 0.06); border: 1px solid rgba(161, 44, 44, 0.35); border-left: 3px solid #A12C2C; color: #7F1D1D; font: 500 0.84rem/1.45 var(--sans); }
  .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 16px; }
  input[type="text"], input[type="password"], input[type="email"] {
    background: var(--bg); color: var(--fg); border: 1px solid var(--line); border-radius: 0;
    padding: 0.52rem 0.85rem; font: 0.85rem var(--sans); outline: none;
  }
  input:focus { border-color: var(--accent); background: #fff; }
  input.totp { width: 168px; font: 500 1rem var(--mono); letter-spacing: 0.18em; text-align: center; }
  button { background: var(--accent); color: #F4F1EA; border: 1px solid var(--accent); border-radius: 0; padding: 0.52rem 1.15rem; font: 500 0.82rem/1.3 var(--sans); letter-spacing: 0.02em; cursor: pointer; transition: all 0.18s ease; }
  button:hover { background: var(--fg); border-color: var(--fg); }
  button.secondary { background: var(--card); color: var(--fg); border: 1px solid var(--line); }
  button.secondary:hover { border-color: var(--accent); color: var(--accent); background: var(--bg); }
  button.danger { background: transparent; color: var(--danger); border: 1px solid rgba(158, 51, 46, 0.4); }
  button.danger:hover { background: rgba(158, 51, 46, 0.09); border-color: var(--danger); }
  button:disabled { opacity: .55; cursor: default; }
  .ok { color: var(--accent); font-weight: 500; }
  .err { color: var(--danger); }
  .diff-drawer { margin-top: 14px; border: 1px solid var(--line); background: #151C19; color: #F4F1EA; padding: 12px 14px; font: 0.76rem/1.5 var(--mono); overflow-x: auto; max-height: 360px; overflow-y: auto; display: none; }
  .diff-line-add { color: #5CE6A0; }
  .diff-line-del { color: #FF8B85; }
  .diff-line-hunk { color: #8AB4F8; }
  .foot { background: var(--bg); border-top: 1px solid var(--line); padding: 2rem 0; }
  .foot-bar { display: flex; align-items: center; justify-content: space-between; gap: 1.5rem; flex-wrap: wrap; }
  .foot-right { display: flex; flex-wrap: wrap; align-items: center; gap: 1.35rem; font-size: 0.78rem; color: var(--ink-muted); }
  .foot-link { font: 0.72rem var(--mono); letter-spacing: 0.06em; color: var(--muted); }
  @media (max-width: 900px) {
    .container, .nav-inner { padding-left: 1.25rem; padding-right: 1.25rem; }
    .nav-links { display: none; }
    main.approve-main { padding: 0 1.25rem; }
  }
</style>
</head>
<body>
  <header class="nav" role="banner">
    <div class="nav-inner">
      <div class="brand-group">
        <a class="brand" href="https://heurion.org/" aria-label="Heurion Research">
          <svg class="brand-mark" viewBox="-2 6 96 88" aria-hidden="true">
            <rect fill="#151C19" x="0" y="10" width="18" height="80" rx="9"/>
            <rect fill="#151C19" x="62" y="30" width="18" height="60" rx="9"/>
            <rect fill="#00C472" x="14" y="42" width="52" height="18" rx="9"/>
            <circle fill="#00C472" cx="80" cy="20" r="11"/>
          </svg>
          <span class="brand-word">HEURION</span>
        </a>
        <span class="brand-sep">/</span>
        <span class="brand-sub">AEGIS OS</span>
      </div>
      <nav class="nav-links" aria-label="Console Navigation">
        <a href="https://heurion.org/" class="nav-link">Heurion.org</a>
        <a href="https://heurion.org/aegis-os/" class="nav-link">Overview</a>
        <a href="https://heurion.org/aegis-os/tutorial/" class="nav-link">Tutorial</a>
        <a id="dash-link" href="dashboard" class="nav-link">Console &amp; Pricing</a>
        <a id="app-link" href="app" class="nav-link">Remote (/app)</a>
        <a href="https://github.com/heurion-org/aegis-os" target="_blank" rel="noopener" class="nav-link">GitHub ↗</a>
      </nav>
      <div class="nav-right">
        <span class="badge" id="mode-badge">Connecting…</span>
        <a id="dash-cta" class="nav-cta" href="dashboard">Console / Pro →</a>
      </div>
    </div>
  </header>

  <section class="sec-hero">
    <div class="container">
      <p class="label-caps">AEGIS OS · POLICY KERNEL · HUMAN-IN-THE-LOOP</p>
      <h1 class="heading-1">Aegis OS — <em>Boundary Approval</em></h1>
      <p style="max-width:46rem;">Review unified diffs, SHA-256 evidence hashes, and approve host boundary crossings (<code>workspace_commit</code>, sensitive files, or domain egress leases). Once approved, your coding agent automatically resumes and completes the operation without needing any CLI commands.</p>
    </div>
  </section>

  <main class="approve-main">
    <div class="card" id="auth-box" style="display:none">
      <p class="label-caps">ACCOUNT SYNC</p>
      <h2>Load Your Account by Email or Org ID</h2>
      <p>Enter your work/billing email or organization ID (e.g. <code>dev-test</code>) to load pending boundary escalations:</p>
      <div class="row">
        <input type="text" id="lookup-email-input" placeholder="you@company.com or org_id" style="flex:1" onkeydown="if(event.key==='Enter')lookupByEmail()">
        <button onclick="lookupByEmail()">Load Account</button>
      </div>
      <p id="lookup-msg"></p>
    </div>

    <div class="card" id="enroll-box" style="display:none">
      <p class="label-caps">RFC 6238 TOTP · 1-TIME SETUP</p>
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

    <div class="card" id="mcp-inventory-card" style="display:none">
      <p class="label-caps">ZERO-TRUST MCP FIREWALL · ORG INVENTORY</p>
      <h2>Installed External MCP Servers</h2>
      <p style="font-size:13px;">Active servers staged into confined sessions, authentication posture, trust/DLP policy, and inline credential controls.</p>
      <div id="mcp-inventory-body"></div>
      <p id="mcp-inventory-msg"></p>
    </div>

    <div class="card" id="mcp-outbox-card" style="display:none">
      <p class="label-caps">ACTION OUTBOX · SHA-256 STAGED WRITES</p>
      <h2>Pending External MCP Writes</h2>
      <p style="font-size:13px;">Write/mutating calls intercepted from untrusted MCP servers. Review exact arguments before host dispatch.</p>
      <div id="mcp-outbox-body"></div>
      <p id="mcp-outbox-msg"></p>
    </div>
  </main>

  <footer class="foot" role="contentinfo">
    <div class="container">
      <div class="foot-bar">
        <a class="brand" href="https://heurion.org/" aria-label="Heurion Research">
          <svg class="brand-mark" viewBox="-2 6 96 88" aria-hidden="true">
            <rect fill="#151C19" x="0" y="10" width="18" height="80" rx="9"/>
            <rect fill="#151C19" x="62" y="30" width="18" height="60" rx="9"/>
            <rect fill="#00C472" x="14" y="42" width="52" height="18" rx="9"/>
            <circle fill="#00C472" cx="80" cy="20" r="11"/>
          </svg>
          <span class="brand-word">HEURION</span>
        </a>
        <div class="foot-right">
          <span>© 2026 Heurion Research · Aegis OS</span>
          <a href="https://heurion.org/aegis-os/" class="foot-link">Aegis OS</a>
          <a href="https://heurion.org/aegis-os/tutorial/" class="foot-link">Tutorial</a>
          <a id="foot-dash-link" href="dashboard" class="foot-link">Cloud Console</a>
          <a href="https://github.com/heurion-org/aegis-os" target="_blank" rel="noopener" class="foot-link">GitHub</a>
        </div>
      </div>
    </div>
  </footer>
<script>
  const qs = new URLSearchParams(location.search);
  const hashParams = new URLSearchParams(location.hash.replace(/^#/, ''));
  const targetId = qs.get('id') || '';
  let targetOrg = qs.get('org') || sessionStorage.getItem('aegis_org_id') || '';
  const mode = qs.get('mode') || 'cloud';
  const apiBase = location.pathname.startsWith('/aegis-cloud') ? '/aegis-cloud' : '';
  ['dash-link', 'dash-cta', 'foot-dash-link'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.href = apiBase + '/dashboard';
  });
  let authKey = hashParams.get('ticket') || hashParams.get('key') || sessionStorage.getItem('aegis_approve_key') || '';
  if (hashParams.get('ticket') || hashParams.get('key')) {
    sessionStorage.setItem('aegis_approve_key', authKey);
    history.replaceState(null, '', location.pathname + location.search);
  }
  const appLinkEl = document.getElementById('app-link');
  if (appLinkEl) {
    appLinkEl.href = apiBase + '/app' + (authKey ? '#key=' + encodeURIComponent(authKey) : '');
  }

  let requireTotp = false;

  function headers() {
    const h = { 'Content-Type': 'application/json' };
    if (authKey) h['Authorization'] = 'Bearer ' + authKey;
    return h;
  }

  async function lookupByEmail() {
    const email = (document.getElementById('lookup-email-input').value || '').trim();
    const msg = document.getElementById('lookup-msg');
    if (!email) return;
    msg.className = '';
    msg.textContent = 'Looking up organization…';
    try {
      const param = email.includes('@') ? 'email=' + encodeURIComponent(email) : 'org_id=' + encodeURIComponent(email);
      const res = await fetch(apiBase + '/v1/billing/status?' + param, { headers: headers() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      if (data.org_id) {
        targetOrg = data.org_id;
        sessionStorage.setItem('aegis_org_id', targetOrg);
      }
      localStorage.setItem('aegis_user_email', email);
      msg.className = 'ok';
      msg.textContent = 'Loaded organization: ' + (targetOrg || email);
      loadState();
    } catch (e) {
      msg.className = 'err';
      msg.textContent = e.message;
    }
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

  async function toggleDiff(escId) {
    const drawer = document.getElementById('diff-' + escId);
    if (!drawer) return;
    if (drawer.style.display === 'block') {
      drawer.style.display = 'none';
      return;
    }
    drawer.style.display = 'block';
    drawer.textContent = 'Loading immutable evidence & unified diff…';
    try {
      const res = await fetch(apiBase + '/v1/approvals/diff?escalation_id=' + encodeURIComponent(escId), { headers: headers() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      drawer.innerHTML = '';
      const diffObj = data.diff || {};
      const udiff = diffObj.unified_diff || '';
      if (udiff) {
        const lines = String(udiff).split('\n');
        for (const line of lines) {
          const div = document.createElement('div');
          if (line.startsWith('+') && !line.startsWith('+++')) div.className = 'diff-line-add';
          else if (line.startsWith('-') && !line.startsWith('---')) div.className = 'diff-line-del';
          else if (line.startsWith('@@')) div.className = 'diff-line-hunk';
          div.textContent = line;
          drawer.appendChild(div);
        }
      } else {
        const pre = document.createElement('div');
        pre.textContent = JSON.stringify(data.diff || data.evidence || data, null, 2);
        drawer.appendChild(pre);
      }
    } catch (e) {
      drawer.textContent = 'Failed to load diff: ' + e.message;
    }
  }

  function safeAuthUrl(raw) {
    try {
      const u = new URL(String(raw || '').trim());
      if (u.protocol === 'https:') return u.toString();
      if (u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost')) {
        return u.toString();
      }
    } catch (_) {}
    return '';
  }

  async function startMcpOAuth(opts, containerEl, msgEl) {
    if (!containerEl) return;
    containerEl.textContent = 'Discovering OAuth 2.1 metadata…';
    if (msgEl) {
      msgEl.className = '';
      msgEl.textContent = 'Starting OAuth 2.1 flow…';
    }
    try {
      const res = await fetch(apiBase + '/v1/mcp/oauth/start', {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify(opts || {})
      });
      const sess = await res.json();
      if (!res.ok) throw new Error(sess.error || res.statusText);

      containerEl.innerHTML = '';
      const info = document.createElement('div');
      info.style.marginTop = '8px';
      info.style.padding = '10px';
      info.style.border = '1px solid #d1d5db';
      info.style.borderRadius = '8px';

      if (sess.flow === 'pkce' && sess.authorize_url) {
        const safeUrl = safeAuthUrl(sess.authorize_url);
        if (!safeUrl) throw new Error('Unsafe authorize URL rejected');
        const p = document.createElement('p');
        p.style.margin = '0 0 6px 0';
        p.textContent = 'Complete authorization in the sign-in window, then return here:';
        info.appendChild(p);
        const a = document.createElement('a');
        a.href = safeUrl;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = 'Open Provider Sign-In →';
        a.style.fontWeight = '600';
        info.appendChild(a);
      } else if (sess.verification_uri) {
        const safeUri = safeAuthUrl(sess.verification_uri);
        if (!safeUri) throw new Error('Unsafe verification URI rejected');
        const p = document.createElement('p');
        p.style.margin = '0 0 6px 0';
        p.textContent = 'Open the verification link and enter the code below:';
        info.appendChild(p);
        const a = document.createElement('a');
        a.href = safeUri;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = safeUri;
        info.appendChild(a);
        if (sess.user_code) {
          const codeEl = document.createElement('div');
          codeEl.style.marginTop = '6px';
          codeEl.style.fontFamily = 'monospace';
          codeEl.style.fontSize = '15px';
          codeEl.style.fontWeight = '700';
          codeEl.textContent = 'User Code: ' + sess.user_code;
          info.appendChild(codeEl);
        }
      } else {
        const p = document.createElement('p');
        p.textContent = 'OAuth status: ' + (sess.status || 'starting');
        info.appendChild(p);
      }

      const stEl = document.createElement('p');
      stEl.style.margin = '8px 0 0 0';
      stEl.style.fontSize = '13px';
      stEl.textContent = 'Waiting for OAuth completion… (' + (sess.status || 'awaiting_user') + ')';
      info.appendChild(stEl);
      containerEl.appendChild(info);

      if (sess.status === 'completed') {
        stEl.className = 'ok';
        stEl.textContent = 'OAuth authenticated and sealed in host Vault.';
        if (msgEl) { msgEl.className = 'ok'; msgEl.textContent = 'Signed in.'; }
        await loadMcpInventory(true);
        return;
      }
      if (sess.status === 'failed') {
        stEl.className = 'err';
        stEl.textContent = 'OAuth failed: ' + (sess.error || 'unknown error');
        return;
      }

      let polls = 0;
      const pollTimer = setInterval(async () => {
        if (++polls > 220) {
          clearInterval(pollTimer);
          stEl.className = 'err';
          stEl.textContent = 'Timed out waiting for OAuth callback.';
          return;
        }
        try {
          const sres = await fetch(
            apiBase + '/v1/mcp/oauth/status?session_id=' + encodeURIComponent(sess.session_id),
            { headers: headers() }
          );
          const sdata = await sres.json();
          if (!sres.ok) throw new Error(sdata.error || sres.statusText);
          if (sdata.status === 'completed') {
            clearInterval(pollTimer);
            stEl.className = 'ok';
            stEl.textContent = 'OAuth authenticated and sealed in host Vault! Agent session will hot-reload automatically.';
            if (msgEl) { msgEl.className = 'ok'; msgEl.textContent = 'OAuth complete.'; }
            await loadMcpInventory(true);
          } else if (sdata.status === 'failed') {
            clearInterval(pollTimer);
            stEl.className = 'err';
            stEl.textContent = 'OAuth failed: ' + (sdata.error || 'unknown error');
            if (msgEl) { msgEl.className = 'err'; msgEl.textContent = sdata.error || 'OAuth failed'; }
          } else {
            stEl.textContent = 'Waiting for OAuth completion… (' + sdata.status + ')';
          }
        } catch (pe) {
          clearInterval(pollTimer);
          stEl.className = 'err';
          stEl.textContent = 'Status poll error: ' + pe.message;
        }
      }, 1500);
    } catch (e) {
      containerEl.innerHTML = '';
      if (msgEl) {
        msgEl.className = 'err';
        msgEl.textContent = 'OAuth error: ' + e.message;
      }
    }
  }

  async function decide(escId, decision, ttlSecs, opts) {
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
      const payload = {
        escalation_id: escId,
        decision,
        ttl_secs: ttlSecs,
        totp: totp || undefined,
        approved_by: mode === 'local' ? 'local-web-console' : 'web-approval-console'
      };
      const tokEl = document.getElementById('mcp-token-' + escId);
      if (tokEl && tokEl.value.trim()) {
        payload.inline_auth_token = tokEl.value.trim();
      }
      const trustEl = document.getElementById('mcp-trust-' + escId);
      if (trustEl && trustEl.value) {
        payload.trust_override = trustEl.value;
      }
      const envEls = document.querySelectorAll('[data-mcp-env-esc="' + escId + '"]');
      if (envEls && envEls.length > 0) {
        const envMap = {};
        envEls.forEach(inp => {
          const k = inp.getAttribute('data-mcp-env-key');
          if (k && inp.value.trim()) envMap[k] = inp.value.trim();
        });
        if (Object.keys(envMap).length > 0) payload.inline_env_secrets = envMap;
      }
      const res = await fetch(apiBase + '/v1/approvals/decide', {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify(payload)
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
      if (decision !== 'deny' && opts && opts.oauthAfter) {
        p.textContent = 'Install approved. Complete OAuth sign-in below to seal credentials directly into host Vault:';
        card.appendChild(h);
        card.appendChild(p);
        const oauthBox = document.createElement('div');
        const oauthMsg = document.createElement('p');
        card.appendChild(oauthBox);
        card.appendChild(oauthMsg);
        await startMcpOAuth(opts.oauthOpts, oauthBox, oauthMsg);
      } else {
        p.textContent = decision === 'deny'
          ? 'The blocked operation was rejected and recorded in the SHA-256 audit chain.'
          : 'Lease granted. Your agent session will automatically resume and complete the operation — you can close this tab.';
        card.appendChild(h);
        card.appendChild(p);
      }
    } catch (e) {
      msgEl.className = 'err';
      msgEl.textContent = 'Error: ' + e.message;
    }
  }

  function formatApprovalTitle(action) {
    const titles = {
      workspace_commit: 'Approve Host Workspace Commit',
      workspace_commit_sensitive: 'HIGH RISK: Approve Sensitive Host Commit',
      workspace_git: 'Approve Host Git Transaction',
      workspace_git_sensitive: 'HIGH RISK: Approve Sensitive Git Transaction',
      fs_import_file: 'Approve Host File Import',
      fs_export_file: 'Approve Host File Export',
      pkg_install: 'Approve Sandbox Package Install',
      pkg_install_scripts: 'HIGH RISK: Approve Package Install With Lifecycle Scripts',
      host_exec: '[HIGH RISK] Host Sibling Execution (host_exec — Unsandboxed, SHA-256 Frozen)',
      github_pr_create: 'Approve GitHub Pull Request Creation',
      github_pr_merge: 'DESTRUCTIVE: Approve GitHub Pull Request Merge',
      github_comment_create: 'Approve GitHub Issue / PR Comment',
      github_ci_rerun: 'Approve GitHub Actions Workflow Rerun',
      mcp_request_install: 'Approve External MCP Installation'
    };
    return titles[action] || ('Approve Boundary Action: ' + (action || 'syscall'));
  }

  function renderEscalation(esc) {
    const card = document.createElement('div');
    card.className = 'card';
    card.id = 'card-' + esc.escalation_id;

    const ev = esc.evidence || esc.metadata || {};
    const isHighRisk = [
      'workspace_commit_sensitive',
      'workspace_git_sensitive',
      'pkg_install_scripts',
      'host_exec',
      'github_pr_merge'
    ].includes(esc.action) || !!ev.allow_scripts || !!ev.force_push || !!ev.force_tag || !!ev.bootstrap_repo;

    const h = document.createElement('h1');
    if (isHighRisk) h.className = 'err';
    h.textContent = formatApprovalTitle(esc.action);
    card.appendChild(h);

    if (isHighRisk) {
      const warn = document.createElement('div');
      warn.className = 'risk-banner';
      const reasons = [];
      if (esc.action === 'host_exec') {
        reasons.push('Runs unsandboxed on the host as a sibling process (input bundle frozen & SHA-256 pinned; 15m/1h leases stay hash-locked)');
      }
      if (esc.action === 'pkg_install_scripts' || ev.allow_scripts) {
        reasons.push('Lifecycle build/postinstall scripts execute arbitrary code');
      }
      if (esc.action === 'workspace_commit_sensitive' || esc.action === 'workspace_git_sensitive') {
        reasons.push('Targets sensitive configuration, hook, or credential-adjacent paths');
      }
      if (ev.force_push) reasons.push('Includes destructive git force push');
      if (ev.force_tag) reasons.push('Includes force tag overwrite');
      if (ev.bootstrap_repo) {
        reasons.push('Initializes a new Git repo and binds origin -> ' + (ev.bootstrap_remote_url || 'local-only'));
      }
      if (esc.action === 'github_pr_merge') reasons.push('Destructive PR merge on remote repository');
      warn.textContent = (esc.action === 'host_exec' ? 'HIGH RISK · HASH-LOCKED HOST EXEC: ' : 'HIGH RISK · ONE-SHOT APPROVAL ONLY: ') +
        (reasons.length ? reasons.join('; ') : 'Elevated security boundary review required') +
        (esc.action === 'host_exec' ? '.' : '. Time-window leases (15m / 1h) are disabled.');
      card.appendChild(warn);
    }

    const p = document.createElement('p');
    p.textContent = esc.reason || 'Human approval required by Aegis OS policy kernel.';
    card.appendChild(p);

    const dl = document.createElement('dl');
    dl.className = 'meta';
    const fields = [
      ['Escalation', esc.escalation_id],
      ['Agent', (esc.org_id ? esc.org_id + '/' : '') + (esc.agent_id || 'agent')],
      ['Action', esc.action],
      ['Resource', esc.target_resource || esc.resource || '/workspace']
    ];
    if (esc.rationale) {
      fields.push(['Agent Rationale', esc.rationale]);
    }
    if (esc.evidence_hash) {
      fields.push(['Evidence SHA-256', esc.evidence_hash]);
    }
    if (ev.manager) {
      fields.push(['Package Manager', ev.manager]);
      fields.push(['Target Subdir', ev.cwd || '.']);
      fields.push(['Packages', Array.isArray(ev.packages) && ev.packages.length ? ev.packages.join(', ') : '<from manifest/lockfile>']);
      fields.push(['Allow Scripts', ev.allow_scripts ? 'true (LIFECYCLE SCRIPTS ENABLED)' : 'false']);
      fields.push(['Offline Mode', String(!!ev.offline)]);
      if (Array.isArray(ev.registry_domains) && ev.registry_domains.length) {
        fields.push(['Registries', ev.registry_domains.join(', ')]);
      }
    }
    if (ev.repo) fields.push(['Repository', ev.repo]);
    if (ev.pr_number !== undefined && ev.pr_number !== null) fields.push(['PR Number', '#' + ev.pr_number]);
    if (ev.number !== undefined && ev.number !== null) fields.push(['Issue / PR', '#' + ev.number]);
    if (ev.title) fields.push(['PR Title', ev.title]);
    if (ev.head || ev.base) fields.push(['Branch Flow', (ev.head || '<current>') + ' -> ' + (ev.base || '<default>')]);
    if (ev.draft !== undefined) fields.push(['Draft PR', String(!!ev.draft)]);
    if (ev.method) fields.push(['Merge Method', ev.method]);
    if (ev.delete_branch !== undefined) fields.push(['Delete Branch', String(!!ev.delete_branch)]);
    if (ev.run_id !== undefined && ev.run_id !== null) fields.push(['Workflow Run', '#' + ev.run_id + (ev.failed_only ? ' (failed jobs)' : '')]);
    if (ev.src_host_path) fields.push(['Host Source', ev.src_host_path]);
    if (ev.import_to) fields.push(['Import Target', ev.import_to + ' -> ' + (ev.dst_path || '')]);
    if (ev.dst_path && !ev.import_to) fields.push(['Destination', ev.dst_path]);
    if (ev.size_bytes !== undefined && ev.size_bytes !== null) fields.push(['Size (bytes)', String(ev.size_bytes)]);
    if (ev.src_sha256 || ev.sha256) fields.push(['Artifact SHA-256', ev.src_sha256 || ev.sha256]);
    if (Array.isArray(ev.paths) && ev.paths.length > 0) {
      fields.push(['Changed Files', ev.paths.join(', ')]);
    }
    if (Array.isArray(ev.shadow_paths) && ev.shadow_paths.length > 0) {
      fields.push(['Shadow Files', ev.shadow_paths.join(', ')]);
    }
    if (ev.branch) fields.push(['Target Branch', ev.branch]);
    if (ev.bootstrap_repo) fields.push(['Bootstrap Repo', 'git init -b ' + (ev.bootstrap_branch || 'main')]);
    if (ev.bootstrap_remote_url) fields.push(['Bootstrap Remote (origin)', ev.bootstrap_remote_url]);
    if (ev.commit_message) fields.push(['Commit Message', ev.commit_message]);
    if (ev.tag) fields.push(['Git Tag', ev.tag + (ev.force_tag ? ' (FORCE TAG)' : '')]);
    if (ev.push !== undefined) fields.push(['Git Push', String(!!ev.push) + (ev.force_push ? ' (FORCE PUSH)' : '')]);
    if (ev.host_root) {
      fields.push(['Host Repo', ev.host_root]);
    }
    if (ev.program) {
      fields.push(['Host Program', ev.program]);
    }
    if (ev.script) {
      fields.push(['Frozen Script', ev.script]);
    }
    if (Array.isArray(ev.args) && ev.args.length > 0) {
      fields.push(['Arguments', ev.args.join(' ')]);
    }
    if (Array.isArray(ev.output_files) && ev.output_files.length > 0) {
      fields.push(['Harvest Outputs', ev.output_files.join(', ')]);
    }
    if (Array.isArray(ev.pass_env_keys) && ev.pass_env_keys.length > 0) {
      fields.push(['Pass Env Keys', ev.pass_env_keys.join(', ')]);
    }
    if (esc.action === 'mcp_request_install') {
      if (ev.target) fields.push(['MCP Target', ev.target]);
      if (ev.server_id) fields.push(['Server Alias', ev.server_id]);
      if (ev.trust_tier) fields.push(['Trust Tier', ev.trust_tier]);
      if (ev.transport_kind) fields.push(['Transport', ev.transport_kind]);
      if (ev.remote_url) fields.push(['Endpoint URL', ev.remote_url]);
      if (Array.isArray(ev.allowed_hosts) && ev.allowed_hosts.length > 0) {
        fields.push(['Pinned Hosts', ev.allowed_hosts.join(', ')]);
      }
      if (ev.package_spec && ev.package_spec.identifier) {
        const ver = ev.package_spec.version ? '@' + ev.package_spec.version : '';
        fields.push(['Package (Sandboxed)', (ev.package_spec.registry_type || 'pkg') + ':' + ev.package_spec.identifier + ver]);
      }
      fields.push(['Default Posture', 'untrusted · DLP pseudonymize · writes staged to Outbox']);
    }
    for (const [k, v] of fields) {
      const dt = document.createElement('dt'); dt.textContent = k;
      const dd = document.createElement('dd'); dd.textContent = v;
      dl.appendChild(dt); dl.appendChild(dd);
    }
    card.appendChild(dl);

    if (esc.action === 'mcp_request_install') {
      const box = document.createElement('div');
      box.style.margin = '12px 0';
      box.style.padding = '12px';
      box.style.border = '1px solid #d1d5db';
      box.style.borderRadius = '8px';
      const note = document.createElement('p');
      note.style.margin = '0 0 8px 0';
      note.style.fontSize = '13px';
      note.textContent = 'Host Custody Auth (optional): paste API Key / Bearer token or env secrets here to seal directly into AES-256-GCM Vault without exposing secrets to the agent or chat.';
      box.appendChild(note);

      if (ev.transport_kind !== 'stdio') {
        const tokInp = document.createElement('input');
        tokInp.type = 'password';
        tokInp.id = 'mcp-token-' + esc.escalation_id;
        tokInp.placeholder = 'Optional static Bearer token / API key (sealed into Vault on approve)';
        tokInp.style.width = '100%';
        tokInp.style.marginBottom = '8px';
        box.appendChild(tokInp);
      }

      if (Array.isArray(ev.required_env_vars)) {
        for (const envName of ev.required_env_vars) {
          const envInp = document.createElement('input');
          envInp.type = 'password';
          envInp.setAttribute('data-mcp-env-esc', esc.escalation_id);
          envInp.setAttribute('data-mcp-env-key', envName);
          envInp.placeholder = envName + ' (Vault-sealed upstream env)';
          envInp.style.width = '100%';
          envInp.style.marginBottom = '6px';
          box.appendChild(envInp);
        }
      }

      const trustSel = document.createElement('select');
      trustSel.id = 'mcp-trust-' + esc.escalation_id;
      trustSel.innerHTML = '<option value=\"untrusted\">Trust: Untrusted External (DLP + Outbox + Taint)</option><option value=\"trusted\">Trust: Trusted Internal</option>';
      box.appendChild(trustSel);
      card.appendChild(box);
    }

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
    btnOnce.textContent = 'Approve Once (SHA-256 Pinned)';
    btnOnce.onclick = () => decide(esc.escalation_id, 'approve', 0);
    row.appendChild(btnOnce);

    if (esc.action === 'mcp_request_install' && ev.transport_kind !== 'stdio') {
      const btnOAuth = document.createElement('button');
      btnOAuth.textContent = 'Approve & Sign in with OAuth';
      btnOAuth.onclick = () => decide(esc.escalation_id, 'approve', 0, {
        oauthAfter: true,
        oauthOpts: {
          org_id: esc.org_id || targetOrg || 'default-org',
          server_id: ev.server_id || undefined,
          remote_url: ev.remote_url || undefined,
          allowed_hosts: Array.isArray(ev.allowed_hosts) ? ev.allowed_hosts : [],
          allow_local_http: !!ev.allow_local_http,
          mode: 'auto'
        }
      });
      row.appendChild(btnOAuth);
    }

    if ((!isHighRisk && esc.action !== 'mcp_request_install') || esc.action === 'host_exec') {
      const btn15m = document.createElement('button');
      btn15m.className = 'secondary';
      btn15m.textContent = 'Approve 15m';
      btn15m.onclick = () => decide(esc.escalation_id, 'approve', 900);
      row.appendChild(btn15m);

      const btnHour = document.createElement('button');
      btnHour.className = 'secondary';
      btnHour.textContent = 'Approve 1h';
      btnHour.onclick = () => decide(esc.escalation_id, 'approve', 3600);
      row.appendChild(btnHour);
    }

    const btnDiff = document.createElement('button');
    btnDiff.className = 'secondary';
    btnDiff.textContent = 'Inspect Diff';
    btnDiff.onclick = () => toggleDiff(esc.escalation_id);
    row.appendChild(btnDiff);

    const btnDeny = document.createElement('button');
    btnDeny.className = 'danger';
    btnDeny.textContent = 'Deny';
    btnDeny.onclick = () => decide(esc.escalation_id, 'deny', 0);
    row.appendChild(btnDeny);

    card.appendChild(row);

    const diffDrawer = document.createElement('pre');
    diffDrawer.className = 'diff-drawer';
    diffDrawer.id = 'diff-' + esc.escalation_id;
    card.appendChild(diffDrawer);

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
        root.innerHTML = '<div class="card"><p class="err">Enter your account email above to view and approve escalations.</p></div>';
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

      let list = (Array.isArray(data.pending_escalations) ? data.pending_escalations : [])
        .filter(e => !e.status || e.status === 'pending');
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
      } else {
        for (const esc of list) {
          root.appendChild(renderEscalation(esc));
        }
      }
      const canManageMcp = isOperatorKey || mode === 'local';
      await loadMcpInventory(canManageMcp);
      await loadMcpOutbox(canManageMcp);
    } catch (e) {
      root.innerHTML = '';
      const errCard = document.createElement('div');
      errCard.className = 'card';
      const errP = document.createElement('p');
      errP.className = 'err';
      errP.textContent = 'Failed to load escalations: ' + (e && e.message ? e.message : String(e));
      errCard.appendChild(errP);
      root.appendChild(errCard);
    }
  }

  async function mcpLogoutRealm(orgId, realmId) {
    const msg = document.getElementById('mcp-inventory-msg');
    try {
      const res = await fetch(apiBase + '/v1/mcp/logout', {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({ org_id: orgId, realm_id: realmId })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      msg.className = 'ok';
      msg.textContent = 'Revoked credentials for realm: ' + realmId;
      await loadMcpInventory(true);
    } catch (e) {
      msg.className = 'err';
      msg.textContent = e.message;
    }
  }

  async function saveMcpPolicy(orgId, serverId, trustLevel, dlpMode, isolateNet, allowedHostsText, allowElicitation) {
    const msg = document.getElementById('mcp-inventory-msg');
    try {
      const payload = {
        org_id: orgId,
        server_id: serverId,
        trust_level: trustLevel,
        dlp_mode: dlpMode
      };
      if (typeof isolateNet === 'boolean') {
        payload.isolate_upstream_network = isolateNet;
      }
      if (typeof allowedHostsText === 'string') {
        payload.allowed_hosts = allowedHostsText
          .split(',')
          .map(x => x.trim())
          .filter(Boolean);
      }
      if (typeof allowElicitation === 'boolean') {
        payload.allow_elicitation = allowElicitation;
      }
      const res = await fetch(apiBase + '/v1/mcp/policy', {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      msg.className = 'ok';
      msg.textContent = 'Updated policy for ' + serverId;
      await loadMcpInventory(true);
    } catch (e) {
      msg.className = 'err';
      msg.textContent = e.message;
    }
  }

  async function saveMcpStaticToken(orgId, serverId, realmId, token) {
    const msg = document.getElementById('mcp-inventory-msg');
    const cleanTok = String(token || '').trim();
    if (!cleanTok) {
      msg.className = 'err';
      msg.textContent = 'Enter a non-empty Bearer token or API key.';
      return;
    }
    try {
      const res = await fetch(apiBase + '/v1/mcp/login-token', {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({
          org_id: orgId,
          server_id: serverId,
          realm_id: realmId || serverId,
          token: cleanTok
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      msg.className = 'ok';
      msg.textContent = 'Sealed token into Vault for ' + serverId;
      await loadMcpInventory(true);
    } catch (e) {
      msg.className = 'err';
      msg.textContent = e.message;
    }
  }

  async function decideMcpOutbox(orgId, ticketId, approve) {
    const msg = document.getElementById('mcp-outbox-msg');
    try {
      const res = await fetch(apiBase + '/v1/mcp/outbox/decide', {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({
          org_id: orgId,
          ticket_id: ticketId,
          approve: !!approve,
          reviewed_by: mode === 'local' ? 'local-web-console' : 'web-approval-console'
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      msg.className = approve ? 'ok' : 'err';
      msg.textContent = (approve ? 'Dispatched ' : 'Denied ') + ticketId + ' (' + ((data.ticket && data.ticket.status) || data.status || 'done') + ')';
      await loadMcpOutbox(true);
      await loadMcpInventory(true);
    } catch (e) {
      msg.className = 'err';
      msg.textContent = e.message;
    }
  }

  async function loadMcpOutbox(canManage) {
    const card = document.getElementById('mcp-outbox-card');
    const body = document.getElementById('mcp-outbox-body');
    if (!card || !body || !canManage) return;
    try {
      const url = apiBase + '/v1/mcp/outbox?status=pending' + (targetOrg ? '&org_id=' + encodeURIComponent(targetOrg) : '');
      const res = await fetch(url, { headers: headers() });
      if (!res.ok) return;
      const data = await res.json();
      const tickets = Array.isArray(data.tickets) ? data.tickets : [];
      card.style.display = 'block';
      body.innerHTML = '';
      if (tickets.length === 0) {
        const p = document.createElement('p');
        p.style.fontSize = '13px';
        p.style.color = '#6b7280';
        p.textContent = 'No pending staged MCP writes.';
        body.appendChild(p);
        return;
      }
      const orgId = data.org_id || targetOrg || 'default-org';
      for (const t of tickets) {
        const item = document.createElement('div');
        item.style.padding = '10px 0';
        item.style.borderTop = '1px solid #e5e7eb';

        const hdr = document.createElement('div');
        hdr.style.fontWeight = '600';
        const shaShort = String(t.payload_sha256 || '').slice(0, 12);
        hdr.textContent = t.server_id + ' · ' + t.tool_name + ' [' + t.risk_class + '] · sha256:' + shaShort + (t.tainted ? ' · tainted' : '');
        item.appendChild(hdr);

        const pre = document.createElement('pre');
        pre.style.fontSize = '12px';
        pre.style.margin = '6px 0';
        pre.style.padding = '8px';
        pre.style.background = '#f9fafb';
        pre.style.borderRadius = '6px';
        pre.style.overflowX = 'auto';
        pre.textContent = JSON.stringify(t.preview_arguments || {}, null, 2);
        item.appendChild(pre);

        const btnRow = document.createElement('div');
        btnRow.className = 'row';
        const btnApp = document.createElement('button');
        btnApp.textContent = 'Approve & Dispatch';
        btnApp.onclick = () => decideMcpOutbox(t.org_id || orgId, t.ticket_id, true);
        btnRow.appendChild(btnApp);

        const btnDen = document.createElement('button');
        btnDen.className = 'danger';
        btnDen.textContent = 'Deny';
        btnDen.onclick = () => decideMcpOutbox(t.org_id || orgId, t.ticket_id, false);
        btnRow.appendChild(btnDen);

        item.appendChild(btnRow);
        body.appendChild(item);
      }
    } catch (_) {}
  }

  async function loadMcpInventory(canManage) {
    const card = document.getElementById('mcp-inventory-card');
    const body = document.getElementById('mcp-inventory-body');
    const msg = document.getElementById('mcp-inventory-msg');
    if (!card || !body || !canManage) return;
    try {
      const url = apiBase + '/v1/mcp/inventory' + (targetOrg ? '?org_id=' + encodeURIComponent(targetOrg) : '');
      const res = await fetch(url, { headers: headers() });
      if (!res.ok) return;
      const inv = await res.json();
      const orgId = inv.org_id || targetOrg || 'default-org';
      const servers = Array.isArray(inv.servers) ? inv.servers : [];
      card.style.display = 'block';
      body.innerHTML = '';
      if (servers.length === 0) {
        const p = document.createElement('p');
        p.style.fontSize = '13px';
        p.style.color = '#6b7280';
        p.textContent = 'No external MCP servers registered for this organization yet.';
        body.appendChild(p);
        return;
      }
      for (const s of servers) {
        const item = document.createElement('div');
        item.style.padding = '10px 0';
        item.style.borderTop = '1px solid #e5e7eb';

        const info = document.createElement('div');
        info.style.fontWeight = '600';
        info.textContent = s.server_id + ' · ' + s.transport + ' · auth=' + s.auth_state + ' · status=' + s.status;
        item.appendChild(info);

        const ctrl = document.createElement('div');
        ctrl.className = 'row';
        ctrl.style.marginTop = '8px';
        ctrl.style.flexWrap = 'wrap';
        ctrl.style.gap = '8px';

        const trustSel = document.createElement('select');
        const tOptU = document.createElement('option');
        tOptU.value = 'untrusted_external';
        tOptU.textContent = 'untrusted';
        const tOptT = document.createElement('option');
        tOptT.value = 'trusted_internal';
        tOptT.textContent = 'trusted';
        trustSel.appendChild(tOptU);
        trustSel.appendChild(tOptT);
        trustSel.value = s.trust_level === 'trusted_internal' ? 'trusted_internal' : 'untrusted_external';
        ctrl.appendChild(trustSel);

        const dlpSel = document.createElement('select');
        for (const dv of ['pseudonymize', 'block', 'off']) {
          const opt = document.createElement('option');
          opt.value = dv;
          opt.textContent = 'dlp:' + dv;
          dlpSel.appendChild(opt);
        }
        dlpSel.value = ['pseudonymize', 'block', 'off'].includes(s.dlp_mode) ? s.dlp_mode : 'pseudonymize';
        ctrl.appendChild(dlpSel);

        const elicitSel = document.createElement('select');
        const eOptOff = document.createElement('option');
        eOptOff.value = 'off';
        eOptOff.textContent = 'elicit:off';
        const eOptOn = document.createElement('option');
        eOptOn.value = 'on';
        eOptOn.textContent = 'elicit:on';
        elicitSel.appendChild(eOptOff);
        elicitSel.appendChild(eOptOn);
        elicitSel.value = s.allow_elicitation ? 'on' : 'off';
        ctrl.appendChild(elicitSel);

        let netSel = null;
        let hostsInp = null;
        if (s.transport === 'stdio') {
          netSel = document.createElement('select');
          const nOptIso = document.createElement('option');
          nOptIso.value = 'isolated';
          nOptIso.textContent = 'net:isolated';
          const nOptHost = document.createElement('option');
          nOptHost.value = 'host';
          nOptHost.textContent = 'net:host';
          netSel.appendChild(nOptIso);
          netSel.appendChild(nOptHost);
          netSel.value = s.isolate_upstream_network ? 'isolated' : 'host';
          ctrl.appendChild(netSel);

          hostsInp = document.createElement('input');
          hostsInp.type = 'text';
          hostsInp.placeholder = 'Allowed hosts (comma-sep)';
          hostsInp.style.width = '200px';
          hostsInp.value = Array.isArray(s.allowed_hosts) ? s.allowed_hosts.join(', ') : '';
          ctrl.appendChild(hostsInp);
        }

        const btnSave = document.createElement('button');
        btnSave.className = 'secondary';
        btnSave.textContent = 'Save Policy';
        btnSave.onclick = () => saveMcpPolicy(
          orgId,
          s.server_id,
          trustSel.value,
          dlpSel.value,
          netSel ? netSel.value === 'isolated' : undefined,
          hostsInp ? hostsInp.value : undefined,
          elicitSel.value === 'on'
        );
        ctrl.appendChild(btnSave);

        const oauthSlot = document.createElement('div');
        if (s.transport !== 'stdio') {
          const btnSign = document.createElement('button');
          btnSign.textContent = 'OAuth Sign-In';
          btnSign.onclick = () => startMcpOAuth(
            { org_id: orgId, server_id: s.server_id, realm_id: s.auth_realm || s.server_id, mode: 'auto' },
            oauthSlot,
            msg
          );
          ctrl.appendChild(btnSign);

          const tokInp = document.createElement('input');
          tokInp.type = 'password';
          tokInp.placeholder = 'Set Bearer / API key';
          tokInp.style.width = '180px';
          ctrl.appendChild(tokInp);

          const btnTok = document.createElement('button');
          btnTok.className = 'secondary';
          btnTok.textContent = 'Set Token';
          btnTok.onclick = () => saveMcpStaticToken(orgId, s.server_id, s.auth_realm || s.server_id, tokInp.value);
          ctrl.appendChild(btnTok);
        }

        if (s.auth_realm) {
          const btnRev = document.createElement('button');
          btnRev.className = 'danger';
          btnRev.textContent = 'Revoke Auth';
          btnRev.onclick = () => mcpLogoutRealm(orgId, s.auth_realm);
          ctrl.appendChild(btnRev);
        }

        item.appendChild(ctrl);
        item.appendChild(oauthSlot);
        body.appendChild(item);
      }
    } catch (_) {}
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

    #[test]
    fn mailer_rejects_control_chars_in_subject_and_config() {
        let dir = tempfile::tempdir().unwrap();
        let err = Mailer::Directory(dir.path().to_path_buf())
            .send("a@b.co", "Hi\r\nBcc: evil@attacker.tld", "link")
            .unwrap_err();
        assert!(err.to_string().contains("control character"));

        let err_api = Mailer::Resend {
            api_key: "re_abc\nurl = \"http://127.0.0.1\"".to_string(),
            from: "Aegis <no-reply@heurion.org>".to_string(),
        }
        .send("a@b.co", "Hi", "link")
        .unwrap_err();
        assert!(err_api.to_string().contains("control character"));
    }
}
