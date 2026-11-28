/// Zero-dependency native WebCrypto implementation of `aegis-e2ee-v1`.
/// Runs identically in modern browsers (`window.crypto.subtle`) and Node.js (`globalThis.crypto.subtle`).
pub const WEBCRYPTO_E2EE_JS: &str = r#"
(function (root) {
  const subtle = (root.crypto || globalThis.crypto).subtle;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function utf8(str) {
    return encoder.encode(str);
  }

  function b64Encode(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < u8.length; i += chunk) {
      bin += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
    }
    return btoa(bin);
  }

  function b64Decode(b64) {
    const bin = atob(String(b64).trim());
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function b64UrlDecode(b64url) {
    let s = String(b64url).trim().replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4 !== 0) s += "=";
    return b64Decode(s);
  }

  function hexEncode(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let out = "";
    for (let i = 0; i < u8.length; i++) {
      out += u8[i].toString(16).padStart(2, "0");
    }
    return out;
  }

  function concatBytes(parts) {
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  }

  function encodeTranscript(parts) {
    let total = 0;
    for (const p of parts) total += 4 + p.length;
    const out = new Uint8Array(total);
    const view = new DataView(out.buffer);
    let off = 0;
    for (const p of parts) {
      view.setUint32(off, p.length, false);
      off += 4;
      out.set(p, off);
      off += p.length;
    }
    return out;
  }

  function validateRawP256(raw) {
    if (!(raw instanceof Uint8Array) || raw.length !== 65 || raw[0] !== 0x04) {
      throw new Error("Invalid P-256 uncompressed SEC1 public key");
    }
  }

  async function sha256(bytes) {
    return new Uint8Array(await subtle.digest("SHA-256", bytes));
  }

  async function deviceIdFromRawPub(raw65) {
    validateRawP256(raw65);
    const digest = await sha256(raw65);
    return "dev_" + hexEncode(digest).slice(0, 16);
  }

  async function fingerprintFromRawPub(raw65) {
    validateRawP256(raw65);
    const digest = await sha256(raw65);
    const hexUpper = hexEncode(digest.subarray(0, 12)).toUpperCase();
    const groups = [];
    for (let i = 0; i < hexUpper.length; i += 4) {
      groups.push(hexUpper.slice(i, i + 4));
    }
    return groups.join("-");
  }

  async function generateIdentityKeyPair(extractable = false) {
    return subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      extractable,
      ["sign", "verify"]
    );
  }

  async function exportRawPublicKey(publicKey) {
    return new Uint8Array(await subtle.exportKey("raw", publicKey));
  }

  function buildNonce(dirByte, epoch, seq) {
    if (epoch < 0 || epoch >= (1 << 24)) {
      throw new Error("Epoch out of 24-bit range");
    }
    const bigSeq = BigInt(seq);
    if (bigSeq <= 0n) {
      throw new Error("Sequence number must be positive");
    }
    const nonce = new Uint8Array(12);
    nonce[0] = dirByte & 0xff;
    nonce[1] = (epoch >>> 16) & 0xff;
    nonce[2] = (epoch >>> 8) & 0xff;
    nonce[3] = epoch & 0xff;
    const view = new DataView(nonce.buffer);
    view.setBigUint64(4, bigSeq, false);
    return nonce;
  }

  function buildAad(orgId, sessionId, from, to, epoch, dirStr, seq, kind) {
    return utf8(
      `aegis-frame-v1|${orgId}|${sessionId}|${from}|${to}|${epoch}|${dirStr}|${seq}|${kind}`
    );
  }

  async function initiateHandshake({
    clientKeyPair,
    trustCert,
    orgId,
    sessionId,
    hostDeviceId,
    requestedMode = "interact",
  }) {
    const clientRawPub = await exportRawPublicKey(clientKeyPair.publicKey);
    const clientDeviceId = await deviceIdFromRawPub(clientRawPub);
    if (trustCert.device_id !== clientDeviceId || trustCert.org_id !== orgId) {
      throw new Error("DeviceTrustCert identity or org mismatch");
    }

    const ephPair = await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const ephRawPub = await exportRawPublicKey(ephPair.publicKey);
    const clientNonce = new Uint8Array(32);
    (root.crypto || globalThis.crypto).getRandomValues(clientNonce);

    const transcript = encodeTranscript([
      utf8("aegis-e2ee-v1-client-hello"),
      utf8(orgId),
      utf8(sessionId),
      utf8(clientDeviceId),
      utf8(hostDeviceId),
      ephRawPub,
      clientNonce,
      utf8(requestedMode),
    ]);

    const sig = new Uint8Array(
      await subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        clientKeyPair.privateKey,
        transcript
      )
    );

    return {
      state: {
        ephPriv: ephPair.privateKey,
        ephRawPub,
        clientNonce,
        clientDeviceId,
        hostDeviceId,
        sessionId,
      },
      init: {
        session_id: sessionId,
        from_device_id: clientDeviceId,
        to_device_id: hostDeviceId,
        trust_cert: trustCert,
        eph_pubkey_sec1_b64: b64Encode(ephRawPub),
        nonce_b64: b64Encode(clientNonce),
        requested_mode: requestedMode,
        sig_b64: b64Encode(sig),
      },
    };
  }

  async function completeHandshake({ state, accept, hostRawPub, orgId }) {
    if (accept.session_id !== state.sessionId) {
      throw new Error("ServerHello session_id mismatch");
    }
    if (accept.from_device_id !== state.hostDeviceId) {
      throw new Error("ServerHello from_device_id mismatch");
    }
    if (accept.to_device_id !== state.clientDeviceId) {
      throw new Error("ServerHello to_device_id mismatch");
    }
    const expectedHostId = await deviceIdFromRawPub(hostRawPub);
    if (expectedHostId !== state.hostDeviceId) {
      throw new Error("hostRawPub mismatch");
    }

    const hostEphRaw = b64Decode(accept.eph_pubkey_sec1_b64);
    validateRawP256(hostEphRaw);
    const hostNonce = b64Decode(accept.nonce_b64);
    if (hostNonce.length !== 32) {
      throw new Error("Invalid ServerHello nonce length");
    }
    const sig = b64Decode(accept.sig_b64);

    const epochBe = new Uint8Array(4);
    new DataView(epochBe.buffer).setUint32(0, accept.epoch >>> 0, false);

    const serverTranscript = encodeTranscript([
      utf8("aegis-e2ee-v1-server-hello"),
      utf8(orgId),
      utf8(state.sessionId),
      utf8(accept.from_device_id),
      utf8(accept.to_device_id),
      hostEphRaw,
      hostNonce,
      state.ephRawPub,
      state.clientNonce,
      epochBe,
      utf8(accept.granted_mode),
    ]);

    const hostEcdsaPub = await subtle.importKey(
      "raw",
      hostRawPub,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    const okSig = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      hostEcdsaPub,
      sig,
      serverTranscript
    );
    if (!okSig) {
      throw new Error("ServerHello ECDSA P-256 signature verification failed");
    }

    const hostEphPubKey = await subtle.importKey(
      "raw",
      hostEphRaw,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    const sharedBits = await subtle.deriveBits(
      { name: "ECDH", public: hostEphPubKey },
      state.ephPriv,
      256
    );
    const hkdfKey = await subtle.importKey("raw", sharedBits, "HKDF", false, [
      "deriveKey",
    ]);
    const salt = await sha256(concatBytes([state.clientNonce, hostNonce]));

    const rxKey = await subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: utf8(`aegis-e2ee-v1|h2c|${orgId}|${state.sessionId}|${accept.epoch}`),
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const txKey = await subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: utf8(`aegis-e2ee-v1|c2h|${orgId}|${state.sessionId}|${accept.epoch}`),
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    let txSeq = 0;
    let lastRxSeq = 0;
    const epoch = accept.epoch;
    const sessionId = state.sessionId;
    const localDeviceId = state.clientDeviceId;
    const peerDeviceId = state.hostDeviceId;

    return {
      epoch,
      grantedMode: accept.granted_mode,
      async encryptFrame(kind, plaintextBytes) {
        txSeq += 1;
        const seq = txSeq;
        const nonce = buildNonce(0x02, epoch, seq);
        const aad = buildAad(
          orgId,
          sessionId,
          localDeviceId,
          peerDeviceId,
          epoch,
          "c2h",
          seq,
          kind
        );
        const ct = new Uint8Array(
          await subtle.encrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
            txKey,
            plaintextBytes
          )
        );
        return {
          v: 1,
          session_id: sessionId,
          from: localDeviceId,
          to: peerDeviceId,
          epoch,
          dir: "c2h",
          seq,
          kind,
          ct: b64Encode(ct),
        };
      },
      async decryptFrame(frame) {
        if (frame.v !== 1) throw new Error("Unsupported protocol version");
        if (frame.session_id !== sessionId) throw new Error("Session mismatch");
        if (frame.epoch !== epoch) throw new Error("Epoch mismatch");
        if (frame.dir !== "h2c") throw new Error("Unexpected frame direction");
        if (frame.from !== peerDeviceId || frame.to !== localDeviceId) {
          throw new Error("Peer routing mismatch");
        }
        if (frame.seq <= lastRxSeq) {
          throw new Error("REPLAY_DETECTED");
        }
        const nonce = buildNonce(0x01, frame.epoch, frame.seq);
        const aad = buildAad(
          orgId,
          sessionId,
          frame.from,
          frame.to,
          frame.epoch,
          frame.dir,
          frame.seq,
          frame.kind
        );
        const pt = new Uint8Array(
          await subtle.decrypt(
            {
              name: "AES-GCM",
              iv: nonce,
              additionalData: aad,
              tagLength: 128,
            },
            rxKey,
            b64Decode(frame.ct)
          )
        );
        lastRxSeq = frame.seq;
        return pt;
      },
    };
  }

  async function decryptHandoffCore({
    syncKeyB64,
    orgId,
    sessionId,
    handoffId,
    nonceB64,
    ctB64,
  }) {
    const syncKey = b64Decode(syncKeyB64);
    const context = utf8(`aegis-handoff-core-v1|${orgId}|${sessionId}|${handoffId}`);
    const hkdfKey = await subtle.importKey("raw", syncKey, "HKDF", false, [
      "deriveKey",
    ]);
    const aesKey = await subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: context, info: context },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    const pt = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: b64Decode(nonceB64),
        additionalData: context,
        tagLength: 128,
      },
      aesKey,
      b64Decode(ctB64)
    );
    return new Uint8Array(pt);
  }

  root.AegisE2ee = {
    utf8,
    decoder,
    b64Encode,
    b64Decode,
    b64UrlDecode,
    hexEncode,
    encodeTranscript,
    deviceIdFromRawPub,
    fingerprintFromRawPub,
    generateIdentityKeyPair,
    exportRawPublicKey,
    initiateHandshake,
    completeHandshake,
    decryptHandoffCore,
  };
})(typeof globalThis !== "undefined" ? globalThis : window);
"#;

pub const PWA_MANIFEST_JSON: &str = r##"{
  "name": "Aegis OS Remote Console",
  "short_name": "Aegis OS",
  "start_url": "/app",
  "scope": "/app",
  "display": "standalone",
  "background_color": "#FAF8F4",
  "theme_color": "#233E33",
  "description": "Zero-Knowledge E2EE cross-device console for any AI Agent running on Aegis OS."
}"##;

pub const MOBILE_APP_HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#233E33">
<link rel="manifest" href="app/manifest.json">
<title>Aegis OS — Remote Console · Heurion Research</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Newsreader:ital,opsz,wght@0,6..72,300;0,6..72,400;1,6..72,300;1,6..72,400&family=Noto+Serif+SC:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  /* Heurion Research — Nordic / Scandinavian Editorial Design System (v6) */
  :root {
    --bg-paper: #FAF8F4;
    --bg-neutral: #EFECE4;
    --bg-elevated: #FDFCF9;
    --ink: #151C19;
    --ink-secondary: #4A534E;
    --ink-muted: #646D68;
    --accent: #233E33;
    --accent-soft: #E3ECE7;
    --mint: #00C472;
    --warn: #8B5E1B;
    --warn-soft: #F7EFE0;
    --danger: #9E332E;
    --danger-soft: #F8E9E8;
    --hairline: #DFDAD0;
    --font-serif: 'Newsreader', 'Noto Serif SC', Georgia, serif;
    --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'PingFang SC', 'Hiragino Sans GB', sans-serif;
    --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    --max-w: 1120px;
  }
  *, *::before, *::after { box-sizing: border-box; }
  html { font-size: 16px; background: var(--bg-paper); color: var(--ink); }
  body {
    margin: 0;
    font-family: var(--font-sans);
    font-weight: 400;
    line-height: 1.65;
    background: var(--bg-paper);
    color: var(--ink);
    padding-bottom: calc(88px + env(safe-area-inset-bottom, 0px));
    -webkit-font-smoothing: antialiased;
  }
  a { color: inherit; text-decoration: none; transition: color 0.18s ease, border-color 0.18s ease, background 0.18s ease; }
  a:hover { color: var(--accent); }
  code { font-family: var(--font-mono); font-size: 0.8em; background: var(--bg-neutral); padding: 0.12rem 0.4rem; border: 1px solid var(--hairline); }

  body[data-lang="zh"] [data-en] { display: none !important; }
  body[data-lang="en"] [data-zh] { display: none !important; }

  .container { max-width: var(--max-w); margin: 0 auto; padding: 0 2.5rem; }

  /* Sticky Editorial Navigation (matches /dashboard & /approve) */
  .nav {
    position: sticky; top: 0; z-index: 50;
    background: rgba(250, 248, 244, 0.94);
    backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--hairline);
  }
  .nav-inner {
    max-width: var(--max-w); margin: 0 auto; padding: 1.05rem 2.5rem;
    display: flex; align-items: center; justify-content: space-between; gap: 1.25rem;
  }
  .brand-group { display: flex; align-items: center; gap: 0.7rem; white-space: nowrap; flex-shrink: 0; }
  .brand { display: inline-flex; align-items: center; gap: 0.65rem; color: var(--ink); white-space: nowrap; flex-shrink: 0; }
  .brand-mark { width: 24px; height: 22px; display: block; flex-shrink: 0; }
  .brand-word { font: 700 0.9rem var(--font-sans); letter-spacing: 0.22em; text-transform: uppercase; color: var(--ink); }
  .brand-sep { color: var(--hairline); font-weight: 300; flex-shrink: 0; }
  .brand-sub {
    font-family: var(--font-mono); font-size: 0.68rem; letter-spacing: 0.12em; text-transform: uppercase;
    color: var(--accent); padding: 0.18rem 0.52rem; background: var(--accent-soft);
    border: 1px solid rgba(35, 62, 51, 0.2); white-space: nowrap; flex-shrink: 0;
  }
  .nav-links { display: flex; align-items: center; gap: 1.4rem; flex-wrap: nowrap; }
  .nav-link { font-size: 0.875rem; letter-spacing: 0.02em; color: var(--ink-secondary); white-space: nowrap; flex-shrink: 0; }
  .nav-link:hover, .nav-link-active { color: var(--ink); font-weight: 500; }
  .nav-right { display: flex; align-items: center; gap: 0.65rem; white-space: nowrap; flex-shrink: 0; }
  .nav-mobile-link { display: none; }
  .lang-switch {
    font-family: var(--font-mono); font-size: 0.72rem; letter-spacing: 0.08em;
    padding: 0.28rem 0.6rem; border: 1px solid var(--hairline); color: var(--ink-secondary);
    background: transparent; cursor: pointer; white-space: nowrap; flex-shrink: 0;
  }
  .lang-switch:hover { border-color: var(--ink); color: var(--ink); background: transparent; }

  .badge {
    display: inline-flex; align-items: center; gap: 0.35rem;
    font-family: var(--font-mono); font-size: 0.68rem; letter-spacing: 0.06em;
    padding: 0.24rem 0.62rem; border: 1px solid var(--hairline);
    color: var(--ink-secondary); background: var(--bg-paper); white-space: nowrap; flex-shrink: 0;
  }
  .badge-ok { color: var(--accent); border-color: rgba(35, 62, 51, 0.32); background: var(--accent-soft); }
  .badge-warn { color: var(--warn); border-color: rgba(139, 94, 27, 0.35); background: var(--warn-soft); }
  .badge-err { color: var(--danger); border-color: rgba(158, 51, 46, 0.35); background: var(--danger-soft); }

  /* Console Hero Strip */
  .console-header {
    padding: 1.75rem 0 1.4rem;
    border-bottom: 1px solid var(--hairline);
    background: linear-gradient(180deg, rgba(239, 236, 228, 0.55) 0%, rgba(250, 248, 244, 0.95) 100%);
  }
  .label-caps {
    font-family: var(--font-mono); font-size: 0.72rem; letter-spacing: 0.14em;
    text-transform: uppercase; color: var(--ink-muted); margin: 0 0 0.4rem;
  }
  .console-title {
    font-family: var(--font-serif); font-weight: 300; font-size: clamp(1.55rem, 2.3vw, 2.05rem);
    line-height: 1.2; letter-spacing: -0.02em; color: var(--ink); margin: 0 0 0.35rem;
  }
  .console-title em { font-style: italic; font-weight: 400; color: var(--accent); }
  .dev-meta-line { font-family: var(--font-mono); font-size: 0.74rem; color: var(--ink-muted); word-break: break-all; }

  main { max-width: var(--max-w); margin: 0 auto; padding: 1.75rem 2.5rem 2.5rem; display: grid; gap: 1.25rem; }
  .card {
    background: var(--bg-elevated); border: 1px solid var(--hairline); border-radius: 0;
    padding: 1.35rem 1.5rem; min-width: 0;
  }
  .paired-strip {
    background: var(--accent-soft); border-color: rgba(35, 62, 51, 0.28);
    border-left: 3px solid var(--accent); padding: 0.85rem 1.25rem;
  }
  .sec-head {
    display: flex; align-items: baseline; justify-content: space-between; gap: 1rem;
    padding-bottom: 0.7rem; margin-bottom: 1rem; border-bottom: 1px solid var(--hairline); flex-wrap: wrap;
  }
  .sec-head-left { display: flex; align-items: baseline; gap: 0.75rem; flex-wrap: wrap; }
  .sec-num { font-family: var(--font-mono); font-size: 0.72rem; letter-spacing: 0.14em; color: var(--ink-muted); text-transform: uppercase; }
  h2 { font-family: var(--font-serif); font-weight: 400; font-size: 1.22rem; color: var(--ink); margin: 0; }

  label {
    display: block; font-family: var(--font-mono); font-size: 0.7rem; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--ink-muted); margin-bottom: 0.35rem;
  }
  input, textarea {
    width: 100%; background: var(--bg-paper); color: var(--ink); border: 1px solid var(--hairline);
    border-radius: 0; padding: 0.55rem 0.8rem; font-family: var(--font-mono); font-size: 0.82rem;
    margin-bottom: 0.85rem; outline: none;
  }
  input:focus, textarea:focus { border-color: var(--accent); background: #fff; }
  .row { display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; }

  button {
    display: inline-flex; align-items: center; justify-content: center; gap: 0.35rem;
    border: 1px solid var(--accent); border-radius: 0; padding: 0.5rem 1rem;
    font-family: var(--font-sans); font-size: 0.8125rem; font-weight: 500; letter-spacing: 0.02em;
    cursor: pointer; background: var(--accent); color: #F4F1EA; white-space: nowrap;
    transition: all 0.18s ease;
  }
  button:hover { background: var(--ink); border-color: var(--ink); color: #F4F1EA; }
  button.secondary {
    background: var(--bg-paper); color: var(--ink-secondary); border: 1px solid var(--hairline);
  }
  button.secondary:hover { border-color: var(--ink); color: var(--ink); background: var(--bg-elevated); }
  button.danger {
    background: transparent; color: var(--danger); border: 1px solid rgba(158, 51, 46, 0.42);
  }
  button.danger:hover { background: var(--danger-soft); border-color: var(--danger); color: var(--danger); }

  .tabs {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
    border: 1px solid var(--hairline); background: var(--bg-paper);
  }
  .tab { border: 0; border-right: 1px solid var(--hairline); padding: 0.55rem 0.6rem; font-size: 0.8rem; }
  .tab:last-child { border-right: 0; }
  .tab.secondary { background: transparent; color: var(--ink-secondary); border-top: 0; border-bottom: 0; border-left: 0; }
  .tab.active { background: var(--accent); color: #F4F1EA; }

  .log {
    background: #151C19; color: #F4F1EA; border: 1px solid #151C19; border-radius: 0;
    padding: 0.9rem 1rem; min-height: 220px; max-height: 52vh; overflow-y: auto;
    font-family: var(--font-mono); font-size: 0.78rem; line-height: 1.55;
    white-space: pre-wrap; word-break: break-word;
  }
  .prompt-bar {
    position: fixed; bottom: 0; left: 0; right: 0; z-index: 40;
    background: rgba(250, 248, 244, 0.96); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
    border-top: 1px solid var(--hairline);
    padding: 0.7rem 1.25rem calc(0.7rem + env(safe-area-inset-bottom, 0px));
    display: none; gap: 0.55rem; align-items: center;
  }
  .prompt-bar input { margin: 0; flex: 1; background: var(--bg-elevated); }
  .muted { color: var(--ink-muted); font-size: 0.82rem; }
  .session-item {
    display: flex; justify-content: space-between; align-items: center; gap: 0.85rem; flex-wrap: wrap;
    padding: 0.75rem 0.9rem; border: 1px solid var(--hairline); background: var(--bg-paper); margin-top: 0.55rem;
  }
  .session-title { font-family: var(--font-sans); font-weight: 500; font-size: 0.9rem; color: var(--ink); }
  .foot { background: var(--bg-paper); border-top: 1px solid var(--hairline); padding: 1.75rem 0; }
  .foot-bar { display: flex; align-items: center; justify-content: space-between; gap: 1.25rem; flex-wrap: wrap; }
  .foot-right { display: flex; flex-wrap: wrap; align-items: center; gap: 1.2rem; font-size: 0.78rem; color: var(--ink-muted); }
  .foot-link { font-family: var(--font-mono); font-size: 0.72rem; letter-spacing: 0.06em; color: var(--ink-secondary); }
  .hidden { display: none !important; }

  @media (max-width: 900px) {
    .container, .nav-inner, main { padding-left: 1.15rem; padding-right: 1.15rem; }
    .nav-links { display: none; }
    .nav-mobile-link {
      display: inline-flex; align-items: center; font-family: var(--font-mono); font-size: 0.72rem;
      padding: 0.28rem 0.6rem; border: 1px solid var(--hairline); color: var(--ink-secondary); background: var(--bg-paper);
    }
    .brand-word { font-size: 0.82rem; letter-spacing: 0.16em; }
  }
</style>
</head>
<body data-lang="zh">
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
      <a href="https://heurion.org/aegis-os/" class="brand-sub">AEGIS OS</a>
    </div>
    <nav class="nav-links" aria-label="Primary Navigation">
      <a href="https://heurion.org/" class="nav-link"><span data-zh>主站</span><span data-en>Heurion.org</span></a>
      <a href="https://heurion.org/aegis-os/" class="nav-link"><span data-zh>概览</span><span data-en>Overview</span></a>
      <a href="https://heurion.org/aegis-os/#pricing" class="nav-link"><span data-zh>方案与购买</span><span data-en>Plans &amp; Buy</span></a>
      <a id="nav-dashboard" href="dashboard" class="nav-link"><span data-zh>我的控制台</span><span data-en>My Console</span></a>
      <a href="#" class="nav-link nav-link-active"><span data-zh>远程终端 (/app)</span><span data-en>Remote (/app)</span></a>
      <a href="https://github.com/heurion-org/aegis-os" target="_blank" rel="noopener" class="nav-link">GitHub ↗</a>
    </nav>
    <div class="nav-right">
      <a id="nav-dashboard-mobile" href="dashboard" class="nav-mobile-link"><span data-zh>控制台</span><span data-en>Console</span></a>
      <span id="conn-badge" class="badge">Offline</span>
      <button type="button" class="lang-switch" id="lang-toggle">EN</button>
    </div>
  </div>
</header>

<section class="console-header">
  <div class="container">
    <p class="label-caps">AEGIS OS · ZERO-KNOWLEDGE E2EE RELAY</p>
    <h1 class="console-title">
      <span data-zh>Aegis OS — <em>跨端加密远程控制台</em></span>
      <span data-en>Aegis OS — <em>Encrypted Remote Console</em></span>
    </h1>
    <div id="dev-meta" class="dev-meta-line">Initializing WebCrypto identity...</div>
  </div>
</section>

<main>
  <section id="paired-bar" class="card paired-strip hidden">
    <div class="row" style="justify-content:space-between;">
      <span id="paired-summary" class="muted" style="color:var(--accent); font-family:var(--font-mono); font-size:0.78rem;">Paired</span>
      <button id="btn-toggle-setup" class="secondary" style="padding:0.35rem 0.75rem; font-size:0.76rem;"><span data-zh>配对与密钥设置</span><span data-en>Pair / Key Settings</span></button>
    </div>
  </section>

  <section id="setup-card" class="card">
    <div class="sec-head">
      <div class="sec-head-left">
        <span class="sec-num">01 / CONNECT &amp; PAIR</span>
        <h2><span data-zh>连接账户并配对工作站</span><span data-en>Connect &amp; Pair Device</span></h2>
      </div>
    </div>
    <p class="muted" style="margin:0 0 0.9rem;">
      <span data-zh>提示：在工作站运行 <code>aegis-os devices pair</code> 后，直接扫码或打开打印的链接即可零输入自动配对。</span>
      <span data-en>Tip: Run <code>aegis-os devices pair</code> on your workstation and scan the QR or open the printed link to pair with zero manual input.</span>
    </p>
    <label>Aegis Cloud API Key (`ak_live_...`)</label>
    <input id="api-key" type="password" placeholder="ak_live_...">
    <label>Pairing Code (`aegis-pair:...` from Workstation QR)</label>
    <input id="pair-code" type="text" placeholder="aegis-pair:...">
    <div class="row">
      <button id="btn-save-key"><span data-zh>保存密钥并加载会话</span><span data-en>Save Key &amp; Load Sessions</span></button>
      <button id="btn-pair" class="secondary"><span data-zh>认领配对码</span><span data-en>Claim Pairing Code</span></button>
    </div>
    <div id="setup-msg" class="muted" style="margin-top:0.65rem; font-family:var(--font-mono); font-size:0.76rem;"></div>
  </section>

  <section id="sessions-card" class="card">
    <div class="sec-head" style="margin-bottom:0.6rem;">
      <div class="sec-head-left">
        <span class="sec-num">02 / SHARED AGENT SESSIONS</span>
        <h2><span data-zh>共享 Agent 会话</span><span data-en>Shared Agent Sessions</span></h2>
      </div>
      <button id="btn-refresh" class="secondary"><span data-zh>刷新</span><span data-en>Refresh</span></button>
    </div>
    <div id="sessions-list" class="muted">No sessions loaded yet.</div>
  </section>

  <section id="detail-card" class="card hidden">
    <div class="sec-head">
      <div class="sec-head-left">
        <span class="sec-num">03 / LIVE E2EE SESSION</span>
        <h2 id="active-title">Session</h2>
      </div>
      <button id="btn-disconnect" class="secondary"><span data-zh>断开连接</span><span data-en>Disconnect</span></button>
    </div>
    <div class="tabs">
      <button class="tab active" data-tab="timeline"><span data-zh>时间线</span><span data-en>Timeline</span></button>
      <button class="tab secondary" data-tab="terminal"><span data-zh>终端</span><span data-en>Terminal</span></button>
      <button class="tab secondary" data-tab="diff"><span data-zh>变更 Diff</span><span data-en>Diff</span></button>
      <button class="tab secondary" data-tab="approve"><span data-zh>边界审批</span><span data-en>Approve</span></button>
    </div>

    <div id="panel-timeline" style="margin-top:0.9rem;">
      <div id="timeline-log" class="log"></div>
    </div>

    <div id="panel-terminal" class="hidden" style="margin-top:0.9rem;">
      <div class="row" style="margin-bottom:0.65rem;">
        <button class="secondary qkey" data-key="ctrl-c">Ctrl+C</button>
        <button class="secondary qkey" data-key="enter">Enter</button>
        <button class="secondary qkey" data-key="tab">Tab</button>
        <button class="secondary qkey" data-key="esc">Esc</button>
      </div>
      <div id="terminal-log" class="log"></div>
    </div>

    <div id="panel-diff" class="hidden" style="margin-top:0.9rem;">
      <div class="row" style="margin-bottom:0.65rem;">
        <button id="btn-fetch-handoff" class="secondary"><span data-zh>解密最新 Handoff</span><span data-en>Decrypt Latest Handoff</span></button>
      </div>
      <div id="diff-log" class="log"></div>
    </div>

    <div id="panel-approve" class="hidden" style="margin-top:0.9rem;">
      <div class="row">
        <input id="totp-code" type="text" inputmode="numeric" maxlength="6" placeholder="6-digit TOTP code" style="flex:1; margin:0;">
        <button id="btn-load-approvals" class="secondary"><span data-zh>重新加载</span><span data-en>Reload</span></button>
      </div>
      <div id="approvals-list" class="muted" style="margin-top:0.75rem;"></div>
    </div>
  </section>
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
        <a href="https://heurion.org/aegis-os/" class="foot-link"><span data-zh>产品概览</span><span data-en>Overview</span></a>
        <a id="foot-dash-link" href="dashboard" class="foot-link"><span data-zh>我的控制台</span><span data-en>My Console</span></a>
        <a href="https://github.com/heurion-org/aegis-os" target="_blank" rel="noopener" class="foot-link">GitHub</a>
      </div>
    </div>
  </div>
</footer>

<div id="prompt-bar" class="prompt-bar">
  <input id="prompt-input" type="text" placeholder="Send encrypted prompt or command...">
  <button id="btn-send"><span data-zh>发送</span><span data-en>Send</span></button>
  <button id="btn-sigint" class="danger">Stop</button>
</div>

<script>__AEGIS_WEBCRYPTO_JS__</script>
<script>
(function () {
  const API_BASE = location.pathname.replace(/\/app\/?$/, "");
  let currentLang = localStorage.getItem("aegis_lang") || "zh";
  function applyLang(lang) {
    currentLang = lang === "en" ? "en" : "zh";
    document.body.setAttribute("data-lang", currentLang);
    document.documentElement.lang = currentLang === "en" ? "en" : "zh-CN";
    const btn = document.getElementById("lang-toggle");
    if (btn) btn.textContent = currentLang === "en" ? "中文" : "EN";
    localStorage.setItem("aegis_lang", currentLang);
  }
  applyLang(currentLang);
  const langToggleBtn = document.getElementById("lang-toggle");
  if (langToggleBtn) {
    langToggleBtn.onclick = () => applyLang(currentLang === "zh" ? "en" : "zh");
  }
  function updateDashboardNavLinks(apiKey) {
    const suffix = apiKey ? "#key=" + encodeURIComponent(apiKey) : "";
    for (const id of ["nav-dashboard", "nav-dashboard-mobile", "foot-dash-link"]) {
      const el = document.getElementById(id);
      if (el) el.href = (API_BASE || "") + "/dashboard" + suffix;
    }
  }
  function setConnBadge(text, state) {
    const el = document.getElementById("conn-badge");
    if (!el) return;
    el.textContent = text;
    el.className = state === "ok"
      ? "badge badge-ok"
      : state === "warn"
        ? "badge badge-warn"
        : state === "err"
          ? "badge badge-err"
          : "badge";
  }
  updateDashboardNavLinks("");
  const QKEYS = { "ctrl-c": "\u0003", enter: "\n", tab: "\t", esc: "\u001b" };
  const DB_NAME = "aegis_e2ee_v1_db";
  const STORE = "state";
  let db = null;
  let localState = {
    keyPair: null,
    deviceId: "",
    fingerprint: "",
    apiKey: "",
    orgId: "",
    trustCert: null,
    trustedPeers: {},
    handoffSyncKeyB64: "",
  };
  let activeWs = null;
  let activeCipher = null;
  let activeSession = null;

  function openDb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  function dbGet(k) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const r = tx.objectStore(STORE).get(k);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }

  function dbPut(k, v) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(v, k);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async function persistProfile() {
    await dbPut("profile", {
      apiKey: localState.apiKey,
      orgId: localState.orgId,
      trustCert: localState.trustCert,
      trustedPeers: localState.trustedPeers,
      handoffSyncKeyB64: localState.handoffSyncKeyB64,
    });
  }

  function updatePairedChrome() {
    const ready = !!(localState.apiKey && localState.trustCert);
    const bar = document.getElementById("paired-bar");
    const setup = document.getElementById("setup-card");
    const sum = document.getElementById("paired-summary");
    if (ready) {
      bar.classList.remove("hidden");
      setup.classList.add("hidden");
      if (sum) sum.textContent = `Paired · org=${localState.orgId || "default"} · ${localState.deviceId}`;
    } else {
      bar.classList.add("hidden");
      setup.classList.remove("hidden");
    }
  }

  async function initIdentity() {
    db = await openDb();
    let kp = await dbGet("keyPair");
    if (!kp) {
      kp = await AegisE2ee.generateIdentityKeyPair(false);
      await dbPut("keyPair", kp);
    }
    const rawPub = await AegisE2ee.exportRawPublicKey(kp.publicKey);
    localState.keyPair = kp;
    localState.deviceId = await AegisE2ee.deviceIdFromRawPub(rawPub);
    localState.fingerprint = await AegisE2ee.fingerprintFromRawPub(rawPub);
    const prof = await dbGet("profile");
    if (prof) Object.assign(localState, prof);

    document.getElementById("dev-meta").textContent =
      `${localState.deviceId} · FP ${localState.fingerprint}`;

    const rawHash = (location.hash || "").replace(/^#/, "");
    const hashParams = new URLSearchParams(rawHash);
    const hashKey = (hashParams.get("key") || "").trim();
    const hashPair = (hashParams.get("pair") || "").trim();
    const hashSession = (hashParams.get("session") || "").trim();
    if (hashKey || hashPair || hashSession) {
      history.replaceState(null, "", location.pathname + location.search);
    }

    if (hashKey) {
      localState.apiKey = hashKey;
      await persistProfile();
    }
    if (localState.apiKey) {
      document.getElementById("api-key").value = localState.apiKey;
      updateDashboardNavLinks(localState.apiKey);
    }
    if (hashPair && hashPair.startsWith("aegis-pair:")) {
      document.getElementById("pair-code").value = hashPair;
      updatePairedChrome();
      await claimPairing();
    } else {
      updatePairedChrome();
    }

    if (localState.apiKey) {
      const sessions = await refreshSessions();
      if (localState.trustCert && sessions.length > 0 && !activeWs) {
        const target = (hashSession && sessions.find((s) => s.session_id === hashSession)) || (sessions.length === 1 ? sessions[0] : null);
        if (target) {
          await connectSession(target, "interact");
        }
      }
    }
  }

  async function apiJson(method, path, body, useAuth = true) {
    const headers = { "Content-Type": "application/json" };
    if (useAuth && localState.apiKey) {
      headers["Authorization"] = "Bearer " + localState.apiKey;
    }
    const resp = await fetch(API_BASE + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || ("HTTP " + resp.status));
    return data;
  }

  function stripAnsi(s) {
    return s.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "");
  }

  function appendLog(elId, text) {
    const el = document.getElementById(elId);
    el.textContent += text;
    if (el.textContent.length > 65536) {
      el.textContent = el.textContent.slice(-49152);
    }
    el.scrollTop = el.scrollHeight;
  }

  async function refreshSessions() {
    const listEl = document.getElementById("sessions-list");
    if (!localState.apiKey) {
      listEl.textContent = "Enter your Aegis Cloud API key above.";
      return [];
    }
    try {
      const data = await apiJson("GET", "/v1/sessions");
      const sessions = data.sessions || [];
      if (!sessions.length) {
        listEl.textContent = "No active shared sessions.";
        return [];
      }
      listEl.textContent = "";
      for (const s of sessions) {
        const row = document.createElement("div");
        row.className = "session-item";
        const info = document.createElement("div");
        const title = document.createElement("div");
        title.className = "session-title";
        title.textContent = `${s.agent_kind} · ${s.project_name} (${s.host_name})`;
        const sub = document.createElement("div");
        sub.className = "muted";
        sub.textContent = `${s.session_id} · ${s.status}`;
        info.appendChild(title);
        info.appendChild(sub);

        const btns = document.createElement("div");
        btns.className = "row";
        const bInt = document.createElement("button");
        bInt.textContent = "Attach";
        bInt.onclick = () => connectSession(s, "interact");
        const bObs = document.createElement("button");
        bObs.className = "secondary";
        bObs.textContent = "Observe";
        bObs.onclick = () => connectSession(s, "observe");
        btns.appendChild(bInt);
        btns.appendChild(bObs);

        row.appendChild(info);
        row.appendChild(btns);
        listEl.appendChild(row);
      }
      return sessions;
    } catch (err) {
      listEl.textContent = "Error: " + err.message;
      return [];
    }
  }

  async function claimPairing() {
    const raw = document.getElementById("pair-code").value.trim();
    const msg = document.getElementById("setup-msg");
    if (!raw.startsWith("aegis-pair:")) {
      msg.textContent = "Enter a valid aegis-pair:... code";
      return;
    }
    try {
      const payload = JSON.parse(AegisE2ee.decoder.decode(AegisE2ee.b64UrlDecode(raw.slice(11))));
      const rawPub = await AegisE2ee.exportRawPublicKey(localState.keyPair.publicKey);
      const claimResp = await apiJson("POST", "/v1/devices/pair/claim", {
        pair_id: payload.pair_id,
        pair_nonce: payload.pair_nonce,
        name: "mobile-pwa",
        platform: "web",
        pubkey_sec1_b64: AegisE2ee.b64Encode(rawPub),
      }, false);

      const hostRaw = AegisE2ee.b64Decode(claimResp.pairing.host_pubkey_sec1_b64);
      const hostId = await AegisE2ee.deviceIdFromRawPub(hostRaw);
      const hostFp = await AegisE2ee.fingerprintFromRawPub(hostRaw);
      if (hostId !== payload.host_device_id || hostFp !== payload.host_fp) {
        throw new Error("PAIR_MITM_DETECTED: host fingerprint mismatch");
      }
      localState.orgId = payload.org_id;
      localState.trustedPeers[hostId] = claimResp.pairing.host_pubkey_sec1_b64;
      if (payload.handoff_sync_key_b64) {
        localState.handoffSyncKeyB64 = payload.handoff_sync_key_b64;
      }
      await persistProfile();
      msg.textContent = "Claimed pairing! Waiting for trust_cert approval if API key is set...";
      if (localState.apiKey) {
        for (let i = 0; i < 15; i++) {
          const devs = await apiJson("GET", "/v1/devices");
          const me = (devs.devices || []).find((d) => d.device_id === localState.deviceId);
          if (me && me.trust_cert) {
            localState.trustCert = me.trust_cert;
            await persistProfile();
            msg.textContent = "Paired & DeviceTrustCert cached!";
            updatePairedChrome();
            break;
          }
          await new Promise((r) => setTimeout(r, 1000));
        }
      }
    } catch (err) {
      msg.textContent = "Pairing error: " + err.message;
    }
  }

  async function connectSession(sess, mode) {
    if (activeWs) activeWs.close();
    activeSession = sess;
    activeCipher = null;
    document.getElementById("detail-card").classList.remove("hidden");
    document.getElementById("active-title").textContent = `${sess.agent_kind} · ${sess.project_name} (${mode})`;
    document.getElementById("timeline-log").textContent = "";
    document.getElementById("terminal-log").textContent = "";
    document.getElementById("diff-log").textContent = "";

    const hostPubB64 = localState.trustedPeers[sess.host_device_id];
    if (!hostPubB64 || !localState.trustCert) {
      appendLog("timeline-log", "Pair this browser with the workstation first.\n");
      return;
    }
    const orgId = localState.orgId || sess.org_id;
    const tk = await apiJson("POST", "/v1/relay/tickets", {
      org_id: orgId,
      session_id: sess.session_id,
      device_id: localState.deviceId,
      role: "client",
      mode,
    });
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${location.host}${API_BASE}${tk.ws_path}`);
    activeWs = ws;
    setConnBadge("Handshaking...", "warn");

    const hs = await AegisE2ee.initiateHandshake({
      clientKeyPair: localState.keyPair,
      trustCert: localState.trustCert,
      orgId,
      sessionId: sess.session_id,
      hostDeviceId: sess.host_device_id,
      requestedMode: mode,
    });
    const sendClientHello = () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          envelope: "handshake",
          handshake: "client_hello",
          ...hs.init,
        }));
      }
    };

    ws.onopen = sendClientHello;

    ws.onmessage = async (ev) => {
      const env = JSON.parse(ev.data);
      if (env.envelope === "handshake" && env.handshake === "server_hello") {
        activeCipher = await AegisE2ee.completeHandshake({
          state: hs.state,
          accept: env,
          hostRawPub: AegisE2ee.b64Decode(hostPubB64),
          orgId,
        });
        setConnBadge("E2EE Active", "ok");
        document.getElementById("prompt-bar").style.display = mode === "interact" ? "flex" : "none";
      } else if (env.envelope === "encrypted" && activeCipher) {
        const pt = await activeCipher.decryptFrame(env);
        const payload = JSON.parse(AegisE2ee.decoder.decode(pt));
        if (payload.type === "pty_replay" || payload.type === "pty_out") {
          const text = stripAnsi(AegisE2ee.decoder.decode(AegisE2ee.b64Decode(payload.data_b64)));
          appendLog("terminal-log", text);
          appendLog("timeline-log", text);
        } else if (payload.type === "sideband_diff") {
          document.getElementById("diff-log").textContent = payload.unified_diff || "(no diff)";
        } else if (payload.type === "sideband_event") {
          appendLog("timeline-log", `[${payload.kind}] ${payload.summary}\n`);
        }
      } else if (env.envelope === "control") {
        appendLog("timeline-log", `[relay:${env.control}]\n`);
        if (env.control === "peer_joined" && env.role === "host" && !activeCipher) {
          sendClientHello();
        }
      }
    };
    ws.onclose = () => {
      setConnBadge("Disconnected", "err");
      document.getElementById("prompt-bar").style.display = "none";
    };
  }

  async function sendEncryptedInput(text) {
    if (!activeWs || !activeCipher) return;
    const payload = AegisE2ee.utf8(JSON.stringify({
      type: "pty_in",
      data_b64: AegisE2ee.b64Encode(AegisE2ee.utf8(text)),
    }));
    const frame = await activeCipher.encryptFrame("pty_in", payload);
    activeWs.send(JSON.stringify({ envelope: "encrypted", ...frame }));
  }

  const toggleBtn = document.getElementById("btn-toggle-setup");
  if (toggleBtn) {
    toggleBtn.onclick = () => {
      document.getElementById("setup-card").classList.toggle("hidden");
    };
  }
  document.getElementById("btn-save-key").onclick = async () => {
    localState.apiKey = document.getElementById("api-key").value.trim();
    updateDashboardNavLinks(localState.apiKey);
    await persistProfile();
    updatePairedChrome();
    await refreshSessions();
  };
  document.getElementById("btn-pair").onclick = async () => {
    await claimPairing();
    if (localState.apiKey) await refreshSessions();
  };
  document.getElementById("btn-refresh").onclick = refreshSessions;
  document.getElementById("btn-disconnect").onclick = () => {
    if (activeWs) activeWs.close();
    document.getElementById("detail-card").classList.add("hidden");
  };
  document.getElementById("btn-send").onclick = async () => {
    const inp = document.getElementById("prompt-input");
    if (!inp.value) return;
    await sendEncryptedInput(inp.value + "\n");
    inp.value = "";
  };
  document.getElementById("prompt-input").onkeydown = async (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey) {
      ev.preventDefault();
      document.getElementById("btn-send").click();
    }
  };
  document.getElementById("btn-sigint").onclick = async () => {
    if (!activeWs || !activeCipher) return;
    const payload = AegisE2ee.utf8(JSON.stringify({ type: "pty_signal", signal: "SIGINT" }));
    const frame = await activeCipher.encryptFrame("pty_signal", payload);
    activeWs.send(JSON.stringify({ envelope: "encrypted", ...frame }));
  };
  for (const b of document.querySelectorAll(".qkey")) {
    b.onclick = () => {
      const seq = QKEYS[b.getAttribute("data-key")];
      if (seq) sendEncryptedInput(seq);
    };
  }
  for (const t of document.querySelectorAll(".tab")) {
    t.onclick = () => {
      for (const x of document.querySelectorAll(".tab")) {
        x.classList.remove("active");
        x.classList.add("secondary");
      }
      t.classList.add("active");
      t.classList.remove("secondary");
      for (const p of ["timeline", "terminal", "diff", "approve"]) {
        document.getElementById("panel-" + p).classList.toggle("hidden", p !== t.getAttribute("data-tab"));
      }
    };
  }
  document.getElementById("btn-fetch-handoff").onclick = async () => {
    if (!activeSession || !localState.handoffSyncKeyB64) return;
    const el = document.getElementById("diff-log");
    try {
      const resp = await apiJson("GET", `/v1/sessions/${activeSession.session_id}/handoff`);
      const h = resp.handoff;
      const gz = await AegisE2ee.decryptHandoffCore({
        syncKeyB64: localState.handoffSyncKeyB64,
        orgId: h.org_id,
        sessionId: h.session_id,
        handoffId: h.handoff_id,
        nonceB64: h.core_nonce_b64,
        ctB64: h.encrypted_core_b64,
      });
      const ds = new DecompressionStream("gzip");
      const rawBuf = await new Response(new Blob([gz]).stream().pipeThrough(ds)).arrayBuffer();
      const core = JSON.parse(AegisE2ee.decoder.decode(new Uint8Array(rawBuf)));
      el.textContent = core.context_md || "";
    } catch (err) {
      el.textContent = "Handoff decrypt error: " + err.message;
    }
  };
  document.getElementById("btn-load-approvals").onclick = async () => {
    const box = document.getElementById("approvals-list");
    try {
      const orgId = localState.orgId || (activeSession && activeSession.org_id) || "";
      const st = await apiJson("GET", "/v1/status?org_id=" + encodeURIComponent(orgId));
      const pending = st.pending_escalations || [];
      box.textContent = "";
      if (!pending.length) {
        box.textContent = "No pending approvals.";
        return;
      }
      for (const esc of pending) {
        const row = document.createElement("div");
        row.className = "session-item";
        const txt = document.createElement("div");
        txt.textContent = `${esc.escalation_id} · ${esc.action || esc.reason || "boundary escalation"}`;
        const bOk = document.createElement("button");
        bOk.textContent = "Approve";
        bOk.onclick = async () => {
          const code = document.getElementById("totp-code").value.trim();
          await apiJson("POST", "/v1/approvals/decide", {
            org_id: orgId,
            escalation_id: esc.escalation_id,
            decision: "approve",
            code,
          });
          document.getElementById("btn-load-approvals").click();
        };
        row.appendChild(txt);
        row.appendChild(bOk);
        box.appendChild(row);
      }
    } catch (err) {
      box.textContent = "Error: " + err.message;
    }
  };

  initIdentity().catch((e) => {
    document.getElementById("dev-meta").textContent = "WebCrypto error: " + e.message;
  });
})();
</script>
</body>
</html>"##;

pub fn render_mobile_app_html() -> String {
    MOBILE_APP_HTML_TEMPLATE.replace("__AEGIS_WEBCRYPTO_JS__", WEBCRYPTO_E2EE_JS)
}
