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
  "background_color": "#0b0f17",
  "theme_color": "#0b0f17",
  "description": "Zero-Knowledge E2EE cross-device console for any AI Agent running on Aegis OS."
}"##;

pub const MOBILE_APP_HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0b0f17">
<link rel="manifest" href="app/manifest.json">
<title>Aegis OS · Any Agent, Any Device</title>
<style>
  :root {
    color-scheme: dark;
    --bg: #0b0f17;
    --card: #131a26;
    --border: #232f45;
    --text: #e6edf7;
    --muted: #8b9bb4;
    --accent: #38bdf8;
    --ok: #34d399;
    --warn: #fbbf24;
    --danger: #f87171;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text); padding-bottom: 84px;
  }
  header {
    position: sticky; top: 0; z-index: 10; background: rgba(11,15,23,0.92);
    backdrop-filter: blur(8px); border-bottom: 1px solid var(--border);
    padding: 12px 16px; display: flex; align-items: center; justify-content: space-between;
  }
  .brand { font-weight: 700; font-size: 15px; letter-spacing: 0.3px; }
  .badge { font-size: 11px; padding: 3px 8px; border-radius: 999px; background: #1e293b; color: var(--accent); }
  main { max-width: 760px; margin: 0 auto; padding: 14px; display: grid; gap: 12px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px; }
  h2 { margin: 0 0 10px; font-size: 15px; }
  label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 4px; }
  input, textarea {
    width: 100%; background: #0b0f17; color: var(--text); border: 1px solid var(--border);
    border-radius: 8px; padding: 10px; font-size: 14px; margin-bottom: 10px;
  }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  button {
    border: 0; border-radius: 8px; padding: 10px 14px; font-size: 13px; font-weight: 600;
    cursor: pointer; background: var(--accent); color: #05131f;
  }
  button.secondary { background: #1e293b; color: var(--text); border: 1px solid var(--border); }
  button.danger { background: var(--danger); color: #190505; }
  .tabs { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; }
  .tab.active { background: var(--accent); color: #05131f; }
  .log {
    background: #070a10; border: 1px solid var(--border); border-radius: 8px;
    padding: 10px; min-height: 220px; max-height: 52vh; overflow-y: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
    white-space: pre-wrap; word-break: break-word;
  }
  .prompt-bar {
    position: fixed; bottom: 0; left: 0; right: 0; background: #0f1521;
    border-top: 1px solid var(--border); padding: 10px 12px; display: none; gap: 8px;
  }
  .prompt-bar input { margin: 0; flex: 1; }
  .muted { color: var(--muted); font-size: 12px; }
  .session-item {
    display: flex; justify-content: space-between; align-items: center; gap: 8px;
    padding: 10px 0; border-top: 1px solid var(--border);
  }
  .hidden { display: none !important; }
</style>
</head>
<body>
<header>
  <div>
    <div class="brand">AEGIS OS · ZERO-KNOWLEDGE RELAY</div>
    <div id="dev-meta" class="muted">Initializing WebCrypto identity...</div>
  </div>
  <span id="conn-badge" class="badge">Offline</span>
</header>

<main>
  <section id="setup-card" class="card">
    <h2>1. Connect & Pair Device</h2>
    <label>Aegis Cloud API Key (`ak_live_...`)</label>
    <input id="api-key" type="password" placeholder="ak_live_...">
    <label>Pairing Code (`aegis-pair:...` from Workstation QR)</label>
    <input id="pair-code" type="text" placeholder="aegis-pair:...">
    <div class="row">
      <button id="btn-save-key">Save Key & Load Sessions</button>
      <button id="btn-pair" class="secondary">Claim Pairing Code</button>
    </div>
    <div id="setup-msg" class="muted" style="margin-top:8px;"></div>
  </section>

  <section id="sessions-card" class="card">
    <div class="row" style="justify-content:space-between;">
      <h2 style="margin:0;">2. Shared Agent Sessions</h2>
      <button id="btn-refresh" class="secondary">Refresh</button>
    </div>
    <div id="sessions-list" class="muted" style="margin-top:8px;">No sessions loaded yet.</div>
  </section>

  <section id="detail-card" class="card hidden">
    <div class="row" style="justify-content:space-between; margin-bottom:10px;">
      <strong id="active-title">Session</strong>
      <button id="btn-disconnect" class="secondary">Disconnect</button>
    </div>
    <div class="tabs">
      <button class="tab active" data-tab="timeline">Timeline</button>
      <button class="tab secondary" data-tab="terminal">Terminal</button>
      <button class="tab secondary" data-tab="diff">Diff</button>
      <button class="tab secondary" data-tab="approve">Approve</button>
    </div>

    <div id="panel-timeline" style="margin-top:10px;">
      <div id="timeline-log" class="log"></div>
    </div>

    <div id="panel-terminal" class="hidden" style="margin-top:10px;">
      <div class="row" style="margin-bottom:8px;">
        <button class="secondary qkey" data-key="ctrl-c">Ctrl+C</button>
        <button class="secondary qkey" data-key="enter">Enter</button>
        <button class="secondary qkey" data-key="tab">Tab</button>
        <button class="secondary qkey" data-key="esc">Esc</button>
      </div>
      <div id="terminal-log" class="log"></div>
    </div>

    <div id="panel-diff" class="hidden" style="margin-top:10px;">
      <div class="row" style="margin-bottom:8px;">
        <button id="btn-fetch-handoff" class="secondary">Decrypt Latest Handoff</button>
      </div>
      <div id="diff-log" class="log"></div>
    </div>

    <div id="panel-approve" class="hidden" style="margin-top:10px;">
      <div class="row">
        <input id="totp-code" type="text" inputmode="numeric" maxlength="6" placeholder="6-digit TOTP code" style="flex:1;">
        <button id="btn-load-approvals" class="secondary">Reload</button>
      </div>
      <div id="approvals-list" class="muted"></div>
    </div>
  </section>
</main>

<div id="prompt-bar" class="prompt-bar">
  <input id="prompt-input" type="text" placeholder="Send encrypted prompt or command...">
  <button id="btn-send">Send</button>
  <button id="btn-sigint" class="danger">Stop</button>
</div>

<script>__AEGIS_WEBCRYPTO_JS__</script>
<script>
(function () {
  const API_BASE = location.pathname.replace(/\/app\/?$/, "");
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
    if (localState.apiKey) {
      document.getElementById("api-key").value = localState.apiKey;
      await refreshSessions();
    }
    const hash = location.hash || "";
    const m = hash.match(/pair=(aegis-pair:[^&]+)/);
    if (m) document.getElementById("pair-code").value = decodeURIComponent(m[1]);
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
      return;
    }
    try {
      const data = await apiJson("GET", "/v1/sessions");
      const sessions = data.sessions || [];
      if (!sessions.length) {
        listEl.textContent = "No active shared sessions.";
        return;
      }
      listEl.textContent = "";
      for (const s of sessions) {
        const row = document.createElement("div");
        row.className = "session-item";
        const info = document.createElement("div");
        const title = document.createElement("div");
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
    } catch (err) {
      listEl.textContent = "Error: " + err.message;
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
    document.getElementById("conn-badge").textContent = "Handshaking...";

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
        document.getElementById("conn-badge").textContent = "E2EE Active";
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
      document.getElementById("conn-badge").textContent = "Disconnected";
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

  document.getElementById("btn-save-key").onclick = async () => {
    localState.apiKey = document.getElementById("api-key").value.trim();
    await persistProfile();
    await refreshSessions();
  };
  document.getElementById("btn-pair").onclick = claimPairing;
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
