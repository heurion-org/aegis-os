import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AuthService } from '../../packages/auth/dist/index.js';
import { MemoryGuard } from '../../packages/guard/dist/index.js';
import { MemoryStore } from '../../packages/store/dist/index.js';
import { JWTTokenIssuer } from '../../packages/token/dist/index.js';

const ADMIN_TOKEN = 'test-admin-token-payload';

function scopes() {
  return {
    read: { tags: ['notes/projects'], keys: [], denyTags: [], denyKeys: [] },
    write: { tags: [], keys: [], denyTags: [], denyKeys: [] },
  };
}

async function createHarness(t) {
  const tempDir = mkdtempSync(join(tmpdir(), 'uomp-payload-'));
  const issuer = new JWTTokenIssuer();
  await issuer.loadOrGenerateKey(join(tempDir, 'secrets'));
  const auth = new AuthService({ dbPath: join(tempDir, 'auth.db'), issuer, adminToken: ADMIN_TOKEN });
  const store = new MemoryStore({ dbPath: join(tempDir, 'memory.db') });
  const guard = new MemoryGuard({
    dbPath: join(tempDir, 'audit.db'),
    memoryDbPath: join(tempDir, 'memory.db'),
    issuer,
    sessionStateProvider: auth,
    adminToken: ADMIN_TOKEN,
  });
  t.after(() => {
    guard.close();
    store.close();
    auth.close();
    rmSync(tempDir, { recursive: true, force: true });
  });
  return { auth, guard };
}

async function grant(auth) {
  const session = auth.createSession({
    agent_id: 'remote-agent',
    agent_name: 'Remote Agent',
    requested_scopes: scopes(),
    duration_minutes: 30,
  });
  const result = await auth.grantSession(session.sessionId, scopes());
  assert.ok(result);
  return { token: result.token, sessionId: session.sessionId };
}

function adminHeaders() {
  return { 'content-type': 'application/json', 'x-uomp-admin-token': ADMIN_TOKEN };
}

test('encrypted payloads are stored and only readable by their session', async t => {
  const { auth, guard } = await createHarness(t);
  const first = await grant(auth);
  const second = await grant(auth);

  const upload = await guard.getApp().fetch(new Request('http://localhost/v1/payload', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${first.token}` },
    body: JSON.stringify({
      encryption: { algorithm: 'ECDH-X25519-AES256GCM', sender_public_key: 'pk', nonce: 'n' },
      ciphertext: 'base64ciphertext',
      format: 'text/markdown',
      size: 2048,
      hash: 'sha256:abc',
    }),
  }));
  assert.equal(upload.status, 201);
  const { payload_id } = await upload.json();

  const read = await guard.getApp().fetch(new Request(`http://localhost/v1/payload/${payload_id}`, {
    headers: { authorization: `Bearer ${first.token}` },
  }));
  assert.equal(read.status, 200);
  const envelope = await read.json();
  assert.equal(envelope.payload_id, payload_id);
  assert.equal(envelope.ciphertext, 'base64ciphertext');
  assert.equal(envelope.session_id, first.sessionId);

  const foreign = await guard.getApp().fetch(new Request(`http://localhost/v1/payload/${payload_id}`, {
    headers: { authorization: `Bearer ${second.token}` },
  }));
  assert.equal(foreign.status, 403);

  const list = await guard.getApp().fetch(new Request('http://localhost/v1/payload', {
    headers: adminHeaders(),
  }));
  assert.equal(list.status, 200);
  const listed = await list.json();
  assert.equal(listed.payloads.length, 1);
  assert.equal(listed.payloads[0].payload_id, payload_id);
  assert.equal(listed.payloads[0].ciphertext, undefined);
});

test('payload upload requires ciphertext and matching session metadata', async t => {
  const { auth, guard } = await createHarness(t);
  const { token, sessionId } = await grant(auth);

  const missing = await guard.getApp().fetch(new Request('http://localhost/v1/payload', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ encryption: { algorithm: 'x' } }),
  }));
  assert.equal(missing.status, 400);

  const mismatch = await guard.getApp().fetch(new Request('http://localhost/v1/payload', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({
      session_id: 'sess_other',
      agent_id: 'remote-agent',
      encryption: { algorithm: 'x' },
      ciphertext: 'c',
    }),
  }));
  assert.equal(mismatch.status, 403);
  assert.ok(sessionId);
});
