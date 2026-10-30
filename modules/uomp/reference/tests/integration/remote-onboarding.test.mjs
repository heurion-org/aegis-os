import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AuthService } from '../../packages/auth/dist/index.js';
import { JWTTokenIssuer } from '../../packages/token/dist/index.js';

const ADMIN_TOKEN = 'test-admin-token-remote-onboarding';
const AUDIENCE = 'https://memory.example.com';

function scopes() {
  return {
    read: { tags: ['notes/projects'], keys: [], denyTags: [], denyKeys: [] },
    write: { tags: [], keys: [], denyTags: [], denyKeys: [] },
  };
}

async function createHarness(t) {
  const tempDir = mkdtempSync(join(tmpdir(), 'uomp-remote-onboarding-'));
  const issuer = new JWTTokenIssuer();
  await issuer.loadOrGenerateKey(join(tempDir, 'secrets'));
  const auth = new AuthService({
    dbPath: join(tempDir, 'auth.db'),
    issuer,
    adminToken: ADMIN_TOKEN,
  });
  t.after(() => {
    auth.close();
    rmSync(tempDir, { recursive: true, force: true });
  });
  return { auth, issuer };
}

function adminHeaders() {
  return { 'content-type': 'application/json', 'x-uomp-admin-token': ADMIN_TOKEN };
}

test('remote agent requests access, user approves, agent polls a remote token once', async t => {
  const { auth, issuer } = await createHarness(t);

  const created = await auth.getApp().fetch(new Request('http://localhost/v1/remote/requests', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      agent_id: 'remote-agent',
      agent_name: 'Remote Agent',
      requested_scopes: scopes(),
      duration_minutes: 5,
      audience: AUDIENCE,
    }),
  }));
  assert.equal(created.status, 201);
  const request = await created.json();
  assert.ok(request.request_id);
  assert.ok(request.poll_secret);

  const pending = await auth.getApp().fetch(new Request(
    `http://localhost/v1/remote/requests/${request.request_id}?secret=${request.poll_secret}`,
  ));
  assert.equal(pending.status, 200);
  assert.equal((await pending.json()).status, 'pending');

  const approved = await auth.getApp().fetch(new Request(
    `http://localhost/v1/consent/requests/${request.request_id}/approve`,
    {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ granted_scopes: scopes() }),
    },
  ));
  assert.equal(approved.status, 200);

  const polled = await auth.getApp().fetch(new Request(
    `http://localhost/v1/remote/requests/${request.request_id}?secret=${request.poll_secret}`,
  ));
  assert.equal(polled.status, 200);
  const tokenResponse = await polled.json();
  assert.equal(tokenResponse.status, 'approved');
  assert.ok(tokenResponse.token);

  const payload = await issuer.verify(tokenResponse.token);
  assert.equal(payload.profile, 'remote');
  assert.equal(payload.audience, AUDIENCE);
  assert.ok(payload.sessionId);

  const secondPoll = await auth.getApp().fetch(new Request(
    `http://localhost/v1/remote/requests/${request.request_id}?secret=${request.poll_secret}`,
  ));
  const delivered = await secondPoll.json();
  assert.equal(delivered.delivered, true);
  assert.equal(delivered.token, undefined);

  const wrongSecret = await auth.getApp().fetch(new Request(
    `http://localhost/v1/remote/requests/${request.request_id}?secret=wrong`,
  ));
  assert.equal(wrongSecret.status, 404);
});

test('remote request denial is visible to the polling agent', async t => {
  const { auth } = await createHarness(t);
  const created = await auth.getApp().fetch(new Request('http://localhost/v1/remote/requests', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      agent_id: 'remote-agent',
      requested_scopes: scopes(),
      duration_minutes: 5,
      audience: AUDIENCE,
    }),
  }));
  const request = await created.json();

  const denied = await auth.getApp().fetch(new Request(
    `http://localhost/v1/consent/requests/${request.request_id}/deny`,
    { method: 'POST', headers: adminHeaders() },
  ));
  assert.equal(denied.status, 200);

  const polled = await auth.getApp().fetch(new Request(
    `http://localhost/v1/remote/requests/${request.request_id}?secret=${request.poll_secret}`,
  ));
  const body = await polled.json();
  assert.equal(body.status, 'denied');
});
