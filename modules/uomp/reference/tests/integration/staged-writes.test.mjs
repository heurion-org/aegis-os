import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AuthService } from '../../packages/auth/dist/index.js';
import { MemoryGuard } from '../../packages/guard/dist/index.js';
import { MemoryStore } from '../../packages/store/dist/index.js';
import { JWTTokenIssuer } from '../../packages/token/dist/index.js';

const ADMIN_TOKEN = 'test-admin-token-staged-writes';

function emptyScope() {
  return { tags: [], keys: [], denyTags: [], denyKeys: [] };
}

function writeScopes(tags = []) {
  return {
    read: emptyScope(),
    write: { tags, keys: [], denyTags: [], denyKeys: [] },
  };
}

async function createHarness(t) {
  const tempDir = mkdtempSync(join(tmpdir(), 'uomp-staged-writes-'));
  const issuer = new JWTTokenIssuer();
  await issuer.loadOrGenerateKey(join(tempDir, 'secrets'));

  const auth = new AuthService({
    dbPath: join(tempDir, 'auth.db'),
    issuer,
    adminToken: ADMIN_TOKEN,
  });
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

  return { auth, guard, store };
}

function adminHeaders() {
  return { 'content-type': 'application/json', 'x-uomp-admin-token': ADMIN_TOKEN };
}

async function grantWriteToken(auth, tags) {
  const scopes = writeScopes(tags);
  const session = auth.createSession({
    agent_id: 'writer-agent',
    agent_name: 'Writer Agent',
    requested_scopes: scopes,
    duration_minutes: 30,
  });
  const grant = await auth.grantSession(session.sessionId, scopes);
  assert.ok(grant);
  return grant.token;
}

test('agent writes are staged and only applied after approval', async t => {
  const { auth, guard, store } = await createHarness(t);
  const token = await grantWriteToken(auth, ['notes/projects']);

  const staged = await guard.getApp().fetch(new Request('http://localhost/v1/memory/note.projects.new', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({
      value: { title: 'New note', body: 'Draft' },
      tags: ['notes/projects'],
      sensitivity: 'low',
    }),
  }));
  assert.equal(staged.status, 202);
  const stagedBody = await staged.json();
  assert.equal(stagedBody.status, 'pending');
  assert.equal(store.get('note.projects.new'), null);

  const list = await guard.getApp().fetch(new Request('http://localhost/v1/staged-writes', {
    headers: adminHeaders(),
  }));
  assert.equal(list.status, 200);
  const listBody = await list.json();
  assert.equal(listBody.staged_writes.length, 1);
  assert.equal(listBody.staged_writes[0].id, stagedBody.staged_write_id);

  const approved = await guard.getApp().fetch(new Request(
    `http://localhost/v1/staged-writes/${stagedBody.staged_write_id}/approve`,
    { method: 'POST', headers: adminHeaders(), body: JSON.stringify({ reviewed_by: 'tester' }) },
  ));
  assert.equal(approved.status, 200);
  const item = store.get('note.projects.new');
  assert.equal(item?.source, 'agent');
  assert.deepEqual(item?.value, { title: 'New note', body: 'Draft' });
});

test('high-sensitivity and out-of-scope writes are rejected before staging', async t => {
  const { auth, guard } = await createHarness(t);
  const token = await grantWriteToken(auth, ['notes/projects']);

  const high = await guard.getApp().fetch(new Request('http://localhost/v1/memory/note.projects.secret', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ value: 'secret', tags: ['notes/projects'], sensitivity: 'high' }),
  }));
  assert.equal(high.status, 403);

  const outside = await guard.getApp().fetch(new Request('http://localhost/v1/memory/note.journal.new', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ value: 'journal', tags: ['notes/journal'], sensitivity: 'low' }),
  }));
  assert.equal(outside.status, 403);
});

test('denying a staged write leaves the store unchanged', async t => {
  const { auth, guard, store } = await createHarness(t);
  const token = await grantWriteToken(auth, ['notes/projects']);

  const staged = await guard.getApp().fetch(new Request('http://localhost/v1/memory/note.projects.denied', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ value: 'nope', tags: ['notes/projects'], sensitivity: 'low' }),
  }));
  assert.equal(staged.status, 202);
  const { staged_write_id } = await staged.json();

  const denied = await guard.getApp().fetch(new Request(
    `http://localhost/v1/staged-writes/${staged_write_id}/deny`,
    { method: 'POST', headers: adminHeaders(), body: JSON.stringify({ reviewed_by: 'tester' }) },
  ));
  assert.equal(denied.status, 200);
  assert.equal(store.get('note.projects.denied'), null);
});
