import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AuthService, loadOrCreateAdminToken } from '../../packages/auth/dist/index.js';
import { MemoryGuard } from '../../packages/guard/dist/index.js';
import { MemoryStore } from '../../packages/store/dist/index.js';
import { JWTTokenIssuer } from '../../packages/token/dist/index.js';
import { buildReadScope } from '../../packages/core/dist/index.js';

const ADMIN_TOKEN = 'test-admin-token-0123456789abcdef';

function emptyScope() {
  return { tags: [], keys: [], denyTags: [], denyKeys: [] };
}

function scopesForTags(tags) {
  return {
    read: { tags, keys: [], denyTags: [], denyKeys: [] },
    write: emptyScope(),
  };
}

async function createHarness(t) {
  const tempDir = mkdtempSync(join(tmpdir(), 'uomp-auth-integrity-'));
  const secretsDir = join(tempDir, 'secrets');
  const issuer = new JWTTokenIssuer();
  await issuer.loadOrGenerateKey(secretsDir);

  const auth = new AuthService({
    dbPath: join(tempDir, 'auth.db'),
    issuer,
    adminToken: ADMIN_TOKEN,
  });
  const guard = new MemoryGuard({
    dbPath: join(tempDir, 'audit.db'),
    memoryDbPath: join(tempDir, 'memory.db'),
    issuer,
    sessionStateProvider: auth,
  });
  const store = new MemoryStore({ dbPath: join(tempDir, 'memory.db') });

  t.after(() => {
    guard.close();
    store.close();
    auth.close();
    rmSync(tempDir, { recursive: true, force: true });
  });

  return { auth, guard, store, issuer, tempDir };
}

function readMemory(guard, token, key = 'portfolio.holdings') {
  return guard.getApp().fetch(new Request(`http://localhost/v1/memory/${key}`, {
    headers: { authorization: `Bearer ${token}` },
  }));
}

function createSession(auth, requestedTags) {
  return auth.createSession({
    agent_id: 'agent_integrity_test',
    agent_name: 'Integrity Test Agent',
    requested_scopes: scopesForTags(requestedTags),
    duration_minutes: 30,
  });
}

function adminRequestHeaders() {
  return {
    'content-type': 'application/json',
    'x-uomp-admin-token': ADMIN_TOKEN,
  };
}

function createSessionViaHttp(auth, requestedScopes) {
  return auth.getApp().fetch(new Request('http://localhost/v1/sessions', {
    method: 'POST',
    headers: adminRequestHeaders(),
    body: JSON.stringify({
      agent_id: 'agent_integrity_test',
      agent_name: 'Integrity Test Agent',
      requested_scopes: requestedScopes,
    }),
  }));
}

function grantViaHttp(auth, sessionId, body) {
  return auth.getApp().fetch(new Request(`http://localhost/v1/sessions/${sessionId}/grant`, {
    method: 'POST',
    headers: adminRequestHeaders(),
    body: JSON.stringify(body),
  }));
}

test('revoke immediately invalidates the token at the guard', async t => {
  const { auth, guard, store } = await createHarness(t);

  store.set({
    key: 'portfolio.holdings',
    value: { cost_basis: 100 },
    tags: ['portfolio'],
    sensitivity: 'low',
    source: 'user',
  });

  const session = createSession(auth, ['portfolio']);
  const grant = await auth.grantSession(session.sessionId, scopesForTags(['portfolio']));
  assert.ok(grant, 'expected a token to be issued');

  const before = await readMemory(guard, grant.token);
  assert.equal(before.status, 200);

  assert.ok(auth.revokeSession(session.sessionId));

  const after = await readMemory(guard, grant.token);
  assert.equal(after.status, 403);
  const body = await after.json();
  assert.equal(body.error.code, 'SESSION_NOT_ACTIVE');

  const validateResponse = await auth.getApp().fetch(new Request('http://localhost/v1/tokens/validate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: grant.token }),
  }));
  assert.equal(validateResponse.status, 200);
  assert.equal((await validateResponse.json()).valid, false);
});

test('a validly signed token for an ungranted session is rejected', async t => {
  const { auth, guard, issuer } = await createHarness(t);

  const session = createSession(auth, ['portfolio']);
  const token = await issuer.issue({
    version: '1.0',
    sessionId: session.sessionId,
    agentId: session.agentId,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    scopes: scopesForTags(['portfolio']),
    profile: 'local',
  });

  const response = await readMemory(guard, token);
  assert.equal(response.status, 403);
  const body = await response.json();
  assert.equal(body.error.code, 'SESSION_NOT_ACTIVE');
});

test('the guard fails closed when no session state provider is configured', async t => {
  const { auth, issuer, tempDir } = await createHarness(t);

  const session = createSession(auth, ['portfolio']);
  const token = await issuer.issue({
    version: '1.0',
    sessionId: session.sessionId,
    agentId: session.agentId,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    scopes: scopesForTags(['portfolio']),
    profile: 'local',
  });

  const bareGuard = new MemoryGuard({
    dbPath: join(tempDir, 'audit-bare.db'),
    memoryDbPath: join(tempDir, 'memory-bare.db'),
    issuer,
  });
  t.after(() => bareGuard.close());

  const response = await readMemory(bareGuard, token);
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.equal(body.error.code, 'SESSION_VALIDATION_UNAVAILABLE');
});

test('creating a session without the admin token is rejected', async t => {
  const { auth } = await createHarness(t);

  const response = await auth.getApp().fetch(new Request('http://localhost/v1/sessions', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      agent_id: 'agent_integrity_test',
      requested_scopes: scopesForTags(['portfolio']),
    }),
  }));

  assert.equal(response.status, 401);
  const body = await response.json();
  assert.equal(body.error.code, 'UNAUTHORIZED');
});

test('grant cannot exceed the requested scopes', async t => {
  const { auth } = await createHarness(t);
  const adminHeaders = {
    'content-type': 'application/json',
    'x-uomp-admin-token': ADMIN_TOKEN,
  };

  const createResponse = await auth.getApp().fetch(new Request('http://localhost/v1/sessions', {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({
      agent_id: 'agent_integrity_test',
      requested_scopes: scopesForTags(['portfolio']),
    }),
  }));
  assert.equal(createResponse.status, 200);
  const { session_id: sessionId } = await createResponse.json();

  const excessive = await auth.getApp().fetch(new Request(`http://localhost/v1/sessions/${sessionId}/grant`, {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({ granted_scopes: scopesForTags(['portfolio', 'secrets']) }),
  }));
  assert.equal(excessive.status, 400);
  assert.equal((await excessive.json()).error.code, 'SCOPE_EXCEEDS_REQUEST');

  const allowed = await auth.getApp().fetch(new Request(`http://localhost/v1/sessions/${sessionId}/grant`, {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({ granted_scopes: scopesForTags(['portfolio']) }),
  }));
  assert.equal(allowed.status, 200);
  assert.ok((await allowed.json()).token);
});

test('an invalid admin token is rejected', async t => {
  const { auth } = await createHarness(t);

  const response = await auth.getApp().fetch(new Request('http://localhost/v1/sessions', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-uomp-admin-token': 'wrong',
    },
    body: JSON.stringify({
      agent_id: 'agent_integrity_test',
      requested_scopes: scopesForTags(['portfolio']),
    }),
  }));

  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, 'UNAUTHORIZED');
});

test('HTTP revoke requires the admin token and invalidates the token at the guard', async t => {
  const { auth, guard, store } = await createHarness(t);

  store.set({
    key: 'portfolio.holdings',
    value: { cost_basis: 100 },
    tags: ['portfolio'],
    sensitivity: 'low',
    source: 'user',
  });

  const createResponse = await createSessionViaHttp(auth, scopesForTags(['portfolio']));
  assert.equal(createResponse.status, 200);
  const { session_id: sessionId } = await createResponse.json();

  const grantResponse = await grantViaHttp(auth, sessionId, { granted_scopes: scopesForTags(['portfolio']) });
  assert.equal(grantResponse.status, 200);
  const { token } = await grantResponse.json();

  const unauthorized = await auth.getApp().fetch(new Request(`http://localhost/v1/sessions/${sessionId}/revoke`, {
    method: 'POST',
  }));
  assert.equal(unauthorized.status, 401);

  const revoked = await auth.getApp().fetch(new Request(`http://localhost/v1/sessions/${sessionId}/revoke`, {
    method: 'POST',
    headers: { 'x-uomp-admin-token': ADMIN_TOKEN },
  }));
  assert.equal(revoked.status, 200);
  assert.equal((await revoked.json()).status, 'revoked');

  const after = await readMemory(guard, token);
  assert.equal(after.status, 403);
  assert.equal((await after.json()).error.code, 'SESSION_NOT_ACTIVE');
});

test('denyTags from the request cannot be removed on grant', async t => {
  const { auth } = await createHarness(t);
  const requestedScopes = {
    read: { tags: ['portfolio'], keys: [], denyTags: ['secrets'], denyKeys: [] },
    write: emptyScope(),
  };

  const createResponse = await createSessionViaHttp(auth, requestedScopes);
  assert.equal(createResponse.status, 200);
  const { session_id: sessionId } = await createResponse.json();

  const response = await grantViaHttp(auth, sessionId, {
    granted_scopes: {
      read: { tags: ['portfolio'], keys: [], denyTags: [], denyKeys: [] },
      write: emptyScope(),
    },
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, 'SCOPE_EXCEEDS_REQUEST');
});

test('granted write scope cannot exceed an empty requested write scope', async t => {
  const { auth } = await createHarness(t);

  const createResponse = await createSessionViaHttp(auth, scopesForTags(['portfolio']));
  assert.equal(createResponse.status, 200);
  const { session_id: sessionId } = await createResponse.json();

  const response = await grantViaHttp(auth, sessionId, {
    granted_scopes: {
      read: { tags: ['portfolio'], keys: [], denyTags: [], denyKeys: [] },
      write: { tags: ['x'], keys: [], denyTags: [], denyKeys: [] },
    },
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, 'SCOPE_EXCEEDS_REQUEST');
});

test('the admin token file is stable and private', async t => {
  const tempDir = mkdtempSync(join(tmpdir(), 'uomp-admin-token-'));
  t.after(() => rmSync(tempDir, { recursive: true, force: true }));

  const secretsDir = join(tempDir, 'secrets');
  const first = loadOrCreateAdminToken(secretsDir);
  const second = loadOrCreateAdminToken(secretsDir);

  assert.equal(first, second);
  assert.equal(first.length, 64);
  assert.equal(statSync(join(secretsDir, 'admin-token')).mode & 0o777, 0o600);
});

test('close immediately invalidates the token at the guard', async t => {
  const { auth, guard, store } = await createHarness(t);

  store.set({
    key: 'portfolio.holdings',
    value: { cost_basis: 100 },
    tags: ['portfolio'],
    sensitivity: 'low',
    source: 'user',
  });

  const session = createSession(auth, ['portfolio']);
  const grant = await auth.grantSession(session.sessionId, scopesForTags(['portfolio']));
  assert.ok(grant);

  assert.equal((await readMemory(guard, grant.token)).status, 200);
  assert.equal(auth.closeSession(session.sessionId).status, 'closed');

  const after = await readMemory(guard, grant.token);
  assert.equal(after.status, 403);
  assert.equal((await after.json()).error.code, 'SESSION_NOT_ACTIVE');
});

test('revoked tokens cannot reach the write endpoints', async t => {
  const { auth, guard } = await createHarness(t);

  const session = createSession(auth, ['portfolio']);
  const grant = await auth.grantSession(session.sessionId, scopesForTags(['portfolio']));
  assert.ok(grant);

  auth.revokeSession(session.sessionId);

  for (const method of ['PUT', 'DELETE']) {
    const response = await guard.getApp().fetch(new Request('http://localhost/v1/memory/portfolio.holdings', {
      method,
      headers: { authorization: `Bearer ${grant.token}` },
    }));
    assert.equal(response.status, 403, `${method} should reject a revoked token`);
    assert.equal((await response.json()).error.code, 'SESSION_NOT_ACTIVE');
  }
});

test('direct grants preserve manifest denials and field restrictions', async t => {
  const { auth, guard, store } = await createHarness(t);

  store.set({
    key: 'portfolio.holdings',
    value: { symbol: 'AAPL' },
    tags: ['portfolio', 'secrets'],
    sensitivity: 'low',
    source: 'user',
  });
  store.set({
    key: 'portfolio.summary',
    value: { total: 1 },
    tags: ['portfolio'],
    sensitivity: 'low',
    source: 'user',
  });

  const requestedScopes = {
    read: { tags: ['portfolio'], keys: [], denyTags: ['secrets'], denyKeys: [], allowedFields: ['key'] },
    write: emptyScope(),
  };
  const session = auth.createSession({
    agent_id: 'agent_integrity_test',
    agent_name: 'Integrity Test Agent',
    requested_scopes: requestedScopes,
    duration_minutes: 30,
  });
  const grant = await auth.grantSession(session.sessionId, {
    read: buildReadScope(requestedScopes.read, ['portfolio']),
    write: emptyScope(),
  });
  assert.ok(grant);

  const denied = await readMemory(guard, grant.token, 'portfolio.holdings');
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).error.code, 'ACCESS_DENIED');

  const allowed = await readMemory(guard, grant.token, 'portfolio.summary');
  assert.equal(allowed.status, 200);
  const body = await allowed.json();
  assert.equal(body.key, 'portfolio.summary');
  assert.equal(body.value, undefined);
  assert.equal(body.tags, undefined);
});

test('buildReadScope preserves the requested deny list and field limit', () => {
  const requested = {
    tags: ['portfolio'],
    keys: ['portfolio.summary'],
    denyTags: ['secrets'],
    denyKeys: ['api.key'],
    allowedFields: ['key'],
  };

  const scope = buildReadScope(requested, ['portfolio', 'profile']);
  assert.deepEqual(scope.tags, ['portfolio', 'profile']);
  assert.deepEqual(scope.keys, ['portfolio.summary']);
  assert.deepEqual(scope.denyTags, ['secrets']);
  assert.deepEqual(scope.denyKeys, ['api.key']);
  assert.deepEqual(scope.allowedFields, ['key']);

  scope.denyTags.push('mutated');
  assert.deepEqual(requested.denyTags, ['secrets']);
});

test('granted fields must be a subset of requested fields', async t => {
  const { auth } = await createHarness(t);
  const requestedScopes = {
    read: { tags: ['portfolio'], keys: [], denyTags: [], denyKeys: [], allowedFields: ['key', 'value'] },
    write: emptyScope(),
  };

  const createResponse = await createSessionViaHttp(auth, requestedScopes);
  assert.equal(createResponse.status, 200);
  const { session_id: sessionId } = await createResponse.json();

  const excessive = await grantViaHttp(auth, sessionId, {
    granted_scopes: requestedScopes,
    allowed_fields: ['key', 'value', 'tags'],
  });
  assert.equal(excessive.status, 400);
  assert.equal((await excessive.json()).error.code, 'SCOPE_EXCEEDS_REQUEST');

  const allowed = await grantViaHttp(auth, sessionId, {
    granted_scopes: requestedScopes,
    allowed_fields: ['key', 'value'],
  });
  assert.equal(allowed.status, 200);
  assert.ok((await allowed.json()).token);
});
