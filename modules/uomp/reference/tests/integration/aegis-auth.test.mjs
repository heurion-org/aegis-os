import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AuthService } from '../../packages/auth/dist/index.js';
import { JWTTokenIssuer } from '../../packages/token/dist/index.js';

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

async function createHarness(t, aegis) {
  const tempDir = mkdtempSync(join(tmpdir(), 'uomp-aegis-auth-'));
  const issuer = new JWTTokenIssuer();
  await issuer.loadOrGenerateKey(join(tempDir, 'secrets'));

  const auth = new AuthService({
    dbPath: join(tempDir, 'auth.db'),
    issuer,
    adminToken: ADMIN_TOKEN,
    aegis,
  });

  t.after(() => {
    auth.close();
    rmSync(tempDir, { recursive: true, force: true });
  });

  return auth;
}

test('Aegis ask creates a UOMP consent request with escalation ids', async t => {
  const evaluations = [];
  const auth = await createHarness(t, {
    async evaluateScopes(scopes) {
      evaluations.push(scopes);
      return { decision: 'ask', escalationIds: ['esc-1', 'esc-2'] };
    },
    async approveEscalations() {
      throw new Error('not used');
    },
  });

  const { request } = await auth.createConsentRequestWithAegis({
    agent_id: 'claude-desktop',
    agent_name: 'Claude Desktop',
    requested_scopes: scopesForTags(['notes/projects']),
    duration_minutes: 30,
  });

  assert.equal(evaluations.length, 1);
  assert.deepEqual(request.aegisEscalationIds, ['esc-1', 'esc-2']);
  assert.deepEqual(
    auth.getConsentRequest(request.requestId)?.aegisEscalationIds,
    ['esc-1', 'esc-2'],
  );
});

test('Aegis deny prevents a consent request from being created', async t => {
  const auth = await createHarness(t, {
    async evaluateScopes() {
      return { decision: 'deny', escalationIds: [] };
    },
    async approveEscalations() {
      throw new Error('not used');
    },
  });

  await assert.rejects(
    () => auth.createConsentRequestWithAegis({
      agent_id: 'claude-desktop',
      requested_scopes: scopesForTags(['notes/journal']),
    }),
    /Aegis denied/,
  );
  assert.equal(auth.listConsentRequests().length, 0);
});

test('approving a UOMP request approves the matching Aegis escalations', async t => {
  const approvals = [];
  const auth = await createHarness(t, {
    async evaluateScopes() {
      return { decision: 'ask', escalationIds: ['esc-1'] };
    },
    async approveEscalations(escalationIds, ttlSecs) {
      approvals.push({ escalationIds, ttlSecs });
      return [];
    },
  });

  const { request } = await auth.createConsentRequestWithAegis({
    agent_id: 'claude-desktop',
    requested_scopes: scopesForTags(['notes/projects']),
    duration_minutes: 30,
  });

  const granted = await auth.approveConsentRequest(
    request.requestId,
    scopesForTags(['notes/projects']),
  );

  assert.ok(granted?.token);
  assert.equal(approvals.length, 1);
  assert.deepEqual(approvals[0].escalationIds, ['esc-1']);
  assert.ok(approvals[0].ttlSecs > 0);
  assert.equal(auth.getConsentRequest(request.requestId)?.status, 'approved');
});

test('denying a UOMP request denies the matching Aegis escalations', async t => {
  const denials = [];
  const auth = await createHarness(t, {
    async evaluateScopes() {
      return { decision: 'ask', escalationIds: ['esc-1'] };
    },
    async approveEscalations() {
      throw new Error('not used');
    },
    async denyEscalations(escalationIds) {
      denials.push(escalationIds);
    },
  });

  const { request } = await auth.createConsentRequestWithAegis({
    agent_id: 'claude-desktop',
    requested_scopes: scopesForTags(['notes/projects']),
  });

  const denied = await auth.denyConsentRequest(request.requestId);

  assert.equal(denied?.status, 'denied');
  assert.deepEqual(denials, [['esc-1']]);
  assert.equal(auth.getConsentRequest(request.requestId)?.status, 'denied');
});
