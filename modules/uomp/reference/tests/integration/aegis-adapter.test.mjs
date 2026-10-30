import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AegisConsentBridge,
  HttpAegisMcpClient,
  aggregateDecisions,
  scopeResources,
  scopesToResources,
} from '../../packages/aegis-adapter/dist/index.js';

function scopes(readTags = [], readKeys = [], writeTags = []) {
  return {
    read: { tags: readTags, keys: readKeys, denyTags: [], denyKeys: [] },
    write: { tags: writeTags, keys: [], denyTags: [], denyKeys: [] },
  };
}

function decision(kind, resource, escalationId) {
  return {
    protocol: 'uomp',
    decision: kind,
    action: 'read',
    resource,
    ...(escalationId ? { escalation_id: escalationId } : {}),
  };
}

test('maps UOMP tags and keys to Aegis memory resources', () => {
  assert.deepEqual(
    scopeResources({ tags: ['notes/projects'], keys: ['note.projects.plan'], denyTags: [], denyKeys: [] }),
    ['memory:tag:notes/projects', 'memory:key:note.projects.plan'],
  );

  assert.deepEqual(scopesToResources(scopes(['notes/projects'], [], ['profile'])), [
    { action: 'read', resource: 'memory:tag:notes/projects' },
    { action: 'write', resource: 'memory:tag:profile' },
  ]);
});

test('aggregates Aegis decisions with deny > ask > allow', () => {
  const requests = [
    { action: 'read', resource: 'memory:tag:notes/projects' },
    { action: 'read', resource: 'memory:tag:notes/journal' },
  ];

  assert.equal(
    aggregateDecisions(
      [decision('allow', requests[0].resource), decision('ask', requests[1].resource, 'esc-1')],
      requests,
    ).decision,
    'ask',
  );
  assert.equal(
    aggregateDecisions(
      [decision('ask', requests[0].resource, 'esc-1'), decision('deny', requests[1].resource)],
      requests,
    ).decision,
    'deny',
  );
  assert.equal(aggregateDecisions([], []).decision, 'deny');
});

test('bridge evaluates every requested resource and collects escalations', async () => {
  const calls = [];
  const client = {
    async evaluate(action, resource) {
      calls.push({ action, resource });
      return resource.includes('journal')
        ? decision('deny', resource)
        : decision('ask', resource, `esc-${calls.length}`);
    },
    async approveEscalation() {
      throw new Error('not used');
    },
  };

  const result = await new AegisConsentBridge(client).evaluateScopes(
    scopes(['notes/projects', 'notes/journal']),
  );

  assert.equal(calls.length, 2);
  assert.equal(result.decision, 'deny');
  assert.deepEqual(result.escalationIds, ['esc-1']);
});

test('HTTP client sends Aegis MCP requests and parses decisions', async () => {
  const requests = [];
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    requests.push({ url, headers: init.headers, body });
    return new Response(JSON.stringify({
      jsonrpc: '2.0',
      id: body.id,
      result: {
        content: [{
          type: 'text',
          text: JSON.stringify({
            protocol: 'uomp',
            decision: 'ask',
            action: 'read',
            resource: 'memory:tag:notes/projects',
            escalation_id: 'esc-42',
            reason: 'Boundary syscall requires explicit lease',
          }),
        }],
      },
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  };

  const client = new HttpAegisMcpClient({
    endpoint: 'http://127.0.0.1:7080/mcp',
    token: 'aop_test',
    orgId: 'local',
    agentId: 'claude-desktop',
    fetchImpl,
  });

  const result = await client.evaluate('read', 'memory:tag:notes/projects');
  assert.equal(result.decision, 'ask');
  assert.equal(result.escalation_id, 'esc-42');
  assert.equal(requests[0].body.params.name, 'memory_policy_evaluate');
  assert.deepEqual(requests[0].body.params.arguments, {
    action: 'read',
    resource: 'memory:tag:notes/projects',
  });
  assert.equal(requests[0].headers.authorization, 'Bearer aop_test');
  assert.equal(requests[0].headers['x-aegis-org'], 'local');
});

test('HTTP client approves and denies through the trusted approval endpoint', async () => {
  let mode = 'approve';
  const requests = [];
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    requests.push({ url, body });
    if (String(url).endsWith('/v1/approvals/decide')) {
      return new Response(JSON.stringify(mode === 'approve'
        ? {
            status: 'approved',
            lease: {
              lease_id: 'lease-1',
              org_id: 'local',
              agent_id: 'claude-desktop',
              action_pattern: 'memory.read',
              resource_pattern: 'memory:tag:notes/projects',
              expires_at_ms: 1_800_000,
              granted_by: 'user',
            },
          }
        : { status: 'denied', escalation: { escalation_id: 'esc-42' } }
      ), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({
      jsonrpc: '2.0',
      id: body.id,
      result: { isError: true, content: [{ type: 'text', text: 'Aegis OS Syscall Error: nope' }] },
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  };

  const client = new HttpAegisMcpClient({
    endpoint: 'http://127.0.0.1:7080/mcp',
    token: 'aop_test',
    orgId: 'local',
    agentId: 'claude-desktop',
    fetchImpl,
  });

  const lease = await client.approveEscalation('esc-42', 1800);
  assert.equal(lease.resource_pattern, 'memory:tag:notes/projects');
  assert.equal(requests[0].url, 'http://127.0.0.1:7080/v1/approvals/decide');
  assert.deepEqual(requests[0].body, {
    escalation_id: 'esc-42',
    decision: 'approve',
    ttl_secs: 1800,
  });

  mode = 'deny';
  await client.denyEscalation('esc-42');
  assert.deepEqual(requests[1].body, {
    escalation_id: 'esc-42',
    decision: 'deny',
    ttl_secs: 0,
  });

  await assert.rejects(
    () => client.evaluate('read', 'memory:tag:notes/projects'),
    /Aegis OS Syscall Error/,
  );
});

test('HTTP client lists Aegis escalations', async () => {
  const fetchImpl = async (_url, init) => {
    const body = JSON.parse(init.body);
    return new Response(JSON.stringify({
      jsonrpc: '2.0',
      id: body.id,
      result: {
        content: [{
          type: 'text',
          text: JSON.stringify({
            escalations: [{
              escalation_id: 'esc-1',
              org_id: 'local',
              agent_id: 'remote-agent',
              action: 'memory.read',
              target_resource: 'memory:tag:notes/projects',
              reason: 'Boundary syscall requires explicit lease',
              suggested_lease_scope: 'action=memory.read, resource=*',
              status: 'pending',
              created_at_ms: 1000,
            }],
          }),
        }],
      },
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  };

  const client = new HttpAegisMcpClient({
    endpoint: 'http://127.0.0.1:7080/mcp',
    token: 'aop_test',
    orgId: 'local',
    agentId: 'uomp',
    fetchImpl,
  });

  const escalations = await client.listEscalations();
  assert.equal(escalations.length, 1);
  assert.equal(escalations[0].escalation_id, 'esc-1');
});
