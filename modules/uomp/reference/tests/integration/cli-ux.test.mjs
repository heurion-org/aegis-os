import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';

import { MemoryStore } from '../../packages/store/dist/index.js';

const CLI = new URL('../../packages/cli/dist/cli.js', import.meta.url).pathname;

function runCli(home, args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
    encoding: 'utf-8',
    timeout: 30_000,
  });
}

function createAgent(root, { id = 'notes-assistant' } = {}) {
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, 'uom.json'), JSON.stringify({
    uomp_version: '1.0',
    agent: {
      id,
      name: 'Notes Assistant',
      version: '0.1.0',
      description: 'Answers questions about project notes',
      publisher: 'test',
    },
    requested_scopes: {
      read: { tags: ['notes/projects'], keys: [], deny_tags: ['notes/journal'], deny_keys: [] },
      write: { tags: [], keys: [], deny_tags: [], deny_keys: [] },
    },
  }, null, 2));
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

async function waitForServer(port, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) return;
    } catch {
      // Not listening yet.
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`server did not start on port ${port}`);
}

test('help shows the core flow and hides advanced commands', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-help-'));
  try {
    const result = runCli(home, ['--help']);
    assert.equal(result.status, 0, result.stderr);

    for (const command of ['init', 'import', 'authorize', 'connect', 'setup', 'serve', 'start', 'status', 'stop', 'disconnect', 'pending', 'approve', 'deny', 'staged', 'payload', 'approvals', 'sessions', 'revoke', 'audit']) {
      assert.match(result.stdout, new RegExp(`^\\s{2}${command}(?:\\s|$)`, 'm'));
    }

    for (const command of ['memory', 'registry', 'discover', 'inspect', 'agent']) {
      assert.doesNotMatch(result.stdout, new RegExp(`^\\s{2}${command}(?:\\s|$)`, 'm'));
    }

    assert.match(result.stdout, /Advanced commands \(hidden\)/);
    assert.match(result.stdout, /Fast path:/);

    const hidden = runCli(home, ['memory', 'list']);
    assert.equal(hidden.status, 0, hidden.stderr);
    assert.match(hidden.stdout, /No memory items found/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('authorize writes a private env file and keeps the token out of stdout', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-authorize-'));
  const agent = join(home, 'agent');
  createAgent(agent);

  try {
    const result = runCli(home, [
      'authorize', agent,
      '--scope', 'notes/projects',
      '--duration', '15',
      '--no-server',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Session granted: (sess_\S+)/);
    assert.match(result.stdout, /Scope\s+notes\/projects/);
    assert.match(result.stdout, /Identity\s+unsigned/);
    assert.match(result.stdout, /Server not started \(--no-server\)/);
    assert.match(result.stdout, /uomp revoke sess_/);

    const sessionId = /Session granted: (sess_\S+)/.exec(result.stdout)[1];
    const envPath = join(home, '.uomp', 'sessions', `${sessionId}.env`);

    assert.ok(existsSync(envPath), `expected ${envPath} to exist`);
    assert.match(result.stdout, new RegExp(envPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.equal(statSync(envPath).mode & 0o777, 0o600);

    const envFile = readFileSync(envPath, 'utf-8');
    assert.match(envFile, /export UOM_TOKEN='eyJ/);
    assert.match(envFile, /export UOMP_BASE_URL='http:\/\/127\.0\.0\.1:9374'/);
    assert.ok(!result.stdout.includes('eyJ'), 'the token must not be printed by default');

    const revoked = runCli(home, ['revoke', sessionId]);
    assert.equal(revoked.status, 0, revoked.stderr);
    assert.match(revoked.stdout, /Revoked session/);
    assert.equal(existsSync(envPath), false, 'revoke should remove the default env file');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('authorize creates a generic MCP session without an agent path', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-generic-authorize-'));

  try {
    const result = runCli(home, [
      'authorize',
      '--scope', 'notes/projects',
      '--no-server',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Agent\s+MCP Client \(mcp-client\)/);

    const sessionId = /Session granted: (sess_\S+)/.exec(result.stdout)[1];
    assert.ok(existsSync(join(home, '.uomp', 'sessions', `${sessionId}.env`)));

    const noScope = runCli(home, ['authorize', '--no-server']);
    assert.equal(noScope.status, 1);
    assert.match(noScope.stdout + noScope.stderr, /Pass --scope/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('authorize --output writes the env file to a custom path', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-output-'));
  const agent = join(home, 'agent');
  const envPath = join(home, 'custom.env');
  createAgent(agent);

  try {
    const result = runCli(home, [
      'authorize', agent,
      '--scope', 'notes/projects',
      '--no-server',
      '--output', envPath,
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.ok(existsSync(envPath));
    assert.equal(statSync(envPath).mode & 0o777, 0o600);
    assert.match(readFileSync(envPath, 'utf-8'), /export UOM_TOKEN='eyJ/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('authorize --print-token prints the token on request', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-print-token-'));
  const agent = join(home, 'agent');
  createAgent(agent);

  try {
    const result = runCli(home, [
      'authorize', agent,
      '--scope', 'notes/projects',
      '--no-server',
      '--print-token',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /export UOM_TOKEN="eyJ/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('authorize sanitizes agent ids before writing the env file', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-injection-'));
  const agent = join(home, 'agent');
  createAgent(agent, { id: 'notes-assistant\nINJECTED=1' });

  try {
    const result = runCli(home, [
      'authorize', agent,
      '--scope', 'notes/projects',
      '--no-server',
    ]);

    assert.equal(result.status, 0, result.stderr);
    const sessionId = /Session granted: (sess_\S+)/.exec(result.stdout)[1];
    const envFile = readFileSync(join(home, '.uomp', 'sessions', `${sessionId}.env`), 'utf-8');

    assert.doesNotMatch(envFile, /^INJECTED=/m);
    assert.match(envFile, /^# agent: notes-assistant INJECTED=1$/m);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('authorize rejects an invalid duration', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-duration-'));
  const agent = join(home, 'agent');
  createAgent(agent);

  try {
    const result = runCli(home, [
      'authorize', agent,
      '--scope', 'notes/projects',
      '--duration', '0',
      '--no-server',
    ]);

    assert.equal(result.status, 1);
    assert.match(`${result.stdout}${result.stderr}`, /Invalid duration "0"/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('serve starts a UOMP server on the requested port', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-serve-'));
  const port = await getFreePort();
  const child = spawn(process.execPath, [CLI, 'serve', '--port', String(port)], {
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  const exited = new Promise(resolve => child.once('exit', resolve));

  t.after(async () => {
    child.kill('SIGTERM');
    await exited;
    rmSync(home, { recursive: true, force: true });
  });

  await waitForServer(port);
  const response = await fetch(`http://127.0.0.1:${port}/v1/memory`);
  assert.equal(response.status, 403);
  const body = await response.json();
  assert.equal(body.error.code, 'INVALID_TOKEN');
});

test('serve reports a port used by another process', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-port-conflict-'));
  const port = await getFreePort();
  const blocker = http.createServer((request, response) => {
    response.statusCode = 404;
    response.end('not uomp');
  });

  await new Promise(resolve => blocker.listen(port, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => blocker.close(resolve));
    rmSync(home, { recursive: true, force: true });
  });

  const result = runCli(home, ['serve', '--port', String(port)]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /another process/);
});

test('authorize revokes the session when the port belongs to another process', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-auth-conflict-'));
  const agent = join(home, 'agent');
  createAgent(agent);

  const port = await getFreePort();
  const blocker = http.createServer((request, response) => {
    response.statusCode = 404;
    response.end('not uomp');
  });

  await new Promise(resolve => blocker.listen(port, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => blocker.close(resolve));
    rmSync(home, { recursive: true, force: true });
  });

  const result = runCli(home, [
    'authorize', agent,
    '--scope', 'notes/projects',
    '--port', String(port),
  ]);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /The session was revoked/);
  assert.deepEqual(readdirSync(join(home, '.uomp', 'sessions')), []);

  const sessions = runCli(home, ['sessions', '--all']);
  assert.match(sessions.stdout, /revoked/);
  assert.doesNotMatch(sessions.stdout, /\bactive\b/);
});

test('sessions and audit summarize the authorization loop', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-inspect-'));
  const agent = join(home, 'agent');
  createAgent(agent);
  mkdirSync(join(home, '.uomp'), { recursive: true });

  const store = new MemoryStore({ dbPath: join(home, '.uomp', 'memory.db') });
  try {
    store.set({
      key: 'note.projects.plan',
      value: { body: 'Ship the CLI.' },
      tags: ['notes/projects'],
      sensitivity: 'low',
      source: 'user',
    });
    store.set({
      key: 'note.journal.private',
      value: { body: 'Do not read.' },
      tags: ['notes/journal'],
      sensitivity: 'low',
      source: 'user',
    });
  } finally {
    store.close();
  }

  const port = await getFreePort();
  const child = spawn(process.execPath, [CLI, 'serve', '--port', String(port)], {
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const exited = new Promise(resolve => child.once('exit', resolve));
  t.after(async () => {
    child.kill('SIGTERM');
    await exited;
    rmSync(home, { recursive: true, force: true });
  });

  await waitForServer(port);

  const authorized = runCli(home, [
    'authorize', agent,
    '--scope', 'notes/projects',
    '--port', String(port),
  ]);
  assert.equal(authorized.status, 0, authorized.stderr);

  const sessionId = /Session granted: (sess_\S+)/.exec(authorized.stdout)[1];
  const envFile = readFileSync(join(home, '.uomp', 'sessions', `${sessionId}.env`), 'utf-8');
  const token = /export UOM_TOKEN='([^']+)'/.exec(envFile)[1];
  const headers = { Authorization: `Bearer ${token}` };

  assert.equal((await fetch(`http://127.0.0.1:${port}/v1/memory/note.projects.plan`, { headers })).status, 200);
  assert.equal((await fetch(`http://127.0.0.1:${port}/v1/memory/note.journal.private`, { headers })).status, 403);

  const sessions = runCli(home, ['sessions']);
  assert.equal(sessions.status, 0, sessions.stderr);
  assert.match(sessions.stdout, /Active sessions \(1\)/);
  assert.match(sessions.stdout, /Notes Assistant \(notes-assistant\)/);
  assert.match(sessions.stdout, /active/);
  assert.match(sessions.stdout, /scope\s+notes\/projects/);
  assert.match(sessions.stdout, /last\s+denied read note\.journal\.private/);

  const sessionsJson = JSON.parse(runCli(home, ['sessions', '--json']).stdout);
  assert.equal(sessionsJson.length, 1);
  assert.equal(sessionsJson[0].sessionId, sessionId);
  assert.equal(sessionsJson[0].status, 'active');
  assert.ok(sessionsJson[0].grantedScopes.read.tags.includes('notes/projects'));
  assert.equal(sessionsJson[0].lastAccess.allowed, false);

  const audit = runCli(home, ['audit', '--limit', '10']);
  assert.equal(audit.status, 0, audit.stderr);
  assert.match(audit.stdout, /Audit log \(2\)/);
  assert.match(audit.stdout, /allow\s+read\s+notes-assistant\s+note\.projects\.plan/);
  assert.match(audit.stdout, /deny\s+read\s+notes-assistant\s+note\.journal\.private/);
  assert.match(audit.stdout, /Key not in authorized scope/);

  const auditJson = JSON.parse(runCli(home, ['audit', '--json']).stdout);
  assert.equal(auditJson.length, 2);
  assert.ok(auditJson.some(log => log.allowed === true && log.key === 'note.projects.plan'));
  assert.ok(auditJson.some(log => log.allowed === false && log.key === 'note.journal.private'));

  const limited = JSON.parse(runCli(home, ['audit', '--json', '--limit', '1']).stdout);
  assert.equal(limited.length, 1);

  const deniedLogs = JSON.parse(runCli(home, ['audit', '--json', '--result', 'deny']).stdout);
  assert.equal(deniedLogs.length, 1);
  assert.equal(deniedLogs[0].allowed, false);
  assert.equal(deniedLogs[0].key, 'note.journal.private');

  const allowedLogs = JSON.parse(runCli(home, ['audit', '--json', '--result', 'allow']).stdout);
  assert.equal(allowedLogs.length, 1);
  assert.equal(allowedLogs[0].allowed, true);

  const keyLogs = JSON.parse(runCli(home, ['audit', '--json', '--key', 'note.projects.plan']).stdout);
  assert.equal(keyLogs.length, 1);
  assert.equal(keyLogs[0].key, 'note.projects.plan');

  const recentLogs = JSON.parse(runCli(home, ['audit', '--json', '--since', '1h']).stdout);
  assert.equal(recentLogs.length, 2);

  const invalidResult = runCli(home, ['audit', '--result', 'nope']);
  assert.equal(invalidResult.status, 1);
  assert.match(invalidResult.stdout + invalidResult.stderr, /Invalid --result/);
});

test('authorize token works against uomp serve on a custom port', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-e2e-'));
  const agent = join(home, 'agent');
  createAgent(agent);
  mkdirSync(join(home, '.uomp'), { recursive: true });

  const store = new MemoryStore({ dbPath: join(home, '.uomp', 'memory.db') });
  try {
    store.set({
      key: 'note.projects.plan',
      value: { body: 'Ship the CLI.' },
      tags: ['notes/projects'],
      sensitivity: 'low',
      source: 'user',
    });
  } finally {
    store.close();
  }

  const port = await getFreePort();
  const child = spawn(process.execPath, [CLI, 'serve', '--port', String(port)], {
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  const exited = new Promise(resolve => child.once('exit', resolve));

  t.after(async () => {
    child.kill('SIGTERM');
    await exited;
    rmSync(home, { recursive: true, force: true });
  });

  await waitForServer(port);

  const authorized = runCli(home, [
    'authorize', agent,
    '--scope', 'notes/projects',
    '--port', String(port),
  ]);

  assert.equal(authorized.status, 0, authorized.stderr);
  assert.match(authorized.stdout, /A UOMP server is already running/);
  assert.ok(!stderr.includes('UOMP server error'), stderr);

  const sessionId = /Session granted: (sess_\S+)/.exec(authorized.stdout)[1];
  const envFile = readFileSync(join(home, '.uomp', 'sessions', `${sessionId}.env`), 'utf-8');
  const token = /export UOM_TOKEN='([^']+)'/.exec(envFile)[1];

  assert.match(envFile, new RegExp(`export UOMP_BASE_URL='http://127\\.0\\.0\\.1:${port}'`));

  const response = await fetch(`http://127.0.0.1:${port}/v1/memory?tag=notes/projects`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.items.length, 1);
  assert.equal(body.items[0].key, 'note.projects.plan');
});
