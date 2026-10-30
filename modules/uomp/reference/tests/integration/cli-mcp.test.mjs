import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { spawn, spawnSync } from 'node:child_process';
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

function createAgent(root) {
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, 'uom.json'), JSON.stringify({
    uomp_version: '1.0',
    agent: {
      id: 'notes-assistant',
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

function startMcp(home, sessionId) {
  const child = spawn(process.execPath, [CLI, 'mcp', '--session', sessionId], {
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });

  const pending = new Map();
  const events = [];
  const lines = createInterface({ input: child.stdout });

  lines.on('line', line => {
    const message = JSON.parse(line);
    if (message.id != null && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    } else {
      events.push(message);
    }
  });

  let nextId = 1;
  const request = (method, params = {}) => new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`timed out waiting for ${method}. stderr: ${stderr}`));
    }, 10_000);

    pending.set(id, message => {
      clearTimeout(timer);
      resolve(message);
    });

    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });

  const exited = new Promise(resolve => child.once('exit', resolve));

  return {
    request,
    events,
    stderr: () => stderr,
    async close() {
      child.stdin.end();
      return exited;
    },
    kill() {
      child.kill('SIGTERM');
    },
  };
}

test('mcp serves authorized memory over stdio', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-mcp-'));
  const agent = join(home, 'agent');
  createAgent(agent);
  mkdirSync(join(home, '.uomp'), { recursive: true });

  const store = new MemoryStore({ dbPath: join(home, '.uomp', 'memory.db') });
  try {
    store.set({
      key: 'note.projects.plan',
      value: { path: 'projects/plan.md', title: 'Plan', content: 'Ship the CLI.' },
      tags: ['notes/projects'],
      sensitivity: 'low',
      source: 'user',
    });
    store.set({
      key: 'note.journal.private',
      value: { path: 'journal/private.md', title: 'Private', content: 'Do not read.' },
      tags: ['notes/journal'],
      sensitivity: 'low',
      source: 'user',
    });
  } finally {
    store.close();
  }

  const port = await getFreePort();
  const server = spawn(process.execPath, [CLI, 'serve', '--port', String(port)], {
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const serverExited = new Promise(resolve => server.once('exit', resolve));

  t.after(async () => {
    server.kill('SIGTERM');
    await serverExited;
    rmSync(home, { recursive: true, force: true });
  });

  await waitForServer(port);

  const envPath = join(home, 'mcp-session.env');
  const authorized = runCli(home, [
    'authorize', agent,
    '--scope', 'notes/projects',
    '--no-server',
    '--port', String(port),
    '--output', envPath,
  ]);
  assert.equal(authorized.status, 0, authorized.stderr);

  const sessionId = /Session granted: (sess_\S+)/.exec(authorized.stdout)[1];

  const printed = runCli(home, ['mcp', '--session', envPath, '--print-config']);
  assert.equal(printed.status, 0, printed.stderr);
  const clientConfig = JSON.parse(printed.stdout);
  assert.ok(clientConfig.mcpServers.uomp.args.includes('mcp'));
  assert.equal(clientConfig.mcpServers.uomp.args.at(-1), envPath);

  const opencodeConfig = JSON.parse(runCli(home, [
    'mcp', '--session', envPath, '--print-config', '--client', 'opencode',
  ]).stdout);
  assert.equal(opencodeConfig.mcp.servers.uomp.type, 'local');
  assert.equal(opencodeConfig.mcp.servers.uomp.codemode, false);
  assert.ok(opencodeConfig.mcp.servers.uomp.command.includes('mcp'));

  const claudeConfig = JSON.parse(runCli(home, [
    'mcp', '--session', envPath, '--print-config', '--client', 'claude',
  ]).stdout);
  assert.equal(typeof claudeConfig.mcpServers.uomp.command, 'string');
  assert.ok(Array.isArray(claudeConfig.mcpServers.uomp.args));

  const badClient = runCli(home, ['mcp', '--session', envPath, '--print-config', '--client', 'nope']);
  assert.equal(badClient.status, 1);
  assert.match(badClient.stderr, /Unknown client/);

  const mcp = startMcp(home, envPath);
  t.after(() => mcp.kill());

  const initialized = await mcp.request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'test', version: '0.0.0' },
  });
  assert.equal(initialized.result.serverInfo.name, 'uomp');
  assert.ok(initialized.result.capabilities.tools);

  const tools = await mcp.request('tools/list');
  assert.deepEqual(tools.result.tools.map(tool => tool.name), ['list_memory', 'search_memory', 'read_memory']);

  const listed = await mcp.request('tools/call', {
    name: 'list_memory',
    arguments: { tag: 'notes/projects' },
  });
  assert.equal(listed.result.isError, false);
  assert.match(listed.result.content[0].text, /note\.projects\.plan/);
  assert.doesNotMatch(listed.result.content[0].text, /note\.journal\.private/);
  assert.doesNotMatch(listed.result.content[0].text, /Ship the CLI\./);

  const searched = await mcp.request('tools/call', {
    name: 'search_memory',
    arguments: { tag: 'notes/projects', query: 'ship' },
  });
  assert.equal(searched.result.isError, false);
  assert.match(searched.result.content[0].text, /note\.projects\.plan/);
  assert.doesNotMatch(searched.result.content[0].text, /Ship the CLI\./);

  const missed = await mcp.request('tools/call', {
    name: 'search_memory',
    arguments: { tag: 'notes/projects', query: 'journal' },
  });
  assert.equal(missed.result.isError, false);
  assert.match(missed.result.content[0].text, /"count": 0/);

  const read = await mcp.request('tools/call', {
    name: 'read_memory',
    arguments: { key: 'note.projects.plan' },
  });
  assert.equal(read.result.isError, false);
  assert.match(read.result.content[0].text, /Ship the CLI\./);

  const denied = await mcp.request('tools/call', {
    name: 'read_memory',
    arguments: { key: 'note.journal.private' },
  });
  assert.equal(denied.result.isError, true);
  assert.match(denied.result.content[0].text, /ACCESS_DENIED/);

  const revoked = runCli(home, ['revoke', sessionId]);
  assert.equal(revoked.status, 0, revoked.stderr);

  const afterRevoke = await mcp.request('tools/call', {
    name: 'list_memory',
    arguments: { tag: 'notes/projects' },
  });
  assert.equal(afterRevoke.result.isError, true);
  assert.match(afterRevoke.result.content[0].text, /SESSION_NOT_ACTIVE/);

  const reauthorized = runCli(home, [
    'authorize', agent,
    '--scope', 'notes/projects',
    '--no-server',
    '--port', String(port),
    '--output', envPath,
  ]);
  assert.equal(reauthorized.status, 0, reauthorized.stderr);

  const afterReauthorize = await mcp.request('tools/call', {
    name: 'list_memory',
    arguments: { tag: 'notes/projects' },
  });
  assert.equal(afterReauthorize.result.isError, false);
  assert.match(afterReauthorize.result.content[0].text, /note\.projects\.plan/);

  const exitCode = await mcp.close();
  assert.equal(exitCode, 0);
  assert.match(mcp.stderr(), /UOMP MCP server ready/);
});

test('mcp fails clearly without a session', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-mcp-nosession-'));

  try {
    const result = runCli(home, ['mcp']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /No UOMP session/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('mcp --print-config works without initializing the data directory', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-mcp-config-'));
  const envPath = join(home, 'session.env');
  writeFileSync(envPath, "export UOM_TOKEN='test-token'\nexport UOMP_BASE_URL='http://127.0.0.1:1'\n");

  try {
    const result = runCli(home, ['mcp', '--session', envPath, '--print-config']);
    assert.equal(result.status, 0, result.stderr);

    const config = JSON.parse(result.stdout);
    assert.equal(config.mcpServers.uomp.args.at(-1), envPath);
    assert.equal(existsSync(join(home, '.uomp')), false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
