import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { spawn, spawnSync } from 'node:child_process';
import net from 'node:net';

const CLI = new URL('../../packages/cli/dist/cli.js', import.meta.url).pathname;

function runCli(home, args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
    encoding: 'utf-8',
    timeout: 30_000,
  });
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

function createVault(home) {
  const vault = join(home, 'vault');
  mkdirSync(join(vault, 'projects'), { recursive: true });
  mkdirSync(join(vault, 'journal'), { recursive: true });
  writeFileSync(join(vault, 'projects', 'plan.md'), '# Plan\nShip it.\n');
  writeFileSync(join(vault, 'journal', 'private.md'), '# Private\nDo not read.\n');
  return vault;
}

function startMcp(home, envPath, port) {
  const child = spawn(process.execPath, [
    CLI,
    'mcp',
    '--session', envPath,
    '--on-demand',
    '--client', 'claude',
    '--base-url', `http://127.0.0.1:${port}`,
    '--no-open',
    '--no-notify',
  ], {
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });

  const pending = new Map();
  const lines = createInterface({ input: child.stdout });
  lines.on('line', line => {
    const message = JSON.parse(line);
    if (message.id != null && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    }
  });

  let nextId = 1;
  const request = (method, params = {}) => new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`timed out waiting for ${method}: ${stderr}`));
    }, 15_000);
    pending.set(id, message => {
      clearTimeout(timer);
      resolve(message);
    });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });

  const exited = new Promise(resolve => child.once('exit', resolve));

  return {
    request,
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

async function waitFor(check, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('timed out waiting for condition');
}

async function approvePage(url, fields) {
  const parsed = new URL(url);
  const requestId = parsed.pathname.split('/').pop();
  const secret = parsed.searchParams.get('secret');
  const response = await fetch(`${parsed.origin}/consent/${requestId}`, {
    method: 'POST',
    body: new URLSearchParams({ secret, action: 'approve', ...fields }),
  });
  return response;
}

test('setup configures a client without granting access, then the agent requests a tag', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-setup-tag-'));
  const vault = createVault(home);
  const configPath = join(home, 'claude.json');
  const envPath = join(home, '.uomp', 'sessions', 'claude.env');
  const port = await getFreePort();

  t.after(() => {
    runCli(home, ['stop']);
    rmSync(home, { recursive: true, force: true });
  });

  const setup = runCli(home, [
    'setup', 'claude',
    '--vault', vault,
    '--port', String(port),
    '--config', configPath,
  ]);
  assert.equal(setup.status, 0, setup.stderr);
  assert.match(setup.stdout, /No access has been granted yet/);
  assert.equal(existsSync(envPath), false);

  const config = JSON.parse(readFileSync(configPath, 'utf-8'));
  const args = config.mcpServers.uomp.args;
  assert.ok(args.includes('--on-demand'));
  assert.equal(args.includes('--request-scope'), false);

  const mcp = startMcp(home, envPath, port);
  t.after(() => mcp.kill());

  await mcp.request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'setup-test', version: '0.0.0' },
  });

  const call = mcp.request('tools/call', {
    name: 'list_memory',
    arguments: { tag: 'notes/projects' },
  });

  await waitFor(() => /UOMP approval required: http/.test(mcp.stderr()));
  const approvalUrl = /UOMP approval required: (\S+)/.exec(mcp.stderr())[1];
  const pending = JSON.parse(runCli(home, ['pending', '--json']).stdout);
  assert.equal(pending.length, 1);
  assert.ok(pending[0].requestedScopes.read.tags.includes('notes/projects'));

  const approved = await approvePage(approvalUrl, { tag: 'notes/projects' });
  assert.equal(approved.status, 200);
  assert.match(await approved.text(), /Access approved/);

  const result = await call;
  assert.equal(result.result.isError, false);
  assert.match(result.result.content[0].text, /note\.projects\.plan/);
  assert.ok(existsSync(envPath));

  const read = await mcp.request('tools/call', {
    name: 'read_memory',
    arguments: { key: 'note.projects.plan' },
  });
  assert.equal(read.result.isError, false);
  assert.match(read.result.content[0].text, /Ship it/);
  assert.equal((mcp.stderr().match(/UOMP approval required/g) ?? []).length, 1);

  await mcp.close();
});

test('setup supports an agent-initiated key-only request', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-setup-key-'));
  const vault = createVault(home);
  const configPath = join(home, 'claude.json');
  const envPath = join(home, '.uomp', 'sessions', 'claude.env');
  const port = await getFreePort();

  t.after(() => {
    runCli(home, ['stop']);
    rmSync(home, { recursive: true, force: true });
  });

  const setup = runCli(home, [
    'setup', 'claude',
    '--vault', vault,
    '--port', String(port),
    '--config', configPath,
  ]);
  assert.equal(setup.status, 0, setup.stderr);

  const mcp = startMcp(home, envPath, port);
  t.after(() => mcp.kill());

  await mcp.request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'setup-test', version: '0.0.0' },
  });

  const call = mcp.request('tools/call', {
    name: 'read_memory',
    arguments: { key: 'note.projects.plan' },
  });

  await waitFor(() => /UOMP approval required: http/.test(mcp.stderr()));
  const approvalUrl = /UOMP approval required: (\S+)/.exec(mcp.stderr())[1];

  const page = await fetch(approvalUrl);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Requested keys/);
  assert.match(html, /note\.projects\.plan/);

  const approved = await approvePage(approvalUrl, { key: 'note.projects.plan' });
  assert.equal(approved.status, 200);

  const result = await call;
  assert.equal(result.result.isError, false);
  assert.match(result.result.content[0].text, /Ship it/);

  await mcp.close();
});
