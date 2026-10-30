import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

function defaultClaudeConfigPath(home) {
  if (process.platform === 'darwin') {
    return join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  }
  if (process.platform === 'win32') {
    return join(process.env.APPDATA ?? join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json');
  }
  return join(home, '.config', 'Claude', 'claude_desktop_config.json');
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

async function waitForFile(path, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(path)) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`file did not appear: ${path}`);
}

test('connect claude --print-config writes the env file but not the client config', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-print-'));
  const envPath = join(home, '.uomp', 'sessions', 'claude.env');

  try {
    const result = runCli(home, [
      'connect', 'claude',
      '--scope', 'notes/projects',
      '--print-config',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /"mcpServers"/);

    const config = JSON.parse(result.stdout);
    assert.equal(config.mcpServers.uomp.args.at(-1), envPath);
    assert.equal(typeof config.mcpServers.uomp.command, 'string');

    assert.ok(existsSync(envPath));
    assert.equal(statSync(envPath).mode & 0o777, 0o600);
    assert.match(readFileSync(envPath, 'utf-8'), /export UOM_TOKEN='eyJ/);
    assert.equal(existsSync(defaultClaudeConfigPath(home)), false);
    assert.match(result.stderr, /Start the UOMP server/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('connect claude merges the client config, preserves other entries, and is idempotent', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-claude-'));
  const configPath = join(home, 'claude.json');
  const envPath = join(home, '.uomp', 'sessions', 'claude.env');

  writeFileSync(configPath, JSON.stringify({
    theme: 'dark',
    mcpServers: {
      other: { command: 'other-cli', args: ['serve'] },
    },
  }, null, 2));

  try {
    const first = runCli(home, [
      'connect', 'claude',
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);

    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /Claude Desktop config/);
    assert.match(first.stdout, /updated/);
    assert.match(first.stdout, /backup:/);
    assert.match(first.stdout, /Restart Claude Desktop/);

    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    assert.equal(config.theme, 'dark');
    assert.deepEqual(config.mcpServers.other, { command: 'other-cli', args: ['serve'] });
    assert.equal(config.mcpServers.uomp.args.at(-1), envPath);
    assert.ok(!JSON.stringify(config).includes('eyJ'), 'the token must not be written to the client config');

    const backups = readdirSync(home).filter(name => name.startsWith('claude.json.bak.'));
    assert.equal(backups.length, 1);
    assert.deepEqual(JSON.parse(readFileSync(join(home, backups[0]), 'utf-8')), {
      theme: 'dark',
      mcpServers: {
        other: { command: 'other-cli', args: ['serve'] },
      },
    });

    const firstToken = readFileSync(envPath, 'utf-8');
    const second = runCli(home, [
      'connect', 'claude',
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);

    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /already up to date/);
    assert.equal(readdirSync(home).filter(name => name.startsWith('claude.json.bak.')).length, 1);
    assert.notEqual(readFileSync(envPath, 'utf-8'), firstToken, 're-connecting should refresh the token');

    const sessions = JSON.parse(runCli(home, ['sessions', '--json']).stdout);
    assert.equal(sessions.length, 1, 're-connecting should revoke the previous session');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('connect opencode writes the mcp.servers shape and preserves other servers', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-opencode-'));
  const configPath = join(home, 'opencode.json');
  const envPath = join(home, '.uomp', 'sessions', 'opencode.env');

  writeFileSync(configPath, JSON.stringify({
    theme: 'dark',
    mcp: {
      servers: {
        other: { type: 'local', command: ['other'] },
      },
    },
  }, null, 2));

  try {
    const result = runCli(home, [
      'connect', 'opencode',
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);

    assert.equal(result.status, 0, result.stderr);

    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    assert.equal(config.theme, 'dark');
    assert.deepEqual(config.mcp.servers.other, { type: 'local', command: ['other'] });
    assert.equal(config.mcp.servers.uomp.type, 'local');
    assert.equal(config.mcp.servers.uomp.codemode, false);
    assert.ok(Array.isArray(config.mcp.servers.uomp.command));
    assert.equal(config.mcp.servers.uomp.command.at(-1), envPath);
    assert.ok(existsSync(envPath));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('connect with an agent path keeps the existing authorize flow', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-agent-'));
  const agent = join(home, 'agent');
  createAgent(agent);

  try {
    const result = runCli(home, [
      'connect', agent,
      '--scope', 'notes/projects',
      '--no-server',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Open a new terminal, then:/);
    assert.match(result.stdout, /Server not started \(--no-server\)/);

    const sessionId = /Session granted: (sess_\S+)/.exec(result.stdout)[1];
    assert.ok(existsSync(join(home, '.uomp', 'sessions', `${sessionId}.env`)));
    assert.equal(existsSync(defaultClaudeConfigPath(home)), false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('connect --skip-config only grants the session', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-skip-'));
  const envPath = join(home, '.uomp', 'sessions', 'claude.env');

  try {
    const result = runCli(home, [
      'connect', 'claude',
      '--scope', 'notes/projects',
      '--no-server',
      '--skip-config',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /skipped \(--skip-config\)/);
    assert.match(result.stdout, /uomp mcp --session/);
    assert.ok(existsSync(envPath));
    assert.equal(existsSync(defaultClaudeConfigPath(home)), false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('connect refuses to overwrite invalid JSON and leaves no session behind', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-invalid-'));
  const configPath = join(home, 'claude.json');
  const original = '{ "mcpServers": ';
  writeFileSync(configPath, original);

  try {
    const result = runCli(home, [
      'connect', 'claude',
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /not valid JSON/);
    assert.equal(readFileSync(configPath, 'utf-8'), original);
    assert.deepEqual(readdirSync(join(home, '.uomp', 'sessions')), []);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('connect rejects unknown targets', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-unknown-'));

  try {
    const result = runCli(home, ['connect', 'nope', '--scope', 'notes/projects', '--no-server']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Unknown target/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('revoke removes the fixed client env file', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-revoke-'));
  const configPath = join(home, 'claude.json');
  const envPath = join(home, '.uomp', 'sessions', 'claude.env');

  try {
    const connected = runCli(home, [
      'connect', 'claude',
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);
    assert.equal(connected.status, 0, connected.stderr);
    assert.ok(existsSync(envPath));

    const sessionId = /Session granted: (sess_\S+)/.exec(connected.stdout)[1];
    const revoked = runCli(home, ['revoke', sessionId]);
    assert.equal(revoked.status, 0, revoked.stderr);
    assert.equal(existsSync(envPath), false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('connect cursor writes the mcpServers shape and cursor.env', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-cursor-'));
  const configPath = join(home, 'cursor.json');

  try {
    const result = runCli(home, [
      'connect', 'cursor',
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);

    assert.equal(result.status, 0, result.stderr);
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    assert.equal(config.mcpServers.uomp.args.at(-1), join(home, '.uomp', 'sessions', 'cursor.env'));
    assert.ok(existsSync(join(home, '.uomp', 'sessions', 'cursor.env')));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('connect requires --scope for MCP clients', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-scope-'));

  try {
    const result = runCli(home, ['connect', 'claude', '--no-server']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Pass --scope when connecting an MCP client/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('disconnect removes the opencode mcp.servers entry', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-disconnect-opencode-'));
  const configPath = join(home, 'opencode.json');
  const envPath = join(home, '.uomp', 'sessions', 'opencode.env');

  try {
    const connected = runCli(home, [
      'connect', 'opencode',
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);
    assert.equal(connected.status, 0, connected.stderr);
    assert.ok(existsSync(envPath));

    const disconnected = runCli(home, ['disconnect', 'opencode', '--config', configPath]);
    assert.equal(disconnected.status, 0, disconnected.stderr);

    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    assert.equal(config.mcp.servers.uomp, undefined);
    assert.equal(existsSync(envPath), false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('disconnect revokes the client session even if the env file is missing', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-disconnect-missing-env-'));
  const configPath = join(home, 'claude.json');
  const envPath = join(home, '.uomp', 'sessions', 'claude.env');

  try {
    const connected = runCli(home, [
      'connect', 'claude',
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);
    assert.equal(connected.status, 0, connected.stderr);
    rmSync(envPath, { force: true });

    const disconnected = runCli(home, ['disconnect', 'claude', '--config', configPath]);
    assert.equal(disconnected.status, 0, disconnected.stderr);
    assert.match(disconnected.stdout, /revoked/);
    assert.deepEqual(JSON.parse(runCli(home, ['sessions', '--json']).stdout), []);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('start launches a managed background server', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-start-'));
  const port = await getFreePort();

  t.after(() => {
    runCli(home, ['stop']);
    rmSync(home, { recursive: true, force: true });
  });

  const result = runCli(home, ['start', '--port', String(port)]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /started in the background/);

  const status = JSON.parse(runCli(home, ['status', '--json']).stdout);
  assert.equal(status.server.running, true);
  assert.equal(status.server.managed, true);
  assert.equal(status.server.url, `http://127.0.0.1:${port}`);

  const stopped = JSON.parse(runCli(home, ['stop', '--json']).stdout);
  assert.equal(stopped.stopped, true);
});

test('connect --foreground starts the server in this terminal', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-server-'));
  const configPath = join(home, 'claude.json');
  const port = await getFreePort();

  const child = spawn(process.execPath, [
    CLI,
    'connect', 'claude',
    '--scope', 'notes/projects',
    '--port', String(port),
    '--foreground',
    '--config', configPath,
  ], {
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
  await waitForFile(configPath);

  const config = JSON.parse(readFileSync(configPath, 'utf-8'));
  assert.equal(config.mcpServers.uomp.args.at(-1), join(home, '.uomp', 'sessions', 'claude.env'));

  const envFile = readFileSync(join(home, '.uomp', 'sessions', 'claude.env'), 'utf-8');
  assert.match(envFile, new RegExp(`export UOMP_BASE_URL='http://127\\.0\\.0\\.1:${port}'`));
  assert.ok(!stderr.includes('UOMP server error'), stderr);
});

test('connect starts a managed background server; status and stop control it', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-background-'));
  const configPath = join(home, 'claude.json');
  const port = await getFreePort();

  t.after(() => {
    runCli(home, ['stop']);
    rmSync(home, { recursive: true, force: true });
  });

  const result = runCli(home, [
    'connect', 'claude',
    '--scope', 'notes/projects',
    '--port', String(port),
    '--config', configPath,
  ]);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /UOMP server started in the background/);
  assert.match(result.stdout, /Stop with: uomp stop/);
  assert.ok(existsSync(configPath));

  const status = JSON.parse(runCli(home, ['status', '--json']).stdout);
  assert.equal(status.server.running, true);
  assert.equal(status.server.managed, true);
  assert.equal(status.server.url, `http://127.0.0.1:${port}`);
  assert.ok(status.sessions.some(session => session.agentId === 'mcp-client-claude'));

  const stopped = JSON.parse(runCli(home, ['stop', '--json']).stdout);
  assert.equal(stopped.stopped, true);

  const after = JSON.parse(runCli(home, ['status', '--json']).stdout);
  assert.equal(after.server.running, false);
});

test('connect --vault imports Markdown before granting the session', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-vault-'));
  const vault = join(home, 'vault');
  const configPath = join(home, 'claude.json');

  mkdirSync(join(vault, 'projects'), { recursive: true });
  mkdirSync(join(vault, 'journal'), { recursive: true });
  writeFileSync(join(vault, 'projects', 'plan.md'), [
    '---',
    'title: Plan',
    'tags: [planning]',
    '---',
    '# Plan',
    'Ship the CLI.',
    '',
  ].join('\n'));
  writeFileSync(join(vault, 'journal', 'private.md'), [
    '---',
    'title: Private',
    '---',
    '# Private',
    'Do not read.',
    '',
  ].join('\n'));

  try {
    const result = runCli(home, [
      'connect', 'claude',
      '--vault', vault,
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Imported 2 notes/);
    assert.match(result.stdout, /notes\/projects/);

    const store = new MemoryStore({ dbPath: join(home, '.uomp', 'memory.db') });
    try {
      const note = store.get('note.projects.plan');
      assert.ok(note);
      assert.ok(note.tags.includes('notes/projects'));
      assert.ok(store.get('note.journal.private'));
    } finally {
      store.close();
    }

    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    assert.equal(config.mcpServers.uomp.args.at(-1), join(home, '.uomp', 'sessions', 'claude.env'));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('connect --vault fails before creating a session when the vault is missing', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-vault-missing-'));
  const configPath = join(home, 'claude.json');

  try {
    const result = runCli(home, [
      'connect', 'claude',
      '--vault', join(home, 'missing-vault'),
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /ENOENT|no such file|not found/i);
    assert.equal(existsSync(configPath), false);
    assert.deepEqual(readdirSync(join(home, '.uomp', 'sessions')), []);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('connect --vault rejects an empty vault without creating a session', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-connect-vault-empty-'));
  const vault = join(home, 'empty-vault');
  const configPath = join(home, 'claude.json');
  mkdirSync(vault, { recursive: true });

  try {
    const result = runCli(home, [
      'connect', 'claude',
      '--vault', vault,
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /No Markdown notes found/);
    assert.equal(existsSync(configPath), false);
    assert.deepEqual(readdirSync(join(home, '.uomp', 'sessions')), []);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('disconnect removes the client config, revokes the session, and removes the env file', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-disconnect-'));
  const configPath = join(home, 'claude.json');
  const envPath = join(home, '.uomp', 'sessions', 'claude.env');

  try {
    const connected = runCli(home, [
      'connect', 'claude',
      '--scope', 'notes/projects',
      '--no-server',
      '--config', configPath,
    ]);
    assert.equal(connected.status, 0, connected.stderr);
    assert.ok(existsSync(envPath));

    const disconnected = runCli(home, ['disconnect', 'claude', '--config', configPath]);
    assert.equal(disconnected.status, 0, disconnected.stderr);
    assert.match(disconnected.stdout, /Disconnected Claude Desktop/);
    assert.match(disconnected.stdout, /revoked/);

    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    assert.equal(config.mcpServers.uomp, undefined);
    assert.ok(!existsSync(envPath));
    assert.deepEqual(JSON.parse(runCli(home, ['sessions', '--json']).stdout), []);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
