import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { MemoryStore } from '../../packages/store/dist/index.js';

const CLI = new URL('../../packages/cli/dist/cli.js', import.meta.url).pathname;

function runCli(home, args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
    encoding: 'utf-8',
    timeout: 30_000,
  });
}

function createAgent(root, { tags = [], keys = [] } = {}) {
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, 'uom.json'), JSON.stringify({
    uomp_version: '1.0',
    agent: {
      id: 'test-agent',
      name: 'Test Agent',
      version: '0.1.0',
    },
    requested_scopes: {
      read: { tags, keys, deny_tags: [], deny_keys: [] },
      write: { tags: [], keys: [], deny_tags: [], deny_keys: [] },
    },
  }, null, 2));
}

function seed(home, items) {
  mkdirSync(join(home, '.uomp'), { recursive: true });
  const store = new MemoryStore({ dbPath: join(home, '.uomp', 'memory.db') });
  try {
    for (const item of items) {
      store.set(item);
    }
  } finally {
    store.close();
  }
}

function grantedScopes(home) {
  const sessions = JSON.parse(runCli(home, ['sessions', '--json']).stdout);
  assert.equal(sessions.length, 1);
  return sessions[0].grantedScopes.read;
}

test('high-sensitivity tags require explicit keys in non-interactive mode', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-high-required-'));
  const agent = join(home, 'agent');
  createAgent(agent, { tags: ['portfolio:holdings'] });
  seed(home, [
    { key: 'holding.AAPL', value: { symbol: 'AAPL' }, tags: ['portfolio:holdings'], sensitivity: 'high', source: 'user' },
    { key: 'holding.MSFT', value: { symbol: 'MSFT' }, tags: ['portfolio:holdings'], sensitivity: 'high', source: 'user' },
  ]);

  try {
    const result = runCli(home, [
      'connect', agent,
      '--scope', 'portfolio:holdings',
      '--no-server',
    ]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /High-sensitivity tags require explicit keys/);
    assert.deepEqual(readdirSync(join(home, '.uomp', 'sessions')), []);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('--allow-key grants only the named high-sensitivity key', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-high-key-'));
  const agent = join(home, 'agent');
  createAgent(agent, { tags: ['portfolio:holdings'] });
  seed(home, [
    { key: 'holding.AAPL', value: { symbol: 'AAPL' }, tags: ['portfolio:holdings'], sensitivity: 'high', source: 'user' },
    { key: 'holding.MSFT', value: { symbol: 'MSFT' }, tags: ['portfolio:holdings'], sensitivity: 'high', source: 'user' },
  ]);

  try {
    const result = runCli(home, [
      'connect', agent,
      '--scope', 'portfolio:holdings',
      '--allow-key', 'holding.AAPL',
      '--no-server',
    ]);

    assert.equal(result.status, 0, result.stderr);
    const scope = grantedScopes(home);
    assert.deepEqual(scope.keys, ['holding.AAPL']);
    assert.ok(scope.tags.includes('portfolio:holdings'));

    const envPath = join(home, '.uomp', 'sessions', `${JSON.parse(runCli(home, ['sessions', '--json']).stdout)[0].sessionId}.env`);
    assert.ok(existsSync(envPath));
    assert.match(readFileSync(envPath, 'utf-8'), /export UOM_TOKEN='eyJ/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('--allow-high grants all keys under the named high-sensitivity tag', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-high-tag-'));
  const agent = join(home, 'agent');
  createAgent(agent, { tags: ['portfolio:holdings'] });
  seed(home, [
    { key: 'holding.AAPL', value: { symbol: 'AAPL' }, tags: ['portfolio:holdings'], sensitivity: 'high', source: 'user' },
    { key: 'holding.MSFT', value: { symbol: 'MSFT' }, tags: ['portfolio:holdings'], sensitivity: 'high', source: 'user' },
  ]);

  try {
    const result = runCli(home, [
      'connect', agent,
      '--scope', 'portfolio:holdings',
      '--allow-high', 'portfolio:holdings',
      '--no-server',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /High-sensitivity override/);
    assert.deepEqual(grantedScopes(home).keys.sort(), ['holding.AAPL', 'holding.MSFT']);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('manifest keys are scoped to the selected tags', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-manifest-keys-'));
  const agent = join(home, 'agent');
  createAgent(agent, {
    tags: ['notes/projects'],
    keys: ['note.projects.plan', 'note.journal.private'],
  });
  seed(home, [
    { key: 'note.projects.plan', value: { title: 'Plan' }, tags: ['notes/projects'], sensitivity: 'low', source: 'user' },
    { key: 'note.journal.private', value: { title: 'Private' }, tags: ['notes/journal'], sensitivity: 'low', source: 'user' },
  ]);

  try {
    const result = runCli(home, [
      'connect', agent,
      '--scope', 'notes/projects',
      '--no-server',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(grantedScopes(home).keys, ['note.projects.plan']);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('high-sensitivity items under a non-keyword tag still need explicit keys', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-high-data-'));
  const agent = join(home, 'agent');
  createAgent(agent, { tags: ['health'] });
  seed(home, [
    { key: 'health.checkup', value: { title: 'Annual checkup' }, tags: ['health'], sensitivity: 'high', source: 'user' },
  ]);

  try {
    const denied = runCli(home, [
      'connect', agent,
      '--scope', 'health',
      '--no-server',
    ]);
    assert.equal(denied.status, 1);
    assert.match(denied.stderr, /High-sensitivity tags require explicit keys/);

    const allowed = runCli(home, [
      'connect', agent,
      '--scope', 'health',
      '--allow-key', 'health.checkup',
      '--no-server',
    ]);
    assert.equal(allowed.status, 0, allowed.stderr);
    assert.deepEqual(grantedScopes(home).keys, ['health.checkup']);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('--allow-high rejects a non-high-sensitivity tag', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-high-invalid-tag-'));
  const agent = join(home, 'agent');
  createAgent(agent, { tags: ['notes/projects'] });

  try {
    const result = runCli(home, [
      'connect', agent,
      '--scope', 'notes/projects',
      '--allow-high', 'notes/projects',
      '--no-server',
    ]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /only applies to high-sensitivity tags/);
    assert.deepEqual(readdirSync(join(home, '.uomp', 'sessions')), []);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('--allow-key rejects keys that are not in the local store', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-high-invalid-key-'));
  const agent = join(home, 'agent');
  createAgent(agent, { tags: ['notes/projects'] });

  try {
    const result = runCli(home, [
      'connect', agent,
      '--scope', 'notes/projects',
      '--allow-key', 'missing.key',
      '--no-server',
    ]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /Key not found in the local memory store/);
    assert.deepEqual(readdirSync(join(home, '.uomp', 'sessions')), []);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
