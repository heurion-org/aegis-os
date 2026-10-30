import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { MemoryStore } from '../../packages/store/dist/index.js';

const CLI = new URL('../../packages/cli/dist/cli.js', import.meta.url).pathname;

function runCli(home, args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    env: { ...process.env, HOME: home },
    encoding: 'utf-8',
    timeout: 30_000,
  });
}

function createVault(root) {
  mkdirSync(join(root, 'projects', 'uomp'), { recursive: true });
  mkdirSync(join(root, 'journal'), { recursive: true });
  mkdirSync(join(root, '.obsidian'), { recursive: true });

  writeFileSync(join(root, 'projects', 'uomp', 'plan.md'), `---
title: "UOMP plan"
tags: [planning, product]
sensitivity: medium
---
# UOMP plan

Ship the CLI.
`);

  writeFileSync(join(root, 'journal', 'private.md'), `---
tags:
  - personal
---
Private note.
`);

  writeFileSync(join(root, '.obsidian', 'workspace.md'), 'not a note');
}

test('imports an Obsidian-style Markdown vault into the memory store', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-markdown-'));
  const vault = join(home, 'Vault');
  createVault(vault);

  t.after(() => rmSync(home, { recursive: true, force: true }));

  const first = runCli(home, ['import', vault]);
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, /Imported 2 notes/);
  assert.match(first.stdout, /new: 2/);

  const store = new MemoryStore({ dbPath: join(home, '.uomp', 'memory.db') });

  try {
    assert.equal(store.count(), 2, 'hidden .obsidian files must be skipped');

    const plan = store.get('note.projects.uomp.plan');
    assert.ok(plan, 'expected the nested note to be imported');
    assert.equal(plan.value.title, 'UOMP plan');
    assert.equal(plan.value.content, '# UOMP plan\n\nShip the CLI.');
    assert.deepEqual(plan.tags, [
      'notes',
      'notes/projects',
      'notes/projects/uomp',
      'planning',
      'product',
    ]);
    assert.equal(plan.sensitivity, 'medium');

    const journal = store.get('note.journal.private');
    assert.ok(journal, 'expected the journal note to be imported');
    assert.ok(journal.tags.includes('notes/journal'));
    assert.ok(journal.tags.includes('personal'));
  } finally {
    store.close();
  }

  const second = runCli(home, ['import', vault]);
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stdout, /updated: 2/);

  const afterSecond = new MemoryStore({ dbPath: join(home, '.uomp', 'memory.db') });
  try {
    assert.equal(afterSecond.count(), 2, 're-import must upsert, not duplicate');
  } finally {
    afterSecond.close();
  }
});

test('dry run reports new notes without writing them', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-markdown-dry-'));
  const vault = join(home, 'Vault');
  createVault(vault);

  t.after(() => rmSync(home, { recursive: true, force: true }));

  assert.equal(runCli(home, ['import', vault]).status, 0);

  writeFileSync(join(vault, 'projects', 'new.md'), 'A new note.\n');

  const dryRun = runCli(home, ['import', vault, '--dry-run']);
  assert.equal(dryRun.status, 0, dryRun.stderr);
  assert.match(dryRun.stdout, /would import 3 notes/);
  assert.match(dryRun.stdout, /new: 1/);
  assert.match(dryRun.stdout, /note\.projects\.new/);

  const store = new MemoryStore({ dbPath: join(home, '.uomp', 'memory.db') });
  try {
    assert.equal(store.count(), 2, 'dry run must not write to the store');
  } finally {
    store.close();
  }
});

test('imports a single Markdown file', async t => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-markdown-file-'));
  const file = join(home, 'standalone.md');
  writeFileSync(file, '# Standalone\n\nOne note.\n');

  t.after(() => rmSync(home, { recursive: true, force: true }));

  const result = runCli(home, ['import', file]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Imported 1 note/);

  const store = new MemoryStore({ dbPath: join(home, '.uomp', 'memory.db') });
  try {
    const note = store.get('note.standalone');
    assert.ok(note);
    assert.equal(note.value.title, 'Standalone');
    assert.deepEqual(note.tags, ['notes']);
  } finally {
    store.close();
  }
});
