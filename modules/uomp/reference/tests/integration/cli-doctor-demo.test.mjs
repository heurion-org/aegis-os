import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const CLI = new URL('../../packages/cli/dist/cli.js', import.meta.url).pathname;

function runCli(home, args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
    encoding: 'utf-8',
    timeout: 30_000,
  });
}

test('demo runs the full loop against isolated data', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-demo-'));

  try {
    const result = runCli(home, ['demo', '--json']);
    assert.equal(result.status, 0, result.stderr);

    const summary = JSON.parse(result.stdout);
    assert.equal(summary.ok, true);
    assert.equal(summary.importedNotes, 2);
    assert.equal(summary.allowedKey, 'note.projects.uomp.plan');
    assert.equal(summary.deniedKey, 'note.journal.private');
    assert.equal(summary.revoked, true);
    assert.equal(summary.dataDir, null);
    assert.ok(summary.auditEntries >= 3);

    assert.equal(existsSync(join(home, '.uomp')), false, 'demo must not touch the real data directory');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('demo --keep leaves an isolated data directory', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-demo-keep-'));
  let keptDir = null;

  try {
    const result = runCli(home, ['demo', '--json', '--keep']);
    assert.equal(result.status, 0, result.stderr);

    const summary = JSON.parse(result.stdout);
    assert.equal(summary.ok, true);
    assert.ok(summary.dataDir, 'expected a kept data directory');
    assert.ok(summary.keptRoot, 'expected the temporary root to be kept');
    keptDir = summary.keptRoot;
    assert.ok(existsSync(keptDir));

    const sessionsDir = join(summary.dataDir, 'sessions');
    assert.equal(statSync(sessionsDir).mode & 0o777, 0o700);
  } finally {
    rmSync(home, { recursive: true, force: true });
    if (keptDir) rmSync(keptDir, { recursive: true, force: true });
  }
});

test('doctor reports missing initialization and passes after init', () => {
  const home = mkdtempSync(join(tmpdir(), 'uomp-cli-doctor-'));

  try {
    const before = runCli(home, ['doctor', '--json']);
    assert.equal(before.status, 1);
    const beforeSummary = JSON.parse(before.stdout);
    assert.equal(beforeSummary.ok, false);
    assert.ok(beforeSummary.checks.some(check => check.name === 'data directory' && check.status === 'fail'));

    const init = runCli(home, ['init']);
    assert.equal(init.status, 0, init.stderr);

    const after = runCli(home, ['doctor', '--json']);
    assert.equal(after.status, 0, after.stderr);
    const afterSummary = JSON.parse(after.stdout);
    assert.equal(afterSummary.ok, true);
    assert.ok(afterSummary.checks.every(check => check.status !== 'fail'));

    const dataDir = afterSummary.checks.find(check => check.name === 'data directory permissions');
    assert.equal(dataDir.status, 'ok');
    assert.equal(dataDir.detail, '700');

    const adminToken = afterSummary.checks.find(check => check.name === 'admin token permissions');
    assert.equal(adminToken.status, 'ok');
    assert.equal(adminToken.detail, '600');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
