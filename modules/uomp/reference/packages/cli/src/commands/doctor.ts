import { Command } from 'commander';
import chalk from 'chalk';
import { existsSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { spawnSync } from 'child_process';
import { ADMIN_TOKEN_FILE_NAME, PRIVATE_KEY_FILE_NAME } from '@uomp/core';
import { AuthService } from '@uomp/auth';
import { MemoryGuard } from '@uomp/guard';
import { MemoryStore } from '@uomp/store';
import { JWTTokenIssuer } from '@uomp/token';
import { UompConfig } from '../config.js';
import { isPortAvailable } from '../utils/server.js';

type CheckStatus = 'ok' | 'warn' | 'fail';

interface DoctorCheck {
  name: string;
  status: CheckStatus;
  detail: string;
  fix?: string;
}

interface DoctorSummary {
  ok: boolean;
  checks: DoctorCheck[];
}

export class DoctorCommands {
  static get(): Command {
    return new Command('doctor')
      .description('Check the local UOMP installation and runtime')
      .option('--json', 'Output JSON')
      .action(async (options: { json?: boolean }) => {
        const summary = await runDoctor(new UompConfig());

        if (options.json) {
          console.log(JSON.stringify(summary, null, 2));
        } else {
          printDoctor(summary);
        }

        if (!summary.ok) {
          process.exitCode = 1;
        }
      });
  }
}

async function runDoctor(config: UompConfig): Promise<DoctorSummary> {
  const checks: DoctorCheck[] = [];
  const add = (name: string, status: CheckStatus, detail: string, fix?: string) => {
    checks.push({ name, status, detail, ...(fix ? { fix } : {}) });
  };

  const nodeMajor = Number(process.versions.node.split('.')[0]);
  add(
    'Node.js',
    nodeMajor >= 22 ? 'ok' : 'fail',
    `${process.version}${nodeMajor >= 22 ? '' : ' (need >= 22)'}`,
    nodeMajor >= 22 ? undefined : 'Install Node.js 22 or newer.'
  );

  const git = spawnSync('git', ['--version'], { encoding: 'utf-8' });
  add(
    'git',
    git.status === 0 ? 'ok' : 'warn',
    git.status === 0 ? git.stdout.trim() : 'not found',
    git.status === 0 ? undefined : 'Install git if you use the one-command installer.'
  );

  if (!existsSync(config.dataDir)) {
    add('data directory', 'fail', `${config.dataDir} does not exist`, 'Run `uomp init`.');
    return summarize(checks);
  }

  add('data directory', 'ok', config.dataDir);
  checkMode(add, 'data directory permissions', config.dataDir, 0o700, 'warn');
  checkMode(add, 'secrets directory permissions', config.secretsDir, 0o700, 'warn');

  const adminTokenPath = join(config.secretsDir, ADMIN_TOKEN_FILE_NAME);
  checkFile(add, 'admin token', adminTokenPath, 'Run `uomp init` to create it.');
  if (existsSync(adminTokenPath)) {
    checkMode(add, 'admin token permissions', adminTokenPath, 0o600, 'warn');
  }

  const privateKeyPath = join(config.secretsDir, PRIVATE_KEY_FILE_NAME);
  checkFile(add, 'Ed25519 private key', privateKeyPath, 'Run `uomp serve` or `uomp authorize` to create it.');
  if (existsSync(privateKeyPath)) {
    checkMode(add, 'Ed25519 key permissions', privateKeyPath, 0o600, 'warn');
  }

  const sessionsDir = config.sessionsDir;
  if (existsSync(sessionsDir)) {
    checkMode(add, 'sessions directory permissions', sessionsDir, 0o700, 'warn');
    const envFiles = readdirSync(sessionsDir).filter(name => name.endsWith('.env'));
    const badModes = envFiles.filter(name => {
      const mode = statSync(join(sessionsDir, name)).mode & 0o777;
      return (mode & 0o077) !== 0;
    });
    add(
      'session env files',
      badModes.length === 0 ? 'ok' : 'warn',
      `${envFiles.length} file${envFiles.length === 1 ? '' : 's'}${badModes.length ? `, ${badModes.length} not 0600` : ''}`,
      badModes.length ? 'Run `chmod 600 ~/.uomp/sessions/*.env`.' : undefined
    );
  } else {
    add('sessions directory', 'warn', 'not created yet', 'Run `uomp init`.');
  }

  let issuer: JWTTokenIssuer | undefined;
  if (existsSync(privateKeyPath)) {
    issuer = new JWTTokenIssuer();
    await issuer.loadOrGenerateKey(config.secretsDir);
  }

  if (existsSync(config.memoryDbPath)) {
    try {
      const store = new MemoryStore({ dbPath: config.memoryDbPath });
      try {
        add('memory.db', 'ok', `${store.count()} items`);
      } finally {
        store.close();
      }
    } catch {
      add('memory.db', 'fail', 'could not open or read the database');
    }
  } else {
    add('memory.db', 'warn', 'not created yet', 'Run `uomp import` to create it.');
  }

  let activeSessions = 0;
  let expiredSessions = 0;
  let revokedSessions = 0;
  if (existsSync(config.authDbPath) && issuer) {
    try {
      const auth = new AuthService({
        dbPath: config.authDbPath,
        issuer,
        adminToken: 'doctor',
      });
      try {
        const now = Date.now();
        for (const session of auth.listSessions({ includeClosed: true })) {
          if (session.status === 'active' && new Date(session.expiresAt).getTime() <= now) {
            expiredSessions += 1;
          } else if (session.status === 'active') {
            activeSessions += 1;
          } else if (session.status === 'revoked') {
            revokedSessions += 1;
          }
        }
        add('auth.db', 'ok', `${activeSessions} active, ${expiredSessions} expired, ${revokedSessions} revoked`);
      } finally {
        auth.close();
      }
    } catch {
      add('auth.db', 'fail', 'could not open or read the database');
    }
  } else {
    add('auth.db', 'warn', 'not created yet', 'Run `uomp authorize` to create it.');
  }

  if (existsSync(config.auditDbPath) && existsSync(config.memoryDbPath) && issuer) {
    try {
      const guard = new MemoryGuard({
        dbPath: config.auditDbPath,
        memoryDbPath: config.memoryDbPath,
        issuer,
      });
      try {
        add('audit.db', 'ok', `${guard.countAuditLogs()} entries`);
      } finally {
        guard.close();
      }
    } catch {
      add('audit.db', 'fail', 'could not open or read the database');
    }
  } else {
    add('audit.db', 'warn', 'not created yet', 'Run `uomp audit` after an agent request.');
  }

  let serverRunning = false;
  try {
    const response = await fetch(`${config.serverUrl}/health`, {
      signal: AbortSignal.timeout(800),
    });
    if (response.ok) {
      const body = await response.json() as { service?: string };
      serverRunning = body.service === 'uomp';
    }
  } catch {
    // The port probe below distinguishes "not running" from "occupied".
  }

  if (serverRunning) {
    add('server', 'ok', `running at ${config.serverUrl}`);
  } else {
    try {
      const available = await isPortAvailable(config.port, config.host);
      if (available) {
        add('server', 'ok', 'not running (normal until `uomp serve` or `uomp authorize`)');
      } else {
        add('server', 'fail', `port ${config.port} is occupied by a non-UOMP process`);
      }
    } catch (error) {
      add('server', 'fail', error instanceof Error ? error.message : String(error));
    }
  }

  if (activeSessions > 0 && !serverRunning) {
    add('active sessions', 'warn', `${activeSessions} active but the server is not running`, 'Start it with `uomp serve`.');
  }
  if (expiredSessions > 0) {
    add('expired sessions', 'warn', `${expiredSessions} expired session record${expiredSessions === 1 ? '' : 's'}`, 'Inspect with `uomp sessions --all`.');
  }

  return summarize(checks);
}

function summarize(checks: DoctorCheck[]): DoctorSummary {
  return {
    ok: checks.every(check => check.status !== 'fail'),
    checks,
  };
}

function checkFile(
  add: (name: string, status: CheckStatus, detail: string, fix?: string) => void,
  name: string,
  path: string,
  fix: string
): void {
  add(name, existsSync(path) ? 'ok' : 'warn', existsSync(path) ? path : 'missing', existsSync(path) ? undefined : fix);
}

function checkMode(
  add: (name: string, status: CheckStatus, detail: string, fix?: string) => void,
  name: string,
  path: string,
  expected: number,
  status: CheckStatus
): void {
  if (!existsSync(path)) return;
  const mode = statSync(path).mode & 0o777;
  const actual = mode.toString(8).padStart(3, '0');
  const wanted = expected.toString(8).padStart(3, '0');
  add(
    name,
    (mode & 0o077) === 0 ? 'ok' : status,
    `${actual}${(mode & 0o077) === 0 ? '' : ` (recommended ${wanted})`}`,
    (mode & 0o077) === 0 ? undefined : `Run \`chmod ${wanted} ${path}\`.`
  );
}

function printDoctor(summary: DoctorSummary): void {
  console.log(chalk.bold('UOMP doctor'));
  console.log('');

  for (const check of summary.checks) {
    const icon = check.status === 'ok' ? chalk.green('✓') : check.status === 'warn' ? chalk.yellow('!') : chalk.red('✗');
    console.log(`  ${icon} ${check.name}: ${check.detail}`);
    if (check.fix) {
      console.log(chalk.gray(`      ${check.fix}`));
    }
  }

  const fails = summary.checks.filter(check => check.status === 'fail').length;
  const warnings = summary.checks.filter(check => check.status === 'warn').length;
  console.log('');
  if (fails === 0) {
    console.log(chalk.green(`No blocking issues.${warnings ? ` ${warnings} warning${warnings === 1 ? '' : 's'}.` : ''}`));
  } else {
    console.log(chalk.red(`${fails} blocking issue${fails === 1 ? '' : 's'} found.`));
  }
}
