import { Command } from 'commander';
import chalk from 'chalk';
import { mkdtemp, mkdir, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { UompConfig } from '../config.js';
import { MemoryStore } from '@uomp/store';
import { importMarkdown } from '../utils/markdown.js';
import { buildReadScope, type Scopes } from '@uomp/core';
import {
  createUompRuntime,
  findAvailablePort,
  startUompServer,
  type ServerStartResult,
  type UompRuntime,
} from '../utils/server.js';

interface DemoOptions {
  json?: boolean;
  keep?: boolean;
}

interface DemoSummary {
  ok: true;
  importedNotes: number;
  sessionId: string;
  url: string;
  allowedKey: string;
  deniedKey: string;
  auditEntries: number;
  revoked: boolean;
  dataDir: string | null;
  keptRoot: string | null;
}

export class DemoCommands {
  static get(): Command {
    return new Command('demo')
      .description('Run an isolated end-to-end demo (no real ~/.uomp data)')
      .option('--json', 'Output JSON')
      .option('--keep', 'Keep the temporary demo data directory')
      .action(async (options: DemoOptions) => {
        try {
          const summary = await runDemo(options);
          if (options.json) {
            console.log(JSON.stringify(summary, null, 2));
          }
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });
  }
}

async function runDemo(options: DemoOptions): Promise<DemoSummary> {
  const quiet = options.json === true;
  const root = await mkdtemp(join(tmpdir(), 'uomp-demo-'));
  const vault = join(root, 'vault');
  const dataDir = join(root, 'data');

  let runtime: UompRuntime | undefined;
  let server: ServerStartResult | undefined;

  try {
    await mkdir(join(vault, 'projects', 'uomp'), { recursive: true });
    await mkdir(join(vault, 'journal'), { recursive: true });
    await mkdir(dataDir, { recursive: true });

    await writeFile(join(vault, 'projects', 'uomp', 'plan.md'), [
      '---',
      'title: "UOMP plan"',
      'tags: [planning, product]',
      'sensitivity: medium',
      '---',
      '# UOMP plan',
      '',
      'Ship the CLI.',
      '',
    ].join('\n'));

    await writeFile(join(vault, 'journal', 'private.md'), [
      '---',
      'title: "Private journal"',
      'tags: [personal]',
      '---',
      'This note is outside the authorized scope.',
      '',
    ].join('\n'));

    const store = new MemoryStore({ dbPath: join(dataDir, 'memory.db') });
    let importedNotes: number;
    try {
      const imported = await importMarkdown(store, vault, { tag: 'notes' });
      importedNotes = imported.notes.length;
    } finally {
      store.close();
    }

    const port = await findAvailablePort();
    const config = new UompConfig({ dataDir, port });
    runtime = await createUompRuntime(config);

    const requestedScopes: Scopes = {
      read: {
        tags: ['notes/projects'],
        keys: [],
        denyTags: ['notes/journal'],
        denyKeys: [],
      },
      write: {
        tags: [],
        keys: [],
        denyTags: [],
        denyKeys: [],
      },
    };

    const session = runtime.auth.createSession({
      agent_id: 'demo-agent',
      agent_name: 'UOMP Demo Agent',
      requested_scopes: requestedScopes,
      duration_minutes: 5,
    });

    const grant = await runtime.auth.grantSession(session.sessionId, {
      read: buildReadScope(requestedScopes.read, ['notes/projects']),
      write: requestedScopes.write,
    });

    if (!grant) {
      throw new Error('Failed to grant the demo session.');
    }

    server = await startUompServer(runtime);
    if (server.status === 'in-use') {
      throw new Error(`Demo port ${port} is already in use.`);
    }

    const headers = { Authorization: `Bearer ${grant.token}` };
    const allowedKey = 'note.projects.uomp.plan';
    const deniedKey = 'note.journal.private';

    const allowedResponse = await fetch(`${server.url}/v1/memory/${allowedKey}`, { headers });
    const allowedBody = await readJson(allowedResponse);
    if (!allowedResponse.ok) {
      throw new Error(`Allowed read failed: ${allowedResponse.status}`);
    }

    const deniedResponse = await fetch(`${server.url}/v1/memory/${deniedKey}`, { headers });
    const deniedBody = await readJson(deniedResponse);
    if (deniedResponse.status !== 403) {
      throw new Error(`Denied read unexpectedly returned ${deniedResponse.status}.`);
    }

    runtime.auth.revokeSession(session.sessionId);
    const afterRevoke = await fetch(`${server.url}/v1/memory/${allowedKey}`, { headers });
    if (afterRevoke.status !== 403) {
      throw new Error(`Revoked read unexpectedly returned ${afterRevoke.status}.`);
    }

    const auditEntries = runtime.guard.countAuditLogs();

    if (!quiet) {
      console.log(chalk.bold('UOMP demo'));
      console.log(chalk.gray(`  isolated data: ${dataDir}`));
      console.log(chalk.green(`  ✓ imported ${importedNotes} notes`));
      console.log(chalk.green(`  ✓ granted ${session.sessionId} for notes/projects (5 min)`));
      console.log(`  ✓ allowed read: ${chalk.cyan(allowedKey)}`);
      console.log(chalk.gray(`    ${allowedBody.value?.title ?? 'note'}: ${firstLine(allowedBody.value?.content)}`));
      console.log(`  ✓ denied read: ${chalk.cyan(deniedKey)}`);
      console.log(chalk.gray(`    ${deniedBody.error?.message ?? 'ACCESS_DENIED'}`));
      console.log(`  ✓ audit entries: ${auditEntries}`);
      console.log(`  ✓ revoked: next request returned ${afterRevoke.status}`);
      console.log('');
      console.log(chalk.green('Demo complete. Your real ~/.uomp was not touched.'));
      if (options.keep) {
        console.log(chalk.gray(`  kept: ${root}`));
      }
    }

    return {
      ok: true,
      importedNotes,
      sessionId: session.sessionId,
      url: server.url,
      allowedKey,
      deniedKey,
      auditEntries,
      revoked: true,
      dataDir: options.keep ? dataDir : null,
      keptRoot: options.keep ? root : null,
    };
  } finally {
    server?.close();
    runtime?.close();
    if (!options.keep) {
      await rm(root, { recursive: true, force: true });
    }
  }
}

async function readJson(response: Response): Promise<any> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function firstLine(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value.split('\n').find(line => line.trim() && !line.trim().startsWith('#'))?.trim() ?? '';
}
