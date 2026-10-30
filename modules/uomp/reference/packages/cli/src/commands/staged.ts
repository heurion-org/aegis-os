import { Command } from 'commander';
import chalk from 'chalk';
import { UompConfig } from '../config.js';

interface StagedWrite {
  id: string;
  key: string;
  agentId: string;
  tags: string[];
  sensitivity: string;
  status: string;
  createdAt: string;
}

export class StagedCommands {
  static get(): Command {
    const command = new Command('staged')
      .description('Review Agent writes that are waiting for approval');

    command
      .command('list')
      .description('List staged writes')
      .option('--status <status>', 'pending, approved, or denied', 'pending')
      .action(async (options: { status: string }) => {
        try {
          const config = await loadConfig();
          const response = await fetch(`${config.serverUrl}/v1/staged-writes?status=${encodeURIComponent(options.status)}`, {
            headers: { 'x-uomp-admin-token': config.adminToken },
          });
          const body = await response.json() as { staged_writes?: StagedWrite[]; error?: { message?: string } };
          if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
          const writes = body.staged_writes ?? [];
          if (writes.length === 0) {
            console.log(chalk.gray(`No ${options.status} staged writes.`));
            return;
          }
          for (const write of writes) {
            console.log(`${chalk.bold(write.id)}  ${write.key}`);
            console.log(chalk.gray(`  agent=${write.agentId} tags=${write.tags.join(', ') || '-'} sensitivity=${write.sensitivity} status=${write.status}`));
          }
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });

    command
      .command('approve')
      .description('Approve a staged write and apply it to the memory store')
      .argument('<id>', 'Staged write ID')
      .action(async (id: string) => {
        await review('approve', id);
      });

    command
      .command('deny')
      .description('Deny a staged write without changing the memory store')
      .argument('<id>', 'Staged write ID')
      .action(async (id: string) => {
        await review('deny', id);
      });

    return command;
  }
}

async function loadConfig(): Promise<UompConfig> {
  const config = new UompConfig();
  await config.init();
  return config;
}

async function review(action: 'approve' | 'deny', id: string): Promise<void> {
  try {
    const config = await loadConfig();
    const response = await fetch(`${config.serverUrl}/v1/staged-writes/${encodeURIComponent(id)}/${action}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-uomp-admin-token': config.adminToken,
      },
      body: JSON.stringify({ reviewed_by: 'cli' }),
    });
    const body = await response.json() as { status?: string; error?: { message?: string } };
    if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
    console.log(chalk.green(`${action === 'approve' ? 'Approved' : 'Denied'} staged write ${id}.`));
  } catch (error) {
    console.error(chalk.red(error instanceof Error ? error.message : String(error)));
    process.exitCode = 1;
  }
}
