import { Command } from 'commander';
import chalk from 'chalk';
import { writeFileSync } from 'fs';
import { UompConfig } from '../config.js';

interface PayloadMetadata {
  payload_id: string;
  session_id: string;
  agent_id: string;
  created_at: string;
  format?: string;
  size?: number;
  hash?: string;
}

export class PayloadCommands {
  static get(): Command {
    const command = new Command('payload')
      .description('Inspect encrypted Agent payloads');

    command
      .command('list')
      .description('List stored payloads')
      .action(async () => {
        try {
          const config = await loadConfig();
          const response = await fetch(`${config.serverUrl}/v1/payload`, {
            headers: { 'x-uomp-admin-token': config.adminToken },
          });
          const body = await response.json() as { payloads?: PayloadMetadata[]; error?: { message?: string } };
          if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
          const payloads = body.payloads ?? [];
          if (payloads.length === 0) {
            console.log(chalk.gray('No payloads stored.'));
            return;
          }
          for (const payload of payloads) {
            console.log(`${chalk.bold(payload.payload_id)}  ${payload.format ?? '-'}  ${payload.size ?? '-'} bytes`);
            console.log(chalk.gray(`  agent=${payload.agent_id} session=${payload.session_id} ${payload.hash ?? ''}`));
          }
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });

    command
      .command('get')
      .description('Fetch an encrypted payload envelope')
      .argument('<id>', 'Payload ID')
      .option('-o, --output <file>', 'Write the JSON envelope to a file')
      .action(async (id: string, options: { output?: string }) => {
        try {
          const config = await loadConfig();
          const response = await fetch(`${config.serverUrl}/v1/payload/${encodeURIComponent(id)}`, {
            headers: { 'x-uomp-admin-token': config.adminToken },
          });
          const body = await response.json() as Record<string, unknown> & { error?: { message?: string } };
          if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
          const json = JSON.stringify(body, null, 2);
          if (options.output) {
            writeFileSync(options.output, `${json}\n`, { mode: 0o600 });
            console.log(chalk.green(`Wrote ${id} to ${options.output}`));
          } else {
            process.stdout.write(`${json}\n`);
          }
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });

    command
      .command('delete')
      .description('Delete a stored payload')
      .argument('<id>', 'Payload ID')
      .action(async (id: string) => {
        try {
          const config = await loadConfig();
          const response = await fetch(`${config.serverUrl}/v1/payload/${encodeURIComponent(id)}`, {
            method: 'DELETE',
            headers: { 'x-uomp-admin-token': config.adminToken },
          });
          const body = await response.json() as { error?: { message?: string } };
          if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
          console.log(chalk.green(`Deleted payload ${id}.`));
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });

    return command;
  }
}

async function loadConfig(): Promise<UompConfig> {
  const config = new UompConfig();
  await config.init();
  return config;
}
