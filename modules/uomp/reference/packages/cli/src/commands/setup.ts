import { Command } from 'commander';
import chalk from 'chalk';
import { join } from 'path';
import { DEFAULT_HOST, DEFAULT_PORT } from '@uomp/core';
import { UompConfig } from '../config.js';
import {
  buildMcpConfig,
  clientLabel,
  isConnectClient,
  upsertMcpClientConfig,
  type ConnectClient,
} from '../utils/mcp-config.js';
import { parseHost, parsePort } from '../utils/server.js';
import { startDetachedServer } from '../utils/server-process.js';
import { importVault } from '../utils/import-vault.js';

interface SetupOptions {
  vault?: string;
  vaultTag?: string;
  config?: string;
  port: string;
  host: string;
  server?: boolean;
  printConfig?: boolean;
  skipConfig?: boolean;
}

export class SetupCommands {
  static get(): Command {
    return new Command('setup')
      .description('Set up an MCP client once without granting any access')
      .argument('<client>', 'claude, cursor, or opencode')
      .option('--vault <path>', 'Import a Markdown vault or file')
      .option('--vault-tag <tag>', 'Base tag for --vault imports', 'notes')
      .option('--config <file>', 'Write the client config to a custom path')
      .option('-p, --port <port>', 'Local server port', String(DEFAULT_PORT))
      .option('--host <host>', 'Local server host', DEFAULT_HOST)
      .option('--no-server', 'Do not start the local Auth + Guard server')
      .option('--print-config', 'Print the client config JSON and exit')
      .option('--skip-config', 'Do not write the client config')
      .action(async (clientArg: string, options: SetupOptions) => {
        try {
          const client = parseClient(clientArg);
          const config = new UompConfig({
            port: parsePort(options.port),
            host: parseHost(options.host),
          });

          await config.init();
          if (options.vault) {
            await importVault(config, options.vault, options.vaultTag ?? 'notes');
          }

          const envPath = join(config.sessionsDir, `${client}.env`);
          const entryOptions = {
            onDemand: true,
            requestScopes: [],
            requestDuration: 30,
          };

          if (options.printConfig) {
            process.stdout.write(`${JSON.stringify(buildMcpConfig(client, envPath, entryOptions), null, 2)}\n`);
            return;
          }

          let serverNote = 'not started';
          if (options.server !== false) {
            const server = await startDetachedServer(config);
            if (server.status === 'started') {
              serverNote = `running in the background on ${server.url} (pid ${server.state.pid})`;
            } else if (server.status === 'running') {
              serverNote = `already running in the background on ${server.url}`;
            } else {
              serverNote = `already running on ${server.url}`;
            }
          }

          let configResult: Awaited<ReturnType<typeof upsertMcpClientConfig>> | undefined;
          if (!options.skipConfig) {
            configResult = await upsertMcpClientConfig(client, envPath, options.config, entryOptions);
          }

          console.log(chalk.green(`UOMP is set up for ${clientLabel(client)}.`));
          console.log(`  Server    ${serverNote}`);
          console.log(`  Env file  ${envPath}`);
          if (configResult) {
            console.log(`  Config    ${configResult.path}`);
            if (configResult.backupPath) {
              console.log(chalk.gray(`  Backup    ${configResult.backupPath}`));
            }
          } else {
            console.log(chalk.gray('  Client config skipped (--skip-config).'));
          }
          console.log('');
          console.log(chalk.bold('No access has been granted yet.'));
          if (options.server === false) {
            console.log(chalk.gray('Start the local server with: uomp start'));
          }
          console.log(`Open ${clientLabel(client)} and ask it to read your notes.`);
          console.log('The first request opens the local UOMP approval page.');
          console.log('');
          console.log(chalk.gray('If the page does not open:'));
          console.log(`  ${chalk.cyan('uomp pending')}`);
          console.log(`  ${chalk.cyan('uomp approve <request-id>')}`);
          console.log('');
          console.log(chalk.gray('Check access with: uomp status'));
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });
  }
}

function parseClient(value: string): ConnectClient {
  const client = value.toLowerCase();
  if (!isConnectClient(client)) {
    throw new Error(`Unknown client "${value}". Use claude, cursor, or opencode.`);
  }
  return client;
}
