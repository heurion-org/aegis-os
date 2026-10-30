import { Command } from 'commander';
import chalk from 'chalk';
import { existsSync } from 'fs';
import { join, resolve } from 'path';
import { UompConfig } from '../config.js';
import { AuthorizeCommands } from './authorize.js';
import {
  buildMcpConfig,
  clientLabel,
  isConnectClient,
  printClientConfig,
  upsertMcpClientConfig,
  type ConnectClient,
} from '../utils/mcp-config.js';
import { parseHost, parsePort } from '../utils/server.js';
import { startDetachedServer } from '../utils/server-process.js';
import { MemoryStore } from '@uomp/store';
import { importMarkdown } from '../utils/markdown.js';
import { printMarkdownImportResult } from '../utils/import-output.js';

interface ConnectOptions {
  scope?: string[];
  allowKey?: string[];
  allowHigh?: string[];
  output?: string;
  duration?: string;
  port?: string;
  host?: string;
  server?: boolean;
  foreground?: boolean;
  printConfig?: boolean;
  skipConfig?: boolean;
  config?: string;
  printToken?: boolean;
  vault?: string;
  vaultTag?: string;
  onDemand?: boolean;
}

export class ConnectCommands {
  static get(): Command {
    return new Command('connect')
      .description('Connect an MCP client or agent package and grant a scoped session')
      .argument('<target>', 'claude, cursor, opencode, or a path to an agent package')
      .option('-s, --scope <scopes...>', 'Read tags to grant; high-sensitivity keys still need explicit approval')
      .option('--allow-key <keys...>', 'Explicitly allow high-sensitivity keys (use with --scope)')
      .option('--allow-high <tags...>', 'Explicitly allow all keys under named high-sensitivity tags')
      .option('-d, --duration <minutes>', 'Session duration in minutes (1-1440)', '30')
      .option('-o, --output <file>', 'Write the session env file to a custom path')
      .option('-p, --port <port>', 'Local server port (default: 9374)')
      .option('--host <host>', 'Local server host (default: 127.0.0.1)')
      .option('--no-server', 'Do not start the local Auth + Guard server')
      .option('--foreground', 'Keep the local server in this terminal instead of the background')
      .option('--print-config', 'Grant a session, print the MCP client config, and exit without writing the client config')
      .option('--skip-config', 'Do not write the MCP client config')
      .option('--config <file>', 'Write the MCP client config to a custom path')
      .option('--vault <path>', 'Import a Markdown vault or file before connecting')
      .option('--vault-tag <tag>', 'Base tag for --vault imports', 'notes')
      .option('--on-demand', 'Ask for consent on the first tool call instead of pre-authorizing')
      .option('--print-token', 'Print the capability token')
      .action(async (target: string, options: ConnectOptions) => {
        try {
          const resolved = resolveTarget(target);

          if (!resolved.client && options.config) {
            throw new Error('--config is only valid for Claude Desktop, Cursor, or OpenCode.');
          }

          const config = new UompConfig({
            port: options.port ? parsePort(options.port) : undefined,
            host: options.host ? parseHost(options.host) : undefined,
          });

          if (options.vault) {
            await importVault(config, options.vault, options.vaultTag ?? 'notes');
          }

          if (options.onDemand) {
            if (!resolved.client) {
              throw new Error('--on-demand is only available for Claude Desktop, Cursor, or OpenCode.');
            }
            await configureOnDemand(resolved.client, config, options);
            return;
          }

          const authorizer = new AuthorizeCommands(config);
          await authorizer.authorize(resolved.agentPath, {
            ...(options.scope ? { scope: options.scope } : {}),
            ...(options.allowKey ? { allowKeys: options.allowKey } : {}),
            ...(options.allowHigh ? { allowHigh: options.allowHigh } : {}),
            ...(options.output ? { output: options.output } : {}),
            ...(options.duration ? { duration: options.duration } : {}),
            ...(options.server === false ? { server: false } : {}),
            ...(options.foreground ? {} : { background: true }),
            ...(options.printToken ? { printToken: true } : {}),
            ...(resolved.client ? { client: resolved.client } : {}),
            ...(options.config ? { configPath: options.config } : {}),
            ...(options.printConfig ? { printConfig: true } : {}),
            ...(options.skipConfig ? { writeConfig: false } : {}),
          });
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });
  }
}

async function configureOnDemand(
  client: ConnectClient,
  config: UompConfig,
  options: ConnectOptions
): Promise<void> {
  if (!options.scope || options.scope.length === 0) {
    throw new Error('--on-demand requires --scope <tag...>.');
  }
  if (options.foreground) {
    throw new Error('--on-demand uses the background server. Use --no-server if you manage the server yourself.');
  }
  if (options.allowKey || options.allowHigh) {
    throw new Error('--allow-key/--allow-high belong to `uomp approve`, not `connect --on-demand`.');
  }
  if (options.printToken) {
    throw new Error('--print-token is not available in on-demand mode; the token is issued after approval.');
  }

  await config.init();
  const envPath = options.output
    ? resolve(options.output)
    : join(config.sessionsDir, `${client}.env`);
  const requestDuration = parseRequestDuration(options.duration);
  const entryOptions = {
    onDemand: true,
    requestScopes: options.scope,
    requestDuration,
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

  console.log(chalk.green(`On-demand consent configured for ${clientLabel(client)}.`));
  console.log(`  Env file  ${envPath}`);
  console.log(`  Server    ${serverNote}`);
  if (configResult) {
    console.log(`  Config    ${configResult.path}`);
    if (configResult.backupPath) {
      console.log(chalk.gray(`  Backup    ${configResult.backupPath}`));
    }
  } else {
    console.log(chalk.gray('  Client config skipped (--skip-config).'));
    console.log(chalk.gray('  Manual config:'));
    console.log(chalk.gray(`    ${JSON.stringify(buildMcpConfig(client, envPath, entryOptions), null, 2)}`));
  }
  console.log('');
  console.log(chalk.gray('The first tool call opens a local consent page. If it does not open, use:'));
  console.log(`  ${chalk.cyan('uomp pending')}`);
  console.log(`  ${chalk.cyan('uomp approve <request-id>')}`);
}

function parseRequestDuration(value?: string): number {
  const minutes = Number(value ?? '30');
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
    throw new Error(`Invalid duration "${value}". Use whole minutes between 1 and 1440.`);
  }
  return minutes;
}

async function importVault(config: UompConfig, target: string, tag: string): Promise<void> {
  await config.init();

  const store = new MemoryStore({ dbPath: config.memoryDbPath });
  try {
    const result = await importMarkdown(store, target, { tag });
    printMarkdownImportResult(result);

    if (result.notes.length === 0) {
      throw new Error(`No Markdown notes found under ${target}.`);
    }
  } finally {
    store.close();
  }
}

function resolveTarget(target: string): { client?: ConnectClient; agentPath?: string } {
  const candidate = resolve(target);

  if (existsSync(join(candidate, 'uom.json'))) {
    return { agentPath: candidate };
  }

  const normalized = target.toLowerCase();
  if (isConnectClient(normalized)) {
    return { client: normalized };
  }

  throw new Error(
    `Unknown target "${target}". Use claude, cursor, opencode, or a path that contains uom.json.`
  );
}
