import { Command } from 'commander';
import chalk from 'chalk';
import { existsSync } from 'fs';
import { UompConfig } from '../config.js';
import { AuthService } from '@uomp/auth';
import { JWTTokenIssuer } from '@uomp/token';
import { formatDateTime, formatRemaining } from '../utils/format.js';
import { clientLabel, inspectMcpClientConfig, type ClientConfigStatus, type ConnectClient } from '../utils/mcp-config.js';
import { getServerStatus, type ServerStatus } from '../utils/server-process.js';
import { parseHost, parsePort } from '../utils/server.js';
import { expandSessionPath } from '../utils/session-files.js';

interface StatusOptions {
  json?: boolean;
  port?: string;
  host?: string;
}

interface SessionStatus {
  sessionId: string;
  agentId: string;
  agentName?: string;
  status: string;
  expiresAt: string;
  remaining: string;
}

export class StatusCommands {
  static get(): Command {
    return new Command('status')
      .description('Show the local server, active sessions, and client config status')
      .option('-p, --port <port>', 'Port of an unmanaged foreground server to probe')
      .option('--host <host>', 'Host of an unmanaged foreground server to probe')
      .option('--json', 'Output JSON')
      .action(async (options: StatusOptions) => {
        try {
          const config = new UompConfig({
            port: options.port ? parsePort(options.port) : undefined,
            host: options.host ? parseHost(options.host) : undefined,
          });
          await config.init();

          const server = await getServerStatus(config);
          const sessions = await listSessions(config);
          const clients = await Promise.all(
            (['claude', 'cursor', 'opencode'] as ConnectClient[])
              .map(client => inspectMcpClientConfig(client))
          );

          if (options.json) {
            console.log(JSON.stringify({ server, sessions, clients }, null, 2));
            return;
          }

          printServer(server);
          printSessions(sessions);
          printClients(clients);
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });
  }
}

async function listSessions(config: UompConfig): Promise<SessionStatus[]> {
  const issuer = new JWTTokenIssuer();
  await issuer.loadOrGenerateKey(config.secretsDir);

  const auth = new AuthService({
    dbPath: config.authDbPath,
    issuer,
    adminToken: config.adminToken,
  });

  try {
    return auth.listSessions({ includeClosed: false })
      .map(session => {
        const remaining = formatRemaining(session.expiresAt);
        const status = session.status === 'active' && remaining === 'expired'
          ? 'expired'
          : session.status;

        return {
          sessionId: session.sessionId,
          agentId: session.agentId,
          ...(session.agentName ? { agentName: session.agentName } : {}),
          status,
          expiresAt: session.expiresAt,
          remaining,
        };
      })
      .filter(session => session.status === 'active');
  } finally {
    auth.close();
  }
}

function printServer(server: ServerStatus): void {
  console.log(chalk.bold('UOMP status'));
  console.log('');
  console.log(chalk.bold('Server'));

  if (!server.running) {
    console.log(chalk.gray('  not running'));
    console.log(chalk.gray('  start with: uomp connect claude --scope <tag>'));
    console.log(chalk.gray('  or:         uomp start'));
    console.log('');
    return;
  }

  if (server.managed) {
    console.log(`  ${chalk.green('running in background')}  ${server.url}`);
    console.log(chalk.gray(`  pid ${server.pid} · log ${server.logPath}`));
    console.log(chalk.gray('  stop with: uomp stop'));
  } else {
    console.log(`  ${chalk.green('running')}  ${server.url}`);
    console.log(chalk.gray('  started outside uomp connect (foreground uomp serve)'));
  }
  console.log('');
}

function printSessions(sessions: SessionStatus[]): void {
  console.log(chalk.bold('Sessions'));

  if (sessions.length === 0) {
    console.log(chalk.gray('  no active sessions'));
    console.log('');
    return;
  }

  console.log(chalk.gray(`  active (${sessions.length})`));
  for (const session of sessions) {
    const agent = session.agentName
      ? `${session.agentName} (${session.agentId})`
      : session.agentId;
    console.log(`  ${chalk.cyan(session.sessionId)}  ${agent}`);
    console.log(chalk.gray(`    expires ${formatDateTime(session.expiresAt)} · ${session.remaining}`));
  }
  console.log('');
}

function printClients(clients: ClientConfigStatus[]): void {
  console.log(chalk.bold('Clients'));

  for (const client of clients) {
    const label = clientLabel(client.client).padEnd(15);
    if (client.error) {
      console.log(`  ${label} ${chalk.red('invalid config')}  ${client.error}`);
      continue;
    }

    if (!client.configured) {
      console.log(`  ${label} ${chalk.gray('not configured')}`);
      continue;
    }

    if (client.sessionPath && !existsSync(expandSessionPath(client.sessionPath))) {
      if (client.onDemand) {
        console.log(`  ${label} ${chalk.green('configured')}  on-demand, no active session`);
        continue;
      }
      console.log(`  ${label} ${chalk.yellow('configured')}  env missing: ${client.sessionPath}`);
      continue;
    }

    console.log(`  ${label} ${chalk.green('configured')}  ${client.sessionPath ?? client.path}`);
  }
}
