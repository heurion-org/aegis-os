import { Command } from 'commander';
import chalk from 'chalk';
import { existsSync } from 'fs';
import { readFile, rm } from 'fs/promises';
import { join, resolve, sep } from 'path';
import { UompConfig } from '../config.js';
import { AuthService } from '@uomp/auth';
import { JWTTokenIssuer } from '@uomp/token';
import {
  clientLabel,
  inspectMcpClientConfig,
  isConnectClient,
  removeMcpClientConfig,
  type ConnectClient,
} from '../utils/mcp-config.js';
import { readSessionIdFromEnv, removeSessionEnvFiles, expandSessionPath } from '../utils/session-files.js';

interface DisconnectOptions {
  config?: string;
  json?: boolean;
}

export class DisconnectCommands {
  static get(): Command {
    return new Command('disconnect')
      .description('Remove a client config entry and revoke its current UOMP session')
      .argument('<client>', 'claude, cursor, or opencode')
      .option('--config <file>', 'Client config path (defaults to the client\'s standard path)')
      .option('--json', 'Output JSON')
      .action(async (clientArg: string, options: DisconnectOptions) => {
        try {
          const client = parseClient(clientArg);
          const config = new UompConfig();
          await config.init();

          const status = await inspectMcpClientConfig(client, options.config);
          if (status.error) {
            throw new Error(status.error);
          }

          const envPath = expandSessionPath(status.sessionPath ?? join(config.sessionsDir, `${client}.env`));
          let sessionId: string | undefined;
          try {
            sessionId = readSessionIdFromEnv(await readFile(envPath, 'utf-8'));
          } catch {
            // The env file may be missing; the config entry can still be removed.
          }

          const revokedIds = await revokeClientSessions(config, client, sessionId);
          const sessionIds = sessionId ? [sessionId] : revokedIds;
          const removedEnvPaths: string[] = [];

          for (const id of sessionIds) {
            removedEnvPaths.push(...await removeSessionEnvFiles(config.sessionsDir, id));
          }

          if (sessionId && !isInside(config.sessionsDir, envPath) && existsSync(envPath)) {
            await rm(envPath, { force: true });
            removedEnvPaths.push(envPath);
          }

          const configResult = await removeMcpClientConfig(client, options.config);
          const result = {
            client,
            configPath: configResult.path,
            configRemoved: configResult.removed,
            ...(configResult.backupPath ? { backupPath: configResult.backupPath } : {}),
            sessionIds,
            revoked: revokedIds.length > 0,
            removedEnvPaths,
          };

          if (options.json) {
            console.log(JSON.stringify(result, null, 2));
            return;
          }

          const label = clientLabel(client);
          if (!configResult.removed && removedEnvPaths.length === 0 && sessionIds.length === 0) {
            console.log(chalk.gray(`Nothing to disconnect for ${label}.`));
            return;
          }

          console.log(chalk.green(`Disconnected ${label}.`));
          console.log(`  config  ${configResult.path}${configResult.removed ? '' : ' (no UOMP entry)'}`);
          if (configResult.backupPath) {
            console.log(chalk.gray(`  backup  ${configResult.backupPath}`));
          }
          for (const id of sessionIds) {
            const wasRevoked = revokedIds.includes(id);
            console.log(`  session ${id} ${wasRevoked ? chalk.green('revoked') : chalk.gray('not found')}`);
          }
          for (const path of removedEnvPaths) {
            console.log(chalk.gray(`  removed ${path}`));
          }
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

async function revokeClientSessions(
  config: UompConfig,
  client: ConnectClient,
  sessionId?: string
): Promise<string[]> {
  const issuer = new JWTTokenIssuer();
  await issuer.loadOrGenerateKey(config.secretsDir);

  const auth = new AuthService({
    dbPath: config.authDbPath,
    issuer,
    adminToken: config.adminToken,
  });

  try {
    if (sessionId) {
      return auth.revokeSession(sessionId) ? [sessionId] : [];
    }

    const active = auth.listSessions({ includeClosed: false })
      .filter(session => session.status === 'active' && session.agentId === `mcp-client-${client}`);

    const revoked: string[] = [];
    for (const session of active) {
      if (auth.revokeSession(session.sessionId)) {
        revoked.push(session.sessionId);
      }
    }
    return revoked;
  } finally {
    auth.close();
  }
}

function isInside(dir: string, path: string): boolean {
  const root = resolve(dir) + sep;
  return resolve(path).startsWith(root);
}
