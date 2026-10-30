import { Command } from 'commander';
import chalk from 'chalk';
import { UompConfig } from '../config.js';
import { AuthService } from '@uomp/auth';
import { MemoryGuard } from '@uomp/guard';
import { JWTTokenIssuer } from '@uomp/token';
import {
  formatClock,
  formatDateTime,
  formatRemaining,
  formatScopes,
  sanitizeText,
} from '../utils/format.js';
import { removeSessionEnvFiles } from '../utils/session-files.js';

export class SessionsCommands {
  private static async getServices(): Promise<{ config: UompConfig; auth: AuthService; guard: MemoryGuard }> {
    const config = new UompConfig();
    await config.init();
    const issuer = new JWTTokenIssuer();
    await issuer.loadOrGenerateKey(config.secretsDir);
    const auth = new AuthService({ dbPath: config.authDbPath, issuer, adminToken: config.adminToken });
    const guard = new MemoryGuard({ dbPath: config.auditDbPath, memoryDbPath: config.memoryDbPath, issuer });
    return { config, auth, guard };
  }

  static list(): Command {
    return new Command('list')
      .description('List active sessions')
      .option('-a, --all', 'Include closed sessions')
      .option('--json', 'Output JSON')
      .action(async (options: { all?: boolean; json?: boolean }) => {
        const { auth, guard } = await this.getServices();
        try {
          const sessions = auth.listSessions({ includeClosed: options.all });
          const views = sessions.map(session => {
            const remaining = formatRemaining(session.expiresAt);
            const status = session.status === 'active' && remaining === 'expired'
              ? 'expired'
              : session.status;
            const lastAccess = guard.getLastAccessForSession(session.sessionId);

            return {
              sessionId: session.sessionId,
              agentId: session.agentId,
              agentName: session.agentName,
              status,
              createdAt: session.createdAt,
              expiresAt: session.expiresAt,
              closedAt: session.closedAt,
              remaining,
              grantedScopes: session.grantedScopes,
              lastAccess: lastAccess
                ? {
                    at: lastAccess.timestamp,
                    action: lastAccess.action,
                    target: lastAccess.endpoint,
                    allowed: lastAccess.allowed,
                    reason: lastAccess.reason,
                  }
                : null,
            };
          }).filter(view => options.all || view.status === 'active');

          if (views.length === 0) {
            if (options.json) {
              console.log('[]');
            } else {
              console.log(chalk.gray('No sessions found.'));
            }
            return;
          }

          if (options.json) {
            console.log(JSON.stringify(views, null, 2));
            return;
          }

          const heading = options.all ? 'All sessions' : 'Active sessions';
          console.log(`${chalk.bold(heading)} ${chalk.gray(`(${views.length})`)}`);

          for (const view of views) {
            const agent = view.agentName
              ? `${sanitizeText(view.agentName)} (${sanitizeText(view.agentId)})`
              : sanitizeText(view.agentId);
            const status = colorStatus(view.status);
            const suffix = view.status === 'active' ? chalk.gray(` · ${view.remaining}`) : '';

            console.log('');
            console.log(`${chalk.cyan(view.sessionId)}  ${agent}  ${status}${suffix}`);
            console.log(`  ${chalk.gray('scope')}    ${formatScopes(view.grantedScopes)}`);
            console.log(`  ${chalk.gray('expires')}  ${formatDateTime(view.expiresAt)}`);

            if (view.closedAt) {
              console.log(`  ${chalk.gray('closed')}   ${formatDateTime(view.closedAt)}`);
            }

            if (view.lastAccess) {
              const outcome = view.lastAccess.allowed ? chalk.green('allowed') : chalk.red('denied');
              const target = view.lastAccess.target ? ` ${sanitizeText(view.lastAccess.target)}` : '';
              const when = formatClock(view.lastAccess.at);
              console.log(`  ${chalk.gray('last')}     ${outcome} ${view.lastAccess.action}${target} · ${when}`);
            }
          }
        } finally {
          auth.close();
          guard.close();
        }
      });
  }

  static revoke(): Command {
    return new Command('revoke')
      .description('Revoke a session')
      .argument('<sessionId>', 'Session ID')
      .action(async (sessionId: string) => {
        const { config, auth, guard } = await this.getServices();
        try {
          const session = auth.revokeSession(sessionId);
          if (session) {
            console.log(chalk.green(`Revoked session: ${sessionId}`));
            console.log(chalk.gray("The agent's next request will fail with 403."));

            for (const envPath of await removeSessionEnvFiles(config.sessionsDir, sessionId)) {
              console.log(chalk.gray(`Removed env file: ${envPath}`));
            }
          } else {
            console.log(chalk.red('Session not found'));
            process.exitCode = 1;
          }
        } finally {
          auth.close();
          guard.close();
        }
      });
  }
}

function colorStatus(status: string): string {
  if (status === 'active') return chalk.green(status);
  if (status === 'expired' || status === 'revoked') return chalk.red(status);
  return chalk.gray(status);
}
