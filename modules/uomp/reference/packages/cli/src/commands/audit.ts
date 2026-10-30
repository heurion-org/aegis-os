import { Command } from 'commander';
import chalk from 'chalk';
import { UompConfig } from '../config.js';
import { MemoryGuard } from '@uomp/guard';
import { JWTTokenIssuer } from '@uomp/token';
import { formatClock, sanitizeText } from '../utils/format.js';

export class AuditCommands {
  private static async getGuard(): Promise<MemoryGuard> {
    const config = new UompConfig();
    await config.init();
    const issuer = new JWTTokenIssuer();
    await issuer.loadOrGenerateKey(config.secretsDir);
    return new MemoryGuard({ dbPath: config.auditDbPath, memoryDbPath: config.memoryDbPath, issuer });
  }

  static list(): Command {
    return new Command('list')
      .description('List audit logs')
      .option('-s, --session <sessionId>', 'Filter by session ID')
      .option('-a, --agent <agentId>', 'Filter by agent ID')
      .option('--since <time>', 'Only entries since 15m, 24h, 7d, or an ISO date')
      .option('--result <result>', 'Filter by result: allow or deny')
      .option('-k, --key <key>', 'Filter by memory key')
      .option('-l, --limit <number>', 'Limit number of results', '50')
      .option('--json', 'Output JSON')
      .action(async (options: {
        session?: string;
        agent?: string;
        since?: string;
        result?: string;
        key?: string;
        limit?: string;
        json?: boolean;
      }) => {
        const limit = parseLimit(options.limit);
        if (limit === null) {
          process.exitCode = 1;
          return;
        }

        const since = parseSince(options.since);
        if (since === null) {
          process.exitCode = 1;
          return;
        }

        const allowed = parseResult(options.result);
        if (allowed === null) {
          process.exitCode = 1;
          return;
        }

        const guard = await this.getGuard();
        try {
          const logs = guard.getAuditLogs({
            sessionId: options.session,
            agentId: options.agent,
            since,
            allowed,
            key: options.key,
            limit,
          });

          if (options.json) {
            console.log(JSON.stringify(logs, null, 2));
            return;
          }

          if (logs.length === 0) {
            console.log(chalk.gray('No audit logs found.'));
            return;
          }

          const filters = [
            options.since ? `since ${options.since}` : null,
            options.result ? `result ${options.result}` : null,
            options.key ? `key ${options.key}` : null,
          ].filter(Boolean);

          console.log(
            `${chalk.bold('Audit log')} ${chalk.gray(`(${logs.length})`)}` +
            (filters.length > 0 ? chalk.gray(` · ${filters.join(' · ')}`) : '')
          );

          for (const log of logs) {
            const outcome = (log.allowed ? 'allow' : 'deny').padEnd(5);
            const outcomeLabel = log.allowed ? chalk.green(outcome) : chalk.red(outcome);
            const action = log.action.padEnd(6);
            const agent = sanitizeText(log.agentId);
            const target = log.key
              ? sanitizeText(log.key)
              : log.tags && log.tags.length > 0
                ? `tag:${log.tags.map(sanitizeText).join(',')}`
                : '-';

            console.log('');
            console.log(`${chalk.gray(formatClock(log.timestamp))}  ${outcomeLabel}  ${action} ${agent}  ${target}`);
            console.log(`  ${chalk.gray(sanitizeText(log.sessionId))} · ${sanitizeText(log.reason)}`);
          }
        } finally {
          guard.close();
        }
      });
  }
}

function parseLimit(value?: string): number | null {
  const limit = Number(value ?? '50');
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
    console.log(chalk.red(`Invalid limit "${value}". Use a number between 1 and 1000.`));
    return null;
  }
  return limit;
}

function parseSince(value?: string): string | undefined | null {
  if (!value) return undefined;

  const duration = /^(\d+)(m|h|d)$/.exec(value);
  if (duration) {
    const amount = Number(duration[1]);
    const unit = duration[2];
    const multiplier = unit === 'm' ? 60_000 : unit === 'h' ? 3_600_000 : 86_400_000;
    return new Date(Date.now() - amount * multiplier).toISOString();
  }

  const date = new Date(value);
  if (!Number.isNaN(date.getTime())) {
    return date.toISOString();
  }

  console.log(chalk.red(`Invalid --since "${value}". Use 15m, 24h, 7d, or an ISO date.`));
  return null;
}

function parseResult(value?: string): boolean | undefined | null {
  if (!value) return undefined;
  if (value === 'allow') return true;
  if (value === 'deny') return false;

  console.log(chalk.red(`Invalid --result "${value}". Use "allow" or "deny".`));
  return null;
}
