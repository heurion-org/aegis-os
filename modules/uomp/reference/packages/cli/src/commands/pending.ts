import { Command } from 'commander';
import chalk from 'chalk';
import { UompConfig } from '../config.js';
import { formatDateTime, formatScopes } from '../utils/format.js';
import { openAuthService } from '../utils/auth-service.js';

interface PendingOptions {
  all?: boolean;
  json?: boolean;
}

export class PendingCommands {
  static get(): Command {
    return new Command('pending')
      .description('List consent requests waiting for approval')
      .option('--all', 'Include approved, denied, and expired requests')
      .option('--json', 'Output JSON')
      .action(async (options: PendingOptions) => {
        try {
          const config = new UompConfig();
          await config.init();
          const auth = await openAuthService(config);

          try {
            const requests = options.all
              ? auth.listConsentRequests('pending')
                .concat(auth.listConsentRequests('approved'))
                .concat(auth.listConsentRequests('denied'))
                .concat(auth.listConsentRequests('expired'))
              : auth.listConsentRequests('pending');

            if (options.json) {
              console.log(JSON.stringify(requests, null, 2));
              return;
            }

            if (requests.length === 0) {
              console.log(chalk.gray('No pending consent requests.'));
              return;
            }

            console.log(chalk.bold(`Consent requests (${requests.length})`));
            for (const request of requests) {
              const label = request.client
                ? `${request.client} · ${request.agentId}`
                : request.agentId;
              console.log('');
              console.log(`${chalk.cyan(request.requestId)}  ${label}  ${statusLabel(request.status)}`);
              console.log(`  ${chalk.gray('scope')}    ${formatScopes(request.requestedScopes)}`);
              console.log(`  ${chalk.gray('expires')}  ${formatDateTime(request.expiresAt)}`);
              if (request.status === 'pending') {
                console.log(`  approve with: ${chalk.cyan(`uomp approve ${request.requestId}`)}`);
              }
            }
          } finally {
            auth.close();
          }
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });
  }
}

function statusLabel(status: string): string {
  if (status === 'pending') return chalk.yellow('pending');
  if (status === 'approved') return chalk.green('approved');
  return chalk.red(status);
}
