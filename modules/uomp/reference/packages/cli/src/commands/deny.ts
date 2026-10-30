import { Command } from 'commander';
import chalk from 'chalk';
import { UompConfig } from '../config.js';
import { openAuthService } from '../utils/auth-service.js';

export class DenyCommands {
  static get(): Command {
    return new Command('deny')
      .description('Deny a pending consent request')
      .argument('<requestId>', 'Consent request ID')
      .action(async (requestId: string) => {
        try {
          const config = new UompConfig();
          await config.init();
          const auth = await openAuthService(config);
          try {
            const request = await auth.denyConsentRequest(requestId);
            if (!request) {
              console.log(chalk.red('Consent request not found or not pending'));
              process.exitCode = 1;
              return;
            }
            console.log(chalk.green(`Denied consent request: ${requestId}`));
            console.log(chalk.gray('The requested session was closed.'));
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
