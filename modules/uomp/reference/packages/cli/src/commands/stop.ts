import { Command } from 'commander';
import chalk from 'chalk';
import { UompConfig } from '../config.js';
import { getServerStatus, stopDetachedServer } from '../utils/server-process.js';

interface StopOptions {
  json?: boolean;
}

export class StopCommands {
  static get(): Command {
    return new Command('stop')
      .description('Stop the background UOMP server')
      .option('--json', 'Output JSON')
      .action(async (options: StopOptions) => {
        try {
          const config = new UompConfig();
          await config.init();
          const result = await stopDetachedServer(config);

          if (options.json) {
            console.log(JSON.stringify(result, null, 2));
            return;
          }

          if (result.stopped) {
            console.log(chalk.green(`Stopped UOMP server${result.pid ? ` (pid ${result.pid})` : ''}.`));
            console.log(chalk.gray('Sessions remain active; use `uomp revoke <id>` or `uomp disconnect <client>`.'));
            return;
          }

          const status = await getServerStatus(config);
          if (status.running && !status.managed) {
            console.log(chalk.yellow(
              `No managed background server. A UOMP server is running on ${status.url}; ` +
              'stop it from the terminal where you started it.'
            ));
            return;
          }

          console.log(chalk.gray('No background UOMP server is running.'));
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });
  }
}
