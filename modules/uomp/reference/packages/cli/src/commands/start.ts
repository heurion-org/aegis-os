import { Command } from 'commander';
import chalk from 'chalk';
import { DEFAULT_HOST, DEFAULT_PORT } from '@uomp/core';
import { UompConfig } from '../config.js';
import { startDetachedServer } from '../utils/server-process.js';
import { isLoopbackHost, parseHost, parsePort } from '../utils/server.js';

interface StartOptions {
  port: string;
  host: string;
}

export class StartCommands {
  static get(): Command {
    return new Command('start')
      .description('Start the local UOMP server in the background')
      .option('-p, --port <port>', 'Port to listen on', String(DEFAULT_PORT))
      .option('--host <host>', 'Host to bind to', DEFAULT_HOST)
      .action(async (options: StartOptions) => {
        try {
          const port = parsePort(options.port);
          const host = parseHost(options.host);
          const config = new UompConfig({ port, host });

          if (!isLoopbackHost(host)) {
            console.log(chalk.yellow(`Warning: ${host} exposes the UOMP server beyond localhost.`));
          }

          const result = await startDetachedServer(config);
          if (result.status === 'started') {
            console.log(chalk.green(`UOMP server started in the background on ${result.url}`));
            console.log(chalk.gray(`  pid ${result.state.pid}`));
            console.log(chalk.gray(`  log ${result.state.logPath}`));
            console.log(chalk.gray('Stop with: uomp stop'));
          } else if (result.status === 'running') {
            console.log(chalk.gray(`UOMP server is already running in the background on ${result.url}.`));
          } else {
            console.log(chalk.gray(`A UOMP server is already running on ${result.url}.`));
          }
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });
  }
}
