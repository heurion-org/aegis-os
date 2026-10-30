import { Command } from 'commander';
import chalk from 'chalk';
import { spawn, execSync } from 'child_process';
import { existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { UompConfig } from '../config.js';

export class GatewayCommands {
  static start(): Command {
    return new Command('start')
      .description('Start the UOMP Gateway with optional Cloudflare Tunnel')
      .option('--no-tunnel', 'Disable Cloudflare Tunnel (Gateway only)')
      .option('--browser', 'Enable CORS for browser-based agents')
      .option('-p, --port <port>', 'Gateway HTTPS port', '9443')
      .option('--host <host>', 'Gateway bind host', '0.0.0.0')
      .action(async (options) => {
        const repoRoot = join(import.meta.dirname, '..', '..', '..', '..');

        // Ensure certs exist
        const certDir = join(homedir(), '.uomp', '.gateway-certs');
        if (!existsSync(join(certDir, 'gateway.crt'))) {
          console.log(chalk.yellow('No Gateway certs found. Generating...'));
          const script = join(repoRoot, 'scripts', 'generate-gateway-certs.sh');
          if (existsSync(script)) {
            execSync(`bash "${script}"`, { stdio: 'inherit', env: { ...process.env, HOME: homedir() } });
          }
        }

        console.log(chalk.cyan('Starting UOMP Gateway...'));
        console.log(chalk.gray(`Port: ${options.port}`));

        const gatewayPath = join(repoRoot, 'apps', 'gateway', 'dist', 'index.js');

        const env: Record<string, string> = {
          ...process.env,
          UOMP_GATEWAY_PORT: options.port,
          UOMP_GATEWAY_HOST: options.host,
          UOMP_GATEWAY_TUNNEL: options.tunnel !== false ? 'true' : 'false',
          UOMP_GATEWAY_BROWSER: options.browser ? 'true' : 'false',
        } as Record<string, string>;

        const child = spawn('node', [gatewayPath], {
          stdio: 'inherit',
          env,
          cwd: repoRoot,
        });

        child.on('exit', (code) => {
          process.exit(code ?? 1);
        });

        process.on('SIGINT', () => { child.kill('SIGINT'); });
        process.on('SIGTERM', () => { child.kill('SIGTERM'); });
      });
  }

  static status(): Command {
    return new Command('status')
      .description('Check Gateway status')
      .action(async () => {
        const config = new UompConfig();
        await config.init();

        const url = process.env.UOMP_GATEWAY_ENDPOINT || 'https://localhost:9443';
        try {
          const resp = await fetch(`${url.replace(/\/$/, '')}/v1/health`, { signal: AbortSignal.timeout(5000) });
          const data = await resp.json() as { status: string; audience: string };
          console.log(chalk.green('Gateway is running'));
          console.log(`  URL: ${url}`);
          console.log(`  Status: ${data.status}`);
          console.log(`  Audience: ${data.audience}`);
        } catch {
          console.log(chalk.red('Gateway is not accessible'));
          console.log(chalk.gray(`  Tried: ${url}/v1/health`));
          console.log(chalk.gray('  Start with: uomp gateway start'));
        }
      });
  }
}
