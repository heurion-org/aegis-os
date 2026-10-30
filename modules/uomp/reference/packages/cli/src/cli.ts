#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { UompConfig } from './config.js';
import { MemoryCommands } from './commands/memory.js';
import { RegistryCommands } from './commands/registry.js';
import { RunCommands } from './commands/run.js';
import { SessionsCommands } from './commands/sessions.js';
import { AuditCommands } from './commands/audit.js';
import { AuthorizeCommands } from './commands/authorize.js';
import { DiscoverCommands } from './commands/discover.js';
import { ConnectCommands } from './commands/connect.js';
import { InspectCommands } from './commands/inspect.js';
import { ImportCommands } from './commands/import.js';
import { ServeCommands } from './commands/serve.js';
import { McpCommands } from './commands/mcp.js';
import { DemoCommands } from './commands/demo.js';
import { DoctorCommands } from './commands/doctor.js';
import { DisconnectCommands } from './commands/disconnect.js';
import { PendingCommands } from './commands/pending.js';
import { ApproveCommands } from './commands/approve.js';
import { DenyCommands } from './commands/deny.js';
import { StatusCommands } from './commands/status.js';
import { StopCommands } from './commands/stop.js';
import { StartCommands } from './commands/start.js';
import { SetupCommands } from './commands/setup.js';
import { StagedCommands } from './commands/staged.js';
import { PayloadCommands } from './commands/payload.js';
import { ApprovalsCommands } from './commands/approvals.js';
import { parseHost, parsePort } from './utils/server.js';

if (process.platform === 'win32') {
  console.error('UOMP supports macOS and Linux only. Windows is not supported.');
  process.exit(1);
}

const program = new Command();

program
  .name('uomp')
  .description('UOMP reference CLI (product entry: aegis-os memory)')
  .version('0.0.1');

program
  .command('init')
  .description('Initialize UOMP data directory')
  .action(async () => {
    const config = new UompConfig();
    await config.init();
    console.log(chalk.green(`UOMP initialized at ${config.dataDir}`));
  });

program
  .command('memory', { hidden: true })
  .description('Manage memory items')
  .addCommand(MemoryCommands.add())
  .addCommand(MemoryCommands.list())
  .addCommand(MemoryCommands.get())
  .addCommand(MemoryCommands.deleteCmd())
  .addCommand(MemoryCommands.importCmd());

// New generic import command (supersedes memory import for external data)
program.addCommand(ImportCommands.get());
program.addCommand(DemoCommands.get());

program
  .command('registry', { hidden: true })
  .description('Agent registry operations')
  .addCommand(RegistryCommands.search())
  .addCommand(RegistryCommands.list())
  .addCommand(RegistryCommands.add())
  .addCommand(RegistryCommands.remove())
  .addCommand(RegistryCommands.install());

program
  .command('discover <agent>', { hidden: true })
  .description('Discover an agent from a local path or registry://<id>')
  .action(async (agent: string) => {
    const config = new UompConfig();
    await config.init();
    const discover = new DiscoverCommands(config);
    await discover.discover(agent);
  });

program
  .command('inspect <agent>', { hidden: true })
  .description('Inspect an agent: verify identity, checksum, and cache manifest')
  .action(async (agent: string) => {
    const config = new UompConfig();
    await config.init();
    const inspector = new InspectCommands(config);
    await inspector.inspect(agent);
  });

program
  .command('authorize [agent]')
  .description('Authorize an agent, or a generic MCP client when no path is given')
  .option('-s, --scope <scopes...>', 'Read tags to grant; high-sensitivity keys still need explicit approval')
  .option('--allow-key <keys...>', 'Explicitly allow high-sensitivity keys (use with --scope)')
  .option('--allow-high <tags...>', 'Explicitly allow all keys under named high-sensitivity tags')
  .option('-o, --output <file>', 'Write the session env file to a custom path')
  .option('-d, --duration <minutes>', 'Session duration in minutes (1-1440)', '30')
  .option('-p, --port <port>', 'Local server port (default: 9374)')
  .option('--host <host>', 'Local server host (default: 127.0.0.1)')
  .option('--print-token', 'Print the capability token (it is also written to the env file)')
  .option('--no-server', 'Do not start the local Auth + Guard server')
  .action(async (agent: string | undefined, options: {
    scope?: string[];
    allowKey?: string[];
    allowHigh?: string[];
    output?: string;
    duration?: string;
    port?: string;
    host?: string;
    printToken?: boolean;
    server?: boolean;
  }) => {
    try {
      const config = new UompConfig({
        port: options.port ? parsePort(options.port) : undefined,
        host: options.host ? parseHost(options.host) : undefined,
      });
      const authorizer = new AuthorizeCommands(config);
      await authorizer.authorize(agent, {
        ...(options.scope ? { scope: options.scope } : {}),
        ...(options.allowKey ? { allowKeys: options.allowKey } : {}),
        ...(options.allowHigh ? { allowHigh: options.allowHigh } : {}),
        ...(options.output ? { output: options.output } : {}),
        ...(options.duration ? { duration: options.duration } : {}),
        ...(options.printToken ? { printToken: true } : {}),
        ...(options.server === false ? { server: false } : {}),
      });
    } catch (error) {
      console.error(chalk.red(error instanceof Error ? error.message : String(error)));
      process.exitCode = 1;
    }
  });

program.addCommand(ConnectCommands.get());
program.addCommand(SetupCommands.get());
program.addCommand(StagedCommands.get());
program.addCommand(PayloadCommands.get());
program.addCommand(ApprovalsCommands.get());
program.addCommand(ServeCommands.get());
program.addCommand(StartCommands.get());
program.addCommand(McpCommands.get());
program.addCommand(StatusCommands.get());
program.addCommand(StopCommands.get());
program.addCommand(DisconnectCommands.get());
program.addCommand(PendingCommands.get());
program.addCommand(ApproveCommands.get());
program.addCommand(DenyCommands.get());

program
  .command('sessions')
  .description('List active sessions')
  .option('-a, --all', 'Include closed sessions')
  .option('--json', 'Output JSON')
  .action(async (options: { all?: boolean; json?: boolean }) => {
    // Reuse the list command action manually
    const cmd = SessionsCommands.list();
    await cmd.parseAsync([
      'node',
      'uomp',
      ...(options.all ? ['--all'] : []),
      ...(options.json ? ['--json'] : []),
    ]);
  });

program
  .command('revoke <sessionId>')
  .description('Revoke a session and invalidate its token')
  .action(async (sessionId: string) => {
    const cmd = SessionsCommands.revoke();
    await cmd.parseAsync(['node', 'uomp', sessionId]);
  });

program
  .command('audit')
  .description('Show what agents read or attempted to read')
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
    const cmd = AuditCommands.list();
    await cmd.parseAsync([
      'node',
      'uomp',
      ...(options.session ? ['--session', options.session] : []),
      ...(options.agent ? ['--agent', options.agent] : []),
      ...(options.since ? ['--since', options.since] : []),
      ...(options.result ? ['--result', options.result] : []),
      ...(options.key ? ['--key', options.key] : []),
      ...(options.limit ? ['--limit', options.limit] : []),
      ...(options.json ? ['--json'] : []),
    ]);
  });

program.addCommand(DoctorCommands.get());

program
  .command('agent', { hidden: true })
  .description('Agent developer commands')
  .addCommand(new Command('run')
    .description('Run an agent as a child process (developer shortcut)')
    .argument('<agent>', 'Agent path')
    .option('-s, --scope <scopes...>', 'Additional read scopes')
    .action(async (agent: string, options: { scope?: string[] }) => {
      const config = new UompConfig();
      await config.init();
      const runner = new RunCommands(config);
      await runner.run(agent, options.scope ?? []);
    }));

program.addHelpText('after', `
Product entry:
  $ aegis-os memory ...   (delegates to this reference CLI during migration)

Fast path:
  $ uomp setup claude --vault ~/Obsidian/MyVault
  $ open Claude and ask it to read your notes
  $ uomp status

The first tool call opens the local UOMP approval page.

Manual / pre-authorize:
  $ uomp connect claude --vault ~/Obsidian/MyVault --scope notes/projects
  $ uomp connect ./my-agent --scope notes/projects
  $ uomp authorize --scope notes/projects --output ~/.uomp/sessions/client.env --no-server
  $ uomp mcp --session ~/.uomp/sessions/client.env --print-config

Manage access:
  $ uomp revoke <session-id>
  $ uomp staged list
  $ uomp staged approve <staged-write-id>
  $ uomp payload list
  $ uomp payload get <payload-id>
  $ uomp approvals
  $ uomp disconnect claude
  $ uomp stop

On-demand consent:
  $ uomp pending
  $ uomp approve <request-id>
  $ uomp deny <request-id>

Optional:
  $ uomp demo
  $ uomp init
  $ uomp doctor

Advanced commands (hidden): memory, registry, discover, inspect, agent
Run \`uomp help <command>\` for details.
`);

program.parse();
