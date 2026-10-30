import { Command } from 'commander';
import chalk from 'chalk';
import { AegisConsentBridge, HttpAegisMcpClient } from '@uomp/aegis-adapter';
import { UompConfig } from '../config.js';

interface ConsentRequest {
  requestId: string;
  agentId: string;
  requestedScopes: {
    read: { tags: string[]; keys: string[] };
  };
  expiresAt: string;
}

export class ApprovalsCommands {
  static get(): Command {
    const command = new Command('approvals')
      .description('Unified view of UOMP consent requests and Aegis escalations');

    command
      .option('--json', 'Print JSON')
      .action(async (options: { json?: boolean }) => {
        try {
          const config = await loadConfig();
          const uomp = await fetchUompRequests(config);
          const aegis = await fetchAegisEscalations();

          if (options.json) {
            process.stdout.write(`${JSON.stringify({ uomp, aegis }, null, 2)}\n`);
            return;
          }

          console.log(chalk.bold(`UOMP consent requests (${uomp.length})`));
          if (uomp.length === 0) console.log(chalk.gray('  none'));
          for (const request of uomp) {
            const scope = [...request.requestedScopes.read.tags, ...request.requestedScopes.read.keys].join(', ');
            console.log(`  ${chalk.bold(request.requestId)}  ${request.agentId}  ${scope}`);
            console.log(chalk.gray(`    expires ${request.expiresAt} · approve with: uomp approve ${request.requestId}`));
          }

          console.log('');
          console.log(chalk.bold(`Aegis escalations (${aegis.length})`));
          if (aegis.length === 0) console.log(chalk.gray('  none'));
          for (const escalation of aegis) {
            console.log(`  ${chalk.bold(escalation.escalation_id)}  ${escalation.agent_id}  ${escalation.action} → ${escalation.target_resource}`);
            console.log(chalk.gray(`    ${escalation.reason}`));
            console.log(chalk.gray(`    approve with: uomp approvals approve ${escalation.escalation_id}`));
          }
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });

    command
      .command('approve')
      .description('Approve an Aegis escalation (UOMP requests use `uomp approve`)')
      .argument('<id>', 'Escalation ID (esc-...)')
      .option('--ttl <seconds>', 'Lease TTL', '600')
      .action(async (id: string, options: { ttl: string }) => {
        try {
          if (!id.startsWith('esc-')) {
            console.log(chalk.yellow(`UOMP request ${id} must be approved with: uomp approve ${id}`));
            return;
          }
          const client = createAegisClient();
          if (!client) throw new Error('UOMP_AEGIS_MCP_URL and UOMP_AEGIS_TOKEN are required');
          const lease = await client.approveEscalation(id, Number(options.ttl));
          console.log(chalk.green(`Approved ${id}`));
          console.log(chalk.gray(`lease=${lease.lease_id} action=${lease.action_pattern} resource=${lease.resource_pattern}`));
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });

    command
      .command('deny')
      .description('Deny an Aegis escalation (UOMP requests use `uomp deny`)')
      .argument('<id>', 'Escalation ID (esc-...)')
      .action(async (id: string) => {
        try {
          if (!id.startsWith('esc-')) {
            console.log(chalk.yellow(`UOMP request ${id} must be denied with: uomp deny ${id}`));
            return;
          }
          const client = createAegisClient();
          if (!client) throw new Error('UOMP_AEGIS_MCP_URL and UOMP_AEGIS_TOKEN are required');
          await client.denyEscalation(id);
          console.log(chalk.green(`Denied ${id}`));
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });

    return command;
  }
}

async function loadConfig(): Promise<UompConfig> {
  const config = new UompConfig();
  await config.init();
  return config;
}

async function fetchUompRequests(config: UompConfig): Promise<ConsentRequest[]> {
  const response = await fetch(`${config.serverUrl}/v1/consent/requests?status=pending`, {
    headers: { 'x-uomp-admin-token': config.adminToken },
  });
  const body = await response.json() as ConsentRequest[] | { error?: { message?: string } };
  if (!response.ok) {
    throw new Error((body as { error?: { message?: string } }).error?.message ?? `HTTP ${response.status}`);
  }
  return body as ConsentRequest[];
}

function createAegisClient(): HttpAegisMcpClient | null {
  const endpoint = process.env.UOMP_AEGIS_MCP_URL;
  const token = process.env.UOMP_AEGIS_TOKEN;
  if (!endpoint || !token) return null;
  return new HttpAegisMcpClient({
    endpoint,
    token,
    orgId: process.env.UOMP_AEGIS_ORG ?? 'local',
    agentId: process.env.UOMP_AEGIS_AGENT ?? 'uomp',
  });
}

async function fetchAegisEscalations() {
  const client = createAegisClient();
  if (!client) return [];
  const bridge = new AegisConsentBridge(client);
  return bridge.listEscalations();
}
