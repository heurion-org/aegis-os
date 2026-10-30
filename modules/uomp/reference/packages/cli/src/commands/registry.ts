import { Command } from 'commander';
import chalk from 'chalk';
import { UompConfig } from '../config.js';
import { LocalRegistry } from '../utils/registry.js';
import { resolve } from 'path';
import { loadRawManifest } from '../utils/manifest.js';
import { createHash } from 'crypto';

export class RegistryCommands {
  private static getRegistry(config: UompConfig): LocalRegistry {
    return new LocalRegistry(config.registryDir);
  }

  static search(): Command {
    return new Command('search')
      .description('Search local registry')
      .argument('<keyword>', 'Search keyword')
      .action(async (keyword: string) => {
        const config = new UompConfig();
        await config.init();
        const registry = this.getRegistry(config);
        const results = await registry.search(keyword);

        if (results.length === 0) {
          console.log(chalk.gray('No agents found.'));
          return;
        }

        for (const agent of results) {
          const verified = agent.verified ? chalk.green('[verified]') : chalk.yellow('[unverified]');
          console.log(`${chalk.cyan(agent.id)} ${verified} v${agent.version}`);
          console.log(`  ${agent.name ?? agent.id}`);
          if (agent.description) console.log(`  ${agent.description}`);
          if (agent.tags) console.log(`  tags: ${agent.tags.join(', ')}`);
        }
      });
  }

  static list(): Command {
    return new Command('list')
      .description('List all agents in local registry')
      .action(async () => {
        const config = new UompConfig();
        await config.init();
        const registry = this.getRegistry(config);
        const results = await registry.list();

        if (results.length === 0) {
          console.log(chalk.gray('No agents in registry.'));
          return;
        }

        for (const agent of results) {
          const verified = agent.verified ? chalk.green('[verified]') : chalk.yellow('[unverified]');
          console.log(`${chalk.cyan(agent.id)} ${verified} v${agent.version}`);
        }
      });
  }

  static add(): Command {
    return new Command('add')
      .description('Add a local agent path to registry')
      .argument('<path>', 'Agent directory path')
      .action(async (agentPath: string) => {
        const config = new UompConfig();
        await config.init();
        const resolved = resolve(agentPath);
        const raw = await loadRawManifest(resolved);
        if (!raw || !raw.agent?.id) {
          console.log(chalk.red(`Could not find valid uom.json in ${resolved}`));
          return;
        }

        const checksum = createHash('sha256').update(JSON.stringify(raw)).digest('hex');
        const registry = this.getRegistry(config);
        await registry.add({
          id: raw.agent.id,
          version: String(raw.agent.version ?? '0.0.1'),
          name: raw.agent.name,
          description: raw.agent.description,
          publisher: raw.agent.publisher,
          sourceUrl: `file://${resolved}`,
          packageChecksum: `sha256:${checksum}`,
          tags: raw.requested_scopes?.read?.tags ?? [],
        });
        console.log(chalk.green(`Added ${raw.agent.id} to local registry`));
      });
  }

  static remove(): Command {
    return new Command('remove')
      .description('Remove an agent from local registry')
      .argument('<id>', 'Agent ID')
      .action(async (id: string) => {
        const config = new UompConfig();
        await config.init();
        const registry = this.getRegistry(config);
        const removed = await registry.remove(id);
        if (removed) {
          console.log(chalk.green(`Removed ${id} from registry`));
        } else {
          console.log(chalk.red('Agent not found'));
        }
      });
  }

  static install(): Command {
    return new Command('install')
      .description('Install an agent from registry (placeholder)')
      .argument('<agentId>', 'Agent ID')
      .action(async (agentId: string) => {
        console.log(chalk.yellow(`Installing ${agentId} from registry is not yet implemented. Use local path or registry add instead.`));
      });
  }
}
