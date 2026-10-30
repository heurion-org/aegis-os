import { resolve } from 'path';
import chalk from 'chalk';
import { IdentityVerifier } from '@uomp/identity';
import { loadManifest } from '../utils/manifest.js';
import { inferSensitivity } from '@uomp/core';
import { LocalRegistry } from '../utils/registry.js';
import type { UompConfig } from '../config.js';

export class DiscoverCommands {
  private config: UompConfig;

  constructor(config: UompConfig) {
    this.config = config;
  }

  async discover(agentRef: string): Promise<void> {
    let agentPath = agentRef;

    if (agentRef.startsWith('registry://')) {
      const id = agentRef.replace('registry://', '');
      const registry = new LocalRegistry(this.config.registryDir);
      const entry = await registry.get(id);
      if (!entry) {
        console.log(chalk.red(`Agent ${id} not found in local registry`));
        return;
      }
      console.log(chalk.bold(`Agent: ${entry.name ?? entry.id} v${entry.version}`));
      console.log(`Publisher: ${entry.publisher ?? 'Unknown'} ${entry.verified ? chalk.green('[verified]') : chalk.yellow('[unverified]')}`);
      console.log(`Description: ${entry.description ?? 'No description'}`);
      console.log(`Source: ${entry.sourceUrl ?? 'N/A'}`);
      if (entry.tags && entry.tags.length > 0) {
        console.log(`Tags: ${entry.tags.join(', ')}`);
      }
      return;
    }

    const resolvedPath = resolve(agentPath);
    const manifest = await loadManifest(resolvedPath);

    if (!manifest) {
      console.log(chalk.red(`Could not find uom.json in ${resolvedPath}`));
      return;
    }

    const verifier = new IdentityVerifier();
    const verification = await verifier.verifyManifest(manifest);

    console.log(chalk.bold(`Agent: ${manifest.agent.name} v${manifest.agent.version}`));
    console.log(`ID: ${manifest.agent.id}`);
    console.log(`Publisher: ${manifest.agent.publisher ?? 'Unknown'} ${verification.valid ? chalk.green(`[verified via ${verification.method}]`) : chalk.yellow('[unverified]')}`);
    console.log(`Description: ${manifest.agent.description ?? 'No description'}`);

    if (manifest.externalDataSources && manifest.externalDataSources.length > 0) {
      console.log(`External data sources: ${manifest.externalDataSources.join(', ')}`);
    }

    if (manifest.dataRetentionPolicy) {
      const rp = manifest.dataRetentionPolicy;
      const retentionLabel = rp.maxRetentionSeconds === 0 ? chalk.green('zero retention') :
        rp.maxRetentionSeconds <= 300 ? chalk.yellow(`${rp.maxRetentionSeconds}s`) :
        chalk.red(`${rp.maxRetentionSeconds}s`);
      console.log(chalk.bold(`\nData retention: ${retentionLabel}`));
      console.log(`  Method: ${rp.deletionMethod}`);
      if (rp.proofRequired) console.log(`  Requires deletion proof: ${chalk.yellow('yes')}`);
      if (rp.thirdPartySharing) console.log(`  ${chalk.red('May share data with third parties')}`);
      if (rp.description) console.log(`  ${rp.description}`);
    }

    console.log(chalk.bold('\nRequested scopes:'));
    const readTags = manifest.requestedScopes.read.tags;
    if (readTags.length === 0) {
      console.log('  (none)');
    } else {
      for (const tag of readTags) {
        const sensitivity = inferSensitivity(tag);
        const label = sensitivity === 'high' ? chalk.red('high') : sensitivity === 'medium' ? chalk.yellow('medium') : chalk.green('low');
        console.log(`  [${label}] ${tag}`);
      }
    }
  }
}
