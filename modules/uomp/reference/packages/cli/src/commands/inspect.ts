import { resolve } from 'path';
import chalk from 'chalk';
import { IdentityVerifier } from '@uomp/identity';
import { loadManifest, loadRawManifest } from '../utils/manifest.js';
import { LocalRegistry } from '../utils/registry.js';
import type { UompConfig } from '../config.js';
import { mkdir, writeFile } from 'fs/promises';

export class InspectCommands {
  private config: UompConfig;

  constructor(config: UompConfig) {
    this.config = config;
  }

  async inspect(agentRef: string): Promise<void> {
    let agentPath = agentRef;

    if (agentRef.startsWith('registry://')) {
      const id = agentRef.replace('registry://', '');
      const registry = new LocalRegistry(this.config.registryDir);
      const entry = await registry.get(id);
      if (!entry) {
        console.log(chalk.red(`Agent ${id} not found in local registry`));
        return;
      }
      console.log(chalk.yellow('Registry agent installation not yet implemented in MVP. Please install manually and use local path.'));
      return;
    }

    const resolvedPath = resolve(agentPath);
    const manifest = await loadManifest(resolvedPath);
    const raw = await loadRawManifest(resolvedPath);

    if (!manifest || !raw) {
      console.log(chalk.red(`Could not find uom.json in ${resolvedPath}`));
      return;
    }

    console.log(chalk.bold(`Inspecting agent: ${manifest.agent.name} v${manifest.agent.version}`));

    // Identity verification
    const verifier = new IdentityVerifier();
    const verification = await verifier.verifyManifest(manifest);
    if (!verification.valid) {
      console.log(chalk.yellow(`Identity verification warning: ${verification.error}`));
    } else {
      console.log(chalk.green(`Identity verified via ${verification.method}`));
    }

    // Package checksum (MVP: hash of uom.json)
    const { createHash } = await import('crypto');
    const checksum = createHash('sha256').update(JSON.stringify(raw)).digest('hex');
    const declaredChecksum = raw.package?.checksum;
    if (declaredChecksum) {
      if (declaredChecksum === `sha256:${checksum}` || declaredChecksum === checksum) {
        console.log(chalk.green(`Package checksum verified: ${checksum.slice(0, 16)}...`));
      } else {
        console.log(chalk.red('Package checksum mismatch'));
        return;
      }
    } else {
      console.log(chalk.gray(`Computed package checksum: ${checksum.slice(0, 16)}... (not declared in uom.json)`));
    }

    // Risk score
    const risk = this.assessRisk(manifest);
    console.log(chalk.bold('\nRisk summary:'));
    console.log(`  High sensitivity tags: ${risk.high}`);
    console.log(`  Medium sensitivity tags: ${risk.medium}`);
    console.log(`  External data sources: ${manifest.externalDataSources?.length ?? 0}`);
    console.log(`  Write permissions: ${manifest.requestedScopes.write.tags.length > 0 ? chalk.red('yes') : chalk.green('none')}`);
    if (manifest.dataRetentionPolicy) {
      const rp = manifest.dataRetentionPolicy;
      const rLabel = rp.maxRetentionSeconds === 0 ? chalk.green('zero retention') : chalk.yellow(`${rp.maxRetentionSeconds}s`);
      console.log(`  Data retention: ${rLabel} (${rp.deletionMethod})`);
      if (rp.thirdPartySharing) console.log(`  Third-party sharing: ${chalk.red('yes')}`);
    }
    console.log(`  Overall risk: ${this.riskLabel(risk.level)}`);

    // Cache manifest
    const cacheDir = `${this.config.agentsDir}/${manifest.agent.id}/${manifest.agent.version}`;
    await mkdir(cacheDir, { recursive: true });
    await writeFile(`${cacheDir}/uom.json`, JSON.stringify(raw, null, 2), 'utf-8');
    console.log(chalk.gray(`\nManifest cached to: ${cacheDir}`));

    console.log(chalk.green('\nInspection complete. Run `uomp connect <agent>` to grant access.'));
  }

  private assessRisk(manifest: import('@uomp/core').AgentManifest) {
    const tags = manifest.requestedScopes.read.tags;
    let high = 0;
    let medium = 0;
    let low = 0;
    for (const tag of tags) {
      if (tag.includes('holdings') || tag.includes('transactions')) high++;
      else if (tag.startsWith('profile:') || tag.includes('watchlist')) medium++;
      else low++;
    }

    let level: 'low' | 'medium' | 'high' = 'low';
    if (manifest.requestedScopes.write.tags.length > 0) level = 'high';
    else if (high > 0) level = 'high';
    else if (medium > 0) level = 'medium';

    return { high, medium, low, level };
  }

  private riskLabel(level: string): string {
    if (level === 'high') return chalk.red('high');
    if (level === 'medium') return chalk.yellow('medium');
    return chalk.green('low');
  }
}
