import { spawn } from 'child_process';
import { readFile } from 'fs/promises';
import { join, resolve } from 'path';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { UompConfig } from '../config.js';
import { AuthService } from '@uomp/auth';
import { MemoryGuard } from '@uomp/guard';
import { JWTTokenIssuer } from '@uomp/token';
import { IdentityVerifier } from '@uomp/identity';
import type { AgentManifest, Scopes } from '@uomp/core';
import { buildReadScope, normalizeManifest } from '@uomp/core';
import { loadManifest } from '../utils/manifest.js';

export class RunCommands {
  private config: UompConfig;
  private issuer: JWTTokenIssuer;
  private authService: AuthService;
  private guard: MemoryGuard;

  constructor(config: UompConfig) {
    this.config = config;
    this.issuer = new JWTTokenIssuer();
    this.authService = new AuthService({
      dbPath: config.authDbPath,
      issuer: this.issuer,
      adminToken: config.adminToken,
    });
    this.guard = new MemoryGuard({
      dbPath: config.auditDbPath,
      memoryDbPath: config.memoryDbPath,
      issuer: this.issuer,
      sessionStateProvider: this.authService,
    });
  }

  async run(agentPath: string, additionalScopes: string[]): Promise<void> {
    await this.ensureKeyPair();

    const resolvedPath = resolve(agentPath);
    const manifest = await loadManifest(resolvedPath);

    if (!manifest) {
      console.log(chalk.red(`Could not find uom.json in ${resolvedPath}`));
      return;
    }

    // Verify identity
    const verifier = new IdentityVerifier();
    const verification = await verifier.verifyManifest(manifest);
    if (!verification.valid) {
      console.log(chalk.yellow(`Identity verification warning: ${verification.error}`));
    } else {
      console.log(chalk.green(`Identity verified via ${verification.method}`));
    }

    // Show authorization panel
    const grantedScopes = await this.promptForScopes(manifest, additionalScopes);

    // Create session
    const session = this.authService.createSession({
      agent_id: manifest.agent.id,
      agent_name: manifest.agent.name,
      requested_scopes: manifest.requestedScopes,
      duration_minutes: 30,
    });

    const grant = await this.authService.grantSession(session.sessionId, grantedScopes);
    if (!grant) {
      console.log(chalk.red('Failed to grant session'));
      return;
    }

    console.log(chalk.green(`Session granted: ${session.sessionId}`));
    console.log(chalk.gray(`Token expires at: ${grant.expiresAt}`));

    // Start server in background
    await this.startServer();

    // Start agent process
    const agentEntry = join(resolvedPath, 'index.js');
    console.log(chalk.blue(`Starting agent: ${agentEntry}`));

    const child = spawn('node', [agentEntry], {
      env: {
        ...process.env,
        UOM_TOKEN: grant.token,
        UOMP_BASE_URL: this.config.serverUrl,
      },
      stdio: 'inherit',
    });

    child.on('exit', async code => {
      console.log(chalk.gray(`Agent exited with code ${code}`));
      this.authService.closeSession(session.sessionId);
      this.authService.close();
      this.guard.close();
      process.exit(code ?? 0);
    });
  }

  private async ensureKeyPair(): Promise<void> {
    await this.issuer.loadOrGenerateKey(this.config.secretsDir);
  }

  private async promptForScopes(manifest: AgentManifest, additionalScopes: string[]): Promise<Scopes> {
    const readTags = [
      ...new Set([
        ...(manifest.requestedScopes.read.tags ?? []),
        ...additionalScopes,
      ]),
    ];

    console.log(chalk.bold(`\nAgent "${manifest.agent.name}" requests access to:`));
    console.log(`Description: ${manifest.agent.description ?? 'No description'}`);
    console.log(`Publisher: ${manifest.agent.publisher ?? 'Unknown'}`);

    if (readTags.length > 0) {
      const { selectedTags } = await inquirer.prompt([
        {
          type: 'checkbox',
          name: 'selectedTags',
          message: 'Select tags to authorize for reading:',
          choices: readTags.map(tag => ({ name: tag, value: tag, checked: true })),
        },
      ]);

      return {
        read: buildReadScope(manifest.requestedScopes.read, selectedTags as string[]),
        write: {
          tags: [],
          keys: [],
          denyTags: [],
          denyKeys: [],
        },
      };
    }

    return {
      read: { tags: [], keys: [], denyTags: [], denyKeys: [] },
      write: { tags: [], keys: [], denyTags: [], denyKeys: [] },
    };
  }

  private async startServer(): Promise<void> {
    const { serve } = await import('@hono/node-server');

    const authApp = this.authService.getApp();
    const guardApp = this.guard.getApp();

    // Combine auth and guard routes
    const combined = authApp;
    combined.route('/', guardApp);

    serve({
      fetch: combined.fetch,
      port: this.config.port,
      hostname: this.config.host,
    });

    console.log(chalk.gray(`UOMP server listening on ${this.config.serverUrl}`));
  }
}
