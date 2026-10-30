import { join, resolve } from 'path';
import { existsSync } from 'fs';
import { rm, readFile } from 'fs/promises';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { UompConfig } from '../config.js';
import { MemoryStore } from '@uomp/store';
import { IdentityVerifier } from '@uomp/identity';
import { loadManifest } from '../utils/manifest.js';
import type { AgentManifest, MemoryItem, ScopeAction, Scopes, Sensitivity } from '@uomp/core';
import { buildReadScope, inferSensitivity, normalizeManifest, DEFAULT_PORT } from '@uomp/core';
import {
  createUompRuntime,
  installShutdownHandlers,
  isLoopbackHost,
  startUompServer,
  type ServerStartResult,
  type UompRuntime,
} from '../utils/server.js';
import { startDetachedServer, stopDetachedServer, type StartDetachedResult } from '../utils/server-process.js';
import { formatDateTime, formatScopes, sanitizeText } from '../utils/format.js';
import { writeSessionEnvFile } from '../utils/session-env-file.js';
import {
  clientLabel,
  printClientConfig,
  upsertMcpClientConfig,
  type ClientConfigResult,
  type ConnectClient,
} from '../utils/mcp-config.js';

export interface AuthorizeOptions {
  scope?: string[];
  output?: string;
  duration?: string;
  server?: boolean;
  printToken?: boolean;
  client?: ConnectClient;
  configPath?: string;
  printConfig?: boolean;
  writeConfig?: boolean;
  background?: boolean;
  allowKeys?: string[];
  allowHigh?: string[];
}

export class AuthorizeCommands {
  private config: UompConfig;

  constructor(config: UompConfig) {
    this.config = config;
  }

  async authorize(agentPath: string | undefined, options: AuthorizeOptions): Promise<void> {
    const durationMinutes = parseDuration(options.duration);
    const client = options.client;
    await this.config.init();

    const resolvedPath = agentPath ? resolve(agentPath) : undefined;
    let manifest: AgentManifest;

    if (resolvedPath && client) {
      throw new Error('Pass either an MCP client name or an agent path, not both.');
    }

    if (options.printConfig && !client) {
      throw new Error('--print-config requires an MCP client target.');
    }

    if (resolvedPath) {
      const loaded = await loadManifest(resolvedPath);
      if (!loaded) {
        throw new Error(`Could not find uom.json in ${resolvedPath}`);
      }
      manifest = loaded;
    } else {
      if (!options.scope || options.scope.length === 0) {
        throw new Error(
          client
            ? 'Pass --scope when connecting an MCP client.'
            : 'Pass --scope when authorizing a generic MCP client, or provide an agent path.'
        );
      }
      manifest = genericMcpManifest(client);
    }

    const verification = await new IdentityVerifier().verifyManifest(manifest);
    const identity = verification.valid
      ? chalk.green(`verified via ${verification.method}`)
      : manifest.identity
        ? chalk.yellow(`unverified (${sanitizeText(verification.error ?? 'unknown error')})`)
        : chalk.gray('unsigned (no identity proof)');

    const grantedScopes = options.scope && options.scope.length > 0
      ? await this.buildScopesFromTags(manifest, options.scope, options)
      : await this.promptForScopes(manifest, [], options);

    const runtime = await createUompRuntime(this.config);
    const session = runtime.auth.createSession({
      agent_id: manifest.agent.id,
      agent_name: manifest.agent.name,
      requested_scopes: manifest.requestedScopes,
      duration_minutes: durationMinutes,
    });

    const grant = await runtime.auth.grantSession(session.sessionId, grantedScopes);
    if (!grant) {
      runtime.close();
      throw new Error('Failed to grant session');
    }

    const envPath = options.output
      ? resolve(options.output)
      : client
        ? join(this.config.sessionsDir, `${client}.env`)
        : join(this.config.sessionsDir, `${session.sessionId}.env`);

    await this.revokePreviousSession(runtime, envPath);

    try {
      await writeSessionEnvFile(envPath, {
        sessionId: session.sessionId,
        agentId: manifest.agent.id,
        expiresAt: grant.expiresAt,
        token: grant.token,
        baseUrl: this.config.serverUrl,
      });
    } catch (error) {
      await this.abortSession(runtime, session.sessionId);
      throw error;
    }

    if (options.printConfig && client) {
      printClientConfig(client, envPath);
      process.stderr.write(`\nSession ${session.sessionId} granted for ${durationMinutes} min.\n`);
      process.stderr.write(`Env file: ${envPath}\n`);
      process.stderr.write('Start the UOMP server before using the client: ' + this.serveCommand() + '\n');
      runtime.close();
      return;
    }

    let server: ServerStartResult | undefined;
    let detached: StartDetachedResult | undefined;
    if (options.server !== false) {
      if (options.background) {
        try {
          detached = await startDetachedServer(this.config);
        } catch (error) {
          await this.abortSession(runtime, session.sessionId, envPath);
          throw error;
        }
      } else {
        try {
          server = await startUompServer(runtime);
        } catch (error) {
          await this.abortSession(runtime, session.sessionId, envPath);
          throw error;
        }

        if (server.status === 'in-use' && !server.isUomp) {
          await this.abortSession(runtime, session.sessionId, envPath, server);
          throw new Error(
            `Port ${this.config.port} is in use by another process. The session was revoked. ` +
            `Stop it, then run \`uomp serve --port ${this.config.port}\` and authorize or connect again.`
          );
        }
      }
    }

    let clientConfig: ClientConfigResult | undefined;
    if (client && options.writeConfig !== false) {
      try {
        clientConfig = await upsertMcpClientConfig(client, envPath, options.configPath);
      } catch (error) {
        if (detached?.status === 'started') {
          await stopDetachedServer(this.config).catch(() => {});
        }
        await this.abortSession(runtime, session.sessionId, envPath, server);
        throw error;
      }
    }

    this.printSummary({
      manifest,
      ...(resolvedPath ? { agentPath: resolvedPath } : {}),
      sessionId: session.sessionId,
      expiresAt: grant.expiresAt,
      durationMinutes,
      scopes: grantedScopes,
      identity,
      envPath,
      token: grant.token,
      printToken: options.printToken === true,
      ...(client ? { client } : {}),
      ...(clientConfig ? { clientConfig } : {}),
    });

    if (detached) {
      runtime.close();
      console.log('');
      if (detached.status === 'started') {
        console.log(chalk.green(`UOMP server started in the background on ${detached.url}`));
        console.log(chalk.gray(`  pid ${detached.state.pid}`));
        console.log(chalk.gray(`  log ${detached.state.logPath}`));
        console.log(chalk.gray('Stop with: uomp stop'));
      } else if (detached.status === 'running') {
        console.log(chalk.gray(`UOMP server is already running in the background on ${detached.url}.`));
      } else {
        console.log(chalk.gray(`A UOMP server is already running on ${detached.url}.`));
      }
      if (!isLoopbackHost(this.config.host)) {
        console.log(chalk.yellow(`Warning: ${this.config.host} exposes the UOMP server beyond localhost.`));
      }
      return;
    }

    if (!server) {
      runtime.close();
      console.log('');
      console.log(chalk.gray('Server not started (--no-server).'));
      console.log(chalk.gray(client
        ? `Start it when the client is ready: ${this.serveCommand()}`
        : `Start it when the Agent is ready: ${this.serveCommand()}`));
      return;
    }

    if (server.status === 'in-use') {
      runtime.close();
      console.log('');
      console.log(chalk.gray(`A UOMP server is already running on ${server.url}.`));
      return;
    }

    console.log('');
    console.log(chalk.green(`UOMP server listening on ${server.url}`));
    if (!isLoopbackHost(this.config.host)) {
      console.log(chalk.yellow(`Warning: ${this.config.host} exposes the UOMP server beyond localhost.`));
    }
    console.log(chalk.gray('Keep this terminal open. Press Ctrl+C to stop.'));
    installShutdownHandlers(() => server.close());
  }

  private async promptForScopes(
    manifest: AgentManifest,
    additionalScopes: string[],
    options: AuthorizeOptions
  ): Promise<Scopes> {
    const readTags = [
      ...new Set([
        ...(manifest.requestedScopes.read.tags ?? []),
        ...additionalScopes,
      ]),
    ];

    if (readTags.length === 0) {
      return emptyScopes();
    }

    const store = new MemoryStore({ dbPath: this.config.memoryDbPath });
    try {
      const sensitivities = new Map(readTags.map(tag => [tag, this.tagSensitivity(store, tag)]));

      console.log(chalk.bold(`\nAgent "${sanitizeText(manifest.agent.name)}" requests access to:`));
      console.log(`  Publisher: ${sanitizeText(manifest.agent.publisher ?? 'Unknown')}`);
      console.log(`  ${sanitizeText(manifest.agent.description ?? 'No description')}`);

      for (const tag of readTags) {
        const sensitivity = sensitivities.get(tag) ?? 'low';
        const levelLabel = sensitivity === 'high'
          ? chalk.red('high')
          : sensitivity === 'medium'
            ? chalk.yellow('medium')
            : chalk.green('low');
        console.log(`  [${levelLabel}] ${sanitizeText(tag)}`);

        if (sensitivity === 'high') {
          const fields = manifest.requestedScopes.read.fields?.[tag];
          const purpose = manifest.requestedScopes.read.purposes?.[tag];
          if (fields && fields.length > 0) {
            console.log(`      Fields: ${fields.join(', ')}`);
          }
          if (purpose) {
            console.log(`      Purpose: ${purpose}`);
          }
        }
      }

      if (readTags.some(tag => sensitivities.get(tag) === 'high')) {
        console.log(chalk.gray('\nHigh-sensitivity tags are unchecked by default. Selecting one asks you to approve keys individually.'));
      }

      const { selectedTags } = await inquirer.prompt([
        {
          type: 'checkbox',
          name: 'selectedTags',
          message: 'Select tags to authorize for reading:',
          choices: readTags,
          default: readTags.filter(tag => sensitivities.get(tag) !== 'high'),
        },
      ]);

      const selected = selectedTags as string[];
      this.validateKeyOverrides(store, selected, options);
      const highTags = selected.filter(tag =>
        sensitivities.get(tag) === 'high' && !(options.allowHigh ?? []).includes(tag)
      );
      const promptedKeys = await this.promptForHighKeys(store, highTags);
      const readScope: ScopeAction = buildReadScope(manifest.requestedScopes.read, selected);
      readScope.keys = this.resolveReadKeys(store, manifest, selected, options, promptedKeys);

      return {
        read: readScope,
        write: emptyScopes().write,
      };
    } finally {
      store.close();
    }
  }

  private async buildScopesFromTags(
    manifest: AgentManifest,
    tags: string[],
    options: AuthorizeOptions
  ): Promise<Scopes> {
    const store = new MemoryStore({ dbPath: this.config.memoryDbPath });
    try {
      this.validateKeyOverrides(store, tags, options);
      if (options.allowHigh?.length) {
        console.log(chalk.yellow(
          `High-sensitivity override: granting all keys under ${options.allowHigh.join(', ')}.`
        ));
      }
      const highTags = tags.filter(tag => this.tagSensitivity(store, tag) === 'high');
      let promptedKeys: string[] = [];

      if (highTags.length > 0 && !options.allowHigh?.length && !options.allowKeys?.length) {
        if (!process.stdin.isTTY) {
          throw new Error(
            `High-sensitivity tags require explicit keys: ${highTags.join(', ')}. ` +
            'Run interactively, or pass --allow-key <key...> / --allow-high <tag...>.'
          );
        }
        promptedKeys = await this.promptForHighKeys(store, highTags);
      }

      const readScope: ScopeAction = buildReadScope(manifest.requestedScopes.read, tags);
      readScope.keys = this.resolveReadKeys(store, manifest, tags, options, promptedKeys);

      return {
        read: readScope,
        write: emptyScopes().write,
      };
    } finally {
      store.close();
    }
  }

  private async promptForHighKeys(store: MemoryStore, highTags: string[]): Promise<string[]> {
    if (highTags.length === 0) return [];

    const selectedKeys: string[] = [];
    for (const tag of highTags) {
      const items = store.getByTag(tag);
      console.log(chalk.bold(`\nHigh-sensitivity tag: ${sanitizeText(tag)}`));

      if (items.length === 0) {
        console.log(chalk.gray('  No items under this tag.'));
        continue;
      }

      console.log(chalk.gray('  High-sensitivity items are never granted by tag alone. Select keys explicitly:'));
      const { keys } = await inquirer.prompt([
        {
          type: 'checkbox',
          name: 'keys',
          message: `Select keys to expose from ${sanitizeText(tag)}:`,
          choices: items.map(item => ({
            name: `${sanitizeText(item.key)} — ${describeItem(item)}`,
            value: item.key,
          })),
          default: [],
        },
      ]);

      if (keys.length === 0) {
        console.log(chalk.yellow(`  No keys selected; high-sensitivity items under ${tag} will be denied.`));
      }
      selectedKeys.push(...keys as string[]);
    }

    return selectedKeys;
  }

  private validateKeyOverrides(store: MemoryStore, tags: string[], options: AuthorizeOptions): void {
    for (const tag of options.allowHigh ?? []) {
      if (!tags.includes(tag)) {
        throw new Error(`--allow-high tag is not in the selected scope: ${tag}`);
      }
      if (this.tagSensitivity(store, tag) !== 'high') {
        throw new Error(`--allow-high only applies to high-sensitivity tags: ${tag}`);
      }
    }

    for (const key of options.allowKeys ?? []) {
      if (!store.get(key)) {
        throw new Error(`Key not found in the local memory store: ${key}`);
      }
    }
  }

  private resolveReadKeys(
    store: MemoryStore,
    manifest: AgentManifest,
    selectedTags: string[],
    options: AuthorizeOptions,
    promptedKeys: string[]
  ): string[] {
    const keys = new Set<string>();
    const selected = new Set(selectedTags);

    for (const key of options.allowKeys ?? []) {
      keys.add(key);
    }

    for (const tag of options.allowHigh ?? []) {
      for (const item of store.getByTag(tag)) {
        keys.add(item.key);
      }
    }

    for (const key of promptedKeys) {
      keys.add(key);
    }

    // Manifest keys are only granted when their item is under a selected tag.
    // High-sensitivity items still require an explicit key selection.
    for (const key of manifest.requestedScopes.read.keys ?? []) {
      const item = store.get(key);
      if (!item) continue;
      if (!item.tags.some(tag => selected.has(tag))) continue;
      if (item.sensitivity === 'high') continue;
      keys.add(key);
    }

    return [...keys];
  }

  private tagSensitivity(store: MemoryStore, tag: string): Sensitivity {
    const inferred = inferSensitivity(tag);
    if (inferred === 'high') return 'high';

    const items = store.getByTag(tag);
    if (items.some(item => item.sensitivity === 'high')) return 'high';
    if (items.some(item => item.sensitivity === 'medium')) return 'medium';
    return inferred;
  }

  private async abortSession(
    runtime: UompRuntime,
    sessionId: string,
    envPath?: string,
    server?: ServerStartResult
  ): Promise<void> {
    try {
      runtime.auth.revokeSession(sessionId);
    } catch {
      // Keep the original error; the session will expire on its own.
    }
    server?.close();
    runtime.close();

    if (!envPath) return;

    try {
      await rm(envPath, { force: true });
    } catch {
      // The env file may not exist yet.
    }
  }

  private serveCommand(): string {
    return this.config.port === DEFAULT_PORT
      ? 'uomp serve'
      : `uomp serve --port ${this.config.port}`;
  }

  private async revokePreviousSession(runtime: UompRuntime, envPath: string): Promise<void> {
    try {
      const content = await readFile(envPath, 'utf-8');
      const match = /^# UOMP session (\S+)$/m.exec(content);
      if (match) {
        runtime.auth.revokeSession(match[1]);
      }
    } catch {
      // No existing env file, or it does not contain a session header.
    }
  }

  private printSummary(input: {
    manifest: AgentManifest;
    agentPath?: string;
    sessionId: string;
    expiresAt: string;
    durationMinutes: number;
    scopes: Scopes;
    identity: string;
    envPath: string;
    token: string;
    printToken: boolean;
    client?: ConnectClient;
    clientConfig?: ClientConfigResult;
  }): void {
    const { manifest, agentPath, sessionId, expiresAt, durationMinutes, scopes, envPath } = input;

    console.log(chalk.green(`Session granted: ${sessionId}`));
    console.log(`  Agent     ${sanitizeText(manifest.agent.name)} (${sanitizeText(manifest.agent.id)})`);
    console.log(`  Scope     ${formatScopes(scopes)}`);
    console.log(`  Expires   ${formatDateTime(expiresAt)} (${durationMinutes} min)`);
    console.log(`  Identity  ${input.identity}`);
    console.log('');

    if (input.client) {
      const label = clientLabel(input.client);

      console.log(chalk.bold('Session env'));
      console.log(`  ${envPath}`);
      console.log('');

      console.log(chalk.bold(`${label} config`));
      if (input.clientConfig) {
        console.log(`  ${input.clientConfig.path}`);
        if (input.clientConfig.action === 'unchanged') {
          console.log(chalk.gray('  already up to date'));
        } else {
          console.log(chalk.gray(`  ${input.clientConfig.action}`));
        }
        if (input.clientConfig.backupPath) {
          console.log(chalk.gray(`  backup: ${input.clientConfig.backupPath}`));
        }
      } else {
        console.log(chalk.gray('  skipped (--skip-config)'));
        console.log(chalk.gray(
          `  manual: uomp mcp --session ${shellQuote(envPath)} --print-config --client ${input.client}`
        ));
      }
      console.log('');

      const firstTag = scopes.read.tags[0];
      if (input.clientConfig && input.clientConfig.action !== 'unchanged') {
        console.log(chalk.bold(`Restart ${label}`));
        console.log(firstTag
          ? `  Then ask: "List notes under ${sanitizeText(firstTag)}"`
          : '  Then ask the client to list memory.');
      } else if (input.clientConfig) {
        console.log(chalk.bold('Client config unchanged'));
        console.log('  No restart needed; the next tool call picks up the new token.');
      } else {
        console.log(chalk.bold('Manual client config'));
        console.log(chalk.gray('  Restart the client after adding the entry.'));
        if (firstTag) {
          console.log(`  Then ask: "List notes under ${sanitizeText(firstTag)}"`);
        }
      }
      console.log('');

      const scopeArg = scopes.read.tags.length > 0 ? ` --scope ${scopes.read.tags.join(' ')}` : '';
      console.log(`Renew with: ${chalk.cyan(`uomp connect ${input.client}${scopeArg}`)}`);
      console.log(`Revoke with: ${chalk.cyan(`uomp revoke ${sessionId}`)}`);

      if (input.printToken) {
        console.log('');
        console.log(chalk.bold('Token'));
        console.log(`  export UOM_TOKEN="${input.token}"`);
      }
      return;
    }

    console.log(chalk.bold('Env file'));
    console.log(`  ${envPath}`);
    console.log('');
    console.log(chalk.bold('Open a new terminal, then:'));
    console.log(`  source ${shellQuote(envPath)}`);
    const entryPoint = agentPath ? join(agentPath, 'index.js') : null;
    if (entryPoint && existsSync(entryPoint)) {
      console.log(chalk.gray(`  node ${shellQuote(entryPoint)}   # example`));
    }

    if (input.printToken) {
      console.log('');
      console.log(chalk.bold('Token'));
      console.log(`  export UOM_TOKEN="${input.token}"`);
    }

    console.log('');
    console.log(`Revoke with: ${chalk.cyan(`uomp revoke ${sessionId}`)}`);
  }
}

function emptyScopes(): Scopes {
  return {
    read: { tags: [], keys: [], denyTags: [], denyKeys: [] },
    write: { tags: [], keys: [], denyTags: [], denyKeys: [] },
  };
}

function describeItem(item: MemoryItem): string {
  const value = item.value as Record<string, unknown> | null | undefined;
  const label = value?.title ?? value?.path ?? item.description ?? item.key;
  return sanitizeText(String(label));
}

function genericMcpManifest(client?: ConnectClient): AgentManifest {
  const label = client ? clientLabel(client) : 'MCP Client';
  const id = client ? `mcp-client-${client}` : 'mcp-client';

  return normalizeManifest({
    uomp_version: '1.0',
    agent: {
      id,
      name: label,
      version: '0.1.0',
      description: client ? `${label} MCP client` : 'Generic MCP client',
      publisher: 'uomp',
    },
    requested_scopes: {
      read: { tags: [], keys: [], deny_tags: [], deny_keys: [] },
      write: { tags: [], keys: [], deny_tags: [], deny_keys: [] },
    },
  });
}

function parseDuration(value?: string): number {
  const raw = (value ?? '30').trim();
  const minutes = Number(raw);

  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
    throw new Error(`Invalid duration "${raw}". Use whole minutes between 1 and 1440.`);
  }

  return minutes;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}
