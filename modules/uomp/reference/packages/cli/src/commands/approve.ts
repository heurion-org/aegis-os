import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { existsSync } from 'fs';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { UompConfig } from '../config.js';
import { MemoryStore } from '@uomp/store';
import type { ConsentRequest } from '@uomp/auth';
import type { MemoryItem, ScopeAction, Scopes, Sensitivity } from '@uomp/core';
import { inferSensitivity } from '@uomp/core';
import { formatDateTime, formatScopes, sanitizeText } from '../utils/format.js';
import { openAuthService } from '../utils/auth-service.js';
import { writeSessionEnvFile } from '../utils/session-env-file.js';
import { readSessionIdFromEnv } from '../utils/session-files.js';

interface ApproveOptions {
  allowKey?: string[];
  allowHigh?: string[];
  json?: boolean;
}

export class ApproveCommands {
  static get(): Command {
    return new Command('approve')
      .description('Approve a pending consent request and write its session token')
      .argument('<requestId>', 'Consent request ID')
      .option('--allow-key <keys...>', 'Explicitly allow high-sensitivity keys')
      .option('--allow-high <tags...>', 'Explicitly allow all keys under named high-sensitivity tags')
      .option('--json', 'Output JSON')
      .action(async (requestId: string, options: ApproveOptions) => {
        try {
          const config = new UompConfig();
          await config.init();
          const auth = await openAuthService(config);

          let request: ConsentRequest | null;
          try {
            request = auth.getConsentRequest(requestId);
            if (!request) {
              throw new Error(`Consent request not found: ${requestId}`);
            }
            if (request.status !== 'pending') {
              throw new Error(`Consent request is already ${request.status}: ${requestId}`);
            }

            const store = new MemoryStore({ dbPath: config.memoryDbPath });
            let scopes: Scopes;
            try {
              scopes = await promptForConsent(request, store, options);
            } finally {
              store.close();
            }

            const result = await auth.approveConsentRequest(requestId, scopes);
            if (!result) {
              throw new Error(`Failed to approve consent request: ${requestId}`);
            }

            const envPath = request.envPath ?? join(
              config.sessionsDir,
              `${request.client ?? 'mcp-client'}.env`
            );
            if (existsSync(envPath)) {
              const existing = await readFile(envPath, 'utf-8').catch(() => '');
              if (!existing.startsWith('# UOMP session ')) {
                throw new Error(`Refusing to overwrite a non-UOMP file: ${envPath}`);
              }
              const previousSession = readSessionIdFromEnv(existing);
              if (previousSession && previousSession !== request.sessionId) {
                auth.revokeSession(previousSession);
              }
            }
            await writeSessionEnvFile(envPath, {
              sessionId: request.sessionId,
              agentId: request.agentId,
              expiresAt: result.expiresAt,
              token: result.token,
              baseUrl: request.baseUrl ?? config.serverUrl,
            });

            const summary = {
              requestId,
              sessionId: request.sessionId,
              client: request.client,
              scopes,
              envPath,
              expiresAt: result.expiresAt,
            };

            if (options.json) {
              console.log(JSON.stringify(summary, null, 2));
              return;
            }

            console.log(chalk.green(`Approved consent request: ${requestId}`));
            console.log(`  Agent     ${sanitizeText(request.agentName ?? request.agentId)}`);
            console.log(`  Scope     ${formatScopes(scopes)}`);
            console.log(`  Expires   ${formatDateTime(result.expiresAt)}`);
            console.log(`  Env file  ${envPath}`);
            console.log('');
            console.log(chalk.gray('The MCP bridge will pick up this token on its next tool call.'));
          } finally {
            auth.close();
          }
        } catch (error) {
          console.error(chalk.red(error instanceof Error ? error.message : String(error)));
          process.exitCode = 1;
        }
      });
  }
}

async function promptForConsent(
  request: ConsentRequest,
  store: MemoryStore,
  options: ApproveOptions
): Promise<Scopes> {
  const requested = request.requestedScopes.read;
  const tags = requested.tags;

  if (tags.length === 0 && requested.keys.length === 0) {
    return {
      read: { tags: [], keys: [], denyTags: requested.denyTags, denyKeys: requested.denyKeys },
      write: emptyWrite(request.requestedScopes.write.denyTags, request.requestedScopes.write.denyKeys),
    };
  }

  const sensitivities = new Map(tags.map(tag => [tag, tagSensitivity(store, tag)]));

  console.log(chalk.bold(`\n${sanitizeText(request.agentName ?? request.agentId)} requests access to:`));
  for (const tag of tags) {
    const sensitivity = sensitivities.get(tag) ?? 'low';
    console.log(`  [${sensitivityLabel(sensitivity)}] ${sanitizeText(tag)}`);
  }

  let selectedTags: string[] = [];
  if (tags.length > 0) {
    if (!process.stdin.isTTY) {
      selectedTags = tags;
      const uncoveredHigh = tags.filter(tag =>
        sensitivities.get(tag) === 'high' && !(options.allowHigh ?? []).includes(tag)
      );
      if (uncoveredHigh.length > 0 && !options.allowKey?.length) {
        throw new Error(
          `High-sensitivity tags require explicit keys: ${uncoveredHigh.join(', ')}. ` +
          'Pass --allow-key <key...> or --allow-high <tag...>.'
        );
      }
    } else {
      const result = await inquirer.prompt([
        {
          type: 'checkbox',
          name: 'selectedTags',
          message: 'Select tags to authorize for reading:',
          choices: tags,
          default: tags.filter(tag => sensitivities.get(tag) !== 'high'),
        },
      ]);
      selectedTags = result.selectedTags as string[];
    }
  }

  validateOverrides(store, selectedTags, options);
  const highTags = selectedTags.filter(tag =>
    sensitivities.get(tag) === 'high' &&
    !(options.allowHigh ?? []).includes(tag) &&
    !(options.allowKey?.length)
  );

  const promptedKeys: string[] = [];
  for (const tag of highTags) {
    const items = store.getByTag(tag);
    if (items.length === 0) {
      console.log(chalk.gray(`  No items under ${sanitizeText(tag)}.`));
      continue;
    }

    console.log(chalk.bold(`\nHigh-sensitivity tag: ${sanitizeText(tag)}`));
    console.log(chalk.gray('  High-sensitivity items are never granted by tag alone. Select keys explicitly:'));
    const result = await inquirer.prompt([
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
    const keys = result.keys as string[];
    if (keys.length === 0) {
      console.log(chalk.yellow(`  No keys selected; high-sensitivity items under ${tag} will be denied.`));
    }
    promptedKeys.push(...keys);
  }

  if (requested.keys.length > 0 && !options.allowKey?.length) {
    const choices = requested.keys.map(key => {
      const item = store.get(key);
      return {
        key,
        sensitivity: item?.sensitivity ?? 'high' as Sensitivity,
        name: `${sanitizeText(key)}${item ? ` — ${describeItem(item)}` : ''}`,
      };
    });

    if (!process.stdin.isTTY) {
      const highKeys = choices.filter(choice => choice.sensitivity === 'high');
      if (highKeys.length > 0) {
        throw new Error(
          `High-sensitivity keys require --allow-key: ${highKeys.map(choice => choice.key).join(', ')}`
        );
      }
      promptedKeys.push(...choices.map(choice => choice.key));
    } else {
      const result = await inquirer.prompt([
        {
          type: 'checkbox',
          name: 'keys',
          message: 'Select requested keys to expose:',
          choices: choices.map(choice => ({
            name: choice.name,
            value: choice.key,
            checked: choice.sensitivity !== 'high',
          })),
        },
      ]);
      promptedKeys.push(...result.keys as string[]);
    }
  }

  const keys = new Set<string>();
  for (const key of options.allowKey ?? []) keys.add(key);
  for (const tag of options.allowHigh ?? []) {
    for (const item of store.getByTag(tag)) keys.add(item.key);
  }
  for (const key of promptedKeys) keys.add(key);

  const selected = new Set(selectedTags);
  for (const key of requested.keys) {
    const item = store.get(key);
    if (!item) continue;
    if (!item.tags.some(tag => selected.has(tag))) continue;
    if (item.sensitivity === 'high') continue;
    keys.add(key);
  }

  const readScope: ScopeAction = {
    tags: selectedTags,
    keys: [...keys],
    denyTags: requested.denyTags,
    denyKeys: requested.denyKeys,
    ...(requested.allowedFields ? { allowedFields: requested.allowedFields } : {}),
  };

  return {
    read: readScope,
    write: emptyWrite(request.requestedScopes.write.denyTags, request.requestedScopes.write.denyKeys),
  };
}

function validateOverrides(store: MemoryStore, selectedTags: string[], options: ApproveOptions): void {
  for (const tag of options.allowHigh ?? []) {
    if (!selectedTags.includes(tag)) {
      throw new Error(`--allow-high tag is not in the selected scope: ${tag}`);
    }
    if (tagSensitivity(store, tag) !== 'high') {
      throw new Error(`--allow-high only applies to high-sensitivity tags: ${tag}`);
    }
  }

  for (const key of options.allowKey ?? []) {
    if (!store.get(key)) {
      throw new Error(`Key not found in the local memory store: ${key}`);
    }
  }
}

function tagSensitivity(store: MemoryStore, tag: string): Sensitivity {
  const inferred = inferSensitivity(tag);
  if (inferred === 'high') return 'high';

  const items = store.getByTag(tag);
  if (items.some(item => item.sensitivity === 'high')) return 'high';
  if (items.some(item => item.sensitivity === 'medium')) return 'medium';
  return inferred;
}

function describeItem(item: MemoryItem): string {
  const value = item.value as Record<string, unknown> | null | undefined;
  const label = value?.title ?? value?.path ?? item.description ?? item.key;
  return sanitizeText(String(label));
}

function sensitivityLabel(sensitivity: Sensitivity): string {
  if (sensitivity === 'high') return chalk.red('high');
  if (sensitivity === 'medium') return chalk.yellow('medium');
  return chalk.green('low');
}

function emptyWrite(denyTags: string[], denyKeys: string[]): ScopeAction {
  return { tags: [], keys: [], denyTags, denyKeys };
}
