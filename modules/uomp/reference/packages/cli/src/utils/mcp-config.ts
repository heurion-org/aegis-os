import { realpathSync } from 'fs';
import { chmod, copyFile, mkdir, readFile, rename, rm, stat, writeFile } from 'fs/promises';
import { homedir } from 'os';
import { dirname, join, resolve } from 'path';
import { isDeepStrictEqual } from 'util';

export type McpClient = 'generic' | 'claude' | 'cursor' | 'opencode';
export type ConnectClient = Exclude<McpClient, 'generic'>;

export interface CliInvocation {
  command: string;
  args: string[];
}

export interface ClientConfigResult {
  path: string;
  action: 'created' | 'updated' | 'unchanged';
  changed: boolean;
  backupPath?: string;
}

export interface RemoveClientConfigResult {
  path: string;
  removed: boolean;
  backupPath?: string;
}

export interface ClientConfigStatus {
  client: ConnectClient;
  path: string;
  configured: boolean;
  sessionPath?: string;
  onDemand?: boolean;
  error?: string;
}

export interface McpEntryOptions {
  onDemand?: boolean;
  requestScopes?: string[];
  requestDuration?: number;
}

export function parseMcpClient(value?: string): McpClient {
  if (!value || value === 'generic') return 'generic';
  if (value === 'claude' || value === 'cursor' || value === 'opencode') return value;

  throw new Error(`Unknown client "${value}". Use claude, cursor, opencode, or generic.`);
}

export function isConnectClient(value: string): value is ConnectClient {
  return value === 'claude' || value === 'cursor' || value === 'opencode';
}

export function clientLabel(client: ConnectClient): string {
  if (client === 'claude') return 'Claude Desktop';
  if (client === 'cursor') return 'Cursor';
  return 'OpenCode';
}

export function getCliInvocation(): CliInvocation {
  const entry = process.argv[1];
  if (!entry) {
    throw new Error('Cannot determine the UOMP CLI path.');
  }

  const cliPath = realpathSync(entry);
  const isScript = /\.[cm]?js$/.test(cliPath);

  return {
    command: isScript ? process.execPath : cliPath,
    args: isScript ? [cliPath] : [],
  };
}

export function buildMcpEntry(
  client: ConnectClient,
  sessionPath: string,
  options: McpEntryOptions = {}
): Record<string, unknown> {
  const invocation = getCliInvocation();
  const args = [...invocation.args, 'mcp', '--session', sessionPath];

  if (options.onDemand) {
    args.push('--on-demand', '--client', client);
    for (const tag of options.requestScopes ?? []) {
      args.push('--request-scope', tag);
    }
    args.push('--request-duration', String(options.requestDuration ?? 30));
  }

  if (client === 'opencode') {
    return {
      type: 'local',
      command: [invocation.command, ...args],
      codemode: false,
    };
  }

  return {
    command: invocation.command,
    args,
  };
}

export function buildMcpConfig(
  client: McpClient,
  sessionPath: string,
  options: McpEntryOptions = {}
): Record<string, unknown> {
  if (client === 'opencode') {
    return {
      mcp: {
        servers: {
          uomp: buildMcpEntry(client, sessionPath, options),
        },
      },
    };
  }

  return {
    mcpServers: {
      uomp: buildMcpEntry('claude', sessionPath, options),
    },
  };
}

export function printClientConfig(
  client: McpClient,
  sessionPath: string,
  options: McpEntryOptions = {}
): void {
  process.stdout.write(`${JSON.stringify(buildMcpConfig(client, sessionPath, options), null, 2)}\n`);

  if (client === 'claude') {
    process.stderr.write(`Add to ${defaultClientConfigPath('claude')}.\n`);
  } else if (client === 'cursor') {
    process.stderr.write('Add to .cursor/mcp.json (project) or ~/.cursor/mcp.json (global).\n');
  } else if (client === 'opencode') {
    process.stderr.write('Add to opencode.json (project) or ~/.config/opencode/opencode.json (global).\n');
  }
}

export function defaultClientConfigPath(
  client: ConnectClient,
  options: { project?: boolean; cwd?: string } = {}
): string {
  const cwd = options.cwd ?? process.cwd();

  if (client === 'claude') {
    if (process.platform === 'darwin') {
      return join(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    }
    return join(homedir(), '.config', 'Claude', 'claude_desktop_config.json');
  }

  if (client === 'cursor') {
    return options.project
      ? join(cwd, '.cursor', 'mcp.json')
      : join(homedir(), '.cursor', 'mcp.json');
  }

  return options.project
    ? join(cwd, 'opencode.json')
    : join(homedir(), '.config', 'opencode', 'opencode.json');
}

export async function upsertMcpClientConfig(
  client: ConnectClient,
  sessionPath: string,
  configPath?: string,
  entryOptions: McpEntryOptions = {}
): Promise<ClientConfigResult> {
  const targetPath = configPath ? resolve(configPath) : defaultClientConfigPath(client);
  const existing = await readExistingConfig(targetPath);
  const next = mergeClientConfig(
    client,
    existing.value,
    buildMcpEntry(client, sessionPath, entryOptions),
    targetPath
  );

  if (existing.exists && isDeepStrictEqual(existing.value, next)) {
    return { path: targetPath, action: 'unchanged', changed: false };
  }

  const backupPath = await writeConfigFile(targetPath, next, existing.mode, existing.exists);

  return {
    path: targetPath,
    action: existing.exists ? 'updated' : 'created',
    changed: true,
    ...(backupPath ? { backupPath } : {}),
  };
}

export async function removeMcpClientConfig(
  client: ConnectClient,
  configPath?: string
): Promise<RemoveClientConfigResult> {
  const targetPath = configPath ? resolve(configPath) : defaultClientConfigPath(client);
  const existing = await readExistingConfig(targetPath);

  if (!existing.exists) {
    return { path: targetPath, removed: false };
  }

  const next = removeClientEntry(client, existing.value);
  if (!next) {
    return { path: targetPath, removed: false };
  }

  const backupPath = await writeConfigFile(targetPath, next, existing.mode, true);

  return {
    path: targetPath,
    removed: true,
    ...(backupPath ? { backupPath } : {}),
  };
}

export async function inspectMcpClientConfig(
  client: ConnectClient,
  configPath?: string
): Promise<ClientConfigStatus> {
  const targetPath = configPath ? resolve(configPath) : defaultClientConfigPath(client);

  let content: string;
  try {
    content = await readFile(targetPath, 'utf-8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { client, path: targetPath, configured: false };
    }
    return { client, path: targetPath, configured: false, error: errorMessage(error) };
  }

  try {
    const value = content.trim() ? parseJsonObject(content, targetPath) : {};
    const entry = getClientEntry(client, value);
    if (!entry) {
      return { client, path: targetPath, configured: false };
    }

    const sessionPath = findSessionPath(entry);
    const onDemand = entryHasOnDemand(entry);
    return {
      client,
      path: targetPath,
      configured: true,
      ...(sessionPath ? { sessionPath } : {}),
      ...(onDemand ? { onDemand: true } : {}),
    };
  } catch (error) {
    return { client, path: targetPath, configured: false, error: errorMessage(error) };
  }
}

export function findSessionPathInEntry(entry: Record<string, unknown>): string | undefined {
  return findSessionPath(entry);
}

async function writeConfigFile(
  targetPath: string,
  value: Record<string, unknown>,
  mode: number,
  exists: boolean
): Promise<string | undefined> {
  await mkdir(dirname(targetPath), { recursive: true });

  let backupPath: string | undefined;
  if (exists) {
    backupPath = `${targetPath}.bak.${timestamp()}`;
    await copyFile(targetPath, backupPath);
    await chmod(backupPath, mode).catch(() => {});
  }

  const tempPath = `${targetPath}.${process.pid}.${Date.now()}.tmp`;
  try {
    await writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, {
      mode,
      flag: 'wx',
    });
    await chmod(tempPath, mode);
    await rename(tempPath, targetPath);
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => {});
    throw error;
  }

  return backupPath;
}

function removeClientEntry(
  client: ConnectClient,
  existing: Record<string, unknown>
): Record<string, unknown> | null {
  if (client === 'opencode') {
    const currentMcp = existing.mcp;
    if (!isPlainObject(currentMcp)) return null;

    const currentServers = currentMcp.servers;
    if (!isPlainObject(currentServers) || !isPlainObject(currentServers.uomp)) return null;

    const servers = { ...currentServers };
    delete servers.uomp;

    return {
      ...existing,
      mcp: {
        ...currentMcp,
        servers,
      },
    };
  }

  const currentServers = existing.mcpServers;
  if (!isPlainObject(currentServers) || !isPlainObject(currentServers.uomp)) return null;

  const servers = { ...currentServers };
  delete servers.uomp;

  return {
    ...existing,
    mcpServers: servers,
  };
}

function getClientEntry(
  client: ConnectClient,
  config: Record<string, unknown>
): Record<string, unknown> | undefined {
  if (client === 'opencode') {
    const mcp = config.mcp;
    if (!isPlainObject(mcp)) return undefined;
    const servers = mcp.servers;
    if (!isPlainObject(servers)) return undefined;
    return isPlainObject(servers.uomp) ? servers.uomp : undefined;
  }

  const servers = config.mcpServers;
  if (!isPlainObject(servers)) return undefined;
  return isPlainObject(servers.uomp) ? servers.uomp : undefined;
}

function findSessionPath(entry: Record<string, unknown>): string | undefined {
  const values = Array.isArray(entry.command)
    ? entry.command
    : Array.isArray(entry.args)
      ? entry.args
      : [];

  const index = values.indexOf('--session');
  const sessionPath = index >= 0 ? values[index + 1] : undefined;
  return typeof sessionPath === 'string' ? sessionPath : undefined;
}

function entryHasOnDemand(entry: Record<string, unknown>): boolean {
  const values = Array.isArray(entry.command)
    ? entry.command
    : Array.isArray(entry.args)
      ? entry.args
      : [];
  return values.includes('--on-demand');
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function readExistingConfig(
  targetPath: string
): Promise<{ exists: boolean; value: Record<string, unknown>; mode: number }> {
  try {
    const info = await stat(targetPath);
    const content = await readFile(targetPath, 'utf-8');
    const value = content.trim() ? parseJsonObject(content, targetPath) : {};

    return {
      exists: true,
      value,
      mode: info.mode & 0o777,
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { exists: false, value: {}, mode: 0o600 };
    }
    throw error;
  }
}

function parseJsonObject(content: string, targetPath: string): Record<string, unknown> {
  let parsed: unknown;

  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error(
      `Cannot update ${targetPath}: the file is not valid JSON. ` +
      'Fix it, or use --print-config to add the UOMP entry manually.'
    );
  }

  if (!isPlainObject(parsed)) {
    throw new Error(
      `Cannot update ${targetPath}: expected a JSON object. ` +
      'Fix it, or use --print-config to add the UOMP entry manually.'
    );
  }

  return parsed;
}

function mergeClientConfig(
  client: ConnectClient,
  existing: Record<string, unknown>,
  entry: Record<string, unknown>,
  targetPath: string
): Record<string, unknown> {
  if (client === 'opencode') {
    const currentMcp = existing.mcp;
    if (currentMcp !== undefined && !isPlainObject(currentMcp)) {
      throw new Error(`Cannot update ${targetPath}: "mcp" must be a JSON object.`);
    }

    const currentServers = currentMcp?.servers;
    if (currentServers !== undefined && !isPlainObject(currentServers)) {
      throw new Error(`Cannot update ${targetPath}: "mcp.servers" must be a JSON object.`);
    }

    const currentUomp = isPlainObject(currentServers?.uomp) ? currentServers.uomp : {};

    return {
      ...existing,
      mcp: {
        ...(currentMcp ?? {}),
        servers: {
          ...(currentServers ?? {}),
          uomp: {
            ...currentUomp,
            ...entry,
          },
        },
      },
    };
  }

  const currentServers = existing.mcpServers;
  if (currentServers !== undefined && !isPlainObject(currentServers)) {
    throw new Error(`Cannot update ${targetPath}: "mcpServers" must be a JSON object.`);
  }

  const currentUomp = isPlainObject(currentServers?.uomp) ? currentServers.uomp : {};

  return {
    ...existing,
    mcpServers: {
      ...(currentServers ?? {}),
      uomp: {
        ...currentUomp,
        ...entry,
      },
    },
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-');
}
