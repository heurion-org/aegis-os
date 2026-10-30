import { Command } from 'commander';
import { createInterface } from 'readline';
import { spawn } from 'child_process';
import { join } from 'path';
import { loadOrCreateAdminToken } from '@uomp/auth';
import { UompConfig } from '../config.js';
import {
  loadSessionCredentials,
  resolveSessionPath,
  type SessionCredentials,
} from '../utils/session-env.js';
import { clientLabel, parseMcpClient, printClientConfig, type ConnectClient } from '../utils/mcp-config.js';
import { writeSessionEnvFile } from '../utils/session-env-file.js';
import { notifyConsentRequest } from '../utils/notify.js';
import type { Scopes } from '@uomp/core';

interface McpOptions {
  session?: string;
  baseUrl?: string;
  printConfig?: boolean;
  client?: string;
  onDemand?: boolean;
  requestScope?: string[];
  requestDuration?: string;
  open?: boolean;
  consentTimeout?: string;
  notify?: boolean;
}

interface JsonRpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

const TOOLS = [
  {
    name: 'list_memory',
    description: 'List keys and metadata authorized by the current UOMP session for a tag. Content is not included; use read_memory for a specific key.',
    inputSchema: {
      type: 'object',
      properties: {
        tag: {
          type: 'string',
          description: 'Scope tag to list, for example notes/projects',
        },
        limit: {
          type: 'number',
          minimum: 1,
          maximum: 100,
          default: 50,
        },
      },
      required: ['tag'],
      additionalProperties: false,
    },
  },
  {
    name: 'search_memory',
    description: 'Search authorized memory items for a tag by text. Returns keys and metadata only; use read_memory for content.',
    inputSchema: {
      type: 'object',
      properties: {
        tag: {
          type: 'string',
          description: 'Scope tag to search, for example notes/projects',
        },
        query: {
          type: 'string',
          description: 'Text to match against key, title, path, description, tags, or content',
        },
        limit: {
          type: 'number',
          minimum: 1,
          maximum: 100,
          default: 20,
        },
      },
      required: ['tag', 'query'],
      additionalProperties: false,
    },
  },
  {
    name: 'read_memory',
    description: 'Read one memory item by key. UOMP scope, expiry, revocation, and audit still apply.',
    inputSchema: {
      type: 'object',
      properties: {
        key: {
          type: 'string',
          description: 'Memory key, for example note.projects.uomp.plan',
        },
      },
      required: ['key'],
      additionalProperties: false,
    },
  },
];

export class McpCommands {
  static get(): Command {
    return new Command('mcp')
      .description('Run a stdio MCP server for Claude Desktop / Cursor')
      .option('-s, --session <session>', 'Session ID or path to a session env file')
      .option('--base-url <url>', 'Override the UOMP server URL')
      .option('--print-config', 'Print an MCP client config and exit')
      .option('--client <client>', 'Client label: claude, cursor, opencode, or generic')
      .option('--on-demand', 'Request approval when no valid session is available')
      .option('--request-scope <tags...>', 'Tags to request in on-demand mode')
      .option('--request-duration <minutes>', 'Requested session duration in on-demand mode', '30')
      .option('--no-open', 'Do not open the consent page automatically')
      .option('--no-notify', 'Do not send a desktop notification for consent requests')
      .option('--consent-timeout <seconds>', 'How long to wait for approval in on-demand mode', '90')
      .action(async (options: McpOptions) => {
        try {
          const config = new UompConfig();
          await new McpCommands(config).serve(options);
        } catch (error) {
          console.error(error instanceof Error ? error.message : String(error));
          process.exitCode = 1;
        }
      });
  }

  private config: UompConfig;
  private sessionInput?: string;
  private baseUrlOverride?: string;
  private credentials?: SessionCredentials;
  private onDemand = false;
  private client: ConnectClient | 'generic' = 'generic';
  private requestScopes: string[] = [];
  private requestDuration = 30;
  private pendingRequestId?: string;
  private pendingSecret?: string;
  private pendingApprovalUrl?: string;
  private pendingScopes?: Scopes;
  private noOpen = false;
  private notify = true;
  private consentTimeoutSeconds = 90;

  constructor(config: UompConfig) {
    this.config = config;
  }

  async serve(options: McpOptions): Promise<void> {
    this.sessionInput = options.session;
    this.baseUrlOverride = options.baseUrl;
    this.onDemand = options.onDemand === true;
    this.client = parseMcpClient(options.client);
    this.requestScopes = options.requestScope ?? [];
    this.requestDuration = parseDurationOption(options.requestDuration);
    this.noOpen = options.open === false;
    this.notify = options.notify !== false;
    this.consentTimeoutSeconds = parseTimeoutOption(options.consentTimeout);

    if (this.client !== 'generic' && !options.printConfig && !this.onDemand) {
      throw new Error('--client requires --print-config unless --on-demand is set.');
    }

    let credentials: SessionCredentials | null = null;
    try {
      credentials = await loadSessionCredentials(this.config, options.session);
    } catch (error) {
      if (!this.onDemand) throw error;
    }

    if (!credentials && !this.onDemand) {
      throw new Error(
        'No UOMP session. Pass --session <id|env-file>, set UOM_TOKEN and UOMP_BASE_URL, or use --on-demand.'
      );
    }

    this.credentials = credentials ?? undefined;

    if (options.printConfig) {
      printClientConfig(this.client, credentials?.source ?? this.defaultEnvPath(), {
        onDemand: this.onDemand,
        requestScopes: this.requestScopes,
        requestDuration: this.requestDuration,
      });
      return;
    }

    if (this.credentials) {
      try {
        await verifySession(this.connectionUrl(), this.credentials.token);
      } catch (error) {
        process.stderr.write(
          `UOMP MCP warning: ${error instanceof Error ? error.message : String(error)}\n` +
          'The server will re-read the session file on the next tool call.\n'
        );
      }
    }

    process.stderr.write(
      `UOMP MCP server ready: ${this.connectionUrl()} (${this.credentials?.source ?? 'on-demand'})\n`
    );

    await this.run();
  }

  private defaultEnvPath(): string {
    const client = this.client === 'generic' ? 'mcp-client' : this.client;
    return join(this.config.sessionsDir, `${client}.env`);
  }

  private connectionUrl(): string {
    return normalizeBaseUrl(
      this.baseUrlOverride ?? this.credentials?.baseUrl ?? this.config.serverUrl
    );
  }

  private async refreshCredentials(): Promise<void> {
    if (!this.sessionInput) return;

    try {
      const next = await loadSessionCredentials(this.config, this.sessionInput);
      if (next) this.credentials = next;
    } catch {
      // Keep the current credentials; the tool call will report the auth error.
    }
  }

  private async run(): Promise<void> {
    const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
    let queue = Promise.resolve();

    input.on('line', line => {
      if (!line.trim()) return;
      queue = queue
        .then(() => this.handleLine(line))
        .catch(error => {
          process.stderr.write(`UOMP MCP error: ${error instanceof Error ? error.message : String(error)}\n`);
        });
    });

    await new Promise<void>(resolve => {
      input.on('close', () => {
        void queue.finally(() => resolve());
      });
    });
  }

  private async handleLine(line: string): Promise<void> {
    let message: JsonRpcMessage;

    try {
      message = JSON.parse(line) as JsonRpcMessage;
    } catch {
      sendError(null, -32700, 'Parse error');
      return;
    }

    if (!message || typeof message !== 'object' || typeof message.method !== 'string') {
      return;
    }

    if (message.id === undefined || message.id === null) {
      // Client notification; no response is expected.
      return;
    }

    try {
      await this.refreshCredentials();
      const result = await this.dispatch(message);
      sendResult(message.id, result);
    } catch (error) {
      if (error instanceof RpcError) {
        sendError(message.id, error.code, error.message);
      } else {
        sendError(message.id, -32603, error instanceof Error ? error.message : String(error));
      }
    }
  }

  private async dispatch(message: JsonRpcMessage): Promise<unknown> {
    switch (message.method) {
      case 'initialize':
        return {
          protocolVersion: typeof message.params?.protocolVersion === 'string'
            ? message.params.protocolVersion
            : '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'uomp', version: '0.0.1' },
        };

      case 'ping':
        return {};

      case 'tools/list':
        return { tools: TOOLS };

      case 'tools/call':
        return this.callTool(message.params);

      default:
        throw new RpcError(-32601, `Method not found: ${message.method}`);
    }
  }

  private async ensureCredentials(requestedScopes: Scopes): Promise<boolean> {
    if (this.pendingRequestId) {
      if (await this.tryLoadCredentials()) {
        if (this.tokenCoversScope(this.credentials!.token, requestedScopes)) {
          this.clearPendingRequest();
          return true;
        }
      }

      const status = await this.pendingRequestStatus();
      if (status === 'denied' || status === 'expired') {
        this.clearPendingRequest();
        return this.requestConsent(requestedScopes);
      }
      return false;
    }

    if (this.credentials) {
      if (!this.onDemand) {
        return true;
      }
      if (
        await this.tokenIsValid(this.credentials)
        && this.tokenCoversScope(this.credentials.token, requestedScopes)
      ) {
        return true;
      }
      this.credentials = undefined;
    }

    if (!this.onDemand) {
      return false;
    }

    return this.requestConsent(requestedScopes);
  }

  private clearPendingRequest(): void {
    this.pendingRequestId = undefined;
    this.pendingApprovalUrl = undefined;
    this.pendingSecret = undefined;
    this.pendingScopes = undefined;
  }

  private tokenCoversScope(token: string, requestedScopes: Scopes): boolean {
    const tags = requestedScopes.read.tags;
    const keys = requestedScopes.read.keys;
    if (tags.length === 0 && keys.length === 0) return true;

    try {
      const payload = JSON.parse(
        Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf-8')
      ) as { scopes?: Scopes };
      const granted = payload.scopes?.read;
      if (!granted) return false;
      const tagsCovered = tags.every(tag => granted.tags.includes(tag));
      const keysCovered = keys.every(key => granted.keys.includes(key));
      // A tag-scoped token may still read keys under that tag; Guard enforces
      // the actual tag/key match. Avoid prompting again for every key read.
      const tagScopeCoversKeys = keys.length > 0 && granted.tags.length > 0;
      return tagsCovered && (keysCovered || tagScopeCoversKeys);
    } catch {
      return false;
    }
  }

  private async tryLoadCredentials(): Promise<boolean> {
    try {
      const next = this.sessionInput
        ? await loadSessionCredentials(this.config, this.sessionInput)
        : (await loadSessionCredentials(this.config))
          ?? await loadSessionCredentials(this.config, this.defaultEnvPath());
      if (!next) return false;
      if (!(await this.tokenIsValid(next))) return false;
      this.credentials = next;
      return true;
    } catch {
      return false;
    }
  }

  private async tokenIsValid(credentials: SessionCredentials): Promise<boolean> {
    try {
      const response = await fetch(`${this.connectionUrl()}/v1/tokens/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: credentials.token }),
      });
      if (!response.ok) return false;
      const body = await response.json() as { valid?: boolean };
      return body.valid === true;
    } catch {
      return false;
    }
  }

  private async pendingRequestStatus(): Promise<string | undefined> {
    if (!this.pendingRequestId) return undefined;

    try {
      await this.config.init();
      const response = await fetch(
        `${this.connectionUrl()}/v1/consent/requests/${encodeURIComponent(this.pendingRequestId)}`,
        {
          headers: { 'x-uomp-admin-token': this.config.adminToken },
        }
      );
      if (!response.ok) return undefined;
      const body = await response.json() as { status?: string };
      return body.status;
    } catch {
      return undefined;
    }
  }

  private async requestConsent(requestedScopes: Scopes): Promise<boolean> {
    const scopes = this.requestScopes.length > 0
      ? scopesFromTags(this.requestScopes)
      : requestedScopes;

    if (scopes.read.tags.length === 0 && scopes.read.keys.length === 0) {
      throw new Error('No readable scope was requested by this tool call.');
    }

    await this.config.init();
    const client = this.client === 'generic' ? 'mcp-client' : this.client;
    const agentName = client === 'mcp-client' ? 'MCP Client' : clientLabel(this.client as ConnectClient);
    const envPath = this.sessionInput
      ? resolveSessionPath(this.config, this.sessionInput)
      : this.defaultEnvPath();

    const response = await fetch(`${this.connectionUrl()}/v1/consent/requests`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-uomp-admin-token': this.config.adminToken,
      },
      body: JSON.stringify({
        client,
        agent_id: client === 'mcp-client' ? 'mcp-client' : `mcp-client-${client}`,
        agent_name: agentName,
        requested_scopes: scopes,
        duration_minutes: this.requestDuration,
        env_path: envPath,
        base_url: this.connectionUrl(),
      }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => null) as { error?: { message?: string } } | null;
      throw new Error(
        `Failed to create a consent request (${response.status}): ` +
        (body?.error?.message ?? response.statusText)
      );
    }

    const body = await response.json() as {
      request_id?: string;
      approval_url?: string;
    };
    if (!body.request_id) {
      throw new Error('Failed to create a consent request.');
    }

    this.pendingRequestId = body.request_id;
    this.pendingApprovalUrl = body.approval_url;
    this.pendingScopes = scopes;

    const scopeSummary = [
      ...scopes.read.tags,
      ...scopes.read.keys,
    ].join(', ');

    if (body.approval_url) {
      const parsed = new URL(body.approval_url);
      this.pendingSecret = parsed.searchParams.get('secret') ?? undefined;
      if (!this.noOpen) {
        openUrl(body.approval_url);
      }
      if (this.notify) {
        notifyConsentRequest({
          title: 'UOMP approval required',
          body: `${agentName} requests ${scopeSummary}`,
          url: body.approval_url,
        });
      }
      process.stderr.write(`UOMP approval required: ${body.approval_url}\n`);
    } else {
      process.stderr.write(`UOMP approval required. Run: uomp approve ${body.request_id}\n`);
    }

    const approved = await this.waitForConsentApproval();
    if (approved) {
      this.clearPendingRequest();
    }
    return approved;
  }

  private async waitForConsentApproval(): Promise<boolean> {
    const deadline = Date.now() + this.consentTimeoutSeconds * 1000;

    while (Date.now() < deadline) {
      if (await this.tryLoadCredentials()) {
        return true;
      }

      const status = await this.getConsentStatus();
      if (status?.status === 'approved' && status.token) {
        const envPath = this.sessionInput
          ? resolveSessionPath(this.config, this.sessionInput)
          : this.defaultEnvPath();
        await writeSessionEnvFile(envPath, {
          sessionId: status.session_id ?? '',
          agentId: status.agent_id ?? (this.client === 'generic' ? 'mcp-client' : `mcp-client-${this.client}`),
          expiresAt: status.token_expires_at ?? new Date().toISOString(),
          token: status.token,
          baseUrl: this.connectionUrl(),
        });
        this.credentials = {
          token: status.token,
          baseUrl: this.connectionUrl(),
          source: envPath,
        };
        return true;
      }

      if (status?.status === 'denied' || status?.status === 'expired') {
        this.pendingRequestId = undefined;
        this.pendingApprovalUrl = undefined;
        this.pendingSecret = undefined;
        return false;
      }

      await sleep(1_000);
    }

    return false;
  }

  private async getConsentStatus(): Promise<{
    status?: string;
    token?: string;
    token_expires_at?: string;
    session_id?: string;
    agent_id?: string;
  } | undefined> {
    if (!this.pendingRequestId) return undefined;

    try {
      const url = new URL(
        `${this.connectionUrl()}/v1/consent/requests/${encodeURIComponent(this.pendingRequestId)}`
      );
      const headers: Record<string, string> = {};
      if (this.pendingSecret) {
        url.searchParams.set('secret', this.pendingSecret);
      } else {
        await this.config.init();
        headers['x-uomp-admin-token'] = this.config.adminToken;
      }

      const response = await fetch(url, { headers });
      if (!response.ok) return undefined;
      return await response.json() as {
        status?: string;
        token?: string;
        token_expires_at?: string;
        session_id?: string;
        agent_id?: string;
      };
    } catch {
      return undefined;
    }
  }

  private approvalMessage(): string {
    if (this.pendingRequestId) {
      const url = this.pendingApprovalUrl ? ` Open: ${this.pendingApprovalUrl}` : '';
      return `UOMP approval required. Run \`uomp approve ${this.pendingRequestId}\` in a terminal, then try again.${url}`;
    }
    return 'No UOMP session. Run `uomp approve <request-id>` after a pending request, or re-run `uomp connect`.';
  }

  private requestedScopesForTool(name: string, args: Record<string, unknown>): Scopes {
    const empty: Scopes = {
      read: { tags: [], keys: [], denyTags: [], denyKeys: [] },
      write: { tags: [], keys: [], denyTags: [], denyKeys: [] },
    };

    if (name === 'list_memory' || name === 'search_memory') {
      const tag = typeof args.tag === 'string' ? args.tag.trim() : '';
      if (!tag) return empty;
      return {
        ...empty,
        read: { ...empty.read, tags: [tag] },
      };
    }

    if (name === 'read_memory') {
      const key = typeof args.key === 'string' ? args.key.trim() : '';
      if (!key) return empty;
      return {
        ...empty,
        read: { ...empty.read, keys: [key] },
      };
    }

    return empty;
  }

  private async callTool(params: Record<string, unknown> | undefined): Promise<unknown> {
    const name = typeof params?.name === 'string' ? params.name : '';
    const args = (params?.arguments && typeof params.arguments === 'object')
      ? params.arguments as Record<string, unknown>
      : {};

    const requestedScopes = this.requestedScopesForTool(name, args);
    if (!(await this.ensureCredentials(requestedScopes))) {
      return toolError(this.approvalMessage());
    }

    const baseUrl = this.connectionUrl();
    const token = this.credentials?.token;
    if (!token) {
      return toolError(this.approvalMessage());
    }

    if (name === 'list_memory') {
      const tag = typeof args.tag === 'string' ? args.tag.trim() : '';
      if (!tag) {
        return toolError('The "tag" argument is required.');
      }

      const result = await fetchItemsByTag(baseUrl, token, tag);
      if (!result.items) {
        return toolError(result.error ?? 'Request failed.');
      }

      const limit = clampLimit(args.limit);
      return toolResult(JSON.stringify({
        count: result.items.length,
        items: result.items.slice(0, limit).map(summarizeItem),
      }, null, 2));
    }

    if (name === 'search_memory') {
      const tag = typeof args.tag === 'string' ? args.tag.trim() : '';
      const query = typeof args.query === 'string' ? args.query.trim() : '';
      if (!tag || !query) {
        return toolError('The "tag" and "query" arguments are required.');
      }

      const result = await fetchItemsByTag(baseUrl, token, tag);
      if (!result.items) {
        return toolError(result.error ?? 'Request failed.');
      }

      const needle = query.toLowerCase();
      const matches = result.items.filter(item => searchableText(item).includes(needle));
      const limit = clampLimit(args.limit, 20);
      return toolResult(JSON.stringify({
        count: matches.length,
        query,
        items: matches.slice(0, limit).map(summarizeItem),
      }, null, 2));
    }

    if (name === 'read_memory') {
      const key = typeof args.key === 'string' ? args.key.trim() : '';
      if (!key) {
        return toolError('The "key" argument is required.');
      }

      const response = await requestJson(`${baseUrl}/v1/memory/${encodeURIComponent(key)}`, token);
      if (!response.response) {
        return toolError(response.error ?? 'Request failed.');
      }
      if (!response.response.ok) {
        return toolError(formatHttpError(response.response, response.body));
      }

      return toolResult(JSON.stringify(response.body, null, 2));
    }

    throw new RpcError(-32602, `Unknown tool: ${name || '(missing)'}`);
  }
}

class RpcError extends Error {
  readonly code: number;

  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

async function verifySession(baseUrl: string, token: string): Promise<void> {
  let response: Response;
  try {
    response = await fetch(`${baseUrl}/v1/audit?limit=1`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch {
    throw new Error(`Cannot reach UOMP at ${baseUrl}. Start it with: uomp serve`);
  }

  if (!response.ok) {
    const body = await readJson(response);
    const reason = body?.error?.message ?? response.statusText;
    throw new Error(
      `UOMP session is not active (${response.status}): ${reason}. ` +
      'Run `uomp authorize <agent>` again to create a new session.'
    );
  }
}

function normalizeBaseUrl(value: string): string {
  const withScheme = /^https?:\/\//i.test(value) ? value : `http://${value}`;
  return withScheme.replace(/\/+$/, '');
}

function parseDurationOption(value?: string): number {
  const minutes = Number(value ?? '30');
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
    throw new Error(`Invalid --request-duration "${value}". Use whole minutes between 1 and 1440.`);
  }
  return minutes;
}

function parseTimeoutOption(value?: string): number {
  const seconds = Number(value ?? '90');
  if (!Number.isInteger(seconds) || seconds < 1 || seconds > 600) {
    throw new Error(`Invalid --consent-timeout "${value}". Use whole seconds between 1 and 600.`);
  }
  return seconds;
}

function openUrl(url: string): void {
  const command = process.platform === 'darwin' ? 'open' : 'xdg-open';
  const args = [url];

  try {
    const child = spawn(command, args, {
      detached: true,
      stdio: 'ignore',
    });
    child.on('error', () => {
      // The URL is printed to stderr as a fallback.
    });
    child.unref();
  } catch {
    // The URL is printed to stderr as a fallback.
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function scopesFromTags(tags: string[]): Scopes {
  return {
    read: { tags, keys: [], denyTags: [], denyKeys: [] },
    write: { tags: [], keys: [], denyTags: [], denyKeys: [] },
  };
}

async function readJson(response: Response): Promise<any> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function fetchItemsByTag(
  baseUrl: string,
  token: string,
  tag: string
): Promise<{ items?: any[]; error?: string }> {
  const url = new URL(`${baseUrl}/v1/memory`);
  url.searchParams.set('tag', tag);

  const result = await requestJson(url, token);
  if (!result.response) {
    return { error: result.error };
  }
  if (!result.response.ok) {
    return { error: formatHttpError(result.response, result.body) };
  }

  return { items: Array.isArray(result.body?.items) ? result.body.items : [] };
}

async function requestJson(
  input: string | URL,
  token: string
): Promise<{ response?: Response; body?: any; error?: string }> {
  try {
    const response = await fetch(input, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return { response, body: await readJson(response) };
  } catch {
    return { error: `Cannot reach UOMP at ${String(input)}. Start it with: uomp serve` };
  }
}

function summarizeItem(item: any): Record<string, unknown> {
  const value = item?.value ?? {};
  return {
    key: item?.key,
    title: value.title,
    path: value.path,
    tags: item?.tags,
    sensitivity: item?.sensitivity,
    description: item?.description,
    updated_at: item?.updated_at,
  };
}

function searchableText(item: any): string {
  const value = item?.value ?? {};
  return [
    item?.key,
    item?.description,
    ...(Array.isArray(item?.tags) ? item.tags : []),
    value.title,
    value.path,
    value.content,
  ]
    .filter(value => typeof value === 'string')
    .join('\n')
    .toLowerCase();
}

function formatHttpError(response: Response, body: any): string {
  const code = body?.error?.code;
  const message = body?.error?.message ?? response.statusText;
  return code ? `${code}: ${message}` : message;
}

function clampLimit(value: unknown, fallback = 50): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return fallback;
  }

  return Math.min(100, Math.max(1, Math.floor(value)));
}

function toolResult(text: string): unknown {
  return {
    content: [{ type: 'text', text }],
    isError: false,
  };
}

function toolError(text: string): unknown {
  return {
    content: [{ type: 'text', text }],
    isError: true,
  };
}

function sendResult(id: string | number | null, result: unknown): void {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, result })}\n`);
}

function sendError(id: string | number | null, code: number, message: string): void {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } })}\n`);
}
