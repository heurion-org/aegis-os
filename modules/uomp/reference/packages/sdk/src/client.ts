import { Transport } from './transport.js';
import { MemoryClient } from './memory.js';
import { AggregateClient } from './aggregate.js';
import { PayloadClient } from './payload.js';
import { SessionClient } from './session.js';
import { AuditClient } from './audit.js';
import { AuthClient } from './auth.js';
import type { UompClientOptions, TokenInfo, Scopes, ScopeAction } from './types.js';

function decodeJWT(token: string): TokenInfo | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    return {
      sessionId: payload.session_id ?? '',
      agentId: payload.agent_id ?? 'uomp-agent',
      issuedAt: payload.issued_at ?? payload.iat ?? '',
      expiresAt: payload.expires_at ?? new Date((payload.exp ?? 0) * 1000).toISOString(),
      scopes: (payload.scopes as Scopes) ?? { read: emptyScope(), write: emptyScope() },
      profile: payload.profile ?? 'local',
      audience: payload.audience,
      allowedFields: payload.allowed_fields,
      aggregationOnly: payload.aggregation_only ?? false,
      taskBound: payload.task_bound ?? false,
      limits: payload.limits,
    };
  } catch { return null; }
}

function emptyScope(): ScopeAction {
  return { tags: [], keys: [], denyTags: [], denyKeys: [] };
}

export class UompClient {
  /** @internal */
  readonly _transport: Transport;
  readonly memory: MemoryClient;
  readonly aggregate: AggregateClient;
  readonly payload: PayloadClient;
  readonly audit: AuditClient;
  readonly auth: AuthClient;
  session: SessionClient;

  private _token: string;
  private _agentId: string;
  private _info: TokenInfo | null;

  constructor(options: UompClientOptions = {}) {
    const token = options.token || process.env.UOM_TOKEN || '';
    const baseUrl = options.baseUrl || process.env.UOMP_BASE_URL || 'http://127.0.0.1:9374';
    const agentId = options.agentId || 'uomp-agent';
    const sessionId = options.sessionId || process.env.UOMP_SESSION_ID || '';

    this._token = token;
    this._agentId = agentId;
    this._info = token ? decodeJWT(token) : null;

    // Auto-extract sessionId/agentId from token if available
    const finalSessionId = sessionId || this._info?.sessionId || '';
    const finalAgentId = agentId === 'uomp-agent' && this._info?.agentId
      ? this._info.agentId : agentId;

    this._transport = new Transport(
      { ...options, baseUrl, agentId: finalAgentId },
      () => this._token
    );

    this.session = new SessionClient(this._transport, finalSessionId, finalAgentId);
    this.memory = new MemoryClient(this._transport, this.session);
    this.aggregate = new AggregateClient(this._transport);
    this.payload = new PayloadClient(this._transport);
    this.audit = new AuditClient(this._transport);
    this.auth = new AuthClient(this._transport);
  }

  get token(): string { return this._token; }
  set token(value: string) {
    this._token = value;
    this._info = decodeJWT(value);
  }

  /** Decoded token claims (scopes, expiresAt, agentId, sessionId...) */
  get tokenInfo(): TokenInfo | null { return this._info; }

  /** Whether using Gateway mTLS */
  get isRemote(): boolean { return this._transport.baseUrl.startsWith('https://'); }

  /** Switch to a different session */
  useSession(sessionId: string, agentId?: string): this {
    this.session = new SessionClient(this._transport, sessionId, agentId ?? this._agentId);
    return this;
  }

  /** Health check */
  async health(): Promise<{ status: string }> {
    return this._transport.requestJson('/v1/health');
  }

  static fromEnv(): UompClient {
    return new UompClient();
  }
}
