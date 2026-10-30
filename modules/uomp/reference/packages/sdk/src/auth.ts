import { Transport } from './transport.js';
import { UompError, UompErrorCode } from './errors.js';
import type { Scopes } from './types.js';

export interface SessionInfo {
  session_id: string;
  status: string;
  agent_id: string;
  requested_scopes?: Scopes;
  expires_at?: string;
}

export interface GrantResult {
  token: string;
  token_type: string;
  expires_at: string;
}

function isLoopbackBaseUrl(baseUrl: string): boolean {
  try {
    const hostname = new URL(baseUrl).hostname;
    return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1' || hostname === '[::1]';
  } catch {
    return false;
  }
}

export class AuthClient {
  private adminToken: string;

  constructor(private transport: Transport) {
    // Admin operations are local-only. Only auto-load the env token when the
    // transport targets loopback, so a local admin secret is never sent to a
    // remote Gateway by accident. Browser builds must not hold admin tokens.
    const isNodeRuntime = typeof process !== 'undefined' && typeof process.versions?.node === 'string';
    this.adminToken = isNodeRuntime && isLoopbackBaseUrl(transport.baseUrl)
      ? process.env?.UOMP_ADMIN_TOKEN ?? ''
      : '';
  }

  /** Set the local admin token used for create/grant/revoke */
  setAdminToken(token: string): void {
    this.adminToken = token;
  }

  private adminHeaders(): Record<string, string> {
    return this.adminToken ? { 'x-uomp-admin-token': this.adminToken } : {};
  }

  /** Create a new session */
  async createSession(params: {
    agentId: string;
    agentName?: string;
    requestedScopes: Scopes;
    durationMinutes?: number;
  }): Promise<SessionInfo> {
    return this.transport.requestJson<SessionInfo>('/v1/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...this.adminHeaders() },
      body: JSON.stringify({
        agent_id: params.agentId,
        agent_name: params.agentName,
        requested_scopes: params.requestedScopes,
        duration_minutes: params.durationMinutes ?? 30,
      }),
    });
  }

  /** Grant a session and get a Capability Token */
  async grant(params: {
    sessionId: string;
    grantedScopes: Scopes;
    profile?: string;
    audience?: string;
    allowedFields?: string[];
    aggregationOnly?: boolean;
    taskBound?: boolean;
  }): Promise<GrantResult> {
    return this.transport.requestJson<GrantResult>(`/v1/sessions/${params.sessionId}/grant`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...this.adminHeaders() },
      body: JSON.stringify({
        granted_scopes: params.grantedScopes,
        profile: params.profile,
        audience: params.audience,
        allowed_fields: params.allowedFields,
        aggregation_only: params.aggregationOnly ?? false,
        task_bound: params.taskBound ?? false,
      }),
    });
  }

  /** Revoke a session */
  async revoke(sessionId: string): Promise<SessionInfo> {
    return this.transport.requestJson<SessionInfo>(`/v1/sessions/${sessionId}/revoke`, {
      method: 'POST',
      headers: this.adminHeaders(),
    });
  }

  /** Close a session */
  async close(sessionId: string): Promise<SessionInfo> {
    return this.transport.requestJson<SessionInfo>(`/v1/sessions/${sessionId}/close`, {
      method: 'POST',
    });
  }

  /** Validate a token */
  async validate(token: string): Promise<{ valid: boolean; session_id: string; expires_at: string }> {
    return this.transport.requestJson('/v1/tokens/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
  }
}
