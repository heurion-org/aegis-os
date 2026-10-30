import Database from 'better-sqlite3';
import { Hono, type Context } from 'hono';
import { z } from 'zod';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import type { Scopes } from '@uomp/core';
import { inferSensitivity } from '@uomp/core';
import { generateId } from '@uomp/core';
import { JWTTokenIssuer, type CapabilityTokenPayload } from '@uomp/token';

export { loadOrCreateAdminToken } from './admin.js';

export interface Session {
  sessionId: string;
  agentId: string;
  agentName?: string;
  status: 'created' | 'active' | 'closed' | 'expired' | 'revoked';
  createdAt: string;
  expiresAt: string;
  closedAt?: string;
  grantedScopes?: Scopes;
  requestedScopes: Scopes;
  tokenHash?: string;
}

export interface AuthServiceOptions {
  dbPath: string;
  issuer: JWTTokenIssuer;
  defaultDurationMinutes?: number;
  adminToken: string;
  consentKeyResolver?: (tag: string) => ConsentKeyInfo[];
  consentKeyLookup?: (key: string) => ConsentKeyInfo | null;
  aegis?: AegisConsentEvaluator;
}

export interface ConsentKeyInfo {
  key: string;
  title?: string;
  sensitivity: 'low' | 'medium' | 'high';
}

export type ConsentRequestStatus = 'pending' | 'approved' | 'denied' | 'expired';

export interface ConsentRequest {
  requestId: string;
  sessionId: string;
  client?: string;
  agentId: string;
  agentName?: string;
  requestedScopes: Scopes;
  envPath?: string;
  baseUrl?: string;
  status: ConsentRequestStatus;
  createdAt: string;
  expiresAt: string;
  approvedAt?: string;
  grantedScopes?: Scopes;
  aegisEscalationIds?: string[];
  remoteAudience?: string;
  remoteProfile?: string;
}

/**
 * Minimal interface implemented by `@uomp/aegis-adapter`. AuthService only
 * needs evaluation and the trusted approval call; the concrete transport is
 * injected by the CLI/server.
 */
export interface AegisConsentEvaluator {
  evaluateScopes(scopes: Scopes): Promise<{
    decision: 'allow' | 'ask' | 'deny';
    escalationIds: string[];
  }>;
  approveEscalations(escalationIds: string[], ttlSecs: number): Promise<unknown[]>;
  denyEscalations?(escalationIds: string[]): Promise<void>;
}

export interface CreateConsentRequestInput {
  client?: string;
  agent_id: string;
  agent_name?: string;
  requested_scopes: Scopes;
  duration_minutes?: number;
  env_path?: string;
  base_url?: string;
  remote?: {
    audience: string;
    profile?: string;
  };
}

export interface RemoteConsentRequestInput {
  agent_id: string;
  agent_name?: string;
  requested_scopes: Scopes;
  duration_minutes?: number;
  audience: string;
}

const scopeActionSchema = z.object({
  tags: z.array(z.string()).default([]),
  keys: z.array(z.string()).default([]),
  denyTags: z.array(z.string()).default([]),
  denyKeys: z.array(z.string()).default([]),
  allowedFields: z.array(z.string()).optional(),
  fields: z.record(z.array(z.string())).optional(),
  purposes: z.record(z.string()).optional(),
});

const scopesSchema = z.object({
  read: scopeActionSchema,
  write: scopeActionSchema,
});

const createSessionSchema = z.object({
  agent_id: z.string(),
  agent_name: z.string().optional(),
  requested_scopes: scopesSchema,
  duration_minutes: z.number().min(1).max(1440).default(30),
});

const grantSessionSchema = z.object({
  granted_scopes: scopesSchema,
  profile: z.string().optional(),
  audience: z.string().optional(),
  allowed_fields: z.array(z.string()).optional(),
  aggregation_only: z.boolean().optional(),
  task_bound: z.boolean().optional(),
});

const remoteRequestSchema = z.object({
  agent_id: z.string(),
  agent_name: z.string().optional(),
  requested_scopes: scopesSchema,
  duration_minutes: z.number().min(1).max(1440).default(10),
  audience: z.string().min(1),
});

const consentRequestSchema = z.object({
  client: z.string().optional(),
  agent_id: z.string(),
  agent_name: z.string().optional(),
  requested_scopes: scopesSchema,
  duration_minutes: z.number().min(1).max(1440).default(30),
  env_path: z.string().optional(),
  base_url: z.string().optional(),
});

const deletionProofSchema = z.object({
  deletion_proof_id: z.string(),
  session_id: z.string(),
  agent_id: z.string(),
  deleted_at: z.string(),
  memory_hash: z.string(),
  fields_accessed: z.array(z.string()).optional(),
  method: z.string(),
  proof_value: z.string(),
});

export function validateGrantedScopes(requested: Scopes, granted: Scopes): string | null {
  const errors: string[] = [];

  for (const action of ['read', 'write'] as const) {
    const requestedAction = requested[action];
    const grantedAction = granted[action];
    if (!requestedAction) {
      errors.push(`${action}: requested scope is missing`);
      continue;
    }
    if (!grantedAction) {
      errors.push(`${action}: granted scope is missing`);
      continue;
    }

    for (const field of ['tags', 'keys'] as const) {
      const extra = (grantedAction[field] ?? []).filter(value => !(requestedAction[field] ?? []).includes(value));
      if (extra.length > 0) {
        errors.push(`${action}.${field} exceeds requested scope: ${extra.join(', ')}`);
      }
    }

    for (const field of ['denyTags', 'denyKeys'] as const) {
      const removed = (requestedAction[field] ?? []).filter(value => !(grantedAction[field] ?? []).includes(value));
      if (removed.length > 0) {
        errors.push(`${action}.${field} removes requested denial: ${removed.join(', ')}`);
      }
    }
  }

  return errors.length > 0 ? errors.join('; ') : null;
}

export function validateGrantedFields(requested: Scopes, granted?: string[]): string | null {
  const requestedFields = requested.read.allowedFields ?? [];
  if (requestedFields.length === 0) {
    return null;
  }

  if (!granted || granted.length === 0) {
    return 'read.allowedFields must be granted when requested';
  }

  const extra = granted.filter(field => !requestedFields.includes(field));
  if (extra.length > 0) {
    return `read.allowedFields exceeds requested scope: ${extra.join(', ')}`;
  }

  return null;
}

export function validateConsentGrant(requested: Scopes, granted: Scopes): string | null {
  const errors: string[] = [];

  for (const action of ['read', 'write'] as const) {
    const requestedAction = requested[action];
    const grantedAction = granted[action];
    if (!requestedAction || !grantedAction) {
      errors.push(`${action}: scope is missing`);
      continue;
    }

    const extraTags = grantedAction.tags.filter(tag => !requestedAction.tags.includes(tag));
    if (extraTags.length > 0) {
      errors.push(`${action}.tags exceeds requested scope: ${extraTags.join(', ')}`);
    }

    for (const field of ['denyTags', 'denyKeys'] as const) {
      const removed = requestedAction[field].filter(value => !grantedAction[field].includes(value));
      if (removed.length > 0) {
        errors.push(`${action}.${field} removes requested denial: ${removed.join(', ')}`);
      }
    }

    if (action === 'write') {
      const extraKeys = grantedAction.keys.filter(key => !requestedAction.keys.includes(key));
      if (extraKeys.length > 0) {
        errors.push(`${action}.keys exceeds requested scope: ${extraKeys.join(', ')}`);
      }
    }
  }

  return errors.length > 0 ? errors.join('; ') : null;
}

function hashSecret(secret: string): string {
  return createHash('sha256').update(secret).digest('hex');
}

function toArray(value: string | File | (string | File)[] | undefined): string[] {
  if (value === undefined) return [];
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === 'string');
  }
  return typeof value === 'string' ? [value] : [];
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderMessagePage(title: string, message: string): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:560px;margin:64px auto;padding:0 20px;color:#111827}h1{font-size:1.3rem}p{color:#4b5563}</style>
</head>
<body><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></body>
</html>`;
}

export class AuthService {
  private db: Database.Database;
  private issuer: JWTTokenIssuer;
  private defaultDurationMinutes: number;
  private adminToken: string;
  private consentKeyResolver?: (tag: string) => ConsentKeyInfo[];
  private consentKeyLookup?: (key: string) => ConsentKeyInfo | null;
  private aegis?: AegisConsentEvaluator;
  private consentTokens = new Map<string, { token: string; expiresAt: string; sessionId: string }>();
  private app: Hono;

  constructor(options: AuthServiceOptions) {
    this.db = new Database(options.dbPath);
    this.issuer = options.issuer;
    this.defaultDurationMinutes = options.defaultDurationMinutes ?? 30;
    this.adminToken = options.adminToken;
    this.consentKeyResolver = options.consentKeyResolver;
    this.consentKeyLookup = options.consentKeyLookup;
    this.aegis = options.aegis;
    this.initSchema();
    this.app = this.createApp();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        agent_name TEXT,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        closed_at TEXT,
        requested_scopes TEXT NOT NULL,
        granted_scopes TEXT,
        token_hash TEXT
      );

      CREATE TABLE IF NOT EXISTS token_blacklist (
        token_hash TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS consent_requests (
        request_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        client TEXT,
        agent_id TEXT NOT NULL,
        agent_name TEXT,
        requested_scopes TEXT NOT NULL,
        env_path TEXT,
        base_url TEXT,
        secret_hash TEXT,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        approved_at TEXT,
        granted_scopes TEXT,
        aegis_escalations TEXT,
        remote_secret_hash TEXT,
        remote_audience TEXT,
        remote_profile TEXT,
        remote_delivered_at TEXT
      );
    `);

    const consentColumns = this.db.prepare('PRAGMA table_info(consent_requests)').all() as { name: string }[];
    if (!consentColumns.some(column => column.name === 'base_url')) {
      this.db.exec('ALTER TABLE consent_requests ADD COLUMN base_url TEXT');
    }
    if (!consentColumns.some(column => column.name === 'secret_hash')) {
      this.db.exec('ALTER TABLE consent_requests ADD COLUMN secret_hash TEXT');
    }
    if (!consentColumns.some(column => column.name === 'aegis_escalations')) {
      this.db.exec('ALTER TABLE consent_requests ADD COLUMN aegis_escalations TEXT');
    }
    if (!consentColumns.some(column => column.name === 'remote_secret_hash')) {
      this.db.exec('ALTER TABLE consent_requests ADD COLUMN remote_secret_hash TEXT');
    }
    if (!consentColumns.some(column => column.name === 'remote_audience')) {
      this.db.exec('ALTER TABLE consent_requests ADD COLUMN remote_audience TEXT');
    }
    if (!consentColumns.some(column => column.name === 'remote_profile')) {
      this.db.exec('ALTER TABLE consent_requests ADD COLUMN remote_profile TEXT');
    }
    if (!consentColumns.some(column => column.name === 'remote_delivered_at')) {
      this.db.exec('ALTER TABLE consent_requests ADD COLUMN remote_delivered_at TEXT');
    }
  }

  getApp(): Hono {
    return this.app;
  }

  private requireAdmin(c: Context): Response | null {
    const provided = c.req.header('x-uomp-admin-token');
    if (!this.adminToken || !provided) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: 'Admin token required' } }, 401);
    }

    const expected = Buffer.from(this.adminToken);
    const actual = Buffer.from(provided);
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: 'Invalid admin token' } }, 401);
    }

    return null;
  }

  private createApp(): Hono {
    const app = new Hono();

    app.get('/health', c => c.json({ status: 'ok', service: 'uomp' }));

    app.post('/v1/sessions', async c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;

      const body = await c.req.json();
      const parsed = createSessionSchema.safeParse(body);
      if (!parsed.success) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: parsed.error.message } }, 400);
      }

      const session = this.createSession(parsed.data);
      return c.json({
        session_id: session.sessionId,
        status: session.status,
        agent_id: session.agentId,
        requested_scopes: session.requestedScopes,
        expires_at: session.expiresAt,
      });
    });

    app.post('/v1/sessions/:id/grant', async c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;

      const sessionId = c.req.param('id');
      const body = await c.req.json();
      const parsed = grantSessionSchema.safeParse(body);
      if (!parsed.success) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: parsed.error.message } }, 400);
      }

      const session = this.getSession(sessionId);
      if (!session) {
        return c.json({ error: { code: 'SESSION_NOT_FOUND', message: 'Session not found or not in created state' } }, 404);
      }

      const scopeError = validateGrantedScopes(session.requestedScopes, parsed.data.granted_scopes);
      if (scopeError) {
        return c.json({ error: { code: 'SCOPE_EXCEEDS_REQUEST', message: scopeError } }, 400);
      }

      const fieldError = validateGrantedFields(session.requestedScopes, parsed.data.allowed_fields);
      if (fieldError) {
        return c.json({ error: { code: 'SCOPE_EXCEEDS_REQUEST', message: fieldError } }, 400);
      }

      const result = await this.grantSession(sessionId, parsed.data.granted_scopes, {
        profile: parsed.data.profile,
        audience: parsed.data.audience,
        allowedFields: parsed.data.allowed_fields,
        aggregationOnly: parsed.data.aggregation_only,
        taskBound: parsed.data.task_bound,
      });
      if (!result) {
        return c.json({ error: { code: 'SESSION_NOT_FOUND', message: 'Session not found or not in created state' } }, 404);
      }

      return c.json({
        token: result.token,
        token_type: 'Bearer',
        expires_at: result.expiresAt,
      });
    });

    app.post('/v1/sessions/:id/close', c => {
      const sessionId = c.req.param('id');
      const session = this.closeSession(sessionId);
      if (!session) {
        return c.json({ error: { code: 'SESSION_NOT_FOUND', message: 'Session not found' } }, 404);
      }
      return c.json({ session_id: session.sessionId, status: session.status });
    });

    app.post('/v1/sessions/:id/revoke', c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;

      const sessionId = c.req.param('id');
      const session = this.revokeSession(sessionId);
      if (!session) {
        return c.json({ error: { code: 'SESSION_NOT_FOUND', message: 'Session not found' } }, 404);
      }
      return c.json({ session_id: session.sessionId, status: session.status });
    });

    app.post('/v1/tokens/validate', async c => {
      const body = await c.req.json();
      const token = body.token as string;
      try {
        const payload = await this.issuer.verify(token);
        const session = this.getSession(payload.sessionId);
        const isBlacklisted = this.isTokenBlacklisted(payload.sessionId);
        const isActive = session?.status === 'active';
        return c.json({
          valid: isActive && !isBlacklisted,
          session_id: payload.sessionId,
          expires_at: payload.expiresAt,
        });
      } catch {
        return c.json({ valid: false }, 400);
      }
    });

    app.post('/v1/sessions/:id/deletion-proof', async c => {
      const sessionId = c.req.param('id');
      const body = await c.req.json();
      const parsed = deletionProofSchema.safeParse(body);
      if (!parsed.success) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: parsed.error.message } }, 400);
      }

      const proof = parsed.data;
      if (proof.session_id !== sessionId) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: 'session_id mismatch' } }, 400);
      }

      const row = this.db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId) as Record<string, string> | undefined;
      if (!row) {
        return c.json({ error: { code: 'SESSION_NOT_FOUND', message: 'Session not found' } }, 404);
      }

      // Close the session if task_bound (or always close on deletion proof)
      this.db.prepare(`
        UPDATE sessions SET status = 'closed', closed_at = ?
        WHERE session_id = ? AND status = 'active'
      `).run(new Date().toISOString(), sessionId);

      return c.json({ status: 'accepted', deletion_proof_id: proof.deletion_proof_id });
    });

    app.post('/v1/remote/requests', async c => {
      const body = await c.req.json();
      const parsed = remoteRequestSchema.safeParse(body);
      if (!parsed.success) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: parsed.error.message } }, 400);
      }

      try {
        const { request, pollSecret } = await this.createRemoteConsentRequest(parsed.data);
        return c.json({
          request_id: request.requestId,
          status: request.status,
          poll_secret: pollSecret,
          poll_url: `/v1/remote/requests/${request.requestId}`,
          expires_at: request.expiresAt,
          audience: request.remoteAudience,
        }, 201);
      } catch (error) {
        return c.json({
          error: {
            code: 'REMOTE_REQUEST_DENIED',
            message: error instanceof Error ? error.message : String(error),
          },
        }, 403);
      }
    });

    app.get('/v1/remote/requests/:id', c => {
      const secret = c.req.query('secret');
      if (!secret) {
        return c.json({ error: { code: 'UNAUTHORIZED', message: 'poll secret required' } }, 401);
      }
      const result = this.getRemoteConsentRequest(c.req.param('id'), secret);
      if (!result) {
        return c.json({ error: { code: 'REQUEST_NOT_FOUND', message: 'Remote request not found' } }, 404);
      }
      return c.json(result);
    });

    app.post('/v1/consent/requests', async c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;

      const body = await c.req.json();
      const parsed = consentRequestSchema.safeParse(body);
      if (!parsed.success) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: parsed.error.message } }, 400);
      }

      const { request, secret } = await this.createConsentRequestWithAegis(parsed.data);
      const origin = new URL(c.req.url).origin;
      return c.json({
        request_id: request.requestId,
        session_id: request.sessionId,
        status: request.status,
        client: request.client,
        agent_id: request.agentId,
        requested_scopes: request.requestedScopes,
        expires_at: request.expiresAt,
        approval_url: `${origin}/consent/${request.requestId}?secret=${secret}`,
      });
    });

    app.get('/v1/consent/requests', c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;

      const status = c.req.query('status') as ConsentRequestStatus | undefined;
      return c.json(this.listConsentRequests(status));
    });

    app.get('/v1/consent/requests/:id', c => {
      const secret = c.req.query('secret');
      if (secret) {
        if (!this.verifyConsentSecret(c.req.param('id'), secret)) {
          return c.json({ error: { code: 'FORBIDDEN', message: 'Invalid consent secret' } }, 403);
        }
      } else {
        const unauthorized = this.requireAdmin(c);
        if (unauthorized) return unauthorized;
      }

      const request = this.getConsentRequest(c.req.param('id'));
      if (!request) {
        return c.json({ error: { code: 'REQUEST_NOT_FOUND', message: 'Consent request not found' } }, 404);
      }

      const token = secret ? this.consentTokens.get(request.requestId) : undefined;
      return c.json({
        ...request,
        session_id: request.sessionId,
        agent_id: request.agentId,
        ...(token
          ? {
              token: token.token,
              token_expires_at: token.expiresAt,
            }
          : {}),
      });
    });

    app.post('/v1/consent/requests/:id/approve', async c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;

      const body = await c.req.json();
      const parsed = grantSessionSchema.safeParse(body);
      if (!parsed.success) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: parsed.error.message } }, 400);
      }

      try {
        const result = await this.approveConsentRequest(c.req.param('id'), parsed.data.granted_scopes);
        if (!result) {
          return c.json({ error: { code: 'REQUEST_NOT_FOUND', message: 'Consent request not found or not pending' } }, 404);
        }
        return c.json({
          token: result.token,
          token_type: 'Bearer',
          session_id: result.sessionId,
          expires_at: result.expiresAt,
        });
      } catch (error) {
        return c.json({
          error: {
            code: 'SCOPE_EXCEEDS_REQUEST',
            message: error instanceof Error ? error.message : String(error),
          },
        }, 400);
      }
    });

    app.post('/v1/consent/requests/:id/deny', async c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;

      const request = await this.denyConsentRequest(c.req.param('id'));
      if (!request) {
        return c.json({ error: { code: 'REQUEST_NOT_FOUND', message: 'Consent request not found or not pending' } }, 404);
      }
      return c.json({ request_id: request.requestId, status: request.status });
    });

    app.get('/consent/:id', c => {
      const requestId = c.req.param('id');
      const secret = c.req.query('secret');
      if (!secret || !this.verifyConsentSecret(requestId, secret)) {
        return c.html(renderMessagePage('Invalid request', 'This consent link is invalid or has expired.'), 403);
      }

      const request = this.getConsentRequest(requestId);
      if (!request) {
        return c.html(renderMessagePage('Request not found', 'This consent request no longer exists.'), 404);
      }
      if (request.status !== 'pending') {
        return c.html(renderMessagePage(
          'Request already handled',
          `This request is ${request.status}.`
        ));
      }

      return c.html(this.renderConsentPage(request, secret));
    });

    app.post('/consent/:id', async c => {
      const requestId = c.req.param('id');
      const body = await c.req.parseBody();
      const secret = typeof body.secret === 'string' ? body.secret : '';
      if (!secret || !this.verifyConsentSecret(requestId, secret)) {
        return c.html(renderMessagePage('Invalid request', 'This consent link is invalid or has expired.'), 403);
      }

      const request = this.getConsentRequest(requestId);
      if (!request) {
        return c.html(renderMessagePage('Request not found', 'This consent request no longer exists.'), 404);
      }
      if (request.status !== 'pending') {
        return c.html(renderMessagePage('Request already handled', `This request is ${request.status}.`));
      }

      const action = typeof body.action === 'string' ? body.action : '';
      if (action === 'deny') {
        await this.denyConsentRequest(requestId);
        return c.html(renderMessagePage('Access denied', 'The agent will not receive a token.'));
      }
      if (action !== 'approve') {
        return c.html(renderMessagePage('Invalid action', 'Choose approve or deny.'), 400);
      }

      const tags = toArray(body.tag).filter(tag => request.requestedScopes.read.tags.includes(tag));
      const requestedKeys = toArray(body.key);
      const allowedKeys = new Set<string>();

      for (const tag of tags) {
        const keys = this.consentKeyResolver?.(tag) ?? [];
        for (const key of keys) {
          if (requestedKeys.includes(key.key)) {
            allowedKeys.add(key.key);
          }
        }
      }

      for (const key of request.requestedScopes.read.keys) {
        if (requestedKeys.includes(key)) {
          allowedKeys.add(key);
        }
      }

      const grantedScopes: Scopes = {
        read: {
          tags,
          keys: [...allowedKeys],
          denyTags: request.requestedScopes.read.denyTags,
          denyKeys: request.requestedScopes.read.denyKeys,
          ...(request.requestedScopes.read.allowedFields
            ? { allowedFields: request.requestedScopes.read.allowedFields }
            : {}),
        },
        write: {
          tags: [],
          keys: [],
          denyTags: request.requestedScopes.write.denyTags,
          denyKeys: request.requestedScopes.write.denyKeys,
        },
      };

      try {
        const result = await this.approveConsentRequest(requestId, grantedScopes);
        if (!result) {
          return c.html(renderMessagePage('Approval failed', 'The request is no longer pending.'), 409);
        }
        return c.html(renderMessagePage(
          'Access approved',
          'The agent will receive a short-lived token. You can close this window.'
        ));
      } catch (error) {
        return c.html(renderMessagePage(
          'Approval failed',
          error instanceof Error ? error.message : String(error)
        ), 400);
      }
    });

    return app;
  }

  createSession(data: z.infer<typeof createSessionSchema>): Session {
    const sessionId = generateId('sess');
    const now = new Date();
    const duration = data.duration_minutes ?? this.defaultDurationMinutes;
    const expiresAt = new Date(now.getTime() + duration * 60 * 1000);

    const session: Session = {
      sessionId,
      agentId: data.agent_id,
      agentName: data.agent_name,
      status: 'created',
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      requestedScopes: data.requested_scopes,
    };

    const stmt = this.db.prepare(`
      INSERT INTO sessions (session_id, agent_id, agent_name, status, created_at, expires_at, requested_scopes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      session.sessionId,
      session.agentId,
      session.agentName ?? null,
      session.status,
      session.createdAt,
      session.expiresAt,
      JSON.stringify(session.requestedScopes)
    );

    return session;
  }

  createConsentRequest(data: CreateConsentRequestInput): { request: ConsentRequest; secret: string } {
    return this.insertConsentRequest(data, []);
  }

  async createConsentRequestWithAegis(
    data: CreateConsentRequestInput,
    options: { remoteSecretHash?: string } = {},
  ): Promise<{ request: ConsentRequest; secret: string }> {
    if (!this.aegis) {
      return this.insertConsentRequest(data, [], options.remoteSecretHash);
    }

    const evaluation = await this.aegis.evaluateScopes(data.requested_scopes);
    if (evaluation.decision === 'deny') {
      throw new Error('Aegis denied the memory request.');
    }

    return this.insertConsentRequest(data, evaluation.escalationIds, options.remoteSecretHash);
  }

  async createRemoteConsentRequest(
    data: RemoteConsentRequestInput,
  ): Promise<{ request: ConsentRequest; secret: string; pollSecret: string }> {
    const pollSecret = randomBytes(24).toString('hex');
    const result = await this.createConsentRequestWithAegis({
      agent_id: data.agent_id,
      ...(data.agent_name ? { agent_name: data.agent_name } : {}),
      requested_scopes: data.requested_scopes,
      duration_minutes: data.duration_minutes ?? this.defaultDurationMinutes,
      remote: { audience: data.audience, profile: 'remote' },
    }, { remoteSecretHash: hashSecret(pollSecret) });

    return { ...result, pollSecret };
  }

  private insertConsentRequest(
    data: CreateConsentRequestInput,
    aegisEscalationIds: string[],
    remoteSecretHash?: string,
  ): { request: ConsentRequest; secret: string } {
    const session = this.createSession({
      agent_id: data.agent_id,
      ...(data.agent_name ? { agent_name: data.agent_name } : {}),
      requested_scopes: data.requested_scopes,
      duration_minutes: data.duration_minutes ?? this.defaultDurationMinutes,
    });

    const requestId = generateId('consent');
    const createdAt = new Date().toISOString();
    const secret = randomBytes(24).toString('hex');
    const secretHash = hashSecret(secret);
    const remoteAudience = data.remote?.audience;
    const remoteProfile = data.remote?.profile ?? (data.remote ? 'remote' : undefined);

    this.db.prepare(`
      INSERT INTO consent_requests (
        request_id, session_id, client, agent_id, agent_name, requested_scopes,
        env_path, base_url, secret_hash, status, created_at, expires_at, aegis_escalations,
        remote_secret_hash, remote_audience, remote_profile
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
    `).run(
      requestId,
      session.sessionId,
      data.client ?? null,
      data.agent_id,
      data.agent_name ?? null,
      JSON.stringify(data.requested_scopes),
      data.env_path ?? null,
      data.base_url ?? null,
      secretHash,
      createdAt,
      session.expiresAt,
      aegisEscalationIds.length > 0 ? JSON.stringify(aegisEscalationIds) : null,
      remoteSecretHash ?? null,
      remoteAudience ?? null,
      remoteProfile ?? null
    );

    return {
      request: {
        requestId,
        sessionId: session.sessionId,
        ...(data.client ? { client: data.client } : {}),
        agentId: data.agent_id,
        ...(data.agent_name ? { agentName: data.agent_name } : {}),
        requestedScopes: data.requested_scopes,
        ...(data.env_path ? { envPath: data.env_path } : {}),
        ...(data.base_url ? { baseUrl: data.base_url } : {}),
        status: 'pending',
        createdAt,
        expiresAt: session.expiresAt,
        ...(aegisEscalationIds.length > 0
          ? { aegisEscalationIds }
          : {}),
        ...(remoteAudience ? { remoteAudience } : {}),
        ...(remoteProfile ? { remoteProfile } : {}),
      },
      secret,
    };
  }

  getRemoteConsentRequest(
    requestId: string,
    pollSecret: string,
  ): { status: ConsentRequestStatus; token?: string; token_type?: string; session_id?: string; expires_at?: string; delivered?: boolean } | null {
    const row = this.db.prepare('SELECT * FROM consent_requests WHERE request_id = ?')
      .get(requestId) as Record<string, string> | undefined;
    if (!row?.remote_secret_hash) return null;

    const expected = Buffer.from(row.remote_secret_hash);
    const actual = Buffer.from(hashSecret(pollSecret));
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      return null;
    }

    const request = this.getConsentRequest(requestId);
    if (!request) return null;

    if (request.status !== 'approved') {
      return { status: request.status, expires_at: request.expiresAt };
    }

    if (row.remote_delivered_at) {
      return { status: 'approved', delivered: true, expires_at: request.expiresAt };
    }

    const stored = this.consentTokens.get(requestId);
    if (!stored) {
      return { status: 'approved', delivered: true, expires_at: request.expiresAt };
    }

    this.db.prepare('UPDATE consent_requests SET remote_delivered_at = ? WHERE request_id = ?')
      .run(new Date().toISOString(), requestId);

    return {
      status: 'approved',
      token: stored.token,
      token_type: 'Bearer',
      session_id: stored.sessionId,
      expires_at: stored.expiresAt,
    };
  }


  getConsentRequest(requestId: string): ConsentRequest | null {
    const row = this.db.prepare('SELECT * FROM consent_requests WHERE request_id = ?')
      .get(requestId) as Record<string, string> | undefined;
    if (!row) return null;

    if (row.status === 'pending' && Date.parse(row.expires_at) <= Date.now()) {
      this.db.prepare("UPDATE consent_requests SET status = 'expired' WHERE request_id = ? AND status = 'pending'")
        .run(requestId);
      this.closeSession(row.session_id);
      return this.deserializeConsentRequest({ ...row, status: 'expired' });
    }

    return this.deserializeConsentRequest(row);
  }

  verifyConsentSecret(requestId: string, secret: string): boolean {
    const row = this.db.prepare('SELECT secret_hash FROM consent_requests WHERE request_id = ?')
      .get(requestId) as { secret_hash?: string } | undefined;
    if (!row?.secret_hash) return false;

    const expected = Buffer.from(row.secret_hash);
    const actual = Buffer.from(hashSecret(secret));
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }

  private renderConsentPage(request: ConsentRequest, secret: string): string {
    const tags = request.requestedScopes.read.tags;
    const renderedKeys = new Set<string>();
    const rows = tags.map(tag => {
      const keys = this.consentKeyResolver?.(tag) ?? [];
      const sensitivity = keys.some(key => key.sensitivity === 'high') || inferSensitivity(tag) === 'high'
        ? 'high'
        : keys.some(key => key.sensitivity === 'medium') || inferSensitivity(tag) === 'medium'
          ? 'medium'
          : 'low';
      const checked = sensitivity === 'high' ? '' : ' checked';
      const keyRows = sensitivity === 'high'
        ? keys.map(key => {
          renderedKeys.add(key.key);
          return `
            <label class="key">
              <input type="checkbox" name="key" value="${escapeHtml(key.key)}">
              <span>${escapeHtml(key.key)}${key.title ? ` — ${escapeHtml(key.title)}` : ''}</span>
            </label>`;
        }).join('')
        : '';

      return `
        <section class="scope">
          <label class="tag">
            <input type="checkbox" name="tag" value="${escapeHtml(tag)}"${checked}>
            <span>${escapeHtml(tag)}</span>
            <em class="${sensitivity}">${sensitivity}</em>
          </label>
          ${keyRows ? `<div class="keys">${keyRows}</div>` : ''}
        </section>`;
    }).join('');

    const requestedKeyRows = request.requestedScopes.read.keys
      .filter(key => !renderedKeys.has(key))
      .map(key => {
        const info = this.consentKeyLookup?.(key);
        const sensitivity = info?.sensitivity ?? 'high';
        const checked = sensitivity === 'high' ? '' : ' checked';
        return `
          <label class="key">
            <input type="checkbox" name="key" value="${escapeHtml(key)}"${checked}>
            <span>${escapeHtml(key)}${info?.title ? ` — ${escapeHtml(info.title)}` : ''}</span>
            <em class="${sensitivity}">${sensitivity}</em>
          </label>`;
      }).join('');

    const title = escapeHtml(request.agentName ?? request.agentId);
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UOMP consent</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 system-ui, sans-serif; max-width: 680px; margin: 48px auto; padding: 0 20px; }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  h2 { font-size: 1rem; margin: 20px 0 8px; }
  .muted { color: #6b7280; }
  .scope { border: 1px solid #d1d5db; border-radius: 10px; padding: 12px 14px; margin: 12px 0; }
  .tag { display: flex; gap: 8px; align-items: center; font-weight: 600; }
  .tag em, .key em { margin-left: auto; font-style: normal; font-size: .7rem; padding: 2px 7px; border-radius: 999px; }
  .tag em.low, .key em.low { background: #dcfce7; color: #166534; }
  .tag em.medium, .key em.medium { background: #fef3c7; color: #92400e; }
  .tag em.high, .key em.high { background: #fee2e2; color: #991b1b; }
  .keys { margin: 10px 0 0 24px; display: grid; gap: 6px; }
  .key { display: flex; gap: 8px; font-size: .9rem; color: #4b5563; padding: 6px 0; }
  .actions { display: flex; gap: 10px; margin-top: 24px; }
  button { font: inherit; padding: 9px 18px; border-radius: 8px; border: 1px solid #d1d5db; cursor: pointer; }
  button.approve { background: #2563eb; color: #fff; border-color: #2563eb; }
  button.deny { background: transparent; }
</style>
</head>
<body>
  <h1>Allow ${title}?</h1>
  <p class="muted">${escapeHtml(request.client ?? request.agentId)} · expires ${escapeHtml(request.expiresAt)}</p>
  <p>High-sensitivity tags and keys are unchecked by default. Select what this agent may read.</p>
  <form method="post" action="/consent/${encodeURIComponent(request.requestId)}">
    <input type="hidden" name="secret" value="${escapeHtml(secret)}">
    ${rows || (requestedKeyRows ? '' : '<p class="muted">This request has no readable scope.</p>')}
    ${requestedKeyRows ? `<h2>Requested keys</h2><section class="scope">${requestedKeyRows}</section>` : ''}
    <div class="actions">
      <button class="approve" name="action" value="approve" type="submit">Approve</button>
      <button class="deny" name="action" value="deny" type="submit">Deny</button>
    </div>
  </form>
</body>
</html>`;
  }


  listConsentRequests(status: ConsentRequestStatus = 'pending'): ConsentRequest[] {
    const rows = this.db.prepare('SELECT * FROM consent_requests WHERE status = ? ORDER BY created_at DESC')
      .all(status) as Record<string, string>[];
    const requests = rows.map(row => this.deserializeConsentRequest(row));

    if (status === 'pending') {
      for (const request of requests) {
        if (Date.parse(request.expiresAt) <= Date.now()) {
          this.db.prepare("UPDATE consent_requests SET status = 'expired' WHERE request_id = ? AND status = 'pending'")
            .run(request.requestId);
          this.closeSession(request.sessionId);
          request.status = 'expired';
        }
      }
      return requests.filter(request => request.status === 'pending');
    }

    return requests;
  }

  async approveConsentRequest(
    requestId: string,
    grantedScopes: Scopes
  ): Promise<{ token: string; expiresAt: string; sessionId: string } | null> {
    const request = this.getConsentRequest(requestId);
    if (!request || request.status !== 'pending') {
      return null;
    }

    const scopeError = validateConsentGrant(request.requestedScopes, grantedScopes);
    if (scopeError) {
      throw new Error(scopeError);
    }

    if (request.aegisEscalationIds?.length && this.aegis) {
      const ttlSecs = Math.max(
        1,
        Math.floor((Date.parse(request.expiresAt) - Date.now()) / 1000),
      );
      await this.aegis.approveEscalations(request.aegisEscalationIds, ttlSecs);
    }

    const result = await this.grantSession(request.sessionId, grantedScopes, {
      ...(request.remoteProfile ? { profile: request.remoteProfile } : {}),
      ...(request.remoteAudience ? { audience: request.remoteAudience } : {}),
    });
    if (!result) {
      return null;
    }

    this.db.prepare(`
      UPDATE consent_requests
      SET status = 'approved', approved_at = ?, granted_scopes = ?
      WHERE request_id = ? AND status = 'pending'
    `).run(new Date().toISOString(), JSON.stringify(grantedScopes), requestId);

    this.consentTokens.set(requestId, {
      token: result.token,
      expiresAt: result.expiresAt,
      sessionId: request.sessionId,
    });

    return {
      token: result.token,
      expiresAt: result.expiresAt,
      sessionId: request.sessionId,
    };
  }

  async denyConsentRequest(requestId: string): Promise<ConsentRequest | null> {
    const request = this.getConsentRequest(requestId);
    if (!request || request.status !== 'pending') {
      return null;
    }

    if (request.aegisEscalationIds?.length && this.aegis?.denyEscalations) {
      await this.aegis.denyEscalations(request.aegisEscalationIds);
    }

    this.db.prepare("UPDATE consent_requests SET status = 'denied', approved_at = ? WHERE request_id = ? AND status = 'pending'")
      .run(new Date().toISOString(), requestId);
    this.closeSession(request.sessionId);

    return { ...request, status: 'denied' };
  }

  async grantSession(
    sessionId: string,
    grantedScopes: Scopes,
    options?: { profile?: string; audience?: string; allowedFields?: string[]; aggregationOnly?: boolean; taskBound?: boolean }
  ): Promise<{ token: string; expiresAt: string } | null> {
    const row = this.db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId) as Record<string, string> | undefined;
    if (!row || row.status !== 'created') {
      return null;
    }

    const expiresAt = new Date(row.expires_at);
    const profile = options?.profile ?? 'local';
    const audience = options?.audience ?? (profile === 'remote' ? undefined : `http://127.0.0.1:9374`);
    const payload: CapabilityTokenPayload = {
      version: '1.0',
      sessionId,
      agentId: row.agent_id,
      issuedAt: new Date().toISOString(),
      expiresAt: expiresAt.toISOString(),
      scopes: grantedScopes,
      profile,
      audience,
      limits: { maxReadQueries: 100, maxWriteQueries: 0 },
      allowedFields: options?.allowedFields ?? grantedScopes.read?.allowedFields,
      aggregationOnly: options?.aggregationOnly ?? false,
      taskBound: options?.taskBound ?? false,
    };

    const token = await this.issuer.issue(payload);
    const tokenHash = this.hashToken(token);

    const updated = this.db.prepare(`
      UPDATE sessions SET status = 'active', granted_scopes = ?, token_hash = ?
      WHERE session_id = ? AND status = 'created'
    `).run(JSON.stringify(grantedScopes), tokenHash, sessionId);
    if (updated.changes !== 1) {
      return null;
    }

    return { token, expiresAt: expiresAt.toISOString() };
  }

  closeSession(sessionId: string): Session | null {
    const row = this.db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId) as Record<string, string> | undefined;
    if (!row) return null;

    if (row.status === 'revoked') {
      return this.deserializeSession(row);
    }

    const now = new Date().toISOString();
    const updated = this.db.prepare(`
      UPDATE sessions SET status = 'closed', closed_at = ?
      WHERE session_id = ? AND status IN ('created', 'active')
    `).run(now, sessionId);

    if (updated.changes === 0) {
      const current = this.db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId) as Record<string, string> | undefined;
      return current ? this.deserializeSession(current) : null;
    }

    if (row.token_hash) {
      this.blacklistToken(row.token_hash, sessionId, row.expires_at);
    }

    return this.deserializeSession(row, 'closed');
  }

  revokeSession(sessionId: string): Session | null {
    const row = this.db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId) as Record<string, string> | undefined;
    if (!row) return null;

    if (row.status === 'revoked') {
      return this.deserializeSession(row);
    }

    const now = new Date().toISOString();
    const updated = this.db.prepare(`
      UPDATE sessions SET status = 'revoked', closed_at = ?
      WHERE session_id = ? AND status != 'revoked'
    `).run(now, sessionId);

    if (updated.changes === 0) {
      const current = this.db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId) as Record<string, string> | undefined;
      return current ? this.deserializeSession(current) : null;
    }

    if (row.token_hash) {
      this.blacklistToken(row.token_hash, sessionId, row.expires_at);
    }

    return this.deserializeSession(row, 'revoked');
  }

  getSession(sessionId: string): Session | null {
    const row = this.db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId) as Record<string, string> | undefined;
    return row ? this.deserializeSession(row) : null;
  }

  listSessions(options: { includeClosed?: boolean } = {}): Session[] {
    const where = options.includeClosed ? '' : "WHERE status = 'active'";
    const rows = this.db.prepare(`SELECT * FROM sessions ${where} ORDER BY created_at DESC`).all() as Record<string, string>[];
    return rows.map(row => this.deserializeSession(row));
  }

  isTokenBlacklisted(sessionId: string): boolean {
    const row = this.db.prepare('SELECT 1 FROM token_blacklist WHERE session_id = ?').get(sessionId);
    return !!row;
  }

  private blacklistToken(tokenHash: string, sessionId: string, expiresAt: string): void {
    this.db.prepare(`
      INSERT OR IGNORE INTO token_blacklist (token_hash, session_id, expires_at)
      VALUES (?, ?, ?)
    `).run(tokenHash, sessionId, expiresAt);
  }

  private hashToken(token: string): string {
    // Simple hash for MVP. In production use crypto.subtle.digest.
    let hash = 0;
    for (let i = 0; i < token.length; i++) {
      const char = token.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return hash.toString(16);
  }

  private deserializeSession(row: Record<string, string>, overrideStatus?: string): Session {
    return {
      sessionId: row.session_id,
      agentId: row.agent_id,
      agentName: row.agent_name,
      status: (overrideStatus ?? row.status) as Session['status'],
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      closedAt: row.closed_at,
      requestedScopes: JSON.parse(row.requested_scopes) as Scopes,
      grantedScopes: row.granted_scopes ? (JSON.parse(row.granted_scopes) as Scopes) : undefined,
      tokenHash: row.token_hash,
    };
  }

  private deserializeConsentRequest(row: Record<string, string>): ConsentRequest {
    return {
      requestId: row.request_id,
      sessionId: row.session_id,
      ...(row.client ? { client: row.client } : {}),
      agentId: row.agent_id,
      ...(row.agent_name ? { agentName: row.agent_name } : {}),
      requestedScopes: JSON.parse(row.requested_scopes) as Scopes,
      ...(row.env_path ? { envPath: row.env_path } : {}),
      ...(row.base_url ? { baseUrl: row.base_url } : {}),
      status: row.status as ConsentRequestStatus,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      ...(row.approved_at ? { approvedAt: row.approved_at } : {}),
      ...(row.granted_scopes ? { grantedScopes: JSON.parse(row.granted_scopes) as Scopes } : {}),
      ...(row.aegis_escalations
        ? { aegisEscalationIds: JSON.parse(row.aegis_escalations) as string[] }
        : {}),
      ...(row.remote_audience ? { remoteAudience: row.remote_audience } : {}),
      ...(row.remote_profile ? { remoteProfile: row.remote_profile } : {}),
    };
  }

  close(): void {
    this.db.close();
  }
}
