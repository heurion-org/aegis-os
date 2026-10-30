import Database from 'better-sqlite3';
import { Hono, type Context } from 'hono';
import { timingSafeEqual } from 'crypto';
import type { MemoryItem } from '@uomp/core';
import { generateId } from '@uomp/core';
import { MemoryStore, AsyncStoreAdapter } from '@uomp/store';
import type { IMemoryStore } from '@uomp/store';
import { JWTTokenIssuer, isTokenExpired, type CapabilityTokenPayload } from '@uomp/token';

export interface GuardSessionState {
  status: string;
  expiresAt: string;
}

export interface SessionStateProvider {
  getSession(sessionId: string): GuardSessionState | null;
  isTokenBlacklisted(sessionId: string): boolean;
}

export interface GuardOptions {
  dbPath: string;
  memoryDbPath: string;
  issuer: JWTTokenIssuer;
  store?: IMemoryStore;
  sessionStateProvider?: SessionStateProvider;
  adminToken?: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  sessionId: string;
  agentId: string;
  action: 'read' | 'write' | 'delete' | 'query';
  key?: string;
  tags?: string[];
  allowed: boolean;
  reason: string;
}

export class MemoryGuard {
  private db: Database.Database;
  private store: IMemoryStore;
  private issuer: JWTTokenIssuer;
  private sessionStateProvider?: SessionStateProvider;
  private adminToken?: string;
  private app: Hono;

  constructor(options: GuardOptions) {
    this.db = new Database(options.dbPath);
    this.store = options.store ?? new AsyncStoreAdapter(new MemoryStore({ dbPath: options.memoryDbPath }));
    this.issuer = options.issuer;
    this.sessionStateProvider = options.sessionStateProvider;
    this.adminToken = options.adminToken;
    this.initSchema();
    this.app = this.createApp();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        session_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        action TEXT NOT NULL,
        key TEXT,
        tags TEXT,
        allowed INTEGER NOT NULL,
        reason TEXT NOT NULL,
        request_size INTEGER,
        response_size INTEGER,
        query_count_remaining INTEGER
      );

      CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_logs(session_id);
      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

      CREATE TABLE IF NOT EXISTS payloads (
        payload_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        envelope TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_payloads_session ON payloads(session_id);
    `);
  }

  getApp(): Hono {
    return this.app;
  }

  private isAdmin(c: Context): boolean {
    if (!this.adminToken) return false;
    const provided = c.req.header('x-uomp-admin-token');
    if (!provided) return false;
    const expected = Buffer.from(this.adminToken);
    const actual = Buffer.from(provided);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }

  private requireAdmin(c: Context): Response | null {
    if (!this.adminToken) {
      return c.json({ error: { code: 'ADMIN_DISABLED', message: 'Admin approval is not configured' } }, 503);
    }
    if (!this.isAdmin(c)) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: 'Admin token required' } }, 401);
    }
    return null;
  }

  private createApp(): Hono {
    const app = new Hono();

    app.get('/v1/memory/aggregate', async c => {
      const tag = c.req.query('tag');
      const op = c.req.query('op');
      const field = c.req.query('field');
      const authHeader = c.req.header('authorization');

      const validation = await this.validateRequest(authHeader);
      if (!validation.valid) {
        this.logAudit({
          sessionId: validation.sessionId ?? 'unknown',
          agentId: validation.agentId ?? 'unknown',
          action: 'read',
          tags: tag ? [tag] : undefined,
          allowed: false,
          reason: validation.reason,
        });
        return c.json(
          { error: { code: validation.errorCode, message: validation.reason, session_id: validation.sessionId } },
          this.statusForValidationError(validation.errorCode)
        );
      }

      if (!tag) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: 'tag query parameter is required' } }, 400);
      }

      if (!op || !['sum', 'avg', 'count', 'min', 'max'].includes(op)) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: 'op must be sum, avg, count, min, or max' } }, 400);
      }

      const allowed = this.isTagAllowed(tag, validation.payload!, 'read');
      this.logAudit({
        sessionId: validation.payload!.sessionId,
        agentId: validation.payload!.agentId,
        action: 'read',
        tags: [tag],
        allowed: allowed.allowed,
        reason: allowed.reason,
      });

      if (!allowed.allowed) {
        return c.json({ error: { code: 'ACCESS_DENIED', message: allowed.reason, session_id: validation.payload!.sessionId } }, 403);
      }

      const items = await this.store.getByTag(tag);
      const filtered = items.filter(item => this.isKeyAllowed(item.key, item, validation.payload!, 'read').allowed);

      const result = this.computeAggregation(filtered, op, field ?? undefined);
      return c.json(result);
    });

    app.get('/v1/memory/:key', async c => {
      const key = c.req.param('key');
      const authHeader = c.req.header('authorization');

      const validation = await this.validateRequest(authHeader);
      if (!validation.valid) {
        this.logAudit({
          sessionId: validation.sessionId ?? 'unknown',
          agentId: validation.agentId ?? 'unknown',
          action: 'read',
          key,
          allowed: false,
          reason: validation.reason,
        });
        return c.json(
          { error: { code: validation.errorCode, message: validation.reason, session_id: validation.sessionId } },
          this.statusForValidationError(validation.errorCode)
        );
      }

      if (validation.payload!.aggregationOnly) {
        return c.json({ error: { code: 'ACCESS_DENIED', message: 'Token only permits aggregation queries' } }, 403);
      }

      const item = await this.store.get(key);
      const allowed = this.isKeyAllowed(key, item, validation.payload!, 'read');

      this.logAudit({
        sessionId: validation.payload!.sessionId,
        agentId: validation.payload!.agentId,
        action: 'read',
        key,
        allowed: allowed.allowed,
        reason: allowed.reason,
      });

      if (!allowed.allowed) {
        return c.json({ error: { code: 'ACCESS_DENIED', message: allowed.reason, session_id: validation.payload!.sessionId } }, 403);
      }

      return c.json(this.serializeItem(item!, validation.payload!.allowedFields));
    });

    app.get('/v1/memory', async c => {
      const tag = c.req.query('tag');
      const authHeader = c.req.header('authorization');

      const validation = await this.validateRequest(authHeader);
      if (!validation.valid) {
        this.logAudit({
          sessionId: validation.sessionId ?? 'unknown',
          agentId: validation.agentId ?? 'unknown',
          action: 'read',
          tags: tag ? [tag] : undefined,
          allowed: false,
          reason: validation.reason,
        });
        return c.json(
          { error: { code: validation.errorCode, message: validation.reason, session_id: validation.sessionId } },
          this.statusForValidationError(validation.errorCode)
        );
      }

      if (validation.payload!.aggregationOnly) {
        return c.json({ error: { code: 'ACCESS_DENIED', message: 'Token only permits aggregation queries' } }, 403);
      }

      if (!tag) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: 'tag query parameter is required' } }, 400);
      }

      const allowed = this.isTagAllowed(tag, validation.payload!, 'read');
      this.logAudit({
        sessionId: validation.payload!.sessionId,
        agentId: validation.payload!.agentId,
        action: 'read',
        tags: [tag],
        allowed: allowed.allowed,
        reason: allowed.reason,
      });

      if (!allowed.allowed) {
        return c.json({ error: { code: 'ACCESS_DENIED', message: allowed.reason, session_id: validation.payload!.sessionId } }, 403);
      }

      const items = await this.store.getByTag(tag);
      const filtered = items.filter(item => this.isKeyAllowed(item.key, item, validation.payload!, 'read').allowed);

      return c.json({ items: filtered.map(item => this.serializeItem(item, validation.payload!.allowedFields)) });
    });

    app.put('/v1/memory/:key', async c => {
      const key = c.req.param('key');
      const authHeader = c.req.header('authorization');
      const validation = await this.validateRequest(authHeader);

      if (!validation.valid) {
        return c.json(
          { error: { code: validation.errorCode, message: validation.reason, session_id: validation.sessionId } },
          this.statusForValidationError(validation.errorCode)
        );
      }

      const body = await c.req.json().catch(() => null) as {
        value?: unknown;
        tags?: string[];
        sensitivity?: 'low' | 'medium' | 'high';
        description?: string;
      } | null;
      if (!body || body.value === undefined) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: 'value is required' } }, 400);
      }

      const tags = Array.isArray(body.tags) ? body.tags.filter((tag): tag is string => typeof tag === 'string') : [];
      const sensitivity = body.sensitivity ?? 'medium';
      const scope = validation.payload.scopes.write;
      const keyAllowed = scope.keys.includes(key) && !scope.denyKeys.includes(key);
      const tagAllowed = tags.some(tag => scope.tags.includes(tag) && !scope.denyTags.includes(tag));

      if (sensitivity === 'high') {
        this.logAudit({
          sessionId: validation.payload.sessionId,
          agentId: validation.payload.agentId,
          action: 'write',
          key,
          tags,
          allowed: false,
          reason: 'HIGH_SENSITIVITY_WRITE_DENIED',
        });
        return c.json({ error: { code: 'HIGH_SENSITIVITY_WRITE_DENIED', message: 'Agent writes to high-sensitivity items are not allowed' } }, 403);
      }

      if (!keyAllowed && !tagAllowed) {
        this.logAudit({
          sessionId: validation.payload.sessionId,
          agentId: validation.payload.agentId,
          action: 'write',
          key,
          tags,
          allowed: false,
          reason: 'WRITE_OUTSIDE_SCOPE',
        });
        return c.json({ error: { code: 'ACCESS_DENIED', message: 'Write is outside the granted scope' } }, 403);
      }

      if (!this.store.stageWrite) {
        return c.json({ error: { code: 'STAGING_UNAVAILABLE', message: 'This store does not support staged writes' } }, 501);
      }

      const staged = await this.store.stageWrite({
        sessionId: validation.payload.sessionId,
        agentId: validation.payload.agentId,
        key,
        value: body.value,
        tags,
        sensitivity,
        ...(body.description ? { description: body.description } : {}),
      });

      this.logAudit({
        sessionId: validation.payload.sessionId,
        agentId: validation.payload.agentId,
        action: 'write',
        key,
        tags,
        allowed: true,
        reason: 'STAGED_FOR_APPROVAL',
      });

      return c.json({
        staged_write_id: staged.id,
        status: staged.status,
        approval_required: true,
        session_id: validation.sessionId,
      }, 202);
    });

    app.get('/v1/staged-writes', async c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;
      if (!this.store.listStagedWrites) {
        return c.json({ error: { code: 'STAGING_UNAVAILABLE', message: 'This store does not support staged writes' } }, 501);
      }
      const status = (c.req.query('status') ?? 'pending') as 'pending' | 'approved' | 'denied';
      return c.json({ staged_writes: await this.store.listStagedWrites(status) });
    });

    app.post('/v1/staged-writes/:id/approve', async c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;
      if (!this.store.approveStagedWrite) {
        return c.json({ error: { code: 'STAGING_UNAVAILABLE', message: 'This store does not support staged writes' } }, 501);
      }
      const body = await c.req.json().catch(() => ({})) as { reviewed_by?: string };
      const item = await this.store.approveStagedWrite(c.req.param('id'), body.reviewed_by ?? 'user');
      if (!item) {
        return c.json({ error: { code: 'STAGED_WRITE_NOT_FOUND', message: 'Staged write not found or not pending' } }, 404);
      }
      this.logAudit({
        sessionId: 'admin',
        agentId: body.reviewed_by ?? 'user',
        action: 'write',
        key: item.key,
        tags: item.tags,
        allowed: true,
        reason: 'STAGED_WRITE_APPROVED',
      });
      return c.json({ status: 'approved', item });
    });

    app.post('/v1/staged-writes/:id/deny', async c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;
      if (!this.store.denyStagedWrite) {
        return c.json({ error: { code: 'STAGING_UNAVAILABLE', message: 'This store does not support staged writes' } }, 501);
      }
      const body = await c.req.json().catch(() => ({})) as { reviewed_by?: string };
      const staged = await this.store.denyStagedWrite(c.req.param('id'), body.reviewed_by ?? 'user');
      if (!staged) {
        return c.json({ error: { code: 'STAGED_WRITE_NOT_FOUND', message: 'Staged write not found or not pending' } }, 404);
      }
      this.logAudit({
        sessionId: 'admin',
        agentId: body.reviewed_by ?? 'user',
        action: 'write',
        key: staged.key,
        tags: staged.tags,
        allowed: false,
        reason: 'STAGED_WRITE_DENIED',
      });
      return c.json({ status: 'denied', staged_write: staged });
    });

    app.post('/v1/payload', async c => {
      const authHeader = c.req.header('authorization');
      const validation = await this.validateRequest(authHeader);
      if (!validation.valid) {
        return c.json(
          { error: { code: validation.errorCode, message: validation.reason, session_id: validation.sessionId } },
          this.statusForValidationError(validation.errorCode)
        );
      }

      const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
      if (!body || typeof body.ciphertext !== 'string' || body.ciphertext.length === 0) {
        return c.json({ error: { code: 'INVALID_REQUEST', message: 'ciphertext is required' } }, 400);
      }
      if (!body.encryption || typeof body.encryption !== 'object') {
        return c.json({ error: { code: 'INVALID_REQUEST', message: 'encryption metadata is required' } }, 400);
      }
      if (body.session_id && body.session_id !== validation.payload.sessionId) {
        return c.json({ error: { code: 'SESSION_MISMATCH', message: 'payload session does not match token' } }, 403);
      }
      if (body.agent_id && body.agent_id !== validation.payload.agentId) {
        return c.json({ error: { code: 'AGENT_MISMATCH', message: 'payload agent does not match token' } }, 403);
      }

      const payloadId = generateId('pay');
      const envelope = {
        ...body,
        payload_id: payloadId,
        session_id: validation.payload.sessionId,
        agent_id: validation.payload.agentId,
        timestamp: typeof body.timestamp === 'string' ? body.timestamp : new Date().toISOString(),
      };
      this.db.prepare(`
        INSERT INTO payloads (payload_id, session_id, agent_id, envelope, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(
        payloadId,
        validation.payload.sessionId,
        validation.payload.agentId,
        JSON.stringify(envelope),
        new Date().toISOString(),
      );

      this.logAudit({
        sessionId: validation.payload.sessionId,
        agentId: validation.payload.agentId,
        action: 'write',
        allowed: true,
        reason: 'PAYLOAD_STORED',
      });

      return c.json({ payload_id: payloadId, status: 'stored', session_id: validation.payload.sessionId }, 201);
    });

    app.get('/v1/payload/:id', async c => {
      const row = this.db.prepare('SELECT * FROM payloads WHERE payload_id = ?')
        .get(c.req.param('id')) as Record<string, string> | undefined;
      if (!row) {
        return c.json({ error: { code: 'PAYLOAD_NOT_FOUND', message: 'Payload not found' } }, 404);
      }

      const validation = await this.validateRequest(c.req.header('authorization'));
      const admin = this.isAdmin(c);
      if (!admin && (!validation.valid || row.session_id !== validation.payload.sessionId)) {
        return c.json({ error: { code: 'ACCESS_DENIED', message: 'Payload belongs to another session' } }, 403);
      }

      return c.json(JSON.parse(row.envelope) as Record<string, unknown>);
    });

    app.get('/v1/payload', async c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;
      const rows = this.db.prepare('SELECT * FROM payloads ORDER BY created_at DESC').all() as Record<string, string>[];
      return c.json({
        payloads: rows.map(row => {
          const envelope = JSON.parse(row.envelope) as Record<string, unknown>;
          return {
            payload_id: row.payload_id,
            session_id: row.session_id,
            agent_id: row.agent_id,
            created_at: row.created_at,
            format: envelope.format,
            size: envelope.size,
            hash: envelope.hash,
          };
        }),
      });
    });

    app.delete('/v1/payload/:id', async c => {
      const unauthorized = this.requireAdmin(c);
      if (unauthorized) return unauthorized;
      const result = this.db.prepare('DELETE FROM payloads WHERE payload_id = ?').run(c.req.param('id'));
      if (result.changes === 0) {
        return c.json({ error: { code: 'PAYLOAD_NOT_FOUND', message: 'Payload not found' } }, 404);
      }
      return c.json({ status: 'deleted', payload_id: c.req.param('id') });
    });

    app.delete('/v1/memory/:key', async c => {
      const key = c.req.param('key');
      const authHeader = c.req.header('authorization');
      const validation = await this.validateRequest(authHeader);

      if (!validation.valid) {
        return c.json(
          { error: { code: validation.errorCode, message: validation.reason, session_id: validation.sessionId } },
          this.statusForValidationError(validation.errorCode)
        );
      }

      this.logAudit({
        sessionId: validation.payload.sessionId,
        agentId: validation.payload.agentId,
        action: 'delete',
        key,
        allowed: false,
        reason: 'DELETE_NOT_AVAILABLE_IN_MVP',
      });

      return c.json({ error: { code: 'WRITE_NOT_AVAILABLE', message: 'Agent deletes are not available in MVP', session_id: validation.sessionId } }, 503);
    });

    app.get('/v1/audit', async c => {
      const authHeader = c.req.header('authorization');
      const sessionId = c.req.query('session_id');
      const agentId = c.req.query('agent_id');
      const limit = c.req.query('limit');

      const validation = await this.validateRequest(authHeader);
      if (!validation.valid) {
        return c.json(
          { error: { code: validation.errorCode, message: validation.reason } },
          this.statusForValidationError(validation.errorCode)
        );
      }

      // Agents may only query their own audit trail
      if (agentId && agentId !== validation.payload!.agentId) {
        return c.json({ error: { code: 'ACCESS_DENIED', message: 'Cannot query audit for another agent' } }, 403);
      }

      const logs = this.getAuditLogs({
        sessionId: sessionId ?? validation.payload!.sessionId,
        limit: limit ? parseInt(limit, 10) : undefined,
      });

      return c.json({ logs });
    });

    return app;
  }

  private async validateRequest(authHeader: string | undefined): Promise<
    | { valid: true; payload: CapabilityTokenPayload; sessionId: string; agentId: string }
    | { valid: false; reason: string; errorCode: string; sessionId?: string; agentId?: string }
  > {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { valid: false, reason: 'Missing or invalid Authorization header', errorCode: 'INVALID_TOKEN' };
    }

    const token = authHeader.slice(7);
    try {
      const payload = await this.issuer.verify(token);

      if (isTokenExpired(payload.expiresAt)) {
        return { valid: false, reason: 'Token expired', errorCode: 'TOKEN_EXPIRED', sessionId: payload.sessionId, agentId: payload.agentId };
      }

      if (!this.sessionStateProvider) {
        return {
          valid: false,
          reason: 'Session state provider is not configured',
          errorCode: 'SESSION_VALIDATION_UNAVAILABLE',
          sessionId: payload.sessionId,
          agentId: payload.agentId,
        };
      }

      const session = this.sessionStateProvider.getSession(payload.sessionId);
      if (!session) {
        return { valid: false, reason: 'Session not found', errorCode: 'SESSION_NOT_FOUND', sessionId: payload.sessionId, agentId: payload.agentId };
      }

      if (session.status !== 'active') {
        return {
          valid: false,
          reason: `Session is not active (status: ${session.status})`,
          errorCode: 'SESSION_NOT_ACTIVE',
          sessionId: payload.sessionId,
          agentId: payload.agentId,
        };
      }

      if (this.sessionStateProvider.isTokenBlacklisted(payload.sessionId)) {
        return { valid: false, reason: 'Token has been revoked', errorCode: 'TOKEN_REVOKED', sessionId: payload.sessionId, agentId: payload.agentId };
      }

      return { valid: true, payload, sessionId: payload.sessionId, agentId: payload.agentId };
    } catch (err) {
      return { valid: false, reason: `Token validation failed: ${(err as Error).message}`, errorCode: 'INVALID_TOKEN' };
    }
  }

  private statusForValidationError(errorCode: string): 403 | 503 {
    return errorCode === 'SESSION_VALIDATION_UNAVAILABLE' ? 503 : 403;
  }

  private isKeyAllowed(key: string, item: MemoryItem | null, payload: CapabilityTokenPayload, action: 'read' | 'write'): { allowed: boolean; reason: string } {
    const scope = payload.scopes[action];
    if (!scope) {
      return { allowed: false, reason: `No ${action} scope granted` };
    }

    if (scope.denyKeys.includes(key)) {
      return { allowed: false, reason: 'Key explicitly denied' };
    }

    if (scope.keys.includes(key)) {
      if (item && item.sensitivity === 'high' && action === 'read' && !scope.keys.includes(key)) {
        // This path shouldn't happen due to above check, but keep for clarity
      }
      return { allowed: true, reason: 'Key explicitly allowed' };
    }

    if (item && item.sensitivity === 'high') {
      return { allowed: false, reason: 'High sensitivity items require explicit key authorization' };
    }

    const matchedTag = item?.tags.find(tag => scope.tags.includes(tag));
    if (matchedTag && !item?.tags.some(tag => scope.denyTags.includes(tag))) {
      return { allowed: true, reason: `Tag ${matchedTag} allowed` };
    }

    return { allowed: false, reason: 'Key not in authorized scope' };
  }

  private isTagAllowed(tag: string, payload: CapabilityTokenPayload, action: 'read' | 'write'): { allowed: boolean; reason: string } {
    const scope = payload.scopes[action];
    if (!scope) {
      return { allowed: false, reason: `No ${action} scope granted` };
    }

    if (scope.denyTags.includes(tag)) {
      return { allowed: false, reason: 'Tag explicitly denied' };
    }

    if (scope.tags.includes(tag)) {
      return { allowed: true, reason: 'Tag allowed' };
    }

    return { allowed: false, reason: 'Tag not in authorized scope' };
  }

  private serializeItem(item: MemoryItem, allowedFields?: string[]): Record<string, unknown> {
    const full: Record<string, unknown> = {
      key: item.key,
      value: item.value,
      tags: item.tags,
      sensitivity: item.sensitivity,
      source: item.source,
      updated_at: item.updatedAt,
      description: item.description,
    };

    if (!allowedFields || allowedFields.length === 0) return full;

    const filtered: Record<string, unknown> = {};
    for (const field of allowedFields) {
      if (full[field] !== undefined) {
        filtered[field] = full[field];
      }
    }
    return filtered;
  }

  private computeAggregation(items: MemoryItem[], op: string, field?: string): Record<string, unknown> {
    if (op === 'count') {
      return { op: 'count', tag: items[0]?.tags[0] ?? '-', result: items.length };
    }

    if (!field) {
      return { error: { code: 'INVALID_REQUEST', message: 'field parameter is required for numeric aggregations' } };
    }

    const path = field.split('.');
    // strip the "value." prefix if present since we start from item.value
    const segments = path[0] === 'value' ? path.slice(1) : path;
    const values: number[] = [];
    for (const item of items) {
      let val: unknown = item.value;
      for (const segment of segments) {
        if (val && typeof val === 'object') {
          val = (val as Record<string, unknown>)[segment];
        } else {
          val = undefined;
          break;
        }
      }
      if (typeof val === 'number') {
        values.push(val);
      } else if (typeof val === 'string') {
        const n = parseFloat(val);
        if (!isNaN(n)) values.push(n);
      }
    }

    if (values.length === 0) {
      return { op, field, result: 0 };
    }

    switch (op) {
      case 'sum': return { op, field, result: values.reduce((a, b) => a + b, 0) };
      case 'avg': return { op, field, result: values.reduce((a, b) => a + b, 0) / values.length };
      case 'min': return { op, field, result: Math.min(...values) };
      case 'max': return { op, field, result: Math.max(...values) };
      default: return { op, field, result: 0 };
    }
  }

  private logAudit(entry: { sessionId: string; agentId: string; action: string; key?: string; tags?: string[]; allowed: boolean; reason: string }): void {
    const id = generateId('log');
    const timestamp = new Date().toISOString();

    this.db.prepare(`
      INSERT INTO audit_logs (id, timestamp, session_id, agent_id, action, key, tags, allowed, reason)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      timestamp,
      entry.sessionId,
      entry.agentId,
      entry.action,
      entry.key ?? null,
      entry.tags ? JSON.stringify(entry.tags) : null,
      entry.allowed ? 1 : 0,
      entry.reason
    );
  }

  countAuditLogs(): number {
    const row = this.db.prepare('SELECT COUNT(*) as cnt FROM audit_logs').get() as { cnt: number };
    return row.cnt;
  }

  getAuditLogs(options: {
    sessionId?: string;
    agentId?: string;
    since?: string;
    allowed?: boolean;
    key?: string;
    limit?: number;
  } = {}): AuditLogEntry[] {
    let sql = 'SELECT * FROM audit_logs WHERE 1=1';
    const params: (string | number)[] = [];
    if (options.sessionId) {
      sql += ' AND session_id = ?';
      params.push(options.sessionId);
    }
    if (options.agentId) {
      sql += ' AND agent_id = ?';
      params.push(options.agentId);
    }
    if (options.since) {
      sql += ' AND timestamp >= ?';
      params.push(options.since);
    }
    if (options.allowed !== undefined) {
      sql += ' AND allowed = ?';
      params.push(options.allowed ? 1 : 0);
    }
    if (options.key) {
      sql += ' AND key = ?';
      params.push(options.key);
    }
    sql += ' ORDER BY timestamp DESC';
    if (options.limit) {
      sql += ' LIMIT ?';
      params.push(options.limit);
    }

    const rows = this.db.prepare(sql).all(...params) as Array<{
      id: string;
      timestamp: string;
      session_id: string;
      agent_id: string;
      action: string;
      key: string | null;
      tags: string | null;
      allowed: number;
      reason: string;
    }>;

    return rows.map(row => ({
      id: row.id,
      timestamp: row.timestamp,
      sessionId: row.session_id,
      agentId: row.agent_id,
      action: row.action as AuditLogEntry['action'],
      key: row.key ?? undefined,
      tags: row.tags ? JSON.parse(row.tags) : undefined,
      allowed: Boolean(row.allowed),
      reason: row.reason,
    }));
  }

  getLastAccessForSession(sessionId: string): { timestamp?: string; action?: string; endpoint?: string; allowed?: boolean; reason?: string } | null {
    const row = this.db.prepare('SELECT timestamp, action, key, tags, allowed, reason FROM audit_logs WHERE session_id = ? ORDER BY timestamp DESC LIMIT 1').get(sessionId) as {
      timestamp: string;
      action: string;
      key: string | null;
      tags: string | null;
      allowed: number;
      reason: string;
    } | undefined;
    if (!row) return null;
    return {
      timestamp: row.timestamp,
      action: row.action,
      endpoint: row.key ?? (row.tags ? JSON.parse(row.tags)[0] : undefined),
      allowed: Boolean(row.allowed),
      reason: row.reason,
    };
  }

  close(): void {
    this.db.close();
    this.store.disconnect().catch(() => {});
  }
}
