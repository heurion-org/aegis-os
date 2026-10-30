import { Transport } from './transport.js';
import type { AuditLogEntry, AuditQueryOptions } from './types.js';

export class AuditClient {
  constructor(private transport: Transport) {}

  async query(options: AuditQueryOptions = {}): Promise<AuditLogEntry[]> {
    const params = new URLSearchParams();
    if (options.sessionId) params.set('session_id', options.sessionId);
    if (options.agentId) params.set('agent_id', options.agentId);
    if (options.limit) params.set('limit', String(options.limit));

    const data = await this.transport.requestJson<{ logs: AuditLogEntry[] }>(
      `/v1/audit?${params.toString()}`
    );
    return data.logs;
  }

  async getLastAccess(sessionId?: string): Promise<AuditLogEntry | null> {
    const logs = await this.query({ sessionId, limit: 1 });
    return logs[0] ?? null;
  }
}
