import { createHash } from 'crypto';
import { Transport } from './transport.js';
import { UompError, UompErrorCode } from './errors.js';
import type { DeletionProofResult, DeletionProofOptions, RefreshResult } from './types.js';

export class SessionClient {
  private sessionId: string;
  private agentId: string;
  private _accessedKeys: Set<string> = new Set();

  constructor(private transport: Transport, sessionId: string, agentId: string) {
    this.sessionId = sessionId;
    this.agentId = agentId;
  }

  /** Track a key that was accessed (for deletion proof hash) */
  trackAccess(key: string): void {
    this._accessedKeys.add(key);
  }

  /** Get all tracked keys */
  get accessedKeys(): string[] {
    return [...this._accessedKeys];
  }

  /** Compute memory hash from tracked keys */
  computeMemoryHash(): string {
    const keys = [...this._accessedKeys].sort().join('');
    return createHash('sha256').update(keys).digest('hex');
  }

  async refresh(refreshToken: string): Promise<RefreshResult> {
    return this.transport.requestJson<RefreshResult>(`/v1/sessions/${this.sessionId}/refresh`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${refreshToken}` },
    });
  }

  async submitDeletionProof(opts: DeletionProofOptions = {}): Promise<DeletionProofResult> {
    const memoryHash = opts.memoryHash ?? this.computeMemoryHash();

    return this.transport.requestJson<DeletionProofResult>(
      `/v1/sessions/${this.sessionId}/deletion-proof`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deletion_proof_id: `del_${Date.now().toString(36)}`,
          session_id: this.sessionId,
          agent_id: this.agentId,
          deleted_at: new Date().toISOString(),
          memory_hash: `sha256:${memoryHash}`,
          fields_accessed: opts.fieldsAccessed ?? ['key', 'value'],
          method: opts.method ?? 'process_termination',
          proof_value: `sha256:${memoryHash}`,
        }),
      }
    );
  }

  async close(): Promise<void> {
    const resp = await this.transport.request(`/v1/sessions/${this.sessionId}/close`, { method: 'POST' });
    if (!resp.ok) {
      throw new UompError(UompErrorCode.UNKNOWN, `Failed to close session ${this.sessionId}`, undefined, resp.status);
    }
  }

  /** Submit deletion proof and close session if task_bound */
  async finalize(opts: DeletionProofOptions = {}): Promise<DeletionProofResult> {
    const result = await this.submitDeletionProof(opts);
    try {
      await this.close();
    } catch { /* session may already be closed by task_bound */ }
    return result;
  }

  async isActive(): Promise<boolean> {
    try {
      await this.transport.requestJson(`/v1/sessions/${this.sessionId}`);
      return true;
    } catch {
      return false;
    }
  }
}
