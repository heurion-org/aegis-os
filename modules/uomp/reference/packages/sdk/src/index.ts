export { UompClient } from './client.js';
export { UompError, UompErrorCode } from './errors.js';
export * from './types.js';

// Sub-clients (for advanced use)
export { MemoryClient } from './memory.js';
export { AggregateClient } from './aggregate.js';
export { PayloadClient } from './payload.js';
export { SessionClient } from './session.js';
export { AuthClient } from './auth.js';
export { AuditClient } from './audit.js';

// Browser components
export { StoreRouter } from './store-router.js';
export type { RouterConfig } from './store-router.js';

// ── Backward compatibility ────────────────────────────────────────

import { MemoryClient } from './memory.js';
import type { MemoryItem, UompClientOptions } from './types.js';
import { UompClient } from './client.js';

export interface UserMemoryClientOptions {
  baseUrl?: string;
  token: string;
  agentId?: string;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
}

export class UserMemory {
  private client: UompClient;

  constructor(options: UserMemoryClientOptions) {
    this.client = new UompClient({
      token: options.token,
      baseUrl: options.baseUrl,
      agentId: options.agentId,
      transport: {
        timeout: options.timeoutMs ?? 10000,
        fetch: options.fetch,
      },
    });
  }

  async get<T = unknown>(key: string): Promise<MemoryItem<T> | null> {
    return this.client.memory.get<T>(key);
  }

  async getByTag<T = unknown>(tag: string): Promise<MemoryItem<T>[]> {
    return this.client.memory.getByTag<T>(tag);
  }

  async set<T = unknown>(_key: string, _value: T): Promise<boolean> {
    throw new UserMemoryError('WRITE_NOT_AVAILABLE', 'Agent writes are not available in MVP', undefined);
  }

  async delete(_key: string): Promise<boolean> {
    throw new UserMemoryError('WRITE_NOT_AVAILABLE', 'Agent deletes are not available in MVP', undefined);
  }
}

export class UserMemoryError extends Error {
  code: string;
  sessionId?: string;

  constructor(code: string, message: string, sessionId?: string) {
    super(message);
    this.name = 'UserMemoryError';
    this.code = code;
    this.sessionId = sessionId;
  }
}
