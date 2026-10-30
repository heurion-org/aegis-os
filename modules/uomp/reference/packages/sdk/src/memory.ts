import { Transport } from './transport.js';
import type { MemoryItem } from './types.js';
import type { SessionClient } from './session.js';

export class MemoryClient {
  constructor(
    private transport: Transport,
    private session?: SessionClient
  ) {}

  async get<T = Record<string, unknown>>(key: string): Promise<MemoryItem<T> | null> {
    try {
      const item = await this.transport.requestJson<MemoryItem<T>>(`/v1/memory/${encodeURIComponent(key)}`);
      this.session?.trackAccess(key);
      return item;
    } catch (err: any) {
      if (err?.statusCode === 404) return null;
      throw err;
    }
  }

  async getByTag<T = Record<string, unknown>>(tag: string): Promise<MemoryItem<T>[]> {
    const data = await this.transport.requestJson<{ items: MemoryItem<T>[] }>(
      `/v1/memory?tag=${encodeURIComponent(tag)}`
    );
    for (const item of data.items) {
      this.session?.trackAccess(item.key);
    }
    return data.items;
  }

  async getByKeys<T = Record<string, unknown>>(keys: string[]): Promise<MemoryItem<T>[]> {
    const results = await Promise.all(keys.map(k => this.get<T>(k).catch(() => null)));
    return results.filter((r): r is MemoryItem<T> => r !== null);
  }

  async listTags(): Promise<string[]> {
    // Get all tags from all memory items (client-side dedup)
    try {
      const data = await this.transport.requestJson<{ items: MemoryItem[] }>('/v1/memory?tag=');
      const tags = new Set<string>();
      for (const item of data.items) {
        for (const tag of item.tags) tags.add(tag);
      }
      return [...tags];
    } catch {
      return [];
    }
  }

  async has(key: string): Promise<boolean> {
    try {
      await this.transport.request(`/v1/memory/${encodeURIComponent(key)}`);
      return true;
    } catch {
      return false;
    }
  }

  async set<T = Record<string, unknown>>(key: string, item: Omit<MemoryItem<T>, 'createdAt' | 'updatedAt' | 'key'>): Promise<boolean> {
    await this.transport.request(`/v1/memory/${encodeURIComponent(key)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(item),
    });
    return true;
  }

  async delete(key: string): Promise<boolean> {
    await this.transport.request(`/v1/memory/${encodeURIComponent(key)}`, { method: 'DELETE' });
    return true;
  }
}
