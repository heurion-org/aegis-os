/**
 * StoreRouter — browser auto-routing between Gateway and S3 direct read.
 */
import type { MemoryItem } from '@uomp/core';

export interface DirectStore {
  get<T>(key: string): Promise<MemoryItem<T> | null>;
  getByTag<T>(tag: string): Promise<MemoryItem<T>[]>;
}

export interface RouterConfig {
  gatewayUrl: string;
  store?: DirectStore;
  token: () => string;
  agentId: string;
}

export class StoreRouter {
  readonly gatewayUrl: string;
  private store?: DirectStore;
  private token: () => string;
  private agentId: string;
  private _gatewayOnline = true;

  constructor(config: RouterConfig) {
    this.gatewayUrl = config.gatewayUrl;
    this.store = config.store;
    this.token = config.token;
    this.agentId = config.agentId;
  }

  get isGatewayOnline(): boolean { return this._gatewayOnline; }

  private authHeaders(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token()}`,
      'X-UOMP-Agent-Id': this.agentId,
      Accept: 'application/json',
    };
  }

  private async tryGateway(url: string, init?: RequestInit): Promise<Response | null> {
    try {
      const resp = await fetch(url, {
        ...init,
        headers: { ...this.authHeaders(), ...(init?.headers as Record<string, string> || {}) },
        signal: AbortSignal.timeout(8000),
      });
      this._gatewayOnline = resp.ok || resp.status >= 400;
      return resp;
    } catch {
      this._gatewayOnline = false;
      return null;
    }
  }

  private gatewayPath(path: string): string {
    return `${this.gatewayUrl.replace(/\/$/, '')}${path}`;
  }

  async get<T>(key: string): Promise<MemoryItem<T> | null> {
    const resp = await this.tryGateway(this.gatewayPath(`/v1/memory/${encodeURIComponent(key)}`));
    if (resp?.ok) return resp.json() as Promise<MemoryItem<T>>;
    if (this.store) return this.store.get<T>(key);
    return null;
  }

  async getByTag<T>(tag: string): Promise<MemoryItem<T>[]> {
    const resp = await this.tryGateway(this.gatewayPath(`/v1/memory?tag=${encodeURIComponent(tag)}`));
    if (resp?.ok) {
      const data = await resp.json() as { items: MemoryItem<T>[] };
      return data.items;
    }
    if (this.store) return this.store.getByTag<T>(tag);
    return [];
  }

  async aggregate(op: string, tag: string, field?: string): Promise<Record<string, unknown> | null> {
    const params = new URLSearchParams({ tag, op });
    if (field) params.set('field', field);
    const resp = await this.tryGateway(this.gatewayPath(`/v1/memory/aggregate?${params}`));
    if (resp?.ok) return resp.json();
    return null;
  }

  async put(key: string, item: unknown): Promise<boolean> {
    const resp = await this.tryGateway(this.gatewayPath(`/v1/memory/${encodeURIComponent(key)}`), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(item),
    });
    if (!resp?.ok) throw new Error('Write requires Gateway');
    return true;
  }

  async uploadPayload(data: string): Promise<string | null> {
    const resp = await this.tryGateway(this.gatewayPath('/v1/payload/upload'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: data,
    });
    if (resp?.ok) {
      const r = await resp.json() as { payload_id: string };
      return r.payload_id;
    }
    return null;
  }

  async health(): Promise<Record<string, unknown> | null> {
    const resp = await this.tryGateway(this.gatewayPath('/v1/health'));
    return resp?.ok ? resp.json() : null;
  }
}
