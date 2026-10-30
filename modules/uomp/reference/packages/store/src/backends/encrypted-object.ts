import type { MemoryItem } from '@uomp/core';
import type { IMemoryStore, StoreStats } from '../types.js';
import { S3Client, type S3Config } from './s3.js';
import { encrypt, decrypt, serializeBlob, deserializeBlob, deriveItemKey } from './encryption.js';

export interface EncryptedStoreConfig {
  s3: S3Config;
  masterKey: Buffer;
  prefix?: string;
}

export class EncryptedObjectStore implements IMemoryStore {
  readonly backend = 'encrypted-object';
  private s3: S3Client;
  private masterKey: Buffer;
  private prefix: string;
  private _indexCache: Map<string, string[]> | null = null;

  constructor(config: EncryptedStoreConfig) {
    this.s3 = new S3Client(config.s3);
    this.masterKey = config.masterKey;
    this.prefix = config.prefix ?? 'uomp-data/';
  }

  get isReady(): boolean { return true; }

  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}

  private itemKey(iKey: string): Buffer {
    return deriveItemKey(this.masterKey, iKey);
  }

  async get<T = unknown>(key: string): Promise<MemoryItem<T> | null> {
    const raw = await this.s3.get(`${this.prefix}items/${key}`);
    if (!raw) return null;
    try {
      const blob = deserializeBlob(raw);
      const plain = decrypt(blob, this.itemKey(key));
      return JSON.parse(plain.toString()) as MemoryItem<T>;
    } catch {
      return null;
    }
  }

  async getByTag<T = unknown>(tag: string): Promise<MemoryItem<T>[]> {
    const index = await this.loadIndex();
    const keys = index.get(tag) || [];
    const items = await Promise.all(keys.map(k => this.get<T>(k)));
    return items.filter((i): i is MemoryItem<T> => i !== null);
  }

  async getAll<T = unknown>(): Promise<MemoryItem<T>[]> {
    const index = await this.loadIndex();
    const allKeys = new Set<string>();
    for (const keys of index.values()) for (const k of keys) allKeys.add(k);
    const items = await Promise.all([...allKeys].map(k => this.get<T>(k)));
    return items.filter((i): i is MemoryItem<T> => i !== null);
  }

  async set<T = unknown>(item: Omit<MemoryItem<T>, 'createdAt' | 'updatedAt'> & Partial<Pick<MemoryItem<T>, 'createdAt' | 'updatedAt'>>): Promise<boolean> {
    const now = new Date().toISOString();
    const existing = await this.get(item.key);
    const fullItem: MemoryItem<T> = {
      key: item.key,
      value: item.value as T,
      tags: item.tags,
      sensitivity: item.sensitivity,
      source: item.source,
      createdAt: existing?.createdAt ?? item.createdAt ?? now,
      updatedAt: item.updatedAt ?? now,
      description: item.description,
    };

    const plain = Buffer.from(JSON.stringify(fullItem));
    const blob = encrypt(plain, this.itemKey(item.key));
    const raw = serializeBlob(blob);
    const ok = await this.s3.put(`${this.prefix}items/${item.key}`, raw);
    if (!ok) return false;

    // Update index
    await this.updateIndex(item.tags, item.key);
    return true;
  }

  async delete(key: string): Promise<boolean> {
    const ok = await this.s3.delete(`${this.prefix}items/${key}`);
    if (ok) {
      const index = await this.loadIndex();
      for (const [tag, keys] of index) {
        const filtered = keys.filter(k => k !== key);
        if (filtered.length !== keys.length) {
          if (filtered.length === 0) index.delete(tag);
          else index.set(tag, filtered);
        }
      }
      await this.saveIndex(index);
    }
    return ok;
  }

  async listTags(): Promise<string[]> {
    const index = await this.loadIndex();
    return [...index.keys()];
  }

  async count(): Promise<number> {
    const keys = await this.s3.list(`${this.prefix}items/`);
    return keys.length;
  }

  async stats(): Promise<StoreStats> {
    const cnt = await this.count();
    return { itemCount: cnt, totalSizeBytes: 0, backend: 'encrypted-object', encryptionEnabled: true };
  }

  // ── Index management ──────────────────────────────────

  private async loadIndex(): Promise<Map<string, string[]>> {
    if (this._indexCache) return this._indexCache;
    const raw = await this.s3.get(`${this.prefix}index.json`);
    if (!raw) { this._indexCache = new Map(); return this._indexCache; }
    try {
      const plain = decrypt(deserializeBlob(raw), this.itemKey('__index__'));
      const parsed = JSON.parse(plain.toString()) as Record<string, string[]>;
      this._indexCache = new Map(Object.entries(parsed));
      return this._indexCache;
    } catch {
      this._indexCache = new Map();
      return this._indexCache;
    }
  }

  private async saveIndex(index: Map<string, string[]>): Promise<void> {
    this._indexCache = index;
    const plain = Buffer.from(JSON.stringify(Object.fromEntries(index)));
    const blob = encrypt(plain, this.itemKey('__index__'));
    await this.s3.put(`${this.prefix}index.json`, serializeBlob(blob));
  }

  private async updateIndex(tags: string[], key: string): Promise<void> {
    const index = await this.loadIndex();
    for (const tag of tags) {
      const keys = index.get(tag) || [];
      if (!keys.includes(key)) keys.push(key);
      index.set(tag, keys);
    }
    await this.saveIndex(index);
  }
}
