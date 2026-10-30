import Database from 'better-sqlite3';
import { generateId, type MemoryItem, type Sensitivity } from '@uomp/core';
import type { IMemoryStore, StagedWrite, StoreStats } from './types.js';

export type { IMemoryStore, StagedWrite, StoreStats, StoreBackendConfig } from './types.js';

export interface StoreOptions {
  dbPath: string;
}

export class MemoryStore {
  readonly backend = 'sqlite';
  private db: Database.Database;

  constructor(options: StoreOptions) {
    this.db = new Database(options.dbPath);
    this.initSchema();
  }

  get isReady(): boolean { return true; }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS memory_items (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        tags TEXT NOT NULL,
        sensitivity TEXT NOT NULL,
        source TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        description TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_memory_items_tags ON memory_items(tags);
      CREATE INDEX IF NOT EXISTS idx_memory_items_source ON memory_items(source);

      CREATE TABLE IF NOT EXISTS staged_writes (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        tags TEXT NOT NULL,
        sensitivity TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        reviewed_at TEXT,
        reviewed_by TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_staged_writes_status ON staged_writes(status);
    `);
  }

  get<T = unknown>(key: string): MemoryItem<T> | null {
    const row = this.db.prepare('SELECT * FROM memory_items WHERE key = ?').get(key) as Record<string, string> | undefined;
    return row ? this.deserialize<T>(row) : null;
  }

  getByTag<T = unknown>(tag: string): MemoryItem<T>[] {
    const rows = this.db
      .prepare("SELECT * FROM memory_items WHERE EXISTS (SELECT 1 FROM json_each(tags) WHERE value = ?)")
      .all(tag) as Record<string, string>[];
    return rows.map(row => this.deserialize<T>(row));
  }

  getAll<T = unknown>(): MemoryItem<T>[] {
    const rows = this.db.prepare('SELECT * FROM memory_items').all() as Record<string, string>[];
    return rows.map(row => this.deserialize<T>(row));
  }

  set<T = unknown>(item: Omit<MemoryItem<T>, 'createdAt' | 'updatedAt'> & Partial<Pick<MemoryItem<T>, 'createdAt' | 'updatedAt'>>): boolean {
    const now = new Date().toISOString();
    const existing = this.get(item.key);
    const createdAt = existing?.createdAt ?? item.createdAt ?? now;
    const updatedAt = item.updatedAt ?? now;

    this.db.prepare(`
      INSERT INTO memory_items (key, value, tags, sensitivity, source, created_at, updated_at, description)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value = excluded.value, tags = excluded.tags, sensitivity = excluded.sensitivity,
        source = excluded.source, updated_at = excluded.updated_at, description = excluded.description
    `).run(item.key, JSON.stringify(item.value), JSON.stringify(item.tags),
      item.sensitivity, item.source, createdAt, updatedAt, item.description ?? null);
    return true;
  }

  stageWrite(input: {
    sessionId: string;
    agentId: string;
    key: string;
    value: unknown;
    tags: string[];
    sensitivity: Sensitivity;
    description?: string;
  }): StagedWrite {
    const staged: StagedWrite = {
      id: generateId('stage'),
      sessionId: input.sessionId,
      agentId: input.agentId,
      key: input.key,
      value: input.value,
      tags: input.tags,
      sensitivity: input.sensitivity,
      ...(input.description ? { description: input.description } : {}),
      status: 'pending',
      createdAt: new Date().toISOString(),
    };

    this.db.prepare(`
      INSERT INTO staged_writes (
        id, session_id, agent_id, key, value, tags, sensitivity, description,
        status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      staged.id,
      staged.sessionId,
      staged.agentId,
      staged.key,
      JSON.stringify(staged.value),
      JSON.stringify(staged.tags),
      staged.sensitivity,
      staged.description ?? null,
      staged.status,
      staged.createdAt,
    );

    return staged;
  }

  listStagedWrites(status: StagedWrite['status'] = 'pending'): StagedWrite[] {
    const rows = this.db
      .prepare('SELECT * FROM staged_writes WHERE status = ? ORDER BY created_at DESC')
      .all(status) as Record<string, string>[];
    return rows.map(row => this.deserializeStagedWrite(row));
  }

  getStagedWrite(id: string): StagedWrite | null {
    const row = this.db.prepare('SELECT * FROM staged_writes WHERE id = ?').get(id) as Record<string, string> | undefined;
    return row ? this.deserializeStagedWrite(row) : null;
  }

  approveStagedWrite(id: string, reviewedBy: string): MemoryItem | null {
    const staged = this.getStagedWrite(id);
    if (!staged || staged.status !== 'pending') {
      return null;
    }

    const apply = this.db.transaction(() => {
      this.set({
        key: staged.key,
        value: staged.value,
        tags: staged.tags,
        sensitivity: staged.sensitivity,
        source: 'agent',
        ...(staged.description ? { description: staged.description } : {}),
      });
      this.db.prepare(`
        UPDATE staged_writes
        SET status = 'approved', reviewed_at = ?, reviewed_by = ?
        WHERE id = ? AND status = 'pending'
      `).run(new Date().toISOString(), reviewedBy, id);
    });
    apply();

    return this.get(staged.key);
  }

  denyStagedWrite(id: string, reviewedBy: string): StagedWrite | null {
    const staged = this.getStagedWrite(id);
    if (!staged || staged.status !== 'pending') {
      return null;
    }

    this.db.prepare(`
      UPDATE staged_writes
      SET status = 'denied', reviewed_at = ?, reviewed_by = ?
      WHERE id = ? AND status = 'pending'
    `).run(new Date().toISOString(), reviewedBy, id);

    return this.getStagedWrite(id);
  }

  delete(key: string): boolean {
    const result = this.db.prepare('DELETE FROM memory_items WHERE key = ?').run(key);
    return result.changes > 0;
  }

  listTags(): string[] {
    const rows = this.db.prepare('SELECT DISTINCT tags FROM memory_items').all() as { tags: string }[];
    const tagSet = new Set<string>();
    for (const row of rows) {
      try { for (const t of JSON.parse(row.tags)) tagSet.add(t); } catch {}
    }
    return [...tagSet];
  }

  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) as cnt FROM memory_items').get() as { cnt: number };
    return row.cnt;
  }

  close(): void {
    this.db.close();
  }

  private deserializeStagedWrite(row: Record<string, string>): StagedWrite {
    return {
      id: row.id,
      sessionId: row.session_id,
      agentId: row.agent_id,
      key: row.key,
      value: JSON.parse(row.value) as unknown,
      tags: JSON.parse(row.tags) as string[],
      sensitivity: row.sensitivity as Sensitivity,
      ...(row.description ? { description: row.description } : {}),
      status: row.status as StagedWrite['status'],
      createdAt: row.created_at,
      ...(row.reviewed_at ? { reviewedAt: row.reviewed_at } : {}),
      ...(row.reviewed_by ? { reviewedBy: row.reviewed_by } : {}),
    };
  }

  private deserialize<T>(row: Record<string, string>): MemoryItem<T> {
    return {
      key: row.key,
      value: JSON.parse(row.value) as T,
      tags: JSON.parse(row.tags) as string[],
      sensitivity: row.sensitivity as Sensitivity,
      source: row.source as 'user' | 'agent',
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      description: row.description,
    };
  }
}

/** Async adapter that wraps sync MemoryStore for IMemoryStore interface */
export class AsyncStoreAdapter implements IMemoryStore {
  readonly backend: string;

  constructor(private store: MemoryStore) {
    this.backend = store.backend;
  }

  get isReady(): boolean { return true; }

  async connect(): Promise<void> {}
  async disconnect(): Promise<void> { this.store.close(); }

  async get<T>(key: string): Promise<MemoryItem<T> | null> { return this.store.get<T>(key); }
  async getByTag<T>(tag: string): Promise<MemoryItem<T>[]> { return this.store.getByTag<T>(tag); }
  async getAll<T>(): Promise<MemoryItem<T>[]> { return this.store.getAll<T>(); }
  async set<T>(item: Omit<MemoryItem<T>, 'createdAt' | 'updatedAt'> & Partial<Pick<MemoryItem<T>, 'createdAt' | 'updatedAt'>>): Promise<boolean> { return this.store.set(item); }
  async delete(key: string): Promise<boolean> { return this.store.delete(key); }
  async listTags(): Promise<string[]> { return this.store.listTags(); }
  async count(): Promise<number> { return this.store.count(); }
  async stats(): Promise<StoreStats> { return { itemCount: this.store.count(), totalSizeBytes: 0, backend: 'sqlite', encryptionEnabled: false }; }
  async stageWrite(input: Parameters<NonNullable<IMemoryStore['stageWrite']>>[0]): Promise<StagedWrite> { return this.store.stageWrite(input); }
  async listStagedWrites(status: StagedWrite['status'] = 'pending'): Promise<StagedWrite[]> { return this.store.listStagedWrites(status); }
  async getStagedWrite(id: string): Promise<StagedWrite | null> { return this.store.getStagedWrite(id); }
  async approveStagedWrite(id: string, reviewedBy: string): Promise<MemoryItem | null> { return this.store.approveStagedWrite(id, reviewedBy); }
  async denyStagedWrite(id: string, reviewedBy: string): Promise<StagedWrite | null> { return this.store.denyStagedWrite(id, reviewedBy); }
}

export { createStore } from './factory.js';
