import type { MemoryItem, Sensitivity } from '@uomp/core';

export interface StoreStats {
  itemCount: number;
  totalSizeBytes: number;
  backend: string;
  encryptionEnabled: boolean;
}

export interface StagedWrite {
  id: string;
  sessionId: string;
  agentId: string;
  key: string;
  value: unknown;
  tags: string[];
  sensitivity: Sensitivity;
  description?: string;
  status: 'pending' | 'approved' | 'denied';
  createdAt: string;
  reviewedAt?: string;
  reviewedBy?: string;
}

export interface IMemoryStore {
  readonly backend: string;
  readonly isReady: boolean;

  connect(config?: Record<string, unknown>): Promise<void>;
  disconnect(): Promise<void>;

  get<T = unknown>(key: string): Promise<MemoryItem<T> | null>;
  getByTag<T = unknown>(tag: string): Promise<MemoryItem<T>[]>;
  getAll<T = unknown>(): Promise<MemoryItem<T>[]>;
  set<T = unknown>(item: Omit<MemoryItem<T>, 'createdAt' | 'updatedAt'> & Partial<Pick<MemoryItem<T>, 'createdAt' | 'updatedAt'>>): Promise<boolean>;
  delete(key: string): Promise<boolean>;

  listTags(): Promise<string[]>;
  count(): Promise<number>;
  stats(): Promise<StoreStats>;

  // Optional staging support. Stores that cannot stage writes may omit these.
  stageWrite?(input: {
    sessionId: string;
    agentId: string;
    key: string;
    value: unknown;
    tags: string[];
    sensitivity: Sensitivity;
    description?: string;
  }): Promise<StagedWrite>;
  listStagedWrites?(status?: StagedWrite['status']): Promise<StagedWrite[]>;
  getStagedWrite?(id: string): Promise<StagedWrite | null>;
  approveStagedWrite?(id: string, reviewedBy: string): Promise<MemoryItem | null>;
  denyStagedWrite?(id: string, reviewedBy: string): Promise<StagedWrite | null>;
}

export interface StoreBackendConfig {
  backend: 'sqlite' | 'encrypted-object' | 'ipfs';
  sqlite?: { dbPath: string };
  s3?: {
    endpoint: string;
    bucket: string;
    region: string;
    accessKeyId: string;
    secretAccessKey: string;
  };
  encryption?: {
    enabled: boolean;
    keyId?: string;
  };
}
