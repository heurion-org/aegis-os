import type { MemoryItem, Sensitivity, AuditLogEntry } from '@uomp/core';

export type { MemoryItem, Sensitivity, AuditLogEntry };

export interface ScopeAction {
  tags: string[];
  keys: string[];
  denyTags: string[];
  denyKeys: string[];
}

export interface Scopes {
  read: ScopeAction;
  write: ScopeAction;
}

export interface TokenLimits {
  maxReadQueries?: number;
  maxWriteQueries?: number;
}

export interface TokenInfo {
  sessionId: string;
  agentId: string;
  issuedAt: string;
  expiresAt: string;
  scopes: Scopes;
  profile: string;
  audience?: string;
  allowedFields?: string[];
  aggregationOnly: boolean;
  taskBound: boolean;
  limits?: TokenLimits;
}

export type AggregateOp = 'sum' | 'avg' | 'count' | 'min' | 'max';

export type AggregateResult =
  | { op: 'count'; tag: string; result: number }
  | { op: 'sum' | 'avg' | 'min' | 'max'; field: string; result: number };

export interface PayloadInfo {
  payload_id: string;
  size: number;
}

export interface DeletionProofResult {
  status: string;
  deletion_proof_id: string;
}

export interface DeletionProofOptions {
  fieldsAccessed?: string[];
  method?: string;
  memoryHash?: string;
}

export interface RefreshResult {
  token: string;
  expires_at: string;
}

export interface AuditQueryOptions {
  sessionId?: string;
  agentId?: string;
  limit?: number;
}

export interface UompClientOptions {
  token?: string;
  baseUrl?: string;
  agentId?: string;
  sessionId?: string;
  tls?: {
    certPath?: string;
    keyPath?: string;
    caPath?: string;
    rejectUnauthorized?: boolean;
  };
  transport?: {
    timeout?: number;
    retries?: number;
    retryBackoff?: number;
    fetch?: typeof fetch;
  };
}
