/**
 * UOMP Core - Shared types, constants, and utilities
 */

export const UOMP_VERSION = '1.0';
export const DEFAULT_PORT = 9374;
export const DEFAULT_HOST = '127.0.0.1';

export const DATA_DIR_NAME = '.uomp';
export const AGENTS_DIR_NAME = 'agents';
export const SECRETS_DIR_NAME = '.secrets';
export const SESSIONS_DIR_NAME = 'sessions';
export const MEMORY_DB_NAME = 'memory.db';
export const AUDIT_DB_NAME = 'audit.db';
export const AUTH_DB_NAME = 'auth.db';
export const PRIVATE_KEY_FILE_NAME = 'ed25519-private.jwk';
export const PUBLIC_KEY_FILE_NAME = 'ed25519-public.jwk';
export const ADMIN_TOKEN_FILE_NAME = 'admin-token';

export type Sensitivity = 'low' | 'medium' | 'high';

export interface MemoryItem<T = unknown> {
  key: string;
  value: T;
  tags: string[];
  sensitivity: Sensitivity;
  source: 'user' | 'agent';
  createdAt: string;
  updatedAt: string;
  description?: string;
}

export interface ScopeAction {
  tags: string[];
  keys: string[];
  denyTags: string[];
  denyKeys: string[];
  allowedFields?: string[];
  fields?: Record<string, string[]>;
  purposes?: Record<string, string>;
}

export interface DataRetentionPolicy {
  maxRetentionSeconds: number;
  deletionMethod: 'process_termination' | 'secure_wipe' | 'ephemeral_storage';
  proofRequired?: boolean;
  description?: string;
  thirdPartySharing?: boolean;
  encryptionAtRest?: boolean;
}

export interface DataDeletionProof {
  deletionProofId: string;
  sessionId: string;
  agentId: string;
  deletedAt: string;
  memoryHash: string;
  fieldsAccessed?: string[];
  method: string;
  proofValue: string;
}

export interface Scopes {
  read: ScopeAction;
  write: ScopeAction;
}

export interface AgentManifest {
  uompVersion: string;
  agent: {
    id: string;
    name: string;
    version: string;
    description?: string;
    publisher?: string;
  };
  requestedScopes: Scopes;
  requiredCapabilities?: string[];
  optionalCapabilities?: string[];
  requiresRemote?: boolean;
  externalDataSources?: string[];
  dataRetentionPolicy?: DataRetentionPolicy;
  identity?: AgentIdentity;
}

export interface AgentIdentity {
  did?: string;
  verificationMethods?: string[];
  proof?: {
    type: string;
    created: string;
    proofValue: string;
  };
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  sessionId: string;
  agentId: string;
  action: 'read' | 'write' | 'delete' | 'query' | 'deletion_proof' | 'deletion_proof_missing';
  key?: string;
  tags?: string[];
  allowed: boolean;
  reason: string;
  requestSize?: number;
  responseSize?: number;
  queryCountRemaining?: number;
}

export function generateId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

export function inferSensitivity(tag: string): Sensitivity {
  if (tag.includes('holdings') || tag.includes('transactions')) return 'high';
  if (tag.startsWith('profile:') || tag.includes('watchlist')) return 'medium';
  return 'low';
}

// ── Manifest loading (shared between CLI and SDK) ────────────

export interface RawScopeAction {
  tags?: string[];
  keys?: string[];
  deny_tags?: string[];
  deny_keys?: string[];
  allowed_fields?: string[];
  fields?: Record<string, string[]>;
  purposes?: Record<string, string>;
}

export interface RawAgentManifest {
  uomp_version?: string;
  agent?: { id?: string; name?: string; version?: string; description?: string; publisher?: string };
  requested_scopes?: { read?: RawScopeAction; write?: RawScopeAction };
  required_capabilities?: string[];
  optional_capabilities?: string[];
  requires_remote?: boolean;
  identity?: { did?: string; verification_methods?: string[]; proof?: { type?: string; created?: string; proofValue?: string } };
  package?: { checksum?: string; signature?: string; source_url?: string };
  external_data_sources?: string[];
  data_retention_policy?: { max_retention_seconds?: number; deletion_method?: string; proof_required?: boolean; description?: string; third_party_sharing?: boolean; encryption_at_rest?: boolean };
}

/**
 * Build the read scope that will actually be granted from a manifest's
 * requested read scope. Denials and field restrictions are carried over so
 * that a narrower manifest request cannot be widened during authorization.
 */
export function buildReadScope(requested: ScopeAction, selectedTags: string[]): ScopeAction {
  return {
    tags: [...selectedTags],
    keys: [...(requested.keys ?? [])],
    denyTags: [...(requested.denyTags ?? [])],
    denyKeys: [...(requested.denyKeys ?? [])],
    ...(requested.allowedFields ? { allowedFields: [...requested.allowedFields] } : {}),
  };
}

export function normalizeManifest(raw: RawAgentManifest): AgentManifest {
  const scopeAction = (rawAction?: RawScopeAction): ScopeAction => ({
    tags: rawAction?.tags ?? [],
    keys: rawAction?.keys ?? [],
    denyTags: rawAction?.deny_tags ?? [],
    denyKeys: rawAction?.deny_keys ?? [],
    allowedFields: rawAction?.allowed_fields,
    fields: rawAction?.fields,
    purposes: rawAction?.purposes,
  });
  const rawScopes = raw.requested_scopes ?? {};
  const rawAgent = raw.agent ?? {};
  return {
    uompVersion: String(raw.uomp_version ?? '1.0'),
    agent: { id: String(rawAgent.id ?? ''), name: String(rawAgent.name ?? ''), version: String(rawAgent.version ?? ''),
      description: rawAgent.description, publisher: rawAgent.publisher },
    requestedScopes: { read: scopeAction(rawScopes.read), write: scopeAction(rawScopes.write) },
    requiredCapabilities: raw.required_capabilities,
    optionalCapabilities: raw.optional_capabilities,
    requiresRemote: Boolean(raw.requires_remote),
    externalDataSources: raw.external_data_sources,
    dataRetentionPolicy: raw.data_retention_policy ? {
      maxRetentionSeconds: raw.data_retention_policy.max_retention_seconds ?? 0,
      deletionMethod: (raw.data_retention_policy.deletion_method as 'process_termination' | 'secure_wipe' | 'ephemeral_storage') ?? 'process_termination',
      proofRequired: raw.data_retention_policy.proof_required ?? false,
      description: raw.data_retention_policy.description,
      thirdPartySharing: raw.data_retention_policy.third_party_sharing ?? false,
      encryptionAtRest: raw.data_retention_policy.encryption_at_rest ?? false,
    } : undefined,
    identity: raw.identity ? { did: raw.identity.did, verificationMethods: raw.identity.verification_methods,
      proof: raw.identity.proof ? { type: String(raw.identity.proof.type ?? ''), created: String(raw.identity.proof.created ?? ''), proofValue: String(raw.identity.proof.proofValue ?? '') } : undefined } : undefined,
  };
}
