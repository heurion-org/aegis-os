/**
 * UOMP User Identity — manages ~/.uomp/user.json
 */
import { readFile, writeFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';

export interface UserProfile {
  user_id: string;
  identities: Array<{
    chain: 'ethereum' | 'starknet';
    address: string;
    wallet?: string;
    last_used?: string;
  }>;
  master_key_hash?: string;
  store_backend?: string;
  sync_enabled?: boolean;
  created_at?: string;
  updated_at?: string;
}

const DATA_DIR = join(homedir(), '.uomp');
const USER_FILE = join(DATA_DIR, 'user.json');

export async function loadUser(): Promise<UserProfile | null> {
  try {
    const content = await readFile(USER_FILE, 'utf-8');
    return JSON.parse(content) as UserProfile;
  } catch {
    return null;
  }
}

export async function saveUser(profile: UserProfile): Promise<void> {
  await mkdir(DATA_DIR, { recursive: true });
  profile.updated_at = new Date().toISOString();
  await writeFile(USER_FILE, JSON.stringify(profile, null, 2), 'utf-8');
}

export async function createUser(opts: {
  chain: 'ethereum' | 'starknet';
  address: string;
  wallet?: string;
  masterKey?: Buffer;
}): Promise<UserProfile> {
  const now = new Date().toISOString();
  const profile: UserProfile = {
    user_id: `${opts.chain}:${opts.address.toLowerCase()}`,
    identities: [{
      chain: opts.chain,
      address: opts.address,
      wallet: opts.wallet,
      last_used: now,
    }],
    master_key_hash: opts.masterKey
      ? createHash('sha256').update(opts.masterKey).digest('hex')
      : undefined,
    store_backend: 'sqlite',
    sync_enabled: false,
    created_at: now,
    updated_at: now,
  };
  await saveUser(profile);
  return profile;
}

export async function updateUser(updates: Partial<UserProfile>): Promise<UserProfile | null> {
  const existing = await loadUser();
  if (!existing) return null;
  const updated = { ...existing, ...updates };
  await saveUser(updated);
  return updated;
}

export function defaultUserPath(): string {
  return USER_FILE;
}
