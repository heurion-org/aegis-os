import { homedir } from 'os';
import { join } from 'path';
import { readFile } from 'fs/promises';
import { MemoryStore, AsyncStoreAdapter } from './index.js';
import { EncryptedObjectStore } from './backends/encrypted-object.js';
import type { IMemoryStore, StoreBackendConfig } from './types.js';

async function loadMasterKey(): Promise<Buffer | null> {
  try {
    const userPath = join(homedir(), '.uomp', 'user.json');
    const user = JSON.parse(await readFile(userPath, 'utf-8'));
    // masterKey should be stored securely — for MVP, look up from env or config
    if (process.env.UOMP_MASTER_KEY) {
      return Buffer.from(process.env.UOMP_MASTER_KEY, 'hex');
    }
    return null;
  } catch {
    return null;
  }
}

export async function createStore(config?: StoreBackendConfig): Promise<IMemoryStore> {
  const backend = config?.backend ?? 'sqlite';

  switch (backend) {
    case 'sqlite': {
      const dbPath = config?.sqlite?.dbPath ?? join(homedir(), '.uomp', 'memory.db');
      const store = new MemoryStore({ dbPath });
      return new AsyncStoreAdapter(store);
    }
    case 'encrypted-object': {
      if (!config?.s3) throw new Error('S3 config required for encrypted-object backend');
      const masterKey = await loadMasterKey();
      if (!masterKey) throw new Error('masterKey required. Set UOMP_MASTER_KEY env or run uomp user init --wallet');
      return new EncryptedObjectStore({ s3: config.s3, masterKey });
    }
    case 'ipfs':
      throw new Error('IPFS Store not yet implemented');
    default:
      throw new Error(`Unknown store backend: ${backend}`);
  }
}
