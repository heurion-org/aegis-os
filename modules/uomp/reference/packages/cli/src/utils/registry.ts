import { readFile, writeFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';

export interface RegistryEntry {
  id: string;
  version: string;
  name?: string;
  description?: string;
  publisher?: string;
  publisherDID?: string;
  metadataURI?: string;
  sourceUrl?: string;
  packageChecksum?: string;
  signature?: string;
  verified?: boolean;
  tags?: string[];
  addedAt?: string;
}

export interface RegistryIndex {
  version: string;
  updatedAt: string;
  agents: RegistryEntry[];
}

export class LocalRegistry {
  private registryDir: string;
  private indexPath: string;
  private cacheDir: string;

  constructor(registryDir: string) {
    this.registryDir = registryDir;
    this.indexPath = join(registryDir, 'index.json');
    this.cacheDir = join(registryDir, 'cache');
  }

  async init(): Promise<void> {
    await mkdir(this.registryDir, { recursive: true });
    await mkdir(this.cacheDir, { recursive: true });
    if (!existsSync(this.indexPath)) {
      await writeFile(this.indexPath, JSON.stringify({ version: '1.0', updatedAt: new Date().toISOString(), agents: [] }, null, 2), 'utf-8');
    }
  }

  async readIndex(): Promise<RegistryIndex> {
    await this.init();
    const content = await readFile(this.indexPath, 'utf-8');
    return JSON.parse(content) as RegistryIndex;
  }

  async writeIndex(index: RegistryIndex): Promise<void> {
    await this.init();
    index.updatedAt = new Date().toISOString();
    await writeFile(this.indexPath, JSON.stringify(index, null, 2), 'utf-8');
  }

  async search(keyword: string): Promise<RegistryEntry[]> {
    const index = await this.readIndex();
    const lower = keyword.toLowerCase();
    return index.agents.filter(
      a =>
        a.id.toLowerCase().includes(lower) ||
        (a.name?.toLowerCase().includes(lower) ?? false) ||
        (a.description?.toLowerCase().includes(lower) ?? false) ||
        (a.tags?.some(t => t.toLowerCase().includes(lower)) ?? false)
    );
  }

  async list(): Promise<RegistryEntry[]> {
    const index = await this.readIndex();
    return index.agents;
  }

  async add(entry: RegistryEntry): Promise<void> {
    const index = await this.readIndex();
    const existing = index.agents.findIndex(a => a.id === entry.id);
    if (existing >= 0) {
      index.agents[existing] = { ...index.agents[existing], ...entry, addedAt: entry.addedAt ?? new Date().toISOString() };
    } else {
      index.agents.push({ ...entry, addedAt: entry.addedAt ?? new Date().toISOString() });
    }
    await this.writeIndex(index);
  }

  async remove(id: string): Promise<boolean> {
    const index = await this.readIndex();
    const before = index.agents.length;
    index.agents = index.agents.filter(a => a.id !== id);
    await this.writeIndex(index);
    return index.agents.length < before;
  }

  async get(id: string): Promise<RegistryEntry | undefined> {
    const index = await this.readIndex();
    return index.agents.find(a => a.id === id);
  }
}
