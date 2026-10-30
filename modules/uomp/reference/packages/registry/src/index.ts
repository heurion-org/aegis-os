import type { AgentManifest } from '@uomp/core';

export interface RegistryEntry {
  agentId: string;
  name: string;
  version: string;
  publisher?: string;
  description?: string;
  uomJsonUrl?: string;
  verified?: boolean;
}

export interface RegistryClient {
  search(keyword: string): Promise<RegistryEntry[]>;
  get(agentId: string): Promise<RegistryEntry | null>;
  install(agentId: string, targetDir: string): Promise<string>;
}

export interface ERC8004RegistryOptions {
  endpoint: string;
}

/**
 * MVP implementation of an ERC8004-compatible registry client.
 * In production, this would query an on-chain or API-based registry.
 */
export class ERC8004RegistryClient implements RegistryClient {
  private endpoint: string;

  constructor(options: ERC8004RegistryOptions) {
    this.endpoint = options.endpoint;
  }

  async search(keyword: string): Promise<RegistryEntry[]> {
    // MVP: return mock results. Replace with actual ERC8004 API call.
    const mockEntries: RegistryEntry[] = [
      {
        agentId: 'calendar_agent',
        name: 'Calendar Assistant',
        version: '1.0.0',
        publisher: 'uomp-community',
        description: 'Helps manage your schedule',
        verified: true,
      },
      {
        agentId: 'email_agent',
        name: 'Email Organizer',
        version: '0.9.0',
        publisher: 'uomp-community',
        description: 'Organizes your inbox',
        verified: false,
      },
    ];

    return mockEntries.filter(
      e =>
        e.agentId.includes(keyword) ||
        e.name.toLowerCase().includes(keyword.toLowerCase()) ||
        (e.description?.toLowerCase().includes(keyword.toLowerCase()) ?? false)
    );
  }

  async get(agentId: string): Promise<RegistryEntry | null> {
    const results = await this.search(agentId);
    return results.find(e => e.agentId === agentId) ?? null;
  }

  async install(agentId: string, targetDir: string): Promise<string> {
    // MVP: just create a placeholder directory. Real implementation downloads agent package.
    const fs = await import('fs/promises');
    const path = await import('path');

    const agentDir = path.join(targetDir, agentId);
    await fs.mkdir(agentDir, { recursive: true });

    const manifest: AgentManifest = {
      uompVersion: '1.0',
      agent: {
        id: agentId,
        name: agentId,
        version: '1.0.0',
      },
      requestedScopes: {
        read: { tags: ['preference'], keys: [], denyTags: [], denyKeys: [] },
        write: { tags: [], keys: [], denyTags: [], denyKeys: [] },
      },
    };

    await fs.writeFile(
      path.join(agentDir, 'uom.json'),
      JSON.stringify(manifest, null, 2)
    );

    return agentDir;
  }
}
