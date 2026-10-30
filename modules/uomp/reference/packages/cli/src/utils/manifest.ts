import { readFile } from 'fs/promises';
import { join } from 'path';
import type { RawAgentManifest } from '@uomp/core';
import { normalizeManifest } from '@uomp/core';

export type { RawAgentManifest };

export async function loadManifest(agentPath: string) {
  try {
    const content = await readFile(join(agentPath, 'uom.json'), 'utf-8');
    const raw = JSON.parse(content) as RawAgentManifest;
    return normalizeManifest(raw);
  } catch {
    return null;
  }
}

export function loadRawManifest(agentPath: string): Promise<RawAgentManifest | null> {
  return readFile(join(agentPath, 'uom.json'), 'utf-8')
    .then(content => JSON.parse(content) as RawAgentManifest)
    .catch(() => null);
}

export function getFieldDeclarations(raw: RawAgentManifest): { fields: Record<string, string[]>; purposes: Record<string, string> } {
  const read = raw.requested_scopes?.read;
  return { fields: read?.fields ?? {}, purposes: read?.purposes ?? {} };
}
