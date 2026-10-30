import { readFile } from 'fs/promises';
import { homedir } from 'os';
import { join, resolve } from 'path';
import type { UompConfig } from '../config.js';

export interface SessionCredentials {
  token: string;
  baseUrl: string;
  source: string;
}

export async function loadSessionCredentials(
  config: UompConfig,
  session?: string
): Promise<SessionCredentials | null> {
  if (session) {
    const envPath = resolveSessionPath(config, session);
    let content: string;
    try {
      content = await readFile(envPath, 'utf-8');
    } catch {
      throw new Error(`Session file not found: ${envPath}`);
    }
    const values = parseExports(content);

    if (!values.UOM_TOKEN) {
      throw new Error(`No UOM_TOKEN found in ${envPath}`);
    }

    return {
      token: values.UOM_TOKEN,
      baseUrl: values.UOMP_BASE_URL ?? config.serverUrl,
      source: envPath,
    };
  }

  if (!process.env.UOM_TOKEN) {
    return null;
  }

  return {
    token: process.env.UOM_TOKEN,
    baseUrl: process.env.UOMP_BASE_URL ?? config.serverUrl,
    source: 'environment',
  };
}

export function resolveSessionPath(config: UompConfig, session: string): string {
  if (session.startsWith('~/')) {
    return join(homedir(), session.slice(2));
  }

  if (session.includes('/') || session.includes('\\') || session.endsWith('.env')) {
    return resolve(session);
  }

  return join(config.sessionsDir, `${session}.env`);
}

function parseExports(content: string): Record<string, string> {
  const values: Record<string, string> = {};

  for (const line of content.split(/\r?\n/)) {
    const match = /^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) continue;

    values[match[1]] = unquote(match[2].trim());
  }

  return values;
}

function unquote(value: string): string {
  if (value.startsWith("'") && value.endsWith("'")) {
    return value.slice(1, -1).replace(/'\\''/g, "'");
  }

  if (value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }

  return value;
}
