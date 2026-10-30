import { existsSync } from 'fs';
import { readdir, readFile, rm } from 'fs/promises';
import { homedir } from 'os';
import { join, resolve } from 'path';

export function readSessionIdFromEnv(content: string): string | undefined {
  return /^# UOMP session (\S+)$/m.exec(content)?.[1];
}

export function expandSessionPath(value: string): string {
  if (value === '~') return homedir();
  if (value.startsWith('~/')) return join(homedir(), value.slice(2));
  return resolve(value);
}

export async function findSessionEnvPaths(sessionsDir: string, sessionId: string): Promise<string[]> {
  const paths = new Set<string>();
  const defaultPath = join(sessionsDir, `${sessionId}.env`);
  if (existsSync(defaultPath)) {
    paths.add(defaultPath);
  }

  let entries: string[];
  try {
    entries = await readdir(sessionsDir);
  } catch {
    return [...paths];
  }

  for (const entry of entries) {
    if (!entry.endsWith('.env')) continue;

    const envPath = join(sessionsDir, entry);
    if (paths.has(envPath)) continue;

    try {
      const content = await readFile(envPath, 'utf-8');
      if (readSessionIdFromEnv(content) === sessionId) {
        paths.add(envPath);
      }
    } catch {
      // Ignore files that disappear or cannot be read.
    }
  }

  return [...paths];
}

export async function removeSessionEnvFiles(sessionsDir: string, sessionId: string): Promise<string[]> {
  const paths = await findSessionEnvPaths(sessionsDir, sessionId);
  for (const envPath of paths) {
    await rm(envPath, { force: true });
  }
  return paths;
}
