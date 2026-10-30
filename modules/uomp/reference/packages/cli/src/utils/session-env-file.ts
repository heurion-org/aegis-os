import { chmod, mkdir, rename, rm, writeFile } from 'fs/promises';
import { dirname } from 'path';
import { sanitizeText } from './format.js';

export interface SessionEnvData {
  sessionId: string;
  agentId: string;
  expiresAt: string;
  token: string;
  baseUrl: string;
}

export async function writeSessionEnvFile(envPath: string, data: SessionEnvData): Promise<void> {
  await mkdir(dirname(envPath), { recursive: true, mode: 0o700 });

  const envBlock = [
    `# UOMP session ${sanitizeText(data.sessionId)}`,
    `# agent: ${sanitizeText(data.agentId)}`,
    `# expires: ${sanitizeText(data.expiresAt)}`,
    `export UOM_TOKEN=${shellQuote(data.token)}`,
    `export UOMP_BASE_URL=${shellQuote(data.baseUrl)}`,
    '',
  ].join('\n');

  const tempPath = `${envPath}.${process.pid}.${Date.now()}.tmp`;
  try {
    await writeFile(tempPath, envBlock, { mode: 0o600, flag: 'wx' });
    await chmod(tempPath, 0o600);
    await rename(tempPath, envPath);
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => {});
    throw error;
  }
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}
