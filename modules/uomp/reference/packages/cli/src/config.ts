import { chmod, mkdir } from 'fs/promises';
import { homedir } from 'os';
import { join } from 'path';
import {
  DATA_DIR_NAME,
  AGENTS_DIR_NAME,
  SECRETS_DIR_NAME,
  SESSIONS_DIR_NAME,
  MEMORY_DB_NAME,
  AUDIT_DB_NAME,
  AUTH_DB_NAME,
  DEFAULT_PORT,
  DEFAULT_HOST,
} from '@uomp/core';
import { loadOrCreateAdminToken } from '@uomp/auth';

export class UompConfig {
  readonly dataDir: string;
  readonly agentsDir: string;
  readonly registryDir: string;
  readonly secretsDir: string;
  readonly sessionsDir: string;
  readonly memoryDbPath: string;
  readonly auditDbPath: string;
  readonly authDbPath: string;
  readonly port: number;
  readonly host: string;
  adminToken!: string;

  constructor(options: { dataDir?: string; port?: number; host?: string } = {}) {
    this.dataDir = options.dataDir ?? join(homedir(), DATA_DIR_NAME);
    this.agentsDir = join(this.dataDir, AGENTS_DIR_NAME);
    this.registryDir = join(this.dataDir, 'registry');
    this.secretsDir = join(this.dataDir, SECRETS_DIR_NAME);
    this.sessionsDir = join(this.dataDir, SESSIONS_DIR_NAME);
    this.memoryDbPath = join(this.dataDir, MEMORY_DB_NAME);
    this.auditDbPath = join(this.dataDir, AUDIT_DB_NAME);
    this.authDbPath = join(this.dataDir, AUTH_DB_NAME);
    this.port = options.port ?? DEFAULT_PORT;
    this.host = options.host ?? DEFAULT_HOST;
  }

  async init(): Promise<void> {
    await mkdir(this.dataDir, { recursive: true, mode: 0o700 });
    await mkdir(this.agentsDir, { recursive: true, mode: 0o700 });
    await mkdir(this.registryDir, { recursive: true, mode: 0o700 });
    await mkdir(this.secretsDir, { recursive: true, mode: 0o700 });
    await mkdir(this.sessionsDir, { recursive: true, mode: 0o700 });
    await chmod(this.dataDir, 0o700).catch(() => {});
    await chmod(this.secretsDir, 0o700).catch(() => {});
    await chmod(this.sessionsDir, 0o700).catch(() => {});
    this.adminToken = loadOrCreateAdminToken(this.secretsDir);
  }

  get serverUrl(): string {
    return formatServerUrl(this.host, this.port);
  }
}

export function formatServerUrl(host: string, port: number): string {
  if (host === '0.0.0.0' || host === '::') {
    host = '127.0.0.1';
  }

  const urlHost = host.includes(':') ? `[${host}]` : host;
  return `http://${urlHost}:${port}`;
}
