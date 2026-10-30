import { serve } from '@hono/node-server';
import { mkdir } from 'fs/promises';
import { homedir } from 'os';
import { join } from 'path';
import { DEFAULT_HOST, DEFAULT_PORT, DATA_DIR_NAME, SECRETS_DIR_NAME } from '@uomp/core';
import { AuthService, loadOrCreateAdminToken } from '@uomp/auth';
import { AegisConsentBridge, HttpAegisMcpClient } from '@uomp/aegis-adapter';
import { MemoryGuard } from '@uomp/guard';
import { MemoryStore } from '@uomp/store';
import { JWTTokenIssuer } from '@uomp/token';

async function main() {
  const dataDir = join(homedir(), DATA_DIR_NAME);
  const secretsDir = join(dataDir, SECRETS_DIR_NAME);
  await mkdir(dataDir, { recursive: true });
  await mkdir(secretsDir, { recursive: true });

  const issuer = new JWTTokenIssuer();
  await issuer.loadOrGenerateKey(secretsDir);

  const authDbPath = join(dataDir, 'auth.db');
  const auditDbPath = join(dataDir, 'audit.db');
  const memoryDbPath = join(dataDir, 'memory.db');

  const adminToken = loadOrCreateAdminToken(secretsDir);

  const aegisEndpoint = process.env.UOMP_AEGIS_MCP_URL;
  const aegisToken = process.env.UOMP_AEGIS_TOKEN;
  const aegis = aegisEndpoint && aegisToken
    ? new AegisConsentBridge(new HttpAegisMcpClient({
        endpoint: aegisEndpoint,
        token: aegisToken,
        orgId: process.env.UOMP_AEGIS_ORG ?? 'local',
        agentId: process.env.UOMP_AEGIS_AGENT ?? 'uomp',
      }))
    : undefined;

  const authService = new AuthService({
    dbPath: authDbPath,
    issuer,
    adminToken,
    aegis,
    consentKeyResolver: (tag: string) => {
      const store = new MemoryStore({ dbPath: memoryDbPath });
      try {
        return store.getByTag(tag).map(item => {
          const value = item.value as Record<string, unknown> | null | undefined;
          const title = value?.title ?? value?.path ?? item.description;
          return {
            key: item.key,
            ...(typeof title === 'string' ? { title } : {}),
            sensitivity: item.sensitivity,
          };
        });
      } finally {
        store.close();
      }
    },
    consentKeyLookup: (key: string) => {
      const store = new MemoryStore({ dbPath: memoryDbPath });
      try {
        const item = store.get(key);
        if (!item) return null;
        const value = item.value as Record<string, unknown> | null | undefined;
        const title = value?.title ?? value?.path ?? item.description;
        return {
          key: item.key,
          ...(typeof title === 'string' ? { title } : {}),
          sensitivity: item.sensitivity,
        };
      } finally {
        store.close();
      }
    },
  });

  const guard = new MemoryGuard({
    dbPath: auditDbPath,
    memoryDbPath,
    issuer,
    sessionStateProvider: authService,
    adminToken,
  });

  const authApp = authService.getApp();
  const guardApp = guard.getApp();

  // Combine both apps
  const app = authApp;
  app.route('/', guardApp);

  const host = process.env.UOMP_HOST ?? DEFAULT_HOST;
  const port = Number(process.env.UOMP_PORT ?? DEFAULT_PORT);

  console.log(`UOMP server starting on http://${host}:${port}`);

  serve({
    fetch: app.fetch,
    port,
    hostname: host,
  });
}

main().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
