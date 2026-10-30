import net from 'net';
import { serve } from '@hono/node-server';
import { AuthService } from '@uomp/auth';
import { MemoryGuard } from '@uomp/guard';
import { MemoryStore } from '@uomp/store';
import { JWTTokenIssuer } from '@uomp/token';
import { formatServerUrl, type UompConfig } from '../config.js';

export interface UompRuntime {
  config: UompConfig;
  issuer: JWTTokenIssuer;
  auth: AuthService;
  guard: MemoryGuard;
  fetch: (request: Request) => Response | Promise<Response>;
  close(): void;
}

export interface ServerStartOptions {
  port?: number;
  host?: string;
}

export type ServerStartResult =
  | { status: 'started'; url: string; close(): void }
  | { status: 'in-use'; url: string; isUomp: boolean; close(): void };

/**
 * Build the Auth + Guard runtime used by `uomp serve` and by
 * `uomp authorize` when it starts the embedded server.
 */
export async function createUompRuntime(config: UompConfig): Promise<UompRuntime> {
  await config.init();

  const issuer = new JWTTokenIssuer();
  await issuer.loadOrGenerateKey(config.secretsDir);

  const auth = new AuthService({
    dbPath: config.authDbPath,
    issuer,
    adminToken: config.adminToken,
    consentKeyResolver: (tag: string) => {
      const store = new MemoryStore({ dbPath: config.memoryDbPath });
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
      const store = new MemoryStore({ dbPath: config.memoryDbPath });
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
    dbPath: config.auditDbPath,
    memoryDbPath: config.memoryDbPath,
    issuer,
    sessionStateProvider: auth,
  });

  const app = auth.getApp();
  app.route('/', guard.getApp());

  let closed = false;
  return {
    config,
    issuer,
    auth,
    guard,
    fetch: app.fetch,
    close() {
      if (closed) return;
      closed = true;
      auth.close();
      guard.close();
    },
  };
}

export async function startUompServer(
  runtime: UompRuntime,
  options: ServerStartOptions = {}
): Promise<ServerStartResult> {
  const port = options.port ?? runtime.config.port;
  const host = options.host ?? runtime.config.host;
  const url = formatServerUrl(host, port);

  let available: boolean;
  try {
    available = await isPortAvailable(port, host);
  } catch (error) {
    runtime.close();
    throw error;
  }

  if (!available) {
    return {
      status: 'in-use',
      url,
      isUomp: await probeUompServer(url),
      close: () => runtime.close(),
    };
  }

  const server = serve({
    fetch: runtime.fetch,
    port,
    hostname: host,
  });

  try {
    await new Promise<void>((resolve, reject) => {
      const onListening = () => {
        server.off('error', onError);
        resolve();
      };
      const onError = (error: Error) => {
        server.off('listening', onListening);
        reject(error);
      };

      server.once('listening', onListening);
      server.once('error', onError);
    });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EADDRINUSE') {
      return {
        status: 'in-use',
        url,
        isUomp: await probeUompServer(url),
        close: () => runtime.close(),
      };
    }
    runtime.close();
    throw error;
  }

  server.on('error', (error: Error) => {
    console.error(`UOMP server error: ${error.message}`);
  });

  let closed = false;
  return {
    status: 'started',
    url,
    close() {
      if (closed) return;
      closed = true;
      server.close();
      runtime.close();
    },
  };
}

export function installShutdownHandlers(close: () => void): void {
  let closing = false;
  const shutdown = (code: number) => {
    if (closing) return;
    closing = true;
    close();
    process.exit(code);
  };

  process.once('SIGINT', () => shutdown(130));
  process.once('SIGTERM', () => shutdown(143));
}

export function parsePort(value: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid port "${value}". Use a number between 1 and 65535.`);
  }
  return port;
}

export function parseHost(value: string): string {
  const host = value.trim();
  if (!host) {
    throw new Error('Host must not be empty.');
  }
  return host;
}

export function findAvailablePort(host = '127.0.0.1'): Promise<number> {
  return new Promise((resolve, reject) => {
    const tester = net.createServer();
    tester.once('error', reject);
    tester.listen(0, host, () => {
      const address = tester.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      tester.close(() => resolve(port));
    });
  });
}

export function isLoopbackHost(host: string): boolean {
  return host === '127.0.0.1' || host === 'localhost' || host === '::1';
}

export async function probeUompServer(url: string): Promise<boolean> {
  try {
    const response = await fetch(`${url}/health`, {
      signal: AbortSignal.timeout(1_000),
    });
    if (!response.ok) {
      return false;
    }

    const body = await response.json() as { service?: string };
    return body.service === 'uomp';
  } catch {
    return false;
  }
}

export async function isPortAvailable(port: number, host: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const tester = net.createServer();
    tester.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EADDRINUSE') {
        resolve(false);
      } else {
        reject(error);
      }
    });
    tester.once('listening', () => {
      tester.close(() => resolve(true));
    });
    tester.listen(port, host);
  });
}
