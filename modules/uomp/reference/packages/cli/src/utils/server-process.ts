import { spawn, type ChildProcess } from 'child_process';
import { closeSync, openSync } from 'fs';
import { mkdir, readFile, rm, writeFile } from 'fs/promises';
import { join } from 'path';
import { formatServerUrl, type UompConfig } from '../config.js';
import { isPortAvailable, probeUompServer } from './server.js';
import { getCliInvocation } from './mcp-config.js';

export interface ManagedServerState {
  pid: number;
  host: string;
  port: number;
  url: string;
  startedAt: string;
  logPath: string;
}

export type StartDetachedResult =
  | { status: 'started'; state: ManagedServerState; url: string }
  | { status: 'running'; state: ManagedServerState; url: string }
  | { status: 'external'; url: string };

export type ServerStatus =
  | { running: true; managed: true; url: string; pid: number; logPath: string; startedAt: string }
  | { running: true; managed: false; url: string }
  | { running: false; url: string };

export interface StopServerResult {
  stopped: boolean;
  pid?: number;
  reason?: string;
}

export function serverStatePath(config: UompConfig): string {
  return join(config.dataDir, 'server.json');
}

export function serverLogPath(config: UompConfig): string {
  return join(config.dataDir, 'server.log');
}

export async function startDetachedServer(config: UompConfig): Promise<StartDetachedResult> {
  await config.init();

  const statePath = serverStatePath(config);
  const existing = await readManagedState(config);
  if (existing) {
    if (await probeUompServer(existing.url)) {
      if (existing.port !== config.port || existing.host !== config.host) {
        throw new Error(
          `A managed UOMP server is already running on ${existing.url}. ` +
          'Stop it with `uomp stop` before starting on a different port or host.'
        );
      }
      return { status: 'running', state: existing, url: existing.url };
    }

    if (isProcessAlive(existing.pid)) {
      try {
        await waitForUomp(existing.url, 3_000);
        return { status: 'running', state: existing, url: existing.url };
      } catch {
        if (isRecent(existing.startedAt)) {
          await terminatePid(existing.pid);
        }
      }
    }

    await rm(statePath, { force: true });
  }

  const url = formatServerUrl(config.host, config.port);
  if (!(await isPortAvailable(config.port, config.host))) {
    if (await probeUompServer(url)) {
      return { status: 'external', url };
    }
    throw new Error(
      `Port ${config.port} is in use by another process. Stop it or choose another port with --port.`
    );
  }

  const logPath = serverLogPath(config);
  await mkdir(config.dataDir, { recursive: true, mode: 0o700 });
  const logFd = openSync(logPath, 'a', 0o600);
  const invocation = getCliInvocation();
  const args = [
    ...invocation.args,
    'serve',
    '--port',
    String(config.port),
    '--host',
    config.host,
  ];

  let child: ChildProcess | undefined;
  try {
    child = spawn(invocation.command, args, {
      detached: true,
      stdio: ['ignore', logFd, logFd],
      env: { ...process.env, UOMP_BACKGROUND: '1' },
    });
  } finally {
    closeSync(logFd);
  }

  if (!child) {
    throw new Error(`Failed to start the UOMP server. See ${logPath}.`);
  }

  child.on('error', () => {
    // The health check reports the failure with the log tail.
  });
  child.unref();

  if (!child.pid) {
    throw new Error(`Failed to start the UOMP server. See ${logPath}.`);
  }

  const state: ManagedServerState = {
    pid: child.pid,
    host: config.host,
    port: config.port,
    url,
    startedAt: new Date().toISOString(),
    logPath,
  };

  try {
    await writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  } catch (error) {
    await terminatePid(child.pid);
    throw error;
  }

  try {
    await waitForUomp(url, 10_000);
  } catch {
    await terminatePid(child.pid);
    await rm(statePath, { force: true });
    const log = await readServerLogTail(config, 15);
    throw new Error(
      `Failed to start the UOMP server. See ${logPath}.` +
      (log ? `\n\n${log}` : '')
    );
  }

  return { status: 'started', state, url };
}

export async function stopDetachedServer(config: UompConfig): Promise<StopServerResult> {
  const statePath = serverStatePath(config);
  const state = await readManagedState(config);

  if (!state) {
    return { stopped: false, reason: 'not running' };
  }

  if (state.pid === process.pid) {
    return { stopped: false, pid: state.pid, reason: 'refusing to stop the current process' };
  }

  const healthy = await probeUompServer(state.url);
  const wasAlive = isProcessAlive(state.pid);
  const shouldStop = wasAlive && (healthy || isRecent(state.startedAt));

  if (shouldStop) {
    await terminatePid(state.pid);
  }

  await rm(statePath, { force: true });

  if (shouldStop) {
    return { stopped: true, pid: state.pid };
  }

  return {
    stopped: false,
    pid: state.pid,
    reason: wasAlive ? 'unhealthy or stale state' : 'stale',
  };
}

export async function getServerStatus(config: UompConfig): Promise<ServerStatus> {
  const state = await readManagedState(config);

  if (state) {
    if (await probeUompServer(state.url)) {
      return {
        running: true,
        managed: true,
        url: state.url,
        pid: state.pid,
        logPath: state.logPath,
        startedAt: state.startedAt,
      };
    }
  }

  if (await probeUompServer(formatServerUrl(config.host, config.port))) {
    return { running: true, managed: false, url: formatServerUrl(config.host, config.port) };
  }

  return { running: false, url: formatServerUrl(config.host, config.port) };
}

export async function readServerLogTail(config: UompConfig, lines = 20): Promise<string> {
  const logPath = serverLogPath(config);
  try {
    const content = await readFile(logPath, 'utf-8');
    return content.trimEnd().split(/\r?\n/).slice(-lines).join('\n');
  } catch {
    return '';
  }
}

async function readManagedState(config: UompConfig): Promise<ManagedServerState | null> {
  try {
    const raw = JSON.parse(await readFile(serverStatePath(config), 'utf-8')) as Partial<ManagedServerState>;
    if (
      typeof raw.pid !== 'number' ||
      typeof raw.host !== 'string' ||
      typeof raw.port !== 'number' ||
      typeof raw.url !== 'string' ||
      typeof raw.startedAt !== 'string' ||
      typeof raw.logPath !== 'string'
    ) {
      return null;
    }
    return raw as ManagedServerState;
  } catch {
    return null;
  }
}

async function waitForUomp(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await probeUompServer(url)) return;
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error(`UOMP server did not become healthy at ${url}.`);
}

function isRecent(iso: string, maxAgeMs = 5 * 60 * 1000): boolean {
  const started = Date.parse(iso);
  return Number.isFinite(started) && Date.now() - started < maxAgeMs;
}

async function terminatePid(pid: number): Promise<void> {
  if (!isProcessAlive(pid)) return;

  try {
    process.kill(pid, 'SIGTERM');
  } catch {
    return;
  }

  if (await waitForExit(pid, 5_000)) return;

  try {
    process.kill(pid, 'SIGKILL');
  } catch {
    // Best effort.
  }

  await waitForExit(pid, 2_000);
}

function isProcessAlive(pid: number): boolean {
  if (pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

async function waitForExit(pid: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!isProcessAlive(pid)) return true;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  return !isProcessAlive(pid);
}
