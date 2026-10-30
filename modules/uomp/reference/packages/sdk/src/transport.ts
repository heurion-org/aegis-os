import https from 'https';
import http from 'http';
import { readFileSync, existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { URL } from 'url';
import { UompError, UompErrorCode, parseApiError } from './errors.js';
import type { UompClientOptions } from './types.js';

export interface TransportInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  signal?: AbortSignal;
}

export interface TransportResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

export class Transport {
  readonly baseUrl: string;
  private agentId?: string;
  private timeoutMs: number;
  private retries: number;
  private retryBackoff: number;
  private customFetch?: typeof fetch;
  private mtlsAgent: https.Agent | null;
  private jwtToken: (() => string) | null;
  private isBrowser: boolean;

  constructor(options: UompClientOptions = {}, jwtToken?: () => string) {
    this.baseUrl = (options.baseUrl || 'http://127.0.0.1:9374').replace(/\/$/, '');
    this.agentId = options.agentId;
    this.timeoutMs = options.transport?.timeout ?? 15000;
    this.retries = options.transport?.retries ?? 2;
    this.retryBackoff = options.transport?.retryBackoff ?? 1000;
    this.customFetch = options.transport?.fetch;
    this.mtlsAgent = null;
    this.jwtToken = jwtToken ?? null;
    this.isBrowser = typeof globalThis.window !== 'undefined' && typeof (globalThis as any).window?.fetch !== 'undefined';

    if (this.baseUrl.startsWith('https://') && !this.isBrowser) {
      this.loadMtlsCert(options.tls);
    }
  }

  private loadMtlsCert(tls?: UompClientOptions['tls']) {
    try {
      const certDir = join(homedir(), '.uomp', '.gateway-certs');
      const certPath = tls?.certPath ?? join(certDir, 'client.crt');
      const keyPath = tls?.keyPath ?? join(certDir, 'client.key');
      const caPath = tls?.caPath ?? join(certDir, 'ca.crt');

      if (!existsSync(certPath) || !existsSync(keyPath)) return;

      const cert = readFileSync(certPath);
      const key = readFileSync(keyPath);
      const ca = existsSync(caPath) ? readFileSync(caPath) : undefined;

      this.mtlsAgent = new https.Agent({
        cert, key, ca,
        rejectUnauthorized: tls?.rejectUnauthorized ?? false,
      });
    } catch {
      this.mtlsAgent = null;
    }
  }

  private token(): string {
    return this.jwtToken?.() ?? '';
  }

  async request(path: string, init: TransportInit = {}): Promise<TransportResponse> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) {
        await new Promise(r => setTimeout(r, this.retryBackoff * attempt));
      }

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

        try {
          const headers: Record<string, string> = {
            Authorization: `Bearer ${this.token()}`,
            Accept: 'application/json',
            ...init.headers,
          };

          if (this.agentId && !headers['x-uomp-agent-id']) {
            headers['X-UOMP-Agent-Id'] = this.agentId;
          }

          const url = `${this.baseUrl}${path}`;
          const f = this.isBrowser
            ? ((this.customFetch ?? (globalThis as any).fetch) as typeof fetch)
            : (this.mtlsAgent ? this.nativeRequest.bind(this) : (this.customFetch ?? fetch));

          const resp = this.isBrowser
            ? await (f as typeof fetch)(url, { method: init.method, headers, body: init.body as any, signal: controller.signal })
            : await (f as typeof this.nativeRequest)(url, { ...init, headers, signal: controller.signal });

          return resp;
        } finally {
          clearTimeout(timeout);
        }
      } catch (err) {
        lastError = err as Error;
        const msg = (err as Error).message?.toLowerCase() || '';

        // Don't retry 4xx errors or abort
        if (msg.includes('abort')) {
          throw new UompError(UompErrorCode.TIMEOUT, `Request timeout after ${this.timeoutMs}ms`);
        }
        // Don't retry non-network errors
        if (attempt === this.retries) break;
      }
    }

    throw new UompError(UompErrorCode.NETWORK_ERROR, lastError?.message ?? 'Network error');
  }

  async requestJson<T>(path: string, init?: TransportInit): Promise<T> {
    const resp = await this.request(path, init);
    if (!resp.ok) {
      const body = await resp.json().catch(() => null);
      throw parseApiError(body, resp.status);
    }
    return resp.json() as Promise<T>;
  }

  private nativeRequest(url: string, init: TransportInit & { signal: AbortSignal }): Promise<TransportResponse> {
    return new Promise((resolve, reject) => {
      const u = new URL(url);
      const isHttps = u.protocol === 'https:';
      const mod = isHttps ? https : http;

      const req = mod.request({
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: u.pathname + u.search,
        method: init.method || 'GET',
        headers: init.headers || {},
        agent: this.mtlsAgent ?? undefined,
      }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks);
          resolve({
            ok: res.statusCode != null && res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode ?? 0,
            json: async () => JSON.parse(body.toString()),
            text: async () => body.toString(),
          });
        });
      });

      req.on('error', reject);
      if (init.body) req.write(init.body);
      req.end();

      init.signal.addEventListener('abort', () => {
        req.destroy(new Error('Aborted'));
      }, { once: true });
    });
  }
}
