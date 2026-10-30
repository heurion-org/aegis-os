/**
 * UOMP Cloud Relay — Stateless public Gateway
 * 
 * Validates Capability Tokens using only the public key (no private key needed).
 * Forwards write requests to Guard. Does NOT store or read plaintext data.
 */
import { Hono, type Context } from 'hono';
import { serve } from '@hono/node-server';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { JWTTokenIssuer, isTokenExpired, type CapabilityTokenPayload } from '@uomp/token';
import { PUBLIC_KEY_FILE_NAME } from '@uomp/core';
import type { JWK } from 'jose';

type Variables = { tokenPayload: CapabilityTokenPayload };
type App = Hono<{ Variables: Variables }>;

interface RelayConfig {
  port: number;
  guardUrl: string;
  secretsDir: string;
  rateLimitWindow: number;
  maxRequestsPerWindow: number;
}

async function loadConfig(): Promise<RelayConfig> {
  return {
    port: parseInt(process.env.RELAY_PORT || '3081', 10),
    guardUrl: process.env.RELAY_GUARD_URL || 'http://127.0.0.1:9374',
    secretsDir: join(homedir(), '.uomp', '.secrets'),
    rateLimitWindow: parseInt(process.env.RELAY_RATE_WINDOW || '60000', 10),
    maxRequestsPerWindow: parseInt(process.env.RELAY_RATE_MAX || '100', 10),
  };
}

async function loadPublicKey(secretsDir: string): Promise<JWTTokenIssuer> {
  const publicPath = join(secretsDir, PUBLIC_KEY_FILE_NAME);
  const content = await readFile(publicPath, 'utf-8');
  const jwk = JSON.parse(content) as JWK;
  const issuer = new JWTTokenIssuer();
  await issuer.importKey(jwk);
  return issuer;
}

// Simple in-memory rate limiter
class RateLimiter {
  private hits = new Map<string, number[]>();

  constructor(private windowMs: number, private max: number) {}

  allow(key: string): boolean {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const history = this.hits.get(key) || [];
    const recent = history.filter(t => t > cutoff);
    if (recent.length >= this.max) return false;
    recent.push(now);
    this.hits.set(key, recent);
    return true;
  }
}

async function main() {
  const config = await loadConfig();

  const issuer = await loadPublicKey(config.secretsDir).catch(err => {
    console.error('Failed to load public key:', err.message);
    console.error(`Ensure ${config.secretsDir}/${PUBLIC_KEY_FILE_NAME} exists`);
    process.exit(1);
  });

  const limiter = new RateLimiter(config.rateLimitWindow, config.maxRequestsPerWindow);
  const app = new Hono<{ Variables: Variables }>();

  // CORS for browser access
  app.use('*', async (c, next) => {
    c.header('Access-Control-Allow-Origin', '*');
    c.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    c.header('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-UOMP-Agent-Id');
    if (c.req.method === 'OPTIONS') return new Response(null, { status: 204 });
    await next();
  });

  app.get('/health', c => c.json({
    status: 'ok',
    relay: 'uomp-cloud-relay',
    version: '1.0.0',
  }));

  // Token verification middleware
  app.use('/v1/*', async (c, next) => {
    const authHeader = c.req.header('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: { code: 'INVALID_TOKEN', message: 'Missing token' } }, 401);
    }

    const token = authHeader.slice(7);
    let payload;
    try {
      payload = await issuer.verify(token);
    } catch {
      return c.json({ error: { code: 'INVALID_TOKEN', message: 'Token verification failed' } }, 401);
    }

    if (isTokenExpired(payload.expiresAt)) {
      return c.json({ error: { code: 'TOKEN_EXPIRED', message: 'Token expired' } }, 401);
    }

    // Rate limit per session
    if (!limiter.allow(payload.sessionId)) {
      return c.json({ error: { code: 'QUOTA_EXCEEDED', message: 'Rate limit exceeded' } }, 429);
    }

    c.set('tokenPayload', payload);
    await next();
  });

  // Forward write requests to Guard (Relay does NOT store or read data)
  app.all('/v1/memory/*', async c => {
    const payload = c.get('tokenPayload');
    const target = `${config.guardUrl}${c.req.path}`;
    const u = new URL(target);
    u.search = new URL(c.req.url).search;

    const headers: Record<string, string> = {
      authorization: `Bearer ${c.req.header('authorization')?.slice(7) || ''}`,
      'x-uomp-agent-id': payload.agentId,
    };
    if (c.req.header('content-type')) headers['content-type'] = c.req.header('content-type')!;

    const body = ['GET', 'HEAD'].includes(c.req.method) ? undefined : await c.req.arrayBuffer();

    const upstream = await fetch(u.toString(), {
      method: c.req.method,
      headers,
      body,
    });

    const responseBody = await upstream.arrayBuffer();
    return c.newResponse(responseBody, upstream.status as any, Object.fromEntries(upstream.headers.entries()));
  });

  // Payload upload relay
  app.post('/v1/payload/upload', async c => {
    const payload = c.get('tokenPayload');
    const target = `${config.guardUrl}/v1/payload/upload`;

    const upstream = await fetch(target, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${c.req.header('authorization')?.slice(7) || ''}`,
        'content-type': c.req.header('content-type') || 'application/octet-stream',
        'x-uomp-agent-id': payload.agentId,
      },
      body: await c.req.arrayBuffer(),
    });

    const responseBody = await upstream.arrayBuffer();
    return c.newResponse(responseBody, upstream.status as any, Object.fromEntries(upstream.headers.entries()));
  });

  // Deletion proof relay
  app.post('/v1/sessions/:id/deletion-proof', async c => {
    const payload = c.get('tokenPayload');
    const sessionId = c.req.param('id');
    const target = `${config.guardUrl}/v1/sessions/${sessionId}/deletion-proof`;

    const upstream = await fetch(target, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${c.req.header('authorization')?.slice(7) || ''}`,
        'content-type': 'application/json',
        'x-uomp-agent-id': payload.agentId,
      },
      body: await c.req.arrayBuffer(),
    });

    const responseBody = await upstream.arrayBuffer();
    return c.newResponse(responseBody, upstream.status as any, Object.fromEntries(upstream.headers.entries()));
  });

  serve({ fetch: app.fetch, port: config.port, hostname: '0.0.0.0' });
  console.log(`UOMP Cloud Relay v1.0.0`);
  console.log(`Listening on http://0.0.0.0:${config.port}`);
  console.log(`Forwarding to ${config.guardUrl}`);
  console.log(`Rate limit: ${config.maxRequestsPerWindow} req / ${config.rateLimitWindow / 1000}s`);
  console.log(`Token verification: public key only (no private key)`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
