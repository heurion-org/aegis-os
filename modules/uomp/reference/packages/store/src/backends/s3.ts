/**
 * S3-compatible object client using fetch (no AWS SDK dependency).
 * Works with AWS S3, Cloudflare R2, Backblaze B2, MinIO.
 */
import { createHash } from 'crypto';

export interface S3Config {
  endpoint: string;
  bucket: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
}

function signRequest(
  method: string,
  path: string,
  region: string,
  service: string,
  accessKey: string,
  secretKey: string,
  body?: string | Buffer,
): Record<string, string> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const host = `${path.split('/')[0]}`;
  const canonicalUri = '/' + path.split('/').slice(1).join('/');
  const canonicalQuery = '';
  const payloadHash = body ? createHash('sha256').update(body).digest('hex') : 'UNSIGNED-PAYLOAD';

  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';

  const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${createHash('sha256').update(canonicalRequest).digest('hex')}`;

  const kDate = hmacSha256(`AWS4${secretKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, 'aws4_request');
  const signature = hmacSha256(kSigning, stringToSign, 'hex');

  return {
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
    Authorization: `AWS4-HMAC-SHA256 Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

function hmacSha256(key: Buffer | string, data: string, encoding?: 'hex'): string {
  const { createHmac } = require('crypto');
  const hmac = createHmac('sha256', key);
  hmac.update(data, 'utf-8');
  return encoding ? hmac.digest(encoding) : hmac.digest();
}

export class S3Client {
  private endpoint: string;
  private bucket: string;
  private region: string;
  private accessKey: string;
  private secretKey: string;

  constructor(config: S3Config) {
    this.endpoint = config.endpoint.replace(/\/$/, '');
    this.bucket = config.bucket;
    this.region = config.region;
    this.accessKey = config.accessKeyId;
    this.secretKey = config.secretAccessKey;
  }

  async get(key: string): Promise<Buffer | null> {
    const url = `${this.endpoint}/${this.bucket}/${key}`;
    const host = new URL(this.endpoint).host;
    const path = `${host}/${this.bucket}/${key}`;
    const headers = signRequest('GET', path, this.region, 's3', this.accessKey, this.secretKey);

    try {
      const resp = await fetch(url, { headers });
      if (!resp.ok) return null;
      return Buffer.from(await resp.arrayBuffer());
    } catch {
      return null;
    }
  }

  async put(key: string, data: Buffer | string, contentType = 'application/octet-stream'): Promise<boolean> {
    const body = typeof data === 'string' ? Buffer.from(data) : data;
    const url = `${this.endpoint}/${this.bucket}/${key}`;
    const host = new URL(this.endpoint).host;
    const path = `${host}/${this.bucket}/${key}`;
    const headers = {
      ...signRequest('PUT', path, this.region, 's3', this.accessKey, this.secretKey, body),
      'Content-Type': contentType,
      'Content-Length': String(body.length),
    };

    try {
      const resp = await fetch(url, { method: 'PUT', headers, body });
      return resp.ok;
    } catch {
      return false;
    }
  }

  async delete(key: string): Promise<boolean> {
    const url = `${this.endpoint}/${this.bucket}/${key}`;
    const host = new URL(this.endpoint).host;
    const path = `${host}/${this.bucket}/${key}`;
    const headers = signRequest('DELETE', path, this.region, 's3', this.accessKey, this.secretKey);

    try {
      const resp = await fetch(url, { method: 'DELETE', headers });
      return resp.ok;
    } catch {
      return false;
    }
  }

  async list(prefix: string): Promise<string[]> {
    const url = `${this.endpoint}/${this.bucket}?list-type=2&prefix=${encodeURIComponent(prefix)}`;
    const host = new URL(this.endpoint).host;
    const path = `${host}/${this.bucket}`;
    const headers = signRequest('GET', path + `?list-type=2&prefix=${encodeURIComponent(prefix)}`, this.region, 's3', this.accessKey, this.secretKey);

    try {
      const resp = await fetch(url, { headers });
      if (!resp.ok) return [];
      const text = await resp.text();
      const keys: string[] = [];
      const matches = text.matchAll(/<Key>([^<]+)<\/Key>/g);
      for (const m of matches) keys.push(m[1]);
      return keys;
    } catch {
      return [];
    }
  }
}
