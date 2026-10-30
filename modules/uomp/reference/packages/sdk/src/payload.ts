import { Transport } from './transport.js';
import { UompError, UompErrorCode, parseApiError } from './errors.js';
import type { PayloadInfo } from './types.js';

export class PayloadClient {
  constructor(private transport: Transport) {}

  async upload(data: string | Buffer | Uint8Array, contentType = 'application/octet-stream'): Promise<string> {
    const body = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data as any);
    const resp = await this.transport.request('/v1/payload/upload', {
      method: 'POST',
      headers: { 'Content-Type': contentType },
      body,
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      throw new UompError(UompErrorCode.UNKNOWN, `Payload upload failed: ${body}`, undefined, resp.status);
    }
    const result = await resp.json() as PayloadInfo;
    return result.payload_id;
  }

  async download(id: string): Promise<Buffer> {
    const resp = await this.transport.request(`/v1/payload/${encodeURIComponent(id)}`, {
      headers: { Accept: 'application/octet-stream' },
    });
    if (!resp.ok) {
      throw new UompError(UompErrorCode.UNKNOWN, `Payload ${id} not found`, undefined, resp.status);
    }
    const text = await resp.text();
    return Buffer.from(text, 'utf-8');
  }

  async info(id: string): Promise<PayloadInfo> {
    try {
      await this.transport.request(`/v1/payload/${encodeURIComponent(id)}`);
    } catch {
      throw new UompError(UompErrorCode.UNKNOWN, `Payload ${id} not found`);
    }
    return { payload_id: id, size: 0 };
  }
}
