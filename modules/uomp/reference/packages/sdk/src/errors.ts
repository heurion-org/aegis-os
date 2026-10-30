export enum UompErrorCode {
  ACCESS_DENIED = 'ACCESS_DENIED',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  INVALID_TOKEN = 'INVALID_TOKEN',
  SESSION_REVOKED = 'SESSION_REVOKED',
  AUDIENCE_MISMATCH = 'AUDIENCE_MISMATCH',
  INVALID_PROFILE = 'INVALID_PROFILE',
  CERT_NOT_ALLOWED = 'CERT_NOT_ALLOWED',
  MTLS_REQUIRED = 'MTLS_REQUIRED',
  ENDPOINT_NOT_ALLOWED = 'ENDPOINT_NOT_ALLOWED',
  QUOTA_EXCEEDED = 'QUOTA_EXCEEDED',
  WRITE_NOT_AVAILABLE = 'WRITE_NOT_AVAILABLE',
  STORE_UNAVAILABLE = 'STORE_UNAVAILABLE',
  SESSION_NOT_FOUND = 'SESSION_NOT_FOUND',
  INVALID_REQUEST = 'INVALID_REQUEST',
  NETWORK_ERROR = 'NETWORK_ERROR',
  TIMEOUT = 'TIMEOUT',
  UNKNOWN = 'UNKNOWN',
}

export class UompError extends Error {
  code: UompErrorCode;
  sessionId?: string;
  statusCode?: number;

  constructor(code: UompErrorCode, message: string, sessionId?: string, statusCode?: number) {
    super(message);
    this.name = 'UompError';
    this.code = code;
    this.sessionId = sessionId;
    this.statusCode = statusCode;
  }

  get isRetryable(): boolean {
    return this.code === UompErrorCode.NETWORK_ERROR
      || this.code === UompErrorCode.TIMEOUT
      || (this.statusCode != null && this.statusCode >= 500);
  }
}

export function parseApiError(body: unknown, status: number): UompError {
  if (body && typeof body === 'object' && 'error' in body) {
    const err = (body as Record<string, { code?: string; message?: string; session_id?: string }>).error;
    const code = (err?.code ?? 'UNKNOWN') as UompErrorCode;
    const msg = err?.message ?? `HTTP ${status}`;
    const sid = err?.session_id;
    return new UompError(code, msg, sid, status);
  }
  return new UompError(UompErrorCode.UNKNOWN, `HTTP ${status}`, undefined, status);
}
