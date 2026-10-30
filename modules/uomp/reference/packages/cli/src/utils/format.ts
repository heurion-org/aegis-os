import type { Scopes } from '@uomp/core';

export function sanitizeText(value: string): string {
  return value.replace(/[\r\n\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 120);
}

export function preview(items: string[], limit: number): string {
  const visible = items.slice(0, limit).map(sanitizeText).join(', ');
  const remaining = items.length - limit;
  return remaining > 0 ? `${visible} +${remaining} more` : visible;
}

export function formatScopes(scopes?: Scopes): string {
  if (!scopes) {
    return 'no scope';
  }

  const read = scopes.read;
  const parts: string[] = [];

  if (read.tags.length > 0) {
    parts.push(preview(read.tags, 4));
  }
  if (read.keys.length > 0) {
    parts.push(`${read.keys.length} explicit key${read.keys.length === 1 ? '' : 's'}`);
  }
  if (parts.length === 0) {
    parts.push('no read scope');
  }
  if (read.denyTags.length > 0) {
    parts.push(`except ${preview(read.denyTags, 3)}`);
  }

  const write = scopes.write;
  if (write.tags.length > 0 || write.keys.length > 0) {
    parts.push(`write ${preview([...write.tags, ...write.keys], 2)}`);
  }

  return parts.join(' · ');
}

export function formatDateTime(iso?: string): string {
  const date = iso ? new Date(iso) : null;
  if (!date || Number.isNaN(date.getTime())) return iso ?? '-';

  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function formatClock(iso?: string, now = new Date()): string {
  const date = iso ? new Date(iso) : null;
  if (!date || Number.isNaN(date.getTime())) return iso ?? '-';

  const pad = (value: number) => String(value).padStart(2, '0');
  const time = `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  const sameDay =
    date.getFullYear() === now.getFullYear() &&
    date.getMonth() === now.getMonth() &&
    date.getDate() === now.getDate();

  return sameDay ? time : `${formatDateTime(iso)}`;
}

export function formatRemaining(expiresAt?: string, now = new Date()): string {
  if (!expiresAt) return 'no expiry';

  const expires = new Date(expiresAt).getTime();
  if (!Number.isFinite(expires)) return 'unknown';

  const diff = expires - now.getTime();
  if (diff <= 0) return 'expired';

  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return '<1 min left';
  if (minutes < 60) return `${minutes} min left`;

  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  if (hours < 24) {
    return remainingMinutes > 0 ? `${hours}h ${remainingMinutes}m left` : `${hours}h left`;
  }

  const days = Math.floor(hours / 24);
  const remainingHours = hours % 24;
  return remainingHours > 0 ? `${days}d ${remainingHours}h left` : `${days}d left`;
}
