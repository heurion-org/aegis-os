import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { randomBytes } from 'crypto';
import { join } from 'path';
import { ADMIN_TOKEN_FILE_NAME } from '@uomp/core';

/**
 * Load the local admin token used to authenticate session create/grant/revoke,
 * generating one on first use. The file is kept private to the current user.
 */
export function loadOrCreateAdminToken(secretsDir: string): string {
  const tokenPath = join(secretsDir, ADMIN_TOKEN_FILE_NAME);
  mkdirSync(secretsDir, { recursive: true });

  const token = randomBytes(32).toString('hex');
  try {
    writeFileSync(tokenPath, token, { mode: 0o600, flag: 'wx' });
    return token;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') {
      throw err;
    }
  }

  // Another process won the race: reuse its token instead of rotating it.
  chmodSync(tokenPath, 0o600);
  const existing = readFileSync(tokenPath, 'utf-8').trim();
  if (!existing) {
    throw new Error(`Admin token file is empty: ${tokenPath}`);
  }
  return existing;
}
