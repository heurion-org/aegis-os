import { AuthService } from '@uomp/auth';
import { JWTTokenIssuer } from '@uomp/token';
import type { UompConfig } from '../config.js';

export async function openAuthService(config: UompConfig): Promise<AuthService> {
  const issuer = new JWTTokenIssuer();
  await issuer.loadOrGenerateKey(config.secretsDir);

  return new AuthService({
    dbPath: config.authDbPath,
    issuer,
    adminToken: config.adminToken,
  });
}
