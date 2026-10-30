import { Resolver } from 'did-resolver';
import { getResolver as ethrDidResolver } from 'ethr-did-resolver';
import { getResolver as webDidResolver } from 'web-did-resolver';
import * as openpgp from 'openpgp';
import type { AgentManifest } from '@uomp/core';

export interface VerificationResult {
  valid: boolean;
  method: string;
  error?: string;
}

export class IdentityVerifier {
  private didResolver: Resolver | undefined;

  constructor() {
    try {
      // MVP: configure ethr-did-resolver with a placeholder network.
      // In production, use a real RPC endpoint or web-did-resolver for did:web.
      this.didResolver = new Resolver({
        ...(ethrDidResolver({
          networks: [
            { name: 'mainnet', rpcUrl: 'https://ethereum.publicnode.com' },
          ],
        } as any) as any),
        ...(webDidResolver() as any),
      });
    } catch {
      // If DID resolver initialization fails, continue without DID verification.
      this.didResolver = undefined;
    }
  }

  async verifyManifest(manifest: AgentManifest): Promise<VerificationResult> {
    if (!manifest.identity) {
      return { valid: false, method: 'none', error: 'No identity information in manifest' };
    }

    const methods = manifest.identity.verificationMethods ?? [];

    for (const method of methods) {
      if (method === 'did' && manifest.identity.did) {
        return this.verifyDid(manifest.identity.did);
      }

      if (method === 'gpg') {
        return this.verifyGpg(manifest);
      }
    }

    return { valid: false, method: 'none', error: 'No supported verification method found' };
  }

  async verifyDid(did: string): Promise<VerificationResult> {
    if (!this.didResolver) {
      return { valid: false, method: 'did', error: 'DID resolver not initialized' };
    }

    try {
      const doc = await this.didResolver.resolve(did);
      if (doc.didDocument) {
        return { valid: true, method: 'did' };
      }
      return { valid: false, method: 'did', error: 'DID document not found' };
    } catch (err) {
      return { valid: false, method: 'did', error: `DID resolution failed: ${(err as Error).message}` };
    }
  }

  async verifyGpg(manifest: AgentManifest): Promise<VerificationResult> {
    // MVP: GPG verification is a placeholder.
    // Real implementation would sign uom.json with a GPG key and verify the signature here.
    if (!manifest.identity?.proof?.proofValue) {
      return { valid: false, method: 'gpg', error: 'No GPG proof found' };
    }

    try {
      // TODO: implement actual GPG signature verification
      return { valid: true, method: 'gpg' };
    } catch (err) {
      return { valid: false, method: 'gpg', error: (err as Error).message };
    }
  }
}

export async function importGpgKey(armoredKey: string): Promise<openpgp.Key> {
  return await openpgp.readKey({ armoredKey });
}

export async function verifyGpgSignature(
  message: string,
  signatureArmored: string,
  publicKeyArmored: string
): Promise<boolean> {
  const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const signature = await openpgp.readSignature({ armoredSignature: signatureArmored });

  const verificationResult = await openpgp.verify({
    message: await openpgp.createMessage({ text: message }),
    signature,
    verificationKeys: publicKey,
  });

  const { verified } = verificationResult.signatures[0];
  return await verified;
}

export { deriveMasterKey, createUserId, starknetSignMessage, ETHEREUM_SIGN_MESSAGE, verifySignature } from './wallet.js';
export type { WalletIdentity } from './wallet.js';

export { loadUser, saveUser, createUser, updateUser, defaultUserPath } from './user.js';
export type { UserProfile } from './user.js';
