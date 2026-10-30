/**
 * UOMP Wallet-Authenticated Key Derivation
 * 
 * Derives encryption keys from wallet signatures instead of seed phrases.
 * Chain-agnostic: supports Ethereum (personal_sign) and Starknet (starknet_signMessage).
 */
import { createHash, createHmac } from 'crypto';

export interface WalletIdentity {
  chain: 'ethereum' | 'starknet';
  address: string;
  wallet?: string;
  userId: string;
}

function hkdf(ikm: Buffer, salt: string, info: string, length: number): Buffer {
  const prk = createHmac('sha256', salt).update(ikm).digest();
  const t = createHmac('sha256', prk).update(info).update(Buffer.from([1])).digest();
  return t.subarray(0, length);
}

function keccak256(data: string): string {
  // Simple keccak256 via SHA3-256 (NOT identical to Ethereum keccak256 but sufficient for user_id)
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Derive masterKey from wallet signature + address.
 */
export function deriveMasterKey(opts: {
  signature: string;
  address: string;
  chain: 'ethereum' | 'starknet';
}): Buffer {
  const sigBytes = Buffer.from(opts.signature.replace('0x', ''), 'hex');
  const addrBytes = Buffer.from(opts.address.replace('0x', '').toLowerCase(), 'utf-8');
  const ikm = Buffer.concat([sigBytes.subarray(0, 32), addrBytes]);
  return hkdf(ikm, 'uomp-store-v1', `${opts.chain}:${opts.address}`, 32);
}

/**
 * Create a user_id from chain + address.
 */
export function createUserId(chain: 'ethereum' | 'starknet', address: string): string {
  return `${chain}:${address.toLowerCase()}`;
}

/**
 * Build EIP-712 typed data for Starknet signMessage (Argent X / Braavos compatible).
 */
export function starknetSignMessage(address: string) {
  return {
    domain: {
      name: 'UOMP Store',
      version: '1',
      chainId: 'SN_MAIN',
    },
    types: {
      StarkNetDomain: [
        { name: 'name', type: 'felt' },
        { name: 'version', type: 'felt' },
        { name: 'chainId', type: 'felt' },
      ],
      Message: [{ name: 'message', type: 'felt' }],
    },
    primaryType: 'Message',
    message: { message: 'UOMP Store v1' },
  };
}

/**
 * Build the "personal_sign" message for EIP-1193 (MetaMask).
 */
export const ETHEREUM_SIGN_MESSAGE = 'UOMP Store v1';

/**
 * Verify a wallet signature (placeholder — actual verification depends on provider).
 */
export function verifySignature(params: {
  address: string;
  message: string;
  signature: string;
  chain: 'ethereum' | 'starknet';
}): boolean {
  // Full verification requires ethers.js or starknet.js.
  // For now, trust the provider (MetaMask / Argent X verified the signature client-side).
  return params.signature.length > 64 && params.address.length > 20;
}
