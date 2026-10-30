/// <reference lib="dom" />

export { UompClient } from './client.js';
export { UompError, UompErrorCode } from './errors.js';
export { StoreRouter } from './store-router.js';
export * from './types.js';
export { MemoryClient } from './memory.js';
export { AggregateClient } from './aggregate.js';
export { PayloadClient } from './payload.js';
export { SessionClient } from './session.js';
export { AuthClient } from './auth.js';
export { AuditClient } from './audit.js';

const TOKEN_KEY = 'uomp_token';
const GATEWAY_KEY = 'uomp_gateway';

export const BrowserSDK = {
  saveToken(token: string) {
    if (typeof sessionStorage !== 'undefined') sessionStorage.setItem(TOKEN_KEY, token);
  },
  loadToken(): string {
    if (typeof sessionStorage !== 'undefined') return sessionStorage.getItem(TOKEN_KEY) || '';
    return '';
  },
  saveGatewayUrl(url: string) {
    if (typeof sessionStorage !== 'undefined') sessionStorage.setItem(GATEWAY_KEY, url);
  },
  loadGatewayUrl(): string {
    if (typeof sessionStorage !== 'undefined') return sessionStorage.getItem(GATEWAY_KEY) || '';
    return '';
  },
  fromUrlHash(): { token: string; gateway: string } {
    if (typeof window === 'undefined') return { token: '', gateway: '' };
    const params = new URLSearchParams(window.location.hash.slice(1));
    const token = params.get('token') || '';
    const gateway = params.get('gateway') || '';
    if (token) this.saveToken(token);
    if (gateway) this.saveGatewayUrl(gateway);
    return { token, gateway };
  },
  createFromStorage(): import('./client.js').UompClient {
    return new (require('./client.js').UompClient)({
      token: this.loadToken(),
      baseUrl: this.loadGatewayUrl() || 'http://127.0.0.1:9374',
    });
  },

  /** Connect via wallet signature (MetaMask / Argent X) */
  async fromWallet(chain: 'ethereum' | 'starknet' = 'ethereum'): Promise<{ key: CryptoKey; userId: string; chain: string; address: string }> {
    let address: string, signature: string;
    const message = 'Authorize UOMP to access your encrypted portfolio data.\n\nThis signature does not send a transaction. It only derives your encryption key.';

    if (chain === 'ethereum') {
      if (!(window as any).ethereum) throw new Error('MetaMask not detected. Install MetaMask extension.');
      const accounts = await (window as any).ethereum.request({ method: 'eth_requestAccounts' });
      address = accounts[0];
      signature = await (window as any).ethereum.request({ method: 'personal_sign', params: [message, address] });
    } else {
      if (!(window as any).starknet) throw new Error('Argent X not detected. Install Argent X extension.');
      await (window as any).starknet.enable();
      address = (window as any).starknet.selectedAddress;
      if (!address) throw new Error('No Starknet account selected');
      const typedData = {
        domain: { name: 'UOMP Store', version: '1', chainId: 'SN_MAIN' },
        types: { StarkNetDomain: [{ name: 'name', type: 'felt' }, { name: 'version', type: 'felt' }, { name: 'chainId', type: 'felt' }], Message: [{ name: 'message', type: 'felt' }] },
        primaryType: 'Message', message: { message: 'UOMP Store v1' },
      };
      const result = await (window as any).starknet.account.signMessage(typedData);
      signature = Array.isArray(result) ? result.join(',') : String(result);
    }

    const input = signature + '\n' + address.toLowerCase() + '\n' + chain + '\nuomp-store-v1';
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(input), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: new TextEncoder().encode('uomp-salt'), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );

    return { key, userId: `${chain}:${address.toLowerCase()}`, chain, address };
  },

  /** Recover from seed phrase */
  async fromSeedPhrase(phrase: string): Promise<{ key: CryptoKey; userId: string }> {
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(phrase), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: new TextEncoder().encode('uomp-seed-salt'), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(phrase));
    const userId = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
    return { key, userId };
  },

  // Encrypted storage helpers
  async saveEncrypted(key: CryptoKey, userId: string, data: unknown): Promise<void> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(data)));
    const enc = { iv: Array.from(iv), d: Array.from(new Uint8Array(ct)) };
    localStorage.setItem('uomp_enc_' + userId, JSON.stringify(enc));
  },

  async loadEncrypted(key: CryptoKey, userId: string): Promise<unknown | null> {
    const raw = localStorage.getItem('uomp_enc_' + userId);
    if (!raw) return null;
    try {
      const enc = JSON.parse(raw);
      const iv = new Uint8Array(enc.iv), data = new Uint8Array(enc.d);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
      return JSON.parse(new TextDecoder().decode(pt));
    } catch {
      localStorage.removeItem('uomp_enc_' + userId);
      return null;
    }
  },
};
