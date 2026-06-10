/**
 * DPoP-Nonce cache manager per RFC 9449 §8.
 * Caches server-issued nonces by origin for use in subsequent DPoP proofs.
 */

export class DPoPNonceCache {
  private cache = new Map<string, string>();

  /**
   * Get cached nonce for an origin.
   */
  get(origin: string): string | undefined {
    return this.cache.get(origin);
  }

  /**
   * Store a nonce for an origin.
   * Overwrites any existing nonce for that origin.
   */
  set(origin: string, nonce: string): void {
    this.cache.set(origin, nonce);
  }

  /**
   * Clear nonce for an origin (e.g., when it's rejected by the server).
   */
  clear(origin: string): void {
    this.cache.delete(origin);
  }

  /**
   * Extract DPoP-Nonce from response headers (case-insensitive).
   */
  static extractNonce(headers?: Headers): string | undefined {
    return typeof headers?.get === 'function' ? headers.get('dpop-nonce') || undefined : undefined;
  }
}

/**
 * Global nonce cache singleton.
 * Shared across all instances to maintain nonce state per-origin.
 */
export const globalNonceCache = new DPoPNonceCache();
