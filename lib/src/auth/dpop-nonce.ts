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
   * Clear all cached nonces. Useful for test teardown.
   */
  clearAll(): void {
    this.cache.clear();
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

/**
 * Record a `DPoP-Nonce` response header into {@link globalNonceCache}, keyed by
 * the request's origin.
 *
 * This works directly off the raw `Response`, so it captures the nonce even when
 * a transport (e.g. Connect-RPC) does not surface response headers on its error
 * type. Some resource servers (KAS) reject a proof minted without a nonce with a
 * raw HTTP 401 carrying `DPoP-Nonce` + `WWW-Authenticate: DPoP error="use_dpop_nonce"`
 * (RFC 9449 §9); capturing here lets the auth layer mint a nonce-bearing proof on
 * retry.
 */
export function captureNonce(requestUrl: string, headers?: Headers): void {
  const nonce = DPoPNonceCache.extractNonce(headers);
  if (!nonce) {
    return;
  }
  try {
    globalNonceCache.set(new URL(requestUrl).origin, nonce);
  } catch {
    // Non-absolute URL: the nonce cache is origin-keyed, so nothing to store.
  }
}
