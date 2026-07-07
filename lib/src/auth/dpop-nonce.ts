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
 * A `DPoP-Nonce` header source: a raw `Response`'s headers or a Connect error's
 * metadata (both are `Headers`, whose `get` is case-insensitive).
 */
type NonceHeaders = Headers | undefined;

/**
 * Given a response's headers, return a *fresh* challenge nonce that differs from
 * the one we just sent (`sentNonce`), recording it in `cache`. Returns
 * `undefined` when there is no nonce or it matches what we already used — i.e.
 * when the caller should NOT retry. RFC 9449 §9.
 */
export function adoptChallengeNonce(
  cache: DPoPNonceCache,
  origin: string,
  headers: NonceHeaders,
  sentNonce: string | undefined
): string | undefined {
  const challenge = DPoPNonceCache.extractNonce(headers);
  if (challenge && challenge !== sentNonce) {
    cache.set(origin, challenge);
    return challenge;
  }
  return undefined;
}

/**
 * Connect-error variant of {@link adoptChallengeNonce}. The transport `fetch`
 * wrapper usually records the nonce off the raw 401, but Connect errors don't
 * reliably surface response headers, so we also consult the cache and the error
 * metadata. Returns a fresh nonce to retry with, or `undefined`.
 */
export function adoptChallengeNonceFromConnectError(
  cache: DPoPNonceCache,
  origin: string,
  metadata: NonceHeaders,
  sentNonce: string | undefined
): string | undefined {
  const serverNonce = cache.get(origin) ?? DPoPNonceCache.extractNonce(metadata);
  if (serverNonce && serverNonce !== sentNonce) {
    cache.set(origin, serverNonce);
    return serverNonce;
  }
  return undefined;
}

/**
 * Warm the cache from a response's `DPoP-Nonce` header (RFC 9449 §8). No-op when
 * the response carries no nonce.
 */
export function warmNonceFromResponse(
  cache: DPoPNonceCache,
  origin: string,
  headers: NonceHeaders
): void {
  const nonce = DPoPNonceCache.extractNonce(headers);
  if (nonce) {
    cache.set(origin, nonce);
  }
}

/**
 * Fallback nonce cache used when a caller (e.g. a custom/legacy `AuthProvider`,
 * or the interceptor-only wiring) does not supply its own. SDK-built providers
 * each own a per-client {@link DPoPNonceCache} instead, so nonces don't leak
 * across clients; this shared instance only backs the paths that opt out of that.
 */
export const defaultNonceCache = new DPoPNonceCache();

/**
 * @deprecated Prefer a per-client {@link DPoPNonceCache} (SDK providers expose
 * one via `nonceCache`). Retained as an alias of {@link defaultNonceCache} for
 * backwards compatibility — it is the *same object*, not a second cache.
 */
export const globalNonceCache = defaultNonceCache;

/**
 * Record a `DPoP-Nonce` response header into `cache`, keyed by the request's origin.
 *
 * This works directly off the raw `Response`, so it captures the nonce even when
 * a transport (e.g. Connect-RPC) does not surface response headers on its error
 * type. Some resource servers (KAS) reject a proof minted without a nonce with a
 * raw HTTP 401 carrying `DPoP-Nonce` + `WWW-Authenticate: DPoP error="use_dpop_nonce"`
 * (RFC 9449 §9); capturing here lets the auth layer mint a nonce-bearing proof on
 * retry.
 */
export function captureNonce(cache: DPoPNonceCache, requestUrl: string, headers?: Headers): void {
  const nonce = DPoPNonceCache.extractNonce(headers);
  if (!nonce) {
    return;
  }
  try {
    cache.set(new URL(requestUrl).origin, nonce);
  } catch {
    // Non-absolute URL: the nonce cache is origin-keyed, so nothing to store.
  }
}
