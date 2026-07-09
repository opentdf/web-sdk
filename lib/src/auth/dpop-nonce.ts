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

/** The origin of an absolute URL, or `undefined` when it is relative/unparseable. */
export function toOrigin(url: string): string | undefined {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

/**
 * Adopt `challenge` as this origin's nonce when it is present and differs from
 * the one we just sent (`sentNonce`), recording it in `cache`. Returns the fresh
 * nonce, or `undefined` when the caller should NOT retry (no nonce, or it matches
 * what we already used). RFC 9449 §9.
 */
function adoptIfFresh(
  cache: DPoPNonceCache,
  origin: string,
  challenge: string | undefined,
  sentNonce: string | undefined
): string | undefined {
  if (challenge && challenge !== sentNonce) {
    cache.set(origin, challenge);
    return challenge;
  }
  return undefined;
}

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
  return adoptIfFresh(cache, origin, DPoPNonceCache.extractNonce(headers), sentNonce);
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
  return adoptIfFresh(
    cache,
    origin,
    cache.get(origin) ?? DPoPNonceCache.extractNonce(metadata),
    sentNonce
  );
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
  adoptIfFresh(cache, origin, DPoPNonceCache.extractNonce(headers), undefined);
}

/**
 * Emit ONE concise warning when a genuine DPoP-Nonce challenge was detected but
 * no fresh nonce could be adopted (the server omitted it, or repeated the one we
 * already sent), so the retry is skipped and the original error propagates. Call
 * only after confirming a challenge was present — otherwise an ordinary 401 would
 * spam a misleading warning. RFC 9449 §9.
 */
export function warnNonceRetryGiveUp(
  context: string,
  origin: string,
  challenge: string | undefined,
  sentNonce: string | undefined
): void {
  const reason = !challenge
    ? 'server omitted the DPoP-Nonce'
    : challenge === sentNonce
      ? 'server repeated the already-used DPoP-Nonce'
      : 'DPoP-Nonce could not be adopted';
  console.warn(`DPoP nonce retry skipped (${context}, ${origin}): ${reason}`);
}

/**
 * Shared, process-wide nonce cache — the default for every DPoP path (the
 * `AccessToken` cache, the auth interceptor, the Connect transport, and the
 * legacy fetch retry) unless a dedicated cache is injected. Keeping one default
 * instance means those layers stay consistent even when a provider is wrapped by
 * a decorator that doesn't forward `nonceCache`. For per-client isolation, pass a
 * dedicated {@link DPoPNonceCache} to the `AccessToken` constructor,
 * `PlatformClientOptions.nonceCache`, or `DPoPInterceptorOptions.nonceCache`.
 */
export const defaultNonceCache = new DPoPNonceCache();

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
  const origin = toOrigin(requestUrl);
  if (origin) {
    cache.set(origin, nonce);
  } else {
    // The cache is origin-keyed, so a relative request URL can't be stored — and
    // since this is the only place a Connect-RPC nonce challenge is captured, that
    // silently disables the retry. Surface it rather than dropping it quietly.
    console.warn(
      `DPoP-Nonce present but request URL is not absolute (${requestUrl}); cannot cache nonce, retry disabled.`
    );
  }
}
