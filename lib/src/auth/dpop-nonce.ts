/**
 * DPoP-Nonce cache manager per RFC 9449 §8.
 * Caches server-issued nonces by origin for use in subsequent DPoP proofs.
 */

import { Code, ConnectError } from '@connectrpc/connect';

export class DPoPNonceCache {
  private readonly cache = new Map<string, string>();

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
  const metadataNonce = DPoPNonceCache.extractNonce(metadata);
  const cachedNonce = cache.get(origin);
  // Prefer metadata when it carries a nonce different from the one sent. The
  // cache can still contain that stale sent nonce when a custom Connect
  // transport exposes response metadata but does not capture raw headers.
  const challenge = metadataNonce && metadataNonce !== sentNonce ? metadataNonce : cachedNonce;
  return adoptIfFresh(cache, origin, challenge, sentNonce);
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

/** Why no fresh nonce could be adopted from a genuine DPoP-Nonce challenge. */
function nonceRetryGiveUpReason(
  challenge: string | undefined,
  sentNonce: string | undefined
): string {
  if (!challenge) {
    return 'server omitted the DPoP-Nonce';
  }
  if (challenge === sentNonce) {
    return 'server repeated the already-used DPoP-Nonce';
  }
  return 'DPoP-Nonce could not be adopted';
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
  const reason = nonceRetryGiveUpReason(challenge, sentNonce);
  console.warn(`DPoP nonce retry skipped (${context}, ${origin}): ${reason}`);
}

/**
 * Run `send`, and on a DPoP-Nonce challenge run it once more with the nonce the
 * server handed back (RFC 9449 §8/§9). The cached nonce for `origin` is passed
 * to `send` so it can mint a proof carrying it — callers that re-sign through an
 * `AuthProvider` (which reads the cache itself) may ignore the argument, since
 * the fresh nonce is written to `cache` before the retry.
 *
 * Whichever response we end on warms the cache. Non-DPoP servers never emit a
 * `DPoP-Nonce`, so they take the single-request path unchanged.
 *
 * @param context short label naming the call site, used in the give-up warning
 */
export async function sendWithNonceRetry(
  cache: DPoPNonceCache,
  origin: string,
  context: string,
  send: (nonce: string | undefined) => Promise<Response>
): Promise<Response> {
  const sentNonce = cache.get(origin);
  let response = await send(sentNonce);

  if (!response.ok) {
    const challenge = DPoPNonceCache.extractNonce(response.headers);
    const freshNonce = adoptChallengeNonce(cache, origin, response.headers, sentNonce);
    if (freshNonce) {
      response = await send(freshNonce);
    } else if (challenge) {
      // A DPoP-Nonce was offered but is stale/unusable, so the retry is skipped;
      // note it (only when a nonce was actually present — never on a plain 401).
      warnNonceRetryGiveUp(context, origin, challenge, sentNonce);
    }
  }

  warmNonceFromResponse(cache, origin, response.headers);
  return response;
}

/** The part of a Connect response this module needs: its response headers. */
type HeaderBearing = { header: Headers };

/**
 * Connect-RPC counterpart of {@link sendWithNonceRetry}. A DPoP resource server
 * rejects a proof minted without (or with a stale) nonce by returning
 * `Unauthenticated` with a fresh `DPoP-Nonce`; re-run `call` once with that nonce
 * (RFC 9449 §9). Any other error propagates untouched.
 *
 * Connect errors don't reliably surface response headers, so the nonce is read
 * from the cache — the transport's fetch wrapper records it off the raw 401 (see
 * {@link captureNonce}) — with the error metadata as a fallback.
 *
 * @param context short label naming the call site, used in the give-up warning
 */
export async function callWithNonceRetry<T extends HeaderBearing>(
  cache: DPoPNonceCache,
  origin: string,
  context: string,
  call: (nonce: string | undefined) => Promise<T>
): Promise<T> {
  const sentNonce = cache.get(origin);
  try {
    const response = await call(sentNonce);
    warmNonceFromResponse(cache, origin, response.header);
    return response;
  } catch (err) {
    if (err instanceof ConnectError && err.code === Code.Unauthenticated) {
      const serverNonce = adoptChallengeNonceFromConnectError(
        cache,
        origin,
        err.metadata,
        sentNonce
      );
      if (serverNonce) {
        const retryResponse = await call(serverNonce);
        warmNonceFromResponse(cache, origin, retryResponse.header);
        return retryResponse;
      }
      // A nonce challenge we can't act on (server omitted/repeated the nonce):
      // surface why the retry was skipped before the original error propagates.
      warnNonceRetryGiveUp(
        context,
        origin,
        cache.get(origin) ?? DPoPNonceCache.extractNonce(err.metadata),
        sentNonce
      );
    }
    throw err;
  }
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
