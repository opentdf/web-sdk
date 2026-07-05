import { type Interceptor } from '@connectrpc/connect';
export type { Interceptor } from '@connectrpc/connect';
import { type CryptoService, type KeyPair } from '../../tdf3/src/crypto/declarations.js';
import * as DefaultCryptoService from '../../tdf3/src/crypto/index.js';
import DPoP from './dpop.js';
import { type AuthProvider } from './auth.js';
import { base64 } from '../encodings/index.js';

/**
 * A function that returns a valid access token string.
 * Called per-request; implementations should handle caching/refresh internally.
 */
export type TokenProvider = () => Promise<string>;

/**
 * Read a JWT's `exp` claim as epoch-milliseconds, WITHOUT verifying the signature.
 * Returns undefined for opaque (non-JWT) tokens or an unreadable payload — so the
 * expiry footgun check below is skipped rather than firing a false positive.
 */
function readJwtExpMs(token: string): number | undefined {
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  try {
    let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    const { exp } = JSON.parse(atob(b64)) as { exp?: number };
    return typeof exp === 'number' ? exp * 1000 : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A common footgun: passing a *static* token getter (e.g. `() => myToken`) to an interceptor.
 * The interceptor faithfully stamps that token on every request, but a static getter never
 * refreshes — so once the (typically short-lived) access token expires, every request goes out
 * with a dead Bearer and the platform answers HTTP 401. Callers routinely mis-diagnose that 401
 * as an authorization / "access denied" failure and lose hours to it.
 *
 * A correctly-refreshing provider NEVER returns an already-expired token, so an expired token is
 * an unambiguous, zero-false-positive signal of the footgun. This factory returns a guard that
 * emits ONE actionable `console.warn` the first time it sees an expired JWT and then stays quiet
 * (no log spam). It never throws and silently ignores opaque tokens whose expiry can't be read.
 */
function makeExpiredTokenWarner(interceptorName: string): (token: string) => void {
  let warned = false;
  return (token: string) => {
    if (warned) return;
    const expMs = readJwtExpMs(token);
    if (expMs !== undefined && expMs <= Date.now()) {
      warned = true;
      // eslint-disable-next-line no-console
      console.warn(
        `[OpenTDF] ${interceptorName} received an already-EXPIRED access token. Your ` +
          '`tokenProvider` is returning a token it never refreshes, so platform requests will ' +
          'fail with HTTP 401 — frequently mis-diagnosed as an authorization / "access denied" ' +
          'error. Fix: wrap a refreshing provider — refreshTokenProvider(), ' +
          'clientCredentialsTokenProvider(), or externalJwtTokenProvider() — or refresh inside ' +
          'your own tokenProvider so it never returns an expired token. ' +
          'Docs: https://github.com/opentdf/web-sdk#authentication'
      );
    }
  };
}

/**
 * Options for creating a DPoP-aware auth interceptor.
 */
export type DPoPInterceptorOptions = {
  /** Function that returns a valid access token (may cache/refresh internally). */
  tokenProvider: TokenProvider;
  /** DPoP signing key pair. If omitted, one is generated automatically. */
  dpopKeys?: KeyPair | Promise<KeyPair>;
  /** CryptoService for signing. Defaults to DefaultCryptoService. */
  cryptoService?: CryptoService;
};

/**
 * A DPoP interceptor that also exposes the resolved signing key pair.
 * TDF encrypt/decrypt needs these keys for request body signing (reqSignature).
 */
export type DPoPInterceptor = Interceptor & {
  /** The resolved DPoP key pair, for use in TDF request token signing. */
  readonly dpopKeys: Promise<KeyPair>;
};

/**
 * Creates a simple bearer-token interceptor.
 * Calls `tokenProvider()` per-request and sets the `Authorization` header.
 *
 * @param tokenProvider Function returning a valid access token.
 * @returns A Connect RPC Interceptor.
 *
 * @example
 * ```ts
 * const opentdf = new OpenTDF({
 *   interceptors: [authTokenInterceptor(() => myAuth.getAccessToken())],
 *   platformUrl: '/api',
 * });
 * ```
 */
export function authTokenInterceptor(tokenProvider: TokenProvider): Interceptor {
  const warnIfExpired = makeExpiredTokenWarner('authTokenInterceptor');
  return (next) => async (req) => {
    const token = await tokenProvider();
    warnIfExpired(token);
    req.header.set('Authorization', `Bearer ${token}`);
    return next(req);
  };
}

/**
 * Creates a DPoP-aware auth interceptor.
 * Per-request: gets token, generates DPoP proof JWT, sets Authorization + DPoP + X-VirtruPubKey headers.
 * Exposes `dpopKeys` for TDF request body signing.
 *
 * @param options DPoP interceptor configuration.
 * @returns A DPoP interceptor with an exposed `dpopKeys` promise.
 *
 * @example
 * ```ts
 * const dpopInterceptor = authTokenDPoPInterceptor({
 *   tokenProvider: () => myAuth.getAccessToken(),
 * });
 * const opentdf = new OpenTDF({
 *   interceptors: [dpopInterceptor],
 *   dpopKeys: dpopInterceptor.dpopKeys,
 *   platformUrl: '/api',
 * });
 * ```
 */
export function authTokenDPoPInterceptor(options: DPoPInterceptorOptions): DPoPInterceptor {
  const cryptoService = options.cryptoService ?? DefaultCryptoService;
  const dpopKeysPromise: Promise<KeyPair> = options.dpopKeys
    ? Promise.resolve(options.dpopKeys)
    : cryptoService.generateSigningKeyPair();
  const warnIfExpired = makeExpiredTokenWarner('authTokenDPoPInterceptor');

  const interceptor: Interceptor = (next) => async (req) => {
    const [token, keys] = await Promise.all([options.tokenProvider(), dpopKeysPromise]);
    warnIfExpired(token);

    const url = new URL(req.url);
    const httpUri = `${url.origin}${url.pathname}`;

    // Generate DPoP proof JWT for this request
    const dpopProof = await DPoP(keys, cryptoService, httpUri, 'POST');

    // Export public key PEM for X-VirtruPubKey header
    const publicKeyPem = await cryptoService.exportPublicKeyPem(keys.publicKey);

    req.header.set('Authorization', `Bearer ${token}`);
    req.header.set('DPoP', dpopProof);
    req.header.set('X-VirtruPubKey', base64.encode(publicKeyPem));

    return next(req);
  };

  // Attach dpopKeys to the interceptor function
  const dpopInterceptor = interceptor as DPoPInterceptor;
  Object.defineProperty(dpopInterceptor, 'dpopKeys', {
    value: dpopKeysPromise,
    writable: false,
    enumerable: true,
  });

  return dpopInterceptor;
}

/**
 * Creates an interceptor that bridges an existing AuthProvider to the Interceptor pattern.
 * Use this for backwards compatibility when migrating from AuthProvider to interceptors.
 *
 * @param authProvider The legacy AuthProvider to bridge.
 * @returns A Connect RPC Interceptor.
 */
export function authProviderInterceptor(authProvider: AuthProvider): Interceptor {
  return (next) => async (req) => {
    const url = new URL(req.url);
    const pathOnly = url.pathname;
    // Signs only the path of the url in the request
    let token;
    try {
      token = await authProvider.withCreds({
        url: pathOnly,
        method: 'POST',
        // Start with any headers Connect already has
        headers: {
          ...Object.fromEntries(req.header.entries()),
          'Content-Type': 'application/json',
        },
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('public key') || msg.includes('updateClientPublicKey')) {
        throw new Error(
          'PlatformClient: DPoP key binding is not complete. ' +
            'If you are using OpenTDF with PlatformClient, create OpenTDF first and ' +
            '`await client.ready` before constructing PlatformClient. ' +
            `Original error: ${msg}`
        );
      }
      throw err;
    }

    Object.entries(token.headers).forEach(([key, value]) => {
      req.header.set(key, value);
    });

    return await next(req);
  };
}

/**
 * Auth configuration: either a legacy AuthProvider or an object with interceptors.
 */
export type AuthConfig = AuthProvider | { interceptors: Interceptor[] };

/**
 * Type guard for AuthConfig with interceptors.
 */
export function isInterceptorConfig(auth: AuthConfig): auth is { interceptors: Interceptor[] } {
  return 'interceptors' in auth && Array.isArray((auth as { interceptors: unknown }).interceptors);
}

/**
 * Resolves an AuthConfig into interceptors for use with PlatformClient.
 * If the config is an AuthProvider, it is bridged via authProviderInterceptor.
 */
export function resolveInterceptors(auth: AuthConfig): Interceptor[] {
  if (isInterceptorConfig(auth)) {
    return auth.interceptors;
  }
  return [authProviderInterceptor(auth)];
}

/**
 * Resolves an AuthConfig into both interceptors and an optional AuthProvider.
 * The AuthProvider is available for legacy code paths that need withCreds().
 */
export function resolveAuthConfig(auth: AuthConfig): {
  interceptors: Interceptor[];
  authProvider?: AuthProvider;
} {
  if (isInterceptorConfig(auth)) {
    return { interceptors: auth.interceptors };
  }
  return {
    interceptors: [authProviderInterceptor(auth)],
    authProvider: auth,
  };
}
