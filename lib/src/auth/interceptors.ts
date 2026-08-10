import { type Interceptor } from '@connectrpc/connect';
export type { Interceptor } from '@connectrpc/connect';
import { type CryptoService, type KeyPair } from '../../tdf3/src/crypto/declarations.js';
import * as DefaultCryptoService from '../../tdf3/src/crypto/index.js';
import DPoP from './dpop.js';
import { type AuthProvider } from './auth.js';
import { base64 } from '../encodings/index.js';
import { callWithNonceRetry, DPoPNonceCache, defaultNonceCache, toOrigin } from './dpop-nonce.js';

/**
 * A function that returns a valid access token string.
 * Called per-request; implementations should handle caching/refresh internally.
 */
export type TokenProvider = () => Promise<string>;

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
  /**
   * Per-client DPoP-Nonce cache (RFC 9449 §8). Defaults to the shared
   * {@link defaultNonceCache}; pass the same instance to `PlatformClient` for
   * strict per-client isolation on the interceptor-only path.
   */
  nonceCache?: DPoPNonceCache;
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
  return (next) => async (req) => {
    const token = await tokenProvider();
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
  const nonceCache = options.nonceCache ?? defaultNonceCache;
  const dpopKeysPromise: Promise<KeyPair> = options.dpopKeys
    ? Promise.resolve(options.dpopKeys)
    : cryptoService.generateSigningKeyPair();

  const interceptor: Interceptor = (next) => async (req) => {
    const [token, keys] = await Promise.all([options.tokenProvider(), dpopKeysPromise]);

    const url = new URL(req.url);
    const origin = url.origin;
    const httpUri = `${origin}${url.pathname}`;

    // Export public key PEM for X-VirtruPubKey header
    const publicKeyPem = await cryptoService.exportPublicKeyPem(keys.publicKey);

    req.header.set('Authorization', `DPoP ${token}`);
    // TODO: rename to X-OpenTDF-PubKey (coordinate with platform Keycloak mapper; see oidc.ts doPost)
    req.header.set('X-VirtruPubKey', base64.encode(publicKeyPem));

    // Mint the proof around whichever nonce applies — the cached one normally,
    // the server's on a DPoP-Nonce challenge retry.
    return callWithNonceRetry(nonceCache, origin, 'rpc interceptor', async (nonce) => {
      req.header.set('DPoP', await DPoP(keys, cryptoService, httpUri, 'POST', nonce, token));
      return next(req);
    });
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
    // Pass the full request URL to withCreds. DPoP-enabled providers need the
    // absolute URL to compute the proof's `htu` claim and the origin for the
    // nonce cache; `new URL()` on a bare path throws "Invalid URL". Non-DPoP
    // providers ignore the URL (they only add a Bearer header), so this stays
    // backwards-compatible with legacy AuthProviders.

    // Re-sign the request via withCreds and apply the resulting headers. Called
    // once normally, and again on a DPoP-Nonce challenge so the provider mints a
    // fresh proof carrying the server-issued nonce (read from nonceCache).
    const sign = async (): Promise<void> => {
      let token;
      try {
        token = await authProvider.withCreds({
          url: req.url,
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
    };

    // Non-absolute URLs have no origin; nonce caching is origin-keyed, so those pass through.
    const origin = toOrigin(req.url);
    if (!origin) {
      await sign();
      return next(req);
    }

    // Share the provider's per-client cache so the nonce withCreds embeds and the
    // one we read back on a 401 are the same instance (falls back to the shared
    // default for custom providers that don't expose one). `sign` re-reads the
    // nonce from that cache itself, so the nonce argument is unused here.
    const nonceCache = authProvider.nonceCache ?? defaultNonceCache;
    return callWithNonceRetry(nonceCache, origin, 'auth interceptor', async () => {
      await sign();
      return next(req);
    });
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
