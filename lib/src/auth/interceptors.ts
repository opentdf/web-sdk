import { type Interceptor } from '@connectrpc/connect';
export type { Interceptor } from '@connectrpc/connect';
import { type CryptoService, type KeyPair } from '../../tdf3/src/crypto/declarations.js';
import * as DefaultCryptoService from '../../tdf3/src/crypto/index.js';
import DPoP from './dpop.js';
import { type AuthProvider } from './auth.js';
import { base64 } from '../encodings/index.js';
import { DPoPModeResolver, type DPoPMode } from './dpop-mode.js';

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
   * Resource proof `htu` style. Defaults to `auto`: per-origin discovery, using the
   * legacy procedure path unless the server advertises RFC 9449 (including when
   * discovery fails). Pass `rfc9449` to always sign the full URL, which was this
   * interceptor's behavior before `dpopMode` existed.
   */
  dpopMode?: DPoPMode;
  /** Share a resolver/cache with other auth paths. Takes precedence over `dpopMode`. */
  dpopModeResolver?: DPoPModeResolver;
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
 * The proof `htu` follows `options.dpopMode`; see {@link DPoPInterceptorOptions.dpopMode}.
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
  const modeResolver = options.dpopModeResolver ?? new DPoPModeResolver({ mode: options.dpopMode });
  const dpopKeysPromise: Promise<KeyPair> = options.dpopKeys
    ? Promise.resolve(options.dpopKeys)
    : cryptoService.generateSigningKeyPair();

  const interceptor: Interceptor = (next) => async (req) => {
    const [token, keys] = await Promise.all([options.tokenProvider(), dpopKeysPromise]);

    const httpUri = await modeResolver.htuForRpc(req.url, req.signal);

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
    const modeResolver = authProvider.dpopModeResolver;
    // Custom providers without a resolver retain the previous path-only input.
    // Providers with a resolver get the absolute URL, plus the negotiated proof
    // htu in dpopHtu.
    const dpopHtu = modeResolver ? await modeResolver.htuForRpc(req.url, req.signal) : undefined;
    let token;
    try {
      token = await authProvider.withCreds({
        url: modeResolver ? req.url : pathOnly,
        dpopHtu,
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
            `Original error: ${msg}`,
          { cause: err }
        );
      }
      throw err;
    }

    Object.entries(token.headers).forEach(([key, value]) => {
      req.header.set(key, String(value));
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
