import { type TokenProvider } from './interceptors.js';
import { ConfigurationError, TdfError } from '../errors.js';
import { rstrip } from '../utils.js';

/**
 * Options for client credentials token provider.
 */
export type ClientCredentialsTokenProviderOptions = {
  /** OIDC client ID. */
  clientId: string;
  /** OIDC client secret. */
  clientSecret: string;
  /** OIDC IdP origin, e.g. 'http://localhost:8080/auth/realms/opentdf'. */
  oidcOrigin: string;
  /** Override the token endpoint (defaults to `${oidcOrigin}/protocol/openid-connect/token`). */
  oidcTokenEndpoint?: string;
};

/**
 * Options for refresh token provider.
 */
export type RefreshTokenProviderOptions = {
  /** OIDC client ID. */
  clientId: string;
  /** Refresh token obtained from a prior login flow. */
  refreshToken: string;
  /** OIDC IdP origin, e.g. 'http://localhost:8080/auth/realms/opentdf'. */
  oidcOrigin: string;
  /** Override the token endpoint. */
  oidcTokenEndpoint?: string;
};

/**
 * Options for external JWT token provider (RFC 8693 token exchange).
 */
export type ExternalJwtTokenProviderOptions = {
  /** OIDC client ID. */
  clientId: string;
  /** External JWT to exchange. */
  externalJwt: string;
  /** OIDC IdP origin, e.g. 'http://localhost:8080/auth/realms/opentdf'. */
  oidcOrigin: string;
  /** Override the token endpoint. */
  oidcTokenEndpoint?: string;
};

type TokenResponse = {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
};

function resolveTokenEndpoint(oidcOrigin: string, override?: string): string {
  if (override?.trim()) return override;
  const base = oidcOrigin?.trim();
  if (!base) {
    throw new ConfigurationError('oidcOrigin or oidcTokenEndpoint is required');
  }
  return `${rstrip(base, '/')}/protocol/openid-connect/token`;
}

/**
 * Decode a JWT's exp claim without verifying the signature.
 * Returns the expiration time in seconds since epoch, or undefined if not present.
 */
function getJwtExpiration(token: string): number | undefined {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return undefined;
    // Base64url decode the payload
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
    const decoded = JSON.parse(atob(padded));
    return typeof decoded.exp === 'number' ? decoded.exp : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Compute the absolute expiry (seconds since epoch) for a token response.
 * Prefers `expires_in` from the token response, falls back to the JWT `exp` claim.
 */
function resolveTokenExpiry(accessToken: string, expiresIn?: number): number | undefined {
  if (typeof expiresIn === 'number') {
    return Date.now() / 1000 + expiresIn;
  }
  return getJwtExpiration(accessToken);
}

function isTokenExpired(expiry: number | undefined, bufferSeconds = 30): boolean {
  if (expiry === undefined) return true;
  return Date.now() / 1000 >= expiry - bufferSeconds;
}

async function fetchToken(
  tokenEndpoint: string,
  body: Record<string, string>
): Promise<TokenResponse> {
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams(body).toString(),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new TdfError(
      `Token request failed: POST [${tokenEndpoint}] => ${response.status} ${response.statusText}: ${text}`
    );
  }
  return (await response.json()) as TokenResponse;
}

/**
 * Creates a TokenProvider that obtains tokens via the OAuth2 client credentials grant.
 * Tokens are cached and automatically refreshed when expired.
 *
 * @example
 * ```ts
 * const client = new OpenTDF({
 *   interceptors: [authTokenInterceptor(clientCredentialsTokenProvider({
 *     clientId: 'opentdf',
 *     clientSecret: 'secret',
 *     oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
 *   }))],
 *   platformUrl: 'http://localhost:8080',
 * });
 * ```
 */
export function clientCredentialsTokenProvider(
  options: ClientCredentialsTokenProviderOptions
): TokenProvider {
  if (!options.clientId || !options.clientSecret) {
    throw new ConfigurationError('clientId and clientSecret are required');
  }
  const tokenEndpoint = resolveTokenEndpoint(options.oidcOrigin, options.oidcTokenEndpoint);
  let cachedToken: string | undefined;
  let cachedExpiry: number | undefined;
  let inFlight: Promise<string> | undefined;

  return async () => {
    if (cachedToken && !isTokenExpired(cachedExpiry)) {
      return cachedToken;
    }
    if (!inFlight) {
      inFlight = (async () => {
        try {
          const resp = await fetchToken(tokenEndpoint, {
            grant_type: 'client_credentials',
            client_id: options.clientId,
            client_secret: options.clientSecret,
          });
          cachedToken = resp.access_token;
          cachedExpiry = resolveTokenExpiry(resp.access_token, resp.expires_in);
          return cachedToken;
        } finally {
          inFlight = undefined;
        }
      })();
    }
    return inFlight;
  };
}

/**
 * Creates a TokenProvider that uses a refresh token to obtain access tokens.
 * On the first call, exchanges the refresh token. Subsequent calls use the
 * latest refresh token from the IdP response.
 *
 * @example
 * ```ts
 * const client = new OpenTDF({
 *   interceptors: [authTokenInterceptor(refreshTokenProvider({
 *     clientId: 'my-app',
 *     refreshToken: 'refresh-token-from-login',
 *     oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
 *   }))],
 *   platformUrl: 'http://localhost:8080',
 * });
 * ```
 */
export function refreshTokenProvider(options: RefreshTokenProviderOptions): TokenProvider {
  if (!options.clientId || !options.refreshToken) {
    throw new ConfigurationError('clientId and refreshToken are required');
  }
  const tokenEndpoint = resolveTokenEndpoint(options.oidcOrigin, options.oidcTokenEndpoint);
  let currentRefreshToken = options.refreshToken;
  let cachedToken: string | undefined;
  let cachedExpiry: number | undefined;
  let inFlight: Promise<string> | undefined;

  return async () => {
    if (cachedToken && !isTokenExpired(cachedExpiry)) {
      return cachedToken;
    }
    if (!inFlight) {
      inFlight = (async () => {
        try {
          const resp = await fetchToken(tokenEndpoint, {
            grant_type: 'refresh_token',
            refresh_token: currentRefreshToken,
            client_id: options.clientId,
          });
          cachedToken = resp.access_token;
          cachedExpiry = resolveTokenExpiry(resp.access_token, resp.expires_in);
          if (resp.refresh_token) {
            currentRefreshToken = resp.refresh_token;
          }
          return cachedToken;
        } finally {
          inFlight = undefined;
        }
      })();
    }
    return inFlight;
  };
}

/**
 * Creates a TokenProvider that exchanges an external JWT for a platform token
 * via RFC 8693 token exchange. After the initial exchange, uses the refresh
 * token for subsequent calls.
 *
 * @example
 * ```ts
 * const client = new OpenTDF({
 *   interceptors: [authTokenInterceptor(externalJwtTokenProvider({
 *     clientId: 'my-app',
 *     externalJwt: 'eyJhbGciOi...',
 *     oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
 *   }))],
 *   platformUrl: 'http://localhost:8080',
 * });
 * ```
 */
export function externalJwtTokenProvider(options: ExternalJwtTokenProviderOptions): TokenProvider {
  if (!options.clientId || !options.externalJwt) {
    throw new ConfigurationError('clientId and externalJwt are required');
  }
  const tokenEndpoint = resolveTokenEndpoint(options.oidcOrigin, options.oidcTokenEndpoint);
  let cachedToken: string | undefined;
  let cachedExpiry: number | undefined;
  let currentRefreshToken: string | undefined;
  let initialExchangeDone = false;
  let inFlight: Promise<string> | undefined;

  return async () => {
    if (cachedToken && !isTokenExpired(cachedExpiry)) {
      return cachedToken;
    }
    if (!inFlight) {
      inFlight = (async () => {
        try {
          let resp: TokenResponse;
          if (!initialExchangeDone) {
            resp = await fetchToken(tokenEndpoint, {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              subject_token: options.externalJwt,
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
              audience: options.clientId,
              client_id: options.clientId,
            });
            initialExchangeDone = true;
          } else if (currentRefreshToken) {
            resp = await fetchToken(tokenEndpoint, {
              grant_type: 'refresh_token',
              refresh_token: currentRefreshToken,
              client_id: options.clientId,
            });
          } else {
            // Re-exchange the original JWT if no refresh token available
            resp = await fetchToken(tokenEndpoint, {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              subject_token: options.externalJwt,
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
              audience: options.clientId,
              client_id: options.clientId,
            });
          }

          cachedToken = resp.access_token;
          cachedExpiry = resolveTokenExpiry(resp.access_token, resp.expires_in);
          if (resp.refresh_token) {
            currentRefreshToken = resp.refresh_token;
          }
          return cachedToken;
        } finally {
          inFlight = undefined;
        }
      })();
    }
    return inFlight;
  };
}
