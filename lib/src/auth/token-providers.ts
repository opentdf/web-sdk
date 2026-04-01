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
  if (override) return override;
  return `${rstrip(oidcOrigin, '/')}/protocol/openid-connect/token`;
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

function isTokenExpired(token: string, bufferSeconds = 30): boolean {
  const exp = getJwtExpiration(token);
  if (exp === undefined) return true;
  return Date.now() / 1000 >= exp - bufferSeconds;
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

  return async () => {
    if (cachedToken && !isTokenExpired(cachedToken)) {
      return cachedToken;
    }
    const resp = await fetchToken(tokenEndpoint, {
      grant_type: 'client_credentials',
      client_id: options.clientId,
      client_secret: options.clientSecret,
    });
    cachedToken = resp.access_token;
    return cachedToken;
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

  return async () => {
    if (cachedToken && !isTokenExpired(cachedToken)) {
      return cachedToken;
    }
    const resp = await fetchToken(tokenEndpoint, {
      grant_type: 'refresh_token',
      refresh_token: currentRefreshToken,
      client_id: options.clientId,
    });
    cachedToken = resp.access_token;
    if (resp.refresh_token) {
      currentRefreshToken = resp.refresh_token;
    }
    return cachedToken;
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
  let currentRefreshToken: string | undefined;
  let initialExchangeDone = false;

  return async () => {
    if (cachedToken && !isTokenExpired(cachedToken)) {
      return cachedToken;
    }

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
    if (resp.refresh_token) {
      currentRefreshToken = resp.refresh_token;
    }
    return cachedToken;
  };
}
