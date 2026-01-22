import { ConfigurationError } from '../errors.js';
import { type AuthProvider, type HttpRequest } from './auth.js';
import { AccessToken, type RefreshTokenCredentials } from './oidc.js';
import { type CryptoService, type PemKeyPair } from '../../tdf3/src/crypto/declarations.js';

/**
 * An AuthProvider that uses an OIDC refresh token to obtain an access token.
 * It exchanges the refresh token for an access token and uses that to augment HTTP requests with credentials.
 *  @example
 * ```ts
 * import { OIDCRefreshTokenProvider } from '@opentdf/sdk';
 * await AuthProviders.refreshAuthProvider({
    clientId: 'my-client-id',
    exchange: 'refresh',
    refreshToken: 'refresh-token-from-oidc-provider',
    oidcOrigin: 'https://example.oidc.provider.com',
  });
  ```
 */
export class OIDCRefreshTokenProvider implements AuthProvider {
  oidcAuth: AccessToken;
  refreshToken?: string;

  constructor(
    {
      clientId,
      refreshToken,
      oidcOrigin,
      oidcTokenEndpoint,
      oidcUserInfoEndpoint,
    }: Partial<RefreshTokenCredentials> & Omit<RefreshTokenCredentials, 'exchange'>,
    cryptoService: CryptoService
  ) {
    if (!clientId || !refreshToken) {
      throw new ConfigurationError('refresh token or client id missing');
    }

    this.oidcAuth = new AccessToken(
      {
        exchange: 'refresh',
        clientId,
        refreshToken,
        oidcOrigin,
        oidcTokenEndpoint,
        oidcUserInfoEndpoint,
      },
      cryptoService
    );
    this.refreshToken = refreshToken;
  }

  async updateClientPublicKey(signingKey: PemKeyPair): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey);
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    //If we've been seeded with an externally-issued refresh token, consume it
    //and exchange it for a Virtru bearer token - if it's already been consumed,
    //skip this step
    if (this.refreshToken) {
      await this.oidcAuth.exchangeForRefreshToken();
      delete this.refreshToken;
    }
    return this.oidcAuth.withCreds(httpReq);
  }
}
