import { ConfigurationError } from '../errors.js';
import { type AuthProvider, type HttpRequest } from './auth.js';
import { AccessToken, type RefreshTokenCredentials } from './oidc.js';

export class OIDCRefreshTokenProvider implements AuthProvider {
  oidcAuth: AccessToken;
  refreshToken?: string;

  constructor({
    clientId,
    refreshToken,
    oidcOrigin,
    oidcTokenEndpoint,
    oidcUserInfoEndpoint,
  }: Partial<RefreshTokenCredentials> & Omit<RefreshTokenCredentials, 'exchange'>) {
    if (!clientId || !refreshToken) {
      throw new ConfigurationError('refresh token or client id missing');
    }

    this.oidcAuth = new AccessToken({
      exchange: 'refresh',
      clientId,
      refreshToken,
      oidcOrigin,
      oidcTokenEndpoint,
      oidcUserInfoEndpoint,
    });
    this.refreshToken = refreshToken;
  }

  async updateClientPublicKey(signingKey: CryptoKeyPair): Promise<void> {
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
