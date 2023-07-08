import { AuthProvider, type HttpRequest } from './auth.js';
import { AccessToken, type RefreshTokenCredentials } from './oidc.js';

export class OIDCRefreshTokenProvider implements AuthProvider {
  oidcAuth: AccessToken;
  refreshToken?: string;

  constructor({
    clientId,
    refreshToken,
    oidcOrigin,
  }: Partial<RefreshTokenCredentials> & Omit<RefreshTokenCredentials, 'exchange'>) {
    if (!clientId || !refreshToken) {
      throw new Error(
        'To use this browser-only provider you must supply clientId/valid OIDC refresh token'
      );
    }

    this.oidcAuth = new AccessToken({
      exchange: 'refresh',
      clientId,
      refreshToken: refreshToken,
      oidcOrigin,
    });
    this.refreshToken = refreshToken;
  }

  async updateClientPublicKey(clientPubkey: string, signingKey?: CryptoKeyPair): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubkey, signingKey);
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
