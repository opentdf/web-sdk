import VirtruOIDC from './virtru-oidc.js';
import { IOIDCRefreshTokenProvider } from '../nanotdf/interfaces/OIDCInterface.js';
import { AuthProvider, HttpRequest } from './auth.js';

export class OIDCRefreshTokenProvider implements AuthProvider {
  oidcAuth: VirtruOIDC;
  externalRefreshToken?: string;

  constructor({
    clientId,
    externalRefreshToken,
    oidcOrigin,
    clientSecret,
  }: IOIDCRefreshTokenProvider) {
    if (!clientId || !externalRefreshToken) {
      throw new Error(
        'To use this browser-only provider you must supply clientId/valid OIDC refresh token'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      clientId,
      clientSecret,
      oidcOrigin,
    });
    this.externalRefreshToken = externalRefreshToken;
  }

  async updateClientPublicKey(clientPubkey: string, signingKey?: CryptoKeyPair): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubkey, signingKey);
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    //If we've been seeded with an externally-issued refresh token, consume it
    //and exchange it for a Virtru bearer token - if it's already been consumed,
    //skip this step
    if (this.externalRefreshToken) {
      await this.oidcAuth.exchangeExternalRefreshToken(this.externalRefreshToken);
      delete this.externalRefreshToken;
    }
    return this.oidcAuth.withCreds(httpReq);
  }
}
