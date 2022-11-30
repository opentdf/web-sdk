import VirtruOIDC from './virtru-oidc';
import { IOIDCRefreshTokenProvider } from '../nanotdf/interfaces/OIDCInterface';
import { AuthProvider, HttpRequest } from './auth';

export class OIDCRefreshTokenProvider implements AuthProvider {
  protected oidcAuth: VirtruOIDC;
  protected signingKey?: CryptoKeyPair;
  protected externalRefreshToken?: string;

  constructor({
    signingKey,
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
      signingKey,
      clientId,
      clientSecret,
      oidcOrigin,
    });
    this.signingKey = signingKey;
    this.externalRefreshToken = externalRefreshToken;
  }

  async updateClientPublicKey(signingKey: CryptoKeyPair): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey);
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
