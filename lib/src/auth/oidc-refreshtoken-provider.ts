import VirtruOIDC from './virtru-oidc';
import { IOIDCRefreshTokenProvider } from '../nanotdf/interfaces/OIDCInterface';
import { AuthProvider, HttpRequest } from './auth';

export class OIDCRefreshTokenProvider implements AuthProvider {
  protected oidcAuth: VirtruOIDC;
  protected externalRefreshToken?: string;

  constructor({
    clientPubKey,
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
      clientPubKey,
      clientId,
      clientSecret,
      oidcOrigin,
    });
    this.externalRefreshToken = externalRefreshToken;
  }

  async updateClientPublicKey(clientPubkey: string): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubkey);
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
