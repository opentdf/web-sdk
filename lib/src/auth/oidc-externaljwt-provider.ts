import { type AuthProvider, type HttpRequest } from './auth.js';
import { AccessToken, type ExternalJwtCredentials } from './oidc.js';

export class OIDCExternalJwtProvider implements AuthProvider {
  oidcAuth: AccessToken;
  externalJwt?: string;

  constructor({
    clientId,
    externalJwt,
    oidcOrigin,
  }: Partial<ExternalJwtCredentials> & Omit<ExternalJwtCredentials, 'exchange'>) {
    if (!clientId || !externalJwt) {
      throw new Error(
        'To use this browser-only provider you must supply clientId/JWT from trusted external IdP'
      );
    }

    this.oidcAuth = new AccessToken({
      exchange: 'external',
      clientId,
      oidcOrigin,
      externalJwt,
    });

    this.externalJwt = externalJwt;
  }

  async updateClientPublicKey(signingKey: CryptoKeyPair): Promise<void> {
    this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey);
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    //If we've been seeded with an externally-issued JWT, consume it
    //and exchange it for a Virtru bearer token.
    if (this.externalJwt) {
      await this.oidcAuth.exchangeForRefreshToken();
      delete this.externalJwt;
    }
    return this.oidcAuth.withCreds(httpReq);
  }
}
