import VirtruOIDC from './virtru-oidc';
import { IOIDCExternalJwtProvider } from '../nanotdf/interfaces/OIDCInterface';
import { AuthProvider, HttpRequest } from './auth';

export class OIDCExternalJwtProvider implements AuthProvider {
  oidcAuth: VirtruOIDC;
  externalJwt?: string;

  constructor({ clientId, externalJwt, oidcOrigin }: IOIDCExternalJwtProvider) {
    if (!clientId || !externalJwt) {
      throw new Error(
        'To use this browser-only provider you must supply clientId/JWT from trusted external IdP'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      clientId,
      oidcOrigin,
    });

    this.externalJwt = externalJwt;
  }

  async updateClientPublicKey(clientPubKey: string): Promise<void> {
    this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubKey);
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    //If we've been seeded with an externally-issued JWT, consume it
    //and exchange it for a Virtru bearer token.
    if (this.externalJwt) {
      this.oidcAuth.exchangeExternalJwt(this.externalJwt);
      delete this.externalJwt;
    }
    return this.oidcAuth.withCreds(httpReq);
  }
}
