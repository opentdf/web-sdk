import VirtruOIDC from './virtru-oidc';
import { IOIDCExternalJwtProvider } from '../nanotdf/interfaces/OIDCInterface';
import { AuthProvider, HttpRequest, withHeaders } from './auth';

export class OIDCExternalJwtProvider implements AuthProvider {
  oidcAuth: VirtruOIDC;
  externalJwt?: string;

  constructor({ signingKey, clientId, externalJwt, oidcOrigin }: IOIDCExternalJwtProvider) {
    if (!clientId || !externalJwt) {
      throw new Error(
        'To use this browser-only provider you must supply clientId/JWT from trusted external IdP'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      signingKey,
      clientId,
      oidcOrigin,
    });

    this.externalJwt = externalJwt;
  }

  async updateClientPublicKey(signingKey: CryptoKeyPair): Promise<void> {
    this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey);
  }

  async injectAuth(httpReq: HttpRequest): Promise<HttpRequest> {
    //If we've been seeded with an externally-issued JWT, consume it
    //and exchange it for a Virtru bearer token.
    if (this.externalJwt) {
      this.oidcAuth.exchangeExternalJwt(this.externalJwt);
      delete this.externalJwt;
    }
    const accessToken = this.oidcAuth.getCurrentAccessToken();
    return withHeaders(httpReq, { Authorization: `Bearer ${accessToken}` });
  }
}
