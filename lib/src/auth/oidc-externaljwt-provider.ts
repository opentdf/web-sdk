import VirtruOIDC from './virtru-oidc.js';
import { IOIDCExternalJwtProvider } from '../nanotdf/interfaces/OIDCInterface.js';
import { AuthProvider } from './auth.js';

export class OIDCExternalJwtProvider implements AuthProvider {
  oidcAuth: VirtruOIDC;
  externalJwt?: string;

  constructor({ clientPubKey, clientId, externalJwt, oidcOrigin }: IOIDCExternalJwtProvider) {
    if (!clientId || !externalJwt) {
      throw new Error(
        'To use this browser-only provider you must supply clientId/JWT from trusted external IdP'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      clientPubKey,
      clientId,
      oidcOrigin,
    });

    this.externalJwt = externalJwt;
  }

  async updateClientPublicKey(clientPubKey: string): Promise<void> {
    this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubKey);
  }

  async authorization(): Promise<string> {
    //If we've been seeded with an externally-issued JWT, consume it
    //and exchange it for a Virtru bearer token.
    if (this.externalJwt) {
      this.oidcAuth.exchangeExternalJwt(this.externalJwt);
      delete this.externalJwt;
    }
    const accessToken = this.oidcAuth.getCurrentAccessToken();

    // NOTE It is generally best practice to keep headers under 8KB
    return `Bearer ${accessToken}`;
  }
}
