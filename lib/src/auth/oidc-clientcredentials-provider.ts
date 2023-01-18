import { AuthProvider, HttpRequest } from './auth.js';
import { IOIDCClientCredentialsProvider } from '../nanotdf/interfaces/OIDCInterface.js';
import VirtruOIDC from './virtru-oidc.js';

export class OIDCClientCredentialsProvider implements AuthProvider {
  oidcAuth: VirtruOIDC;

  constructor({ clientId, clientSecret, oidcOrigin }: IOIDCClientCredentialsProvider) {
    if (!clientId || !clientSecret) {
      throw new Error(
        'To use this nonbrowser-only provider you must supply clientId & clientSecret'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      clientId,
      clientSecret,
      oidcOrigin,
    });
  }

  async updateClientPublicKey(clientPubkey: string, signingKey?: CryptoKeyPair): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubkey, signingKey);
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    return this.oidcAuth.withCreds(httpReq);
  }
}
