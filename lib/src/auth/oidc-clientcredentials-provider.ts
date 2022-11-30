import { AuthProvider, HttpRequest } from './auth';
import { IOIDCClientCredentialsProvider } from '../nanotdf/interfaces/OIDCInterface';
import VirtruOIDC from './virtru-oidc';

export class OIDCClientCredentialsProvider implements AuthProvider {
  oidcAuth: VirtruOIDC;

  constructor({ signingKey, clientId, clientSecret, oidcOrigin }: IOIDCClientCredentialsProvider) {
    if (!clientId || !clientSecret) {
      throw new Error(
        'To use this nonbrowser-only provider you must supply clientId & clientSecret'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      signingKey,
      clientId,
      clientSecret,
      oidcOrigin,
    });
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    return this.oidcAuth.withCreds(httpReq);
  }

  async updateClientPublicKey(signingKey: CryptoKeyPair): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey);
  }
}
