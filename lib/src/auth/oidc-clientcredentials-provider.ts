import { AuthProvider, HttpRequest } from './auth';
import { IOIDCClientCredentialsProvider } from '../nanotdf/interfaces/OIDCInterface';
import VirtruOIDC from './virtru-oidc';

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

  async updateClientPublicKey(clientPubkey: string): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubkey);
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    return this.oidcAuth.withCreds(httpReq);
  }
}
