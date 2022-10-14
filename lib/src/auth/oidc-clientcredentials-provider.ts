import { AuthProvider } from './auth.js';
import { IOIDCClientCredentialsProvider } from '../nanotdf/interfaces/OIDCInterface.js';
import VirtruOIDC from './virtru-oidc.js';

export class OIDCClientCredentialsProvider implements AuthProvider {
  oidcAuth: VirtruOIDC;

  constructor({
    clientPubKey,
    clientId,
    clientSecret,
    oidcOrigin,
  }: IOIDCClientCredentialsProvider) {
    if (!clientId || !clientSecret) {
      throw new Error(
        'To use this nonbrowser-only provider you must supply clientId & clientSecret'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      clientPubKey,
      clientId,
      clientSecret,
      oidcOrigin,
    });
  }

  async updateClientPublicKey(clientPubkey: string): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubkey);
  }

  async authorization(): Promise<string> {
    const accessToken = await this.oidcAuth.getCurrentAccessToken();

    // NOTE It is generally best practice to keep headers under 8KB
    return `Bearer ${accessToken}`;
  }
}
