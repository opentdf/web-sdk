import { AuthProvider } from './auth';
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

  async updateClientPublicKey(signingKey: CryptoKeyPair): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey);
  }

  async authorization(): Promise<string> {
    const accessToken = await this.oidcAuth.getCurrentAccessToken();

    // NOTE It is generally best practice to keep headers under 8KB
    return `Bearer ${accessToken}`;
  }
}
