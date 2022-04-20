import VirtruOIDC from './virtru-oidc';
import { IOIDCRefreshTokenProvider } from '../nanotdf/interfaces/OIDCInterface';
import { AuthProvider } from './auth';

export class OIDCRefreshTokenProvider implements AuthProvider {
  protected oidcAuth: VirtruOIDC;
  protected clientPubKey?: string;
  protected externalRefreshToken?: string;

  constructor({
    organizationName,
    clientPubKey,
    clientId,
    externalRefreshToken,
    oidcOrigin,
    clientSecret,
  }: IOIDCRefreshTokenProvider) {
    if (!organizationName || !clientId || !externalRefreshToken) {
      throw new Error(
        'To use this browser-only provider you must supply organizationName/clientId/valid OIDC refresh token'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      organizationName,
      clientPubKey,
      clientId,
      clientSecret,
      oidcOrigin,
    });
    this.clientPubKey = clientPubKey;
    this.externalRefreshToken = externalRefreshToken;
  }

  async updateClientPublicKey(clientPubkey: string): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubkey);
  }

  async authorization(): Promise<string> {
    //If we've been seeded with an externally-issued refresh token, consume it
    //and exchange it for a Virtru bearer token - if it's already been consumed,
    //skip this step
    if (this.externalRefreshToken) {
      await this.oidcAuth.exchangeExternalRefreshToken(this.externalRefreshToken);
      delete this.externalRefreshToken;
    }

    const accessToken = await this.oidcAuth.getCurrentAccessToken();

    // NOTE It is generally best practice to keep headers under 8KB
    return `Bearer ${accessToken}`;
  }
}
