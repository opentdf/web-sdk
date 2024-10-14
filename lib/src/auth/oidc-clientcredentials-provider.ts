import { ConfigurationError } from '../errors.js';
import { AuthProvider, type HttpRequest } from './auth.js';
import { AccessToken, type ClientSecretCredentials } from './oidc.js';

export class OIDCClientCredentialsProvider implements AuthProvider {
  oidcAuth: AccessToken;

  constructor({
    clientId,
    clientSecret,
    oidcOrigin,
  }: Partial<ClientSecretCredentials> & Omit<ClientSecretCredentials, 'exchange'>) {
    if (!clientId || !clientSecret) {
      throw new ConfigurationError('clientId & clientSecret required for client credentials flow');
    }

    this.oidcAuth = new AccessToken({
      exchange: 'client',
      clientId,
      clientSecret,
      oidcOrigin,
    });
  }

  async updateClientPublicKey(signingKey: CryptoKeyPair): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey);
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    return this.oidcAuth.withCreds(httpReq);
  }
}
