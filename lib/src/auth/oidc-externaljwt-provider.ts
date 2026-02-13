import { ConfigurationError } from '../errors.js';
import { type AuthProvider, type HttpRequest } from './auth.js';
import { AccessToken, type ExternalJwtCredentials } from './oidc.js';
import { type CryptoService, type KeyPair } from '../../tdf3/src/crypto/declarations.js';

export class OIDCExternalJwtProvider implements AuthProvider {
  oidcAuth: AccessToken;
  externalJwt?: string;

  constructor(
    {
      clientId,
      externalJwt,
      oidcOrigin,
      oidcTokenEndpoint,
      oidcUserInfoEndpoint,
    }: Partial<ExternalJwtCredentials> & Omit<ExternalJwtCredentials, 'exchange'>,
    cryptoService: CryptoService
  ) {
    if (!clientId || !externalJwt) {
      throw new ConfigurationError('external JWT exchange reequires client id and jwt');
    }

    this.oidcAuth = new AccessToken(
      {
        exchange: 'external',
        clientId,
        externalJwt,
        oidcOrigin,
        oidcTokenEndpoint,
        oidcUserInfoEndpoint,
      },
      cryptoService
    );

    this.externalJwt = externalJwt;
  }

  async updateClientPublicKey(signingKey: KeyPair): Promise<void> {
    this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey);
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    //If we've been seeded with an externally-issued JWT, consume it
    //and exchange it for a Virtru bearer token.
    if (this.externalJwt) {
      await this.oidcAuth.exchangeForRefreshToken();
      delete this.externalJwt;
    }
    return this.oidcAuth.withCreds(httpReq);
  }
}
