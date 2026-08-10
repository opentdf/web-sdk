import { ConfigurationError } from '../errors.js';
import { type AuthProvider, type HttpRequest } from './auth.js';
import { AccessToken, type ExternalJwtCredentials } from './oidc.js';
import { type DPoPNonceCache } from './dpop-nonce.js';
import * as defaultCryptoService from '../../tdf3/src/crypto/index.js';
import { type CryptoService, type KeyPair } from '../../tdf3/src/crypto/declarations.js';
import type { DPoPModeResolver } from './dpop-mode.js';

export class OIDCExternalJwtProvider implements AuthProvider {
  oidcAuth: AccessToken;
  get dpopModeResolver(): DPoPModeResolver | undefined {
    return this.oidcAuth.dpopModeResolver;
  }
  externalJwt?: string;

  constructor(
    {
      clientId,
      externalJwt,
      oidcOrigin,
      oidcTokenEndpoint,
      oidcUserInfoEndpoint,
      dpopEnabled,
      dpopMode,
      signingKey,
    }: Partial<ExternalJwtCredentials> & Omit<ExternalJwtCredentials, 'exchange'>,
    cryptoService: CryptoService = defaultCryptoService
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
        dpopEnabled,
        dpopMode,
        signingKey,
      },
      cryptoService
    );

    this.externalJwt = externalJwt;
  }

  async updateClientPublicKey(signingKey: KeyPair): Promise<void> {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey);
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

  /** Per-client DPoP-Nonce cache, shared with the underlying {@link AccessToken}. */
  get nonceCache(): DPoPNonceCache {
    return this.oidcAuth.nonceCache;
  }
}
