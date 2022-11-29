export interface IVirtruOIDCBase {
  /** the client's public key, base64 encoded. Will be bound to the OIDC token. Optional. If not set in the constructor, */
  signingKey?: CryptoKeyPair;

  /**If using client credentials mode, the client ID. Optional, used for non-browser contexts. */
  clientId: string;

  /** The endpoint of the OIDC IdP to authenticate against, ex. 'https://virtru.com/auth/realms/demo' */
  oidcOrigin: string;
}

export interface IVirtruOIDC extends IVirtruOIDCBase {
  /** If using client credentials mode, the client secret. Optional, used for non-browser contexts. */
  clientSecret?: string;
}

export interface IOIDCRefreshTokenProvider extends IVirtruOIDCBase {
  clientSecret?: string;
  externalRefreshToken: string | null;
}

export interface IOIDCExternalJwtProvider extends IVirtruOIDCBase {
  externalJwt: string | null;
}

export interface IOIDCClientCredentialsProvider extends IVirtruOIDCBase {
  clientSecret: string | null;
}
