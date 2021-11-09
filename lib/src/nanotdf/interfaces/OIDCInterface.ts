export interface IVirtruOIDCBase {
  organizationName: string;
  clientPubKey?: string;
  clientId: string;
  oidcOrigin: string;
}

export interface IVirtruOIDC extends IVirtruOIDCBase {
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
