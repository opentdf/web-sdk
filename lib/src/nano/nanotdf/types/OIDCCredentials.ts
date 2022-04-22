export type CommonCredentials = {
  organizationName: string;
  clientId: string;
  oidcOrigin: string;
};

export type ClientSecretCredentials = CommonCredentials & {
  exchange: 'client';
  clientSecret: string;
};

export type RefreshTokenCredentials = CommonCredentials & {
  exchange: 'refresh';
  oidcRefreshToken: string;
};

export type ExternalJwtCredentials = CommonCredentials & {
  exchange: 'external';
  externalJwt: string;
};

export type OIDCCredentials =
  | ClientSecretCredentials
  | ExternalJwtCredentials
  | RefreshTokenCredentials;
