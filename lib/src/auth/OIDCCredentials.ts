/**
 * Common fields used by all OIDC credentialing flows.
 */
export type CommonCredentials = {
  /** The organization the calling user belongs to (in Keycloak, this is the Realm) */
  organizationName: string;
  /** The OIDC client ID used for token issuance and exchange flows */
  clientId: string;
  /** The endpoint of the OIDC IdP to authenticate against, ex. 'https://virtru.com/auth' */
  oidcOrigin: string;
};

/**
 * Information needed for Client Secret OIDC credentialing flow
 */
export type ClientSecretCredentials = CommonCredentials & {
  exchange: 'client';
  /** The OIDC client secret, used for token issuance and exchange flows */
  clientSecret: string;
};

/**
 * Information needed for getting new access tokens with a refresh token
 */
export type RefreshTokenCredentials = CommonCredentials & {
  exchange: 'refresh';
  /** The OIDC refresh token content */
  oidcRefreshToken: string;
};

/**
 * Information needed to exchange a standard or external JWT for a TDF claims
 * annotated JWT
 */
export type ExternalJwtCredentials = CommonCredentials & {
  exchange: 'external';
  /** The external JWT used for exchange */
  externalJwt: string;
};

export type OIDCCredentials =
  | ClientSecretCredentials
  | ExternalJwtCredentials
  | RefreshTokenCredentials;
