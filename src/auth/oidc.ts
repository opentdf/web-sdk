import { default as dpopFn } from 'dpop';
import { HttpRequest, withHeaders } from './auth.js';
import { IllegalArgumentError } from '../../tdf3/src/errors.js';
import { rstrip } from '../utils.js';

/**
 * Common fields used by all OIDC credentialing flows.
 */
export type CommonCredentials = {
  /** The OIDC client ID used for token issuance and exchange flows */
  clientId: string;
  /** The endpoint of the OIDC IdP to authenticate against, ex. 'https://virtru.com/auth' */
  oidcOrigin: string;

  /** the client's public key, base64 encoded. Will be bound to the OIDC token. Deprecated. If not set in the constructor, */
  clientPubKey?: string;

  /** the client's public key, base64 encoded. Will be bound to the OIDC token. Deprecated. If not set in the constructor, */
  signingKey?: CryptoKeyPair;
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
  refreshToken: string;
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

const qstringify = (obj: Record<string, string>) => new URLSearchParams(obj).toString();

export type AccessTokenResponse = {
  access_token: string;
  refresh_token?: string;
};

/**
 * Class that provides OIDC functionality to auth providers, assuming 'enhanced'
 * tokens and sessions with tdf_claims and either one or both of signing keys
 * or DPoP.
 *
 * Note that this class itself is not a provider - providers implement
 * `AuthProvider` and make use of this class.
 *
 * Both browser and non-browser flows use OIDC, but the supported OIDC auth
 * mechanisms differ between  public (e.g. browser) clients, and confidential
 * (e.g. Node) clients.
 *
 * The non-browser flow just expects a `clientId` and `clientSecret` to be
 * provided in the `clientConfig`, and will use that
 * to grant tokens via the OIDC `clientCredentials` flow.
 *
 * For either kind of client, the client's public key must be set in all OIDC
 * token requests in order to recieve a token with valid TDF claims. The public
 * key may be passed to this provider's constructor, or supplied
 * post-construction by calling @see updateClientPublicKey, which forces an
 * explicit token refresh
 */
export class AccessToken {
  config: OIDCCredentials;

  request?: (input: RequestInfo, init?: RequestInit) => Promise<Response>;

  data?: AccessTokenResponse;

  baseUrl: string;

  signingKey?: CryptoKeyPair;

  clientPubKey?: string;

  extraHeaders: Record<string, string> = {};

  currentAccessToken?: string;

  constructor(cfg: OIDCCredentials, request?: typeof fetch) {
    if (!cfg.clientId) {
      throw new Error('A Keycloak client identifier is currently required for all auth mechanisms');
    }
    if (cfg.exchange === 'client' && !cfg.clientSecret) {
      throw new Error('When using client credentials, both clientId and clientSecret are required');
    }
    if (cfg.exchange === 'refresh' && !cfg.refreshToken) {
      throw new Error('When using refresh token, a refresh token must be provided');
    }
    if (cfg.exchange === 'external' && !cfg.externalJwt) {
      throw new Error('When using external JWT, the jwt must be provided');
    }
    if (!cfg.exchange) {
      throw new Error('Invalid oidc configuration');
    }
    this.config = cfg;
    this.request = request;
    this.baseUrl = rstrip(cfg.oidcOrigin, '/');
    this.signingKey = cfg.signingKey;
    this.clientPubKey = cfg.clientPubKey;
  }

  /**
   * https://connect2id.com/products/server/docs/api/userinfo
   * @param accessToken the current access_token or code
   * @returns
   */
  async info(accessToken: string): Promise<unknown> {
    const url = `${this.baseUrl}/protocol/openid-connect/userinfo`;
    const headers = {
      ...this.extraHeaders,
      Authorization: `Bearer ${accessToken}`,
    } as Record<string, string>;
    if (this.signingKey) {
      headers.DPoP = await dpopFn(this.signingKey, url, 'POST');
    }
    const response = await (this.request || fetch)(url, {
      headers,
    });
    if (!response.ok) {
      console.error(await response.text());
      throw new Error(`${response.status} ${response.statusText}`);
    }

    return (await response.json()) as unknown;
  }

  async doPost(url: string, o: Record<string, string>) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    };
    if (this.clientPubKey) {
      headers['X-VirtruPubKey'] = this.clientPubKey;
    } else {
      throw new IllegalArgumentError('No signature configured');
    }
    if (this.signingKey) {
      headers.DPoP = await dpopFn(this.signingKey, url, 'POST');
    }
    if (!this.clientPubKey && !this.signingKey) {
      throw new IllegalArgumentError('No signature configured');
    }
    return (this.request || fetch)(url, {
      method: 'POST',
      headers,
      body: qstringify(o),
    });
  }

  async accessTokenLookup(cfg: OIDCCredentials) {
    const url = `${this.baseUrl}/protocol/openid-connect/token`;
    let body;
    switch (cfg.exchange) {
      case 'client':
        body = {
          grant_type: 'client_credentials',
          client_id: cfg.clientId,
          client_secret: cfg.clientSecret,
        };
        break;
      case 'external':
        body = {
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: cfg.externalJwt,
          subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          audience: cfg.clientId,
          client_id: cfg.clientId,
        };
        break;
      case 'refresh':
        body = {
          grant_type: 'refresh_token',
          refresh_token: cfg.refreshToken,
          client_id: cfg.clientId,
        };
        break;
    }
    const response = await this.doPost(url, body);
    if (!response.ok) {
      console.error(await response.text());
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json();
  }

  /**
   * Gets an access token; operates lazily/cached, with an optional check for freshness.
   * @param validate if we should run a inline check against the OIDC 'userinfo' endpoint to make sure any cached access token is still valid
   * @returns
   */
  async get(validate = true): Promise<string> {
    if (this.data?.access_token) {
      try {
        if (validate) {
          await this.info(this.data.access_token);
        }
        return this.data.access_token;
      } catch (e) {
        console.log('access_token fails on user_info endpoint; attempting to renew', e);
        if (this.data.refresh_token) {
          // Prefer the latest refresh_token if present over creds passed in
          // to constructor
          this.config = {
            ...this.config,
            exchange: 'refresh',
            refreshToken: this.data.refresh_token,
          };
        }
        delete this.data;
      }
    }

    const tokenResponse = (this.data = await this.accessTokenLookup(this.config));
    return tokenResponse.access_token;
  }

  /**
   * A TDF client MUST call this method whenever the client wants to use a new
   * ephemeral key set. This updates the keys used to:
   * or wishes to set the keypair after creating the object.
   *
   * Calling this function will trigger a forcible token refresh using the cached refresh token, and contact the auth server.
   */
  async refreshTokenClaimsWithClientPubkeyIfNeeded(
    clientPubKey: string,
    signingKey?: CryptoKeyPair
  ): Promise<void> {
    // If we already have a token, and the pubkey changes,
    // we need to force a refresh now - otherwise
    // we can wait until we create the token for the first time
    if (this.currentAccessToken && clientPubKey === this.clientPubKey) {
      return;
    }
    delete this.currentAccessToken;
    this.clientPubKey = clientPubKey;
    this.signingKey = signingKey;
  }

  /**
   * Converts included refresh token or external JWT for a new one.
   */
  async exchangeForRefreshToken(): Promise<string> {
    const cfg = this.config;
    if (cfg.exchange != 'external' && cfg.exchange != 'refresh') {
      throw new Error('No refresh token provided!');
    }
    const tokenResponse = (this.data = await this.accessTokenLookup(this.config));
    if (!tokenResponse.refresh_token) {
      console.log('No refresh_token returned');
      return (
        (cfg.exchange == 'refresh' && cfg.refreshToken) ||
        (cfg.exchange == 'external' && cfg.externalJwt) ||
        ''
      );
    }
    // Prefer the latest refresh_token if present over creds passed in
    // to constructor
    this.config = {
      ...this.config,
      exchange: 'refresh',
      refreshToken: tokenResponse.refresh_token,
    };
    return tokenResponse.access_token;
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    if (!this.clientPubKey && !this.signingKey) {
      throw new Error(
        'Client public key was not set via `updateClientPublicKey` or passed in via constructor, cannot fetch OIDC token with valid Virtru claims'
      );
    }
    const accessToken = (this.currentAccessToken ??= await this.get());
    if (this.signingKey) {
      const dpopToken = await dpopFn(
        this.signingKey,
        httpReq.url,
        httpReq.method,
        /* nonce */ undefined,
        accessToken
      );
      // TODO: Consider: only set DPoP if cnf.jkt is present in access token?
      return withHeaders(httpReq, { Authorization: `Bearer ${accessToken}`, DPoP: dpopToken });
    }
    return withHeaders(httpReq, { Authorization: `Bearer ${accessToken}` });
  }
}
