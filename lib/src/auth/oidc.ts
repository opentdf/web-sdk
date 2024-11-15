import { default as dpopFn } from 'dpop';
import { HttpRequest, withHeaders } from './auth.js';
import { base64 } from '../encodings/index.js';
import { ConfigurationError, TdfError } from '../errors.js';
import { cryptoPublicToPem, rstrip } from '../utils.js';

/**
 * Common fields used by all OIDC credentialing flows.
 */
export type CommonCredentials = {
  /** The OIDC client ID used for token issuance and exchange flows */
  clientId: string;
  /** The endpoint of the OIDC IdP to authenticate against, ex. 'https://virtru.com/auth' */
  oidcOrigin: string;
  /** Whether or not DPoP is enabled. */
  dpopEnabled?: boolean;

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

export type TimeStamp = {
  when: number;
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

  // For mocking fetch
  request?: (input: RequestInfo, init?: RequestInit) => Promise<Response>;

  data?: Promise<AccessTokenResponse & TimeStamp>;

  baseUrl: string;

  signingKey?: CryptoKeyPair;

  extraHeaders: Record<string, string> = {};

  currentAccessToken?: string;

  constructor(cfg: OIDCCredentials, request?: typeof fetch) {
    if (!cfg.clientId) {
      throw new ConfigurationError(
        'A Keycloak client identifier is currently required for all auth mechanisms'
      );
    }
    if (cfg.exchange === 'client' && !cfg.clientSecret) {
      throw new ConfigurationError(
        'When using client credentials, both clientId and clientSecret are required'
      );
    }
    if (cfg.exchange === 'refresh' && !cfg.refreshToken) {
      throw new ConfigurationError('When using refresh token, a refresh token must be provided');
    }
    if (cfg.exchange === 'external' && !cfg.externalJwt) {
      throw new ConfigurationError('When using external JWT, the jwt must be provided');
    }
    if (!cfg.exchange) {
      throw new ConfigurationError('Invalid oidc configuration');
    }
    this.config = cfg;
    this.request = request;
    this.baseUrl = rstrip(cfg.oidcOrigin, '/');
    this.signingKey = cfg.signingKey;
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
    if (this.config.dpopEnabled && this.signingKey) {
      headers.DPoP = await dpopFn(this.signingKey, url, 'POST');
    }
    const response = await (this.request || fetch)(url, {
      headers,
    });
    if (!response.ok) {
      console.error(await response.text());
      throw new TdfError(
        `auth info fail: GET [${url}] => ${response.status} ${response.statusText}`
      );
    }

    return (await response.json()) as unknown;
  }

  async doPost(url: string, o: Record<string, string>) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    };
    // add DPoP headers if configured
    if (this.config.dpopEnabled) {
      if (!this.signingKey) {
        throw new ConfigurationError('No signature configured');
      }
      const clientPubKey = await cryptoPublicToPem(this.signingKey.publicKey);
      headers['X-VirtruPubKey'] = base64.encode(clientPubKey);
      headers.DPoP = await dpopFn(this.signingKey, url, 'POST');
    }
    return (this.request || fetch)(url, {
      method: 'POST',
      headers,
      body: qstringify(o),
    });
  }

  async accessTokenLookup(cfg: OIDCCredentials): Promise<AccessTokenResponse & TimeStamp> {
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
      throw new TdfError(
        `token/code exchange fail: POST [${url}] => ${response.status} ${response.statusText}`
      );
    }
    const r = await response.json();
    r.when = Date.now();
    return r;
  }

  /**
   * Gets an access token; operates lazily/cached, with an optional check for freshness.
   * @param validate if we should run a inline check against the OIDC 'userinfo' endpoint to make sure any cached access token is still valid
   * @returns
   */
  async get(validate?: boolean): Promise<string> {
    let isNew = false;
    const now = Date.now();
    let currentData = this.data;
    if (!currentData) {
      currentData = this.accessTokenLookup(this.config);
      this.data = currentData;
      isNew = true;
    }
    let tokenResponse: AccessTokenResponse & TimeStamp;
    try {
      tokenResponse = await currentData;
    } catch (e) {
      // Failed during token exchange.
      if (this.data === currentData) {
        delete this.data;
      }
      throw e;
    }
    if (isNew) {
      // If we just did the first token exchange, we may have a refresh token.
      if (tokenResponse.refresh_token) {
        // Upgrade to refresh token type, if we have one
        this.config = {
          ...this.config,
          exchange: 'refresh',
          refreshToken: tokenResponse.refresh_token,
        };
      }
      return tokenResponse.access_token;
    }

    // Validate if explicitly requested or, if not defined, when the token is older than 5 minutes.
    if (!!validate || (validate === undefined && now - tokenResponse.when > 1000 * 60 * 5)) {
      try {
        await this.info(tokenResponse.access_token);
      } catch (e) {
        console.log('access_token fails on user_info endpoint; attempting to renew', e);
        if (this.data === currentData) {
          delete this.data;
        }
        return this.get(false);
      }
    }
    return tokenResponse.access_token;
  }

  /**
   * A TDF client MUST call this method whenever the client wants to use a new
   * ephemeral key set. This updates the keys used to:
   * or wishes to set the keypair after creating the object.
   *
   * Calling this function will trigger a forcible token refresh using the cached refresh token, and contact the auth server.
   */
  async refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey: CryptoKeyPair): Promise<void> {
    // If we already have a token, and the pubkey changes,
    // we need to force a refresh now - otherwise
    // we can wait until we create the token for the first time
    if (this.currentAccessToken && signingKey === this.signingKey) {
      return;
    }
    delete this.currentAccessToken;
    this.signingKey = signingKey;
  }

  /**
   * Converts included refresh token or external JWT for a new one.
   */
  async exchangeForRefreshToken(): Promise<void> {
    const cfg = this.config;
    if (cfg.exchange != 'external' && cfg.exchange != 'refresh') {
      throw new ConfigurationError('no refresh token provided!');
    }
    const tokenResponse = await (this.data = this.accessTokenLookup(this.config));
    if (!tokenResponse.refresh_token) {
      return;
    }
    // Prefer the latest refresh_token if present over creds passed in
    // to constructor, for token exchange. Refresh tokens usually stay the same.
    this.config = {
      ...this.config,
      exchange: 'refresh',
      refreshToken: tokenResponse.refresh_token,
    };
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    if (!this.signingKey) {
      throw new ConfigurationError(
        'Client public key was not set via `updateClientPublicKey` or passed in via constructor, cannot fetch OIDC token with valid Virtru claims'
      );
    }
    const accessToken = (this.currentAccessToken ??= await this.get());
    if (this.config.dpopEnabled && this.signingKey) {
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
