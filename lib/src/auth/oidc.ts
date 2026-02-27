import { default as dpopFn } from './dpop.js';
import { HttpRequest, withHeaders } from './auth.js';
import { base64 } from '../encodings/index.js';
import { ConfigurationError, TdfError } from '../errors.js';
import { rstrip } from '../utils.js';
import { type CryptoService, type PemKeyPair } from '../../tdf3/src/crypto/declarations.js';

/**
 * Common fields used by all OIDC credentialing flows.
 */
export type CommonCredentials = {
  /** The OIDC client ID used for token issuance and exchange flows */
  clientId: string;
  /** The endpoint of the OIDC IdP to authenticate against, ex. 'https://virtru.com/auth' */
  oidcOrigin: string;
  oidcTokenEndpoint?: string;
  oidcUserInfoEndpoint?: string;
  /** Whether or not DPoP is enabled. */
  dpopEnabled?: boolean;

  /** the client's public key, base64 encoded. Will be bound to the OIDC token. Deprecated. If not set in the constructor, */
  signingKey?: PemKeyPair;
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
  tokenEndpoint: string;
  userInfoEndpoint: string;

  signingKey?: PemKeyPair;

  extraHeaders: Record<string, string> = {};

  currentAccessToken?: string;

  cryptoService: CryptoService;

  constructor(cfg: OIDCCredentials, cryptoService: CryptoService, request?: typeof fetch) {
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
    this.cryptoService = cryptoService;
    this.request = request;
    this.baseUrl = rstrip(cfg.oidcOrigin, '/');
    this.tokenEndpoint = cfg.oidcTokenEndpoint || `${this.baseUrl}/protocol/openid-connect/token`;
    this.userInfoEndpoint =
      cfg.oidcUserInfoEndpoint || `${this.baseUrl}/protocol/openid-connect/userinfo`;
    this.signingKey = cfg.signingKey;
  }

  /**
   * https://connect2id.com/products/server/docs/api/userinfo
   * @param accessToken the current access_token or code
   * @returns
   */
  async info(accessToken: string): Promise<unknown> {
    const headers = {
      ...this.extraHeaders,
      Authorization: `Bearer ${accessToken}`,
    } as Record<string, string>;
    if (this.config.dpopEnabled && this.signingKey) {
      headers.DPoP = await dpopFn(
        this.signingKey,
        this.cryptoService,
        this.userInfoEndpoint,
        'POST'
      );
    }
    const response = await (this.request || fetch)(this.userInfoEndpoint, {
      headers,
    });
    if (!response.ok) {
      console.error(await response.text());
      throw new TdfError(
        `auth info fail: GET [${this.userInfoEndpoint}] => ${response.status} ${response.statusText}`
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
      // signingKey.publicKey is already PEM format
      headers['X-VirtruPubKey'] = base64.encode(this.signingKey.publicKey);
      headers.DPoP = await dpopFn(this.signingKey, this.cryptoService, url, 'POST');
    }
    return (this.request || fetch)(url, {
      method: 'POST',
      headers,
      body: qstringify(o),
    });
  }

  async accessTokenLookup(cfg: OIDCCredentials) {
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
    const response = await this.doPost(this.tokenEndpoint, body);
    if (!response.ok) {
      console.error(await response.text());
      throw new TdfError(
        `token/code exchange fail: POST [${this.tokenEndpoint}] => ${response.status} ${response.statusText}`
      );
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
        if (this.data?.refresh_token) {
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
  async refreshTokenClaimsWithClientPubkeyIfNeeded(signingKey: PemKeyPair): Promise<void> {
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
  async exchangeForRefreshToken(): Promise<string> {
    const cfg = this.config;
    if (cfg.exchange != 'external' && cfg.exchange != 'refresh') {
      throw new ConfigurationError('no refresh token provided!');
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
    if (!this.signingKey) {
      throw new ConfigurationError(
        'Client public key was not set via `updateClientPublicKey` or passed in via constructor, cannot fetch OIDC token with valid Virtru claims'
      );
    }
    const accessToken = (this.currentAccessToken ??= await this.get());
    if (this.config.dpopEnabled && this.signingKey) {
      // Convert PEM to CryptoKeyPair for dpop library (dpop requires Web Crypto keys)
      const cryptoKeyPair = await toCryptoKeyPair(this.signingKey);
      const dpopToken = await dpopFn(
        this.signingKey,
        this.cryptoService,
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
