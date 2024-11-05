import { decodeJwt } from 'jose';
import { default as dpopFn } from 'dpop';
import { base64 } from '@opentdf/sdk/encodings';
import { AuthProvider, HttpRequest, withHeaders } from '@opentdf/sdk';

export type OpenidConfiguration = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  scopes_supported: string[];
};

export type AuthorizationError =
  // the request is missing a parameter, contains an invalid parameter, includes a parameter more than once, or is otherwise invalid.
  | 'invalid_request'
  // the user or authorization server denied the request
  | 'access_denied'
  // the client is not allowed to request an authorization code using this method, for example if a confidential client attempts to use the implicit grant type.
  | 'unauthorized_client'
  // the server does not support obtaining an authorization code using this method, for example if the authorization server never implemented the implicit grant type.
  | 'unsupported_response_type'
  // the requested scope is invalid or unknown.
  | 'invalid_scope'
  // instead of displaying a 500 Internal Server Error page to the user, the server can redirect with this error code.
  | 'server_error'
  // if the server is undergoing maintenance, or is otherwise unavailable, this error code can be returned instead of responding with a 503 Service Unavailable status code.
  | 'temporarily_unavailable';

type AuthorizationResponseSuccess = {
  _: 'OK';
  code: string;
  state: string;
};
type AuthorizationResponseError = {
  _: 'FAIL';
  error: AuthorizationError;
  error_description: string;
};
type AuthorizationResponse = AuthorizationResponseError | AuthorizationResponseSuccess;

/**
 * Response returned from a successful token endpoint request
 */
export type TokenResponse = {
  access_token: string;
  expires_in: number;
  id_token: string;
  refresh_token: string;
};

/**
 * Authenticated user details
 */
export type User = {
  userId: string;
  accessToken: string;
  expiresAt: number;
  idToken: string;
  refreshToken: string;
};

/**
 * start -> redirecting -> { error | loggedin }
 */
export type SessionState = 'start' | 'loggedin' | 'redirecting' | 'error';

export type SessionInformation = {
  /** Current state diagram position */
  sessionState: SessionState;
  /** User info, if possible */
  user?: User;
};

type AuthRequestState = SessionInformation & {
  redirectUri: string;
  /** Random state parameter. Unique per redirect request; can identify them. Proves the redirect is for the correct request. */
  state: string;
  /** Random code verifier parameter for PKCE. Unique per redirect request. Semi-secret. Proves the code exchange is for the same client session. */
  codeVerifier: string;
  /** When this started */
  start: number;
  /** Auth Codes */
  usedCodes: string[];
};

export type Sessions = {
  config: OpenidConfiguration;
  /** state -> auth request */
  requests: Record<string, AuthRequestState>;
  /** state for most recent request */
  lastRequest?: string;
  /** DPoP key */
  k?: string[];
};

function getTimestampInSeconds() {
  return Math.floor(Date.now() / 1000);
}

function rsaPkcs1Sha256(): RsaHashedKeyGenParams {
  return {
    name: 'RSASSA-PKCS1-v1_5',
    hash: {
      name: 'SHA-256',
    },
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 24 bit representation of 65537
  };
}

const extractAuthorizationResponse = (url: string): AuthorizationResponse | null => {
  const queryParams = new URLSearchParams(url);
  console.log(`response: ${JSON.stringify(queryParams.toString())}`);
  // state=ApkI9hDcVp8nIOZq4rqxM65mv_mEQDUEHTulLFt9jRA
  // &session_state=96a991a3-e94f-456d-8c85-75904e1fbdbb
  // &code=c0a1fc73-f2c5-4182-a9de-2569c55cc878.96a991a3-e94f-456d-8c85-75904e1fbdbb.b4877ed3-6dc1-41f1-b6ca-d9efdb7d8d7f
  const error = queryParams.get('error');
  if (error) {
    const s = queryParams.get('state');
    if (s) {
      console.log(`state: {s}`);
    }
    return {
      _: 'FAIL',
      error: error as AuthorizationError,
      error_description: queryParams.get('error_description') || '',
    };
  }
  const code = queryParams.get('code');
  const state = queryParams.get('state');
  if (code || state) {
    if (!code || !state) {
      throw new Error('Invalid response state');
    }
    return {
      _: 'OK',
      code,
      state,
    };
  }
  return null;
};

function createCodeVerifier(): string {
  const r = new Uint8Array(32);
  crypto.getRandomValues(r);
  const verifier = base64.encodeArrayBuffer(r, true);
  return verifier;
}

async function createCodeChallenge(code: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code));
  return base64.encodeArrayBuffer(hash, true);
}

async function fetchConfig(server: string): Promise<unknown> {
  const response = await fetch(`${server}/.well-known/openid-configuration`, {
    headers: {
      accept: 'application/json',
    },
  });
  if (!response.ok) {
    throw new Error(response.statusText);
  }
  return response.json();
}

export class OidcClient implements AuthProvider {
  clientId: string;
  host: string;
  scope: string;
  sessionIdentifier: string;
  _sessions?: Sessions;
  signingKey?: CryptoKeyPair;

  constructor(host: string, clientId: string, sessionIdentifier: string) {
    this.clientId = clientId;
    this.host = host;
    this.sessionIdentifier = sessionIdentifier;
    this.scope = 'openid profile email offline_access';
  }

  ssk(key: string): string {
    return `${this.host}-${this.sessionIdentifier}-${key}`;
  }

  async loadSessions(): Promise<Sessions> {
    if (this._sessions) {
      return this._sessions;
    }
    const key = this.ssk('sessions');
    const rawData = sessionStorage.getItem(key);
    if (rawData) {
      return (this._sessions = JSON.parse(rawData));
    }
    const config = (await fetchConfig(this.host)) as OpenidConfiguration;
    console.log(config);
    this._sessions = {
      config,
      requests: {},
    };
    sessionStorage.setItem(key, JSON.stringify(this._sessions));
    return this._sessions;
  }

  storeSessions() {
    sessionStorage.setItem(this.ssk('sessions'), JSON.stringify(this._sessions));
  }

  /**
   * Initiate a login flow with PKCE and code. By default, this will result in
   * a page reaload of the current page (or a load of the redirect page) with the
   * oidc response in the URL parameters (either state and code for success or
   * optionally error and error_description for failures).
   *
   * So whenever loading the page, check for the redirect parameters
   * and do something good with them as appropriate.
   *
   * @param redirectUri Where to return the user to after a successful login. Defaults to current location
   */
  async authViaRedirect(redirectUri?: string) {
    const codeVerifier = createCodeVerifier();
    const sessions = await this.loadSessions();
    const newSession: AuthRequestState = {
      sessionState: 'redirecting',
      // just use 32 random bytes for state as well. This should be safe
      state: createCodeVerifier(),
      redirectUri: redirectUri || window.location.href.split('?')[0],
      codeVerifier,
      start: getTimestampInSeconds(),
      usedCodes: [],
    };
    sessions.lastRequest = newSession.state;
    sessions.requests[newSession.state] = newSession;
    this.storeSessions();

    const args = new URLSearchParams({
      client_id: this.clientId,
      code_challenge: await createCodeChallenge(newSession.codeVerifier),
      code_challenge_method: 'S256',
      redirect_uri: newSession.redirectUri,
      response_type: 'code',
      scope: this.scope,
      state: newSession.state,
    });
    const whereto = `${sessions.config.authorization_endpoint}/?${args}`;
    console.log('Navigating to ', whereto);
    window.location.href = whereto;
  }

  _cs?: Promise<SessionInformation>;

  async currentSession(): Promise<SessionInformation> {
    if (!this._cs) {
      this._cs = (async (): Promise<SessionInformation> => {
        const s = await this.handleRedirect();
        if (s) {
          console.log('redirected');
          return s;
        }
        const sessions = await this.loadSessions();
        if (!sessions?.lastRequest) {
          return { sessionState: 'start' };
        }
        const thisSession = sessions.requests[sessions.lastRequest];
        return thisSession;
      })();
    }
    return this._cs;
  }

  async currentUser(): Promise<User | undefined> {
    return (await this.currentSession()).user;
  }

  async handleRedirect(): Promise<AuthRequestState | undefined> {
    const response = extractAuthorizationResponse(window.location.search);
    if (!response) {
      return;
    }
    const sessions = await this.loadSessions();
    if (response._ === 'FAIL') {
      throw new Error(`OIDC auth ${response.error || 'error'}: [${response.error_description}]`);
    }
    const currentSession = sessions.requests[response.state];
    if (!currentSession) {
      throw new Error(`OIDC auth error: session storage missing state for ${response}`);
    }
    const usedRedirectCodes = currentSession.usedCodes;
    console.log('redirect response:', response, usedRedirectCodes);
    if (usedRedirectCodes.includes(response.code)) {
      console.log('Ignoring repeated redirect code');
      return;
    }
    currentSession.usedCodes.push(response.code);
    this.storeSessions();
    try {
      currentSession.user = await this._makeAccessTokenRequest({
        grantType: 'authorization_code',
        codeOrRefreshToken: response.code,
        codeVerifier: currentSession.codeVerifier,
        redirectUri: currentSession.redirectUri,
      });
      currentSession.sessionState = 'loggedin';
      this.storeSessions();
      return currentSession;
    } finally {
      // no catch needed as we want error to be thrown
      // history state should still be cleaned up regardless
      window.history.replaceState({}, '', window.location.pathname);
    }
  }

  async getSigningKey(): Promise<CryptoKeyPair> {
    if (this.signingKey) {
      return this.signingKey;
    }
    if (this._sessions?.k) {
      const k = this._sessions?.k.map((e) => base64.decodeArrayBuffer(e));
      const algorithm = rsaPkcs1Sha256();
      const [publicKey, privateKey] = await Promise.all([
        crypto.subtle.importKey('spki', k[0], algorithm, true, ['verify']),
        crypto.subtle.importKey('pkcs8', k[1], algorithm, true, ['sign']),
      ]);
      this.signingKey = { privateKey, publicKey };
    } else {
      this.signingKey = await crypto.subtle.generateKey(rsaPkcs1Sha256(), true, ['sign']);
    }
    return this.signingKey;
  }

  private async _makeAccessTokenRequest(options: {
    grantType: 'authorization_code' | 'refresh_token';
    codeOrRefreshToken: string;
    codeVerifier: string;
    redirectUri: string;
  }): Promise<User> {
    const params = new URLSearchParams();
    params.set('client_id', this.clientId);
    params.set('redirect_uri', options.redirectUri);
    params.set('grant_type', options.grantType);

    if (options.grantType === 'authorization_code') {
      params.set('code', options.codeOrRefreshToken);
    } else {
      params.set('refresh_token', options.codeOrRefreshToken);
    }

    params.set('code_verifier', options.codeVerifier);
    params.set('scope', this.scope);

    const config = this._sessions?.config;
    if (!config) {
      throw new Error('Unable to autoconfigure OIDC');
    }
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };
    const signingKey = await this.getSigningKey();
    if (this._sessions && this.signingKey) {
      const k = await Promise.all([
        crypto.subtle.exportKey('spki', this.signingKey.publicKey),
        crypto.subtle.exportKey('pkcs8', this.signingKey.privateKey),
      ]);
      this._sessions.k = k.map((e) => base64.encodeArrayBuffer(e));
    }
    console.info(
      `signing token request with DPoP key ${JSON.stringify(
        await crypto.subtle.exportKey('jwk', signingKey.publicKey)
      )}`
    );
    headers.DPoP = await dpopFn(signingKey, config.token_endpoint, 'POST');
    const response = await fetch(config.token_endpoint, {
      method: 'POST',
      headers,
      body: params,
      credentials: 'include',
    });
    if (!response.ok) {
      throw new Error(response.statusText);
    }
    const { access_token, expires_in, id_token, refresh_token } = await response.json();

    const { virtru_user_id } = decodeJwt(access_token);

    return {
      userId: virtru_user_id as string,
      accessToken: access_token,
      expiresAt: new Date().getTime() + expires_in * 1000,
      idToken: id_token,
      refreshToken: refresh_token,
    };
  }

  async updateClientPublicKey(signingKey: CryptoKeyPair): Promise<void> {
    this.signingKey = signingKey;
  }

  async withCreds(httpReq: HttpRequest): Promise<HttpRequest> {
    const user = await this.currentUser();
    if (!user) {
      console.error('Not logged in');
      return httpReq;
    }
    const { accessToken } = user;
    const { signingKey } = this;
    if (!signingKey || !signingKey.publicKey) {
      console.error('missing DPoP key');
      return httpReq;
    }
    console.info(
      `signing request for ${httpReq.url} with DPoP key ${JSON.stringify(
        await crypto.subtle.exportKey('jwk', signingKey.publicKey)
      )}`
    );
    const dpopToken = await dpopFn(
      signingKey,
      httpReq.url,
      httpReq.method,
      /* nonce */ undefined,
      accessToken
    );
    // TODO: Consider: only set DPoP if cnf.jkt is present in access token?
    return withHeaders(httpReq, { Authorization: `Bearer ${accessToken}`, DPoP: dpopToken });
  }
}
