import { decodeJwt } from 'jose';
import { base64 } from '@opentdf/client/encodings';

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
};

function getTimestampInSeconds() {
  return Math.floor(Date.now() / 1000);
}

const extractAuthorizationResponse = (url: string): AuthorizationResponse | null => {
  const queryParams = new URLSearchParams(window.location.search);
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

export class OidcClient {
  clientId: string;
  host: string;
  scope: string;
  sessionIdentifier: string;
  _sessions?: Sessions;

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

  async storeSessions() {
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

  async currentSession(): Promise<SessionInformation> {
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

    const response = await fetch(this._sessions?.config.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
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
}
