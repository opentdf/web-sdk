import { KasPublicKeyAlgorithm, KasPublicKeyInfo, OriginAllowList } from '../access.js';
import { type AuthProvider } from '../auth/auth.js';
import {
  ConfigurationError,
  InvalidFileError,
  NetworkError,
  PermissionDeniedError,
  ServiceError,
  TokenExpiredError,
  UnauthenticatedError,
} from '../errors.js';
import { readJwtExpMs } from '../auth/interceptors.js';
import { validateSecureUrl } from '../utils.js';

export type RewrapRequest = {
  signedRequestToken: string;
};

export type RewrapResponseLegacy = {
  metadata: Record<string, unknown>;
  entityWrappedKey: string;
  sessionPublicKey: string;
  schemaVersion: string;
};

/**
 * Classify a rewrap 401. When the `Authorization` header this SDK STAMPED on the request
 * carries a JWT that was already expired (by local clock) as the request went out, the 401
 * is the well-known static-token-provider footgun — surfaced as {@link TokenExpiredError},
 * which has a clear recovery path (refresh the token and retry) and must not be conflated
 * with an authorization denial. Anything else — an opaque token, an unreadable JWT, a
 * still-valid `exp` — classifies as the generic {@link UnauthenticatedError}: an expired
 * stamp is the ONLY trigger, so the specific error is zero-false-positive.
 */
function classifyRewrap401(
  headers: Record<string, string> | undefined,
  url: string
): UnauthenticatedError {
  const auth = headers?.['Authorization'] ?? headers?.['authorization'];
  const match = typeof auth === 'string' ? auth.match(/^(?:Bearer|DPoP)\s+(.+)$/i) : null;
  const expMs = match ? readJwtExpMs(match[1]) : undefined;
  if (expMs !== undefined && expMs <= Date.now()) {
    return new TokenExpiredError(
      `401 for [${url}]; rewrap auth failure: the stamped access token was already EXPIRED — ` +
        'refresh it and retry (see refreshTokenProvider / clientCredentialsTokenProvider / ' +
        'externalJwtTokenProvider)'
    );
  }
  return new UnauthenticatedError(`401 for [${url}]; rewrap auth failure`);
}

/**
 * Get a rewrapped access key to the document, if possible
 * @param url Key access server rewrap endpoint
 * @param requestBody a signed request with an encrypted document key
 * @param authProvider Authorization middleware
 * @param rewrapAdditionalContextHeader optional value for 'X-Rewrap-Additional-Context'
 */
export async function fetchWrappedKey(
  url: string,
  requestBody: RewrapRequest,
  authProvider: AuthProvider
): Promise<RewrapResponseLegacy> {
  const req = await authProvider.withCreds({
    url,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestBody),
  });

  let response: Response;

  try {
    response = await fetch(req.url, {
      method: req.method,
      mode: 'cors', // no-cors, *cors, same-origin
      cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
      credentials: 'same-origin', // include, *same-origin, omit
      headers: req.headers,
      redirect: 'follow', // manual, *follow, error
      referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
      body: req.body as BodyInit,
    });
  } catch (e) {
    throw new NetworkError(`unable to fetch wrapped key from [${url}]`, e);
  }

  if (!response.ok) {
    switch (response.status) {
      case 400:
        throw new InvalidFileError(
          `400 for [${req.url}]: rewrap bad request [${await response.text()}]`
        );
      case 401:
        // Distinguish the static-token-provider footgun (expired stamp -> TokenExpiredError,
        // recoverable by refresh+retry) from a generic auth failure. See classifyRewrap401.
        throw classifyRewrap401(req.headers, req.url);
      case 403:
        throw new PermissionDeniedError(
          `403 for [${req.url}]; rewrap permission denied: forbidden`
        );
      default:
        if (response.status >= 500) {
          throw new ServiceError(
            `${response.status} for [${req.url}]: rewrap failure due to service error [${await response.text()}]`
          );
        }
        throw new NetworkError(
          `${req.method} ${req.url} => ${response.status} ${response.statusText}`
        );
    }
  }

  return response.json();
}

export async function fetchKeyAccessServers(
  platformUrl: string,
  authProvider: AuthProvider
): Promise<OriginAllowList> {
  let nextOffset = 0;
  const allServers = [];
  do {
    const req = await authProvider.withCreds({
      url: `${platformUrl}/key-access-servers?pagination.offset=${nextOffset}`,
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    let response: Response;
    try {
      response = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body as BodyInit,
        mode: 'cors',
        cache: 'no-cache',
        credentials: 'same-origin',
        redirect: 'follow',
        referrerPolicy: 'no-referrer',
      });
    } catch (e) {
      throw new NetworkError(`unable to fetch kas list from [${req.url}]`, e);
    }
    // if we get an error from the kas registry, throw an error
    if (!response.ok) {
      throw new ServiceError(
        `unable to fetch kas list from [${req.url}], status: ${response.status}`
      );
    }
    const { keyAccessServers = [], pagination = {} } = await response.json();
    allServers.push(...keyAccessServers);
    nextOffset = pagination.nextOffset || 0;
  } while (nextOffset > 0);

  const serverUrls = allServers.map((server) => server.uri);
  // add base platform kas
  if (!serverUrls.includes(`${platformUrl}/kas`)) {
    serverUrls.push(`${platformUrl}/kas`);
  }

  return new OriginAllowList(serverUrls, false);
}

export async function fetchKasPubKey(
  kasEndpoint: string,
  algorithm?: KasPublicKeyAlgorithm
): Promise<KasPublicKeyInfo> {
  if (!kasEndpoint) {
    throw new ConfigurationError('KAS definition not found');
  }
  // Logs insecure KAS. Secure is enforced in constructor
  validateSecureUrl(kasEndpoint);

  // Parse kasEndpoint to URL, then append to its path and update its query parameters
  let pkUrlV2: URL;
  try {
    pkUrlV2 = new URL(kasEndpoint);
  } catch (e) {
    throw new ConfigurationError(`KAS definition invalid: [${kasEndpoint}]`, e);
  }
  if (!pkUrlV2.pathname.endsWith('kas_public_key')) {
    if (!pkUrlV2.pathname.endsWith('/')) {
      pkUrlV2.pathname += '/';
    }
    pkUrlV2.pathname += 'v2/kas_public_key';
  }
  pkUrlV2.searchParams.set('algorithm', algorithm || 'rsa:2048');
  if (!pkUrlV2.searchParams.get('v')) {
    pkUrlV2.searchParams.set('v', '2');
  }

  let kasPubKeyResponseV2: Response;
  try {
    kasPubKeyResponseV2 = await fetch(pkUrlV2);
  } catch (e) {
    throw new NetworkError(`unable to fetch public key from [${pkUrlV2}]`, e);
  }
  if (!kasPubKeyResponseV2.ok) {
    switch (kasPubKeyResponseV2.status) {
      case 404:
        throw new ConfigurationError(`404 for [${pkUrlV2}]`);
      case 401:
        throw new UnauthenticatedError(`401 for [${pkUrlV2}]`);
      case 403:
        throw new PermissionDeniedError(`403 for [${pkUrlV2}]`);
      default:
        throw new NetworkError(
          `${pkUrlV2} => ${kasPubKeyResponseV2.status} ${kasPubKeyResponseV2.statusText}`
        );
    }
  }
  const jsonContent = await kasPubKeyResponseV2.json();
  const { publicKey, kid }: KasPublicKeyInfo = jsonContent;
  if (!publicKey) {
    throw new NetworkError(
      `invalid response from public key endpoint [${JSON.stringify(jsonContent)}]`
    );
  }
  return {
    publicKey,
    url: kasEndpoint,
    algorithm: algorithm || 'rsa:2048',
    ...(kid && { kid }),
  };
}
