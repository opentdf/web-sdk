import { KasPublicKeyAlgorithm, KasPublicKeyInfo, OriginAllowList } from '../access.js';
import { type AuthProvider, type HttpRequest } from '../auth/auth.js';
import { DPoPNonceCache, globalNonceCache } from '../auth/dpop-nonce.js';
import {
  ConfigurationError,
  InvalidFileError,
  NetworkError,
  PermissionDeniedError,
  ServiceError,
  UnauthenticatedError,
} from '../errors.js';
import { validateSecureUrl } from '../utils.js';

/** fetch() options shared by the authenticated legacy requests. */
type FetchInit = Omit<RequestInit, 'method' | 'headers' | 'body'>;

/**
 * Signs `httpReq` via the AuthProvider, sends it, and handles a single
 * DPoP-Nonce challenge (RFC 9449 §9): if a resource server rejects the request
 * with a fresh `DPoP-Nonce` header, cache the nonce and retry once so
 * `withCreds` can mint a proof carrying it. Non-DPoP providers and servers
 * never emit a `DPoP-Nonce`, so they take the single-request path unchanged.
 *
 * The caller keeps ownership of status-code handling; this only owns transport
 * and the nonce retry.
 */
async function fetchWithCredsAndNonceRetry(
  authProvider: AuthProvider,
  httpReq: HttpRequest,
  init: FetchInit,
  networkErrorMessage: string
): Promise<Response> {
  const send = async (): Promise<Response> => {
    const req = await authProvider.withCreds(httpReq);
    try {
      return await fetch(req.url, {
        ...init,
        method: req.method,
        headers: req.headers,
        body: req.body as BodyInit,
      });
    } catch (e) {
      throw new NetworkError(`${networkErrorMessage} [${req.url}]`, e);
    }
  };

  let origin: string | undefined;
  try {
    origin = new URL(httpReq.url).origin;
  } catch {
    // Non-absolute URL: nonce caching is keyed by origin, so just pass through.
  }

  let response = await send();

  if (!response.ok && origin) {
    const challengeNonce = DPoPNonceCache.extractNonce(response.headers);
    if (challengeNonce && challengeNonce !== globalNonceCache.get(origin)) {
      globalNonceCache.set(origin, challengeNonce);
      response = await send();
    }
  }

  // Keep the cache warm from whichever response we end on.
  if (origin) {
    const responseNonce = DPoPNonceCache.extractNonce(response.headers);
    if (responseNonce) {
      globalNonceCache.set(origin, responseNonce);
    }
  }

  return response;
}

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
  const response = await fetchWithCredsAndNonceRetry(
    authProvider,
    {
      url,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    } as HttpRequest,
    {
      mode: 'cors', // no-cors, *cors, same-origin
      cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
      credentials: 'same-origin', // include, *same-origin, omit
      redirect: 'follow', // manual, *follow, error
      referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
    },
    'unable to fetch wrapped key from'
  );

  if (!response.ok) {
    switch (response.status) {
      case 400:
        throw new InvalidFileError(
          `400 for [${url}]: rewrap bad request [${await response.text()}]`
        );
      case 401:
        throw new UnauthenticatedError(`401 for [${url}]; rewrap auth failure`);
      case 403:
        throw new PermissionDeniedError(`403 for [${url}]; rewrap permission denied`);
      default:
        if (response.status >= 500) {
          throw new ServiceError(
            `${response.status} for [${url}]: rewrap failure due to service error [${await response.text()}]`
          );
        }
        throw new NetworkError(`POST ${url} => ${response.status} ${response.statusText}`);
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
    const requestUrl = `${platformUrl}/key-access-servers?pagination.offset=${nextOffset}`;
    const response = await fetchWithCredsAndNonceRetry(
      authProvider,
      {
        url: requestUrl,
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      } as HttpRequest,
      {
        mode: 'cors',
        cache: 'no-cache',
        credentials: 'same-origin',
        redirect: 'follow',
        referrerPolicy: 'no-referrer',
      },
      'unable to fetch kas list from'
    );
    // if we get an error from the kas registry, throw an error
    if (!response.ok) {
      throw new ServiceError(
        `unable to fetch kas list from [${requestUrl}], status: ${response.status}`
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
