import { type AuthProvider } from './auth/auth.js';
import {
  InvalidFileError,
  NetworkError,
  PermissionDeniedError,
  ServiceError,
  TdfError,
  UnauthenticatedError,
} from './errors.js';
import { pemToCryptoPublicKey, validateSecureUrl } from './utils.js';

export class RewrapRequest {
  signedRequestToken = '';
}

export class RewrapResponse {
  entityWrappedKey = '';
  sessionPublicKey = '';
}

/**
 * Get a rewrapped access key to the document, if possible
 * @param url Key access server rewrap endpoint
 * @param requestBody a signed request with an encrypted document key
 * @param authProvider Authorization middleware
 * @param clientVersion
 */
export async function fetchWrappedKey(
  url: string,
  requestBody: RewrapRequest,
  authProvider: AuthProvider,
  clientVersion: string
): Promise<RewrapResponse> {
  const req = await authProvider.withCreds({
    url,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'virtru-ntdf-version': clientVersion,
    },
    body: JSON.stringify(requestBody),
  });

  try {
    const response = await fetch(req.url, {
      method: req.method,
      mode: 'cors', // no-cors, *cors, same-origin
      cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
      credentials: 'same-origin', // include, *same-origin, omit
      headers: req.headers,
      redirect: 'follow', // manual, *follow, error
      referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
      body: req.body as BodyInit,
    });

    if (!response.ok) {
      switch (response.status) {
        case 400:
          throw new InvalidFileError(
            `400 for [${req.url}]: rewrap failure [${await response.text()}]`
          );
        case 401:
          throw new UnauthenticatedError(`401 for [${req.url}]`);
        case 403:
          throw new PermissionDeniedError(`403 for [${req.url}]`);
        default:
          throw new NetworkError(
            `${req.method} ${req.url} => ${response.status} ${response.statusText}`
          );
      }
    }

    return response.json();
  } catch (e) {
    throw new NetworkError(`unable to fetch wrapped key from [${url}]: ${e}`);
  }
}

export type KasPublicKeyAlgorithm = 'ec:secp256r1' | 'rsa:2048';

/**
 * Information about one of a KAS's published public keys.
 * A KAS may publish multiple keys with a given algorithm type.
 */
export type KasPublicKeyInfo = {
  /** The locator to the given KAS associated with this key */
  url: string;

  /** The encryption algorithm the key is to be used with. */
  algorithm: KasPublicKeyAlgorithm;

  /** If present, an identifier which is tied to this specific key. */
  kid?: string;

  /** The key value, encoded within a PEM envelope */
  publicKey: string;

  /** A subtle crypto version of the key.
   * This can be used for wrapping key data for key access objects (with RSA)
   * or to derive key data (with EC keys). */
  key: Promise<CryptoKey>;
};

async function noteInvalidPublicKey(url: string, r: Promise<CryptoKey>): Promise<CryptoKey> {
  try {
    return await r;
  } catch (e) {
    if (e instanceof TypeError) {
      throw new ServiceError(`invalid public key from [${url}]`, e);
    }
    throw e;
  }
}

/**
 * If we have KAS url but not public key we can fetch it from KAS, fetching
 * the value from `${kas}/kas_public_key`.
 */
export async function fetchECKasPubKey(kasEndpoint: string): Promise<KasPublicKeyInfo> {
  validateSecureUrl(kasEndpoint);
  const pkUrlV2 = `${kasEndpoint}/v2/kas_public_key?algorithm=ec:secp256r1&v=2`;
  const kasPubKeyResponseV2 = await fetch(pkUrlV2);
  if (!kasPubKeyResponseV2.ok) {
    switch (kasPubKeyResponseV2.status) {
      case 404:
        // v2 not implemented, perhaps a legacy server
        break;
      case 401:
        throw new UnauthenticatedError(`401 for [${pkUrlV2}]`);
      case 403:
        throw new PermissionDeniedError(`403 for [${pkUrlV2}]`);
      default:
        throw new NetworkError(
          `${pkUrlV2} => ${kasPubKeyResponseV2.status} ${kasPubKeyResponseV2.statusText}`
        );
    }
    // most likely a server that does not implement v2 endpoint, so no key identifier
    const pkUrlV1 = `${kasEndpoint}/kas_public_key?algorithm=ec:secp256r1`;
    const r2 = await fetch(pkUrlV1);
    if (!r2.ok) {
      switch (r2.status) {
        case 401:
          throw new UnauthenticatedError(`401 for [${pkUrlV2}]`);
        case 403:
          throw new PermissionDeniedError(`403 for [${pkUrlV2}]`);
        default:
          throw new NetworkError(
            `unable to load KAS public key from [${pkUrlV1}]. Received [${r2.status}:${r2.statusText}]`
          );
      }
    }
    const pem = await r2.json();
    return {
      key: noteInvalidPublicKey(pkUrlV1, pemToCryptoPublicKey(pem)),
      publicKey: pem,
      url: kasEndpoint,
      algorithm: 'ec:secp256r1',
    };
  }
  const jsonContent = await kasPubKeyResponseV2.json();
  const { publicKey, kid }: KasPublicKeyInfo = jsonContent;
  if (!publicKey) {
    throw new NetworkError(
      `invalid response from public key endpoint [${JSON.stringify(jsonContent)}]`
    );
  }
  return {
    key: noteInvalidPublicKey(pkUrlV2, pemToCryptoPublicKey(publicKey)),
    publicKey,
    url: kasEndpoint,
    algorithm: 'ec:secp256r1',
    ...(kid && { kid }),
  };
}

const origin = (u: string): string => {
  try {
    return new URL(u).origin;
  } catch (e) {
    console.log(`invalid kas url: [${u}]`);
    throw e;
  }
};

export class OriginAllowList {
  origins: string[];
  allowAll: boolean;
  constructor(urls: string[], allowAll?: boolean) {
    this.origins = urls.map(origin);
    urls.forEach(validateSecureUrl);
    this.allowAll = !!allowAll;
  }
  allows(url: string): boolean {
    if (this.allowAll) {
      return true;
    }
    return this.origins.includes(origin(url));
  }
}
