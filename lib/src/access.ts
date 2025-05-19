import { type AuthProvider } from './auth/auth.js';
import { ServiceError } from './errors.js';
import { RewrapResponse } from './platform/kas/kas_pb.js';
import { getPlatformUrlFromKasEndpoint, validateSecureUrl } from './utils.js';

import { fetchKeyAccessServers as fetchKeyAccessServersRpc } from './access/access-rpc.js';
import { fetchKeyAccessServers as fetchKeyAccessServersLegacy } from './access/access-fetch.js';
import { fetchWrappedKey as fetchWrappedKeysRpc } from './access/access-rpc.js';
import { fetchWrappedKey as fetchWrappedKeysLegacy } from './access/access-fetch.js';
import { fetchKasPubKey as fetchKasPubKeyRpc } from './access/access-rpc.js';
import { fetchKasPubKey as fetchKasPubKeyLegacy } from './access/access-fetch.js';

export type RewrapRequest = {
  signedRequestToken: string;
};

/**
 * Get a rewrapped access key to the document, if possible
 * @param url Key access server rewrap endpoint
 * @param requestBody a signed request with an encrypted document key
 * @param authProvider Authorization middleware
 * @param clientVersion
 */
export async function fetchWrappedKey(
  url: string,
  signedRequestToken: string,
  authProvider: AuthProvider
): Promise<RewrapResponse> {
  const platformUrl = getPlatformUrlFromKasEndpoint(url);

  return await tryPromisesUntilFirstSuccess(
    () => fetchWrappedKeysRpc(platformUrl, signedRequestToken, authProvider),
    () =>
      fetchWrappedKeysLegacy(
        url,
        { signedRequestToken },
        authProvider
      ) as unknown as Promise<RewrapResponse>
  );
}

export type KasPublicKeyAlgorithm = 'ec:secp256r1' | 'rsa:2048';

export const isPublicKeyAlgorithm = (a: string): a is KasPublicKeyAlgorithm => {
  return a === 'ec:secp256r1' || a === 'rsa:2048';
};

export const keyAlgorithmToPublicKeyAlgorithm = (a: KeyAlgorithm): KasPublicKeyAlgorithm => {
  if (a.name === 'ECDSA' || a.name === 'ECDH') {
    const eca = a as EcKeyAlgorithm;
    if (eca.namedCurve === 'P-256') {
      return 'ec:secp256r1';
    }
    throw new Error(`unsupported EC curve: ${eca.namedCurve}`);
  }
  if (a.name === 'RSA-OAEP') {
    const rsaa = a as RsaHashedKeyAlgorithm;
    if (rsaa.modulusLength === 2048) {
      // if (rsaa.hash.name !== 'RSASSA-PKCS1-v1_5') {
      //   throw new Error(`unsupported RSA hash: ${rsaa.hash.name}`);
      // }
      if (rsaa.publicExponent.toString() !== '1,0,1') {
        throw new Error(`unsupported RSA public exponent: ${rsaa.publicExponent}`);
      }
      return 'rsa:2048';
    }
  }
  throw new Error(`unsupported key algorithm: ${a.name}`);
};

export const publicKeyAlgorithmToJwa = (a: KasPublicKeyAlgorithm): string => {
  switch (a) {
    case 'ec:secp256r1':
      return 'ES256';
    case 'rsa:2048':
      return 'RS256';
  }
};

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

export async function noteInvalidPublicKey(url: URL, r: Promise<CryptoKey>): Promise<CryptoKey> {
  try {
    return await r;
  } catch (e) {
    if (e instanceof TypeError) {
      throw new ServiceError(`invalid public key from [${url}]`, e);
    }
    throw e;
  }
}

export async function fetchKeyAccessServers(
  platformUrl: string,
  authProvider: AuthProvider
): Promise<OriginAllowList> {
  return await tryPromisesUntilFirstSuccess(
    () => fetchKeyAccessServersRpc(platformUrl, authProvider),
    () => fetchKeyAccessServersLegacy(platformUrl, authProvider)
  );
}

/**
 * If we have KAS url but not public key we can fetch it from KAS, fetching
 * the value from `${kas}/kas_public_key`.
 */
export async function fetchECKasPubKey(kasEndpoint: string): Promise<KasPublicKeyInfo> {
  return fetchKasPubKey(kasEndpoint, 'ec:secp256r1');
}

export async function fetchKasPubKey(
  kasEndpoint: string,
  algorithm?: KasPublicKeyAlgorithm
): Promise<KasPublicKeyInfo> {
  return await tryPromisesUntilFirstSuccess(
    () => fetchKasPubKeyRpc(kasEndpoint, algorithm),
    () => fetchKasPubKeyLegacy(kasEndpoint, algorithm)
  );
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

/**
 * Tries two promise-returning functions in order and returns the first successful result.
 * If both fail, throws the error from the second.
 * @param first First function returning a promise to try.
 * @param second Second function returning a promise to try if the first fails.
 */
async function tryPromisesUntilFirstSuccess<T>(
  first: () => Promise<T>,
  second: () => Promise<T>
): Promise<T> {
  try {
    return await first();
  } catch {
    try {
      return await second();
    } catch (err) {
      throw err;
    }
  }
}
