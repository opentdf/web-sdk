import { type AuthProvider } from './auth/auth.js';
import { ServiceError } from './errors.js';
import { RewrapResponse } from './platform/kas/kas_pb.js';
import { getPlatformUrlFromKasEndpoint, validateSecureUrl } from './utils.js';
import { base64 } from './encodings/index.js';

import {
  fetchKasBasePubKey,
  fetchKeyAccessServers as fetchKeyAccessServersRpc,
} from './access/access-rpc.js';
import { fetchKeyAccessServers as fetchKeyAccessServersLegacy } from './access/access-fetch.js';
import { fetchWrappedKey as fetchWrappedKeysRpc } from './access/access-rpc.js';
import { fetchWrappedKey as fetchWrappedKeysLegacy } from './access/access-fetch.js';
import { fetchKasPubKey as fetchKasPubKeyRpc } from './access/access-rpc.js';
import { fetchKasPubKey as fetchKasPubKeyLegacy } from './access/access-fetch.js';

/**
 * Header value structure for 'X-Rewrap-Additional-Context`
*/
export type RewrapAdditionalContext = {
  obligations: {
    fqns: string[];
  }
}

export type RewrapRequest = {
  signedRequestToken: string;
};

/**
 * Get a rewrapped access key to the document, if possible
 * @param url Key access server rewrap endpoint
 * @param requestBody a signed request with an encrypted document key
 * @param authProvider Authorization middleware
 * @param rewrapAdditionalContextHeader optional value for 'X-Rewrap-Additional-Context'
 * @param clientVersion
 */
export async function fetchWrappedKey(
  url: string,
  signedRequestToken: string,
  authProvider: AuthProvider,
  rewrapAdditionalContextHeader?: string
): Promise<RewrapResponse> {
  const platformUrl = getPlatformUrlFromKasEndpoint(url);

  return await tryPromisesUntilFirstSuccess(
    () => fetchWrappedKeysRpc(platformUrl, signedRequestToken, authProvider, rewrapAdditionalContextHeader),
    () =>
      fetchWrappedKeysLegacy(
        url,
        { signedRequestToken },
        authProvider
      ) as unknown as Promise<RewrapResponse>
  );
}

/**
 * Transform fulfillable, fully-qualified obligations into the expected KAS Rewrap 'X-Rewrap-Additional-Context' header value.
 * @param fulfillableObligationValueFQNs 
 */
export const rewrapAdditionalContextHeader = (fulfillableObligationValueFQNs?: string[]): string | undefined => {
  if (!fulfillableObligationValueFQNs) return;

  const context: RewrapAdditionalContext = {
    obligations: {
      fqns: fulfillableObligationValueFQNs,
    }
  };
  return base64.encode(JSON.stringify(context));
}

export type KasPublicKeyAlgorithm =
  | 'ec:secp256r1'
  | 'ec:secp384r1'
  | 'ec:secp521r1'
  | 'rsa:2048'
  | 'rsa:4096';

export const isPublicKeyAlgorithm = (a: string): a is KasPublicKeyAlgorithm => {
  return a === 'ec:secp256r1' || a === 'rsa:2048';
};

export const keyAlgorithmToPublicKeyAlgorithm = (k: CryptoKey): KasPublicKeyAlgorithm => {
  const a = k.algorithm;
  if (a.name === 'ECDSA' || a.name === 'ECDH') {
    const eca = a as EcKeyAlgorithm;
    switch (eca.namedCurve) {
      case 'P-256':
        return 'ec:secp256r1';
      case 'P-384':
        return 'ec:secp384r1';
      case 'P-521':
        return 'ec:secp521r1';
      default:
        throw new Error(`unsupported EC curve: ${eca.namedCurve}`);
    }
  }
  if (a.name === 'RSA-OAEP' || a.name === 'RSASSA-PKCS1-v1_5') {
    const rsaa = a as RsaHashedKeyAlgorithm;
    if (rsaa.publicExponent.toString() !== '1,0,1') {
      throw new Error(`unsupported RSA public exponent: ${rsaa.publicExponent}`);
    }
    switch (rsaa.modulusLength) {
      case 2048:
        return 'rsa:2048';
      case 4096:
        return 'rsa:4096';
      default:
        throw new Error(`unsupported RSA modulus length: ${rsaa.modulusLength}`);
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
    case 'rsa:4096':
      return 'RS512';
    case 'ec:secp384r1':
      return 'ES384';
    case 'ec:secp521r1':
      return 'ES512';
    default:
      throw new Error(`unsupported public key algorithm: ${a}`);
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

/**
 * Fetches the key access servers for a given platform URL.
 * @param platformUrl The platform URL to fetch key access servers for.
 * @param authProvider The authentication provider to use for the request.
 * @returns A promise that resolves to an OriginAllowList.
 */
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
 * Fetch the EC (secp256r1) public key for a KAS endpoint.
 * @param kasEndpoint The KAS endpoint URL.
 * @returns The public key information for the KAS endpoint.
 */
export async function fetchECKasPubKey(kasEndpoint: string): Promise<KasPublicKeyInfo> {
  return fetchKasPubKey(kasEndpoint, 'ec:secp256r1');
}

/**
 * Fetch the public key for a KAS endpoint.
 * This function will first try to fetch the base public key,
 * then it will try to fetch the public key using the RPC method,
 * and finally it will try to fetch the public key using the legacy method.
 * If all attempts fail, it will return the error from RPC Public Key fetch.
 * @param kasEndpoint The KAS endpoint URL.
 * @param algorithm Optional algorithm to fetch the public key for.
 * @returns The public key information.
 */
export async function fetchKasPubKey(
  kasEndpoint: string,
  algorithm?: KasPublicKeyAlgorithm
): Promise<KasPublicKeyInfo> {
  try {
    return await fetchKasBasePubKey(kasEndpoint);
  } catch (e) {
    console.log(e);
  }

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

/**
 * Manages a list of origins that are allowed to access the Key Access Server (KAS).
 * @origins A list of origins that are allowed to access the KAS.
 * @allowAll If true, all origins are allowed to access the KAS.
 * If false, only the origins in the list are allowed to access the KAS.
 * @description This class is used to manage a list of origins that are allowed to access the KAS.
 * It validates the URLs and provides a method to check if a given URL is allowed.
 * It is used to ensure that only authorized origins can access the KAS.
 */
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
  } catch (e1) {
    console.info('v2 request error', e1);
    try {
      return await second();
    } catch (err) {
      throw err;
    }
  }
}
