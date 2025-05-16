import { type AuthProvider } from './auth/auth.js';
import { ConfigurationError, NetworkError, ServiceError } from './errors.js';
import { PlatformClient } from './platform.js';
import { RewrapResponse } from './platform/kas/kas_pb.js';
import { ListKeyAccessServersResponse } from './platform/policy/kasregistry/key_access_server_registry_pb.js';
import {
  extractRpcErrorMessage,
  getPlatformUrlFromKasEndpoint,
  pemToCryptoPublicKey,
  validateSecureUrl,
} from './utils.js';

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
  const platform = new PlatformClient({ authProvider, platformUrl });
  try {
    return await platform.v1.access.rewrap({
      signedRequestToken,
    });
  } catch (e) {
    throw new NetworkError(`[${platformUrl}] [Rewrap] ${extractRpcErrorMessage(e)}`);
  }
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

async function noteInvalidPublicKey(url: URL, r: Promise<CryptoKey>): Promise<CryptoKey> {
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
  let nextOffset = 0;
  const allServers = [];
  const platform = new PlatformClient({ authProvider, platformUrl });

  do {
    let response: ListKeyAccessServersResponse;
    try {
      response = await platform.v1.keyAccessServerRegistry.listKeyAccessServers({
        pagination: {
          offset: nextOffset,
        },
      });
    } catch (e) {
      throw new NetworkError(
        `[${platformUrl}] [ListKeyAccessServers] ${extractRpcErrorMessage(e)}`
      );
    }

    allServers.push(...response.keyAccessServers);
    nextOffset = response?.pagination?.nextOffset || 0;
  } while (nextOffset > 0);

  const serverUrls = allServers.map((server) => server.uri);
  // add base platform kas
  if (!serverUrls.includes(`${platformUrl}/kas`)) {
    serverUrls.push(`${platformUrl}/kas`);
  }

  return new OriginAllowList(serverUrls, false);
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
  if (!kasEndpoint) {
    throw new ConfigurationError('KAS definition not found');
  }
  // Logs insecure KAS. Secure is enforced in constructor
  validateSecureUrl(kasEndpoint);

  const platformUrl = getPlatformUrlFromKasEndpoint(kasEndpoint);
  const platform = new PlatformClient({
    platformUrl,
  });
  try {
    const { kid, publicKey } = await platform.v1.access.publicKey({
      algorithm: algorithm || 'rsa:2048',
      v: '2',
    });
    const result: KasPublicKeyInfo = {
      key: noteInvalidPublicKey(new URL(platformUrl), pemToCryptoPublicKey(publicKey)),
      publicKey,
      url: kasEndpoint,
      algorithm: algorithm || 'rsa:2048',
      ...(kid && { kid }),
    };
    return result;
  } catch (e) {
    throw new NetworkError(`[${platformUrl}] [PublicKey] ${extractRpcErrorMessage(e)}`);
  }
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
