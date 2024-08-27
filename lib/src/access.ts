import { type AuthProvider } from './auth/auth.js';
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
    throw new Error(`${req.method} ${req.url} => ${response.status} ${response.statusText}`);
  }

  return response.json();
}

export type KasPublicKeyAlgorithm = 'ec:secp256r1' | 'rsa:2048';

export type KasPublicKeyInfo = {
  url: string;
  algorithm: KasPublicKeyAlgorithm;
  kid?: string;
  publicKey: string;
  key: Promise<CryptoKey>;
};

/**
 * If we have KAS url but not public key we can fetch it from KAS, fetching
 * the value from `${kas}/kas_public_key`.
 */

export async function fetchECKasPubKey(kasEndpoint: string): Promise<KasPublicKeyInfo> {
  validateSecureUrl(kasEndpoint);
  const pkUrlV2 = `${kasEndpoint}/v2/kas_public_key?algorithm=ec:secp256r1&v=2`;
  const kasPubKeyResponse = await fetch(pkUrlV2);
  if (!kasPubKeyResponse.ok) {
    if (kasPubKeyResponse.status != 404) {
      throw new Error(
        `unable to load KAS public key from [${pkUrlV2}]. Received [${kasPubKeyResponse.status}:${kasPubKeyResponse.statusText}]`
      );
    }
    console.log('falling back to v1 key');
    // most likely a server that does not implement v2 endpoint, so no key identifier
    const pkUrlV1 = `${kasEndpoint}/kas_public_key?algorithm=ec:secp256r1`;
    const r2 = await fetch(pkUrlV1);
    if (!r2.ok) {
      throw new Error(
        `unable to load KAS public key from [${pkUrlV1}]. Received [${r2.status}:${r2.statusText}]`
      );
    }
    const pem = await r2.json();
    console.log('pem returned', pem);
    return {
      key: pemToCryptoPublicKey(pem),
      publicKey: pem,
      url: kasEndpoint,
      algorithm: 'ec:secp256r1',
    };
  }
  const jsonContent = await kasPubKeyResponse.json();
  const { publicKey, kid }: KasPublicKeyInfo = jsonContent;
  if (!publicKey) {
    throw new Error(`Invalid response from public key endpoint [${JSON.stringify(jsonContent)}]`);
  }
  return {
    key: pemToCryptoPublicKey(publicKey),
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
