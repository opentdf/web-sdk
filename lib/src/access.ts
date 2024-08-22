import axios from 'axios';

import { TdfError } from './errors.js';
import { type AuthProvider } from './auth/auth.js';
import { extractPemFromKeyString, pemToCryptoPublicKey, validateSecureUrl } from './utils.js';

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

export type KasPublicKeyInfo = {
  url: string;
  algorithm: KasPublicKeyAlgorithm;
  kid?: string;
  publicKey: string;
  key: CryptoKey;
};

export type KasPublicKeyAlgorithm = 'ec:secp256r1' | 'rsa:2048';

export type KasPublicKeyFormat = 'pkcs8' | 'jwks';

type KasPublicKeyParams = {
  algorithm?: KasPublicKeyAlgorithm;
  fmt?: KasPublicKeyFormat;
  v?: '1' | '2';
};

/**
 * If we have KAS url but not public key we can fetch it from KAS, fetching
 * the value from `${kas}/kas_public_key`.
 */
export async function fetchKasPublicKey(
  kas: string,
  algorithm?: KasPublicKeyAlgorithm
): Promise<KasPublicKeyInfo> {
  if (!kas) {
    throw new TdfError('KAS definition not found');
  }
  // Logs insecure KAS. Secure is enforced in constructor
  validateSecureUrl(kas);
  const infoStatic = { url: kas, algorithm: algorithm || 'rsa:2048' };
  const params: KasPublicKeyParams = {};
  if (algorithm) {
    params.algorithm = algorithm;
  }
  try {
    const response: { data: string | KasPublicKeyInfo } = await axios.get(`${kas}/kas_public_key`, {
      params: {
        ...params,
        v: '2',
      },
    });
    const publicKey =
      typeof response.data === 'string'
        ? await extractPemFromKeyString(response.data)
        : response.data.publicKey;
    const key = await pemToCryptoPublicKey(publicKey);
    return {
      key,
      publicKey,
      ...infoStatic,
      ...(typeof response.data !== 'string' && response.data.kid && { kid: response.data.kid }),
    };
  } catch (cause) {
    if (cause?.response?.status != 400) {
      throw new TdfError(
        `Retrieving KAS public key [${kas}] failed [${cause.name}] [${cause.message}]`,
        cause
      );
    }
  }
  // Retry with v1 params
  try {
    const response: { data: string | KasPublicKeyInfo } = await axios.get(`${kas}/kas_public_key`, {
      params,
    });
    const publicKey =
      typeof response.data === 'string'
        ? await extractPemFromKeyString(response.data)
        : response.data.publicKey;
    // future proof: allow v2 response even if not specified.
    const key = await pemToCryptoPublicKey(publicKey);
    return {
      key,
      publicKey,
      ...infoStatic,
      ...(typeof response.data !== 'string' && response.data.kid && { kid: response.data.kid }),
    };
  } catch (cause) {
    throw new TdfError(
      `Retrieving KAS public key [${kas}] failed [${cause.name}] [${cause.message}]`,
      cause
    );
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
