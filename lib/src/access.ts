import { Code, ConnectError } from '@connectrpc/connect';
import { type AuthConfig, resolveAuthConfig } from './auth/interceptors.js';
import { RewrapResponse } from './platform/kas/kas_pb.js';
import { getPlatformUrlFromKasEndpoint, validateSecureUrl } from './utils.js';
import { base64 } from './encodings/index.js';
import {
  KEY_ALGORITHMS,
  type KeyAlgorithm,
  isKeyAlgorithm,
} from '../tdf3/src/crypto/declarations.js';
import { InvalidFileError, PermissionDeniedError, UnauthenticatedError } from './errors.js';

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
    fulfillableFQNs: string[];
  };
};

export type RewrapRequest = {
  signedRequestToken: string;
};

/**
 * Get a rewrapped access key to the document, if possible
 * @param url Key access server rewrap endpoint
 * @param requestBody a signed request with an encrypted document key
 * @param authProvider Authorization middleware
 * @param fulfillableObligationFQNs client-configured list of obligation value FQNs that can be fulfilled in this PEP
 * @param clientVersion
 */
export async function fetchWrappedKey(
  url: string,
  signedRequestToken: string,
  auth: AuthConfig,
  fulfillableObligationFQNs: string[]
): Promise<RewrapResponse> {
  const platformUrl = getPlatformUrlFromKasEndpoint(url);
  const { authProvider } = resolveAuthConfig(auth);

  // Pass the original AuthConfig (not just its interceptors) so the RPC layer can
  // recover the provider's per-client DPoP nonce cache and keep the transport's
  // nonce capture and the interceptor's retry on the same instance (RFC 9449 §9).
  const rpcCall = () =>
    fetchWrappedKeysRpc(
      platformUrl,
      signedRequestToken,
      auth,
      rewrapAdditionalContextHeader(fulfillableObligationFQNs)
    );

  // When no AuthProvider is available, skip the legacy fallback so the real
  // RPC error propagates instead of being masked.
  if (!authProvider) {
    return await rpcCall();
  }

  // Try the modern Connect-RPC rewrap first, falling back to the legacy REST
  // rewrap only for non-auth failures (older, non-Connect platforms). A
  // definitive KAS auth/validation answer (401/403/400 — incl. a post-nonce-
  // challenge 401, RFC 9449 §9) surfaces as-is via tryRpcThenLegacy rather than
  // being masked by the legacy 404 on Connect-only platforms.
  // We intentionally omit the rewrap additional context from legacy requests:
  // platforms new enough to know about obligations handle RPC successfully.
  return await tryRpcThenLegacy(
    rpcCall,
    async () =>
      (await fetchWrappedKeysLegacy(
        url,
        { signedRequestToken },
        authProvider
      )) as unknown as RewrapResponse
  );
}

/**
 * An auth/validation error from the RPC rewrap represents a definitive answer
 * from KAS and must not be masked by the legacy REST fallback (which 404s on
 * Connect-only platforms). Other errors (network failures, or an old platform
 * missing the Connect endpoint) remain eligible for the legacy fallback.
 */
function isRewrapAuthError(e: unknown): boolean {
  return (
    e instanceof UnauthenticatedError ||
    e instanceof PermissionDeniedError ||
    e instanceof InvalidFileError
  );
}

/**
 * Transform fulfillable, fully-qualified obligations into the expected KAS Rewrap 'X-Rewrap-Additional-Context' header value.
 * @param fulfillableObligationValueFQNs
 */
export const rewrapAdditionalContextHeader = (
  fulfillableObligationValueFQNs: string[]
): string | undefined => {
  if (!fulfillableObligationValueFQNs.length) return;

  const context: RewrapAdditionalContext = {
    obligations: {
      fulfillableFQNs: fulfillableObligationValueFQNs.map((fqn) => fqn.toLowerCase()),
    },
  };
  return base64.encode(JSON.stringify(context));
};

// The supported key algorithms are defined in one place, `crypto/declarations.ts`.
// These public aliases preserve the historic `access.ts` API surface (name, tuple
// order, and guard behavior) while delegating to that single source of truth.
export const PUBLIC_KEY_ALGORITHMS = KEY_ALGORITHMS;

export type KasPublicKeyAlgorithm = KeyAlgorithm;

export const isPublicKeyAlgorithm = (a: string): a is KasPublicKeyAlgorithm => isKeyAlgorithm(a);

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
    case 'mlkem:768':
      return 'ML-KEM-768+A192KW';
    case 'mlkem:1024':
      return 'ML-KEM-1024+A256KW';
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
};

/**
 * Fetches the key access servers for a given platform URL.
 * @param platformUrl The platform URL to fetch key access servers for.
 * @param authProvider The authentication provider to use for the request.
 * @returns A promise that resolves to an OriginAllowList.
 */
export async function fetchKeyAccessServers(
  platformUrl: string,
  auth: AuthConfig
): Promise<OriginAllowList> {
  const { authProvider } = resolveAuthConfig(auth);

  // Pass the original AuthConfig so the RPC layer shares the provider's per-client
  // DPoP nonce cache with the transport (see fetchWrappedKey).
  const rpcCall = () => fetchKeyAccessServersRpc(platformUrl, auth);

  if (!authProvider) {
    return await rpcCall();
  }

  return await tryRpcThenLegacy(rpcCall, () =>
    fetchKeyAccessServersLegacy(platformUrl, authProvider)
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
    // Base key is optional; fall back to the RPC/legacy public-key path. Log a
    // one-line summary via errBrief (never the raw error object, which for Connect
    // errors can carry response metadata including DPoP nonces).
    console.log(`base key fetch failed, falling back to RPC/legacy public key: ${errBrief(e)}`);
  }

  return await tryRpcThenLegacy(
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

export type KasAllowListCache = Map<string, Promise<OriginAllowList>>;

export function fetchKeyAccessServersWithCache(
  cache: KasAllowListCache,
  platformUrl: string,
  auth: AuthConfig
): Promise<OriginAllowList> {
  const cached = cache.get(platformUrl);
  if (cached) {
    return cached;
  }
  const promise = fetchKeyAccessServers(platformUrl, auth).catch((e) => {
    if (cache.get(platformUrl) === promise) {
      cache.delete(platformUrl);
    }
    throw e;
  });
  cache.set(platformUrl, promise);
  return promise;
}

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
 * Try the modern Connect-RPC call first, falling back to the legacy REST call
 * only for non-auth failures. A definitive auth/validation answer from the RPC
 * layer short-circuits: the legacy endpoint 404s on Connect-only platforms and
 * would otherwise mask the real error. On a double failure, surface the (more
 * meaningful) RPC error while still logging the legacy one so the fallback path
 * stays debuggable.
 * @param rpcCall The modern Connect-RPC call to try first.
 * @param legacyCall The legacy REST call to fall back to for non-auth failures.
 * @param isAuthError Predicate identifying a definitive auth/validation error
 *   that must surface as-is rather than trigger the legacy fallback.
 */
async function tryRpcThenLegacy<T>(
  rpcCall: () => Promise<T>,
  legacyCall: () => Promise<T>,
  isAuthError: (e: unknown) => boolean = isRewrapAuthError
): Promise<T> {
  try {
    return await rpcCall();
  } catch (rpcError) {
    if (isAuthError(rpcError)) {
      throw rpcError;
    }
    console.info('v2 request error:', errBrief(rpcError));
    try {
      return await legacyCall();
    } catch (legacyError) {
      console.info('legacy fallback also failed:', errBrief(legacyError));
      throw rpcError;
    }
  }
}

/**
 * A log-safe one-line summary of an error: its message (and Connect code), never
 * the whole error object — Connect errors can carry response headers/metadata
 * (including DPoP nonces) that should not be dumped to logs on the auth path.
 */
function errBrief(e: unknown): string {
  if (e instanceof ConnectError) {
    return `${Code[e.code]}: ${e.message}`;
  }
  if (e instanceof Error) {
    return e.message;
  }
  return String(e);
}
