import {
  isPublicKeyAlgorithm,
  KasPublicKeyAlgorithm,
  KasPublicKeyInfo,
  noteInvalidPublicKey,
  OriginAllowList,
} from '../access.js';
import { type AuthProvider } from '../auth/auth.js';
import { ConfigurationError, NetworkError } from '../errors.js';
import { PlatformClient } from '../platform.js';
import { RewrapResponse } from '../platform/kas/kas_pb.js';
import { ListKeyAccessServersResponse } from '../platform/policy/kasregistry/key_access_server_registry_pb.js';
import {
  extractRpcErrorMessage,
  getPlatformUrlFromKasEndpoint,
  pemToCryptoPublicKey,
  validateSecureUrl,
} from '../utils.js';

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

interface PlatformBaseKey {
  kas_id?: string;
  kas_uri: string;
  public_key: {
    algorithm: KasPublicKeyAlgorithm;
    kid: string;
    pem: string;
  };
}

function isBaseKey(baseKey?: unknown): baseKey is PlatformBaseKey {
  if (!baseKey) {
    return false;
  }
  const bk = baseKey as PlatformBaseKey;
  return (
    !!bk.kas_uri &&
    !!bk.public_key &&
    typeof bk.public_key === 'object' &&
    !!bk.public_key.pem &&
    !!bk.public_key.algorithm &&
    isPublicKeyAlgorithm(bk.public_key.algorithm)
  );
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

/**
 * Fetch the base public key from WellKnownConfiguration of the platform.
 * @param kasEndpoint The KAS endpoint URL.
 * @throws {ConfigurationError} If the KAS endpoint is not defined.
 * @throws {NetworkError} If there is an error fetching the public key from the KAS endpoint.
 * @returns The base public key information for the KAS endpoint.
 */
export async function fetchKasBasePubKey(kasEndpoint: string): Promise<KasPublicKeyInfo> {
  if (!kasEndpoint) {
    throw new ConfigurationError('KAS definition not found');
  }
  validateSecureUrl(kasEndpoint);

  const platformUrl = getPlatformUrlFromKasEndpoint(kasEndpoint);
  const platform = new PlatformClient({
    platformUrl,
  });
  try {
    const { configuration } = await platform.v1.wellknown.getWellKnownConfiguration({});
    const baseKey = configuration?.base_key as unknown as PlatformBaseKey;
    if (!isBaseKey(baseKey)) {
      throw new NetworkError(
        `Invalid Platform Configuration: [${kasEndpoint}] is missing BaseKey in WellKnownConfiguration`
      );
    }

    const result: KasPublicKeyInfo = {
      key: noteInvalidPublicKey(
        new URL(baseKey.kas_uri),
        pemToCryptoPublicKey(baseKey.public_key.pem)
      ),
      publicKey: baseKey.public_key.pem,
      url: baseKey.kas_uri,
      algorithm: baseKey.public_key.algorithm,
      kid: baseKey.public_key.kid,
    };
    return result;
  } catch (e) {
    throw new NetworkError(`[${platformUrl}] [PublicKey] ${extractRpcErrorMessage(e)}`);
  }
}
