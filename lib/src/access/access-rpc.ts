import {
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
