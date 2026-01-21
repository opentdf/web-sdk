import { v4 } from 'uuid';
import {
  keyMiddleware as defaultKeyMiddleware,
  streamToBuffer,
  ZipReader,
} from '../utils/index.js';
import { base64 } from '../../../src/encodings/index.js';
import {
  buildKeyAccess,
  type EncryptConfiguration,
  fetchKasPublicKey,
  loadTDFStream,
  readStream,
  validatePolicyObject,
  writeStream,
} from '../tdf.js';
import { unwrapHtml } from '../utils/unwrap.js';
import { OIDCRefreshTokenProvider } from '../../../src/auth/oidc-refreshtoken-provider.js';
import { OIDCExternalJwtProvider } from '../../../src/auth/oidc-externaljwt-provider.js';
import { CryptoService } from '../crypto/declarations.js';
import { type AuthProvider, HttpRequest, withHeaders } from '../../../src/auth/auth.js';
import {
  getPlatformUrlFromKasEndpoint,
  pemToCryptoPublicKey,
  rstrip,
  validateSecureUrl,
} from '../../../src/utils.js';

import {
  type DecryptParams,
  DecryptParamsBuilder,
  type DecryptSource,
  type DecryptStreamMiddleware,
  DEFAULT_SEGMENT_SIZE,
  type EncryptKeyMiddleware,
  type EncryptParams,
  EncryptParamsBuilder,
  type EncryptStreamMiddleware,
  type Scope,
} from './builders.js';
import { DecoratedReadableStream } from './DecoratedReadableStream.js';
import {
  fetchKeyAccessServers,
  type KasPublicKeyInfo,
  keyAlgorithmToPublicKeyAlgorithm,
  OriginAllowList,
} from '../../../src/access.js';
import { ConfigurationError } from '../../../src/errors.js';
import { Binary } from '../binary.js';
import { AesGcmCipher } from '../ciphers/aes-gcm-cipher.js';
import { toCryptoKeyPair } from '../crypto/crypto-utils.js';
import * as defaultCryptoService from '../crypto/index.js';
import {
  type AttributeObject,
  type KeyAccessType,
  type Policy,
  SplitKey,
} from '../models/index.js';
import { plan } from '../../../src/policy/granter.js';
import { attributeFQNsAsValues } from '../../../src/policy/api.js';
import { type Chunker, fromBuffer, fromSource } from '../../../src/seekable.js';
import { Algorithm, SimpleKasKey } from '../../../src/platform/policy/objects_pb.js';

const GLOBAL_BYTE_LIMIT = 64 * 1000 * 1000 * 1000; // 64 GB, see WS-9363.

// No default config for now. Delegate to Virtru wrapper for endpoints.
const defaultClientConfig = { oidcOrigin: '', cryptoService: defaultCryptoService };

const getFirstTwoBytes = async (chunker: Chunker) => new TextDecoder().decode(await chunker(0, 2));

async function algorithmFromPEM(pem: string) {
  const k: CryptoKey = await pemToCryptoPublicKey(pem);
  return keyAlgorithmToPublicKeyAlgorithm(k);
}

// Convert a PEM string to a CryptoKey
export const resolveKasInfo = async (
  pem: string,
  uri: string,
  kid?: string
): Promise<KasPublicKeyInfo> => {
  const k: CryptoKey = await pemToCryptoPublicKey(pem);
  const algorithm = keyAlgorithmToPublicKeyAlgorithm(k);
  return {
    key: Promise.resolve(k),
    publicKey: pem,
    url: uri,
    algorithm,
    kid: kid,
  };
};

const makeChunkable = async (source: DecryptSource) => {
  if (!source) {
    throw new ConfigurationError('invalid source');
  }
  // dump stream to buffer
  // we don't support streams anyways (see zipreader.js)
  let initialChunker: Chunker;
  let buf = null;
  switch (source.type) {
    case 'stream':
      buf = await streamToBuffer(source.location);
      initialChunker = fromBuffer(buf);
      break;
    case 'buffer':
      buf = source.location;
      initialChunker = fromBuffer(buf);
      break;
    case 'chunker':
      initialChunker = source.location;
      break;
    default:
      initialChunker = await fromSource(source);
  }

  const magic: string = await getFirstTwoBytes(initialChunker);
  // Pull first two bytes from source.
  if (magic === 'PK') {
    return initialChunker;
  }
  // Unwrap if it's html.
  // If NOT zip (html), convert/dump to buffer, unwrap, and continue.
  const htmlBuf = buf ?? (await initialChunker());
  const zipBuf = unwrapHtml(htmlBuf);
  return fromBuffer(zipBuf);
};

export interface ClientConfig {
  cryptoService?: CryptoService;
  /// oauth client id; used to generate oauth authProvider
  clientId?: string;
  dpopEnabled?: boolean;
  dpopKeys?: Promise<CryptoKeyPair>;
  kasEndpoint: string;
  /**
   * Service to use to look up ABAC. Used during autoconfigure. Defaults to
   * kasEndpoint without the trailing `/kas` path segment, if present.
   */
  policyEndpoint?: string;
  /**
   * List of allowed KASes to connect to for rewrap requests.
   * Defaults to `[]`.
   */
  allowedKases?: string[];
  /**
   * List of obligation value FQNs in platform policy that can be fulfilled
   * by the PEP handling this client (i.e. 'https://example.com/obl/drm/value/mask').
   * Defaults to '[]'.
   */
  fulfillableObligationFQNs?: string[];
  // Platform URL to use to lookup allowed KASes when allowedKases is empty
  platformUrl?: string;
  ignoreAllowList?: boolean;
  easEndpoint?: string;
  // DEPRECATED Ignored
  keyRewrapEndpoint?: string;
  // DEPRECATED Ignored
  keyUpsertEndpoint?: string;
  refreshToken?: string;
  kasPublicKey?: string;
  oidcOrigin?: string;
  externalJwt?: string;
  authProvider?: AuthProvider;
  readerUrl?: string;
  entityObjectEndpoint?: string;
  fileStreamServiceWorker?: string;
  progressHandler?: (bytesProcessed: number) => void;
}

/*
 * Extract a keypair provided as part of the options dict.
 * Default to using the clientwide keypair, generating one if necessary.
 *
 * Additionally, update the auth injector with the (potentially new) pubkey
 */
export async function createSessionKeys({
  authProvider,
  // FIXME use cryptoservice to generate keys again
  cryptoService,
  dpopKeys,
}: {
  authProvider?: AuthProvider;
  cryptoService: CryptoService;
  dpopKeys?: Promise<CryptoKeyPair>;
}): Promise<CryptoKeyPair> {
  let signingKeys: CryptoKeyPair;
  if (dpopKeys) {
    signingKeys = await dpopKeys;
  } else {
    const keys = await cryptoService.generateSigningKeyPair();
    // signingKeys = await crypto.subtle.generateKey(rsaPkcs1Sha256(), true, ['sign']);
    signingKeys = await toCryptoKeyPair(keys);
  }

  // This will contact the auth server and forcibly refresh the auth token claims,
  // binding the token and the (new) pubkey together.
  // Note that we base64 encode the PEM string here as a quick workaround, simply because
  // a formatted raw PEM string isn't a valid header value and sending it raw makes keycloak's
  // header parser barf. There are more subtle ways to solve this, but this works for now.
  if (authProvider) {
    await authProvider?.updateClientPublicKey(signingKeys);
  }
  return signingKeys;
}

/*
 * Create a policy object for an encrypt operation.
 */
function asPolicy(scope: Scope): Policy {
  if (scope.policyObject) {
    // use the client override if provided
    return scope.policyObject;
  }
  const policyId = scope.policyId ?? v4();
  let dataAttributes: AttributeObject[];
  if (scope.attributeValues) {
    dataAttributes = scope.attributeValues
      .filter(({ fqn }) => !!fqn)
      .map(({ fqn }): AttributeObject => {
        return { attribute: fqn! };
      });
  } else {
    dataAttributes = (scope.attributes ?? []).map((attribute) =>
      typeof attribute === 'string' ? { attribute } : attribute
    );
  }
  return {
    uuid: policyId,
    body: {
      dataAttributes,
      dissem: scope.dissem ?? [],
    },
  };
}

type KasKeyInfoCache = [
  ...Parameters<typeof fetchKasPublicKey>,
  keyInfoPromise: ReturnType<typeof fetchKasPublicKey>,
][];

export function findEntryInCache(
  cache: KasKeyInfoCache,
  ...params: Parameters<typeof fetchKasPublicKey>
) {
  const [wantedKas, wantedAlgorithm, wantedKid] = params;
  for (const item of cache) {
    const [itemKas, itemAlgorithm, itemKid, itemKeyInfoPromise] = item;
    if (itemKas !== wantedKas) {
      continue;
    }
    // This makes undefined only match with undefined (base key).
    // We could potentially consider any key a match if undefined algorithm?
    if (itemAlgorithm !== wantedAlgorithm) {
      continue;
    }
    if (wantedKid && itemKid !== wantedKid) {
      continue;
    }
    return itemKeyInfoPromise;
  }
  return null;
}

const fetchKasKeyWithCache = (
  cache: KasKeyInfoCache,
  ...params: Parameters<typeof fetchKasPublicKey>
): ReturnType<typeof fetchKasPublicKey> => {
  const cachedEntry = findEntryInCache(cache, ...params);
  if (cachedEntry !== null) {
    return cachedEntry;
  }
  const keyInfoPromise = fetchKasPublicKey(...params);
  cache.push([...params, keyInfoPromise]);
  return keyInfoPromise;
};

function algorithmEnumValueToString(algorithmEnumValue: Algorithm) {
  switch (algorithmEnumValue) {
    case Algorithm.RSA_2048:
      return 'rsa:2048';
    case Algorithm.RSA_4096:
      return 'rsa:4096';
    case Algorithm.EC_P256:
      return 'ec:secp256r1';
    case Algorithm.EC_P384:
      return 'ec:secp384r1';
    case Algorithm.EC_P521:
      return 'ec:secp521r1';
    case Algorithm.UNSPECIFIED:
      // Not entirely sure undefined is correct here, but since we need to generate a key for our cache
      // synchonously, it seems to be the best approach for now.
      return undefined;
    default:
      return undefined;
  }
}

const putKasKeyIntoCache = (
  cache: KasKeyInfoCache,
  kasKey: Omit<SimpleKasKey, 'publicKey'> & {
    publicKey: Exclude<SimpleKasKey['publicKey'], undefined>;
  }
): ReturnType<typeof fetchKasPublicKey> => {
  const algorithmString = algorithmEnumValueToString(kasKey.publicKey.algorithm);
  const cachedEntry = findEntryInCache(cache, kasKey.kasUri, algorithmString, kasKey.publicKey.kid);
  if (cachedEntry) {
    return cachedEntry;
  }
  const keyInfoPromise = (async function () {
    const keyPromise = pemToCryptoPublicKey(kasKey.publicKey.pem);
    const key = await keyPromise;
    const algorithm = keyAlgorithmToPublicKeyAlgorithm(key);
    return {
      algorithm: algorithm,
      key: keyPromise,
      kid: kasKey.publicKey.kid,
      publicKey: kasKey.publicKey.pem,
      url: kasKey.kasUri,
    };
  })();
  cache.push([kasKey.kasUri, algorithmString, kasKey.publicKey.kid, keyInfoPromise]);
  return keyInfoPromise;
};

export class Client {
  readonly cryptoService: CryptoService;

  /**
   * Default kas endpoint, if present. Required for encrypt.
   */
  readonly kasEndpoint: string;

  /**
   * Policy service endpoint, if present.
   * Required for autoconfiguration with ABAC.
   */
  readonly policyEndpoint: string;

  /**
   * List of allowed KASes to connect to for rewrap requests.
   * Defaults to `[this.kasEndpoint]`.
   */
  readonly allowedKases?: OriginAllowList;

  /**
   * List of obligation value FQNs in platform policy that can be fulfilled
   * by the PEP utilizing this client (i.e. 'https://example.com/obl/drm/value/mask').
   * Defaults to '[]'. Currently set per Client and not per TDF.
   */
  readonly fulfillableObligationFQNs: string[];

  /**
   * URL of the platform, required to fetch list of allowed KASes when allowedKases is empty
   */
  readonly platformUrl?: string;

  readonly kasKeyInfoCache: KasKeyInfoCache = [];

  readonly easEndpoint?: string;

  readonly clientId?: string;

  readonly authProvider?: AuthProvider;

  readonly readerUrl?: string;

  readonly fileStreamServiceWorker?: string;

  /**
   * Session binding keys. Used for DPoP and signed request bodies.
   */
  readonly dpopKeys: Promise<CryptoKeyPair>;

  readonly dpopEnabled: boolean;

  readonly clientConfig: ClientConfig;

  /**
   * An abstraction for protecting and accessing data using TDF3 services.
   * @param {Object} [config.keypair] - keypair generated for signing. Optional, will be generated by sdk if not passed
   * @param {String} [config.clientId]
   * @param {String} [config.kasEndpoint] - Key Access Server url
   * @param {String} [config.refreshToken] - After logging in to browser OIDC interface user
   * receives fresh token that needed by SDK for auth needs
   * @param {String} [config.externalJwt] - JWT from external authority (eg Google)
   * @param {String} [config.oidcOrigin] - Endpoint of authentication service
   */
  constructor(config: ClientConfig) {
    const clientConfig = { ...defaultClientConfig, ...config };
    this.cryptoService = clientConfig.cryptoService;
    this.dpopEnabled = !!(clientConfig.dpopEnabled || clientConfig.dpopKeys);

    clientConfig.readerUrl && (this.readerUrl = clientConfig.readerUrl);

    if (clientConfig.kasEndpoint) {
      this.kasEndpoint = clientConfig.kasEndpoint;
    } else {
      // handle Deprecated `kasRewrapEndpoint` parameter
      if (!clientConfig.keyRewrapEndpoint) {
        throw new ConfigurationError('KAS definition not found');
      }
      this.kasEndpoint = clientConfig.keyRewrapEndpoint.replace(/\/rewrap$/, '');
    }
    this.kasEndpoint = rstrip(this.kasEndpoint, '/');

    if (!validateSecureUrl(this.kasEndpoint)) {
      throw new ConfigurationError(`Invalid KAS endpoint [${this.kasEndpoint}]`);
    }

    if (config.platformUrl) {
      this.platformUrl = config.platformUrl;
    }

    if (clientConfig.policyEndpoint) {
      this.policyEndpoint = getPlatformUrlFromKasEndpoint(clientConfig.policyEndpoint);
    }

    const kasOrigin = new URL(this.kasEndpoint).origin;
    if (clientConfig.allowedKases) {
      this.allowedKases = new OriginAllowList(
        clientConfig.allowedKases,
        !!clientConfig.ignoreAllowList
      );
      if (!this.allowedKases.allows(kasOrigin)) {
        // TODO PR: ask if in this cases it makes more sense to add defaultKASEndpoint to the allow list if the allowList is not empty but doesn't have the defaultKas
        throw new ConfigurationError(
          `Invalid KAS endpoint [${this.kasEndpoint}]. When allowedKases is set, defaultKASEndpoint needs to be in the allow list`
        );
      }
    }

    this.fulfillableObligationFQNs = config.fulfillableObligationFQNs?.length
      ? config.fulfillableObligationFQNs
      : [];

    if (clientConfig.easEndpoint) {
      this.easEndpoint = clientConfig.easEndpoint;
    }

    this.authProvider = config.authProvider;
    this.clientConfig = clientConfig;

    this.clientId = clientConfig.clientId;
    if (!this.authProvider) {
      if (!clientConfig.clientId) {
        throw new ConfigurationError('Client ID or custom AuthProvider must be defined');
      }

      //Are we exchanging a refreshToken for a bearer token (normal AuthCode browser auth flow)?
      //If this is a browser context, we expect the caller to handle the initial
      //browser-based OIDC login and authentication process against the OIDC endpoint using their chosen method,
      //and provide us with a valid refresh token/clientId obtained from that process.
      if (clientConfig.refreshToken) {
        this.authProvider = new OIDCRefreshTokenProvider({
          clientId: clientConfig.clientId,
          refreshToken: clientConfig.refreshToken,
          oidcOrigin: clientConfig.oidcOrigin,
        });
      } else if (clientConfig.externalJwt) {
        //Are we exchanging a JWT previously issued by a trusted external entity (e.g. Google) for a bearer token?
        this.authProvider = new OIDCExternalJwtProvider({
          clientId: clientConfig.clientId,
          externalJwt: clientConfig.externalJwt,
          oidcOrigin: clientConfig.oidcOrigin,
        });
      }
    }
    this.dpopKeys = createSessionKeys({
      authProvider: this.authProvider,
      cryptoService: this.cryptoService,
      dpopKeys: clientConfig.dpopKeys,
    });
  }

  /** Necessary only for testing. A dependency-injection approach should be preferred, but that is difficult currently */
  _doFetchKasKeyWithCache(
    ...params: Parameters<typeof fetchKasKeyWithCache>
  ): ReturnType<typeof fetchKasKeyWithCache> {
    return fetchKasKeyWithCache(...params);
  }

  /**
   * Encrypt plaintext into TDF ciphertext. One of the core operations of the Virtru SDK.
   *
   * @param scope dissem and attributes for constructing the policy
   * @param source source object of unencrypted data
   * @param [autoconfigure] If we should use scope.attributes to configure KAOs
   * @param [metadata] Additional non-secret data to store with the TDF
   * @param [opts] Test only
   * @param [mimeType] mime type of source. defaults to `unknown`
   * @param [windowSize] - segment size in bytes. Defaults to a a million bytes.
   * @param [keyMiddleware] - function that handle keys
   * @param [streamMiddleware] - function that handle stream
   * @param [eo] - (deprecated) entity object
   * @return a {@link https://nodejs.org/api/stream.html#stream_class_stream_readable|Readable} a new stream containing the TDF ciphertext
   */
  async encrypt(opts: EncryptParams): Promise<DecoratedReadableStream> {
    if (opts.offline === false) {
      throw new ConfigurationError('online mode not supported');
    }
    if (opts.asHtml) {
      throw new ConfigurationError('html mode not supported');
    }
    const dpopKeys = await this.dpopKeys;
    const {
      autoconfigure,
      metadata,
      mimeType = 'unknown',
      windowSize = DEFAULT_SEGMENT_SIZE,
      keyMiddleware = defaultKeyMiddleware,
      splitPlan: preconfiguredSplitPlan,
      streamMiddleware = async (stream: DecoratedReadableStream) => stream,
      tdfSpecVersion,
      wrappingKeyAlgorithm,
    } = opts;
    const scope = opts.scope ?? { attributes: [], dissem: [] };

    for (const attributeValue of scope.attributeValues || []) {
      for (const kasKey of attributeValue.kasKeys) {
        if (kasKey.publicKey !== undefined) {
          await putKasKeyIntoCache(this.kasKeyInfoCache, {
            // TypeScript is silly and cannot infer that publicKey is not undefined, without re-referencing it like this, even though we checked already.
            ...kasKey,
            publicKey: kasKey.publicKey,
          });
        }
      }
    }

    const policyObject = asPolicy(scope);
    validatePolicyObject(policyObject);

    const splitPlan: {
      kas: string;
      kid?: string;
      pem: string;
      sid?: string;
    }[] = [];
    if (preconfiguredSplitPlan) {
      for (const preconfiguredSplit of preconfiguredSplitPlan) {
        const kasPublicKeyInfo = await this._doFetchKasKeyWithCache(
          this.kasKeyInfoCache,
          preconfiguredSplit.kas,
          wrappingKeyAlgorithm,
          preconfiguredSplit.kid
        );
        splitPlan.push({
          kas: kasPublicKeyInfo.url,
          kid: kasPublicKeyInfo.kid,
          pem: kasPublicKeyInfo.publicKey,
          sid: preconfiguredSplit.sid,
        });
      }
    } else if (autoconfigure) {
      const attributeValues = scope.attributeValues ?? [];
      if (!scope.attributes) {
        scope.attributes = attributeValues.map(({ fqn }) => fqn);
      }
      const attributeFQNs = (scope.attributes ?? []).map((attribute) =>
        typeof attribute === 'string' ? attribute : attribute.attribute
      );
      const fqnsWithoutValues = attributeFQNs.filter((fqn) =>
        attributeValues.every((av) => av.fqn !== fqn)
      );

      if (fqnsWithoutValues.length) {
        // Hydrate missing avs from policy endpoint given the fqns
        if (!this.platformUrl) {
          throw new ConfigurationError('platformUrl not set in TDF3 Client constructor');
        }
        const fetchedFQNValues = await attributeFQNsAsValues(
          this.platformUrl,
          this.authProvider as AuthProvider,
          ...fqnsWithoutValues
        );
        fetchedFQNValues.forEach((fetchedValue) => {
          attributeValues.push(fetchedValue);
        });
      }

      const hasAllFQNs = attributeFQNs.every((fqn) =>
        attributeValues.some((attributeValue) => attributeValue.fqn === fqn)
      );
      if (attributeFQNs.length != attributeValues.length || !hasAllFQNs) {
        throw new ConfigurationError(
          `Attribute mismatch between [${attributeFQNs}] and explicit values ${JSON.stringify(
            attributeValues.map(({ fqn }) => fqn)
          )}`
        );
      }

      const cacheKasKeys = async (kasKeys: SimpleKasKey[]) => {
        for (const kasKey of kasKeys) {
          if (kasKey.publicKey !== undefined) {
            await putKasKeyIntoCache(this.kasKeyInfoCache, {
              // TypeScript is silly and cannot infer that publicKey is not undefined, without re-referencing it like this, even though we checked already.
              ...kasKey,
              publicKey: kasKey.publicKey,
            });
          }
        }
      };

      for (const attributeValue of attributeValues) {
        let effectiveKasKeys = attributeValue.kasKeys;
        if (!effectiveKasKeys.length) {
          effectiveKasKeys = attributeValue.attribute?.kasKeys ?? [];
        }
        if (!effectiveKasKeys.length) {
          effectiveKasKeys = attributeValue.attribute?.namespace?.kasKeys ?? [];
        }
        await cacheKasKeys(effectiveKasKeys);
      }

      const detailedPlan = plan(attributeValues);
      for (const item of detailedPlan) {
        if ('kid' in item.kas) {
          const pemAlgorithm = await algorithmFromPEM(item.kas.pem);
          const kasPublicKeyInfo = await this._doFetchKasKeyWithCache(
            this.kasKeyInfoCache,
            item.kas.kasUri,
            pemAlgorithm,
            item.kas.kid
          );
          splitPlan.push({
            kas: kasPublicKeyInfo.url,
            kid: kasPublicKeyInfo.kid,
            pem: kasPublicKeyInfo.publicKey,
            sid: item.sid,
          });
          continue;
        }

        if (!item.kas.publicKey) {
          const kasPublicKeyInfo = await this._doFetchKasKeyWithCache(
            this.kasKeyInfoCache,
            item.kas.uri,
            wrappingKeyAlgorithm,
            undefined
          );
          splitPlan.push({
            kas: kasPublicKeyInfo.url,
            kid: kasPublicKeyInfo.kid,
            pem: kasPublicKeyInfo.publicKey,
            sid: item.sid,
          });
          continue;
        }

        switch (item.kas.publicKey.publicKey.case) {
          case 'remote':
            const kasPublicKeyInfo = await this._doFetchKasKeyWithCache(
              this.kasKeyInfoCache,
              item.kas.publicKey.publicKey.value,
              wrappingKeyAlgorithm,
              undefined
            );
            splitPlan.push({
              kas: kasPublicKeyInfo.url,
              kid: kasPublicKeyInfo.kid,
              pem: kasPublicKeyInfo.publicKey,
              sid: item.sid,
            });
            break;

          case 'cached':
            for (const cachedPublicKey of item.kas.publicKey.publicKey.value.keys) {
              splitPlan.push({
                kas: item.kas.uri,
                kid: cachedPublicKey.kid,
                pem: cachedPublicKey.pem,
                sid: item.sid,
              });
            }
            break;

          default:
            throw new Error(`Unknown public key type: ${item.kas.publicKey.publicKey.case}`);
        }
      }
    }

    // TODO: Refactor underlying builder to remove some of this unnecessary config.

    const maxByteLimit = GLOBAL_BYTE_LIMIT;
    const byteLimit =
      opts.byteLimit === undefined || opts.byteLimit <= 0 || opts.byteLimit > maxByteLimit
        ? maxByteLimit
        : opts.byteLimit;
    const encryptionInformation = new SplitKey(new AesGcmCipher(this.cryptoService));
    if (splitPlan.length === 0) {
      const kasPublicKeyInfo = await this._doFetchKasKeyWithCache(
        this.kasKeyInfoCache,
        opts.defaultKASEndpoint ?? this.kasEndpoint,
        wrappingKeyAlgorithm,
        undefined
      );
      splitPlan.push({
        kas: kasPublicKeyInfo.url,
        kid: kasPublicKeyInfo.kid,
        pem: kasPublicKeyInfo.publicKey,
      });
    }
    encryptionInformation.keyAccess = await Promise.all(
      splitPlan.map(async ({ kas, kid, pem, sid }) => {
        const algorithm = await algorithmFromPEM(pem);
        if (algorithm !== wrappingKeyAlgorithm) {
          console.warn(
            `Mismatched wrapping key algorithm: [${algorithm}] is not requested type, [${wrappingKeyAlgorithm}]`
          );
        }
        let type: KeyAccessType;
        switch (algorithm) {
          case 'rsa:2048':
          case 'rsa:4096':
            type = 'wrapped';
            break;
          case 'ec:secp384r1':
          case 'ec:secp521r1':
          case 'ec:secp256r1':
            type = 'ec-wrapped';
            break;
          default:
            throw new ConfigurationError(`Unsupported algorithm ${algorithm}`);
        }
        return buildKeyAccess({
          alg: algorithm,
          type,
          url: kas,
          kid: kid,
          publicKey: pem,
          metadata,
          sid,
        });
      })
    );
    const { keyForEncryption, keyForManifest } = await (keyMiddleware as EncryptKeyMiddleware)();
    const ecfg: EncryptConfiguration = {
      allowList: this.allowedKases,
      byteLimit,
      cryptoService: this.cryptoService,
      dpopKeys,
      encryptionInformation,
      segmentSizeDefault: windowSize,
      integrityAlgorithm: 'HS256',
      segmentIntegrityAlgorithm: 'GMAC',
      contentStream: opts.source,
      mimeType,
      policy: policyObject,
      authProvider: this.authProvider,
      progressHandler: this.clientConfig.progressHandler,
      keyForEncryption,
      keyForManifest,
      assertionConfigs: opts.assertionConfigs,
      systemMetadataAssertion: opts.systemMetadataAssertion,
      tdfSpecVersion,
    };

    return (streamMiddleware as EncryptStreamMiddleware)(await writeStream(ecfg));
  }

  /**
   * Decrypt TDF ciphertext into plaintext. One of the core operations of the Virtru SDK.
   *
   * @param params keyMiddleware fucntion to process key
   * @param params streamMiddleware fucntion to process streamMiddleware
   * @param params.source A data stream object, one of remote, stream, buffer, etc. types.
   * @param params.eo Optional entity object (legacy AuthZ)
   * @param params.assertionVerificationKeys Optional verification keys for assertions.
   * @param params.fulfillableObligationFQNs Optional fulfillable obligation value FQNs (overrides those on the Client)
   * @return a {@link https://nodejs.org/api/stream.html#stream_class_stream_readable|Readable} stream containing the decrypted plaintext.
   * @see DecryptParamsBuilder
   */
  async decrypt({
    source,
    allowList,
    keyMiddleware = async (key: Binary) => key,
    streamMiddleware = async (stream: DecoratedReadableStream) => stream,
    assertionVerificationKeys,
    noVerifyAssertions,
    concurrencyLimit = 1,
    wrappingKeyAlgorithm,
    fulfillableObligationFQNs = [],
  }: DecryptParams): Promise<DecoratedReadableStream> {
    const dpopKeys = await this.dpopKeys;
    if (!this.authProvider) {
      throw new ConfigurationError('AuthProvider missing');
    }
    const chunker = await makeChunkable(source);
    if (!allowList && this.allowedKases) {
      allowList = this.allowedKases;
    } else if (this.platformUrl) {
      allowList = await fetchKeyAccessServers(this.platformUrl, this.authProvider);
    } else {
      throw new ConfigurationError('platformUrl is required when allowedKases is empty');
    }

    const hasEmptyDecryptParamObligationsButGlobal =
      !fulfillableObligationFQNs.length && this.fulfillableObligationFQNs.length;
    if (hasEmptyDecryptParamObligationsButGlobal) {
      fulfillableObligationFQNs = this.fulfillableObligationFQNs;
    }

    // Await in order to catch any errors from this call.
    // TODO: Write error event to stream and don't await.
    return await (streamMiddleware as DecryptStreamMiddleware)(
      await readStream({
        allowList,
        authProvider: this.authProvider,
        chunker,
        concurrencyLimit,
        cryptoService: this.cryptoService,
        dpopKeys,
        fileStreamServiceWorker: this.clientConfig.fileStreamServiceWorker,
        keyMiddleware,
        progressHandler: this.clientConfig.progressHandler,
        assertionVerificationKeys,
        noVerifyAssertions,
        wrappingKeyAlgorithm,
        fulfillableObligations: fulfillableObligationFQNs,
      })
    );
  }

  /**
   * Get the unique policyId associated with TDF ciphertext. Useful for managing authorization policies of encrypted data.
   * <br/><br/>
   * The policyId is embedded in the ciphertext so this is a local operation.
   *
   * @param {object} source - Required. TDF data stream,
   * generated using {@link DecryptParamsBuilder#build|DecryptParamsBuilder's build()}.
   * @return {string} - the unique policyId, which can be used for tracking purposes or policy management operations.
   * @see DecryptParamsBuilder
   */
  async getPolicyId({ source }: { source: DecryptSource }) {
    const chunker = await makeChunkable(source);
    const zipHelper = new ZipReader(chunker);
    const centralDirectory = await zipHelper.getCentralDirectory();
    const manifest = await zipHelper.getManifest(centralDirectory, '0.manifest.json');
    const policyJson = base64.decode(manifest.encryptionInformation.policy);
    return JSON.parse(policyJson).uuid;
  }

  async loadTDFStream({ source }: { source: DecryptSource }) {
    const chunker = await makeChunkable(source);
    return loadTDFStream(chunker);
  }
}

export type { AuthProvider };

export { DecryptParamsBuilder, DecryptSource, EncryptParamsBuilder, HttpRequest, withHeaders };
