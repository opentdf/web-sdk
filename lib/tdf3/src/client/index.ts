import { v4 } from 'uuid';
import {
  ZipReader,
  streamToBuffer,
  keyMiddleware as defaultKeyMiddleware,
} from '../utils/index.js';
import { base64 } from '../../../src/encodings/index.js';
import {
  buildKeyAccess,
  EncryptConfiguration,
  fetchKasPublicKey,
  loadTDFStream,
  validatePolicyObject,
  readStream,
  writeStream,
} from '../tdf.js';
import { unwrapHtml } from '../utils/unwrap.js';
import { OIDCRefreshTokenProvider } from '../../../src/auth/oidc-refreshtoken-provider.js';
import { OIDCExternalJwtProvider } from '../../../src/auth/oidc-externaljwt-provider.js';
import { CryptoService } from '../crypto/declarations.js';
import { type AuthProvider, HttpRequest, withHeaders } from '../../../src/auth/auth.js';
import { pemToCryptoPublicKey, rstrip, validateSecureUrl } from '../../../src/utils.js';

import {
  EncryptParams,
  DecryptParams,
  type Scope,
  DecryptStreamMiddleware,
  EncryptKeyMiddleware,
  EncryptStreamMiddleware,
  SplitStep,
} from './builders.js';
import { DecoratedReadableStream } from './DecoratedReadableStream.js';

import {
  DEFAULT_SEGMENT_SIZE,
  DecryptParamsBuilder,
  type DecryptSource,
  EncryptParamsBuilder,
} from './builders.js';
import { KasPublicKeyInfo, OriginAllowList } from '../../../src/access.js';
import { ConfigurationError } from '../../../src/errors.js';
import { Binary } from '../binary.js';
import { AesGcmCipher } from '../ciphers/aes-gcm-cipher.js';
import { toCryptoKeyPair } from '../crypto/crypto-utils.js';
import * as defaultCryptoService from '../crypto/index.js';
import { type AttributeObject, type Policy, SplitKey } from '../models/index.js';
import { plan } from '../../../src/policy/granter.js';
import { attributeFQNsAsValues } from '../../../src/policy/api.js';
import { type Value } from '../../../src/policy/attributes.js';
import { type Chunker, fromBuffer, fromSource } from '../../../src/seekable.js';

const GLOBAL_BYTE_LIMIT = 64 * 1000 * 1000 * 1000; // 64 GB, see WS-9363.

// No default config for now. Delegate to Virtru wrapper for endpoints.
const defaultClientConfig = { oidcOrigin: '', cryptoService: defaultCryptoService };

const getFirstTwoBytes = async (chunker: Chunker) => new TextDecoder().decode(await chunker(0, 2));

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
  kasEndpoint?: string;
  /**
   * Service to use to look up ABAC. Used during autoconfigure. Defaults to
   * kasEndpoint without the trailing `/kas` path segment, if present.
   */
  policyEndpoint?: string;
  /**
   * List of allowed KASes to connect to for rewrap requests.
   * Defaults to `[kasEndpoint]`.
   */
  allowedKases?: string[];
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
  readonly allowedKases: OriginAllowList;

  readonly kasKeys: Record<string, Promise<KasPublicKeyInfo>> = {};

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
    if (clientConfig.policyEndpoint) {
      this.policyEndpoint = rstrip(clientConfig.policyEndpoint, '/');
    } else if (this.kasEndpoint.endsWith('/kas')) {
      this.policyEndpoint = this.kasEndpoint.slice(0, -4);
    }

    const kasOrigin = new URL(this.kasEndpoint).origin;
    if (clientConfig.allowedKases) {
      this.allowedKases = new OriginAllowList(
        clientConfig.allowedKases,
        !!clientConfig.ignoreAllowList
      );
      if (!validateSecureUrl(this.kasEndpoint) && !this.allowedKases.allows(kasOrigin)) {
        throw new ConfigurationError(`Invalid KAS endpoint [${this.kasEndpoint}]`);
      }
    } else {
      if (!validateSecureUrl(this.kasEndpoint)) {
        throw new ConfigurationError(
          `Invalid KAS endpoint [${this.kasEndpoint}]; to force, please list it among allowedKases`
        );
      }
      this.allowedKases = new OriginAllowList([kasOrigin], !!clientConfig.ignoreAllowList);
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
    if (clientConfig.kasPublicKey) {
      this.kasKeys[this.kasEndpoint] = Promise.resolve({
        url: this.kasEndpoint,
        algorithm: 'rsa:2048',
        key: pemToCryptoPublicKey(clientConfig.kasPublicKey),
        publicKey: clientConfig.kasPublicKey,
      });
    }
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
      streamMiddleware = async (stream: DecoratedReadableStream) => stream,
    } = opts;
    const scope = opts.scope ?? { attributes: [], dissem: [] };

    const policyObject = asPolicy(scope);
    validatePolicyObject(policyObject);

    let splitPlan = opts.splitPlan;
    if (!splitPlan && autoconfigure) {
      let avs: Value[] = scope.attributeValues ?? [];
      const fqns: string[] = scope.attributes
        ? scope.attributes.map((attribute) =>
            typeof attribute === 'string' ? attribute : attribute.attribute
          )
        : [];

      if (!avs.length && fqns.length) {
        // Hydrate avs from policy endpoint givnen the fqns
        if (!this.policyEndpoint) {
          throw new ConfigurationError('policyEndpoint not set in TDF3 Client constructor');
        }
        avs = await attributeFQNsAsValues(
          this.policyEndpoint,
          this.authProvider as AuthProvider,
          ...fqns
        );
      } else if (scope.attributeValues) {
        avs = scope.attributeValues;
        if (!scope.attributes) {
          scope.attributes = avs.map(({ fqn }) => fqn);
        }
      }
      if (
        avs.length != (scope.attributes?.length || 0) ||
        !avs.map(({ fqn }) => fqn).every((a) => fqns.indexOf(a) >= 0)
      ) {
        throw new ConfigurationError(
          `Attribute mismatch between [${fqns}] and explicit values ${JSON.stringify(
            avs.map(({ fqn }) => fqn)
          )}`
        );
      }
      const detailedPlan = plan(avs);
      splitPlan = detailedPlan.map((kat) => {
        const { kas, sid } = kat;
        if (kas?.publicKey?.cached?.keys && !(kas.uri in this.kasKeys)) {
          const keys = kas.publicKey.cached.keys.filter(
            ({ alg }) => alg == 'KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048'
          );
          if (keys?.length) {
            const key = keys[0];
            this.kasKeys[kas.uri] = Promise.resolve({
              key: pemToCryptoPublicKey(key.pem),
              publicKey: key.pem,
              url: kas.uri,
              algorithm: 'rsa:2048',
              kid: key.kid,
            });
          }
        }
        return { kas: kas.uri, sid };
      });
    }

    // TODO: Refactor underlying builder to remove some of this unnecessary config.

    const maxByteLimit = GLOBAL_BYTE_LIMIT;
    const byteLimit =
      opts.byteLimit === undefined || opts.byteLimit <= 0 || opts.byteLimit > maxByteLimit
        ? maxByteLimit
        : opts.byteLimit;
    const encryptionInformation = new SplitKey(new AesGcmCipher(this.cryptoService));
    const splits: SplitStep[] = splitPlan?.length
      ? splitPlan
      : [{ kas: opts.defaultKASEndpoint ?? this.kasEndpoint }];
    encryptionInformation.keyAccess = await Promise.all(
      splits.map(async ({ kas, sid }) => {
        if (!(kas in this.kasKeys)) {
          this.kasKeys[kas] = fetchKasPublicKey(kas);
        }
        const kasPublicKey = await this.kasKeys[kas];
        return buildKeyAccess({
          type: 'wrapped',
          url: kasPublicKey.url,
          kid: kasPublicKey.kid,
          publicKey: kasPublicKey.publicKey,
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
  }: DecryptParams): Promise<DecoratedReadableStream> {
    const dpopKeys = await this.dpopKeys;
    if (!this.authProvider) {
      throw new ConfigurationError('AuthProvider missing');
    }
    const chunker = await makeChunkable(source);
    if (!allowList) {
      allowList = this.allowedKases;
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
