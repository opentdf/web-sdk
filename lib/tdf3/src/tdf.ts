import { exportSPKI, importX509 } from 'jose';

import {
  KasPublicKeyAlgorithm,
  KasPublicKeyInfo,
  OriginAllowList,
  fetchKasPubKey as fetchKasPubKeyV2,
  fetchWrappedKey,
  publicKeyAlgorithmToJwa,
} from '../../src/access.js';
import { create, toJsonString } from '@bufbuild/protobuf';
import {
  KeyAccessSchema,
  UnsignedRewrapRequestSchema,
  UnsignedRewrapRequest_WithPolicyRequestSchema,
  UnsignedRewrapRequest_WithPolicySchema,
  UnsignedRewrapRequest_WithKeyAccessObjectSchema,
} from '../../src/platform/kas/kas_pb.js';
import { type AuthProvider, reqSignature } from '../../src/auth/auth.js';
import { handleRpcRewrapErrorString } from '../../src/access/access-rpc.js';
import { allPool, anyPool } from '../../src/concurrency.js';
import { base64, hex } from '../../src/encodings/index.js';
import {
  ConfigurationError,
  DecryptError,
  InvalidFileError,
  IntegrityError,
  NetworkError,
  UnsafeUrlError,
  UnsupportedFeatureError as UnsupportedError,
} from '../../src/errors.js';
import { generateKeyPair } from '../../src/nanotdf-crypto/generateKeyPair.js';
import { keyAgreement } from '../../src/nanotdf-crypto/keyAgreement.js';
import { pemPublicToCrypto } from '../../src/nanotdf-crypto/pemPublicToCrypto.js';
import { type Chunker } from '../../src/seekable.js';
import { tdfSpecVersion } from '../../src/version.js';
import { AssertionConfig, AssertionKey, AssertionVerificationKeys } from './assertions.js';
import * as assertions from './assertions.js';
import { Binary } from './binary.js';
import { AesGcmCipher } from './ciphers/aes-gcm-cipher.js';
import { SymmetricCipher } from './ciphers/symmetric-cipher-base.js';
import { DecryptParams } from './client/builders.js';
import { DecoratedReadableStream } from './client/DecoratedReadableStream.js';
import {
  AnyKeyPair,
  PemKeyPair,
  type CryptoService,
  type DecryptResult,
} from './crypto/declarations.js';
import {
  ECWrapped,
  KeyAccessType,
  KeyInfo,
  Manifest,
  Policy,
  SplitKey,
  Wrapped,
  KeyAccess,
  KeyAccessObject,
  SplitType,
} from './models/index.js';
import { unsigned } from './utils/buffer-crc32.js';
import { ZipReader, ZipWriter, keyMerge, concatUint8, buffToString } from './utils/index.js';
import { CentralDirectory } from './utils/zip-reader.js';
import { ztdfSalt } from './crypto/salt.js';
import { Payload } from './models/payload.js';
import {
  getRequiredObligationFQNs,
  upgradeRewrapResponseV1,
  getPlatformUrlFromKasEndpoint,
} from '../../src/utils.js';

// TODO: input validation on manifest JSON
const DEFAULT_SEGMENT_SIZE = 1024 * 1024;

const HEX_SEMVER_VERSION = '4.2.2';

/**
 * Configuration for TDF3
 */
export type EncryptionOptions = {
  /**
   * Defaults to `split`, the currently only implmented key wrap algorithm.
   */
  type?: SplitType;
  // Defaults to AES-256-GCM for the encryption.
  cipher?: string;
};

type KeyMiddleware = DecryptParams['keyMiddleware'];

export type Metadata = unknown;

export type BuildKeyAccess = {
  type: KeyAccessType;
  alg?: KasPublicKeyAlgorithm;
  url?: string;
  kid?: string;
  publicKey: string;
  metadata?: Metadata;
  sid?: string;
};

type Segment = {
  hash: string;
  segmentSize?: number;
  encryptedSegmentSize?: number;
};

type EntryInfo = {
  filename: string;
  offset?: number;
  crcCounter?: number;
  fileByteCount?: number;
};

type Mailbox<T> = Promise<T> & {
  set: (value: T) => void;
  reject: (error: Error) => void;
};

function mailbox<T>(): Mailbox<T> {
  let set: (value: T) => void;
  let reject: (error: Error) => void;

  const promise = new Promise<T>((resolve, rejectFn) => {
    set = resolve;
    reject = rejectFn;
  }) as Mailbox<T>;

  promise.set = set!;
  promise.reject = reject!;

  return promise;
}

type Chunk = {
  hash: string;
  plainSegmentSize?: number;
  encryptedOffset: number;
  encryptedSegmentSize?: number;
  decryptedChunk: Mailbox<DecryptResult>;
};

export type IntegrityAlgorithm = 'GMAC' | 'HS256';

export type EncryptConfiguration = {
  allowList?: OriginAllowList;
  cryptoService: CryptoService;
  dpopKeys: CryptoKeyPair;
  encryptionInformation: SplitKey;
  segmentSizeDefault: number;
  integrityAlgorithm: IntegrityAlgorithm;
  segmentIntegrityAlgorithm: IntegrityAlgorithm;
  contentStream: ReadableStream<Uint8Array>;
  mimeType?: string;
  policy: Policy;
  authProvider?: AuthProvider;
  byteLimit: number;
  progressHandler?: (bytesProcessed: number) => void;
  keyForEncryption: KeyInfo;
  keyForManifest: KeyInfo;
  assertionConfigs?: AssertionConfig[];
  systemMetadataAssertion?: boolean;
  tdfSpecVersion?: string;
};

export type DecryptConfiguration = {
  fulfillableObligations: string[];
  allowedKases?: string[];
  allowList?: OriginAllowList;
  authProvider: AuthProvider;
  cryptoService: CryptoService;

  dpopKeys: CryptoKeyPair;

  chunker: Chunker;
  keyMiddleware: KeyMiddleware;
  progressHandler?: (bytesProcessed: number) => void;
  fileStreamServiceWorker?: string;
  assertionVerificationKeys?: AssertionVerificationKeys;
  noVerifyAssertions?: boolean;
  concurrencyLimit?: number;
  wrappingKeyAlgorithm?: KasPublicKeyAlgorithm;
};

export type UpsertConfiguration = {
  allowedKases?: string[];
  allowList?: OriginAllowList;
  authProvider: AuthProvider;

  privateKey: CryptoKey;

  unsavedManifest: Manifest;
  // if true skips the key access type check when syncing
  ignoreType?: boolean;
};

export type RewrapRequest = {
  signedRequestToken: string;
};

export type KasPublicKeyFormat = 'pkcs8' | 'jwks';

/**
 * If we have KAS url but not public key we can fetch it from KAS, fetching
 * the value from `${kas}/kas_public_key`.
 */
export async function fetchKasPublicKey(
  kas: string,
  algorithm?: KasPublicKeyAlgorithm,
  kid?: string
): Promise<KasPublicKeyInfo> {
  if (kid) {
    // Some specific thing for fetching a key by kid?
    // Currently this is just "using" `kid` so TypeScript doesn't complain and
    // we can use the type for our cache parameters.
    // So this empty `if` is actually doing something.
  }
  return fetchKasPubKeyV2(kas, algorithm);
}

export async function extractPemFromKeyString(
  keyString: string,
  alg: KasPublicKeyAlgorithm
): Promise<string> {
  let pem: string = keyString;

  // Skip the public key extraction if we find that the KAS url provides a
  // PEM-encoded key instead of certificate
  if (keyString.includes('CERTIFICATE')) {
    const a = publicKeyAlgorithmToJwa(alg);
    const cert = await importX509(keyString, a, { extractable: true });
    pem = await exportSPKI(cert);
  }

  return pem;
}

/**
 * Build a key access object and add it to the list. Can specify either
 * a (url, publicKey) pair (legacy, deprecated) or an attribute URL (future).
 * If all are missing then it attempts to use the default attribute. If that
 * is missing it throws an error.
 * @param  {Object} options
 * @param  {String} options.type - enum representing how the object key is treated
 * @param  {String} options.url - directly set the KAS URL
 * @param  {String} options.publicKey - directly set the (KAS) public key
 * @param  {String?} options.kid - Key identifier of KAS public key
 * @param  {String? Object?} options.metadata - Metadata. Appears to be dead code.
 * @return {KeyAccess}- the key access object loaded
 */
export async function buildKeyAccess({
  type,
  url,
  publicKey,
  kid,
  metadata,
  sid = '',
  alg = 'rsa:2048',
}: BuildKeyAccess): Promise<KeyAccess> {
  // if url and pulicKey are specified load the key access object with them
  if (!url && !publicKey) {
    throw new ConfigurationError('TDF.buildKeyAccess: No source for kasUrl or pubKey');
  } else if (!url) {
    throw new ConfigurationError('TDF.buildKeyAccess: No kasUrl');
  } else if (!publicKey) {
    throw new ConfigurationError('TDF.buildKeyAccess: No kas public key');
  }

  let pubKey: string;
  try {
    pubKey = await extractPemFromKeyString(publicKey, alg);
  } catch (e) {
    throw new ConfigurationError(
      `TDF.buildKeyAccess: Invalid public key [${publicKey}], caused by [${e}]`,
      e
    );
  }
  switch (type) {
    case 'wrapped':
      return new Wrapped(url, kid, pubKey, metadata, sid);
    case 'ec-wrapped':
      return new ECWrapped(url, kid, pubKey, metadata, sid);
    default:
      throw new ConfigurationError(`buildKeyAccess: Key access type [${type}] is unsupported`);
  }
}

export function validatePolicyObject(policy: Policy): void {
  const missingFields: string[] = [];

  if (!policy.uuid) missingFields.push('uuid');
  if (!policy.body) missingFields.push('body', 'body.dissem');
  if (policy.body && !policy.body.dissem) missingFields.push('body.dissem');

  if (missingFields.length) {
    throw new ConfigurationError(
      `The given policy object requires the following properties: ${missingFields}`
    );
  }
}

async function _generateManifest(
  keyInfo: KeyInfo,
  encryptionInformation: SplitKey,
  policy: Policy,
  mimeType?: string,
  targetSpecVersion?: string
): Promise<Manifest> {
  // (maybe) Fields are quoted to avoid renaming
  const payload: Payload = {
    type: 'reference',
    url: '0.payload',
    protocol: 'zip',
    isEncrypted: true,
    ...(mimeType && { mimeType }),
  };

  const encryptionInformationStr = await encryptionInformation.write(policy, keyInfo);
  const assertions: assertions.Assertion[] = [];
  const partial = {
    payload,
    // generate the manifest first, then insert integrity information into it
    encryptionInformation: encryptionInformationStr,
    assertions: assertions,
  };
  const schemaVersion = targetSpecVersion || tdfSpecVersion;
  if (schemaVersion === '4.2.2') {
    return partial;
  }
  return {
    ...partial,
    schemaVersion,
  };
}

async function getSignature(
  unwrappedKey: Uint8Array,
  content: Uint8Array,
  algorithmType: IntegrityAlgorithm
): Promise<Uint8Array> {
  switch (algorithmType.toUpperCase()) {
    case 'GMAC':
      // use the auth tag baked into the encrypted payload
      return content.slice(-16);
    case 'HS256': {
      // simple hmac is the default
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        unwrappedKey,
        {
          name: 'HMAC',
          hash: { name: 'SHA-256' },
        },
        true,
        ['sign', 'verify']
      );
      const signature = await crypto.subtle.sign('HMAC', cryptoKey, content);
      return new Uint8Array(signature);
    }
    default:
      throw new ConfigurationError(`Unsupported signature alg [${algorithmType}]`);
  }
}

async function getSignatureVersion422(
  unwrappedKeyBinary: Binary,
  payloadBinary: Binary,
  algorithmType: IntegrityAlgorithm,
  cryptoService: CryptoService
): Promise<string> {
  switch (algorithmType.toUpperCase()) {
    case 'GMAC':
      // use the auth tag baked into the encrypted payload
      return buffToString(Uint8Array.from(payloadBinary.asByteArray()).slice(-16), 'hex');
    case 'HS256':
      return await cryptoService.hmac(
        buffToString(new Uint8Array(unwrappedKeyBinary.asArrayBuffer()), 'hex'),
        buffToString(new Uint8Array(payloadBinary.asArrayBuffer()), 'utf-8')
      );
    default:
      throw new ConfigurationError(`Unsupported signature alg [${algorithmType}]`);
  }
}

function isTargetSpecLegacyTDF(targetSpecVersion?: string): boolean {
  return targetSpecVersion === HEX_SEMVER_VERSION;
}

export async function writeStream(cfg: EncryptConfiguration): Promise<DecoratedReadableStream> {
  if (!cfg.authProvider) {
    throw new ConfigurationError('No authorization middleware defined');
  }
  if (!cfg.contentStream) {
    throw new ConfigurationError('No input stream defined');
  }

  // eslint-disable-next-line @typescript-eslint/no-this-alias
  const segmentInfos: Segment[] = [];

  cfg.byteLimit ??= Number.MAX_SAFE_INTEGER;

  const entryInfos: EntryInfo[] = [
    {
      filename: '0.payload',
    },
    {
      filename: '0.manifest.json',
    },
  ];

  let currentBuffer = new Uint8Array();

  let totalByteCount = 0;
  let bytesProcessed = 0;
  let crcCounter = 0;
  let fileByteCount = 0;
  let aggregateHash422 = '';
  const segmentHashList: Uint8Array[] = [];

  const zipWriter = new ZipWriter();
  const manifest = await _generateManifest(
    cfg.keyForManifest,
    cfg.encryptionInformation,
    cfg.policy,
    cfg.mimeType,
    cfg.tdfSpecVersion
  );

  if (!manifest) {
    // Set in encrypt; should never be reached.
    throw new ConfigurationError('internal: please use "loadTDFStream" first to load a manifest.');
  }

  // determine default segment size by writing empty buffer
  const { segmentSizeDefault } = cfg;
  const encryptedBlargh = await cfg.encryptionInformation.encrypt(
    Binary.fromArrayBuffer(new ArrayBuffer(segmentSizeDefault)),
    cfg.keyForEncryption.unwrappedKeyBinary
  );
  const payloadBuffer = new Uint8Array(encryptedBlargh.payload.asByteArray());
  const encryptedSegmentSizeDefault = payloadBuffer.length;

  // start writing the content
  entryInfos[0].filename = '0.payload';
  entryInfos[0].offset = totalByteCount;
  const sourceReader = cfg.contentStream.getReader();

  /*
  TODO: Code duplication should be addressed
  - RCA operations require that the write stream has already finished executing it's .on('end') handler before being returned,
    thus both handlers are wrapped in a encompassing promise when we have an RCA source. We should investigate
    if this causes O(n) promises to be loaded into memory.
  - LFS operations can have the write stream returned immediately after both .on('end') and .on('data') handlers
    have been defined, thus not requiring the handlers to be wrapped in a promise.
  */
  const underlingSource = {
    start: (controller: ReadableStreamDefaultController) => {
      controller.enqueue(getHeader(entryInfos[0].filename));
      _countChunk(getHeader(entryInfos[0].filename));
      crcCounter = 0;
      fileByteCount = 0;
    },

    pull: async (controller: ReadableStreamDefaultController) => {
      let isDone;

      while (currentBuffer.length < segmentSizeDefault && !isDone) {
        const { value, done } = await sourceReader.read();
        isDone = done;
        if (value) {
          currentBuffer = concatUint8([currentBuffer, value]);
        }
      }

      while (
        currentBuffer.length >= segmentSizeDefault &&
        !!controller.desiredSize &&
        controller.desiredSize > 0
      ) {
        const segment = currentBuffer.slice(0, segmentSizeDefault);
        const encryptedSegment = await _encryptAndCountSegment(segment);
        controller.enqueue(encryptedSegment);

        currentBuffer = currentBuffer.slice(segmentSizeDefault);
      }

      const isFinalChunkLeft = isDone && currentBuffer.length;

      if (isFinalChunkLeft) {
        const encryptedSegment = await _encryptAndCountSegment(currentBuffer);
        controller.enqueue(encryptedSegment);
        currentBuffer = new Uint8Array();
      }

      if (isDone && currentBuffer.length === 0) {
        entryInfos[0].crcCounter = crcCounter;
        entryInfos[0].fileByteCount = fileByteCount;
        const payloadDataDescriptor = zipWriter.writeDataDescriptor(crcCounter, fileByteCount);

        controller.enqueue(payloadDataDescriptor);
        _countChunk(payloadDataDescriptor);

        // prepare the manifest
        entryInfos[1].filename = '0.manifest.json';
        entryInfos[1].offset = totalByteCount;
        controller.enqueue(getHeader(entryInfos[1].filename));
        _countChunk(getHeader(entryInfos[1].filename));
        crcCounter = 0;
        fileByteCount = 0;

        let aggregateHash: string | Uint8Array;
        if (isTargetSpecLegacyTDF(cfg.tdfSpecVersion)) {
          aggregateHash = aggregateHash422;
          const payloadSigStr = await getSignatureVersion422(
            cfg.keyForEncryption.unwrappedKeyBinary,
            Binary.fromString(aggregateHash),
            cfg.integrityAlgorithm,
            cfg.cryptoService
          );
          manifest.encryptionInformation.integrityInformation.rootSignature.sig =
            base64.encode(payloadSigStr);
        } else {
          // hash the concat of all hashes
          aggregateHash = await concatenateUint8Array(segmentHashList);

          const payloadSig = await getSignature(
            new Uint8Array(cfg.keyForEncryption.unwrappedKeyBinary.asArrayBuffer()),
            aggregateHash,
            cfg.integrityAlgorithm
          );

          const rootSig = base64.encodeArrayBuffer(payloadSig);
          manifest.encryptionInformation.integrityInformation.rootSignature.sig = rootSig;
        }
        manifest.encryptionInformation.integrityInformation.rootSignature.alg =
          cfg.integrityAlgorithm;

        manifest.encryptionInformation.integrityInformation.segmentSizeDefault = segmentSizeDefault;
        manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault =
          encryptedSegmentSizeDefault;
        manifest.encryptionInformation.integrityInformation.segmentHashAlg =
          cfg.segmentIntegrityAlgorithm;
        manifest.encryptionInformation.integrityInformation.segments = segmentInfos;

        manifest.encryptionInformation.method.isStreamable = true;
        const signedAssertions: assertions.Assertion[] = [];
        if (cfg.systemMetadataAssertion) {
          const systemMetadataConfigBase = assertions.getSystemMetadataAssertionConfig();
          const signingKeyForSystemMetadata: AssertionKey = {
            alg: 'HS256', // Default algorithm, can be configured if needed
            key: new Uint8Array(cfg.keyForEncryption.unwrappedKeyBinary.asArrayBuffer()),
          };
          signedAssertions.push(
            await assertions.CreateAssertion(
              aggregateHash,
              {
                ...systemMetadataConfigBase, // Spread the properties from the base config
                signingKey: signingKeyForSystemMetadata, // Add the signing key
              },
              cfg.tdfSpecVersion // Pass the TDF spec version
            )
          );
        }
        if (cfg.assertionConfigs && cfg.assertionConfigs.length > 0) {
          await Promise.all(
            cfg.assertionConfigs.map(async (assertionConfig) => {
              // Create assertion using the assertionConfig values
              const signingKey: AssertionKey = assertionConfig.signingKey ?? {
                alg: 'HS256',
                key: new Uint8Array(cfg.keyForEncryption.unwrappedKeyBinary.asArrayBuffer()),
              };
              const assertion = await assertions.CreateAssertion(
                aggregateHash,
                {
                  ...assertionConfig,
                  signingKey,
                },
                cfg.tdfSpecVersion
              );

              // Add signed assertion to the signedAssertions array
              signedAssertions.push(assertion);
            })
          );
        }

        manifest.assertions = signedAssertions;

        // write the manifest
        const manifestBuffer = new TextEncoder().encode(JSON.stringify(manifest));
        controller.enqueue(manifestBuffer);
        _countChunk(manifestBuffer);
        entryInfos[1].crcCounter = crcCounter;
        entryInfos[1].fileByteCount = fileByteCount;
        const manifestDataDescriptor = zipWriter.writeDataDescriptor(crcCounter, fileByteCount);
        controller.enqueue(manifestDataDescriptor);
        _countChunk(manifestDataDescriptor);

        // write the central directory out
        const centralDirectoryByteCount = totalByteCount;
        for (let i = 0; i < entryInfos.length; i++) {
          const entryInfo = entryInfos[i];
          const result = zipWriter.writeCentralDirectoryRecord(
            entryInfo.fileByteCount || 0,
            entryInfo.filename,
            entryInfo.offset || 0,
            entryInfo.crcCounter || 0,
            2175008768
          );
          controller.enqueue(result);
          _countChunk(result);
        }
        const endOfCentralDirectoryByteCount = totalByteCount - centralDirectoryByteCount;
        const finalChunk = zipWriter.writeEndOfCentralDirectoryRecord(
          entryInfos.length,
          endOfCentralDirectoryByteCount,
          centralDirectoryByteCount
        );
        controller.enqueue(finalChunk);
        _countChunk(finalChunk);

        controller.close();
      }
    },
  };

  const plaintextStream = new DecoratedReadableStream(underlingSource);
  plaintextStream.manifest = manifest;

  return plaintextStream;

  // nested helper fn's
  function getHeader(filename: string) {
    return zipWriter.getLocalFileHeader(filename, 0, 0, 0);
  }

  function _countChunk(chunk: string | Uint8Array) {
    if (typeof chunk === 'string') {
      chunk = new TextEncoder().encode(chunk);
    }
    totalByteCount += chunk.length;
    if (totalByteCount > cfg.byteLimit) {
      throw new ConfigurationError(`Safe byte limit (${cfg.byteLimit}) exceeded`);
    }
    //new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    crcCounter = unsigned(chunk, crcCounter);
    fileByteCount += chunk.length;
  }

  async function _encryptAndCountSegment(chunk: Uint8Array) {
    bytesProcessed += chunk.length;
    cfg.progressHandler?.(bytesProcessed);

    // Don't pass in an IV here. The encrypt function will generate one for you, ensuring that each segment has a unique IV.
    const encryptedResult = await cfg.encryptionInformation.encrypt(
      Binary.fromArrayBuffer(chunk.buffer),
      cfg.keyForEncryption.unwrappedKeyBinary
    );
    const payloadBuffer = new Uint8Array(encryptedResult.payload.asByteArray());
    let hash: string;
    if (isTargetSpecLegacyTDF(cfg.tdfSpecVersion)) {
      const payloadSigStr = await getSignatureVersion422(
        cfg.keyForEncryption.unwrappedKeyBinary,
        encryptedResult.payload,
        cfg.segmentIntegrityAlgorithm,
        cfg.cryptoService
      );
      // combined string of all hashes for root signature
      aggregateHash422 += payloadSigStr;
      hash = base64.encode(payloadSigStr);
    } else {
      const payloadSig = await getSignature(
        new Uint8Array(cfg.keyForEncryption.unwrappedKeyBinary.asArrayBuffer()),
        new Uint8Array(encryptedResult.payload.asArrayBuffer()),
        cfg.segmentIntegrityAlgorithm
      );

      segmentHashList.push(new Uint8Array(payloadSig));
      hash = base64.encodeArrayBuffer(payloadSig);
    }

    segmentInfos.push({
      hash,
      segmentSize: chunk.length === segmentSizeDefault ? undefined : chunk.length,
      encryptedSegmentSize:
        payloadBuffer.length === encryptedSegmentSizeDefault ? undefined : payloadBuffer.length,
    });
    const result = new Uint8Array(encryptedResult.payload.asByteArray());
    _countChunk(result);

    return result;
  }
}

export type InspectedTDFOverview = {
  manifest: Manifest;
  zipReader: ZipReader;
  centralDirectory: CentralDirectory[];
};

// load the TDF as a stream in memory, for further use in reading and key syncing
export async function loadTDFStream(chunker: Chunker): Promise<InspectedTDFOverview> {
  const zipReader = new ZipReader(chunker);
  const centralDirectory = await zipReader.getCentralDirectory();
  const manifest = await zipReader.getManifest(centralDirectory, '0.manifest.json');
  return { manifest, zipReader, centralDirectory };
}

export function splitLookupTableFactory(
  keyAccess: KeyAccessObject[],
  allowedKases: OriginAllowList
): Record<string, Record<string, KeyAccessObject>> {
  const allowed = (k: KeyAccessObject) => allowedKases.allows(k.url);
  const splitIds = new Set(keyAccess.map(({ sid }) => sid ?? ''));

  const accessibleSplits = new Set(keyAccess.filter(allowed).map(({ sid }) => sid));
  if (splitIds.size > accessibleSplits.size) {
    const disallowedKases = new Set(keyAccess.filter((k) => !allowed(k)).map(({ url }) => url));
    throw new UnsafeUrlError(
      `Unreconstructable key - disallowed KASes include: ${JSON.stringify([
        ...disallowedKases,
      ])} from splitIds ${JSON.stringify([...splitIds])}`,
      ...disallowedKases
    );
  }
  const splitPotentials: Record<string, Record<string, KeyAccessObject>> = Object.fromEntries(
    [...splitIds].map((s) => [s, {}])
  );
  for (const kao of keyAccess) {
    const disjunction = splitPotentials[kao.sid ?? ''];
    if (kao.url in disjunction) {
      throw new InvalidFileError(
        `TODO: Fallback to no split ids. Repetition found for [${kao.url}] on split [${kao.sid}]`
      );
    }
    if (allowed(kao)) {
      disjunction[kao.url] = kao;
    }
  }
  return splitPotentials;
}

type RewrapResponseData = {
  key: Uint8Array;
  metadata: Record<string, unknown>;
  requiredObligations: string[];
};

async function unwrapKey({
  manifest,
  allowedKases,
  authProvider,
  dpopKeys,
  concurrencyLimit,
  cryptoService,
  wrappingKeyAlgorithm,
  fulfillableObligations,
}: {
  manifest: Manifest;
  allowedKases: OriginAllowList;
  authProvider: AuthProvider;
  concurrencyLimit?: number;
  dpopKeys: CryptoKeyPair;
  cryptoService: CryptoService;
  wrappingKeyAlgorithm?: KasPublicKeyAlgorithm;
  fulfillableObligations: string[];
}) {
  if (authProvider === undefined) {
    throw new ConfigurationError(
      'rewrap requires auth provider; must be configured in client constructor'
    );
  }
  const { keyAccess } = manifest.encryptionInformation;
  const splitPotentials = splitLookupTableFactory(keyAccess, allowedKases);

  async function tryKasRewrap(keySplitInfo: KeyAccessObject): Promise<RewrapResponseData> {
    const url = `${keySplitInfo.url}/v2/rewrap`;
    let ephemeralEncryptionKeysRaw: AnyKeyPair;
    let ephemeralEncryptionKeys: PemKeyPair;
    if (wrappingKeyAlgorithm === 'ec:secp256r1') {
      ephemeralEncryptionKeysRaw = await generateKeyPair();
      ephemeralEncryptionKeys = await cryptoService.cryptoToPemPair(ephemeralEncryptionKeysRaw);
    } else if (wrappingKeyAlgorithm === 'rsa:2048' || !wrappingKeyAlgorithm) {
      ephemeralEncryptionKeysRaw = await cryptoService.generateKeyPair();
      ephemeralEncryptionKeys = await cryptoService.cryptoToPemPair(ephemeralEncryptionKeysRaw);
    } else {
      throw new ConfigurationError(`Unsupported wrapping key algorithm [${wrappingKeyAlgorithm}]`);
    }

    const clientPublicKey = ephemeralEncryptionKeys.publicKey;

    // Convert keySplitInfo to protobuf KeyAccess
    const keyAccessProto = create(KeyAccessSchema, {
      ...(keySplitInfo.type && { keyType: keySplitInfo.type }),
      ...(keySplitInfo.url && { kasUrl: keySplitInfo.url }),
      ...(keySplitInfo.protocol && { protocol: keySplitInfo.protocol }),
      ...(keySplitInfo.wrappedKey && {
        wrappedKey: new Uint8Array(base64.decodeArrayBuffer(keySplitInfo.wrappedKey)),
      }),
      ...(keySplitInfo.policyBinding && { policyBinding: keySplitInfo.policyBinding }),
      ...(keySplitInfo.kid && { kid: keySplitInfo.kid }),
      ...(keySplitInfo.sid && { splitId: keySplitInfo.sid }),
      ...(keySplitInfo.encryptedMetadata && { encryptedMetadata: keySplitInfo.encryptedMetadata }),
      ...(keySplitInfo.ephemeralPublicKey && {
        ephemeralPublicKey: keySplitInfo.ephemeralPublicKey,
      }),
    });

    // Create the protobuf request
    const unsignedRequest = create(UnsignedRewrapRequestSchema, {
      clientPublicKey,
      requests: [
        create(UnsignedRewrapRequest_WithPolicyRequestSchema, {
          keyAccessObjects: [
            create(UnsignedRewrapRequest_WithKeyAccessObjectSchema, {
              keyAccessObjectId: 'kao-0',
              keyAccessObject: keyAccessProto,
            }),
          ],
          ...(manifest.encryptionInformation.policy && {
            policy: create(UnsignedRewrapRequest_WithPolicySchema, {
              id: 'policy',
              body: manifest.encryptionInformation.policy,
            }),
          }),
        }),
      ],
      // include deprecated fields for backward compatibility
      algorithm: 'RS256',
      keyAccess: keyAccessProto,
      policy: manifest.encryptionInformation.policy,
    });

    const requestBodyStr = toJsonString(UnsignedRewrapRequestSchema, unsignedRequest);

    const jwtPayload = { requestBody: requestBodyStr };
    const signedRequestToken = await reqSignature(jwtPayload, dpopKeys.privateKey);

    const rewrapResp = await fetchWrappedKey(
      url,
      signedRequestToken,
      authProvider,
      fulfillableObligations
    );
    // Upgrade V1 response to V2 format if needed
    upgradeRewrapResponseV1(rewrapResp);
    const { sessionPublicKey } = rewrapResp;
    const requiredObligations = getRequiredObligationFQNs(rewrapResp);
    // Assume only one response and one result for now (V1 style)
    const result = rewrapResp.responses?.[0]?.results?.[0];
    if (!result) {
      // This should not happen - KAS should always return at least one response and one result
      // or the upgradeRewrapResponseV1 should have created them
      throw new DecryptError('KAS rewrap response missing expected response or result');
    }
    const metadata = result.metadata;
    // Handle the different cases of result.result
    switch (result.result.case) {
      case 'kasWrappedKey': {
        const entityWrappedKey = result.result.value;

        if (wrappingKeyAlgorithm === 'ec:secp256r1') {
          const serverEphemeralKey: CryptoKey = await pemPublicToCrypto(sessionPublicKey);
          const ekr = ephemeralEncryptionKeysRaw as CryptoKeyPair;
          const kek = await keyAgreement(ekr.privateKey, serverEphemeralKey, {
            hkdfSalt: await ztdfSalt,
            hkdfHash: 'SHA-256',
          });
          const wrappedKeyAndNonce = entityWrappedKey;
          const iv = wrappedKeyAndNonce.slice(0, 12);
          const wrappedKey = wrappedKeyAndNonce.slice(12);

          const dek = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kek, wrappedKey);

          return {
            key: new Uint8Array(dek),
            metadata,
            requiredObligations,
          };
        }
        const key = Binary.fromArrayBuffer(entityWrappedKey);
        const decryptedKeyBinary = await cryptoService.decryptWithPrivateKey(
          key,
          ephemeralEncryptionKeys.privateKey
        );

        return {
          key: new Uint8Array(decryptedKeyBinary.asByteArray()),
          metadata,
          requiredObligations,
        };
      }

      case 'error': {
        handleRpcRewrapErrorString(
          result.result.value,
          getPlatformUrlFromKasEndpoint(url),
          requiredObligations
        );
      }

      default: {
        throw new DecryptError('KAS rewrap response missing wrapped key');
      }
    }
  }

  let poolSize = 1;
  if (concurrencyLimit !== undefined && concurrencyLimit > 1) {
    poolSize = concurrencyLimit;
  }
  const splitPromises: Record<string, () => Promise<RewrapResponseData>> = {};
  for (const splitId of Object.keys(splitPotentials)) {
    const potentials = splitPotentials[splitId];
    if (!potentials || !Object.keys(potentials).length) {
      throw new UnsafeUrlError(
        `Unreconstructable key - no valid KAS found for split ${JSON.stringify(splitId)}`,
        ''
      );
    }
    const anyPromises: Record<string, () => Promise<RewrapResponseData>> = {};
    for (const [kas, keySplitInfo] of Object.entries(potentials)) {
      anyPromises[kas] = async () => {
        try {
          return await tryKasRewrap(keySplitInfo);
        } catch (e) {
          throw handleRewrapError(e as Error);
        }
      };
    }
    splitPromises[splitId] = () => anyPool(poolSize, anyPromises);
  }
  try {
    const rewrapResponseData = await allPool(poolSize, splitPromises);
    const splitKeys = [];
    const requiredObligations = new Set<string>();
    for (const resp of rewrapResponseData) {
      splitKeys.push(resp.key);
      for (const requiredObligation of resp.requiredObligations) {
        requiredObligations.add(requiredObligation.toLowerCase());
      }
    }
    const reconstructedKey = keyMerge(splitKeys);
    return {
      reconstructedKeyBinary: Binary.fromArrayBuffer(reconstructedKey),
      metadata: rewrapResponseData[0].metadata, // Use metadata from first split
      requiredObligations: [...requiredObligations],
    };
  } catch (e) {
    if (e instanceof AggregateError) {
      const errors = e.errors;
      if (errors.length === 1) {
        throw errors[0];
      }
    }
    throw e;
  }
}

function handleRewrapError(error: Error) {
  if (error.name === 'InvalidAccessError' || error.name === 'OperationError') {
    return new DecryptError('unable to unwrap key from kas', error);
  }
  return error;
}

async function decryptChunk(
  encryptedChunk: Uint8Array,
  reconstructedKeyBinary: Binary,
  hash: string,
  cipher: SymmetricCipher,
  segmentIntegrityAlgorithm: IntegrityAlgorithm,
  specVersion: string
): Promise<DecryptResult> {
  if (segmentIntegrityAlgorithm !== 'GMAC' && segmentIntegrityAlgorithm !== 'HS256') {
    throw new UnsupportedError(`Unsupported integrity alg [${segmentIntegrityAlgorithm}]`);
  }
  const segmentSig = await getSignature(
    new Uint8Array(reconstructedKeyBinary.asArrayBuffer()),
    encryptedChunk,
    segmentIntegrityAlgorithm
  );

  const segmentHash = isTargetSpecLegacyTDF(specVersion)
    ? base64.encode(hex.encodeArrayBuffer(segmentSig))
    : base64.encodeArrayBuffer(segmentSig);

  if (hash !== segmentHash) {
    throw new IntegrityError('Failed integrity check on segment hash');
  }
  return await cipher.decrypt(encryptedChunk, reconstructedKeyBinary);
}

async function updateChunkQueue(
  chunkMap: Chunk[],
  centralDirectory: CentralDirectory[],
  zipReader: ZipReader,
  reconstructedKeyBinary: Binary,
  cipher: SymmetricCipher,
  segmentIntegrityAlgorithm: IntegrityAlgorithm,
  cryptoService: CryptoService,
  specVersion: string
) {
  const chunksInOneDownload = 500;
  let requests = [];
  const maxLength = 3;

  for (let i = 0; i < chunkMap.length; i += chunksInOneDownload) {
    if (requests.length === maxLength) {
      await Promise.all(requests);
      requests = [];
    }
    requests.push(
      (async () => {
        let buffer: Uint8Array | null;

        const slice = chunkMap.slice(i, i + chunksInOneDownload);
        try {
          const bufferSize = slice.reduce(
            (currentVal, { encryptedSegmentSize }) => currentVal + (encryptedSegmentSize as number),
            0
          );
          buffer = await zipReader.getPayloadSegment(
            centralDirectory,
            '0.payload',
            slice[0].encryptedOffset,
            bufferSize
          );
        } catch (e) {
          if (e instanceof InvalidFileError) {
            throw e;
          }
          throw new NetworkError('unable to fetch payload segment', e);
        }
        if (buffer) {
          sliceAndDecrypt({
            buffer,
            cryptoService,
            reconstructedKeyBinary,
            slice,
            cipher,
            segmentIntegrityAlgorithm,
            specVersion,
          });
        }
      })()
    );
  }
}

export async function sliceAndDecrypt({
  buffer,
  reconstructedKeyBinary,
  slice,
  cipher,
  segmentIntegrityAlgorithm,
  specVersion,
}: {
  buffer: Uint8Array;
  reconstructedKeyBinary: Binary;
  slice: Chunk[];
  cipher: SymmetricCipher;
  cryptoService: CryptoService;
  segmentIntegrityAlgorithm: IntegrityAlgorithm;
  specVersion: string;
}) {
  for (const index in slice) {
    const { encryptedOffset, encryptedSegmentSize, plainSegmentSize } = slice[index];

    const offset =
      slice[0].encryptedOffset === 0 ? encryptedOffset : encryptedOffset % slice[0].encryptedOffset;
    const encryptedChunk = new Uint8Array(
      buffer.slice(offset, offset + (encryptedSegmentSize as number))
    );

    if (encryptedChunk.length !== encryptedSegmentSize) {
      throw new DecryptError('Failed to fetch entire segment');
    }

    try {
      const result = await decryptChunk(
        encryptedChunk,
        reconstructedKeyBinary,
        slice[index]['hash'],
        cipher,
        segmentIntegrityAlgorithm,
        specVersion
      );
      if (plainSegmentSize && result.payload.length() !== plainSegmentSize) {
        throw new DecryptError(
          `incorrect segment size: found [${result.payload.length()}], expected [${plainSegmentSize}]`
        );
      }
      slice[index].decryptedChunk.set(result);
    } catch (e) {
      slice[index].decryptedChunk.reject(e);
    }
  }
}

export async function readStream(cfg: DecryptConfiguration) {
  const overview = await loadTDFStream(cfg.chunker);
  return decryptStreamFrom(cfg, overview);
}

export async function decryptStreamFrom(
  cfg: DecryptConfiguration,
  { manifest, zipReader, centralDirectory }: InspectedTDFOverview
) {
  let { allowList } = cfg;
  if (!allowList) {
    if (!cfg.allowedKases) {
      throw new ConfigurationError('Upsert cannot be done without allowlist');
    }
    allowList = new OriginAllowList(cfg.allowedKases);
  }

  if (!manifest) {
    throw new InvalidFileError('Missing manifest data');
  }

  cfg.keyMiddleware ??= async (key) => key;

  const {
    encryptedSegmentSizeDefault: defaultSegmentSize,
    rootSignature,
    segmentHashAlg,
    segmentSizeDefault,
    segments,
  } = manifest.encryptionInformation.integrityInformation;
  const { metadata, reconstructedKeyBinary, requiredObligations } = await unwrapKey({
    fulfillableObligations: cfg.fulfillableObligations,
    manifest,
    authProvider: cfg.authProvider,
    allowedKases: allowList,
    dpopKeys: cfg.dpopKeys,
    cryptoService: cfg.cryptoService,
  });
  // async function unwrapKey(manifest: Manifest, allowedKases: string[], authProvider: AuthProvider | AppIdAuthProvider, publicKey: string, privateKey: string, entity: EntityObject) {
  const keyForDecryption = await cfg.keyMiddleware(reconstructedKeyBinary);
  const encryptedSegmentSizeDefault = defaultSegmentSize || DEFAULT_SEGMENT_SIZE;

  // check if the TDF is a legacy TDF
  const specVersion = manifest.schemaVersion || manifest.tdf_spec_version || '4.2.2';
  const isLegacyTDF = isTargetSpecLegacyTDF(specVersion);

  // Decode each hash and store it in an array of Uint8Array
  const segmentHashList = segments.map(
    ({ hash }) => new Uint8Array(base64.decodeArrayBuffer(hash))
  );

  // Concatenate all segment hashes into a single Uint8Array
  const aggregateHash = await concatenateUint8Array(segmentHashList);

  const integrityAlgorithm = rootSignature.alg;
  if (integrityAlgorithm !== 'GMAC' && integrityAlgorithm !== 'HS256') {
    throw new UnsupportedError(`Unsupported integrity alg [${integrityAlgorithm}]`);
  }

  const payloadSig = await getSignature(
    new Uint8Array(keyForDecryption.asArrayBuffer()),
    aggregateHash,
    integrityAlgorithm
  );

  if (!cfg.noVerifyAssertions) {
    for (const assertion of manifest.assertions || []) {
      // Create a default assertion key
      let assertionKey: AssertionKey = {
        alg: 'HS256',
        key: new Uint8Array(reconstructedKeyBinary.asArrayBuffer()),
      };

      if (cfg.assertionVerificationKeys) {
        const foundKey = cfg.assertionVerificationKeys.Keys[assertion.id];
        if (foundKey) {
          assertionKey = foundKey;
        }
      }
      await assertions.verify(assertion, aggregateHash, assertionKey, isLegacyTDF);
    }
  }

  const rootSig = isLegacyTDF
    ? base64.encode(hex.encodeArrayBuffer(payloadSig))
    : base64.encodeArrayBuffer(payloadSig);

  if (manifest.encryptionInformation.integrityInformation.rootSignature.sig !== rootSig) {
    throw new IntegrityError('Failed integrity check on root signature');
  }

  let mapOfRequestsOffset = 0;
  const chunkMap = new Map(
    segments.map(
      ({
        hash,
        encryptedSegmentSize = encryptedSegmentSizeDefault,
        segmentSize = segmentSizeDefault,
      }) => {
        const result = (() => {
          const chunk: Chunk = {
            hash,
            encryptedOffset: mapOfRequestsOffset,
            encryptedSegmentSize,
            decryptedChunk: mailbox<DecryptResult>(),
            plainSegmentSize: segmentSize,
          };
          return chunk;
        })();
        mapOfRequestsOffset += encryptedSegmentSize;
        return [hash, result];
      }
    )
  );

  const cipher = new AesGcmCipher(cfg.cryptoService);
  const segmentIntegrityAlg = segmentHashAlg || integrityAlgorithm;
  if (segmentIntegrityAlg !== 'GMAC' && segmentIntegrityAlg !== 'HS256') {
    throw new UnsupportedError(`Unsupported segment hash alg [${segmentIntegrityAlg}]`);
  }

  // Not waiting for Promise to resolve
  updateChunkQueue(
    Array.from(chunkMap.values()),
    centralDirectory,
    zipReader,
    keyForDecryption,
    cipher,
    segmentIntegrityAlg,
    cfg.cryptoService,
    specVersion
  );

  let progress = 0;
  const underlyingSource = {
    pull: async (controller: ReadableStreamDefaultController) => {
      if (chunkMap.size === 0) {
        controller.close();
        return;
      }

      const [hash, chunk] = chunkMap.entries().next().value;
      const decryptedSegment = await chunk.decryptedChunk;

      controller.enqueue(new Uint8Array(decryptedSegment.payload.asByteArray()));
      progress += chunk.encryptedSegmentSize;
      cfg.progressHandler?.(progress);
      chunkMap.delete(hash);
    },
    ...(cfg.fileStreamServiceWorker && { fileStreamServiceWorker: cfg.fileStreamServiceWorker }),
  };

  const outputStream = new DecoratedReadableStream(underlyingSource);

  outputStream.requiredObligations = requiredObligations;
  outputStream.manifest = manifest;
  outputStream.metadata = metadata;
  return outputStream;
}

async function concatenateUint8Array(uint8arrays: Uint8Array[]): Promise<Uint8Array> {
  const blob = new Blob(uint8arrays);
  const buffer = await blob.arrayBuffer();
  return new Uint8Array(buffer);
}
