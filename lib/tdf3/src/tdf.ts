import { unsigned } from './utils/buffer-crc32.js';
import { exportSPKI, importX509 } from 'jose';
import { DecoratedReadableStream } from './client/DecoratedReadableStream.js';
import { fetchKasPubKey as fetchKasPubKeyV2, fetchWrappedKey } from '../../src/access.js';
import { DecryptParams } from './client/builders.js';
import { AssertionConfig, AssertionKey, AssertionVerificationKeys } from './assertions.js';
import { version } from './version.js';
import { hex } from '../../src/encodings/index.js';
import * as assertions from './assertions.js';

import {
  KeyAccessType,
  KeyInfo,
  Manifest,
  Policy,
  Remote as KeyAccessRemote,
  SplitKey,
  Wrapped as KeyAccessWrapped,
  KeyAccess,
  KeyAccessObject,
  SplitType,
} from './models/index.js';
import { base64 } from '../../src/encodings/index.js';
import { ZipReader, ZipWriter, keyMerge, concatUint8 } from './utils/index.js';
import { Binary } from './binary.js';
import { KasPublicKeyAlgorithm, KasPublicKeyInfo, OriginAllowList } from '../../src/access.js';
import {
  ConfigurationError,
  DecryptError,
  InvalidFileError,
  IntegrityError,
  NetworkError,
  UnsafeUrlError,
  UnsupportedFeatureError as UnsupportedError,
} from '../../src/errors.js';

// configurable
// TODO: remove dependencies from ciphers so that we can open-source instead of relying on other Virtru libs
import { AesGcmCipher } from './ciphers/index.js';
import { type AuthProvider, reqSignature } from '../../src/auth/auth.js';
import { PolicyObject } from '../../src/tdf/PolicyObject.js';
import { type CryptoService, type DecryptResult } from './crypto/declarations.js';
import { CentralDirectory } from './utils/zip-reader.js';
import { SymmetricCipher } from './ciphers/symmetric-cipher-base.js';
import { allPool, anyPool } from '../../src/concurrency.js';
import { type Chunker } from '../../src/seekable.js';

// TODO: input validation on manifest JSON
const DEFAULT_SEGMENT_SIZE = 1024 * 1024;

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

export type Metadata = {
  connectOptions?: {
    testUrl: string;
  };
  policyObject?: PolicyObject;
};

export type BuildKeyAccess = {
  type: KeyAccessType;
  url?: string;
  kid?: string;
  publicKey: string;
  metadata?: Metadata;
  sid?: string;
};

type Segment = {
  hash: string;
  segmentSize: number | undefined;
  encryptedSegmentSize: number | undefined;
};

type EntryInfo = {
  filename: string;
  offset?: number;
  crcCounter?: number;
  fileByteCount?: number;
};

type Chunk = {
  hash: string;
  encryptedOffset: number;
  encryptedSegmentSize?: number;
  decryptedChunk?: null | DecryptResult;
  promise: Promise<unknown>;
  _resolve?: (value: unknown) => void;
  _reject?: (value: unknown) => void;
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
};

export type DecryptConfiguration = {
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

export type RewrapResponse = {
  entityWrappedKey: string;
  sessionPublicKey: string;
};

/**
 * If we have KAS url but not public key we can fetch it from KAS, fetching
 * the value from `${kas}/kas_public_key`.
 */
export async function fetchKasPublicKey(
  kas: string,
  algorithm?: KasPublicKeyAlgorithm
): Promise<KasPublicKeyInfo> {
  return fetchKasPubKeyV2(kas, algorithm || 'rsa:2048');
}

export async function extractPemFromKeyString(keyString: string): Promise<string> {
  let pem: string = keyString;

  // Skip the public key extraction if we find that the KAS url provides a
  // PEM-encoded key instead of certificate
  if (keyString.includes('CERTIFICATE')) {
    const cert = await importX509(keyString, 'RS256', { extractable: true });
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
}: BuildKeyAccess): Promise<KeyAccess> {
  /** Internal function to keep it DRY */
  function createKeyAccess(
    type: KeyAccessType,
    kasUrl: string,
    kasKeyIdentifier: string | undefined,
    pubKey: string,
    metadata?: Metadata
  ) {
    switch (type) {
      case 'wrapped':
        return new KeyAccessWrapped(kasUrl, kasKeyIdentifier, pubKey, metadata, sid);
      case 'remote':
        return new KeyAccessRemote(kasUrl, kasKeyIdentifier, pubKey, metadata, sid);
      default:
        throw new ConfigurationError(`buildKeyAccess: Key access type ${type} is unknown`);
    }
  }

  // if url and pulicKey are specified load the key access object with them
  if (url && publicKey) {
    return createKeyAccess(type, url, kid, await extractPemFromKeyString(publicKey), metadata);
  }

  // All failed. Raise an error.
  throw new ConfigurationError('TDF.buildKeyAccess: No source for kasUrl or pubKey');
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
  mimeType: string | undefined
): Promise<Manifest> {
  // (maybe) Fields are quoted to avoid renaming
  const payload = {
    type: 'reference',
    url: '0.payload',
    protocol: 'zip',
    isEncrypted: true,
    schemaVersion: '3.0.0',
    ...(mimeType && { mimeType }),
  };

  const encryptionInformationStr = await encryptionInformation.write(policy, keyInfo);
  const assertions: assertions.Assertion[] = [];
  return {
    payload,
    // generate the manifest first, then insert integrity information into it
    encryptionInformation: encryptionInformationStr,
    assertions: assertions,
    tdf_spec_version: version,
  };
}

async function getSignature(
  unwrappedKey: Uint8Array,
  content: Uint8Array,
  algorithmType: IntegrityAlgorithm,
  cryptoService: CryptoService
) : Promise<Uint8Array> {
  switch (algorithmType.toUpperCase()) {
    case 'GMAC':
      // use the auth tag baked into the encrypted payload
      return content.slice(-16);
    case 'HS256':
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
    default:``
      throw new ConfigurationError(`Unsupported signature alg [${algorithmType}]`);
  }
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
  const segmentHashList: Uint8Array[] = [];

  const zipWriter = new ZipWriter();
  const manifest = await _generateManifest(
    cfg.keyForManifest,
    cfg.encryptionInformation,
    cfg.policy,
    cfg.mimeType
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

        // hash the concat of all hashes
        const aggregateHash = await concatenateUint8Array(segmentHashList);

        const payloadSig = await getSignature(
          new Uint8Array(cfg.keyForEncryption.unwrappedKeyBinary.asArrayBuffer()),
          aggregateHash,
          cfg.integrityAlgorithm,
          cfg.cryptoService
        );

        const rootSig = base64.encodeArrayBuffer(payloadSig);
        manifest.encryptionInformation.integrityInformation.rootSignature.sig = rootSig;
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
        if (cfg.assertionConfigs && cfg.assertionConfigs.length > 0) {
          await Promise.all(
            cfg.assertionConfigs.map(async (assertionConfig) => {
              // Create assertion using the assertionConfig values
              const signingKey: AssertionKey = assertionConfig.signingKey ?? {
                alg: 'HS256',
                key: new Uint8Array(cfg.keyForEncryption.unwrappedKeyBinary.asArrayBuffer()),
              };
              const assertion = await assertions.CreateAssertion(aggregateHash, {
                ...assertionConfig,
                signingKey,
              });

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
    const payloadSig = await getSignature(
      new Uint8Array(cfg.keyForEncryption.unwrappedKeyBinary.asArrayBuffer()),
      new Uint8Array(encryptedResult.payload.asArrayBuffer()),
      cfg.segmentIntegrityAlgorithm,
      cfg.cryptoService
    );
    
    segmentHashList.push(new Uint8Array(payloadSig));

    segmentInfos.push({
      hash: base64.encodeArrayBuffer(payloadSig),
      segmentSize: chunk.length === segmentSizeDefault ? undefined : chunk.length,
      encryptedSegmentSize:
        payloadBuffer.length === encryptedSegmentSizeDefault ? undefined : payloadBuffer.length,
    });
    const result = new Uint8Array(encryptedResult.payload.asByteArray());
    _countChunk(result);

    return result;
  }
}

// load the TDF as a stream in memory, for further use in reading and key syncing
export async function loadTDFStream(
  chunker: Chunker
): Promise<{ manifest: Manifest; zipReader: ZipReader; centralDirectory: CentralDirectory[] }> {
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
};

async function unwrapKey({
  manifest,
  allowedKases,
  authProvider,
  dpopKeys,
  concurrencyLimit,
  cryptoService,
}: {
  manifest: Manifest;
  allowedKases: OriginAllowList;
  authProvider: AuthProvider;
  concurrencyLimit?: number;
  dpopKeys: CryptoKeyPair;
  cryptoService: CryptoService;
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
    const ephemeralEncryptionKeys = await cryptoService.cryptoToPemPair(
      await cryptoService.generateKeyPair()
    );
    const clientPublicKey = ephemeralEncryptionKeys.publicKey;

    const requestBodyStr = JSON.stringify({
      algorithm: 'RS256',
      keyAccess: keySplitInfo,
      policy: manifest.encryptionInformation.policy,
      clientPublicKey,
    });

    const jwtPayload = { requestBody: requestBodyStr };
    const signedRequestToken = await reqSignature(jwtPayload, dpopKeys.privateKey);

    const { entityWrappedKey, metadata } = await fetchWrappedKey(
      url,
      { signedRequestToken },
      authProvider,
      '0.0.1'
    );

    const key = Binary.fromString(base64.decode(entityWrappedKey));
    const decryptedKeyBinary = await cryptoService.decryptWithPrivateKey(
      key,
      ephemeralEncryptionKeys.privateKey
    );

    return {
      key: new Uint8Array(decryptedKeyBinary.asByteArray()),
      metadata,
    };
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
    const splitResults = await allPool(poolSize, splitPromises);
    // Merge all the split keys
    const reconstructedKey = keyMerge(splitResults.map((r) => r.key));
    return {
      reconstructedKeyBinary: Binary.fromArrayBuffer(reconstructedKey),
      metadata: splitResults[0].metadata, // Use metadata from first split
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
  cryptoService: CryptoService,
  isLegacyTDF: boolean
): Promise<DecryptResult> {
  if (segmentIntegrityAlgorithm !== 'GMAC' && segmentIntegrityAlgorithm !== 'HS256') {
  }
  const segmentSig = await getSignature(
    new Uint8Array(reconstructedKeyBinary.asArrayBuffer()),
    encryptedChunk,
    segmentIntegrityAlgorithm,
    cryptoService
  );

  const segmentHash = isLegacyTDF ? base64.encode(hex.encodeArrayBuffer(segmentSig)) :base64.encodeArrayBuffer(segmentSig);

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
  isLegacyTDF: boolean
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
            isLegacyTDF,
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
  cryptoService,
  segmentIntegrityAlgorithm,
  isLegacyTDF,
}: {
  buffer: Uint8Array;
  reconstructedKeyBinary: Binary;
  slice: Chunk[];
  cipher: SymmetricCipher;
  cryptoService: CryptoService;
  segmentIntegrityAlgorithm: IntegrityAlgorithm;
  isLegacyTDF: boolean;
}) {
  for (const index in slice) {
    const { encryptedOffset, encryptedSegmentSize, _resolve, _reject } = slice[index];

    const offset =
      slice[0].encryptedOffset === 0 ? encryptedOffset : encryptedOffset % slice[0].encryptedOffset;
    const encryptedChunk = new Uint8Array(
      buffer.slice(offset, offset + (encryptedSegmentSize as number))
    );

    try {
      const result = await decryptChunk(
        encryptedChunk,
        reconstructedKeyBinary,
        slice[index]['hash'],
        cipher,
        segmentIntegrityAlgorithm,
        cryptoService,
        isLegacyTDF
      );
      slice[index].decryptedChunk = result;
      if (_resolve) {
        _resolve(null);
      }
    } catch (e) {
      if (_reject) {
        _reject(e);
      } else {
        throw e;
      }
    }
  }
}

export async function readStream(cfg: DecryptConfiguration) {
  let { allowList } = cfg;
  if (!allowList) {
    if (!cfg.allowedKases) {
      throw new ConfigurationError('Upsert cannot be done without allowlist');
    }
    allowList = new OriginAllowList(cfg.allowedKases);
  }
  const { manifest, zipReader, centralDirectory } = await loadTDFStream(cfg.chunker);
  if (!manifest) {
    throw new InvalidFileError('Missing manifest data');
  }
  cfg.keyMiddleware ??= async (key) => key;

  const {
    encryptedSegmentSizeDefault: defaultSegmentSize,
    rootSignature,
    segmentHashAlg,
    segments,
  } = manifest.encryptionInformation.integrityInformation;
  const { metadata, reconstructedKeyBinary } = await unwrapKey({
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
  const isLegacyTDF = manifest.tdf_spec_version ? false : true;

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

  const payloadForSigCalculation = isLegacyTDF ?
  new TextEncoder().encode(hex.encodeArrayBuffer(aggregateHash)) : aggregateHash;
  const payloadSig = await getSignature(
    new Uint8Array(keyForDecryption.asArrayBuffer()),
    payloadForSigCalculation,
    integrityAlgorithm,
    cfg.cryptoService
  );

  const rootSig = isLegacyTDF
    ? base64.encode(hex.encodeArrayBuffer(payloadSig))
    : base64.encodeArrayBuffer(payloadSig);

  if (manifest.encryptionInformation.integrityInformation.rootSignature.sig !== rootSig) {
    throw new IntegrityError('Failed integrity check on root signature');
  }

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

  let mapOfRequestsOffset = 0;
  const chunkMap = new Map(
    segments.map(({ hash, encryptedSegmentSize = encryptedSegmentSizeDefault }) => {
      const result = (() => {
        let _resolve, _reject;
        const chunk: Chunk = {
          hash,
          encryptedOffset: mapOfRequestsOffset,
          encryptedSegmentSize,
          promise: new Promise((resolve, reject) => {
            _resolve = resolve;
            _reject = reject;
          }),
        };
        chunk._resolve = _resolve;
        chunk._reject = _reject;
        return chunk;
      })();
      mapOfRequestsOffset += encryptedSegmentSize || encryptedSegmentSizeDefault;
      return [hash, result];
    })
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
    isLegacyTDF
  );

  let progress = 0;
  const underlyingSource = {
    pull: async (controller: ReadableStreamDefaultController) => {
      if (chunkMap.size === 0) {
        controller.close();
        return;
      }

      const [hash, chunk] = chunkMap.entries().next().value;
      if (!chunk.decryptedChunk) {
        await chunk.promise;
      }
      const decryptedSegment = chunk.decryptedChunk;

      controller.enqueue(new Uint8Array(decryptedSegment.payload.asByteArray()));
      progress += chunk.encryptedSegmentSize;
      cfg.progressHandler?.(progress);

      chunk.decryptedChunk = null;
      chunkMap.delete(hash);
    },
    ...(cfg.fileStreamServiceWorker && { fileStreamServiceWorker: cfg.fileStreamServiceWorker }),
  };

  const outputStream = new DecoratedReadableStream(underlyingSource);

  outputStream.manifest = manifest;
  outputStream.metadata = metadata;
  return outputStream;
}

async function concatenateUint8Array(uint8arrays: Uint8Array[]): Promise<Uint8Array> {
  const blob = new Blob(uint8arrays);
  const buffer = await blob.arrayBuffer();
  return new Uint8Array(buffer);
}
