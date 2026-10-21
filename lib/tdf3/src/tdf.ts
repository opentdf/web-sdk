import type { KasPublicKeyAlgorithm, KasPublicKeyInfo } from '../../src/access.js';
import {
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
import { type AuthConfig } from '../../src/auth/interceptors.js';
import { handleRpcRewrapErrorString } from '../../src/access/access-rpc.js';
import { allPool, anyPool } from '../../src/concurrency.js';
import { base64, hex } from '../../src/encodings/index.js';
import {
  asError,
  ConfigurationError,
  DecryptError,
  InvalidFileError,
  IntegrityError,
  NetworkError,
  UnsafeUrlError,
  UnsupportedFeatureError as UnsupportedError,
} from '../../src/errors.js';
import { type Chunker } from '../../src/seekable.js';
import { tdfSpecVersion } from '../../src/version.js';
import type { AssertionConfig, AssertionKey, AssertionVerificationKeys } from './assertions.js';
import * as assertions from './assertions.js';
import { Binary } from './binary.js';
import { AesGcmCipher } from './ciphers/aes-gcm-cipher.js';
import type { SymmetricCipher } from './ciphers/symmetric-cipher-base.js';
import type { DecryptParams } from './client/builders.js';
import { DecoratedReadableStream } from './client/DecoratedReadableStream.js';
import {
  type AsymmetricSigningAlgorithm,
  type CryptoService,
  type DecryptResult,
  isMlKemKeyAlgorithm,
  type KeyAlgorithm,
  type KeyPair,
  mlKemAlgorithmToLevel,
  type SymmetricKey,
} from './crypto/declarations.js';
import { Algorithms } from './ciphers/index.js';
import type {
  KeyAccessType,
  KeyInfo,
  Manifest,
  Policy,
  SplitKey,
  KeyAccess,
  KeyAccessObject,
  SplitType,
} from './models/index.js';
import {
  ECWrapped,
  MLKEM_CT_SIZES,
  MlKemWrapped,
  Wrapped,
  resolveSpecVersion,
} from './models/index.js';
import { unsigned } from './utils/buffer-crc32.js';
import { ZipReader, ZipWriter, buffToString, toArrayBuffer } from './utils/index.js';
import type { CentralDirectory } from './utils/zip-reader.js';
import { derivePrefetchWindow } from './utils/prefetch-window.js';
import { getZtdfSalt } from './crypto/salt.js';
import { decodeKemEnvelopeDer } from './crypto/core/mlkem-asn1.js';
import type { Payload } from './models/payload.js';
import {
  getRequiredObligationFQNs,
  upgradeRewrapResponseV1,
  getPlatformUrlFromKasEndpoint,
} from '../../src/utils.js';

// TODO: input validation on manifest JSON
// Read-side fallback for manifests that omit `encryptedSegmentSizeDefault`.
// Deliberately not the writer's default (`DEFAULT_SEGMENT_SIZE` in
// `client/builders.ts`): changing that must not change how old files parse.
const DEFAULT_SEGMENT_SIZE = 1024 * 1024;

/** Where the spec puts the manifest: at the root of the OpenTDF zip archive. */
export const manifestFileName = 'manifest.json';

/**
 * What this SDK has always called the manifest. The `0.` prefix anticipated
 * several payload/manifest pairs per archive, a design that never shipped.
 */
export const offspecManifestFileName = '0.manifest.json';

/**
 * The name `writeStream` gives the manifest entry by default, that is, unless
 * `unprefixedManifestName` opts into the spec name (see `manifestEntryNameFor`).
 * Distinct from the constants above on purpose: making the spec name the default
 * (a breaking file-format change, tracked in opentdf/platform#3513) means
 * repointing *this* binding, and repointing it leaves the read side below
 * untouched, so archives written by every earlier release keep opening.
 */
export const manifestEntryNameToWrite: string = offspecManifestFileName;

/**
 * The manifest entry to read from an archive: the spec name when the archive
 * carries it, otherwise the name this SDK writes.
 *
 * Resolving against the central directory rather than against a failed read keeps
 * other failures honest: an out-of-bounds or truncated manifest under the spec
 * name stays a read error instead of silently yielding a non-aligned entry. The
 * cost of preferring the spec name is that an archive carrying both entries
 * resolves to the spec one even when this SDK wrote the other — see the PR discussion of appended
 * central-directory records.
 */
export function manifestEntryName(centralDirectory: CentralDirectory[]): string {
  return centralDirectory.some(({ fileName }) => fileName === manifestFileName)
    ? manifestFileName
    : offspecManifestFileName;
}

const HEX_SEMVER_VERSION = '4.2.2';

/**
 * The manifest entry name to write for a given configuration: the legacy
 * prefixed name when the target is a legacy TDF, the spec name when
 * unprefixedManifestName is enabled, and `manifestEntryNameToWrite` otherwise.
 */
export function manifestEntryNameFor(cfg: EncryptConfiguration): string {
  if (isTargetSpecLegacyTDF(cfg.tdfSpecVersion)) {
    return offspecManifestFileName;
  }
  return cfg.unprefixedManifestName ? manifestFileName : manifestEntryNameToWrite;
}

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
  cryptoService: CryptoService;
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

type Chunk = {
  hash: string;
  plainSegmentSize?: number;
  encryptedOffset: number;
  encryptedSegmentSize?: number;
};

/**
 * One ranged read's worth of segments, queued in order. `plaintext` starts
 * resolving as soon as the batch is queued, so the queue's length is the
 * number of batches in flight or decrypted and waiting for the reader.
 */
type SegmentBatch = {
  slice: Chunk[];
  plaintext: Promise<Uint8Array[]>;
};

/**
 * Algorithms usable for *per-segment* integrity.
 *
 * `GMAC` is legitimate here: the segment's bytes were just processed by
 * AES-GCM under the DEK, so the trailing 16 bytes are the tag the AEAD itself
 * produced. See {@link segmentIntegrity}.
 */
export type SegmentIntegrityAlgorithm = 'GMAC' | 'HS256';

/**
 * Algorithms usable for the *root* signature.
 *
 * Deliberately narrower than {@link SegmentIntegrityAlgorithm}: AES-GCM never
 * processes the aggregate hash, so there is no tag to extract and `GMAC` would
 * degenerate into copying the last segment hash — a keyless, forgeable value.
 * The type carries the invariant so a root algorithm cannot even be *typed* as
 * `'GMAC'`. See {@link rootIntegrity}.
 */
export type RootIntegrityAlgorithm = 'HS256';

/**
 * @deprecated Prefer {@link SegmentIntegrityAlgorithm} or
 * {@link RootIntegrityAlgorithm}, which say which position they are valid in.
 */
export type IntegrityAlgorithm = SegmentIntegrityAlgorithm;

/** The only root integrity algorithm this SDK reads or writes. */
export const ROOT_INTEGRITY_ALGORITHM: RootIntegrityAlgorithm = 'HS256';

/** Default per-segment integrity algorithm. */
export const SEGMENT_INTEGRITY_ALGORITHM: SegmentIntegrityAlgorithm = 'GMAC';

/** Length in bytes of an AES-GCM authentication tag. */
const GMAC_TAG_LENGTH = 16;

/**
 * Case-insensitive test for a supported segment integrity algorithm.
 * An explicit allowlist, so unknown algorithms are rejected rather than
 * silently defaulted.
 */
export function isSegmentIntegrityAlgorithm(alg: unknown): alg is SegmentIntegrityAlgorithm {
  return typeof alg === 'string' && ['GMAC', 'HS256'].includes(alg.toUpperCase());
}

/**
 * Case-insensitive test for a supported root integrity algorithm.
 * `GMAC` in *any* casing is not a member: the JS reader historically compared
 * exactly (`!== 'GMAC'`), so `"gmac"` took a different path than in the Go and
 * Java SDKs. Normalizing first closes that gap.
 */
export function isRootIntegrityAlgorithm(alg: unknown): alg is RootIntegrityAlgorithm {
  return typeof alg === 'string' && alg.toUpperCase() === ROOT_INTEGRITY_ALGORITHM;
}

/**
 * Normalize a manifest-declared segment algorithm, rejecting anything unknown.
 */
export function asSegmentIntegrityAlgorithm(alg: unknown): SegmentIntegrityAlgorithm {
  if (!isSegmentIntegrityAlgorithm(alg)) {
    throw new UnsupportedError(`Unsupported segment hash alg [${String(alg)}]`);
  }
  return alg.toUpperCase() as SegmentIntegrityAlgorithm;
}

/**
 * Normalize a manifest-declared root algorithm, failing *closed*.
 *
 * A base TDF's `rootSignature.alg` is unauthenticated manifest data. Accepting
 * `GMAC` there lets a keyless attacker downgrade an HS256-rooted file and then
 * truncate, reorder, duplicate or drop segments undetected, so reject it (and
 * every unknown algorithm) instead of coercing to HS256 — coercion would
 * validate a forged file against the wrong algorithm and mask the downgrade.
 */
export function asRootIntegrityAlgorithm(alg: unknown): RootIntegrityAlgorithm {
  if (!isRootIntegrityAlgorithm(alg)) {
    throw new IntegrityError(
      `unsupported root integrity algorithm [${String(alg)}]; only [${ROOT_INTEGRITY_ALGORITHM}] is supported`
    );
  }
  return ROOT_INTEGRITY_ALGORITHM;
}

export type EncryptConfiguration = {
  allowList?: OriginAllowList;
  cryptoService: CryptoService;
  dpopKeys: KeyPair;
  encryptionInformation: SplitKey;
  segmentSizeDefault: number;
  rootIntegrityAlgorithm: RootIntegrityAlgorithm;
  segmentIntegrityAlgorithm: SegmentIntegrityAlgorithm;
  contentStream: ReadableStream<Uint8Array>;
  mimeType?: string;
  policy: Policy;
  /** Auth configuration: AuthProvider or { interceptors }. */
  auth?: AuthConfig;
  byteLimit: number;
  progressHandler?: (bytesProcessed: number) => void;
  keyForEncryption: KeyInfo;
  keyForManifest: KeyInfo;
  assertionConfigs?: AssertionConfig[];
  systemMetadataAssertion?: boolean;
  tdfSpecVersion?: string;
  /**
   * Store the manifest under the zip entry name manifest.json, the name the TDF
   * spec defines, instead of the legacy 0.manifest.json written by default.
   * Readers that predate manifest.json support can't open the result. A
   * tdfSpecVersion of 4.2.2, the legacy format, overrides this option and keeps
   * the legacy name; no other version does.
   */
  unprefixedManifestName?: boolean;
};

export type DecryptConfiguration = {
  fulfillableObligations: string[];
  allowedKases?: string[];
  allowList?: OriginAllowList;
  /** Auth configuration: AuthProvider or { interceptors }. */
  auth?: AuthConfig;
  cryptoService: CryptoService;

  dpopKeys: KeyPair;

  chunker: Chunker;
  keyMiddleware: KeyMiddleware;
  progressHandler?: (bytesProcessed: number) => void;
  fileStreamServiceWorker?: string;
  assertionVerificationKeys?: AssertionVerificationKeys;
  noVerifyAssertions?: boolean;
  concurrencyLimit?: number;
  segmentBatchSize?: number;
  maxConcurrentSegmentBatches?: number;
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
  alg: KasPublicKeyAlgorithm,
  cryptoService: CryptoService
): Promise<string> {
  // Convert KAS algorithm to JWA algorithm if provided
  const jwaAlgorithm = publicKeyAlgorithmToJwa(alg);
  // extractPublicKeyPem handles both X.509 certificates and raw PEM keys
  return cryptoService.extractPublicKeyPem(keyString, jwaAlgorithm);
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
  cryptoService,
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
    pubKey = await extractPemFromKeyString(publicKey, alg, cryptoService);
  } catch (e) {
    throw new ConfigurationError(
      `TDF.buildKeyAccess: Invalid public key [${publicKey}], caused by [${String(e)}]`,
      asError(e)
    );
  }
  switch (type) {
    case 'wrapped':
      return new Wrapped(url, kid, pubKey, metadata, cryptoService, sid);
    case 'ec-wrapped':
      return new ECWrapped(url, kid, pubKey, metadata, cryptoService, sid);
    case 'mlkem-wrapped':
      if (!isMlKemKeyAlgorithm(alg)) {
        throw new ConfigurationError(
          `buildKeyAccess: algorithm [${alg}] is not valid for mlkem-wrapped`
        );
      }
      if (!kid?.trim()) {
        throw new ConfigurationError(
          `buildKeyAccess: kid is required for ML-KEM algorithm [${alg}]`
        );
      }
      return new MlKemWrapped(url, kid, pubKey, metadata, cryptoService, sid, alg);
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
      `The given policy object requires the following properties: ${missingFields.join(', ')}`
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

/**
 * Integrity value for a single *segment* of AES-GCM ciphertext.
 *
 * `GMAC` is sound here and only here: `ciphertext` is exactly the buffer
 * AES-GCM produced (or is about to authenticate) under `unwrappedKey`, so its
 * trailing 16 bytes are the GHASH tag the AEAD already computed. The key
 * parameter looks unused because it was already used — by the cipher, a moment
 * earlier.
 *
 * Never call this with data that has not gone through the AEAD; see
 * {@link rootIntegrity} for the aggregate hash.
 */
async function segmentIntegrity(
  ciphertext: Uint8Array,
  unwrappedKey: SymmetricKey,
  algorithmType: SegmentIntegrityAlgorithm,
  cryptoService: CryptoService
): Promise<Uint8Array> {
  switch (algorithmType) {
    case 'GMAC':
      // read out the auth tag AES-GCM baked into these exact bytes
      return ciphertext.slice(-GMAC_TAG_LENGTH);
    case 'HS256':
      // Use CryptoService for HMAC-SHA256 signing
      return cryptoService.hmac(ciphertext, unwrappedKey);
    default:
      throw new ConfigurationError(`Unsupported segment integrity alg [${String(algorithmType)}]`);
  }
}

/**
 * Integrity value for the *root*: the aggregate of every segment hash.
 *
 * AES-GCM never processed `aggregateHash`, so there is no tag to read out and
 * the trailing-16-bytes trick would just copy the last segment hash — a value
 * already sitting in the manifest, computable with no key. Only a real keyed
 * MAC is accepted.
 */
async function rootIntegrity(
  aggregateHash: Uint8Array,
  unwrappedKey: SymmetricKey,
  algorithmType: RootIntegrityAlgorithm,
  cryptoService: CryptoService
): Promise<Uint8Array> {
  // Runtime guard as well as a type-level one: callers may hand us a value
  // parsed out of an untrusted manifest.
  if (!isRootIntegrityAlgorithm(algorithmType)) {
    throw new ConfigurationError(`unsupported root integrity algorithm [${String(algorithmType)}]`);
  }
  return cryptoService.hmac(aggregateHash, unwrappedKey);
}

/**
 * Legacy (TDF spec 4.2.2) segment integrity: the value is hex-encoded before
 * it is base64'd by the caller.
 */
async function segmentIntegrityVersion422(
  payloadBinary: Binary,
  unwrappedKey: SymmetricKey,
  algorithmType: SegmentIntegrityAlgorithm,
  cryptoService: CryptoService
): Promise<string> {
  switch (algorithmType) {
    case 'GMAC':
      // read out the auth tag AES-GCM baked into these exact bytes
      return buffToString(
        new Uint8Array(payloadBinary.asArrayBuffer()).slice(-GMAC_TAG_LENGTH),
        'hex'
      );
    case 'HS256': {
      const content = buffToString(new Uint8Array(payloadBinary.asArrayBuffer()), 'utf-8');
      const sig = await cryptoService.hmac(new TextEncoder().encode(content), unwrappedKey);
      return hex.encodeArrayBuffer(toArrayBuffer(sig));
    }
    default:
      throw new ConfigurationError(`Unsupported segment integrity alg [${String(algorithmType)}]`);
  }
}

/**
 * Legacy (TDF spec 4.2.2) root integrity. Same hex-then-base64 encoding as
 * before, same HS256-only domain as {@link rootIntegrity}.
 */
async function rootIntegrityVersion422(
  aggregateHash: Binary,
  unwrappedKey: SymmetricKey,
  algorithmType: RootIntegrityAlgorithm,
  cryptoService: CryptoService
): Promise<string> {
  if (!isRootIntegrityAlgorithm(algorithmType)) {
    throw new ConfigurationError(`unsupported root integrity algorithm [${String(algorithmType)}]`);
  }
  const content = buffToString(new Uint8Array(aggregateHash.asArrayBuffer()), 'utf-8');
  const sig = await cryptoService.hmac(new TextEncoder().encode(content), unwrappedKey);
  return hex.encodeArrayBuffer(toArrayBuffer(sig));
}

function isTargetSpecLegacyTDF(targetSpecVersion?: string): boolean {
  return targetSpecVersion === HEX_SEMVER_VERSION;
}

export async function writeStream(cfg: EncryptConfiguration): Promise<DecoratedReadableStream> {
  if (!cfg.auth) {
    throw new ConfigurationError('No authorization middleware defined');
  }
  if (!cfg.contentStream) {
    throw new ConfigurationError('No input stream defined');
  }
  if (!isRootIntegrityAlgorithm(cfg.rootIntegrityAlgorithm)) {
    throw new ConfigurationError(
      `unsupported root integrity algorithm [${String(cfg.rootIntegrityAlgorithm)}]; only [${ROOT_INTEGRITY_ALGORITHM}] is supported`
    );
  }
  if (!isSegmentIntegrityAlgorithm(cfg.segmentIntegrityAlgorithm)) {
    throw new ConfigurationError(
      `unsupported segment integrity algorithm [${String(cfg.segmentIntegrityAlgorithm)}]`
    );
  }
  // `client.encrypt` forwards `windowSize` here unchecked. Zero would loop
  // forever accumulating an empty segment; a fractional or negative size would
  // write a manifest whose declared segment sizes no reader can follow.
  if (!Number.isInteger(cfg.segmentSizeDefault) || cfg.segmentSizeDefault <= 0) {
    throw new ConfigurationError(
      `segment size must be a positive integer; got [${cfg.segmentSizeDefault}]`
    );
  }

  // The guards above are deliberately case-insensitive, so callers may pass user
  // input straight through. Manifests, however, are read back by strict parsers --
  // this SDK's own reader included -- so everything below writes and signs with the
  // canonical uppercase spelling.
  const rootIntegrityAlgorithm = cfg.rootIntegrityAlgorithm.toUpperCase() as RootIntegrityAlgorithm;
  const segmentIntegrityAlgorithm =
    cfg.segmentIntegrityAlgorithm.toUpperCase() as SegmentIntegrityAlgorithm;

  const segmentInfos: Segment[] = [];

  cfg.byteLimit ??= Number.MAX_SAFE_INTEGER;

  const entryInfos: EntryInfo[] = [
    {
      filename: '0.payload',
    },
    {
      filename: manifestEntryNameFor(cfg),
    },
  ];

  // Plaintext waiting to be encrypted: complete segments, then the one being
  // filled. Each input byte is copied once, into the segment it belongs to, so
  // filling a segment costs O(segment size) however small the input chunks are.
  // A segment's buffer is allocated at full size when its first byte arrives,
  // so even a tiny input holds one `segmentSizeDefault` buffer.
  const fullSegments: Uint8Array[] = [];
  let partialSegment: Uint8Array | undefined;
  let partialLength = 0;

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

  const { segmentSizeDefault } = cfg;
  const encryptedSegmentSizeDefault =
    cfg.encryptionInformation.cipher.encryptedPayloadSize(segmentSizeDefault);

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
      try {
        let isDone;

        while (!fullSegments.length && !isDone) {
          const { value, done } = await sourceReader.read();
          isDone = done;
          if (value) {
            _appendPlaintext(_asBytes(value));
          }
        }

        while (fullSegments.length && !!controller.desiredSize && controller.desiredSize > 0) {
          const encryptedSegment = await _encryptAndCountSegment(fullSegments.shift()!);
          controller.enqueue(encryptedSegment);
        }

        const isFinalChunkLeft = isDone && !fullSegments.length && partialLength;

        if (isFinalChunkLeft) {
          const encryptedSegment = await _encryptAndCountSegment(
            partialSegment!.subarray(0, partialLength)
          );
          controller.enqueue(encryptedSegment);
          partialSegment = undefined;
          partialLength = 0;
        }

        if (isDone && !fullSegments.length && partialLength === 0) {
          entryInfos[0].crcCounter = crcCounter;
          entryInfos[0].fileByteCount = fileByteCount;
          const payloadDataDescriptor = zipWriter.writeDataDescriptor(crcCounter, fileByteCount);

          controller.enqueue(payloadDataDescriptor);
          _countChunk(payloadDataDescriptor);

          // prepare the manifest
          entryInfos[1].filename = manifestEntryNameFor(cfg);
          entryInfos[1].offset = totalByteCount;
          controller.enqueue(getHeader(entryInfos[1].filename));
          _countChunk(getHeader(entryInfos[1].filename));
          crcCounter = 0;
          fileByteCount = 0;

          let aggregateHash: string | Uint8Array;
          if (isTargetSpecLegacyTDF(cfg.tdfSpecVersion)) {
            aggregateHash = aggregateHash422;
            const payloadSigStr = await rootIntegrityVersion422(
              Binary.fromString(aggregateHash),
              cfg.keyForEncryption.unwrappedKey,
              rootIntegrityAlgorithm,
              cfg.cryptoService
            );
            manifest.encryptionInformation.integrityInformation.rootSignature.sig =
              base64.encode(payloadSigStr);
          } else {
            // hash the concat of all hashes
            aggregateHash = await concatenateUint8Array(segmentHashList);

            const payloadSig = await rootIntegrity(
              aggregateHash,
              cfg.keyForEncryption.unwrappedKey,
              rootIntegrityAlgorithm,
              cfg.cryptoService
            );

            const rootSig = base64.encodeArrayBuffer(payloadSig);
            manifest.encryptionInformation.integrityInformation.rootSignature.sig = rootSig;
          }
          manifest.encryptionInformation.integrityInformation.rootSignature.alg =
            rootIntegrityAlgorithm;

          manifest.encryptionInformation.integrityInformation.segmentSizeDefault =
            segmentSizeDefault;
          manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault =
            encryptedSegmentSizeDefault;
          manifest.encryptionInformation.integrityInformation.segmentHashAlg =
            segmentIntegrityAlgorithm;
          manifest.encryptionInformation.integrityInformation.segments = segmentInfos;

          manifest.encryptionInformation.method.isStreamable = true;
          const signedAssertions: assertions.Assertion[] = [];
          if (cfg.systemMetadataAssertion) {
            const systemMetadataConfigBase = assertions.getSystemMetadataAssertionConfig();
            const signingKeyForSystemMetadata: AssertionKey = {
              alg: 'HS256', // Default algorithm, can be configured if needed
              key: cfg.keyForEncryption.unwrappedKey,
            };
            signedAssertions.push(
              await assertions.CreateAssertion(
                aggregateHash,
                {
                  ...systemMetadataConfigBase, // Spread the properties from the base config
                  signingKey: signingKeyForSystemMetadata, // Add the signing key
                },
                cfg.cryptoService,
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
                  key: cfg.keyForEncryption.unwrappedKey,
                };
                const assertion = await assertions.CreateAssertion(
                  aggregateHash,
                  {
                    ...assertionConfig,
                    signingKey,
                  },
                  cfg.cryptoService,
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
      } catch (e) {
        // Without this the input stays locked and open (file handle, socket,
        // download) after the write fails. Best effort and not awaited: a slow
        // or failed cancel must not delay or replace the error the consumer
        // needs to see. A source that itself errored rejects cancel with that
        // same error, so only warn about a different one.
        sourceReader.cancel(e).catch((cancelErr) => {
          if (cancelErr !== e) {
            console.warn('TDF write: failed to cancel source stream after error:', cancelErr);
          }
        });
        throw e;
      }
    },

    cancel: (reason: unknown) => sourceReader.cancel(reason),
  };

  const plaintextStream = new DecoratedReadableStream(underlingSource);
  plaintextStream.manifest = manifest;

  return plaintextStream;

  // nested helper fn's
  function getHeader(filename: string) {
    return zipWriter.getLocalFileHeader(filename, 0, 0, 0);
  }

  // `contentStream` is typed as bytes, but JavaScript callers can enqueue
  // anything. A chunk without a `length` would otherwise drop out of the
  // payload unnoticed.
  function _asBytes(chunk: unknown): Uint8Array {
    if (chunk instanceof Uint8Array) {
      return chunk;
    }
    if (ArrayBuffer.isView(chunk)) {
      return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    }
    if (chunk instanceof ArrayBuffer) {
      return new Uint8Array(chunk);
    }
    throw new ConfigurationError(
      `contentStream must yield binary chunks; got ${Object.prototype.toString.call(chunk)}`
    );
  }

  function _appendPlaintext(chunk: Uint8Array) {
    let offset = 0;
    while (offset < chunk.length) {
      partialSegment ??= new Uint8Array(segmentSizeDefault);
      const n = Math.min(chunk.length - offset, segmentSizeDefault - partialLength);
      partialSegment.set(chunk.subarray(offset, offset + n), partialLength);
      partialLength += n;
      offset += n;
      if (partialLength === segmentSizeDefault) {
        fullSegments.push(partialSegment);
        partialSegment = undefined;
        partialLength = 0;
      }
    }
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
    // Read once: a `CryptoService` may transfer the buffer below, detaching `chunk`.
    const plaintextLength = chunk.length;
    bytesProcessed += plaintextLength;
    cfg.progressHandler?.(bytesProcessed);

    // A full segment views the whole of a buffer that `_appendPlaintext`
    // allocated and no longer references, so it is handed over without another
    // copy. The final short segment is a `subarray` of its buffer and is copied.
    const plaintext =
      chunk.buffer instanceof ArrayBuffer &&
      chunk.byteOffset === 0 &&
      chunk.byteLength === chunk.buffer.byteLength
        ? chunk.buffer
        : toArrayBuffer(chunk);

    // Don't pass in an IV here. The encrypt function will generate one for you, ensuring that each segment has a unique IV.
    const encryptedResult = await cfg.encryptionInformation.encrypt(
      Binary.fromArrayBuffer(plaintext),
      cfg.keyForEncryption.unwrappedKey
    );
    const payloadBuffer = new Uint8Array(encryptedResult.payload.asArrayBuffer());

    // Since `CryptoService` is an extension point, double check its output matches the expected size.
    const expectedSize = cfg.encryptionInformation.cipher.encryptedPayloadSize(plaintextLength);
    if (payloadBuffer.length !== expectedSize) {
      throw new ConfigurationError(
        `Cipher [${cfg.encryptionInformation.cipher.name}] produced ${payloadBuffer.length} bytes for a ${plaintextLength} byte segment, but reports ${expectedSize}`
      );
    }

    let hash: string;
    if (isTargetSpecLegacyTDF(cfg.tdfSpecVersion)) {
      const payloadSigStr = await segmentIntegrityVersion422(
        encryptedResult.payload,
        cfg.keyForEncryption.unwrappedKey,
        segmentIntegrityAlgorithm,
        cfg.cryptoService
      );
      // combined string of all hashes for root signature
      aggregateHash422 += payloadSigStr;
      hash = base64.encode(payloadSigStr);
    } else {
      const payloadSig = await segmentIntegrity(
        payloadBuffer,
        cfg.keyForEncryption.unwrappedKey,
        segmentIntegrityAlgorithm,
        cfg.cryptoService
      );

      segmentHashList.push(new Uint8Array(payloadSig));
      hash = base64.encodeArrayBuffer(payloadSig);
    }

    segmentInfos.push({
      hash,
      segmentSize: plaintextLength === segmentSizeDefault ? undefined : plaintextLength,
      encryptedSegmentSize:
        payloadBuffer.length === encryptedSegmentSizeDefault ? undefined : payloadBuffer.length,
    });
    // Keep emitted chunks independent of the crypto service's payload buffer.
    const result = payloadBuffer.slice();
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
  const manifest = await zipReader.getManifest(
    centralDirectory,
    manifestEntryName(centralDirectory)
  );
  return { manifest, zipReader, centralDirectory };
}

export function splitLookupTableFactory(
  keyAccess: KeyAccessObject[],
  allowedKases: OriginAllowList
): Record<string, KeyAccessObject[]> {
  const allowed = (k: KeyAccessObject) => allowedKases.allows(k.url);
  const splitIds = new Set(keyAccess.map(({ sid }) => sid ?? ''));

  const accessibleSplits = new Set(keyAccess.filter(allowed).map(({ sid }) => sid ?? ''));
  if (splitIds.size > accessibleSplits.size) {
    const disallowedKases = new Set(keyAccess.filter((k) => !allowed(k)).map(({ url }) => url));
    throw new UnsafeUrlError(
      `Unreconstructable key - disallowed KASes include: ${JSON.stringify([
        ...disallowedKases,
      ])} from splitIds ${JSON.stringify([...splitIds])}`,
      ...disallowedKases
    );
  }
  // Each split id maps to the list of KAOs that can unwrap it (in a disjunction,
  // any one succeeding unwraps the split). A KAS may appear several times for
  // the same split, possibly using different keys during rotation.
  const splitPotentials: Record<string, KeyAccessObject[]> = Object.fromEntries(
    [...splitIds].map((s) => [s, []])
  );
  for (const kao of keyAccess) {
    if (allowed(kao)) {
      splitPotentials[kao.sid ?? ''].push(kao);
    }
  }
  return splitPotentials;
}

type RewrapResponseData = {
  key: Uint8Array;
  metadata: Record<string, unknown>;
  requiredObligations: string[];
};

/**
 * Map an opaque key's algorithm to the JWS signing algorithm used to sign the
 * rewrap request token. RSA keys sign with RS256; EC keys sign with the ECDSA
 * algorithm matching their curve.
 */
function signingAlgForKeyAlgorithm(algorithm: KeyAlgorithm): AsymmetricSigningAlgorithm {
  switch (algorithm) {
    case 'rsa:2048':
    case 'rsa:4096':
      return 'RS256';
    case 'ec:secp256r1':
      return 'ES256';
    case 'ec:secp384r1':
      return 'ES384';
    case 'ec:secp521r1':
      return 'ES512';
    default:
      throw new ConfigurationError(`Unsupported signing key algorithm [${algorithm}]`);
  }
}

async function unwrapKey({
  manifest,
  allowedKases,
  auth,
  dpopKeys,
  concurrencyLimit,
  cryptoService,
  wrappingKeyAlgorithm,
  fulfillableObligations,
}: {
  manifest: Manifest;
  allowedKases: OriginAllowList;
  /** Auth configuration: AuthProvider or { interceptors }. */
  auth?: AuthConfig;
  concurrencyLimit?: number;
  dpopKeys: KeyPair;
  cryptoService: CryptoService;
  wrappingKeyAlgorithm?: KasPublicKeyAlgorithm;
  fulfillableObligations: string[];
}) {
  if (!auth) {
    throw new ConfigurationError('rewrap requires auth; must be configured in client constructor');
  }
  const resolvedAuth: AuthConfig = auth;
  const { keyAccess } = manifest.encryptionInformation;
  const splitPotentials = splitLookupTableFactory(keyAccess, allowedKases);

  async function tryKasRewrap(keySplitInfo: KeyAccessObject): Promise<RewrapResponseData> {
    const url = `${keySplitInfo.url}/v2/rewrap`;
    let ephemeralEncryptionKeys: KeyPair;
    if (wrappingKeyAlgorithm === 'ec:secp256r1') {
      // Generate EC key pair via CryptoService (returns opaque keys)
      ephemeralEncryptionKeys = await cryptoService.generateECKeyPair('P-256');
    } else if (wrappingKeyAlgorithm === 'rsa:2048' || !wrappingKeyAlgorithm) {
      // generateKeyPair() returns opaque keys
      ephemeralEncryptionKeys = await cryptoService.generateKeyPair();
    } else if (isMlKemKeyAlgorithm(wrappingKeyAlgorithm)) {
      if (!cryptoService.generateMlKemKeyPair) {
        throw new ConfigurationError(
          'CryptoService does not support ML-KEM (generateMlKemKeyPair)'
        );
      }
      const level = mlKemAlgorithmToLevel(wrappingKeyAlgorithm);
      ephemeralEncryptionKeys = await cryptoService.generateMlKemKeyPair(level);
    } else {
      throw new ConfigurationError(`Unsupported wrapping key algorithm [${wrappingKeyAlgorithm}]`);
    }

    // Export public key to PEM for protobuf request
    const clientPublicKey = await cryptoService.exportPublicKeyPem(
      ephemeralEncryptionKeys.publicKey
    );

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
    // The request token must be signed with the algorithm matching the dpop key
    // type. Defaulting to RS256 breaks EC keys (e.g. DPoP ES256), since WebCrypto
    // rejects signing an EC key with RSA params ("Unable to use this key to sign").
    const signedRequestToken = await reqSignature(jwtPayload, dpopKeys.privateKey, cryptoService, {
      alg: signingAlgForKeyAlgorithm(dpopKeys.privateKey.algorithm),
    });

    const rewrapResp = await fetchWrappedKey(
      url,
      signedRequestToken,
      resolvedAuth,
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
          // Import KAS session public key from PEM
          const sessionPublicKeyOpaque = await cryptoService.importPublicKey(sessionPublicKey, {
            usage: 'derive',
          });

          // Derive decryption key using ECDH + HKDF via CryptoService (returns SymmetricKey)
          const derivedKey = await cryptoService.deriveKeyFromECDH(
            ephemeralEncryptionKeys.privateKey,
            sessionPublicKeyOpaque,
            {
              hash: 'SHA-256',
              salt: await getZtdfSalt(cryptoService),
            }
          );

          const wrappedKeyAndNonce = entityWrappedKey;
          const iv = wrappedKeyAndNonce.slice(0, 12);
          const wrappedKey = wrappedKeyAndNonce.slice(12);

          // Decrypt using CryptoService with opaque symmetric key
          const decryptResult = await cryptoService.decrypt(
            Binary.fromArrayBuffer(toArrayBuffer(wrappedKey)),
            derivedKey, // SymmetricKey (opaque)
            Binary.fromArrayBuffer(toArrayBuffer(iv)),
            Algorithms.AES_256_GCM
          );

          return {
            key: new Uint8Array(decryptResult.payload.asArrayBuffer()),
            metadata,
            requiredObligations,
          };
        }

        if (wrappingKeyAlgorithm && isMlKemKeyAlgorithm(wrappingKeyAlgorithm)) {
          // The KAS rewrap response uses the platform's canonical ML-KEM
          // "direct key wrap" container:
          //   DER( kemEnvelope { [0] kemCiphertext, [1] encryptedDek } )
          // where encryptedDek = nonce(12) || aes_ct || tag(16) and the AES-256
          // key is the raw ML-KEM shared secret (no HKDF).
          const level = mlKemAlgorithmToLevel(wrappingKeyAlgorithm);
          const { kemCiphertext, encryptedDek } = decodeKemEnvelopeDer(entityWrappedKey);
          const expectedCtLen = MLKEM_CT_SIZES[level];
          if (kemCiphertext.length !== expectedCtLen) {
            throw new DecryptError(
              `malformed ML-KEM wrapped key for ${wrappingKeyAlgorithm}: KEM ciphertext is ${kemCiphertext.length} bytes, expected ${expectedCtLen}`
            );
          }
          // encryptedDek must hold at least a 12B nonce and a 16B GCM tag.
          if (encryptedDek.length < 12 + 16) {
            throw new DecryptError(
              `malformed ML-KEM wrapped key for ${wrappingKeyAlgorithm}: encrypted DEK is only ${encryptedDek.length} bytes`
            );
          }
          const iv = encryptedDek.slice(0, 12);
          const wrappedKey = encryptedDek.slice(12);

          if (!cryptoService.mlKemDecapsulate) {
            throw new ConfigurationError(
              'CryptoService does not support ML-KEM (mlKemDecapsulate)'
            );
          }
          const sharedSecret = await cryptoService.mlKemDecapsulate(
            ephemeralEncryptionKeys.privateKey,
            kemCiphertext
          );

          const decryptResult = await cryptoService.decrypt(
            Binary.fromArrayBuffer(toArrayBuffer(wrappedKey)),
            sharedSecret,
            Binary.fromArrayBuffer(toArrayBuffer(iv)),
            Algorithms.AES_256_GCM
          );

          return {
            key: new Uint8Array(decryptResult.payload.asArrayBuffer()),
            metadata,
            requiredObligations,
          };
        }

        const key = Binary.fromArrayBuffer(toArrayBuffer(entityWrappedKey));
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
        break;
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
    if (!potentials?.length) {
      throw new UnsafeUrlError(
        `Unreconstructable key - no valid KAS found for split ${JSON.stringify(splitId)}`,
        ''
      );
    }
    const anyPromises: Record<string, () => Promise<RewrapResponseData>> = {};
    potentials.forEach((keySplitInfo, i) => {
      const alternativeKey = `${keySplitInfo.url}#${keySplitInfo.kid ?? ''}#${i}`;
      anyPromises[alternativeKey] = async () => {
        try {
          return await tryKasRewrap(keySplitInfo);
        } catch (e) {
          throw handleRewrapError(e);
        }
      };
    });
    splitPromises[splitId] = () => anyPool(poolSize, anyPromises);
  }
  try {
    const rewrapResponseData = await allPool(poolSize, splitPromises);
    const splitKeys = [];
    const requiredObligations = new Set<string>();
    for (const resp of rewrapResponseData) {
      // Import each split key as opaque SymmetricKey
      const splitKeyOpaque = await cryptoService.importSymmetricKey(resp.key);
      splitKeys.push(splitKeyOpaque);
      for (const requiredObligation of resp.requiredObligations) {
        requiredObligations.add(requiredObligation.toLowerCase());
      }
    }
    // Merge symmetric keys via CryptoService
    const reconstructedKey = await cryptoService.mergeSymmetricKeys(splitKeys);
    return {
      reconstructedKey, // SymmetricKey (opaque)
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

function handleRewrapError(error: unknown): Error {
  const cause = asError(error);
  if (cause.name === 'InvalidAccessError' || cause.name === 'OperationError') {
    return new DecryptError('unable to unwrap key from kas', cause);
  }
  return cause;
}

async function decryptChunk(
  encryptedChunk: Uint8Array,
  reconstructedKey: SymmetricKey,
  hash: string,
  cipher: SymmetricCipher,
  segmentIntegrityAlgorithm: SegmentIntegrityAlgorithm,
  specVersion: string,
  cryptoService: CryptoService
): Promise<DecryptResult> {
  const segmentSig = await segmentIntegrity(
    encryptedChunk,
    reconstructedKey, // SymmetricKey (opaque)
    asSegmentIntegrityAlgorithm(segmentIntegrityAlgorithm),
    cryptoService
  );

  const segmentHash = isTargetSpecLegacyTDF(specVersion)
    ? base64.encode(hex.encodeArrayBuffer(segmentSig))
    : base64.encodeArrayBuffer(segmentSig);

  if (hash !== segmentHash) {
    throw new IntegrityError('Failed integrity check on segment hash');
  }
  return await cipher.decrypt(encryptedChunk, reconstructedKey);
}

function asDecryptError(error: unknown, fallbackMessage: string): Error {
  if (error instanceof Error) {
    return error;
  }
  return new DecryptError(fallbackMessage, new Error(String(error)));
}

async function fetchAndDecryptChunkSlice({
  centralDirectory,
  zipReader,
  reconstructedKey,
  cipher,
  segmentIntegrityAlgorithm,
  cryptoService,
  specVersion,
  slice,
}: {
  centralDirectory: CentralDirectory[];
  zipReader: ZipReader;
  reconstructedKey: SymmetricKey;
  cipher: SymmetricCipher;
  segmentIntegrityAlgorithm: SegmentIntegrityAlgorithm;
  cryptoService: CryptoService;
  specVersion: string;
  slice: Chunk[];
}): Promise<Uint8Array[]> {
  const firstChunk = slice[0];
  let buffer!: Uint8Array;
  const bufferSize = slice.reduce(
    (currentVal, { encryptedSegmentSize }) => currentVal + (encryptedSegmentSize as number),
    0
  );
  try {
    buffer = await zipReader.getPayloadSegment(
      centralDirectory,
      '0.payload',
      firstChunk.encryptedOffset,
      bufferSize
    );
  } catch (error) {
    throw error instanceof InvalidFileError
      ? error
      : new NetworkError('unable to fetch payload segment', asError(error));
  }

  try {
    return await sliceAndDecrypt({
      buffer,
      cryptoService,
      reconstructedKey,
      slice,
      cipher,
      segmentIntegrityAlgorithm,
      specVersion,
    });
  } catch (error) {
    throw asDecryptError(error, 'failed to decrypt payload segment');
  }
}

/**
 * Fetches and decrypts payload segments ahead of the reader, in batches of
 * `segmentBatchSize` segments per ranged read.
 *
 * Backpressure is the Streams API's own: `pull` queues a batch whose decrypt
 * has already started, without awaiting it, so the stream keeps pulling until
 * its high-water mark is reached. Every queued batch is in flight or decrypted
 * and waiting. The reader also holds the batch it is draining, so the
 * high-water mark is one less than the number of batches allowed at once.
 */
export function prefetchSegmentBatches({
  chunks,
  segmentBatchSize,
  maxConcurrentSegmentBatches,
  fetchBatch,
}: {
  chunks: Chunk[];
  segmentBatchSize: number;
  maxConcurrentSegmentBatches: number;
  fetchBatch: (slice: Chunk[]) => Promise<Uint8Array[]>;
}): ReadableStream<SegmentBatch> {
  let next = 0;
  return new ReadableStream<SegmentBatch>(
    {
      pull(controller) {
        if (next >= chunks.length) {
          controller.close();
          return;
        }
        const slice = chunks.slice(next, next + segmentBatchSize);
        next += slice.length;
        const plaintext = fetchBatch(slice);
        // The reader awaits batches in order and stops at the first failure, so
        // later batches may never be awaited. Their errors must not surface as
        // unhandled rejections (fatal in Node); awaiting one still throws.
        plaintext.catch(() => undefined);
        controller.enqueue({ slice, plaintext });
      },
    },
    new CountQueuingStrategy({ highWaterMark: maxConcurrentSegmentBatches - 1 })
  );
}

function normalizeSegmentBatchSetting(
  value: number | undefined,
  defaultValue: number,
  name: 'segmentBatchSize' | 'maxConcurrentSegmentBatches'
) {
  const normalized = value ?? defaultValue;
  if (!Number.isInteger(normalized) || normalized < 1) {
    throw new ConfigurationError(`${name} must be a positive integer; got [${normalized}]`);
  }
  return normalized;
}

/**
 * Resolves the batch size and concurrency for a decrypt.
 *
 * Each unset knob takes its value from `derivePrefetchWindow(segmentSize)`. An
 * explicit knob is used as-is and does not rescale the other, so explicit
 * settings can exceed the byte budget.
 */
export function getBoundedSegmentSchedulerOptions({
  segmentBatchSize,
  maxConcurrentSegmentBatches,
  segmentSize,
}: Pick<DecryptConfiguration, 'segmentBatchSize' | 'maxConcurrentSegmentBatches'> & {
  segmentSize: number;
}) {
  const derived = derivePrefetchWindow({ segmentSize });
  return {
    segmentBatchSize: normalizeSegmentBatchSetting(
      segmentBatchSize,
      derived.segmentBatchSize,
      'segmentBatchSize'
    ),
    maxConcurrentSegmentBatches: normalizeSegmentBatchSetting(
      maxConcurrentSegmentBatches,
      derived.maxConcurrentSegmentBatches,
      'maxConcurrentSegmentBatches'
    ),
  };
}

export async function sliceAndDecrypt({
  buffer,
  reconstructedKey,
  slice,
  cipher,
  cryptoService,
  segmentIntegrityAlgorithm,
  specVersion,
}: {
  buffer: Uint8Array;
  reconstructedKey: SymmetricKey;
  slice: Chunk[];
  cipher: SymmetricCipher;
  cryptoService: CryptoService;
  segmentIntegrityAlgorithm: SegmentIntegrityAlgorithm;
  specVersion: string;
}): Promise<Uint8Array[]> {
  const plaintexts: Uint8Array[] = [];
  for (const chunk of slice) {
    const { encryptedOffset, encryptedSegmentSize, plainSegmentSize } = chunk;

    const offset =
      slice[0].encryptedOffset === 0 ? encryptedOffset : encryptedOffset % slice[0].encryptedOffset;
    const encryptedChunk = buffer.subarray(offset, offset + (encryptedSegmentSize as number));

    if (encryptedChunk.length !== encryptedSegmentSize) {
      throw new DecryptError('Failed to fetch entire segment');
    }

    const result = await decryptChunk(
      encryptedChunk,
      reconstructedKey,
      chunk.hash,
      cipher,
      segmentIntegrityAlgorithm,
      specVersion,
      cryptoService
    );
    if (plainSegmentSize && result.payload.length() !== plainSegmentSize) {
      throw new DecryptError(
        `incorrect segment size: found [${result.payload.length()}], expected [${plainSegmentSize}]`
      );
    }
    plaintexts.push(new Uint8Array(result.payload.asArrayBuffer()));
  }
  return plaintexts;
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

  cfg.keyMiddleware ??= async (key) => {
    await Promise.resolve();
    return key;
  };

  const {
    encryptedSegmentSizeDefault: defaultSegmentSize,
    rootSignature,
    segmentHashAlg,
    segmentSizeDefault,
    segments,
  } = manifest.encryptionInformation.integrityInformation;
  // Absent or zero falls back to DEFAULT_SEGMENT_SIZE. Anything else must be
  // usable as a size. Validate it, and the caller's batch settings, before the
  // rewrap so a bad file or bad config costs no KAS call.
  if (defaultSegmentSize && !(Number.isInteger(defaultSegmentSize) && defaultSegmentSize > 0)) {
    throw new InvalidFileError(
      `manifest encryptedSegmentSizeDefault must be a positive integer; got [${defaultSegmentSize}]`
    );
  }
  const encryptedSegmentSizeDefault = defaultSegmentSize || DEFAULT_SEGMENT_SIZE;
  // Size the window by the largest segment, not the default: a manifest may
  // declare per-segment sizes far above it. A loop, not Math.max(...), so a
  // file with many segments cannot overflow the call stack.
  let largestEncryptedSegmentSize = encryptedSegmentSizeDefault;
  for (const { encryptedSegmentSize } of segments) {
    if (encryptedSegmentSize === undefined) {
      continue;
    }
    if (!(Number.isInteger(encryptedSegmentSize) && encryptedSegmentSize > 0)) {
      throw new InvalidFileError(
        `manifest segment encryptedSegmentSize must be a positive integer; got [${encryptedSegmentSize}]`
      );
    }
    largestEncryptedSegmentSize = Math.max(largestEncryptedSegmentSize, encryptedSegmentSize);
  }
  // The window mostly holds decrypted plaintext awaiting the reader, which the
  // encrypted size bounds. In-flight batches also hold their ciphertext until
  // decryption finishes, so the transient peak can exceed the budget by up to
  // one window of ciphertext.
  const schedulerOptions = getBoundedSegmentSchedulerOptions({
    ...cfg,
    segmentSize: largestEncryptedSegmentSize,
  });
  const { metadata, reconstructedKey, requiredObligations } = await unwrapKey({
    fulfillableObligations: cfg.fulfillableObligations,
    manifest,
    auth: cfg.auth,
    allowedKases: allowList,
    dpopKeys: cfg.dpopKeys,
    cryptoService: cfg.cryptoService,
    wrappingKeyAlgorithm: cfg.wrappingKeyAlgorithm,
  });
  // async function unwrapKey(manifest: Manifest, allowedKases: string[], authProvider: AuthProvider | AppIdAuthProvider, publicKey: string, privateKey: string, entity: EntityObject) {
  const keyForDecryption = await cfg.keyMiddleware(reconstructedKey);

  // check if the TDF is a legacy TDF. See resolveSpecVersion for where the
  // version is looked for; a manifest that records none is read as 4.2.2.
  const specVersion = resolveSpecVersion(manifest) || '4.2.2';
  const isLegacyTDF = isTargetSpecLegacyTDF(specVersion);

  // Decode each hash and store it in an array of Uint8Array
  const segmentHashList = segments.map(
    ({ hash }) => new Uint8Array(base64.decodeArrayBuffer(hash))
  );

  // Concatenate all segment hashes into a single Uint8Array
  const aggregateHash = await concatenateUint8Array(segmentHashList);

  // `rootSignature.alg` is unauthenticated manifest data. Reject GMAC (in any
  // casing) and every unknown algorithm here, before it can select a
  // verification routine: a GMAC "root signature" is just a copy of the last
  // segment hash, so honouring it would let a keyless attacker truncate,
  // reorder, duplicate or drop segments undetected.
  const rootIntegrityAlgorithm = asRootIntegrityAlgorithm(rootSignature.alg);

  const payloadSig = await rootIntegrity(
    aggregateHash,
    keyForDecryption, // SymmetricKey (opaque)
    rootIntegrityAlgorithm,
    cfg.cryptoService
  );

  if (!cfg.noVerifyAssertions) {
    for (const assertion of manifest.assertions || []) {
      // Create a default assertion key
      let assertionKey: AssertionKey = {
        alg: 'HS256',
        key: keyForDecryption, // SymmetricKey (opaque)
      };

      if (cfg.assertionVerificationKeys) {
        const foundKey = cfg.assertionVerificationKeys.Keys[assertion.id];
        if (foundKey) {
          assertionKey = foundKey;
        }
      }
      await assertions.verify(
        assertion,
        aggregateHash,
        assertionKey,
        isLegacyTDF,
        cfg.cryptoService
      );
    }
  }

  const rootSig = isLegacyTDF
    ? base64.encode(hex.encodeArrayBuffer(payloadSig))
    : base64.encodeArrayBuffer(payloadSig);

  if (manifest.encryptionInformation.integrityInformation.rootSignature.sig !== rootSig) {
    throw new IntegrityError('Failed integrity check on root signature');
  }

  let mapOfRequestsOffset = 0;
  const chunks = segments.map(
    ({
      hash,
      encryptedSegmentSize = encryptedSegmentSizeDefault,
      segmentSize = segmentSizeDefault,
    }) => {
      const chunk: Chunk = {
        hash,
        encryptedOffset: mapOfRequestsOffset,
        encryptedSegmentSize,
        plainSegmentSize: segmentSize,
      };
      mapOfRequestsOffset += encryptedSegmentSize;
      return chunk;
    }
  );

  const cipher = new AesGcmCipher(cfg.cryptoService);
  // Segment GMAC is sound (it is the AEAD's own tag), so both algorithms stay
  // valid here; only unknown ones are rejected.
  const segmentIntegrityAlg = asSegmentIntegrityAlgorithm(segmentHashAlg || rootIntegrityAlgorithm);

  const batches = prefetchSegmentBatches({
    chunks,
    ...schedulerOptions,
    fetchBatch: (slice) =>
      fetchAndDecryptChunkSlice({
        centralDirectory,
        zipReader,
        reconstructedKey: keyForDecryption,
        cipher,
        segmentIntegrityAlgorithm: segmentIntegrityAlg,
        cryptoService: cfg.cryptoService,
        specVersion,
        slice,
      }),
  }).getReader();

  let progress = 0;
  // The batch being drained, one segment per pull. Taking segments off the
  // front releases each one as soon as it is handed to the consumer.
  let draining: Array<{ plaintext: Uint8Array; encryptedSegmentSize: number }> = [];
  const underlyingSource = {
    pull: async (controller: ReadableStreamDefaultController) => {
      if (!draining.length) {
        const { done, value: batch } = await batches.read();
        if (done) {
          controller.close();
          return;
        }
        try {
          const plaintexts = await batch.plaintext;
          draining = batch.slice.map(({ encryptedSegmentSize = 0 }, i) => ({
            plaintext: plaintexts[i],
            encryptedSegmentSize,
          }));
        } catch (e) {
          // Drop the queued batches and stop fetching more.
          batches.cancel(e).catch(() => undefined);
          throw e;
        }
      }

      const { plaintext, encryptedSegmentSize } = draining.shift()!;
      controller.enqueue(plaintext);
      progress += encryptedSegmentSize;
      cfg.progressHandler?.(progress);
    },
    cancel: (reason: unknown) => batches.cancel(reason),
    ...(cfg.fileStreamServiceWorker && { fileStreamServiceWorker: cfg.fileStreamServiceWorker }),
  };

  const outputStream = new DecoratedReadableStream(underlyingSource);

  outputStream.requiredObligations = requiredObligations;
  outputStream.manifest = manifest;
  outputStream.metadata = metadata;
  return outputStream;
}

async function concatenateUint8Array(uint8arrays: Uint8Array[]): Promise<Uint8Array> {
  const blob = new Blob(uint8arrays.map(toArrayBuffer));
  const buffer = await blob.arrayBuffer();
  return new Uint8Array(buffer);
}
