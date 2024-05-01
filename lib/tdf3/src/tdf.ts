import axios from 'axios';
import { unsigned } from './utils/buffer-crc32.js';
import { exportSPKI, importX509 } from 'jose';
import { DecoratedReadableStream } from './client/DecoratedReadableStream.js';
import { EntityObject } from '../../src/tdf/EntityObject.js';
import { validateSecureUrl } from '../../src/utils.js';
import { DecryptParams } from './client/builders.js';

import {
  AttributeSet,
  isRemote as isRemoteKeyAccess,
  KeyAccessType,
  KeyInfo,
  Manifest,
  Policy,
  Remote as KeyAccessRemote,
  SplitKey,
  UpsertResponse,
  Wrapped as KeyAccessWrapped,
  KeyAccess,
} from './models/index.js';
import { base64 } from '../../src/encodings/index.js';
import {
  type Chunker,
  ZipReader,
  ZipWriter,
  base64ToBuffer,
  isAppIdProviderCheck,
  keyMerge,
  buffToString,
  concatUint8,
} from './utils/index.js';
import { Binary } from './binary.js';
import {
  IllegalArgumentError,
  KasDecryptError,
  KasUpsertError,
  KeyAccessError,
  ManifestIntegrityError,
  PolicyIntegrityError,
  TdfDecryptError,
  TdfError,
  TdfPayloadExtractionError,
} from '../../src/errors.js';
import { htmlWrapperTemplate } from './templates/index.js';

// configurable
// TODO: remove dependencies from ciphers so that we can open-source instead of relying on other Virtru libs
import { AesGcmCipher } from './ciphers/index.js';
import {
  type AuthProvider,
  AppIdAuthProvider,
  HttpRequest,
  type HttpMethod,
  reqSignature,
} from '../../src/auth/auth.js';
import PolicyObject from '../../src/tdf/PolicyObject.js';
import { type CryptoService, type DecryptResult } from './crypto/declarations.js';
import { CentralDirectory } from './utils/zip-reader.js';
import { SymmetricCipher } from './ciphers/symmetric-cipher-base.js';

// TODO: input validation on manifest JSON
const DEFAULT_SEGMENT_SIZE = 1024 * 1024;

/**
 * Configuration for TDF3
 */
export type EncryptionOptions = {
  /**
   * Defaults to `split`, the currently only implmented key wrap algorithm.
   */
  type?: string;
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
  attributeSet?: AttributeSet;
  type: KeyAccessType;
  url?: string;
  kid?: string;
  publicKey: string;
  attributeUrl?: string;
  metadata?: Metadata;
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

export type TDFConfiguration = {
  allowedKases?: string[];
  cryptoService: CryptoService;
};

export type IntegrityAlgorithm = 'GMAC' | 'HS256';

export type EncryptConfiguration = {
  allowedKases?: string[];
  cryptoService: CryptoService;
  dpopKeys: CryptoKeyPair;
  encryptionInformation: SplitKey;
  segmentSizeDefault: number;
  integrityAlgorithm: IntegrityAlgorithm;
  segmentIntegrityAlgorithm: IntegrityAlgorithm;
  contentStream: ReadableStream<Uint8Array>;
  mimeType?: string;
  policy: Policy;
  entity?: EntityObject;
  attributeSet?: AttributeSet;
  authProvider?: AuthProvider | AppIdAuthProvider;
  byteLimit: number;
  progressHandler?: (bytesProcessed: number) => void;
  keyForEncryption: KeyInfo;
  keyForManifest: KeyInfo;
};

export type DecryptConfiguration = {
  allowedKases: string[];
  authProvider: AuthProvider | AppIdAuthProvider;
  cryptoService: CryptoService;
  entity?: EntityObject;

  dpopKeys: CryptoKeyPair;

  chunker: Chunker;
  keyMiddleware: KeyMiddleware;
  progressHandler?: (bytesProcessed: number) => void;
  fileStreamServiceWorker?: string;
};

export type UpsertConfiguration = {
  allowedKases: string[];
  authProvider: AuthProvider | AppIdAuthProvider;
  entity?: EntityObject;

  privateKey: CryptoKey;

  unsavedManifest: Manifest;
  // if true skips the key access type check when syncing
  ignoreType?: boolean;
};

export type RewrapRequest = {
  signedRequestToken: string;
};

export type KasPublicKeyInfo = {
  url: string;
  algorithm: KasPublicKeyAlgorithm;
  kid?: string;
  publicKey: string;
};

export type KasPublicKeyAlgorithm = 'ec:secp256r1' | 'rsa:2048';

export type KasPublicKeyFormat = 'pkcs8' | 'jwks';

type KasPublicKeyParams = {
  algorithm?: KasPublicKeyAlgorithm;
  fmt?: KasPublicKeyFormat;
  v?: '1' | '2';
};

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
    return {
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
    return {
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
/**
 *
 * @param payload The TDF content to encode in HTML
 * @param manifest A copy of the manifest
 * @param transferUrl reader web-service start page
 * @return utf-8 encoded HTML data
 */
export function wrapHtml(
  payload: Uint8Array,
  manifest: Manifest | string,
  transferUrl: string
): Uint8Array {
  const { origin } = new URL(transferUrl);
  const exportManifest: string = typeof manifest === 'string' ? manifest : JSON.stringify(manifest);

  const fullHtmlString = htmlWrapperTemplate({
    transferUrl,
    transferBaseUrl: origin,
    manifest: base64.encode(exportManifest),
    payload: buffToString(payload, 'base64'),
  });

  return new TextEncoder().encode(fullHtmlString);
}

export function unwrapHtml(htmlPayload: ArrayBuffer | Uint8Array | Binary | string) {
  let html;
  if (htmlPayload instanceof ArrayBuffer || ArrayBuffer.isView(htmlPayload)) {
    html = new TextDecoder().decode(htmlPayload);
  } else {
    html = htmlPayload.toString();
  }
  const payloadRe = /<input id=['"]?data-input['"]?[^>]*value=['"]?([a-zA-Z0-9+/=]+)['"]?/;
  const reResult = payloadRe.exec(html);
  if (reResult === null) {
    throw new TdfPayloadExtractionError('Payload is missing');
  }
  const base64Payload = reResult[1];
  try {
    return base64ToBuffer(base64Payload);
  } catch (e) {
    throw new TdfPayloadExtractionError('There was a problem extracting the TDF3 payload', e);
  }
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
 * @param  {String} options.attributeUrl - URL of the attribute to use for pubKey and kasUrl. Omit to use default.
 * @param  {String} options.url - directly set the KAS URL
 * @param  {String} options.publicKey - directly set the (KAS) public key
 * @param  {String?} options.kid - Key identifier of KAS public key
 * @param  {String? Object?} options.metadata - Metadata. Appears to be dead code.
 * @return {KeyAccess}- the key access object loaded
 */
export async function buildKeyAccess({
  attributeSet,
  type,
  url,
  publicKey,
  kid,
  attributeUrl,
  metadata,
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
        return new KeyAccessWrapped(kasUrl, kasKeyIdentifier, pubKey, metadata);
      case 'remote':
        return new KeyAccessRemote(kasUrl, kasKeyIdentifier, pubKey, metadata);
      default:
        throw new KeyAccessError(`buildKeyAccess: Key access type ${type} is unknown`);
    }
  }

  // If an attributeUrl is provided try to load with that first.
  if (attributeUrl && attributeSet) {
    const attr = attributeSet.get(attributeUrl);
    if (attr && attr.kasUrl && attr.pubKey) {
      return createKeyAccess(type, attr.kasUrl, attr.kid, attr.pubKey, metadata);
    }
  }

  // if url and pulicKey are specified load the key access object with them
  if (url && publicKey) {
    return createKeyAccess(type, url, kid, await extractPemFromKeyString(publicKey), metadata);
  }

  // Assume the default attribute is the source for kasUrl and pubKey
  const defaultAttr = attributeSet?.getDefault();
  if (defaultAttr) {
    const { pubKey, kasUrl } = defaultAttr;
    if (pubKey && kasUrl) {
      return createKeyAccess(type, kasUrl, kid, await extractPemFromKeyString(pubKey), metadata);
    }
  }
  // All failed. Raise an error.
  throw new KeyAccessError('TDF.buildKeyAccess: No source for kasUrl or pubKey');
}

export function validatePolicyObject(policy: Policy): void {
  const missingFields: string[] = [];

  if (!policy.uuid) missingFields.push('uuid');
  if (!policy.body) missingFields.push('body', 'body.dissem');
  if (policy.body && !policy.body.dissem) missingFields.push('body.dissem');

  if (missingFields.length) {
    throw new PolicyIntegrityError(
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

  if (!policy) {
    throw new Error(`No policy provided`);
  }
  const encryptionInformationStr = await encryptionInformation.write(policy, keyInfo);

  if (!encryptionInformationStr) {
    throw new Error('Missing encryption information');
  }

  return {
    payload,
    // generate the manifest first, then insert integrity information into it
    encryptionInformation: encryptionInformationStr,
  };
}

async function getSignature(
  unwrappedKeyBinary: Binary,
  payloadBinary: Binary,
  algorithmType: IntegrityAlgorithm,
  cryptoService: CryptoService
) {
  switch (algorithmType.toUpperCase()) {
    case 'GMAC':
      // use the auth tag baked into the encrypted payload
      return buffToString(Uint8Array.from(payloadBinary.asByteArray()).slice(-16), 'hex');
    case 'HS256':
      // simple hmac is the default
      return await cryptoService.hmac(
        buffToString(new Uint8Array(unwrappedKeyBinary.asArrayBuffer()), 'hex'),
        buffToString(new Uint8Array(payloadBinary.asArrayBuffer()), 'utf-8')
      );
    default:
      throw new IllegalArgumentError(`Unsupported signature alg [${algorithmType}]`);
  }
}

function buildRequest(method: HttpMethod, url: string, body?: unknown): HttpRequest {
  return {
    headers: {},
    method: method,
    url: url,
    body,
  };
}

export async function upsert({
  allowedKases,
  authProvider,
  entity,
  privateKey,
  unsavedManifest,
  ignoreType,
}: UpsertConfiguration): Promise<UpsertResponse> {
  const { keyAccess, policy } = unsavedManifest.encryptionInformation;
  const isAppIdProvider = authProvider && isAppIdProviderCheck(authProvider);
  if (authProvider === undefined) {
    throw new Error('Upsert cannot be done without auth provider');
  }
  return Promise.all(
    keyAccess.map(async (keyAccessObject) => {
      // We only care about remote key access objects for the policy sync portion
      const isRemote = isRemoteKeyAccess(keyAccessObject);
      if (!ignoreType && !isRemote) {
        return;
      }

      if (!allowedKases.includes(keyAccessObject.url)) {
        throw new KasUpsertError(`Unexpected KAS url: [${keyAccessObject.url}]`);
      }

      const url = `${keyAccessObject.url}/${isAppIdProvider ? '' : 'v2/'}upsert`;

      //TODO I dont' think we need a body at all for KAS requests
      // Do we need ANY of this if it's already embedded in the EO in the Bearer OIDC token?
      const body: Record<string, unknown> = {
        keyAccess: keyAccessObject,
        policy: unsavedManifest.encryptionInformation.policy,
        entity: isAppIdProviderCheck(authProvider) ? entity : undefined,
        authToken: undefined,
        clientPayloadSignature: undefined,
      };

      if (isAppIdProviderCheck(authProvider)) {
        body.authToken = await reqSignature({}, privateKey);
      } else {
        body.clientPayloadSignature = await reqSignature(body, privateKey);
      }
      const httpReq = await authProvider.withCreds(buildRequest('POST', url, body));

      try {
        const response = await axios.post(httpReq.url, httpReq.body, {
          headers: httpReq.headers,
        });

        // Remove additional properties which were needed to sync, but not that we want to save to
        // the manifest
        delete keyAccessObject.wrappedKey;
        delete keyAccessObject.encryptedMetadata;
        delete keyAccessObject.policyBinding;

        if (isRemote) {
          // Decode the policy and extract only the required info to save -- the uuid
          const decodedPolicy = JSON.parse(base64.decode(policy));
          unsavedManifest.encryptionInformation.policy = base64.encode(
            JSON.stringify({ uuid: decodedPolicy.uuid })
          );
        }
        return response.data;
      } catch (e) {
        throw new KasUpsertError(
          `Unable to perform upsert operation on the KAS: [${e.name}: ${e.message}], response: [${e?.response?.body}]`,
          e
        );
      }
    })
  );
}

export async function writeStream(cfg: EncryptConfiguration): Promise<DecoratedReadableStream> {
  if (!cfg.authProvider) {
    throw new IllegalArgumentError('No authorization middleware defined');
  }
  if (!cfg.contentStream) {
    throw new IllegalArgumentError('No input stream defined');
  }
  if (!cfg.encryptionInformation) {
    throw new IllegalArgumentError('No encryption type specified');
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
  let aggregateHash = '';

  const zipWriter = new ZipWriter();

  if (!cfg.encryptionInformation) {
    throw new Error('Missing encryptionInformation');
  }

  const manifest = await _generateManifest(
    cfg.keyForManifest,
    cfg.encryptionInformation,
    cfg.policy,
    cfg.mimeType
  );

  // For all remote key access objects, sync its policy
  if (!manifest) {
    throw new Error('Please use "loadTDFStream" first to load a manifest.');
  }
  const pkKeyLike = cfg.dpopKeys.privateKey;

  const upsertResponse = await upsert({
    allowedKases: cfg.allowedKases || [],
    authProvider: cfg.authProvider,
    entity: cfg.entity,
    privateKey: pkKeyLike,
    unsavedManifest: manifest,
  });

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
        const payloadSigStr = await getSignature(
          cfg.keyForEncryption.unwrappedKeyBinary,
          Binary.fromString(aggregateHash),
          cfg.integrityAlgorithm,
          cfg.cryptoService
        );
        manifest.encryptionInformation.integrityInformation.rootSignature.sig =
          base64.encode(payloadSigStr);
        manifest.encryptionInformation.integrityInformation.rootSignature.alg =
          cfg.integrityAlgorithm;

        manifest.encryptionInformation.integrityInformation.segmentSizeDefault = segmentSizeDefault;
        manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault =
          encryptedSegmentSizeDefault;
        manifest.encryptionInformation.integrityInformation.segmentHashAlg =
          cfg.segmentIntegrityAlgorithm;
        manifest.encryptionInformation.integrityInformation.segments = segmentInfos;

        manifest.encryptionInformation.method.isStreamable = true;

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

  if (upsertResponse) {
    plaintextStream.upsertResponse = upsertResponse;
    plaintextStream.tdfSize = totalByteCount;
    plaintextStream.algorithm = manifest.encryptionInformation.method.algorithm;
  }

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
      throw new Error(`Safe byte limit (${cfg.byteLimit}) exceeded`);
    }
    //new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    crcCounter = unsigned(chunk as Uint8Array, crcCounter);
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
    const payloadSigStr = await getSignature(
      cfg.keyForEncryption.unwrappedKeyBinary,
      encryptedResult.payload,
      cfg.segmentIntegrityAlgorithm,
      cfg.cryptoService
    );

    // combined string of all hashes for root signature
    aggregateHash += payloadSigStr;

    segmentInfos.push({
      hash: base64.encode(payloadSigStr),
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
async function loadTDFStream(
  chunker: Chunker
): Promise<{ manifest: Manifest; zipReader: ZipReader; centralDirectory: CentralDirectory[] }> {
  const zipReader = new ZipReader(chunker);
  const centralDirectory = await zipReader.getCentralDirectory();
  const manifest = await zipReader.getManifest(centralDirectory, '0.manifest.json');
  return { manifest, zipReader, centralDirectory };
}

async function unwrapKey({
  manifest,
  allowedKases,
  authProvider,
  dpopKeys,
  entity,
  cryptoService,
}: {
  manifest: Manifest;
  allowedKases: string[];
  authProvider: AuthProvider | AppIdAuthProvider;
  dpopKeys: CryptoKeyPair;
  entity: EntityObject | undefined;
  cryptoService: CryptoService;
}) {
  if (authProvider === undefined) {
    throw new Error('Upsert can be done without auth provider');
  }
  const { keyAccess } = manifest.encryptionInformation;
  let responseMetadata;
  const isAppIdProvider = authProvider && isAppIdProviderCheck(authProvider);
  // const pkKeyLike = await importPKCS8(privateKey, 'RS256');
  // Get key access information to know the KAS URLS
  // TODO: logic that runs on multiple KAS's
  const ephemeralEncryptionKeys = await cryptoService.cryptoToPemPair(
    await cryptoService.generateKeyPair()
  );
  const clientPublicKey = ephemeralEncryptionKeys.publicKey;

  const rewrappedKeys = await Promise.all(
    keyAccess.map(async (keySplitInfo) => {
      if (!allowedKases.includes(keySplitInfo.url)) {
        throw new KasUpsertError(`Unexpected KAS url: [${keySplitInfo.url}]`);
      }
      const url = `${keySplitInfo.url}/${isAppIdProvider ? '' : 'v2/'}rewrap`;

      const requestBodyStr = JSON.stringify({
        algorithm: 'RS256',
        keyAccess: keySplitInfo,
        policy: manifest.encryptionInformation.policy,
        clientPublicKey,
      });

      const jwtPayload = { requestBody: requestBodyStr };
      const signedRequestToken = await reqSignature(
        isAppIdProvider ? {} : jwtPayload,
        dpopKeys.privateKey
      );

      let requestBody;
      if (isAppIdProvider) {
        requestBody = {
          keyAccess: keySplitInfo,
          policy: manifest.encryptionInformation.policy,
          entity: {
            ...entity,
            publicKey: clientPublicKey,
          },
          authToken: signedRequestToken,
        };
      } else {
        requestBody = {
          signedRequestToken,
        };
      }

      // Create a PoP token by signing the body so KAS knows we actually have a private key
      // Expires in 60 seconds
      const httpReq = await authProvider.withCreds(buildRequest('POST', url, requestBody));

      try {
        // The response from KAS on a rewrap
        const {
          data: { entityWrappedKey, metadata },
        } = await axios.post(httpReq.url, httpReq.body, { headers: httpReq.headers });
        responseMetadata = metadata;
        const key = Binary.fromString(base64.decode(entityWrappedKey));
        const decryptedKeyBinary = await cryptoService.decryptWithPrivateKey(
          key,
          ephemeralEncryptionKeys.privateKey
        );
        return new Uint8Array(decryptedKeyBinary.asByteArray());
      } catch (e) {
        console.error(e);
        throw new KasDecryptError(
          `Unable to decrypt the response from KAS: [${e.name}: ${e.message}], response: [${e?.response?.body}]`,
          e
        );
      }
    })
  );

  // Merge the unwrapped keys from each KAS
  const reconstructedKey = keyMerge(rewrappedKeys);
  const reconstructedKeyBinary = Binary.fromArrayBuffer(reconstructedKey);

  return {
    reconstructedKeyBinary,
    metadata: responseMetadata,
  };
}

async function decryptChunk(
  encryptedChunk: Uint8Array,
  reconstructedKeyBinary: Binary,
  hash: string,
  cipher: SymmetricCipher,
  segmentIntegrityAlgorithm: IntegrityAlgorithm,
  cryptoService: CryptoService
): Promise<DecryptResult> {
  const segmentHashStr = await getSignature(
    reconstructedKeyBinary,
    Binary.fromArrayBuffer(encryptedChunk.buffer),
    segmentIntegrityAlgorithm,
    cryptoService
  );
  if (hash !== btoa(segmentHashStr)) {
    throw new ManifestIntegrityError('Failed integrity check on segment hash');
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
  cryptoService: CryptoService
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
        try {
          const slice = chunkMap.slice(i, i + chunksInOneDownload);
          const bufferSize = slice.reduce(
            (currentVal, { encryptedSegmentSize }) => currentVal + (encryptedSegmentSize as number),
            0
          );
          const buffer: Uint8Array | null = await zipReader.getPayloadSegment(
            centralDirectory,
            '0.payload',
            slice[0].encryptedOffset,
            bufferSize
          );
          if (buffer) {
            sliceAndDecrypt({
              buffer,
              cryptoService,
              reconstructedKeyBinary,
              slice,
              cipher,
              segmentIntegrityAlgorithm,
            });
          }
        } catch (e) {
          throw new TdfDecryptError(
            'Error decrypting payload. This suggests the key used to decrypt the payload is not correct.',
            e
          );
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
}: {
  buffer: Uint8Array;
  reconstructedKeyBinary: Binary;
  slice: Chunk[];
  cipher: SymmetricCipher;
  cryptoService: CryptoService;
  segmentIntegrityAlgorithm: IntegrityAlgorithm;
}) {
  for (const index in slice) {
    const { encryptedOffset, encryptedSegmentSize, _resolve, _reject } = slice[index];

    const offset =
      slice[0].encryptedOffset === 0 ? encryptedOffset : encryptedOffset % slice[0].encryptedOffset;
    const encryptedChunk = new Uint8Array(
      buffer.slice(offset, offset + (encryptedSegmentSize as number))
    );

    await decryptChunk(
      encryptedChunk,
      reconstructedKeyBinary,
      slice[index]['hash'],
      cipher,
      segmentIntegrityAlgorithm,
      cryptoService
    )
      .then((result) => {
        slice[index].decryptedChunk = result;
        return null;
      })
      .then(_resolve, _reject);
  }
}

export async function readStream(cfg: DecryptConfiguration) {
  const { manifest, zipReader, centralDirectory } = await loadTDFStream(cfg.chunker);
  if (!manifest) {
    throw new Error('Missing manifest data');
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
    allowedKases: cfg.allowedKases,
    dpopKeys: cfg.dpopKeys,
    entity: cfg.entity,
    cryptoService: cfg.cryptoService,
  });
  // async function unwrapKey(manifest: Manifest, allowedKases: string[], authProvider: AuthProvider | AppIdAuthProvider, publicKey: string, privateKey: string, entity: EntityObject) {
  const keyForDecryption = await cfg.keyMiddleware(reconstructedKeyBinary);
  const encryptedSegmentSizeDefault = defaultSegmentSize || DEFAULT_SEGMENT_SIZE;

  // check the combined string of hashes
  const integrityAlgorithm = rootSignature.alg;
  const payloadSigStr = await getSignature(
    keyForDecryption,
    Binary.fromString(segments.map((segment) => base64.decode(segment.hash)).join('')),
    integrityAlgorithm,
    cfg.cryptoService
  );

  if (
    manifest.encryptionInformation.integrityInformation.rootSignature.sig !==
    base64.encode(payloadSigStr)
  ) {
    throw new ManifestIntegrityError('Failed integrity check on root signature');
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

  // Not waiting for Promise to resolve
  updateChunkQueue(
    Array.from(chunkMap.values()),
    centralDirectory,
    zipReader,
    keyForDecryption,
    cipher,
    segmentHashAlg || integrityAlgorithm,
    cfg.cryptoService
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
  outputStream.emit('manifest', manifest);
  outputStream.metadata = metadata;
  outputStream.emit('rewrap', metadata);
  return outputStream;
}
