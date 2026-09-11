import { fromBuffer } from '../../../src/seekable.js';
import { AesGcmCipher } from '../../../tdf3/src/ciphers/aes-gcm-cipher.js';
import type { AssertionConfig } from '../../../tdf3/src/assertions.js';
import type { CryptoService } from '../../../tdf3/src/crypto/declarations.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import { SplitKey } from '../../../tdf3/src/models/index.js';
import type { Manifest } from '../../../tdf3/src/models/index.js';
import {
  buildKeyAccess,
  writeStream,
  type EncryptConfiguration,
  type IntegrityAlgorithm,
} from '../../../tdf3/src/tdf.js';
import { ZipReader } from '../../../tdf3/src/utils/zip-reader.js';
import { getMocks } from '../../mocks/index.js';

const Mocks = getMocks();

/**
 * Drives `writeStream` directly, with no KAS and no network, so tests can
 * exercise manifest shape and segment accounting cheaply. Going through the
 * public builders would clamp `segmentSize` to sane values; several scale tests
 * deliberately want tiny segments so a small payload produces a large segment
 * count.
 */
export type WriteTdfOptions = {
  plaintext: Uint8Array;
  segmentSize: number;
  integrityAlgorithm?: IntegrityAlgorithm;
  segmentIntegrityAlgorithm?: IntegrityAlgorithm;
  assertionConfigs?: AssertionConfig[];
  byteLimit?: number;
  cryptoService?: CryptoService;
  contentStream?: ReadableStream<Uint8Array>;
  knownSourceSize?: number;
  manifestMaxSize?: number;
};

export type WrittenTdf = {
  /** The whole zip container. */
  zipBytes: Uint8Array;
  /** The manifest exactly as it was written, before any parse/serialize round trip. */
  manifestBytes: Uint8Array;
  manifest: Manifest;
};

function streamOf(plaintext: Uint8Array, chunkSize: number): ReadableStream<Uint8Array> {
  let offset = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset >= plaintext.length) {
        controller.close();
        return;
      }
      controller.enqueue(plaintext.subarray(offset, offset + chunkSize));
      offset += chunkSize;
    },
  });
}

/** Builds an `EncryptConfiguration` wired to mock keys, resolving no endpoints. */
export async function encryptConfiguration(opts: WriteTdfOptions): Promise<EncryptConfiguration> {
  const cryptoService = opts.cryptoService ?? DefaultCryptoService;
  const encryptionInformation = new SplitKey(new AesGcmCipher(cryptoService));
  encryptionInformation.keyAccess = [
    await buildKeyAccess({
      type: 'wrapped',
      url: Mocks.getKasUrl(),
      publicKey: Mocks.kasPublicKey,
      cryptoService,
    }),
  ];
  const keyInfo = await encryptionInformation.generateKey();

  return {
    auth: { updateClientPublicKey: async () => undefined, withCreds: async (req) => req },
    byteLimit: opts.byteLimit ?? Number.MAX_SAFE_INTEGER,
    contentStream: opts.contentStream ?? streamOf(opts.plaintext, Math.max(1, opts.segmentSize)),
    cryptoService,
    dpopKeys: await Mocks.entityKeyPair(),
    encryptionInformation,
    integrityAlgorithm: opts.integrityAlgorithm ?? 'HS256',
    keyForEncryption: keyInfo,
    keyForManifest: keyInfo,
    policy: Mocks.getPolicyObject(),
    segmentIntegrityAlgorithm: opts.segmentIntegrityAlgorithm ?? 'GMAC',
    segmentSizeDefault: opts.segmentSize,
    ...(opts.assertionConfigs && { assertionConfigs: opts.assertionConfigs }),
    ...(opts.knownSourceSize !== undefined && { knownSourceSize: opts.knownSourceSize }),
    ...(opts.manifestMaxSize !== undefined && { manifestMaxSize: opts.manifestMaxSize }),
  };
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    parts.push(value);
  }
  return new Uint8Array(await new Blob(parts).arrayBuffer());
}

/**
 * Reads `0.manifest.json` back out of a written container as raw bytes, using
 * the central directory rather than re-serializing the parsed object, so
 * assertions about the emitted byte length are about what was really emitted.
 */
export async function readManifestBytes(zipBytes: Uint8Array): Promise<Uint8Array> {
  const chunker = fromBuffer(zipBytes);
  const zipReader = new ZipReader(chunker);
  const centralDirectory = await zipReader.getCentralDirectory();
  const entry = centralDirectory.find(({ fileName }) => fileName === '0.manifest.json');
  if (!entry) {
    throw new Error('no manifest entry in the written container');
  }
  const byteStart = entry.relativeOffsetOfLocalHeader + entry.headerLength;
  return chunker(byteStart, byteStart + entry.uncompressedSize);
}

/** Encrypts `plaintext` and returns the container plus the manifest it carries. */
export async function writeTdf(opts: WriteTdfOptions): Promise<WrittenTdf> {
  const stream = await writeStream(await encryptConfiguration(opts));
  const zipBytes = await drain(stream.stream);
  const manifestBytes = await readManifestBytes(zipBytes);
  return {
    zipBytes,
    manifestBytes,
    manifest: JSON.parse(new TextDecoder().decode(manifestBytes)),
  };
}

/** Serialized length of just the `segments` array of a written manifest. */
export function segmentsArrayBytes(manifest: Manifest): number {
  return new TextEncoder().encode(
    JSON.stringify(manifest.encryptionInformation.integrityInformation.segments)
  ).length;
}
