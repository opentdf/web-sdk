/**
 * Shared scaffolding for the integrity specs: build a real multi-segment TDF,
 * take it apart, edit it the way an attacker with no key can, and hand it back
 * to a reader.
 *
 * `root-signature.spec.ts` and `integrity-algorithms.spec.ts` each carry their
 * own copy of most of this. Rather than add a third, new specs import from
 * here; folding the existing two in is left as a separate cleanup.
 */
import { assert } from 'chai';

import { getMocks } from '../../mocks/index.js';
import { AuthProvider, HttpRequest } from '../../../src/auth/auth.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../../tdf3/index.js';
import { Client } from '../../../tdf3/src/index.js';
import { type EncryptParams } from '../../../tdf3/src/client/builders.js';
import { type Manifest } from '../../../tdf3/src/models/manifest.js';
import { type CryptoService } from '../../../tdf3/src/crypto/declarations.js';
import { loadTDFStream } from '../../../tdf3/src/tdf.js';
import { concatUint8, ZipWriter } from '../../../tdf3/src/utils/index.js';
import { unsigned } from '../../../tdf3/src/utils/buffer-crc32.js';
import { fromBuffer } from '../../../src/seekable.js';

const Mocks = getMocks();

export const kasUrl = 'http://localhost:3000';

export const authProvider: AuthProvider = {
  updateClientPublicKey: async () => {},
  withCreds: async (httpReq: HttpRequest) => httpReq,
};

/** Small enough to keep these tests quick, large enough to be a real segment. */
export const SEGMENT_SIZE = 1024;
export const SEGMENT_COUNT = 4;
const EXTERNAL_FILE_ATTRIBUTES = 2175008768;

/**
 * A payload of `count` distinguishable segments, so a reordered or truncated
 * decryption is visible in the output rather than only in an error.
 */
export function segmentedPlaintext(count = SEGMENT_COUNT): Uint8Array {
  const out = new Uint8Array(count * SEGMENT_SIZE);
  for (let i = 0; i < count; i++) {
    out.fill('A'.charCodeAt(0) + i, i * SEGMENT_SIZE, (i + 1) * SEGMENT_SIZE);
  }
  return out;
}

export function newClient(overrides: { cryptoService?: CryptoService } = {}): Client.Client {
  return new Client.Client({
    kasEndpoint: kasUrl,
    platformUrl: kasUrl,
    dpopKeys: Mocks.entityKeyPair(),
    clientId: 'id',
    authProvider,
    ...overrides,
  });
}

export type EncryptOverrides = Omit<Partial<EncryptParams>, 'source' | 'keyMiddleware'>;

/** Encrypt `plaintext` into a complete, in-memory TDF. */
export async function encryptToBuffer(
  client: Client.Client,
  plaintext: Uint8Array,
  overrides: EncryptOverrides = {}
): Promise<{ buffer: Uint8Array; manifest: Manifest }> {
  const encryptionInformation = new SplitKey(new AesGcmCipher(WebCryptoService));
  const key = await encryptionInformation.generateKey();
  const stream = await client.encrypt({
    metadata: Mocks.getMetadataObject(),
    offline: true,
    scope: { dissem: ['user@domain.com'], attributes: [] },
    windowSize: SEGMENT_SIZE,
    keyMiddleware: async () => ({ keyForEncryption: key, keyForManifest: key }),
    source: new ReadableStream({
      start(controller) {
        controller.enqueue(plaintext);
        controller.close();
      },
    }),
    ...overrides,
  });
  const buffer = await stream.toBuffer();
  return { buffer, manifest: stream.manifest };
}

/** Decrypt a (possibly tampered) TDF buffer to its plaintext bytes. */
export async function decryptBuffer(
  client: Client.Client,
  buffer: Uint8Array
): Promise<Uint8Array> {
  const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
  return new Uint8Array(await stream.toBuffer());
}

/** Split a TDF into the two pieces an attacker edits: payload bytes + manifest. */
export async function unpackTdf(
  buffer: Uint8Array
): Promise<{ payload: Uint8Array; manifest: Manifest }> {
  const { manifest, zipReader, centralDirectory } = await loadTDFStream(fromBuffer(buffer));
  const info = manifest.encryptionInformation.integrityInformation;
  const payloadSize = info.segments.reduce(
    (total, { encryptedSegmentSize }) =>
      total + (encryptedSegmentSize ?? info.encryptedSegmentSizeDefault ?? 0),
    0
  );
  const payload = await zipReader.getPayloadSegment(centralDirectory, '0.payload', 0, payloadSize);
  return { payload, manifest };
}

/**
 * Reassemble a TDF from payload bytes and a manifest, mirroring the layout
 * `writeStream` emits (stored entries with trailing data descriptors). This is
 * pure zip carpentry — no key material is involved, which is the point.
 */
export function packTdf(payload: Uint8Array, manifest: unknown): Uint8Array {
  const zipWriter = new ZipWriter();
  const entries = [
    { filename: '0.payload', content: payload },
    { filename: '0.manifest.json', content: new TextEncoder().encode(JSON.stringify(manifest)) },
  ];

  const parts: Uint8Array[] = [];
  let offset = 0;
  const push = (chunk: Uint8Array) => {
    parts.push(chunk);
    offset += chunk.length;
  };

  const written = entries.map(({ filename, content }) => {
    const localHeaderOffset = offset;
    push(zipWriter.getLocalFileHeader(filename, 0, 0, 0));
    push(content);
    const crc = unsigned(content, 0);
    push(zipWriter.writeDataDescriptor(crc, content.length));
    return { filename, size: content.length, localHeaderOffset, crc };
  });

  const centralDirectoryOffset = offset;
  for (const { filename, size, localHeaderOffset, crc } of written) {
    push(
      zipWriter.writeCentralDirectoryRecord(
        size,
        filename,
        localHeaderOffset,
        crc,
        EXTERNAL_FILE_ATTRIBUTES
      )
    );
  }
  push(
    zipWriter.writeEndOfCentralDirectoryRecord(
      written.length,
      offset - centralDirectoryOffset,
      centralDirectoryOffset
    )
  );
  return concatUint8(parts);
}

export type Tamper = (parts: { payload: Uint8Array; manifest: Manifest }) => {
  payload: Uint8Array;
  manifest: unknown;
} | void;

/** Encrypt, apply a keyless edit to the result, and hand it back to a reader. */
export async function tamperTdf(
  client: Client.Client,
  plaintext: Uint8Array,
  tamper: Tamper,
  overrides: EncryptOverrides = {}
): Promise<Uint8Array> {
  const { buffer } = await encryptToBuffer(client, plaintext, overrides);
  const parts = await unpackTdf(buffer);
  const tampered = tamper(parts) ?? parts;
  return decryptBuffer(client, packTdf(tampered.payload, tampered.manifest));
}

export function integrityInfo(manifest: Manifest) {
  return manifest.encryptionInformation.integrityInformation;
}

/**
 * The error `promise` rejected with, or a test failure if it resolved.
 *
 * The `assert.fail` deliberately sits *outside* the `catch`: inside, its own
 * `AssertionError` is caught by the adjacent handler and re-reported as
 * whatever type assertion runs next, which diagnoses a real regression as the
 * wrong problem.
 */
export async function rejectionOf(promise: Promise<unknown>, why: string): Promise<unknown> {
  let error: unknown;
  let resolved = false;
  try {
    await promise;
    resolved = true;
  } catch (e) {
    error = e;
  }
  if (resolved) {
    assert.fail(`expected a rejection: ${why}`);
  }
  return error;
}

export function describeError(e: unknown): string {
  return e instanceof Error ? `${e.name}: ${e.message}` : `${e}`;
}

/**
 * Flip a byte inside segment `index`'s authentication tag. Both segment
 * algorithms cover it: GMAC *is* the tag, HS256 hashes the ciphertext
 * containing it.
 */
export function corruptSegment(payload: Uint8Array, manifest: Manifest, index: number): Uint8Array {
  const flipped = payload.slice();
  const segmentSize = integrityInfo(manifest).encryptedSegmentSizeDefault as number;
  flipped[(index + 1) * segmentSize - 1] ^= 0xff;
  return flipped;
}
