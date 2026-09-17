/**
 * The root signature is the only thing in a base TDF that authenticates
 * the *manifest's* description of the payload: the ordered list of segment
 * hashes. Per-segment AES-GCM tags authenticate each segment's bytes in
 * isolation, but nothing in a segment binds it to its index or to the total
 * segment count, so a manifest that lies about the segment list is only caught
 * by the root signature.
 *
 * The old `getSignature` GMAC branch ignored the key entirely — it returned the
 * trailing 16 bytes of its input. Over a segment's ciphertext that is the
 * segment's GCM tag, a genuine authenticator. Over the aggregate hash it is
 * just a copy of the last segment hash, which is attacker-supplied manifest
 * data. And `rootSignature.alg` is read from the manifest, so any reader that
 * honours it can be downgraded onto that branch without the payload key.
 *
 * These tests pin that boundary. The controls establish that tampering is
 * normally caught (without them the exploit cases prove nothing); the exploit
 * cases establish that a keyless attacker can no longer push a forged segment
 * list past the reader.
 *
 * Ported from platform/sdk/tdf_root_signature_test.go.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { type EncryptParams } from '../../tdf3/src/client/builders.js';
import { type Manifest } from '../../tdf3/src/models/manifest.js';
import { loadTDFStream } from '../../tdf3/src/tdf.js';
import { concatUint8, ZipWriter } from '../../tdf3/src/utils/index.js';
import { unsigned } from '../../tdf3/src/utils/buffer-crc32.js';
import { fromBuffer } from '../../src/seekable.js';
import { base64 } from '../../src/encodings/index.js';
import { IntegrityError } from '../../src/errors.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000';

const authProvider: AuthProvider = {
  updateClientPublicKey: async () => {},
  withCreds: async (httpReq: HttpRequest) => httpReq,
};

/** Small enough to keep these tests quick, large enough to be a real segment. */
const SEGMENT_SIZE = 1024;
const SEGMENT_COUNT = 4;
const GMAC_TAG_LENGTH = 16;
const EXTERNAL_FILE_ATTRIBUTES = 2175008768;

/**
 * A payload of `count` distinguishable segments, so a reordered or truncated
 * decryption is visible in the output rather than only in an error.
 */
function segmentedPlaintext(count = SEGMENT_COUNT): Uint8Array {
  const out = new Uint8Array(count * SEGMENT_SIZE);
  for (let i = 0; i < count; i++) {
    out.fill('A'.charCodeAt(0) + i, i * SEGMENT_SIZE, (i + 1) * SEGMENT_SIZE);
  }
  return out;
}

function newClient(): Client.Client {
  return new Client.Client({
    kasEndpoint: kasUrl,
    platformUrl: kasUrl,
    dpopKeys: Mocks.entityKeyPair(),
    clientId: 'id',
    authProvider,
  });
}

type EncryptOverrides = Omit<Partial<EncryptParams>, 'source' | 'keyMiddleware'>;

/** Encrypt `plaintext` into a complete, in-memory TDF. */
async function encryptToBuffer(
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
async function decryptBuffer(client: Client.Client, buffer: Uint8Array): Promise<Uint8Array> {
  const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
  return new Uint8Array(await stream.toBuffer());
}

/** Split a TDF into the two pieces an attacker edits: payload bytes + manifest. */
async function unpackTdf(buffer: Uint8Array): Promise<{ payload: Uint8Array; manifest: Manifest }> {
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
function packTdf(payload: Uint8Array, manifest: Manifest): Uint8Array {
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

type Tamper = (parts: { payload: Uint8Array; manifest: Manifest }) => {
  payload: Uint8Array;
  manifest: Manifest;
} | void;

/** Encrypt, apply a keyless edit to the result, and hand it back to a reader. */
async function tamperTdf(
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

function integrityInfo(manifest: Manifest) {
  return manifest.encryptionInformation.integrityInformation;
}

/**
 * Rewrite the root signature the way an attacker with no key can: declare GMAC,
 * then emit the trailing 16 bytes of the aggregate hash. Every input is
 * manifest data the attacker already controls.
 */
function forgeGmacRootSignature(manifest: Manifest, alg = 'GMAC') {
  const info = integrityInfo(manifest);
  const aggregate = concatUint8(
    info.segments.map(({ hash }) => new Uint8Array(base64.decodeArrayBuffer(hash)))
  );
  info.rootSignature.alg = alg;
  info.rootSignature.sig = base64.encodeArrayBuffer(aggregate.slice(-GMAC_TAG_LENGTH));
}

/**
 * Truncate the manifest's segment list. The payload keeps every segment's
 * ciphertext; the reader walks the manifest, so the trailing bytes are simply
 * never read.
 */
function keepSegments(manifest: Manifest, n: number) {
  const info = integrityInfo(manifest);
  info.segments = info.segments.slice(0, n);
}

/**
 * Reverse the segment order. The ciphertext has to move too, since the reader
 * walks the payload sequentially — but that is still a keyless edit, and every
 * segment keeps its own valid GCM tag. Nothing in AES-GCM binds a segment to
 * its index, so per-segment authentication cannot notice the permutation.
 */
function reverseSegments(payload: Uint8Array, manifest: Manifest): Uint8Array {
  const info = integrityInfo(manifest);
  const encryptedSegmentSize = info.encryptedSegmentSizeDefault as number;
  info.segments = [...info.segments].reverse();
  const blocks: Uint8Array[] = [];
  for (let end = payload.length; end > 0; end -= encryptedSegmentSize) {
    blocks.push(payload.slice(end - encryptedSegmentSize, end));
  }
  return concatUint8(blocks);
}

async function expectIntegrityError(promise: Promise<unknown>, why: string) {
  try {
    await promise;
    assert.fail(`expected an IntegrityError: ${why}`);
  } catch (e) {
    assert.instanceOf(e, IntegrityError, why);
  }
}

describe('root signature integrity (DSPX-4703)', function () {
  const plaintext = segmentedPlaintext();
  let client: Client.Client;

  beforeEach(function () {
    client = newClient();
  });

  describe('controls', function () {
    // Without these, the exploit cases below prove nothing: they establish
    // that the checks are otherwise effective, and that neither the downgrade
    // nor the forged signature alone is sufficient.

    it('positive: an untouched (repacked) file round-trips', async function () {
      const got = await tamperTdf(client, plaintext, () => {});
      assert.deepEqual(got, plaintext);
    });

    it('positive: the fixture really is multi-segment', async function () {
      const { manifest } = await encryptToBuffer(client, plaintext);
      assert.lengthOf(integrityInfo(manifest).segments, SEGMENT_COUNT);
    });

    it('negative: truncation under HS256 is caught', async function () {
      await expectIntegrityError(
        tamperTdf(client, plaintext, ({ manifest }) => {
          keepSegments(manifest, 2);
        }),
        'HS256 root must catch a shortened segment list'
      );
    });

    it('negative: a segment hash edit under HS256 is caught', async function () {
      await expectIntegrityError(
        tamperTdf(client, plaintext, ({ manifest }) => {
          const info = integrityInfo(manifest);
          const decoded = new Uint8Array(base64.decodeArrayBuffer(info.segments[0].hash));
          decoded[0] ^= 0xff;
          info.segments = [
            { ...info.segments[0], hash: base64.encodeArrayBuffer(decoded) },
            ...info.segments.slice(1),
          ];
        }),
        'HS256 root must catch an edited segment hash'
      );
    });

    it('negative: reordering under HS256 is caught', async function () {
      await expectIntegrityError(
        tamperTdf(client, plaintext, (parts) => ({
          manifest: parts.manifest,
          payload: reverseSegments(parts.payload, parts.manifest),
        })),
        'HS256 root must catch a permuted segment list'
      );
    });

    it('negative: a GMAC downgrade without fixing the sig is caught', async function () {
      // Isolates the downgrade itself from the forged signature: flipping
      // `alg` alone must not validate.
      await expectIntegrityError(
        tamperTdf(client, plaintext, ({ manifest }) => {
          integrityInfo(manifest).rootSignature.alg = 'GMAC';
        }),
        'a bare downgrade must not validate'
      );
    });
  });

  describe('exploit: GMAC root downgrade', function () {
    it('rejects a GMAC root even with nothing else changed', async function () {
      await expectIntegrityError(
        tamperTdf(client, plaintext, ({ manifest }) => {
          forgeGmacRootSignature(manifest);
        }),
        'a GMAC root is never acceptable'
      );
    });

    it('rejects a GMAC downgrade + forged sig + truncated segments', async function () {
      await expectIntegrityError(
        tamperTdf(client, plaintext, ({ manifest }) => {
          keepSegments(manifest, 2);
          forgeGmacRootSignature(manifest);
        }),
        'keyless truncation must not pass the integrity checks'
      );
    });

    it('rejects a GMAC downgrade + forged sig + reordered segments', async function () {
      await expectIntegrityError(
        tamperTdf(client, plaintext, (parts) => {
          const payload = reverseSegments(parts.payload, parts.manifest);
          forgeGmacRootSignature(parts.manifest);
          return { payload, manifest: parts.manifest };
        }),
        'keyless reordering must not pass the integrity checks'
      );
    });

    for (const alg of ['GMAC', 'gmac', 'GMac', 'gMAC']) {
      it(`rejects a forged GMAC root spelled "${alg}"`, async function () {
        // The JS reader used to compare exactly (`!== 'GMAC'`), so lowercase
        // spellings took a different path than in the Go and Java SDKs.
        await expectIntegrityError(
          tamperTdf(client, plaintext, ({ manifest }) => {
            keepSegments(manifest, 2);
            forgeGmacRootSignature(manifest, alg);
          }),
          `"${alg}" must be rejected like "GMAC"`
        );
      });
    }

    it('rejects an unknown root algorithm rather than defaulting to HS256', async function () {
      await expectIntegrityError(
        tamperTdf(client, plaintext, ({ manifest }) => {
          integrityInfo(manifest).rootSignature.alg = 'HS512';
        }),
        'unknown root algorithms must fail closed'
      );
    });
  });

  describe('segment integrity is unaffected', function () {
    for (const segmentIntegrityAlgorithm of ['GMAC', 'HS256'] as const) {
      const hashLength = segmentIntegrityAlgorithm === 'GMAC' ? 16 : 32;

      it(`round-trips with ${segmentIntegrityAlgorithm} segments`, async function () {
        const { buffer, manifest } = await encryptToBuffer(client, plaintext, {
          segmentIntegrityAlgorithm,
        });
        const info = integrityInfo(manifest);
        assert.equal(info.segmentHashAlg, segmentIntegrityAlgorithm);
        assert.equal(info.rootSignature.alg, 'HS256', 'the root stays HS256');
        for (const { hash } of info.segments) {
          assert.lengthOf(new Uint8Array(base64.decodeArrayBuffer(hash)), hashLength);
        }
        assert.deepEqual(await decryptBuffer(client, buffer), plaintext);
      });

      it(`detects payload tampering with ${segmentIntegrityAlgorithm} segments`, async function () {
        await expectIntegrityError(
          tamperTdf(
            client,
            plaintext,
            ({ payload, manifest }) => {
              // Flip a byte in the first segment's authentication tag, which
              // both algorithms cover: GMAC *is* the tag, HS256 hashes it.
              const flipped = payload.slice();
              const segmentSize = integrityInfo(manifest).encryptedSegmentSizeDefault as number;
              flipped[segmentSize - 1] ^= 0xff;
              return { payload: flipped, manifest };
            },
            { segmentIntegrityAlgorithm }
          ),
          'a flipped ciphertext byte must be caught'
        );
      });
    }

    it('still reads a manifest that spells segmentHashAlg in lowercase', async function () {
      const got = await tamperTdf(client, plaintext, ({ manifest }) => {
        integrityInfo(manifest).segmentHashAlg = 'gmac';
      });
      assert.deepEqual(got, plaintext);
    });

    it('rejects an unknown segment hash algorithm', async function () {
      try {
        await tamperTdf(client, plaintext, ({ manifest }) => {
          integrityInfo(manifest).segmentHashAlg = 'CRC32';
        });
        assert.fail('expected an error for an unknown segment hash alg');
      } catch (e) {
        assert.instanceOf(e, Error);
        assert.match((e as Error).message, /Unsupported segment hash alg/);
      }
    });
  });

  describe('legacy 4.2.2 files', function () {
    const legacy: EncryptOverrides = { tdfSpecVersion: '4.2.2' };

    it('positive: hex-then-base64 HS256 root still validates', async function () {
      const { buffer, manifest } = await encryptToBuffer(client, plaintext, legacy);
      assert.equal(integrityInfo(manifest).rootSignature.alg, 'HS256');
      assert.deepEqual(await decryptBuffer(client, buffer), plaintext);
    });

    it('negative: truncation is caught', async function () {
      await expectIntegrityError(
        tamperTdf(
          client,
          plaintext,
          ({ manifest }) => {
            keepSegments(manifest, 2);
          },
          legacy
        ),
        'a 4.2.2 HS256 root must catch truncation'
      );
    });

    it('rejects a GMAC root downgrade', async function () {
      await expectIntegrityError(
        tamperTdf(
          client,
          plaintext,
          ({ manifest }) => {
            keepSegments(manifest, 2);
            forgeGmacRootSignature(manifest);
          },
          legacy
        ),
        'a 4.2.2 file must not accept a GMAC root either'
      );
    });
  });
});
