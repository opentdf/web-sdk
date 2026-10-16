/**
 * Plaintext byte-range decrypt (DSPX-5116): a range read returns exactly the
 * requested plaintext, fetches only the segments that cover it, still checks
 * each of them, and refuses an unsatisfiable range before the KAS rewrap.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { type DecryptParams } from '../../tdf3/src/client/builders.js';
import { type KeyInfo } from '../../tdf3/src/models/encryption-information.js';
import { loadTDFStream } from '../../tdf3/src/tdf.js';
import { type PlaintextRange } from '../../tdf3/src/utils/plaintext-range.js';
import { concatUint8 } from '../../tdf3/src/utils/index.js';
import { type Chunker, fromBuffer } from '../../src/seekable.js';
import { base64 } from '../../src/encodings/index.js';
import { ConfigurationError, IntegrityError, InvalidFileError } from '../../src/errors.js';
import { packTdf, sparseTdf, unpackTdf } from './helpers/tdf-archive.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000';

const SEGMENT_SIZE = 1024;
/** Seven full segments and a short last one. */
const PLAINTEXT_SIZE = 7 * SEGMENT_SIZE + 500;
const SEGMENT_COUNT = 8;
const GCM_OVERHEAD = 12 + 16;
const ENCRYPTED_SEGMENT_SIZE = SEGMENT_SIZE + GCM_OVERHEAD;

/** Counts KAS rewrap requests, which all go through auth. */
function countingAuthProvider(): AuthProvider & { calls: number } {
  const provider = {
    calls: 0,
    updateClientPublicKey: async () => {},
    withCreds: (httpReq: HttpRequest) => {
      if (/rewrap/i.test(httpReq.url)) {
        provider.calls += 1;
      }
      return Promise.resolve(httpReq);
    },
  };
  return provider;
}

function newClient(authProvider: AuthProvider): Client.Client {
  return new Client.Client({
    kasEndpoint: kasUrl,
    platformUrl: kasUrl,
    dpopKeys: Mocks.entityKeyPair(),
    clientId: 'id',
    authProvider,
  });
}

/** No two nearby bytes alike, so an off-by-one anywhere shows in the output. */
function patternedPlaintext(): Uint8Array {
  const out = new Uint8Array(PLAINTEXT_SIZE);
  for (let i = 0; i < out.length; i++) {
    out[i] = (i * 7 + (i >> 10)) % 251;
  }
  return out;
}

async function encryptToBuffer(client: Client.Client, plaintext: Uint8Array) {
  const encryptionInformation = new SplitKey(new AesGcmCipher(WebCryptoService));
  const key = await encryptionInformation.generateKey();
  const stream = await client.encrypt({
    metadata: Mocks.getMetadataObject(),
    offline: true,
    scope: { dissem: ['user@domain.com'], attributes: [] },
    windowSize: SEGMENT_SIZE,
    keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
    source: new ReadableStream({
      start(controller) {
        controller.enqueue(plaintext);
        controller.close();
      },
    }),
  });
  return { buffer: await stream.toBuffer(), key };
}

/** Where the payload's bytes sit in the archive. */
async function payloadBounds(chunker: Chunker) {
  const { centralDirectory } = await loadTDFStream(chunker);
  const entry = centralDirectory.find(({ fileName }) => fileName === '0.payload')!;
  const start = entry.relativeOffsetOfLocalHeader + entry.headerLength;
  return { start, end: start + entry.compressedSize };
}

async function expectRejection(
  promise: Promise<unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  type: new (...args: any[]) => Error,
  pattern?: RegExp
) {
  try {
    await promise;
  } catch (e) {
    assert.instanceOf(e, type);
    if (pattern) {
      assert.match(e.message, pattern);
    }
    return;
  }
  assert.fail(`expected a ${type.name}`);
}

describe('decrypt plaintext range', function () {
  const plaintext = patternedPlaintext();
  let auth: ReturnType<typeof countingAuthProvider>;
  let client: Client.Client;
  let buffer: Uint8Array;
  let key: KeyInfo;

  before(async function () {
    auth = countingAuthProvider();
    client = newClient(auth);
    ({ buffer, key } = await encryptToBuffer(client, plaintext));
    const { manifest } = await loadTDFStream(fromBuffer(buffer));
    assert.lengthOf(manifest.encryptionInformation.integrityInformation.segments, SEGMENT_COUNT);
  });

  beforeEach(function () {
    auth.calls = 0;
  });

  async function decryptRange(
    range: PlaintextRange,
    { source = { type: 'buffer', location: buffer }, ...rest }: Partial<DecryptParams> = {}
  ) {
    const stream = await client.decrypt({ source, range, ...rest });
    return new Uint8Array(await stream.toBuffer());
  }

  describe('returns exactly the requested bytes', function () {
    const cases: Array<[string, PlaintextRange]> = [
      ['offset 0', { offset: 0, length: 10 }],
      ['offset 0 to the end', { offset: 0 }],
      ['inside one segment', { offset: SEGMENT_SIZE + 6, length: 100 }],
      ['a whole segment', { offset: 2 * SEGMENT_SIZE, length: SEGMENT_SIZE }],
      ['across a segment boundary', { offset: SEGMENT_SIZE - 24, length: 48 }],
      ['across several segments', { offset: 1500, length: 4000 }],
      ['into the last, short segment', { offset: 7 * SEGMENT_SIZE - 5, length: 10 }],
      ['within the last, short segment', { offset: 7 * SEGMENT_SIZE + 10, length: 400 }],
      ['the last byte', { offset: PLAINTEXT_SIZE - 1, length: 1 }],
      ['to the end, without a length', { offset: 5000 }],
      ['to the end, with a length past it', { offset: 7000, length: 10_000 }],
    ];
    for (const [name, range] of cases) {
      it(name, async function () {
        const end = range.length === undefined ? undefined : range.offset + range.length;
        assert.deepEqual(await decryptRange(range), plaintext.slice(range.offset, end));
      });
    }

    it('in batches that do not start at the first segment', async function () {
      // Batches of two over segments 1..6: every batch after the first starts
      // mid-file, which needs offsets relative to the batch.
      const range = { offset: SEGMENT_SIZE + 1, length: 5 * SEGMENT_SIZE };
      assert.deepEqual(
        await decryptRange(range, { segmentBatchSize: 2, maxConcurrentSegmentBatches: 2 }),
        plaintext.slice(range.offset, range.offset + range.length)
      );
    });

    it('matching the same slice of a full decrypt', async function () {
      // Each decrypt is a rewrap; browsers take a while over this many.
      this.timeout(30_000);
      const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
      const full = new Uint8Array(await stream.toBuffer());
      assert.deepEqual(full, plaintext);
      for (const offset of [0, 1023, 1024, 1025, 3333, 7167, PLAINTEXT_SIZE - 2]) {
        for (const length of [1, 1024, 3000]) {
          assert.deepEqual(
            await decryptRange({ offset, length }),
            full.slice(offset, offset + length),
            `offset ${offset}, length ${length}`
          );
        }
      }
    });
  });

  it('returns nothing for length 0, and reads no payload', async function () {
    const base = fromBuffer(buffer);
    const { start, end } = await payloadBounds(base);
    let payloadReads = 0;
    const chunker: Chunker = (byteStart, byteEnd) => {
      if (byteStart !== undefined && byteStart >= start && byteStart < end) {
        payloadReads += 1;
      }
      return base(byteStart, byteEnd);
    };
    const out = await decryptRange(
      { offset: 3000, length: 0 },
      { source: { type: 'chunker', location: chunker } }
    );
    assert.lengthOf(out, 0);
    assert.equal(payloadReads, 0);
  });

  it('reads only the tail, central directory, headers, manifest and covering segments', async function () {
    const base = fromBuffer(buffer);
    const { centralDirectory } = await loadTDFStream(base);
    const payload = await payloadBounds(base);
    const localHeaders = centralDirectory.map(
      ({ relativeOffsetOfLocalHeader }) => relativeOffsetOfLocalHeader
    );
    const manifestEntry = centralDirectory.find(({ fileName }) => fileName !== '0.payload')!;
    const manifestStart = manifestEntry.relativeOffsetOfLocalHeader + manifestEntry.headerLength;

    const reads: Array<[number, number]> = [];
    const chunker: Chunker = (byteStart = 0, byteEnd = buffer.length) => {
      reads.push([byteStart < 0 ? buffer.length + byteStart : byteStart, byteEnd]);
      return base(byteStart, byteEnd);
    };
    // Segments 2 to 4.
    const range = { offset: 2 * SEGMENT_SIZE + 100, length: 2 * SEGMENT_SIZE };
    assert.deepEqual(
      await decryptRange(range, { source: { type: 'chunker', location: chunker } }),
      plaintext.slice(range.offset, range.offset + range.length)
    );

    // The manifest entry follows the payload, so bound both ends.
    const touchesPayload = ([start, end]: [number, number]) =>
      start < payload.end && end > payload.start;
    const payloadReads = reads.filter(touchesPayload);
    assert.deepEqual(payloadReads, [
      [payload.start + 2 * ENCRYPTED_SEGMENT_SIZE, payload.start + 5 * ENCRYPTED_SEGMENT_SIZE],
    ]);
    // Everything else is format sniffing, the zip structures, or the manifest.
    for (const [start, end] of reads.filter((read) => !touchesPayload(read))) {
      const isFormatSniff = start === 0 && end <= payload.start;
      const isLocalHeader = localHeaders.includes(start);
      const isManifest = start === manifestStart;
      // Tail, central directory and zip64 records all follow the manifest.
      const isZipTrailer = start > manifestStart;
      assert.isTrue(
        isFormatSniff || isLocalHeader || isManifest || isZipTrailer,
        `unexpected read [${start}, ${end})`
      );
    }
  });

  describe('integrity', function () {
    /** Flip a byte in the given segment's ciphertext. */
    async function tamperSegment(index: number) {
      const { payload, manifest } = await unpackTdf(buffer);
      const tampered = payload.slice();
      tampered[index * ENCRYPTED_SEGMENT_SIZE + 40] ^= 0xff;
      return packTdf(tampered, manifest);
    }

    it('fails when a segment in the range is tampered with', async function () {
      const tampered = await tamperSegment(3);
      await expectRejection(
        decryptRange(
          { offset: 3 * SEGMENT_SIZE + 10, length: 10 },
          { source: { type: 'buffer', location: tampered } }
        ),
        // A flipped ciphertext byte fails the AEAD (a DecryptError, whose
        // message depends on the platform); a flipped tag fails the hash check.
        InvalidFileError
      );
    });

    it('does not read, so does not notice, a tampered segment outside the range', async function () {
      const tampered = await tamperSegment(0);
      const range = { offset: 5 * SEGMENT_SIZE, length: 10 };
      assert.deepEqual(
        await decryptRange(range, { source: { type: 'buffer', location: tampered } }),
        plaintext.slice(range.offset, range.offset + range.length)
      );
    });

    it('still verifies the root signature', async function () {
      const { payload, manifest } = await unpackTdf(buffer);
      const info = manifest.encryptionInformation.integrityInformation;
      // Swapping two segments outside the range breaks only the root signature.
      [info.segments[0], info.segments[1]] = [info.segments[1], info.segments[0]];
      await expectRejection(
        decryptRange(
          { offset: 5 * SEGMENT_SIZE, length: 10 },
          { source: { type: 'buffer', location: packTdf(payload, manifest) } }
        ),
        IntegrityError,
        /root signature/
      );
    });
  });

  describe('rejects before the KAS rewrap', function () {
    const cases: Array<[string, PlaintextRange, RegExp]> = [
      ['an offset at the end', { offset: PLAINTEXT_SIZE }, /at or past the end/],
      ['an offset past the end', { offset: PLAINTEXT_SIZE + 1, length: 0 }, /at or past the end/],
      ['a negative offset', { offset: -1 }, /offset must be/],
      ['a fractional offset', { offset: 1.5 }, /offset must be/],
      ['an unsafe offset', { offset: 2 ** 53 }, /offset must be/],
      ['a NaN offset', { offset: NaN }, /offset must be/],
      ['a negative length', { offset: 0, length: -1 }, /length must be/],
      ['an infinite length', { offset: 0, length: Infinity }, /length must be/],
    ];
    for (const [name, range, pattern] of cases) {
      it(name, async function () {
        await expectRejection(decryptRange(range), ConfigurationError, pattern);
        assert.equal(auth.calls, 0, 'a bad range must not cost a KAS call');
      });
    }

    it('a file whose segments do not record plaintext sizes', async function () {
      const { payload, manifest } = await unpackTdf(buffer);
      const info = manifest.encryptionInformation.integrityInformation as {
        segmentSizeDefault?: number;
      };
      delete info.segmentSizeDefault;
      await expectRejection(
        decryptRange(
          { offset: 0, length: 1 },
          { source: { type: 'buffer', location: packTdf(payload, manifest) } }
        ),
        Error,
        /cannot map a plaintext range/
      );
      assert.equal(auth.calls, 0);
    });
  });

  it('handles offsets above 2^32 (sparse archive)', async function () {
    // Prefix the real segments with enough 1 MiB segments to push them past
    // 4 GiB. The prefix exists only as manifest entries and a hole in the
    // archive: a read that touches it fails. Re-signing the root with the
    // data key keeps the forged segment list valid.
    const MIB = 1024 * 1024;
    const prefixCount = 4097;
    const prefixPlainSize = prefixCount * MIB;
    const prefixEncryptedSize = prefixCount * (MIB + GCM_OVERHEAD);
    assert.isAbove(prefixPlainSize, 2 ** 32);

    const { payload, manifest } = await unpackTdf(buffer);
    const info = manifest.encryptionInformation.integrityInformation;
    const prefix = Array.from({ length: prefixCount }, (_, i) => {
      const hash = new Uint8Array(16);
      new DataView(hash.buffer).setUint32(0, i + 1);
      return {
        hash: base64.encodeArrayBuffer(hash.buffer),
        segmentSize: MIB,
        encryptedSegmentSize: MIB + GCM_OVERHEAD,
      };
    });
    info.segments = [...prefix, ...info.segments];
    const aggregate = concatUint8(
      info.segments.map(({ hash }) => new Uint8Array(base64.decodeArrayBuffer(hash)))
    );
    const sig = await WebCryptoService.hmac(aggregate, key.unwrappedKey);
    info.rootSignature.sig = base64.encodeArrayBuffer(
      sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength)
    );

    const sparse = sparseTdf([prefixEncryptedSize, payload], manifest);
    assert.isAbove(sparse.size, 2 ** 32);
    const source = { type: 'chunker', location: sparse.chunker } as const;

    for (const range of [
      { offset: prefixPlainSize, length: 10 },
      { offset: prefixPlainSize + 1500, length: 3000 },
      { offset: prefixPlainSize + 7000 },
    ]) {
      const out = await decryptRange(range, { source, noVerifyAssertions: true });
      const start = range.offset - prefixPlainSize;
      const end = range.length === undefined ? undefined : start + range.length;
      assert.deepEqual(out, plaintext.slice(start, end), JSON.stringify(range));
    }
    const lastRead = sparse.reads[sparse.reads.length - 1];
    assert.isAbove(lastRead[0], 2 ** 32, 'payload reads are addressed above 4 GiB');

    await expectRejection(
      decryptRange({ offset: prefixPlainSize + PLAINTEXT_SIZE }, { source }),
      ConfigurationError,
      new RegExp(`past the end of the plaintext \\[${prefixPlainSize + PLAINTEXT_SIZE}\\]`)
    );
  });
});
