/**
 * Plaintext byte-range decrypt (DSPX-5116): a range read returns exactly the
 * requested plaintext, fetches only the segments it needs, checks each of them,
 * never lets a manifest edit move an authentic segment to another offset, and
 * refuses an unsatisfiable range before the KAS rewrap.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { type DecryptParams } from '../../tdf3/src/client/builders.js';
import { type KeyInfo } from '../../tdf3/src/models/encryption-information.js';
import { type Manifest } from '../../tdf3/src/models/manifest.js';
import { loadTDFStream } from '../../tdf3/src/tdf.js';
import { type PlaintextRange } from '../../tdf3/src/utils/plaintext-range.js';
import { concatUint8 } from '../../tdf3/src/utils/index.js';
import { type Chunker, fromBuffer } from '../../src/seekable.js';
import { base64 } from '../../src/encodings/index.js';
import {
  ConfigurationError,
  IntegrityError,
  InvalidFileError,
  PlaintextRangeError,
} from '../../src/errors.js';
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

async function newKey(): Promise<KeyInfo> {
  return new SplitKey(new AesGcmCipher(WebCryptoService)).generateKey();
}

async function encryptToBuffer(
  client: Client.Client,
  plaintext: Uint8Array,
  { windowSize = SEGMENT_SIZE, key }: { windowSize?: number; key?: KeyInfo } = {}
) {
  const keyInfo = key ?? (await newKey());
  const stream = await client.encrypt({
    metadata: Mocks.getMetadataObject(),
    offline: true,
    scope: { dissem: ['user@domain.com'], attributes: [] },
    windowSize,
    keyMiddleware: () => Promise.resolve({ keyForEncryption: keyInfo, keyForManifest: keyInfo }),
    source: new ReadableStream({
      start(controller) {
        controller.enqueue(plaintext);
        controller.close();
      },
    }),
  });
  return { buffer: await stream.toBuffer(), key: keyInfo };
}

/** Re-sign the root over the manifest's (edited) segment hashes with the data key. */
async function resignRoot(manifest: Manifest, key: KeyInfo) {
  const info = manifest.encryptionInformation.integrityInformation;
  const aggregate = concatUint8(
    info.segments.map(({ hash }) => new Uint8Array(base64.decodeArrayBuffer(hash)))
  );
  const sig = await WebCryptoService.hmac(aggregate, key.unwrappedKey);
  info.rootSignature.sig = base64.encodeArrayBuffer(
    sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength)
  );
}

/** A chunker that records every read, as [start, end). */
function recordingChunker(buffer: Uint8Array) {
  const base = fromBuffer(buffer);
  const reads: Array<[number, number]> = [];
  const chunker: Chunker = (byteStart = 0, byteEnd = buffer.length) => {
    reads.push([byteStart < 0 ? buffer.length + byteStart : byteStart, byteEnd]);
    return base(byteStart, byteEnd);
  };
  return { chunker, reads };
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

  before(async function () {
    auth = countingAuthProvider();
    client = newClient(auth);
    ({ buffer } = await encryptToBuffer(client, plaintext));
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

  describe('Blob.slice end semantics', function () {
    /** Decrypt a range, counting reads inside the payload entry. */
    async function payloadReadsFor(range: PlaintextRange, tdf = buffer) {
      const { chunker, reads } = recordingChunker(tdf);
      const payload = await payloadBounds(fromBuffer(tdf));
      const out = await decryptRange(range, { source: { type: 'chunker', location: chunker } });
      const payloadReads = reads.filter(
        ([start, end]) => start < payload.end && end > payload.start
      );
      return { out, payloadReads };
    }

    for (const range of [
      { offset: 3000, length: 0 },
      { offset: PLAINTEXT_SIZE },
      { offset: PLAINTEXT_SIZE, length: 0 },
      { offset: PLAINTEXT_SIZE, length: 5 },
    ]) {
      it(`returns nothing for ${JSON.stringify(range)}, and reads no payload`, async function () {
        const { out, payloadReads } = await payloadReadsFor(range);
        assert.lengthOf(out, 0);
        assert.isEmpty(payloadReads);
      });
    }

    it('returns nothing from an empty plaintext at offset 0', async function () {
      const empty = (await encryptToBuffer(client, new Uint8Array(0))).buffer;
      for (const length of [undefined, 0, 10]) {
        const { out } = await payloadReadsFor({ offset: 0, length }, empty);
        assert.lengthOf(out, 0);
      }
      await expectRejection(
        decryptRange({ offset: 1 }, { source: { type: 'buffer', location: empty } }),
        PlaintextRangeError,
        /past the end of the plaintext \[0\]/
      );
    });
  });

  describe('reads only what it needs', function () {
    let payload: { start: number; end: number };
    let localHeaders: number[];
    let manifestStart: number;
    before(async function () {
      const base = fromBuffer(buffer);
      const { centralDirectory } = await loadTDFStream(base);
      payload = await payloadBounds(base);
      localHeaders = centralDirectory.map(
        ({ relativeOffsetOfLocalHeader }) => relativeOffsetOfLocalHeader
      );
      const manifestEntry = centralDirectory.find(({ fileName }) => fileName !== '0.payload')!;
      manifestStart = manifestEntry.relativeOffsetOfLocalHeader + manifestEntry.headerLength;
    });

    /** Decrypts the range and returns the payload reads, as segment indices. */
    async function payloadSegmentReads(range: { offset: number; length: number }) {
      const { chunker, reads } = recordingChunker(buffer);
      assert.deepEqual(
        await decryptRange(range, { source: { type: 'chunker', location: chunker } }),
        plaintext.slice(range.offset, range.offset + range.length)
      );
      // The manifest entry follows the payload, so bound both ends.
      const touchesPayload = ([start, end]: [number, number]) =>
        start < payload.end && end > payload.start;
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
      return reads
        .filter(touchesPayload)
        .map(([start, end]) => [
          (start - payload.start) / ENCRYPTED_SEGMENT_SIZE,
          Math.ceil((end - payload.start) / ENCRYPTED_SEGMENT_SIZE),
        ]);
    }

    it('the covering segments, in one ranged read', async function () {
      // Segments 2 to 4.
      const range = { offset: 2 * SEGMENT_SIZE + 100, length: 2 * SEGMENT_SIZE };
      assert.deepEqual(await payloadSegmentReads(range), [[2, 5]]);
    });

    it('the segment before the last, when only the last covers the range', async function () {
      // A non-last segment's authenticated length is what confirms the segment
      // size, and so the last segment's position.
      const range = { offset: 7 * SEGMENT_SIZE + 10, length: 20 };
      assert.deepEqual(await payloadSegmentReads(range), [[6, 8]]);
    });
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

  // A keyless attacker can rewrite the manifest's segment sizes and the payload
  // bytes, but not the root-signed segment hash list. Positions computed from
  // recorded sizes would let them move an authentic segment to another offset:
  // a range read must either fail or return the right bytes.
  describe('manifest edits cannot move a segment', function () {
    type Segment = Manifest['encryptionInformation']['integrityInformation']['segments'][number];

    async function expectCorrectOrRejected(tdf: Uint8Array, range: PlaintextRange) {
      let out: Uint8Array;
      try {
        out = await decryptRange(range, { source: { type: 'buffer', location: tdf } });
      } catch (e) {
        assert.instanceOf(e, InvalidFileError);
        return;
      }
      const end = range.length === undefined ? undefined : range.offset + range.length;
      assert.deepEqual(out, plaintext.slice(range.offset, end));
    }

    /** Rewrites the manifest's segment entries and, optionally, the payload. */
    async function edit(
      editSegments: (segments: Segment[]) => Segment[],
      editPayload: (payload: Uint8Array) => Uint8Array = (p) => p,
      editInfo: (info: Record<string, unknown>) => void = () => {}
    ) {
      const { payload, manifest } = await unpackTdf(buffer);
      const info = manifest.encryptionInformation.integrityInformation;
      info.segments = editSegments(info.segments);
      editInfo(info);
      return packTdf(editPayload(payload), manifest);
    }

    it('shrinking an earlier segment', async function () {
      // Summing recorded sizes would put segment 1 at offset 1000.
      const tdf = await edit(([first, ...rest]) => [{ ...first, segmentSize: 1000 }, ...rest]);
      for (const offset of [1000, 1024, 3000]) {
        await expectCorrectOrRejected(tdf, { offset, length: 10 });
      }
    });

    it('inflating an earlier segment and padding the payload to match', async function () {
      // Every later segment still sits at its recorded ciphertext offset and
      // passes its hash check, so offsets from ciphertext positions would be
      // off by 100.
      const pad = 100;
      const tdf = await edit(
        ([first, ...rest]) => [
          {
            ...first,
            segmentSize: SEGMENT_SIZE + pad,
            encryptedSegmentSize: ENCRYPTED_SEGMENT_SIZE + pad,
          },
          ...rest,
        ],
        (payload) =>
          concatUint8([
            payload.subarray(0, ENCRYPTED_SEGMENT_SIZE),
            new Uint8Array(pad),
            payload.subarray(ENCRYPTED_SEGMENT_SIZE),
          ])
      );
      for (const offset of [SEGMENT_SIZE + pad, 3000, 7 * SEGMENT_SIZE + pad]) {
        await expectCorrectOrRejected(tdf, { offset, length: 10 });
      }
    });

    it('relabelling the layout with a different uniform segment size', async function () {
      const tdf = await edit(
        (segments) => segments,
        undefined,
        (info) => {
          info.segmentSizeDefault = 1000;
          info.encryptedSegmentSizeDefault = 1000 + GCM_OVERHEAD;
        }
      );
      for (const offset of [1000, 3000, 7000]) {
        await expectCorrectOrRejected(tdf, { offset, length: 10 });
      }
    });
  });

  describe('a layout no SDK writer produces', function () {
    // Segments of 1024, 976, 512, 512 and 476: authentic (one key, re-signed
    // root) but not uniform, so positions come from decrypting from the start.
    const partA = patternedPlaintext().slice(0, 2000);
    const partB = patternedPlaintext()
      .slice(3000, 4500)
      .map((b) => b ^ 0x55);
    const spliced = concatUint8([partA, partB]);
    let tdf: Uint8Array;
    let payload: { start: number; end: number };

    before(async function () {
      const key = await newKey();
      const a = await unpackTdf((await encryptToBuffer(client, partA, { key })).buffer);
      const b = await unpackTdf(
        (await encryptToBuffer(client, partB, { key, windowSize: 512 })).buffer
      );
      const explicit = ({ integrityInformation: info }: Manifest['encryptionInformation']) =>
        info.segments.map((segment) => {
          const plain = segment.segmentSize ?? info.segmentSizeDefault!;
          return {
            ...segment,
            segmentSize: plain,
            encryptedSegmentSize: segment.encryptedSegmentSize ?? plain + GCM_OVERHEAD,
          };
        });
      const segments = [
        ...explicit(a.manifest.encryptionInformation),
        ...explicit(b.manifest.encryptionInformation),
      ];
      assert.deepEqual(
        segments.map(({ segmentSize }) => segmentSize),
        [1024, 976, 512, 512, 476]
      );
      const manifest = a.manifest;
      manifest.encryptionInformation.integrityInformation.segments = segments;
      await resignRoot(manifest, key);
      tdf = packTdf(concatUint8([a.payload, b.payload]), manifest);
      payload = await payloadBounds(fromBuffer(tdf));
    });

    it('decrypts from the first segment and stops after the range', async function () {
      const { chunker, reads } = recordingChunker(tdf);
      // Segments 2 and 3 cover [2500, 2800).
      const range = { offset: 2500, length: 300 };
      const out = await decryptRange(range, {
        source: { type: 'chunker', location: chunker },
        segmentBatchSize: 1,
        maxConcurrentSegmentBatches: 1,
        noVerifyAssertions: true,
      });
      assert.deepEqual(out, spliced.slice(2500, 2800));
      const payloadReads = reads
        .filter(([start, end]) => start < payload.end && end > payload.start)
        .map(([start]) => start - payload.start);
      const offsets = [0, 1052, 2056, 2596];
      assert.deepEqual(payloadReads, offsets, 'segments 0 to 3, but not 4');
    });

    it('matches a full decrypt', async function () {
      const stream = await client.decrypt({
        source: { type: 'buffer', location: tdf },
        noVerifyAssertions: true,
      });
      assert.deepEqual(new Uint8Array(await stream.toBuffer()), spliced);
      const ranges: Array<[number, number | undefined]> = [
        [0, 10],
        [1020, 10],
        [1999, 2],
        [3000, 500],
        [3400, undefined],
      ];
      for (const [offset, length] of ranges) {
        const end = length === undefined ? undefined : offset + length;
        assert.deepEqual(
          await decryptRange(
            { offset, length },
            { source: { type: 'buffer', location: tdf }, noVerifyAssertions: true }
          ),
          spliced.slice(offset, end),
          `offset ${offset}, length ${length}`
        );
      }
    });
  });

  describe('rejects before the KAS rewrap', function () {
    const cases: Array<[string, PlaintextRange, RegExp]> = [
      ['an offset past the end', { offset: PLAINTEXT_SIZE + 1 }, /past the end/],
      ['an offset past the end, length 0', { offset: PLAINTEXT_SIZE + 1, length: 0 }, /past/],
      ['a negative offset', { offset: -1 }, /offset must be/],
      ['a fractional offset', { offset: 1.5 }, /offset must be/],
      ['an unsafe offset', { offset: 2 ** 53 }, /offset must be/],
      ['a NaN offset', { offset: NaN }, /offset must be/],
      ['a negative length', { offset: 0, length: -1 }, /length must be/],
      ['an infinite length', { offset: 0, length: Infinity }, /length must be/],
    ];
    for (const [name, range, pattern] of cases) {
      it(name, async function () {
        await expectRejection(decryptRange(range), PlaintextRangeError, pattern);
        assert.equal(auth.calls, 0, 'a bad range must not cost a KAS call');
      });
    }

    it('with an error that is still a ConfigurationError', async function () {
      await expectRejection(decryptRange({ offset: -1 }), ConfigurationError);
    });

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
        InvalidFileError,
        /cannot map a plaintext range/
      );
      assert.equal(auth.calls, 0);
    });
  });

  it('handles offsets above 2^32 (sparse archive)', async function () {
    this.timeout(30_000);
    // Encrypt with 1 MiB segments, then prefix them with enough 1 MiB segments
    // to push them past 4 GiB. The prefix exists only as manifest entries and a
    // hole in the archive: a read that touches it fails. Re-signing the root
    // with the data key keeps the extended segment list valid.
    const MIB = 1024 * 1024;
    const real = new Uint8Array(2 * MIB + 1000);
    for (let i = 0; i < real.length; i++) {
      real[i] = (i * 13 + (i >> 20)) % 251;
    }
    const encrypted = await encryptToBuffer(client, real, { windowSize: MIB });
    const prefixCount = 4097;
    const prefixPlainSize = prefixCount * MIB;
    const prefixEncryptedSize = prefixCount * (MIB + GCM_OVERHEAD);
    assert.isAbove(prefixPlainSize, 2 ** 32);

    const { payload, manifest } = await unpackTdf(encrypted.buffer);
    const info = manifest.encryptionInformation.integrityInformation;
    assert.lengthOf(info.segments, 3);
    const prefix = Array.from({ length: prefixCount }, (_, i) => {
      const hash = new Uint8Array(16);
      new DataView(hash.buffer).setUint32(0, i + 1);
      return { hash: base64.encodeArrayBuffer(hash.buffer) };
    });
    info.segments = [...prefix, ...info.segments];
    await resignRoot(manifest, encrypted.key);

    const sparse = sparseTdf([prefixEncryptedSize, payload], manifest);
    assert.isAbove(sparse.size, 2 ** 32);
    const source = { type: 'chunker', location: sparse.chunker } as const;
    const total = prefixPlainSize + real.length;

    for (const range of [
      { offset: prefixPlainSize, length: 10 },
      { offset: prefixPlainSize + MIB - 5, length: 10 },
      // Inside the last segment: also reads the one before, which is real.
      { offset: prefixPlainSize + 2 * MIB + 10 },
      { offset: total },
    ]) {
      const out = await decryptRange(range, { source, noVerifyAssertions: true });
      const start = range.offset - prefixPlainSize;
      const end = range.length === undefined ? undefined : start + range.length;
      assert.deepEqual(out, real.slice(start, end), JSON.stringify(range));
    }
    assert.isTrue(
      sparse.reads.some(([start]) => start > 2 ** 32),
      'payload reads are addressed above 4 GiB'
    );

    await expectRejection(
      decryptRange({ offset: total + 1 }, { source }),
      PlaintextRangeError,
      new RegExp(`past the end of the plaintext \\[${total}\\]`)
    );
  });
});
