/**
 * Reading TDF archives whose entries are DEFLATE-compressed (ZIP compression
 * method 8).
 *
 * This SDK only ever writes STORED entries, and must keep doing so. Other
 * ZTDF/TDF writers may compress the manifest, the payload, or both, so the
 * reader inflates method 8 entries and still rejects every other method.
 *
 * The end-to-end fixtures are archives this SDK wrote, rebuilt with their
 * entries deflated by the platform `CompressionStream`, then decrypted. They
 * are written in a classic zip dialect (sizes in the local header, no data
 * descriptors) unlike this SDK's own, and in zip64 form as well.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { InvalidFileError, NetworkError } from '../../src/errors.js';
import { type Chunker, fromBuffer } from '../../src/seekable.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { unsigned } from '../../tdf3/src/utils/buffer-crc32.js';
import { concatUint8 } from '../../tdf3/src/utils/index.js';
import { type CentralDirectory, ZipReader } from '../../tdf3/src/utils/zip-reader.js';
import { ZipWriter } from '../../tdf3/src/utils/zip-writer.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000';

const STORED = 0;
const DEFLATED = 8;
const SPEC_MANIFEST = 'manifest.json';
const OFFSPEC_MANIFEST = '0.manifest.json';
const PAYLOAD = '0.payload';

const authProvider: AuthProvider = {
  updateClientPublicKey: async () => {},
  withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
};

function newClient(): Client.Client {
  return new Client.Client({
    kasEndpoint: kasUrl,
    platformUrl: kasUrl,
    dpopKeys: Mocks.entityKeyPair(),
    clientId: 'id',
    authProvider,
  });
}

/** Bytes that don't repeat within any 256, so a dropped or moved byte is visible. */
function patterned(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (i * 31 + 7) & 0xff);
}

/** Deterministic bytes that deflate cannot shrink. */
function incompressible(length: number): Uint8Array {
  const out = new Uint8Array(length);
  let x = 0x2545f491;
  for (let i = 0; i < length; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  return out;
}

/** Raw DEFLATE (RFC 1951), as compression method 8 stores it. */
async function deflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const deflated = new Blob([data.slice()])
    .stream()
    .pipeThrough(new CompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(deflated).arrayBuffer());
}

async function encrypt(
  client: Client.Client,
  plaintext: Uint8Array,
  windowSize?: number
): Promise<Uint8Array> {
  const key = await new SplitKey(new AesGcmCipher(WebCryptoService)).generateKey();
  const stream = await client.encrypt({
    metadata: Mocks.getMetadataObject(),
    offline: true,
    scope: { dissem: ['user@domain.com'], attributes: [] },
    ...(windowSize && { windowSize }),
    keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
    source: new ReadableStream({
      start(controller) {
        controller.enqueue(plaintext);
        controller.close();
      },
    }),
  });
  return new Uint8Array(await stream.toBuffer());
}

/** One entry of a fixture archive, as written. */
type FixtureEntry = {
  fileName: string;
  method: number;
  /** The entry's data exactly as it appears in the archive. */
  data: Uint8Array;
  /** Recorded in the local header and central directory. */
  uncompressedSize: number;
  crc32: number;
};

function storedEntry(fileName: string, content: Uint8Array): FixtureEntry {
  return {
    fileName,
    method: STORED,
    data: content,
    uncompressedSize: content.length,
    crc32: unsigned(content, 0),
  };
}

async function deflatedEntry(fileName: string, content: Uint8Array): Promise<FixtureEntry> {
  return {
    fileName,
    method: DEFLATED,
    data: await deflateRaw(content),
    uncompressedSize: content.length,
    crc32: unsigned(content, 0),
  };
}

/** A zip64 extended information extra field holding `values` as 8 byte integers. */
function zip64Extra(values: number[]): Uint8Array {
  const extra = new Uint8Array(4 + 8 * values.length);
  const view = new DataView(extra.buffer);
  view.setUint16(0, 0x0001, true);
  view.setUint16(2, 8 * values.length, true);
  values.forEach((value, i) => view.setBigUint64(4 + 8 * i, BigInt(value), true));
  return extra;
}

/**
 * Writes `entries` as a zip archive with sizes and CRCs up front and no data
 * descriptors: the layout many general purpose zip writers produce. With
 * `zip64`, every size and offset moves to a zip64 extra field.
 */
function buildZip(entries: FixtureEntry[], { zip64 = false } = {}): Uint8Array {
  const versionNeeded = zip64 ? 45 : 20;
  const parts: Uint8Array[] = [];
  const records: Uint8Array[] = [];
  let offset = 0;
  for (const { fileName, method, data, uncompressedSize, crc32 } of entries) {
    const name = new TextEncoder().encode(fileName);

    const localExtra = zip64 ? zip64Extra([uncompressedSize, data.length]) : new Uint8Array(0);
    const local = new Uint8Array(30 + name.length + localExtra.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, versionNeeded, true);
    lv.setUint16(6, 0x0800, true); // UTF-8 file name
    lv.setUint16(8, method, true);
    lv.setUint32(14, crc32, true);
    lv.setUint32(18, zip64 ? 0xffffffff : data.length, true);
    lv.setUint32(22, zip64 ? 0xffffffff : uncompressedSize, true);
    lv.setUint16(26, name.length, true);
    lv.setUint16(28, localExtra.length, true);
    local.set(name, 30);
    local.set(localExtra, 30 + name.length);

    const cdExtra = zip64 ? zip64Extra([uncompressedSize, data.length, offset]) : new Uint8Array(0);
    const record = new Uint8Array(46 + name.length + cdExtra.length);
    const rv = new DataView(record.buffer);
    rv.setUint32(0, 0x02014b50, true);
    rv.setUint16(4, (3 << 8) | 63, true);
    rv.setUint16(6, versionNeeded, true);
    rv.setUint16(8, 0x0800, true);
    rv.setUint16(10, method, true);
    rv.setUint32(16, crc32, true);
    rv.setUint32(20, zip64 ? 0xffffffff : data.length, true);
    rv.setUint32(24, zip64 ? 0xffffffff : uncompressedSize, true);
    rv.setUint16(28, name.length, true);
    rv.setUint16(30, cdExtra.length, true);
    rv.setUint32(38, 0x81a40000, true);
    rv.setUint32(42, zip64 ? 0xffffffff : offset, true);
    record.set(name, 46);
    record.set(cdExtra, 46 + name.length);

    parts.push(local, data);
    records.push(record);
    offset += local.length + data.length;
  }
  const centralDirectoryOffset = offset;
  const centralDirectorySize = records.reduce((n, r) => n + r.length, 0);
  const writer = new ZipWriter();
  writer.zip64 = zip64;
  return concatUint8([
    ...parts,
    ...records,
    writer.writeEndOfCentralDirectoryRecord(
      records.length,
      centralDirectorySize,
      centralDirectoryOffset
    ),
  ]);
}

async function centralDirectoryOf(archive: Uint8Array): Promise<CentralDirectory[]> {
  return new ZipReader(fromBuffer(archive)).getCentralDirectory();
}

/** The manifest and payload bytes of an archive this SDK wrote. */
async function contentsOf(tdf: Uint8Array): Promise<{ manifest: Uint8Array; payload: Uint8Array }> {
  const bytesOf = async (name: string) => {
    const cd = (await centralDirectoryOf(tdf)).find(({ fileName }) => fileName === name)!;
    assert.equal(cd.compressionMethod, STORED);
    const start = cd.relativeOffsetOfLocalHeader + cd.headerLength;
    return tdf.slice(start, start + cd.compressedSize);
  };
  return { manifest: await bytesOf(OFFSPEC_MANIFEST), payload: await bytesOf(PAYLOAD) };
}

type Method = typeof STORED | typeof DEFLATED;

async function entryFor(fileName: string, content: Uint8Array, method: Method) {
  return method === DEFLATED ? deflatedEntry(fileName, content) : storedEntry(fileName, content);
}

/** Rebuilds an archive this SDK wrote with each entry stored or deflated as asked. */
async function rebuild(
  tdf: Uint8Array,
  {
    manifest = DEFLATED,
    payload = DEFLATED,
    manifestName = OFFSPEC_MANIFEST,
    zip64 = false,
  }: { manifest?: Method; payload?: Method; manifestName?: string; zip64?: boolean } = {}
): Promise<Uint8Array> {
  const contents = await contentsOf(tdf);
  return buildZip(
    [
      await entryFor(PAYLOAD, contents.payload, payload),
      await entryFor(manifestName, contents.manifest, manifest),
    ],
    { zip64 }
  );
}

async function decrypt(
  client: Client.Client,
  archive: Uint8Array | Chunker,
  options: { segmentBatchSize?: number; maxConcurrentSegmentBatches?: number } = {}
): Promise<Uint8Array> {
  const source =
    archive instanceof Uint8Array
      ? ({ type: 'buffer', location: archive } as const)
      : ({ type: 'chunker', location: archive } as const);
  const stream = await client.decrypt({ source, ...options });
  return new Uint8Array(await stream.toBuffer());
}

async function rejection(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (e) {
    assert.instanceOf(e, Error);
    return e;
  }
  return assert.fail('expected a rejection');
}

async function assertInvalidFile(promise: Promise<unknown>, pattern: RegExp): Promise<void> {
  const e = await rejection(promise);
  assert.instanceOf(e, InvalidFileError);
  assert.match(e.message, pattern);
}

/** Records every range a chunker is asked for. */
function recording(archive: Uint8Array): { chunker: Chunker; reads: Array<[number, number]> } {
  const base = fromBuffer(archive);
  const reads: Array<[number, number]> = [];
  const chunker: Chunker = async (start, end) => {
    const chunk = await base(start, end);
    if (start !== undefined && start >= 0) {
      reads.push([start, start + chunk.length]);
    }
    return chunk;
  };
  return { chunker, reads };
}

/** Where an entry's data sits in its archive. */
function dataRange(cd: CentralDirectory): [number, number] {
  const start = cd.relativeOffsetOfLocalHeader + cd.headerLength;
  return [start, start + cd.compressedSize];
}

function captureUnhandledRejections() {
  const reasons: unknown[] = [];
  const onNode = (reason: unknown) => reasons.push(reason);
  const onBrowser = (event: PromiseRejectionEvent) => {
    reasons.push(event.reason);
    event.preventDefault();
  };
  const proc = (globalThis as { process?: NodeJS.Process }).process;
  if (proc?.on) {
    proc.on('unhandledRejection', onNode);
  } else {
    globalThis.addEventListener('unhandledrejection', onBrowser);
  }
  return {
    reasons,
    async stop() {
      // Unhandled rejections are reported on a later macrotask.
      await new Promise((resolve) => setTimeout(resolve, 20));
      if (proc?.on) {
        proc.off('unhandledRejection', onNode);
      } else {
        globalThis.removeEventListener('unhandledrejection', onBrowser);
      }
    },
  };
}

describe('deflate-compressed zip entries', function () {
  let client: Client.Client;

  beforeEach(function () {
    client = newClient();
  });

  describe('writer', function () {
    it('still stores every entry uncompressed', async function () {
      const tdf = await encrypt(client, patterned(5000), 1000);
      const centralDirectory = await centralDirectoryOf(tdf);
      assert.lengthOf(centralDirectory, 2);
      for (const cd of centralDirectory) {
        assert.equal(cd.compressionMethod, STORED, cd.fileName);
        assert.equal(cd.compressedSize, cd.uncompressedSize, cd.fileName);
      }
    });
  });

  describe('decrypting rebuilt archives', function () {
    // 40 segments of 1000 bytes: the payload inflates in pieces that do not line
    // up with segment boundaries, and several batches are in flight at once.
    const plaintext = patterned(40_000);
    let tdf: Uint8Array;

    beforeEach(async function () {
      tdf = await encrypt(client, plaintext, 1000);
    });

    for (const manifestName of [SPEC_MANIFEST, OFFSPEC_MANIFEST]) {
      for (const zip64 of [false, true]) {
        it(`deflated manifest [${manifestName}] and payload${zip64 ? ', zip64' : ''}`, async function () {
          const archive = await rebuild(tdf, { manifestName, zip64 });
          const centralDirectory = await centralDirectoryOf(archive);
          assert.deepEqual(
            centralDirectory.map(({ fileName, compressionMethod }) => [
              fileName,
              compressionMethod,
            ]),
            [
              [PAYLOAD, DEFLATED],
              [manifestName, DEFLATED],
            ]
          );
          const manifestRecord = centralDirectory.find(
            ({ fileName }) => fileName === manifestName
          )!;
          assert.isBelow(manifestRecord.compressedSize, manifestRecord.uncompressedSize);

          assert.deepEqual(
            await decrypt(client, archive, { segmentBatchSize: 3, maxConcurrentSegmentBatches: 3 }),
            plaintext
          );
        });
      }
    }

    it('one segment per batch, many batches in flight', async function () {
      const archive = await rebuild(tdf);
      assert.deepEqual(
        await decrypt(client, archive, { segmentBatchSize: 1, maxConcurrentSegmentBatches: 8 }),
        plaintext
      );
    });

    it('deflated manifest, stored payload', async function () {
      const archive = await rebuild(tdf, { manifest: DEFLATED, payload: STORED });
      assert.deepEqual(await decrypt(client, archive), plaintext);
    });

    it('stored manifest, deflated payload', async function () {
      const archive = await rebuild(tdf, { manifest: STORED, payload: DEFLATED });
      assert.deepEqual(await decrypt(client, archive), plaintext);
    });

    it('both stored, in the classic layout', async function () {
      const archive = await rebuild(tdf, { manifest: STORED, payload: STORED });
      assert.deepEqual(await decrypt(client, archive), plaintext);
    });

    it('reads the policy id from a deflated manifest', async function () {
      const archive = await rebuild(tdf);
      assert.equal(
        await client.getPolicyId({ source: { type: 'buffer', location: archive } }),
        await client.getPolicyId({ source: { type: 'buffer', location: tdf } })
      );
    });

    it('rejects an entry with an unsupported compression method', async function () {
      const contents = await contentsOf(tdf);
      const archive = buildZip([
        // 12 is bzip2. The data is stored, so only the method is wrong.
        { ...storedEntry(PAYLOAD, contents.payload), method: 12 },
        storedEntry(OFFSPEC_MANIFEST, contents.manifest),
      ]);
      await assertInvalidFile(
        decrypt(client, archive),
        /entry \[0\.payload\] uses unsupported compression method \[12\]/
      );
    });

    it('rejects a deflated payload that inflates past its declared size', async function () {
      const contents = await contentsOf(tdf);
      const payload = await deflatedEntry(PAYLOAD, contents.payload);
      const archive = buildZip([
        { ...payload, uncompressedSize: payload.uncompressedSize - 1 },
        storedEntry(OFFSPEC_MANIFEST, contents.manifest),
      ]);
      // Depending on where the inflated pieces fall, either the cursor sees the
      // extra byte first or the last segment is refused as out of bounds.
      await assertInvalidFile(
        decrypt(client, archive),
        /entry \[0\.payload\] inflates to more than its declared uncompressed size|is outside entry \[0\.payload\]/
      );
    });

    it('rejects a deflated payload that inflates short of its declared size', async function () {
      const contents = await contentsOf(tdf);
      const payload = await deflatedEntry(PAYLOAD, contents.payload);
      const archive = buildZip([
        // Every segment is present; only the end of the entry is missing.
        { ...payload, uncompressedSize: payload.uncompressedSize + 10 },
        storedEntry(OFFSPEC_MANIFEST, contents.manifest),
      ]);
      await assertInvalidFile(
        decrypt(client, archive),
        /entry \[0\.payload\] inflates to \[\d+\] bytes, fewer than its declared uncompressed size/
      );
    });

    it('rejects a deflated manifest that inflates past its declared size', async function () {
      const contents = await contentsOf(tdf);
      const manifest = await deflatedEntry(OFFSPEC_MANIFEST, contents.manifest);
      const archive = buildZip([
        storedEntry(PAYLOAD, contents.payload),
        { ...manifest, uncompressedSize: manifest.uncompressedSize - 1 },
      ]);
      await assertInvalidFile(
        decrypt(client, archive),
        /inflates to more than its declared uncompressed size/
      );
    });

    it('rejects a deflated manifest that inflates short of its declared size', async function () {
      const contents = await contentsOf(tdf);
      const manifest = await deflatedEntry(OFFSPEC_MANIFEST, contents.manifest);
      const archive = buildZip([
        storedEntry(PAYLOAD, contents.payload),
        { ...manifest, uncompressedSize: manifest.uncompressedSize + 1 },
      ]);
      await assertInvalidFile(
        client.getPolicyId({ source: { type: 'buffer', location: archive } }),
        /fewer than its declared uncompressed size/
      );
    });

    it('reports a failed read of a deflated payload as a network error', async function () {
      const archive = await rebuild(tdf);
      const payloadRecord = (await centralDirectoryOf(archive)).find(
        ({ fileName }) => fileName === PAYLOAD
      )!;
      const [payloadStart] = dataRange(payloadRecord);
      const base = fromBuffer(archive);
      const chunker: Chunker = (start, end) =>
        start === payloadStart ? Promise.reject(new Error('connection reset')) : base(start, end);

      const unhandled = captureUnhandledRejections();
      let failure: Error;
      try {
        failure = await rejection(
          decrypt(client, chunker, { segmentBatchSize: 2, maxConcurrentSegmentBatches: 4 })
        );
      } finally {
        await unhandled.stop();
      }
      assert.instanceOf(failure, NetworkError);
      assert.isEmpty(unhandled.reasons, 'a failed decrypt must not leak rejections');
    });
  });

  describe('a payload larger than one compressed read', function () {
    it('is fetched front to back in several ranged reads', async function () {
      // Three default-sized (1 MiB) segments of ciphertext, which does not compress.
      const plaintext = patterned(2.5 * 1024 * 1024);
      const archive = await rebuild(await encrypt(client, plaintext));
      const payloadRecord = (await centralDirectoryOf(archive)).find(
        ({ fileName }) => fileName === PAYLOAD
      )!;
      const [start, end] = dataRange(payloadRecord);

      const { chunker, reads } = recording(archive);
      assert.deepEqual(await decrypt(client, chunker), plaintext);

      const payloadReads = reads.filter(([s]) => s >= start && s < end);
      assert.isAbove(payloadReads.length, 1, 'the payload is not read in one piece');
      let next = start;
      for (const [s, e] of payloadReads) {
        assert.equal(s, next, 'compressed reads are contiguous and in order');
        next = e;
      }
      assert.equal(next, end, 'the whole compressed entry is read, and nothing past it');
    });
  });

  describe('ZipReader', function () {
    const manifestJson = new TextEncoder().encode(JSON.stringify({ hello: 'manifest' }));

    async function readerFor(archive: Uint8Array) {
      const reader = new ZipReader(fromBuffer(archive));
      return { reader, centralDirectory: await reader.getCentralDirectory() };
    }

    it('reads a manifest deflated by another compressor', async function () {
      // zlib's raw deflate of `{"a":1}`.
      const deflated = Uint8Array.from([0xab, 0x56, 0x4a, 0x54, 0xb2, 0x32, 0xac, 0x05, 0x00]);
      const content = new TextEncoder().encode('{"a":1}');
      const archive = buildZip([
        {
          fileName: SPEC_MANIFEST,
          method: DEFLATED,
          data: deflated,
          uncompressedSize: content.length,
          crc32: unsigned(content, 0),
        },
      ]);
      const { reader, centralDirectory } = await readerFor(archive);
      assert.deepEqual<unknown>(await reader.getManifest(centralDirectory, SPEC_MANIFEST), {
        a: 1,
      });
    });

    for (const method of [1, 9, 12, 14, 93, 99]) {
      it(`still rejects compression method ${method}`, async function () {
        const archive = buildZip([{ ...storedEntry(SPEC_MANIFEST, manifestJson), method }]);
        await assertInvalidFile(
          centralDirectoryOf(archive),
          new RegExp(`uses unsupported compression method \\[${method}\\]`)
        );
      });
    }

    it('rejects an unsupported method on a central directory that skipped validation', async function () {
      const archive = buildZip([await deflatedEntry(SPEC_MANIFEST, manifestJson)]);
      const { reader, centralDirectory } = await readerFor(archive);
      const tampered = centralDirectory.map((cd) => ({ ...cd, compressionMethod: 12 }));
      await assertInvalidFile(
        reader.getManifest(tampered, SPEC_MANIFEST),
        /unsupported compression method \[12\]/
      );
    });

    it('applies the declared uncompressed size, not the compressed size, to a manifest', async function () {
      // Highly compressible, so the compressed entry is far smaller than the JSON.
      const big = new TextEncoder().encode(JSON.stringify({ pad: 'x'.repeat(100_000) }));
      const entry = await deflatedEntry(SPEC_MANIFEST, big);
      assert.isBelow(entry.data.length, 1000);
      const ok = await readerFor(buildZip([entry]));
      assert.equal(
        (
          (await ok.reader.getManifest(ok.centralDirectory, SPEC_MANIFEST)) as unknown as {
            pad: string;
          }
        ).pad.length,
        100_000
      );
      // Declaring the compressed size as the uncompressed one is not enough room.
      const lying = await readerFor(buildZip([{ ...entry, uncompressedSize: entry.data.length }]));
      await assertInvalidFile(
        lying.reader.getManifest(lying.centralDirectory, SPEC_MANIFEST),
        new RegExp(`more than its declared uncompressed size \\[${entry.data.length}\\]`)
      );
    });

    it('rejects a deflated entry that is not valid deflate data', async function () {
      const archive = buildZip([
        {
          ...storedEntry(SPEC_MANIFEST, manifestJson),
          method: DEFLATED,
          data: Uint8Array.from([0xff, 0xff, 0xff, 0xff]),
        },
      ]);
      const { reader, centralDirectory } = await readerFor(archive);
      await assertInvalidFile(
        reader.getManifest(centralDirectory, SPEC_MANIFEST),
        /entry \[manifest\.json\] is not valid deflate data/
      );
    });

    it('rejects a deflated entry whose compressed data is cut short', async function () {
      const entry = await deflatedEntry(PAYLOAD, patterned(10_000));
      const archive = buildZip([{ ...entry, data: entry.data.slice(0, entry.data.length - 4) }]);
      const { reader, centralDirectory } = await readerFor(archive);
      await assertInvalidFile(
        reader.getPayloadSegment(centralDirectory, PAYLOAD, 0, 10_000),
        /entry \[0\.payload\] (is not valid deflate data|inflates to \[\d+\] bytes, fewer)/
      );
    });

    it('stops reading compressed data once the entry inflates past its declared size', async function () {
      const content = incompressible(4 * 1024 * 1024);
      const entry = await deflatedEntry(PAYLOAD, content);
      const archive = buildZip([{ ...entry, uncompressedSize: 1000 }]);
      const { chunker, reads } = recording(archive);
      const reader = new ZipReader(chunker);
      const centralDirectory = await reader.getCentralDirectory();
      const [start, end] = dataRange(centralDirectory[0]);
      await assertInvalidFile(
        reader.getPayloadSegment(centralDirectory, PAYLOAD, 0, 1000),
        /entry \[0\.payload\] inflates to more than its declared uncompressed size \[1000\]/
      );
      const fetched = reads
        .filter(([s]) => s >= start && s < end)
        .reduce((n, [s, e]) => n + (e - s), 0);
      assert.isBelow(fetched, end - start, 'reading stopped before the end of the entry');
    });

    it('rejects a zip bomb without inflating it', async function () {
      // 32 MiB of zeros deflates to a few dozen KiB.
      const entry = await deflatedEntry(PAYLOAD, new Uint8Array(32 * 1024 * 1024));
      assert.isBelow(entry.data.length, 64 * 1024);
      const archive = buildZip([{ ...entry, uncompressedSize: 1024 }]);
      const { reader, centralDirectory } = await readerFor(archive);
      await assertInvalidFile(
        reader.getPayloadSegment(centralDirectory, PAYLOAD, 0, 1024),
        /more than its declared uncompressed size \[1024\]/
      );
    });

    it('rejects a read past the end of what a deflated entry really holds', async function () {
      const content = patterned(5000);
      const entry = await deflatedEntry(PAYLOAD, content);
      const archive = buildZip([{ ...entry, uncompressedSize: 6000 }]);
      const { reader, centralDirectory } = await readerFor(archive);
      assert.deepEqual(
        await reader.getPayloadSegment(centralDirectory, PAYLOAD, 4000, 1000),
        content.slice(4000)
      );
      await assertInvalidFile(
        reader.getPayloadSegment(centralDirectory, PAYLOAD, 4000, 1001),
        /inflates to \[5000\] bytes, fewer than its declared uncompressed size \[6000\]/
      );
    });

    it('bounds segment reads by the uncompressed size', async function () {
      const content = patterned(5000);
      const { reader, centralDirectory } = await readerFor(
        buildZip([await deflatedEntry(PAYLOAD, content)])
      );
      assert.isBelow(centralDirectory[0].compressedSize, 5000);
      assert.deepEqual(await reader.getPayloadSegment(centralDirectory, PAYLOAD, 0, 5000), content);
      assert.deepEqual(
        await reader.getPayloadSegment(centralDirectory, PAYLOAD, 5000, 0),
        new Uint8Array(0)
      );
      for (const [offset, size] of [
        [0, 5001],
        [5000, 1],
        [-1, 2],
        [0.5, 1],
      ]) {
        await assertInvalidFile(
          reader.getPayloadSegment(centralDirectory, PAYLOAD, offset, size),
          /outside entry \[0\.payload\] of \[5000\] bytes/
        );
      }
    });

    describe('openEntry on a deflated entry', function () {
      const content = patterned(300_000);
      let archive: Uint8Array;

      beforeEach(async function () {
        archive = buildZip([
          await deflatedEntry(PAYLOAD, content),
          storedEntry(SPEC_MANIFEST, manifestJson),
        ]);
      });

      it('serves ascending reads from one pass over the compressed data', async function () {
        const { chunker, reads } = recording(archive);
        const reader = new ZipReader(chunker);
        const centralDirectory = await reader.getCentralDirectory();
        const [start, end] = dataRange(centralDirectory[0]);
        const entry = reader.openEntry(centralDirectory, PAYLOAD);
        // Issued together, as the decrypt's batches are, and with a gap.
        const pieces = await Promise.all([
          entry.read(0, 70_000),
          entry.read(70_000, 1),
          entry.read(70_001, 100_000),
          entry.read(200_000, 100_000),
        ]);
        await entry.finish();
        assert.deepEqual(pieces[0], content.slice(0, 70_000));
        assert.deepEqual(pieces[1], content.slice(70_000, 70_001));
        assert.deepEqual(pieces[2], content.slice(70_001, 170_001));
        assert.deepEqual(pieces[3], content.slice(200_000));
        const fetched = reads
          .filter(([s]) => s >= start && s < end)
          .reduce((n, [s, e]) => n + (e - s), 0);
        assert.equal(fetched, end - start, 'each compressed byte is fetched once');
      });

      it('starts over for a read behind the cursor', async function () {
        const { reader, centralDirectory } = await readerFor(archive);
        const entry = reader.openEntry(centralDirectory, PAYLOAD);
        assert.deepEqual(await entry.read(200_000, 10), content.slice(200_000, 200_010));
        assert.deepEqual(await entry.read(5, 10), content.slice(5, 15));
        assert.deepEqual(await entry.read(5, 10), content.slice(5, 15));
        await entry.finish();
      });

      it('hands each read its own buffer', async function () {
        const { reader, centralDirectory } = await readerFor(archive);
        const entry = reader.openEntry(centralDirectory, PAYLOAD);
        const first = await entry.read(0, 10);
        const second = await entry.read(10, 10);
        assert.equal(first.byteOffset, 0);
        assert.equal(first.buffer.byteLength, 10);
        assert.notStrictEqual(first.buffer, second.buffer);
      });

      it('fails every later read after a failure', async function () {
        const { reader, centralDirectory } = await readerFor(archive);
        const lying = centralDirectory.map((cd) =>
          cd.fileName === PAYLOAD ? { ...cd, uncompressedSize: 100 } : cd
        );
        const entry = reader.openEntry(lying, PAYLOAD);
        await assertInvalidFile(entry.read(0, 10), /more than its declared uncompressed size/);
        await assertInvalidFile(entry.read(0, 10), /more than its declared uncompressed size/);
      });

      it('rejects reads after close', async function () {
        const { reader, centralDirectory } = await readerFor(archive);
        const entry = reader.openEntry(centralDirectory, PAYLOAD);
        await entry.read(0, 10);
        entry.close();
        await rejection(entry.read(10, 10));
      });
    });

    it('openEntry on a stored entry reads ranges in any order', async function () {
      const content = patterned(1000);
      const { reader, centralDirectory } = await readerFor(
        buildZip([storedEntry(PAYLOAD, content)])
      );
      const entry = reader.openEntry(centralDirectory, PAYLOAD);
      assert.deepEqual(await entry.read(500, 10), content.slice(500, 510));
      assert.deepEqual(await entry.read(0, 10), content.slice(0, 10));
      await entry.finish();
    });
  });
});
