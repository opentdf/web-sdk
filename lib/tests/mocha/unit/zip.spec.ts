import { expect } from 'chai';

import { encodeArrayBuffer } from '../../../src/encodings/base64.js';
import { InvalidFileError } from '../../../src/errors.js';
import { fromBuffer } from '../../../src/seekable.js';
import type { CentralDirectory } from '../../../tdf3/src/utils/zip-reader.js';
import { parseCDBuffer, readUInt64LE, ZipReader } from '../../../tdf3/src/utils/zip-reader.js';
import { ZipWriter, dateToDosDateTime, writeUInt64LE } from '../../../tdf3/src/utils/zip-writer.js';
import { readUInt16LE, readUInt32LE } from '../../../tdf3/src/utils/index.js';

const CD_SIGNATURE_BYTES = new Uint8Array([0x50, 0x4b, 0x01, 0x02]);
const EOCD_SIGNATURE_BYTES = new Uint8Array([0x50, 0x4b, 0x05, 0x06]);
const DATA_DESCRIPTOR_SIZE = 16;
const ZIP64_DATA_DESCRIPTOR_SIZE = 24;
const FIXED_DATE = new Date('1980-01-01T00:00:00');

function concat(chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

function u16(buf: Uint8Array, offset: number): number {
  return buf[offset] | (buf[offset + 1] << 8);
}

function setU16(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >> 8) & 0xff;
}

function setU32(buf: Uint8Array, offset: number, value: number): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setUint32(offset, value, true);
}

function setU64(buf: Uint8Array, offset: number, value: bigint): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setBigUint64(offset, value, true);
}

/**
 * Offset of the relative header offset inside the zip64 extended information
 * extra field that ZipWriter emits: the field follows the file name, and its
 * data (after a 4 byte header) is uncompressed size, compressed size, offset.
 */
function zip64ExtraOffsetField(record: Uint8Array): number {
  return 46 + u16(record, 28) + 4 + 16;
}

/** Asserts that `fn` rejects with an InvalidFileError and returns its message. */
async function expectInvalidFile(fn: () => Promise<unknown>, why: string): Promise<string> {
  try {
    await fn();
  } catch (e) {
    expect(e, why).to.be.instanceOf(InvalidFileError);
    return messageOf(e);
  }
  expect.fail(`expected an InvalidFileError: ${why}`);
}

type ZipEntry = { name: string; data: Uint8Array };

type BuildZipOptions = {
  zip64?: boolean;
  /** Trailing .ZIP file comment, appended after the end of central directory record. */
  comment?: Uint8Array;
  /** Rewrites each central directory record before it is appended. */
  mapCentralDirectoryRecord?: (record: Uint8Array, index: number) => Uint8Array;
};

/**
 * Assembles a complete, well formed zip archive in memory so the reader can be
 * exercised end to end rather than against hand-rolled record fragments.
 */
function buildZip(entries: ZipEntry[], options: BuildZipOptions = {}): Uint8Array {
  const { zip64 = true, comment, mapCentralDirectoryRecord } = options;
  const zipWriter = new ZipWriter();
  zipWriter.zip64 = zip64;
  const descriptorSize = zip64 ? ZIP64_DATA_DESCRIPTOR_SIZE : DATA_DESCRIPTOR_SIZE;

  const body: Uint8Array[] = [];
  const centralDirectory: Uint8Array[] = [];
  let offset = 0;
  entries.forEach(({ name, data }, index) => {
    const crc32 = 0;
    const localFileHeader = zipWriter.getLocalFileHeader(
      name,
      crc32,
      data.length,
      data.length,
      FIXED_DATE
    );
    body.push(localFileHeader, data, zipWriter.writeDataDescriptor(crc32, data.length));
    let record = zipWriter.writeCentralDirectoryRecord(
      data.length,
      name,
      offset,
      crc32,
      0x81a40000,
      FIXED_DATE
    );
    if (mapCentralDirectoryRecord) {
      record = mapCentralDirectoryRecord(record, index);
    }
    centralDirectory.push(record);
    offset += localFileHeader.length + data.length + descriptorSize;
  });

  const cdBuffer = concat(centralDirectory);
  const eocdBuffer = zipWriter.writeEndOfCentralDirectoryRecord(
    entries.length,
    cdBuffer.length,
    offset
  );
  if (!comment?.length) {
    return concat([...body, cdBuffer, eocdBuffer]);
  }
  // The end of central directory record is always the final 22 bytes of what the
  // writer returns; patch its comment length and append the comment itself.
  setU16(eocdBuffer, eocdBuffer.length - 2, comment.length);
  return concat([...body, cdBuffer, eocdBuffer, comment]);
}

/**
 * Inserts an extra field ahead of whatever extra fields a central directory record
 * already carries, so the ZIP64 extra field is no longer the first one.
 */
function prependExtraField(record: Uint8Array, headerId: number, data: Uint8Array): Uint8Array {
  const fileNameLength = u16(record, 28);
  const extraFieldLength = u16(record, 30);
  const extraStart = 46 + fileNameLength;

  const inserted = new Uint8Array(4 + data.length);
  setU16(inserted, 0, headerId);
  setU16(inserted, 2, data.length);
  inserted.set(data, 4);

  const head = record.slice(0, extraStart);
  setU16(head, 30, extraFieldLength + inserted.length);
  return concat([head, inserted, record.slice(extraStart)]);
}

/**
 * The pre-DSPX-4591 reader: scan the tail of the file backwards and treat every
 * central directory signature as the start of an entry. Kept here only to
 * demonstrate that the archives below actually defeat it.
 */
function legacyCentralDirectoryScan(chunkBuffer: Uint8Array): number {
  let found = 0;
  for (let i = chunkBuffer.length - 22; i >= 0; i -= 1) {
    if (
      chunkBuffer[i] !== 0x50 ||
      chunkBuffer[i + 1] !== 0x4b ||
      chunkBuffer[i + 2] !== 0x01 ||
      chunkBuffer[i + 3] !== 0x02
    ) {
      continue;
    }
    found += 1;
    i -= 22;
  }
  return found;
}

const manifestBytes = (manifest: unknown) => new TextEncoder().encode(JSON.stringify(manifest));

const messageOf = (e: unknown) => (e instanceof Error ? e.message : String(e));

describe('zip utilities', () => {
  describe('dateToDos', () => {
    it('zero', () => {
      const dosEpochStart = new Date('1980-01-01T00:00:00');
      const { date, time } = dateToDosDateTime(dosEpochStart);
      // DOS used 1-indexed day-of-month and month-of-year fields.

      expect(date).to.equal(0x1 | (0x1 << 5));
      expect(time).to.equal(0);
    });
    it('ninteen ninety nine', () => {
      const dosEpochStart = new Date('1999-12-31T23:59:59');
      const { date, time } = dateToDosDateTime(dosEpochStart);

      expect(date).to.equal(31 | (12 << 5) | (19 << 9));
      // File modificaiton stamps only had two-second granularity.

      expect(time).to.equal(29 | (59 << 5) | (23 << 11));
    });
  });

  describe('writeUInt64LE', () => {
    it('not too different', () => {
      // allocate a new uint8array with 8 bytes
      const b0 = new Uint8Array(8);
      new DataView(b0.buffer).setBigUint64(0, BigInt(1), true);
      const b1 = new Uint8Array(8);
      writeUInt64LE(b1, 1, 0);
      expect(b1).to.eql(b0);
    });
    it('unsafe ints throw', () => {
      expect(() => writeUInt64LE(new Uint8Array(0), 2 ** 54, 0)).to.throw(/unsafe number/);
    });
  });
  describe('readUInt64LE', () => {
    it('one', () => {
      const b0 = new Uint8Array(8);
      new DataView(b0.buffer).setBigUint64(0, 1n, true);
      expect(readUInt64LE(b0, 0)).to.equal(1);
    });
    it('unsafe ints throw', () => {
      const b0 = new Uint8Array(8);
      new DataView(b0.buffer).setBigUint64(0, 9007199254740992n, true);
      expect(() => readUInt64LE(b0, 0)).to.throw(/exceeds/);
    });
    it('0xffffffffffffffff throws InvalidFileError', () => {
      const b0 = new Uint8Array(8).fill(0xff);
      expect(() => readUInt64LE(b0, 0)).to.throw(InvalidFileError, /exceeds/);
    });
    it('out of bounds reads throw', () => {
      expect(() => readUInt64LE(new Uint8Array(7), 0)).to.throw(InvalidFileError);
    });
  });

  describe('readUInt16LE / readUInt32LE bounds', () => {
    it('read in range', () => {
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(readUInt16LE(b, 2)).to.equal(0x0403);
      expect(readUInt32LE(b, 0)).to.equal(0x04030201);
    });
    it('throw instead of reading past the end', () => {
      const b = new Uint8Array(3);
      expect(() => readUInt16LE(b, 2)).to.throw(InvalidFileError);
      expect(() => readUInt32LE(b, 0)).to.throw(InvalidFileError);
      expect(() => readUInt16LE(b, -1)).to.throw(InvalidFileError);
      expect(() => readUInt32LE(b, 0.5)).to.throw(InvalidFileError);
    });
  });

  describe('localFileHeaders', () => {
    it('standard', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = false;
      const headerBuffer = zipWriter.getLocalFileHeader(
        'Hey.txt',
        0x1337,
        5,
        500,
        new Date('1980-01-01T00:00:00')
      );
      expect(encodeArrayBuffer(headerBuffer.buffer)).to.equal(
        'UEsDBBQACAgAAAAAIQA3EwAABQAAAPQBAAAHAAAASGV5LnR4dA=='
      );
    });
    it('zip64', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = true;
      const headerBuffer = zipWriter.getLocalFileHeader(
        'Hey.txt',
        0x1337,
        5,
        500,
        new Date('1980-01-01T00:00:00')
      );
      expect(encodeArrayBuffer(headerBuffer.buffer)).to.equal(
        'UEsDBBQACAgAAAAAIQA3EwAA//////////8HABwASGV5LnR4dAEAGAAFAAAAAAAAAPQBAAAAAAAAAAAAAAAAAAA='
      );
    });
  });

  describe('dataDescriptors', () => {
    it('standard', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = false;
      const descriptorBuffer = zipWriter.writeDataDescriptor(0x1337, 500);
      expect(encodeArrayBuffer(descriptorBuffer.buffer)).to.equal('UEsHCDcTAAD0AQAA9AEAAA==');
    });
    it('zip64', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = true;
      const descriptorBuffer = zipWriter.writeDataDescriptor(0x1337, 500);
      expect(encodeArrayBuffer(descriptorBuffer.buffer)).to.equal(
        'UEsHCDcTAAD0AQAAAAAAAPQBAAAAAAAA'
      );
    });
    // DSPX-4591 finding 3: the record is `signature, crc-32, compressed size,
    // uncompressed size`. The non-zip64 branch used to write the uncompressed size
    // into both slots, which only looked right because we always STORE.
    it('standard, distinct compressed size', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = false;
      const descriptorBuffer = zipWriter.writeDataDescriptor(0x1337, 500, 321);
      const view = new DataView(
        descriptorBuffer.buffer,
        descriptorBuffer.byteOffset,
        descriptorBuffer.byteLength
      );
      expect(descriptorBuffer.length).to.equal(DATA_DESCRIPTOR_SIZE);
      expect(view.getUint32(0, true)).to.equal(0x08074b50);
      expect(view.getUint32(4, true)).to.equal(0x1337);
      expect(view.getUint32(8, true)).to.equal(321);
      expect(view.getUint32(12, true)).to.equal(500);
    });
    it('zip64, distinct compressed size', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = true;
      const descriptorBuffer = zipWriter.writeDataDescriptor(0x1337, 500, 321);
      const view = new DataView(
        descriptorBuffer.buffer,
        descriptorBuffer.byteOffset,
        descriptorBuffer.byteLength
      );
      expect(descriptorBuffer.length).to.equal(ZIP64_DATA_DESCRIPTOR_SIZE);
      expect(view.getUint32(0, true)).to.equal(0x08074b50);
      expect(view.getUint32(4, true)).to.equal(0x1337);
      expect(view.getBigUint64(8, true)).to.equal(321n);
      expect(view.getBigUint64(16, true)).to.equal(500n);
    });
  });

  // CHARACTERISTIC TESTS of zip files.
  // TODO(PLAT-1134) Include samples generated by c++ sdk
  describe('centralDirectoryRecords', () => {
    it('standard', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = false;
      const cdrBuffer = zipWriter.writeCentralDirectoryRecord(
        500,
        'Hey.txt',
        2000,
        0x1337,
        0x81a40000,
        new Date('1980-01-01T00:00:00')
      );
      expect(parseCDBuffer(cdrBuffer)).to.deep.include({
        compressedSize: 500,
        uncompressedSize: 500,
        fileName: 'Hey.txt',
        crc32: 0x1337,
        relativeOffsetOfLocalHeader: 2000,
        externalFileAttributes: 2175008768,
        lastModFileDate: 33,
        lastModFileTime: 0,
      });
      expect(encodeArrayBuffer(cdrBuffer.buffer)).to.equal(
        'UEsBAj8DFAAICAAAAAAhADcTAAD0AQAA9AEAAAcAAAAAAAAAAAAAAKSB0AcAAEhleS50eHQ='
      );
    });
    it('zip64', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = true;
      const cdrBuffer = zipWriter.writeCentralDirectoryRecord(
        2 ** 50,
        'Hey.txt',
        2000,
        0x1337,
        0x81a40000,
        new Date('1980-01-01T00:00:00')
      );
      expect(parseCDBuffer(cdrBuffer)).to.deep.include({
        compressedSize: 2 ** 50,
        uncompressedSize: 2 ** 50,
        fileName: 'Hey.txt',
        crc32: 0x1337,
        relativeOffsetOfLocalHeader: 2000,
        externalFileAttributes: 2175008768,
        lastModFileDate: 33,
        lastModFileTime: 0,
      });
      expect(encodeArrayBuffer(cdrBuffer.buffer)).to.equal(
        'UEsBAj8DLQAICAAAAAAhADcTAAD//////////wcAHAAAAAAAAAAAAKSB/////0hleS50eHQBABgAAAAAAAAABAAAAAAAAAAEANAHAAAAAAAA'
      );
    });
  });

  describe('endOfentralDirectoryRecords', () => {
    it('standard', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = false;
      const eocdrBuffer = zipWriter.writeEndOfCentralDirectoryRecord(2, 200, 2000);
      expect(encodeArrayBuffer(eocdrBuffer)).to.equal('UEsFBgAAAAACAAIAyAAAANAHAAAAAA==');
    });
    it('zip64', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = true;
      const eocdrBuffer = zipWriter.writeEndOfCentralDirectoryRecord(2, 200, 2000);
      expect(encodeArrayBuffer(eocdrBuffer)).to.equal(
        'UEsGBiwAAAAAAAAAPwMtAAAAAAAAAAAAAgAAAAAAAAACAAAAAAAAAMgAAAAAAAAA0AcAAAAAAABQSwYHAAAAAJgIAAAAAAAAAQAAAFBLBQYAAAAA////////////////AAA='
      );
    });
  });
});

describe('reader', () => {
  it('fails on bad manifest size', async () => {
    const reader = new ZipReader(() => Promise.resolve(new Uint8Array([])));
    const fileName = '0.manifest.json';
    try {
      expect(
        await reader.getManifest(
          [
            {
              fileName,
              relativeOffsetOfLocalHeader: 0,
              headerLength: 1024,
              uncompressedSize: 1024 * 1024 * 128,
            } as CentralDirectory,
          ],
          fileName
        )
      ).to.be.undefined;
    } catch (e) {
      expect(e).to.be.instanceOf(Error);
      if (e instanceof Error) expect(e.message).to.contain('too large');
    }
  });

  // DSPX-4591 finding 4: `>>` coerces to signed 32 bits, so 2 GiB used to be
  // reported as a negative number of KiB.
  it('reports oversized manifests without 32 bit wraparound', async () => {
    const reader = new ZipReader(() => Promise.resolve(new Uint8Array([])));
    const fileName = '0.manifest.json';
    let message = '';
    try {
      await reader.getManifest(
        [
          {
            fileName,
            relativeOffsetOfLocalHeader: 0,
            headerLength: 1024,
            uncompressedSize: 2 ** 31,
          } as CentralDirectory,
        ],
        fileName
      );
      expect.fail('expected an oversized manifest to be rejected');
    } catch (e) {
      message = messageOf(e);
    }
    expect(message).to.contain('too large');
    expect(message).to.not.contain('-');
    expect(message).to.contain((2 ** 21).toLocaleString());
  });

  describe('getCentralDirectory', () => {
    const manifest = { payload: { type: 'reference' } };

    it('reads a zip64 archive written by ZipWriter', async () => {
      const zipFile = buildZip([
        { name: '0.manifest.json', data: manifestBytes(manifest) },
        { name: '0.payload', data: new Uint8Array([1, 2, 3, 4, 5]) },
      ]);
      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      expect(centralDirectory.map(({ fileName }) => fileName)).to.eql([
        '0.manifest.json',
        '0.payload',
      ]);
      expect(await reader.getManifest(centralDirectory, '0.manifest.json')).to.eql(manifest);
      expect(await reader.getPayloadSegment(centralDirectory, '0.payload', 0, 5)).to.eql(
        new Uint8Array([1, 2, 3, 4, 5])
      );
    });

    it('reads a non-zip64 archive', async () => {
      const zipFile = buildZip(
        [
          { name: '0.manifest.json', data: manifestBytes(manifest) },
          { name: '0.payload', data: new Uint8Array([9, 8, 7]) },
        ],
        { zip64: false }
      );
      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      expect(centralDirectory.map(({ fileName }) => fileName)).to.eql([
        '0.manifest.json',
        '0.payload',
      ]);
      expect(await reader.getManifest(centralDirectory, '0.manifest.json')).to.eql(manifest);
    });

    // DSPX-4591 finding 1: the EOCD is not necessarily the last bytes of the file.
    it('reads an archive with a trailing comment', async () => {
      const comment = new TextEncoder().encode('a comment that follows the EOCD record');
      const zipFile = buildZip(
        [
          { name: '0.manifest.json', data: manifestBytes(manifest) },
          { name: '0.payload', data: new Uint8Array([1, 2, 3]) },
        ],
        { comment }
      );
      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      expect(centralDirectory.map(({ fileName }) => fileName)).to.eql([
        '0.manifest.json',
        '0.payload',
      ]);
      expect(await reader.getManifest(centralDirectory, '0.manifest.json')).to.eql(manifest);
    });

    it('reads an archive whose comment contains an EOCD signature', async () => {
      const comment = concat([
        new TextEncoder().encode('trailing '),
        EOCD_SIGNATURE_BYTES,
        new TextEncoder().encode(' bytes'),
      ]);
      const zipFile = buildZip([{ name: '0.manifest.json', data: manifestBytes(manifest) }], {
        comment,
      });
      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      expect(centralDirectory).to.have.length(1);
      expect(await reader.getManifest(centralDirectory, '0.manifest.json')).to.eql(manifest);
    });

    it('reads an archive with a maximum length comment', async () => {
      const comment = new Uint8Array(0xffff).fill(0x2e);
      const zipFile = buildZip([{ name: '0.manifest.json', data: manifestBytes(manifest) }], {
        comment,
      });
      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      expect(centralDirectory.map(({ fileName }) => fileName)).to.eql(['0.manifest.json']);
    });

    // DSPX-4591 finding 1, the false positive case. A payload that happens to
    // contain 0x02014b50 defeated the backward signature scan.
    it('ignores central directory signatures inside the payload', async () => {
      const payload = concat([
        new Uint8Array([0xde, 0xad]),
        CD_SIGNATURE_BYTES,
        new Uint8Array(64).fill(0x00),
        CD_SIGNATURE_BYTES,
        new Uint8Array([0xbe, 0xef]),
      ]);
      const zipFile = buildZip([
        { name: '0.manifest.json', data: manifestBytes(manifest) },
        { name: '0.payload', data: payload },
      ]);

      // Precondition: the old backward scan really does see more than two entries.
      expect(legacyCentralDirectoryScan(zipFile)).to.be.greaterThan(2);

      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      expect(centralDirectory.map(({ fileName }) => fileName)).to.eql([
        '0.manifest.json',
        '0.payload',
      ]);
      expect(await reader.getManifest(centralDirectory, '0.manifest.json')).to.eql(manifest);
      expect(
        await reader.getPayloadSegment(centralDirectory, '0.payload', 0, payload.length)
      ).to.eql(payload);
    });

    it('rejects an archive with no end of central directory record', async () => {
      const zipFile = buildZip([{ name: '0.manifest.json', data: manifestBytes(manifest) }]);
      // Drop the EOCD record (and any zip64 trailer) entirely.
      const truncated = zipFile.slice(0, zipFile.length - 98);
      const reader = new ZipReader(fromBuffer(truncated));
      let message = '';
      try {
        await reader.getCentralDirectory();
        expect.fail('expected a missing EOCD to be rejected');
      } catch (e) {
        message = messageOf(e);
      }
      expect(message).to.contain('end of central directory');
    });

    it('rejects a zip64 archive whose locator is missing', async () => {
      const zipFile = buildZip([{ name: '0.manifest.json', data: manifestBytes(manifest) }]);
      // Corrupt the zip64 end of central directory locator signature.
      zipFile[zipFile.length - 22 - 20] ^= 0xff;
      const reader = new ZipReader(fromBuffer(zipFile));
      let message = '';
      try {
        await reader.getCentralDirectory();
        expect.fail('expected a missing zip64 locator to be rejected');
      } catch (e) {
        message = messageOf(e);
      }
      expect(message).to.contain('zip64 locator');
    });

    it('rejects an end of central directory record that overstates the entry count', async () => {
      const zipFile = buildZip(
        [
          { name: '0.manifest.json', data: manifestBytes(manifest) },
          { name: '0.payload', data: new Uint8Array([1, 2, 3]) },
        ],
        { zip64: false }
      );
      // 22 byte EOCD at the end: entry counts live at offsets 8 and 10.
      const eocdStart = zipFile.length - 22;
      setU16(zipFile, eocdStart + 8, 3);
      setU16(zipFile, eocdStart + 10, 3);
      const reader = new ZipReader(fromBuffer(zipFile));
      let message = '';
      try {
        await reader.getCentralDirectory();
        expect.fail('expected a bad entry count to be rejected');
      } catch (e) {
        message = messageOf(e);
      }
      expect(message).to.contain('central directory');
    });
  });

  // DSPX-4591 findings 5 and 6: hostile offsets and sizes must surface as
  // InvalidFileError, never as a generic Error, a SyntaxError from parsing an
  // empty manifest, or an out-of-range read that silently returns garbage.
  describe('hostile offsets and sizes', () => {
    const manifest = { payload: { type: 'reference' } };
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const entries = () => [
      { name: '0.manifest.json', data: manifestBytes(manifest) },
      { name: '0.payload', data: payload },
    ];

    it('rejects a zip64 local header offset of 0xffffffffffffffff', async () => {
      const zipFile = buildZip(entries(), {
        mapCentralDirectoryRecord: (record, i) => {
          if (i === 1) {
            setU64(record, zip64ExtraOffsetField(record), 0xffffffffffffffffn);
          }
          return record;
        },
      });
      const message = await expectInvalidFile(
        () => new ZipReader(fromBuffer(zipFile)).getCentralDirectory(),
        'zip64 overflow'
      );
      expect(message).to.contain('MAX_SAFE_INTEGER');
    });

    it('rejects a zip64 end of central directory with 0xffffffffffffffff entries', async () => {
      const zipFile = buildZip(entries());
      // zip64 EOCD record (56) + locator (20) + EOCD (22) end the file; the
      // entry count lives at offset 32 of the zip64 EOCD record.
      setU64(zipFile, zipFile.length - 22 - 20 - 56 + 32, 0xffffffffffffffffn);
      await expectInvalidFile(
        () => new ZipReader(fromBuffer(zipFile)).getCentralDirectory(),
        'zip64 EOCD overflow'
      );
    });

    it('rejects a local header offset past the end of the file', async () => {
      const zipFile = buildZip(entries(), {
        zip64: false,
        mapCentralDirectoryRecord: (record, i) => {
          if (i === 0) {
            // 42 - relative offset of local file header
            setU32(record, 42, 0x7fffffff);
          }
          return record;
        },
      });
      const message = await expectInvalidFile(
        () => new ZipReader(fromBuffer(zipFile)).getCentralDirectory(),
        'local header offset past EOF'
      );
      expect(message).to.contain('central directory');
    });

    it('rejects a safe zip64 local header offset past the end of the file', async () => {
      const zipFile = buildZip(entries(), {
        mapCentralDirectoryRecord: (record, i) => {
          if (i === 0) {
            setU64(record, zip64ExtraOffsetField(record), 2n ** 40n);
          }
          return record;
        },
      });
      await expectInvalidFile(
        () => new ZipReader(fromBuffer(zipFile)).getCentralDirectory(),
        'zip64 local header offset past EOF'
      );
    });

    it('rejects a local header offset that does not point at a local header', async () => {
      const zipFile = buildZip(entries(), {
        zip64: false,
        mapCentralDirectoryRecord: (record, i) => {
          if (i === 1) {
            setU32(record, 42, 1);
          }
          return record;
        },
      });
      const message = await expectInvalidFile(
        () => new ZipReader(fromBuffer(zipFile)).getCentralDirectory(),
        'misaligned local header'
      );
      expect(message).to.contain('local file header');
    });

    it('rejects a compressed size past the end of the file', async () => {
      const zipFile = buildZip(entries(), {
        zip64: false,
        mapCentralDirectoryRecord: (record, i) => {
          if (i === 1) {
            // 20 - compressed size
            setU32(record, 20, 0x7fffffff);
          }
          return record;
        },
      });
      const message = await expectInvalidFile(
        () => new ZipReader(fromBuffer(zipFile)).getCentralDirectory(),
        'compressed size past EOF'
      );
      expect(message).to.contain('0.payload');
    });

    it('rejects a manifest size that runs into the central directory', async () => {
      const zipFile = buildZip(entries(), {
        zip64: false,
        mapCentralDirectoryRecord: (record, i) => {
          if (i === 0) {
            // 24 - uncompressed size; still under the manifest size limit.
            setU32(record, 24, 1024 * 1024);
          }
          return record;
        },
      });
      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      await expectInvalidFile(
        () => reader.getManifest(centralDirectory, '0.manifest.json'),
        'manifest past EOF'
      );
    });

    it('rejects a manifest that is not JSON', async () => {
      const zipFile = buildZip([{ name: '0.manifest.json', data: new Uint8Array([0x7b]) }]);
      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      await expectInvalidFile(
        () => reader.getManifest(centralDirectory, '0.manifest.json'),
        'manifest not JSON'
      );
    });

    it('rejects payload segments outside the payload entry', async () => {
      const reader = new ZipReader(fromBuffer(buildZip(entries())));
      const centralDirectory = await reader.getCentralDirectory();
      expect(await reader.getPayloadSegment(centralDirectory, '0.payload', 1, 4)).to.eql(
        payload.slice(1)
      );
      for (const [offset, size] of [
        [0, payload.length + 1],
        [payload.length, 1],
        [-1, 2],
        [0, -1],
        [0.5, 1],
        [2 ** 53, 1],
      ]) {
        await expectInvalidFile(
          () => reader.getPayloadSegment(centralDirectory, '0.payload', offset, size),
          `segment [${offset}, +${size})`
        );
      }
    });

    it('detects short reads from the source', async () => {
      const zipFile = buildZip(entries());
      const full = fromBuffer(zipFile);
      let truncate = false;
      const reader = new ZipReader(async (start, end) => {
        const chunk = await full(start, end);
        return truncate ? chunk.slice(0, chunk.length - 1) : chunk;
      });
      const centralDirectory = await reader.getCentralDirectory();
      truncate = true;
      const manifestMessage = await expectInvalidFile(
        () => reader.getManifest(centralDirectory, '0.manifest.json'),
        'short manifest read'
      );
      expect(manifestMessage).to.contain('read [');
      await expectInvalidFile(
        () => reader.getPayloadSegment(centralDirectory, '0.payload', 0, payload.length),
        'short payload read'
      );
      await expectInvalidFile(
        () => new ZipReader(reader.getChunk).getCentralDirectory(),
        'short tail read'
      );
    });

    it('detects a short local header read', async () => {
      const zipFile = buildZip(entries());
      const full = fromBuffer(zipFile);
      // Every read that starts at offset 0 (the first local header) comes back short.
      const reader = new ZipReader(async (start, end) => {
        const chunk = await full(start, end);
        return start === 0 ? chunk.slice(0, 10) : chunk;
      });
      await expectInvalidFile(() => reader.getCentralDirectory(), 'short local header read');
    });
  });

  // DSPX-4591 finding 2: the zip64 extra field is selected by the sentinel values,
  // not by its position in the extra field area nor by versionNeededToExtract.
  describe('zip64 extended information extra field', () => {
    it('is honoured when it is not the first extra field', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = true;
      const record = prependExtraField(
        zipWriter.writeCentralDirectoryRecord(
          2 ** 50,
          'Hey.txt',
          2000,
          0x1337,
          0x81a40000,
          FIXED_DATE
        ),
        // 0x5455 is the "extended timestamp" field; any non-zip64 field will do.
        0x5455,
        new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x00])
      );
      expect(parseCDBuffer(record)).to.deep.include({
        compressedSize: 2 ** 50,
        uncompressedSize: 2 ** 50,
        relativeOffsetOfLocalHeader: 2000,
        fileName: 'Hey.txt',
      });
    });

    it('is honoured in a full archive when it is not the first extra field', async () => {
      const manifest = { payload: { type: 'reference' } };
      const zipFile = buildZip(
        [
          { name: '0.manifest.json', data: manifestBytes(manifest) },
          { name: '0.payload', data: new Uint8Array([4, 5, 6]) },
        ],
        {
          mapCentralDirectoryRecord: (record) =>
            prependExtraField(record, 0x5455, new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x00])),
        }
      );
      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      expect(centralDirectory.map(({ fileName }) => fileName)).to.eql([
        '0.manifest.json',
        '0.payload',
      ]);
      expect(await reader.getManifest(centralDirectory, '0.manifest.json')).to.eql(manifest);
    });

    it('is honoured when versionNeededToExtract is below 45', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = true;
      const record = zipWriter.writeCentralDirectoryRecord(
        2 ** 50,
        'Hey.txt',
        2000,
        0x1337,
        0x81a40000,
        FIXED_DATE
      );
      // 6 - version needed to extract. Claim 2.0, keep the zip64 extra field.
      setU16(record, 6, 20);
      expect(parseCDBuffer(record)).to.deep.include({
        versionNeededToExtract: 20,
        compressedSize: 2 ** 50,
        uncompressedSize: 2 ** 50,
        relativeOffsetOfLocalHeader: 2000,
      });
    });
  });
});
