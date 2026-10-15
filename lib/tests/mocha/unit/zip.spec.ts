import { expect } from 'chai';
import sinon from 'sinon';

import { InvalidFileError } from '../../../src/errors.js';
import { encodeArrayBuffer } from '../../../src/encodings/base64.js';
import { fromBuffer, fromUrl } from '../../../src/seekable.js';
import type { CentralDirectory } from '../../../tdf3/src/utils/zip-reader.js';
import { parseCDBuffer, readUInt64LE, ZipReader } from '../../../tdf3/src/utils/zip-reader.js';
import { ZipWriter, dateToDosDateTime, writeUInt64LE } from '../../../tdf3/src/utils/zip-writer.js';

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

function u32(buf: Uint8Array, offset: number): number {
  return (u16(buf, offset) + u16(buf, offset + 2) * 0x10000) >>> 0;
}

/** Size of the end of central directory record when the archive has no comment. */
const EOCD_SIZE = 22;
/** Size of the zip64 end of central directory locator. */
const ZIP64_LOCATOR_SIZE = 20;
/** Size of the zip64 end of central directory record as written by ZipWriter. */
const ZIP64_EOCD_RECORD_SIZE = 56;
/** Bytes ZipWriter appends after the central directory in a comment-less zip64 archive. */
const ZIP64_TRAILER_SIZE = ZIP64_EOCD_RECORD_SIZE + ZIP64_LOCATOR_SIZE + EOCD_SIZE;

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

/** Asserts that reading the central directory of `zipFile` fails with `expected` in the message. */
async function expectCentralDirectoryRejected(zipFile: Uint8Array, expected: string) {
  const reader = new ZipReader(fromBuffer(zipFile));
  let error: unknown;
  try {
    await reader.getCentralDirectory();
  } catch (e) {
    error = e;
  }
  expect(error, 'expected getCentralDirectory to reject').to.exist;
  expect(messageOf(error)).to.contain(expected);
}

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
      expect(() => readUInt64LE(b0, 0)).to.throw(InvalidFileError, /exceeds/);
    });
    it('0xffffffffffffffff throws InvalidFileError', () => {
      const b0 = new Uint8Array(8).fill(0xff);
      expect(() => readUInt64LE(b0, 0)).to.throw(InvalidFileError, /exceeds/);
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

    for (const zip64 of [false, true]) {
      it(`can read a ${zip64 ? 'zip64' : 'non-zip64'} central directory twice`, async () => {
        const zipFile = buildZip([{ name: '0.manifest.json', data: manifestBytes(manifest) }], {
          zip64,
        });
        const reader = new ZipReader(fromBuffer(zipFile));
        expect(await reader.getCentralDirectory()).to.eql(await reader.getCentralDirectory());
      });
    }

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
      // A complete fake EOCD record (all counts zero) at the start of a 40 byte
      // comment. It sits more than 22 bytes from the end, so the backward scan
      // reaches it before the real record; only its comment length (999, which
      // does not land on the end of the archive) tells the reader to skip it.
      const fakeEocd = new Uint8Array(EOCD_SIZE);
      fakeEocd.set(EOCD_SIGNATURE_BYTES, 0);
      setU16(fakeEocd, 20, 999);
      const comment = concat([fakeEocd, new Uint8Array(18).fill(0x2e)]);
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

    // DSPX-4591 finding 1 (post-review): a comment long enough to push the
    // zip64 locator out of the initial 1 KiB tail read, but not so long that
    // the EOCD itself is missed, used to be rejected as "no zip64 locator was
    // found" even though the locator is present in the file.
    it('reads a zip64 archive whose comment pushes the zip64 locator out of the initial tail read', async () => {
      const comment = new Uint8Array(990).fill(0x2e);
      const zipFile = buildZip([{ name: '0.manifest.json', data: manifestBytes(manifest) }], {
        comment,
      });
      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      expect(centralDirectory.map(({ fileName }) => fileName)).to.eql(['0.manifest.json']);
      expect(await reader.getManifest(centralDirectory, '0.manifest.json')).to.eql(manifest);
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
      // Drop the zip64 EOCD record, zip64 locator and EOCD record entirely.
      const truncated = zipFile.slice(0, zipFile.length - ZIP64_TRAILER_SIZE);
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
      zipFile[zipFile.length - EOCD_SIZE - ZIP64_LOCATOR_SIZE] ^= 0xff;
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

    // DSPX-4591 finding 2 (post-review): a zip64 archive entry that carries the
    // 0xffffffff sentinel but has no zip64 extended information extra field to
    // resolve it must be rejected, not silently used as a literal offset/size.
    it('rejects a zip64 archive whose entry sentinel has no zip64 extra field', async () => {
      const zipFile = buildZip(
        [
          { name: '0.manifest.json', data: manifestBytes(manifest) },
          { name: '0.payload', data: new Uint8Array([1, 2, 3]) },
        ],
        {
          mapCentralDirectoryRecord: (record, index) => {
            if (index !== 1) {
              return record;
            }
            // Strip the zip64 extended information extra field, leaving the
            // 0xffffffff sentinels already in the fixed-size fields unresolved.
            const fileNameLength = u16(record, 28);
            const stripped = record.slice(0, 46 + fileNameLength);
            setU16(stripped, 30, 0);
            return stripped;
          },
        }
      );
      const reader = new ZipReader(fromBuffer(zipFile));
      let message = '';
      try {
        await reader.getCentralDirectory();
        expect.fail('expected getCentralDirectory to reject the malformed entry');
      } catch (e) {
        message = messageOf(e);
      }
      expect(message).to.contain('zip64');
    });

    it('rejects an end of central directory record that overstates the entry count', async () => {
      const zipFile = buildZip(
        [
          { name: '0.manifest.json', data: manifestBytes(manifest) },
          { name: '0.payload', data: new Uint8Array([1, 2, 3]) },
        ],
        { zip64: false }
      );
      // 22 byte EOCD at the end: entry counts live at offsets 8 and 10. The
      // declared CD size (two records) is now too small for three records.
      const eocdStart = zipFile.length - EOCD_SIZE;
      setU16(zipFile, eocdStart + 8, 3);
      setU16(zipFile, eocdStart + 10, 3);
      await expectCentralDirectoryRejected(zipFile, 'too small for [3] entries');
    });

    describe('rejects a malformed archive', () => {
      const twoEntries = () => [
        { name: '0.manifest.json', data: manifestBytes(manifest) },
        { name: '0.payload', data: new Uint8Array([1, 2, 3]) },
      ];
      const zip32 = () => buildZip(twoEntries(), { zip64: false });
      const zip64 = () => buildZip(twoEntries());
      // Field offsets within the 32 bit EOCD record and the zip64 EOCD record.
      const eocdStart = (zipFile: Uint8Array) => zipFile.length - EOCD_SIZE;
      const zip64RecordStart = (zipFile: Uint8Array) => zipFile.length - ZIP64_TRAILER_SIZE;
      const zip64LocatorStart = (zipFile: Uint8Array) =>
        zipFile.length - EOCD_SIZE - ZIP64_LOCATOR_SIZE;

      it('when the central directory runs past the end of the file', async () => {
        const zipFile = zip32();
        // 16 - offset of start of central directory
        setU32(zipFile, eocdStart(zipFile) + 16, zipFile.length);
        await expectCentralDirectoryRejected(zipFile, 'central directory truncated');
      });

      it('when the declared central directory exceeds the size bound', async () => {
        const zipFile = zip32();
        // 12 - size of the central directory. Not 0xffffffff, which would mean zip64.
        setU32(zipFile, eocdStart(zipFile) + 12, 16 * 1024 * 1024 + 1);
        await expectCentralDirectoryRejected(zipFile, 'central directory too large');
      });

      it('when the zip64 central directory exceeds the size bound', async () => {
        const zipFile = zip64();
        // 40 - size of the central directory (8 bytes)
        writeUInt64LE(zipFile, 2 ** 40, zip64RecordStart(zipFile) + 40);
        await expectCentralDirectoryRejected(zipFile, 'central directory too large');
      });

      it('when a zip64 end of central directory field exceeds MAX_SAFE_INTEGER', async () => {
        const zipFile = zip64();
        // 40 - size of the central directory (8 bytes): 2^60 in the high word.
        setU32(zipFile, zip64RecordStart(zipFile) + 44, 0x10000000);
        const reader = new ZipReader(fromBuffer(zipFile));
        let error: unknown;
        try {
          await reader.getCentralDirectory();
        } catch (e) {
          error = e;
        }
        expect(error).to.be.instanceOf(InvalidFileError);
        expect(messageOf(error)).to.contain('exceeds MAX_SAFE_INTEGER');
      });

      it('when the zip64 end of central directory record signature is wrong', async () => {
        const zipFile = zip64();
        zipFile[zip64RecordStart(zipFile)] ^= 0xff;
        await expectCentralDirectoryRejected(
          zipFile,
          'invalid zip64 end of central directory record'
        );
      });

      it('when the zip64 locator points past the end of the file', async () => {
        const zipFile = zip64();
        // 8 - relative offset of the zip64 end of central directory record (8 bytes)
        writeUInt64LE(zipFile, zipFile.length, zip64LocatorStart(zipFile) + 8);
        await expectCentralDirectoryRejected(
          zipFile,
          'zip64 end of central directory record truncated'
        );
      });

      it('when the central directory offset does not land on a record', async () => {
        const zipFile = zip32();
        const at = eocdStart(zipFile) + 16;
        setU32(zipFile, at, u32(zipFile, at) + 1);
        await expectCentralDirectoryRejected(
          zipFile,
          'invalid central directory file header signature for entry [0]'
        );
      });

      it('when a record overruns the central directory', async () => {
        const zipFile = buildZip(twoEntries(), {
          mapCentralDirectoryRecord: (record, index) => {
            if (index === 1) {
              // 32 - file comment length, with no comment bytes actually present.
              setU16(record, 32, 100);
            }
            return record;
          },
        });
        await expectCentralDirectoryRejected(zipFile, 'central directory record [1] of length');
      });

      it('when the central directory ends before the declared entry count', async () => {
        const zipFile = zip32();
        const eocd = eocdStart(zipFile);
        setU16(zipFile, eocd + 8, 3);
        setU16(zipFile, eocd + 10, 3);
        // Widen the declared size to cover the EOCD that follows, so it is large
        // enough for three records and still lies inside the file.
        const centralDirectorySize = u32(zipFile, eocd + 12) + EOCD_SIZE;
        expect(centralDirectorySize).to.be.at.least(3 * 46);
        setU32(zipFile, eocd + 12, centralDirectorySize);
        await expectCentralDirectoryRejected(
          zipFile,
          'central directory ended early: found [2] of [3]'
        );
      });
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

    it('rejects remote EOCD offsets past EOF before requesting them', async () => {
      const zipFile = buildZip(entries(), { zip64: false });
      setU32(zipFile, zipFile.length - EOCD_SIZE + 16, 0x7fffffff);
      const ranges: string[] = [];
      const fetchStub = sinon.stub(globalThis, 'fetch').callsFake((_input, init) => {
        ranges.push(new Headers(init?.headers).get('Range') ?? '');
        return Promise.resolve(
          new Response(new Uint8Array(zipFile), {
            status: 206,
            headers: { 'Content-Range': `bytes 0-${zipFile.length - 1}/${zipFile.length}` },
          })
        );
      });
      try {
        const reader = new ZipReader(await fromUrl('https://example.test/archive.tdf'));
        await expectInvalidFile(() => reader.getCentralDirectory(), 'remote EOCD offset');
        expect(ranges).to.eql(['bytes=-1024']);
      } finally {
        fetchStub.restore();
      }
    });

    it('rejects remote zip64 locator offsets past EOF before requesting them', async () => {
      const zipFile = buildZip(entries());
      setU64(zipFile, zipFile.length - EOCD_SIZE - ZIP64_LOCATOR_SIZE + 8, 2n ** 40n);
      const ranges: string[] = [];
      const fetchStub = sinon.stub(globalThis, 'fetch').callsFake((_input, init) => {
        ranges.push(new Headers(init?.headers).get('Range') ?? '');
        return Promise.resolve(
          new Response(new Uint8Array(zipFile), {
            status: 206,
            headers: { 'Content-Range': `bytes 0-${zipFile.length - 1}/${zipFile.length}` },
          })
        );
      });
      try {
        const reader = new ZipReader(await fromUrl('https://example.test/archive.tdf'));
        await expectInvalidFile(() => reader.getCentralDirectory(), 'remote zip64 locator offset');
        expect(ranges).to.eql(['bytes=-1024']);
      } finally {
        fetchStub.restore();
      }
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
            // 20 - compressed size, 24 - uncompressed size
            setU32(record, 20, 0x7fffffff);
            setU32(record, 24, 0x7fffffff);
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
            // 20 - compressed size, 24 - uncompressed size; still under the
            // manifest size limit.
            setU32(record, 20, 1024 * 1024);
            setU32(record, 24, 1024 * 1024);
          }
          return record;
        },
      });
      const message = await expectInvalidFile(
        () => new ZipReader(fromBuffer(zipFile)).getCentralDirectory(),
        'manifest past EOF'
      );
      expect(message).to.contain('0.manifest.json');
    });

    it('rejects a manifest read that runs into the central directory', async () => {
      const zipFile = buildZip(entries(), { zip64: false });
      const reader = new ZipReader(fromBuffer(zipFile));
      const centralDirectory = await reader.getCentralDirectory();
      const [manifestRecord] = centralDirectory;
      const message = await expectInvalidFile(
        () =>
          reader.getManifest(
            [{ ...manifestRecord, uncompressedSize: 1024 * 1024 }],
            '0.manifest.json'
          ),
        'manifest read past the central directory'
      );
      expect(message).to.contain('central directory');
    });

    for (const zip64 of [false, true]) {
      it(`rejects ${zip64 ? 'zip64' : 'non-zip64'} sizes that disagree for a stored entry`, async () => {
        const zipFile = buildZip(entries(), {
          zip64,
          mapCentralDirectoryRecord: (record, i) => {
            if (i === 0) {
              if (zip64) {
                // zip64 extra field data: uncompressed size (8), compressed size (8)
                setU64(record, zip64ExtraOffsetField(record) - 16, 1024n * 1024n);
              } else {
                // 24 - uncompressed size
                setU32(record, 24, 1024 * 1024);
              }
            }
            return record;
          },
        });
        const message = await expectInvalidFile(
          () => new ZipReader(fromBuffer(zipFile)).getCentralDirectory(),
          'size mismatch'
        );
        expect(message).to.contain('uncompressed size [1048576]');
      });
    }

    it('rejects a compressed entry', async () => {
      const zipFile = buildZip(entries(), {
        zip64: false,
        mapCentralDirectoryRecord: (record, i) => {
          if (i === 1) {
            // 10 - compression method; 8 is deflate
            setU16(record, 10, 8);
          }
          return record;
        },
      });
      const message = await expectInvalidFile(
        () => new ZipReader(fromBuffer(zipFile)).getCentralDirectory(),
        'deflated entry'
      );
      expect(message).to.contain('compression method [8]');
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

    for (const json of ['null', '42', '"manifest"', '[]']) {
      it(`rejects a manifest that is ${json} rather than an object`, async () => {
        const zipFile = buildZip([
          { name: '0.manifest.json', data: new TextEncoder().encode(json) },
        ]);
        const reader = new ZipReader(fromBuffer(zipFile));
        const centralDirectory = await reader.getCentralDirectory();
        const message = await expectInvalidFile(
          () => reader.getManifest(centralDirectory, '0.manifest.json'),
          `manifest ${json}`
        );
        expect(message).to.contain('not a JSON object');
      });
    }

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

    // DSPX-4591 finding 2 (post-review): an unresolved sentinel is only an
    // error in a zip64 archive. A non-zip64 archive may legitimately carry a
    // literal 0xffffffff size, and zip-writer.ts writes caller-provided sizes
    // directly when zip64 mode is disabled.
    it('rejects an unresolved sentinel only when the archive is zip64', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = true;
      const record = zipWriter.writeCentralDirectoryRecord(
        2 ** 40,
        'Hey.txt',
        2000,
        0x1337,
        0x81a40000,
        FIXED_DATE
      );
      // Strip the zip64 extended information extra field, leaving the
      // 0xffffffff sentinels already written into the fixed-size fields
      // unresolved.
      const fileNameLength = u16(record, 28);
      const stripped = record.slice(0, 46 + fileNameLength);
      setU16(stripped, 30, 0);

      expect(() => parseCDBuffer(stripped, true)).to.throw(/zip64/i);
      expect(() => parseCDBuffer(stripped, false)).to.not.throw();
      expect(() => parseCDBuffer(stripped)).to.not.throw();
    });

    it('rejects an unresolved sentinel when the extra field lacks a 0x0001 tag', () => {
      const zipWriter = new ZipWriter();
      zipWriter.zip64 = true;
      const full = zipWriter.writeCentralDirectoryRecord(
        2 ** 40,
        'Hey.txt',
        2000,
        0x1337,
        0x81a40000,
        FIXED_DATE
      );
      // Drop the zip64 extra field, leaving the sentinels unresolved, then add
      // back an unrelated extra field so extraFieldLength is nonzero.
      const fileNameLength = u16(full, 28);
      const stripped = full.slice(0, 46 + fileNameLength);
      setU16(stripped, 30, 0);
      const record = prependExtraField(
        stripped,
        // 0x5455 is the "extended timestamp" field; any non-zip64 field will do.
        0x5455,
        new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x00])
      );

      expect(() => parseCDBuffer(record, true)).to.throw(/zip64/i);
      expect(() => parseCDBuffer(record, false)).to.not.throw();
    });
  });

  describe('parseCDBuffer', () => {
    const record = () =>
      new ZipWriter().writeCentralDirectoryRecord(3, 'a.txt', 0, 0, 0x81a40000, FIXED_DATE);

    it('rejects a record shorter than the fixed header', () => {
      expect(() => parseCDBuffer(record().slice(0, 45))).to.throw(
        /Truncated central directory file header/
      );
    });

    it('rejects a record with the wrong signature', () => {
      const bad = record();
      bad[0] ^= 0xff;
      expect(() => parseCDBuffer(bad)).to.throw(/Invalid central directory file header signature/);
    });
  });
});
