import { writeUInt32LE, writeUInt16LE, concatUint8 } from './index.js';

const CD_SIGNATURE = 0x02014b50;
const LOCAL_FILE_HEADER_FIXED_SIZE = 30;
const VERSION_NEEDED_TO_EXTRACT_UTF8 = 20;
const VERSION_NEEDED_TO_EXTRACT_ZIP64 = 45;
const FILE_NAME_IS_UTF8 = 1 << 11;
const UNKNOWN_CRC32_AND_FILE_SIZES = 1 << 3;

/*

{ versionMadeBy: 831,
    versionNeededToExtract: 20,
    generalPurposeBitFlag: 2048,
    compressionMethod: 0,
    lastModFileTime: 29443,
    lastModFileDate: 19762,
    crc32: 3735382831,
    compressedSize: 2583,
    uncompressedSize: 2583,
    fileNameLength: 15,
    extraFieldLength: 0,
    fileCommentLength: 0,
    internalFileAttributes: 0,
    externalFileAttributes: 2176057344,
    relativeOffsetOfLocalHeader: 0,
    fileName: '0.manifest.json',
    headerLength: 45 }


*/

const CENTRAL_DIRECTORY_RECORD_FIXED_SIZE = 46;
const ZIP64_EXTENDED_INFORMATION_EXTRA_FIELD_SIZE = 28;

// 3 = unix. 63 = spec version 6.3
const VERSION_MADE_BY = (3 << 8) | 63;

const NO_COMPRESSION = 0;

const DATA_DESCRIPTOR_SIZE = 16;
const ZIP64_DATA_DESCRIPTOR_SIZE = 24;

const END_OF_CENTRAL_DIRECTORY_RECORD_SIZE = 22;
const ZIP64_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE = 56;
const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE = 20;

// write a 64bit integer by writing 2 32bit integers
export function writeUInt64LE(buffer: Uint8Array, n: number, offset: number): void {
  if (!Number.isSafeInteger(n)) {
    throw new Error(`Unsafe number [${n}]`);
  }
  const high = Math.floor(n / 0x100000000);
  const low = n % 0x100000000;
  writeUInt32LE(buffer, low, offset);
  writeUInt32LE(buffer, high, offset + 4);
}

/**
 * Strangely encoded date/time found in FAT* file systems
 */
export type DosDateTime = {
  /**
   * The MS-DOS date. The date is a packed value with the following format.
   *  Bits    Description
   *  0-4     Day of the month (1–31)
   *  5-8     Month (1 = January, 2 = February, and so on)
   *  9-15    Year offset from 1980 (add 1980 to get actual year)
   */
  date: number;

  /**
   * The MS-DOS time. The time is a packed value with the following format.
   * Bits   Description
   * 0-4    Second divided by 2
   * 5-10   Minute (0–59)
   * 11-15  Hour (0–23 on a 24-hour clock)
   */
  time: number;
};

// MS-DOS 64 bit date/time fields, as described:
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime
export function dateToDosDateTime(jsDate: Date): DosDateTime {
  let date = 0;
  date |= jsDate.getDate() & 0x1f; // 1-31
  date |= ((jsDate.getMonth() + 1) & 0xf) << 5; // 0-11, 1-12
  date |= ((jsDate.getFullYear() - 1980) & 0x7f) << 9; // 0-128, 1980-2108

  let time = 0;
  time |= Math.floor(jsDate.getSeconds() / 2); // 0-59, 0-29 (lose odd numbers)
  time |= (jsDate.getMinutes() & 0x3f) << 5; // 0-59
  time |= (jsDate.getHours() & 0x1f) << 11; // 0-23

  return { date, time };
}

/**
 * Utilities for writing zip file structures.
 */
export class ZipWriter {
  zip64: boolean;
  constructor() {
    // Enable zip64
    this.zip64 = true;
  }

  getLocalFileHeader(
    utf8FileName: string,
    crc32: number,
    compressedSize: number,
    uncompressedSize: number,
    now = new Date()
  ) {
    const fixedSizeStuff = new Uint8Array(LOCAL_FILE_HEADER_FIXED_SIZE);
    let generalPurposeBitFlag = FILE_NAME_IS_UTF8;

    // we can't know the size in advance
    // TODO: this means we need to add a data descriptor!
    generalPurposeBitFlag |= UNKNOWN_CRC32_AND_FILE_SIZES;

    const dateModified = dateToDosDateTime(now);
    const filenameBuffer = new TextEncoder().encode(utf8FileName);

    // local file header signature     4 bytes  (0x04034b50)
    writeUInt32LE(fixedSizeStuff, 0x04034b50, 0);
    // version needed to extract       2 bytes
    writeUInt16LE(fixedSizeStuff, VERSION_NEEDED_TO_EXTRACT_UTF8, 4);
    // general purpose bit flag        2 bytes
    writeUInt16LE(fixedSizeStuff, generalPurposeBitFlag, 6);
    // compression method              2 bytes
    writeUInt16LE(fixedSizeStuff, NO_COMPRESSION, 8);
    // last mod file time              2 bytes
    writeUInt16LE(fixedSizeStuff, dateModified.time, 10);
    // last mod file date              2 bytes
    writeUInt16LE(fixedSizeStuff, dateModified.date, 12);
    // crc-32                          4 bytes
    writeUInt32LE(fixedSizeStuff, crc32, 14);
    // compressed size                 4 bytes
    writeUInt32LE(fixedSizeStuff, this.zip64 ? 0xffffffff : compressedSize, 18);
    // uncompressed size               4 bytes
    writeUInt32LE(fixedSizeStuff, this.zip64 ? 0xffffffff : uncompressedSize, 22);
    // file name length                2 bytes
    writeUInt16LE(fixedSizeStuff, filenameBuffer.length, 26);

    let zeiefBuffer = new Uint8Array(0);
    if (this.zip64) {
      // ZIP64 extended information extra field
      zeiefBuffer = new Uint8Array(ZIP64_EXTENDED_INFORMATION_EXTRA_FIELD_SIZE);
      // 0x0001                  2 bytes    Tag for this "extra" block type
      writeUInt16LE(zeiefBuffer, 0x0001, 0);
      // size                    2 bytes    Size of this "extra" block
      writeUInt16LE(zeiefBuffer, ZIP64_EXTENDED_INFORMATION_EXTRA_FIELD_SIZE - 4, 2);
      writeUInt64LE(zeiefBuffer, compressedSize, 4);
      writeUInt64LE(zeiefBuffer, uncompressedSize, 12);
      writeUInt64LE(zeiefBuffer, 0, 20);
    }

    // extra field length              2 bytes
    writeUInt16LE(fixedSizeStuff, zeiefBuffer.length, 28);

    return concatUint8([
      fixedSizeStuff,
      // file name (variable size)
      filenameBuffer,
      // extra field (variable size)
      zeiefBuffer,
    ]);
  }

  writeDataDescriptor(crc32: number, uncompressedSize: number): Uint8Array {
    // NOTE(PLAT-1134): optional signature (required according to Archive Utility)
    // 4.3.9.3 Although not originally assigned a signature, the value
    // 0x08074b50 has commonly been adopted as a signature value
    // for the data descriptor record.  Implementers should be
    // aware that ZIP files may be encountered with or without this
    // signature marking data descriptors and SHOULD account for
    // either case when reading ZIP files to ensure compatibility.
    const ddSig = 0x08074b50;

    let buffer: Uint8Array;
    if (this.zip64) {
      // 4.3.9.2 When compressing files, compressed and uncompressed sizes
      // SHOULD be stored in ZIP64 format (as 8 byte values) when a
      // file's size exceeds 0xFFFFFFFF.   However ZIP64 format MAY be
      // used regardless of the size of a file.  When extracting, if
      // the zip64 extended information extra field is present for
      // the file the compressed and uncompressed sizes will be 8
      // byte values.
      buffer = new Uint8Array(ZIP64_DATA_DESCRIPTOR_SIZE);
      writeUInt32LE(buffer, crc32, 4);
      writeUInt32LE(buffer, ddSig, 0);
      // We just use STORE, so compressed and uncompressed are the same.
      writeUInt64LE(buffer, uncompressedSize, 8);
      writeUInt64LE(buffer, uncompressedSize, 16);
    } else {
      buffer = new Uint8Array(DATA_DESCRIPTOR_SIZE);
      writeUInt32LE(buffer, ddSig, 0);
      writeUInt32LE(buffer, crc32, 4);
      writeUInt32LE(buffer, uncompressedSize, 8);
      writeUInt32LE(buffer, uncompressedSize, 12);
    }
    return buffer;
  }

  writeCentralDirectoryRecord(
    uncompressedSize: number,
    utf8FileName: string,
    relativeOffsetOfLocalHeader: number,
    crc32: number,
    externalFileAttributes: number,
    now = new Date()
  ): Uint8Array {
    const fixedSizeStuff = new Uint8Array(CENTRAL_DIRECTORY_RECORD_FIXED_SIZE);
    let generalPurposeBitFlag = FILE_NAME_IS_UTF8;

    // we can't know the size in advance
    // TODO: this means we need to add a data descriptor!
    generalPurposeBitFlag |= UNKNOWN_CRC32_AND_FILE_SIZES;

    let normalCompressedSize = uncompressedSize;
    let normalUncompressedSize = uncompressedSize;
    let normalRelativeOffsetOfLocalHeader = relativeOffsetOfLocalHeader;
    let versionNeededToExtract = VERSION_NEEDED_TO_EXTRACT_UTF8;
    let zeiefBuffer = new Uint8Array(0);

    if (this.zip64) {
      versionNeededToExtract = VERSION_NEEDED_TO_EXTRACT_ZIP64;
      normalCompressedSize = 0xffffffff;
      normalUncompressedSize = 0xffffffff;
      normalRelativeOffsetOfLocalHeader = 0xffffffff;

      // ZIP64 extended information extra field
      zeiefBuffer = new Uint8Array(ZIP64_EXTENDED_INFORMATION_EXTRA_FIELD_SIZE);
      // 0x0001                  2 bytes    Tag for this "extra" block type
      writeUInt16LE(zeiefBuffer, 0x0001, 0);
      // size                    2 bytes    Size of this "extra" block
      writeUInt16LE(zeiefBuffer, ZIP64_EXTENDED_INFORMATION_EXTRA_FIELD_SIZE - 4, 2);
      // uncompressed size       8 bytes    Original uncompressed file size
      writeUInt64LE(zeiefBuffer, uncompressedSize, 4);
      // compressed Size          8 bytes    Size of compressed data
      writeUInt64LE(zeiefBuffer, uncompressedSize, 12);
      // relative header offset  8 bytes    Offset of local header record
      writeUInt64LE(zeiefBuffer, relativeOffsetOfLocalHeader, 20);
      // Disk Start Number       4 bytes    Number of the disk on which this file starts
      // (omit)
      // console.log(`zeif Buffer ${utf8FileName}: ${zeiefBuffer.toString('hex')}`);
    }

    const dateModified = dateToDosDateTime(now);
    const filenameBuffer = new TextEncoder().encode(utf8FileName);

    // central file header signature   4 bytes  (0x02014b50)
    writeUInt32LE(fixedSizeStuff, CD_SIGNATURE, 0);
    // version made by                 2 bytes
    writeUInt16LE(fixedSizeStuff, VERSION_MADE_BY, 4);
    // version needed to extract       2 bytes
    writeUInt16LE(fixedSizeStuff, versionNeededToExtract, 6);
    // general purpose bit flag        2 bytes
    writeUInt16LE(fixedSizeStuff, generalPurposeBitFlag, 8);
    // compression method              2 bytes
    writeUInt16LE(fixedSizeStuff, NO_COMPRESSION, 10);
    // last mod file time              2 bytes
    writeUInt16LE(fixedSizeStuff, dateModified.time, 12);
    // last mod file date              2 bytes
    writeUInt16LE(fixedSizeStuff, dateModified.date, 14);
    // crc-32                          4 bytes
    writeUInt32LE(fixedSizeStuff, crc32, 16);
    // compressed size                 4 bytes
    writeUInt32LE(fixedSizeStuff, normalCompressedSize, 20);
    // uncompressed size               4 bytes
    writeUInt32LE(fixedSizeStuff, normalUncompressedSize, 24);
    // file name length                2 bytes
    writeUInt16LE(fixedSizeStuff, filenameBuffer.length, 28);
    // extra field length              2 bytes
    writeUInt16LE(fixedSizeStuff, zeiefBuffer.length, 30);
    // file comment length             2 bytes
    writeUInt16LE(fixedSizeStuff, 0, 32);
    // disk number start               2 bytes
    writeUInt16LE(fixedSizeStuff, 0, 34);
    // internal file attributes        2 bytes
    writeUInt16LE(fixedSizeStuff, 0, 36);
    // external file attributes        4 bytes
    writeUInt32LE(fixedSizeStuff, externalFileAttributes, 38);
    // relative offset of local header 4 bytes
    writeUInt32LE(fixedSizeStuff, normalRelativeOffsetOfLocalHeader, 42);

    return concatUint8([
      fixedSizeStuff,
      // file name (variable size)
      filenameBuffer,
      // extra field (variable size)
      zeiefBuffer,
      // file comment (variable size)
      // empty comment
    ]);
  }

  writeEndOfCentralDirectoryRecord(
    entriesLength: number,
    sizeOfCentralDirectory: number,
    offsetOfStartOfCentralDirectory: number
  ) {
    let normalEntriesLength = entriesLength;
    let normalSizeOfCentralDirectory = sizeOfCentralDirectory;
    let normalOffsetOfStartOfCentralDirectory = offsetOfStartOfCentralDirectory;
    if (this.zip64) {
      normalEntriesLength = 0xffff;
      normalSizeOfCentralDirectory = 0xffffffff;
      normalOffsetOfStartOfCentralDirectory = 0xffffffff;
    }
    const eocdrBuffer = new Uint8Array(END_OF_CENTRAL_DIRECTORY_RECORD_SIZE);
    // end of central dir signature                       4 bytes  (0x06054b50)
    writeUInt32LE(eocdrBuffer, 0x06054b50, 0);
    // number of this disk                                2 bytes
    writeUInt16LE(eocdrBuffer, 0, 4);
    // number of the disk with the start of the central directory  2 bytes
    writeUInt16LE(eocdrBuffer, 0, 6);
    // total number of entries in the central directory on this disk  2 bytes
    writeUInt16LE(eocdrBuffer, normalEntriesLength, 8);
    // total number of entries in the central directory   2 bytes
    writeUInt16LE(eocdrBuffer, normalEntriesLength, 10);
    // size of the central directory                      4 bytes
    writeUInt32LE(eocdrBuffer, normalSizeOfCentralDirectory, 12);
    // offset of start of central directory with respect to the starting disk number  4 bytes
    writeUInt32LE(eocdrBuffer, normalOffsetOfStartOfCentralDirectory, 16);
    // .ZIP file comment length                           2 bytes
    writeUInt16LE(eocdrBuffer, 0, 20);
    // .ZIP file comment                                  (variable size)
    // no comment

    if (!this.zip64) {
      return eocdrBuffer;
    }

    // ZIP64 format
    // ZIP64 End of Central Directory Record
    const zip64EocdrBuffer = new Uint8Array(ZIP64_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE);
    // zip64 end of central dir signature                                             4 bytes  (0x06064b50)
    writeUInt32LE(zip64EocdrBuffer, 0x06064b50, 0);
    // size of zip64 end of central directory record                                  8 bytes
    writeUInt64LE(zip64EocdrBuffer, ZIP64_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE - 12, 4);
    // version made by                                                                2 bytes
    writeUInt16LE(zip64EocdrBuffer, VERSION_MADE_BY, 12);
    // version needed to extract                                                      2 bytes
    writeUInt16LE(zip64EocdrBuffer, VERSION_NEEDED_TO_EXTRACT_ZIP64, 14);
    // number of this disk                                                            4 bytes
    writeUInt32LE(zip64EocdrBuffer, 0, 16);
    // number of the disk with the start of the central directory                     4 bytes
    writeUInt32LE(zip64EocdrBuffer, 0, 20);
    // total number of entries in the central directory on this disk                  8 bytes
    writeUInt64LE(zip64EocdrBuffer, entriesLength, 24);
    // total number of entries in the central directory                               8 bytes
    writeUInt64LE(zip64EocdrBuffer, entriesLength, 32);
    // size of the central directory                                                  8 bytes
    writeUInt64LE(zip64EocdrBuffer, sizeOfCentralDirectory, 40);
    // offset of start of central directory with respect to the starting disk number  8 bytes
    writeUInt64LE(zip64EocdrBuffer, offsetOfStartOfCentralDirectory, 48);
    // zip64 extensible data sector                                                   (variable size)
    // nothing in the zip64 extensible data sector

    // ZIP64 End of Central Directory Locator
    const zip64EocdlBuffer = new Uint8Array(ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE);
    // zip64 end of central dir locator signature                               4 bytes  (0x07064b50)
    writeUInt32LE(zip64EocdlBuffer, 0x07064b50, 0);
    // number of the disk with the start of the zip64 end of central directory  4 bytes
    writeUInt32LE(zip64EocdlBuffer, 0, 4);
    // relative offset of the zip64 end of central directory record             8 bytes
    writeUInt64LE(zip64EocdlBuffer, offsetOfStartOfCentralDirectory + sizeOfCentralDirectory, 8);
    // total number of disks                                                    4 bytes
    writeUInt32LE(zip64EocdlBuffer, 1, 16);

    return concatUint8([zip64EocdrBuffer, zip64EocdlBuffer, eocdrBuffer]);
  }
}
