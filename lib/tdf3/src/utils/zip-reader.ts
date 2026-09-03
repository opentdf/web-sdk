import { InvalidFileError } from '../../../src/errors.js';
import { type Chunker } from '../../../src/seekable.js';
import { Manifest } from '../models/index.js';
import { readUInt32LE, readUInt16LE, copyUint8Arr, buffToString } from './index.js';

// Signatures and fixed record sizes from PKWARE APPNOTE.TXT sections 4.3.12-4.3.16.
/** Central file header signature (APPNOTE 4.3.12). */
const CD_SIGNATURE = 0x02014b50;
/** End of central directory record signature (APPNOTE 4.3.16). */
const EOCDR_SIGNATURE = 0x06054b50;
/** ZIP64 end of central directory record signature (APPNOTE 4.3.14). */
const ZIP64_EOCDR_SIGNATURE = 0x06064b50;
/** ZIP64 end of central directory locator signature (APPNOTE 4.3.15). */
const ZIP64_EOCDL_SIGNATURE = 0x07064b50;

/** Size of a central file header, excluding name, extra field and comment. */
const CENTRAL_DIRECTORY_RECORD_FIXED_SIZE = 46;
/** Size of a local file header, excluding name and extra field. */
const LOCAL_FILE_HEADER_FIXED_SIZE = 30;
/** Size of an end of central directory record, excluding the archive comment. */
const END_OF_CENTRAL_DIRECTORY_RECORD_SIZE = 22;
/** Size of a ZIP64 end of central directory locator. Fixed length. */
const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE = 20;
/** Bytes of the ZIP64 end of central directory record that we read and rely on. */
const ZIP64_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE = 56;

/** The archive comment length field is 2 bytes, so a comment is at most 64 KiB. */
const MAX_ARCHIVE_COMMENT_SIZE = 0xffff;
/**
 * Enough bytes to always contain the EOCD record, its (optional) ZIP64 locator,
 * and a maximum length archive comment.
 */
const MAX_EOCDR_SEARCH_SIZE =
  END_OF_CENTRAL_DIRECTORY_RECORD_SIZE +
  MAX_ARCHIVE_COMMENT_SIZE +
  ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE;
/**
 * First guess at how much of the tail to read. TDF containers are written without
 * an archive comment, so the EOCD is the last 22 bytes and one small read suffices.
 * If the EOCD is not in here we fall back to {@link MAX_EOCDR_SEARCH_SIZE}.
 */
const INITIAL_EOCDR_SEARCH_SIZE = 1024;

/**
 * Sanity bound on the central directory we are willing to buffer. At 46 bytes per
 * record this still allows for hundreds of thousands of entries, while keeping a
 * hostile or corrupt EOCD from asking us to allocate the declared 4 GiB.
 */
const MAX_CENTRAL_DIRECTORY_SIZE = 16 * 1024 * 1024;

const manifestMaxSize = 1024 * 1024 * 10; // 10 MB

const cp437 =
  '\u0000☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨↑↓→←∟↔▲▼ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~⌂ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ';

export type CentralDirectory = CentralDirectoryFixedLengthPrefix &
  CentralDirectoryVariableLengthItems;
export type CentralDirectoryFixedLengthPrefix = {
  // Version set at creation time
  versionMadeBy: number;
  // Version needed to extract (minimum)
  versionNeededToExtract: number;
  // General purpose bit flag
  generalPurposeBitFlag: number;
  // Compression method
  compressionMethod: number;
  // File last modification time
  lastModFileTime: number;
  // File last modification date
  lastModFileDate: number;
  // CRC-32
  crc32: number;
  // Compressed size
  compressedSize: number;
  // Uncompressed size
  uncompressedSize: number;
  // File name length (n)
  fileNameLength: number;
  // Extra field length (m)
  extraFieldLength: number;
  // File comment length (k)
  fileCommentLength: number;
  // Internal file attributes
  internalFileAttributes: number;
  // External file attributes
  externalFileAttributes: number;
  // Relative offset of local file header
  relativeOffsetOfLocalHeader: number;
};
export type CentralDirectoryVariableLengthItems = {
  fileName: string;
  headerLength: number;
};

/**
 * The parts of the end of central directory record (APPNOTE 4.3.16), with the
 * ZIP64 end of central directory record (APPNOTE 4.3.14) already applied where
 * the 32 bit record carried a sentinel value.
 */
export type EndOfCentralDirectory = {
  /** Total number of central directory records. */
  entryCount: number;
  /** Size in bytes of the central directory. */
  centralDirectorySize: number;
  /** Offset of the first central directory record from the start of the archive. */
  centralDirectoryOffset: number;
  /** True if the values above were read from a ZIP64 end of central directory record. */
  zip64: boolean;
};

/**
 *
 * ZipReader -
 *
 * This class is used to extract parts of a TDF. You may pull bytes of a given range from a
 * or request specific important chunks like the 'manifest', or 'payload'.
 */
export class ZipReader {
  getChunk: Chunker;

  constructor(getChunk: Chunker) {
    this.getChunk = getChunk;
  }

  /**
   * Utility function to get the centralDirectory for the zip file.
   *
   * Reads the end of central directory record (following the ZIP64 locator when
   * the EOCD carries a sentinel), then walks exactly the declared number of
   * records starting at the declared central directory offset.
   *
   * @return The central directory represented as an object
   */
  async getCentralDirectory(): Promise<CentralDirectory[]> {
    const eocd = await this.getEndOfCentralDirectory();
    const cdChunk = await this.getChunk(
      eocd.centralDirectoryOffset,
      eocd.centralDirectoryOffset + eocd.centralDirectorySize
    );
    if (cdChunk.length !== eocd.centralDirectorySize) {
      throw new InvalidFileError(
        `central directory truncated: expected [${eocd.centralDirectorySize}] bytes at [${eocd.centralDirectoryOffset}], read [${cdChunk.length}]`
      );
    }

    const cdParsedBuffers = this.getCDBuffers(cdChunk, eocd.entryCount).map(parseCDBuffer);
    for (const buffer of cdParsedBuffers) {
      await this.adjustHeaders(buffer);
    }
    return cdParsedBuffers;
  }

  /**
   * Locates and parses the end of central directory record, resolving it against
   * the ZIP64 end of central directory record when any of the three EOCD fields
   * carries its sentinel value (APPNOTE 4.3.14 - 4.3.16).
   */
  async getEndOfCentralDirectory(): Promise<EndOfCentralDirectory> {
    let tail = await this.getChunk(-INITIAL_EOCDR_SEARCH_SIZE);
    let eocdrOffset = findEndOfCentralDirectoryRecord(tail);
    if (eocdrOffset < 0 && tail.length >= INITIAL_EOCDR_SEARCH_SIZE) {
      // The archive may carry a comment of up to 64 KiB; widen the search once.
      tail = await this.getChunk(-MAX_EOCDR_SEARCH_SIZE);
      eocdrOffset = findEndOfCentralDirectoryRecord(tail);
    }
    if (eocdrOffset < 0) {
      throw new InvalidFileError('unable to find end of central directory record');
    }

    // 8 - total number of entries in the central directory on this disk (2 bytes)
    // 10 - total number of entries in the central directory (2 bytes)
    let entryCount = readUInt16LE(tail, eocdrOffset + 10);
    // 12 - size of the central directory (4 bytes)
    let centralDirectorySize = readUInt32LE(tail, eocdrOffset + 12);
    // 16 - offset of start of central directory (4 bytes)
    let centralDirectoryOffset = readUInt32LE(tail, eocdrOffset + 16);

    const needsZip64 =
      entryCount === 0xffff ||
      centralDirectorySize === 0xffffffff ||
      centralDirectoryOffset === 0xffffffff;
    if (needsZip64) {
      const zip64 = await this.getZip64EndOfCentralDirectory(tail, eocdrOffset);
      ({ entryCount, centralDirectorySize, centralDirectoryOffset } = zip64);
    }

    if (centralDirectorySize > MAX_CENTRAL_DIRECTORY_SIZE) {
      throw new InvalidFileError(
        `central directory too large: [${centralDirectorySize}] bytes exceeds [${MAX_CENTRAL_DIRECTORY_SIZE}]`
      );
    }
    if (centralDirectorySize < entryCount * CENTRAL_DIRECTORY_RECORD_FIXED_SIZE) {
      throw new InvalidFileError(
        `central directory size [${centralDirectorySize}] too small for [${entryCount}] entries`
      );
    }

    return { entryCount, centralDirectorySize, centralDirectoryOffset, zip64: needsZip64 };
  }

  /**
   * Follows the ZIP64 end of central directory locator, which sits immediately
   * before the EOCD record, and reads the ZIP64 EOCD record it points at.
   */
  private async getZip64EndOfCentralDirectory(
    tail: Uint8Array,
    eocdrOffset: number
  ): Promise<Omit<EndOfCentralDirectory, 'zip64'>> {
    const locatorOffset = eocdrOffset - ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE;
    if (locatorOffset < 0 || readUInt32LE(tail, locatorOffset) !== ZIP64_EOCDL_SIGNATURE) {
      throw new InvalidFileError(
        'end of central directory record requires zip64, but no zip64 locator was found'
      );
    }
    // 8 - relative offset of the zip64 end of central directory record (8 bytes)
    const zip64EocdrOffset = readUInt64LE(tail, locatorOffset + 8);
    const record = await this.getChunk(
      zip64EocdrOffset,
      zip64EocdrOffset + ZIP64_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE
    );
    if (
      record.length < ZIP64_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE ||
      readUInt32LE(record, 0) !== ZIP64_EOCDR_SIGNATURE
    ) {
      throw new InvalidFileError(
        `invalid zip64 end of central directory record at [${zip64EocdrOffset}]`
      );
    }
    return {
      // 32 - total number of entries in the central directory (8 bytes)
      entryCount: readUInt64LE(record, 32),
      // 40 - size of the central directory (8 bytes)
      centralDirectorySize: readUInt64LE(record, 40),
      // 48 - offset of start of central directory (8 bytes)
      centralDirectoryOffset: readUInt64LE(record, 48),
    };
  }

  /**
   * Gets the manifest
   * @returns The manifest as a buffer represented as JSON
   */
  async getManifest(cdBuffers: CentralDirectory[], manifestFileName: string): Promise<Manifest> {
    const cdObj = cdBuffers.find(({ fileName }) => fileName === manifestFileName);
    if (!cdObj) {
      throw new InvalidFileError('Unable to retrieve CD manifest');
    }
    const byteStart = cdObj.relativeOffsetOfLocalHeader + cdObj.headerLength;
    if (cdObj.uncompressedSize > manifestMaxSize) {
      throw new InvalidFileError(
        `manifest file too large: ${Math.floor(cdObj.uncompressedSize / 1024).toLocaleString()} KiB`
      );
    }
    const byteEnd = byteStart + cdObj.uncompressedSize;
    const manifest = await this.getChunk(byteStart, byteEnd);

    return JSON.parse(new TextDecoder().decode(manifest));
  }

  async adjustHeaders(cdObj: CentralDirectory): Promise<void> {
    if (!cdObj) {
      throw new InvalidFileError('Unable to retrieve CD adjust');
    }
    // Calculate header length -- tdf3-js writes 0 in all the header fields
    // and does not include extra field for zip64
    const headerChunk = await this.getChunk(
      cdObj.relativeOffsetOfLocalHeader,
      cdObj.relativeOffsetOfLocalHeader + cdObj.headerLength
    );
    cdObj.headerLength = recalculateHeaderLength(headerChunk);
  }

  async getPayloadSegment(
    cdBuffers: CentralDirectory[],
    payloadName: string,
    encrpytedSegmentOffset: number,
    encryptedSegmentSize: number
  ): Promise<Uint8Array> {
    const cdObj = cdBuffers.find(({ fileName }) => payloadName === fileName);
    if (!cdObj) {
      throw new InvalidFileError('Unable to retrieve CD');
    }
    const byteStart =
      cdObj.relativeOffsetOfLocalHeader + cdObj.headerLength + encrpytedSegmentOffset;
    // TODO: what's the exact byte start?
    const byteEnd = byteStart + encryptedSegmentSize;
    return this.getChunk(byteStart, byteEnd);
  }

  /**
   * Splits the central directory into its individual records.
   *
   * Boundaries come from each record's own declared name, extra field and comment
   * lengths - not from scanning for the next signature - and exactly `entryCount`
   * records are read, as declared by the end of central directory record.
   *
   * @param cdChunk the central directory, starting at its first record
   * @param entryCount the number of records the EOCD says are present
   * @returns an array of typed arrays, each element corresponding to a central directory record
   */
  getCDBuffers(cdChunk: Uint8Array, entryCount: number): Uint8Array[] {
    const cdBuffers: Uint8Array[] = [];
    let offset = 0;
    for (let i = 0; i < entryCount; i++) {
      if (offset + CENTRAL_DIRECTORY_RECORD_FIXED_SIZE > cdChunk.length) {
        throw new InvalidFileError(
          `central directory ended early: found [${i}] of [${entryCount}] declared entries`
        );
      }
      if (readUInt32LE(cdChunk, offset) !== CD_SIGNATURE) {
        throw new InvalidFileError(
          `invalid central directory file header signature for entry [${i}]`
        );
      }
      // 28 - file name length (n), 30 - extra field length (m), 32 - file comment length (k)
      const fileNameLength = readUInt16LE(cdChunk, offset + 28);
      const extraFieldLength = readUInt16LE(cdChunk, offset + 30);
      const fileCommentLength = readUInt16LE(cdChunk, offset + 32);
      const recordLength =
        CENTRAL_DIRECTORY_RECORD_FIXED_SIZE + fileNameLength + extraFieldLength + fileCommentLength;
      if (offset + recordLength > cdChunk.length) {
        throw new InvalidFileError(
          `central directory record [${i}] of length [${recordLength}] overruns the central directory`
        );
      }
      cdBuffers.push(cdChunk.slice(offset, offset + recordLength));
      offset += recordLength;
    }
    return cdBuffers;
  }
}

/**
 * Scans a buffer whose final byte is the final byte of the archive for the end of
 * central directory record.
 *
 * A candidate is only accepted when its declared comment length places the end of
 * the comment exactly at the end of the archive, which rules out payload bytes that
 * happen to spell the signature.
 *
 * @returns the index of the EOCD signature within `tail`, or -1 if not found
 */
function findEndOfCentralDirectoryRecord(tail: Uint8Array): number {
  for (let i = tail.length - END_OF_CENTRAL_DIRECTORY_RECORD_SIZE; i >= 0; i--) {
    if (readUInt32LE(tail, i) !== EOCDR_SIGNATURE) {
      continue;
    }
    // 20 - .ZIP file comment length (2 bytes)
    const commentLength = readUInt16LE(tail, i + 20);
    if (i + END_OF_CENTRAL_DIRECTORY_RECORD_SIZE + commentLength === tail.length) {
      return i;
    }
  }
  return -1;
}

function parseCentralDirectoryWithNoExtras(cdBuffer: Uint8Array): CentralDirectory {
  const cd: Partial<CentralDirectory> = {};
  // 4 - Version made by
  cd.versionMadeBy = readUInt16LE(cdBuffer, 4);
  // 6 - Version needed to extract (minimum)
  cd.versionNeededToExtract = readUInt16LE(cdBuffer, 6);
  // 8 - General purpose bit flag
  cd.generalPurposeBitFlag = readUInt16LE(cdBuffer, 8);
  // 10 - Compression method
  cd.compressionMethod = readUInt16LE(cdBuffer, 10);
  // 12 - File last modification time
  cd.lastModFileTime = readUInt16LE(cdBuffer, 12);
  // 14 - File last modification date
  cd.lastModFileDate = readUInt16LE(cdBuffer, 14);
  // 16 - CRC-32
  cd.crc32 = readUInt32LE(cdBuffer, 16);
  // 20 - Compressed size
  cd.compressedSize = readUInt32LE(cdBuffer, 20);
  // 24 - Uncompressed size
  cd.uncompressedSize = readUInt32LE(cdBuffer, 24);
  // 28 - File name length (n)
  cd.fileNameLength = readUInt16LE(cdBuffer, 28);
  // 30 - Extra field length (m)
  cd.extraFieldLength = readUInt16LE(cdBuffer, 30);
  // 32 - File comment length (k)
  cd.fileCommentLength = readUInt16LE(cdBuffer, 32);
  // 34 - Disk number where file starts
  // 36 - Internal file attributes
  cd.internalFileAttributes = readUInt16LE(cdBuffer, 36);
  // 38 - External file attributes
  cd.externalFileAttributes = readUInt32LE(cdBuffer, 38);
  // 42 - Relative offset of local file header
  cd.relativeOffsetOfLocalHeader = readUInt32LE(cdBuffer, 42);
  const fileNameBuffer = cdBuffer.slice(
    CENTRAL_DIRECTORY_RECORD_FIXED_SIZE,
    CENTRAL_DIRECTORY_RECORD_FIXED_SIZE + cd.fileNameLength
  );
  // eslint-disable-next-line no-bitwise
  const isUtf8 = !!(cd.generalPurposeBitFlag & 0x800);
  cd.fileName = bufferToString(fileNameBuffer, 0, cd.fileNameLength, isUtf8);
  cd.headerLength = LOCAL_FILE_HEADER_FIXED_SIZE + cd.fileNameLength + cd.extraFieldLength;
  return cd as CentralDirectory;
}

/**
 * Takes a central directory buffer and turns it into a manageable object
 * that represents the CD
 * @param  cdBuffer The central directory buffer to parse
 * @return The CD object
 */
export function parseCDBuffer(cdBuffer: Uint8Array): CentralDirectory {
  if (cdBuffer.length < CENTRAL_DIRECTORY_RECORD_FIXED_SIZE) {
    throw new InvalidFileError('Truncated central directory file header');
  }
  if (readUInt32LE(cdBuffer, 0) !== CD_SIGNATURE) {
    throw new InvalidFileError('Invalid central directory file header signature');
  }

  const cd = parseCentralDirectoryWithNoExtras(cdBuffer);

  // NOTE(DSPX-4591): APPNOTE 4.5.3 does not condition the validity of a zip64
  // extended information extra field on `version needed to extract`; the sentinel
  // values in the fixed-size fields are what select it. Gating on the version byte
  // silently dropped the extra field, leaving 0xffffffff to flow into offset and
  // size arithmetic as if it were a real number.
  if (!cd.extraFieldLength) {
    return cd;
  }

  // Zip-64 information
  const extraFieldBuffer = cdBuffer.slice(
    CENTRAL_DIRECTORY_RECORD_FIXED_SIZE + cd.fileNameLength,
    CENTRAL_DIRECTORY_RECORD_FIXED_SIZE + cd.fileNameLength + cd.extraFieldLength
  );

  const extraFields = sliceExtraFields(extraFieldBuffer, cd);
  const zip64EiefBuffer = extraFields[1];
  if (zip64EiefBuffer) {
    let index = 0;
    // 0 - Original Size          8 bytes
    if (cd.uncompressedSize === 0xffffffff) {
      if (index + 8 > zip64EiefBuffer.length) {
        throw new InvalidFileError(
          'zip64 extended information extra field does not include uncompressed size'
        );
      }
      cd.uncompressedSize = readUInt64LE(zip64EiefBuffer, index);
      index += 8;
    }
    // 8 - Compressed Size        8 bytes
    if (cd.compressedSize === 0xffffffff) {
      if (index + 8 > zip64EiefBuffer.length) {
        throw new InvalidFileError(
          'zip64 extended information extra field does not include compressed size'
        );
      }
      cd.compressedSize = readUInt64LE(zip64EiefBuffer, index);
      index += 8;
    }
    // 16 - Relative Header Offset 8 bytes
    if (cd.relativeOffsetOfLocalHeader === 0xffffffff) {
      if (index + 8 > zip64EiefBuffer.length) {
        throw new InvalidFileError(
          'zip64 extended information extra field does not include relative header offset'
        );
      }
      cd.relativeOffsetOfLocalHeader = readUInt64LE(zip64EiefBuffer, index);
    }
    // 24 - Disk Start Number      4 bytes
    // not needed
  }
  return cd;
}

/**
 * Takes a buffer, and turns it into a string
 * @param  buffer The buffer to convert
 * @param  start  The start location of the part of the buffer to convert
 * @param  end    The end location of the part of the buffer to convert
 * @param  isUtf8 Is it utf8? Otherwise, assumed to be CP-437
 * @return The converted string
 */
function bufferToString(buffer: Uint8Array, start: number, end: number, isUtf8: boolean): string {
  if (isUtf8) {
    return buffToString(buffer, 'utf-8', start, end);
  }

  let result = '';
  for (let i = start; i < end; i++) {
    if (cp437[buffer[i]]) {
      result += cp437[buffer[i]];
    }
  }
  return result;
}

function recalculateHeaderLength(tempHeaderBuffer: Uint8Array): number {
  const fileNameLength = readUInt16LE(tempHeaderBuffer, 26);
  const extraFieldLength = readUInt16LE(tempHeaderBuffer, 28);
  return LOCAL_FILE_HEADER_FIXED_SIZE + fileNameLength + extraFieldLength;
}

export function readUInt64LE(buffer: Uint8Array, offset: number): number {
  const lower32 = readUInt32LE(buffer, offset);
  const upper32 = readUInt32LE(buffer, offset + 4);
  const combined = upper32 * 0x100000000 + lower32;
  if (!Number.isSafeInteger(combined)) {
    throw Error(`Value exceeds MAX_SAFE_INTEGER: ${combined}`);
  }

  return combined;
}

/**
 * Breaks extra field buffer into slices by field identifier.
 */
function sliceExtraFields(
  extraFieldBuffer: Uint8Array,
  cd: CentralDirectory
): Record<number, Uint8Array> {
  const extraFields: Record<number, Uint8Array> = {};

  let i = 0;
  while (i < extraFieldBuffer.length - 3) {
    const headerId = readUInt16LE(extraFieldBuffer, i + 0);
    const dataSize = readUInt16LE(extraFieldBuffer, i + 2);
    const dataStart = i + 4;
    const dataEnd = dataStart + dataSize;
    if (dataEnd > extraFieldBuffer.length) {
      throw new InvalidFileError('extra field length exceeds extra field buffer size');
    }
    const dataBuffer = new Uint8Array(dataSize);
    copyUint8Arr(extraFieldBuffer, dataBuffer, 0, dataStart, dataEnd);
    if (extraFields[headerId]) {
      throw new InvalidFileError(`Conflicting extra field #${headerId} for entry [${cd.fileName}]`);
    }
    extraFields[headerId] = dataBuffer;
    i = dataEnd;
  }
  return extraFields;
}
