import { InvalidFileError } from '../../../src/errors.js';
import { type Chunker } from '../../../src/seekable.js';
import { Manifest } from '../models/index.js';
import { readUInt32LE, readUInt16LE, copyUint8Arr, buffToString } from './index.js';

// TODO: Better document what these constants are
// TODO: Document each function please
const CD_SIGNATURE = 0x02014b50;
const CENTRAL_DIRECTORY_RECORD_FIXED_SIZE = 46;
const LOCAL_FILE_HEADER_FIXED_SIZE = 30;
const VERSION_NEEDED_TO_EXTRACT_ZIP64 = 45;
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
   * It reads the end of the file to find it.
   * @return The central directory represented as an object
   */
  async getCentralDirectory(): Promise<CentralDirectory[]> {
    const chunk = await this.getChunk(-1000);
    // TODO: Does this need to be tuned??!?
    // Slice off the EOCDR (End of Central Directory Record) part of the buffer so we can figure out the CD size
    const cdBuffers = this.getCDBuffers(chunk);

    const cdParsedBuffers = cdBuffers.map(parseCDBuffer);
    for (const buffer of cdParsedBuffers) {
      await this.adjustHeaders(buffer);
    }
    return cdParsedBuffers;
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
        `manifest file too large: ${(cdObj.uncompressedSize >> 10).toLocaleString()} KiB`
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

    return await this.getChunk(byteStart, byteEnd);
  }

  /**
   * extracts the CD buffer entries from the end of a zip file.
   * @param  chunkBuffer The last portion of a zip file
   * @returns an array of typed arrays, each element corresponding to a central directory record
   */
  getCDBuffers(chunkBuffer: Uint8Array): Uint8Array[] {
    const cdBuffers = [];
    let lastBufferOffset = chunkBuffer.length;
    for (let i = chunkBuffer.length - 22; i >= 0; i -= 1) {
      // If what we're locking at isn't the start of a central directory, skip it..
      if (readUInt32LE(chunkBuffer, i) !== CD_SIGNATURE) {
        // eslint-disable-next-line no-continue
        continue;
      }
      // Slice off that CD from it's start until the end of either the buffer, or whatever the start of the previously
      // found CD was
      cdBuffers.push(chunkBuffer.slice(i, lastBufferOffset));
      // Store the last offset location so we know how to slice off hte next CD.
      lastBufferOffset = i;
      // We can skip over 22 iterations since we know the minimum size of a CD is 22.
      i -= 22;
    }

    // They should be in the correct order. Since we iterate backwards, it's built backwards.
    return cdBuffers.reverse();
  }
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
  if (readUInt32LE(cdBuffer, 0) !== CD_SIGNATURE) {
    throw new InvalidFileError('Invalid central directory file header signature');
  }

  const cd = parseCentralDirectoryWithNoExtras(cdBuffer);

  if (cd.versionNeededToExtract < VERSION_NEEDED_TO_EXTRACT_ZIP64 || !cd.extraFieldLength) {
    // NOTE(PLAT-1134) Zip64 was added in pkzip 4.5
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
