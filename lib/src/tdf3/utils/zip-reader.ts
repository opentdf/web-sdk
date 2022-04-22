import { chunker } from './chunkers';

// TODO: Better document what these constants are
// TODO: Document each function please
const CD_SIGNATURE = 0x02014b50;
const CENTRAL_DIRECTORY_RECORD_FIXED_SIZE = 46;
const LOCAL_FILE_HEADER_FIXED_SIZE = 30;
const VERSION_NEEDED_TO_EXTRACT_ZIP64 = 45;
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
  getChunk: chunker;

  constructor(getChunk: chunker) {
    this.getChunk = getChunk;
  }

  /**
   * Utility function to get the centralDirectory for the zip file.
   * @param  {Buffer} chunkBuffer Takes a buffer of a portion of the file
   * @return {Object}             The central directory represented as an object
   */
  async getCentralDirectory(): Promise<CentralDirectory[]> {
    const chunk = await this.getChunk(-1000);
    // TODO: Does this need to be tuned??!?
    // Full buffer for the file chunk
    const chunkBuffer = Buffer.from(chunk);
    // Slice off the EOCDR (End of Central Directory Record) part of the buffer so we can figure out the CD size
    const cdBuffers = this.getCDBuffers(chunkBuffer);

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
  async getManifest(cdBuffers: CentralDirectory[], manifestFileName: string) {
    const cdObj = cdBuffers.find(({ fileName }) => fileName === manifestFileName);
    if (!cdObj) {
      throw new Error('Unable to retrieve CD manifest');
    }
    const byteStart = cdObj.relativeOffsetOfLocalHeader + cdObj.headerLength;
    const byteEnd = byteStart + cdObj.uncompressedSize;
    const manifest = await this.getChunk(byteStart, byteEnd);
    const manifestBuffer = Buffer.from(manifest);

    return JSON.parse(manifestBuffer.toString());
  }

  async adjustHeaders(cdObj: CentralDirectory) {
    if (!cdObj) {
      throw new Error('Unable to retrieve CD adjust');
    }
    // Calculate header length -- tdf3-js writes 0 in all the header fields
    // and does not include extra field for zip64
    const headerChunk = await this.getChunk(
      cdObj.relativeOffsetOfLocalHeader,
      cdObj.relativeOffsetOfLocalHeader + cdObj.headerLength
    );
    const headerBuffer = Buffer.from(headerChunk);
    cdObj.headerLength = recalculateHeaderLength(headerBuffer);
  }

  async getPayloadSegment(
    cdBuffers: CentralDirectory[],
    payloadName: string,
    encrpytedSegmentOffset: number,
    encryptedSegmentSize: number
  ) {
    const cdObj = cdBuffers.find(({ fileName }) => payloadName === fileName);
    if (!cdObj) {
      throw new Error('Unable to retrieve CD');
    }
    const byteStart =
      cdObj.relativeOffsetOfLocalHeader + cdObj.headerLength + encrpytedSegmentOffset;
    // TODO: what's the exact byte start?
    const byteEnd = byteStart + encryptedSegmentSize;

    const chunk = await this.getChunk(byteStart, byteEnd);
    const segmentBuffer = Buffer.from(chunk);
    return segmentBuffer;
  }

  /**
   * Takes a portion of a ZIP (must be the last portion of a ZIP to work) and returns an array of Buffers
   * that correspond to each central directory.
   * @param  {Buffer} chunkBuffer The last portion of a zip file
   * @returns {Array}             An array of buffers
   */
  getCDBuffers(chunkBuffer: Buffer): Buffer[] {
    const cdBuffers = [];
    let lastBufferOffset = chunkBuffer.length;
    for (let i = chunkBuffer.length - 22; i >= 0; i -= 1) {
      // If what we're locking at isn't the start of a central directory, skip it..
      if (chunkBuffer.readUInt32LE(i) !== CD_SIGNATURE) {
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

function parseCentralDirectoryWithNoExtras(cdBuffer: Buffer): CentralDirectory {
  const cd: Partial<CentralDirectory> = {};
  // 4 - Version made by
  cd.versionMadeBy = cdBuffer.readUInt16LE(4);
  // 6 - Version needed to extract (minimum)
  cd.versionNeededToExtract = cdBuffer.readUInt16LE(6);
  // 8 - General purpose bit flag
  cd.generalPurposeBitFlag = cdBuffer.readUInt16LE(8);
  // 10 - Compression method
  cd.compressionMethod = cdBuffer.readUInt16LE(10);
  // 12 - File last modification time
  cd.lastModFileTime = cdBuffer.readUInt16LE(12);
  // 14 - File last modification date
  cd.lastModFileDate = cdBuffer.readUInt16LE(14);
  // 16 - CRC-32
  cd.crc32 = cdBuffer.readUInt32LE(16);
  // 20 - Compressed size
  cd.compressedSize = cdBuffer.readUInt32LE(20);
  // 24 - Uncompressed size
  cd.uncompressedSize = cdBuffer.readUInt32LE(24);
  // 28 - File name length (n)
  cd.fileNameLength = cdBuffer.readUInt16LE(28);
  // 30 - Extra field length (m)
  cd.extraFieldLength = cdBuffer.readUInt16LE(30);
  // 32 - File comment length (k)
  cd.fileCommentLength = cdBuffer.readUInt16LE(32);
  // 34 - Disk number where file starts
  // 36 - Internal file attributes
  cd.internalFileAttributes = cdBuffer.readUInt16LE(36);
  // 38 - External file attributes
  cd.externalFileAttributes = cdBuffer.readUInt32LE(38);
  // 42 - Relative offset of local file header
  cd.relativeOffsetOfLocalHeader = cdBuffer.readUInt32LE(42);
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
export function parseCDBuffer(cdBuffer: Buffer): CentralDirectory {
  if (cdBuffer.readUInt32LE(0) !== CD_SIGNATURE) {
    throw new Error('Invalid central directory file header signature');
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
        throw new Error(
          'zip64 extended information extra field does not include uncompressed size'
        );
      }
      cd.uncompressedSize = readUInt64LE(zip64EiefBuffer, index);
      index += 8;
    }
    // 8 - Compressed Size        8 bytes
    if (cd.compressedSize === 0xffffffff) {
      if (index + 8 > zip64EiefBuffer.length) {
        throw new Error('zip64 extended information extra field does not include compressed size');
      }
      cd.compressedSize = readUInt64LE(zip64EiefBuffer, index);
      index += 8;
    }
    // 16 - Relative Header Offset 8 bytes
    if (cd.relativeOffsetOfLocalHeader === 0xffffffff) {
      if (index + 8 > zip64EiefBuffer.length) {
        throw new Error(
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
function bufferToString(buffer: Buffer, start: number, end: number, isUtf8: boolean): string {
  if (isUtf8) {
    return buffer.toString('utf8', start, end);
  }

  let result = '';
  for (let i = start; i < end; i++) {
    if (cp437[buffer[i]]) {
      result += cp437[buffer[i]];
    }
  }
  return result;
}

function recalculateHeaderLength(tempHeaderBuffer: Buffer): number {
  const fileNameLength = tempHeaderBuffer.readUInt16LE(26);
  const extraFieldLength = tempHeaderBuffer.readUInt16LE(28);
  return LOCAL_FILE_HEADER_FIXED_SIZE + fileNameLength + extraFieldLength;
}

export function readUInt64LE(buffer: Buffer, offset: number): number {
  const lower32 = buffer.readUInt32LE(offset);
  const upper32 = buffer.readUInt32LE(offset + 4);
  const combined = upper32 * 0x100000000 + lower32;
  if (!Number.isSafeInteger(combined)) {
    throw Error(`Value exceeds MAX_SAFE_INTEGER: ${combined}`);
  }

  return combined;
}

/**
 * Breaks extra field buffer into slices by field identifier.
 */
function sliceExtraFields(extraFieldBuffer: Buffer, cd: CentralDirectory): Record<number, Buffer> {
  const extraFields = {};

  let i = 0;
  while (i < extraFieldBuffer.length - 3) {
    const headerId = extraFieldBuffer.readUInt16LE(i + 0);
    const dataSize = extraFieldBuffer.readUInt16LE(i + 2);
    const dataStart = i + 4;
    const dataEnd = dataStart + dataSize;
    if (dataEnd > extraFieldBuffer.length) {
      throw new Error('extra field length exceeds extra field buffer size');
    }
    const dataBuffer = Buffer.allocUnsafe(dataSize);
    extraFieldBuffer.copy(dataBuffer, 0, dataStart, dataEnd);
    if (extraFields[headerId]) {
      throw new Error(`Conflicting extra field #${headerId} for entry [${cd.fileName}]`);
    }
    extraFields[headerId] = dataBuffer;
    i = dataEnd;
  }
  return extraFields;
}
