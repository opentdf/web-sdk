import { InvalidFileError, UnsupportedFeatureError, asError } from '../../../src/errors.js';
import { type Chunker } from '../../../src/seekable.js';
import type { Manifest } from '../models/index.js';
import { readUInt32LE, readUInt16LE, copyUint8Arr, buffToString, concatUint8 } from './index.js';

// Signatures and fixed record sizes from PKWARE APPNOTE.TXT sections 4.3.7-4.3.16.
/** Local file header signature (APPNOTE 4.3.7). */
const LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
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

/** Compression method 0: the entry's data is stored as is (APPNOTE 4.4.5). */
const COMPRESSION_METHOD_STORED = 0;
/** Compression method 8: the entry's data is raw DEFLATE, RFC 1951 (APPNOTE 4.4.5). */
const COMPRESSION_METHOD_DEFLATED = 8;

/**
 * Compressed bytes fetched per ranged read while inflating a deflated entry. For
 * a remote source each read is one HTTP Range request. One read is kept in flight
 * ahead of the decompressor.
 */
const INFLATE_READ_SIZE = 1024 * 1024;
/**
 * Compressed bytes handed to the decompressor per write. Deflate expands by at
 * most about 1032:1, so even a runtime that inflates a whole write before
 * applying backpressure produces at most about 16 MiB from one. That bounds how
 * far inflating can run past an entry's declared size before it is stopped.
 */
const INFLATE_WRITE_SIZE = 16 * 1024;
/**
 * A deflated entry may declare an uncompressed size up to the larger of the
 * archive's length and this. The inflater never produces more than the declared
 * size, so this caps the memory a small archive can make it use: deflate expands
 * up to about 1032:1, and the manifest is buffered whole before it is validated.
 * A TDF payload is ciphertext, which does not compress, so a genuine one never
 * declares more than the archive holds.
 */
const DEFLATED_SIZE_FLOOR = 10 * 1024 * 1024;

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
  /**
   * Length of the archive as its end records lay it out: the central directory,
   * then the ZIP64 end records if any, then the end of central directory record
   * and its comment. Exact for archives without padding between those records.
   */
  archiveLength: number;
};

/**
 * Reads one archive entry by offset into its uncompressed bytes. Get one from
 * {@link ZipReader.openEntry}.
 *
 * A stored entry is read with one ranged read per call, so calls may overlap and
 * come in any order. A deflated entry can only be decoded front to back, so it is
 * read through a single forward-only cursor: calls are served one at a time, in
 * the order they were made, and a call for bytes behind the cursor inflates the
 * entry again from its start. Read a deflated entry in ascending order, with one
 * reader per pass.
 */
export interface ZipEntryReader {
  /**
   * Reads `size` bytes at `offset` into the entry's uncompressed bytes, into a
   * buffer of its own.
   * @throws InvalidFileError if the range is outside the entry, the source is
   * short, or a deflated entry is corrupt or does not match its declared size
   */
  read(offset: number, size: number): Promise<Uint8Array>;
  /**
   * Confirms that the entry holds exactly its declared uncompressed size. A
   * deflated entry is inflated to its end, past whatever was read; a stored
   * entry's bounds were already checked against the central directory.
   * @throws InvalidFileError if a deflated entry inflates to any other size
   */
  finish(): Promise<void>;
  /** Stops any inflating in progress. Later calls reject. */
  close(): void;
}

/**
 *
 * ZipReader -
 *
 * This class is used to extract parts of a TDF. You may pull bytes of a given range from a
 * or request specific important chunks like the 'manifest', or 'payload'.
 */
export class ZipReader {
  getChunk: Chunker;

  /**
   * Offset of the start of the central directory, once {@link getCentralDirectory}
   * has read it. Local file headers and file data always precede the central
   * directory (APPNOTE 4.3.6), so this is an upper bound on every byte range an
   * entry may reference. It lets us reject hostile offsets and sizes before they
   * are sliced or sent to a server as an HTTP Range, without needing to know the
   * length of the underlying source. Until then (for example, when a central
   * directory read by another reader is passed in) entry reads are only checked
   * for short reads.
   */
  private dataRegionEnd?: number;

  /**
   * The archive's length, once {@link getCentralDirectory} has read it (see
   * {@link EndOfCentralDirectory.archiveLength}). It sets how large a deflated
   * entry may declare itself; until it is known, only
   * {@link DEFLATED_SIZE_FLOOR} applies.
   */
  private archiveLength?: number;

  constructor(getChunk: Chunker) {
    this.getChunk = getChunk;
  }

  /**
   * Reads exactly the bytes `[byteStart, byteEnd)` of the archive.
   *
   * When `withinDataRegion` is set and {@link dataRegionEnd} is known, the range
   * must end before the central directory, and is rejected before anything is
   * requested. Central directory and zip64 records pass `false`, since they sit
   * at or after that offset. The result is checked for a short read: buffer and
   * Blob sources silently clamp out-of-range slices, and a remote server may
   * return fewer bytes.
   *
   * @param what names the structure being read, as a prefix for error messages
   * @throws InvalidFileError if the range is invalid, out of bounds, short, or
   * too large to allocate
   */
  private async readRange(
    byteStart: number,
    byteEnd: number,
    what: string,
    withinDataRegion = true
  ): Promise<Uint8Array> {
    if (!Number.isSafeInteger(byteStart) || !Number.isSafeInteger(byteEnd)) {
      throw new InvalidFileError(
        `${what}: byte range [${byteStart}, ${byteEnd}) is not representable`
      );
    }
    if (byteStart < 0 || byteEnd < byteStart) {
      throw new InvalidFileError(`${what}: invalid byte range [${byteStart}, ${byteEnd})`);
    }
    if (withinDataRegion && this.dataRegionEnd !== undefined && byteEnd > this.dataRegionEnd) {
      throw new InvalidFileError(
        `${what}: byte range [${byteStart}, ${byteEnd}) extends past the start of the central directory at [${this.dataRegionEnd}]`
      );
    }
    const expected = byteEnd - byteStart;
    if (expected === 0) {
      return new Uint8Array(0);
    }
    let chunk: Uint8Array;
    try {
      chunk = await this.getChunk(byteStart, byteEnd);
    } catch (e) {
      // Without a fixed size cap, a large declared size can exceed what the
      // runtime is able to allocate; report it as a bad file, not a RangeError.
      if (e instanceof RangeError) {
        throw new InvalidFileError(`${what}: unable to allocate [${expected}] bytes`, e);
      }
      throw e;
    }
    if (chunk.length !== expected) {
      throw new InvalidFileError(
        `${what} truncated: expected [${expected}] bytes at [${byteStart}], read [${chunk.length}]`
      );
    }
    return chunk;
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
    const cdChunk = await this.readRange(
      eocd.centralDirectoryOffset,
      eocd.centralDirectoryOffset + eocd.centralDirectorySize,
      'central directory',
      false
    );
    this.dataRegionEnd = eocd.centralDirectoryOffset;
    this.archiveLength = eocd.archiveLength;

    const cdParsedBuffers = this.getCDBuffers(cdChunk, eocd.entryCount).map((buffer) =>
      parseCDBuffer(buffer, eocd.zip64)
    );
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
      if (
        eocdrOffset < ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE &&
        tail.length < MAX_EOCDR_SEARCH_SIZE
      ) {
        // The locator immediately precedes the EOCD; if the EOCD landed near the
        // start of this tail (a short comment pushed it there), the locator may
        // have been cut off. Re-read with the maximum window and re-find the EOCD.
        tail = await this.getChunk(-MAX_EOCDR_SEARCH_SIZE);
        eocdrOffset = findEndOfCentralDirectoryRecord(tail);
        if (eocdrOffset < 0) {
          throw new InvalidFileError('unable to find end of central directory record');
        }
      }
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

    const archiveLength =
      centralDirectoryOffset +
      centralDirectorySize +
      (needsZip64
        ? ZIP64_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE + ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE
        : 0) +
      (tail.length - eocdrOffset);
    return {
      entryCount,
      centralDirectorySize,
      centralDirectoryOffset,
      zip64: needsZip64,
      archiveLength,
    };
  }

  /**
   * Follows the ZIP64 end of central directory locator, which sits immediately
   * before the EOCD record, and reads the ZIP64 EOCD record it points at.
   */
  private async getZip64EndOfCentralDirectory(
    tail: Uint8Array,
    eocdrOffset: number
  ): Promise<Omit<EndOfCentralDirectory, 'zip64' | 'archiveLength'>> {
    const locatorOffset = eocdrOffset - ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE;
    if (locatorOffset < 0 || readUInt32LE(tail, locatorOffset) !== ZIP64_EOCDL_SIGNATURE) {
      throw new InvalidFileError(
        'end of central directory record requires zip64, but no zip64 locator was found'
      );
    }
    // 8 - relative offset of the zip64 end of central directory record (8 bytes)
    const zip64EocdrOffset = readUInt64LE(tail, locatorOffset + 8);
    const record = await this.readRange(
      zip64EocdrOffset,
      zip64EocdrOffset + ZIP64_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE,
      'zip64 end of central directory record',
      false
    );
    if (readUInt32LE(record, 0) !== ZIP64_EOCDR_SIGNATURE) {
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
   * Reads and parses the manifest entry.
   * @returns The manifest, parsed from JSON
   * @throws InvalidFileError if the entry is missing, out of bounds, short, too
   * large to decode, not valid JSON, or not a JSON object
   */
  async getManifest(cdBuffers: CentralDirectory[], manifestFileName: string): Promise<Manifest> {
    const cdObj = cdBuffers.find(({ fileName }) => fileName === manifestFileName);
    if (!cdObj) {
      throw new InvalidFileError('Unable to retrieve CD manifest');
    }
    let manifest: Uint8Array;
    if (supportedCompressionMethod(cdObj) === COMPRESSION_METHOD_DEFLATED) {
      // Bounded by its declared uncompressed size, which entryReader has
      // capped (see DEFLATED_SIZE_FLOOR).
      const entry = this.entryReader(cdObj);
      try {
        manifest = await entry.read(0, cdObj.uncompressedSize);
        await entry.finish();
      } finally {
        entry.close();
      }
    } else {
      const byteStart = cdObj.relativeOffsetOfLocalHeader + cdObj.headerLength;
      const byteEnd = byteStart + cdObj.uncompressedSize;
      manifest = await this.readRange(byteStart, byteEnd, `manifest [${manifestFileName}]`);
    }

    let text: string;
    try {
      text = new TextDecoder().decode(manifest);
    } catch (e) {
      throw new InvalidFileError(
        `manifest [${manifestFileName}] of [${manifest.length}] bytes is too large to decode`,
        e instanceof Error ? e : undefined
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      throw new InvalidFileError(
        `manifest [${manifestFileName}] is not valid JSON`,
        e instanceof Error ? e : undefined
      );
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new InvalidFileError(`manifest [${manifestFileName}] is not a JSON object`);
    }
    return parsed as Manifest;
  }

  async adjustHeaders(cdObj: CentralDirectory): Promise<void> {
    if (!cdObj) {
      throw new InvalidFileError('Unable to retrieve CD adjust');
    }
    // Only stored and deflated entries can be read (APPNOTE 4.4.5). A stored
    // entry is read verbatim, so its sizes must agree (APPNOTE 4.4.8); otherwise
    // the manifest read (by uncompressed size) and the data bound (by compressed
    // size) would disagree about where the entry ends. A deflated entry's
    // compressed size bounds the bytes read from the archive, and its
    // uncompressed size is exactly what they must inflate to, so it is capped
    // here, before any of the entry is read.
    if (supportedCompressionMethod(cdObj) === COMPRESSION_METHOD_DEFLATED) {
      this.checkDeclaredInflatedSize(cdObj);
    } else if (cdObj.compressedSize !== cdObj.uncompressedSize) {
      throw new InvalidFileError(
        `stored entry [${cdObj.fileName}] has compressed size [${cdObj.compressedSize}] but uncompressed size [${cdObj.uncompressedSize}]`
      );
    }
    // Read the local header at the length the central directory implies, check
    // its signature, then recompute the length from the local header's own name
    // and extra field lengths. tdf3-js writes 0 in the local header size fields
    // and omits the zip64 extra field there, so the two can differ.
    const headerChunk = await this.readRange(
      cdObj.relativeOffsetOfLocalHeader,
      cdObj.relativeOffsetOfLocalHeader + cdObj.headerLength,
      `local file header for [${cdObj.fileName}]`
    );
    if (readUInt32LE(headerChunk, 0) !== LOCAL_FILE_HEADER_SIGNATURE) {
      throw new InvalidFileError(
        `invalid local file header signature for [${cdObj.fileName}] at [${cdObj.relativeOffsetOfLocalHeader}]`
      );
    }
    cdObj.headerLength = recalculateHeaderLength(headerChunk);

    // The local header's own name and extra field lengths may differ from the
    // central directory's; whatever they say, the entry's data must still end
    // before the central directory begins.
    const dataEnd = cdObj.relativeOffsetOfLocalHeader + cdObj.headerLength + cdObj.compressedSize;
    if (
      !Number.isSafeInteger(dataEnd) ||
      (this.dataRegionEnd !== undefined && dataEnd > this.dataRegionEnd)
    ) {
      throw new InvalidFileError(
        `entry [${cdObj.fileName}] of [${cdObj.compressedSize}] bytes at [${cdObj.relativeOffsetOfLocalHeader}] extends past the start of the central directory`
      );
    }
  }

  /**
   * Opens the entry named `fileName` for reading by offset into its
   * uncompressed bytes. See {@link ZipEntryReader} for how stored and deflated
   * entries differ.
   * @throws InvalidFileError if there is no such entry, or it uses an
   * unsupported compression method
   * @throws UnsupportedFeatureError if the entry is deflated and this runtime
   * has no `DecompressionStream`
   */
  openEntry(cdBuffers: CentralDirectory[], fileName: string): ZipEntryReader {
    const cdObj = cdBuffers.find((cd) => cd.fileName === fileName);
    if (!cdObj) {
      throw new InvalidFileError('Unable to retrieve CD');
    }
    return this.entryReader(cdObj);
  }

  private entryReader(cdObj: CentralDirectory): ZipEntryReader {
    const { fileName } = cdObj;
    const dataStart = cdObj.relativeOffsetOfLocalHeader + cdObj.headerLength;
    if (supportedCompressionMethod(cdObj) === COMPRESSION_METHOD_DEFLATED) {
      // Again here, for a central directory passed in without adjustHeaders.
      this.checkDeclaredInflatedSize(cdObj);
      return new InflatingEntryReader(
        (start, end) =>
          this.readRange(dataStart + start, dataStart + end, `compressed entry [${fileName}]`),
        fileName,
        cdObj.compressedSize,
        cdObj.uncompressedSize
      );
    }
    return {
      read: async (offset, size) => {
        checkEntryRange(fileName, cdObj.compressedSize, offset, size);
        return this.readRange(dataStart + offset, dataStart + offset + size, `entry [${fileName}]`);
      },
      finish: () => Promise.resolve(),
      close: () => undefined,
    };
  }

  /**
   * Rejects a deflated entry that declares an uncompressed size larger than the
   * larger of the archive's length and {@link DEFLATED_SIZE_FLOOR}.
   */
  private checkDeclaredInflatedSize(cdObj: CentralDirectory) {
    const limit = Math.max(this.archiveLength ?? 0, DEFLATED_SIZE_FLOOR);
    if (cdObj.uncompressedSize > limit) {
      const archiveLength =
        this.archiveLength === undefined ? '(unknown)' : `[${this.archiveLength}]`;
      throw new InvalidFileError(
        `deflated entry [${cdObj.fileName}] declares uncompressed size [${cdObj.uncompressedSize}], over the limit [${limit}]: the larger of the archive length ${archiveLength} and [${DEFLATED_SIZE_FLOOR}]`
      );
    }
  }

  /**
   * Reads `encryptedSegmentSize` bytes at `encrpytedSegmentOffset` into the
   * payload entry's uncompressed bytes.
   *
   * Each call opens the entry afresh, so for a deflated entry it inflates
   * everything before the offset again. To read a deflated entry segment by
   * segment, read it through one {@link openEntry} reader.
   */
  async getPayloadSegment(
    cdBuffers: CentralDirectory[],
    payloadName: string,
    encrpytedSegmentOffset: number,
    encryptedSegmentSize: number
  ): Promise<Uint8Array> {
    const entry = this.openEntry(cdBuffers, payloadName);
    try {
      return await entry.read(encrpytedSegmentOffset, encryptedSegmentSize);
    } finally {
      entry.close();
    }
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
 * The compression method of `cdObj`, if this reader can extract it.
 * @throws InvalidFileError for any method other than stored (0) or deflated (8)
 */
function supportedCompressionMethod(cdObj: CentralDirectory): number {
  const { compressionMethod, fileName } = cdObj;
  if (
    compressionMethod !== COMPRESSION_METHOD_STORED &&
    compressionMethod !== COMPRESSION_METHOD_DEFLATED
  ) {
    throw new InvalidFileError(
      `entry [${fileName}] uses unsupported compression method [${compressionMethod}]`
    );
  }
  return compressionMethod;
}

/**
 * Rejects a read of `size` bytes at `offset` that is not inside an entry of
 * `entrySize` uncompressed bytes. Offsets and sizes come from the manifest, so
 * they are untrusted too.
 */
function checkEntryRange(fileName: string, entrySize: number, offset: number, size: number) {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(size) ||
    offset < 0 ||
    size < 0 ||
    offset + size > entrySize
  ) {
    throw new InvalidFileError(
      `byte range [${offset}, +${size}) is outside entry [${fileName}] of [${entrySize}] bytes`
    );
  }
}

/** `bytes` as an ArrayBuffer-backed view, copied only if it is backed by a SharedArrayBuffer. */
function asArrayBufferView(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.buffer instanceof ArrayBuffer
    ? (bytes as Uint8Array<ArrayBuffer>)
    : new Uint8Array(bytes);
}

/** One pass of the decompressor over a deflated entry. */
type Inflation = {
  reader: ReadableStreamDefaultReader<Uint8Array>;
  /**
   * Set if fetching compressed bytes failed. The decompressor is then aborted
   * with that error, which is what the reader should report.
   */
  sourceError?: { error: unknown };
};

/**
 * Reads a deflated entry (compression method 8) through the runtime's
 * `DecompressionStream('deflate-raw')`.
 *
 * Deflate can only be decoded front to back, and an offset into the inflated
 * bytes says nothing about where they sit in the compressed ones. So reads are
 * served by one forward-only cursor, one at a time, in the order they were made.
 * Bytes before a read's offset are inflated and dropped, and a read behind the
 * cursor inflates the entry again from its start. The compressed bytes are
 * fetched in sequential ranged reads of {@link INFLATE_READ_SIZE}, one read ahead
 * of the decompressor, so neither the compressed nor the inflated entry is ever
 * held in full. Unlike a stored entry, a deflated one gets no parallel range
 * reads.
 *
 * The central directory's sizes are binding. The compressed size bounds what is
 * fetched from the archive, and the entry must inflate to exactly its
 * uncompressed size. Inflating stops as soon as the output passes that size, so
 * a small entry cannot inflate to a large one, and buffers grow only with bytes
 * actually inflated, never with a declared size alone. {@link ZipReader} caps
 * the declared size itself before opening the entry (see
 * {@link DEFLATED_SIZE_FLOOR}).
 *
 * The CRC-32 is not checked, just as it is not for stored entries. It is no
 * defense against tampering, since anyone can recompute it. A TDF's integrity
 * rests on its segment hashes and root signature instead.
 */
class InflatingEntryReader implements ZipEntryReader {
  /** Offset into the inflated entry of the next byte the cursor hands out. */
  private position = 0;
  /** Bytes the current inflation has produced so far. */
  private inflated = 0;
  /** Inflated bytes not handed out yet. They start at {@link position}. */
  private leftover?: Uint8Array;
  private inflation?: Inflation;
  /** Set once a call fails or the reader is closed. Every later call rejects with it. */
  private failure?: { error: unknown };
  /** Settles once the latest call has. Each call waits for the one before it. */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly readCompressed: (start: number, end: number) => Promise<Uint8Array>,
    private readonly fileName: string,
    private readonly compressedSize: number,
    private readonly uncompressedSize: number
  ) {
    if (typeof DecompressionStream === 'undefined') {
      throw new UnsupportedFeatureError(
        `entry [${fileName}] is deflate-compressed, and this runtime has no DecompressionStream`
      );
    }
  }

  async read(offset: number, size: number): Promise<Uint8Array> {
    // Neither a bad range nor an empty one touches the cursor. The call is
    // queued synchronously, so reads still run in the order they were made.
    checkEntryRange(this.fileName, this.uncompressedSize, offset, size);
    if (size === 0) {
      return new Uint8Array(0);
    }
    return this.enqueue(() => this.readAt(offset, size));
  }

  finish(): Promise<void> {
    return this.enqueue(async () => {
      // Inflate and drop whatever no read asked for, then expect the end of the
      // deflate stream. `pull` rejects any byte past the declared size.
      while (this.position < this.uncompressedSize) {
        await this.take(this.uncompressedSize - this.position);
      }
      while (await this.pull()) {
        // Only empty pieces can get here.
      }
    });
  }

  close(): void {
    this.fail(new Error(`entry [${this.fileName}] reader is closed`));
  }

  private enqueue<T>(call: () => Promise<T>): Promise<T> {
    const result = this.queue.then(async () => {
      if (this.failure) {
        throw this.failure.error;
      }
      try {
        return await call();
      } catch (error) {
        this.fail(error);
        throw error;
      }
    });
    this.queue = result.catch(() => undefined);
    return result;
  }

  private fail(error: unknown) {
    this.failure ??= { error };
    this.stopInflating();
  }

  private stopInflating() {
    this.inflation?.reader.cancel().catch(() => undefined);
    this.inflation = undefined;
    this.leftover = undefined;
    this.position = 0;
    this.inflated = 0;
  }

  private async readAt(offset: number, size: number): Promise<Uint8Array> {
    if (offset < this.position) {
      this.stopInflating();
    }
    while (this.position < offset) {
      await this.take(offset - this.position);
    }
    const parts: Uint8Array[] = [];
    for (let collected = 0; collected < size;) {
      const part = await this.take(size - collected);
      parts.push(part);
      collected += part.length;
    }
    // Always copied: each part is a view of the decompressor's output, which
    // the leftover, and so the next read, may share.
    return concatUint8(parts);
  }

  /** Hands out up to `max` inflated bytes at the cursor, inflating more if needed. */
  private async take(max: number): Promise<Uint8Array> {
    let piece = this.leftover ?? (await this.pull());
    if (!piece) {
      throw new InvalidFileError(
        `entry [${this.fileName}] inflates to [${this.inflated}] bytes, fewer than its declared uncompressed size [${this.uncompressedSize}]`
      );
    }
    this.leftover = undefined;
    if (piece.length > max) {
      this.leftover = piece.subarray(max);
      piece = piece.subarray(0, max);
    }
    this.position += piece.length;
    return piece;
  }

  /**
   * The next piece of inflated output, or undefined at the end of the deflate
   * stream.
   * @throws InvalidFileError as soon as the entry inflates past its declared
   * uncompressed size, or if its data is not valid deflate
   */
  private async pull(): Promise<Uint8Array | undefined> {
    const inflation = (this.inflation ??= this.startInflating());
    let result: ReadableStreamReadResult<Uint8Array>;
    try {
      result = await inflation.reader.read();
    } catch (error) {
      if (inflation.sourceError) {
        throw inflation.sourceError.error;
      }
      throw new InvalidFileError(
        `entry [${this.fileName}] is not valid deflate data`,
        asError(error)
      );
    }
    // Closed or failed while waiting, which also ends the stream early.
    if (this.failure) {
      throw this.failure.error;
    }
    if (inflation.sourceError) {
      throw inflation.sourceError.error;
    }
    if (result.done) {
      return undefined;
    }
    this.inflated += result.value.length;
    if (this.inflated > this.uncompressedSize) {
      throw new InvalidFileError(
        `entry [${this.fileName}] inflates to more than its declared uncompressed size [${this.uncompressedSize}]`
      );
    }
    return result.value;
  }

  /**
   * Starts feeding the compressed entry to a new decompressor, which pulls it
   * through as fast as {@link pull} drains the output.
   */
  private startInflating(): Inflation {
    const decompressor = new DecompressionStream('deflate-raw');
    const writer = decompressor.writable.getWriter();
    const inflation: Inflation = { reader: decompressor.readable.getReader() };
    const fetchFrom = (start: number): Promise<Uint8Array<ArrayBuffer>> => {
      const end = Math.min(start + INFLATE_READ_SIZE, this.compressedSize);
      const chunk = this.readCompressed(start, end).then(asArrayBufferView, (error: unknown) => {
        inflation.sourceError ??= { error };
        throw error;
      });
      // Fetched one ahead, so if inflating stops first nothing awaits it.
      chunk.catch(() => undefined);
      return chunk;
    };
    const feed = async () => {
      let fetched = 0;
      let next = this.compressedSize > 0 ? fetchFrom(0) : undefined;
      while (next) {
        const chunk = await next;
        fetched += chunk.length;
        next = fetched < this.compressedSize ? fetchFrom(fetched) : undefined;
        for (let i = 0; i < chunk.length; i += INFLATE_WRITE_SIZE) {
          await writer.write(chunk.subarray(i, i + INFLATE_WRITE_SIZE));
        }
      }
      await writer.close();
    };
    feed().catch((error: unknown) => {
      // Fails the pending `pull`. A no-op if the decompressor has already
      // failed, or was cancelled, which is what stopped the feed.
      writer.abort(error).catch(() => undefined);
    });
    return inflation;
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
export function parseCDBuffer(cdBuffer: Uint8Array, archiveIsZip64 = false): CentralDirectory {
  if (cdBuffer.length < CENTRAL_DIRECTORY_RECORD_FIXED_SIZE) {
    throw new InvalidFileError('Truncated central directory file header');
  }
  if (readUInt32LE(cdBuffer, 0) !== CD_SIGNATURE) {
    throw new InvalidFileError('Invalid central directory file header signature');
  }

  const cd = parseCentralDirectoryWithNoExtras(cdBuffer);
  // A ZIP64 archive entry that carries a sentinel here but has no ZIP64 extended
  // information extra field to resolve it is malformed; without this check the
  // sentinel would flow into offset/size arithmetic as if it were a real value.
  const hasUnresolvedSentinel = () =>
    cd.uncompressedSize === 0xffffffff ||
    cd.compressedSize === 0xffffffff ||
    cd.relativeOffsetOfLocalHeader === 0xffffffff;

  // NOTE(DSPX-4591): APPNOTE 4.5.3 does not condition the validity of a zip64
  // extended information extra field on `version needed to extract`; the sentinel
  // values in the fixed-size fields are what select it. Gating on the version byte
  // silently dropped the extra field, leaving 0xffffffff to flow into offset and
  // size arithmetic as if it were a real number.
  if (!cd.extraFieldLength) {
    if (archiveIsZip64 && hasUnresolvedSentinel()) {
      throw new InvalidFileError(
        'zip64 sentinel present without a zip64 extended information extra field'
      );
    }
    return cd;
  }

  // Zip-64 information
  const extraFieldBuffer = cdBuffer.slice(
    CENTRAL_DIRECTORY_RECORD_FIXED_SIZE + cd.fileNameLength,
    CENTRAL_DIRECTORY_RECORD_FIXED_SIZE + cd.fileNameLength + cd.extraFieldLength
  );

  const extraFields = sliceExtraFields(extraFieldBuffer, cd);
  const zip64EiefBuffer = extraFields[1];
  if (archiveIsZip64 && !zip64EiefBuffer && hasUnresolvedSentinel()) {
    throw new InvalidFileError(
      'zip64 sentinel present without a zip64 extended information extra field'
    );
  }
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
    throw new InvalidFileError(`Value exceeds MAX_SAFE_INTEGER: ${combined}`);
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
