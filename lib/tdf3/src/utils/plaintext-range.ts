import { InvalidFileError, DecryptRangeError } from '../../../src/errors.js';

/**
 * Decrypt selected portions of ciphertext, given as a span of bytes of the
 * decrypted data. Only the segments that hold it are fetched and decrypted (see
 * planPlaintextRange), and the output is trimmed to exactly these bytes.
 *
 * As with `Blob.slice(offset, offset + length)`, an offset equal to the size of
 * the decrypted data gives empty output, and a span running past the end is cut
 * short there. Unlike `Blob.slice`, negative values are rejected and an offset
 * past the end throws.
 */
export type DecryptRange = {
  /** First byte of the decrypted data to return. At most its size. */
  offset: number;
  /** Number of bytes to return. Omit to read to the end of the decrypted data. */
  length?: number;
};

/** The segment fields a range is mapped with. */
export type RangeSegment = {
  plainSegmentSize?: number;
  encryptedSegmentSize?: number;
};

/** Which segments a range read decrypts, and what it does with their output. */
export type RangePlan<T> = {
  /**
   * Segments to fetch and decrypt, in order. All of them, even once `take`
   * bytes have been returned: the later ones confirm where the plaintext ends.
   */
  chunks: T[];
  /** Plaintext bytes to drop from the front of the decrypted segments. */
  skip: number;
  /** Plaintext bytes to return after that. */
  take: number;
};

function isNonNegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

/**
 * Checks the shape of a caller's plaintext range, independent of any file.
 *
 * @throws DecryptRangeError if offset or length is not a non-negative safe integer
 */
export function validatePlaintextRange({ offset, length }: DecryptRange): void {
  if (!isNonNegativeSafeInteger(offset)) {
    throw new DecryptRangeError(
      `range offset must be a non-negative safe integer; got [${String(offset)}]`
    );
  }
  if (length !== undefined && !isNonNegativeSafeInteger(length)) {
    throw new DecryptRangeError(
      `range length must be a non-negative safe integer; got [${String(length)}]`
    );
  }
}

/**
 * The common segment size S if every segment but the last records plaintext
 * size S and the matching ciphertext size, and the last records a size in
 * (0, S] with its matching ciphertext size. Otherwise undefined. A lone
 * segment is uniform, with S its own size.
 */
function uniformSegmentSize(
  chunks: RangeSegment[],
  encryptedSize: (plaintextSize: number) => number
): number | undefined {
  const size = chunks[0]?.plainSegmentSize;
  if (!size) {
    return undefined;
  }
  const fits = ({ plainSegmentSize, encryptedSegmentSize }: RangeSegment) =>
    !!plainSegmentSize &&
    plainSegmentSize <= size &&
    encryptedSegmentSize === encryptedSize(plainSegmentSize);
  const last = chunks.length - 1;
  for (let i = 0; i < last; i++) {
    if (chunks[i].plainSegmentSize !== size || !fits(chunks[i])) {
      return undefined;
    }
  }
  return fits(chunks[last]) ? size : undefined;
}

/**
 * Plans which portions of ciphertext to decrypt for a plaintext range.
 *
 * Plaintext positions must not rest on unauthenticated manifest data. The root
 * signature fixes the segment count and each segment's ciphertext (and so,
 * once its hash is checked, its length), but not the recorded sizes of
 * segments that are never read. Summing recorded sizes, or deriving positions
 * from ciphertext offsets, would let a keyless editor shift which authentic
 * segment an offset lands on, and understating sizes would let them end a read
 * early. So:
 *
 * - **Uniform layout** (what this SDK's writer produces): segment i starts at
 *   i * S. S comes from the manifest, so the plan always decrypts at least one
 *   non-last segment, whose authenticated length must equal S; a range inside
 *   the last segment also reads the one before it, and drops its output. (A
 *   lone segment starts at 0, so there is nothing to confirm.)
 * - **Any other layout**: decrypt from segment 0 and drop the output before the
 *   offset, so positions are those of the authenticated plaintext itself.
 *   Slower, as it reads everything before the range.
 *
 * A range that reaches the recorded end of the plaintext, including an offset
 * equal to it, also decrypts the last segment, so the end is confirmed rather
 * than read from the manifest. Only a length of 0, or a file with no segments,
 * decrypts nothing.
 *
 * The caller must decrypt every planned segment, even after `take` bytes have
 * been returned, and check that each one's plaintext length equals its
 * recorded `plainSegmentSize` (zero included): `skip` and `take` are computed
 * from those sizes.
 *
 * Remaining gap: the layout itself is not signed. A keyless editor can relabel
 * a file written with segments of differing sizes (some writers take segments
 * of any length) as uniform; the segments read then pass their checks, but the
 * unread ones before them are not checked, so the range can come from the
 * wrong offset. Closing this needs the format to sign the segment sizes.
 *
 * The end-of-file check that throws `DecryptRangeError` uses the recorded
 * plaintext size, before the root signature is verified, so that error can
 * also come from a tampered manifest.
 *
 * @param encryptedSize the cipher's ciphertext size for a given plaintext size
 * @throws DecryptRangeError if the range is malformed or starts past the end
 * @throws InvalidFileError if a segment's plaintext size is missing or unusable
 */
export function planPlaintextRange<T extends RangeSegment>(
  chunks: T[],
  range: DecryptRange,
  encryptedSize: (plaintextSize: number) => number
): RangePlan<T> {
  validatePlaintextRange(range);
  let total = 0;
  for (const { plainSegmentSize } of chunks) {
    if (!isNonNegativeSafeInteger(plainSegmentSize)) {
      throw new InvalidFileError(
        `cannot map a plaintext range: segment plaintext size is [${String(plainSegmentSize)}]`
      );
    }
    total += plainSegmentSize;
    if (!Number.isSafeInteger(total)) {
      throw new InvalidFileError(
        'cannot map a plaintext range: plaintext size is not representable'
      );
    }
  }
  const { offset } = range;
  if (offset > total) {
    throw new DecryptRangeError(
      `range offset [${offset}] is past the end of the decrypted data [${total}], as recorded in the manifest`
    );
  }
  const take = Math.min(range.length ?? total - offset, total - offset);
  if (range.length === 0 || !chunks.length) {
    // Nothing asked for, or nothing to read: the segment count is root-signed.
    return { chunks: [], skip: 0, take: 0 };
  }
  // A range reaching the recorded end reads the last segment, to confirm it.
  const toEnd = offset + take === total;
  const lastIndex = chunks.length - 1;

  const segmentSize = uniformSegmentSize(chunks, encryptedSize);
  if (segmentSize === undefined) {
    // Through the segment holding the range's last byte, or the last segment.
    // The length checks confirm the recorded sizes of every segment read.
    let end = 0;
    const last = toEnd
      ? lastIndex
      : chunks.findIndex(({ plainSegmentSize = 0 }) => (end += plainSegmentSize) >= offset + take);
    return { chunks: chunks.slice(0, last + 1), skip: offset, take };
  }
  let first = Math.min(Math.floor(offset / segmentSize), lastIndex);
  const last = toEnd ? lastIndex : Math.floor((offset + take - 1) / segmentSize);
  if (first === lastIndex && first > 0) {
    // Only the last segment covers the range, and its length cannot confirm S.
    first -= 1;
  }
  return {
    chunks: chunks.slice(first, last + 1),
    skip: offset - first * segmentSize,
    take,
  };
}
