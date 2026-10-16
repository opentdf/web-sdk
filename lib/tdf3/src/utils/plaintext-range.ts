import { InvalidFileError, PlaintextRangeError } from '../../../src/errors.js';

/**
 * A span of plaintext bytes to decrypt. Only the segments that cover it are
 * fetched and decrypted, and the output is trimmed to exactly these bytes.
 *
 * Follows `Blob.slice`: an offset equal to the plaintext size gives empty
 * output, and a span running past the end is cut short there.
 */
export type PlaintextRange = {
  /** First plaintext byte to return. At most the plaintext size. */
  offset: number;
  /** Number of bytes to return. Omit to read to the end of the plaintext. */
  length?: number;
};

/** The segment fields a range is mapped with. */
export type RangeSegment = {
  plainSegmentSize?: number;
  encryptedSegmentSize?: number;
};

/** Which segments a range read decrypts, and what it does with their output. */
export type RangePlan<T> = {
  /** Segments to fetch and decrypt, in order. */
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
 * @throws PlaintextRangeError if offset or length is not a non-negative safe integer
 */
export function validatePlaintextRange({ offset, length }: PlaintextRange): void {
  if (!isNonNegativeSafeInteger(offset)) {
    throw new PlaintextRangeError(
      `range offset must be a non-negative safe integer; got [${String(offset)}]`
    );
  }
  if (length !== undefined && !isNonNegativeSafeInteger(length)) {
    throw new PlaintextRangeError(
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
 * Plans the decrypt of a plaintext range.
 *
 * Plaintext positions must not rest on unauthenticated manifest data. The root
 * signature fixes the segment count and each segment's ciphertext (and so,
 * once its hash is checked, its length), but not the recorded sizes of
 * segments that are never read. Summing recorded sizes, or deriving positions
 * from ciphertext offsets, would let a keyless editor shift which authentic
 * segment an offset lands on. So:
 *
 * - **Uniform layout** (what every SDK writer produces): segment i starts at
 *   i * S. S comes from the manifest, so the plan always decrypts at least one
 *   non-last segment, whose authenticated length must equal S; a range inside
 *   the last segment also reads the one before it, and drops its output. (A
 *   lone segment starts at 0, so there is nothing to confirm.)
 * - **Any other layout**: decrypt from segment 0 and drop the output before the
 *   offset, so positions are those of the authenticated plaintext itself.
 *   Slower, but no SDK writer produces such files.
 *
 * Either way, the caller must check that every decrypted segment's plaintext
 * length equals its recorded `plainSegmentSize` (zero included): `skip` and
 * `take` are computed from those sizes.
 *
 * The end-of-file checks use the recorded plaintext size, before the root
 * signature is verified, so a `PlaintextRangeError` can also come from a
 * tampered manifest; a decrypt that goes ahead fails its length checks instead.
 *
 * @param encryptedSize the cipher's ciphertext size for a given plaintext size
 * @throws PlaintextRangeError if the range is malformed or starts past the end
 * @throws InvalidFileError if a segment's plaintext size is missing or unusable
 */
export function planPlaintextRange<T extends RangeSegment>(
  chunks: T[],
  range: PlaintextRange,
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
    throw new PlaintextRangeError(
      `range offset [${offset}] is past the end of the plaintext [${total}]`
    );
  }
  const take = Math.min(range.length ?? total - offset, total - offset);
  if (take === 0) {
    return { chunks: [], skip: 0, take };
  }

  const segmentSize = uniformSegmentSize(chunks, encryptedSize);
  if (segmentSize === undefined) {
    return { chunks, skip: offset, take };
  }
  const lastIndex = chunks.length - 1;
  let first = Math.floor(offset / segmentSize);
  const last = Math.min(Math.floor((offset + take - 1) / segmentSize), lastIndex);
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
