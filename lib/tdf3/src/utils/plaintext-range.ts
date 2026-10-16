import { ConfigurationError, InvalidFileError } from '../../../src/errors.js';

/**
 * A span of plaintext bytes to decrypt. Only the segments that cover it are
 * fetched and decrypted, and the output is trimmed to exactly these bytes.
 */
export type PlaintextRange = {
  /** First plaintext byte to return. Must be less than the plaintext size. */
  offset: number;
  /**
   * Number of bytes to return. Omit to read to the end of the plaintext. A
   * span running past the end is cut short there.
   */
  length?: number;
};

function isNonNegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

/**
 * Checks the shape of a caller's plaintext range, independent of any file.
 *
 * @throws ConfigurationError if offset or length is not a non-negative safe integer
 */
export function validatePlaintextRange({ offset, length }: PlaintextRange): void {
  if (!isNonNegativeSafeInteger(offset)) {
    throw new ConfigurationError(
      `range offset must be a non-negative safe integer; got [${String(offset)}]`
    );
  }
  if (length !== undefined && !isNonNegativeSafeInteger(length)) {
    throw new ConfigurationError(
      `range length must be a non-negative safe integer; got [${String(length)}]`
    );
  }
}

/**
 * Maps a plaintext range onto the segments that cover it.
 *
 * Plaintext positions come from each segment's plaintext size, so every
 * segment must record one (or the manifest must have a default). Sizes may
 * vary; the last segment is usually short.
 *
 * @returns the covering segments, the bytes to drop from the front of the
 *   first one, and the number of bytes to return in total
 * @throws ConfigurationError if the offset is at or past the end of the plaintext
 * @throws InvalidFileError if a segment's plaintext size is missing or unusable
 */
export function plaintextRangeChunks<T extends { plainSegmentSize?: number }>(
  chunks: T[],
  range: PlaintextRange
): { chunks: T[]; skip: number; take: number } {
  validatePlaintextRange(range);
  // ends[i] is the plaintext offset just past segment i.
  const ends: number[] = [];
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
    ends.push(total);
  }
  const { offset } = range;
  if (offset >= total) {
    throw new ConfigurationError(
      `range offset [${offset}] is at or past the end of the plaintext [${total}]`
    );
  }
  const take = Math.min(range.length ?? total - offset, total - offset);
  if (take === 0) {
    return { chunks: [], skip: 0, take };
  }
  // First segment whose end is past `target`.
  const firstEndingAfter = (target: number) => {
    let lo = 0;
    let hi = ends.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (ends[mid] > target) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    }
    return lo;
  };
  const first = firstEndingAfter(offset);
  const last = firstEndingAfter(offset + take - 1);
  const covering = chunks.slice(first, last + 1);
  // Decryption only checks a segment's length against a nonzero recorded size,
  // so an empty segment inside the span could smuggle in unaccounted bytes.
  if (covering.some(({ plainSegmentSize }) => !plainSegmentSize)) {
    throw new InvalidFileError('cannot map a plaintext range: empty segment inside the range');
  }
  const firstStart = ends[first] - (chunks[first].plainSegmentSize as number);
  return { chunks: covering, skip: offset - firstStart, take };
}
