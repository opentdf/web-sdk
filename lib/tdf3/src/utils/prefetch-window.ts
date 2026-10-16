import { ConfigurationError } from '../../../src/errors.js';

/**
 * How much decrypted-but-unconsumed payload the reader will hold ahead of the
 * consumer.
 *
 * The prefetch window has to be a *byte* budget, not a segment count. A window
 * of "8 segments x 3 batches" is 24 MiB at a 1 MiB segment size and 384 MiB at
 * 16 MiB -- the same configuration, sixteen times the memory, with nothing in
 * the numbers to suggest it. Budgeting bytes makes the window mean the same
 * thing at every segment size.
 *
 * 128 MiB is enough to keep several ranged reads in flight on a fast link while
 * staying somewhere a browser tab can live.
 */
export const DEFAULT_PREFETCH_BYTE_BUDGET = 128 * 1024 * 1024;

/**
 * Most batches to keep in flight at once, before the byte budget reduces it.
 *
 * Concurrency hides request latency; past a handful it mostly adds memory. The
 * legacy path used 3 and there is no evidence more helped.
 */
export const DEFAULT_MAX_CONCURRENT_SEGMENT_BATCHES = 3;

/**
 * Most segments in a single batch, i.e. a single ranged read.
 *
 * The byte budget alone would allow enormous batches at small segment sizes
 * (43,690 segments per batch at 1 KiB), which stays within budget but makes the
 * consumer wait on one absurd ranged read before the first byte. This is the
 * legacy batch size, so tiny-segment files keep behaving as they always did.
 */
export const MAX_SEGMENT_BATCH_SIZE = 500;

/**
 * Splits a byte budget into a batch size and a concurrency level.
 *
 * The product of the two is the window, so both have to come out of the same
 * division. Concurrency is filled first: three batches of one segment is a better
 * use of a tight budget than one batch of three, because the reads overlap.
 *
 * When a single segment already exceeds the budget the window is one segment
 * and the budget is knowingly blown -- there is no smaller unit to schedule,
 * and refusing to decrypt would be worse than using the memory.
 */
export function derivePrefetchWindow({
  segmentSize,
  byteBudget = DEFAULT_PREFETCH_BYTE_BUDGET,
  maxConcurrentSegmentBatches = DEFAULT_MAX_CONCURRENT_SEGMENT_BATCHES,
  maxSegmentBatchSize = MAX_SEGMENT_BATCH_SIZE,
}: {
  segmentSize: number;
  byteBudget?: number;
  maxConcurrentSegmentBatches?: number;
  maxSegmentBatchSize?: number;
}): { segmentBatchSize: number; maxConcurrentSegmentBatches: number } {
  assertPositiveInteger(segmentSize, 'segmentSize');
  assertPositiveInteger(byteBudget, 'byteBudget');
  assertPositiveInteger(maxConcurrentSegmentBatches, 'maxConcurrentSegmentBatches');
  assertPositiveInteger(maxSegmentBatchSize, 'maxSegmentBatchSize');

  const segmentsInWindow = Math.max(1, Math.floor(byteBudget / segmentSize));
  const batches = Math.min(maxConcurrentSegmentBatches, segmentsInWindow);
  return {
    segmentBatchSize: Math.min(
      maxSegmentBatchSize,
      Math.max(1, Math.floor(segmentsInWindow / batches))
    ),
    maxConcurrentSegmentBatches: batches,
  };
}

function assertPositiveInteger(value: number, name: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new ConfigurationError(`${name} must be a positive integer; got [${value}]`);
  }
}
