import { expect } from 'chai';

import { ConfigurationError } from '../../../src/errors.js';
import {
  DEFAULT_MAX_CONCURRENT_SEGMENT_BATCHES,
  DEFAULT_PREFETCH_BYTE_BUDGET,
  derivePrefetchWindow,
  MAX_SEGMENT_BATCH_SIZE,
} from '../../../tdf3/src/utils/prefetch-window.js';

const KIB = 1024;
const MIB = 1024 * KIB;

describe('derivePrefetchWindow', () => {
  const windowBytes = (segmentSize: number, opts = {}) => {
    const { segmentBatchSize, maxConcurrentSegmentBatches } = derivePrefetchWindow({
      segmentSize,
      ...opts,
    });
    return segmentBatchSize * maxConcurrentSegmentBatches * segmentSize;
  };

  // The whole point of the change: the window is a byte count, not a segment
  // count, so growing the segment size must not grow peak memory.
  it('keeps the window inside the byte budget across segment sizes', () => {
    // Includes the encrypted size of a 2 MiB segment (go/java default), which is
    // not a power of two.
    for (const segmentSize of [KIB, 64 * KIB, MIB, 2 * MIB + 28, 4 * MIB, 16 * MIB, 64 * MIB]) {
      expect(windowBytes(segmentSize), `${segmentSize} bytes`).to.be.at.most(
        DEFAULT_PREFETCH_BYTE_BUDGET
      );
    }
  });

  it('spends the budget on concurrency before batch size', () => {
    // 128 MiB / 16 MiB = 8 segments, split 3 ways -> 2 per batch, 3 batches.
    expect(derivePrefetchWindow({ segmentSize: 16 * MIB })).to.deep.equal({
      segmentBatchSize: 2,
      maxConcurrentSegmentBatches: 3,
    });
    // 128 MiB / 64 MiB = 2 segments: not enough for three batches, so
    // concurrency drops rather than rounding the batch size down to zero.
    expect(derivePrefetchWindow({ segmentSize: 64 * MIB })).to.deep.equal({
      segmentBatchSize: 1,
      maxConcurrentSegmentBatches: 2,
    });
  });

  it('caps the batch size so a small-segment file is not one enormous read', () => {
    // 128 MiB / 1 KiB = 131,072 segments; within budget, but the consumer
    // would wait on a 43,690-segment read before its first byte.
    const { segmentBatchSize, maxConcurrentSegmentBatches } = derivePrefetchWindow({
      segmentSize: KIB,
    });
    expect(segmentBatchSize).to.equal(MAX_SEGMENT_BATCH_SIZE);
    expect(maxConcurrentSegmentBatches).to.equal(DEFAULT_MAX_CONCURRENT_SEGMENT_BATCHES);
  });

  it('derives 21 x 3 for the 2 MiB writer default segment size', () => {
    // Encrypted size: 2 MiB plaintext + 12-byte IV + 16-byte tag.
    expect(derivePrefetchWindow({ segmentSize: 2 * MIB + 28 })).to.deep.equal({
      segmentBatchSize: 21,
      maxConcurrentSegmentBatches: 3,
    });
  });

  it('derives 42 x 3 for the 1 MiB reader fallback segment size', () => {
    expect(derivePrefetchWindow({ segmentSize: MIB })).to.deep.equal({
      segmentBatchSize: 42,
      maxConcurrentSegmentBatches: 3,
    });
  });

  // No smaller unit exists, so the alternative to blowing the budget is
  // refusing to decrypt at all.
  it('falls back to a single segment when one segment exceeds the budget', () => {
    expect(derivePrefetchWindow({ segmentSize: 256 * MIB })).to.deep.equal({
      segmentBatchSize: 1,
      maxConcurrentSegmentBatches: 1,
    });
    expect(windowBytes(256 * MIB)).to.be.above(DEFAULT_PREFETCH_BYTE_BUDGET);
  });

  it('honours a caller-supplied budget', () => {
    expect(windowBytes(MIB, { byteBudget: 6 * MIB })).to.be.at.most(6 * MIB);
    expect(derivePrefetchWindow({ segmentSize: MIB, byteBudget: 6 * MIB })).to.deep.equal({
      segmentBatchSize: 2,
      maxConcurrentSegmentBatches: 3,
    });
  });

  it('rejects nonsense inputs rather than deriving a nonsense window', () => {
    for (const bad of [0, -1, 1.5, NaN]) {
      expect(() => derivePrefetchWindow({ segmentSize: bad }), `${bad}`).to.throw(
        ConfigurationError
      );
      expect(() => derivePrefetchWindow({ segmentSize: MIB, byteBudget: bad })).to.throw(
        ConfigurationError
      );
    }
  });
});
