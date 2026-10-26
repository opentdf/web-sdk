import { expect } from 'chai';

import {
  planPlaintextRange,
  validatePlaintextRange,
} from '../../../tdf3/src/utils/plaintext-range.js';
import { ConfigurationError, InvalidFileError, DecryptRangeError } from '../../../src/errors.js';

const OVERHEAD = 28;
const encryptedSize = (size: number) => size + OVERHEAD;

/** Segments recording these plaintext sizes, with matching ciphertext sizes. */
const sized = (...sizes: Array<number | undefined>) =>
  sizes.map((plainSegmentSize, index) => ({
    index,
    plainSegmentSize,
    encryptedSegmentSize: plainSegmentSize === undefined ? undefined : plainSegmentSize + OVERHEAD,
  }));

const plan = (chunks: ReturnType<typeof sized>, offset: number, length?: number) => {
  const { chunks: covering, ...rest } = planPlaintextRange(
    chunks,
    { offset, length },
    encryptedSize
  );
  return { indices: covering.map(({ index }) => index), ...rest };
};

describe('validatePlaintextRange', () => {
  it('accepts non-negative safe integers, and an absent length', () => {
    for (const range of [
      { offset: 0 },
      { offset: 0, length: 0 },
      { offset: Number.MAX_SAFE_INTEGER, length: Number.MAX_SAFE_INTEGER },
    ]) {
      expect(() => validatePlaintextRange(range)).not.to.throw();
    }
  });

  for (const offset of [-1, 0.5, NaN, Infinity, 2 ** 53, '1' as unknown as number]) {
    it(`rejects offset ${String(offset)}`, () => {
      expect(() => validatePlaintextRange({ offset })).to.throw(DecryptRangeError, 'offset');
    });
  }

  for (const length of [-1, 0.5, NaN, Infinity, 2 ** 53, null as unknown as number]) {
    it(`rejects length ${String(length)}`, () => {
      expect(() => validatePlaintextRange({ offset: 0, length })).to.throw(
        DecryptRangeError,
        'length'
      );
    });
  }

  it('is still a ConfigurationError', () => {
    expect(() => validatePlaintextRange({ offset: -1 })).to.throw(ConfigurationError);
  });
});

describe('planPlaintextRange', () => {
  describe('uniform layout', () => {
    // Segments of 10, 10, 10 and a short 4: plaintext [0, 34).
    const chunks = sized(10, 10, 10, 4);

    it('maps a range inside one segment', () => {
      expect(plan(chunks, 12, 5)).to.deep.equal({
        indices: [1],
        skip: 2,
        take: 5,
      });
    });

    it('maps a range ending exactly on a segment boundary', () => {
      expect(plan(chunks, 10, 10)).to.include({ skip: 0, take: 10 });
      expect(plan(chunks, 10, 10).indices).to.deep.equal([1]);
    });

    it('maps a range across segment boundaries', () => {
      expect(plan(chunks, 9, 13)).to.deep.equal({
        indices: [0, 1, 2],
        skip: 9,
        take: 13,
      });
    });

    it('also reads the segment before the last, to confirm the segment size', () => {
      for (const length of [undefined, 4, 1000]) {
        expect(plan(chunks, 30, length)).to.deep.equal({
          indices: [2, 3],
          skip: 10,
          take: 4,
        });
      }
      expect(plan(chunks, 33)).to.include({ skip: 13, take: 1 });
    });

    it('reads through the last segment when the range reaches the end', () => {
      expect(plan(chunks, 5)).to.deep.equal({
        indices: [0, 1, 2, 3],
        skip: 5,
        take: 29,
      });
      expect(plan(chunks, 25, 1000)).to.deep.equal({
        indices: [2, 3],
        skip: 5,
        take: 9,
      });
    });

    it('reads a lone segment by itself', () => {
      expect(plan(sized(7), 3, 2)).to.deep.equal({
        indices: [0],
        skip: 3,
        take: 2,
      });
    });

    it('accepts a last segment as long as the others', () => {
      expect(plan(sized(10, 10), 15, 1)).to.deep.equal({
        indices: [0, 1],
        skip: 15,
        take: 1,
      });
    });

    it('works above 2^32 with many segments', () => {
      const MIB = 1024 * 1024;
      // 5000 MiB in 1 MiB segments, then a short one.
      const many = sized(...new Array<number>(5000).fill(MIB), 7);
      const offset = 4100 * MIB + 3;
      expect(offset).to.be.above(2 ** 32);
      expect(plan(many, offset, 2 * MIB)).to.deep.equal({
        indices: [4100, 4101, 4102],
        skip: 3,
        take: 2 * MIB,
      });
      expect(plan(many, 5000 * MIB + 1)).to.deep.equal({
        indices: [4999, 5000],
        skip: MIB + 1,
        take: 6,
      });
    });
  });

  describe('Blob.slice end semantics', () => {
    const chunks = sized(10, 10, 4);

    it('returns nothing at the end, but reads the last segments to confirm it', () => {
      // The recorded total is not signed: the last segment's length confirms
      // it, and the one before confirms the segment size.
      for (const length of [undefined, 5]) {
        expect(plan(chunks, 24, length)).to.deep.equal({
          indices: [1, 2],
          skip: 14,
          take: 0,
        });
      }
    });

    it('reads nothing for length 0', () => {
      for (const offset of [5, 24]) {
        expect(plan(chunks, offset, 0)).to.deep.equal({ indices: [], skip: 0, take: 0 });
      }
    });

    it('reads nothing from a file with no segments', () => {
      expect(plan(sized(), 0)).to.deep.equal({ indices: [], skip: 0, take: 0 });
    });

    it('reads a lone empty segment, to confirm it is empty', () => {
      expect(plan(sized(0), 0)).to.deep.equal({ indices: [0], skip: 0, take: 0 });
    });

    it('rejects an offset past the end', () => {
      expect(() => plan(chunks, 25, 0)).to.throw(
        DecryptRangeError,
        'past the end of the decrypted data [24]'
      );
      expect(() => plan(sized(), 1)).to.throw(DecryptRangeError);
    });
  });

  describe('other layouts decrypt from the start', () => {
    /** Plans [12, 15), expecting segments 0 to `through`, which holds byte 14. */
    const fallback = (chunks: ReturnType<typeof sized>, through: number) => {
      expect(plan(chunks, 12, 3)).to.deep.equal({
        indices: chunks.slice(0, through + 1).map(({ index }) => index),
        skip: 12,
        take: 3,
      });
    };

    it('segments of different sizes', () => fallback(sized(5, 10, 10, 4), 1));
    it('a last segment longer than the others', () => fallback(sized(10, 10, 11), 1));
    it('an empty segment', () => fallback(sized(10, 0, 10, 4), 2));
    it('a ciphertext size that does not match', () => {
      const chunks = sized(10, 10, 10);
      chunks[0].encryptedSegmentSize = 100;
      fallback(chunks, 1);
    });

    it('reads through the last segment when the range reaches the end', () => {
      // A recorded 0 may understate the total; decrypting the segment checks it.
      const chunks = sized(10, 10, 0);
      expect(plan(chunks, 5)).to.deep.equal({ indices: [0, 1, 2], skip: 5, take: 15 });
      expect(plan(chunks, 20)).to.deep.equal({ indices: [0, 1, 2], skip: 20, take: 0 });
      expect(plan(chunks, 5, 3).indices).to.deep.equal([0]);
    });
  });

  it('refuses segments without a plaintext size', () => {
    expect(() => plan(sized(10, undefined), 0)).to.throw(
      InvalidFileError,
      'cannot map a plaintext range'
    );
    expect(() => plan(sized(10, -1), 0)).to.throw(InvalidFileError);
  });

  it('refuses a plaintext too large to address', () => {
    expect(() => plan(sized(Number.MAX_SAFE_INTEGER, 1), 0)).to.throw(
      InvalidFileError,
      'not representable'
    );
  });
});
