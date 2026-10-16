import { expect } from 'chai';

import {
  planPlaintextRange,
  validatePlaintextRange,
} from '../../../tdf3/src/utils/plaintext-range.js';
import { ConfigurationError, InvalidFileError, PlaintextRangeError } from '../../../src/errors.js';

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
      expect(() => validatePlaintextRange({ offset })).to.throw(PlaintextRangeError, 'offset');
    });
  }

  for (const length of [-1, 0.5, NaN, Infinity, 2 ** 53, null as unknown as number]) {
    it(`rejects length ${String(length)}`, () => {
      expect(() => validatePlaintextRange({ offset: 0, length })).to.throw(
        PlaintextRangeError,
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

    it('reads nothing at the end, whatever the length', () => {
      for (const length of [undefined, 0, 5]) {
        expect(plan(chunks, 24, length)).to.deep.equal({
          indices: [],
          skip: 0,
          take: 0,
        });
      }
    });

    it('reads nothing for length 0', () => {
      expect(plan(chunks, 5, 0)).to.include({ take: 0 });
      expect(plan(chunks, 5, 0).indices).to.deep.equal([]);
    });

    it('reads nothing from an empty plaintext at offset 0', () => {
      expect(plan(sized(), 0).indices).to.deep.equal([]);
      expect(plan(sized(0), 0).indices).to.deep.equal([]);
    });

    it('rejects an offset past the end', () => {
      expect(() => plan(chunks, 25, 0)).to.throw(
        PlaintextRangeError,
        'past the end of the plaintext [24]'
      );
      expect(() => plan(sized(), 1)).to.throw(PlaintextRangeError);
    });
  });

  describe('other layouts decrypt from the start', () => {
    const fallback = (chunks: ReturnType<typeof sized>) => {
      expect(plan(chunks, 12, 3)).to.deep.equal({
        indices: chunks.map(({ index }) => index),
        skip: 12,
        take: 3,
      });
    };

    it('segments of different sizes', () => fallback(sized(5, 10, 10, 4)));
    it('a last segment longer than the others', () => fallback(sized(10, 10, 11)));
    it('an empty segment', () => fallback(sized(10, 0, 10, 4)));
    it('a ciphertext size that does not match', () => {
      const chunks = sized(10, 10, 10);
      chunks[0].encryptedSegmentSize = 100;
      fallback(chunks);
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
