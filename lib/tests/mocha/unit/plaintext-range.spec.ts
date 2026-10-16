import { expect } from 'chai';

import {
  plaintextRangeChunks,
  validatePlaintextRange,
} from '../../../tdf3/src/utils/plaintext-range.js';
import { ConfigurationError, InvalidFileError } from '../../../src/errors.js';

const sized = (...sizes: Array<number | undefined>) =>
  sizes.map((plainSegmentSize, index) => ({ index, plainSegmentSize }));

const indices = ({ chunks }: { chunks: Array<{ index: number }> }) =>
  chunks.map(({ index }) => index);

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
      expect(() => validatePlaintextRange({ offset })).to.throw(ConfigurationError, 'offset');
    });
  }

  for (const length of [-1, 0.5, NaN, Infinity, 2 ** 53, null as unknown as number]) {
    it(`rejects length ${String(length)}`, () => {
      expect(() => validatePlaintextRange({ offset: 0, length })).to.throw(
        ConfigurationError,
        'length'
      );
    });
  }
});

describe('plaintextRangeChunks', () => {
  // Segments of 10, 10, 10 and a short 4: plaintext [0, 34).
  const chunks = sized(10, 10, 10, 4);

  it('maps a range inside one segment', () => {
    const result = plaintextRangeChunks(chunks, { offset: 12, length: 5 });
    expect(indices(result)).to.deep.equal([1]);
    expect(result).to.include({ skip: 2, take: 5 });
  });

  it('maps a range ending exactly on a segment boundary', () => {
    const result = plaintextRangeChunks(chunks, { offset: 10, length: 10 });
    expect(indices(result)).to.deep.equal([1]);
    expect(result).to.include({ skip: 0, take: 10 });
  });

  it('maps a range across segment boundaries', () => {
    const result = plaintextRangeChunks(chunks, { offset: 9, length: 13 });
    expect(indices(result)).to.deep.equal([0, 1, 2]);
    expect(result).to.include({ skip: 9, take: 13 });
  });

  it('reads to the end when the length is absent or too long', () => {
    for (const length of [undefined, 4, 1000]) {
      const result = plaintextRangeChunks(chunks, { offset: 30, length });
      expect(indices(result)).to.deep.equal([3]);
      expect(result).to.include({ skip: 0, take: 4 });
    }
  });

  it('covers no segments for length 0', () => {
    expect(plaintextRangeChunks(chunks, { offset: 5, length: 0 })).to.deep.equal({
      chunks: [],
      skip: 0,
      take: 0,
    });
  });

  it('rejects an offset at or past the end', () => {
    for (const offset of [34, 35]) {
      expect(() => plaintextRangeChunks(chunks, { offset, length: 0 })).to.throw(
        ConfigurationError,
        'at or past the end of the plaintext [34]'
      );
    }
  });

  it('skips empty segments before the range but refuses them inside it', () => {
    const result = plaintextRangeChunks(sized(10, 0, 10), { offset: 10, length: 2 });
    expect(indices(result)).to.deep.equal([2]);
    expect(() => plaintextRangeChunks(sized(10, 0, 10), { offset: 5, length: 10 })).to.throw(
      InvalidFileError,
      'empty segment'
    );
  });

  it('refuses segments without a plaintext size', () => {
    expect(() => plaintextRangeChunks(sized(10, undefined), { offset: 0 })).to.throw(
      InvalidFileError,
      'cannot map a plaintext range'
    );
    expect(() => plaintextRangeChunks(sized(10, -1), { offset: 0 })).to.throw(InvalidFileError);
  });

  it('refuses a plaintext too large to address', () => {
    expect(() => plaintextRangeChunks(sized(Number.MAX_SAFE_INTEGER, 1), { offset: 0 })).to.throw(
      InvalidFileError,
      'not representable'
    );
  });

  it('works above 2^32 with many segments', () => {
    const MIB = 1024 * 1024;
    // 5000 MiB in 1 MiB segments, then a short one.
    const many = sized(...new Array<number>(5000).fill(MIB), 7);
    const offset = 4100 * MIB + 3;
    expect(offset).to.be.above(2 ** 32);
    const result = plaintextRangeChunks(many, { offset, length: 2 * MIB });
    expect(indices(result)).to.deep.equal([4100, 4101, 4102]);
    expect(result).to.include({ skip: 3, take: 2 * MIB });

    const tail = plaintextRangeChunks(many, { offset: 5000 * MIB + 1 });
    expect(indices(tail)).to.deep.equal([5000]);
    expect(tail).to.include({ skip: 1, take: 6 });
  });
});
