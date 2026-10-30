import { expect } from 'chai';

import { InvalidFileError } from '../../../src/errors.js';
import { readUInt16LE, readUInt32LE } from '../../../tdf3/src/utils/index.js';
import { readUInt64LE } from '../../../tdf3/src/utils/zip-reader.js';

// Indexing a typed array out of range yields `undefined`, which bitwise operators
// coerce to 0, so an unchecked read of a truncated or hostile buffer used to
// return a plausible-looking number instead of failing.
describe('little-endian byte readers', () => {
  describe('readUInt16LE / readUInt32LE', () => {
    it('read in range', () => {
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(readUInt16LE(b, 2)).to.equal(0x0403);
      expect(readUInt32LE(b, 0)).to.equal(0x04030201);
    });
    it('throw instead of reading past the end', () => {
      const b = new Uint8Array(3);
      expect(() => readUInt16LE(b, 2)).to.throw(InvalidFileError);
      expect(() => readUInt32LE(b, 0)).to.throw(InvalidFileError);
    });
    it('throw on negative or non-integer offsets', () => {
      const b = new Uint8Array(4);
      expect(() => readUInt16LE(b, -1)).to.throw(InvalidFileError);
      expect(() => readUInt32LE(b, 0.5)).to.throw(InvalidFileError);
      expect(() => readUInt32LE(b, NaN)).to.throw(InvalidFileError);
    });
  });

  describe('readUInt64LE', () => {
    it('throws instead of reading past the end', () => {
      expect(() => readUInt64LE(new Uint8Array(7), 0)).to.throw(InvalidFileError);
    });
  });
});
