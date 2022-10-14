import { assert } from 'chai';
import { Binary } from '../src/binary.js';

describe('Binary Stress Tests', function () {
  const MB_1 = Buffer.alloc(1 << 20);

  describe('Converts with a 1 MB buffer', function () {
    it('converts to String', function () {
      const binary = Binary.fromBuffer(MB_1);
      const str = binary.asString();
      const other = Binary.fromString(str);
      const otherBuffer = other.asBuffer();
      assert.equal(otherBuffer.length, MB_1.length);
    });
  });
});
