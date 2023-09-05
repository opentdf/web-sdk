import { assert } from 'chai';
import { Binary } from '../../tdf3/src/binary.js';

describe('Binary Stress Tests', function () {
  const MB_1 = new Uint8Array(1 << 20).buffer;
  describe('Converts with a 1 MB buffer', function () {
    it('converts to String', function () {
      const binary = Binary.fromArrayBuffer(MB_1);
      const str = binary.asString();
      const other = Binary.fromString(str);
      const otherBuffer = other.asArrayBuffer();
      assert.equal(otherBuffer.byteLength, MB_1.byteLength);
    });
  });
});
