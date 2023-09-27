import { expect } from 'chai';
import { buffToString, base64ToBytes, utf8Slice } from '../../../tdf3/src/utils/index.js'; // Replace with the actual path to your module

describe('Buffer Conversion Functions', () => {
  describe('buffToString()', () => {
    it('should convert a Uint8Array to a hex string', () => {
      const buffer = new Uint8Array([72, 101, 108, 108, 111]); // "Hello" in ASCII
      const result = buffToString(buffer, 'hex');
      expect(result).to.equal('48656c6c6f');
    });

    it('should convert a Uint8Array to a UTF-8 string', () => {
      const buffer = new Uint8Array([72, 101, 108, 108, 111]); // "Hello" in ASCII
      const result = buffToString(buffer, 'utf8');
      expect(result).to.equal('Hello');
    });
  });

  describe('base64ToBytes()', () => {
    it('should convert a base64 string to a Uint8Array', () => {
      const base64Str = 'SGVsbG8='; // "Hello" in base64
      const result = base64ToBytes(base64Str);
      expect(result).to.deep.equal(new Uint8Array([72, 101, 108, 108, 111])); // "Hello" in ASCII
    });
  });
  describe('utf8Slice()', () => {
    it('should correctly handle a two-byte UTF-8 character', () => {
      // UTF-8 representation of 'é' (U+00E9)
      const buffer = new Uint8Array([0xc3, 0xa9]);
      const result = utf8Slice(buffer, 0, 2);
      expect(result).to.equal('é');
    });

    it('should correctly handle a three-byte UTF-8 character', () => {
      // UTF-8 representation of '€' (U+20AC)
      const buffer = new Uint8Array([0xe2, 0x82, 0xac]);
      const result = utf8Slice(buffer, 0, 3);
      expect(result).to.equal('€');
    });

    it('should correctly handle a four-byte UTF-8 character', () => {
      // UTF-8 representation of '𝄞' (U+1D11E)
      const buffer = new Uint8Array([0xf0, 0x9d, 0x84, 0x9e]);
      const result = utf8Slice(buffer, 0, 4);
      expect(result).to.equal('𝄞');
    });
  });

});
