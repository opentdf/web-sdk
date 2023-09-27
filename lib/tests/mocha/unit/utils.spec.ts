import { expect } from 'chai';
import { buffToString, base64ToBytes } from '../../../tdf3/src/utils/index.js'; // Replace with the actual path to your module

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
});
