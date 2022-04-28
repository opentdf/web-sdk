import { base64 } from '../../src/encodings';
import { expect } from 'chai';

const { decode, decodeArrayBuffer, encode, encodeArrayBuffer } = base64;

const HELLO = 'hello';
const HELLO_AS_B64 = 'aGVsbG8=';
const FOO = 'foo';
const FOO_AS_B64 = 'Zm9v';

const asciiToBytes = (s: string) => {
  const chars = [];
  for (let i = 0; i < s.length; ++i) {
    chars.push(s.charCodeAt(i)); /*from  w  ww. j  a  v  a  2s.c o  m*/
  }
  return new Uint8Array(chars);
};

const tests = (decode: (i: string) => string, encode: (i: string) => string) => {
  describe('encode', function () {
    it('encodes bytes', function () {
      expect(encodeArrayBuffer(asciiToBytes(HELLO))).to.equal(HELLO_AS_B64);
      expect(encodeArrayBuffer(asciiToBytes(FOO))).to.equal(FOO_AS_B64);
    });
    it('encodes strings', function () {
      expect(encode(HELLO)).to.equal(HELLO_AS_B64);
      expect(encode(FOO)).to.equal(FOO_AS_B64);
    });
  });
  describe('decode', function () {
    it('decodes bytes', function () {
      expect(new Uint8Array(decodeArrayBuffer(HELLO_AS_B64))).to.eql(asciiToBytes(HELLO));
      expect(new Uint8Array(decodeArrayBuffer(FOO_AS_B64))).to.eql(asciiToBytes(FOO));
    });
  });
  describe('encodeAB', function () {
    it('encodes strings', function () {
      expect(encode(HELLO)).to.equal(HELLO_AS_B64);
      expect(encode(FOO)).to.equal(FOO_AS_B64);
    });
  });
  describe('decode', function () {
    it('decodes strings', function () {
      expect(decode(HELLO_AS_B64)).to.equal(HELLO);
      expect(decode(FOO_AS_B64)).to.equal(FOO);
    });
  });

  describe('Fail cases', function () {
    it('fails on invalid input', function () {
      expect(() => decode('a')).to.throw(/[Ii]nvalid/);
    });
    it('TODO(PLAT-1106)', function () {
      // Encode currently assumes bytes are
      // incorrect, should either fail or throw on high chars:
      expect(encode('µ')).not.to.equal('wrU=');
      expect(decode('wrU=')).not.to.equal('µ');

      expect(() => encode('じすせ')).to.throw(/[Ii]nvalid/);
      // .to.equal('44GY44GZ44Gb');
      expect(decode('44GY44GZ44Gb')).not.to.equal('じすせ');

      expect(() => encode('🤣')).to.throw(/[Ii]nvalid/);
      // .to.equal('8J+kow==');
      expect(decode('8J+kow==')).not.to.equal('🤣');
    });
  });
};

describe('Base64 Selected', function () {
  tests(decode, encode);
});
