import { expect } from '@esm-bundle/chai';

import {
  decode,
  decodeArrayBuffer,
  encode,
  encodeArrayBuffer,
} from '../../src/encodings/base64.js';

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
      expect(encodeArrayBuffer(asciiToBytes(HELLO))).to.eql(HELLO_AS_B64);
      expect(encodeArrayBuffer(asciiToBytes(FOO))).to.eql(FOO_AS_B64);
    });
    it('encodes strings', function () {
      expect(encode(HELLO)).to.eql(HELLO_AS_B64);
      expect(encode(FOO)).to.eql(FOO_AS_B64);
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
      expect(encode(HELLO)).to.eql(HELLO_AS_B64);
      expect(encode(FOO)).to.eql(FOO_AS_B64);
    });
  });
  describe('decode', function () {
    it('decodes strings', function () {
      expect(decode(HELLO_AS_B64)).to.eql(HELLO);
      expect(decode(FOO_AS_B64)).to.eql(FOO);
    });
  });

  describe('Fail cases', function () {
    it('fails on invalid input', function () {
      expect(() => decode('a')).to.throw(/[Ii]nvalid/);
    });
    it('TODO(PLAT-1106)', function () {
      // Encode currently assumes bytes are
      // incorrect, should either fail or throw on high chars:
      expect(encode('µ')).not.to.eql('wrU=');
      expect(decode('wrU=')).not.to.eql('µ');

      expect(() => encode('じすせ')).to.throw(/[Ii]nvalid/);
      // .to.eql('44GY44GZ44Gb');
      expect(decode('44GY44GZ44Gb')).not.to.eql('じすせ');

      expect(() => encode('🤣')).to.throw(/[Ii]nvalid/);
      // .to.eql('8J+kow==');
      expect(decode('8J+kow==')).not.to.eql('🤣');
    });
  });
};

describe('Base64 Selected', function () {
  tests(decode, encode);
});
