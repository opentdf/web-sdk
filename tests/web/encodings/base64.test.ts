import { expect } from '@esm-bundle/chai';

import {
  decode,
  decodeArrayBuffer,
  encode,
  encodeArrayBuffer,
} from '../../../src/encodings/base64.js';

const asciiToBytes = (s: string) => {
  const chars: number[] = [];
  for (let i = 0; i < s.length; ++i) {
    chars.push(s.charCodeAt(i)); /*from  w  ww. j  a  v  a  2s.c o  m*/
  }
  return new Uint8Array(chars);
};

describe('Base64', function () {
  const tests = {
    '': '',
    f: 'Zg==',
    fo: 'Zm8=',
    foo: 'Zm9v',
    foob: 'Zm9vYg==',
    fooba: 'Zm9vYmE=',
    foobar: 'Zm9vYmFy',
    // y with umlaut is Unicode 255
    ÿ: '/w==',
    ÿÿ: '//8=',
    ÿÿÿ: '////',
    ÿï: '/+8=',
    ÿïþ: '/+/+',
  };

  for (const [decoded, encoded] of Object.entries(tests)) {
    const urlEncoded = encoded.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    it(`decode(${encoded})`, function () {
      expect(decode(encoded)).to.eql(decoded);
      expect(decode(urlEncoded)).to.eql(decoded);
    });
    it(`decodeArrayBuffer(${encoded})`, function () {
      expect(new Uint8Array(decodeArrayBuffer(encoded))).to.eql(asciiToBytes(decoded));
      expect(new Uint8Array(decodeArrayBuffer(urlEncoded))).to.eql(asciiToBytes(decoded));
    });
    it(`encode(${decoded})`, function () {
      expect(encode(decoded)).to.eql(encoded);
    });
    it(`encodeArrayBuffer(${decoded})`, function () {
      expect(encodeArrayBuffer(asciiToBytes(decoded))).to.eql(encoded);
    });

    it(`encode(${decoded}, true)`, function () {
      expect(encode(decoded, true)).to.eql(urlEncoded);
    });
    it(`encodeArrayBuffer(${decoded}, true)`, function () {
      expect(encodeArrayBuffer(asciiToBytes(decoded), true)).to.eql(urlEncoded);
    });
  }

  const invalidEncoded = {
    _: 'input must not be congruent to 4 mod 1',
    '_===': 'input must not be congruent to 4 mod 1',
    '///~': 'unrecognized character',
    じじ: 'high character',
    '🔥🔥🔥🔥': 'higher character',
    '╯°□°': 'more high characters',
  };
  for (const [invalid, message] of Object.entries(invalidEncoded)) {
    it(`invalid decode(${invalid}) -- ${message}`, function () {
      expect(() => decode(invalid), message).to.throw(/[Ii]nvalid/);
      expect(() => new Uint8Array(decodeArrayBuffer(invalid))).to.throw(/[Ii]nvalid/);
    });
  }

  describe('Fail cases', function () {
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
});
