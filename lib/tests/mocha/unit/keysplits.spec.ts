import { expect } from 'chai';

import { bxor, keySplit, keyMerge } from '../../../tdf3/src/utils/keysplit.js';
import { randomBytes } from '../../../tdf3/src/crypto/index.js';
import { hex } from '../../../src/encodings/index.js';
import { Binary } from '../../../tdf3/src/binary.js';
import * as defaultCryptoService from '../../../tdf3/src/crypto/index.js';

describe('keysplits', () => {
  it('binary xor', () => {
    expect(bxor(new Uint8Array([0x0f]), new Uint8Array([0xf0]))).to.eql(new Uint8Array([0xff]));
    expect(bxor(new Uint8Array([0x0f]), new Uint8Array([0x0f]))).to.eql(new Uint8Array([0x00]));
  });

  it('should return the original byte array with split set to one part', async () => {
    const expected = new Uint8Array([1, 2, 3, 4]);
    const splits = await keySplit(expected, 1, defaultCryptoService);
    expect(splits[0]).to.eql(expected);
    expect(keyMerge(splits)).to.eql(expected);
  });

  it('should return the original byte array with split set to three parts', async () => {
    const expected = new Uint8Array([1, 2, 3, 4]);
    const splits = await keySplit(expected, 3, defaultCryptoService);
    expect(expected).to.not.be.oneOf(splits);
    expect(keyMerge(splits)).to.eql(expected);
  });

  it(`should serialize hex key into Binary and back`, async () => {
    const keyBytes = await randomBytes(4);
    const keyHex = hex.encodeArrayBuffer(keyBytes.buffer);

    const unwrappedKeyBinary = Binary.fromString(hex.decode(keyHex));
    const splits = await keySplit(
      new Uint8Array(unwrappedKeyBinary.asArrayBuffer()),
      1,
      defaultCryptoService
    );

    expect(hex.encodeArrayBuffer(splits[0])).to.eql(keyHex);
  });
});
