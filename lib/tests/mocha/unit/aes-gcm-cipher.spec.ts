import { expect } from 'chai';

import { AesGcmCipher } from '../../../tdf3/src/ciphers/aes-gcm-cipher.js';
import { SymmetricCipher } from '../../../tdf3/src/ciphers/symmetric-cipher-base.js';
import { Binary } from '../../../tdf3/src/binary.js';
import * as WebCryptoService from '../../../tdf3/src/crypto/index.js';
import { ConfigurationError } from '../../../src/errors.js';

describe('AesGcmCipher', () => {
  const cipher = new AesGcmCipher(WebCryptoService);

  const encryptBytes = async (plaintextSize: number) => {
    const key = await cipher.generateKey();
    const iv = await WebCryptoService.randomBytes(12);
    const { payload } = await cipher.encrypt(
      Binary.fromArrayBuffer(new ArrayBuffer(plaintextSize)),
      key,
      Binary.fromArrayBuffer(iv.buffer as ArrayBuffer)
    );
    return payload.length();
  };

  // `writeStream` records `encryptedPayloadSize` as the manifest's
  // `encryptedSegmentSizeDefault` and readers seek by it, so an estimate that
  // is merely close produces a file whose segment offsets are wrong. The
  // segment-size probe that used to keep the two honest is gone; this is its
  // replacement.
  it('predicts the exact ciphertext length', async () => {
    for (const plaintextSize of [0, 1, 15, 16, 17, 1024, 1024 * 1024]) {
      expect(await encryptBytes(plaintextSize)).to.equal(
        cipher.encryptedPayloadSize(plaintextSize),
        `mismatch for a ${plaintextSize} byte plaintext`
      );
    }
  });
});

describe('SymmetricCipher', () => {
  // `encryptedPayloadSize` is concrete rather than abstract so that a cipher
  // written against an older release still satisfies the class structurally.
  // That only helps if the default fails legibly instead of returning garbage.
  it('names the cipher when a subclass has no size arithmetic', () => {
    class SizelessCipher extends SymmetricCipher {
      constructor() {
        super(WebCryptoService);
        this.name = 'NO-SUCH-CIPHER';
        this.ivLength = 12;
        this.keyLength = 32;
      }
      override encrypt(): Promise<never> {
        return Promise.reject(new Error('not implemented'));
      }
      override decrypt(): Promise<never> {
        return Promise.reject(new Error('not implemented'));
      }
    }

    expect(() => new SizelessCipher().encryptedPayloadSize(1024))
      .to.throw(ConfigurationError)
      .that.matches(/Cipher \[NO-SUCH-CIPHER\] does not implement encryptedPayloadSize/);
  });
});
