import { assert, expect } from 'chai';

import { AesGcmCipher } from '../../../tdf3/src/ciphers/aes-gcm-cipher.js';
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

  it('rejects an IV that is not exactly twelve bytes', async () => {
    const key = await cipher.generateKey();
    for (const ivLength of [0, 11, 13, 16]) {
      try {
        await cipher.encrypt(
          Binary.fromArrayBuffer(new ArrayBuffer(8)),
          key,
          Binary.fromArrayBuffer(new ArrayBuffer(ivLength))
        );
        assert.fail(`a ${ivLength} byte IV should be rejected`);
      } catch (e) {
        assert.instanceOf(e, ConfigurationError);
        expect(e.message).to.include('Invalid AES-GCM IV length');
      }
    }
  });
});
