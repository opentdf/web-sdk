import { assert, expect } from 'chai';

import { AesGcmCipher } from '../../../tdf3/src/ciphers/aes-gcm-cipher.js';
import { Binary } from '../../../tdf3/src/binary.js';
import * as WebCryptoService from '../../../tdf3/src/crypto/index.js';
import { ConfigurationError } from '../../../src/errors.js';

describe('AesGcmCipher IV length', () => {
  const cipher = new AesGcmCipher(WebCryptoService);

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
