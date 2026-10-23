import { expect } from 'chai';

import { base64 } from '../../../src/encodings/index.js';
import { AesGcmCipher } from '../../../tdf3/src/ciphers/aes-gcm-cipher.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import { SplitKey } from '../../../tdf3/src/models/encryption-information.js';
import { type KeyAccessObject, Wrapped } from '../../../tdf3/src/models/key-access.js';
import { getMocks } from '../../mocks/index.js';

const Mocks = getMocks();

/** The `{ ciphertext, iv }` pair a key access object carries, decoded to bytes. */
function encryptedMetadataOf(kao: KeyAccessObject): { ciphertext: Uint8Array; iv: Uint8Array } {
  const { ciphertext, iv } = JSON.parse(base64.decode(kao.encryptedMetadata ?? '')) as {
    ciphertext: string;
    iv: string;
  };
  return {
    ciphertext: new Uint8Array(base64.decodeArrayBuffer(ciphertext)),
    iv: new Uint8Array(base64.decodeArrayBuffer(iv)),
  };
}

describe('SplitKey key access metadata', () => {
  it('encrypts each object under its own IV when objects share a split (DSPX-4492)', async () => {
    const cipher = new AesGcmCipher(DefaultCryptoService);
    const splitKey = new SplitKey(cipher);
    // No sids: one split, so both objects encrypt under the payload key itself.
    splitKey.keyAccess = ['kas-a', 'kas-b'].map(
      (kas) =>
        new Wrapped(Mocks.getKasUrl(), undefined, Mocks.kasPublicKey, { kas }, DefaultCryptoService)
    );
    const keyInfo = await splitKey.generateKey();

    const kaos = await splitKey.getKeyAccessObjects(Mocks.getPolicyObject(), keyInfo);
    const [a, b] = kaos.map(encryptedMetadataOf);

    expect(a.iv).to.not.deep.equal(b.iv);
    for (const [i, { ciphertext, iv }] of [a, b].entries()) {
      // The ciphertext carries its IV as a 12-byte prefix; it must agree with
      // the separate `iv` field, since readers may use either.
      expect(ciphertext.slice(0, 12)).to.deep.equal(iv);
      expect(iv).to.not.deep.equal(new Uint8Array(keyInfo.unwrappedKeyIvBinary.asArrayBuffer()));
      const { payload } = await cipher.decrypt(ciphertext, keyInfo.unwrappedKey);
      expect(JSON.parse(payload.asString('utf8'))).to.deep.equal({ kas: ['kas-a', 'kas-b'][i] });
    }
  });

  describe('payloadKeyMetadataInvocations', () => {
    function withSids(...sids: (string | undefined)[]): SplitKey {
      const splitKey = new SplitKey(new AesGcmCipher(DefaultCryptoService));
      splitKey.keyAccess = sids.map(
        (sid) =>
          new Wrapped(
            Mocks.getKasUrl(),
            undefined,
            Mocks.kasPublicKey,
            {},
            DefaultCryptoService,
            sid
          )
      );
      return splitKey;
    }

    it('counts every object when there is a single split', () => {
      expect(withSids(undefined).payloadKeyMetadataInvocations()).to.equal(1);
      expect(withSids(undefined, undefined).payloadKeyMetadataInvocations()).to.equal(2);
      expect(withSids('a', 'a', 'a').payloadKeyMetadataInvocations()).to.equal(3);
    });

    it('counts none when there are several splits', () => {
      expect(withSids('a', 'b').payloadKeyMetadataInvocations()).to.equal(0);
      expect(withSids('a', 'a', 'b').payloadKeyMetadataInvocations()).to.equal(0);
    });
  });
});
