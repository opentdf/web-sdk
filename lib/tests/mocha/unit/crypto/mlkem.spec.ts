import { expect } from 'chai';
import {
  generateMlKemKeyPair,
  mlKemEncapsulate,
  mlKemDecapsulate,
  hkdfDerive,
} from '../../../../tdf3/src/crypto/core/mlkem.js';
import { unwrapMlKemKey } from '../../../../tdf3/src/crypto/core/keys.js';
import { unwrapSymmetricKey } from '../../../../tdf3/src/crypto/core/keys.js';
import { isPublicKeyAlgorithm } from '../../../../src/access.js';
import {
  importPublicKey,
  exportPublicKeyPem,
} from '../../../../tdf3/src/crypto/core/key-format.js';

describe('ML-KEM crypto', () => {
  for (const level of [512, 768, 1024] as const) {
    describe(`ML-KEM-${level}`, () => {
      it('generateMlKemKeyPair produces correctly-sized keys', async () => {
        const { publicKey, privateKey } = await generateMlKemKeyPair(level);
        expect(publicKey.algorithm).to.equal(`mlkem:${level}`);
        expect(publicKey.mlKemLevel).to.equal(level);
        expect(privateKey.algorithm).to.equal(`mlkem:${level}`);
        expect(privateKey.mlKemLevel).to.equal(level);

        const pkBytes = unwrapMlKemKey(publicKey);
        const skBytes = unwrapMlKemKey(privateKey);
        const expectedPkSizes = { 512: 800, 768: 1184, 1024: 1568 };
        const expectedSkSizes = { 512: 1632, 768: 2400, 1024: 3168 };
        expect(pkBytes.length).to.equal(expectedPkSizes[level]);
        expect(skBytes.length).to.equal(expectedSkSizes[level]);
      });

      it('encapsulate/decapsulate round-trip recovers shared secret', async () => {
        const { publicKey, privateKey } = await generateMlKemKeyPair(level);
        const { ciphertext, sharedSecret: ss1 } = await mlKemEncapsulate(publicKey);
        const ss2 = await mlKemDecapsulate(privateKey, ciphertext);

        const ss1Bytes = unwrapSymmetricKey(ss1);
        const ss2Bytes = unwrapSymmetricKey(ss2);
        expect(ss1Bytes).to.deep.equal(ss2Bytes);
        expect(ss1Bytes.length).to.equal(32);
      });

      it('exportPublicKeyPem / importPublicKey round-trip', async () => {
        const { publicKey } = await generateMlKemKeyPair(level);
        const pem = await exportPublicKeyPem(publicKey);
        // Should be raw base64 (no PEM header)
        expect(pem).to.not.include('BEGIN');
        const reimported = await importPublicKey(pem, { algorithmHint: `mlkem:${level}` });
        expect(reimported.algorithm).to.equal(`mlkem:${level}`);
        expect(unwrapMlKemKey(reimported)).to.deep.equal(unwrapMlKemKey(publicKey));
      });
    });
  }

  describe('hkdfDerive', () => {
    it('produces deterministic 32-byte output for fixed inputs', async () => {
      const { sharedSecret } = await mlKemEncapsulate(
        (await generateMlKemKeyPair(512)).publicKey
      );
      const salt = new Uint8Array(32);
      const derived1 = await hkdfDerive(sharedSecret, { hash: 'SHA-256', salt });
      const derived2 = await hkdfDerive(sharedSecret, { hash: 'SHA-256', salt });
      const key1Bytes = unwrapSymmetricKey(derived1);
      const key2Bytes = unwrapSymmetricKey(derived2);
      expect(key1Bytes).to.deep.equal(key2Bytes);
      expect(key1Bytes.length).to.equal(32);
    });

    it('produces different keys for different salts', async () => {
      const { sharedSecret } = await mlKemEncapsulate(
        (await generateMlKemKeyPair(512)).publicKey
      );
      const salt1 = new Uint8Array(32).fill(1);
      const salt2 = new Uint8Array(32).fill(2);
      const key1 = unwrapSymmetricKey(await hkdfDerive(sharedSecret, { hash: 'SHA-256', salt: salt1 }));
      const key2 = unwrapSymmetricKey(await hkdfDerive(sharedSecret, { hash: 'SHA-256', salt: salt2 }));
      expect(key1).to.not.deep.equal(key2);
    });
  });

  describe('isPublicKeyAlgorithm', () => {
    it('returns true for all 8 valid tokens', () => {
      const valid = [
        'ec:secp256r1', 'ec:secp384r1', 'ec:secp521r1',
        'rsa:2048', 'rsa:4096',
        'mlkem:512', 'mlkem:768', 'mlkem:1024',
      ];
      for (const alg of valid) {
        expect(isPublicKeyAlgorithm(alg), alg).to.be.true;
      }
    });

    it('returns false for invalid tokens', () => {
      const invalid = ['ec:foo', 'rsa:1024', 'mlkem:256', 'aes:256', '', 'rsa'];
      for (const alg of invalid) {
        expect(isPublicKeyAlgorithm(alg), alg).to.be.false;
      }
    });
  });
});
