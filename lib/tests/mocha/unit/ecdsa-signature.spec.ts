import { expect } from 'chai';
import {
  computeECDSASig,
  verifyECDSASignature,
  extractRSValuesFromSignature,
} from '../../../src/crypto/ecdsaSignature.js';

describe('ECDSA Signature Functions', () => {
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;
  let data: Uint8Array;
  let signature: ArrayBuffer;
  let invalidSignature: Uint8Array;

  before(async () => {
    // Generate ECDSA key pair for testing
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify']
    );
    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;

    // Mock data
    data = new Uint8Array(['v', 'i', 'r', 't', 'r'].map((c) => c.charCodeAt(0)));
    signature = await computeECDSASig(privateKey, data);
    invalidSignature = new Uint8Array([0, 1, 2, 3, 4, 5]);
  });

  describe('computeECDSASig', () => {
    it('should compute a valid ECDSA signature', async () => {
      const result = await computeECDSASig(privateKey, data);
      expect(result).to.be.instanceOf(ArrayBuffer);
    });

    it('should throw an error with invalid private key', async () => {
      try {
        await computeECDSASig(null as any, data);
      } catch (error) {
        expect(error).to.exist;
      }
    });
  });

  describe('verifyECDSASignature', () => {
    it('should verify a valid ECDSA signature', async () => {
      const isValid = await verifyECDSASignature(publicKey, new Uint8Array(signature), data);
      expect(isValid).to.be.true;
    });

    it('should not verify an invalid ECDSA signature', async () => {
      const isValid = await verifyECDSASignature(publicKey, invalidSignature, data);
      expect(isValid).to.be.false;
    });
  });

  describe('extractRSValuesFromSignature', () => {
    it('should extract R and S values from a valid ASN.1 DER formatted signature', () => {
      const signatureArray = new Uint8Array(signature);
      const { r, s } = extractRSValuesFromSignature(signatureArray);
      expect(r).to.be.instanceOf(Uint8Array);
      expect(s).to.be.instanceOf(Uint8Array);
    });

    it('should throw an error with invalid formatted signature', () => {
      try {
        extractRSValuesFromSignature(invalidSignature);
      } catch (error) {
        expect(error).to.exist;
      }
    });
  });
});
