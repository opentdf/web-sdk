import { assert, expect } from 'chai';

import { Algorithms } from '../../../../tdf3/src/ciphers/index.js';
import {
  decrypt,
  decryptWithPrivateKey,
  deriveKeyFromECDH,
  digest,
  encrypt,
  encryptWithPublicKey,
  exportPublicKeyPem,
  generateECKeyPair,
  generateKey,
  generateKeyPair,
  generateSigningKeyPair,
  hex2Ab,
  parsePublicKeyPem,
  importSymmetricKey,
  jwkToPublicKeyPem,
  randomBytesAsHex,
  sign,
  hmac,
  verifyHmac,
  verify,
} from '../../../../tdf3/src/crypto/index.js';
import { hex } from '../../../../src/encodings/index.js';
import { Binary } from '../../../../tdf3/src/binary.js';
import { decodeArrayBuffer, encodeArrayBuffer } from '../../../../src/encodings/base64.js';

describe('Crypto Service', () => {
  describe('hmac (known-answer)', () => {
    it('a', async () => {
      const keyBytes = new Uint8Array(hex.decodeArrayBuffer('0b'));
      const key = await importSymmetricKey(keyBytes);
      const sig = await hmac(new TextEncoder().encode('a'), key);
      assert.equal(
        hex.encodeArrayBuffer(sig.buffer),
        '481294b9ead3f3c62cab40bbfda108e6678f8536d03264e37a583babbfacafc9'
      );
    });
    it('content with 1-byte key', async () => {
      const keyBytes = new Uint8Array(hex.decodeArrayBuffer('00'));
      const key = await importSymmetricKey(keyBytes);
      const sig = await hmac(new TextEncoder().encode('content'), key);
      assert.equal(
        hex.encodeArrayBuffer(sig.buffer),
        '2cc732a9b86e2ff403e8c0e07ee82e69dcb1820e424d465efe69c63eacb0ee95'
      );
    });
    it('content with 3-byte key', async () => {
      const keyBytes = new Uint8Array(hex.decodeArrayBuffer('000000'));
      const key = await importSymmetricKey(keyBytes);
      const sig = await hmac(new TextEncoder().encode('content'), key);
      assert.equal(
        hex.encodeArrayBuffer(sig.buffer),
        '2cc732a9b86e2ff403e8c0e07ee82e69dcb1820e424d465efe69c63eacb0ee95'
      );
    });
    it('random string', async () => {
      const keyBytes = new Uint8Array(
        hex.decodeArrayBuffer('d3d71c8ad8dd6e99be3eea609f69fd92a2903e2e2f0f064293997cff06ea4a6d')
      );
      const key = await importSymmetricKey(keyBytes);
      const sig = await hmac(new TextEncoder().encode('e12e1b9689c9f3f56f8c185269391577'), key);
      assert.equal(
        hex.encodeArrayBuffer(sig.buffer),
        '185fe0d7324b01a3fbf30e56cd7f868689b3f9c2904642603b6bb969c790ccfc'
      );
    });
  });

  it('should create hex to array buffer', () => {
    const ab = hex2Ab('22');
    expect(ab).to.have.property('byteLength');
  });

  describe('digest (sha256)', () => {
    it('a', async () => {
      const hashBytes = await digest('SHA-256', new TextEncoder().encode('a'));
      assert.equal(
        hex.encodeArrayBuffer(hashBytes.buffer),
        'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
      );
    });
    it('content', async () => {
      const hashBytes = await digest('SHA-256', new TextEncoder().encode('content'));
      assert.equal(
        hex.encodeArrayBuffer(hashBytes.buffer),
        'ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73'
      );
    });
  });

  describe('generateKey', () => {
    it('default length (32 bytes)', async () => {
      const key = await generateKey(0);
      expect(key).to.be.an('object');
      expect(key).to.have.property('_brand', 'SymmetricKey');
      expect(key).to.have.property('length', 32 * 8); // bits
    });
    it('short', async () => {
      const key = await generateKey(1);
      expect(key).to.be.an('object');
      expect(key).to.have.property('_brand', 'SymmetricKey');
      expect(key).to.have.property('length', 1 * 8); // bits
    });
    it('reasonable bytes', async () => {
      const key = await generateKey(20);
      expect(key).to.be.an('object');
      expect(key).to.have.property('_brand', 'SymmetricKey');
      expect(key).to.have.property('length', 20 * 8); // bits
    });
    it('undefined bytes', async () => {
      const key = await generateKey(undefined);
      expect(key).to.be.an('object');
      expect(key).to.have.property('_brand', 'SymmetricKey');
      expect(key).to.have.property('length', 32 * 8); // bits (default)
    });
    it('null bytes', async () => {
      const key = await generateKey();
      expect(key).to.be.an('object');
      expect(key).to.have.property('_brand', 'SymmetricKey');
      expect(key).to.have.property('length', 32 * 8); // bits (default)
    });
  });

  describe('generateKeyPair', () => {
    it('should generate pair with undefined', async () => {
      const obj = await generateKeyPair(undefined);
      expect(obj).to.have.own.property('publicKey');
    });

    it('should generate pair', async () => {
      const res = await generateKeyPair(2048);
      expect(res).to.have.own.property('publicKey');
    });

    it('should generate pair 2048', async () => {
      const res = await generateKeyPair(2048);
      expect(res).to.have.own.property('publicKey');
    });

    describe('throws when', () => {
      it('short length', async () => {
        try {
          await generateKeyPair(1);
          assert.fail();
        } catch (e) {
          expect(e.message).to.match(/Invalid key size requested/);
        }
      });
      it('invalid length', async () => {
        try {
          await generateKeyPair(2000);
          assert.fail();
        } catch (e) {
          expect(e.message).to.match(/Invalid key size requested/);
        }
      });
    });
  });

  describe('randomBytesAsHex', () => {
    it('1 byte', async () => {
      const randomHexBytes = await randomBytesAsHex(1);
      expect(randomHexBytes).to.have.lengthOf(2);
    });
    it('10 bytes', async () => {
      const randomHexBytes2 = await randomBytesAsHex(10);
      expect(randomHexBytes2).to.have.lengthOf(20);
    });
  });

  it('should encrypt with public key and decrypt with private key', async () => {
    const { publicKey, privateKey } = await generateKeyPair(2048);
    const rawData = '1';
    const payload = Binary.fromString(rawData);

    const encrypted = await encryptWithPublicKey(payload, publicKey);
    const decrypted = await decryptWithPrivateKey(encrypted, privateKey);

    expect(decrypted.asString()).to.equal(rawData);
  });

  it('should encrypt with publicKey', async () => {
    const { publicKey, privateKey } = await generateKeyPair(2048);
    const rawData = '1';
    const payload = Binary.fromString(rawData);

    const encrypted = await encryptWithPublicKey(payload, publicKey);
    const decrypted = await decryptWithPrivateKey(encrypted, privateKey);

    expect(decrypted.asString()).to.equal(rawData);
  });

  it('should encrypt file', async () => {
    const rawData = '1';
    const keyBytes = new Uint8Array(
      // crypto.scryptSync('test', 'salt', 32) =>
      decodeArrayBuffer('cvR6X2vLG5ap13ssLxRjOV1KOjJfraYpD8D+97zdtY4=')
    );
    const symmetricKey = await importSymmetricKey(keyBytes);
    const algorithm = Algorithms.AES_256_GCM;
    const payload = Binary.fromString(rawData);
    const iv = '0'.repeat(32);
    const binaryIV = Binary.fromString(iv);

    const encrypted = await encrypt(payload, symmetricKey, binaryIV, algorithm);
    expect(encodeArrayBuffer(encrypted.payload.asArrayBuffer())).to.eql('8Q==');
    const expectArrayBuffer = (encrypted.authTag as Binary).asArrayBuffer();
    expect(encodeArrayBuffer(expectArrayBuffer)).to.eql('d0HF3e42QRxb5nnvFl57ZQ==');
  });

  it('should encrypt with pub key and decrypt with private', async () => {
    const { publicKey, privateKey } = await generateKeyPair(2048);
    const rawData = '1';
    const payload = Binary.fromString(rawData);

    const encrypted = await encryptWithPublicKey(payload, publicKey);
    const decrypted = await decryptWithPrivateKey(encrypted, privateKey);

    expect(encrypted.asString()).to.not.eql('1');
    expect(decrypted.asString()).to.equal(rawData);
  });

  it('should encrypt with aes_256_gcm and decrypt', async () => {
    const rawData = '1';
    const payload = Binary.fromString(rawData);

    const keyBytes = new Uint8Array(
      // crypto.scryptSync('test', 'salt', 32) =>
      decodeArrayBuffer('cvR6X2vLG5ap13ssLxRjOV1KOjJfraYpD8D+97zdtY4=')
    );
    const key = await importSymmetricKey(keyBytes);
    const iv = Binary.fromString(await randomBytesAsHex(16));
    const algo = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';

    const encrypted = await encrypt(payload, key, iv, algo);
    expect(encrypted).to.have.property('authTag');
    const decrypted = await decrypt(encrypted.payload, key, iv, algo, encrypted.authTag);
    expect(decrypted.payload.asString()).to.be.equal(rawData);
  });

  describe('generateECKeyPair', () => {
    it('should generate P-256 key pair', async () => {
      const keyPair = await generateECKeyPair('P-256');
      expect(keyPair).to.have.property('publicKey');
      expect(keyPair).to.have.property('privateKey');
      expect(keyPair.publicKey).to.have.property('_brand', 'PublicKey');
      expect(keyPair.publicKey).to.have.property('algorithm', 'ec:secp256r1');
      expect(keyPair.publicKey).to.have.property('curve', 'P-256');
      expect(keyPair.privateKey).to.have.property('_brand', 'PrivateKey');
      expect(keyPair.privateKey).to.have.property('algorithm', 'ec:secp256r1');
      expect(keyPair.privateKey).to.have.property('curve', 'P-256');
    });

    it('should generate P-384 key pair', async () => {
      const keyPair = await generateECKeyPair('P-384');
      expect(keyPair).to.have.property('publicKey');
      expect(keyPair).to.have.property('privateKey');
      expect(keyPair.publicKey).to.have.property('algorithm', 'ec:secp384r1');
      expect(keyPair.publicKey).to.have.property('curve', 'P-384');
    });

    it('should generate P-521 key pair', async () => {
      const keyPair = await generateECKeyPair('P-521');
      expect(keyPair).to.have.property('publicKey');
      expect(keyPair).to.have.property('privateKey');
      expect(keyPair.publicKey).to.have.property('algorithm', 'ec:secp521r1');
      expect(keyPair.publicKey).to.have.property('curve', 'P-521');
    });

    it('should default to P-256', async () => {
      const keyPair = await generateECKeyPair();
      expect(keyPair).to.have.property('publicKey');
      expect(keyPair).to.have.property('privateKey');
      expect(keyPair.publicKey).to.have.property('algorithm', 'ec:secp256r1');
    });
  });

  describe('deriveKeyFromECDH', () => {
    it('should derive key from ECDH with P-256', async () => {
      const aliceKeys = await generateECKeyPair('P-256');
      const bobKeys = await generateECKeyPair('P-256');

      const aliceDerivedKey = await deriveKeyFromECDH(aliceKeys.privateKey, bobKeys.publicKey, {
        hash: 'SHA-256',
        salt: new Uint8Array(16),
        info: new Uint8Array(0),
        keyLength: 256,
      });

      const bobDerivedKey = await deriveKeyFromECDH(bobKeys.privateKey, aliceKeys.publicKey, {
        hash: 'SHA-256',
        salt: new Uint8Array(16),
        info: new Uint8Array(0),
        keyLength: 256,
      });

      // Now returns SymmetricKey instead of Uint8Array
      expect(aliceDerivedKey).to.have.property('_brand', 'SymmetricKey');
      expect(aliceDerivedKey).to.have.property('length', 256); // 256 bits
      expect(bobDerivedKey).to.have.property('_brand', 'SymmetricKey');
      expect(bobDerivedKey).to.have.property('length', 256); // 256 bits
      // Keys should be equal (deep comparison of opaque structure)
      expect(aliceDerivedKey).to.deep.equal(bobDerivedKey);
    });

    it('should derive key from ECDH with P-384', async () => {
      const aliceKeys = await generateECKeyPair('P-384');
      const bobKeys = await generateECKeyPair('P-384');

      const aliceDerivedKey = await deriveKeyFromECDH(aliceKeys.privateKey, bobKeys.publicKey, {
        hash: 'SHA-384',
        salt: new Uint8Array(16),
        keyLength: 256,
      });

      const bobDerivedKey = await deriveKeyFromECDH(bobKeys.privateKey, aliceKeys.publicKey, {
        hash: 'SHA-384',
        salt: new Uint8Array(16),
        keyLength: 256,
      });

      expect(aliceDerivedKey).to.deep.equal(bobDerivedKey);
      expect(aliceDerivedKey).to.have.property('length', 256); // 256 bits
    });
  });

  describe('hmac and verifyHmac', () => {
    it('should sign and verify with HMAC-SHA256', async () => {
      const data = new TextEncoder().encode('test data');
      const keyBytes = new Uint8Array(32);
      crypto.getRandomValues(keyBytes);
      const key = await importSymmetricKey(keyBytes);

      const signature = await hmac(data, key);
      expect(signature).to.have.lengthOf(32);

      const valid = await verifyHmac(data, signature, key);
      expect(valid).to.be.true;
    });

    it('should reject invalid signature', async () => {
      const data = new TextEncoder().encode('test data');
      const keyBytes = new Uint8Array(32);
      crypto.getRandomValues(keyBytes);
      const key = await importSymmetricKey(keyBytes);

      const signature = await hmac(data, key);
      signature[0] ^= 0xff;

      const valid = await verifyHmac(data, signature, key);
      expect(valid).to.be.false;
    });

    it('should reject wrong key', async () => {
      const data = new TextEncoder().encode('test data');
      const key1 = await importSymmetricKey(crypto.getRandomValues(new Uint8Array(32)));
      const key2 = await importSymmetricKey(crypto.getRandomValues(new Uint8Array(32)));

      const signature = await hmac(data, key1);
      const valid = await verifyHmac(data, signature, key2);
      expect(valid).to.be.false;
    });
  });

  describe('parsePublicKeyPem', () => {
    it('should import RSA public key', async () => {
      const keyPair = await generateKeyPair(2048);
      const publicKeyPem = await exportPublicKeyPem(keyPair.publicKey);

      const result = await parsePublicKeyPem(publicKeyPem);
      expect(result.algorithm).to.equal('rsa:2048');
      expect(result.pem).to.equal(publicKeyPem);
    });

    it('should import EC P-256 public key', async () => {
      const ecKeyPair = await generateECKeyPair('P-256');
      const publicKeyPem = await exportPublicKeyPem(ecKeyPair.publicKey);

      const result = await parsePublicKeyPem(publicKeyPem);
      expect(result.algorithm).to.equal('ec:secp256r1');
      expect(result.pem).to.equal(publicKeyPem);
    });

    it('should import EC P-384 public key', async () => {
      const ecKeyPair = await generateECKeyPair('P-384');
      const publicKeyPem = await exportPublicKeyPem(ecKeyPair.publicKey);

      const result = await parsePublicKeyPem(publicKeyPem);
      expect(result.algorithm).to.equal('ec:secp384r1');
      expect(result.pem).to.equal(publicKeyPem);
    });

    it('should import EC P-521 public key', async () => {
      const ecKeyPair = await generateECKeyPair('P-521');
      const publicKeyPem = await exportPublicKeyPem(ecKeyPair.publicKey);

      const result = await parsePublicKeyPem(publicKeyPem);
      expect(result.algorithm).to.equal('ec:secp521r1');
      expect(result.pem).to.equal(publicKeyPem);
    });
  });

  describe('sign and verify with ES256', () => {
    // Note: generateECKeyPair() generates ECDH keys for key agreement, not signing.
    // For ES256 signing tests, we generate ECDSA keys directly.
    it('should sign and verify with ES256', async () => {
      // Generate ECDSA key pair for signing (not ECDH)
      const webCryptoKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );
      // Wrap as opaque keys
      const ecKeyPair = {
        publicKey: {
          _brand: 'PublicKey',
          algorithm: 'ec:secp256r1',
          curve: 'P-256',
          _internal: webCryptoKeyPair.publicKey,
        } as any,
        privateKey: {
          _brand: 'PrivateKey',
          algorithm: 'ec:secp256r1',
          curve: 'P-256',
          _internal: webCryptoKeyPair.privateKey,
        } as any,
      };
      const data = new TextEncoder().encode('test data for ECDSA');

      const signature = await sign(data, ecKeyPair.privateKey, 'ES256');
      expect(signature).to.be.instanceOf(Uint8Array);

      const valid = await verify(data, signature, ecKeyPair.publicKey, 'ES256');
      expect(valid).to.be.true;
    });

    it('should reject tampered data with ES256', async () => {
      const webCryptoKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );
      const ecKeyPair = {
        publicKey: {
          _brand: 'PublicKey',
          algorithm: 'ec:secp256r1',
          curve: 'P-256',
          _internal: webCryptoKeyPair.publicKey,
        } as any,
        privateKey: {
          _brand: 'PrivateKey',
          algorithm: 'ec:secp256r1',
          curve: 'P-256',
          _internal: webCryptoKeyPair.privateKey,
        } as any,
      };
      const data = new TextEncoder().encode('original data');
      const tamperedData = new TextEncoder().encode('tampered data');

      const signature = await sign(data, ecKeyPair.privateKey, 'ES256');
      const valid = await verify(tamperedData, signature, ecKeyPair.publicKey, 'ES256');
      expect(valid).to.be.false;
    });

    it('should sign and verify with ES384', async () => {
      const webCryptoKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign', 'verify']
      );
      const ecKeyPair = {
        publicKey: {
          _brand: 'PublicKey',
          algorithm: 'ec:secp384r1',
          curve: 'P-384',
          _internal: webCryptoKeyPair.publicKey,
        } as any,
        privateKey: {
          _brand: 'PrivateKey',
          algorithm: 'ec:secp384r1',
          curve: 'P-384',
          _internal: webCryptoKeyPair.privateKey,
        } as any,
      };
      const data = new TextEncoder().encode('test data for ES384');

      const signature = await sign(data, ecKeyPair.privateKey, 'ES384');
      const valid = await verify(data, signature, ecKeyPair.publicKey, 'ES384');
      expect(valid).to.be.true;
    });

    it('should sign and verify with ES512', async () => {
      const webCryptoKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-521' },
        true,
        ['sign', 'verify']
      );
      const ecKeyPair = {
        publicKey: {
          _brand: 'PublicKey',
          algorithm: 'ec:secp521r1',
          curve: 'P-521',
          _internal: webCryptoKeyPair.publicKey,
        } as any,
        privateKey: {
          _brand: 'PrivateKey',
          algorithm: 'ec:secp521r1',
          curve: 'P-521',
          _internal: webCryptoKeyPair.privateKey,
        } as any,
      };
      const data = new TextEncoder().encode('test data for ES512');

      const signature = await sign(data, ecKeyPair.privateKey, 'ES512');
      const valid = await verify(data, signature, ecKeyPair.publicKey, 'ES512');
      expect(valid).to.be.true;
    });
  });

  describe('sign and verify with RS256', () => {
    it('should sign and verify with RS256', async () => {
      const pemPair = await generateSigningKeyPair();
      const data = new TextEncoder().encode('test data for RSA');

      const signature = await sign(data, pemPair.privateKey, 'RS256');
      expect(signature).to.be.instanceOf(Uint8Array);

      const valid = await verify(data, signature, pemPair.publicKey, 'RS256');
      expect(valid).to.be.true;
    });

    it('should reject tampered data with RS256', async () => {
      const pemPair = await generateSigningKeyPair();
      const data = new TextEncoder().encode('original data');
      const tamperedData = new TextEncoder().encode('tampered data');

      const signature = await sign(data, pemPair.privateKey, 'RS256');
      const valid = await verify(tamperedData, signature, pemPair.publicKey, 'RS256');
      expect(valid).to.be.false;
    });
  });

  describe('digest', () => {
    it('should compute SHA-256 digest', async () => {
      const data = new TextEncoder().encode('test');
      const hash = await digest('SHA-256', data);
      expect(hash).to.have.lengthOf(32);
    });

    it('should compute SHA-384 digest', async () => {
      const data = new TextEncoder().encode('test');
      const hash = await digest('SHA-384', data);
      expect(hash).to.have.lengthOf(48);
    });

    it('should compute SHA-512 digest', async () => {
      const data = new TextEncoder().encode('test');
      const hash = await digest('SHA-512', data);
      expect(hash).to.have.lengthOf(64);
    });
  });

  describe('jwkToPublicKeyPem', () => {
    it('should convert RSA JWK to PEM', async () => {
      // Generate an RSA key pair and export to JWK
      const rsaKeyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );
      const jwk = await crypto.subtle.exportKey('jwk', rsaKeyPair.publicKey);

      const pem = await jwkToPublicKeyPem(jwk);
      expect(pem).to.include('-----BEGIN PUBLIC KEY-----');
      expect(pem).to.include('-----END PUBLIC KEY-----');
    });

    it('should convert EC P-256 JWK to PEM', async () => {
      // Generate an EC key pair and export to JWK
      const ecKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
      );
      const jwk = await crypto.subtle.exportKey('jwk', ecKeyPair.publicKey);

      const pem = await jwkToPublicKeyPem(jwk);
      expect(pem).to.include('-----BEGIN PUBLIC KEY-----');
      expect(pem).to.include('-----END PUBLIC KEY-----');

      // Verify the PEM can be imported back
      const keyInfo = await parsePublicKeyPem(pem);
      expect(keyInfo.algorithm).to.equal('ec:secp256r1');
    });

    it('should convert EC P-384 JWK to PEM', async () => {
      const ecKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        ['deriveBits']
      );
      const jwk = await crypto.subtle.exportKey('jwk', ecKeyPair.publicKey);

      const pem = await jwkToPublicKeyPem(jwk);
      expect(pem).to.include('-----BEGIN PUBLIC KEY-----');

      const keyInfo = await parsePublicKeyPem(pem);
      expect(keyInfo.algorithm).to.equal('ec:secp384r1');
    });
  });
});
