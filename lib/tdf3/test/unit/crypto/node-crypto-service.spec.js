import { expect } from 'chai';
import crypto from 'crypto';
import { Binary } from '../../../src/binary';
import NodeCryptoService from '../../../src/crypto/node-crypto-service';

const {
  decrypt,
  decryptWithPrivateKey,
  encrypt,
  encryptWithPublicKey,
  generateInitializationVector,
  generateKey,
  generateKeyPair,
  hmac,
  randomBytesAsHex,
  sha256,
} = NodeCryptoService;

describe('NodeCryptoService', () => {
  const isNode = () => typeof window === 'undefined';

  if (isNode()) {
    it('should generate sha256 hash', async () => {
      const hash = await sha256('content');
      const testHash = 'ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73';

      expect(hash).to.be.equal(testHash);
    });
  }

  if (isNode()) {
    it('should generate hmac hash', async () => {
      const hash = await hmac('key', 'content');
      const testHash = '2cc732a9b86e2ff403e8c0e07ee82e69dcb1820e424d465efe69c63eacb0ee95';

      expect(hash).to.be.equal(testHash);
    });
  }

  if (isNode()) {
    it('should generate random bytes as hex', () => {
      const randomHexBytes = randomBytesAsHex(1);
      const randomHexBytes2 = randomBytesAsHex(10);

      expect(randomHexBytes).to.have.lengthOf(2);
      expect(randomHexBytes2).to.have.lengthOf(20);
    });
  }

  if (isNode()) {
    it('should generate iv', () => {
      const iv = generateInitializationVector(1);
      const iv2 = generateInitializationVector(null);
      const iv3 = generateInitializationVector(0);
      const iv4 = generateInitializationVector(undefined);

      expect(iv).to.have.lengthOf(2);
      expect(iv2).to.have.lengthOf(32);
      expect(iv3).to.have.lengthOf(32);
      expect(iv4).to.have.lengthOf(32);
    });
  }

  if (isNode()) {
    it('should generate key', () => {
      const key = generateKey();
      const key2 = generateKey(undefined);
      const key3 = generateKey(1);

      expect(key).to.have.lengthOf(64);
      expect(key2).to.have.lengthOf(64);
      expect(key3).to.have.lengthOf(2);
    });
  }

  describe('generate key pair', () => {
    if (isNode()) {
      it('should generate key pair', async () => {
        generateKeyPair(undefined).then((obj) => {
          expect(obj).to.have.own.property('publicKey');
        });

        generateKeyPair(2049).then((res) => {
          expect(res).to.have.own.property('publicKey');
        });
      });
    }

    if (isNode()) {
      it('should throw an error', () => {
        expect(() => generateKeyPair(2000)).to.throw(Error, /Invalid key size requested/);
      });
    }
  });

  if (isNode()) {
    it('should encrypt with pub key and decrypt with private', async () => {
      const { publicKey, privateKey } = await generateKeyPair(2049);
      const rawData = '1';
      const payload = Binary.fromString(rawData);

      const encrypted = await encryptWithPublicKey(payload, publicKey);
      const decrypted = await decryptWithPrivateKey(encrypted, privateKey);

      expect(encrypted.asString()).to.not.eql('1');
      expect(decrypted.asString()).to.equal(rawData);
    });
  }

  if (isNode()) {
    it('should encrypt with aes_256_gcm and decrypt', async () => {
      const rawData = '1';
      const payload = Binary.fromString(rawData);

      const key = Binary.fromBuffer(crypto.scryptSync('test', 'salt', 32));
      const iv = Binary.fromString(generateInitializationVector(16));
      const algo = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';

      const encrypted = await encrypt(payload, key, iv, algo);
      expect(encrypted).to.have.property('authTag');
      const decrypted = await decrypt(encrypted.payload, key, iv, algo, encrypted.authTag);
      expect(decrypted.payload.asString()).to.be.equal(rawData);
    });
  }
});
