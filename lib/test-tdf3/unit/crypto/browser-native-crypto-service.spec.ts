import chai, { expect } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Binary } from '../../../src/tdf3/binary';
import BrowserNativeCryptoService from '../../../src/tdf3/crypto/browser-native-crypto-service';

chai.use(chaiAsPromised);

describe('browser-native-crypto-service', () => {
  const isBrowser = () => typeof window !== 'undefined';
  const service = BrowserNativeCryptoService;

  if (isBrowser()) {
    it('should encrypt with public key and decrypt with private key', async () => {
      const { publicKey, privateKey } = await service.generateKeyPair(2056);
      const rawData = '1';
      const payload = Binary.fromString(rawData);

      const encrypted = await service.encryptWithPublicKey(payload, publicKey);
      const decrypted = await service.decryptWithPrivateKey(encrypted, privateKey);

      expect(decrypted.asString()).to.equal(rawData);
    });
  }

  if (isBrowser()) {
    it('should generate pair with undefined', async () => {
      service.generateKeyPair(undefined).then((obj) => {
        expect(obj).to.have.own.property('publicKey');
      });
    });
  }

  if (isBrowser()) {
    it('should generate key pair', () => {
      service.generateKeyPair(2056).then((res) => {
        expect(res).to.have.own.property('publicKey');
      });
    });
  }

  it('should throw generateKeyPair', async () => {
    const errorMsg = 'Invalid key size requested';
    expect(service.generateKeyPair(0)).to.eventually.throw(errorMsg);
    expect(service.generateKeyPair(null)).to.eventually.throw(errorMsg);
    expect(service.generateKeyPair(2000)).to.eventually.throw(errorMsg);
  });

  if (isBrowser()) {
    it('should generate initialization vector', () => {
      const iv = service.generateInitializationVector(1);
      expect(iv).to.have.lengthOf(2);
    });
  }

  if (isBrowser()) {
    it('should generate key', () => {
      const key = service.generateKey(1);
      expect(key).to.have.lengthOf(2);
    });
  }

  if (isBrowser()) {
    it('should create SHA256 hash', async () => {
      const sha256 = await service.sha256('string');
      const testHash = '473287f8298dba7163a897908958f7c0eae733e25d2e027992ea2edc9bed2fa8';
      expect(sha256).to.equal(testHash);
    });
  }

  if (isBrowser()) {
    it('should create HMAC hash', async () => {
      const hmac = await service.hmac('string', 'content');
      const testHmac = '2cc732a9b86e2ff403e8c0e07ee82e69dcb1820e424d465efe69c63eacb0ee95';
      expect(hmac).to.equal(testHmac);
    });
  }

  if (isBrowser()) {
    it('should create hex to array buffer', () => {
      const ab = service.hex2Ab('22');
      expect(ab).to.have.property('byteLength');
    });
  }
});
