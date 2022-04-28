import chai, { assert, expect } from 'chai';
// @ts-ignore
import chaiAsPromised from 'chai-as-promised';
import { Algorithms } from '../../../src/ciphers';
import { BrowserJsCryptoService } from '../../../src/crypto';
import { Binary } from '../../../src/binary';
// @ts-ignore
import hs256Fixture from '../../__fixtures__/hs256.json';

chai.use(chaiAsPromised);

describe('Browser JS Crypto Service', () => {
  // @ts-ignore
  hs256Fixture.forEach(({ message, key, sig }) => {
    it(`should generate valid hmac for ${key}:${message}`, async () => {
      const hash = await BrowserJsCryptoService.hmac(key, message);
      assert.equal(hash, sig);
    });
  });

  it('should generate valid sha256', async () => {
    const [fixture] = hs256Fixture;

    const hash = await BrowserJsCryptoService.sha256(fixture.message);
    assert.equal(hash, 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb');
  });

  it('should generate key', () => {
    const key = BrowserJsCryptoService.generateKey(0);
    const key2 = BrowserJsCryptoService.generateKey(1);
    const key3 = BrowserJsCryptoService.generateKey(20);
    // @ts-ignore
    const key4 = BrowserJsCryptoService.generateKey(undefined);
    // @ts-ignore
    const key5 = BrowserJsCryptoService.generateKey(null);

    expect(key).to.be.a('string');
    expect(key2).to.have.lengthOf(8);
    expect(key3).to.be.a('string');
    expect(key4).to.be.a('string');
    expect(key5).to.be.a('string');
  });

  describe('generateKeyPair', () => {
    it('should generate pair with undefined', async () =>
      BrowserJsCryptoService.generateKeyPair(undefined).then((obj) => {
        expect(obj).to.have.own.property('publicKey');
      }));

    it('should generate pair', async () =>
      BrowserJsCryptoService.generateKeyPair(2056).then((res) => {
        expect(res).to.have.own.property('publicKey');
      }));

    it('should throw generateKeyPair', async () => {
      const errorMsg = 'Invalid key size requested';
      // @ts-ignore
      expect(BrowserJsCryptoService.generateKeyPair(0)).to.eventually.throw(errorMsg);
      // @ts-ignore
      expect(BrowserJsCryptoService.generateKeyPair(null)).to.eventually.throw(errorMsg);
      // @ts-ignore
      expect(BrowserJsCryptoService.generateKeyPair(2000)).to.eventually.throw(errorMsg);
    });
  });

  it('should generateInitializationVector', async () => {
    expect(BrowserJsCryptoService.generateInitializationVector(1)).to.have.lengthOf(8);
  });

  it('should encrypt with publicKey', async () => {
    console.log('should encrypt with publicKey: A');
    const { publicKey, privateKey } = await BrowserJsCryptoService.generateKeyPair(2048);
    const rawData = '1';
    const payload = Binary.fromString(rawData);
    console.log('should encrypt with publicKey: B');

    const encrypted = await BrowserJsCryptoService.encryptWithPublicKey(payload, publicKey);
    console.log('should encrypt with publicKey: C');
    const decrypted = await BrowserJsCryptoService.decryptWithPrivateKey(encrypted, privateKey);
    console.log('should encrypt with publicKey: D');

    expect(decrypted.asString()).to.equal(rawData);
  });

  it.skip('should encrypt file', async () => {
    const rawData = '1';
    const key = 'key';
    const binaryKey = Binary.fromString(key);
    const algorithm = Algorithms.AES_256_GCM;
    const payload = Binary.fromString(rawData);
    const iv = await BrowserJsCryptoService.generateInitializationVector(1);
    const binaryIV = Binary.fromString(iv);

    const encrypted = BrowserJsCryptoService.encrypt(payload, binaryKey, binaryIV, algorithm);
    // @ts-ignore
    expect(encrypted).to.be.okay;
  });
});
