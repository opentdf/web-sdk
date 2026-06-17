import { expect } from 'chai';

import { ECWrapped, MlKemWrapped, Wrapped } from '../../../tdf3/src/models/key-access.js';
import { Policy } from '../../../tdf3/src/models/policy.js';
import { base64 } from '../../../src/encodings/index.js';
import { ConfigurationError } from '../../../src/errors.js';
import type { CryptoService, KeyPair } from '../../../tdf3/src/crypto/declarations.js';
import { Binary } from '../../../tdf3/src/binary.js';
import { importSymmetricKey } from '../../../tdf3/src/crypto/index.js';
import { buildKeyAccess } from '../../../tdf3/src/tdf.js';

// Mock CryptoService for testing
const mockCryptoService: CryptoService = {
  async generateECKeyPair(): Promise<KeyPair> {
    return {
      publicKey: { _brand: 'PublicKey', algorithm: 'ec:secp256r1', curve: 'P-256' } as any,
      privateKey: { _brand: 'PrivateKey', algorithm: 'ec:secp256r1', curve: 'P-256' } as any,
    };
  },
  async deriveKeyFromECDH() {
    const keyBytes = new Uint8Array(32);
    return await importSymmetricKey(keyBytes);
  },
  async generateMlKemKeyPair(): Promise<KeyPair> {
    return {
      publicKey: { _brand: 'PublicKey', algorithm: 'mlkem:768', mlKemLevel: 768 } as any,
      privateKey: { _brand: 'PrivateKey', algorithm: 'mlkem:768', mlKemLevel: 768 } as any,
    };
  },
  async mlKemEncapsulate() {
    return {
      ciphertext: new Uint8Array([1, 2, 3, 4]),
      sharedSecret: await importSymmetricKey(new Uint8Array(32)),
    };
  },
  async mlKemDecapsulate() {
    return await importSymmetricKey(new Uint8Array(32));
  },
  async randomBytes(length: number): Promise<Uint8Array> {
    return new Uint8Array(length);
  },
  async digest() {
    return new Uint8Array(32);
  },
  async encrypt() {
    return {
      payload: Binary.fromArrayBuffer(new Uint8Array(16).buffer),
      authTag: Binary.fromArrayBuffer(new Uint8Array(16).buffer),
    };
  },
  async hmac(): Promise<Uint8Array> {
    return new Uint8Array(32);
  },
  async encryptWithPublicKey() {
    return Binary.fromString('mock-wrapped-key');
  },
  async importPublicKey() {
    return { _brand: 'PublicKey', algorithm: 'rsa:2048' } as any;
  },
  async exportPublicKeyPem() {
    return 'ephemeral-public-key-pem';
  },
} as unknown as CryptoService;

describe('ECWrapped', () => {
  const url = 'https://example.com';
  const kid = 'test-kid';
  const publicKey = 'test-public-key';
  const rawMlKemPublicKey = base64.encodeArrayBuffer(new Uint8Array(1184).buffer);
  const metadata = { key: 'value' };
  const sid = 'test-sid';
  const policy: Policy = { uuid: 'test-policy' };
  const dekBytes = new Uint8Array([1, 2, 3, 4, 5]);
  const encryptedMetadataStr = 'encrypted-metadata';

  ['ECWrapped', 'Wrapped'].forEach((typeName) => {
    describe(typeName, () => {
      it(`should write and return a KeyAccessObject for ${typeName}`, async () => {
        const wrappedInstance = new (typeName === 'ECWrapped' ? ECWrapped : Wrapped)(
          url,
          kid,
          publicKey,
          metadata,
          mockCryptoService,
          sid
        );

        const dek = await importSymmetricKey(dekBytes);
        const keyAccessObject = await wrappedInstance.write(policy, dek, encryptedMetadataStr);

        // Type value has hyphen for ec-wrapped, no hyphen for wrapped
        const expectedType = typeName === 'ECWrapped' ? 'ec-wrapped' : 'wrapped';
        expect(keyAccessObject).to.have.property('type', expectedType);
        expect(keyAccessObject).to.have.property('url', url);
        expect(keyAccessObject).to.have.property('protocol', 'kas');
        expect(keyAccessObject).to.have.property('wrappedKey');
        expect(keyAccessObject).to.have.property(
          'encryptedMetadata',
          base64.encode(encryptedMetadataStr)
        );
        expect(keyAccessObject).to.have.property('policyBinding');
        expect(keyAccessObject.policyBinding).to.have.property('alg', 'HS256');
        expect(keyAccessObject.policyBinding).to.have.property('hash');
        expect(keyAccessObject).to.have.property('schemaVersion', '1.0');
        // Only ECWrapped has ephemeralPublicKey
        if (typeName === 'ECWrapped') {
          expect(keyAccessObject).to.have.property(
            'ephemeralPublicKey',
            'ephemeral-public-key-pem'
          );
        }
        expect(keyAccessObject).to.have.property('kid', kid);
        expect(keyAccessObject).to.have.property('sid', sid);
      });
    });
  });

  it('should initialize ECWrapped with correct properties', async () => {
    const ecWrapped = new ECWrapped(url, kid, publicKey, metadata, mockCryptoService, sid);
    expect(ecWrapped.type).to.equal('ec-wrapped');
    const ek = await ecWrapped.ephemeralKeyPair;
    expect(ek).to.have.property('publicKey');
  });

  it('should initialize Wrapped with correct properties', async () => {
    const wrapped = new Wrapped(url, kid, publicKey, metadata, mockCryptoService, sid);
    expect(wrapped.type).to.equal('wrapped');
  });

  it('should write and preserve the ML-KEM wrapped key layout', async () => {
    const wrapped = new MlKemWrapped(
      url,
      kid,
      rawMlKemPublicKey,
      'mlkem:768',
      metadata,
      mockCryptoService,
      sid
    );

    const dek = await importSymmetricKey(dekBytes);
    const keyAccessObject = await wrapped.write(policy, dek, encryptedMetadataStr);
    const wrappedKey = new Uint8Array(base64.decodeArrayBuffer(keyAccessObject.wrappedKey || ''));

    expect(keyAccessObject.type).to.equal('wrapped');
    expect(wrappedKey.byteLength).to.equal(4 + 12 + 16 + 16);
    expect(Array.from(wrappedKey.slice(0, 4))).to.deep.equal([1, 2, 3, 4]);
    expect(Array.from(wrappedKey.slice(4))).to.deep.equal(Array.from(new Uint8Array(44)));
  });

  it('should require a non-empty kid for MlKemWrapped', () => {
    expect(
      () =>
        new MlKemWrapped(url, '', rawMlKemPublicKey, 'mlkem:768', metadata, mockCryptoService, sid)
    ).to.throw(ConfigurationError, 'ML-KEM wrapped key access requires a non-empty kid');
  });

  it('should reject undefined kid for MlKemWrapped', () => {
    expect(
      () =>
        new MlKemWrapped(
          url,
          undefined as unknown as string,
          rawMlKemPublicKey,
          'mlkem:768',
          metadata,
          mockCryptoService,
          sid
        )
    ).to.throw(ConfigurationError, 'ML-KEM wrapped key access requires a non-empty kid');
  });

  it('should build an ML-KEM key access when kid is present', async () => {
    const wrapped = await buildKeyAccess({
      type: 'wrapped',
      alg: 'mlkem:768',
      url,
      kid,
      publicKey: rawMlKemPublicKey,
      metadata,
      sid,
      cryptoService: mockCryptoService,
    });

    expect(wrapped).to.be.instanceOf(MlKemWrapped);
    expect(wrapped.kid).to.equal(kid);
  });

  it('should reject missing kid when building ML-KEM key access', async () => {
    try {
      await buildKeyAccess({
        type: 'wrapped',
        alg: 'mlkem:768',
        url,
        publicKey: rawMlKemPublicKey,
        metadata,
        sid,
        cryptoService: mockCryptoService,
      });
      expect.fail('Expected buildKeyAccess to throw');
    } catch (error) {
      expect(error).to.be.instanceOf(ConfigurationError);
      expect((error as Error).message).to.include(
        'ML-KEM wrapped key access requires a non-empty kid'
      );
    }
  });

  it('should reject empty kid when building ML-KEM key access', async () => {
    try {
      await buildKeyAccess({
        type: 'wrapped',
        alg: 'mlkem:768',
        url,
        kid: '',
        publicKey: rawMlKemPublicKey,
        metadata,
        sid,
        cryptoService: mockCryptoService,
      });
      expect.fail('Expected buildKeyAccess to throw');
    } catch (error) {
      expect(error).to.be.instanceOf(ConfigurationError);
      expect((error as Error).message).to.include(
        'ML-KEM wrapped key access requires a non-empty kid'
      );
    }
  });

  it(`should handle undefined kid for ECWrapped`, () => {
    const wrappedInstance = new ECWrapped(url, undefined, publicKey, metadata, mockCryptoService);
    expect(wrappedInstance.kid).to.be.undefined;
  });

  it(`should handle undefined kid for Wrapped`, () => {
    const wrappedInstance = new Wrapped(url, undefined, publicKey, metadata, mockCryptoService);
    expect(wrappedInstance.kid).to.be.undefined;
  });

  it(`should handle undefined sid for ECWrapped`, () => {
    const wrappedInstance = new ECWrapped(url, kid, publicKey, metadata, mockCryptoService);
    expect(wrappedInstance.sid).to.be.undefined;
  });

  it(`should handle undefined sid for Wrapped`, () => {
    const wrappedInstance = new Wrapped(url, kid, publicKey, metadata, mockCryptoService);
    expect(wrappedInstance.sid).to.be.undefined;
  });
});
