import { expect } from 'chai';

import { ECWrapped, Wrapped } from '../../../tdf3/src/models/key-access.js';
import { Policy } from '../../../tdf3/src/models/policy.js';
import { base64 } from '../../../src/encodings/index.js';
import type { CryptoService, KeyPair } from '../../../tdf3/src/crypto/declarations.js';
import { Binary } from '../../../tdf3/src/binary.js';
import { importSymmetricKey } from '../../../tdf3/src/crypto/index.js';

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
  async randomBytes(length: number): Promise<Uint8Array> {
    return new Uint8Array(length);
  },
  async encrypt() {
    return {
      payload: Binary.fromArrayBuffer(new Uint8Array(16).buffer),
      authTag: Binary.fromArrayBuffer(new Uint8Array(16).buffer),
    };
  },
  async hmac(): Promise<string> {
    return 'mock-hmac-hash';
  },
  async encryptWithPublicKey() {
    return Binary.fromString('mock-wrapped-key');
  },
  async exportPublicKeyPem() {
    return 'ephemeral-public-key-pem';
  },
} as unknown as CryptoService;

describe('ECWrapped', () => {
  const url = 'https://example.com';
  const kid = 'test-kid';
  const publicKey = 'test-public-key';
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
