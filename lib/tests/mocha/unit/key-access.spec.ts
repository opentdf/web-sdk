import { expect } from 'chai';

import { ECWrapped, Wrapped, policyBindingHash } from '../../../tdf3/src/models/key-access.js';
import type { Policy } from '../../../tdf3/src/models/policy.js';
import { base64 } from '../../../src/encodings/index.js';
import type { CryptoService, KeyPair, PublicKey } from '../../../tdf3/src/crypto/declarations.js';
import { Binary } from '../../../tdf3/src/binary.js';
import { importSymmetricKey } from '../../../tdf3/src/crypto/index.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';

// Mock CryptoService for testing
const mockCryptoService: CryptoService = {
  importPublicKey(): Promise<PublicKey> {
    return Promise.resolve({ _brand: 'PublicKey', algorithm: 'rsa:2048', modulusBits: 2048 });
  },
  generateECKeyPair(): Promise<KeyPair> {
    return Promise.resolve({
      publicKey: { _brand: 'PublicKey', algorithm: 'ec:secp256r1', curve: 'P-256' },
      privateKey: { _brand: 'PrivateKey', algorithm: 'ec:secp256r1', curve: 'P-256' },
    });
  },
  async deriveKeyFromECDH() {
    const keyBytes = new Uint8Array(32);
    return await importSymmetricKey(keyBytes);
  },
  randomBytes(length: number): Promise<Uint8Array> {
    return Promise.resolve(new Uint8Array(length));
  },
  encrypt() {
    return Promise.resolve({
      payload: Binary.fromArrayBuffer(new Uint8Array(16).buffer),
      authTag: Binary.fromArrayBuffer(new Uint8Array(16).buffer),
    });
  },
  hmac(): Promise<Uint8Array> {
    return Promise.resolve(new Uint8Array(32));
  },
  digest(): Promise<Uint8Array> {
    return Promise.resolve(new Uint8Array(32));
  },
  encryptWithPublicKey() {
    return Promise.resolve(Binary.fromString('mock-wrapped-key'));
  },
  exportPublicKeyPem() {
    return Promise.resolve('ephemeral-public-key-pem');
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

      it(`writes a 32-byte policy binding for ${typeName} when hexless is set`, async () => {
        const wrappedInstance = new (typeName === 'ECWrapped' ? ECWrapped : Wrapped)(
          url,
          kid,
          publicKey,
          metadata,
          mockCryptoService,
          sid
        );
        const dek = await importSymmetricKey(dekBytes);

        const legacy = await wrappedInstance.write(policy, dek, encryptedMetadataStr);
        expect(base64.decodeArrayBuffer(legacy.policyBinding!.hash).byteLength).to.equal(64);

        const hexless = await wrappedInstance.write(policy, dek, encryptedMetadataStr, true);
        expect(base64.decodeArrayBuffer(hexless.policyBinding!.hash).byteLength).to.equal(32);
      });
    });
  });

  it('should initialize ECWrapped with correct properties', async () => {
    const ecWrapped = new ECWrapped(url, kid, publicKey, metadata, mockCryptoService, sid);
    expect(ecWrapped.type).to.equal('ec-wrapped');
    const ek = await ecWrapped.ephemeralKeyPair;
    expect(ek).to.have.property('publicKey');
  });

  it('should initialize Wrapped with correct properties', () => {
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

describe('policyBindingHash', () => {
  it('should compute known answer legacy binding', async () => {
    // Known-answer test from Go's TestCreatePolicyBinding
    const fixedKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      fixedKey[i] = i;
    }
    const dek = await importSymmetricKey(fixedKey);
    const policyStr = JSON.stringify({ uuid: 'test' });

    const binding = await policyBindingHash(DefaultCryptoService, policyStr, dek, false);

    expect(binding).to.equal(
      'YzFjZTM3OWQ0Y2FiMTZkNmRhNzJkYjllYWQ2NGQ3Y2I0Y2E5YmRhY2FiOGMwNjg1ZmY5MmUzZjc0YWEyYzEyZA=='
    );
  });

  it('should compute known answer hexless binding', async () => {
    // Known-answer test from Go's TestCreatePolicyBinding (hexless variant)
    const fixedKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      fixedKey[i] = i;
    }
    const dek = await importSymmetricKey(fixedKey);
    const policyStr = JSON.stringify({ uuid: 'test' });

    const binding = await policyBindingHash(DefaultCryptoService, policyStr, dek, true);

    expect(binding).to.equal('wc43nUyrFtbactuerWTXy0ypvayrjAaF/5Lj90qiwS0=');
  });

  it('should use the injected crypto service hmac', async () => {
    let hmacCalled = false;
    const testCryptoService = {
      ...mockCryptoService,
      hmac() {
        hmacCalled = true;
        return Promise.resolve(new Uint8Array(32));
      },
    } as unknown as CryptoService;

    const fixedKey = new Uint8Array(32);
    const dek = await importSymmetricKey(fixedKey);
    const policyStr = JSON.stringify({ uuid: 'test' });

    await policyBindingHash(testCryptoService, policyStr, dek, false);

    expect(hmacCalled).to.be.true;
  });
});
