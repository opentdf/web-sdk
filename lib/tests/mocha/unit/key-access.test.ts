import { expect } from 'chai';

import { ECWrapped, Wrapped } from '../../../tdf3/src/models/key-access.js';
import { Policy } from '../../../tdf3/src/models/policy.js';
import { base64 } from '../../../src/encodings/index.js';

describe('ECWrapped', () => {
  const url = 'https://example.com';
  const kid = 'test-kid';
  const publicKey = 'test-public-key';
  const metadata = { key: 'value' };
  const sid = 'test-sid';
  const policy: Policy = { uuid: 'test-policy' };
  const dek = new Uint8Array([1, 2, 3, 4, 5]);
  const encryptedMetadataStr = 'encrypted-metadata';

  ['ECWrapped', 'Wrapped'].forEach((type) => {
    describe(type, () => {
      it(`should write and return a KeyAccessObject for ${type}`, async () => {
        const wrappedInstance = new (type === 'ECWrapped' ? ECWrapped : Wrapped)(
          url,
          kid,
          publicKey,
          metadata,
          sid
        );

        const keyAccessObject = await wrappedInstance.write(policy, dek, encryptedMetadataStr);

        expect(keyAccessObject).to.have.property('type', type.toLowerCase());
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
        expect(keyAccessObject).to.have.property('ephemeralPublicKey', 'ephemeral-public-key-pem');
        expect(keyAccessObject).to.have.property('kid', kid);
        expect(keyAccessObject).to.have.property('sid', sid);
      });
    });
  });

  it('should initialize ECWrapped with correct properties', async () => {
    const ecWrapped = new ECWrapped(url, kid, publicKey, metadata, sid);
    expect(ecWrapped.type).to.equal('ec-wrapped');
    const ek = await ecWrapped.ephemeralKeyPair;
    expect(ek).to.have('publicKey');
  });

  it('should initialize Wrapped with correct properties', async () => {
    const wrapped = new Wrapped(url, kid, publicKey, metadata, sid);
    expect(wrapped.type).to.equal('wrapped');
  });

  it(`should handle undefined kid for ECWrapped`, () => {
    const wrappedInstance = new ECWrapped(url, undefined, publicKey, metadata);
    expect(wrappedInstance.kid).to.be.undefined;
  });

  it(`should handle undefined kid for Wrapped`, () => {
    const wrappedInstance = new Wrapped(url, undefined, publicKey, metadata);
    expect(wrappedInstance.kid).to.be.undefined;
  });

  it(`should handle undefined sid for ECWrapped`, () => {
    const wrappedInstance = new ECWrapped(url, kid, publicKey, metadata);
    expect(wrappedInstance.sid).to.be.undefined;
  });

  it(`should handle undefined sid for Wrapped`, () => {
    const wrappedInstance = new Wrapped(url, kid, publicKey, metadata);
    expect(wrappedInstance.sid).to.be.undefined;
  });
});
