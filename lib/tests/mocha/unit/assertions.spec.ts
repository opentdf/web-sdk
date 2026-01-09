// tests for assertions.ts

import { expect } from 'chai';
import { generateKeyPair, SignJWT, exportJWK } from 'jose';

import * as assertions from '../../../tdf3/src/assertions.js';
import { hex, base64 } from '../../../src/encodings/index.js';

describe('assertions', () => {
  describe('isAssertionConfig', () => {
    it('validates config', () => {
      expect(
        assertions.isAssertionConfig({
          id: 'assertion1',
          type: 'handling',
          scope: 'tdo',
          appliesToState: 'unencrypted',
          statement: {
            format: 'base64binary',
            schema: 'text',
            value: 'ICAgIDxlZGoOkVkaD4=',
          },
        })
      ).to.be.true;
    });

    it('normalizes assertions', async () => {
      let assertion: any = {
        appliesToState: 'unencrypted',
        id: 'system-metadata',
        binding: {
          method: 'jws',
          signature: 'test-signature',
        },
        signingKey: {
          alg: 'ES256',
          key: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
        },
        scope: 'payload',
        statement: {
          format: 'json',
          schema: 'system-metadata-v1',
          value:
            '{"tdf_spec_version":"4.3.0","creation_date":"2025-07-23T09:25:51.255364+02:00","operating_system":"Mac OS X","sdk_version":"Java-0.8.2-SNAPSHOT","java_version":"17.0.14","architecture":"aarch64"}',
        },
        type: 'other',
      };

      let h1 = await assertions.hash(assertion);
      delete assertion.signingKey;
      let h2 = await assertions.hash(assertion);

      expect(h1).to.equal(h2);
    });
  });

  describe('verify', () => {
    const aggregateHash = new Uint8Array([1, 2, 3]);
    const isLegacyTDF = false;

    it('should verify assertion using jwk from header', async () => {
      const { publicKey, privateKey } = await generateKeyPair('ES256');
      const jwk = await exportJWK(publicKey);

      const assertion: assertions.Assertion = {
        id: 'test-assertion',
        type: 'handling',
        scope: 'tdo',
        appliesToState: 'unencrypted',
        statement: {
          format: 'json',
          schema: 'test-schema',
          value: '{"foo":"bar"}',
        },
        binding: {
          method: 'jws',
          signature: '',
        },
      };

      const assertionHash = await assertions.hash(assertion);
      const combinedHash = new Uint8Array(aggregateHash.length + 32);
      combinedHash.set(aggregateHash, 0);
      combinedHash.set(new Uint8Array(hex.decodeArrayBuffer(assertionHash)), aggregateHash.length);
      const encodedHash = base64.encodeArrayBuffer(combinedHash);

      const payload: assertions.AssertionPayload = {
        assertionHash,
        assertionSig: encodedHash,
      };

      const token = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'ES256', jwk })
        .sign(privateKey);

      assertion.binding.signature = token;

      // This should now pass because we implemented the fix
      const dummyKey: assertions.AssertionKey = {
        alg: 'HS256',
        key: new Uint8Array(32),
      };

      await assertions.verify(assertion, aggregateHash, dummyKey, isLegacyTDF);
    });

    it('should fallback to provided key if no key in header', async () => {
      const key: assertions.AssertionKey = {
        alg: 'HS256',
        key: new Uint8Array(32).fill(1),
      };

      const assertion: assertions.Assertion = {
        id: 'test-assertion-fallback',
        type: 'handling',
        scope: 'tdo',
        appliesToState: 'unencrypted',
        statement: {
          format: 'json',
          schema: 'test-schema',
          value: '{"foo":"bar"}',
        },
        binding: {
          method: 'jws',
          signature: '',
        },
      };

      const assertionHash = await assertions.hash(assertion);
      const combinedHash = new Uint8Array(aggregateHash.length + 32);
      combinedHash.set(aggregateHash, 0);
      combinedHash.set(new Uint8Array(hex.decodeArrayBuffer(assertionHash)), aggregateHash.length);
      const encodedHash = base64.encodeArrayBuffer(combinedHash);

      const payload: assertions.AssertionPayload = {
        assertionHash,
        assertionSig: encodedHash,
      };

      const token = await new SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).sign(key.key);

      assertion.binding.signature = token;

      await assertions.verify(assertion, aggregateHash, key, isLegacyTDF);
    });
  });
});
