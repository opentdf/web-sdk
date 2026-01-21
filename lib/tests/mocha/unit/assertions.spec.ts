// tests for assertions.ts

import { expect } from 'chai';

import * as assertions from '../../../tdf3/src/assertions.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import { hex, base64 } from '../../../src/encodings/index.js';
import { signJwt } from '../../../tdf3/src/crypto/jwt.js';
import type { CryptoService } from '../../../tdf3/src/crypto/declarations.js';

describe('assertions', () => {
  const cryptoService: CryptoService = DefaultCryptoService;

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

      let h1 = await assertions.hash(assertion, cryptoService);
      delete assertion.signingKey;
      let h2 = await assertions.hash(assertion, cryptoService);

      expect(h1).to.equal(h2);
    });
  });

  describe('verify', () => {
    const aggregateHash = new Uint8Array([1, 2, 3]);
    const isLegacyTDF = false;

    it('should verify assertion using jwk from header', async () => {
      // Generate EC key pair for ES256
      const keyPair = await cryptoService.generateECKeyPair('P-256');
      // Get JWK from the public key
      const publicKeyBuffer = await crypto.subtle.importKey(
        'spki',
        pemToArrayBuffer(keyPair.publicKey),
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      );
      const jwk = await crypto.subtle.exportKey('jwk', publicKeyBuffer);

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

      const assertionHash = await assertions.hash(assertion, cryptoService);
      const combinedHash = new Uint8Array(aggregateHash.length + 32);
      combinedHash.set(aggregateHash, 0);
      combinedHash.set(new Uint8Array(hex.decodeArrayBuffer(assertionHash)), aggregateHash.length);
      const encodedHash = base64.encodeArrayBuffer(combinedHash);

      const payload: assertions.AssertionPayload = {
        assertionHash,
        assertionSig: encodedHash,
      };

      // Sign with ES256 and embed JWK in header
      const token = await signJwt(cryptoService, payload, keyPair.privateKey, {
        alg: 'ES256',
        jwk,
      });

      assertion.binding.signature = token;

      // Verify should work with embedded JWK - dummy key is ignored when JWK is present
      const dummyKey: assertions.AssertionKey = {
        alg: 'ES256',
        key: keyPair.publicKey, // Not actually used since JWK is in header
      };

      await assertions.verify(assertion, aggregateHash, dummyKey, isLegacyTDF, cryptoService);
    });

    it('should fallback to provided key if no key in header', async () => {
      const symmetricKey = await cryptoService.randomBytes(32);
      const key: assertions.AssertionKey = {
        alg: 'HS256',
        key: symmetricKey,
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

      const assertionHash = await assertions.hash(assertion, cryptoService);
      const combinedHash = new Uint8Array(aggregateHash.length + 32);
      combinedHash.set(aggregateHash, 0);
      combinedHash.set(new Uint8Array(hex.decodeArrayBuffer(assertionHash)), aggregateHash.length);
      const encodedHash = base64.encodeArrayBuffer(combinedHash);

      const payload: assertions.AssertionPayload = {
        assertionHash,
        assertionSig: encodedHash,
      };

      // Sign with HS256 using symmetric key
      const token = await signJwt(cryptoService, payload, symmetricKey, { alg: 'HS256' });

      assertion.binding.signature = token;

      await assertions.verify(assertion, aggregateHash, key, isLegacyTDF, cryptoService);
    });
  });
});

/**
 * Helper to convert PEM to ArrayBuffer for crypto.subtle operations.
 */
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN.*-----/, '')
    .replace(/-----END.*-----/, '')
    .replace(/\s/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
