// tests for assertions.ts

import { expect } from 'chai';

import * as assertions from '../../../tdf3/src/assertions.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import { hex, base64 } from '../../../src/encodings/index.js';
import { signJwt } from '../../../tdf3/src/crypto/jwt.js';
import type { CryptoService } from '../../../tdf3/src/crypto/declarations.js';
import { wrapPrivateKey, wrapPublicKey } from '../../../tdf3/src/crypto/core/keys.js';
import { InvalidFileError } from '../../../src/errors.js';

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
      const assertion: assertions.Assertion & {
        signingKey?: assertions.AssertionKey;
      } = {
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

      const h1 = await assertions.hash(assertion, cryptoService);
      delete assertion.signingKey;
      const h2 = await assertions.hash(assertion, cryptoService);

      expect(h1).to.equal(h2);
    });
  });

  describe('verify', () => {
    const aggregateHash = new Uint8Array([1, 2, 3]);
    const isLegacyTDF = false;

    it('should verify assertion using jwk from header', async () => {
      // Generate ECDSA key pair for ES256 signing (not ECDH)
      const webCryptoKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );
      const keyPair = {
        publicKey: wrapPublicKey(webCryptoKeyPair.publicKey, 'ec:secp256r1'),
        privateKey: wrapPrivateKey(webCryptoKeyPair.privateKey, 'ec:secp256r1'),
      };
      // Get JWK from the public key
      const jwk = await crypto.subtle.exportKey('jwk', webCryptoKeyPair.publicKey);

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

      // An embedded JWK is informational; verification uses the caller's key.
      const trustedKey: assertions.AssertionKey = {
        alg: 'ES256',
        key: keyPair.publicKey,
      };

      await assertions.verify(assertion, aggregateHash, trustedKey, isLegacyTDF, cryptoService);
    });

    it('should not let an embedded jwk override the configured verification key', async () => {
      const generateEcdsa = async () => {
        const raw = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
          'sign',
          'verify',
        ]);
        return {
          raw,
          publicKey: wrapPublicKey(raw.publicKey, 'ec:secp256r1'),
          privateKey: wrapPrivateKey(raw.privateKey, 'ec:secp256r1'),
        };
      };
      const trusted = await generateEcdsa();
      const untrusted = await generateEcdsa();

      const assertion: assertions.Assertion = {
        id: 'test-assertion-untrusted-jwk',
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
      const payload: assertions.AssertionPayload = {
        assertionHash,
        assertionSig: base64.encodeArrayBuffer(combinedHash),
      };

      // Signed by a key the verifier does not trust, which advertises itself in the header.
      assertion.binding.signature = await signJwt(cryptoService, payload, untrusted.privateKey, {
        alg: 'ES256',
        jwk: await crypto.subtle.exportKey('jwk', untrusted.raw.publicKey),
      });

      const trustedKey: assertions.AssertionKey = { alg: 'ES256', key: trusted.publicKey };

      let caught: unknown;
      try {
        await assertions.verify(assertion, aggregateHash, trustedKey, isLegacyTDF, cryptoService);
      } catch (e) {
        caught = e;
      }
      expect(caught).to.be.instanceOf(InvalidFileError);
    });

    it('should fallback to provided key if no key in header', async () => {
      const symmetricKey = await cryptoService.importSymmetricKey(
        await cryptoService.randomBytes(32)
      );
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
