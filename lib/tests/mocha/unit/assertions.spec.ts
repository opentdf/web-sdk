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

  describe('resolveVerificationKey', () => {
    const aggregateHash = new Uint8Array([1, 2, 3]);
    const defaultKey: assertions.AssertionKey = { alg: 'HS256', key: new Uint8Array(32) };

    // An assertion bound to aggregateHash and signed with `signingKey` under `header`.
    const boundAssertion = async (
      signingKey: Parameters<typeof signJwt>[2],
      header: Parameters<typeof signJwt>[3]
    ) => {
      const assertion: assertions.Assertion = {
        id: 'embedded',
        type: 'handling',
        scope: 'tdo',
        appliesToState: 'unencrypted',
        statement: { format: 'json', schema: 'test-schema', value: '{}' },
        binding: { method: 'jws', signature: '' },
      };
      const assertionHash = await assertions.hash(assertion, cryptoService);
      const combinedHash = new Uint8Array(aggregateHash.length + 32);
      combinedHash.set(aggregateHash, 0);
      combinedHash.set(new Uint8Array(hex.decodeArrayBuffer(assertionHash)), aggregateHash.length);
      const payload: assertions.AssertionPayload = {
        assertionHash,
        assertionSig: base64.encodeArrayBuffer(combinedHash),
      };
      assertion.binding.signature = await signJwt(cryptoService, payload, signingKey, header);
      return assertion;
    };

    const ecdsaWithJwk = async () => {
      const raw = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign',
        'verify',
      ]);
      return {
        privateKey: wrapPrivateKey(raw.privateKey, 'ec:secp256r1'),
        publicKey: wrapPublicKey(raw.publicKey, 'ec:secp256r1'),
        jwk: await crypto.subtle.exportKey('jwk', raw.publicKey),
      };
    };

    it('verifies with an embedded jwk and reports it as embedded', async () => {
      const signer = await ecdsaWithJwk();
      const assertion = await boundAssertion(signer.privateKey, { alg: 'ES256', jwk: signer.jwk });

      const { key, keySource, header } = await assertions.resolveVerificationKey(
        assertion,
        { Keys: {} },
        defaultKey,
        cryptoService
      );
      expect(keySource).to.equal('embedded');
      expect(header.jwk).to.deep.equal(signer.jwk);
      await assertions.verify(assertion, aggregateHash, key, false, cryptoService);
    });

    it('prefers a configured key over an embedded one', async () => {
      const signer = await ecdsaWithJwk();
      const assertion = await boundAssertion(signer.privateKey, { alg: 'ES256', jwk: signer.jwk });
      const configured: assertions.AssertionKey = { alg: 'ES256', key: signer.publicKey };

      const { key, keySource } = await assertions.resolveVerificationKey(
        assertion,
        { Keys: { embedded: configured } },
        defaultKey,
        cryptoService
      );
      expect(keySource).to.equal('configured');
      expect(key).to.equal(configured);
    });

    it('uses the default key when the header embeds no key', async () => {
      const hmacKey = await cryptoService.importSymmetricKey(new Uint8Array(32));
      const assertion = await boundAssertion(hmacKey, { alg: 'HS256' });

      const { key, keySource } = await assertions.resolveVerificationKey(
        assertion,
        undefined,
        defaultKey,
        cryptoService
      );
      expect(keySource).to.equal('default');
      expect(key).to.equal(defaultKey);
    });

    it('ignores an embedded key under a symmetric alg', async () => {
      const signer = await ecdsaWithJwk();
      const hmacKey = await cryptoService.importSymmetricKey(new Uint8Array(32));
      const assertion = await boundAssertion(hmacKey, { alg: 'HS256', jwk: signer.jwk });

      const { keySource } = await assertions.resolveVerificationKey(
        assertion,
        { Keys: {} },
        defaultKey,
        cryptoService
      );
      expect(keySource).to.equal('default');
    });

    it('rejects a malformed binding with InvalidFileError', async () => {
      const assertion = await boundAssertion(
        await cryptoService.importSymmetricKey(new Uint8Array(32)),
        { alg: 'HS256' }
      );
      assertion.binding.signature = 'not-a-jws';
      let caught: unknown;
      try {
        await assertions.resolveVerificationKey(assertion, undefined, defaultKey, cryptoService);
      } catch (e) {
        caught = e;
      }
      expect(caught).to.be.instanceOf(InvalidFileError);
    });
  });
});
