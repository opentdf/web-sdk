// tests for assertions.ts

import { expect } from 'chai';
import { base64url } from 'jose';

import * as assertions from '../../../tdf3/src/assertions.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import { hex, base64 } from '../../../src/encodings/index.js';
import { exportPublicKeyJwk } from '../../../tdf3/src/crypto/core/key-format.js';
import { signJwt } from '../../../tdf3/src/crypto/jwt.js';
import type { CryptoService, PrivateKey } from '../../../tdf3/src/crypto/declarations.js';
import { InvalidFileError } from '../../../src/errors.js';
import { ecdsaKeyPair, rsaKeyPair } from '../helpers/jws-keys.js';
import { selfSignedCertificate } from '../helpers/x509.js';

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

    it('accepts an embedded jwk that names the configured key', async () => {
      // ES256 signing key pair (ECDSA, not ECDH)
      const { sdk: keyPair } = await ecdsaKeyPair('P-256');
      // Get JWK from the public key
      const jwk = await exportPublicKeyJwk(keyPair.publicKey);

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

      // The configured key verifies; the embedded jwk happens to name the same key.
      const configuredKey: assertions.AssertionKey = {
        alg: 'ES256',
        key: keyPair.publicKey,
      };

      await assertions.verify(assertion, aggregateHash, configuredKey, isLegacyTDF, cryptoService);
    });

    it('persists ES256 bindings as raw IEEE P1363, the only encoding on the wire', async () => {
      // binding.signature is the one signature this SDK writes to durable
      // storage — it lands in the manifest and is read back by other SDKs. RFC
      // 7518 §3.4 requires raw R || S (64 bytes for P-256); ASN.1 DER is 69-72
      // bytes and is rejected on length by conformant verifiers. Pin the width
      // so no encoding change can slip into the file format unnoticed.
      const { sdk: keyPair } = await ecdsaKeyPair('P-256');
      const signingKey: assertions.AssertionKey = {
        alg: 'ES256',
        key: keyPair.privateKey,
      };

      const assertion = await assertions.CreateAssertion(
        aggregateHash,
        {
          id: 'raw-p1363-binding',
          type: 'handling',
          scope: 'tdo',
          appliesToState: 'unencrypted',
          statement: {
            format: 'json',
            schema: 'test-schema',
            value: '{"foo":"bar"}',
          },
          signingKey,
        },
        cryptoService
      );

      const [, , signatureB64url] = assertion.binding.signature.split('.');
      expect(base64url.decode(signatureB64url).length).to.equal(64);

      await assertions.verify(
        assertion,
        aggregateHash,
        {
          alg: 'ES256',
          key: keyPair.publicKey,
        },
        isLegacyTDF,
        cryptoService
      );
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

    describe('keys embedded in the binding header', () => {
      /** An assertion whose binding is signed with `signingKey` under `header`. */
      async function signedAssertion(
        signingKey: PrivateKey,
        header: { alg: assertions.AssertionKeyAlg } & Record<string, unknown>
      ): Promise<assertions.Assertion> {
        const assertion: assertions.Assertion = {
          id: 'embedded-key-assertion',
          type: 'handling',
          scope: 'tdo',
          appliesToState: 'unencrypted',
          statement: { format: 'json', schema: 'test-schema', value: '{"foo":"bar"}' },
          binding: { method: 'jws', signature: '' },
        };
        const assertionHash = await assertions.hash(assertion, cryptoService);
        const combinedHash = new Uint8Array(aggregateHash.length + 32);
        combinedHash.set(aggregateHash, 0);
        combinedHash.set(
          new Uint8Array(hex.decodeArrayBuffer(assertionHash)),
          aggregateHash.length
        );
        const payload: assertions.AssertionPayload = {
          assertionHash,
          assertionSig: base64.encodeArrayBuffer(combinedHash),
        };
        assertion.binding.signature = await signJwt(cryptoService, payload, signingKey, header);
        return assertion;
      }

      async function expectRejected(
        assertion: assertions.Assertion,
        key: assertions.AssertionKey
      ): Promise<void> {
        let error: unknown;
        try {
          await assertions.verify(assertion, aggregateHash, key, isLegacyTDF, cryptoService);
        } catch (e) {
          error = e;
        }
        expect(error).to.be.instanceOf(InvalidFileError);
      }

      it('does not verify with a jwk for another key', async () => {
        const { sdk: configured, pubPem } = await rsaKeyPair();
        const { sdk: other } = await rsaKeyPair();
        const { kty, n, e } = await exportPublicKeyJwk(other.publicKey);
        const assertion = await signedAssertion(other.privateKey, {
          alg: 'RS256',
          jwk: { kty, n, e },
        });

        await expectRejected(assertion, { alg: 'RS256', key: configured.publicKey });
        await expectRejected(assertion, { alg: 'RS256', key: pubPem });

        const { sdk: configuredEc } = await ecdsaKeyPair('P-256');
        const { sdk: otherEc } = await ecdsaKeyPair('P-256');
        const jwk = await exportPublicKeyJwk(otherEc.publicKey);
        const ecAssertion = await signedAssertion(otherEc.privateKey, { alg: 'ES256', jwk });

        await expectRejected(ecAssertion, { alg: 'ES256', key: configuredEc.publicKey });
      });

      it('does not verify with an x5c certificate for another key', async () => {
        const { sdk: configured } = await rsaKeyPair();
        const { sdk: other } = await rsaKeyPair();
        const certificate = await selfSignedCertificate(cryptoService, other, 'RS256');
        const assertion = await signedAssertion(other.privateKey, {
          alg: 'RS256',
          x5c: [certificate],
        });

        await expectRejected(assertion, { alg: 'RS256', key: configured.publicKey });
      });

      it('does not verify an RS256 binding with an embedded jwk under the payload key', async () => {
        const { sdk: other } = await rsaKeyPair();
        const jwk = await exportPublicKeyJwk(other.publicKey);
        const assertion = await signedAssertion(other.privateKey, { alg: 'RS256', jwk });
        const payloadKey = await cryptoService.importSymmetricKey(
          await cryptoService.randomBytes(32)
        );

        await expectRejected(assertion, { alg: 'HS256', key: payloadKey });
      });

      it("requires the header alg to be the configured key's alg", async () => {
        const { sdk: rsa } = await rsaKeyPair();
        const { sdk: ec } = await ecdsaKeyPair('P-256');
        const jwk = await exportPublicKeyJwk(ec.publicKey);
        const assertion = await signedAssertion(ec.privateKey, { alg: 'ES256', jwk });

        await expectRejected(assertion, { alg: 'RS256', key: rsa.publicKey });
      });

      it('still verifies with the configured key when an x5c names it', async () => {
        const { sdk: configured } = await rsaKeyPair();
        const certificate = await selfSignedCertificate(cryptoService, configured, 'RS256');
        const assertion = await signedAssertion(configured.privateKey, {
          alg: 'RS256',
          x5c: [certificate],
        });

        await assertions.verify(
          assertion,
          aggregateHash,
          { alg: 'RS256', key: configured.publicKey },
          isLegacyTDF,
          cryptoService
        );
      });
    });
  });
});
