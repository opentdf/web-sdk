// tests for assertions.ts

import { expect } from 'chai';
import { base64url } from 'jose';

import * as assertions from '../../../tdf3/src/assertions.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import { hex, base64 } from '../../../src/encodings/index.js';
import { exportPublicKeyJwk } from '../../../tdf3/src/crypto/core/key-format.js';
import { signJwt } from '../../../tdf3/src/crypto/jwt.js';
import type { CryptoService } from '../../../tdf3/src/crypto/declarations.js';
import { ecdsaKeyPair } from '../helpers/jws-keys.js';
import { IntegrityError } from '../../../src/errors.js';

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

      // Verify should work with embedded JWK - dummy key is ignored when JWK is present
      const dummyKey: assertions.AssertionKey = {
        alg: 'ES256',
        key: keyPair.publicKey, // Not actually used since JWK is in header
      };

      await assertions.verify(assertion, aggregateHash, dummyKey, isLegacyTDF, cryptoService);
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

    describe('assertion signature encoding', () => {
      // assertionSig is base64 over the aggregate hash followed by the
      // assertion hash, which writers have spelled two ways: as raw bytes
      // (4.3.0 and later) or as its hex string (earlier). Which one a file
      // used is not taken from the spec version, so verify accepts either,
      // whatever `isLegacyTDF` says.
      const raw = (h: string) => new Uint8Array(hex.decodeArrayBuffer(h));
      const asHex = (h: string) => new TextEncoder().encode(h);

      async function hs256Setup(spelling: (assertionHash: string) => Uint8Array) {
        const symmetricKey = await cryptoService.importSymmetricKey(
          await cryptoService.randomBytes(32)
        );
        const key: assertions.AssertionKey = { alg: 'HS256', key: symmetricKey };
        const assertion: assertions.Assertion = {
          id: 'test-assertion-encoding',
          type: 'handling',
          scope: 'tdo',
          appliesToState: 'unencrypted',
          statement: { format: 'json', schema: 'test-schema', value: '{"foo":"bar"}' },
          binding: { method: 'jws', signature: '' },
        };
        const assertionHash = await assertions.hash(assertion, cryptoService);
        const spelled = spelling(assertionHash);
        const combined = new Uint8Array(aggregateHash.length + spelled.length);
        combined.set(aggregateHash, 0);
        combined.set(spelled, aggregateHash.length);
        const payload: assertions.AssertionPayload = {
          assertionHash,
          assertionSig: base64.encodeArrayBuffer(combined),
        };
        assertion.binding.signature = await signJwt(cryptoService, payload, symmetricKey, {
          alg: 'HS256',
        });
        return { assertion, key };
      }

      for (const legacy of [false, true]) {
        it(`accepts a raw assertion hash with isLegacyTDF=${legacy}`, async () => {
          const { assertion, key } = await hs256Setup(raw);
          await assertions.verify(assertion, aggregateHash, key, legacy, cryptoService);
        });

        it(`accepts a hex assertion hash with isLegacyTDF=${legacy}`, async () => {
          const { assertion, key } = await hs256Setup(asHex);
          await assertions.verify(assertion, aggregateHash, key, legacy, cryptoService);
        });

        for (const [label, spelling] of [
          ['raw', raw],
          ['hex', asHex],
        ] as const) {
          it(`rejects a ${label} signature over another aggregate with isLegacyTDF=${legacy}`, async () => {
            const { assertion, key } = await hs256Setup(spelling);
            let caught: unknown;
            try {
              await assertions.verify(
                assertion,
                new Uint8Array([9, 9, 9]),
                key,
                legacy,
                cryptoService
              );
            } catch (e) {
              caught = e;
            }
            expect(caught).to.be.instanceOf(IntegrityError);
            expect((caught as Error).message).to.match(/assertion signature/);
          });
        }
      }
    });
  });
});
