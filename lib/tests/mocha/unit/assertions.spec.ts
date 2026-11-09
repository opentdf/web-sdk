// tests for assertions.ts and assertion-hash.ts

import { expect } from 'chai';
import { base64url } from 'jose';

import * as assertions from '../../../tdf3/src/assertions.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import { hex, base64 } from '../../../src/encodings/index.js';
import { exportPublicKeyJwk } from '../../../tdf3/src/crypto/core/key-format.js';
import { signJwt } from '../../../tdf3/src/crypto/jwt.js';
import type { CryptoService } from '../../../tdf3/src/crypto/declarations.js';
import {
  AssertionVerificationError,
  ConfigurationError,
  IntegrityError,
  type AssertionFailureReason,
} from '../../../src/errors.js';
import { ecdsaKeyPair, rsaKeyPair, type TestKeyPair } from '../helpers/jws-keys.js';

const cryptoService: CryptoService = DefaultCryptoService;
const aggregateHash = new Uint8Array([1, 2, 3, 250, 251, 252]);

type Json = Record<string, unknown>;

function baseAssertion(id = 'a1', extra: Json = {}): Json {
  return {
    id,
    type: 'handling',
    scope: 'tdo',
    appliesToState: 'unencrypted',
    statement: { format: 'json', schema: 'test-schema', value: '{"foo":"bar"}' },
    ...extra,
  };
}

function withoutBinding(a: Json): Json {
  return Object.fromEntries(Object.entries(a).filter(([name]) => name !== 'binding'));
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (e) {
    return e;
  }
  return expect.fail('expected a rejection');
}

async function expectFailure(
  promise: Promise<unknown>,
  reason: AssertionFailureReason,
  assertionId?: string
): Promise<AssertionVerificationError> {
  const e = await rejection(promise);
  expect(e).to.be.instanceOf(AssertionVerificationError);
  const err = e as AssertionVerificationError;
  expect(err.reason, err.message).to.equal(reason);
  expect(err.assertionId).to.equal(assertionId);
  expect(err.message).to.contain(`reason=${reason}`);
  if (assertionId !== undefined) {
    expect(err.message).to.contain(`id: ${assertionId}`);
  }
  return err;
}

const verify = (a: Json, key: assertions.AssertionKey, legacy = false) =>
  assertions.verify(a as assertions.Assertion, aggregateHash, key, legacy, cryptoService);

describe('assertions', () => {
  let signer: TestKeyPair;
  let ecSignerKey: TestKeyPair;
  let secret: Uint8Array;

  before(async () => {
    [signer, ecSignerKey] = await Promise.all([rsaKeyPair(), ecdsaKeyPair('P-256')]);
    secret = await cryptoService.randomBytes(32);
  });

  const rsaKey = (): assertions.AssertionKey => ({ alg: 'RS256', key: signer.pubPem });

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
  });

  describe('hash', () => {
    const classification = {
      appliesToState: 'unencrypted',
      id: 'classification',
      scope: 'payload',
      statement: {
        format: 'json+stanag5636',
        schema: 'urn:nato:stanag:5636:A:1:elements:json',
        value:
          '{"ocl":{"pol":"62c76c68-d73d-4628-8ccc-4c1e18118c22","cls":"SECRET","dcr":"2024-10-21T20:47:36Z"}}',
      },
      type: 'handling',
    };

    it('matches the contract worked examples', async () => {
      expect(await assertions.hash(classification, cryptoService)).to.equal(
        '456d05d6a3f48a14aeee20c8d5f0429d07e5be3f1695fcec2dbc755cd9d64495'
      );
      expect(
        await assertions.hash(
          { ...classification, extensions: { hash: 'deadbeef', note: 'coi' } },
          cryptoService
        )
      ).to.equal('a7347ff1c718c0ee7e88558de64389d5e7194990eb6c78662d0bcd9cfb19c7ba');
      const acp240 = `{"id":"3f1c2d9e-8a4b-4c6d-9e0f-1a2b3c4d5e6f","type":"handling","scope":"payload","appliesToState":"encrypted","statement":{"format":"json-structured","schema":"urn:nato:stanag:5636:A:1:elements:json","value":{"@context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"},"ocl":{"pol":"62c76c68-d73d-4628-8ccc-4c1e18118c22","cls":"CONFIDENTIAL","catl":[{"type":"P","name":"Releasable To","vals":["USA"]}],"dcr":"2026-11-06T12:00:00Z"}}},"binding":{"bdo":"opaque"}}`;
      expect(await assertions.computeAssertionHash(acp240)).to.equal(
        '46853cb52912fd76f3ff90df3936158ee220b8e5973c5d02bb6e50f468596fba'
      );
    });

    it('removes only the top-level binding', async () => {
      const bare = await assertions.hash(classification, cryptoService);
      expect(
        await assertions.hash(
          { ...classification, binding: { method: 'jws', signature: 'x' } },
          cryptoService
        )
      ).to.equal(bare);
      for (const name of ['hash', 'binding', 'sign', 'verify', 'signingKey']) {
        const nested = {
          ...classification,
          statement: { ...classification.statement, [name]: 'x' },
        };
        expect(await assertions.hash(nested, cryptoService), name).to.not.equal(bare);
        expect(
          await assertions.hash({ ...classification, extensions: { [name]: 'x' } }, cryptoService),
          name
        ).to.not.equal(bare);
      }
      for (const name of ['hash', 'signingKey', 'Binding', 'unmodelled']) {
        expect(
          await assertions.hash({ ...classification, [name]: 'x' }, cryptoService),
          name
        ).to.not.equal(bare);
      }
    });

    it('canonicalizes a member named toJSON like any other', async () => {
      const a = await assertions.computeAssertionHash('{"id":"x","toJSON":1,"b":2,"a":3}');
      const b = await assertions.computeAssertionHash('{"a":3,"b":2,"toJSON":1,"id":"x"}');
      expect(a).to.equal(b);
    });

    it('agrees between raw text and the parsed object', async () => {
      const text = JSON.stringify({
        ...classification,
        statement: { ...classification.statement, value: { n: 1.5e3, s: 'é😀' } },
      });
      expect(await assertions.computeAssertionHash(text)).to.equal(
        await assertions.hash(JSON.parse(text) as Json, cryptoService)
      );
    });

    const rejects: Array<[string, string, AssertionFailureReason, string?]> = [
      ['duplicate members', '{"id":"a","type":"x","type":"y"}', 'duplicate-member', 'a'],
      ['escaped duplicate members', '{"id":"a","\\u0069d":"b"}', 'duplicate-member'],
      [
        'duplicate nested members',
        '{"id":"a","statement":{"value":{"k":1,"k":2}}}',
        'duplicate-member',
        'a',
      ],
      ['an ID variant', '{"id":"a","ID":"b"}', 'ambiguous-member', 'a'],
      ['an alias-only id', '{"Id":"a"}', 'ambiguous-member'],
      ['a long-s variant', '{"id":"a","\\u017Fcope":"tdo"}', 'ambiguous-member', 'a'],
      ['a statement variant', '{"id":"a","statement":{"Value":"x"}}', 'ambiguous-member', 'a'],
      ['a binding variant', '{"id":"a","binding":{"Signature":"x"}}', 'ambiguous-member', 'a'],
      ['a lone surrogate', '{"id":"a","statement":{"value":"\\uDEAD"}}', 'invalid-json', 'a'],
      ['a lone surrogate member name', '{"id":"a","\\uD800":1}', 'invalid-json', 'a'],
      ['a noncharacter', '{"id":"a","x":"\\uFDD0"}', 'invalid-json', 'a'],
      ['an out-of-range number', '{"id":"a","x":1e400}', 'invalid-json', 'a'],
      ['invalid JSON', '{"id":"a",}', 'invalid-json'],
      ['a missing id', '{"type":"handling"}', 'invalid-id'],
      ['an empty id', '{"id":""}', 'invalid-id'],
      ['a numeric id', '{"id":7}', 'invalid-id'],
      ['a non-object', '["id"]', 'invalid-json'],
    ];
    for (const [what, text, reason, id] of rejects) {
      it(`computeAssertionHash rejects ${what}`, async () => {
        await expectFailure(assertions.computeAssertionHash(text), reason, id);
      });
    }

    it('reports duplicates before case variants before I-JSON', async () => {
      await expectFailure(
        assertions.computeAssertionHash('{"id":"a","x":1e400,"ID":"b","t":1,"t":2}'),
        'duplicate-member',
        'a'
      );
      await expectFailure(
        assertions.computeAssertionHash('{"id":"a","x":"\\uDEAD","ID":"b"}'),
        'ambiguous-member',
        'a'
      );
    });

    it('does not apply case-variant rules inside statement values', async () => {
      await assertions.computeAssertionHash('{"id":"a","statement":{"value":{"ID":1,"Value":2}}}');
      await assertions.computeAssertionHash('{"id":"a","ext":{"ID":1}}');
      // U+0131 (dotless i) folds to I under Unicode but not under the contract's rule.
      await assertions.computeAssertionHash('{"id":"a","\\u0131d":1}');
    });
  });

  describe('CreateAssertion', () => {
    it('writes and signs the wire object, without configuration', async () => {
      const assertion = await assertions.CreateAssertion(
        aggregateHash,
        {
          id: 'with-extras',
          type: 'handling',
          scope: 'payload',
          appliesToState: 'encrypted',
          statement: {
            format: 'json',
            schema: 'test-schema',
            value: '{"foo":"bar"}',
            hash: 'deadbeef',
          } as assertions.Statement,
          signingKey: { alg: 'RS256', key: signer.sdk.privateKey },
        },
        cryptoService
      );
      expect(assertion).to.not.have.property('signingKey');
      expect(Object.keys(assertion)).to.deep.equal([
        'id',
        'type',
        'scope',
        'appliesToState',
        'statement',
        'binding',
      ]);
      expect(assertion.statement).to.have.property('hash', 'deadbeef');

      // Round trip through JSON, as the manifest does.
      const read = JSON.parse(JSON.stringify(assertion)) as Json;
      const [, payload] = assertion.binding.signature.split('.');
      const claims = JSON.parse(new TextDecoder().decode(base64url.decode(payload))) as Json;
      const unbound = withoutBinding(read);
      expect(claims.assertionHash).to.equal(
        await assertions.computeAssertionHash(JSON.stringify(unbound))
      );
      await verify(read, rsaKey());

      // statement.hash is authenticated now.
      (read.statement as Json).hash = 'cafef00d';
      expect(await rejection(verify(read, rsaKey()))).to.be.instanceOf(IntegrityError);
    });

    it('omits an unset appliesToState', async () => {
      const assertion = await assertions.CreateAssertion(
        aggregateHash,
        {
          id: 'no-state',
          type: 'other',
          scope: 'tdo',
          statement: { format: 'string', schema: 's', value: 'v' },
          signingKey: { alg: 'HS256', key: secret },
        } as unknown as assertions.AssertionConfig,
        cryptoService
      );
      expect(assertion).to.not.have.property('appliesToState');
      await verify(assertion, { alg: 'HS256', key: secret });
    });

    it('refuses content that readers would reject', async () => {
      for (const statement of [
        { format: 'string', schema: 's', value: '\ud800' },
        { format: 'string', schema: 's', value: 'v', Value: 'w' },
      ]) {
        const e = await rejection(
          assertions.CreateAssertion(
            aggregateHash,
            {
              id: 'bad',
              type: 'other',
              scope: 'tdo',
              appliesToState: 'encrypted',
              statement,
              signingKey: { alg: 'HS256', key: secret },
            },
            cryptoService
          )
        );
        expect(e).to.be.instanceOf(ConfigurationError);
        expect(e).to.not.be.instanceOf(IntegrityError);
        expect((e as Error).message).to.not.match(/integrity|tamper/i);
      }
      for (const id of ['', 7]) {
        const e = await rejection(
          assertions.CreateAssertion(
            aggregateHash,
            {
              ...(baseAssertion() as unknown as assertions.AssertionConfig),
              id: id as string,
              signingKey: { alg: 'HS256', key: secret },
            },
            cryptoService
          )
        );
        expect(e).to.be.instanceOf(ConfigurationError);
        expect(e).to.not.be.instanceOf(IntegrityError);
      }
    });

    it('persists ES256 bindings as raw IEEE P1363, the only encoding on the wire', async () => {
      // binding.signature is the one signature this SDK writes to durable
      // storage — it lands in the manifest and is read back by other SDKs. RFC
      // 7518 §3.4 requires raw R || S (64 bytes for P-256); ASN.1 DER is 69-72
      // bytes and is rejected on length by conformant verifiers. Pin the width
      // so no encoding change can slip into the file format unnoticed.
      const assertion = await assertions.CreateAssertion(
        aggregateHash,
        {
          id: 'raw-p1363-binding',
          type: 'handling',
          scope: 'tdo',
          appliesToState: 'unencrypted',
          statement: { format: 'json', schema: 'test-schema', value: '{"foo":"bar"}' },
          signingKey: { alg: 'ES256', key: ecSignerKey.sdk.privateKey },
        },
        cryptoService
      );

      const [, , signatureB64url] = assertion.binding.signature.split('.');
      expect(base64url.decode(signatureB64url).length).to.equal(64);

      await verify(assertion, { alg: 'ES256', key: ecSignerKey.sdk.publicKey });
    });

    it('writes legacy 4.2.2 bindings that verify under the legacy encoding', async () => {
      const aggregate = '0123abcd';
      const assertion = await assertions.CreateAssertion(
        aggregate,
        {
          ...(baseAssertion('legacy') as unknown as assertions.AssertionConfig),
          signingKey: { alg: 'HS256', key: secret },
        },
        cryptoService,
        '4.2.2'
      );
      await assertions.verify(
        assertion,
        new TextEncoder().encode(aggregate),
        { alg: 'HS256', key: secret },
        true,
        cryptoService
      );
      expect(
        await rejection(
          assertions.verify(
            assertion,
            new TextEncoder().encode(aggregate),
            { alg: 'HS256', key: secret },
            false,
            cryptoService
          )
        )
      ).to.be.instanceOf(IntegrityError);
    });
  });

  describe('verify', () => {
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
