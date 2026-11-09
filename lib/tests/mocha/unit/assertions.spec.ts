// tests for assertions.ts, assertion-hash.ts, and assertion-verifier.ts

import { expect } from 'chai';
import { base64url, importX509 } from 'jose';

import * as assertions from '../../../tdf3/src/assertions.js';
import {
  selectVerificationKey,
  verifyManifestAssertion,
} from '../../../tdf3/src/assertion-verifier.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import { hex, base64 } from '../../../src/encodings/index.js';
import { exportPublicKeyJwk } from '../../../tdf3/src/crypto/core/key-format.js';
import { wrapPublicKey } from '../../../tdf3/src/crypto/core/keys.js';
import {
  decodeBase64Padded,
  jwkIdentity,
  MalformedKeyError,
} from '../../../tdf3/src/key-identity.js';
import { base64urlEncode } from '../../../tdf3/src/crypto/jwt.js';
import type {
  CryptoService,
  KeyPair,
  SymmetricKey,
} from '../../../tdf3/src/crypto/declarations.js';
import {
  AssertionVerificationError,
  ConfigurationError,
  IntegrityError,
  InvalidFileError,
  type AssertionFailureReason,
} from '../../../src/errors.js';
import { ecdsaKeyPair, rsaKeyPair, type TestKeyPair } from '../helpers/jws-keys.js';
import { kasECCert, kasECPrivateKey } from '../../mocks/pems.js';
import {
  certificateFrom,
  commonName,
  integer,
  oid,
  selfSignedCertificate,
  sequence,
  set,
  spkiOf,
  tlv,
  utcTime,
} from '../helpers/x509.js';

const cryptoService: CryptoService = DefaultCryptoService;
const aggregateHash = new Uint8Array([1, 2, 3, 250, 251, 252]);

type Json = Record<string, unknown>;
type Signer = (input: Uint8Array) => Promise<Uint8Array>;

const rsaSigner =
  (kp: KeyPair): Signer =>
  (input) =>
    cryptoService.sign(input, kp.privateKey, 'RS256');
const ecSigner =
  (kp: KeyPair): Signer =>
  (input) =>
    cryptoService.sign(input, kp.privateKey, 'ES256');
const hmacSigner =
  (secret: SymmetricKey): Signer =>
  (input) =>
    cryptoService.hmac(input, secret);

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

async function claimsFor(a: Json, legacy = false, aggregate = aggregateHash) {
  const assertionHash = await assertions.hash(a, cryptoService);
  const hashBytes = legacy
    ? new TextEncoder().encode(assertionHash)
    : new Uint8Array(hex.decodeArrayBuffer(assertionHash));
  const combined = new Uint8Array(aggregate.length + hashBytes.length);
  combined.set(aggregate, 0);
  combined.set(hashBytes, aggregate.length);
  return { assertionHash, assertionSig: base64.encodeArrayBuffer(combined) };
}

/** The same base64url text with non-zero bits after its last whole octet. */
function withTrailingBits(text: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const padded = text.length % 4 ? text : `${text}AA`;
  return padded.slice(0, -1) + alphabet[alphabet.indexOf(padded[padded.length - 1]) | 1];
}

function withoutBinding(a: Json): Json {
  return Object.fromEntries(Object.entries(a).filter(([name]) => name !== 'binding'));
}

async function compactJws(header: Json, payload: Json, signer: Signer): Promise<string> {
  const input = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(
    JSON.stringify(payload)
  )}`;
  const signature = await signer(new TextEncoder().encode(input));
  return `${input}.${base64urlEncode(signature)}`;
}

/** Sign `a` (minus any binding) and attach the binding, as a writer would. */
async function signed(
  a: Json,
  signer: Signer,
  header: Json,
  { legacy = false, claims }: { legacy?: boolean; claims?: Json } = {}
): Promise<Json> {
  const unbound = withoutBinding(a);
  const payload = claims ?? (await claimsFor(unbound, legacy));
  return {
    ...unbound,
    binding: { method: 'jws', signature: await compactJws(header, payload, signer) },
  };
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
  let other: TestKeyPair;
  let ecSignerKey: TestKeyPair;
  let otherEc: TestKeyPair;
  let secret: Uint8Array;
  let payloadKey: SymmetricKey;

  before(async () => {
    [signer, other, ecSignerKey, otherEc] = await Promise.all([
      rsaKeyPair(),
      rsaKeyPair(),
      ecdsaKeyPair('P-256'),
      ecdsaKeyPair('P-256'),
    ]);
    secret = await cryptoService.randomBytes(32);
    payloadKey = await cryptoService.importSymmetricKey(await cryptoService.randomBytes(32));
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
      await expectFailure(verify(read, rsaKey()), 'binding-mismatch', 'with-extras');
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
      await expectFailure(
        assertions.verify(
          assertion,
          new TextEncoder().encode(aggregate),
          { alg: 'HS256', key: secret },
          false,
          cryptoService
        ),
        'binding-mismatch',
        'legacy'
      );
    });
  });

  describe('verify', () => {
    describe('positive controls', () => {
      it('accepts HS256 with the configured secret', async () => {
        const a = await signed(
          baseAssertion(),
          hmacSigner(await cryptoService.importSymmetricKey(secret)),
          { alg: 'HS256' }
        );
        await verify(a, { alg: 'HS256', key: secret });
      });

      it('accepts RS256 with a PEM or opaque public key', async () => {
        const a = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        await verify(a, rsaKey());
        await verify(a, { alg: 'RS256', key: signer.sdk.publicKey });
      });

      it('accepts ES256 with the configured key', async () => {
        const a = await signed(baseAssertion(), ecSigner(ecSignerKey.sdk), { alg: 'ES256' });
        await verify(a, { alg: 'ES256', key: ecSignerKey.pubPem });
      });

      it('accepts an embedded jwk that names the configured key', async () => {
        const jwk = await exportPublicKeyJwk(signer.sdk.publicKey);
        const a = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256', jwk });
        await verify(a, rsaKey());
        const ecJwk = await exportPublicKeyJwk(ecSignerKey.sdk.publicKey);
        const b = await signed(baseAssertion(), ecSigner(ecSignerKey.sdk), {
          alg: 'ES256',
          jwk: ecJwk,
        });
        await verify(b, { alg: 'ES256', key: ecSignerKey.sdk.publicKey });
      });

      it('accepts a self-signed x5c whose leaf is the configured key', async () => {
        const cert = await selfSignedCertificate(cryptoService, signer.sdk, 'RS256');
        // The helper must make certificates that an independent parser accepts.
        await importX509(
          `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`,
          'RS256'
        );
        const a = await signed(baseAssertion(), rsaSigner(signer.sdk), {
          alg: 'RS256',
          x5c: [cert],
        });
        await verify(a, rsaKey());

        const ecCert = await selfSignedCertificate(cryptoService, ecSignerKey.sdk, 'ES256');
        const jwk = await exportPublicKeyJwk(ecSignerKey.sdk.publicKey);
        const b = await signed(baseAssertion(), ecSigner(ecSignerKey.sdk), {
          alg: 'ES256',
          jwk,
          x5c: [ecCert, 'AAAA'],
        });
        await verify(b, { alg: 'ES256', key: ecSignerKey.pubPem });
      });

      it('ignores kid', async () => {
        const a = await signed(baseAssertion(), rsaSigner(signer.sdk), {
          alg: 'RS256',
          kid: 'other',
        });
        await verify(a, rsaKey());
      });
    });

    describe('embedded keys never replace the selected key', () => {
      it('rejects a jwk for another RSA key', async () => {
        const jwk = await exportPublicKeyJwk(other.sdk.publicKey);
        const resigned = await signed(baseAssertion(), rsaSigner(other.sdk), {
          alg: 'RS256',
          jwk,
        });
        await expectFailure(verify(resigned, rsaKey()), 'signer-not-permitted', 'a1');
      });

      it('rejects a jwk for another ES256 key', async () => {
        const jwk = await exportPublicKeyJwk(otherEc.sdk.publicKey);
        const resigned = await signed(baseAssertion(), ecSigner(otherEc.sdk), {
          alg: 'ES256',
          jwk,
        });
        await expectFailure(
          verify(resigned, { alg: 'ES256', key: ecSignerKey.pubPem }),
          'signer-not-permitted',
          'a1'
        );
      });

      it('rejects a self-signed x5c for another key', async () => {
        const cert = await selfSignedCertificate(cryptoService, other.sdk, 'RS256');
        const resigned = await signed(baseAssertion(), rsaSigner(other.sdk), {
          alg: 'RS256',
          x5c: [cert],
        });
        await expectFailure(verify(resigned, rsaKey()), 'signer-not-permitted', 'a1');
      });

      it('rejects a matching jwk on a signature by another key', async () => {
        const jwk = await exportPublicKeyJwk(signer.sdk.publicKey);
        const resigned = await signed(baseAssertion(), rsaSigner(other.sdk), {
          alg: 'RS256',
          jwk,
        });
        await expectFailure(verify(resigned, rsaKey()), 'signature-invalid', 'a1');
      });

      it('rejects any embedded key in HMAC mode', async () => {
        const hmacKey = await cryptoService.importSymmetricKey(secret);
        const jwk = await exportPublicKeyJwk(other.sdk.publicKey);
        const cert = await selfSignedCertificate(cryptoService, other.sdk, 'RS256');
        for (const extra of [{ jwk }, { x5c: [cert] }, { jwk: { kty: 'oct', k: 'AAAA' } }]) {
          const a = await signed(baseAssertion(), hmacSigner(hmacKey), { alg: 'HS256', ...extra });
          await expectFailure(
            verify(a, { alg: 'HS256', key: secret }),
            'invalid-embedded-key',
            'a1'
          );
          await expectFailure(
            verify(a, { alg: 'HS256', key: hmacKey }),
            'invalid-embedded-key',
            'a1'
          );
        }
      });

      it('rejects symmetric, private, malformed, and contradictory embedded keys', async () => {
        const jwk = (await exportPublicKeyJwk(signer.sdk.publicKey)) as Json;
        const otherJwk = await exportPublicKeyJwk(other.sdk.publicKey);
        const cert = await selfSignedCertificate(cryptoService, signer.sdk, 'RS256');
        const cases: Json[] = [
          { jwk: { kty: 'oct', k: 'c2VjcmV0' } },
          { jwk: { ...jwk, d: 'AQAB' } },
          { jwk: { ...jwk, oth: [] } },
          { jwk: { ...jwk, qi: 'AQAB' } },
          { jwk: 'not an object' },
          { jwk: null },
          { jwk: { n: jwk.n, e: jwk.e } },
          { jwk: { ...jwk, n: 'not base64url!' } },
          { jwk: { ...jwk, e: '' } },
          { jwk: { ...jwk, n: 7 } },
          { jwk: { kty: 'XYZ' } },
          { jwk: { kty: 'EC', crv: 'P-256', x: 'AAAA' } },
          { jwk: { kty: 'EC', crv: 7, x: 'AAAA', y: 'AAAA' } },
          { jwk: { kty: 'OKP', crv: 'Ed25519', x: 'A' } },
          { jwk: { ...jwk, e: 'AQAC' }, note: 'control' },
          { jwk: { ...jwk, e: 'AQB' } },
          { jwk: { ...jwk, e: 'AQAB=' } },
          { x5c: cert },
          { x5c: [] },
          { x5c: ['not base64!'] },
          { x5c: [cert, 7] },
          { x5c: [cert, 'not base64!'] },
          { x5c: [cert, 'AAA'] },
          { x5c: ['AAAA'] },
          { x5c: [base64.encodeArrayBuffer(new TextEncoder().encode('garbage'))] },
          { jwk: otherJwk, x5c: [cert] },
        ];
        for (const { note, ...extra } of cases) {
          const a = await signed(baseAssertion(), rsaSigner(signer.sdk), {
            alg: 'RS256',
            ...extra,
          });
          // A well-formed exponent of another key is not malformed, just different.
          await expectFailure(
            verify(a, rsaKey()),
            note === 'control' ? 'signer-not-permitted' : 'invalid-embedded-key',
            'a1'
          );
        }
      });

      it('requires curve coordinates of exactly the curve length', async () => {
        const jwk = (await exportPublicKeyJwk(ecSignerKey.sdk.publicKey)) as Json;
        const x = base64url.decode(jwk.x as string);
        const cases: Json[] = [
          { ...jwk, x: base64urlEncode(x.subarray(1)) },
          { ...jwk, x: base64urlEncode(new Uint8Array([0, ...x])) },
          { ...jwk, crv: 'P-384' },
          { ...jwk, crv: 'secp256k1' },
        ];
        for (const bad of cases) {
          const a = await signed(baseAssertion(), ecSigner(ecSignerKey.sdk), {
            alg: 'ES256',
            jwk: bad,
          });
          await expectFailure(
            verify(a, { alg: 'ES256', key: ecSignerKey.pubPem }),
            'invalid-embedded-key',
            'a1'
          );
        }
      });

      it('rejects embedded keys of a type that cannot be the selected key', async () => {
        const ecJwk = (await exportPublicKeyJwk(ecSignerKey.sdk.publicKey)) as Json;
        const okp = { kty: 'OKP', crv: 'Ed25519', x: base64urlEncode(new Uint8Array(32)) };
        for (const jwk of [okp, ecJwk]) {
          const a = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256', jwk });
          await expectFailure(verify(a, rsaKey()), 'signer-not-permitted', 'a1');
        }
        const rsaJwk = await exportPublicKeyJwk(signer.sdk.publicKey);
        const b = await signed(baseAssertion(), ecSigner(ecSignerKey.sdk), {
          alg: 'ES256',
          jwk: rsaJwk,
        });
        await expectFailure(
          verify(b, { alg: 'ES256', key: ecSignerKey.pubPem }),
          'signer-not-permitted',
          'a1'
        );
        const ecCert = await selfSignedCertificate(cryptoService, ecSignerKey.sdk, 'ES256');
        const c = await signed(baseAssertion(), rsaSigner(signer.sdk), {
          alg: 'RS256',
          x5c: [ecCert],
        });
        await expectFailure(verify(c, rsaKey()), 'signer-not-permitted', 'a1');
      });

      it('requires RSA jwk integers in their minimal form', async () => {
        const jwk = (await exportPublicKeyJwk(signer.sdk.publicKey)) as Json;
        const padded = (v: unknown) =>
          base64urlEncode(new Uint8Array([0, ...base64url.decode(v as string)]));
        for (const bad of [
          { kty: 'RSA', n: padded(jwk.n), e: jwk.e },
          { kty: 'RSA', n: jwk.n, e: padded(jwk.e) },
        ]) {
          const a = await signed(baseAssertion(), rsaSigner(signer.sdk), {
            alg: 'RS256',
            jwk: bad,
          });
          await expectFailure(verify(a, rsaKey()), 'invalid-embedded-key', 'a1');
        }
        const minimal = await signed(baseAssertion(), rsaSigner(signer.sdk), {
          alg: 'RS256',
          jwk: { kty: 'RSA', n: jwk.n, e: jwk.e, kid: 'ignored', use: 'sig' },
        });
        await verify(minimal, rsaKey());
      });

      it('rejects jwk and x5c that agree with each other but not with the selected key', async () => {
        const jwk = await exportPublicKeyJwk(other.sdk.publicKey);
        const cert = await selfSignedCertificate(cryptoService, other.sdk, 'RS256');
        const resigned = await signed(baseAssertion(), rsaSigner(other.sdk), {
          alg: 'RS256',
          jwk,
          x5c: [cert],
        });
        await expectFailure(verify(resigned, rsaKey()), 'signer-not-permitted', 'a1');
      });
    });

    describe('x5c certificates', () => {
      const withLeaf = (leaf: string) =>
        signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256', x5c: [leaf] });

      it('accepts a well-formed certificate built from parts, and a real one', async () => {
        await verify(await withLeaf(certificateFrom({ spki: await spkiOf(signer.sdk) })), rsaKey());

        // An OpenSSL-made certificate with extensions, past its validity period:
        // Phase 0 parses certificates but makes no claim about them.
        const der = kasECCert.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, '');
        const signingKey = await cryptoService.importPrivateKey!(kasECPrivateKey, {
          usage: 'sign',
        });
        const a = await signed(
          baseAssertion(),
          (input) => cryptoService.sign(input, signingKey, 'ES256'),
          { alg: 'ES256', x5c: [der] }
        );
        await verify(a, { alg: 'ES256', key: kasECCert });
        await expectFailure(
          verify(a, { alg: 'ES256', key: ecSignerKey.pubPem }),
          'signer-not-permitted',
          'a1'
        );
      });

      it('rejects certificates that a strict X.509 parser would', async () => {
        const spki = await spkiOf(signer.sdk);
        const empty = sequence();
        const now = new Date();
        const shapes: Array<[string, string]> = [
          [
            'only a TLV skeleton',
            base64.encodeArrayBuffer(
              sequence(
                sequence(integer(Uint8Array.of(1)), empty, empty, empty, empty, spki),
                empty,
                tlv(0x03, Uint8Array.of(0))
              )
            ),
          ],
          [
            'an unknown version',
            certificateFrom({ spki, version: tlv(0xa0, integer(Uint8Array.of(3))) }),
          ],
          [
            'a non-minimal serial',
            certificateFrom({ spki, serial: tlv(0x02, Uint8Array.of(0, 1)) }),
          ],
          [
            'an empty algorithm OID',
            certificateFrom({ spki, signature: sequence(tlv(0x06, new Uint8Array())) }),
          ],
          [
            'a non-minimal algorithm OID',
            certificateFrom({
              spki,
              signature: sequence(tlv(0x06, Uint8Array.of(0x2a, 0x80, 0x01))),
            }),
          ],
          ['an issuer with an empty RDN', certificateFrom({ spki, issuer: sequence(set()) })],
          [
            'an issuer attribute without a value',
            certificateFrom({ spki, issuer: sequence(set(sequence(oid('2.5.4.3')))) }),
          ],
          [
            'an issuer that is not a Name',
            certificateFrom({ spki, issuer: tlv(0x0c, Uint8Array.of(0x41)) }),
          ],
          ['a validity with one time', certificateFrom({ spki, validity: sequence(utcTime(now)) })],
          [
            'a validity with three times',
            certificateFrom({ spki, validity: sequence(utcTime(now), utcTime(now), utcTime(now)) }),
          ],
          [
            'a validity time that is not a time',
            certificateFrom({
              spki,
              validity: sequence(
                tlv(0x17, new TextEncoder().encode('991399999999Z')),
                utcTime(now)
              ),
            }),
          ],
          [
            'a subject that is not a Name',
            certificateFrom({ spki, subject: empty.subarray(0, 1) }),
          ],
          [
            'a public key info with extra data',
            certificateFrom({
              spki: sequence(spki.subarray(4), integer(Uint8Array.of(1))),
            }),
          ],
          [
            'extensions that are not a list of extensions',
            certificateFrom({ spki, extensions: tlv(0xa3, sequence(integer(Uint8Array.of(1)))) }),
          ],
          [
            'different inner and outer signature algorithms',
            certificateFrom({ spki, signatureAlgorithm: sequence(oid('1.2.840.10045.4.3.2')) }),
          ],
          ['no signature value', certificateFrom({ spki, signatureValue: new Uint8Array() })],
          ['trailing bytes', certificateFrom({ spki, trailing: Uint8Array.of(0) })],
        ];
        for (const [what, leaf] of shapes) {
          const err = await expectFailure(
            verify(await withLeaf(leaf), rsaKey()),
            'invalid-embedded-key',
            'a1'
          );
          expect(err.message, what).to.contain('x5c');
        }
      });
    });

    describe('embedded key form', () => {
      const flipLastBit = (b64u: string) => {
        const bytes = base64url.decode(b64u);
        bytes[bytes.length - 1] ^= 1;
        return base64urlEncode(bytes);
      };

      it('accepts points on P-256, P-384, and P-521 and rejects points off them', async () => {
        for (const crv of ['P-256', 'P-384', 'P-521'] as const) {
          const { sdk } = await ecdsaKeyPair(crv);
          const jwk = (await exportPublicKeyJwk(sdk.publicKey)) as Json;
          const onCurve = { kty: 'EC', crv, x: jwk.x, y: jwk.y };
          await jwkIdentity(onCurve, cryptoService);
          const offCurve = { ...onCurve, y: flipLastBit(jwk.y as string) };
          const e = await rejection(jwkIdentity(offCurve, cryptoService));
          expect(e, crv).to.be.instanceOf(MalformedKeyError);
        }
        const jwk = (await exportPublicKeyJwk(ecSignerKey.sdk.publicKey)) as Json;
        const a = await signed(baseAssertion(), ecSigner(ecSignerKey.sdk), {
          alg: 'ES256',
          jwk: { ...jwk, y: flipLastBit(jwk.y as string) },
        });
        await expectFailure(
          verify(a, { alg: 'ES256', key: ecSignerKey.pubPem }),
          'invalid-embedded-key',
          'a1'
        );
      });

      it('accepts Ed25519 and Ed448 jwks, and no other OKP curve', async () => {
        await jwkIdentity(
          { kty: 'OKP', crv: 'Ed25519', x: base64urlEncode(new Uint8Array(32)) },
          cryptoService
        );
        await jwkIdentity(
          { kty: 'OKP', crv: 'Ed448', x: base64urlEncode(new Uint8Array(57)) },
          cryptoService
        );
        for (const crv of ['X25519', 'X448', 'Ed25519ph']) {
          const e = await rejection(
            jwkIdentity({ kty: 'OKP', crv, x: base64urlEncode(new Uint8Array(32)) }, cryptoService)
          );
          expect(e, crv).to.be.instanceOf(MalformedKeyError);
        }
      });

      it('requires canonical padded base64 in x5c', async () => {
        const cert = await selfSignedCertificate(cryptoService, signer.sdk, 'RS256');
        expect(decodeBase64Padded(cert)).to.exist;
        expect(decodeBase64Padded('AQ==')).to.deep.equal(Uint8Array.of(1));
        for (const bad of ['AR==', 'AQF=', 'AQ', 'AQ=', '-_8=']) {
          expect(decodeBase64Padded(bad), bad).to.equal(undefined);
        }
        // A certificate whose base64 ends in padding, so it has spare bits.
        const spki = await spkiOf(signer.sdk);
        const padded = ['a', 'ab', 'abc']
          .map((cn) => certificateFrom({ spki, subject: commonName(cn) }))
          .find((c) => c.endsWith('='))!;
        const padding = padded.endsWith('==') ? 2 : 1;
        const i = padded.length - 1 - padding;
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        const loose =
          padded.slice(0, i) + alphabet[alphabet.indexOf(padded[i]) | 1] + padded.slice(i + 1);
        await verify(
          await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256', x5c: [padded] }),
          rsaKey()
        );
        const a = await signed(baseAssertion(), rsaSigner(signer.sdk), {
          alg: 'RS256',
          x5c: [loose],
        });
        await expectFailure(verify(a, rsaKey()), 'invalid-embedded-key', 'a1');
        const b = await signed(baseAssertion(), rsaSigner(signer.sdk), {
          alg: 'RS256',
          x5c: [padded, loose],
        });
        await expectFailure(verify(b, rsaKey()), 'invalid-embedded-key', 'a1');
      });
    });

    describe('configured key identity', () => {
      // A CryptoService that cannot export public keys, like an HSM.
      const noExport: CryptoService = {
        ...DefaultCryptoService,
        exportPublicKeyPem: () => Promise.reject(new Error('not extractable')),
        exportPublicKeyJwk: () => Promise.reject(new Error('not extractable')),
      };
      const verifyWith = (a: Json, key: assertions.AssertionKey, cs: CryptoService) =>
        assertions.verify(a as assertions.Assertion, aggregateHash, key, false, cs);

      it('reads a key configured as PEM from the PEM, without exporting it', async () => {
        const jwk = await exportPublicKeyJwk(signer.sdk.publicKey);
        const cert = await selfSignedCertificate(cryptoService, signer.sdk, 'RS256');
        for (const header of [{ jwk }, { x5c: [cert] }]) {
          const a = await signed(baseAssertion(), rsaSigner(signer.sdk), {
            alg: 'RS256',
            ...header,
          });
          await verifyWith(a, rsaKey(), noExport);
          await verifyWith(
            a,
            {
              alg: 'RS256',
              key: `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`,
            },
            noExport
          );
        }
      });

      it('fails closed only when an opaque key that cannot be exported must be compared', async () => {
        const plain = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        const withJwk = await signed(baseAssertion(), rsaSigner(signer.sdk), {
          alg: 'RS256',
          jwk: await exportPublicKeyJwk(signer.sdk.publicKey),
        });
        const opaque = { alg: 'RS256', key: signer.sdk.publicKey } as const;
        await verifyWith(plain, opaque, noExport);
        const err = await expectFailure(
          verifyWith(withJwk, opaque, noExport),
          'configuration-error',
          'a1'
        );
        expect(err.message).to.contain('not extractable');
      });

      it('fails closed for a WebCrypto key imported as not extractable', async function () {
        const key = await cryptoService.importPublicKey(signer.pubPem, {
          usage: 'sign',
          extractable: false,
        });
        const exportable = await cryptoService.exportPublicKeyPem(key).then(
          () => true,
          () => false
        );
        if (exportable) {
          // This engine exports public keys regardless of the flag.
          this.skip();
        }
        const plain = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        await verify(plain, { alg: 'RS256', key });
        const withJwk = await signed(baseAssertion(), rsaSigner(signer.sdk), {
          alg: 'RS256',
          jwk: await exportPublicKeyJwk(signer.sdk.publicKey),
        });
        await expectFailure(verify(withJwk, { alg: 'RS256', key }), 'configuration-error', 'a1');
      });
    });

    describe('JOSE header', () => {
      it('pins the algorithm to the selected key', async () => {
        const hmacKey = await cryptoService.importSymmetricKey(secret);
        const rs = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        await expectFailure(verify(rs, { alg: 'HS256', key: secret }), 'algorithm-mismatch', 'a1');
        await expectFailure(
          verify(rs, { alg: 'ES256', key: ecSignerKey.pubPem }),
          'algorithm-mismatch',
          'a1'
        );
        const hs = await signed(baseAssertion(), hmacSigner(hmacKey), { alg: 'HS256' });
        await expectFailure(verify(hs, rsaKey()), 'algorithm-mismatch', 'a1');
      });

      it('rejects missing, none, and unsupported algorithms', async () => {
        const sign = rsaSigner(signer.sdk);
        for (const header of [
          {},
          { alg: 7 },
          { alg: 'none' },
          { alg: 'ES384' },
          { alg: 'rs256' },
          { alg: 'PS256' },
        ]) {
          const a = await signed(baseAssertion(), sign, header);
          await expectFailure(verify(a, rsaKey()), 'unsupported-algorithm', 'a1');
        }
      });

      it('rejects crit headers', async () => {
        const a = await signed(baseAssertion(), rsaSigner(signer.sdk), {
          alg: 'RS256',
          crit: ['b64'],
          b64: true,
        });
        await expectFailure(verify(a, rsaKey()), 'invalid-binding', 'a1');
        const b = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256', crit: [] });
        await expectFailure(verify(b, rsaKey()), 'invalid-binding', 'a1');
      });

      it('rejects malformed tokens', async () => {
        const good = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        const token = (good.binding as Json).signature as string;
        const [h, p, s] = token.split('.');
        const notObject = base64urlEncode('[]');
        for (const signature of [
          `${h}.${p}`,
          `${h}.${p}.${s}.${s}`,
          `${h}..${s}`,
          `${notObject}.${p}.${s}`,
          `${h}.${notObject}.${s}`,
          JSON.stringify({ protected: h, payload: p, signature: s }),
          '',
          `${withTrailingBits(h)}.${p}.${s}`,
          `${h}.${withTrailingBits(p)}.${s}`,
        ]) {
          const a = { ...good, binding: { method: 'jws', signature } };
          await expectFailure(verify(a, rsaKey()), 'invalid-binding', 'a1');
        }
      });

      it('rejects duplicate members in the JWS header or payload', async () => {
        const good = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        const [h, p] = ((good.binding as Json).signature as string).split('.');
        const sign = rsaSigner(signer.sdk);
        const header = JSON.parse(new TextDecoder().decode(base64url.decode(h))) as Json;
        const claims = new TextDecoder().decode(base64url.decode(p));
        for (const [headerText, claimsText] of [
          ['{"alg":"HS256","alg":"RS256"}', claims],
          [JSON.stringify(header), claims.replace('{', '{"assertionHash":"x",')],
        ]) {
          const input = `${base64urlEncode(headerText)}.${base64urlEncode(claimsText)}`;
          const sig = await sign(new TextEncoder().encode(input));
          const a = { ...good, binding: { signature: `${input}.${base64urlEncode(sig)}` } };
          await expectFailure(verify(a, rsaKey()), 'invalid-binding', 'a1');
        }
      });

      it('rejects a signature that does not verify under the selected key', async () => {
        const good = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        const [h, p, s] = ((good.binding as Json).signature as string).split('.');
        for (const signature of [
          `${h}.${p}.${s}=`,
          `${h}.${p}.***`,
          `${h}.${p}.`,
          `${h}.${p}.${withTrailingBits(s)}`,
        ]) {
          const bad = { ...good, binding: { method: 'jws', signature } };
          await expectFailure(verify(bad, rsaKey()), 'signature-invalid', 'a1');
        }
        const a = await signed(baseAssertion(), rsaSigner(other.sdk), { alg: 'RS256' });
        await expectFailure(verify(a, rsaKey()), 'signature-invalid', 'a1');
        const b = await signed(baseAssertion(), hmacSigner(payloadKey), { alg: 'HS256' });
        await expectFailure(verify(b, { alg: 'HS256', key: secret }), 'signature-invalid', 'a1');
      });
    });

    describe('claims', () => {
      it('rejects missing or non-string claims', async () => {
        const good = await claimsFor(baseAssertion());
        for (const claims of [
          {},
          { assertionHash: good.assertionHash },
          { assertionSig: good.assertionSig },
          { ...good, assertionHash: 1 },
          { ...good, assertionSig: null },
        ]) {
          const a = await signed(
            baseAssertion(),
            rsaSigner(signer.sdk),
            { alg: 'RS256' },
            { claims }
          );
          await expectFailure(verify(a, rsaKey()), 'binding-mismatch', 'a1');
        }
      });

      it('rejects a changed assertion, and the other encoding', async () => {
        const a = await signed(
          baseAssertion('a1', { extensions: { note: 'x' } }),
          rsaSigner(signer.sdk),
          { alg: 'RS256' }
        );
        await verify(a, rsaKey());
        for (const edit of [
          (x: Json) => ((x.extensions as Json).note = 'y'),
          (x: Json) => (x.scope = 'payload'),
          (x: Json) => (x.extra = true),
          (x: Json) => ((x.statement as Json).hash = 'deadbeef'),
        ]) {
          const tampered = JSON.parse(JSON.stringify(a)) as Json;
          edit(tampered);
          await expectFailure(verify(tampered, rsaKey()), 'binding-mismatch', 'a1');
        }
        await expectFailure(verify(a, rsaKey(), true), 'binding-mismatch', 'a1');
        const legacy = await signed(
          baseAssertion(),
          rsaSigner(signer.sdk),
          { alg: 'RS256' },
          { legacy: true }
        );
        await verify(legacy, rsaKey(), true);
        await expectFailure(verify(legacy, rsaKey(), false), 'binding-mismatch', 'a1');
      });
    });

    describe('binding forms', () => {
      let token: string;
      before(async () => {
        const a = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        token = (a.binding as Json).signature as string;
      });
      const withBinding = (binding: unknown) => {
        const a = baseAssertion();
        if (binding !== undefined) {
          a.binding = binding;
        }
        return a;
      };

      it('accepts jws, JWS, and a missing method', async () => {
        for (const binding of [
          { method: 'jws', signature: token },
          { method: 'JWS', signature: token },
          { signature: token },
        ]) {
          await verify(withBinding(binding), rsaKey());
        }
      });

      const cases: Array<[string, unknown, AssertionFailureReason]> = [
        ['no binding', undefined, 'invalid-binding'],
        ['a string binding', 'jws', 'invalid-binding'],
        ['a null binding', null, 'invalid-binding'],
        ['an array binding', [], 'invalid-binding'],
        ['neither form', { method: 'jws' }, 'invalid-binding'],
        ['both forms', { method: 'jws', signature: 'x', bdo: 'y' }, 'invalid-binding'],
        ['a binding object', { bdo: 'opaque' }, 'unsupported-binding'],
        ['a binding object with a method', { method: 'jws', bdo: {} }, 'unsupported-binding'],
        ['a binding object with a bad method', { method: 7, bdo: {} }, 'unsupported-binding'],
        ['an unknown method', { method: 'xmldsig', signature: 'x' }, 'unsupported-binding'],
        ['a case-variant method value', { method: 'Jws', signature: 'x' }, 'unsupported-binding'],
        ['a non-string method', { method: null, signature: 'x' }, 'invalid-binding'],
        ['a non-string signature', { method: 'jws', signature: 7 }, 'invalid-binding'],
      ];
      for (const [what, binding, reason] of cases) {
        it(`rejects ${what} with ${reason}`, async () => {
          await expectFailure(verify(withBinding(binding), rsaKey()), reason, 'a1');
        });
      }
    });

    describe('errors', () => {
      it('are typed integrity errors with a reason and the exact id', async () => {
        const resigned = await signed(baseAssertion(' Idé '), rsaSigner(other.sdk), {
          alg: 'RS256',
        });
        const err = await expectFailure(verify(resigned, rsaKey()), 'signature-invalid', ' Idé ');
        expect(err).to.be.instanceOf(IntegrityError);
        expect(err).to.be.instanceOf(InvalidFileError);
        expect(err.name).to.equal('AssertionVerificationError');
        expect(err.message).to.match(/assertion/);
        expect(err.message).to.match(/integrity check/);
      });

      it('rejects invalid ids before anything else', async () => {
        for (const id of [undefined, null, '', 7, ['a']]) {
          const a = baseAssertion();
          if (id === undefined) {
            delete a.id;
          } else {
            a.id = id;
          }
          await expectFailure(verify(a, { alg: 'RS256', key: '' }), 'invalid-id');
        }
      });

      it('reports public-key text configured as an HS256 secret as a configuration error', async () => {
        const hs = await signed(baseAssertion(), hmacSigner(payloadKey), { alg: 'HS256' });
        const pemBytes = new TextEncoder().encode(signer.pubPem);
        for (const key of [pemBytes, await cryptoService.importSymmetricKey(pemBytes)]) {
          await expectFailure(verify(hs, { alg: 'HS256', key }), 'configuration-error', 'a1');
        }
      });

      it('reports keys imported for another algorithm or usage as configuration errors', async () => {
        const a = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        const der = await spkiOf(signer.sdk);
        const sha512 = wrapPublicKey(
          await crypto.subtle.importKey(
            'spki',
            new Uint8Array(der),
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
            true,
            ['verify']
          ),
          'rsa:2048'
        );
        const oaep = await cryptoService.importPublicKey(signer.pubPem, { usage: 'encrypt' });
        for (const key of [oaep, sha512]) {
          await expectFailure(verify(a, { alg: 'RS256', key }), 'configuration-error', 'a1');
        }
        const ecdh = await cryptoService.importPublicKey(ecSignerKey.pubPem, { usage: 'derive' });
        const es = await signed(baseAssertion(), ecSigner(ecSignerKey.sdk), { alg: 'ES256' });
        await expectFailure(verify(es, { alg: 'ES256', key: ecdh }), 'configuration-error', 'a1');
      });

      it('tells a key that cannot verify from a signature that does not', async () => {
        const a = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        const throwing: CryptoService = {
          ...DefaultCryptoService,
          verify: () => Promise.reject(new Error('unsupported')),
        };
        const refusing: CryptoService = {
          ...DefaultCryptoService,
          verify: () => Promise.resolve(false),
        };
        await expectFailure(
          assertions.verify(a as assertions.Assertion, aggregateHash, rsaKey(), false, throwing),
          'configuration-error',
          'a1'
        );
        await expectFailure(
          assertions.verify(a as assertions.Assertion, aggregateHash, rsaKey(), false, refusing),
          'signature-invalid',
          'a1'
        );
      });

      it('reports invalid configured keys as configuration errors', async () => {
        const a = await signed(baseAssertion(), rsaSigner(signer.sdk), { alg: 'RS256' });
        const hmacKey = await cryptoService.importSymmetricKey(secret);
        const keys = [
          { alg: 'RS256', key: '' },
          { alg: 'RS256', key: 'not a pem' },
          { alg: 'RS256', key: signer.sdk.privateKey },
          { alg: 'RS256', key: secret },
          { alg: 'RS256', key: hmacKey },
          { alg: 'RS256', key: ecSignerKey.pubPem },
          { alg: 'ES256', key: signer.pubPem },
          { alg: 'HS256', key: new Uint8Array() },
          { alg: 'HS256', key: 'secret as a string' },
          { alg: 'HS256', key: signer.sdk.publicKey },
          { alg: 'PS256', key: signer.pubPem },
          { alg: 'rs256', key: signer.pubPem },
          { alg: 'ES512' },
          { key: signer.pubPem },
          null,
        ];
        for (const key of keys) {
          await expectFailure(
            verify(a, key as assertions.AssertionKey),
            'configuration-error',
            'a1'
          );
        }
      });
    });
  });

  describe('key selection', () => {
    const verifyWith = (a: Json, keys?: assertions.AssertionVerificationKeys) =>
      verifyManifestAssertion(a, aggregateHash, keys, payloadKey, false, cryptoService);

    let payloadSigned: Json;
    let signerSigned: Json;
    let defaultSigned: Json;
    let defaultKeyPair: TestKeyPair;
    before(async () => {
      defaultKeyPair = await rsaKeyPair();
      payloadSigned = await signed(baseAssertion('a1'), hmacSigner(payloadKey), { alg: 'HS256' });
      signerSigned = await signed(baseAssertion('a1'), rsaSigner(signer.sdk), { alg: 'RS256' });
      defaultSigned = await signed(baseAssertion('a1'), rsaSigner(defaultKeyPair.sdk), {
        alg: 'RS256',
      });
    });

    it('uses the payload key only when nothing is configured', async () => {
      await verifyWith(payloadSigned);
      await verifyWith(payloadSigned, { Keys: {} });
      await verifyWith(payloadSigned, { Keys: {}, DefaultKey: {} as assertions.AssertionKey });
      await verifyWith(payloadSigned, {
        Keys: { other: rsaKey() },
        DefaultKey: { alg: '', key: '' } as unknown as assertions.AssertionKey,
      });
      await expectFailure(verifyWith(signerSigned), 'algorithm-mismatch', 'a1');
    });

    it('prefers the per-ID key and never falls back from it', async () => {
      const keys = {
        Keys: { a1: rsaKey() },
        DefaultKey: { alg: 'RS256', key: defaultKeyPair.pubPem },
      } as assertions.AssertionVerificationKeys;
      await verifyWith(signerSigned, keys);
      // Valid under the default key and the payload key, but a1 has its own key.
      await expectFailure(verifyWith(defaultSigned, keys), 'signature-invalid', 'a1');
      await expectFailure(verifyWith(payloadSigned, keys), 'algorithm-mismatch', 'a1');
    });

    it('uses the default key when there is no per-ID key, and never falls back from it', async () => {
      const keys = {
        Keys: { other: rsaKey() },
        DefaultKey: { alg: 'RS256', key: defaultKeyPair.pubPem },
      } as assertions.AssertionVerificationKeys;
      await verifyWith(defaultSigned, keys);
      await expectFailure(verifyWith(signerSigned, keys), 'signature-invalid', 'a1');
      await expectFailure(verifyWith(payloadSigned, keys), 'algorithm-mismatch', 'a1');
      // DefaultKey without Keys, as JavaScript callers may pass it.
      await verifyWith(defaultSigned, {
        DefaultKey: { alg: 'RS256', key: defaultKeyPair.sdk.publicKey },
      } as assertions.AssertionVerificationKeys);
    });

    it('accepts a default HS256 secret', async () => {
      const a = await signed(
        baseAssertion('anything'),
        hmacSigner(await cryptoService.importSymmetricKey(secret)),
        { alg: 'HS256' }
      );
      await verifyWith(a, { Keys: {}, DefaultKey: { alg: 'HS256', key: secret } });
      await expectFailure(verifyWith(a), 'signature-invalid', 'anything');
    });

    it('treats an invalid selected entry as a configuration error', async () => {
      const cases = [
        { Keys: { a1: undefined } },
        { Keys: { a1: null } },
        { Keys: { a1: { alg: 'RS256', key: '' } } },
        { Keys: { a1: { alg: 'RS256' } }, DefaultKey: rsaKey() },
        { Keys: {}, DefaultKey: { alg: 'RS256' } },
        { Keys: {}, DefaultKey: { key: signer.pubPem } },
        { Keys: {}, DefaultKey: 'RS256' },
        { Keys: {}, DefaultKey: { alg: 'rs256', key: signer.pubPem } },
        { DefaultKey: { alg: 'ES512' } },
        { Keys: 'a1' },
      ];
      for (const keys of cases) {
        await expectFailure(
          verifyWith(payloadSigned, keys as unknown as assertions.AssertionVerificationKeys),
          'configuration-error',
          'a1'
        );
      }
    });

    it('looks ids up exactly, as own entries', async () => {
      const keys = {
        Keys: { A1: rsaKey(), 'a1 ': rsaKey() },
      } as assertions.AssertionVerificationKeys;
      await verifyWith(payloadSigned, keys);
      for (const id of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
        const a = await signed(baseAssertion(id), hmacSigner(payloadKey), { alg: 'HS256' });
        await verifyWith(a, { Keys: {} });
      }
      // Inherited Keys and DefaultKey are not configuration.
      const inherited = Object.create({
        Keys: { a1: rsaKey() },
        DefaultKey: rsaKey(),
      }) as assertions.AssertionVerificationKeys;
      await verifyWith(payloadSigned, inherited);
      expect(selectVerificationKey('a1', undefined, payloadKey)).to.deep.equal({
        alg: 'HS256',
        key: payloadKey,
      });
    });

    it('rejects an invalid id before selecting a key', async () => {
      const a = { ...payloadSigned, id: 7 };
      await expectFailure(
        verifyWith(a, { Keys: {}, DefaultKey: { alg: 'RS256' } as assertions.AssertionKey }),
        'invalid-id'
      );
    });
  });
});
