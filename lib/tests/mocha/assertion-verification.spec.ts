import { assert, expect } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { HttpRequest } from '../../src/auth/auth.js';
import { base64 } from '../../src/encodings/index.js';
import { AssertionVerificationError, type AssertionFailureReason } from '../../src/errors.js';
import { OpenTDF } from '../../src/opentdf.js';
import { fromBuffer } from '../../src/seekable.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import type { AssertionConfig, AssertionVerificationKeys } from '../../tdf3/src/assertions.js';
import * as assertions from '../../tdf3/src/assertions.js';
import { exportPublicKeyJwk } from '../../tdf3/src/crypto/core/key-format.js';
import { base64urlEncode } from '../../tdf3/src/crypto/jwt.js';
import { Client } from '../../tdf3/src/index.js';
import type { Manifest } from '../../tdf3/src/models/manifest.js';
import { packTdf, packTdfWithManifestText, unpackTdf } from './helpers/tdf-archive.js';
import { rsaKeyPair, type TestKeyPair } from './helpers/jws-keys.js';
import { selfSignedCertificate } from './helpers/x509.js';

const Mocks = getMocks();
const cryptoService = WebCryptoService;

type Json = Record<string, unknown>;

/**
 * End-to-end checks that decrypt selects assertion verification keys only from
 * the caller's configuration (per-ID key, then default key, then the payload
 * key), whatever keys an edited file embeds in its bindings.
 */
describe('assertion verification on decrypt', function () {
  const kasUrl = 'http://localhost:3000';
  const plaintext = 'assertion verification test';
  const authProvider = {
    updateClientPublicKey: async () => {},
    withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
  };

  let client: Client.Client;
  let signer: TestKeyPair;
  let other: TestKeyPair;
  let tdf: Uint8Array;
  let payload: Uint8Array;
  let manifest: Manifest;

  const statement = (value: string) => ({ format: 'json', schema: 'test-schema', value });

  before(async function () {
    client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });
    [signer, other] = await Promise.all([rsaKeyPair(), rsaKeyPair()]);
    const key = await new SplitKey(new AesGcmCipher(WebCryptoService)).generateKey();
    const stream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      offline: true,
      scope: { dissem: ['user@domain.com'], attributes: [] },
      keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(plaintext));
          controller.close();
        },
      }),
      assertionConfigs: [
        {
          id: 'a1',
          type: 'handling',
          scope: 'tdo',
          appliesToState: 'encrypted',
          statement: statement('{"classification":"A"}'),
          signingKey: { alg: 'RS256', key: signer.sdk.privateKey },
        },
      ] as AssertionConfig[],
    });
    tdf = await stream.toBuffer();
    ({ payload, manifest } = await unpackTdf(tdf));
  });

  async function decrypt(
    file: Uint8Array,
    assertionVerificationKeys?: AssertionVerificationKeys,
    noVerifyAssertions?: boolean
  ): Promise<string> {
    const stream = await client.decrypt({
      source: { type: 'buffer', location: file },
      assertionVerificationKeys,
      noVerifyAssertions,
    });
    return stream.toString();
  }

  async function expectRejected(
    promise: Promise<unknown>,
    reason: AssertionFailureReason,
    assertionId?: string
  ) {
    let error: unknown;
    try {
      await promise;
    } catch (e) {
      error = e;
    }
    expect(error, 'expected decrypt to fail').to.be.instanceOf(AssertionVerificationError);
    const e = error as AssertionVerificationError;
    expect(e.reason, e.message).to.equal(reason);
    expect(e.assertionId).to.equal(assertionId);
    expect(e.message).to.contain(`reason=${reason}`);
  }

  /** A new assertion over this file's segments, signed by `by` with `header`. */
  async function resign(id: string, by: TestKeyPair, header: Json): Promise<Json> {
    const a: Json = {
      id,
      type: 'handling',
      scope: 'tdo',
      appliesToState: 'encrypted',
      statement: statement('{"classification":"B"}'),
    };
    const segments = manifest.encryptionInformation.integrityInformation.segments.map(
      ({ hash }) => new Uint8Array(base64.decodeArrayBuffer(hash))
    );
    const assertionHash = await assertions.hash(a, cryptoService);
    const parts = [...segments, hexBytes(assertionHash)];
    const sig = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const p of parts) {
      sig.set(p, offset);
      offset += p.length;
    }
    const claims = { assertionHash, assertionSig: base64.encodeArrayBuffer(sig) };
    const input = `${base64urlEncode(JSON.stringify({ alg: 'RS256', ...header }))}.${base64urlEncode(
      JSON.stringify(claims)
    )}`;
    const signature = await cryptoService.sign(
      new TextEncoder().encode(input),
      by.sdk.privateKey,
      'RS256'
    );
    return {
      ...a,
      binding: { method: 'jws', signature: `${input}.${base64urlEncode(signature)}` },
    };
  }

  function hexBytes(h: string): Uint8Array {
    return Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
  }

  function withAssertions(list: unknown[]): Uint8Array {
    return packTdf(payload, { ...manifest, assertions: list });
  }

  const perId = (): AssertionVerificationKeys => ({
    Keys: { a1: { alg: 'RS256', key: signer.pubPem } },
  });
  const withDefault = (): AssertionVerificationKeys => ({
    Keys: { a1: { alg: 'RS256', key: signer.pubPem } },
    DefaultKey: { alg: 'RS256', key: signer.pubPem },
  });
  const defaultOnly = (): AssertionVerificationKeys => ({
    Keys: {},
    DefaultKey: { alg: 'RS256', key: signer.pubPem },
  });

  it('decrypts with the per-ID key or the default key', async function () {
    assert.equal(await decrypt(tdf, perId()), plaintext);
    assert.equal(await decrypt(tdf, defaultOnly()), plaintext);
    assert.equal(await decrypt(tdf, withDefault()), plaintext);
  });

  it('does not fall back to the payload key for a keyed assertion', async function () {
    await expectRejected(decrypt(tdf), 'algorithm-mismatch', 'a1');
    await expectRejected(
      decrypt(tdf, {
        Keys: { a1: { alg: 'RS256', key: other.pubPem } },
        DefaultKey: { alg: 'RS256', key: signer.pubPem },
      }),
      'signature-invalid',
      'a1'
    );
  });

  describe('an assertion re-signed in place', function () {
    it('fails a binding by another key that carries its jwk', async function () {
      const resigned = await resign('a1', other, {
        jwk: await exportPublicKeyJwk(other.sdk.publicKey),
      });
      await expectRejected(
        decrypt(withAssertions([resigned]), perId()),
        'signer-not-permitted',
        'a1'
      );
      await expectRejected(
        decrypt(withAssertions([resigned]), defaultOnly()),
        'signer-not-permitted',
        'a1'
      );
      await expectRejected(decrypt(withAssertions([resigned])), 'algorithm-mismatch', 'a1');
    });

    it('fails a binding by another key that carries a self-signed x5c', async function () {
      const resigned = await resign('a1', other, {
        x5c: [await selfSignedCertificate(cryptoService, other.sdk, 'RS256')],
      });
      await expectRejected(
        decrypt(withAssertions([resigned]), perId()),
        'signer-not-permitted',
        'a1'
      );
      await expectRejected(
        decrypt(withAssertions([resigned]), defaultOnly()),
        'signer-not-permitted',
        'a1'
      );
    });

    it('accepts a binding re-signed by the configured key', async function () {
      const replacement = await resign('a1', signer, {
        jwk: await exportPublicKeyJwk(signer.sdk.publicKey),
        x5c: [await selfSignedCertificate(cryptoService, signer.sdk, 'RS256')],
      });
      assert.equal(await decrypt(withAssertions([replacement]), perId()), plaintext);
    });
  });

  describe('an added assertion', function () {
    it('fails a binding by another key under the default key', async function () {
      for (const header of [
        { jwk: await exportPublicKeyJwk(other.sdk.publicKey) },
        { x5c: [await selfSignedCertificate(cryptoService, other.sdk, 'RS256')] },
      ]) {
        const resigned = await resign('a2', other, header);
        const file = withAssertions([...manifest.assertions, resigned]);
        await expectRejected(decrypt(file, withDefault()), 'signer-not-permitted', 'a2');
        await expectRejected(decrypt(file, defaultOnly()), 'signer-not-permitted', 'a2');
        await expectRejected(decrypt(file, perId()), 'algorithm-mismatch', 'a2');
      }
    });

    it('accepts an added assertion signed by the default key', async function () {
      const appended = await resign('a2', signer, {
        jwk: await exportPublicKeyJwk(signer.sdk.publicKey),
      });
      const file = withAssertions([...manifest.assertions, appended]);
      assert.equal(await decrypt(file, withDefault()), plaintext);
      await expectRejected(decrypt(file, perId()), 'algorithm-mismatch', 'a2');
    });
  });

  it('skips assertion checks only when verification is disabled', async function () {
    const resigned = await resign('a1', other, {
      jwk: await exportPublicKeyJwk(other.sdk.publicKey),
    });
    assert.equal(await decrypt(withAssertions([resigned]), undefined, true), plaintext);
  });

  it('parses the manifest strictly even when verification is disabled', async function () {
    const text = JSON.stringify(manifest);
    const cases: Array<[string, AssertionFailureReason, string?]> = [
      [text.replace('"assertions":', '"Assertions":[],"assertions":'), 'ambiguous-member'],
      [text.replace('"id":"a1"', '"id":"a1","ID":"a2"'), 'ambiguous-member', 'a1'],
      [text.replace('"id":"a1"', '"id":"a2","\\u0069d":"a1"'), 'duplicate-member'],
      [text.replace('"id":"a1"', '"id":"a1","n":1e400'), 'invalid-json', 'a1'],
    ];
    for (const [edited, reason, id] of cases) {
      expect(edited).to.not.equal(text);
      const file = packTdfWithManifestText(payload, edited);
      await expectRejected(decrypt(file, perId(), true), reason, id);
      await expectRejected(decrypt(file, perId()), reason, id);
    }
  });

  it('rejects an assertion whose hash input changed', async function () {
    const edited = JSON.parse(JSON.stringify(manifest)) as Manifest;
    (edited.assertions[0] as unknown as Json).note = 'added';
    await expectRejected(decrypt(packTdf(payload, edited), perId()), 'binding-mismatch', 'a1');
  });

  it('applies the default key through the OpenTDF reader', async function () {
    const opentdf = new OpenTDF({
      authProvider,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
    });
    try {
      const read = (file: Uint8Array, assertionVerificationKeys?: AssertionVerificationKeys) =>
        opentdf
          .read({
            source: { type: 'chunker', location: fromBuffer(file) },
            allowedKASEndpoints: [kasUrl],
            assertionVerificationKeys,
          })
          .then((stream) => new Response(stream).text());
      assert.equal(await read(tdf, defaultOnly()), plaintext);
      const resigned = await resign('a2', other, {
        jwk: await exportPublicKeyJwk(other.sdk.publicKey),
      });
      await expectRejected(
        read(withAssertions([...manifest.assertions, resigned]), defaultOnly()),
        'signer-not-permitted',
        'a2'
      );
    } finally {
      opentdf.close();
    }
  });
});
