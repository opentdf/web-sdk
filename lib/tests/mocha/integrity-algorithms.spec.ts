/**
 * DSPX-4736 — the writer's choice of integrity algorithm.
 *
 * A ZTDF records two of them, and they are not interchangeable. Each segment's
 * hash covers ciphertext that AES-GCM actually produced, so `GMAC` there means
 * reading back a genuine authentication tag. The root signature covers the
 * aggregate of those hashes, which never passes through AES-GCM — there is no
 * tag to read out, so `HS256` is the only value that authenticates anything.
 *
 * These tests pin the defaults and the refusals. What a *reader* should do with
 * a manifest that already declares a GMAC root is a separate question, covered
 * by DSPX-4703.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { type EncryptParams } from '../../tdf3/src/client/builders.js';
import { asManifest, type Manifest } from '../../tdf3/src/models/manifest.js';
import { ConfigurationError } from '../../src/errors.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000';

const authProvider: AuthProvider = {
  updateClientPublicKey: async () => {},
  withCreds: async (httpReq: HttpRequest) => httpReq,
};

const SEGMENT_SIZE = 1024;
const SEGMENT_COUNT = 4;

function segmentedPlaintext(count = SEGMENT_COUNT): Uint8Array {
  const out = new Uint8Array(count * SEGMENT_SIZE);
  for (let i = 0; i < count; i++) {
    out.fill('A'.charCodeAt(0) + i, i * SEGMENT_SIZE, (i + 1) * SEGMENT_SIZE);
  }
  return out;
}

function newClient(): Client.Client {
  return new Client.Client({
    kasEndpoint: kasUrl,
    platformUrl: kasUrl,
    dpopKeys: Mocks.entityKeyPair(),
    clientId: 'id',
    authProvider,
  });
}

type EncryptOverrides = Omit<Partial<EncryptParams>, 'source' | 'keyMiddleware'>;

async function encryptToBuffer(
  client: Client.Client,
  plaintext: Uint8Array,
  overrides: EncryptOverrides = {}
): Promise<{ buffer: Uint8Array; manifest: Manifest }> {
  const encryptionInformation = new SplitKey(new AesGcmCipher(WebCryptoService));
  const key = await encryptionInformation.generateKey();
  const stream = await client.encrypt({
    metadata: Mocks.getMetadataObject(),
    offline: true,
    scope: { dissem: ['user@domain.com'], attributes: [] },
    windowSize: SEGMENT_SIZE,
    keyMiddleware: async () => ({ keyForEncryption: key, keyForManifest: key }),
    source: new ReadableStream({
      start(controller) {
        controller.enqueue(plaintext);
        controller.close();
      },
    }),
    ...overrides,
  });
  const buffer = await stream.toBuffer();
  return { buffer, manifest: stream.manifest };
}

function integrityInfo(manifest: Manifest) {
  return manifest.encryptionInformation.integrityInformation;
}

describe('integrity algorithm selection (DSPX-4736)', function () {
  let client: Client.Client;
  const plaintext = segmentedPlaintext();

  beforeEach(function () {
    client = newClient();
  });

  it('defaults to an HS256 root and GMAC segments', async function () {
    const { manifest } = await encryptToBuffer(client, plaintext);
    const info = integrityInfo(manifest);
    assert.equal(info.rootSignature.alg, 'HS256');
    assert.equal(info.segmentHashAlg, 'GMAC');
  });

  it('accepts an explicit HS256 root and round-trips', async function () {
    const { buffer, manifest } = await encryptToBuffer(client, plaintext, {
      rootIntegrityAlgorithm: 'HS256',
    });
    assert.equal(integrityInfo(manifest).rootSignature.alg, 'HS256');
    const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
    assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
  });

  for (const segmentIntegrityAlgorithm of ['GMAC', 'HS256'] as const) {
    it(`accepts ${segmentIntegrityAlgorithm} segments and round-trips`, async function () {
      const { buffer, manifest } = await encryptToBuffer(client, plaintext, {
        segmentIntegrityAlgorithm,
      });
      assert.equal(integrityInfo(manifest).segmentHashAlg, segmentIntegrityAlgorithm);
      const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
      assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
    });
  }

  it('refuses to write a GMAC root', async function () {
    try {
      await encryptToBuffer(client, plaintext, {
        // Only reachable by casting: `RootIntegrityAlgorithm` cannot be 'GMAC'.
        rootIntegrityAlgorithm: 'GMAC' as never,
      });
      assert.fail('expected a ConfigurationError');
    } catch (e) {
      assert.instanceOf(e, ConfigurationError);
      assert.include((e as Error).message, 'unsupported root integrity algorithm');
    }
  });

  it('refuses to write an unknown root algorithm', async function () {
    try {
      await encryptToBuffer(client, plaintext, {
        rootIntegrityAlgorithm: 'CRC32' as never,
      });
      assert.fail('expected a ConfigurationError');
    } catch (e) {
      assert.instanceOf(e, ConfigurationError);
      assert.include((e as Error).message, 'unsupported root integrity algorithm');
    }
  });

  it('refuses to write an unknown segment algorithm', async function () {
    try {
      await encryptToBuffer(client, plaintext, {
        segmentIntegrityAlgorithm: 'CRC32' as never,
      });
      assert.fail('expected a ConfigurationError');
    } catch (e) {
      assert.instanceOf(e, ConfigurationError);
      assert.include((e as Error).message, 'unsupported segment integrity algorithm');
    }
  });

  // The guards accept any casing so that callers can hand us user input directly.
  // What lands in the manifest is a separate question: readers -- ours included --
  // match the spec's uppercase spelling exactly, so a lowercase manifest is one no
  // one can open. These pin the writer's canonicalization rather than the guards'.
  for (const segment of ['gmac', 'hs256'] as const) {
    it(`canonicalizes lowercase '${segment}' segments and a lowercase root`, async function () {
      const { buffer, manifest } = await encryptToBuffer(client, plaintext, {
        rootIntegrityAlgorithm: 'hs256' as never,
        segmentIntegrityAlgorithm: segment as never,
      });
      assert.equal(integrityInfo(manifest).rootSignature.alg, 'HS256');
      assert.equal(integrityInfo(manifest).segmentHashAlg, segment.toUpperCase());

      // Re-read the bytes we actually wrote, not the in-memory manifest. The
      // read boundary hands back unvalidated JSON, so run it through asManifest
      // -- which is itself part of the assertion, since it rejects a manifest
      // whose algorithms are not spelled the way the spec requires.
      const { manifest: onDisk } = await client.loadTDFStream({
        source: { type: 'buffer', location: buffer },
      });
      const parsed = asManifest(onDisk);
      assert.equal(integrityInfo(parsed).rootSignature.alg, 'HS256');
      assert.equal(integrityInfo(parsed).segmentHashAlg, segment.toUpperCase());

      // And the strict reader can open it, which a lowercase manifest cannot.
      const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
      assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
    });
  }

  it('canonicalizes lowercase algorithms in a 4.2.2 manifest too', async function () {
    const { manifest } = await encryptToBuffer(client, plaintext, {
      tdfSpecVersion: '4.2.2',
      rootIntegrityAlgorithm: 'hs256' as never,
      segmentIntegrityAlgorithm: 'gmac' as never,
    });
    assert.equal(integrityInfo(manifest).rootSignature.alg, 'HS256');
    assert.equal(integrityInfo(manifest).segmentHashAlg, 'GMAC');
  });
});
