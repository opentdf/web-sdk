/**
 * DSPX-4703 — the legacy (TDF spec 4.2.2) integrity encoding.
 *
 * 4.2.2 differs from the current spec in *encoding* only. Where a modern
 * manifest stores `base64(mac)`, a 4.2.2 manifest stores `base64(hex(mac))`.
 * The MAC itself covers the same bytes either way — the Go SDK's
 * `calculateSignature` is one `if isLegacyTDF` around the encoding, with
 * identical input on both sides of it.
 *
 * Our legacy writer disagreed. Before HMACing a segment it ran the ciphertext
 * through a UTF-8 decode, which turns every byte sequence that is not valid
 * UTF-8 into U+FFFD. AES-GCM output is indistinguishable from random, so
 * nearly every segment was mangled and the writer signed a digest that nothing
 * could reproduce — not Go, not Java, not our own reader, which HMACs the
 * ciphertext as it stands. `GMAC` hid it for two years: that branch reads the
 * AEAD tag back out of the bytes without decoding anything, and `GMAC` is the
 * default segment algorithm.
 *
 * So these tests pin the encoding to the cross-SDK definition and not to
 * whatever the writer happens to emit. A round-trip assertion alone would be
 * satisfied by teaching the reader to mangle its input too, which would leave
 * us self-consistent and alone.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { type EncryptParams } from '../../tdf3/src/client/builders.js';
import { type SymmetricKey } from '../../tdf3/src/crypto/declarations.js';
import { type Manifest } from '../../tdf3/src/models/manifest.js';
import { loadTDFStream } from '../../tdf3/src/tdf.js';
import { fromBuffer } from '../../src/seekable.js';
import { base64, hex } from '../../src/encodings/index.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000';

const authProvider: AuthProvider = {
  updateClientPublicKey: async () => {},
  withCreds: async (httpReq: HttpRequest) => httpReq,
};

const SEGMENT_SIZE = 1024;
const SEGMENT_COUNT = 4;
const GMAC_TAG_LENGTH = 16;

/**
 * Distinguishable segments, so a decryption that silently returns the wrong
 * bytes fails the assertion rather than passing on length alone.
 */
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

/**
 * Encrypt into a complete in-memory 4.2.2 TDF, keeping the DEK so the test can
 * recompute the manifest's integrity values from first principles.
 */
async function encrypt422(
  client: Client.Client,
  plaintext: Uint8Array,
  overrides: EncryptOverrides = {}
): Promise<{ buffer: Uint8Array; manifest: Manifest; dek: SymmetricKey }> {
  const encryptionInformation = new SplitKey(new AesGcmCipher(WebCryptoService));
  const key = await encryptionInformation.generateKey();
  const stream = await client.encrypt({
    metadata: Mocks.getMetadataObject(),
    offline: true,
    scope: { dissem: ['user@domain.com'], attributes: [] },
    windowSize: SEGMENT_SIZE,
    tdfSpecVersion: '4.2.2',
    keyMiddleware: async () => ({ keyForEncryption: key, keyForManifest: key }),
    source: new ReadableStream({
      start(controller) {
        controller.enqueue(plaintext);
        controller.close();
      },
    }),
    ...overrides,
  });
  return {
    buffer: await stream.toBuffer(),
    manifest: stream.manifest,
    dek: key.unwrappedKey,
  };
}

function integrityInfo(manifest: Manifest) {
  return manifest.encryptionInformation.integrityInformation;
}

/** The payload split back into the ciphertext segments the writer hashed. */
async function ciphertextSegments(buffer: Uint8Array, manifest: Manifest): Promise<Uint8Array[]> {
  const info = integrityInfo(manifest);
  const sizes = info.segments.map(
    ({ encryptedSegmentSize }) =>
      encryptedSegmentSize ?? info.encryptedSegmentSizeDefault ?? SEGMENT_SIZE
  );
  const { zipReader, centralDirectory } = await loadTDFStream(fromBuffer(buffer));
  const payload = await zipReader.getPayloadSegment(
    centralDirectory,
    '0.payload',
    0,
    sizes.reduce((a, b) => a + b, 0)
  );

  const out: Uint8Array[] = [];
  let offset = 0;
  for (const size of sizes) {
    out.push(payload.subarray(offset, offset + size));
    offset += size;
  }
  return out;
}

/** `base64(hex(bytes))`, the one thing 4.2.2 does differently. */
function legacyEncode(mac: Uint8Array): string {
  return base64.encode(hex.encodeArrayBuffer(Uint8Array.from(mac).buffer));
}

describe('legacy 4.2.2 integrity encoding (DSPX-4703)', function () {
  const plaintext = segmentedPlaintext();

  for (const segmentIntegrityAlgorithm of ['GMAC', 'HS256'] as const) {
    it(`round-trips a 4.2.2 file with ${segmentIntegrityAlgorithm} segments`, async function () {
      const client = newClient();
      const { buffer } = await encrypt422(client, plaintext, { segmentIntegrityAlgorithm });
      const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
      assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
    });
  }

  it('hashes HS256 segments over the ciphertext as it stands', async function () {
    const client = newClient();
    const { buffer, manifest, dek } = await encrypt422(client, plaintext, {
      segmentIntegrityAlgorithm: 'HS256',
    });
    const segments = integrityInfo(manifest).segments;
    const ciphertexts = await ciphertextSegments(buffer, manifest);
    assert.lengthOf(ciphertexts, SEGMENT_COUNT);

    for (const [i, ciphertext] of ciphertexts.entries()) {
      const expected = legacyEncode(await WebCryptoService.hmac(ciphertext, dek));
      assert.equal(segments[i].hash, expected, `segment ${i}`);
    }
  });

  it('hashes GMAC segments as the trailing AEAD tag', async function () {
    const client = newClient();
    const { buffer, manifest } = await encrypt422(client, plaintext, {
      segmentIntegrityAlgorithm: 'GMAC',
    });
    const segments = integrityInfo(manifest).segments;
    const ciphertexts = await ciphertextSegments(buffer, manifest);

    for (const [i, ciphertext] of ciphertexts.entries()) {
      const expected = legacyEncode(ciphertext.slice(-GMAC_TAG_LENGTH));
      assert.equal(segments[i].hash, expected, `segment ${i}`);
    }
  });

  // The aggregate hash is a run of hex digits, so the UTF-8 decode was the
  // identity here and this passed before the fix as well. It is pinned so the
  // two legacy writers cannot drift apart again unnoticed.
  it('signs the root over the aggregate of the segment hashes', async function () {
    const client = newClient();
    const { manifest, dek } = await encrypt422(client, plaintext, {
      segmentIntegrityAlgorithm: 'HS256',
    });
    const info = integrityInfo(manifest);

    // Each stored hash is base64 of that segment's hex digits; the writer
    // aggregates the hex, not the base64.
    const aggregate = info.segments.map(({ hash }) => base64.decode(hash)).join('');
    const expected = legacyEncode(
      await WebCryptoService.hmac(new TextEncoder().encode(aggregate), dek)
    );

    assert.equal(info.rootSignature.alg, 'HS256');
    assert.equal(info.rootSignature.sig, expected);
  });
});
