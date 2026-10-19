/**
 * `writeStream` cuts its input into `windowSize` segments however the source
 * happens to chunk it. These tests pin that the segment boundaries, and the
 * bytes inside them, do not depend on the input chunking.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { type Manifest } from '../../tdf3/src/models/manifest.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000';
const SEGMENT_SIZE = 7;

function newClient(): Client.Client {
  return new Client.Client({
    kasEndpoint: kasUrl,
    platformUrl: kasUrl,
    dpopKeys: Mocks.entityKeyPair(),
    clientId: 'id',
    authProvider: {
      updateClientPublicKey: async () => {},
      withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
    },
  });
}

/** Distinct bytes, so a dropped, repeated or reordered byte changes the output. */
function plaintextOf(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (i * 31 + 7) & 0xff);
}

/** A source that delivers `plaintext` in pieces of the given sizes, cycling. */
function chunkedSource(plaintext: Uint8Array, sizes: number[]): ReadableStream<Uint8Array> {
  let offset = 0;
  let i = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset >= plaintext.length) {
        controller.close();
        return;
      }
      const n = sizes[i++ % sizes.length];
      controller.enqueue(plaintext.slice(offset, offset + n));
      offset += n;
    },
  });
}

async function roundTrip(
  source: ReadableStream<Uint8Array>
): Promise<{ manifest: Manifest; decrypted: Uint8Array }> {
  const client = newClient();
  const key = await new SplitKey(new AesGcmCipher(WebCryptoService)).generateKey();
  const stream = await client.encrypt({
    metadata: Mocks.getMetadataObject(),
    offline: true,
    scope: { dissem: ['user@domain.com'], attributes: [] },
    windowSize: SEGMENT_SIZE,
    keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
    source,
  });
  const buffer = await stream.toBuffer();
  const decrypted = await client.decrypt({ source: { type: 'buffer', location: buffer } });
  return { manifest: stream.manifest, decrypted: new Uint8Array(await decrypted.toBuffer()) };
}

/** The plaintext size of each segment, as the manifest records it. */
function segmentSizes(manifest: Manifest): number[] {
  const info = manifest.encryptionInformation.integrityInformation;
  return info.segments.map(({ segmentSize }) => segmentSize ?? info.segmentSizeDefault!);
}

function expectedSegmentSizes(length: number): number[] {
  const sizes = Array<number>(Math.floor(length / SEGMENT_SIZE)).fill(SEGMENT_SIZE);
  return length % SEGMENT_SIZE ? [...sizes, length % SEGMENT_SIZE] : sizes;
}

describe('writeStream segmentation', function () {
  const cases: { name: string; length: number; sizes: number[] }[] = [
    { name: 'no input at all', length: 0, sizes: [1] },
    { name: 'one chunk shorter than a segment', length: 5, sizes: [5] },
    { name: 'one byte at a time', length: 30, sizes: [1] },
    { name: 'chunks that straddle segment boundaries', length: 40, sizes: [3, 5] },
    { name: 'chunks of exactly one segment', length: 28, sizes: [SEGMENT_SIZE] },
    { name: 'one chunk holding several segments', length: 33, sizes: [33] },
    { name: 'a large chunk after a partial segment', length: 50, sizes: [2, 30, 1] },
  ];

  for (const { name, length, sizes } of cases) {
    it(name, async function () {
      const plaintext = plaintextOf(length);
      const { manifest, decrypted } = await roundTrip(chunkedSource(plaintext, sizes));
      assert.deepEqual(segmentSizes(manifest), expectedSegmentSizes(length));
      assert.deepEqual(decrypted, plaintext);
    });
  }
});
