/**
 * `writeStream` cuts its input into segments of `segmentSizeDefault` bytes
 * (`windowSize` to `Client.encrypt`) however the source happens to chunk it and
 * however fast the output is read. These tests pin that the segment
 * boundaries, and the bytes inside them, depend on neither.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { HttpRequest } from '../../src/auth/auth.js';
import { ConfigurationError } from '../../src/errors.js';
import type { CryptoService } from '../../tdf3/index.js';
import { AesGcmCipher, Binary, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import type { DecoratedReadableStream } from '../../tdf3/src/client/DecoratedReadableStream.js';
import { type Manifest } from '../../tdf3/src/models/manifest.js';
import { concatUint8 } from '../../tdf3/src/utils/index.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000';
const SEGMENT_SIZE = 7;

async function rejection(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (e) {
    return e as Error;
  }
  return assert.fail('expected a rejection');
}

function nextTask(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function newClient(cryptoService: CryptoService = WebCryptoService): Client.Client {
  return new Client.Client({
    kasEndpoint: kasUrl,
    platformUrl: kasUrl,
    dpopKeys: Mocks.entityKeyPair(),
    clientId: 'id',
    authProvider: {
      updateClientPublicKey: async () => {},
      withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
    },
    cryptoService,
  });
}

/**
 * Bytes that don't repeat within any 256, so a dropped, repeated or reordered
 * byte changes the output.
 */
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

/** A source that delivers exactly `chunks`, whatever their type. */
function sourceOf(chunks: unknown[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(chunk as Uint8Array);
      }
      controller.close();
    },
  });
}

/** Wraps `WebCryptoService`, passing each `encrypt` call through `encrypt`. */
function withEncrypt(encrypt: CryptoService['encrypt']): CryptoService {
  return new Proxy(WebCryptoService, {
    get(target, property, receiver) {
      return property === 'encrypt'
        ? encrypt
        : (Reflect.get(target, property, receiver) as unknown);
    },
  });
}

async function encrypt(
  source: ReadableStream<Uint8Array>,
  cryptoService?: CryptoService
): Promise<DecoratedReadableStream> {
  const key = await new SplitKey(new AesGcmCipher(WebCryptoService)).generateKey();
  return newClient(cryptoService).encrypt({
    metadata: Mocks.getMetadataObject(),
    offline: true,
    scope: { dissem: ['user@domain.com'], attributes: [] },
    windowSize: SEGMENT_SIZE,
    keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
    source,
  });
}

async function decrypt(tdf: Uint8Array): Promise<Uint8Array> {
  const decrypted = await newClient().decrypt({ source: { type: 'buffer', location: tdf } });
  return new Uint8Array(await decrypted.toBuffer());
}

async function roundTrip(
  source: ReadableStream<Uint8Array>,
  cryptoService?: CryptoService
): Promise<{ manifest: Manifest; decrypted: Uint8Array }> {
  const stream = await encrypt(source, cryptoService);
  const decrypted = await decrypt(await stream.toBuffer());
  return { manifest: stream.manifest, decrypted };
}

/**
 * The plaintext size of each segment, as the manifest records it. Segments of
 * the default size leave `segmentSize` out.
 */
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
    { name: 'empty chunks between the others', length: 20, sizes: [0, 3, 0, 7] },
  ];

  for (const { name, length, sizes } of cases) {
    it(name, async function () {
      const plaintext = plaintextOf(length);
      const { manifest, decrypted } = await roundTrip(chunkedSource(plaintext, sizes));
      assert.deepEqual(segmentSizes(manifest), expectedSegmentSizes(length));
      assert.deepEqual(decrypted, plaintext);
    });
  }

  it('stops encrypting while the reader is idle, then picks up where it left off', async function () {
    // One chunk holds four full segments. With nothing reading, `pull` must
    // stop after one of them, and later pulls must encrypt the rest from the
    // queue before reading the source again.
    let encrypted = 0;
    const counting = withEncrypt(async (...args) => {
      const result = await WebCryptoService.encrypt(...args);
      encrypted++;
      return result;
    });
    const plaintext = plaintextOf(33);
    const stream = await encrypt(chunkedSource(plaintext, [33]), counting);
    const before = encrypted;

    const reader = stream.stream.getReader();
    const chunks: Uint8Array[] = [];
    const header = await reader.read();
    chunks.push(header.value!);
    while (encrypted === before) {
      await nextTask();
    }
    // With GMAC, only microtasks remain between that encrypt and the end of
    // `pull`, so by the next task it has returned with three segments still
    // queued. A few more give a `pull` that ignores backpressure time to show.
    for (let i = 0; i < 5; i++) {
      await nextTask();
    }
    assert.equal(encrypted - before, 1, 'encrypted ahead of an idle reader');

    for (let r = await reader.read(); !r.done; r = await reader.read()) {
      chunks.push(r.value);
    }
    assert.deepEqual(segmentSizes(stream.manifest), expectedSegmentSizes(33));
    assert.deepEqual(await decrypt(concatUint8(chunks)), plaintext);
  });

  it('lets the crypto service take ownership of the plaintext', async function () {
    // A service that hands work to a Worker may transfer its input, which
    // detaches it. A full segment is passed as its own buffer, so `writeStream`
    // must not look at the segment again once it is encrypted.
    const transferring = withEncrypt((payload, ...rest) => {
      if (!(payload instanceof Binary)) {
        return WebCryptoService.encrypt(payload, ...rest);
      }
      const buffer = payload.asArrayBuffer();
      const moved = structuredClone(buffer, { transfer: [buffer] });
      return WebCryptoService.encrypt(Binary.fromArrayBuffer(moved), ...rest);
    });
    const plaintext = plaintextOf(30);
    const { manifest, decrypted } = await roundTrip(chunkedSource(plaintext, [3, 5]), transferring);
    assert.deepEqual(segmentSizes(manifest), expectedSegmentSizes(30));
    assert.deepEqual(decrypted, plaintext);
  });

  it('reads ArrayBuffer, DataView and wider typed array chunks as their bytes', async function () {
    // The source is typed as Uint8Array, but JavaScript callers can pass any
    // binary chunk. One without a `length` used to drop out of the payload.
    const plaintext = plaintextOf(20);
    const { manifest, decrypted } = await roundTrip(
      sourceOf([
        plaintext.slice(0, 3),
        plaintext.slice(3, 9).buffer,
        new DataView(plaintext.slice().buffer, 9, 6),
        new Uint16Array(plaintext.slice(15, 19).buffer),
        plaintext.slice(19),
      ])
    );
    assert.deepEqual(segmentSizes(manifest), expectedSegmentSizes(20));
    assert.deepEqual(decrypted, plaintext);
  });

  it('rejects a chunk that is not binary', async function () {
    const stream = await encrypt(sourceOf([plaintextOf(3), 'abc']));
    const error = await rejection(stream.toBuffer());
    assert.instanceOf(error, ConfigurationError);
    assert.match(error.message, /\[object String\]/);
  });
});
