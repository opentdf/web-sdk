/**
 * DSPX-4703 — `toBuffer()` must not launder a decrypt failure into a network error.
 *
 * The obvious implementation, `new Response(stream).arrayBuffer()`, does exactly
 * that on Chrome: whatever the body stream errors with is replaced by a bare
 * `TypeError: Failed to fetch`. A caller then cannot tell a tampered payload from
 * a dropped connection — and the first is an attack while the second is a retry.
 *
 * These run under both mocha (Node) and karma (Chrome); the masking only ever
 * reproduced in the browser, so the browser run is the one that matters.
 */
import { assert } from 'chai';

import {
  DecoratedReadableStream,
  streamToBuffer,
} from '../../../tdf3/src/client/DecoratedReadableStream.js';
import { IntegrityError } from '../../../src/errors.js';

function streamOf(...chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(chunk);
      }
      controller.close();
    },
  });
}

/** A stream that yields `before`, then fails the way a bad segment does. */
function failingStream(error: Error, before?: Uint8Array): ReadableStream<Uint8Array> {
  let pulls = 0;
  return new ReadableStream({
    pull(controller) {
      if (before && pulls++ === 0) {
        controller.enqueue(before);
        return;
      }
      throw error;
    },
  });
}

describe('streamToBuffer', function () {
  it('concatenates every chunk in order', async function () {
    const got = await streamToBuffer(
      streamOf(new Uint8Array([1, 2]), new Uint8Array([]), new Uint8Array([3, 4, 5]))
    );
    assert.deepEqual(got, new Uint8Array([1, 2, 3, 4, 5]));
  });

  it('returns empty for an empty stream', async function () {
    assert.deepEqual(await streamToBuffer(streamOf()), new Uint8Array([]));
  });

  for (const [when, before] of [
    ['on the first pull', undefined],
    ['after some output', new Uint8Array([1, 2, 3])],
  ] as const) {
    it(`propagates the original error ${when}`, async function () {
      const thrown = new IntegrityError('Failed integrity check on segment hash');
      try {
        await streamToBuffer(failingStream(thrown, before));
        assert.fail('expected the stream error to surface');
      } catch (e) {
        // Not just the type: the identical instance, so no layer re-wraps it.
        assert.strictEqual(e, thrown);
      }
    });
  }
});

describe('DecoratedReadableStream', function () {
  it('toBuffer propagates a stream error rather than masking it', async function () {
    const thrown = new IntegrityError('Failed integrity check on segment hash');
    const decorated = new DecoratedReadableStream({
      pull() {
        throw thrown;
      },
    });
    try {
      await decorated.toBuffer();
      assert.fail('expected the stream error to surface');
    } catch (e) {
      assert.strictEqual(e, thrown);
    }
  });

  it('toString propagates a stream error rather than masking it', async function () {
    const thrown = new IntegrityError('Failed integrity check on segment hash');
    const decorated = new DecoratedReadableStream({
      pull() {
        throw thrown;
      },
    });
    try {
      await decorated.toString();
      assert.fail('expected the stream error to surface');
    } catch (e) {
      assert.strictEqual(e, thrown);
    }
  });

  it('toString decodes the stream as utf-8', async function () {
    const decorated = new DecoratedReadableStream({
      start(controller) {
        // Split a multi-byte character across chunks: decoding per chunk would
        // corrupt it, decoding the joined buffer does not.
        controller.enqueue(new Uint8Array([0xe2, 0x9c]));
        controller.enqueue(new Uint8Array([0x93]));
        controller.close();
      },
    });
    assert.equal(await decorated.toString(), '✓');
  });
});
