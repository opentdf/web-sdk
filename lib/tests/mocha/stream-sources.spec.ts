/**
 * Two `{type: 'stream'}` readers, two different contracts.
 *
 * DSPX-4703 replaced `new Response(stream).arrayBuffer()` with a reader loop in
 * `tdf3/src/client/DecoratedReadableStream.ts`, because Chrome rewrites any
 * error raised while it drains a `Response` body into a bare
 * `TypeError: Failed to fetch`. The same construct is still in
 * `src/seekable.ts`, on the path `OpenTDF.open()` / `read()` take, so the
 * modern API still launders an `IntegrityError` into a network error on Chrome.
 * (Under mocha/Node there is nothing to mask; the karma run is the one that
 * matters — the same reason the existing `streamToBuffer` tests run in both.)
 *
 * The swap also narrowed what a `{type: 'stream'}` source may be. `Response`
 * took any `BodyInit`; `streamToBuffer` requires something with `getReader`.
 * `fromSource` still takes the wider set, so the same source object is now
 * accepted by one half of the SDK and rejected by the other.
 */
import { assert } from 'chai';

import { Client } from '../../tdf3/src/index.js';
import { fromSource } from '../../src/seekable.js';
import { IntegrityError } from '../../src/errors.js';
import {
  decryptBuffer,
  describeError,
  encryptToBuffer,
  newClient,
  rejectionOf,
  segmentedPlaintext,
} from './helpers/tdf-fixtures.js';

/** A stream that fails the way a tampered segment does. */
function failingStream(error: Error): ReadableStream<Uint8Array> {
  return new ReadableStream({
    pull() {
      throw error;
    },
  });
}

describe('{type: "stream"} sources', function () {
  const plaintext = segmentedPlaintext();
  let client: Client.Client;

  beforeEach(function () {
    client = newClient();
  });

  it('fromSource propagates the original error rather than masking it', async function () {
    const thrown = new IntegrityError('Failed integrity check on segment hash');
    const e = await rejectionOf(
      fromSource({ type: 'stream', location: failingStream(thrown) }),
      'the stream error must survive'
    );
    // The identical instance, so no layer re-wraps it.
    assert.strictEqual(e, thrown, describeError(e));
  });

  it('control: a buffer source round-trips', async function () {
    const { buffer } = await encryptToBuffer(client, plaintext);
    assert.deepEqual(await decryptBuffer(client, buffer), plaintext);
  });

  it('control: fromSource accepts a Blob as a stream source', async function () {
    const { buffer } = await encryptToBuffer(client, plaintext);
    const blob = new Blob([buffer as BlobPart]);
    const chunker = await fromSource({
      type: 'stream',
      location: blob as unknown as ReadableStream<Uint8Array>,
    });
    assert.deepEqual(await chunker(), buffer);
  });

  it('decrypt accepts the same stream sources fromSource does', async function () {
    const { buffer } = await encryptToBuffer(client, plaintext);
    const blob = new Blob([buffer as BlobPart]);
    const stream = await client.decrypt({
      source: { type: 'stream', location: blob as unknown as ReadableStream<Uint8Array> },
    });
    assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
  });
});
