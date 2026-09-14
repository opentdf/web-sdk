/**
 * `CryptoService.hmac` returns a `Uint8Array`, and a `Uint8Array` is a *view*.
 *
 * The legacy (4.2.2) writer hex-encodes `sig.buffer` — the whole backing
 * `ArrayBuffer` — instead of the view. `hex.encodeArrayBuffer` then does
 * `new Uint8Array(arrayBuffer)`, ignoring `byteOffset`/`byteLength`. When the
 * view starts at offset 0 and spans the buffer the two are the same string, so
 * the bundled `WebCryptoService` hides it; when it does not, the manifest gets
 * the hex of unrelated memory.
 *
 * `CryptoService` is a documented plug point, and the obvious Node
 * implementation returns a `Buffer`, which is pooled: `Buffer.from(...)` and
 * `Buffer.concat(...)` both hand back views into a shared 8 KiB block. Such an
 * integrator writes files that fail their own read with "Failed integrity check
 * on root signature" — indistinguishable from tampering — and leaks heap into
 * the manifest.
 *
 * The 4.3.0 writer is fine: it passes the view itself.
 */
import { assert } from 'chai';

import { WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { type CryptoService } from '../../tdf3/src/crypto/declarations.js';
import {
  decryptBuffer,
  encryptToBuffer,
  newClient,
  segmentedPlaintext,
} from './helpers/tdf-fixtures.js';

const PAD = 48;

/**
 * A conforming `CryptoService` whose `hmac` returns a view into a larger
 * buffer, the way a pooled `Buffer` does. Nothing else changes.
 */
const pooledCryptoService: CryptoService = {
  ...WebCryptoService,
  async hmac(data, key) {
    const sig = await WebCryptoService.hmac(data, key);
    const pool = new Uint8Array(sig.length + 2 * PAD).fill(0xab);
    pool.set(sig, PAD);
    return pool.subarray(PAD, PAD + sig.length);
  },
};

describe('a CryptoService whose hmac returns a pooled view', function () {
  const plaintext = segmentedPlaintext();
  let client: Client.Client;

  beforeEach(function () {
    client = newClient({ cryptoService: pooledCryptoService });
  });

  it('control: the wrapper is faithful, just offset', async function () {
    const key = await WebCryptoService.generateKey();
    const data = new Uint8Array([1, 2, 3, 4]);
    const plain = await WebCryptoService.hmac(data, key);
    const pooled = await pooledCryptoService.hmac(data, key);
    assert.deepEqual(Array.from(pooled), Array.from(plain), 'same bytes');
    assert.equal(pooled.byteOffset, PAD, 'but not at the start of its buffer');
  });

  it('control: a 4.3.0 file round-trips', async function () {
    const { buffer } = await encryptToBuffer(client, plaintext);
    assert.deepEqual(await decryptBuffer(client, buffer), plaintext);
  });

  it('writes a 4.2.2 file it can read back', async function () {
    const { buffer } = await encryptToBuffer(client, plaintext, { tdfSpecVersion: '4.2.2' });
    assert.deepEqual(await decryptBuffer(client, buffer), plaintext);
  });
});
