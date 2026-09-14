/**
 * A 4.2.2 file written with HS256 segments cannot be read back.
 *
 * `segmentIntegrityVersion422`'s HS256 branch HMACs a UTF-8 *round-trip* of the
 * ciphertext — `buffToString(bytes, 'utf-8')` then `TextEncoder.encode(...)`.
 * That round-trip is lossy: every byte sequence that is not valid UTF-8 becomes
 * U+FFFD, so the bytes fed to the HMAC are not the bytes on disk. The reader
 * HMACs the raw ciphertext, so the two can never agree.
 *
 * The combination only became reachable in DSPX-4736, which made
 * `segmentIntegrityAlgorithm` a caller-visible option (`CreateZTDFOptions`, and
 * `opentdf --tdfSpecVersion 4.2.2 --segmentIntegrityAlgorithm hs256`). Callers
 * who use it write archives nothing can open, and the failure is reported as
 * tampering.
 */
import { assert } from 'chai';

import { Client } from '../../tdf3/src/index.js';
import {
  decryptBuffer,
  encryptToBuffer,
  newClient,
  segmentedPlaintext,
} from './helpers/tdf-fixtures.js';

describe('4.2.2 files with HS256 segments', function () {
  const plaintext = segmentedPlaintext();
  let client: Client.Client;

  beforeEach(function () {
    client = newClient();
  });

  // Controls: the other three corners of (spec version x segment algorithm)
  // round-trip, so a failure below is about this pairing and not about the
  // harness, the legacy writer, or HS256 segments in general.
  for (const [tdfSpecVersion, segmentIntegrityAlgorithm] of [
    ['4.2.2', 'GMAC'],
    ['4.3.0', 'GMAC'],
    ['4.3.0', 'HS256'],
  ] as const) {
    it(`control: ${tdfSpecVersion} + ${segmentIntegrityAlgorithm} segments round-trip`, async function () {
      const { buffer } = await encryptToBuffer(client, plaintext, {
        tdfSpecVersion,
        segmentIntegrityAlgorithm,
      });
      assert.deepEqual(await decryptBuffer(client, buffer), plaintext);
    });
  }

  it('round-trips', async function () {
    const { buffer } = await encryptToBuffer(client, plaintext, {
      tdfSpecVersion: '4.2.2',
      segmentIntegrityAlgorithm: 'HS256',
    });
    assert.deepEqual(await decryptBuffer(client, buffer), plaintext);
  });
});
