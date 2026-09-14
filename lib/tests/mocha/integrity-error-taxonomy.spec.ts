/**
 * "Corrupt or tampered" and "written by a newer SDK" are different answers.
 *
 * `src/errors.ts` draws the line: `IntegrityError extends InvalidFileError`
 * means *this file is corrupt or has been tampered with*, while
 * `UnsupportedFeatureError extends TdfError` means *this SDK does not
 * implement that yet*. Callers and telemetry branch on it — the first is an
 * attack to investigate, the second is a client to upgrade.
 *
 * `asRootIntegrityAlgorithm` throws `IntegrityError` for every value that is
 * not HS256, so a ZTDF a future spec revision roots with, say, HS384 is
 * reported as an attack. Only GMAC is the downgrade: it is refused because the
 * construction is forgeable, not because it is unrecognized.
 *
 * The neighbours already disagree with it, which is the other half of the
 * problem: an unknown *segment* algorithm is an `UnsupportedFeatureError`, and
 * the writer-side guards are `ConfigurationError`s — three classes for one
 * condition, depending only on where in the manifest the value sat.
 *
 * NOTE: the HS512 case below contradicts
 * `root-signature.spec.ts` -> "rejects an unknown root algorithm rather than
 * defaulting to HS256", which asserts `IntegrityError` for the same input.
 * Both cannot hold; that assertion is the one this branch says is wrong.
 */
import { assert } from 'chai';

import { Client } from '../../tdf3/src/index.js';
import { IntegrityError, UnsupportedFeatureError } from '../../src/errors.js';
import {
  decryptBuffer,
  describeError,
  encryptToBuffer,
  integrityInfo,
  newClient,
  packTdf,
  rejectionOf,
  segmentedPlaintext,
  unpackTdf,
} from './helpers/tdf-fixtures.js';

describe('root algorithm rejection taxonomy', function () {
  const plaintext = segmentedPlaintext();
  let client: Client.Client;

  beforeEach(function () {
    client = newClient();
  });

  async function decryptWithRootAlg(alg: string): Promise<unknown> {
    const { buffer } = await encryptToBuffer(client, plaintext);
    const { payload, manifest } = await unpackTdf(buffer);
    integrityInfo(manifest).rootSignature.alg = alg;
    return rejectionOf(decryptBuffer(client, packTdf(payload, manifest)), `root alg [${alg}]`);
  }

  // A GMAC root is a downgrade attempt whatever its spelling: the value is
  // forgeable from manifest data alone, so a file declaring it is hostile.
  for (const alg of ['GMAC', 'gmac']) {
    it(`control: "${alg}" is reported as tampering`, async function () {
      const e = await decryptWithRootAlg(alg);
      assert.instanceOf(e, IntegrityError, describeError(e));
    });
  }

  // These are not forgeable constructions, just ones this build does not know.
  for (const alg of ['HS384', 'HS512']) {
    it(`"${alg}" is reported as unsupported, not as tampering`, async function () {
      const e = await decryptWithRootAlg(alg);
      assert.instanceOf(e, UnsupportedFeatureError, describeError(e));
      assert.notInstanceOf(
        e,
        IntegrityError,
        'a file from a newer SDK is not an attack on this one'
      );
    });
  }

  it('an unknown segment algorithm is already classified that way', async function () {
    // The sibling guard, for contrast: same shape of condition, different
    // position in the manifest, and it gets the taxonomy right.
    const { buffer } = await encryptToBuffer(client, plaintext);
    const { payload, manifest } = await unpackTdf(buffer);
    integrityInfo(manifest).segmentHashAlg = 'HS384';
    const e = await rejectionOf(
      decryptBuffer(client, packTdf(payload, manifest)),
      'segment alg [HS384]'
    );
    assert.instanceOf(e, UnsupportedFeatureError, describeError(e));
  });
});
