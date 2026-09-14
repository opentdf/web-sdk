/**
 * There is no parse boundary between a manifest and the reader.
 *
 * `ZipReader.getManifest` does a bare `JSON.parse` and hands the result
 * straight to `decryptStreamFrom`, which indexes into it. A manifest that is
 * merely *shaped* wrong — not signed wrong — therefore surfaces as a raw
 * `TypeError` or `InvalidCharacterError`, neither of which is a `TdfError`.
 *
 * That matters because the SDK documents its error taxonomy as the way callers
 * tell these cases apart: `InvalidFileError` means "this file is corrupt or
 * tampered", `TdfError` means "something the SDK has an opinion about". A bare
 * `TypeError` reads as an SDK bug, so a caller branching on the taxonomy
 * mishandles exactly the hostile input DSPX-4703 is about — and each of these
 * lands *before* `asRootIntegrityAlgorithm` gets a chance to fail closed.
 */
import { assert } from 'chai';

import { Client } from '../../tdf3/src/index.js';
import { TdfError } from '../../src/errors.js';
import {
  decryptBuffer,
  describeError,
  encryptToBuffer,
  newClient,
  packTdf,
  rejectionOf,
  segmentedPlaintext,
  unpackTdf,
} from './helpers/tdf-fixtures.js';

/** A manifest as it exists between `JSON.parse` and the reader: unvalidated. */
type RawManifest = Record<string, never>;

function rawIntegrityInfo(manifest: unknown) {
  return (manifest as { encryptionInformation: { integrityInformation: RawManifest } })
    .encryptionInformation.integrityInformation;
}

const cases: [string, (manifest: unknown) => void][] = [
  [
    'a manifest with no segment list',
    (manifest) => {
      delete rawIntegrityInfo(manifest).segments;
    },
  ],
  [
    'a manifest with no root signature',
    (manifest) => {
      delete rawIntegrityInfo(manifest).rootSignature;
    },
  ],
  [
    'a segment hash that is not base64',
    (manifest) => {
      (rawIntegrityInfo(manifest).segments as unknown as { hash: string }[])[0].hash = '!!!';
    },
  ],
];

describe('manifest validation', function () {
  const plaintext = segmentedPlaintext();
  let client: Client.Client;

  beforeEach(function () {
    client = newClient();
  });

  it('control: an untouched repack still reads', async function () {
    const { buffer } = await encryptToBuffer(client, plaintext);
    const { payload, manifest } = await unpackTdf(buffer);
    assert.deepEqual(await decryptBuffer(client, packTdf(payload, manifest)), plaintext);
  });

  for (const [what, break_] of cases) {
    it(`reports ${what} as a TdfError`, async function () {
      const { buffer } = await encryptToBuffer(client, plaintext);
      const { payload, manifest } = await unpackTdf(buffer);
      break_(manifest);
      const e = await rejectionOf(decryptBuffer(client, packTdf(payload, manifest)), what);
      assert.instanceOf(
        e,
        TdfError,
        `a caller cannot tell a hostile file from an SDK bug: ${describeError(e)}`
      );
    });
  }
});
