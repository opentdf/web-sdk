/**
 * Order of operations on the read path.
 *
 * `decryptStreamFrom` does three things with an untrusted manifest: it asks the
 * KAS to rewrap the DEK, it verifies the assertions, and it checks the root
 * signature. Only the third establishes that the manifest is authentic, and it
 * runs last — so the first two are performed on input that has not been
 * authenticated at all.
 *
 * Both are cheap to reorder: `rootSignature` is destructured before the
 * `unwrapKey` call, and the signature comparison needs nothing the assertion
 * loop produces.
 */
import { assert } from 'chai';

import { Client } from '../../tdf3/src/index.js';
import { IntegrityError } from '../../src/errors.js';
import { type AssertionConfig } from '../../tdf3/src/assertions.js';
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

/** Count outbound requests, so "did this reach the KAS?" is observable. */
function countRequests(): { count: number; stop(): void } {
  const original = globalThis.fetch;
  const counter = {
    count: 0,
    stop() {
      globalThis.fetch = original;
    },
  };
  globalThis.fetch = (...args: Parameters<typeof fetch>) => {
    counter.count++;
    return original(...args);
  };
  return counter;
}

const assertionConfig: AssertionConfig = {
  id: 'assertion-1',
  type: 'handling',
  scope: 'tdo',
  appliesToState: 'unencrypted',
  statement: {
    format: 'json',
    schema: 'urn:example:schema',
    value: '{"ok":true}',
  },
};

describe('read path ordering', function () {
  const plaintext = segmentedPlaintext();
  let client: Client.Client;

  beforeEach(function () {
    client = newClient();
  });

  describe('a root algorithm this SDK refuses', function () {
    it('control: a well-formed file does reach the KAS', async function () {
      const { buffer } = await encryptToBuffer(client, plaintext);
      const requests = countRequests();
      try {
        await decryptBuffer(client, buffer);
      } finally {
        requests.stop();
      }
      assert.isAbove(requests.count, 0, 'otherwise the counter proves nothing');
    });

    it('is rejected without a rewrap', async function () {
      // `alg` alone is enough: the SDK refuses a GMAC root whatever the
      // signature says, so nothing about this file is salvageable. An attacker
      // who cannot read it can still spend the KAS's policy decisions, audit
      // records and DEK releases by resubmitting copies.
      const { buffer } = await encryptToBuffer(client, plaintext);
      const { payload, manifest } = await unpackTdf(buffer);
      integrityInfo(manifest).rootSignature.alg = 'GMAC';

      const requests = countRequests();
      let e: unknown;
      try {
        e = await rejectionOf(
          decryptBuffer(client, packTdf(payload, manifest)),
          'a GMAC root is never acceptable'
        );
      } finally {
        requests.stop();
      }
      assert.instanceOf(e, IntegrityError, describeError(e));
      assert.equal(requests.count, 0, 'a file we categorically refuse must not cost a rewrap');
    });
  });

  describe('assertions', function () {
    it('control: a file with an assertion round-trips', async function () {
      const { buffer } = await encryptToBuffer(client, plaintext, {
        assertionConfigs: [assertionConfig],
      });
      assert.deepEqual(await decryptBuffer(client, buffer), plaintext);
    });

    it('are not interpreted before the root signature is verified', async function () {
      // Break the root signature, and make the assertion binding something no
      // JWT parser will touch. The manifest is unauthenticated, so the reader
      // has no business parsing an attacker's JWT header out of it yet --
      // `assertions.verify` reads `header.jwk` and `header.x5c` and takes its
      // *verification key* from them.
      const { buffer } = await encryptToBuffer(client, plaintext, {
        assertionConfigs: [assertionConfig],
      });
      const { payload, manifest } = await unpackTdf(buffer);
      const sig = integrityInfo(manifest).rootSignature.sig;
      integrityInfo(manifest).rootSignature.sig =
        `${sig.slice(0, -2)}${sig.endsWith('A') ? 'B' : 'A'}=`;
      (manifest.assertions as { binding: { signature: string } }[])[0].binding.signature =
        'not-a-jwt';

      const e = await rejectionOf(
        decryptBuffer(client, packTdf(payload, manifest)),
        'an unauthenticated manifest must not be interpreted'
      );
      assert.instanceOf(e, IntegrityError, describeError(e));
      assert.match(
        (e as Error).message,
        /root signature/,
        'the root signature check must be what rejects this file'
      );
    });
  });
});
