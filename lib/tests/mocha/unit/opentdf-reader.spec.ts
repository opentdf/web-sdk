import { expect } from 'chai';

import { getMocks } from '../../mocks/index.js';
import type { HttpRequest } from '../../../src/auth/auth.js';
import { AssertionVerificationError } from '../../../src/errors.js';
import { OpenTDF } from '../../../src/opentdf.js';
import { archive } from '../../validation-fixtures.js';

const Mocks = getMocks();

/**
 * Collects unhandled rejections in Node and browsers alike. Mocha's own Node
 * listener would otherwise swallow them, so a leak would not fail the suite.
 */
function captureUnhandledRejections() {
  const reasons: unknown[] = [];
  const onNode = (reason: unknown) => reasons.push(reason);
  const onBrowser = (event: PromiseRejectionEvent) => {
    reasons.push(event.reason);
    event.preventDefault();
  };
  const proc = (globalThis as { process?: NodeJS.Process }).process;
  if (proc?.on) {
    proc.on('unhandledRejection', onNode);
  } else {
    globalThis.addEventListener('unhandledrejection', onBrowser);
  }
  return {
    reasons,
    async stop() {
      // Unhandled rejections are reported on a later macrotask.
      await new Promise((resolve) => setTimeout(resolve, 20));
      if (proc?.on) {
        proc.off('unhandledRejection', onNode);
      } else {
        globalThis.removeEventListener('unhandledrejection', onBrowser);
      }
    },
  };
}

describe('OpenTDF reader', function () {
  it('rejects a manifest that fails strict parsing, without an unhandled rejection', async function () {
    // The duplicate member is outside any assertion: strict parsing covers the
    // whole manifest, before any KAS call.
    const manifest =
      '{"payload":{"type":"reference","url":"0.payload","url":"other"},' +
      '"encryptionInformation":{},"assertions":[]}';
    const tdf = archive([
      { name: '0.payload', data: new Uint8Array(16) },
      { name: '0.manifest.json', data: new TextEncoder().encode(manifest) },
    ]);
    // Hold the DPoP keys back so decrypt is still waiting on them when the
    // manifest load fails, as it is while a real client generates its keys.
    let releaseKeys!: () => void;
    const keysReleased = new Promise<void>((resolve) => (releaseKeys = resolve));
    const opentdf = new OpenTDF({
      authProvider: {
        updateClientPublicKey: async () => {},
        withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
      },
      platformUrl: 'http://localhost:3000',
      dpopKeys: keysReleased.then(() => Mocks.entityKeyPair()),
    });
    const unhandled = captureUnhandledRejections();
    let error: unknown;
    try {
      const reading = opentdf.read({
        source: { type: 'buffer', location: tdf },
        allowedKASEndpoints: ['http://localhost:3000'],
      });
      await new Promise((resolve) => setTimeout(resolve, 50));
      releaseKeys();
      error = await reading.then(
        () => undefined,
        (e: unknown) => e
      );
    } finally {
      await unhandled.stop();
      opentdf.close();
    }
    expect(error).to.be.instanceOf(AssertionVerificationError);
    const e = error as AssertionVerificationError;
    expect(e.reason).to.equal('duplicate-member');
    expect(e.message).to.contain('reason=duplicate-member');
    expect(unhandled.reasons).to.deep.equal([]);
  });
});
