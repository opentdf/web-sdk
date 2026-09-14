/**
 * A caught decrypt failure must stay caught.
 *
 * `sliceAndDecrypt` rejects *every* failed chunk's mailbox, but the stream's
 * `pull` only ever awaits chunks up to the first failure — after that the
 * stream is errored and nothing reads the rest. Each surplus rejection is a
 * promise no one is waiting on, which Node turns into an `unhandledRejection`
 * (terminating the process by default) and Chrome logs as
 * `Uncaught (in promise)`.
 *
 * That is the opposite of what DSPX-4703 is for: a caller who correctly wraps
 * `decrypt` in a try/catch, and sees the `IntegrityError`, still has their
 * process torn down by the same tampered file.
 *
 * Every existing tampering test corrupts segment 0 — the one chunk `pull` does
 * await — which is why the suite has never noticed.
 */
import { assert } from 'chai';

import { Client } from '../../tdf3/src/index.js';
import { InvalidFileError } from '../../src/errors.js';
import {
  corruptSegment,
  newClient,
  segmentedPlaintext,
  tamperTdf,
} from './helpers/tdf-fixtures.js';

type RejectionCapture = { readonly reasons: unknown[]; stop(): void };

/**
 * Collect unhandled rejections rather than letting the runner act on them:
 * mocha would fail the *next* test with them, which hides where they came
 * from, and Chrome would only print them. Either way the point is to assert on
 * them here.
 */
function captureUnhandledRejections(): RejectionCapture {
  const reasons: unknown[] = [];
  const proc = (globalThis as { process?: NodeJS.Process }).process;
  if (typeof proc?.on === 'function') {
    const handler = (reason: unknown) => {
      reasons.push(reason);
    };
    const installed = proc.listeners('unhandledRejection');
    proc.removeAllListeners('unhandledRejection');
    proc.on('unhandledRejection', handler);
    return {
      reasons,
      stop() {
        proc.removeListener('unhandledRejection', handler);
        for (const listener of installed) {
          proc.on('unhandledRejection', listener);
        }
      },
    };
  }
  const handler = (event: PromiseRejectionEvent) => {
    reasons.push(event.reason);
    event.preventDefault();
  };
  addEventListener('unhandledrejection', handler);
  return {
    reasons,
    stop() {
      removeEventListener('unhandledrejection', handler);
    },
  };
}

/** Both runtimes report an unhandled rejection a macrotask after the fact. */
function settle(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 100));
}

async function expectCaught(promise: Promise<unknown>, why: string) {
  try {
    await promise;
  } catch (e) {
    assert.instanceOf(e, InvalidFileError, why);
    return;
  }
  assert.fail(`expected a rejection: ${why}`);
}

describe('decrypt error propagation', function () {
  const plaintext = segmentedPlaintext();
  let client: Client.Client;
  let capture: RejectionCapture;

  beforeEach(function () {
    client = newClient();
    capture = captureUnhandledRejections();
  });

  afterEach(function () {
    capture.stop();
  });

  // One corrupt segment is the case `pull` happens to await, so it establishes
  // that the harness itself is quiet.
  it('control: one corrupt segment leaves nothing unhandled', async function () {
    await expectCaught(
      tamperTdf(client, plaintext, ({ payload, manifest }) => ({
        manifest,
        payload: corruptSegment(payload, manifest, 0),
      })),
      'a flipped tag byte must be caught'
    );
    await settle();
    assert.deepEqual(capture.reasons, []);
  });

  it('leaves nothing unhandled when several segments fail', async function () {
    await expectCaught(
      tamperTdf(client, plaintext, ({ payload, manifest }) => ({
        manifest,
        payload: corruptSegment(corruptSegment(payload, manifest, 1), manifest, 2),
      })),
      'a flipped tag byte must be caught'
    );
    await settle();
    assert.deepEqual(
      capture.reasons,
      [],
      'the caller caught the error; no rejection may escape to the runtime'
    );
  });
});
