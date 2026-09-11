import { expect } from 'chai';

import { ConfigurationError } from '../../../src/errors.js';
import { writeStream } from '../../../tdf3/src/tdf.js';
import type { IntegrityAlgorithm } from '../../../tdf3/src/tdf.js';
import {
  DEFAULT_MANIFEST_MAX_SIZE,
  MAX_PAYLOAD_SEGMENTS_PER_KEY,
  estimateManifestBytes,
  maxEncryptableBytes,
  maxSegmentsFor,
} from '../../../tdf3/src/utils/scale-limits.js';
import { MANIFEST_MAX_SIZE } from '../../../tdf3/src/utils/zip-reader.js';
import { encryptConfiguration, segmentsArrayBytes, writeTdf } from '../helpers/write-tdf.js';

/**
 * A stream that reports how many times it was pulled, so a test can prove the
 * up-front budget check rejects without encrypting anything.
 */
function countingStream(plaintext: Uint8Array, chunkSize: number) {
  const counter = { pulls: 0 };
  let offset = 0;
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        counter.pulls += 1;
        if (offset >= plaintext.length) {
          controller.close();
          return;
        }
        controller.enqueue(plaintext.subarray(offset, offset + chunkSize));
        offset += chunkSize;
      },
    },
    // Without this the stream pre-pulls one chunk at construction time, which
    // would show up as a read nobody asked for.
    { highWaterMark: 0 }
  );
  return { stream, counter };
}

describe('manifest size budget', () => {
  // The read and write sides must agree, or the SDK can produce a container it
  // then refuses to open.
  it('uses one ceiling on both the read and write paths', () => {
    expect(MANIFEST_MAX_SIZE).to.equal(DEFAULT_MANIFEST_MAX_SIZE);
  });

  describe('up-front rejection', () => {
    const segmentSize = 64;
    // 400 segments at 36 bytes each is ~14.4 KiB of `segments`, comfortably
    // over a 4 KiB budget but small enough to encrypt if the check misses.
    const plaintext = new Uint8Array(400 * segmentSize);
    const manifestMaxSize = 4096;
    // A budget no manifest will ever reach, so the invocation ceiling is the
    // only thing left that can bind.
    const hugeManifestBudget = 2 ** 40;

    it('rejects before reading a single byte of the source', async () => {
      const { stream, counter } = countingStream(plaintext, segmentSize);
      const cfg = await encryptConfiguration({
        plaintext,
        segmentSize,
        contentStream: stream,
        knownSourceSize: plaintext.length,
        manifestMaxSize,
      });

      let error: Error | undefined;
      try {
        await writeStream(cfg);
      } catch (e) {
        error = e;
      }

      expect(error, 'expected the oversized manifest to be rejected').to.be.instanceOf(
        ConfigurationError
      );
      expect(error?.message).to.contain('an estimated');
      expect(error?.message).to.contain('400 segments');
      expect(counter.pulls, 'source was read despite an up-front rejection').to.equal(0);
    });

    it('still catches the same case at end of stream when the size is unknown', async () => {
      let error: Error | undefined;
      try {
        await writeTdf({ plaintext, segmentSize, manifestMaxSize });
      } catch (e) {
        error = e;
      }
      expect(error).to.be.instanceOf(ConfigurationError);
      expect(error?.message).to.contain('too large');
      // The late check measures the real manifest, so it does not hedge.
      expect(error?.message).to.not.contain('an estimated');
    });

    it('lets a manifest that fits through, size known or not', async () => {
      for (const knownSourceSize of [plaintext.length, undefined]) {
        const { manifest, manifestBytes } = await writeTdf({
          plaintext,
          segmentSize,
          knownSourceSize,
          manifestMaxSize: 64 * 1024,
        });
        expect(manifest.encryptionInformation.integrityInformation.segments).to.have.lengthOf(400);
        expect(manifestBytes.length).to.be.at.most(64 * 1024);
      }
    });

    // The manifest check cannot see this: with a generous manifest budget the
    // segments array fits fine, and it is the AES-GCM per-key invocation
    // ceiling that the payload runs out of. GcmIvCounter would catch it, but
    // only on the segment that overflows.
    it('rejects a source past the AES-GCM invocation ceiling, not just the manifest', async () => {
      // A 1 TiB manifest budget puts the manifest nowhere near binding, so the
      // only thing left to run out of is invocations. `knownSourceSize` is just
      // a number here -- no bytes are produced, which is the point.
      const maxBytes = maxEncryptableBytes({
        segmentSize,
        alg: 'GMAC',
        manifestMaxSize: hugeManifestBudget,
      });
      expect(maxSegmentsFor({ alg: 'GMAC', manifestMaxSize: hugeManifestBudget })).to.equal(
        MAX_PAYLOAD_SEGMENTS_PER_KEY
      );

      const { stream, counter } = countingStream(plaintext, segmentSize);
      const cfg = await encryptConfiguration({
        plaintext,
        segmentSize,
        segmentIntegrityAlgorithm: 'GMAC',
        contentStream: stream,
        knownSourceSize: maxBytes + 1,
        manifestMaxSize: hugeManifestBudget,
      });

      let error: Error | undefined;
      try {
        await writeStream(cfg);
      } catch (e) {
        error = e;
      }
      expect(error).to.be.instanceOf(ConfigurationError);
      expect(error?.message, 'should be the invocation ceiling, not the manifest').to.contain(
        'too large to encrypt under a single key'
      );
      expect(counter.pulls).to.equal(0);
    });

    it('admits a source exactly at the ceiling', async () => {
      const maxBytes = maxEncryptableBytes({
        segmentSize,
        alg: 'GMAC',
        manifestMaxSize: hugeManifestBudget,
      });
      const { stream } = countingStream(plaintext, segmentSize);
      const cfg = await encryptConfiguration({
        plaintext,
        segmentSize,
        segmentIntegrityAlgorithm: 'GMAC',
        contentStream: stream,
        knownSourceSize: maxBytes,
        manifestMaxSize: hugeManifestBudget,
      });
      // Resolves rather than throwing; the stream is never drained, so this
      // only exercises the up-front checks.
      expect(await writeStream(cfg)).to.exist;
    });

    // An estimate under the truth would let a doomed encrypt start; an estimate
    // wildly over it would reject payloads that would have been fine. Measured
    // against a real manifest, the slack is exactly one byte -- the separating
    // comma counted for the last entry, which has none.
    it('estimates the whole manifest to within a byte of what is written', async () => {
      for (const alg of ['GMAC', 'HS256'] as IntegrityAlgorithm[]) {
        for (const sourceSize of [1, 63, 64, 65, 200, 640, 4096]) {
          const written = await writeTdf({
            plaintext: new Uint8Array(sourceSize),
            segmentSize,
            segmentIntegrityAlgorithm: alg,
            knownSourceSize: sourceSize,
          });
          const estimate = estimateManifestBytes({
            sourceSize,
            segmentSize,
            alg,
            baseManifestBytes: written.manifestBytes.length - segmentsArrayBytes(written.manifest),
          });
          expect(estimate - written.manifestBytes.length, `${sourceSize} bytes at ${alg}`).to.equal(
            1
          );
        }
      }
    });
  });
});
