import { expect } from 'chai';

import { ConfigurationError } from '../../../src/errors.js';
import { MAX_GCM_INVOCATIONS_PER_KEY } from '../../../tdf3/src/ciphers/gcm-iv-counter.js';
import type { IntegrityAlgorithm } from '../../../tdf3/src/tdf.js';
import {
  base64Length,
  estimateSegmentsArrayBytes,
  FIFTY_TEBIBYTES,
  finalSegmentEntryBytes,
  minSegmentSizeFor,
  perSegmentEntryBytes,
  segmentCountFor,
} from '../../../tdf3/src/utils/scale-limits.js';
import { segmentsArrayBytes, writeTdf } from '../helpers/write-tdf.js';

const MIB = 1024 * 1024;

describe('scale-limits', () => {
  describe('base64Length', () => {
    it('matches the encoder, padding included', () => {
      for (const byteLength of [0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 64]) {
        const encoded = btoa(String.fromCharCode(...new Uint8Array(byteLength)));
        expect(base64Length(byteLength), `${byteLength} bytes`).to.equal(encoded.length);
      }
    });
  });

  describe('perSegmentEntryBytes', () => {
    it('costs 36 bytes per GMAC segment and 56 per HS256 segment', () => {
      expect(perSegmentEntryBytes('GMAC')).to.equal(36);
      expect(perSegmentEntryBytes('HS256')).to.equal(56);
    });

    it('rejects an unknown algorithm', () => {
      expect(() => perSegmentEntryBytes('SHA1' as IntegrityAlgorithm)).to.throw(ConfigurationError);
    });
  });

  describe('segmentCountFor', () => {
    it('counts a trailing partial segment', () => {
      expect(segmentCountFor(0, 1024)).to.equal(0);
      expect(segmentCountFor(1, 1024)).to.equal(1);
      expect(segmentCountFor(1024, 1024)).to.equal(1);
      expect(segmentCountFor(1025, 1024)).to.equal(2);
      expect(segmentCountFor(FIFTY_TEBIBYTES, 16 * MIB)).to.equal(3_276_800);
    });

    it('rejects a nonsensical segment size', () => {
      expect(() => segmentCountFor(1024, 0)).to.throw(ConfigurationError);
      expect(() => segmentCountFor(1024, 1.5)).to.throw(ConfigurationError);
    });
  });

  describe('minSegmentSizeFor', () => {
    it('derives the 12.5 KiB floor a 50 TiB payload needs to stay under the IV ceiling', () => {
      expect(minSegmentSizeFor(FIFTY_TEBIBYTES)).to.equal(12_800);
      expect(FIFTY_TEBIBYTES / minSegmentSizeFor(FIFTY_TEBIBYTES)).to.be.at.most(
        MAX_GCM_INVOCATIONS_PER_KEY
      );
    });

    it('is far below every segment size we would actually pick', () => {
      expect(minSegmentSizeFor(FIFTY_TEBIBYTES)).to.be.below(MIB);
    });
  });

  // The whole point of extracting these is that 50 TiB is reachable in a unit
  // test. These are the numbers the plan in
  // `spec/DSPX-4648-web-sdk-large-files.md` is argued from.
  describe('manifest size at 50 TiB', () => {
    const cases: [segmentSize: number, alg: IntegrityAlgorithm, approxBytes: number][] = [
      [MIB, 'HS256', 2.936e9],
      [4 * MIB, 'HS256', 7.34e8],
      [16 * MIB, 'HS256', 1.835e8],
      [64 * MIB, 'HS256', 4.588e7],
      [MIB, 'GMAC', 1.887e9],
      [16 * MIB, 'GMAC', 1.18e8],
    ];

    for (const [segmentSize, alg, approxBytes] of cases) {
      it(`50TiB@${segmentSize / MIB}MiB/${alg} -> ~${(approxBytes / 1e6).toFixed(0)} MB`, () => {
        const actual = estimateSegmentsArrayBytes({
          sourceSize: FIFTY_TEBIBYTES,
          segmentSize,
          alg,
        });
        // 50 TiB divides evenly by every power-of-two segment size, so this is
        // exact: no trailing partial segment to account for.
        expect(actual).to.equal(2 + (FIFTY_TEBIBYTES / segmentSize) * perSegmentEntryBytes(alg));
        expect(actual).to.be.closeTo(approxBytes, approxBytes * 0.01);
      });
    }
  });
});

// Guards the constants above against drifting from what `writeStream` really
// serializes. Rather than asserting on a hand-built entry, this measures the
// delta a real extra segment adds to a real emitted manifest.
describe('scale-limits agreement with the manifest serializer', () => {
  const segmentSize = 64;

  for (const alg of ['GMAC', 'HS256'] as IntegrityAlgorithm[]) {
    it(`one more full ${alg} segment costs exactly perSegmentEntryBytes`, async () => {
      const four = await writeTdf({
        plaintext: new Uint8Array(4 * segmentSize),
        segmentSize,
        segmentIntegrityAlgorithm: alg,
      });
      const five = await writeTdf({
        plaintext: new Uint8Array(5 * segmentSize),
        segmentSize,
        segmentIntegrityAlgorithm: alg,
      });

      expect(four.manifest.encryptionInformation.integrityInformation.segments).to.have.lengthOf(4);
      expect(five.manifest.encryptionInformation.integrityInformation.segments).to.have.lengthOf(5);
      expect(segmentsArrayBytes(five.manifest) - segmentsArrayBytes(four.manifest)).to.equal(
        perSegmentEntryBytes(alg)
      );
    });

    it(`a trailing partial ${alg} segment costs exactly finalSegmentEntryBytes`, async () => {
      const remainder = 17;
      const { manifest } = await writeTdf({
        plaintext: new Uint8Array(2 * segmentSize + remainder),
        segmentSize,
        segmentIntegrityAlgorithm: alg,
      });
      const { segments, encryptedSegmentSizeDefault } =
        manifest.encryptionInformation.integrityInformation;
      const last = segments[segments.length - 1];

      expect(segments).to.have.lengthOf(3);
      expect(last.segmentSize).to.equal(remainder);
      expect(encryptedSegmentSizeDefault).to.equal(segmentSize + 28);
      expect(new TextEncoder().encode(`${JSON.stringify(last)},`).length).to.equal(
        finalSegmentEntryBytes(alg, remainder, last.encryptedSegmentSize as number)
      );
    });

    it(`estimateSegmentsArrayBytes never under-estimates a real ${alg} manifest`, async () => {
      for (const sourceSize of [0, 1, 63, 64, 65, 127, 128, 200, 640]) {
        const { manifest } = await writeTdf({
          plaintext: new Uint8Array(sourceSize),
          segmentSize,
          segmentIntegrityAlgorithm: alg,
        });
        expect(
          estimateSegmentsArrayBytes({ sourceSize, segmentSize, alg }),
          `${sourceSize} bytes at ${alg}`
        ).to.be.at.least(segmentsArrayBytes(manifest));
      }
    });
  }
});
