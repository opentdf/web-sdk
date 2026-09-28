import { ConfigurationError } from '../../../src/errors.js';
import { MAX_GCM_INVOCATIONS_PER_KEY } from '../ciphers/gcm-iv-counter.js';
import type { IntegrityAlgorithm } from '../tdf.js';

/**
 * Size arithmetic for very large TDFs, kept separate from the code that moves
 * bytes. Whether a manifest will fit, how big a payload may be, what segment
 * size to pick and how much to prefetch are all pure functions of sizes -- none
 * of them need a single byte of payload. Keeping them here means the behaviour
 * at 50 TiB is reachable in a unit test instead of only by encrypting 50 TiB.
 *
 * @see `spec/DSPX-4648-web-sdk-large-files.md`
 */

/** 50 TiB, the current S3 maximum object size and the target this module is sized against. */
export const FIFTY_TEBIBYTES = 50 * 2 ** 40;

/** Digest length, in bytes, of a per-segment integrity value. */
const SEGMENT_DIGEST_BYTES: Record<IntegrityAlgorithm, number> = {
  // The GCM auth tag the cipher already computed.
  GMAC: 16,
  // A separate HMAC-SHA256 pass over the segment ciphertext.
  HS256: 32,
};

/**
 * Serialized cost of a segment entry excluding its hash, i.e. `{"hash":""}`
 * plus the comma that separates it from the next entry.
 */
const SEGMENT_ENTRY_OVERHEAD_BYTES = '{"hash":""},'.length;

/**
 * The trailing partial segment is the only one whose size differs from the
 * default, so it is the only one that serializes these two extra fields
 * (`lib/tdf3/src/tdf.ts`, `_encryptAndCountSegment`).
 */
const FINAL_SEGMENT_SIZE_KEY_BYTES = ',"segmentSize":'.length;
const FINAL_ENCRYPTED_SEGMENT_SIZE_KEY_BYTES = ',"encryptedSegmentSize":'.length;

/** Length of the base64 encoding of `byteLength` bytes, including padding. */
export function base64Length(byteLength: number): number {
  return 4 * Math.ceil(byteLength / 3);
}

/**
 * Bytes a single full-size `segments` entry adds to the serialized manifest.
 *
 * This is the constant every size in `spec/DSPX-4648-web-sdk-large-files.md` is
 * derived from: 36 bytes for GMAC, 56 for HS256. HS256 is the conservative case
 * and is what the limits here are sized against, whichever default is in force.
 */
export function perSegmentEntryBytes(alg: IntegrityAlgorithm): number {
  const digestBytes = SEGMENT_DIGEST_BYTES[alg];
  if (!digestBytes) {
    throw new ConfigurationError(`Unsupported segment integrity alg [${alg}]`);
  }
  return SEGMENT_ENTRY_OVERHEAD_BYTES + base64Length(digestBytes);
}

/**
 * Bytes the trailing partial segment adds. It carries explicit `segmentSize`
 * and `encryptedSegmentSize` fields because it is shorter than the default, so
 * it costs meaningfully more than {@link perSegmentEntryBytes}.
 */
export function finalSegmentEntryBytes(
  alg: IntegrityAlgorithm,
  segmentSize: number,
  encryptedSegmentSize: number
): number {
  return (
    perSegmentEntryBytes(alg) +
    FINAL_SEGMENT_SIZE_KEY_BYTES +
    `${segmentSize}`.length +
    FINAL_ENCRYPTED_SEGMENT_SIZE_KEY_BYTES +
    `${encryptedSegmentSize}`.length
  );
}

/** AES-GCM prepends a 12 byte IV and appends a 16 byte auth tag. */
const GCM_SEGMENT_OVERHEAD_BYTES = 28;

/** How many segments a source of `sourceSize` bytes produces at `segmentSize`. */
export function segmentCountFor(sourceSize: number, segmentSize: number): number {
  assertPositiveInteger(segmentSize, 'segmentSize');
  return Math.ceil(sourceSize / segmentSize);
}

/**
 * Serialized size of the manifest's `segments` array, brackets included.
 *
 * Deliberately an over-estimate: every entry is counted with its separating
 * comma even though the last one has none, which pays for the closing bracket
 * with a byte to spare. Under-estimating here would let a doomed encrypt start.
 */
export function estimateSegmentsArrayBytes({
  sourceSize,
  segmentSize,
  alg,
  encryptedSegmentOverhead = GCM_SEGMENT_OVERHEAD_BYTES,
}: {
  sourceSize: number;
  segmentSize: number;
  alg: IntegrityAlgorithm;
  encryptedSegmentOverhead?: number;
}): number {
  const brackets = '[]'.length;
  const segments = segmentCountFor(sourceSize, segmentSize);
  if (segments === 0) {
    return brackets;
  }

  const remainder = sourceSize % segmentSize;
  if (remainder === 0) {
    return brackets + segments * perSegmentEntryBytes(alg);
  }
  return (
    brackets +
    (segments - 1) * perSegmentEntryBytes(alg) +
    finalSegmentEntryBytes(alg, remainder, remainder + encryptedSegmentOverhead)
  );
}

/**
 * Upper bound on the serialized manifest for a source of known length.
 *
 * `baseManifestBytes` is the rest of the manifest -- policy, key access,
 * payload, schema version -- which callers can measure exactly by stringifying
 * the manifest they already built. `assertionBytes` cannot be known before the
 * assertions are signed, so it is an input rather than something estimated
 * here; that is why the end-of-stream check in `writeStream` has to stay as a
 * backstop even once this runs up front.
 */
export function estimateManifestBytes({
  sourceSize,
  segmentSize,
  alg,
  baseManifestBytes = 0,
  assertionBytes = 0,
  encryptedSegmentOverhead,
}: {
  sourceSize: number;
  segmentSize: number;
  alg: IntegrityAlgorithm;
  baseManifestBytes?: number;
  assertionBytes?: number;
  encryptedSegmentOverhead?: number;
}): number {
  return (
    baseManifestBytes +
    assertionBytes +
    estimateSegmentsArrayBytes({ sourceSize, segmentSize, alg, encryptedSegmentOverhead })
  );
}

/**
 * The smallest segment size a source of `sourceSize` bytes may use without
 * exhausting the AES-GCM per-key invocation ceiling that `GcmIvCounter`
 * enforces. At 50 TiB this is 12,800 bytes, orders of magnitude below every
 * segment size we would actually choose -- but it is the floor any future
 * change to the default has to stay above.
 */
export function minSegmentSizeFor(sourceSize: number): number {
  return Math.ceil(sourceSize / MAX_GCM_INVOCATIONS_PER_KEY);
}

function assertPositiveInteger(value: number, name: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new ConfigurationError(`${name} must be a positive integer; got [${value}]`);
  }
}
