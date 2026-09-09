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

/** Digest length, in bytes, a segment integrity value occupies before base64. */
export function segmentDigestBytes(alg: IntegrityAlgorithm): number {
  const digestBytes = SEGMENT_DIGEST_BYTES[alg];
  if (!digestBytes) {
    throw new ConfigurationError(`Unsupported segment integrity alg [${alg}]`);
  }
  return digestBytes;
}

/**
 * Bytes a single full-size `segments` entry adds to the serialized manifest.
 *
 * This is the constant every size in `spec/DSPX-4648-web-sdk-large-files.md` is
 * derived from: 36 bytes for GMAC, 56 for HS256. HS256 is the conservative case
 * and is what the limits here are sized against, whichever default is in force.
 */
export function perSegmentEntryBytes(alg: IntegrityAlgorithm): number {
  return SEGMENT_ENTRY_OVERHEAD_BYTES + base64Length(segmentDigestBytes(alg));
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
 * Ceiling on the serialized manifest, shared by the read and write paths so a
 * TDF can never be written successfully and then turn out to be unreadable.
 *
 * 256 MiB. Sized so 50 TiB fits at 16 MiB segments with HS256 segment
 * integrity -- ~184 MB of `segments`, about 28% headroom -- while staying small
 * enough that the read path's one-shot `JSON.parse` is still viable. A 184 MB
 * manifest is roughly 3.3M objects and 300-400 MB of transient V8 heap to
 * parse; that is affordable, and a streaming JSON parser is not needed. If this
 * is ever raised past ~512 MiB, that decision has to be revisited.
 */
export const DEFAULT_MANIFEST_MAX_SIZE = 256 * 2 ** 20;

/**
 * Segment sizes {@link chooseSegmentSize} will pick from, smallest first.
 *
 * Larger segments buy a smaller manifest and pay for it three ways: seek
 * granularity on decrypt, the blast radius of a failed integrity check (AES-GCM
 * verification is all-or-nothing per segment, so one bad byte costs a whole
 * segment re-fetch), and per-segment memory -- which is what bounds the
 * prefetch window on the read side. The ladder stops at 256 MiB because beyond
 * that a single segment is too much to hold in a browser tab.
 */
export const SEGMENT_SIZE_LADDER: readonly number[] = [1, 4, 16, 64, 256].map(
  (mib) => mib * 2 ** 20
);

/**
 * Share of the manifest budget the `segments` array is allowed to claim. The
 * rest is headroom for policy, key access, and assertions, whose size is not
 * known when the segment size has to be chosen.
 */
const SEGMENT_ARRAY_BUDGET_FRACTION = 0.8;

/**
 * Smallest ladder segment size whose `segments` array fits the manifest budget.
 *
 * Small inputs keep the historical 1 MiB default, so ordinary files are
 * unaffected; the size only climbs when the manifest would otherwise not fit.
 * If nothing on the ladder is enough the largest rung is returned rather than
 * throwing -- the caller's up-front budget check then rejects with a message
 * that names the real numbers, which is more useful than an error from here.
 */
export function chooseSegmentSize({
  sourceSize,
  alg,
  manifestMaxSize = DEFAULT_MANIFEST_MAX_SIZE,
  ladder = SEGMENT_SIZE_LADDER,
}: {
  sourceSize: number;
  alg: IntegrityAlgorithm;
  manifestMaxSize?: number;
  ladder?: readonly number[];
}): number {
  const budget = manifestMaxSize * SEGMENT_ARRAY_BUDGET_FRACTION;
  for (const segmentSize of ladder) {
    if (estimateSegmentsArrayBytes({ sourceSize, segmentSize, alg }) <= budget) {
      return segmentSize;
    }
  }
  return ladder[ladder.length - 1];
}

/**
 * Payload segments a single key may encrypt.
 *
 * One fewer than {@link MAX_GCM_INVOCATIONS_PER_KEY}: `GcmIvCounter` reserves
 * invocation 0 for the encrypted metadata and refuses to issue invocation
 * `limit` itself, so the usable payload invocations are `1..limit-1`. Using the
 * invocation ceiling directly would over-count by one and let a payload sized
 * exactly at the boundary fail mid-stream.
 */
export const MAX_PAYLOAD_SEGMENTS_PER_KEY = MAX_GCM_INVOCATIONS_PER_KEY - 1;

/**
 * The smallest segment size a source of `sourceSize` bytes may use without
 * exhausting the AES-GCM per-key invocation ceiling that `GcmIvCounter`
 * enforces. At 50 TiB this is 12,801 bytes, orders of magnitude below every
 * segment size we would actually choose -- but it is the floor any future
 * change to the default has to stay above.
 */
export function minSegmentSizeFor(sourceSize: number): number {
  return Math.ceil(sourceSize / MAX_PAYLOAD_SEGMENTS_PER_KEY);
}

/**
 * Most segments a single TDF may carry: the tighter of the AES-GCM per-key
 * invocation ceiling and what the manifest budget can describe.
 *
 * At the recommended configuration (256 MiB cap, HS256 at 56 B/entry) the
 * manifest binds at 4,793,490 segments; the IV ceiling of ~4.29e9 is nowhere
 * near. It only becomes the binding constraint for very small segments.
 */
export function maxSegmentsFor({
  alg,
  manifestMaxSize = DEFAULT_MANIFEST_MAX_SIZE,
}: {
  alg: IntegrityAlgorithm;
  manifestMaxSize?: number;
}): number {
  return Math.min(
    MAX_PAYLOAD_SEGMENTS_PER_KEY,
    Math.floor(manifestMaxSize / perSegmentEntryBytes(alg))
  );
}

/**
 * Largest payload, in plaintext bytes, that can be encrypted under one key at
 * this configuration.
 *
 * This is the ceiling that replaces the hardcoded 64 GB `GLOBAL_BYTE_LIMIT`. It
 * is *derived* rather than picked: both terms are real limits the format
 * imposes, so raising the manifest cap or the segment size raises this in step
 * instead of requiring a second arbitrary number to be revised alongside.
 *
 * At 16 MiB segments with a 256 MiB cap it is ~80.4 TB under HS256 and ~125 TB
 * under GMAC, both comfortably past the 50 TiB target.
 */
export function maxEncryptableBytes({
  segmentSize,
  alg,
  manifestMaxSize = DEFAULT_MANIFEST_MAX_SIZE,
}: {
  segmentSize: number;
  alg: IntegrityAlgorithm;
  manifestMaxSize?: number;
}): number {
  assertPositiveInteger(segmentSize, 'segmentSize');
  return segmentSize * maxSegmentsFor({ alg, manifestMaxSize });
}

/**
 * Largest ZIP output the same configuration can produce.
 *
 * Distinct from {@link maxEncryptableBytes} because `byteLimit` is checked
 * against `totalByteCount`, the bytes written out, not the bytes read in: every
 * segment gains a 12 byte IV and a 16 byte tag, and the container also carries
 * the manifest and the zip records. Comparing a plaintext ceiling against an
 * output counter would reject payloads that actually fit.
 */
export function maxOutputBytes({
  segmentSize,
  alg,
  manifestMaxSize = DEFAULT_MANIFEST_MAX_SIZE,
  encryptedSegmentOverhead = GCM_SEGMENT_OVERHEAD_BYTES,
}: {
  segmentSize: number;
  alg: IntegrityAlgorithm;
  manifestMaxSize?: number;
  encryptedSegmentOverhead?: number;
}): number {
  const segments = maxSegmentsFor({ alg, manifestMaxSize });
  return (
    segments * (segmentSize + encryptedSegmentOverhead) + manifestMaxSize + ZIP_CONTAINER_OVERHEAD
  );
}

/**
 * Slack for the zip64 local headers, data descriptors, central directory and
 * EOCD records around the two entries a TDF contains. A few hundred bytes in
 * practice; 64 KiB is generous and the number it pads is measured in terabytes.
 */
const ZIP_CONTAINER_OVERHEAD = 64 * 1024;

function assertPositiveInteger(value: number, name: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new ConfigurationError(`${name} must be a positive integer; got [${value}]`);
  }
}
