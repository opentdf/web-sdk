import {
  IntegrityError,
  UnsupportedFeatureError as UnsupportedError,
} from '../../../src/errors.js';

/**
 * Algorithms usable for *per-segment* integrity.
 *
 * `GMAC` is legitimate here: the segment's bytes were just processed by
 * AES-GCM under the DEK, so the trailing 16 bytes are the tag the AEAD itself
 * produced. See `segmentIntegrity`.
 */
export type SegmentIntegrityAlgorithm = 'GMAC' | 'HS256';

/**
 * Algorithms usable for the *root* signature.
 *
 * Deliberately narrower than {@link SegmentIntegrityAlgorithm}: AES-GCM never
 * processes the aggregate hash, so there is no tag to extract and `GMAC` would
 * degenerate into copying the last segment hash — a keyless, forgeable value.
 * The type carries the invariant so a root algorithm cannot even be *typed* as
 * `'GMAC'`. See `rootIntegrity`.
 */
export type RootIntegrityAlgorithm = 'HS256';

/**
 * @deprecated Prefer {@link SegmentIntegrityAlgorithm} or
 * {@link RootIntegrityAlgorithm}, which say which position they are valid in.
 */
export type IntegrityAlgorithm = SegmentIntegrityAlgorithm;

/** The only root integrity algorithm this SDK reads or writes. */
export const ROOT_INTEGRITY_ALGORITHM: RootIntegrityAlgorithm = 'HS256';

/** Default per-segment integrity algorithm. */
export const SEGMENT_INTEGRITY_ALGORITHM: SegmentIntegrityAlgorithm = 'GMAC';

/**
 * Case-insensitive test for a supported segment integrity algorithm.
 * An explicit allowlist, so unknown algorithms are rejected rather than
 * silently defaulted.
 */
export function isSegmentIntegrityAlgorithm(alg: unknown): alg is SegmentIntegrityAlgorithm {
  return typeof alg === 'string' && ['GMAC', 'HS256'].includes(alg.toUpperCase());
}

/**
 * Case-insensitive test for a supported root integrity algorithm.
 * `GMAC` in *any* casing is not a member: the JS reader historically compared
 * exactly (`!== 'GMAC'`), so `"gmac"` took a different path than in the Go and
 * Java SDKs. Normalizing first closes that gap.
 */
export function isRootIntegrityAlgorithm(alg: unknown): alg is RootIntegrityAlgorithm {
  return typeof alg === 'string' && alg.toUpperCase() === ROOT_INTEGRITY_ALGORITHM;
}

/**
 * Normalize a manifest-declared segment algorithm, rejecting anything unknown.
 */
export function asSegmentIntegrityAlgorithm(alg: unknown): SegmentIntegrityAlgorithm {
  if (!isSegmentIntegrityAlgorithm(alg)) {
    throw new UnsupportedError(`Unsupported segment hash alg [${alg}]`);
  }
  return alg.toUpperCase() as SegmentIntegrityAlgorithm;
}

/**
 * Normalize a manifest-declared root algorithm, failing *closed*.
 *
 * A ZTDF's `rootSignature.alg` is unauthenticated manifest data. Accepting
 * `GMAC` there lets a keyless attacker downgrade an HS256-rooted file and then
 * truncate, reorder, duplicate or drop segments undetected, so reject it (and
 * every unknown algorithm) instead of coercing to HS256 — coercion would
 * validate a forged file against the wrong algorithm and mask the downgrade.
 */
export function asRootIntegrityAlgorithm(alg: unknown): RootIntegrityAlgorithm {
  if (!isRootIntegrityAlgorithm(alg)) {
    throw new IntegrityError(
      `unsupported root integrity algorithm [${alg}]; only [${ROOT_INTEGRITY_ALGORITHM}] is supported`
    );
  }
  return ROOT_INTEGRITY_ALGORITHM;
}
