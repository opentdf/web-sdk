import { type Assertion } from '../assertions.js';
import { type Payload } from './payload.js';
import { type EncryptionInformation } from './encryption-information.js';
import { asOptionalString, asRecord, type Unvalidated } from '../../../src/json.js';
import { asRootIntegrityAlgorithm, asSegmentIntegrityAlgorithm } from './integrity-algorithms.js';

export type Manifest = {
  payload: Payload;
  encryptionInformation: EncryptionInformation;
  assertions: Assertion[];
  // Required in later versions, optional prior to 4.3.0
  schemaVersion?: string;
  // Deprecated
  tdf_spec_version?: string;
};

/**
 * Prove the parts of a manifest that the reader makes decisions from, and
 * return it as a `Manifest`.
 *
 * This is the only gate between {@link Unvalidated}`<Manifest>` — whatever
 * `JSON.parse` produced from a file we did not write — and `Manifest`.
 * Inspection paths deliberately stay on the unvalidated type so that a forged
 * file is still dumpable; the decrypt path calls this first.
 */
export function asManifest(m: Unvalidated<Manifest>): Manifest {
  const ei = asRecord(m.encryptionInformation, 'manifest.encryptionInformation');
  const ii = asRecord(
    ei.integrityInformation,
    'manifest.encryptionInformation.integrityInformation'
  );
  const rs = asRecord(
    ii.rootSignature,
    'manifest.encryptionInformation.integrityInformation.rootSignature'
  );

  // `rootSignature.alg` is unauthenticated manifest data and it selects a
  // verification routine. Reject GMAC (in any casing) and every unknown value
  // here: a GMAC "root signature" is just a copy of the last segment hash, so
  // honouring it would let a keyless attacker truncate, reorder, duplicate or
  // drop segments undetected. Fail closed rather than coerce — coercing would
  // validate a forged file against the wrong algorithm and mask the downgrade.
  const alg = asRootIntegrityAlgorithm(rs.alg);

  // Absent, null, or empty means "use the root algorithm", matching the
  // `segmentHashAlg || rootIntegrityAlgorithm` fallback this replaces.
  const rawSegmentHashAlg = ii.segmentHashAlg;
  const segmentHashAlg =
    rawSegmentHashAlg === undefined || rawSegmentHashAlg === null || rawSegmentHashAlg === ''
      ? undefined
      : asSegmentIntegrityAlgorithm(rawSegmentHashAlg);

  // The spec version selects the legacy 4.2.2 *encoding* for the root
  // signature, segment hashes and assertion signatures. Those branches change
  // encoding, not strength — all of them still HMAC under the DEK — so a
  // flipped version yields a mismatch, not a forgery. Require a string anyway,
  // so the `=== '4.2.2'` comparisons compare two strings rather than silently
  // taking the modern path on an object.
  //
  // Deliberately not an allowlist: any value other than '4.2.2' takes the
  // modern path, so a future '4.4.0' file stays readable. Closing the set
  // would trade a real forward-compatibility regression for nothing.
  const schemaVersion = asOptionalString(m.schemaVersion, 'manifest.schemaVersion');
  const tdf_spec_version = asOptionalString(m.tdf_spec_version, 'manifest.tdf_spec_version');

  // Everything else is still an unproven assertion, exactly as it was before
  // this gate existed: payload, method, policy, keyAccess, segments,
  // assertions. Only the fields the reader branches on are checked here.
  const checked = m as Manifest;
  return {
    ...checked,
    schemaVersion,
    tdf_spec_version,
    encryptionInformation: {
      ...checked.encryptionInformation,
      integrityInformation: {
        ...checked.encryptionInformation.integrityInformation,
        rootSignature: {
          ...checked.encryptionInformation.integrityInformation.rootSignature,
          alg,
        },
        segmentHashAlg,
      },
    },
  };
}
