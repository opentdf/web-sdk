import { type Assertion } from '../assertions.js';
import { type Payload } from './payload.js';
import { type EncryptionInformation } from './encryption-information.js';

export type Manifest = {
  payload: Payload;
  encryptionInformation: EncryptionInformation;
  assertions: Assertion[];
  // Required in later versions, optional prior to 4.3.0
  schemaVersion?: string;
  // Non-aligned name for schemaVersion, found in archival files. Read by
  // resolveSpecVersion; never written.
  tdf_spec_version?: string;
};

/**
 * The TDF spec version a manifest records, or `undefined` if it records none.
 *
 * Precedence is `schemaVersion`, then `tdf_spec_version` at the root, then
 * `tdf_spec_version` under `payload`. Only non-empty strings count; any other
 * value (the key is known in the wild carrying `null`) is skipped rather than
 * treated as an error, since reporting malformed manifests is not this
 * function's job.
 *
 * `schemaVersion` is the canonical name. `tdf_spec_version` is not a former
 * spelling that was renamed; it entered some specification drafts and older
 * documentation in error, and writers built from them emitted it. Both of its
 * placements are probed because both occur in archival files. The root is
 * where the spec's own manifest.md has always documented the field, and where
 * this SDK wrote it (until #414 switched the writer to `schemaVersion`) and has
 * read it since. Under `payload` is where revisions of the JSON schema
 * declared it in error, which led at least one writer to emit the key there
 * with a `null` value. Nothing is ever written under the non-aligned name: the
 * writer emits `schemaVersion` only.
 *
 * The reader uses the result to choose how the integrity digests are encoded:
 * hex before 4.3.0, raw bytes since. A manifest that records no version is read
 * as 4.2.2.
 *
 * Mirrors the Go SDK's `Manifest.UnmarshalJSON` (opentdf/platform#4060).
 */
export function resolveSpecVersion(manifest: unknown): string | undefined {
  if (!isObject(manifest)) {
    return undefined;
  }
  const payload = isObject(manifest.payload) ? manifest.payload : {};
  for (const candidate of [
    manifest.schemaVersion,
    manifest.tdf_spec_version,
    payload.tdf_spec_version,
  ]) {
    if (typeof candidate === 'string' && candidate !== '') {
      return candidate;
    }
  }
  return undefined;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
