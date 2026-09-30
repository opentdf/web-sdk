import { type Assertion } from '../assertions.js';
import { type Payload } from './payload.js';
import { type EncryptionInformation } from './encryption-information.js';

export type Manifest = {
  payload: Payload;
  encryptionInformation: EncryptionInformation;
  assertions: Assertion[];
  // Required in later versions, optional prior to 4.3.0
  schemaVersion?: string;
  // Deprecated
  tdf_spec_version?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Whether `value` could be a manifest. The entry is resolved by name, so it may
 * hold anything; without this the first dereference throws a `TypeError` from
 * outside the `TdfError` hierarchy.
 *
 * Intentionally weaker than `Manifest`: it rejects only what every caller would
 * crash on, since `getPolicyId` needs just `encryptionInformation.policy` and
 * demanding more would narrow a reader we just widened. Says nothing about
 * authenticity — that is the root signature's job, later.
 */
export function isManifest(value: unknown): value is Manifest {
  return isRecord(value) && isRecord(value.encryptionInformation);
}
