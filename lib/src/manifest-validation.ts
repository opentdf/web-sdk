import { Validator, type OutputUnit } from '@cfworker/json-schema';
import manifestSchema from './manifest-lax.schema.js';
import type { TdfValidationResult } from './validation.js';

const validator = new Validator(manifestSchema, '2020-12');

/**
 * Checks the lax schema without claiming the complete Manifest TypeScript shape.
 * On failure, the reason names the most specific schema error.
 */
export function validateManifest(manifest: unknown): TdfValidationResult {
  const { valid, errors } = validator.validate(manifest);
  if (valid) {
    return { valid: true };
  }
  return { valid: false, reason: `manifest does not match the lax schema: ${describe(errors)}` };
}

/**
 * The validator reports a failure as a chain of errors from the root down to the
 * failing keyword. The deepest instance location is the most useful; on a tie,
 * the first error wins.
 */
function describe(errors: OutputUnit[]): string {
  const deepest = errors.reduce<OutputUnit | undefined>(
    (best, unit) =>
      !best || unit.instanceLocation.length > best.instanceLocation.length ? unit : best,
    undefined
  );
  return deepest ? `${deepest.instanceLocation}: ${deepest.error}` : 'unknown schema error';
}
