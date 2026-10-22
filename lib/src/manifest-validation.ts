import { Validator } from '@cfworker/json-schema';
import manifestSchema from './manifest-lax.schema.js';

// Loaded on first validation, so other root API consumers do not load the schema.
const validator = new Validator(manifestSchema, '2020-12');

/** Check the lax schema without claiming the complete Manifest TypeScript shape. */
export function validateManifest(manifest: unknown): boolean {
  return validator.validate(manifest).valid;
}
