import { Validator } from '@cfworker/json-schema';
import { InvalidFileError } from './errors.js';
import { fromBuffer, fromBrowserFile } from './seekable.js';
import { loadTDFStream } from '../tdf3/src/tdf.js';
import manifestSchema from './manifest-lax.schema.js';
import type { Manifest } from '../tdf3/src/models/manifest.js';

const validator = new Validator(manifestSchema, '2020-12');

/**
 * Validate an existing TDF using the Go SDK IsValidTdf validation rules.
 * Opens the archive, reads its manifest, and applies the same lax manifest schema.
 * Returns the parsed manifest; no authenticated client or KAS access is needed.
 * This does not validate the payload, verify cryptographic integrity,
 * establish decryptability, or enforce service-specific policy requirements.
 * @example
 * ```ts
 * import { validateTdf } from '@opentdf/sdk';
 * const manifest = await validateTdf(new Uint8Array(await file.arrayBuffer()));
 * console.log(manifest.payload.mimeType);
 * ```
 * @throws InvalidFileError if the archive or manifest cannot be read, or the
 * manifest does not satisfy the lax schema.
 */
export async function validateTdf(source: Uint8Array | Blob): Promise<Manifest> {
  const { manifest } = await loadTDFStream(
    source instanceof Uint8Array ? fromBuffer(source) : fromBrowserFile(source)
  );
  if (!validator.validate(manifest).valid) {
    throw new InvalidFileError('TDF manifest does not satisfy the lax schema');
  }
  return manifest;
}
