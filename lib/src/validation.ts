import { InvalidFileError } from './errors.js';
import { fromBuffer, fromBrowserFile } from './seekable.js';
import { loadTDFStream } from '../tdf3/src/tdf.js';

/**
 * Check an existing TDF using the Go SDK IsValidTdf validation rules.
 * Opens the archive, reads its manifest, and applies the lax manifest schema.
 * Supports experimental mlkem-wrapped key access.
 * Returns false for an invalid archive or manifest and true when validation passes.
 * No client or KAS access is needed. Unexpected errors, including source read
 * failures, propagate to the caller.
 * This does not validate the payload, verify cryptographic integrity,
 * establish decryptability, or enforce service-specific policy requirements.
 * @example
 * ```ts
 * import { isValidTdf } from '@opentdf/sdk';
 * if (!(await isValidTdf(new Uint8Array(await file.arrayBuffer())))) {
 *   throw new Error('Invalid TDF');
 * }
 * ```
 */
export async function isValidTdf(source: Uint8Array | Blob): Promise<boolean> {
  try {
    const { manifest } = await loadTDFStream(
      source instanceof Uint8Array ? fromBuffer(source) : fromBrowserFile(source)
    );
    const { validateManifest } = await import('./manifest-validation.js');
    return validateManifest(manifest);
  } catch (error) {
    if (error instanceof InvalidFileError) return false;
    throw error;
  }
}
