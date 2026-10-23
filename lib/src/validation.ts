import { ConfigurationError, InvalidFileError } from './errors.js';
import { type Chunker, fromBuffer, fromBrowserFile } from './seekable.js';
import { loadTDFStream } from '../tdf3/src/tdf.js';
import type * as ManifestValidation from './manifest-validation.js';

/**
 * The result of {@link validateTdf}. On failure, `reason` describes the first
 * problem found, for logs and diagnostics. Its wording may change between
 * releases, so do not match on it.
 */
export type TdfValidationResult = { valid: true } | { valid: false; reason: string };

/**
 * A TDF to validate: its bytes, a `Blob` (including a `File`), or a {@link Chunker}.
 */
export type TdfValidationSource = Uint8Array | Blob | Chunker;

/**
 * Checks whether `source` is a structurally valid TDF, and reports why when it is not.
 *
 * Opens the ZIP archive and reads the manifest entry: `manifest.json` if present,
 * otherwise `0.manifest.json`. The manifest must parse as a JSON object and pass
 * the lax manifest schema from the Go SDK (v0.35.0), extended with the experimental
 * `mlkem-wrapped` key access type. Only the end of the archive, its central
 * directory and the manifest are read, so a large source is never loaded whole. No
 * client is created and no KAS is contacted.
 *
 * This is not full parity with the Go SDK's `IsValidTdf`. The manifest entry names
 * and duplicate entry selection (the last record wins) match, and so does the schema
 * apart from `mlkem-wrapped`. Otherwise it differs in both directions:
 * - Laxer than Go: it accepts `mlkem-wrapped` key access, an archive with a ZIP
 *   comment, and manifest JSON nested deeper than Go's parser allows.
 * - Stricter than Go: it rejects trailing bytes or a second JSON value after the
 *   manifest, compressed entries, entries whose compressed and uncompressed sizes
 *   differ, and an end of central directory record that overstates the central
 *   directory size.
 *
 * It does not check that the payload exists, its length or checksums, cryptographic
 * integrity, decryptability, or any service-specific policy.
 *
 * @param source the TDF as bytes, as a `Blob` (including a `File`), or as a
 * {@link Chunker}. Blobs work in browsers and in Node. A chunker must support
 * negative offsets, which read from the end; `fromUrl` and `fromSource` return
 * suitable ones. Use one where a Blob would misreport the source: Node
 * reports the size of a file-backed Blob (`fs.openAsBlob`) modulo 2^32, so a TDF of
 * 4 GiB or more read that way is checked against the wrong bytes.
 * @returns `{ valid: true }`, or `{ valid: false, reason }` for an invalid archive
 * or manifest
 * @throws ConfigurationError if `source` is not a `Uint8Array`, a `Blob` or a function
 * @throws other errors, such as source read failures, unchanged; they do not
 * resolve as invalid
 */
export async function validateTdf(source: TdfValidationSource): Promise<TdfValidationResult> {
  const chunker = toChunker(source);
  let manifest: unknown;
  try {
    ({ manifest } = await loadTDFStream(chunker));
  } catch (error) {
    if (error instanceof InvalidFileError) {
      return { valid: false, reason: error.message };
    }
    throw error;
  }
  const { validateManifest } = await loadManifestValidator();
  return validateManifest(manifest);
}

/**
 * Checks whether `source` is a structurally valid TDF. This is {@link validateTdf}
 * without the reason; see it for what is and is not checked.
 *
 * @example
 * ```ts
 * import { isValidTdf } from '@opentdf/sdk';
 * // `file` is a File or Blob. Only the parts of it that are needed are read.
 * if (!(await isValidTdf(file))) {
 *   throw new Error('Invalid TDF');
 * }
 * ```
 * @returns true when validation passes, false for an invalid archive or manifest
 * @throws ConfigurationError if `source` is not a `Uint8Array`, a `Blob` or a function
 */
export async function isValidTdf(source: TdfValidationSource): Promise<boolean> {
  return (await validateTdf(source)).valid;
}

/**
 * Loads the schema validator. It is a dynamic import so that importing the SDK
 * root does not also load the schema and its JSON Schema library; only callers of
 * {@link validateTdf} pay for them. In a browser the import is a network fetch,
 * so a failure gets context here instead of surfacing as a bare "Failed to fetch
 * dynamically imported module".
 *
 * @param load the import to run; replaceable for tests
 * @internal
 */
export async function loadManifestValidator(
  load: () => Promise<typeof ManifestValidation> = () => import('./manifest-validation.js')
): Promise<typeof ManifestValidation> {
  try {
    return await load();
  } catch (cause) {
    throw new Error('validateTdf: failed to load the manifest validator', { cause });
  }
}

/**
 * Picks a reader for `source`. Anything else is rejected up front: read as a Blob,
 * a value such as a `number[]` or a string would resolve as invalid and hide the
 * caller's mistake.
 */
function toChunker(source: unknown): Chunker {
  if (source instanceof Uint8Array) {
    return fromBuffer(source);
  }
  if (isBlobLike(source)) {
    return fromBrowserFile(source);
  }
  if (typeof source === 'function') {
    return source as Chunker;
  }
  throw new ConfigurationError(
    `validateTdf: expected a Uint8Array, Blob or Chunker, not ${Object.prototype.toString.call(source)}`
  );
}

/**
 * Duck-typed, because `instanceof Blob` is false for a Blob from another realm,
 * such as an iframe, and for Blob implementations that do not extend the global
 * `Blob`. {@link fromBrowserFile} reads through `slice` and `arrayBuffer`.
 */
function isBlobLike(value: unknown): value is Blob {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const blob = value as Partial<Blob>;
  return (
    typeof blob.size === 'number' &&
    typeof blob.slice === 'function' &&
    typeof blob.arrayBuffer === 'function'
  );
}
