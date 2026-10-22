import { InvalidFileError } from './errors.js';
import { fromBuffer, fromBrowserFile } from './seekable.js';
import { loadTDFStream, manifestEntryName } from '../tdf3/src/tdf.js';
import type { Manifest } from '../tdf3/src/models/manifest.js';

/**
 * Validate a local encrypted ZIP TDF before storing or forwarding it.
 * Checks ZIP/ZIP64 bounds, unambiguous stored entries, payload references,
 * encrypted segment lengths, readable bytes, and ZIP CRCs. Payload buffers are
 * bounded; the manifest is decoded in memory. No KAS or network access occurs.
 * Returns the parsed manifest for metadata extraction.
 * This does not verify cryptographic signatures, decryptability, authorization,
 * or service-specific policy requirements. ZIP checksums are not authentication.
 * @example
 * ```ts
 * import { validateTdf } from '@opentdf/sdk';
 * const manifest = await validateTdf(new Uint8Array(await file.arrayBuffer()));
 * console.log(manifest.payload.mimeType);
 * ```
 * @throws InvalidFileError for unsupported or structurally inconsistent input.
 */
export async function validateTdf(source: Uint8Array | Blob): Promise<Manifest> {
  const { manifest, zipReader, centralDirectory } = await loadTDFStream(
    source instanceof Uint8Array ? fromBuffer(source) : fromBrowserFile(source)
  );
  const names = new Set<string>();
  const ranges = centralDirectory
    .map((entry) => {
      if (names.has(entry.fileName))
        throw new InvalidFileError(`Duplicate ZIP entry [${entry.fileName}]`);
      names.add(entry.fileName);
      return {
        start: entry.relativeOffsetOfLocalHeader,
        end: entry.relativeOffsetOfLocalHeader + entry.headerLength + entry.compressedSize,
      };
    })
    .sort((a, b) => a.start - b.start);
  for (let i = 1; i < ranges.length; i++) {
    if (ranges[i].start < ranges[i - 1].end) throw new InvalidFileError('Overlapping ZIP entries');
  }
  const { payload, encryptionInformation: encryption } = manifest;
  if (
    !payload ||
    payload.type !== 'reference' ||
    payload.protocol !== 'zip' ||
    payload.isEncrypted !== true ||
    typeof payload.url !== 'string' ||
    !payload.url
  ) {
    throw new InvalidFileError('Expected an encrypted ZIP payload reference');
  }
  const manifestName = manifestEntryName(centralDirectory);
  const payloadEntry = centralDirectory.find(({ fileName }) => fileName === payload.url);
  if (!payloadEntry || payload.url === manifestName) {
    throw new InvalidFileError('Missing or invalid referenced payload entry');
  }
  if (
    !encryption ||
    encryption.type !== 'split' ||
    typeof encryption.policy !== 'string' ||
    !encryption.policy ||
    !Array.isArray(encryption.keyAccess) ||
    !encryption.keyAccess.length ||
    encryption.method?.algorithm !== 'AES-256-GCM'
  ) {
    throw new InvalidFileError('Unsupported or missing TDF encryption declarations');
  }
  const integrity = encryption.integrityInformation;
  if (
    !integrity ||
    !Array.isArray(integrity.segments) ||
    !integrity.rootSignature ||
    typeof integrity.rootSignature.sig !== 'string' ||
    !integrity.rootSignature.sig
  ) {
    throw new InvalidFileError('Missing TDF segment integrity declarations');
  }
  const defaultSize = integrity.encryptedSegmentSizeDefault;
  if (defaultSize !== undefined && (!Number.isSafeInteger(defaultSize) || defaultSize < 0)) {
    throw new InvalidFileError('Invalid default encrypted segment size');
  }
  // Match the decrypt reader's legacy absent/zero default.
  const fallback = defaultSize || 1024 * 1024;
  let expectedSize = 0;
  for (const segment of integrity.segments) {
    const size = segment?.encryptedSegmentSize ?? fallback;
    if (
      !Number.isSafeInteger(size) ||
      size <= 0 ||
      typeof segment?.hash !== 'string' ||
      !segment.hash
    ) {
      throw new InvalidFileError('Invalid encrypted segment declaration');
    }
    expectedSize += size;
    if (!Number.isSafeInteger(expectedSize))
      throw new InvalidFileError('Encrypted payload size is not representable');
  }
  if (expectedSize !== payloadEntry.compressedSize) {
    throw new InvalidFileError('Encrypted segment sizes do not match the payload length');
  }
  await zipReader.validateEntry(
    centralDirectory.find(({ fileName }) => fileName === manifestName)!
  );
  await zipReader.validateEntry(payloadEntry);
  return manifest;
}
