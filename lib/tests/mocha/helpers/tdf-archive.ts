import { type Manifest } from '../../../tdf3/src/models/manifest.js';
import { loadTDFStream } from '../../../tdf3/src/tdf.js';
import { concatUint8, ZipWriter } from '../../../tdf3/src/utils/index.js';
import { unsigned } from '../../../tdf3/src/utils/buffer-crc32.js';
import { fromBuffer } from '../../../src/seekable.js';

const EXTERNAL_FILE_ATTRIBUTES = 2175008768;

/** The two pieces of a TDF that a keyless edit can change. */
export type TdfParts = { payload: Uint8Array; manifest: Manifest };

/** Split a TDF into its payload bytes and its parsed manifest. */
export async function unpackTdf(buffer: Uint8Array): Promise<TdfParts> {
  const { manifest, zipReader, centralDirectory } = await loadTDFStream(fromBuffer(buffer));
  const info = manifest.encryptionInformation.integrityInformation;
  const payloadSize = info.segments.reduce(
    (total, { encryptedSegmentSize }) =>
      total + (encryptedSegmentSize ?? info.encryptedSegmentSizeDefault ?? 0),
    0
  );
  const payload = await zipReader.getPayloadSegment(centralDirectory, '0.payload', 0, payloadSize);
  return { payload, manifest };
}

/**
 * Reassemble a TDF from payload bytes and a manifest, mirroring the layout
 * `writeStream` emits (stored entries with trailing data descriptors). No key
 * material is involved.
 */
export function packTdf(payload: Uint8Array, manifest: unknown): Uint8Array {
  const zipWriter = new ZipWriter();
  const entries = [
    { filename: '0.payload', content: payload },
    { filename: '0.manifest.json', content: new TextEncoder().encode(JSON.stringify(manifest)) },
  ];

  const parts: Uint8Array[] = [];
  let offset = 0;
  const push = (chunk: Uint8Array) => {
    parts.push(chunk);
    offset += chunk.length;
  };

  const written = entries.map(({ filename, content }) => {
    const localHeaderOffset = offset;
    push(zipWriter.getLocalFileHeader(filename, 0, 0, 0));
    push(content);
    const crc = unsigned(content, 0);
    push(zipWriter.writeDataDescriptor(crc, content.length));
    return { filename, size: content.length, localHeaderOffset, crc };
  });

  const centralDirectoryOffset = offset;
  for (const { filename, size, localHeaderOffset, crc } of written) {
    push(
      zipWriter.writeCentralDirectoryRecord(
        size,
        filename,
        localHeaderOffset,
        crc,
        EXTERNAL_FILE_ATTRIBUTES
      )
    );
  }
  push(
    zipWriter.writeEndOfCentralDirectoryRecord(
      written.length,
      offset - centralDirectoryOffset,
      centralDirectoryOffset
    )
  );
  return concatUint8(parts);
}
