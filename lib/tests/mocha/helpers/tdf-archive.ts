import { type Manifest } from '../../../tdf3/src/models/manifest.js';
import { loadTDFStream } from '../../../tdf3/src/tdf.js';
import { concatUint8, ZipWriter } from '../../../tdf3/src/utils/index.js';
import { unsigned } from '../../../tdf3/src/utils/buffer-crc32.js';
import { type Chunker, fromBuffer } from '../../../src/seekable.js';

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

/**
 * A stretch of a sparse archive: real bytes, or a hole of the given length that
 * must never be read.
 */
export type SparsePiece = Uint8Array | number;

/**
 * Lay out a TDF whose payload may contain holes, and serve it through a
 * chunker. Holes let a test describe a payload far larger than it could
 * allocate (for example, more than 4 GiB) as long as the reader skips them.
 * Any read that touches a hole fails, and every read is recorded.
 */
export function sparseTdf(payload: SparsePiece[], manifest: unknown) {
  const zipWriter = new ZipWriter();
  const pieces: Array<{ start: number; piece: SparsePiece }> = [];
  let offset = 0;
  const push = (piece: SparsePiece) => {
    pieces.push({ start: offset, piece });
    offset += typeof piece === 'number' ? piece : piece.length;
  };

  const entries: Array<{ filename: string; content: SparsePiece[] }> = [
    { filename: '0.payload', content: payload },
    {
      filename: '0.manifest.json',
      content: [new TextEncoder().encode(JSON.stringify(manifest))],
    },
  ];
  const written = entries.map(({ filename, content }) => {
    const localHeaderOffset = offset;
    push(zipWriter.getLocalFileHeader(filename, 0, 0, 0));
    const contentStart = offset;
    content.forEach(push);
    const size = offset - contentStart;
    // The reader never checks CRCs, and a hole has no bytes to sum.
    push(zipWriter.writeDataDescriptor(0, size));
    return { filename, size, localHeaderOffset };
  });
  const centralDirectoryOffset = offset;
  for (const { filename, size, localHeaderOffset } of written) {
    push(
      zipWriter.writeCentralDirectoryRecord(
        size,
        filename,
        localHeaderOffset,
        0,
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
  const size = offset;

  const reads: Array<[number, number]> = [];
  const read = (byteStart: number, byteEnd: number) => {
    const start = byteStart < 0 ? size + byteStart : byteStart;
    const end = Math.min(byteEnd, size);
    reads.push([start, end]);
    const out = new Uint8Array(Math.max(end - start, 0));
    for (const { start: pieceStart, piece } of pieces) {
      const pieceEnd = pieceStart + (typeof piece === 'number' ? piece : piece.length);
      if (pieceEnd <= start || pieceStart >= end) {
        continue;
      }
      if (typeof piece === 'number') {
        throw new Error(`read [${start}, ${end}) touches a hole at [${pieceStart}, ${pieceEnd})`);
      }
      const from = Math.max(start, pieceStart);
      const to = Math.min(end, pieceEnd);
      out.set(piece.subarray(from - pieceStart, to - pieceStart), from - start);
    }
    return out;
  };
  const chunker: Chunker = (byteStart = 0, byteEnd = size) => {
    try {
      return Promise.resolve(read(byteStart, byteEnd));
    } catch (e) {
      return Promise.reject(e instanceof Error ? e : new Error(String(e)));
    }
  };
  return { chunker, reads, size };
}
