import { ZipWriter } from '../tdf3/src/utils/zip-writer.js';
import { unsigned } from '../tdf3/src/utils/buffer-crc32.js';
import manifestCases from './mocks/validation/manifest-cases.js';

type Entry = { name: string; data: Uint8Array };
export function archive(entries: Entry[], zip64 = true): Uint8Array {
  const writer = new ZipWriter();
  writer.zip64 = zip64;
  const body: Uint8Array[] = [];
  const records: Uint8Array[] = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const crc = unsigned(data, 0);
    const header = writer.getLocalFileHeader(name, crc, data.length, data.length);
    const descriptor = writer.writeDataDescriptor(crc, data.length);
    body.push(header, data, descriptor);
    records.push(writer.writeCentralDirectoryRecord(data.length, name, offset, crc, 0));
    offset += header.length + data.length + descriptor.length;
  }
  const directory = concat(records);
  return concat([
    ...body,
    directory,
    writer.writeEndOfCentralDirectoryRecord(entries.length, directory.length, offset),
  ]);
}
function concat(chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, chunk) => n + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Duplicate-manifest archives exported byte-for-byte to the Go verifier. */
export function archiveParityCases(): {
  name: string;
  bytes: Uint8Array;
  valid: boolean;
  expected?: unknown;
}[] {
  const good = manifestCases[0].manifest;
  const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  return ['manifest.json', '0.manifest.json'].flatMap((name) =>
    [false, true].map((validLast) => ({
      name: `duplicate ${name}: ${validLast ? 'valid' : 'invalid'} last entry wins`,
      bytes: archive([
        { name, data: encode(validLast ? {} : good) },
        { name, data: encode(validLast ? good : {}) },
      ]),
      valid: validLast,
      expected: validLast ? good : undefined,
    }))
  );
}
