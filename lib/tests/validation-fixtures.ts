import { ZipWriter } from '../tdf3/src/utils/zip-writer.js';
import { unsigned } from '../tdf3/src/utils/buffer-crc32.js';

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
