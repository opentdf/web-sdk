import { open } from 'node:fs/promises';

/**
 * One stored archive entry. An entry with `data` has those bytes written; an entry
 * with only a `size` is left as a hole of that many zero bytes.
 */
export type FixtureEntry = { name: string } & ({ data: Uint8Array } | { size: number });

const view = (bytes: Uint8Array) => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

/**
 * Writes a minimal ZIP64 archive of stored entries to `path` and returns its size.
 * The layout is the one the SDK writes: local headers and data, the central
 * directory, a ZIP64 end of central directory record and locator, and an end of
 * central directory record whose fields all point at the ZIP64 record. CRCs are
 * zero, which `validate` does not check.
 *
 * Holes are never written, so a multi-gigabyte archive takes a few KiB on
 * filesystems with sparse files (APFS, ext4).
 *
 * Give the last entry at least 8 bytes of data. The SDK reads each local header
 * at the length the central directory implies, which here is 8 bytes longer than
 * the local header (the central directory's ZIP64 field also holds the offset),
 * and rejects a read that runs into the central directory.
 */
export async function writeZip64(path: string, entries: FixtureEntry[]): Promise<number> {
  const pieces: { at: number; bytes: Uint8Array }[] = [];
  const records: Uint8Array[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = new TextEncoder().encode(entry.name);
    const size = BigInt('data' in entry ? entry.data.length : entry.size);

    // Local file header (APPNOTE 4.3.7) with a ZIP64 extra field for both sizes.
    const header = new Uint8Array(30 + name.length + 20);
    const h = view(header);
    h.setUint32(0, 0x04034b50, true);
    h.setUint16(4, 45, true); // version needed to extract: ZIP64
    h.setUint32(18, 0xffffffff, true); // compressed size, in the extra field
    h.setUint32(22, 0xffffffff, true); // uncompressed size, in the extra field
    h.setUint16(26, name.length, true);
    h.setUint16(28, 20, true);
    header.set(name, 30);
    h.setUint16(30 + name.length, 0x0001, true);
    h.setUint16(32 + name.length, 16, true);
    h.setBigUint64(34 + name.length, size, true);
    h.setBigUint64(42 + name.length, size, true);
    pieces.push({ at: offset, bytes: header });
    if ('data' in entry) {
      pieces.push({ at: offset + header.length, bytes: entry.data });
    }

    // Central directory header (APPNOTE 4.3.12) with a ZIP64 extra field for
    // both sizes and the local header offset.
    const record = new Uint8Array(46 + name.length + 28);
    const r = view(record);
    r.setUint32(0, 0x02014b50, true);
    r.setUint16(4, 45, true); // version made by
    r.setUint16(6, 45, true); // version needed to extract
    r.setUint32(20, 0xffffffff, true);
    r.setUint32(24, 0xffffffff, true);
    r.setUint16(28, name.length, true);
    r.setUint16(30, 28, true);
    r.setUint32(42, 0xffffffff, true);
    record.set(name, 46);
    r.setUint16(46 + name.length, 0x0001, true);
    r.setUint16(48 + name.length, 24, true);
    r.setBigUint64(50 + name.length, size, true);
    r.setBigUint64(58 + name.length, size, true);
    r.setBigUint64(66 + name.length, BigInt(offset), true);
    records.push(record);

    offset += header.length + Number(size);
  }

  const directoryOffset = offset;
  for (const record of records) {
    pieces.push({ at: offset, bytes: record });
    offset += record.length;
  }
  const directorySize = offset - directoryOffset;

  const trailer = new Uint8Array(56 + 20 + 22);
  const t = view(trailer);
  // ZIP64 end of central directory record (APPNOTE 4.3.14)
  t.setUint32(0, 0x06064b50, true);
  t.setBigUint64(4, 44n, true); // size of the rest of this record
  t.setUint16(12, 45, true);
  t.setUint16(14, 45, true);
  t.setBigUint64(24, BigInt(entries.length), true);
  t.setBigUint64(32, BigInt(entries.length), true);
  t.setBigUint64(40, BigInt(directorySize), true);
  t.setBigUint64(48, BigInt(directoryOffset), true);
  // ZIP64 end of central directory locator (APPNOTE 4.3.15)
  t.setUint32(56, 0x07064b50, true);
  t.setBigUint64(64, BigInt(offset), true);
  t.setUint32(72, 1, true);
  // End of central directory record (APPNOTE 4.3.16), every field a sentinel
  t.setUint32(76, 0x06054b50, true);
  t.setUint16(84, 0xffff, true);
  t.setUint16(86, 0xffff, true);
  t.setUint32(88, 0xffffffff, true);
  t.setUint32(92, 0xffffffff, true);
  pieces.push({ at: offset, bytes: trailer });
  offset += trailer.length;

  const file = await open(path, 'w');
  try {
    await file.truncate(offset);
    for (const { at, bytes } of pieces) {
      await file.write(bytes, 0, bytes.length, at);
    }
  } finally {
    await file.close();
  }
  return offset;
}
