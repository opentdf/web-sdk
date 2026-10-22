import { expect } from 'chai';
import { validateTdf } from '../../../src/validation.js';
import { loadTDFStream } from '../../../tdf3/src/tdf.js';
import { fromBuffer } from '../../../src/seekable.js';
import { InvalidFileError } from '../../../src/errors.js';
import { ZipWriter } from '../../../tdf3/src/utils/zip-writer.js';
import { unsigned } from '../../../tdf3/src/utils/buffer-crc32.js';
import type { Manifest } from '../../../tdf3/src/models/manifest.js';

// Structural fixtures, not claims of cryptographic validity. The ciphertext is
// deliberately opaque: local validation must not need a key or contact KAS.
function manifest(size = 28): Manifest {
  return {
    payload: { type: 'reference', protocol: 'zip', url: '0.payload', isEncrypted: true },
    encryptionInformation: {
      type: 'split',
      policy: 'e30=',
      keyAccess: [{}] as Manifest['encryptionInformation']['keyAccess'],
      method: { algorithm: 'AES-256-GCM', isStreamable: true, iv: 'aXY=' },
      integrityInformation: {
        rootSignature: { alg: 'HS256', sig: 'c2ln' },
        segments: size ? [{ hash: 'aGFzaA==', encryptedSegmentSize: size }] : [],
      },
    },
    assertions: [],
  };
}

type Entry = { name: string; data: Uint8Array };
function archive(entries: Entry[], zip64 = true): Uint8Array {
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
const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
function entries(m = manifest(), name = '0.manifest.json', payload = new Uint8Array(28)): Entry[] {
  return [
    { name, data: json(m) },
    { name: '0.payload', data: payload },
  ];
}
async function rejects(bytes: Uint8Array, pattern: RegExp): Promise<void> {
  try {
    await validateTdf(bytes);
    expect.fail('Validation should reject malformed TDF');
  } catch (error) {
    expect(error).to.be.instanceOf(InvalidFileError);
    expect((error as Error).message).to.match(pattern);
  }
}

describe('validateTdf', () => {
  for (const zip64 of [false, true]) {
    for (const name of ['manifest.json', '0.manifest.json']) {
      it(`accepts stored ${zip64 ? 'ZIP64' : 'ZIP'} with ${name}`, async () => {
        const bytes = archive(entries(manifest(), name), zip64);
        expect(await validateTdf(bytes)).to.deep.equal(manifest());
        expect(await validateTdf(new Blob([new Uint8Array(bytes)]))).to.deep.equal(manifest());
      });
    }
  }
  it('demonstrates manifest-only inspection misses a missing payload', async () => {
    const bytes = archive(entries().slice(0, 1));
    expect((await loadTDFStream(fromBuffer(bytes))).manifest).to.deep.equal(manifest());
    await rejects(bytes, /payload entry/);
  });
  it('accepts an empty payload represented by zero encrypted segments', async () => {
    expect(
      await validateTdf(archive(entries(manifest(0), 'manifest.json', new Uint8Array())))
    ).to.deep.equal(manifest(0));
  });
  it('accepts an encrypted empty plaintext segment (IV plus authentication tag)', async () => {
    expect(await validateTdf(archive(entries(manifest(28))))).to.deep.equal(manifest(28));
  });
  it('reads payloads larger than one validation chunk', async () => {
    const size = 2 * 1024 * 1024 + 1;
    expect(
      await validateTdf(archive(entries(manifest(size), 'manifest.json', new Uint8Array(size))))
    ).to.deep.equal(manifest(size));
  });
  it('rejects a payload reference to a missing entry', async () => {
    const m = manifest();
    m.payload.url = 'missing';
    await rejects(archive(entries(m)), /payload entry/);
  });
  it('rejects a manifest referencing itself as payload', async () => {
    const m = manifest();
    m.payload.url = '0.manifest.json';
    await rejects(archive(entries(m)), /payload entry/);
  });
  for (const name of ['0.payload', '0.manifest.json']) {
    it(`rejects duplicate ${name}`, async () => {
      const files = entries();
      files.push(files.find((file) => file.name === name)!);
      await rejects(archive(files), /Duplicate/);
    });
  }
  for (const size of [0, 27, 29]) {
    it(`rejects payload length ${size} inconsistent with encrypted segments`, async () => {
      await rejects(
        archive(entries(manifest(), '0.manifest.json', new Uint8Array(size))),
        /segment sizes/
      );
    });
  }
  it('rejects a truncated archive', async () => {
    await rejects(archive(entries()).slice(0, -10), /central directory/);
  });
  it('rejects corruption in payload bytes despite a readable manifest', async () => {
    const bytes = archive(entries());
    const { centralDirectory } = await loadTDFStream(fromBuffer(bytes));
    const payload = centralDirectory.find((entry) => entry.fileName === '0.payload')!;
    bytes[payload.relativeOffsetOfLocalHeader + payload.headerLength] ^= 1;
    await rejects(bytes, /checksum/);
  });
  for (const kind of ['name', 'compression', 'ZIP encryption flag']) {
    it(`rejects a payload local header with inconsistent ${kind}`, async () => {
      const bytes = archive(entries());
      const { centralDirectory } = await loadTDFStream(fromBuffer(bytes));
      const payload = centralDirectory.find((entry) => entry.fileName === '0.payload')!;
      const start = payload.relativeOffsetOfLocalHeader;
      if (kind === 'name') bytes[start + 30] ^= 1;
      if (kind === 'compression') bytes[start + 8] = 8;
      if (kind === 'ZIP encryption flag') bytes[start + 6] |= 1;
      await rejects(bytes, /Inconsistent or encrypted ZIP entry/);
    });
  }
  it('rejects a manifest with a stale ZIP checksum even when JSON remains readable', async () => {
    const bytes = archive(entries());
    const { centralDirectory } = await loadTDFStream(fromBuffer(bytes));
    const entry = centralDirectory.find((entry) => entry.fileName === '0.manifest.json')!;
    const start = entry.relativeOffsetOfLocalHeader + entry.headerLength;
    // Change a policy character without changing the JSON shape or entry length.
    const text = new TextDecoder().decode(bytes.subarray(start, start + entry.compressedSize));
    bytes[start + text.indexOf('e30=')] = 'f'.charCodeAt(0);
    await rejects(bytes, /checksum/);
  });
  it('rejects missing encryption declarations', async () => {
    await rejects(archive(entries({ payload: manifest().payload } as Manifest)), /encryption/);
  });
  it('rejects missing integrity declarations', async () => {
    const m = manifest();
    Reflect.deleteProperty(m.encryptionInformation, 'integrityInformation');
    await rejects(archive(entries(m)), /integrity/);
  });
  it('rejects invalid segment sizes', async () => {
    const m = manifest();
    m.encryptionInformation.integrityInformation.segments = [
      { hash: 'hash', encryptedSegmentSize: -1 },
    ];
    await rejects(archive(entries(m)), /segment declaration/);
  });
});
