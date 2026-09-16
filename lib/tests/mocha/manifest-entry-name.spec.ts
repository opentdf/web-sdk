/**
 * opentdf/platform#3513 — what the manifest entry inside a TDF archive is called.
 *
 * The spec says `manifest.json` at the archive root; this SDK writes and, until
 * now, only read `0.manifest.json`. The `0.` prefix is a holdover from an early
 * design that allowed several payload/manifest pairs per archive and never
 * shipped.
 *
 * This change is read-only: the reader accepts either name, preferring the spec
 * one, so archives from spec-conforming implementations open. The writer still
 * emits `0.manifest.json` — renaming it is a breaking file-format change tracked
 * separately.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import {
  offspecManifestFileName,
  manifestEntryName,
  manifestFileName,
} from '../../tdf3/src/tdf.js';
import { type CentralDirectory, ZipReader } from '../../tdf3/src/utils/zip-reader.js';
import { ZipWriter } from '../../tdf3/src/utils/zip-writer.js';
import { concatUint8 } from '../../tdf3/src/utils/index.js';
import { fromBuffer } from '../../src/seekable.js';
import { InvalidFileError } from '../../src/errors.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000';

const authProvider: AuthProvider = {
  updateClientPublicKey: async () => {},
  withCreds: async (httpReq: HttpRequest) => httpReq,
};

const plaintext = new TextEncoder().encode('the manifest is at the archive root');

function entry(fileName: string, overrides: Partial<CentralDirectory> = {}): CentralDirectory {
  return { fileName, ...overrides } as CentralDirectory;
}

function newClient(): Client.Client {
  return new Client.Client({
    kasEndpoint: kasUrl,
    platformUrl: kasUrl,
    dpopKeys: Mocks.entityKeyPair(),
    clientId: 'id',
    authProvider,
  });
}

async function encryptToBuffer(client: Client.Client): Promise<Uint8Array> {
  const encryptionInformation = new SplitKey(new AesGcmCipher(WebCryptoService));
  const key = await encryptionInformation.generateKey();
  const stream = await client.encrypt({
    metadata: Mocks.getMetadataObject(),
    offline: true,
    scope: { dissem: ['user@domain.com'], attributes: [] },
    keyMiddleware: async () => ({ keyForEncryption: key, keyForManifest: key }),
    source: new ReadableStream({
      start(controller) {
        controller.enqueue(plaintext);
        controller.close();
      },
    }),
  });
  return new Uint8Array(await stream.toBuffer());
}

async function centralDirectoryOf(buffer: Uint8Array): Promise<CentralDirectory[]> {
  return new ZipReader(fromBuffer(buffer)).getCentralDirectory();
}

/**
 * Rebuild `buffer` with every entry's bytes preserved and the manifest entry
 * renamed. Entry names differ in length, so the local headers, the central
 * directory offsets and the EOCDR all have to be rewritten rather than patched.
 */
async function renameManifestEntry(buffer: Uint8Array, newName: string): Promise<Uint8Array> {
  const zipWriter = new ZipWriter();
  const parts: Uint8Array[] = [];
  const written: { fileName: string; offset: number; crc32: number; size: number }[] = [];
  let offset = 0;

  for (const cd of await centralDirectoryOf(buffer)) {
    const fileName = cd.fileName === offspecManifestFileName ? newName : cd.fileName;
    const dataStart = cd.relativeOffsetOfLocalHeader + cd.headerLength;
    const chunks = [
      zipWriter.getLocalFileHeader(fileName, 0, 0, 0),
      buffer.slice(dataStart, dataStart + cd.uncompressedSize),
      zipWriter.writeDataDescriptor(cd.crc32, cd.uncompressedSize),
    ];
    written.push({ fileName, offset, crc32: cd.crc32, size: cd.uncompressedSize });
    parts.push(...chunks);
    offset += chunks.reduce((total, { length }) => total + length, 0);
  }

  const centralDirectoryOffset = offset;
  for (const { fileName, offset: localHeaderOffset, crc32, size } of written) {
    const record = zipWriter.writeCentralDirectoryRecord(
      size,
      fileName,
      localHeaderOffset,
      crc32,
      2175008768
    );
    parts.push(record);
    offset += record.length;
  }
  parts.push(
    zipWriter.writeEndOfCentralDirectoryRecord(
      written.length,
      offset - centralDirectoryOffset,
      centralDirectoryOffset
    )
  );

  return concatUint8(parts);
}

describe('manifest entry name (platform#3513)', function () {
  describe('manifestEntryName', function () {
    it('asks for the spec name when the archive carries it', function () {
      assert.equal(
        manifestEntryName([entry('0.payload'), entry(manifestFileName)]),
        manifestFileName
      );
    });

    it('asks for the off-spec name when the spec name is absent', function () {
      assert.equal(
        manifestEntryName([entry('0.payload'), entry(offspecManifestFileName)]),
        offspecManifestFileName
      );
    });

    it('prefers the spec name when an archive carries both', function () {
      assert.equal(
        manifestEntryName([entry(offspecManifestFileName), entry(manifestFileName)]),
        manifestFileName
      );
    });

    it('asks for the off-spec name when the archive carries neither', function () {
      assert.equal(manifestEntryName([entry('0.payload')]), offspecManifestFileName);
    });
  });

  describe('reader', function () {
    it('reports an oversized spec-named manifest instead of falling back', async function () {
      const reader = new ZipReader(async () => new Uint8Array([]));
      const centralDirectory = [
        entry(offspecManifestFileName, {
          relativeOffsetOfLocalHeader: 0,
          headerLength: 1024,
          uncompressedSize: 16,
        }),
        entry(manifestFileName, {
          relativeOffsetOfLocalHeader: 2048,
          headerLength: 1024,
          uncompressedSize: 1024 * 1024 * 128,
        }),
      ];
      try {
        await reader.getManifest(centralDirectory, manifestEntryName(centralDirectory));
        assert.fail('Expected the oversized manifest to be rejected');
      } catch (error) {
        assert.instanceOf(error, InvalidFileError);
        assert.include((error as Error).message, 'too large');
      }
    });
  });

  describe('writer', function () {
    let client: Client.Client;

    beforeEach(function () {
      client = newClient();
    });

    it('still names the manifest entry 0.manifest.json', async function () {
      const centralDirectory = await centralDirectoryOf(await encryptToBuffer(client));
      assert.deepEqual(
        centralDirectory.map(({ fileName }) => fileName),
        ['0.payload', offspecManifestFileName]
      );
    });

    it('round-trips an archive it wrote', async function () {
      const buffer = await encryptToBuffer(client);
      const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
      assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
    });
  });

  describe('spec-named archives', function () {
    let client: Client.Client;
    let specNamed: Uint8Array;

    beforeEach(async function () {
      client = newClient();
      specNamed = await renameManifestEntry(await encryptToBuffer(client), manifestFileName);
    });

    it('is a fixture that really uses the spec name', async function () {
      assert.deepEqual(
        (await centralDirectoryOf(specNamed)).map(({ fileName }) => fileName),
        ['0.payload', manifestFileName]
      );
    });

    it('decrypts an archive whose manifest entry uses the spec name', async function () {
      const stream = await client.decrypt({ source: { type: 'buffer', location: specNamed } });
      assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
    });

    it('reads the policy id from an archive using the spec name', async function () {
      const policyId = await client.getPolicyId({
        source: { type: 'buffer', location: specNamed },
      });
      assert.isString(policyId);
    });
  });
});
