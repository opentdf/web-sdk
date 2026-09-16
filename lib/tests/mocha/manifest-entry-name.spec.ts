/**
 * opentdf/platform#3513 — what the manifest entry inside a TDF archive is called.
 *
 * The spec says `manifest.json` at the archive root; this SDK writes and, until
 * now, only read `0.manifest.json`. The `0.` prefix is a holdover from an early
 * design that allowed several payload/manifest pairs per archive and never
 * shipped.
 *
 * This change is read-only: the reader accepts either name, preferring the spec
 * one. The writer still emits `0.manifest.json` — renaming it is a breaking
 * file-format change tracked separately.
 *
 * Both fixtures here are archives this SDK wrote, rebuilt with the manifest
 * entry renamed, so what they pin is name resolution and nothing more. They are
 * this SDK's zip dialect throughout (zip64, data descriptors, STORE); an archive
 * from a producer with a different dialect exercises `parseCDBuffer` paths that
 * these tests do not reach.
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

/** What `writeStream` stamps on every entry it writes. */
const EXTERNAL_FILE_ATTRIBUTES = 2175008768;

/** Comfortably past the reader's 10 MiB manifest ceiling. */
const OVERSIZED = 1024 * 1024 * 128;

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

async function fileNamesOf(buffer: Uint8Array): Promise<string[]> {
  return (await centralDirectoryOf(buffer)).map(({ fileName }) => fileName);
}

async function assertRejects(promise: Promise<unknown>, messageFragment: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    assert.instanceOf(error, InvalidFileError);
    assert.include((error as Error).message, messageFragment);
    return;
  }
  assert.fail(`Expected a rejection mentioning "${messageFragment}"`);
}

type ArchiveEntry = { fileName: string; data: Uint8Array; crc32: number };

/**
 * A central-directory record with no data of its own: it names `fileName` but
 * points at the local header of `sameDataAs` and reports `uncompressedSize`
 * rather than that entry's real size. Lets a fixture claim a second name for the
 * manifest without disturbing the entry that name shadows.
 */
type AliasRecord = { fileName: string; sameDataAs: string; uncompressedSize: number };

/** Every entry of `buffer`, as name plus stored bytes. */
async function entriesOf(buffer: Uint8Array): Promise<ArchiveEntry[]> {
  return (await centralDirectoryOf(buffer)).map((cd) => {
    const dataStart = cd.relativeOffsetOfLocalHeader + cd.headerLength;
    return {
      fileName: cd.fileName,
      // The writer only ever STOREs, so the stored bytes are the file itself.
      data: buffer.slice(dataStart, dataStart + cd.compressedSize),
      crc32: cd.crc32,
    };
  });
}

/**
 * Write `entries` back out as an archive, plus a central-directory record for
 * each alias. Entry names differ in length, so the local headers, the central
 * directory offsets and the EOCDR all have to be rebuilt rather than patched.
 */
function buildArchive(entries: ArchiveEntry[], aliases: AliasRecord[] = []): Uint8Array {
  const zipWriter = new ZipWriter();
  const parts: Uint8Array[] = [];
  const offsets: Record<string, number> = {};
  let offset = 0;

  for (const { fileName, data, crc32 } of entries) {
    const chunks = [
      zipWriter.getLocalFileHeader(fileName, 0, 0, 0),
      data,
      zipWriter.writeDataDescriptor(crc32, data.length),
    ];
    offsets[fileName] = offset;
    parts.push(...chunks);
    offset += chunks.reduce((total, { length }) => total + length, 0);
  }

  const records = [
    ...entries.map(({ fileName, data, crc32 }) => ({
      fileName,
      uncompressedSize: data.length,
      localHeaderOffset: offsets[fileName],
      crc32,
    })),
    ...aliases.map(({ fileName, sameDataAs, uncompressedSize }) => {
      const aliased = entries.find((e) => e.fileName === sameDataAs);
      if (!aliased) {
        throw new Error(`buildArchive: no entry named ${sameDataAs} to alias`);
      }
      return {
        fileName,
        uncompressedSize,
        localHeaderOffset: offsets[sameDataAs],
        crc32: aliased.crc32,
      };
    }),
  ];

  const centralDirectoryOffset = offset;
  for (const { fileName, uncompressedSize, localHeaderOffset, crc32 } of records) {
    const record = zipWriter.writeCentralDirectoryRecord(
      uncompressedSize,
      fileName,
      localHeaderOffset,
      crc32,
      EXTERNAL_FILE_ATTRIBUTES
    );
    parts.push(record);
    offset += record.length;
  }
  parts.push(
    zipWriter.writeEndOfCentralDirectoryRecord(
      records.length,
      offset - centralDirectoryOffset,
      centralDirectoryOffset
    )
  );

  return concatUint8(parts);
}

/**
 * Rebuild `buffer` with its manifest entry named `newName` and every entry's
 * bytes preserved. Throws unless exactly one entry looked like a manifest, so a
 * fixture can never quietly come back unrenamed — including once the writer
 * switches to the spec name.
 */
async function renameManifestEntry(buffer: Uint8Array, newName: string): Promise<Uint8Array> {
  const entries = await entriesOf(buffer);
  const manifests = entries.filter(
    ({ fileName }) => fileName === manifestFileName || fileName === offspecManifestFileName
  );
  if (manifests.length !== 1) {
    throw new Error(`renameManifestEntry: expected one manifest entry, found ${manifests.length}`);
  }
  return buildArchive(entries.map((e) => (e === manifests[0] ? { ...e, fileName: newName } : e)));
}

describe('manifest entry name (platform#3513)', function () {
  let client: Client.Client;

  beforeEach(function () {
    client = newClient();
  });

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

  describe('writer', function () {
    it('still names the manifest entry 0.manifest.json', async function () {
      assert.deepEqual(await fileNamesOf(await encryptToBuffer(client)), [
        '0.payload',
        offspecManifestFileName,
      ]);
    });

    it('round-trips an archive it wrote', async function () {
      const buffer = await encryptToBuffer(client);
      const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
      assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
    });
  });

  for (const [named, entryName] of [
    ['spec', manifestFileName],
    ['off-spec', offspecManifestFileName],
  ] as const) {
    describe(`${named}-named archives`, function () {
      let original: Uint8Array;
      let renamed: Uint8Array;

      beforeEach(async function () {
        original = await encryptToBuffer(client);
        renamed = await renameManifestEntry(original, entryName);
      });

      it(`is a fixture that really uses the ${named} name`, async function () {
        assert.deepEqual(await fileNamesOf(renamed), ['0.payload', entryName]);
      });

      it('decrypts', async function () {
        const stream = await client.decrypt({ source: { type: 'buffer', location: renamed } });
        assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
      });

      it('reads the policy id', async function () {
        assert.equal(
          await client.getPolicyId({ source: { type: 'buffer', location: renamed } }),
          await client.getPolicyId({ source: { type: 'buffer', location: original } })
        );
      });
    });
  }

  /**
   * Resolving the name against the central directory, rather than retrying the
   * spec name's failure under the off-spec one, is what keeps these honest: a
   * `try { spec } catch { off-spec }` reader would serve the valid off-spec
   * manifest here and swallow the size error entirely.
   */
  describe('an oversized spec-named entry shadowing a valid off-spec one', function () {
    let shadowed: Uint8Array;

    beforeEach(async function () {
      const entries = await entriesOf(
        await renameManifestEntry(await encryptToBuffer(client), offspecManifestFileName)
      );
      shadowed = buildArchive(entries, [
        {
          fileName: manifestFileName,
          sameDataAs: offspecManifestFileName,
          uncompressedSize: OVERSIZED,
        },
      ]);
    });

    it('is a fixture carrying both names, the off-spec one readable', async function () {
      assert.deepEqual(await fileNamesOf(shadowed), [
        '0.payload',
        offspecManifestFileName,
        manifestFileName,
      ]);
      const centralDirectory = await centralDirectoryOf(shadowed);
      const reader = new ZipReader(fromBuffer(shadowed));
      const manifest = await reader.getManifest(centralDirectory, offspecManifestFileName);
      assert.isString(manifest.encryptionInformation.policy);
    });

    it('fails the decrypt on size rather than falling back', async function () {
      await assertRejects(
        client.decrypt({ source: { type: 'buffer', location: shadowed } }),
        'too large'
      );
    });

    it('fails getPolicyId on size rather than falling back', async function () {
      await assertRejects(
        client.getPolicyId({ source: { type: 'buffer', location: shadowed } }),
        'too large'
      );
    });
  });

  describe('archives with no manifest entry under either name', function () {
    it('reports a missing manifest', async function () {
      const nameless = await renameManifestEntry(await encryptToBuffer(client), 'not-a-manifest');
      await assertRejects(
        client.decrypt({ source: { type: 'buffer', location: nameless } }),
        'Unable to retrieve CD manifest'
      );
    });
  });
});
