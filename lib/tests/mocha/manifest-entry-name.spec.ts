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
 * Every fixture here is an archive this SDK wrote, rebuilt with its manifest
 * entry renamed, so what they pin is name resolution and nothing more. They are
 * this SDK's zip dialect throughout (zip64, data descriptors, STORE); an archive
 * from a producer with a different dialect exercises `parseCDBuffer` paths that
 * these tests do not reach.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { manifestEntryName } from '../../tdf3/src/tdf.js';
import { type CentralDirectory, ZipReader } from '../../tdf3/src/utils/zip-reader.js';
import { ZipWriter } from '../../tdf3/src/utils/zip-writer.js';
import { concatUint8 } from '../../tdf3/src/utils/index.js';
import { fromBuffer } from '../../src/seekable.js';
import { InvalidFileError } from '../../src/errors.js';
import { base64 } from '../../src/encodings/index.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000';

const authProvider: AuthProvider = {
  updateClientPublicKey: async () => {},
  withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
};

const plaintext = new TextEncoder().encode('the manifest is at the archive root');

/**
 * Spelled out rather than imported from `tdf.ts`. A suite written in terms of
 * the constants it is testing cannot notice them changing: repoint
 * `offspecManifestFileName` at the spec name and every assertion below follows
 * it, including the writer tripwire.
 */
const SPEC_NAME = 'manifest.json';
const OFFSPEC_NAME = '0.manifest.json';

/** What `writeStream` stamps on every entry it writes. */
const EXTERNAL_FILE_ATTRIBUTES = 2175008768;

/** Comfortably past the reader's 10 MiB manifest ceiling. */
const OVERSIZED = 1024 * 1024 * 128;

/**
 * A central-directory record with only the field `manifestEntryName` consults.
 * The cast hides CentralDirectory's other 16 fields, so if the resolver ever
 * starts reading one of them these fixtures will read `undefined` rather than
 * fail to compile — widen this helper at the same time.
 */
function entry(fileName: string): CentralDirectory {
  return { fileName } as CentralDirectory;
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
    keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
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

async function policyIdIn(buffer: Uint8Array, entryName: string): Promise<string> {
  const manifest = await new ZipReader(fromBuffer(buffer)).getManifest(
    await centralDirectoryOf(buffer),
    entryName
  );
  const policy: unknown = JSON.parse(atob(manifest.encryptionInformation.policy));
  if (
    !policy ||
    typeof policy !== 'object' ||
    !('uuid' in policy) ||
    typeof policy.uuid !== 'string'
  ) {
    throw new Error('fixture policy has no UUID');
  }
  assert.match(policy.uuid, /^[0-9a-f-]{36}$/);
  return policy.uuid;
}

async function assertRejects(promise: Promise<unknown>, messageFragment: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    assert.instanceOf(error, InvalidFileError);
    assert.include(error.message, messageFragment);
    return;
  }
  assert.fail(`Expected a rejection mentioning "${messageFragment}"`);
}

/**
 * `InvalidFileError` itself, not a subclass: `DecryptError`, `IntegrityError`
 * and `UnsafeUrlError` all extend it, so `instanceOf` would also accept a
 * failure from further down the read path.
 */
async function assertInvalidFile(promise: Promise<unknown>): Promise<void> {
  try {
    await promise;
  } catch (error) {
    const { constructor, message } = error as Error;
    assert.strictEqual(
      constructor,
      InvalidFileError,
      `Expected InvalidFileError, got ${constructor.name}: ${message}`
    );
    return;
  }
  assert.fail('Expected an InvalidFileError');
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
 * fixture built from an archive this SDK stops naming the way we expect fails
 * loudly instead of coming back subtly wrong. Whether a rename actually happened
 * is a separate question — when `newName` is already the writer's name this is a
 * pure rebuild — so each caller asserts the name it ended up with.
 */
async function renameManifestEntry(buffer: Uint8Array, newName: string): Promise<Uint8Array> {
  const entries = await entriesOf(buffer);
  const manifests = entries.filter(
    ({ fileName }) => fileName === SPEC_NAME || fileName === OFFSPEC_NAME
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
      assert.equal(manifestEntryName([entry('0.payload'), entry(SPEC_NAME)]), SPEC_NAME);
    });

    it('asks for the off-spec name when the spec name is absent', function () {
      assert.equal(manifestEntryName([entry('0.payload'), entry(OFFSPEC_NAME)]), OFFSPEC_NAME);
    });

    it('prefers the spec name when an archive carries both', function () {
      assert.equal(manifestEntryName([entry(OFFSPEC_NAME), entry(SPEC_NAME)]), SPEC_NAME);
    });

    it('asks for the off-spec name when the archive carries neither', function () {
      assert.equal(manifestEntryName([entry('0.payload')]), OFFSPEC_NAME);
    });
  });

  describe('writer', function () {
    it('still names the manifest entry 0.manifest.json', async function () {
      assert.deepEqual(await fileNamesOf(await encryptToBuffer(client)), [
        '0.payload',
        OFFSPEC_NAME,
      ]);
    });

    it('round-trips an archive it wrote', async function () {
      const buffer = await encryptToBuffer(client);
      const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
      assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
    });
  });

  for (const [named, entryName] of [
    ['spec', SPEC_NAME],
    ['off-spec', OFFSPEC_NAME],
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
          await policyIdIn(renamed, entryName)
        );
      });

      it('reads the policy id when getPolicyId is passed as a callback', async function () {
        // eslint-disable-next-line @typescript-eslint/unbound-method -- An unbound callback is the behavior under test.
        const getPolicyId = client.getPolicyId;
        assert.equal(
          await getPolicyId({ source: { type: 'buffer', location: renamed } }),
          await policyIdIn(renamed, entryName)
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
        await renameManifestEntry(await encryptToBuffer(client), OFFSPEC_NAME)
      );
      shadowed = buildArchive(entries, [
        {
          fileName: SPEC_NAME,
          sameDataAs: OFFSPEC_NAME,
          uncompressedSize: OVERSIZED,
        },
      ]);
    });

    it('is a fixture carrying both names, the off-spec one readable', async function () {
      assert.deepEqual(await fileNamesOf(shadowed), ['0.payload', OFFSPEC_NAME, SPEC_NAME]);
      const centralDirectory = await centralDirectoryOf(shadowed);
      const reader = new ZipReader(fromBuffer(shadowed));
      const manifest = await reader.getManifest(centralDirectory, OFFSPEC_NAME);
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

  /**
   * The spec name is selected on presence alone, so an entry holding something
   * other than a manifest now reaches the reader. Each fixture keeps its intact
   * `0.manifest.json`, so all of them decrypt on an off-spec-only reader —
   * what's under test is strictly the cost of widening the lookup.
   */
  describe('a spec-named entry that is not a TDF manifest', function () {
    const encode = (text: string) => new TextEncoder().encode(text);
    const notManifests: [string, Uint8Array][] = [
      ['a web app manifest', encode('{"name":"my-web-app","icons":[]}')],
      ['a manifest missing encryptionInformation', encode('{"payload":{"url":"0.payload"}}')],
      ['a JSON array', encode('[]')],
      ['JSON null', encode('null')],
      ['a JSON string', encode('"manifest"')],
      ['bytes that are not JSON', encode('hello')],
      ['a zero-length entry', new Uint8Array(0)],
    ];

    for (const [named, data] of notManifests) {
      describe(named, function () {
        let archive: Uint8Array;

        beforeEach(async function () {
          archive = buildArchive([
            ...(await entriesOf(await encryptToBuffer(client))),
            { fileName: SPEC_NAME, data, crc32: 0 },
          ]);
        });

        it('is a fixture whose off-spec manifest is still intact', async function () {
          assert.deepEqual(await fileNamesOf(archive), ['0.payload', OFFSPEC_NAME, SPEC_NAME]);
          const reader = new ZipReader(fromBuffer(archive));
          const manifest = await reader.getManifest(
            await centralDirectoryOf(archive),
            OFFSPEC_NAME
          );
          assert.isString(manifest.encryptionInformation.policy);
        });

        it('rejects the decrypt as an invalid file', async function () {
          await assertInvalidFile(
            client.decrypt({ source: { type: 'buffer', location: archive } })
          );
        });

        it('rejects getPolicyId as an invalid file', async function () {
          await assertInvalidFile(
            client.getPolicyId({ source: { type: 'buffer', location: archive } })
          );
        });
      });
    }
  });

  /**
   * Why the guard is thin. `getPolicyId` reads `encryptionInformation.policy`
   * and stops, so demanding the `keyAccess` or `integrityInformation` only
   * `decrypt` needs would turn this widening into a narrowing.
   */
  describe('a spec-named manifest carrying only what its caller reads', function () {
    const policyId = '4f8d09a3-6b21-4d0e-9f2c-71a5b3e8c604';
    let archive: Uint8Array;

    beforeEach(async function () {
      const policy = base64.encode(
        JSON.stringify({ uuid: policyId, body: { dataAttributes: [], dissem: [] } })
      );
      const payload = (await entriesOf(await encryptToBuffer(client))).find(
        ({ fileName }) => fileName === '0.payload'
      );
      assert.isDefined(payload, 'fixture needs the payload entry');
      archive = buildArchive([
        payload,
        {
          fileName: SPEC_NAME,
          data: new TextEncoder().encode(JSON.stringify({ encryptionInformation: { policy } })),
          crc32: 0,
        },
      ]);
    });

    it('reads the policy id rather than rejecting the manifest', async function () {
      assert.equal(
        await client.getPolicyId({ source: { type: 'buffer', location: archive } }),
        policyId
      );
    });
  });
});
