/**
 * The TDF spec version in the manifest, and what the reader does with it.
 *
 * `schemaVersion` at the manifest root is the canonical name. Archival files
 * also carry the version under the non-aligned name `tdf_spec_version`, both
 * at the root and under `payload`, so the reader looks in all three places.
 *
 * None of those decide how the integrity digests are encoded, though. The
 * field is unauthenticated, and it only ever tracked the encoding because this
 * SDK's writer sets both from one setting. The reader recomputes each digest
 * and accepts either spelling a writer has used for it: base64 of the raw
 * bytes (4.3.0 and later) or base64 of their hex (earlier). These tests pin
 * that a file decrypts whatever its version label says, and that tampering is
 * still caught either way.
 *
 * Mirrors opentdf/platform#4060.
 */
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { type EncryptParams } from '../../tdf3/src/client/builders.js';
import { type Manifest } from '../../tdf3/src/models/manifest.js';
import { base64 } from '../../src/encodings/index.js';
import { IntegrityError } from '../../src/errors.js';
import { packTdf, unpackTdf, type TdfParts } from './helpers/tdf-archive.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000';

const authProvider: AuthProvider = {
  updateClientPublicKey: async () => {},
  withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
};

const SEGMENT_SIZE = 1024;
const SEGMENT_COUNT = 3;

function segmentedPlaintext(count = SEGMENT_COUNT): Uint8Array {
  const out = new Uint8Array(count * SEGMENT_SIZE);
  for (let i = 0; i < count; i++) {
    out.fill('A'.charCodeAt(0) + i, i * SEGMENT_SIZE, (i + 1) * SEGMENT_SIZE);
  }
  return out;
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

type EncryptOverrides = Omit<Partial<EncryptParams>, 'source' | 'keyMiddleware'>;

/** Raw-digest files: the default writer, 4.3.0 and later. */
const RAW: EncryptOverrides = {};
/** Hex-digest files: what the writer emits when asked for 4.2.2. */
const HEX: EncryptOverrides = { tdfSpecVersion: '4.2.2' };

async function encryptToBuffer(
  client: Client.Client,
  plaintext: Uint8Array,
  overrides: EncryptOverrides
): Promise<{ buffer: Uint8Array; manifest: Manifest }> {
  const encryptionInformation = new SplitKey(new AesGcmCipher(WebCryptoService));
  const key = await encryptionInformation.generateKey();
  const stream = await client.encrypt({
    metadata: Mocks.getMetadataObject(),
    offline: true,
    scope: { dissem: ['user@domain.com'], attributes: [] },
    windowSize: SEGMENT_SIZE,
    // Exercise the assertion signature too: it is the third digest whose
    // encoding used to follow the spec version.
    systemMetadataAssertion: true,
    keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
    source: new ReadableStream({
      start(controller) {
        controller.enqueue(plaintext);
        controller.close();
      },
    }),
    ...overrides,
  });
  const buffer = await stream.toBuffer();
  return { buffer, manifest: stream.manifest };
}

async function decryptBuffer(client: Client.Client, buffer: Uint8Array): Promise<Uint8Array> {
  const stream = await client.decrypt({ source: { type: 'buffer', location: buffer } });
  return new Uint8Array(await stream.toBuffer());
}

/** Encrypt, apply a keyless edit to the archive, and decrypt the result. */
async function editAndDecrypt(
  client: Client.Client,
  plaintext: Uint8Array,
  overrides: EncryptOverrides,
  edit: (parts: TdfParts) => void
): Promise<Uint8Array> {
  const { buffer } = await encryptToBuffer(client, plaintext, overrides);
  const parts = await unpackTdf(buffer);
  edit(parts);
  return decryptBuffer(client, packTdf(parts.payload, parts.manifest));
}

type Placement = 'schemaVersion' | 'root tdf_spec_version' | 'payload tdf_spec_version';

/**
 * Remove the spec version from every place it can occur, then, if a placement
 * is given, write `value` there. Values are `unknown` because real files carry
 * `null` and a reader must not choke on other types either.
 */
function relabel(manifest: Manifest, placement?: Placement, value?: unknown) {
  const root = manifest as unknown as Record<string, unknown>;
  const payload = manifest.payload as unknown as Record<string, unknown>;
  delete root.schemaVersion;
  delete root.tdf_spec_version;
  delete payload.tdf_spec_version;
  switch (placement) {
    case 'schemaVersion':
      root.schemaVersion = value;
      break;
    case 'root tdf_spec_version':
      root.tdf_spec_version = value;
      break;
    case 'payload tdf_spec_version':
      payload.tdf_spec_version = value;
      break;
  }
}

function flipFirstByteOfBase64(value: string): string {
  const decoded = new Uint8Array(base64.decodeArrayBuffer(value));
  decoded[0] ^= 0x01;
  return base64.encodeArrayBuffer(decoded);
}

/** The keyless edits every file must still reject, whatever its label. */
const TAMPERS: Record<string, (parts: TdfParts) => void> = {
  'an edited segment hash': ({ manifest }) => {
    const info = manifest.encryptionInformation.integrityInformation;
    info.segments[1] = { ...info.segments[1], hash: flipFirstByteOfBase64(info.segments[1].hash) };
  },
  'an edited root signature': ({ manifest }) => {
    const { rootSignature } = manifest.encryptionInformation.integrityInformation;
    rootSignature.sig = flipFirstByteOfBase64(rootSignature.sig);
  },
  'a flipped ciphertext byte': (parts) => {
    const segmentSize =
      parts.manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault ?? 0;
    const flipped = parts.payload.slice();
    flipped[segmentSize - 1] ^= 0xff;
    parts.payload = flipped;
  },
};

async function expectIntegrityError(promise: Promise<unknown>, why: string) {
  try {
    await promise;
    assert.fail(`expected an IntegrityError: ${why}`);
  } catch (e) {
    assert.instanceOf(e, IntegrityError, why);
  }
}

describe('TDF spec version in the manifest', function () {
  const plaintext = segmentedPlaintext();
  let client: Client.Client;

  beforeEach(function () {
    client = newClient();
  });

  describe('writer', function () {
    it('emits schemaVersion at the root, and never tdf_spec_version', async function () {
      const { buffer } = await encryptToBuffer(client, plaintext, RAW);
      const { manifest } = await unpackTdf(buffer);
      const root = manifest as unknown as Record<string, unknown>;
      assert.equal(root.schemaVersion, '4.3.0');
      assert.notProperty(root, 'tdf_spec_version');
      assert.notProperty(manifest.payload, 'tdf_spec_version');
    });

    it('emits no version under either name for a 4.2.2 file', async function () {
      const { buffer } = await encryptToBuffer(client, plaintext, HEX);
      const { manifest } = await unpackTdf(buffer);
      const root = manifest as unknown as Record<string, unknown>;
      assert.notProperty(root, 'schemaVersion');
      assert.notProperty(root, 'tdf_spec_version');
      assert.notProperty(manifest.payload, 'tdf_spec_version');
    });
  });

  describe('raw-digest (4.3.0) files', function () {
    for (const placement of [
      'schemaVersion',
      'root tdf_spec_version',
      'payload tdf_spec_version',
    ] as const) {
      it(`decrypts with the version only in ${placement}`, async function () {
        const got = await editAndDecrypt(client, plaintext, RAW, ({ manifest }) =>
          relabel(manifest, placement, '4.3.0')
        );
        assert.deepEqual(got, plaintext);
      });
    }

    it('decrypts with no version at all', async function () {
      const got = await editAndDecrypt(client, plaintext, RAW, ({ manifest }) => relabel(manifest));
      assert.deepEqual(got, plaintext);
    });

    it('decrypts when mislabelled 4.2.2', async function () {
      const got = await editAndDecrypt(client, plaintext, RAW, ({ manifest }) =>
        relabel(manifest, 'schemaVersion', '4.2.2')
      );
      assert.deepEqual(got, plaintext);
    });

    for (const placement of ['root tdf_spec_version', 'payload tdf_spec_version'] as const) {
      for (const [label, value] of [
        ['null', null],
        ['a number', 430],
        ['an object', { major: 4 }],
        ['an array', ['4.3.0']],
        ['empty', ''],
      ] as const) {
        it(`skips ${label} in ${placement} without throwing`, async function () {
          const got = await editAndDecrypt(client, plaintext, RAW, ({ manifest }) =>
            relabel(manifest, placement, value)
          );
          assert.deepEqual(got, plaintext);
        });
      }
    }

    for (const [name, tamper] of Object.entries(TAMPERS)) {
      it(`rejects ${name}`, async function () {
        await expectIntegrityError(
          editAndDecrypt(client, plaintext, RAW, tamper),
          `${name} must be caught`
        );
      });
    }
  });

  describe('hex-digest (pre-4.3.0) files', function () {
    it('decrypts with no version', async function () {
      const { buffer } = await encryptToBuffer(client, plaintext, HEX);
      assert.deepEqual(await decryptBuffer(client, buffer), plaintext);
    });

    for (const placement of [
      'schemaVersion',
      'root tdf_spec_version',
      'payload tdf_spec_version',
    ] as const) {
      it(`decrypts when ${placement} claims 4.3.0`, async function () {
        const got = await editAndDecrypt(client, plaintext, HEX, ({ manifest }) =>
          relabel(manifest, placement, '4.3.0')
        );
        assert.deepEqual(got, plaintext);
      });
    }

    for (const [name, tamper] of Object.entries(TAMPERS)) {
      it(`rejects ${name}`, async function () {
        await expectIntegrityError(
          editAndDecrypt(client, plaintext, HEX, tamper),
          `${name} must be caught`
        );
      });

      it(`rejects ${name} when relabelled 4.3.0`, async function () {
        await expectIntegrityError(
          editAndDecrypt(client, plaintext, HEX, (parts) => {
            relabel(parts.manifest, 'schemaVersion', '4.3.0');
            tamper(parts);
          }),
          `${name} must be caught whatever the label says`
        );
      });
    }
  });
});
