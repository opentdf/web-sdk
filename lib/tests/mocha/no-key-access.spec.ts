import { assert, expect } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { HttpRequest } from '../../src/auth/auth.js';
import { InvalidFileError } from '../../src/errors.js';
import { OpenTDF } from '../../src/opentdf.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import type { Manifest } from '../../tdf3/src/models/manifest.js';
import { packTdf, unpackTdf } from './helpers/tdf-archive.js';

const Mocks = getMocks();

describe('manifests with no key access objects', function () {
  const kasUrl = 'http://localhost:3000';
  const plaintext = 'key access test';
  let requests: string[];
  const authProvider = {
    updateClientPublicKey: async () => {},
    withCreds: (httpReq: HttpRequest) => {
      requests.push(httpReq.url);
      return Promise.resolve(httpReq);
    },
  };
  let client: Client.Client;
  let tdf: Uint8Array;
  let payload: Uint8Array;
  let manifest: Manifest;

  before(async function () {
    requests = [];
    client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });
    const key = await new SplitKey(new AesGcmCipher(WebCryptoService)).generateKey();
    const stream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      offline: true,
      scope: { dissem: ['user@domain.com'], attributes: [] },
      keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(plaintext));
          controller.close();
        },
      }),
    });
    tdf = await stream.toBuffer();
    ({ payload, manifest } = await unpackTdf(tdf));
  });

  beforeEach(function () {
    requests = [];
  });

  /** The same TDF with its key access list replaced, or removed when undefined. */
  function withKeyAccess(keyAccess: unknown[] | undefined): Uint8Array {
    const encryptionInformation = Object.fromEntries(
      Object.entries(manifest.encryptionInformation).filter(([name]) => name !== 'keyAccess')
    );
    return packTdf(payload, {
      ...manifest,
      encryptionInformation:
        keyAccess === undefined ? encryptionInformation : { ...encryptionInformation, keyAccess },
    });
  }

  const rewraps = () => requests.filter((url) => /rewrap/i.test(url));

  async function expectNoKeyAccess(reading: Promise<unknown>) {
    let error: unknown;
    try {
      await reading;
    } catch (e) {
      error = e;
    }
    expect(error).to.be.instanceOf(InvalidFileError);
    expect((error as Error).message).to.contain('no key access objects');
    expect(rewraps()).to.deep.equal([]);
  }

  const tdf3Decrypt = async (file: Uint8Array) =>
    (await client.decrypt({ source: { type: 'buffer', location: file } })).toString();

  it('decrypts the unmodified file', async function () {
    assert.equal(await tdf3Decrypt(tdf), plaintext);
    expect(rewraps()).to.not.be.empty;
  });

  it('refuses an empty or absent key access list before contacting a KAS', async function () {
    for (const file of [withKeyAccess([]), withKeyAccess(undefined)]) {
      await expectNoKeyAccess(tdf3Decrypt(file));
    }
  });

  it('refuses it through the OpenTDF reader too', async function () {
    const opentdf = new OpenTDF({
      authProvider,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
    });
    try {
      const read = (file: Uint8Array) =>
        opentdf
          .read({ source: { type: 'buffer', location: file }, allowedKASEndpoints: [kasUrl] })
          .then((stream) => new Response(stream).text());
      assert.equal(await read(tdf), plaintext);
      requests = [];
      for (const file of [withKeyAccess([]), withKeyAccess(undefined)]) {
        await expectNoKeyAccess(read(file));
      }
    } finally {
      opentdf.close();
    }
  });
});
