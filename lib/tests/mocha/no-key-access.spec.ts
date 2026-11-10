import { assert, expect } from 'chai';
import sinon from 'sinon';

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

  /** Run `read` while counting network requests from any client in this realm. */
  async function counting(read: () => Promise<unknown>) {
    const fetchSpy = sinon.spy(globalThis, 'fetch');
    requests = [];
    let error: unknown;
    try {
      await read();
    } catch (e) {
      error = e;
    } finally {
      fetchSpy.restore();
    }
    return { error, fetches: fetchSpy.callCount };
  }

  async function expectRefusedWithoutRequests(read: () => Promise<unknown>) {
    const { error, fetches } = await counting(read);
    expect(error).to.be.instanceOf(InvalidFileError);
    expect((error as Error).message).to.contain('no key access objects');
    expect(fetches, 'network requests').to.equal(0);
    expect(requests, 'authorized requests').to.deep.equal([]);
  }

  // A fresh client has no cached KAS allowlist, so it fetches one from the
  // platform before decrypting.
  const freshClient = () =>
    new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });
  const tdf3Decrypt = async (file: Uint8Array) =>
    (await freshClient().decrypt({ source: { type: 'buffer', location: file } })).toString();

  const openTdfRead = async (file: Uint8Array) => {
    const opentdf = new OpenTDF({
      authProvider,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
    });
    try {
      // No allowlist in the read options, so the reader fetches one.
      const stream = await opentdf.read({
        source: { type: 'buffer', location: file },
        platformUrl: kasUrl,
      });
      return await new Response(stream).text();
    } finally {
      opentdf.close();
    }
  };

  for (const [path, read] of [
    ['tdf3 decrypt', tdf3Decrypt],
    ['OpenTDF read', openTdfRead],
  ] as const) {
    describe(path, function () {
      it('decrypts the unmodified file, contacting the platform and a KAS', async function () {
        let text = '';
        const { error, fetches } = await counting(async () => {
          text = await read(tdf);
        });
        expect(error).to.equal(undefined);
        assert.equal(text, plaintext);
        expect(fetches).to.be.greaterThan(0);
        expect(rewraps()).to.not.be.empty;
      });

      it('refuses an empty or absent key access list before any request', async function () {
        for (const file of [withKeyAccess([]), withKeyAccess(undefined)]) {
          await expectRefusedWithoutRequests(() => read(file));
        }
      });
    });
  }
});
