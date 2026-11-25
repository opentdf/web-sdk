import { expect } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { HttpRequest } from '../../src/auth/auth.js';
import { InvalidFileError } from '../../src/errors.js';
import { AesGcmCipher, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import type {
  AssertionConfig,
  AssertionKey,
  AssertionVerificationKeys,
} from '../../tdf3/src/assertions.js';
import { Client } from '../../tdf3/src/index.js';
import { rsaKeyPair, type TestKeyPair } from './helpers/jws-keys.js';

const Mocks = getMocks();

describe('default assertion verification key on decrypt', function () {
  const kasUrl = 'http://localhost:3000';
  const plaintext = 'default assertion key test';
  const authProvider = {
    updateClientPublicKey: async () => {},
    withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
  };

  let client: Client.Client;
  let signer: TestKeyPair;
  let other: TestKeyPair;
  let tdf: Uint8Array;

  before(async function () {
    client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });
    [signer, other] = await Promise.all([rsaKeyPair(), rsaKeyPair()]);
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
      // `toString` also names an Object.prototype member, which is not a
      // per-ID entry.
      assertionConfigs: ['a1', 'toString'].map((id): AssertionConfig => ({
        id,
        type: 'handling',
        scope: 'tdo',
        appliesToState: 'encrypted',
        statement: { format: 'json', schema: 'test-schema', value: '{"foo":"bar"}' },
        signingKey: { alg: 'RS256', key: signer.sdk.privateKey },
      })),
    });
    tdf = await stream.toBuffer();
  });

  async function decrypt(assertionVerificationKeys?: AssertionVerificationKeys) {
    const stream = await client.decrypt({
      source: { type: 'buffer', location: tdf },
      assertionVerificationKeys,
    });
    return stream.toString();
  }

  async function expectRejected(assertionVerificationKeys?: AssertionVerificationKeys) {
    let error: unknown;
    try {
      await decrypt(assertionVerificationKeys);
    } catch (e) {
      error = e;
    }
    expect(error, 'expected decrypt to fail').to.be.instanceOf(InvalidFileError);
  }

  it('verifies assertions with no own per-ID entry with the default key', async function () {
    expect(await decrypt({ Keys: {}, DefaultKey: { alg: 'RS256', key: signer.pubPem } })).to.equal(
      plaintext
    );
  });

  it('prefers the per-ID key over the default key', async function () {
    const signerKey: AssertionKey = { alg: 'RS256', key: signer.pubPem };
    const keys: AssertionVerificationKeys = {
      Keys: { a1: signerKey, toString: signerKey },
      DefaultKey: { alg: 'RS256', key: other.pubPem },
    };
    expect(await decrypt(keys)).to.equal(plaintext);
    await expectRejected({
      Keys: { a1: { alg: 'RS256', key: other.pubPem } },
      DefaultKey: { alg: 'RS256', key: signer.pubPem },
    });
  });

  it('does not fall back from a default key that does not verify', async function () {
    await expectRejected({ Keys: {}, DefaultKey: { alg: 'RS256', key: other.pubPem } });
  });
});
