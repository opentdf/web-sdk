// Simplest HTTP server that supports RANGE headers AFAIK.
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import { HttpRequest } from '../../src/auth/auth.js';
import { WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { SplitKey } from '../../tdf3/src/models/encryption-information.js';
import { AesGcmCipher } from '../../tdf3/src/ciphers/aes-gcm-cipher.js';
import { Scope } from '../../tdf3/src/client/builders.js';
const Mocks = getMocks();

const authProvider = {
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  updateClientPublicKey: async () => {},
  withCreds: async (httpReq: HttpRequest) => httpReq,
};

describe('encrypt decrypt test', async function () {
  const expectedVal = 'hello world';
  const kasUrl = `http://localhost:3000`;

  it('encrypt-decrypt stream source happy path', async function () {
    const cipher = new AesGcmCipher(WebCryptoService);
    const encryptionInformation = new SplitKey(cipher);
    const key1 = await encryptionInformation.generateKey();
    const keyMiddleware = async () => ({ keyForEncryption: key1, keyForManifest: key1 });

    // sandbox.spy(tdf1, '_generateManifest');
    // sandbox.stub(tdf1, 'unwrapKey').callsFake(async () => {
    //   // @ts-ignore
    //   const keyInfo = tdf1._generateManifest.lastCall.args[0];
    //   return {
    //     reconstructedKeyBinary: keyInfo.unwrappedKeyBinary as Binary,
    //     metadata: undefined,
    //   };
    // });
    const client = new Client.Client({
      kasEndpoint: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });

    const eo = await Mocks.getEntityObject();
    const scope: Scope = {
      dissem: ['user@domain.com'],
      attributes: [],
    };

    const encryptedStream = await client.encrypt({
      eo,
      metadata: Mocks.getMetadataObject(),
      offline: true,
      scope,
      keyMiddleware,
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(expectedVal));
          controller.close();
        },
      }),
    });

    const decryptStream = await client.decrypt({
      eo,
      source: {
        type: 'stream',
        location: encryptedStream.stream,
      },
    });

    const { value: decryptedText } = await decryptStream.stream.getReader().read();

    assert.equal(new TextDecoder().decode(decryptedText), expectedVal);
  });
});
