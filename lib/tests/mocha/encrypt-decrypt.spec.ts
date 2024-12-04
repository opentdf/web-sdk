// Simplest HTTP server that supports RANGE headers AFAIK.
import { assert, expect } from 'chai';

import { getMocks } from '../mocks/index.js';
import { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, KeyInfo, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import { AssertionConfig, AssertionVerificationKeys } from '../../tdf3/src/assertions.js';
import { Scope } from '../../tdf3/src/client/builders.js';
import {
  InvalidFileError,
  NetworkError,
  PermissionDeniedError,
  ServiceError,
  UnauthenticatedError,
} from '../../src/errors.js';

const Mocks = getMocks();

const authProvider = {
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  updateClientPublicKey: async () => {},
  withCreds: async (httpReq: HttpRequest) => httpReq,
};

describe('rewrap error cases', function () {
  const kasUrl = 'http://localhost:3000';
  const expectedVal = 'test data';
  let client: Client.Client;
  let cipher: AesGcmCipher;
  let encryptionInformation: SplitKey;
  let key1: KeyInfo;

  beforeEach(async function () {
    // Setup base auth provider that will be modified per test
    const baseAuthProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (httpReq: HttpRequest) => httpReq,
    };

    client = new Client.Client({
      kasEndpoint: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider: baseAuthProvider,
    });

    cipher = new AesGcmCipher(WebCryptoService);
    encryptionInformation = new SplitKey(cipher);
    key1 = await encryptionInformation.generateKey();
  });

  async function encryptTestData({ customAuthProvider }: { customAuthProvider?: AuthProvider }) {
    const keyMiddleware = async () => ({ keyForEncryption: key1, keyForManifest: key1 });

    if (customAuthProvider) {
      client = new Client.Client({
        kasEndpoint: kasUrl,
        dpopKeys: Mocks.entityKeyPair(),
        clientId: 'id',
        authProvider: customAuthProvider,
      });
    }

    return client.encrypt({
      metadata: Mocks.getMetadataObject(),
      offline: true,
      scope: {
        dissem: ['user@domain.com'],
        attributes: [],
      },
      keyMiddleware,
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(expectedVal));
          controller.close();
        },
      }),
    });
  }

  it('should handle 401 Unauthorized error', async function () {
    const authProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (httpReq: HttpRequest) => ({
        ...httpReq,
        headers: { ...httpReq.headers, authorization: 'Invalid' },
      }),
    };

    const encryptedStream = await encryptTestData({ customAuthProvider: authProvider });

    try {
      await client.decrypt({
        source: {
          type: 'stream',
          location: encryptedStream.stream,
        },
      });
      assert.fail('Expected UnauthenticatedError');
    } catch (error) {
      assert.instanceOf(error, UnauthenticatedError);
      assert.include(error.message, 'rewrap auth failure');
    }
  });

  it('should handle 403 Forbidden error', async function () {
    const authProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (httpReq: HttpRequest) => ({
        ...httpReq,
        headers: { ...httpReq.headers, 'x-test-response': '403' },
      }),
    };

    const encryptedStream = await encryptTestData({ customAuthProvider: authProvider });

    try {
      await client.decrypt({
        source: {
          type: 'stream',
          location: encryptedStream.stream,
        },
      });
      assert.fail('Expected PermissionDeniedError');
    } catch (error) {
      assert.instanceOf(error, PermissionDeniedError);
      assert.include(error.message, 'rewrap permission denied');
    }
  });

  it('should handle 400 Bad Request error', async function () {
    // Modify the mock server to return 400 for invalid body
    const authProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (httpReq: HttpRequest) => ({
        ...httpReq,
        headers: {
          ...httpReq.headers,
          'x-test-response': '400',
          'x-test-response-message': 'IntegrityError',
        },
      }),
    };

    const encryptedStream = await encryptTestData({ customAuthProvider: authProvider });

    try {
      await client.decrypt({
        source: {
          type: 'stream',
          location: encryptedStream.stream,
        },
      });
      assert.fail('Expected InvalidFileError');
    } catch (error) {
      assert.instanceOf(error, InvalidFileError);
      assert.include(error.message, 'rewrap bad request');
    }
  });

  it('should handle 500 Server error', async function () {
    const authProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (httpReq: HttpRequest) => ({
        ...httpReq,
        headers: { ...httpReq.headers, 'x-test-response': '500' },
      }),
    };

    const encryptedStream = await encryptTestData({ customAuthProvider: authProvider });

    try {
      await client.decrypt({
        source: {
          type: 'stream',
          location: encryptedStream.stream,
        },
      });
      assert.fail('Expected ServiceError');
    } catch (error) {
      expect(() => {
        throw error;
      }).to.throw(ServiceError, 'rewrap failure');
    }
  });

  it('should handle network failures', async function () {
    try {
      // Point to a non-existent server
      client = new Client.Client({
        kasEndpoint: 'http://localhost:9999',
        dpopKeys: Mocks.entityKeyPair(),
        clientId: 'id',
        authProvider: {
          updateClientPublicKey: async () => {},
          withCreds: async (httpReq: HttpRequest) => httpReq,
        },
      });

      const encryptedStream = await encryptTestData({});

      await client.decrypt({
        source: {
          type: 'stream',
          location: encryptedStream.stream,
        },
      });
      assert.fail('Expected NetworkError');
    } catch (error) {
      expect(() => {
        throw error;
      }).to.throw(NetworkError);
    }
  });

  it('should handle decrypt errors with invalid keys', async function () {
    const authProvider: AuthProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (httpReq: HttpRequest) => ({
        ...httpReq,
        body: new URLSearchParams({ invalidKey: 'true' }),
        headers: {
          ...httpReq.headers,
          'x-test-response': '400',
          'x-test-response-message': 'DecryptError',
        },
      }),
    };

    const encryptedStream = await encryptTestData({ customAuthProvider: authProvider });

    try {
      await client.decrypt({
        source: {
          type: 'stream',
          location: encryptedStream.stream,
        },
      });
      assert.fail('Expected InvalidFileError');
    } catch (error) {
      expect(() => {
        throw error;
      }).to.throw(InvalidFileError, 'rewrap bad request');
    }
  });
});

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
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: { name: 'SHA-256' },
      },
      true,
      ['sign', 'verify']
    );
    const publicKey = keyPair.publicKey;
    const scope: Scope = {
      dissem: ['user@domain.com'],
      attributes: [],
    };

    // Generate a random HS256 key
    const hs256Key = new Uint8Array(32);
    crypto.getRandomValues(hs256Key);

    const encryptedStream = await client.encrypt({
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
      assertionConfigs: [
        {
          id: 'assertion1',
          type: 'handling',
          scope: 'tdo',
          statement: {
            format: 'json',
            schema: 'https://example.com/schema',
            value: '{"example": "value"}',
          },
          appliesToState: 'encrypted',
          signingKey: {
            alg: 'HS256',
            key: hs256Key,
          },
        },
        {
          id: 'assertion2',
          type: 'handling',
          scope: 'tdo',
          statement: {
            format: 'json',
            schema: 'https://example.com/schema',
            value: '{"example": "value"}',
          },
          appliesToState: 'encrypted',
          signingKey: {
            alg: 'RS256',
            key: keyPair.privateKey,
          },
        },
        {
          id: 'assertion3',
          type: 'handling',
          scope: 'tdo',
          statement: {
            format: 'json',
            schema: 'https://example.com/schema',
            value: '{"example": "value"}',
          },
          appliesToState: 'encrypted',
        },
        // Add more assertion configs as needed
      ] as AssertionConfig[],
    });

    // Create AssertionVerificationKeys for verification
    const assertionVerificationKeys: AssertionVerificationKeys = {
      Keys: {
        assertion1: {
          alg: 'HS256',
          key: hs256Key,
        },
        assertion2: {
          alg: 'RS256',
          key: publicKey,
        },
      },
    };

    const decryptStream = await client.decrypt({
      source: {
        type: 'stream',
        location: encryptedStream.stream,
      },
      assertionVerificationKeys,
    });

    const { value: decryptedText } = await decryptStream.stream.getReader().read();
    assert.equal(new TextDecoder().decode(decryptedText), expectedVal);
  });
});
