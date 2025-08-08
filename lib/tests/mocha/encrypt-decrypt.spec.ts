// Simplest HTTP server that supports RANGE headers AFAIK.
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import { KasPublicKeyAlgorithm } from '../../src/access.js';
import { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import { AesGcmCipher, KeyInfo, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import {
  AssertionConfig,
  AssertionVerificationKeys,
  getSystemMetadataAssertionConfig,
  Assertion,
} from '../../tdf3/src/assertions.js';
import { Scope } from '../../tdf3/src/client/builders.js';
import { NetworkError } from '../../src/errors.js';

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
      platformUrl: kasUrl,
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
        allowedKases: [kasUrl],
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
      assert.fail('Expected Error');
    } catch (error) {
      assert.instanceOf(error, NetworkError);
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
      assert.fail('Expected Error');
    } catch (error) {
      assert.instanceOf(error, NetworkError);
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
      assert.fail('Expected Error');
    } catch (error) {
      assert.instanceOf(error, NetworkError);
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
      assert.instanceOf(error, NetworkError);
    }
  });

  it('should handle network failures', async function () {
    try {
      // Point to a non-existent server
      client = new Client.Client({
        kasEndpoint: 'http://localhost:9999',
        allowedKases: ['http://localhost:9999'],
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
      assert.instanceOf(error, NetworkError);
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
      assert.instanceOf(error, NetworkError);
      assert.include(error.message, '404 Not Found');
    }
  });
});

describe('encrypt decrypt test', async function () {
  const expectedVal = 'hello world';
  const kasUrl = `http://localhost:3000`;

  for (const encapKeyType of ['ec:secp256r1', 'rsa:2048'] as KasPublicKeyAlgorithm[]) {
    for (const rewrapKeyType of ['ec:secp256r1', 'rsa:2048'] as KasPublicKeyAlgorithm[]) {
      it(`encrypt-decrypt stream source happy path {encap: ${encapKeyType}, rewrap: ${rewrapKeyType}}`, async function () {
        const cipher = new AesGcmCipher(WebCryptoService);
        const encryptionInformation = new SplitKey(cipher);
        const key1 = await encryptionInformation.generateKey();
        const keyMiddleware = async () => ({ keyForEncryption: key1, keyForManifest: key1 });

        const client = new Client.Client({
          kasEndpoint: kasUrl,
          platformUrl: kasUrl,
          dpopKeys: Mocks.entityKeyPair(),
          clientId: 'id',
          authProvider,
        });

        const assertionKeys = await crypto.subtle.generateKey(
          {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: { name: 'SHA-256' },
          },
          true,
          ['sign', 'verify']
        );
        const assertionPublicKey = assertionKeys.publicKey;
        const scope: Scope = {
          dissem: ['user@domain.com'],
          attributes: [],
        };

        // Generate a random HS256 key
        const hs256Key = new Uint8Array(32);
        crypto.getRandomValues(hs256Key);

        console.log('ASDF about to encrypt');

        const encryptedStream = await client.encrypt({
          metadata: Mocks.getMetadataObject(),
          wrappingKeyAlgorithm: encapKeyType,
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
                key: assertionKeys.privateKey,
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
              key: assertionPublicKey,
            },
          },
        };

        const decryptStream = await client.decrypt({
          source: {
            type: 'stream',
            location: encryptedStream.stream,
          },
          assertionVerificationKeys,
          wrappingKeyAlgorithm: rewrapKeyType,
        });

        const { value: decryptedText } = await decryptStream.stream.getReader().read();
        assert.equal(new TextDecoder().decode(decryptedText), expectedVal);
      });
    }
  }

  it('encrypt-decrypt with system metadata assertion', async function () {
    const cipher = new AesGcmCipher(WebCryptoService);
    const encryptionInformation = new SplitKey(cipher);
    const key1 = await encryptionInformation.generateKey();
    const keyMiddleware = async () => ({ keyForEncryption: key1, keyForManifest: key1 });

    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });

    const scope: Scope = {
      dissem: ['user@domain.com'],
      attributes: [],
    };

    const encryptedStream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      wrappingKeyAlgorithm: 'rsa:2048',
      offline: true,
      scope,
      keyMiddleware,
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(expectedVal));
          controller.close();
        },
      }),
      systemMetadataAssertion: true, // Enable the system metadata assertion
    });

    // Consume the stream into a buffer. This also ensures manifest population is complete.
    const encryptedTdfBuffer = await encryptedStream.toBuffer();

    // Verify the manifest for the system metadata assertion
    const manifest = encryptedStream.manifest;
    assert.isArray(manifest.assertions, 'Manifest assertions should be an array');
    assert.lengthOf(manifest.assertions, 1, 'Should have one assertion for system metadata');

    const systemAssertion = manifest.assertions.find(
      (assertion: Assertion) => assertion.id === 'system-metadata'
    );
    assert.isDefined(systemAssertion, 'System metadata assertion should be found');
    if (systemAssertion) {
      assert.equal(systemAssertion.type, 'other', 'Assertion type should be "other"');
      assert.equal(systemAssertion.scope, 'tdo', 'Assertion scope should be "tdo"');
      assert.equal(systemAssertion.statement.format, 'json', 'Statement format should be "json"');
      assert.equal(
        systemAssertion.statement.schema,
        'system-metadata-v1',
        'Statement schema should be "system-metadata-v1"'
      );

      const metadataValue = JSON.parse(systemAssertion.statement.value);
      assert.property(metadataValue, 'tdf_spec_version', 'Metadata should have tdfSpecVersion');
      assert.property(metadataValue, 'creation_date', 'Metadata should have creationDate');
      assert.property(metadataValue, 'sdk_version', 'Metadata should have sdkVersion');
      assert.property(metadataValue, 'browser_user_agent', 'Metadata should have browserUserAgent');
      assert.property(metadataValue, 'platform', 'Metadata should have platform');

      // Compare Values
      const systemMetadata = getSystemMetadataAssertionConfig();
      assert.equal(systemMetadata.id, systemAssertion.id, 'ID should match');
      assert.equal(systemMetadata.type, systemAssertion.type, 'Type should match');
      assert.equal(systemMetadata.scope, systemAssertion.scope, 'Scope should match');
      assert.equal(
        systemMetadata.statement.format,
        systemAssertion.statement.format,
        'Statement format should match'
      );
      assert.equal(
        systemMetadata.statement.schema,
        systemAssertion.statement.schema,
        'Statement schema should match'
      );
      assert.equal(
        systemMetadata.appliesToState,
        systemAssertion.appliesToState,
        'AppliesToState should match'
      );

      // Parse statement.value and compare individual fields, ignoring creationDate for direct equality
      const expectedMetadataValue = JSON.parse(systemMetadata.statement.value);
      const actualMetadataValue = JSON.parse(systemAssertion.statement.value);

      assert.isString(actualMetadataValue.creation_date, 'creation_date should be a string');
      assert.isNotEmpty(actualMetadataValue.creation_date, 'creation_date should not be empty');
      assert.equal(
        actualMetadataValue.tdf_spec_version,
        expectedMetadataValue.tdf_spec_version,
        'tdf_spec_version should match'
      );
      assert.equal(
        actualMetadataValue.sdk_version,
        expectedMetadataValue.sdk_version,
        'sdk_version should match'
      );
      assert.equal(
        actualMetadataValue.browser_user_agent,
        expectedMetadataValue.browser_user_agent,
        'browser_user_agent should match'
      );
      assert.equal(
        actualMetadataValue.platform,
        expectedMetadataValue.platform,
        'platform should match'
      );
    }

    const decryptStream = await client.decrypt({
      source: { type: 'buffer', location: encryptedTdfBuffer },
    });

    const { value: decryptedText } = await decryptStream.stream.getReader().read();
    assert.equal(new TextDecoder().decode(decryptedText), expectedVal);
  });
});
