// Simplest HTTP server that supports RANGE headers AFAIK.
import { assert } from 'chai';
import sinon from 'sinon';

import { getMocks } from '../mocks/index.js';
import type { KasPublicKeyAlgorithm } from '../../src/access.js';
import type { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import type { CryptoService, KeyInfo } from '../../tdf3/index.js';
import { AesGcmCipher, Binary, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import type {
  AssertionConfig,
  AssertionVerificationKeys,
  Assertion,
} from '../../tdf3/src/assertions.js';
import { getSystemMetadataAssertionConfig } from '../../tdf3/src/assertions.js';
import type { Scope } from '../../tdf3/src/client/builders.js';
import { loadTDFStream } from '../../tdf3/src/tdf.js';
import { concatUint8 } from '../../tdf3/src/utils/index.js';
import { type Chunker, fromBuffer } from '../../src/seekable.js';
import { ConfigurationError, InvalidFileError, NetworkError } from '../../src/errors.js';
import { packTdf, unpackTdf, type TdfParts } from './helpers/tdf-archive.js';

const Mocks = getMocks();

/** Resolve to the error `promise` rejects with, or fail if it resolves. */
async function rejection(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (e) {
    return e as Error;
  }
  return assert.fail('expected a rejection');
}

type SystemMetadata = {
  creation_date: string;
  tdf_spec_version: string;
  sdk_version: string;
  browser_user_agent: string;
  platform: string;
};

const authProvider = {
  updateClientPublicKey: async () => {},
  withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
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
      withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
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
    const keyMiddleware = () => Promise.resolve({ keyForEncryption: key1, keyForManifest: key1 });

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
      withCreds: (httpReq: HttpRequest) =>
        Promise.resolve({
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
      withCreds: (httpReq: HttpRequest) =>
        Promise.resolve({
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
      withCreds: (httpReq: HttpRequest) =>
        Promise.resolve({
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
      withCreds: (httpReq: HttpRequest) =>
        Promise.resolve({
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
          withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
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
      withCreds: (httpReq: HttpRequest) =>
        Promise.resolve({
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

describe('encrypt decrypt test', function () {
  const expectedVal = 'hello world';
  const kasUrl = `http://localhost:3000`;

  for (const encapKeyType of [
    'ec:secp256r1',
    'rsa:2048',
    'mlkem:768',
    'mlkem:1024',
  ] as KasPublicKeyAlgorithm[]) {
    for (const rewrapKeyType of [
      'ec:secp256r1',
      'rsa:2048',
      'mlkem:768',
      'mlkem:1024',
    ] as KasPublicKeyAlgorithm[]) {
      it(`encrypt-decrypt stream source happy path {encap: ${encapKeyType}, rewrap: ${rewrapKeyType}}`, async function () {
        const cipher = new AesGcmCipher(WebCryptoService);
        const encryptionInformation = new SplitKey(cipher);
        const key1 = await encryptionInformation.generateKey();
        const keyMiddleware = () =>
          Promise.resolve({ keyForEncryption: key1, keyForManifest: key1 });

        const client = new Client.Client({
          kasEndpoint: kasUrl,
          platformUrl: kasUrl,
          dpopKeys: Mocks.entityKeyPair(),
          clientId: 'id',
          authProvider,
        });

        // Generate RSA key pair for RS256 assertions as PEM strings
        const assertionKeys = await client.cryptoService.generateSigningKeyPair();
        const assertionPublicKey = assertionKeys.publicKey;
        const assertionPrivateKey = assertionKeys.privateKey;
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
                key: assertionPrivateKey,
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

  it('fails the write when the cipher disagrees with its own size arithmetic', async function () {
    // An injected `CryptoService` whose output length differs from what
    // `encryptedPayloadSize` predicts would silently desynchronize the
    // manifest's `encryptedSegmentSizeDefault` from the payload. Truncating
    // the auth tag by one byte is the cheapest way to produce that mismatch.
    let segmentsEncrypted = 0;
    const truncatingCryptoService: CryptoService = new Proxy(WebCryptoService, {
      get(target, property, receiver) {
        if (property !== 'encrypt') {
          return Reflect.get(target, property, receiver) as unknown;
        }
        return async (...args: Parameters<CryptoService['encrypt']>) => {
          const result = await target.encrypt(...args);
          // Let the metadata and the first two payload segments through, so
          // the failure lands mid-stream rather than on the first `pull`.
          if (result.authTag && ++segmentsEncrypted > 3) {
            const tag = result.authTag.asByteArray();
            result.authTag = Binary.fromByteArray(tag.slice(0, tag.length - 1));
          }
          return result;
        };
      },
    });

    const cipher = new AesGcmCipher(truncatingCryptoService);
    const encryptionInformation = new SplitKey(cipher);
    const key = await encryptionInformation.generateKey();
    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
      cryptoService: truncatingCryptoService,
    });

    const encryptedStream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      wrappingKeyAlgorithm: 'rsa:2048',
      offline: true,
      scope: { dissem: ['user@domain.com'], attributes: [] },
      keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
      windowSize: 3,
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('123456789012'));
          controller.close();
        },
      }),
    });

    // Also pins the propagation path: `writeStream` raises this from inside
    // `pull`, not from `encrypt`.
    const error = await rejection(encryptedStream.toBuffer());
    assert.equal(segmentsEncrypted, 4);
    assert.instanceOf(error, ConfigurationError);
    assert.match(error.message, /produced 30 bytes for a 3 byte segment, but reports 31$/);
  });

  describe('releases the source when the write stops early', function () {
    let warn: sinon.SinonStub;
    beforeEach(function () {
      warn = sinon.stub(console, 'warn');
    });
    afterEach(function () {
      warn.restore();
    });

    /** An endless source that records why it was cancelled, then throws `cancelError` if set. */
    function endlessSource(cancelError?: Error) {
      const cancelled: { reason?: unknown; called: boolean } = { called: false };
      const source = new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.enqueue(new TextEncoder().encode('123'));
        },
        cancel(reason) {
          cancelled.called = true;
          cancelled.reason = reason;
          if (cancelError) {
            throw cancelError;
          }
        },
      });
      return { source, cancelled };
    }

    /** A crypto service that rejects with `failure` once the write is mid-stream. */
    function failingCryptoService(failure: Error): CryptoService {
      let encrypts = 0;
      return new Proxy(WebCryptoService, {
        get(target, property, receiver) {
          if (property !== 'encrypt') {
            return Reflect.get(target, property, receiver) as unknown;
          }
          return (...args: Parameters<CryptoService['encrypt']>) => {
            // The metadata, then two payload segments, then fail mid-stream.
            if (++encrypts > 3) {
              return Promise.reject(failure);
            }
            return target.encrypt(...args);
          };
        },
      });
    }

    /** Let the un-awaited source cancel settle, then return its warnings. */
    async function cancelWarnings() {
      await new Promise((resolve) => setTimeout(resolve, 0));
      return warn.getCalls().filter((c) => String(c.args[0]).includes('cancel source'));
    }

    async function encryptWith(cryptoService: CryptoService, source: ReadableStream<Uint8Array>) {
      const encryptionInformation = new SplitKey(new AesGcmCipher(cryptoService));
      const key = await encryptionInformation.generateKey();
      const client = new Client.Client({
        kasEndpoint: kasUrl,
        platformUrl: kasUrl,
        dpopKeys: Mocks.entityKeyPair(),
        clientId: 'id',
        authProvider,
        cryptoService,
      });
      return client.encrypt({
        metadata: Mocks.getMetadataObject(),
        offline: true,
        scope: { dissem: ['user@domain.com'], attributes: [] },
        keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
        windowSize: 3,
        source,
      });
    }

    it('cancels the source with the error that failed the write', async function () {
      const failure = new Error('cipher failed');
      const { source, cancelled } = endlessSource();
      const encryptedStream = await encryptWith(failingCryptoService(failure), source);

      const error = await rejection(encryptedStream.toBuffer());
      assert.strictEqual(error, failure);
      assert.isTrue(cancelled.called);
      assert.strictEqual(cancelled.reason, failure);
      assert.isEmpty(await cancelWarnings());
    });

    it('keeps the write error and warns when cancelling the source fails', async function () {
      const failure = new Error('cipher failed');
      const cancelError = new Error('close failed');
      const { source } = endlessSource(cancelError);
      const encryptedStream = await encryptWith(failingCryptoService(failure), source);

      const error = await rejection(encryptedStream.toBuffer());
      assert.strictEqual(error, failure);
      const warnings = await cancelWarnings();
      assert.lengthOf(warnings, 1);
      assert.strictEqual(warnings[0].args[1], cancelError);
    });

    it('does not warn when the source itself failed the write', async function () {
      const failure = new Error('read failed');
      const source = new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.error(failure);
        },
      });
      const encryptedStream = await encryptWith(WebCryptoService, source);

      const error = await rejection(encryptedStream.toBuffer());
      assert.strictEqual(error, failure);
      assert.isEmpty(await cancelWarnings());
    });

    it('cancels the source when the consumer cancels', async function () {
      const { source, cancelled } = endlessSource();
      const encryptedStream = await encryptWith(WebCryptoService, source);

      const reader = encryptedStream.stream.getReader();
      await reader.read();
      await reader.cancel('consumer gave up');
      assert.isTrue(cancelled.called);
      assert.equal(cancelled.reason, 'consumer gave up');
    });
  });

  it('decrypts when the same KAS wraps the same split twice (DSPX-3379)', async function () {
    const cipher = new AesGcmCipher(WebCryptoService);
    const encryptionInformation = new SplitKey(cipher);
    const key1 = await encryptionInformation.generateKey();
    const keyMiddleware = () => Promise.resolve({ keyForEncryption: key1, keyForManifest: key1 });

    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      allowedKases: [kasUrl],
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });
    const scope: Scope = { dissem: ['user@domain.com'], attributes: [] };

    const encryptedStream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      wrappingKeyAlgorithm: 'rsa:2048',
      offline: true,
      scope,
      keyMiddleware,
      splitPlan: [
        { kas: kasUrl, sid: '1' },
        { kas: kasUrl, sid: '1' },
      ],
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(expectedVal));
          controller.close();
        },
      }),
    });

    const kaos = encryptedStream.manifest.encryptionInformation.keyAccess;
    assert.equal(kaos.length, 2, 'expected two KAOs for the duplicated split');
    assert.equal(kaos[0].url, kaos[1].url);
    assert.equal(kaos[0].sid, kaos[1].sid);

    const decryptStream = await client.decrypt({
      source: { type: 'stream', location: encryptedStream.stream },
      wrappingKeyAlgorithm: 'rsa:2048',
    });
    const { value: decryptedText } = await decryptStream.stream.getReader().read();
    assert.equal(new TextDecoder().decode(decryptedText), expectedVal);
  });

  it('writes 2 MiB segments when no window size is given', async function () {
    const cipher = new AesGcmCipher(WebCryptoService);
    const encryptionInformation = new SplitKey(cipher);
    const key = await encryptionInformation.generateKey();
    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      allowedKases: [kasUrl],
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });

    const encryptedStream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      wrappingKeyAlgorithm: 'rsa:2048',
      offline: true,
      scope: { dissem: ['user@domain.com'], attributes: [] },
      keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(expectedVal));
          controller.close();
        },
      }),
    });
    const encryptedTdf = await encryptedStream.toBuffer();

    // Matches the default segment size of the other SDKs.
    const { segmentSizeDefault, encryptedSegmentSizeDefault } =
      encryptedStream.manifest.encryptionInformation.integrityInformation;
    assert.equal(segmentSizeDefault, 2 * 1024 * 1024);
    // 12 byte IV + segment + 16 byte tag.
    assert.equal(encryptedSegmentSizeDefault, 2 * 1024 * 1024 + 28);

    const decryptStream = await client.decrypt({
      source: { type: 'buffer', location: encryptedTdf },
      wrappingKeyAlgorithm: 'rsa:2048',
    });
    assert.equal(new TextDecoder().decode(await decryptStream.toBuffer()), expectedVal);
  });

  it('decrypt signs the rewrap request token with EC dpop keys (ES256)', async function () {
    // Regression for DSPX-3397: the rewrap request token was always signed with
    // RS256, which made WebCrypto reject EC dpop keys ("Unable to use this key to
    // sign"). The token alg must follow the dpop key algorithm.
    const cipher = new AesGcmCipher(WebCryptoService);
    const encryptionInformation = new SplitKey(cipher);
    const key1 = await encryptionInformation.generateKey();
    const keyMiddleware = () => Promise.resolve({ keyForEncryption: key1, keyForManifest: key1 });

    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityECKeyPair(),
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
    });

    const decryptStream = await client.decrypt({
      source: {
        type: 'stream',
        location: encryptedStream.stream,
      },
    });

    const { value: decryptedText } = await decryptStream.stream.getReader().read();
    assert.equal(new TextDecoder().decode(decryptedText), expectedVal);
  });

  it('encrypt-decrypt with system metadata assertion', async function () {
    const cipher = new AesGcmCipher(WebCryptoService);
    const encryptionInformation = new SplitKey(cipher);
    const key1 = await encryptionInformation.generateKey();
    const keyMiddleware = () => Promise.resolve({ keyForEncryption: key1, keyForManifest: key1 });

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

      const metadataValue = JSON.parse(systemAssertion.statement.value) as SystemMetadata;
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
      const expectedMetadataValue = JSON.parse(systemMetadata.statement.value) as SystemMetadata;
      const actualMetadataValue = JSON.parse(systemAssertion.statement.value) as SystemMetadata;

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

  it('rejects a zero window size instead of hanging', async function () {
    const cipher = new AesGcmCipher(WebCryptoService);
    const encryptionInformation = new SplitKey(cipher);
    const key = await encryptionInformation.generateKey();
    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });

    // `windowSize: 0` used to spin forever in the segmentation loop, which
    // never accumulates enough bytes to emit a zero-length segment. The
    // destructuring default in `Client.encrypt` only fires on `undefined`, so
    // zero reaches the writer.
    try {
      await client.encrypt({
        metadata: Mocks.getMetadataObject(),
        wrappingKeyAlgorithm: 'rsa:2048',
        offline: true,
        scope: { dissem: ['user@domain.com'], attributes: [] },
        keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
        windowSize: 0,
        source: new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(expectedVal));
            controller.close();
          },
        }),
      });
      assert.fail('a zero window size should be rejected');
    } catch (e) {
      assert.equal((e as Error).name, 'ConfigurationError');
      assert.match((e as Error).message, /segment size must be a positive integer/);
    }
  });
});

/**
 * Collects unhandled rejections in Node and browsers alike. Mocha's own Node
 * listener would otherwise swallow them, so a leak would not fail the suite.
 */
function captureUnhandledRejections() {
  const reasons: unknown[] = [];
  const onNode = (reason: unknown) => reasons.push(reason);
  const onBrowser = (event: PromiseRejectionEvent) => {
    reasons.push(event.reason);
    event.preventDefault();
  };
  const proc = (globalThis as { process?: NodeJS.Process }).process;
  if (proc?.on) {
    proc.on('unhandledRejection', onNode);
  } else {
    globalThis.addEventListener('unhandledrejection', onBrowser);
  }
  return {
    reasons,
    async stop() {
      // Unhandled rejections are reported on a later macrotask.
      await new Promise((resolve) => setTimeout(resolve, 20));
      if (proc?.on) {
        proc.off('unhandledRejection', onNode);
      } else {
        globalThis.removeEventListener('unhandledrejection', onBrowser);
      }
    },
  };
}

describe('decrypt prefetch', function () {
  const kasUrl = 'http://localhost:3000';
  const SEGMENT_SIZE = 1024;
  const SEGMENT_COUNT = 8;
  // Distinguishable segments, so a dropped or reordered segment is visible.
  const plaintext = new Uint8Array(SEGMENT_COUNT * SEGMENT_SIZE);
  for (let i = 0; i < SEGMENT_COUNT; i++) {
    plaintext.fill('A'.charCodeAt(0) + i, i * SEGMENT_SIZE, (i + 1) * SEGMENT_SIZE);
  }

  let rewraps: number;
  let client: Client.Client;
  let buffer: Uint8Array;

  beforeEach(async function () {
    rewraps = 0;
    client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider: {
        updateClientPublicKey: async () => {},
        withCreds: (httpReq: HttpRequest) => {
          if (/rewrap/i.test(httpReq.url)) {
            rewraps += 1;
          }
          return Promise.resolve(httpReq);
        },
      },
    });
    const key = await new SplitKey(new AesGcmCipher(WebCryptoService)).generateKey();
    const stream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      offline: true,
      scope: { dissem: ['user@domain.com'], attributes: [] },
      windowSize: SEGMENT_SIZE,
      keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(plaintext);
          controller.close();
        },
      }),
    });
    buffer = await stream.toBuffer();
  });

  /** Rebuild the TDF around an edited manifest. */
  async function withManifest(
    edit: (info: TdfParts['manifest']['encryptionInformation']['integrityInformation']) => void
  ) {
    const { payload, manifest } = await unpackTdf(buffer);
    edit(manifest.encryptionInformation.integrityInformation);
    return packTdf(payload, manifest);
  }

  it('surfaces a failed ranged read to the reader and stops fetching', async function () {
    const { manifest, centralDirectory } = await loadTDFStream(fromBuffer(buffer));
    const entry = centralDirectory.find(({ fileName }) => fileName === '0.payload')!;
    const payloadStart = entry.relativeOffsetOfLocalHeader + entry.headerLength;
    const payloadEnd = payloadStart + entry.compressedSize;
    const batchBytes =
      2 * manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault!;
    const batchStart = (n: number) => payloadStart + n * batchBytes;

    const base = fromBuffer(buffer);
    const starts: Array<number | undefined> = [];
    // The connection drops partway: every read from batch 1 on fails. Batch 2
    // is already prefetched when batch 1 fails, so its rejection is one the
    // reader never awaits.
    const chunker: Chunker = (byteStart, byteEnd) => {
      starts.push(byteStart);
      return byteStart !== undefined && byteStart >= batchStart(1) && byteStart < payloadEnd
        ? Promise.reject(new Error('connection reset'))
        : base(byteStart, byteEnd);
    };

    const unhandled = captureUnhandledRejections();
    const received: Uint8Array[] = [];
    let failure: unknown;
    try {
      const stream = await client.decrypt({
        source: { type: 'chunker', location: chunker },
        segmentBatchSize: 2,
        maxConcurrentSegmentBatches: 2,
      });
      const reader = stream.stream.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received.push(value);
      }
    } catch (e) {
      failure = e;
    } finally {
      await unhandled.stop();
    }

    assert.instanceOf(failure, NetworkError);
    // The batch before the failure is delivered intact.
    assert.deepEqual(concatUint8(received), plaintext.slice(0, 2 * SEGMENT_SIZE));
    assert.include(starts, batchStart(2), 'the batch after the failure was prefetched');
    assert.notInclude(starts, batchStart(3), 'fetching stops at the failure');
    assert.isEmpty(unhandled.reasons, 'a failed decrypt must not leak rejections');
  });

  describe('rejects bad input before the KAS rewrap', function () {
    for (const bad of [-1, 1.5, '1024']) {
      it(`manifest encryptedSegmentSizeDefault of ${JSON.stringify(bad)}`, async function () {
        const tampered = await withManifest((info) => {
          (info as { encryptedSegmentSizeDefault: unknown }).encryptedSegmentSizeDefault = bad;
        });
        const e = await rejection(
          client.decrypt({ source: { type: 'buffer', location: tampered } })
        );
        assert.instanceOf(e, InvalidFileError);
        assert.match(e.message, /positive integer/);
        assert.equal(rewraps, 0, 'a malformed file must not cost a KAS call');
      });

      it(`manifest segment encryptedSegmentSize of ${JSON.stringify(bad)}`, async function () {
        const tampered = await withManifest((info) => {
          (info.segments[0] as { encryptedSegmentSize?: unknown }).encryptedSegmentSize = bad;
        });
        const e = await rejection(
          client.decrypt({ source: { type: 'buffer', location: tampered } })
        );
        assert.instanceOf(e, InvalidFileError);
        assert.match(e.message, /positive integer/);
        assert.equal(rewraps, 0, 'a malformed file must not cost a KAS call');
      });
    }

    it('a non-positive segmentBatchSize', async function () {
      const e = await rejection(
        client.decrypt({ source: { type: 'buffer', location: buffer }, segmentBatchSize: 0 })
      );
      assert.instanceOf(e, ConfigurationError);
      assert.match(e.message, /segmentBatchSize/);
      assert.equal(rewraps, 0, 'a bad config must not cost a KAS call');
    });
  });

  it('falls back to per-segment sizes when the manifest omits the default', async function () {
    const tampered = await withManifest((info) => {
      const size = info.encryptedSegmentSizeDefault;
      info.segments = info.segments.map((s) => ({ ...s, encryptedSegmentSize: size }));
      delete (info as { encryptedSegmentSizeDefault?: number }).encryptedSegmentSizeDefault;
    });
    const stream = await client.decrypt({ source: { type: 'buffer', location: tampered } });
    assert.deepEqual(new Uint8Array(await stream.toBuffer()), plaintext);
    // Also shows the rewrap counter used above really sees rewraps.
    assert.equal(rewraps, 1);
  });
});
