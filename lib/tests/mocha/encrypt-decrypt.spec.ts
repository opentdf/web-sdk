// Simplest HTTP server that supports RANGE headers AFAIK.
import { assert } from 'chai';

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
import { base64 } from '../../src/encodings/index.js';
import { ConfigurationError, NetworkError } from '../../src/errors.js';
import { fromBuffer } from '../../src/seekable.js';
import { ZipReader } from '../../tdf3/src/utils/zip-reader.js';

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

  it('writes deterministic payload IVs after the reserved metadata IV', async function () {
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

    const encryptedStream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      wrappingKeyAlgorithm: 'rsa:2048',
      offline: true,
      scope: { dissem: ['user@domain.com'], attributes: [] },
      keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
      windowSize: 3,
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('1234567'));
          controller.close();
        },
      }),
    });

    const encryptedTdf = await encryptedStream.toBuffer();
    const { manifest } = encryptedStream;

    // Invocation zero of the stream's counter: the same 8-byte fixed field the
    // payload uses, then four zero bytes.
    const metadataIv = Uint8Array.from(
      Binary.fromBase64(manifest.encryptionInformation.method.iv).asByteArray()
    );
    assert.lengthOf(metadataIv, 12);
    const fixedField = metadataIv.subarray(0, 8);
    assert.deepEqual(metadataIv.subarray(8), new Uint8Array(4));
    // A constant fixed field would mean every TDF reuses these IVs.
    assert.notDeepEqual(fixedField, new Uint8Array(8), 'fixed field should be random');

    const zipReader = new ZipReader(fromBuffer(encryptedTdf));
    const centralDirectory = await zipReader.getCentralDirectory();
    const { encryptedSegmentSizeDefault, segmentSizeDefault, segments } =
      manifest.encryptionInformation.integrityInformation;
    assert.lengthOf(segments, 3);
    assert.equal(segmentSizeDefault, 3);
    // 12 byte IV + 3 byte segment + 16 byte tag.
    assert.equal(encryptedSegmentSizeDefault, 31);
    let encryptedOffset = 0;

    for (const [index, segmentInfo] of segments.entries()) {
      const encryptedSize = segmentInfo.encryptedSegmentSize ?? encryptedSegmentSizeDefault;
      if (encryptedSize === undefined) {
        assert.fail(`payload segment ${index} has no encrypted size`);
      }
      const encryptedSegment = await zipReader.getPayloadSegment(
        centralDirectory,
        '0.payload',
        encryptedOffset,
        encryptedSize
      );
      const expectedIv = new Uint8Array(12);
      expectedIv.set(fixedField);
      new DataView(expectedIv.buffer).setUint32(8, index + 1);
      assert.deepEqual(
        encryptedSegment.subarray(0, 12),
        expectedIv,
        `payload segment ${index} should use invocation ${index + 1} of the stream's fixed field`
      );
      encryptedOffset += encryptedSize;
    }

    // '1234567' is 7 bytes in 3 byte segments, so the last one is short and
    // must carry its own sizes rather than inherit the defaults.
    assert.equal(segments[2].segmentSize, 1);
    assert.equal(segments[2].encryptedSegmentSize, 29);
  });

  it('gives two TDFs sharing one key disjoint IVs (DSPX-4496)', async function () {
    const cipher = new AesGcmCipher(WebCryptoService);
    const encryptionInformation = new SplitKey(cipher);
    // The hazard this guards: `keyMiddleware` lets a caller hand the same
    // symmetric key to two encrypts. Deterministic IVs would then repeat
    // exactly, which breaks AES-GCM's confidentiality *and* its authenticity.
    const key = await encryptionInformation.generateKey();
    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });

    const encryptOnce = async () => {
      const stream = await client.encrypt({
        metadata: Mocks.getMetadataObject(),
        wrappingKeyAlgorithm: 'rsa:2048',
        offline: true,
        scope: { dissem: ['user@domain.com'], attributes: [] },
        keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
        windowSize: 3,
        source: new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('1234567'));
            controller.close();
          },
        }),
      });
      const buffer = await stream.toBuffer();
      const zipReader = new ZipReader(fromBuffer(buffer));
      const centralDirectory = await zipReader.getCentralDirectory();
      const firstSegment = await zipReader.getPayloadSegment(centralDirectory, '0.payload', 0, 31);
      return {
        metadataIv: stream.manifest.encryptionInformation.method.iv,
        firstPayloadIv: firstSegment.subarray(0, 12),
      };
    };

    const a = await encryptOnce();
    const b = await encryptOnce();

    assert.notEqual(a.metadataIv, b.metadataIv, 'metadata IVs must differ');
    assert.notDeepEqual(a.firstPayloadIv, b.firstPayloadIv, 'payload IVs must differ');
  });

  it('spends no payload IV on an empty payload', async function () {
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
          controller.close();
        },
      }),
    });
    const encryptedTdf = await encryptedStream.toBuffer();

    // No segments means no `next()` call, so nothing follows invocation zero.
    const { segments } = encryptedStream.manifest.encryptionInformation.integrityInformation;
    assert.lengthOf(segments, 0);

    const decryptStream = await client.decrypt({
      source: { type: 'buffer', location: encryptedTdf },
      wrappingKeyAlgorithm: 'rsa:2048',
    });
    assert.lengthOf(await decryptStream.toBuffer(), 0);
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
    const error = await rejection(
      client.encrypt({
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
      })
    );
    assert.instanceOf(error, ConfigurationError);
    assert.match(error.message, /segment size must be a positive integer/);
  });

  it('fails the write when the cipher disagrees with its own size arithmetic', async function () {
    // `encryptedSegmentSizeDefault` is now computed rather than measured, so a
    // crypto service whose output length does not match `encryptedPayloadSize`
    // would silently desynchronize the manifest from the payload. Truncating
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
    // `pull`, and `IvExhaustionError` would surface the same way.
    const error = await rejection(encryptedStream.toBuffer());
    assert.instanceOf(error, ConfigurationError);
    assert.match(error.message, /but reports 31$/);
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

    // Both KAOs encrypt their metadata under invocation zero of the stream's
    // counter, which is what `method.iv` records. They share an `sid`, so they
    // share a split key too -- safe only because the metadata plaintext is
    // byte-identical. Giving them differing metadata without differing IVs
    // would be outright AES-GCM nonce reuse.
    const metadataIv = encryptedStream.manifest.encryptionInformation.method.iv;
    const kaoMetadata = ({ encryptedMetadata }: (typeof kaos)[number]) =>
      JSON.parse(base64.decode(encryptedMetadata ?? '')) as { iv: string; ciphertext: string };
    for (const [index, kao] of kaos.entries()) {
      const { iv, ciphertext } = kaoMetadata(kao);
      assert.equal(iv, metadataIv, `KAO ${index} should use the metadata IV`);
      assert.equal(ciphertext, kaoMetadata(kaos[0]).ciphertext);
    }

    const decryptStream = await client.decrypt({
      source: { type: 'stream', location: encryptedStream.stream },
      wrappingKeyAlgorithm: 'rsa:2048',
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
});
