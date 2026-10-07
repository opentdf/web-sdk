// Simplest HTTP server that supports RANGE headers AFAIK.
import { assert } from 'chai';

import { getMocks } from '../mocks/index.js';
import type { KasPublicKeyAlgorithm } from '../../src/access.js';
import type { AuthProvider, HttpRequest } from '../../src/auth/auth.js';
import type { AesGcmEncryptor, CryptoService, KeyInfo, SymmetricKey } from '../../tdf3/index.js';
import { AesGcmCipher, Algorithms, Binary, SplitKey, WebCryptoService } from '../../tdf3/index.js';
import { Client } from '../../tdf3/src/index.js';
import type {
  AssertionConfig,
  AssertionVerificationKeys,
  Assertion,
} from '../../tdf3/src/assertions.js';
import { getSystemMetadataAssertionConfig } from '../../tdf3/src/assertions.js';
import type { Scope } from '../../tdf3/src/client/builders.js';
import { base64 } from '../../src/encodings/index.js';
import { ConfigurationError, IvExhaustionError, NetworkError } from '../../src/errors.js';
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

/**
 * Whether a caller-IV `encrypt` call is encrypting data, as opposed to EC or
 * ML-KEM key wrapping, which seals a `SymmetricKey` under a separately derived
 * key and is outside the encryptor's scope.
 */
const isDataEncrypt = ([payload]: Parameters<CryptoService['encrypt']>) =>
  payload instanceof Binary;

/**
 * A provider that generates RBG IVs inside its own encryptors, recording every
 * IV it issues and every data encryption the SDK makes through the caller-IV
 * `encrypt`.
 */
function spyRbgProvider(invocationLimit = 2 ** 26) {
  const issuedIvs: Uint8Array[] = [];
  const spy = { issuedIvs, callerIvEncrypts: 0 };
  const service: CryptoService = new Proxy(WebCryptoService, {
    get(target, property, receiver) {
      if (property === 'encrypt') {
        return (...args: Parameters<CryptoService['encrypt']>) => {
          if (isDataEncrypt(args)) {
            spy.callerIvEncrypts += 1;
          }
          return target.encrypt(...args);
        };
      }
      if (property === 'createAesGcmEncryptor') {
        return (key: SymmetricKey): Promise<AesGcmEncryptor> =>
          Promise.resolve({
            ivConstruction: 'rbg',
            invocationLimit,
            async encrypt(plaintext: Uint8Array) {
              const iv = await target.randomBytes(12);
              issuedIvs.push(iv);
              const { payload, authTag } = await target.encrypt(
                Binary.fromArrayBuffer(plaintext.slice().buffer),
                key,
                Binary.fromArrayBuffer(iv.slice().buffer),
                Algorithms.AES_256_GCM
              );
              return {
                iv,
                ciphertext: new Uint8Array(payload.asArrayBuffer()),
                tag: new Uint8Array(authTag?.asArrayBuffer() ?? new ArrayBuffer(0)),
              };
            },
          });
      }
      return Reflect.get(target, property, receiver) as unknown;
    },
  });
  return { service, spy };
}

/** Every payload segment's 12-byte IV prefix, in order. */
async function segmentIvs(
  encryptedTdf: Uint8Array,
  integrityInformation: { segments: { encryptedSegmentSize?: number }[] } & {
    encryptedSegmentSizeDefault?: number;
  }
): Promise<Uint8Array[]> {
  const zipReader = new ZipReader(fromBuffer(encryptedTdf));
  const centralDirectory = await zipReader.getCentralDirectory();
  const ivs: Uint8Array[] = [];
  let offset = 0;
  for (const segment of integrityInformation.segments) {
    const size = segment.encryptedSegmentSize ?? integrityInformation.encryptedSegmentSizeDefault;
    if (size === undefined) {
      return assert.fail('segment has no encrypted size');
    }
    const bytes = await zipReader.getPayloadSegment(centralDirectory, '0.payload', offset, size);
    ivs.push(bytes.slice(0, 12));
    offset += size;
  }
  return ivs;
}

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

  it('writes deterministic payload IVs after the metadata IV by default', async function () {
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

    // The payload encryptor's first call, invocation zero: the same 8-byte
    // fixed field the payload uses, then four zero bytes.
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
        `payload segment ${index} should use invocation ${index + 1} of the encryptor's fixed field`
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

    // No segments means no payload encrypt, so nothing follows the metadata.
    const { segments } = encryptedStream.manifest.encryptionInformation.integrityInformation;
    assert.lengthOf(segments, 0);

    const decryptStream = await client.decrypt({
      source: { type: 'buffer', location: encryptedTdf },
      wrappingKeyAlgorithm: 'rsa:2048',
    });
    assert.lengthOf(await decryptStream.toBuffer(), 0);
  });

  it('fails the write when a fallback provider returns a short auth tag', async function () {
    // A provider without `createAesGcmEncryptor` takes the SDK-side
    // deterministic path through its caller-IV `encrypt`. Truncating the auth
    // tag by one byte would silently desynchronize the computed
    // `encryptedSegmentSizeDefault` from the payload, so the writer must refuse.
    let segmentsEncrypted = 0;
    const truncatingCryptoService: CryptoService = new Proxy(WebCryptoService, {
      get(target, property, receiver) {
        if (property === 'createAesGcmEncryptor') {
          return undefined;
        }
        if (property !== 'encrypt') {
          return Reflect.get(target, property, receiver) as unknown;
        }
        return async (...args: Parameters<CryptoService['encrypt']>) => {
          const result = await target.encrypt(...args);
          // Let the metadata and the first two payload segments through, so
          // the failure lands mid-stream rather than on the first `pull`.
          if (result.authTag && isDataEncrypt(args) && ++segmentsEncrypted > 3) {
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
    // `pull`, and `IvExhaustionError` surfaces the same way.
    const error = await rejection(encryptedStream.toBuffer());
    assert.equal(segmentsEncrypted, 4);
    assert.instanceOf(error, ConfigurationError);
    assert.match(error.message, /Invalid AES-GCM tag length: 15/);
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

    // The two KAOs share an `sid`, and so a split key. Each draws its own IV
    // from that key's encryptor, so differing metadata could never become
    // AES-GCM nonce reuse. `method.iv` records the first KAO's IV.
    const metadataIv = encryptedStream.manifest.encryptionInformation.method.iv;
    const kaoMetadata = ({ encryptedMetadata }: (typeof kaos)[number]) =>
      JSON.parse(base64.decode(encryptedMetadata ?? '')) as { iv: string; ciphertext: string };
    const [first, second] = kaos.map(kaoMetadata);
    assert.equal(first.iv, metadataIv, 'method.iv should record the first KAO metadata IV');
    assert.notEqual(first.iv, second.iv, 'same-sid KAOs must not share a metadata IV');

    const decryptStream = await client.decrypt({
      source: { type: 'stream', location: encryptedStream.stream },
      wrappingKeyAlgorithm: 'rsa:2048',
    });
    const { value: decryptedText } = await decryptStream.stream.getReader().read();
    assert.equal(new TextDecoder().decode(decryptedText), expectedVal);
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

  it('records provider-generated IVs everywhere and never passes one in', async function () {
    const { service, spy } = spyRbgProvider();
    const cipher = new AesGcmCipher(service);
    const key = await new SplitKey(cipher).generateKey();
    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      allowedKases: [kasUrl],
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
      cryptoService: service,
    });

    const plaintext = '1234567';
    const encryptedStream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      wrappingKeyAlgorithm: 'rsa:2048',
      offline: true,
      scope: { dissem: ['user@domain.com'], attributes: [] },
      keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
      windowSize: 3,
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(plaintext));
          controller.close();
        },
      }),
    });
    const encryptedTdf = await encryptedStream.toBuffer();
    const { encryptionInformation } = encryptedStream.manifest;

    assert.equal(spy.callerIvEncrypts, 0, 'the SDK must not supply an IV of its own');
    // One metadata call, then one per segment, all on the payload key's encryptor.
    assert.lengthOf(spy.issuedIvs, 4);
    const [metadataIv, ...payloadIvs] = spy.issuedIvs;
    assert.equal(encryptionInformation.method.iv, base64.encodeArrayBuffer(metadataIv));
    const { iv: kaoIv } = JSON.parse(
      base64.decode(encryptionInformation.keyAccess[0].encryptedMetadata ?? '')
    ) as { iv: string };
    assert.equal(kaoIv, base64.encodeArrayBuffer(metadataIv));
    assert.deepEqual(
      await segmentIvs(encryptedTdf, encryptionInformation.integrityInformation),
      payloadIvs
    );

    const decryptStream = await client.decrypt({
      source: { type: 'buffer', location: encryptedTdf },
      wrappingKeyAlgorithm: 'rsa:2048',
    });
    assert.equal(new TextDecoder().decode(await decryptStream.toBuffer()), plaintext);
  });

  it("stops with IvExhaustionError at the provider's invocation limit", async function () {
    // Metadata plus two segments fit; the third segment does not.
    const { service, spy } = spyRbgProvider(3);
    const cipher = new AesGcmCipher(service);
    const key = await new SplitKey(cipher).generateKey();
    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
      cryptoService: service,
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

    const error = await rejection(encryptedStream.toBuffer());
    assert.instanceOf(error, IvExhaustionError);
    assert.match(error.message, /maximum of 3 AES-GCM invocations/);
    assert.lengthOf(spy.issuedIvs, 3, 'the writer must refuse before asking for a fourth IV');
  });

  it('gives each split key its own encryptor for its metadata', async function () {
    const { service, spy } = spyRbgProvider();
    const cipher = new AesGcmCipher(service);
    const key = await new SplitKey(cipher).generateKey();
    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      allowedKases: [kasUrl],
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
      cryptoService: service,
    });

    const encryptedStream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      wrappingKeyAlgorithm: 'rsa:2048',
      offline: true,
      scope: { dissem: ['user@domain.com'], attributes: [] },
      keyMiddleware: () => Promise.resolve({ keyForEncryption: key, keyForManifest: key }),
      splitPlan: [
        { kas: kasUrl, sid: '1' },
        { kas: kasUrl, sid: '2' },
      ],
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(expectedVal));
          controller.close();
        },
      }),
    });
    const encryptedTdf = await encryptedStream.toBuffer();
    const { encryptionInformation } = encryptedStream.manifest;

    assert.equal(spy.callerIvEncrypts, 0);
    // Two split-key metadata calls and one payload segment.
    assert.lengthOf(spy.issuedIvs, 3);
    const kaoIvs = encryptionInformation.keyAccess.map(
      ({ encryptedMetadata }) =>
        (JSON.parse(base64.decode(encryptedMetadata ?? '')) as { iv: string }).iv
    );
    assert.notEqual(kaoIvs[0], kaoIvs[1]);
    assert.equal(encryptionInformation.method.iv, kaoIvs[0]);
    const issued = spy.issuedIvs.map((iv) => base64.encodeArrayBuffer(iv));
    for (const kaoIv of kaoIvs) {
      assert.include(issued, kaoIv);
    }

    const decryptStream = await client.decrypt({
      source: { type: 'buffer', location: encryptedTdf },
      wrappingKeyAlgorithm: 'rsa:2048',
    });
    assert.equal(new TextDecoder().decode(await decryptStream.toBuffer()), expectedVal);
  });

  it('falls back to SDK-side deterministic IVs for providers without encryptors', async function () {
    const callerIvs: Uint8Array[] = [];
    const legacyService: CryptoService = new Proxy(WebCryptoService, {
      get(target, property, receiver) {
        if (property === 'createAesGcmEncryptor') {
          return undefined;
        }
        if (property === 'encrypt') {
          return (...args: Parameters<CryptoService['encrypt']>) => {
            if (isDataEncrypt(args)) {
              callerIvs.push(new Uint8Array(args[2].asArrayBuffer()));
            }
            return target.encrypt(...args);
          };
        }
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    const cipher = new AesGcmCipher(legacyService);
    const key = await new SplitKey(cipher).generateKey();
    const client = new Client.Client({
      kasEndpoint: kasUrl,
      platformUrl: kasUrl,
      allowedKases: [kasUrl],
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
      cryptoService: legacyService,
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
    const { encryptionInformation } = encryptedStream.manifest;

    // The #1018 layout: metadata at invocation zero, segments from one, all
    // under one random fixed field, every IV passed through `encrypt`.
    assert.lengthOf(callerIvs, 4);
    const fixedField = callerIvs[0].subarray(0, 8);
    assert.notDeepEqual(fixedField, new Uint8Array(8));
    for (const [invocation, iv] of callerIvs.entries()) {
      const expected = new Uint8Array(12);
      expected.set(fixedField);
      new DataView(expected.buffer).setUint32(8, invocation);
      assert.deepEqual(iv, expected, `invocation ${invocation}`);
    }
    assert.equal(encryptionInformation.method.iv, base64.encodeArrayBuffer(callerIvs[0]));
    assert.deepEqual(
      await segmentIvs(encryptedTdf, encryptionInformation.integrityInformation),
      callerIvs.slice(1)
    );

    const decryptStream = await client.decrypt({
      source: { type: 'buffer', location: encryptedTdf },
      wrappingKeyAlgorithm: 'rsa:2048',
    });
    assert.equal(new TextDecoder().decode(await decryptStream.toBuffer()), '1234567');
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
