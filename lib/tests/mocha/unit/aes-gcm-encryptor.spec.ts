import { assert, expect } from 'chai';

import {
  createAesGcmEncryptorFor,
  deterministicAesGcmEncryptor,
  guardAesGcmEncryptor,
  MAX_AES_GCM_INVOCATIONS,
} from '../../../tdf3/src/ciphers/aes-gcm-encryptor.js';
import { AesGcmCipher } from '../../../tdf3/src/ciphers/aes-gcm-cipher.js';
import { Binary } from '../../../tdf3/src/binary.js';
import { concatUint8 } from '../../../tdf3/src/utils/index.js';
import * as WebCryptoService from '../../../tdf3/src/crypto/index.js';
import type {
  AesGcmEncryptor,
  AesGcmEncryptResult,
  AesGcmIvConstruction,
  CryptoService,
  SymmetricKey,
} from '../../../tdf3/src/crypto/declarations.js';
import { ConfigurationError, IvExhaustionError } from '../../../src/errors.js';

/** Resolve to the error `promise` rejects with, or fail if it resolves. */
async function rejection(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (e) {
    return e as Error;
  }
  return assert.fail('expected a rejection');
}

/**
 * An encryptor that returns `result` from every call, counting them. Its
 * fields are mutable so tests can misbehave the way a provider might.
 */
type StubEncryptor = { -readonly [K in keyof AesGcmEncryptor]: AesGcmEncryptor[K] } & {
  calls: number;
};
function stubEncryptor(
  invocationLimit: number,
  result: (plaintext: Uint8Array) => AesGcmEncryptResult
): StubEncryptor {
  const stub: StubEncryptor = {
    ivConstruction: 'rbg',
    invocationLimit,
    calls: 0,
    encrypt(plaintext: Uint8Array) {
      stub.calls += 1;
      // A throwing `result` must surface as a rejection, as from a real provider.
      return new Promise((resolve) => resolve(result(plaintext)));
    },
  };
  return stub;
}

const wellFormed = (plaintext: Uint8Array): AesGcmEncryptResult => ({
  iv: new Uint8Array(12),
  ciphertext: new Uint8Array(plaintext.length),
  tag: new Uint8Array(16),
});

/** A promise and the function that resolves it, for holding a call open. */
function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

describe('createAesGcmEncryptorFor(DefaultCryptoService)', () => {
  const cipher = new AesGcmCipher(WebCryptoService);
  const { DefaultCryptoService } = WebCryptoService;

  it('leaves createAesGcmEncryptor unset so spread providers keep their overrides', () => {
    expect(DefaultCryptoService.createAesGcmEncryptor).to.be.undefined;
  });

  it('reports deterministic IVs and the full 32-bit invocation space', async () => {
    const key = await cipher.generateKey();
    const encryptor = await createAesGcmEncryptorFor(DefaultCryptoService, key);

    expect(encryptor.ivConstruction).to.equal('deterministic');
    expect(encryptor.invocationLimit).to.equal(2 ** 32);
  });

  it('counts up under one random fixed field, decryptable by the reader', async () => {
    const key = await cipher.generateKey();
    const encryptor = await createAesGcmEncryptorFor(DefaultCryptoService, key);
    const plaintext = new TextEncoder().encode('hello world');

    const first = await encryptor.encrypt(plaintext);
    const second = await encryptor.encrypt(plaintext);

    expect(first.iv.subarray(0, 8)).to.deep.equal(second.iv.subarray(0, 8));
    expect(first.iv.subarray(0, 8)).to.not.deep.equal(new Uint8Array(8));
    expect(first.iv.subarray(8)).to.deep.equal(Uint8Array.from([0, 0, 0, 0]));
    expect(second.iv.subarray(8)).to.deep.equal(Uint8Array.from([0, 0, 0, 1]));

    // The segment layout the writer emits: IV, ciphertext, tag.
    const { payload } = await cipher.decrypt(
      concatUint8([second.iv, second.ciphertext, second.tag]),
      key
    );
    expect(new Uint8Array(payload.asArrayBuffer())).to.deep.equal(plaintext);
  });

  it('draws a fresh fixed field for every encryptor on the same key', async () => {
    const key = await cipher.generateKey();
    const a = await createAesGcmEncryptorFor(DefaultCryptoService, key);
    const b = await createAesGcmEncryptorFor(DefaultCryptoService, key);

    const ivA = (await a.encrypt(new Uint8Array(1))).iv;
    const ivB = (await b.encrypt(new Uint8Array(1))).iv;
    expect(ivA).to.not.deep.equal(ivB);
  });

  it("routes a spread provider's encrypt and randomBytes overrides", async () => {
    const fixedField = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const randomBytesCalls: number[] = [];
    let encryptCalls = 0;
    const provider: CryptoService = {
      ...DefaultCryptoService,
      randomBytes: (length) => {
        randomBytesCalls.push(length);
        return Promise.resolve(fixedField.slice(0, length));
      },
      encrypt: async (...args) => {
        encryptCalls += 1;
        return DefaultCryptoService.encrypt(...args);
      },
    };
    const key = await cipher.generateKey();

    const { iv } = await (await createAesGcmEncryptorFor(provider, key)).encrypt(new Uint8Array(1));

    expect(randomBytesCalls).to.deep.equal([8]);
    expect(encryptCalls).to.equal(1);
    expect(iv.subarray(0, 8)).to.deep.equal(fixedField);
  });
});

describe('deterministicAesGcmEncryptor', () => {
  it('splits a tag left on the end of the payload by a caller-IV service', async () => {
    const cipher = new AesGcmCipher(WebCryptoService);
    const key = await cipher.generateKey();
    // `AesGcmCipher.encrypt` always tolerated services that return the tag
    // inside the payload rather than as `authTag`; the fallback must too.
    const tagInPayload: CryptoService['encrypt'] = async (...args) => {
      const { payload, authTag } = await WebCryptoService.encrypt(...args);
      return {
        payload: Binary.fromArrayBuffer(
          concatUint8([
            new Uint8Array(payload.asArrayBuffer()),
            new Uint8Array(authTag?.asArrayBuffer() ?? new ArrayBuffer(0)),
          ]).buffer as ArrayBuffer
        ),
      };
    };
    const encryptor = await deterministicAesGcmEncryptor(
      key,
      WebCryptoService.randomBytes,
      tagInPayload
    );

    const plaintext = new TextEncoder().encode('split me');
    const { iv, ciphertext, tag } = await encryptor.encrypt(plaintext);
    expect(ciphertext).to.have.length(plaintext.length);
    expect(tag).to.have.length(16);

    const { payload } = await cipher.decrypt(concatUint8([iv, ciphertext, tag]), key);
    expect(new Uint8Array(payload.asArrayBuffer())).to.deep.equal(plaintext);
  });

  it('spends the IV of an attempt that fails', async () => {
    const ivsPassed: Uint8Array[] = [];
    let failNext = true;
    const flaky: CryptoService['encrypt'] = async (payload, key, iv, algorithm) => {
      ivsPassed.push(new Uint8Array(iv.asArrayBuffer()));
      if (failNext) {
        failNext = false;
        throw new Error('timeout');
      }
      return WebCryptoService.encrypt(payload, key, iv, algorithm);
    };
    const key = await WebCryptoService.generateKey();
    const encryptor = await deterministicAesGcmEncryptor(key, WebCryptoService.randomBytes, flaky);

    expect((await rejection(encryptor.encrypt(new Uint8Array(1)))).message).to.equal('timeout');
    const { iv } = await encryptor.encrypt(new Uint8Array(1));

    // A provider that timed out may still have encrypted under invocation 0.
    expect(iv.subarray(8)).to.deep.equal(Uint8Array.from([0, 0, 0, 1]));
    expect(ivsPassed.map((v) => v[11])).to.deep.equal([0, 1]);
  });

  it('gives concurrent calls distinct, consecutive IVs', async () => {
    const gate = deferred();
    const slow: CryptoService['encrypt'] = async (...args) => {
      await gate.promise;
      return WebCryptoService.encrypt(...args);
    };
    const key = await WebCryptoService.generateKey();
    const encryptor = await deterministicAesGcmEncryptor(key, WebCryptoService.randomBytes, slow);

    const pending = Array.from({ length: 50 }, () => encryptor.encrypt(new Uint8Array(1)));
    gate.resolve();
    const counters = (await Promise.all(pending)).map(({ iv }) =>
      new DataView(iv.buffer, iv.byteOffset).getUint32(8)
    );

    expect(counters).to.deep.equal(Array.from({ length: 50 }, (_, i) => i));
  });
});

describe('guardAesGcmEncryptor', () => {
  it('throws IvExhaustionError once the declared limit is reached', async () => {
    const inner = stubEncryptor(2, wellFormed);
    const guarded = guardAesGcmEncryptor(inner);

    await guarded.encrypt(new Uint8Array(1));
    await guarded.encrypt(new Uint8Array(1));
    const error = await rejection(guarded.encrypt(new Uint8Array(1)));

    expect(error).to.be.instanceOf(IvExhaustionError);
    expect(error.message).to.contain('maximum of 2 AES-GCM invocations');
    // Refused before reaching the provider, not after.
    expect(inner.calls).to.equal(2);
  });

  it('counts failed attempts against the limit', async () => {
    let failNext = true;
    const inner = stubEncryptor(2, (plaintext) => {
      if (failNext) {
        failNext = false;
        throw new Error('transient');
      }
      return wellFormed(plaintext);
    });
    const guarded = guardAesGcmEncryptor(inner);

    expect((await rejection(guarded.encrypt(new Uint8Array(1)))).message).to.equal('transient');
    await guarded.encrypt(new Uint8Array(1));
    expect(await rejection(guarded.encrypt(new Uint8Array(1)))).to.be.instanceOf(IvExhaustionError);
    expect(inner.calls).to.equal(2);
  });

  it('cannot be overshot by concurrent calls', async () => {
    const gate = deferred();
    const inner = stubEncryptor(3, wellFormed);
    const innerEncrypt = inner.encrypt;
    inner.encrypt = async (plaintext) => {
      await gate.promise;
      return innerEncrypt(plaintext);
    };
    const guarded = guardAesGcmEncryptor(inner);

    const settled = Promise.allSettled(
      Array.from({ length: 4 }, () => guarded.encrypt(new Uint8Array(1)))
    );
    gate.resolve();
    const results = await settled;

    expect(results.filter(({ status }) => status === 'fulfilled')).to.have.length(3);
    const [rejected] = results.filter((r) => r.status === 'rejected');
    expect(rejected.reason).to.be.instanceOf(IvExhaustionError);
    expect(inner.calls).to.equal(3);
  });

  it('reads the limit once, so a provider cannot raise it mid-stream', async () => {
    const inner = stubEncryptor(1, wellFormed);
    const guarded = guardAesGcmEncryptor(inner);
    inner.invocationLimit = 100;

    await guarded.encrypt(new Uint8Array(1));
    expect(await rejection(guarded.encrypt(new Uint8Array(1)))).to.be.instanceOf(IvExhaustionError);
  });

  it('rejects limits that are not integers from 1 to 2^32', () => {
    for (const limit of [0, -1, 1.5, NaN, Infinity, '5', undefined, MAX_AES_GCM_INVOCATIONS + 1]) {
      const stub = stubEncryptor(limit as number, wellFormed);
      expect(() => guardAesGcmEncryptor(stub), `${String(limit)}`).to.throw(
        ConfigurationError,
        'Invalid AES-GCM encryptor invocation limit'
      );
    }
    expect(() =>
      guardAesGcmEncryptor(stubEncryptor(MAX_AES_GCM_INVOCATIONS, wellFormed))
    ).to.not.throw();
  });

  it('rejects an unknown IV construction', () => {
    const stub = stubEncryptor(1, wellFormed);
    stub.ivConstruction = 'counter' as AesGcmIvConstruction;
    expect(() => guardAesGcmEncryptor(stub)).to.throw(
      ConfigurationError,
      'Invalid AES-GCM encryptor IV construction: counter'
    );
  });

  for (const [what, malformed, message] of [
    ['a long iv', { iv: new Uint8Array(16) }, 'Invalid AES-GCM IV length: 16'],
    ['a non-byte iv', { iv: new Array<number>(12).fill(0) }, 'Invalid AES-GCM IV length: 12'],
    ['a short tag', { tag: new Uint8Array(12) }, 'Invalid AES-GCM tag length: 12'],
    ['an empty ciphertext', { ciphertext: new Uint8Array(0) }, 'ciphertext length: 0'],
    // The likeliest provider bug: the tag left on the ciphertext as well.
    ['a ciphertext with the tag', { ciphertext: new Uint8Array(20) }, 'ciphertext length: 20'],
  ] as const) {
    it(`rejects ${what}`, async () => {
      const guarded = guardAesGcmEncryptor(
        stubEncryptor(10, (plaintext) => ({
          ...wellFormed(plaintext),
          ...(malformed as Partial<AesGcmEncryptResult>),
        }))
      );
      const error = await rejection(guarded.encrypt(new Uint8Array(4)));
      expect(error).to.be.instanceOf(ConfigurationError);
      expect(error.message).to.contain(message);
    });
  }

  it('rejects a missing result with a ConfigurationError, not a TypeError', async () => {
    const guarded = guardAesGcmEncryptor(
      stubEncryptor(10, () => undefined as unknown as AesGcmEncryptResult)
    );
    expect(await rejection(guarded.encrypt(new Uint8Array(4)))).to.be.instanceOf(
      ConfigurationError
    );
  });

  it('copies the IV and tag, so a provider reusing its buffers cannot change them', async () => {
    const iv = new Uint8Array(12).fill(7);
    const tag = new Uint8Array(16).fill(9);
    const guarded = guardAesGcmEncryptor(
      stubEncryptor(10, (plaintext) => ({ iv, ciphertext: new Uint8Array(plaintext.length), tag }))
    );

    const result = await guarded.encrypt(new Uint8Array(4));
    iv.fill(0);
    tag.fill(0);

    expect(result.iv).to.deep.equal(new Uint8Array(12).fill(7));
    expect(result.tag).to.deep.equal(new Uint8Array(16).fill(9));
  });

  it('is not a ConfigurationError when exhausted', async () => {
    const guarded = guardAesGcmEncryptor(stubEncryptor(1, wellFormed));
    await guarded.encrypt(new Uint8Array(1));
    const error = await rejection(guarded.encrypt(new Uint8Array(1)));
    expect(error).to.not.be.instanceOf(ConfigurationError);
    expect(error.name).to.equal('IvExhaustionError');
  });
});

describe('createAesGcmEncryptorFor', () => {
  it("uses the provider's encryptor for the given key when it offers one", async () => {
    const providerEncryptor = stubEncryptor(5, wellFormed);
    const keysSeen: SymmetricKey[] = [];
    const provider: CryptoService = {
      ...WebCryptoService.DefaultCryptoService,
      createAesGcmEncryptor: (key) => {
        keysSeen.push(key);
        return Promise.resolve(providerEncryptor);
      },
    };
    const key = await WebCryptoService.generateKey();

    const encryptor = await createAesGcmEncryptorFor(provider, key);
    await encryptor.encrypt(new Uint8Array(1));

    expect(keysSeen).to.deep.equal([key]);
    expect(encryptor.ivConstruction).to.equal('rbg');
    expect(encryptor.invocationLimit).to.equal(5);
    expect(providerEncryptor.calls).to.equal(1);
  });

  describe("guards the provider's encryptor", () => {
    const withEncryptor = (encryptor: AesGcmEncryptor): CryptoService => ({
      ...WebCryptoService.DefaultCryptoService,
      createAesGcmEncryptor: () => Promise.resolve(encryptor),
    });

    it('rejecting an out-of-range limit', async () => {
      const key = await WebCryptoService.generateKey();
      const provider = withEncryptor(stubEncryptor(2 ** 33, wellFormed));
      expect(await rejection(createAesGcmEncryptorFor(provider, key))).to.be.instanceOf(
        ConfigurationError
      );
    });

    it('enforcing its limit', async () => {
      const key = await WebCryptoService.generateKey();
      const encryptor = await createAesGcmEncryptorFor(
        withEncryptor(stubEncryptor(1, wellFormed)),
        key
      );
      await encryptor.encrypt(new Uint8Array(1));
      expect(await rejection(encryptor.encrypt(new Uint8Array(1)))).to.be.instanceOf(
        IvExhaustionError
      );
    });

    it('rejecting a malformed IV', async () => {
      const key = await WebCryptoService.generateKey();
      const encryptor = await createAesGcmEncryptorFor(
        withEncryptor(
          stubEncryptor(5, (plaintext) => ({ ...wellFormed(plaintext), iv: new Uint8Array(13) }))
        ),
        key
      );
      expect(await rejection(encryptor.encrypt(new Uint8Array(1)))).to.be.instanceOf(
        ConfigurationError
      );
    });
  });

  it('falls back to SDK-side deterministic IVs over the caller-IV encrypt', async () => {
    const ivsPassed: Uint8Array[] = [];
    const provider: CryptoService = {
      ...WebCryptoService.DefaultCryptoService,
      encrypt: async (payload, key, iv, algorithm) => {
        ivsPassed.push(new Uint8Array(iv.asArrayBuffer()));
        return WebCryptoService.encrypt(payload, key, iv, algorithm);
      },
    };
    const key = await WebCryptoService.generateKey();

    const encryptor = await createAesGcmEncryptorFor(provider, key);
    const first = await encryptor.encrypt(new Uint8Array(1));
    const second = await encryptor.encrypt(new Uint8Array(1));

    expect(encryptor.ivConstruction).to.equal('deterministic');
    expect(ivsPassed).to.deep.equal([first.iv, second.iv]);
    expect(second.iv.subarray(8)).to.deep.equal(Uint8Array.from([0, 0, 0, 1]));
  });

  it('rejects a fallback service that returns no tag at all', async () => {
    const provider: CryptoService = {
      ...WebCryptoService.DefaultCryptoService,
      encrypt: async (...args) => {
        const { payload } = await WebCryptoService.encrypt(...args);
        return { payload };
      },
    };
    const key = await WebCryptoService.generateKey();
    const encryptor = await createAesGcmEncryptorFor(provider, key);

    const error = await rejection(encryptor.encrypt(new Uint8Array(32)));
    expect(error).to.be.instanceOf(ConfigurationError);
    expect(error.message).to.contain('ciphertext length: 16');
  });
});
