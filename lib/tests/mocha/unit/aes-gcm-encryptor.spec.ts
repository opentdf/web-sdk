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
  CryptoService,
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

describe('DefaultCryptoService.createAesGcmEncryptor', () => {
  const cipher = new AesGcmCipher(WebCryptoService);

  it('reports deterministic IVs and the full 32-bit invocation space', async () => {
    const key = await cipher.generateKey();
    const encryptor = await WebCryptoService.createAesGcmEncryptor(key);

    expect(encryptor.ivConstruction).to.equal('deterministic');
    expect(encryptor.invocationLimit).to.equal(2 ** 32);
  });

  it('counts up under one random fixed field, decryptable by the reader', async () => {
    const key = await cipher.generateKey();
    const encryptor = await WebCryptoService.createAesGcmEncryptor(key);
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
    const a = await WebCryptoService.createAesGcmEncryptor(key);
    const b = await WebCryptoService.createAesGcmEncryptor(key);

    const ivA = (await a.encrypt(new Uint8Array(1))).iv;
    const ivB = (await b.encrypt(new Uint8Array(1))).iv;
    expect(ivA).to.not.deep.equal(ivB);
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
});

describe('guardAesGcmEncryptor', () => {
  it('throws IvExhaustionError once the declared limit is reached', async () => {
    const inner = stubEncryptor(2, wellFormed);
    const guarded = guardAesGcmEncryptor(inner);

    await guarded.encrypt(new Uint8Array(1));
    await guarded.encrypt(new Uint8Array(1));
    const error = await rejection(guarded.encrypt(new Uint8Array(1)));

    expect(error).to.be.instanceOf(IvExhaustionError);
    expect(error.message).to.match(/maximum of 2 AES-GCM invocations for one key \(rbg IVs\)/);
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

  it('reads the limit once, so a provider cannot raise it mid-stream', async () => {
    const inner = stubEncryptor(1, wellFormed);
    const guarded = guardAesGcmEncryptor(inner);
    inner.invocationLimit = 100;

    await guarded.encrypt(new Uint8Array(1));
    expect(await rejection(guarded.encrypt(new Uint8Array(1)))).to.be.instanceOf(IvExhaustionError);
  });

  it('rejects limits that are not integers from 1 to 2^32', () => {
    for (const limit of [0, -1, 1.5, NaN, MAX_AES_GCM_INVOCATIONS + 1]) {
      expect(() => guardAesGcmEncryptor(stubEncryptor(limit, wellFormed)), `${limit}`).to.throw(
        ConfigurationError,
        'Invalid AES-GCM encryptor invocation limit'
      );
    }
    expect(() =>
      guardAesGcmEncryptor(stubEncryptor(MAX_AES_GCM_INVOCATIONS, wellFormed))
    ).to.not.throw();
  });

  for (const [field, malformed, message] of [
    ['iv', { iv: new Uint8Array(16) }, 'Invalid AES-GCM IV length: 16'],
    ['tag', { tag: new Uint8Array(12) }, 'Invalid AES-GCM tag length: 12'],
    ['ciphertext', { ciphertext: new Uint8Array(0) }, 'Invalid AES-GCM ciphertext length: 0'],
  ] as const) {
    it(`rejects a malformed ${field}`, async () => {
      const guarded = guardAesGcmEncryptor(
        stubEncryptor(10, (plaintext) => ({ ...wellFormed(plaintext), ...malformed }))
      );
      const error = await rejection(guarded.encrypt(new Uint8Array(4)));
      expect(error).to.be.instanceOf(ConfigurationError);
      expect(error.message).to.contain(message);
    });
  }
});

describe('createAesGcmEncryptorFor', () => {
  it("uses the provider's encryptor when it offers one", async () => {
    const providerEncryptor = stubEncryptor(5, wellFormed);
    const provider: CryptoService = {
      ...WebCryptoService.DefaultCryptoService,
      createAesGcmEncryptor: () => Promise.resolve(providerEncryptor),
    };
    const key = await WebCryptoService.generateKey();

    const encryptor = await createAesGcmEncryptorFor(provider, key);
    await encryptor.encrypt(new Uint8Array(1));

    expect(encryptor.ivConstruction).to.equal('rbg');
    expect(encryptor.invocationLimit).to.equal(5);
    expect(providerEncryptor.calls).to.equal(1);
  });

  it('falls back to SDK-side deterministic IVs over the caller-IV encrypt', async () => {
    const ivsPassed: Uint8Array[] = [];
    const { createAesGcmEncryptor: _omitted, ...legacy } = WebCryptoService.DefaultCryptoService;
    void _omitted;
    const provider: CryptoService = {
      ...legacy,
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
});
