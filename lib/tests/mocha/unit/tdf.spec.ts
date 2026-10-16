import { expect } from 'chai';

import * as TDF from '../../../tdf3/src/tdf.js';
import type { KeyAccessObject } from '../../../tdf3/src/models/key-access.js';
import type { PolicyBody } from '../../../tdf3/src/models/policy.js';
import { type Policy } from '../../../tdf3/src/models/policy.js';
import { OriginAllowList } from '../../../src/access.js';
import {
  ConfigurationError,
  InvalidFileError,
  IvExhaustionError,
  UnsafeUrlError,
} from '../../../src/errors.js';
import { getMocks } from '../../mocks/index.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import type { CryptoService } from '../../../tdf3/src/crypto/declarations.js';
import { isMlKemKeyAlgorithm } from '../../../tdf3/src/crypto/declarations.js';
import {
  GcmIvCounter,
  MAX_GCM_INVOCATIONS_PER_FIXED_FIELD,
} from '../../../tdf3/src/ciphers/gcm-iv-counter.js';

const sampleCert = `
-----BEGIN CERTIFICATE-----
MIIFnjCCA4YCCQCnKw0cfbMLJTANBgkqhkiG9w0BAQsFADCBkDELMAkGA1UEBhMC
VUExCzAJBgNVBAgMAk9EMQ4wDAYDVQQHDAVPREVTQTEPMA0GA1UECgwGVklSVFJV
MREwDwYDVQQLDAhQTEFURk9STTEZMBcGA1UEAwwQbG9jYWwudmlydHJ1LmNvbTEl
MCMGCSqGSIb3DQEJARYWc2l2YW5vdi5jdHJAdmlydHJ1LmNvbTAeFw0yMzA3MDYx
MTUxMzFaFw0yNDA3MDUxMTUxMzFaMIGQMQswCQYDVQQGEwJVQTELMAkGA1UECAwC
T0QxDjAMBgNVBAcMBU9ERVNBMQ8wDQYDVQQKDAZWSVJUUlUxETAPBgNVBAsMCFBM
QVRGT1JNMRkwFwYDVQQDDBBsb2NhbC52aXJ0cnUuY29tMSUwIwYJKoZIhvcNAQkB
FhZzaXZhbm92LmN0ckB2aXJ0cnUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAn+CvhpQZ6lPZG8j07l8JWWQnmPATKB2GDbcyC/Yg1rJAcFLZmBvH
VR3SamYQrSKxFRsoBGVruIFQBpoYMSolRWVVRnRBmpB5O8vCdP8J78mRaXGoJAez
xexuZBEoUIJJAn0Uoxg462201RgzLrZq+b+gOHZzcOfMlh/HPWhTeLdW2i0oMddL
yeykUa8ARHeCbA1Ux/IZju9n+lY3Pv7pI7z0mYuU14p33lvQbTZ1psY4frwFeyqC
rqHR1NqKjX+CnitFDrVKV48ZNlBQ6y348NpCaNH0wmy4FRAuGS6dJb9KFK6C+KIj
EQlWaucPTgvf6/dgZ6IZdLPvHUQNwC9yidRpnyLTUZlxwCXVO3P1sP7ifq75RwFk
OhvGqnoWNxUwd+23YUOFhE5b7WSO8NwRiMPBeEhNiWaiCmu1v88h52mgRr74MjCQ
mftuJlPwhsqWMpdYuv42851Y95x5s7BFWtntBNcU/+TTSKcygPNGkuR/tNw79JrM
bMl/Wj+cJoCW/3+1KzmPX13Nf2Cq2KZ8Kx6JCy+zFj/Hu8O/iqZ1vxA7gUyESPrd
NFB988QD7H8AQLCeDh6mOTdK08ZG74FlRBSk788A4oyslx8DslOkWbqHLdA7frv6
rEtl3mJ9UchFVpJOXw5nT3plE0ZRx4NWRLAG2+8GIUsL6eylpFUfVH8CAwEAATAN
BgkqhkiG9w0BAQsFAAOCAgEAlS3ph3ZcPf90uo0Y0l6Pca5I7ztuq6wu6reKAqnz
kh6N1rpLSe6EdRIOOCkMWMYTlZYFnSG/USGRfiCV0TOoo2C+jFvARRn6oir1v3B4
XBQORRNrOP8xV6kXAmNxs9Zl8CpAxfejV0vBHzN709q2HDfwmMmmp/yhlsAa1/iL
ARYV3TIJBmAOpec2CemuSVwGvYF7Ojl4sTYl0qMzrmm85wMBHJWR9EJbbFZBDDi4
GKVx26SfxaeauZXRgbO7Tav0q7mbJXI6u95aWO6iwkABRfnEQbimfVCjRI4TKlNs
WX5PS3QXXJg/9ocEglNGDwTouDwD/yMevR2tJ4clb9SJkJjJ3I0t7aUoFHXBl0B2
merKiN1ZE4OlbG/BsJypwAqV7Xk6tK3LM8fCMxhP1K0XX5Ifi1+hbN4Wr7a/zpEq
RWFMXtPKqTne0Ut6M7Xv5BBjY3uBmp0AX9hXt00olAiZsrOfj4gjAVULxdsbaEpr
nTqI65s26fls4y9bCZSfY//YNMAAtSRfmGbCZfrnzyvMtZfSMHqxhzMX7jXonV9c
TuHue7faEGaGlWGQVdNeudZaQ/eimDWeWnbhoUz6hSX7NICUFE64W6+GVFsAte3s
jtfbjUcLqvZzZt+u7YDapWbEbdgYjn/lUt0sTNyY65IagXJel9iacjCIVdzoKPzn
HJg=
-----END CERTIFICATE-----
`.trim();

const { kasECCert } = getMocks();

// `process` is undefined in the browser test runner (karma), so guard access.
// BASE_KEY_ALG is a local-dev toggle used to point the mock server at an
// ML-KEM base key; when unset (as in CI) these tests expect the default EC key.
const baseKeyAlg = typeof process !== 'undefined' ? process.env.BASE_KEY_ALG || '' : '';

describe('TDF', () => {
  const cryptoService: CryptoService = DefaultCryptoService;

  it('should return key', async () => {
    const pem = await TDF.extractPemFromKeyString(sampleCert, 'rsa:2048', cryptoService);
    expect(pem).to.include('-----BEGIN PUBLIC KEY-----');
    expect(pem).to.include('-----END PUBLIC KEY-----');
  });

  it('should return pem', async () => {
    const sampleKey = sampleCert
      .replace('BEGIN CERTIFICATE', 'BEGIN PUBLIC KEY')
      .replace('END CERTIFICATE', 'END PUBLIC KEY');
    const pem = await TDF.extractPemFromKeyString(sampleKey, 'rsa:2048', cryptoService);
    expect(pem).to.equal(sampleKey);
  });

  it('should return ec pem', async () => {
    const pem = await TDF.extractPemFromKeyString(kasECCert, 'ec:secp256r1', cryptoService);
    expect(pem).to.include('-----BEGIN PUBLIC KEY-----');
    expect(pem).to.include('-----END PUBLIC KEY-----');
  });
});

describe('GcmIvCounter', () => {
  const ff = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);

  it('issues consecutive invocations starting at zero', () => {
    const counter = new GcmIvCounter(ff);

    expect(counter.next()).to.deep.equal(Uint8Array.from([...ff, 0, 0, 0, 0]));
    expect(counter.next()).to.deep.equal(Uint8Array.from([...ff, 0, 0, 0, 1]));
    expect(counter.next()).to.deep.equal(Uint8Array.from([...ff, 0, 0, 0, 2]));
  });

  it('gives two counters disjoint IVs even when the key is reused', () => {
    const a = new GcmIvCounter(Uint8Array.from([1, 1, 1, 1, 1, 1, 1, 1]));
    const b = new GcmIvCounter(Uint8Array.from([2, 2, 2, 2, 2, 2, 2, 2]));

    expect(a.next()).to.not.deep.equal(b.next());
    expect(a.next()).to.not.deep.equal(b.next());
  });

  it('holds the fixed field steady across a multi-byte carry', () => {
    const counter = new GcmIvCounter(ff, 0xffff, 0x10002);

    expect(counter.next()).to.deep.equal(Uint8Array.from([...ff, 0, 0, 0xff, 0xff]));
    expect(counter.next()).to.deep.equal(Uint8Array.from([...ff, 0, 1, 0, 0]));
    expect(counter.next()).to.deep.equal(Uint8Array.from([...ff, 0, 1, 0, 1]));
  });

  it('copies the fixed field so later caller mutations cannot shift IVs', () => {
    const mutable = Uint8Array.from(ff);
    const counter = new GcmIvCounter(mutable);
    mutable.fill(0);

    expect(counter.next()).to.deep.equal(Uint8Array.from([...ff, 0, 0, 0, 0]));
  });

  it('stops before the per-fixed-field invocation ceiling', () => {
    const counter = new GcmIvCounter(
      ff,
      MAX_GCM_INVOCATIONS_PER_FIXED_FIELD - 1,
      MAX_GCM_INVOCATIONS_PER_FIXED_FIELD
    );

    expect(counter.next()).to.deep.equal(Uint8Array.from([...ff, 0xff, 0xff, 0xff, 0xff]));
    expect(() => counter.next()).to.throw(IvExhaustionError);
    // Still throws rather than wrapping around to invocation zero.
    expect(() => counter.next()).to.throw(IvExhaustionError);
  });

  it('rejects a fixed field that is not exactly eight bytes', () => {
    expect(() => new GcmIvCounter(new Uint8Array(7))).to.throw(
      ConfigurationError,
      'Invalid fixed field length'
    );
    expect(() => new GcmIvCounter(new Uint8Array(12))).to.throw(
      ConfigurationError,
      'Invalid fixed field length'
    );
  });

  it('rejects ranges that start below zero or exceed the invocation ceiling', () => {
    expect(() => new GcmIvCounter(ff, -1)).to.throw(ConfigurationError, 'Invalid first invocation');
    expect(() => new GcmIvCounter(ff, 2, 1)).to.throw(
      ConfigurationError,
      'Invalid invocation limit'
    );
    // A limit equal to the first invocation yields a counter that could never
    // issue an IV, so it is rejected up front rather than on first use.
    expect(() => new GcmIvCounter(ff, 1, 1)).to.throw(
      ConfigurationError,
      'Invalid invocation limit'
    );
    expect(() => new GcmIvCounter(ff, 1, MAX_GCM_INVOCATIONS_PER_FIXED_FIELD + 1)).to.throw(
      ConfigurationError,
      'exceeds the maximum'
    );
  });
});

describe('fetchKasPublicKey', () => {
  it('missing kas names throw', async () => {
    try {
      await TDF.fetchKasPublicKey('');
      expect.fail('did not throw');
    } catch (e) {
      expect(() => {
        throw e;
      }).to.throw(ConfigurationError);
    }
  });

  it('invalid kas names throw', async () => {
    try {
      await TDF.fetchKasPublicKey('~~~');
      expect.fail('did not throw');
    } catch (e) {
      expect(e).to.exist;
    }
  });

  it('localhost kas is valid', async () => {
    const pk2 = await TDF.fetchKasPublicKey('http://localhost:3000');
    if (isMlKemKeyAlgorithm(baseKeyAlg)) {
      expect(pk2.publicKey).to.include('BEGIN PUBLIC KEY');
      expect(pk2.kid).to.match(/^mlkem(768|1024)$/);
    } else {
      expect(pk2.publicKey).to.include('BEGIN CERTIFICATE');
      expect(pk2.kid).to.equal('e1');
    }
  });

  it('invalid algorithms', async () => {
    try {
      const res = await TDF.fetchKasPublicKey('http://localhost:3000', 'rsa:512' as never); //ts-ignore
      console.log(res);
      expect.fail('did not throw');
    } catch (e) {
      expect(!!e).to.equal(true);
    }
  });

  it('localhost BaseKey', async () => {
    const pk2 = await TDF.fetchKasPublicKey('http://localhost:3000');
    if (isMlKemKeyAlgorithm(baseKeyAlg)) {
      expect(pk2.publicKey).to.include('BEGIN PUBLIC KEY');
      expect(pk2.kid).to.match(/^mlkem(768|1024)$/);
    } else {
      expect(pk2.publicKey).to.include('BEGIN CERTIFICATE');
      expect(pk2.kid).to.equal('e1');
    }
  });
});

describe('validatePolicyObject', () => {
  const testCases: { title: string; policy: Partial<Policy>; error?: string }[] = [
    {
      title: 'missing uuid',
      policy: { body: { dataAttributes: [], dissem: ['someDissem'] } },
      error: 'uuid',
    },
    {
      title: 'missing body',
      policy: { uuid: 'someUuid' },
      error: 'body',
    },
    {
      title: 'missing body.dissem',
      policy: { uuid: 'someUuid', body: {} as PolicyBody },
      error: 'dissem',
    },
    {
      title: 'valid policy',
      policy: { uuid: 'someUuid', body: { dataAttributes: [], dissem: ['someDissem'] } },
    },
  ];

  testCases.forEach(({ title, policy, error }) => {
    it(`should handle ${title}`, () => {
      if (error) {
        expect(() => TDF.validatePolicyObject(policy)).to.throw(ConfigurationError, error);
      } else {
        expect(() => TDF.validatePolicyObject(policy)).to.not.throw();
      }
    });
  });
});

describe('getBoundedSegmentSchedulerOptions', () => {
  const MIB = 1024 * 1024;

  it('derives a window from the segment size when nothing is configured', () => {
    // With nothing configured, the bound scales with the segment size rather
    // than being a fixed segment count.
    expect(TDF.getBoundedSegmentSchedulerOptions({ segmentSize: MIB })).to.deep.equal({
      segmentBatchSize: 42,
      maxConcurrentSegmentBatches: 3,
    });
    expect(TDF.getBoundedSegmentSchedulerOptions({ segmentSize: 16 * MIB })).to.deep.equal({
      segmentBatchSize: 2,
      maxConcurrentSegmentBatches: 3,
    });
  });

  it('lets an explicit setting win without rescaling the other', () => {
    expect(
      TDF.getBoundedSegmentSchedulerOptions({ segmentSize: 16 * MIB, segmentBatchSize: 500 })
    ).to.deep.equal({
      segmentBatchSize: 500,
      maxConcurrentSegmentBatches: 3,
    });
    expect(
      TDF.getBoundedSegmentSchedulerOptions({
        segmentSize: 16 * MIB,
        maxConcurrentSegmentBatches: 1,
      })
    ).to.deep.equal({
      segmentBatchSize: 2,
      maxConcurrentSegmentBatches: 1,
    });
  });

  it('rejects a non-positive setting', () => {
    expect(() =>
      TDF.getBoundedSegmentSchedulerOptions({ segmentSize: MIB, segmentBatchSize: 0 })
    ).to.throw(ConfigurationError, 'segmentBatchSize');
    expect(() =>
      TDF.getBoundedSegmentSchedulerOptions({ segmentSize: MIB, maxConcurrentSegmentBatches: -1 })
    ).to.throw(ConfigurationError, 'maxConcurrentSegmentBatches');
  });
});

describe('prefetchSegmentBatches', () => {
  const chunks = Array.from({ length: 8 }, (_, i) => ({
    hash: `${i}`,
    encryptedOffset: i * 100,
    encryptedSegmentSize: 100,
  }));
  // The stream pulls on later tasks, so let it run to quiescence.
  const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

  /** A batch stream whose fetches stay pending until released. */
  function heldBatches(segmentBatchSize: number, maxConcurrentSegmentBatches: number) {
    const fetched: string[][] = [];
    const held: Array<() => void> = [];
    const reader = TDF.prefetchSegmentBatches({
      chunks,
      segmentBatchSize,
      maxConcurrentSegmentBatches,
      fetchBatch: (slice) => {
        fetched.push(slice.map(({ hash }) => hash));
        return new Promise((resolve) => held.push(() => resolve([])));
      },
    }).getReader();
    const releaseAll = () => held.splice(0).forEach((release) => release());
    return { fetched, reader, releaseAll };
  }

  it('slices chunks into ordered batches and closes after the last', async () => {
    const { fetched, reader, releaseAll } = heldBatches(3, 2);
    releaseAll();
    const slices: string[][] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      slices.push(value.slice.map(({ hash }) => hash));
      releaseAll();
    }
    const expected = [
      ['0', '1', '2'],
      ['3', '4', '5'],
      ['6', '7'],
    ];
    expect(slices).to.deep.equal(expected);
    expect(fetched).to.deep.equal(expected);
  });

  it('keeps at most maxConcurrentSegmentBatches batches ahead of the reader', async () => {
    const { fetched, reader, releaseAll } = heldBatches(1, 3);
    await settle();
    // The queue holds one fewer than the limit: the reader holds the other.
    expect(fetched).to.have.lengthOf(2, 'fills the queue without waiting for the reader');

    await reader.read();
    await settle();
    expect(fetched).to.have.lengthOf(3, 'the batch the reader holds still counts');

    // Finishing those fetches frees nothing: their plaintext is still unread.
    releaseAll();
    await settle();
    expect(fetched).to.have.lengthOf(3, 'completed but unread batches still count');

    await reader.read();
    await settle();
    expect(fetched).to.have.lengthOf(4, 'each batch read lets one more start');
  });
});

describe('splitLookupTableFactory', () => {
  it('should return a correct split table for valid input', () => {
    const keyAccess: KeyAccessObject[] = [
      { sid: 'split1', type: 'remote', url: 'https://kas1', protocol: 'kas' },
      { sid: 'split2', type: 'remote', url: 'https://kas2', protocol: 'kas' },
    ];
    const allowedKases = new OriginAllowList(['https://kas1', 'https://kas2']);

    const result = TDF.splitLookupTableFactory(keyAccess, allowedKases);

    expect(result).to.deep.equal({
      split1: [keyAccess[0]],
      split2: [keyAccess[1]],
    });
  });

  it('should return a correct split table for valid input with ignoreAllowList', () => {
    const keyAccess: KeyAccessObject[] = [
      { sid: 'split1', type: 'remote', url: 'https://kas1', protocol: 'kas' },
      { sid: 'split2', type: 'remote', url: 'https://kas2', protocol: 'kas' },
    ];
    const allowedKases = new OriginAllowList([], true);

    const result = TDF.splitLookupTableFactory(keyAccess, allowedKases);

    expect(result).to.deep.equal({
      split1: [keyAccess[0]],
      split2: [keyAccess[1]],
    });
  });

  it('should throw UnsafeUrlError for disallowed KASes', () => {
    const keyAccess: KeyAccessObject[] = [
      { sid: 'split1', type: 'remote', url: 'https://kas1', protocol: 'kas' },
      { sid: 'split2', type: 'remote', url: 'https://kas3', protocol: 'kas' }, // kas3 is not allowed
    ];
    const allowedKases = new OriginAllowList(['https://kas1']);

    expect(() => TDF.splitLookupTableFactory(keyAccess, allowedKases)).to.throw(
      UnsafeUrlError,
      'Unreconstructable key - disallowed KASes include: ["https://kas3"] from splitIds ["split1","split2"]'
    );
  });

  it('should keep duplicate URLs in the same splitId as alternatives (DSPX-3379)', () => {
    const keyAccess: KeyAccessObject[] = [
      { sid: 'split1', type: 'remote', url: 'https://kas1', protocol: 'kas' },
      { sid: 'split1', type: 'remote', url: 'https://kas1', protocol: 'kas' },
    ];
    const allowedKases = new OriginAllowList(['https://kas1']);

    expect(TDF.splitLookupTableFactory(keyAccess, allowedKases)).to.deep.equal({
      split1: [keyAccess[0], keyAccess[1]],
    });
  });

  it('should keep same-KAS different-kid entries as alternatives (DSPX-3379)', () => {
    const keyAccess: KeyAccessObject[] = [
      { sid: 'split1', type: 'remote', url: 'https://kas1', protocol: 'kas', kid: 'k1' },
      { sid: 'split1', type: 'remote', url: 'https://kas1', protocol: 'kas', kid: 'k2' },
    ];
    const allowedKases = new OriginAllowList(['https://kas1']);

    expect(TDF.splitLookupTableFactory(keyAccess, allowedKases)).to.deep.equal({
      split1: [keyAccess[0], keyAccess[1]],
    });
  });

  it('should handle empty keyAccess array', () => {
    const keyAccess: KeyAccessObject[] = [];
    const allowedKases = new OriginAllowList([]);

    const result = TDF.splitLookupTableFactory(keyAccess, allowedKases);

    expect(result).to.deep.equal({});
  });

  it('should handle empty allowedKases array', () => {
    const keyAccess: KeyAccessObject[] = [
      { sid: 'split1', type: 'remote', url: 'https://kas1', protocol: 'kas' },
    ];
    const allowedKases = new OriginAllowList([]);

    expect(() => TDF.splitLookupTableFactory(keyAccess, allowedKases)).to.throw(
      InvalidFileError,
      'Unreconstructable key - disallowed KASes include: ["https://kas1"]'
    );
  });

  it('should handle cases where sid is undefined', () => {
    const keyAccess: KeyAccessObject[] = [
      { sid: undefined, type: 'remote', url: 'https://kas1', protocol: 'kas' },
    ];
    const allowedKases = ['https://kas1'];

    const result = TDF.splitLookupTableFactory(keyAccess, new OriginAllowList(allowedKases));

    expect(result).to.deep.equal({
      '': [keyAccess[0]],
    });
  });
});
