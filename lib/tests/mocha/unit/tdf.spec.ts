import { expect } from 'chai';

import * as TDF from '../../../tdf3/src/tdf.js';
import { KeyAccessObject } from '../../../tdf3/src/models/key-access.js';
import { OriginAllowList } from '../../../src/access.js';
import { ConfigurationError, InvalidFileError, UnsafeUrlError } from '../../../src/errors.js';

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

describe('TDF', () => {
  it('should return key', async () => {
    const pem = await TDF.extractPemFromKeyString(sampleCert);
    expect(pem).to.include('-----BEGIN PUBLIC KEY-----');
    expect(pem).to.include('-----END PUBLIC KEY-----');
  });

  it('should return pem', async () => {
    const sampleKey = sampleCert
      .replace('BEGIN CERTIFICATE', 'BEGIN PUBLIC KEY')
      .replace('END CERTIFICATE', 'END PUBLIC KEY');
    const pem = await TDF.extractPemFromKeyString(sampleKey);
    expect(pem).to.equal(sampleKey);
  });
});

describe('fetchKasPublicKey', async () => {
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
      expect(() => {
        throw e;
      }).to.throw(ConfigurationError);
    }
  });

  it('localhost kas is valid', async () => {
    const pk2 = await TDF.fetchKasPublicKey('http://localhost:3000');
    expect(pk2.publicKey).to.include('BEGIN CERTIFICATE');
    expect(pk2.kid).to.equal('r1');
  });

  it('invalid algorithms', async () => {
    try {
      await TDF.fetchKasPublicKey('http://localhost:3000', 'rsa:512' as any as 'rsa:2048'); //ts-ignore
      expect.fail('did not throw');
    } catch (e) {
      expect(() => {
        throw e;
      }).to.throw(ConfigurationError);
    }
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
      split1: { 'https://kas1': keyAccess[0] },
      split2: { 'https://kas2': keyAccess[1] },
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
      split1: { 'https://kas1': keyAccess[0] },
      split2: { 'https://kas2': keyAccess[1] },
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

  it('should throw for duplicate URLs in the same splitId', () => {
    const keyAccess: KeyAccessObject[] = [
      { sid: 'split1', type: 'remote', url: 'https://kas1', protocol: 'kas' },
      { sid: 'split1', type: 'remote', url: 'https://kas1', protocol: 'kas' }, // duplicate URL in same splitId
    ];
    const allowedKases = new OriginAllowList(['https://kas1']);

    expect(() => TDF.splitLookupTableFactory(keyAccess, allowedKases)).to.throw(
      InvalidFileError,
      'TODO: Fallback to no split ids. Repetition found for [https://kas1] on split [split1]'
    );
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
      '': { 'https://kas1': keyAccess[0] },
    });
  });
});
