import { expect } from 'chai';

import { TDF, fetchKasPublicKey } from '../../../tdf3/src/tdf.js';
import * as cryptoService from '../../../tdf3/src/crypto/index.js';
import { AesGcmCipher } from '../../../tdf3/src/ciphers/aes-gcm-cipher.js';
import { TdfError } from '../../../src/errors.js';
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
  it('constructs', () => {
    const actual = new TDF({ cryptoService });
    expect(actual).to.be.an.instanceof(TDF);
  });

  it('creates', () => {
    const actual = TDF.create({ cryptoService });
    expect(actual).to.be.an.instanceof(TDF);
  });

  it('allowedKases', () => {
    const cfg = { allowedKases: ['https://local.virtru.com'], cryptoService };
    const actual = TDF.create(cfg);
    expect(actual.allowedKases).to.contain('https://local.virtru.com');
  });

  it('Encodes the postMessage origin properly in wrapHtml', () => {
    const cipherText = 'abcezas123';
    const transferUrl = 'https://local.virtru.com/start?htmlProtocol=1';
    const wrapped = TDF.wrapHtml(
      Buffer.from(cipherText),
      JSON.stringify({ thisIs: 'metadata' }),
      transferUrl
    );
    const rawHtml = new TextDecoder().decode(wrapped);
    expect(rawHtml).to.include("'https://local.virtru.com', [channel.port2]);");
  });

  it('Round Trip wrapHtml and unwrapHtml', () => {
    const cipherText = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2]);
    const transferUrl = 'https://local.virtru.com/start?htmlProtocol=1';
    const wrapped = TDF.wrapHtml(cipherText, JSON.stringify({ thisIs: 'metadata' }), transferUrl);
    expect(TDF.unwrapHtml(wrapped)).to.eql(cipherText);
    expect(TDF.unwrapHtml(wrapped.buffer)).to.eql(cipherText);
    expect(TDF.unwrapHtml(new TextDecoder().decode(wrapped))).to.eql(cipherText);
  });

  it('should fail on invalid cypher param', () => {
    try {
      TDF.create({ cryptoService }).createCipher('nonexistent cypher');
    } catch (e) {
      expect(e.message).to.include('nonexistent cypher');
    }
  });

  it('should return cypher', () => {
    const cypher = TDF.create({ cryptoService }).createCipher('aes-256-gcm');
    expect(cypher instanceof AesGcmCipher).to.equal(true);
  });

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

  it('should ensure that policy id is uuid format', async () => {
    const uuid = await TDF.create({ cryptoService }).generatePolicyUuid();
    expect(uuid).to.match(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });
});

describe('fetchKasPublicKey', async () => {
  it('missing kas names throw', async () => {
    try {
      await fetchKasPublicKey('');
      expect.fail('did not throw');
    } catch (e) {
      expect(e).to.be.an.instanceof(TdfError);
    }
  });

  it('localhost kas is valid', async () => {
    const pk2 = await fetchKasPublicKey('http://localhost:3000');
    expect(pk2.pem).to.include('BEGIN CERTIFICATE');
    expect(pk2.kid).to.equal('kid-a');
  });
});
