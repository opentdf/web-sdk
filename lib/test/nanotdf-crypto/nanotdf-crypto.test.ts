import { expect } from '@esm-bundle/chai';

import { decrypt, encrypt, extractPublicFromCertToCrypto } from '../../src/nanotdf-crypto/index.js';

/**
 * Alice will act as data creator
 * Bob will act as data recipient
 */
describe('NanoTDF Crypto', () => {
  const plainTextExpected = 'Lorem Ipsum';
  const txtEnc = new TextEncoder();
  const txtDec = new TextDecoder();
  let aliceKeyPair: CryptoKeyPair;
  let aliceSecKey: CryptoKey;
  let bobKeyPair: CryptoKeyPair;
  let bobSecKey: CryptoKey;

  before(async () => {
    aliceKeyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-521',
      },
      false,
      ['deriveKey']
    );

    bobKeyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-521',
      },
      false,
      ['deriveKey']
    );

    if (!aliceKeyPair.privateKey) {
      throw new Error('incomplete ephemeral key');
    }
    aliceSecKey = await window.crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: bobKeyPair.publicKey,
      },
      aliceKeyPair.privateKey,
      {
        name: 'AES-GCM',
        length: 256,
      },
      false,
      ['encrypt', 'decrypt']
    );

    if (!bobKeyPair.privateKey) {
      throw new Error('incomplete ephemeral key');
    }
    bobSecKey = await window.crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: aliceKeyPair.publicKey,
      },
      bobKeyPair.privateKey,
      {
        name: 'AES-GCM',
        length: 256,
      },
      false,
      ['encrypt', 'decrypt']
    );
  });

  it('should encrypt and decrypt data with same key', async () => {
    const encryptorKey = aliceSecKey;
    const encrypteeKey = aliceSecKey;

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const cipherText = await encrypt(encryptorKey, txtEnc.encode(plainTextExpected), iv);
    expect(cipherText).to.be.instanceOf(ArrayBuffer);
    expect(txtDec.decode(cipherText)).not.to.be.equal(plainTextExpected);

    const plainText = await decrypt(encrypteeKey, new Uint8Array(cipherText), iv);
    expect(txtDec.decode(plainText)).to.be.equal(plainTextExpected);
  });

  it('should encrypt and decrypt data with shared key', async () => {
    const encryptorKey = aliceSecKey;
    const encrypteeKey = bobSecKey;

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const cipherText = await encrypt(encryptorKey, txtEnc.encode(plainTextExpected), iv, 0);
    expect(cipherText).to.be.instanceOf(ArrayBuffer);
    expect(txtDec.decode(cipherText)).not.to.be.equal(plainTextExpected);

    const plainText = await decrypt(encrypteeKey, new Uint8Array(cipherText), iv);
    expect(txtDec.decode(plainText)).to.be.equal(plainTextExpected);
  });

  it('handles KAS public key', async () => {
    const pem = `-----BEGIN CERTIFICATE-----
MIIBCzCBsgIJAL1qc/lWpG3HMAoGCCqGSM49BAMCMA4xDDAKBgNVBAMMA2thczAe
Fw0yMTA5MTUxNDExNDlaFw0yMjA5MTUxNDExNDlaMA4xDDAKBgNVBAMMA2thczBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABH2VM7Ws9SVr19rywr/o3fewDBj+170/
6y8zo4leVaJqCl76Nd9QfDNy4KjNCtmmjo6ftTS+iFAhnPCeugAJOWUwCgYIKoZI
zj0EAwIDSAAwRQIhAIFdrqhwvgL8ctPjUtmULXmg2ii0PFKg/Mox2GiCVXQdAiAW
UDdeafEoprE+qc4paMmbWoEpRXLlo+3S7rnc5T12Kw==
-----END CERTIFICATE-----`;
    const key = await extractPublicFromCertToCrypto(pem);
    expect(key.algorithm).to.eql({ name: 'ECDH', namedCurve: 'P-256' });
    expect(key.extractable).to.be.true;
    expect(key.usages).to.be.empty;
  });

  it('handles another example cert', async () => {
    // Copied from https://github.com/panva/jose/blob/main/docs/functions/key_import.importX509.md
    const pem = `-----BEGIN CERTIFICATE-----
        MIIBXjCCAQSgAwIBAgIGAXvykuMKMAoGCCqGSM49BAMCMDYxNDAyBgNVBAMMK3Np
        QXBNOXpBdk1VaXhXVWVGaGtjZXg1NjJRRzFyQUhXaV96UlFQTVpQaG8wHhcNMjEw
        OTE3MDcwNTE3WhcNMjIwNzE0MDcwNTE3WjA2MTQwMgYDVQQDDCtzaUFwTTl6QXZN
        VWl4V1VlRmhrY2V4NTYyUUcxckFIV2lfelJRUE1aUGhvMFkwEwYHKoZIzj0CAQYI
        KoZIzj0DAQcDQgAE8PbPvCv5D5xBFHEZlBp/q5OEUymq7RIgWIi7tkl9aGSpYE35
        UH+kBKDnphJO3odpPZ5gvgKs2nwRWcrDnUjYLDAKBggqhkjOPQQDAgNIADBFAiEA
        1yyMTRe66MhEXID9+uVub7woMkNYd0LhSHwKSPMUUTkCIFQGsfm1ecXOpeGOufAh
        v+A1QWZMuTWqYt+uh/YSRNDn
        -----END CERTIFICATE-----`;
    const key = await extractPublicFromCertToCrypto(pem);
    expect(key.algorithm).to.eql({ name: 'ECDH', namedCurve: 'P-256' });
    expect(key.extractable).to.be.true;
    expect(key.usages).to.be.empty;
  });
});
