/* globals window describe it chai bufferToHex fixtures_basicExample */
import { expect } from '@esm-bundle/chai';

import { decrypt, encrypt } from '../src/nanotdf-crypto/index.js';

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
});
