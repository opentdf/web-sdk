/**
 *
 * Copyright (c) 2016 SafeBash
 * Cryptography consultant: Andrew Kozlik, Ph.D.
 *
 * @link https://github.com/safebash/opencrypto
 *
 */

/**
 * MIT License
 *
 * Copyright (c) 2016 SafeBash
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import { keyAlgorithmToPublicKeyAlgorithm } from '../access.js';
import { ConfigurationError } from '../errors.js';
import { AlgorithmName, CipherType, HashType, KeyFormat, KeyType, KeyUsageType } from './enums.js';

const KEY_USAGE_DERIVE_KEY = 'deriveKey';

interface KeyAgreementOptions {
  bitLength: number;
  hkdfHash: HashAlgorithmIdentifier;
  hkdfInfo: Uint8Array;
  hkdfSalt: Uint8Array | ArrayBuffer;
  keyCipher: string;
  keyLength: number;
  keyUsages: KeyUsage[];
  isExtractable: boolean;
}

/**
 *
 * ECDH Key Agreement
 * - publicKey          {CryptoKey}     default: "undefined"
 * - privateKey         {CryptoKey}     default: "undefined"
 * - options            {Object}        default: { bitLength: 256, hkdfHash: 'SHA-512', hkdfSalt: "new UInt8Array()", hkdfInfo: "new UInt8Array()", keyCipher: 'AES-GCM', keyLength: 256, keyUsages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 */
export async function keyAgreement(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  options: Partial<KeyAgreementOptions> = {
    bitLength: 256,
    hkdfHash: HashType.Sha256,
    hkdfInfo: new Uint8Array(),
    hkdfSalt: new Uint8Array(),
    keyCipher: CipherType.AesGcm,
    keyLength: 256,
    keyUsages: [
      KeyUsageType.Encrypt,
      KeyUsageType.Decrypt,
      KeyUsageType.UnwrapKey,
      KeyUsageType.WrapKey,
    ],
    isExtractable: true,
  }
): Promise<CryptoKey> {
  for (const k of [privateKey, publicKey]) {
    const mechanism = keyAlgorithmToPublicKeyAlgorithm(k.algorithm);
    if (mechanism !== 'ec:secp256r1') {
      throw new ConfigurationError(
        `${k.type} CryptoKey is expected to be of type ECDSA or ECDH, not [${k.algorithm?.name}]`
      );
    }
  }

  if (privateKey.type !== KeyType.Private) {
    throw new ConfigurationError(
      `Expected input of privateKey to be a CryptoKey of type private, not [${privateKey.type}]`
    );
  }

  if (publicKey.type !== KeyType.Public) {
    throw new ConfigurationError(
      `Expected input of publicKey to be a CryptoKey of type public, not [${publicKey.type}]`
    );
  }

  const {
    hkdfInfo = new Uint8Array(),
    hkdfSalt = new Uint8Array(),
    keyCipher = CipherType.AesGcm,
    keyLength = 256,
    isExtractable = true,
    keyUsages = [
      KeyUsageType.Encrypt,
      KeyUsageType.Decrypt,
      KeyUsageType.UnwrapKey,
      KeyUsageType.WrapKey,
    ],
  } = options;

  const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: AlgorithmName.ECDH,
      public: publicKey,
    },
    privateKey,
    256
  );

  const ikm = await crypto.subtle.importKey(
    KeyFormat.Raw,
    sharedSecret,
    {
      name: AlgorithmName.HKDF,
    },
    false,
    ['deriveKey']
  );

  const symmetricKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: hkdfSalt,
      info: hkdfInfo,
    },
    ikm,
    {
      name: keyCipher,
      length: keyLength,
    },
    isExtractable,
    keyUsages
  );

  return symmetricKey;
}
