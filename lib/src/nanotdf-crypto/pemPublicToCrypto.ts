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

import * as base64 from '../encodings/base64.js';
import getCryptoLib from './getCryptoLib.js';
import removeLines from './helpers/removeLines.js';
import arrayBufferToHex from './helpers/arrayBufferToHex.js';

const ECDH = 'ECDH';
const ECDSA = 'ECDSA';
const RSA_OID = '06092a864886f70d010101';
const EC_OID = '06072a8648ce3d0201';
const P256_OID = '06082a8648ce3d030107';
const P384_OID = '06052b81040022';
const P521_OID = '06052b81040023';
const RSA_OAEP = 'RSA-OAEP';
const RSA_PSS = 'RSA-PSS';
const SHA_512 = 'SHA-512';
const SPKI = 'spki';
const CERT_BEGIN = '-----BEGIN CERTIFICATE-----';
const CERT_END = '-----END CERTIFICATE-----';

enum CurveName {
  P_256 = 'P-256',
  P_384 = 'P-384',
  P_512 = 'P-512',
}

enum AlgorithmNames {
  ECDH = 'ECDH',
  ECDSA = 'ECDSA',
  RSA_OAEP = 'RSA-OAEP',
  RSA_PSS = 'RSA-PSS',
}

interface PemPublicToCryptoOptions {
  name?: string;
  hash?: string;
  usages?: KeyUsage[];
  isExtractable: boolean;
}

function getKeyUsages(algorithmName: AlgorithmNames, usages?: KeyUsage[]): KeyUsage[] {
  if (usages) return usages;
  switch (algorithmName) {
    case ECDSA:
      return ['verify'];
    case RSA_OAEP:
      return ['encrypt', 'wrapKey'];
    case RSA_PSS:
      return ['verify'];
    case ECDH:
    default:
      return [];
  }
}

function getAlgorithmName(hex: string, algorithmName?: string): AlgorithmNames | never {
  if (hex.includes(EC_OID)) {
    if (!algorithmName || algorithmName === ECDH) {
      return AlgorithmNames.ECDH;
    } else if (algorithmName === AlgorithmNames.ECDSA) {
      return AlgorithmNames.ECDSA;
    }
  } else if (hex.includes(RSA_OID)) {
    if (!algorithmName || algorithmName === RSA_OAEP) {
      return AlgorithmNames.RSA_OAEP;
    } else if (algorithmName === AlgorithmNames.RSA_PSS) {
      return AlgorithmNames.RSA_PSS;
    }
  }
  throw new TypeError(`Invalid public key, ${algorithmName}`);
}

function getCurveName(hex: string): string | never {
  if (hex.includes(P256_OID)) {
    return CurveName.P_256;
  } else if (hex.includes(P384_OID)) {
    return CurveName.P_384;
  } else if (hex.includes(P521_OID)) {
    return CurveName.P_512;
  }
  throw new Error('Unsupported curve name or invalid key');
}

/**
 *
 * Converts asymmetric public key from PEM to CryptoKey
 * - publicKey       {String}      default: "undefined" PEM public key
 * - options         {Object}      default: (depends on algorithm)
 * -- ECDH: { name: 'ECDH', usages: [], isExtractable: true }
 * -- ECDSA: { name: 'ECDSA', usages: ['verify'], isExtractable: true }
 * -- RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, usages: ['encrypt', 'wrapKey'], isExtractable: true }
 * -- RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, usages: ['verify'], isExtractable: true }
 */
export default async function pemPublicToCrypto(
  pem: string,
  options: PemPublicToCryptoOptions = {
    isExtractable: true,
  }
): Promise<CryptoKey> {
  const crypto = getCryptoLib();

  pem = pem.replace('-----BEGIN PUBLIC KEY-----', '');
  pem = pem.replace('-----END PUBLIC KEY-----', '');
  const b64 = removeLines(pem);
  const arrayBuffer = base64.decodeArrayBuffer(b64);
  const hex = arrayBufferToHex(arrayBuffer);

  const algorithmName = getAlgorithmName(hex, options.name);
  const keyUsages = getKeyUsages(algorithmName, options.usages);

  if (algorithmName === AlgorithmNames.ECDH || algorithmName === AlgorithmNames.ECDSA) {
    return crypto.importKey(
      SPKI,
      arrayBuffer,
      {
        name: algorithmName,
        namedCurve: getCurveName(hex),
      },
      options.isExtractable,
      keyUsages
    );
  } else if (
    algorithmName === AlgorithmNames.RSA_OAEP ||
    algorithmName === AlgorithmNames.RSA_PSS
  ) {
    return crypto.importKey(
      SPKI,
      arrayBuffer,
      {
        name: algorithmName,
        hash: {
          name: options.hash || SHA_512,
        },
      },
      options.isExtractable,
      keyUsages
    );
  } else {
    throw new TypeError('Invalid public key');
  }
}

export async function extractPublicFromCertToCrypto(
  crt: string,
  options: PemPublicToCryptoOptions = {
    isExtractable: true,
  }
): Promise<CryptoKey> {
  const crypto = getCryptoLib();

  crt = crt.replace(CERT_BEGIN, '');
  crt = crt.replace(CERT_END, '');
  const b64 = removeLines(crt);
  const arrayBuffer = base64.decodeArrayBuffer(b64);
  const hex = arrayBufferToHex(arrayBuffer);

  const algorithmName = getAlgorithmName(hex, options.name);
  const keyUsages = getKeyUsages(algorithmName, options.usages);

  if (algorithmName === AlgorithmNames.ECDH || algorithmName === AlgorithmNames.ECDSA) {
    return crypto.importKey(
      'pkcs8',
      arrayBuffer,
      {
        name: algorithmName,
        namedCurve: getCurveName(hex),
      },
      options.isExtractable,
      keyUsages
    );
  } else if (
    algorithmName === AlgorithmNames.RSA_OAEP ||
    algorithmName === AlgorithmNames.RSA_PSS
  ) {
    return crypto.importKey(
      'pkcs8',
      arrayBuffer,
      {
        name: algorithmName,
        hash: {
          name: options.hash || SHA_512,
        },
      },
      options.isExtractable,
      keyUsages
    );
  } else {
    throw new TypeError('Invalid public key');
  }
}
