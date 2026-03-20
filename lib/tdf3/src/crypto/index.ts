/**
 * This file is for using native crypto in the browser.
 *
 * @private
 */

import { type CryptoService, type SymmetricKey } from './declarations.js';
import {
  decrypt,
  digest,
  encrypt,
  generateKey,
  hex2Ab,
  hmac,
  importSymmetricKey,
  mergeSymmetricKeys,
  randomBytes,
  randomBytesAsHex,
  verifyHmac,
} from './core/symmetric.js';
import { keySplit } from '../utils/keysplit.js';
import { unwrapSymmetricKey, wrapSymmetricKey } from './core/keys.js';
import {
  decryptWithPrivateKey,
  encryptWithPublicKey,
  generateKeyPair,
  generateSigningKeyPair,
  rsaOaepSha1,
  rsaPkcs1Sha256,
} from './core/rsa.js';
import { deriveKeyFromECDH, generateECKeyPair } from './core/ec.js';
import { sign, verify } from './core/signing.js';
import {
  exportPrivateKeyPem,
  exportPublicKeyJwk,
  exportPublicKeyPem,
  extractPublicKeyPem,
  importPrivateKey,
  importPublicKey,
  jwkToPublicKeyPem,
  parsePublicKeyPem,
  publicKeyPemToJwk,
} from './core/key-format.js';

export const isSupported = typeof globalThis?.crypto !== 'undefined';
export const method = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
export const name = 'BrowserNativeCryptoService';

/**
 * Split a symmetric key into N shares using XOR secret sharing.
 * Key bytes are extracted internally for splitting.
 * HSM implementations cannot extract bytes and should throw ConfigurationError.
 *
 * NOTE: This wrapper lives in index.ts (instead of core/symmetric.ts) because it
 * needs DefaultCryptoService for keySplit() randomness. Moving it to core/symmetric
 * would require importing DefaultCryptoService and create a circular dependency.
 */
export async function splitSymmetricKey(
  key: SymmetricKey,
  numShares: number
): Promise<SymmetricKey[]> {
  const keyBytes = unwrapSymmetricKey(key);
  const splits = await keySplit(keyBytes, numShares, DefaultCryptoService);
  return splits.map(wrapSymmetricKey);
}

export {
  decrypt,
  decryptWithPrivateKey,
  deriveKeyFromECDH,
  digest,
  encrypt,
  encryptWithPublicKey,
  exportPrivateKeyPem,
  exportPublicKeyJwk,
  exportPublicKeyPem,
  extractPublicKeyPem,
  generateECKeyPair,
  generateKey,
  generateKeyPair,
  generateSigningKeyPair,
  hex2Ab,
  hmac,
  importPrivateKey,
  importPublicKey,
  importSymmetricKey,
  jwkToPublicKeyPem,
  mergeSymmetricKeys,
  parsePublicKeyPem,
  publicKeyPemToJwk,
  randomBytes,
  randomBytesAsHex,
  rsaOaepSha1,
  rsaPkcs1Sha256,
  sign,
  verify,
  verifyHmac,
};

export const DefaultCryptoService: CryptoService = {
  name,
  method,
  decrypt,
  decryptWithPrivateKey,
  deriveKeyFromECDH,
  digest,
  encrypt,
  encryptWithPublicKey,
  exportPublicKeyJwk,
  exportPrivateKeyPem,
  exportPublicKeyPem,
  extractPublicKeyPem,
  generateECKeyPair,
  generateKey,
  generateKeyPair,
  generateSigningKeyPair,
  importPrivateKey,
  importPublicKey,
  importSymmetricKey,
  jwkToPublicKeyPem,
  mergeSymmetricKeys,
  parsePublicKeyPem,
  randomBytes,
  hmac,
  verifyHmac,
  sign,
  splitSymmetricKey,
  verify,
};
