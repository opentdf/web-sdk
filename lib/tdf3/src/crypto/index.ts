/**
 * This file is for using native crypto in the browser.
 *
 * @private
 */

import { Algorithms } from '../ciphers';
import { Binary } from '../binary';
import {
  DecryptResult,
  EncryptResult,
  MIN_ASYMMETRIC_KEY_SIZE_BITS,
  PemKeyPair,
} from './declarations';
import { TdfDecryptError } from '../errors';
import { formatAsPem, isValidAsymmetricKeySize, removePemFormatting } from './crypto-utils';
import { encodeArrayBuffer as hexEncode } from '../../../src/encodings/hex';
import {
  decodeArrayBuffer as base64Decode,
  encodeArrayBuffer as base64Encode,
} from '../../../src/encodings/base64';

// Used to pass into native crypto functions
const METHODS: KeyUsage[] = ['encrypt', 'decrypt'];

export const isSupported = crypto !== undefined;

export const method = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
export const name = 'BrowserNativeCryptoService';

const RSA_IMPORT_PARAMS: RsaHashedImportParams = {
  name: 'RSA-OAEP',
  hash: {
    name: 'SHA-1',
  },
};

/**
 * Get a DOMString representing the algorithm to use for an
 * asymmetric key generation.
 */
function getRsaHashedKeyGenParams(modulusLength: number): RsaHashedKeyGenParams {
  return {
    ...RSA_IMPORT_PARAMS,
    modulusLength,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 24 bit representation of 65537
  };
}

/**
 * Generate a random hex key
 * @return New key as a hex string
 */
export function generateKey(length?: number): string {
  return randomBytesAsHex(length || 32);
}

/**
 * Generate an RSA key pair
 * @see    {@link https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey}
 * @param  size in bits
 */
export async function generateKeyPair(size?: number): Promise<PemKeyPair> {
  const minKeySize = MIN_ASYMMETRIC_KEY_SIZE_BITS;

  if (!isValidAsymmetricKeySize(size, minKeySize)) {
    throw new Error('Invalid key size requested');
  }

  const algoDomString = getRsaHashedKeyGenParams(size || MIN_ASYMMETRIC_KEY_SIZE_BITS);

  const keys = await crypto.subtle.generateKey(algoDomString, true, METHODS);
  const [exPublic, exPrivate] = await Promise.all([
    crypto.subtle.exportKey('spki', keys.publicKey),
    crypto.subtle.exportKey('pkcs8', keys.privateKey),
  ]);
  const publicBase64String = base64Encode(exPublic);
  const privateBase64String = base64Encode(exPrivate);
  return {
    publicKey: formatAsPem(publicBase64String, 'PUBLIC KEY'),
    privateKey: formatAsPem(privateBase64String, 'PRIVATE KEY'),
  };
}

/**
 * Encrypt using a public key
 * @param payload Payload to encrypt
 * @param publicKey PEM formatted public key
 * @return Encrypted payload
 */
export async function encryptWithPublicKey(payload: Binary, publicKey: string): Promise<Binary> {
  console.assert(typeof payload === 'object');
  console.assert(typeof publicKey === 'string');

  const algoDomString = RSA_IMPORT_PARAMS;

  // Web Crypto APIs don't work with PEM formatted strings
  publicKey = removePemFormatting(publicKey);

  const keyBuffer = base64Decode(publicKey);
  const cryptoKey = await crypto.subtle.importKey('spki', keyBuffer, algoDomString, false, [
    'encrypt',
  ]);
  const result = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    cryptoKey,
    payload.asArrayBuffer()
  );
  return Binary.fromArrayBuffer(result);
}

/**
 * Generate a 16-byte initialization vector
 */
export function generateInitializationVector(length?: number): string {
  return randomBytesAsHex(length || 16);
}

export function randomBytes(length: number): Uint8Array {
  const r = new Uint8Array(length);
  crypto.getRandomValues(r);
  return r;
}

/**
 * Returns a promise to the encryption key as a binary string.
 *
 * Note: This function should almost never fail as it includes a fallback
 * if for some reason the native generate key fails.
 *
 * @param length The key length, defaults to 256
 *
 * @returns The hex string.
 */
export function randomBytesAsHex(length: number): string {
  // Create a typed array of the correct length to fill
  const r = new Uint8Array(length);
  crypto.getRandomValues(r);
  return hexEncode(r.buffer);
}

/**
 * Decrypt a public-key encrypted payload with a private key
 * @param  encryptedPayload  Payload to decrypt
 * @param  privateKey        PEM formatted private keynpmv
 * @return Decrypted payload
 */
export async function decryptWithPrivateKey(
  encryptedPayload: Binary,
  privateKey: string
): Promise<Binary> {
  console.assert(typeof encryptedPayload === 'object');
  console.assert(typeof privateKey === 'string');

  const algoDomString = RSA_IMPORT_PARAMS;

  // Web Crypto APIs don't work with PEM formatted strings
  const keyDataString = removePemFormatting(privateKey);
  const keyData = base64Decode(keyDataString);

  const key = await crypto.subtle.importKey('pkcs8', keyData, algoDomString, false, ['decrypt']);
  const payload = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    key,
    encryptedPayload.asArrayBuffer()
  );
  const bufferView = new Uint8Array(payload);
  return Binary.fromArrayBuffer(bufferView.buffer);
}

/**
 * Decrypt content synchronously
 * @param payload The payload to decrypt
 * @param key     The encryption key
 * @param iv      The initialization vector
 * @param algorithm The algorithm to use for encryption
 * @param authTag The authentication tag for authenticated crypto.
 */
export function decrypt(
  payload: Binary,
  key: Binary,
  iv: Binary,
  algorithm?: string,
  authTag?: Binary
): Promise<DecryptResult> {
  return _doDecrypt(payload, key, iv, algorithm, authTag);
}

/**
 * Encrypt content synchronously
 * @param payload   The payload to encrypt
 * @param key       The encryption key
 * @param iv        The initialization vector
 * @param algorithm The algorithm to use for encryption
 */
export function encrypt(
  payload: Binary,
  key: Binary,
  iv: Binary,
  algorithm?: string
): Promise<EncryptResult> {
  // @ts-ignore
  return _doEncrypt(payload, key, iv, algorithm);
}

async function _doEncrypt(
  payload: Binary,
  key: Binary,
  iv: Binary,
  algorithm: string
): Promise<EncryptResult> {
  console.assert(payload != null);
  console.assert(key != null);
  console.assert(iv != null);

  const payloadBuffer = payload.asArrayBuffer();
  const algoDomString = getSymmetricAlgoDomString(iv, algorithm);

  const importedKey = await _importKey(key, algoDomString);
  const encrypted = await crypto.subtle.encrypt(algoDomString, importedKey, payloadBuffer);
  if (algoDomString.name === 'AES-GCM') {
    return {
      payload: Binary.fromArrayBuffer(encrypted.slice(0, -16)),
      authTag: Binary.fromArrayBuffer(encrypted.slice(-16)),
    };
  }
  return {
    payload: Binary.fromArrayBuffer(encrypted),
  };
}

async function _doDecrypt(
  payload: Binary,
  key: Binary,
  iv: Binary,
  algorithm?: string,
  authTag?: Binary
): Promise<DecryptResult> {
  console.assert(payload != null);
  console.assert(key != null);
  console.assert(iv != null);

  let payloadBuffer = payload.asArrayBuffer();

  // Concat the the auth tag to the payload for decryption
  if (authTag) {
    const authTagBuffer = authTag.asArrayBuffer();
    const gcmPayload = new Uint8Array(payloadBuffer.byteLength + authTagBuffer.byteLength);
    gcmPayload.set(new Uint8Array(payloadBuffer), 0);
    gcmPayload.set(new Uint8Array(authTagBuffer), payloadBuffer.byteLength);
    payloadBuffer = gcmPayload.buffer;
  }

  const algoDomString = getSymmetricAlgoDomString(iv, algorithm);

  const importedKey = await _importKey(key, algoDomString);
  algoDomString.iv = iv.asArrayBuffer();

  const decrypted = await crypto.subtle
    .decrypt(algoDomString, importedKey, payloadBuffer)
    // Catching this error so we can specifically check for OperationError
    .catch((err) => {
      if (err.name === 'OperationError') {
        throw new TdfDecryptError(err);
      }

      throw err;
    });
  return { payload: Binary.fromArrayBuffer(decrypted) };
}

function _importKey(key: Binary, algorithm: AesCbcParams | AesGcmParams) {
  return crypto.subtle.importKey('raw', key.asArrayBuffer(), algorithm, true, METHODS);
}

/**
 * Get a DOMString representing the algorithm to use for a crypto
 * operation. Defaults to AES-CBC.
 * @param  {String|undefined} algorithm
 * @return {DOMString} Algorithm to use
 */
function getSymmetricAlgoDomString(iv: Binary, algorithm?: string): AesCbcParams | AesGcmParams {
  let nativeAlgorithm = 'AES-CBC';
  if (algorithm === Algorithms.AES_256_GCM) {
    nativeAlgorithm = 'AES-GCM';
  }

  return {
    name: nativeAlgorithm,
    iv: iv.asArrayBuffer(),
  };
}

/**
 * Create a SHA256 hash. Code refrenced from MDN:
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
 * @param  content  String content
 * @return Hex hash
 */
export async function sha256(content: string): Promise<string> {
  const buffer = new TextEncoder().encode(content);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return hexEncode(hashBuffer);
}

/**
 * Create an HMAC SHA256 hash
 * @param  key     Key string
 * @param  content Content string
 * @return Hex hash
 */
export async function hmac(key: string, content: string): Promise<string> {
  const contentBuffer = new TextEncoder().encode(content);
  const keyBuffer = hex2Ab(key);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    {
      name: 'HMAC',
      hash: { name: 'SHA-256' },
    },
    true,
    ['sign', 'verify']
  );
  const hashBuffer = await crypto.subtle.sign('HMAC', cryptoKey, contentBuffer);
  return hexEncode(hashBuffer);
}

/**
 * Create an ArrayBuffer from a hex string.
 * https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String?hl=en
 * @param  hex - Hex string
 */
export function hex2Ab(hex: string): ArrayBuffer {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bufferView = new Uint8Array(buffer);

  for (let i = 0; i < hex.length; i += 2) {
    bufferView[i / 2] = parseInt(hex.substr(i, 2), 16);
  }

  return buffer;
}
