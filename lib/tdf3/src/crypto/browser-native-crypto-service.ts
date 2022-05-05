/* globals msCrypto */
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
import IENativeShim from './ie-native-shim';
import { TdfDecryptError } from '../errors';
import { formatAsPem, isValidAsymmetricKeySize, removePemFormatting } from './crypto-utils';

// Used to pass into native crypto functions
const METHODS: KeyUsage[] = ['encrypt', 'decrypt'];

let nativeCrypto: Crypto;
let subtle: SubtleCrypto;
// let subtle: { importKey: any; encrypt: any; decrypt: any; generateKey?: any; exportKey?: any; digest?: any; sign?: any; };

if (typeof crypto !== 'undefined') {
  // eslint-disable-next-line
  // @ts-ignore: support older safari
  subtle = crypto.subtle || crypto.webkitSubtle;
  nativeCrypto = crypto;
} else {
  // eslint-disable-next-line
  // @ts-ignore: support IE11
  if (typeof msCrypto !== 'undefined') {
    // eslint-disable-next-line
    // @ts-ignore: support IE11
    subtle = IENativeShim;
    // eslint-disable-next-line
    // @ts-ignore: support IE11
    nativeCrypto = msCrypto;
  }
}

// These are the required functions we need to support using the native crypto
// @ts-ignore
if (!nativeCrypto || !subtle || !subtle.importKey || !subtle.encrypt || !subtle.decrypt) {
  // @ts-ignore
  nativeCrypto = undefined;
  // @ts-ignore
  subtle = undefined;
}

const RSA_IMPORT_PARAMS: RsaHashedImportParams = {
  name: 'RSA-OAEP',
  hash: {
    name: 'SHA-1',
  },
};

/**
 * Get a DOMString representing the algorithm to use for an
 * asymmetric key generation.
 * @param isGenerate (only used for subtle.generateKey())
 * @param size
 * @return {DOMString} Algorithm to use
 */
function getRsaHashedKeyGenParams(size?: number): RsaHashedKeyGenParams {
  return {
    ...RSA_IMPORT_PARAMS,
    modulusLength: size || MIN_ASYMMETRIC_KEY_SIZE_BITS,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 24 bit representation of 65537
  };
}

/**
 * Generate a random hex key
 * @return New key as a hex string
 */
function generateKey(length?: number): string {
  return randomBytesAsHex(length || 32);
}

/**
 * Generate an RSA key pair
 * @see    {@link https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey}
 * @param  size in bits
 */
async function generateKeyPair(size: number): Promise<PemKeyPair> {
  const minKeySize = MIN_ASYMMETRIC_KEY_SIZE_BITS;

  if (!isValidAsymmetricKeySize(size, minKeySize)) {
    throw new Error('Invalid key size requested');
  }

  const algoDomString = getRsaHashedKeyGenParams(size);

  const keys = await subtle.generateKey(algoDomString, true, METHODS);
  const [exPublic, exPrivate] = await Promise.all([
    // @ts-ignore
    subtle.exportKey('spki', keys.publicKey),
    // @ts-ignore
    subtle.exportKey('pkcs8', keys.privateKey),
  ]);
  const publicBase64String = Binary.fromArrayBuffer(exPublic).asBuffer().toString('base64');
  const privateBase64String = Binary.fromArrayBuffer(exPrivate).asBuffer().toString('base64');
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
async function encryptWithPublicKey(payload: Binary, publicKey: string): Promise<Binary> {
  console.assert(typeof payload === 'object');
  console.assert(typeof publicKey === 'string');

  const algoDomString = RSA_IMPORT_PARAMS;

  // Web Crypto APIs don't work with PEM formatted strings
  publicKey = removePemFormatting(publicKey);

  const keyBuffer = Buffer.from(publicKey, 'base64').buffer;
  const cryptoKey = await subtle.importKey('spki', keyBuffer, algoDomString, false, ['encrypt']);
  const result = await subtle.encrypt({ name: 'RSA-OAEP' }, cryptoKey, payload.asArrayBuffer());
  return Binary.fromArrayBuffer(result);
}

/**
 * Generate a 16-byte initialization vector
 * @return {String}
 */
function generateInitializationVector(length?: number): string {
  return randomBytesAsHex(length || 16);
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
function randomBytesAsHex(length: number): string {
  // Create a typed array of the correct length to fill
  const random = new Uint8Array(length);
  nativeCrypto.getRandomValues(random);

  const binary = Binary.fromArrayBuffer(random.buffer);

  // Convert the byte array to a hex string
  let key = '';
  const arr = binary.asByteArray();
  for (let i = 0; i < length; i++) {
    let str = arr[i].toString(16);
    if (str.length === 1) {
      str = `0${str}`;
    }
    key += str;
  }

  return key;
}

/**
 * Decrypt a public-key encrypted payload with a private key
 * @param  encryptedPayload  Payload to decrypt
 * @param  privateKey        PEM formatted private key
 * @return Decrypted payload
 */
async function decryptWithPrivateKey(
  encryptedPayload: Binary,
  privateKey: string
): Promise<Binary> {
  console.assert(typeof encryptedPayload === 'object');
  console.assert(typeof privateKey === 'string');

  const algoDomString = RSA_IMPORT_PARAMS;

  // Web Crypto APIs don't work with PEM formatted strings
  const keyDataString = removePemFormatting(privateKey);
  const keyData = Buffer.from(keyDataString, 'base64').buffer;

  const key = await subtle.importKey('pkcs8', keyData, algoDomString, false, ['decrypt']);
  const payload = await subtle.decrypt({ name: 'RSA-OAEP' }, key, encryptedPayload.asArrayBuffer());
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
function decrypt(
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
function encrypt(
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
  const encrypted = await subtle.encrypt(algoDomString, importedKey, payloadBuffer);
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

  const decrypted = await subtle
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
  return subtle.importKey('raw', key.asArrayBuffer(), algorithm, true, METHODS);
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
async function sha256(content: string): Promise<string> {
  const buffer = new TextEncoder().encode(content);
  const hashBuffer = await subtle.digest('SHA-256', buffer);
  return Buffer.from(new Uint8Array(hashBuffer)).toString('hex');
}

/**
 * Create an HMAC SHA256 hash
 * @param  key     Key string
 * @param  content Content string
 * @return Hex hash
 */
async function hmac(key: string, content: string): Promise<string> {
  const contentBuffer = new TextEncoder().encode(content);
  const keyBuffer = hex2Ab(key);
  const cryptoKey = await subtle.importKey(
    'raw',
    keyBuffer,
    {
      name: 'HMAC',
      hash: { name: 'SHA-256' },
    },
    true,
    ['sign', 'verify']
  );
  const hashBuffer = await subtle.sign('HMAC', cryptoKey, contentBuffer);
  return Buffer.from(new Uint8Array(hashBuffer)).toString('hex');
}

/**
 * Create an ArrayBuffer from a hex string.
 * https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String?hl=en
 * @param  hex - Hex string
 */
function hex2Ab(hex: string): ArrayBuffer {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bufferView = new Uint8Array(buffer);

  for (let i = 0; i < hex.length; i += 2) {
    bufferView[i / 2] = parseInt(hex.substr(i, 2), 16);
  }

  return buffer;
}

export default {
  decrypt,
  decryptWithPrivateKey,
  encrypt,
  encryptWithPublicKey,
  generateInitializationVector,
  generateKey,
  generateKeyPair,
  hex2Ab,
  hmac,
  isSupported: nativeCrypto !== undefined,
  method: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  name: 'BrowserNativeCryptoService',
  sha256,
};
