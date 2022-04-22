import constants from 'constants';
import * as Crypto from 'crypto';

import { isStream } from '../utils';
import { Algorithms } from '../ciphers';
import { Binary } from '../binary';
import { TdfDecryptError } from '../errors';
import {
  DecryptResult,
  EncryptResult,
  MIN_ASYMMETRIC_KEY_SIZE_BITS,
  PemKeyPair,
} from './declarations';
import { isValidAsymmetricKeySize } from './crypto-utils';
import { Stream } from 'stream';

let crypto;

try {
  if (typeof window === 'undefined') {
    crypto = Crypto;
  }
} catch (err) {
  /** Ignore errors */
}

/**
 * Encrypt content.
 * @param {Binary} payload - The payload to encrypt
 * @param {Binary} key     - The encryption key
 * @param {Binary} iv      - The initialization vector
 * @param {String} [algorithm] - The algorithm to use for encryption
 * @return {Object} - The encrypted output
 * {
 *   payload: {Binary} - The encrypted payload.
 *   [authTag]: {Binary} The authentication tag generated.
 * }
 * @property
 */

function encrypt(
  payload: Binary | Stream,
  key: Binary,
  iv: Binary,
  algorithm: string
): Promise<EncryptResult> {
  console.assert(typeof payload === 'object');
  console.assert(typeof key === 'object');
  console.assert(typeof iv === 'object');

  const alg = selectAlgorithm(algorithm);
  if (alg === 'aes-256-gcm') {
    return isStream(payload)
      ? _doStreamingGcmEncrypt(payload, key, iv)
      : _doGcmEncryptSync(payload, key, iv);
  }

  // CBC
  console.assert(algorithm === 'aes-256-cbc');
  return isStream(payload)
    ? _doStreamingCrypt('createCipheriv', payload, key, iv)
    : cbcCrypt('createCipheriv', payload, key, iv);
}

/**
 * Decrypt content
 * @param payload The payload to decrypt
 * @param key The encryption key
 * @param iv The initialization vector
 * @param algorithm The algorithm to use for encryption
 * @param authTag The authentication tag for authenticated crypto.
 */
function decrypt(
  payload: Binary | Stream,
  key: Binary,
  iv: Binary,
  algorithm?: string,
  authTag?: Binary
): Promise<DecryptResult> {
  console.assert(typeof payload === 'object');
  console.assert(typeof key === 'object');
  console.assert(typeof iv === 'object');

  const alg = selectAlgorithm(algorithm);
  if (alg === 'aes-256-gcm') {
    console.assert(typeof authTag === 'object');
    return isStream(payload)
      ? _doStreamingGcmDecrypt(payload, key, iv, authTag)
      : _doGcmDecryptSync(payload, key, iv, authTag);
  }

  // CBC
  console.assert(algorithm === 'aes-256-cbc');
  return isStream(payload)
    ? _doStreamingCrypt('createDecipheriv', payload, key, iv)
    : cbcCrypt('createDecipheriv', payload, key, iv);
}

/**
 * Decrypt a public-key encrypted payload with a private key
 * @param  encryptedPayload Payload to decrypt
 * @param  privateKey PEM formatted private key
 */
function decryptWithPrivateKey(encryptedPayload: Binary, privateKey: string): Promise<Binary> {
  console.assert(typeof encryptedPayload === 'object');
  console.assert(typeof privateKey === 'string');

  return new Promise((resolve, reject) => {
    try {
      const key = {
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
      };
      const payload = encryptedPayload.asBuffer().toString('base64');
      const cleartext = crypto.privateDecrypt(key, Buffer.from(payload, 'base64'));
      return resolve(Binary.fromBuffer(cleartext));
    } catch (e) {
      reject(e);
    }
  });
}

function _doStreamingCrypt(
  method: string,
  stream: Stream,
  key: Binary,
  iv: Binary
): Promise<DecryptResult> {
  const cryptoStream = crypto[method]('aes-256-cbc', key.asBuffer(), iv.asBuffer());

  stream.pipe(cryptoStream);

  return Promise.resolve({
    payload: cryptoStream,
  });
}

function _doStreamingGcmEncrypt(stream: Stream, key: Binary, iv: Binary): Promise<EncryptResult> {
  const cryptoStream = crypto.createCipheriv('aes-256-gcm', key.asBuffer(), iv.asBuffer());

  stream.pipe(cryptoStream);

  return Promise.resolve({
    payload: cryptoStream,
  });
}

function _doStreamingGcmDecrypt(
  stream: Stream,
  key: Binary,
  iv: Binary,
  authTag: Binary
): Promise<DecryptResult> {
  const cryptoStream = crypto.createDecipheriv('aes-256-gcm', key.asBuffer(), iv.asBuffer());

  cryptoStream.setAuthTag(authTag.asBuffer());
  stream.pipe(cryptoStream);

  return Promise.resolve({
    payload: cryptoStream,
  });
}

function cbcCrypt(
  method: string,
  payload: Binary,
  key: Binary,
  iv: Binary
): Promise<DecryptResult> {
  return new Promise((resolve, reject) => {
    try {
      const cryptoStream = crypto[method]('aes-256-cbc', key.asBuffer(), iv.asBuffer());

      const data = cryptoStream.update(payload.asBuffer());
      const final = cryptoStream.final();

      resolve({
        payload: Binary.fromBuffer(Buffer.concat([data, final])),
      });
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Encrypts synchronously using GCM
 * @param payload
 * @param key
 * @param iv
 * @private
 */
function _doGcmEncryptSync(payload: Binary, key: Binary, iv: Binary): Promise<EncryptResult> {
  return new Promise((resolve, reject) => {
    try {
      const cryptoStream = crypto.createCipheriv('aes-256-gcm', key.asBuffer(), iv.asBuffer());

      const data = cryptoStream.update(payload.asBuffer());
      const final = cryptoStream.final();

      const result = {
        payload: Binary.fromBuffer(Buffer.concat([data, final])),
        authTag: Binary.fromBuffer(cryptoStream.getAuthTag()),
      };
      resolve(result);
    } catch (err) {
      reject(err);
    }
  });
}

function _doGcmDecryptSync(
  payload: Binary,
  key: Binary,
  iv: Binary,
  authTag: Binary
): Promise<DecryptResult> {
  return new Promise((resolve, reject) => {
    try {
      const cryptoStream = crypto.createDecipheriv('aes-256-gcm', key.asBuffer(), iv.asBuffer());

      cryptoStream.setAuthTag(authTag.asBuffer());
      const data = cryptoStream.update(payload.asBuffer());
      const final = cryptoStream.final();

      return resolve({
        payload: Binary.fromBuffer(Buffer.concat([data, final])),
      });
    } catch (err) {
      if (err.message.includes('unable to authenticate data')) {
        return reject(new TdfDecryptError(err));
      }

      return reject(err);
    }
  });
}

function selectAlgorithm(algorithm: string) {
  if (algorithm === Algorithms.AES_256_GCM) {
    return 'aes-256-gcm';
  }
  return 'aes-256-cbc';
}

function randomBytesAsHex(size?: number) {
  return crypto.randomBytes(size).toString('hex');
}

function generateInitializationVector(length?: number) {
  return randomBytesAsHex(length || 16);
}

function generateKey(length?: number) {
  return randomBytesAsHex(length || 32);
}

/**
 * Encrypt using a public key.
 * Returns a promise to be consistent with the
 * promise-based browser native implementation.
 * @param payload Payloat to encrypt
 * @param publicKey PEM formatted public key
 * @return Encrypted payload
 */
function encryptWithPublicKey(payload: Binary, publicKey: string): Promise<Binary> {
  console.assert(typeof payload === 'object');
  console.assert(typeof publicKey === 'string');

  return new Promise((resolve, reject) => {
    try {
      const key = {
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
      };
      const ciphertext = crypto.publicEncrypt(key, Buffer.from(payload.asBuffer()));
      return resolve(Binary.fromBuffer(ciphertext));
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Generate an RSA key pair.
 * @param  size in bits
 */
function generateKeyPair(size?: number): Promise<PemKeyPair> {
  const minKeySize = MIN_ASYMMETRIC_KEY_SIZE_BITS;

  if (!isValidAsymmetricKeySize(size, minKeySize)) {
    throw new Error('Invalid key size requested');
  }

  const { generateKeyPair } = Crypto;

  return new Promise((resolve, reject) => {
    const keySize = !size ? minKeySize : size;

    generateKeyPair('rsa', {
      modulusLength: keySize,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      }
    },
      (err, publicKey, privateKey) => {
        if (err) {
          reject(err);
        } else {
          resolve({ publicKey, privateKey });
        }
      }
    );
  });
}

/**
 * Create a SHA256 hash
 * @param  content  String content
 * @return Hex hash
 */
function sha256(content: string) {
  const hash = crypto.createHash('sha256');
  hash.update(content, 'binary');
  return Promise.resolve(hash.digest('hex'));
}

/**
 * Create an HMAC SHA256 hash
 * @param  key Key string
 * @param  content Content string
 * @return Hex hash
 */
function hmac(key: string, content: string): Promise<string> {
  const decoded = Buffer.from(key, 'hex');

  const hmacObj = crypto.createHmac('sha256', decoded);

  // FIXME: defaults to utf8 encoding. Is this what we want
  hmacObj.update(content);
  const digest = hmacObj.digest('hex');

  return Promise.resolve(digest);
}

export default {
  encrypt,
  decrypt,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  generateKey,
  generateKeyPair,
  generateInitializationVector,
  isSupported: crypto !== undefined,
  method: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  sha256,
  hmac,
  randomBytesAsHex,
  name: 'NodeCryptoService',
};
