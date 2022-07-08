import constants from 'constants';
import * as Crypto from 'crypto';

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
  payload: Binary,
  key: Binary,
  iv: Binary,
  algorithm: string
): Promise<EncryptResult> {
  console.assert(typeof payload === 'object');
  console.assert(typeof key === 'object');
  console.assert(typeof iv === 'object');

  const alg = selectAlgorithm(algorithm);
  if (alg === 'aes-256-gcm') {
    return _doGcmEncryptSync(payload, key, iv);
  }

  // CBC
  console.assert(algorithm === 'aes-256-cbc');
  return cbcCrypt(true, payload, key, iv);
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
  payload: Binary,
  key: Binary,
  iv: Binary,
  algorithm?: string,
  authTag?: Binary
): Promise<DecryptResult> {
  console.assert(typeof payload === 'object');
  console.assert(typeof key === 'object');
  console.assert(typeof iv === 'object');

  // @ts-ignore
  const alg = selectAlgorithm(algorithm);
  if (alg === 'aes-256-gcm') {
    console.assert(typeof authTag === 'object');
    return _doGcmDecryptSync(payload, key, iv, authTag);
  }

  // CBC
  console.assert(algorithm === 'aes-256-cbc');
  return cbcCrypt(false, payload, key, iv);
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
      // @ts-ignore
      const cleartext = Crypto.privateDecrypt(key, Buffer.from(payload, 'base64'));
      return resolve(Binary.fromBuffer(cleartext));
    } catch (e) {
      reject(e);
    }
  });
}

function cbcCrypt(
  cipher: boolean,
  payload: Binary,
  key: Binary,
  iv: Binary
): Promise<DecryptResult> {
  return new Promise((resolve, reject) => {
    try {
      const cryptoStream = (cipher ? Crypto.createCipheriv : Crypto.createDecipheriv)(
        'aes-256-cbc',
        key.asBuffer(),
        iv.asBuffer()
      );

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
      // @ts-ignore
      const cryptoStream = Crypto.createCipheriv('aes-256-gcm', key.asBuffer(), iv.asBuffer());

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
  authTag?: Binary
): Promise<DecryptResult> {
  return new Promise((resolve, reject) => {
    try {
      // @ts-ignore
      const cryptoStream = Crypto.createDecipheriv('aes-256-gcm', key.asBuffer(), iv.asBuffer());

      if (authTag) {
        cryptoStream.setAuthTag(authTag.asBuffer());
      }
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

function randomBytesAsHex(size: number) {
  return Crypto.randomBytes(size).toString('hex');
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
      // @ts-ignore
      const ciphertext = Crypto.publicEncrypt(key, Buffer.from(payload.asBuffer()));
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
  // @ts-ignore
  if (!isValidAsymmetricKeySize(size, minKeySize)) {
    throw new Error('Invalid key size requested');
  }

  const { generateKeyPair } = Crypto;

  return new Promise((resolve, reject) => {
    const keySize = !size ? minKeySize : size;

    generateKeyPair(
      'rsa',
      {
        modulusLength: keySize,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
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
  // @ts-ignore
  const hash = Crypto.createHash('sha256');
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
  // @ts-ignore
  const hmacObj = Crypto.createHmac('sha256', decoded);

  // FIXME: defaults to utf8 encoding. Is this what we want
  hmacObj.update(content);
  const digest = hmacObj.digest('hex');

  return Promise.resolve(digest);
}

function hex2Ab(content: string): ArrayBuffer {
  return Buffer.from(content, 'hex').buffer;
}

export {
  encrypt,
  decrypt,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  generateKey,
  generateKeyPair,
  generateInitializationVector,
  hex2Ab,
  hmac,
  randomBytesAsHex,
  sha256,
};
