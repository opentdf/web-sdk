import sjcl from 'sjcl';
import { pki } from 'node-forge';

import { Algorithms } from '../ciphers';
import { Binary } from '../binary';
import { TdfCorruptError, TdfDecryptError } from '../errors';
import {
  DecryptResult,
  EncryptResult,
  MIN_ASYMMETRIC_KEY_SIZE_BITS,
  PemKeyPair,
} from './declarations';
import { isValidAsymmetricKeySize } from './crypto-utils';

let isSupported = false;

if (typeof window !== 'undefined') {
  sjcl.random.startCollectors();
  isSupported = true;
}

try {
  // eslint-disable-next-line
  // @ts-ignore: Still present on our fork
  sjcl.beware["CBC mode is dangerous because it doesn't protect message integrity."]();
} catch (e) {
  /** ignore error * */
}

/**
 * Generate a random hex key
 * @return New key as a hex string
 */
function generateKey(length: number): string {
  // Workaround when there isn't enough entropy (seen on IE 10)
  while (!sjcl.random.isReady()) {
    sjcl.random.addEntropy(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER), 1, 'Math.random()');
  }

  return generateKeyInternal(length * 2 || 64);
}

/**
 * Generate a 32-byte initialization vector as a hex string
 */
function generateInitializationVector(length: number): string {
  return generateKeyInternal(length * 2 || 32);
}

/**
 * Generate a key/IV value
 * @param  length Key length
 * @return New key/IV
 */
function generateKeyInternal(length: number): string {
  let key = '';
  do {
    const arr = sjclWordsToBytes(sjcl.random.randomWords(1));
    for (let i = 0; i < 4; i++) {
      let str = arr[i].toString(16);
      if (str.length === 1) {
        str = `0${str}`;
      }
      key += str;
    }
  } while (key.length < length);
  return key;
}

/**
 * Encrypt using a public key.
 * @param payload Payload to encrypt
 * @param publicKey PEM formatted public key
 * @return Encrypted payload
 */
async function encryptWithPublicKey(payload: Binary, publicKey: string): Promise<Binary> {
  console.assert(typeof payload === 'object');
  console.assert(typeof publicKey === 'string');
  const key = pki.publicKeyFromPem(publicKey);
  const ciphertext = key.encrypt(payload.asString(), 'RSA-OAEP');
  const result = Binary.fromBuffer(Buffer.from(ciphertext, 'binary'));
  return result;
}

/**
 * Generate an RSA key pair
 * @param size in bits, defaults to
 */
async function generateKeyPair(size: number = MIN_ASYMMETRIC_KEY_SIZE_BITS): Promise<PemKeyPair> {
  if (!isValidAsymmetricKeySize(size, MIN_ASYMMETRIC_KEY_SIZE_BITS)) {
    throw new Error('Invalid key size requested');
  }

  const keys: pki.rsa.KeyPair = await new Promise((resolve, reject) => {
    pki.rsa.generateKeyPair(size, /* exponent */ 0x10001, (err, keypair) => {
      if (err) {
        reject(err);
      } else {
        resolve(keypair);
      }
    });
  });
  return {
    publicKey: pki.publicKeyToPem(keys.publicKey),
    privateKey: pki.privateKeyToPem(keys.privateKey),
  };
}

function sjclWordsToBytes(words: sjcl.BitArray): number[] {
  // We want to represent the input as a 8-bytes array
  const byteArray = [];
  // An SJCL word is 32 bits
  for (let i = 0; i < words.length; i++) {
    let long = words[i];
    for (let j = 0; j < 4; j++) {
      /* eslint-disable no-bitwise */
      const byte = long & 0xff;
      /* eslint-enable no-bitwise */
      byteArray.push(byte);
      long = (long - byte) / 256;
    }
  }
  return byteArray;
}

function decryptSync(payload: Binary, key: Binary, iv: Binary, algorithm: string, authTag: Binary) {
  // Convert the key into a word array
  try {
    const cryptor = selectCryptor(algorithm);

    let payloadBytes = payload.asByteArray();
    if (algorithm === Algorithms.AES_256_GCM) {
      payloadBytes = payloadBytes.concat(authTag.asByteArray());
    }

    const keyWordArray = sjcl.codec.bytes.toBits(key.asByteArray());
    const blockCipher = new sjcl.cipher.aes(keyWordArray);
    const decryptedBitArray = cryptor.decrypt(
      blockCipher,
      sjcl.codec.bytes.toBits(payloadBytes),
      sjcl.codec.bytes.toBits(iv.asByteArray())
    );
    const decryptedByteArray = sjcl.codec.bytes.fromBits(decryptedBitArray);
    const decryptedBinary = Binary.fromByteArray(decryptedByteArray);

    return { payload: decryptedBinary };
  } catch (err) {
    if (err.message === "gcm: tag doesn't match") {
      throw new TdfDecryptError(err);
    }

    throw new TdfCorruptError('The TDF package is corrupt.', err, err.message);
  }
}

/**
 * Decrypt content synchronously
 * @param payload The payload to decrypt
 * @param key     The encryption key
 * @param iv      The initialization vector
 * @param algorithm The algorithm to use for encryption
 * @param authTag The authentication tag for authenticated crypto.
 */
async function decrypt(
  payload: Binary,
  key: Binary,
  iv: Binary,
  algorithm?: string,
  authTag?: Binary
): Promise<DecryptResult> {
  // @ts-ignore
  return decryptSync(payload, key, iv, algorithm, authTag);
}

/**
 * Decrypt a public-key encrypted payload with a private key
 * @param encryptedPayload Payload to decrypt
 * @param privateKey PEM formatted private key
 * @return Decrypted payload
 */
async function decryptWithPrivateKey(
  encryptedPayload: Binary,
  privateKey: string
): Promise<Binary> {
  console.assert(typeof encryptedPayload === 'object');
  console.assert(typeof privateKey === 'string');
  const key = pki.privateKeyFromPem(privateKey);
  const cleartext = key.decrypt(encryptedPayload.asString(), 'RSA-OAEP');
  return Binary.fromString(cleartext);
}

/**
 * Create a SHA256 hash
 * @param content String content
 * @return Hex hash
 */
function sha256(content: string): Promise<string> {
  const bitArray = sjcl.hash.sha256.hash(content);
  const hex = sjcl.codec.hex.fromBits(bitArray);
  return Promise.resolve(hex);
}

/**
 * Create an HMAC SHA256 hash
 * @param  key Key string
 * @param  content Content string
 * @return Hex hash
 */
async function hmac(key: string, content: string): Promise<string> {
  const hs256 = new sjcl.misc.hmac(sjcl.codec.hex.toBits(key), sjcl.hash.sha256);
  const hash = hs256.mac(sjcl.codec.utf8String.toBits(content));
  return sjcl.codec.hex.fromBits(hash);
}

/**
 * Encrypt content synchronously
 * @param payload The payload to encrypt
 * @param key The encryption key
 * @param iv The initialization vector
 * @return The encrypted output
 */
function encryptSync(payload: Binary, key: Binary, iv: Binary, algorithm?: string): EncryptResult {
  // Convert the key into a word array
  const encryptor = selectCryptor(algorithm);

  const keyWordArray = sjcl.codec.bytes.toBits(key.asByteArray());
  const blockCipher = new sjcl.cipher.aes(keyWordArray);
  const encryptResult = encryptor.encrypt(
    blockCipher,
    sjcl.codec.bytes.toBits(payload.asByteArray()),
    sjcl.codec.bytes.toBits(iv.asByteArray())
  );

  const encryptedPayload = sjcl.codec.bytes.fromBits(encryptResult);

  if (algorithm !== Algorithms.AES_256_GCM) {
    return {
      payload: Binary.fromByteArray(encryptedPayload),
    };
  }

  return {
    payload: Binary.fromByteArray(encryptedPayload.slice(0, -16)),
    authTag: Binary.fromByteArray(encryptedPayload.slice(-16)),
  };
}

type Cryptor = sjcl.SjclGCMMode | sjcl.SjclCBCMode;

function selectCryptor(algorithm?: string): Cryptor {
  if (algorithm === Algorithms.AES_256_GCM) {
    return sjcl.mode.gcm;
  }
  return sjcl.mode.cbc;
}

/**
 * Encrypt content.
 * @param payload   The payload to encrypt
 * @param key       The encryption key
 * @param iv        The initialization vector
 * @param algorithm The algorithm to use for encryption
 * @return The encrypted output
 */
function encrypt(
  payload: Binary,
  key: Binary,
  iv: Binary,
  algorithm?: string
): Promise<EncryptResult> {
  return Promise.resolve(encryptSync(payload, key, iv, algorithm));
}

export default {
  decrypt,
  decryptWithPrivateKey,
  encrypt,
  encryptWithPublicKey,
  generateInitializationVector,
  generateKey,
  generateKeyPair,
  hmac,
  isSupported,
  method: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  name: 'BrowserJsCryptoService',
  sha256,
};
