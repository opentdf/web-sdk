import { Algorithms, type AlgorithmUrn } from '../../ciphers/algorithms.js';
import { Binary } from '../../binary.js';
import {
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
  type HashAlgorithm,
  type SymmetricKey,
} from '../declarations.js';
import { ConfigurationError, DecryptError } from '../../../../src/errors.js';
import { encodeArrayBuffer as hexEncode } from '../../../../src/encodings/hex.js';
import { keyMerge, keySplit } from '../../utils/keysplit.js';
import { unwrapSymmetricKey, wrapSymmetricKey } from './keys.js';

const ENC_DEC_METHODS: KeyUsage[] = ['encrypt', 'decrypt'];

/**
 * Generate a random symmetric key (opaque).
 * @param length - Key length in bytes (default 32 for AES-256)
 * @return Opaque symmetric key
 */
export async function generateKey(length?: number): Promise<SymmetricKey> {
  const keyBytes = await randomBytes(length || 32);
  return wrapSymmetricKey(keyBytes);
}

export async function randomBytes(byteLength: number): Promise<Uint8Array> {
  const randomValues = new Uint8Array(byteLength);
  crypto.getRandomValues(randomValues);
  return randomValues;
}

/**
 * Returns a promise to the encryption key as a binary string.
 */
export async function randomBytesAsHex(length: number): Promise<string> {
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  return hexEncode(randomValues.buffer);
}

/**
 * Decrypt content synchronously
 */
export function decrypt(
  payload: Binary,
  key: SymmetricKey,
  iv: Binary,
  algorithm?: AlgorithmUrn,
  authTag?: Binary
): Promise<DecryptResult> {
  return _doDecrypt(payload, key, iv, algorithm, authTag);
}

/**
 * Encrypt content synchronously
 */
export function encrypt(
  payload: Binary | SymmetricKey,
  key: SymmetricKey,
  iv: Binary,
  algorithm?: AlgorithmUrn
): Promise<EncryptResult> {
  return _doEncrypt(payload, key, iv, algorithm);
}

async function _doEncrypt(
  payload: Binary | SymmetricKey,
  key: SymmetricKey,
  iv: Binary,
  algorithm?: AlgorithmUrn
): Promise<EncryptResult> {
  console.assert(payload != null);
  console.assert(key != null);
  console.assert(iv != null);

  let payloadBuffer: BufferSource;
  if ('_brand' in payload && payload._brand === 'SymmetricKey') {
    payloadBuffer = unwrapSymmetricKey(payload);
  } else {
    payloadBuffer = (payload as Binary).asArrayBuffer();
  }

  const algoDomString = getSymmetricAlgoDomString(iv, algorithm);
  const keyBytes = unwrapSymmetricKey(key);
  const importedKey = await _importKey(keyBytes, algoDomString);
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
  key: SymmetricKey,
  iv: Binary,
  algorithm?: AlgorithmUrn,
  authTag?: Binary
): Promise<DecryptResult> {
  console.assert(payload != null);
  console.assert(key != null);
  console.assert(iv != null);

  let payloadBuffer = payload.asArrayBuffer();

  if (authTag) {
    const authTagBuffer = authTag.asArrayBuffer();
    const gcmPayload = new Uint8Array(payloadBuffer.byteLength + authTagBuffer.byteLength);
    gcmPayload.set(new Uint8Array(payloadBuffer), 0);
    gcmPayload.set(new Uint8Array(authTagBuffer), payloadBuffer.byteLength);
    payloadBuffer = gcmPayload.buffer;
  }

  const algoDomString = getSymmetricAlgoDomString(iv, algorithm);
  const keyBytes = unwrapSymmetricKey(key);
  const importedKey = await _importKey(keyBytes, algoDomString);
  algoDomString.iv = iv.asArrayBuffer();

  const decrypted = await crypto.subtle
    .decrypt(algoDomString, importedKey, payloadBuffer)
    .catch((err) => {
      if (err.name === 'OperationError') {
        throw new DecryptError(err);
      }

      throw err;
    });
  return { payload: Binary.fromArrayBuffer(decrypted) };
}

function _importKey(keyBytes: Uint8Array, algorithm: AesCbcParams | AesGcmParams) {
  return crypto.subtle.importKey('raw', keyBytes, algorithm, true, ENC_DEC_METHODS);
}

/**
 * Get a DOMString representing the algorithm to use for a crypto
 * operation. Defaults to AES-CBC.
 */
function getSymmetricAlgoDomString(
  iv: Binary,
  algorithm?: AlgorithmUrn
): AesCbcParams | AesGcmParams {
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
 * Create an ArrayBuffer from a hex string.
 */
export function hex2Ab(hex: string): ArrayBuffer {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bufferView = new Uint8Array(buffer);

  for (let index = 0; index < hex.length; index += 2) {
    bufferView[index / 2] = parseInt(hex.substr(index, 2), 16);
  }

  return buffer;
}

/**
 * Compute hash digest.
 */
export async function digest(algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> {
  const validAlgorithms: HashAlgorithm[] = ['SHA-256', 'SHA-384', 'SHA-512'];
  if (!validAlgorithms.includes(algorithm)) {
    throw new ConfigurationError(`Unsupported hash algorithm: ${algorithm}`);
  }

  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  return new Uint8Array(hashBuffer);
}

/**
 * Compute HMAC-SHA256 of data with a symmetric key.
 */
export async function hmac(data: Uint8Array, key: SymmetricKey): Promise<Uint8Array> {
  const keyBytes = unwrapSymmetricKey(key);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return new Uint8Array(signature);
}

/**
 * Verify HMAC-SHA256.
 */
export async function verifyHmac(
  data: Uint8Array,
  signature: Uint8Array,
  key: SymmetricKey
): Promise<boolean> {
  const keyBytes = unwrapSymmetricKey(key);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  return crypto.subtle.verify('HMAC', cryptoKey, signature, data);
}

/**
 * Import raw key bytes as an opaque symmetric key.
 */
export async function importSymmetricKey(keyBytes: Uint8Array): Promise<SymmetricKey> {
  return wrapSymmetricKey(keyBytes);
}

/**
 * Split a symmetric key into N shares using XOR secret sharing.
 */
export async function splitSymmetricKey(
  key: SymmetricKey,
  numShares: number
): Promise<SymmetricKey[]> {
  const keyBytes = unwrapSymmetricKey(key);
  const randomService = { randomBytes } as unknown as CryptoService;
  const splits = await keySplit(keyBytes, numShares, randomService);
  return splits.map(wrapSymmetricKey);
}

/**
 * Merge symmetric key shares back into the original key using XOR.
 */
export async function mergeSymmetricKeys(shares: SymmetricKey[]): Promise<SymmetricKey> {
  const splitBytes = shares.map(unwrapSymmetricKey);
  const merged = keyMerge(splitBytes);
  return wrapSymmetricKey(merged);
}
