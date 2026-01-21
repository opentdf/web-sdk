/**
 * This file is for using native crypto in the browser.
 *
 * @private
 */

import { Algorithms } from '../ciphers/index.js';
import { Binary } from '../binary.js';
import {
  type AsymmetricSigningAlgorithm,
  type CryptoService,
  type DecryptResult,
  type ECCurve,
  type EncryptResult,
  type HashAlgorithm,
  type HkdfParams,
  MIN_ASYMMETRIC_KEY_SIZE_BITS,
  type PemKeyPair,
  type PublicKeyInfo,
} from './declarations.js';
import { ConfigurationError, DecryptError } from '../../../src/errors.js';
import { formatAsPem, removePemFormatting } from './crypto-utils.js';
import { encodeArrayBuffer as hexEncode } from '../../../src/encodings/hex.js';
import { decodeArrayBuffer as base64Decode } from '../../../src/encodings/base64.js';
import { AlgorithmUrn } from '../ciphers/algorithms.js';
import { exportSPKI, importX509 } from 'jose';

// Used to pass into native crypto functions
const METHODS: KeyUsage[] = ['encrypt', 'decrypt'];
export const isSupported = typeof globalThis?.crypto !== 'undefined';

export const method = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
export const name = 'BrowserNativeCryptoService';

/**
 * Get a DOMString representing the algorithm to use for an
 * asymmetric key generation.
 */
export function rsaOaepSha1(
  modulusLength: number = MIN_ASYMMETRIC_KEY_SIZE_BITS
): RsaHashedKeyGenParams {
  if (!modulusLength || modulusLength < MIN_ASYMMETRIC_KEY_SIZE_BITS) {
    throw new ConfigurationError('Invalid key size requested');
  }
  return {
    name: 'RSA-OAEP',
    hash: {
      name: 'SHA-1',
    },
    modulusLength,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 24 bit representation of 65537
  };
}

export function rsaPkcs1Sha256(
  modulusLength: number = MIN_ASYMMETRIC_KEY_SIZE_BITS
): RsaHashedKeyGenParams {
  if (!modulusLength || modulusLength < MIN_ASYMMETRIC_KEY_SIZE_BITS) {
    throw new ConfigurationError('Invalid key size requested');
  }
  return {
    name: 'RSASSA-PKCS1-v1_5',
    hash: {
      name: 'SHA-256',
    },
    modulusLength,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 24 bit representation of 65537
  };
}

/**
 * Generate a random hex key
 * @return New key as a hex string
 */
export async function generateKey(length?: number): Promise<string> {
  return randomBytesAsHex(length || 32);
}

/**
 * Generate an RSA key pair
 * @see    {@link https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey}
 * @param  size in bits
 */
export async function generateKeyPair(size?: number): Promise<CryptoKeyPair> {
  const algoDomString = rsaOaepSha1(size || MIN_ASYMMETRIC_KEY_SIZE_BITS);
  return crypto.subtle.generateKey(algoDomString, true, METHODS);
}

/**
 * Generate an RSA key pair suitable for signatures
 * @see    {@link https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey}
 */
export async function generateSigningKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    },
    true,
    ['sign', 'verify']
  );
}

export async function cryptoToPemPair(keysMaybe: unknown): Promise<PemKeyPair> {
  const keys = keysMaybe as CryptoKeyPair;
  if (!keys.privateKey || !keys.publicKey) {
    // These are only ever generated here, so this should not happen
    throw new Error('internal: invalid keys');
  }

  const [exPublic, exPrivate] = await Promise.all([
    crypto.subtle.exportKey('spki', keys.publicKey),
    crypto.subtle.exportKey('pkcs8', keys.privateKey),
  ]);
  return {
    publicKey: formatAsPem(exPublic, 'PUBLIC KEY'),
    privateKey: formatAsPem(exPrivate, 'PRIVATE KEY'),
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

  const algoDomString = rsaOaepSha1();

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
export async function generateInitializationVector(length?: number): Promise<string> {
  return randomBytesAsHex(length || 16);
}

export async function randomBytes(byteLength: number): Promise<Uint8Array> {
  const r = new Uint8Array(byteLength);
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
export async function randomBytesAsHex(length: number): Promise<string> {
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
  console.assert(typeof encryptedPayload === 'object', 'encryptedPayload must be object');
  console.assert(typeof privateKey === 'string', 'privateKey must be string');

  const algoDomString = rsaOaepSha1();

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
  algorithm?: AlgorithmUrn,
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
  algorithm?: AlgorithmUrn
): Promise<EncryptResult> {
  return _doEncrypt(payload, key, iv, algorithm);
}

async function _doEncrypt(
  payload: Binary,
  key: Binary,
  iv: Binary,
  algorithm?: AlgorithmUrn
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
  algorithm?: AlgorithmUrn,
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
        throw new DecryptError(err);
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

/**
 * Get the Web Crypto algorithm parameters for a signing algorithm.
 */
function getSigningAlgorithmParams(algorithm: AsymmetricSigningAlgorithm): {
  importParams: RsaHashedImportParams | EcKeyImportParams;
  signParams: AlgorithmIdentifier | EcdsaParams;
} {
  switch (algorithm) {
    case 'RS256':
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        signParams: 'RSASSA-PKCS1-v1_5',
      };
    case 'ES256':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-256' },
        signParams: { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
      };
    case 'ES384':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-384' },
        signParams: { name: 'ECDSA', hash: 'SHA-384' } as EcdsaParams,
      };
    case 'ES512':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-521' },
        signParams: { name: 'ECDSA', hash: 'SHA-512' } as EcdsaParams,
      };
    default:
      throw new ConfigurationError(`Unsupported signing algorithm: ${algorithm}`);
  }
}

/**
 * Convert IEEE P1363 signature format (used by WebCrypto ECDSA) to DER format (used by JWT).
 * RS256 signatures don't need conversion.
 */
function ieeeP1363ToDer(signature: Uint8Array, algorithm: AsymmetricSigningAlgorithm): Uint8Array {
  if (algorithm === 'RS256') {
    return signature;
  }

  // IEEE P1363: r || s where each is padded to key size
  const halfLen = signature.length / 2;
  const r = signature.slice(0, halfLen);
  const s = signature.slice(halfLen);

  // Remove leading zeros but keep one if the high bit is set
  const trimLeadingZeros = (arr: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < arr.length - 1 && arr[i] === 0) i++;
    return arr.slice(i);
  };

  let rTrimmed = trimLeadingZeros(r);
  let sTrimmed = trimLeadingZeros(s);

  // Add leading zero if high bit is set (to keep positive in DER)
  if (rTrimmed[0] & 0x80) {
    const padded = new Uint8Array(rTrimmed.length + 1);
    padded.set(rTrimmed, 1);
    rTrimmed = padded;
  }
  if (sTrimmed[0] & 0x80) {
    const padded = new Uint8Array(sTrimmed.length + 1);
    padded.set(sTrimmed, 1);
    sTrimmed = padded;
  }

  // DER SEQUENCE: 0x30 [length] [r INTEGER] [s INTEGER]
  // INTEGER: 0x02 [length] [value]
  const rDer = new Uint8Array([0x02, rTrimmed.length, ...rTrimmed]);
  const sDer = new Uint8Array([0x02, sTrimmed.length, ...sTrimmed]);

  const seqLen = rDer.length + sDer.length;
  const result = new Uint8Array(2 + seqLen);
  result[0] = 0x30;
  result[1] = seqLen;
  result.set(rDer, 2);
  result.set(sDer, 2 + rDer.length);

  return result;
}

/**
 * Convert DER signature format (used by JWT) to IEEE P1363 format (used by WebCrypto ECDSA).
 * RS256 signatures don't need conversion.
 */
function derToIeeeP1363(signature: Uint8Array, algorithm: AsymmetricSigningAlgorithm): Uint8Array {
  if (algorithm === 'RS256') {
    return signature;
  }

  // Determine the expected component length based on algorithm
  let componentLen: number;
  switch (algorithm) {
    case 'ES256':
      componentLen = 32;
      break;
    case 'ES384':
      componentLen = 48;
      break;
    case 'ES512':
      componentLen = 66;
      break;
    default:
      throw new ConfigurationError(`Unsupported algorithm for DER conversion: ${algorithm}`);
  }

  // Parse DER: SEQUENCE { INTEGER r, INTEGER s }
  if (signature[0] !== 0x30) {
    throw new ConfigurationError('Invalid DER signature: expected SEQUENCE');
  }

  let offset = 2; // Skip SEQUENCE tag and length

  // Parse r INTEGER
  if (signature[offset] !== 0x02) {
    throw new ConfigurationError('Invalid DER signature: expected INTEGER for r');
  }
  const rLen = signature[offset + 1];
  offset += 2;
  let r = signature.slice(offset, offset + rLen);
  offset += rLen;

  // Parse s INTEGER
  if (signature[offset] !== 0x02) {
    throw new ConfigurationError('Invalid DER signature: expected INTEGER for s');
  }
  const sLen = signature[offset + 1];
  offset += 2;
  let s = signature.slice(offset, offset + sLen);

  // Remove leading zero padding if present
  if (r[0] === 0 && r.length > componentLen) {
    r = r.slice(1);
  }
  if (s[0] === 0 && s.length > componentLen) {
    s = s.slice(1);
  }

  // Pad to component length
  const result = new Uint8Array(componentLen * 2);
  result.set(r, componentLen - r.length);
  result.set(s, componentLen * 2 - s.length);

  return result;
}

/**
 * Sign data with an asymmetric private key.
 */
export async function sign(
  data: Uint8Array,
  privateKeyPem: string,
  algorithm: AsymmetricSigningAlgorithm
): Promise<Uint8Array> {
  const { importParams, signParams } = getSigningAlgorithmParams(algorithm);

  // Remove PEM formatting and decode
  const keyData = removePemFormatting(privateKeyPem);
  const keyBuffer = base64Decode(keyData);

  // Import private key
  const key = await crypto.subtle.importKey('pkcs8', keyBuffer, importParams, false, ['sign']);

  // Sign the data
  const signature = await crypto.subtle.sign(signParams, key, data);

  // Convert from IEEE P1363 to DER for EC algorithms
  return ieeeP1363ToDer(new Uint8Array(signature), algorithm);
}

/**
 * Verify signature with an asymmetric public key.
 */
export async function verify(
  data: Uint8Array,
  signature: Uint8Array,
  publicKeyPem: string,
  algorithm: AsymmetricSigningAlgorithm
): Promise<boolean> {
  const { importParams, signParams } = getSigningAlgorithmParams(algorithm);

  // Remove PEM formatting and decode
  const keyData = removePemFormatting(publicKeyPem);
  const keyBuffer = base64Decode(keyData);

  // Import public key
  const key = await crypto.subtle.importKey('spki', keyBuffer, importParams, false, ['verify']);

  // Convert from DER to IEEE P1363 for EC algorithms
  const ieeeSignature = derToIeeeP1363(signature, algorithm);

  // Verify the signature
  return crypto.subtle.verify(signParams, key, ieeeSignature, data);
}

/**
 * Compute hash digest.
 */
export async function digest(algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> {
  // Validate algorithm and map to Web Crypto name
  const validAlgorithms: HashAlgorithm[] = ['SHA-256', 'SHA-384', 'SHA-512'];
  if (!validAlgorithms.includes(algorithm)) {
    throw new ConfigurationError(`Unsupported hash algorithm: ${algorithm}`);
  }

  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  return new Uint8Array(hashBuffer);
}

/**
 * Extract PEM public key from X.509 certificate or return PEM key as-is.
 *
 * Note: Currently only RS256 (RSA with SHA-256) X.509 certificates are supported,
 * because the underlying `jose.importX509` API requires an explicit algorithm
 * and this function passes `'RS256'` as that parameter.
 */
export async function extractPublicKeyPem(certOrPem: string): Promise<string> {
  // If it's a certificate, extract the public key
  if (certOrPem.includes('-----BEGIN CERTIFICATE-----')) {
    const cert = await importX509(certOrPem, 'RS256', { extractable: true });
    return exportSPKI(cert);
  }

  // If it's already a PEM public key, return as-is
  if (certOrPem.includes('-----BEGIN PUBLIC KEY-----')) {
    return certOrPem;
  }

  throw new ConfigurationError('Input must be a PEM-encoded certificate or public key');
}

/**
 * Map ECCurve to Web Crypto named curve.
 */
function curveToNamedCurve(curve: ECCurve): string {
  switch (curve) {
    case 'P-256':
      return 'P-256';
    case 'P-384':
      return 'P-384';
    case 'P-521':
      return 'P-521';
    default:
      throw new ConfigurationError(`Unsupported curve: ${curve}`);
  }
}

/**
 * Generate an EC key pair for ECDH key agreement or ECDSA signing.
 */
export async function generateECKeyPair(curve: ECCurve = 'P-256'): Promise<PemKeyPair> {
  const namedCurve = curveToNamedCurve(curve);

  // Generate key pair using ECDH (can be used for both ECDH and ECDSA)
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve }, true, [
    'deriveBits',
  ]);

  // Export to PEM format
  const [publicKeyBuffer, privateKeyBuffer] = await Promise.all([
    crypto.subtle.exportKey('spki', keyPair.publicKey),
    crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
  ]);

  return {
    publicKey: formatAsPem(publicKeyBuffer, 'PUBLIC KEY'),
    privateKey: formatAsPem(privateKeyBuffer, 'PRIVATE KEY'),
  };
}

/**
 * Known EC curve OIDs mapped to their names.
 * - P-256 (secp256r1): 1.2.840.10045.3.1.7
 * - P-384 (secp384r1): 1.3.132.0.34
 * - P-521 (secp521r1): 1.3.132.0.35
 */
const EC_CURVE_OIDS: { oid: number[]; curve: 'P-256' | 'P-384' | 'P-521' }[] = [
  { oid: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], curve: 'P-256' }, // 1.2.840.10045.3.1.7
  { oid: [0x2b, 0x81, 0x04, 0x00, 0x22], curve: 'P-384' }, // 1.3.132.0.34
  { oid: [0x2b, 0x81, 0x04, 0x00, 0x23], curve: 'P-521' }, // 1.3.132.0.35
];

/**
 * Extract EC curve name from SPKI or PKCS#8 DER-encoded key.
 *
 * SPKI structure for EC:
 * SEQUENCE {
 *   SEQUENCE {
 *     OBJECT IDENTIFIER id-ecPublicKey (1.2.840.10045.2.1)
 *     OBJECT IDENTIFIER namedCurve
 *   }
 *   BIT STRING (public key point)
 * }
 *
 * PKCS#8 structure for EC:
 * SEQUENCE {
 *   INTEGER version
 *   SEQUENCE {
 *     OBJECT IDENTIFIER id-ecPublicKey (1.2.840.10045.2.1)
 *     OBJECT IDENTIFIER namedCurve
 *   }
 *   OCTET STRING (private key)
 * }
 */
function extractEcCurveFromKey(keyData: Uint8Array): 'P-256' | 'P-384' | 'P-521' {
  // Search for curve OID in the key data
  // The curve OID follows the ecPublicKey OID (1.2.840.10045.2.1)
  for (const { oid, curve } of EC_CURVE_OIDS) {
    // Search for this OID pattern in the key data
    const oidWithTag = [0x06, oid.length, ...oid]; // OBJECT IDENTIFIER tag + length + oid
    for (let i = 0; i < keyData.length - oidWithTag.length; i++) {
      let match = true;
      for (let j = 0; j < oidWithTag.length; j++) {
        if (keyData[i + j] !== oidWithTag[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        return curve;
      }
    }
  }

  throw new ConfigurationError('Unable to determine EC curve from key - unsupported curve');
}

/**
 * Perform ECDH key agreement followed by HKDF key derivation.
 */
export async function deriveKeyFromECDH(
  privateKeyPem: string,
  publicKeyPem: string,
  hkdfParams: HkdfParams
): Promise<Uint8Array> {
  const privateKeyData = base64Decode(removePemFormatting(privateKeyPem));
  const publicKeyData = base64Decode(removePemFormatting(publicKeyPem));

  // Extract curve from the public key's ASN.1 structure
  const detectedCurve = extractEcCurveFromKey(new Uint8Array(publicKeyData));

  // Import keys with the detected curve
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyData,
    { name: 'ECDH', namedCurve: detectedCurve },
    false,
    ['deriveBits']
  );
  const publicKey = await crypto.subtle.importKey(
    'spki',
    publicKeyData,
    { name: 'ECDH', namedCurve: detectedCurve },
    false,
    []
  );

  // Determine bits based on curve
  let bits: number;
  switch (detectedCurve) {
    case 'P-256':
      bits = 256;
      break;
    case 'P-384':
      bits = 384;
      break;
    case 'P-521':
      bits = 528; // P-521 derives 528 bits (66 bytes)
      break;
  }

  // Perform ECDH to get shared secret
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    bits
  );

  // Import shared secret as HKDF key material
  const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);

  // Derive the final key using HKDF
  const keyLength = hkdfParams.keyLength ?? 256;
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: hkdfParams.hash,
      salt: hkdfParams.salt,
      info: hkdfParams.info ?? new Uint8Array(0),
    },
    hkdfKey,
    { name: 'AES-GCM', length: keyLength },
    true,
    ['encrypt', 'decrypt']
  );

  // Export the derived key as raw bytes
  const keyBytes = await crypto.subtle.exportKey('raw', derivedKey);
  return new Uint8Array(keyBytes);
}

/**
 * Sign data with a symmetric key (HMAC-SHA256).
 */
export async function signSymmetric(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return new Uint8Array(signature);
}

/**
 * Verify symmetric signature (HMAC-SHA256).
 */
export async function verifySymmetric(
  data: Uint8Array,
  signature: Uint8Array,
  key: Uint8Array
): Promise<boolean> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  return crypto.subtle.verify('HMAC', cryptoKey, signature, data);
}

/**
 * Parse ASN.1 DER length field.
 * Returns [length, bytesConsumed].
 */
function parseAsn1Length(data: Uint8Array, offset: number): [number, number] {
  const firstByte = data[offset];
  if (firstByte < 0x80) {
    // Short form: length is directly encoded
    return [firstByte, 1];
  }
  // Long form: first byte indicates number of length bytes
  const numLengthBytes = firstByte & 0x7f;
  let length = 0;
  for (let i = 0; i < numLengthBytes; i++) {
    length = (length << 8) | data[offset + 1 + i];
  }
  return [length, 1 + numLengthBytes];
}

/**
 * Extract RSA modulus bit length from SPKI DER-encoded public key.
 *
 * SPKI structure for RSA:
 * SEQUENCE {
 *   SEQUENCE { OBJECT IDENTIFIER rsaEncryption, NULL }
 *   BIT STRING {
 *     SEQUENCE {
 *       INTEGER modulus (n)
 *       INTEGER publicExponent (e)
 *     }
 *   }
 * }
 */
function extractRsaModulusBitLength(spkiData: Uint8Array): number {
  let offset = 0;

  // Outer SEQUENCE
  if (spkiData[offset] !== 0x30) {
    throw new ConfigurationError('Invalid SPKI: expected SEQUENCE');
  }
  offset++;
  const [, outerLenBytes] = parseAsn1Length(spkiData, offset);
  offset += outerLenBytes;

  // Algorithm SEQUENCE
  if (spkiData[offset] !== 0x30) {
    throw new ConfigurationError('Invalid SPKI: expected algorithm SEQUENCE');
  }
  offset++;
  const [algLen, algLenBytes] = parseAsn1Length(spkiData, offset);
  offset += algLenBytes + algLen; // Skip entire algorithm sequence

  // BIT STRING containing the public key
  if (spkiData[offset] !== 0x03) {
    throw new ConfigurationError('Invalid SPKI: expected BIT STRING');
  }
  offset++;
  const [, bitStringLenBytes] = parseAsn1Length(spkiData, offset);
  offset += bitStringLenBytes;

  // Skip unused bits byte (should be 0 for RSA keys)
  offset++;

  // Inner SEQUENCE containing modulus and exponent
  if (spkiData[offset] !== 0x30) {
    throw new ConfigurationError('Invalid SPKI: expected inner SEQUENCE');
  }
  offset++;
  const [, innerLenBytes] = parseAsn1Length(spkiData, offset);
  offset += innerLenBytes;

  // INTEGER (modulus)
  if (spkiData[offset] !== 0x02) {
    throw new ConfigurationError('Invalid SPKI: expected INTEGER for modulus');
  }
  offset++;
  const [modulusLen] = parseAsn1Length(spkiData, offset);

  // The modulus length in bytes, accounting for possible leading zero padding
  // (ASN.1 integers are signed, so a leading 0x00 is added if high bit is set)
  let effectiveLen = modulusLen;
  const modulusOffset = offset + parseAsn1Length(spkiData, offset)[1];
  if (spkiData[modulusOffset] === 0x00) {
    effectiveLen--;
  }

  return effectiveLen * 8;
}

/**
 * Import and validate a PEM public key, returning algorithm info.
 */
export async function importPublicKeyPem(pem: string): Promise<PublicKeyInfo> {
  // First extract public key if it's a certificate
  let publicKeyPem = pem;
  if (pem.includes('-----BEGIN CERTIFICATE-----')) {
    publicKeyPem = await extractPublicKeyPem(pem);
  }

  if (!publicKeyPem.includes('-----BEGIN PUBLIC KEY-----')) {
    throw new ConfigurationError('Input must be a PEM-encoded public key or certificate');
  }

  const keyData = base64Decode(removePemFormatting(publicKeyPem));

  // Try RSA first
  try {
    await crypto.subtle.importKey('spki', keyData, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, [
      'encrypt',
    ]);
    // Parse ASN.1 to get the actual modulus bit length
    const modulusBits = extractRsaModulusBitLength(new Uint8Array(keyData));
    let algorithm: PublicKeyInfo['algorithm'];
    if (modulusBits <= 2048) {
      algorithm = 'rsa:2048';
    } else if (modulusBits <= 4096) {
      algorithm = 'rsa:4096';
    } else {
      throw new ConfigurationError(`Unsupported RSA key size: ${modulusBits} bits`);
    }
    return { algorithm, pem: publicKeyPem };
  } catch (e) {
    // If it's our own error about key size, rethrow
    if (e instanceof ConfigurationError && e.message.includes('RSA key size')) {
      throw e;
    }
    // Not an RSA key, try EC curves next
  }

  // Try EC - extract curve from ASN.1 structure
  try {
    const detectedCurve = extractEcCurveFromKey(new Uint8Array(keyData));
    // Validate by attempting import with the detected curve
    await crypto.subtle.importKey('spki', keyData, { name: 'ECDH', namedCurve: detectedCurve }, false, []);
    const curveMap = {
      'P-256': 'ec:secp256r1',
      'P-384': 'ec:secp384r1',
      'P-521': 'ec:secp521r1',
    } as const;
    return { algorithm: curveMap[detectedCurve], pem: publicKeyPem };
  } catch {
    // Not a valid EC key
  }

  throw new ConfigurationError('Unable to determine public key algorithm - unsupported key type');
}

/**
 * Convert a JWK (JSON Web Key) to PEM format.
 */
export async function jwkToPem(jwk: JsonWebKey): Promise<string> {
  let key: CryptoKey;

  if (jwk.kty === 'RSA') {
    // RSA key
    key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [
      'encrypt',
    ]);
  } else if (jwk.kty === 'EC') {
    // EC key
    const crv = jwk.crv;
    if (!crv || !['P-256', 'P-384', 'P-521'].includes(crv)) {
      throw new ConfigurationError(`Unsupported EC curve: ${crv}`);
    }
    key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: crv }, true, []);
  } else {
    throw new ConfigurationError(`Unsupported JWK key type: ${jwk.kty}`);
  }

  const spkiBuffer = await crypto.subtle.exportKey('spki', key);
  return formatAsPem(spkiBuffer, 'PUBLIC KEY');
}

export const DefaultCryptoService: CryptoService = {
  name,
  method,
  cryptoToPemPair,
  decrypt,
  decryptWithPrivateKey,
  deriveKeyFromECDH,
  digest,
  encrypt,
  encryptWithPublicKey,
  extractPublicKeyPem,
  generateECKeyPair,
  generateInitializationVector,
  generateKey,
  generateKeyPair,
  generateSigningKeyPair,
  hmac,
  importPublicKeyPem,
  jwkToPem,
  randomBytes,
  sha256,
  sign,
  signSymmetric,
  verify,
  verifySymmetric,
};
