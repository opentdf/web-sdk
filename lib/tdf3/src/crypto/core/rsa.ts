import { Binary } from '../../binary.js';
import {
  type KeyAlgorithm,
  type KeyPair,
  MIN_ASYMMETRIC_KEY_SIZE_BITS,
  type PrivateKey,
  type PublicKey,
  type SymmetricKey,
} from '../declarations.js';
import { ConfigurationError } from '../../../../src/errors.js';
import { unwrapKey, unwrapSymmetricKey, wrapPrivateKey, wrapPublicKey } from './keys.js';

const ENC_DEC_METHODS: KeyUsage[] = ['encrypt', 'decrypt'];
const SIGN_VERIFY_METHODS: KeyUsage[] = ['sign', 'verify'];

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
    // 24 bit representation of 65537
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
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
    // 24 bit representation of 65537
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  };
}

/**
 * Generate an RSA key pair
 * @see    {@link https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey}
 * @param  size in bits
 */
export async function generateKeyPair(size?: number): Promise<KeyPair> {
  const keySize = size || MIN_ASYMMETRIC_KEY_SIZE_BITS;
  const algoDomString = rsaOaepSha1(keySize);
  const keyPair = await crypto.subtle.generateKey(algoDomString, true, ENC_DEC_METHODS);

  // Map to supported algorithm sizes
  let algorithm: KeyAlgorithm;
  if (keySize === 2048) {
    algorithm = 'rsa:2048';
  } else if (keySize === 4096) {
    algorithm = 'rsa:4096';
  } else {
    throw new ConfigurationError(
      `Unsupported RSA key size: ${keySize}. Only 2048 and 4096 are supported.`
    );
  }

  return {
    publicKey: wrapPublicKey(keyPair.publicKey, algorithm),
    privateKey: wrapPrivateKey(keyPair.privateKey, algorithm),
  };
}

/**
 * Generate an RSA key pair suitable for signatures
 * @see    {@link https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey}
 */
export async function generateSigningKeyPair(): Promise<KeyPair> {
  const rsaParams = rsaPkcs1Sha256(2048);
  const keyPair = await crypto.subtle.generateKey(rsaParams, true, SIGN_VERIFY_METHODS);

  const algorithm: KeyAlgorithm = 'rsa:2048';
  return {
    publicKey: wrapPublicKey(keyPair.publicKey, algorithm),
    privateKey: wrapPrivateKey(keyPair.privateKey, algorithm),
  };
}

/**
 * Encrypt using a public key (RSA-OAEP).
 * Accepts Binary or SymmetricKey for key wrapping.
 * @param payload Payload to encrypt (Binary) or symmetric key to wrap (SymmetricKey)
 * @param publicKey Opaque public key
 * @return Encrypted payload
 */
export async function encryptWithPublicKey(
  payload: Binary | SymmetricKey,
  publicKey: PublicKey
): Promise<Binary> {
  let payloadBuffer: BufferSource;

  // Handle SymmetricKey unwrapping
  if ('_brand' in payload && payload._brand === 'SymmetricKey') {
    // Pass Uint8Array directly — Web Crypto respects byteOffset/byteLength on typed array views.
    payloadBuffer = unwrapSymmetricKey(payload);
  } else {
    // Binary payload
    payloadBuffer = (payload as Binary).asArrayBuffer();
  }

  const cryptoKey = unwrapKey(publicKey);
  const result = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, cryptoKey, payloadBuffer);
  return Binary.fromArrayBuffer(result);
}

/**
 * Decrypt a public-key encrypted payload with a private key
 * @param  encryptedPayload  Payload to decrypt
 * @param  privateKey        Opaque private key
 * @return Decrypted payload
 */
export async function decryptWithPrivateKey(
  encryptedPayload: Binary,
  privateKey: PrivateKey
): Promise<Binary> {
  console.assert(typeof encryptedPayload === 'object', 'encryptedPayload must be object');

  const cryptoKey = unwrapKey(privateKey);
  const payload = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    cryptoKey,
    encryptedPayload.asArrayBuffer()
  );
  const bufferView = new Uint8Array(payload);
  return Binary.fromArrayBuffer(bufferView.buffer);
}
