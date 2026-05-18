import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { decodeArrayBuffer as base64Decode } from '../encodings/base64.js';
import { encodeArrayBuffer as hexEncode } from '../encodings/hex.js';

export const MLKEM768_OID_HEX = '0609608648016503040402';
export const MLKEM768_EK_BYTES = 1184;
export const MLKEM768_CT_BYTES = 1088;

// Bytes before the raw key in a well-formed ML-KEM-768 SPKI:
//   4 outer SEQUENCE header + 13 AlgorithmIdentifier + 4 BIT STRING header + 1 unused-bits = 22
const MLKEM768_SPKI_EK_OFFSET = 22;

/**
 * Extract the raw 1184-byte encapsulation key from an ML-KEM-768 SPKI blob.
 */
export function extractMLKEM768EkFromSpki(spkiBytes: ArrayBuffer): Uint8Array {
  const hex = hexEncode(spkiBytes);
  if (!hex.includes(MLKEM768_OID_HEX)) {
    throw new Error('Not an ML-KEM-768 SPKI public key');
  }
  const view = new Uint8Array(spkiBytes);
  if (view.length !== MLKEM768_SPKI_EK_OFFSET + MLKEM768_EK_BYTES) {
    throw new Error(`Invalid ML-KEM-768 SPKI length: ${view.length}`);
  }
  return view.slice(MLKEM768_SPKI_EK_OFFSET);
}

/**
 * Parse an ML-KEM-768 PEM public key and return the raw 1184-byte encapsulation key.
 */
export function parseMLKEM768PublicKeyPem(pem: string): Uint8Array {
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, '');
  const spkiBytes = base64Decode(b64);
  return extractMLKEM768EkFromSpki(spkiBytes);
}

/**
 * Encapsulate using ML-KEM-768: returns 1088-byte ciphertext and 32-byte shared secret.
 */
export function mlkem768Encapsulate(ek: Uint8Array): {
  cipherText: Uint8Array;
  sharedSecret: Uint8Array;
} {
  return ml_kem768.encapsulate(ek);
}

/**
 * AES-256 Key Wrap (RFC 3394) of raw key bytes using the given 32-byte wrapping key.
 * Returns 40 bytes for a 32-byte input key.
 */
export async function aesKwWrap(
  keyBytes: Uint8Array,
  wrappingKeyBytes: Uint8Array
): Promise<Uint8Array> {
  const wrappingKey = await crypto.subtle.importKey('raw', wrappingKeyBytes, 'AES-KW', false, [
    'wrapKey',
  ]);
  const keyToWrap = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const wrapped = await crypto.subtle.wrapKey('raw', keyToWrap, wrappingKey, 'AES-KW');
  return new Uint8Array(wrapped);
}
