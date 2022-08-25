import { Ciphers, CipherTagLengths } from './ciphers';

/**
 * Encrypt plaintext buffer to ciphertext buffer
 *
 * Only supports AES-GCM
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt
 *
 * @param key Encryption key
 * @param plaintext Buffer to encrypt
 * @param iv Initialization vector
 * @param tagLength Size (bits) of authentication tag
 * @returns Resolves ciphertext buffer
 */
export default async function encrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
  iv: Uint8Array,
  tagLength?: number
): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt(
    {
      name: Ciphers.AesGcm,
      iv,
      tagLength: tagLength || CipherTagLengths.AesGcm,
    },
    key,
    plaintext
  );
}
