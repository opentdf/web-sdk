import { Ciphers, CipherTagLengths } from './ciphers';

/**
 * Decrypt plaintext buffer to plaintext buffer
 *
 * Only supports AES-GCM
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
 *
 * @param key Encryption key
 * @param ciphertext Encrypted buffer
 * @param iv Initialization vector
 * @param tagLength Size (bits) of authentication tag
 * @returns Resolves plaintext buffer
 */
export default async function decrypt(
  key: CryptoKey,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tagLength?: number
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    {
      name: Ciphers.AesGcm,
      iv,
      tagLength: tagLength || CipherTagLengths.AesGcm,
    },
    key,
    ciphertext
  );
}
