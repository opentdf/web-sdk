import { CipherType, KeyFormat, KeyUsageType } from './enums';

/**
 * Import raw key
 *
 * A specific implementation of the importKey method to import raw keys. Specifies some defaults
 * to ensure security.
 *
 * @param key Key which needs to be imported
 * @param keyUsages How the key will be used
 * @param isExtractable Whether key is extractable
 */
export default async function importRawKey(
  key: ArrayBuffer,
  keyUsages: Array<KeyUsageType>,
  isExtractable = false
): Promise<CryptoKey> {
  return crypto.subtle.importKey(KeyFormat.Raw, key, CipherType.AesGcm, isExtractable, keyUsages);
}
